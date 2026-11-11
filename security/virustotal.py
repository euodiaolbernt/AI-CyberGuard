"""
VirusTotal API v3 client.

A thin wrapper around the three endpoints this system needs:

  GET  /api/v3/urls/{url_id}   fetch an EXISTING analysis report
  POST /api/v3/urls            submit a URL for a NEW analysis
  GET  /api/v3/analyses/{id}   poll a submitted analysis until it finishes

The API key is read from config.py (itself from .env), is only ever
sent as the "x-apikey" request header, and is never logged, returned
to the frontend, or written to the database.

Nothing in this module opens the submitted URL itself - VirusTotal's
own infrastructure does the fetching/sandboxing on their end; we only
ever call virustotal.com.
"""
import base64
import time

import requests

import config

BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15           # seconds, per HTTP call
POLL_ATTEMPTS = 4              # for a freshly-submitted URL with no report yet
POLL_DELAY_SECONDS = 4


class VirusTotalError(Exception):
    """Any VirusTotal API failure: missing key, auth, rate limit, network."""


def _headers():
    if not config.VIRUSTOTAL_API_KEY:
        raise VirusTotalError(
            "VIRUSTOTAL_API_KEY is not configured. Add it to your .env file."
        )
    return {"x-apikey": config.VIRUSTOTAL_API_KEY}


def _url_id(url: str) -> str:
    """VirusTotal's documented URL identifier: URL-safe base64 of the
    URL string, with padding stripped."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _request(method: str, url: str, *, allow_404: bool = False, **kwargs) -> requests.Response:
    """Shared request wrapper: distinguishes a genuine network failure
    from a timeout (requirement: group these as "service/connectivity
    problems", but still tell them apart in the log), then checks the
    response for every documented VT v3 error status BEFORE handing
    control back to the caller - so every endpoint (urls, analyses)
    gets the exact same clear, specific error for the exact same
    status code, instead of each one inventing its own handling.

    Diagnostic detail (status code, endpoint path, VT's own error
    code/message if present) is logged to the server console for
    development - never the request headers, so the API key (sent only
    ever as "x-apikey") can never end up in a log line or an on-screen
    message."""
    try:
        resp = requests.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
    except requests.Timeout:
        print(f"[virustotal] timeout calling {method} {url}")
        raise VirusTotalError(
            "VirusTotal did not respond in time. This is usually temporary - please try again."
        )
    except requests.RequestException as e:
        print(f"[virustotal] network error calling {method} {url}: {type(e).__name__}")
        raise VirusTotalError(
            "Could not reach VirusTotal - check your internet connection and try again."
        )

    if allow_404 and resp.status_code == 404:
        return resp
    _raise_for_known_errors(resp, method, url)
    return resp


def get_existing_report(url: str):
    """Return VirusTotal's existing analysis report for `url` (a dict),
    or None if they have never scanned it (an ordinary, expected
    outcome - not an error, so allow_404 keeps it from being raised as
    one). Never submits a new scan."""
    resp = _request("GET", f"{BASE_URL}/urls/{_url_id(url)}", headers=_headers(), allow_404=True)
    if resp.status_code == 404:
        return None
    return resp.json()["data"]


def submit_url(url: str) -> str:
    """Submit `url` to VirusTotal for a fresh scan. Returns the analysis id."""
    resp = _request("POST", f"{BASE_URL}/urls", headers=_headers(), data={"url": url})
    return resp.json()["data"]["id"]


def poll_analysis(analysis_id: str):
    """Poll a submitted analysis until it completes or attempts run out.
    Returns the analysis data dict - its 'status' may still be
    'queued'/'inprogress' if it genuinely didn't finish in time; the
    caller decides how to present that."""
    data = None
    for _ in range(POLL_ATTEMPTS):
        resp = _request("GET", f"{BASE_URL}/analyses/{analysis_id}", headers=_headers())
        data = resp.json()["data"]
        if data["attributes"]["status"] == "completed":
            return data
        time.sleep(POLL_DELAY_SECONDS)
    return data


def _vt_error_detail(resp: requests.Response) -> str:
    """VirusTotal's own error code/message from the JSON body, if any -
    useful detail for the server-side log, never shown raw to the user
    (the caller's own messages below are what's user-facing)."""
    try:
        err = resp.json().get("error", {})
        return f"{err.get('code', '?')}: {err.get('message', '?')}"
    except Exception:
        return resp.text[:200]


def _raise_for_known_errors(resp: requests.Response, method: str, url: str):
    """One place covering every VT v3 status this app's own requirements
    call out by name, each with its own clear, specific message - a 400
    reads differently from a 401, which reads differently from a 429,
    instead of all of them collapsing into the same generic
    requests.HTTPError text. 404 is NOT handled here: the only endpoint
    that can legitimately 404 (an existing-report lookup, meaning "never
    scanned before") treats it as a normal, non-error outcome in
    get_existing_report() - this only covers a 404 from anywhere else
    (e.g. an analysis id that's gone missing), which genuinely is an error."""
    if resp.status_code < 400:
        return

    detail = _vt_error_detail(resp)
    print(f"[virustotal] {method} {url} -> HTTP {resp.status_code}: {detail}")

    if resp.status_code == 400:
        raise VirusTotalError(
            "VirusTotal rejected this request as malformed (400 Bad Request). "
            "This usually means the URL isn't in a format VirusTotal accepts - "
            "double-check it and try again."
        )
    if resp.status_code in (401, 403):
        raise VirusTotalError(
            "VirusTotal rejected the API key or denied permission for this "
            f"operation ({resp.status_code}). Check VIRUSTOTAL_API_KEY in your "
            "`.env` file and that your VirusTotal account allows this request."
        )
    if resp.status_code == 404:
        raise VirusTotalError("VirusTotal could not find the requested resource (404).")
    if resp.status_code == 429:
        raise VirusTotalError(
            "VirusTotal's API quota or rate limit has been reached (429). "
            "Please wait before scanning again."
        )
    if resp.status_code >= 500:
        raise VirusTotalError(
            f"VirusTotal's service is having problems right now ({resp.status_code}). "
            "This is on their end, not yours - please try again shortly."
        )
    raise VirusTotalError(
        f"VirusTotal returned an unexpected error (HTTP {resp.status_code})."
    )
