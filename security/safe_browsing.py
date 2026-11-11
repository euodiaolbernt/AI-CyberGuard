"""
Google Safe Browsing API v4 client.

A thin wrapper around the one endpoint this system needs:

    POST https://safebrowsing.googleapis.com/v4/threatMatches:find

- Optional second threat-intel source: security/url_scanner.py already
  works on VirusTotal alone; this is consulted ADDITIONALLY when
  config.GOOGLE_SAFE_BROWSING_API_KEY is set, never required.
- The API key is sent only as the documented "key" query parameter,
  read from config.py (itself from .env) - never logged, returned to
  the frontend, or written to the database.
- Nothing here opens, fetches, or executes the submitted URL - Google's
  own infrastructure checks it against their threat lists; we only
  ever call safebrowsing.googleapis.com with the URL string.
"""
import requests

import config

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
REQUEST_TIMEOUT = 10  # seconds

# The 4 threat types Safe Browsing reports, in the exact spelling its
# API uses - matched case-sensitively against what Google returns.
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",       # Google's name for phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

_PLATFORM_TYPES = ["ANY_PLATFORM"]
_THREAT_ENTRY_TYPES = ["URL"]


class SafeBrowsingError(Exception):
    """Any Safe Browsing API failure: auth, rate limit, network."""


def check_url(url: str):
    """Return the list of threat type strings (e.g. ["SOCIAL_ENGINEERING"])
    Google Safe Browsing matched for `url`, or an empty list if clean.
    Raises SafeBrowsingError on a genuine API/network failure - the
    caller (security/url_scanner.py) treats that as "this source
    couldn't be consulted", never as "therefore malicious" or
    "therefore safe". Returns [] immediately, without a request, if no
    API key is configured - this source is purely additive."""
    if not config.GOOGLE_SAFE_BROWSING_API_KEY:
        return []

    body = {
        "client": {"clientId": "ai-cyberguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": _PLATFORM_TYPES,
            "threatEntryTypes": _THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            _ENDPOINT,
            params={"key": config.GOOGLE_SAFE_BROWSING_API_KEY},
            json=body,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.Timeout:
        print(f"[safe_browsing] timeout calling threatMatches:find")
        raise SafeBrowsingError("Google Safe Browsing did not respond in time.")
    except requests.RequestException as e:
        print(f"[safe_browsing] network error: {type(e).__name__}")
        raise SafeBrowsingError("Could not reach Google Safe Browsing.")

    if resp.status_code == 429:
        raise SafeBrowsingError("Google Safe Browsing's rate limit was reached.")
    if resp.status_code in (401, 403):
        raise SafeBrowsingError(
            "Google Safe Browsing rejected the API key. Check "
            "GOOGLE_SAFE_BROWSING_API_KEY in your `.env` file."
        )
    if resp.status_code >= 400:
        detail = resp.text[:200]
        print(f"[safe_browsing] HTTP {resp.status_code}: {detail}")
        raise SafeBrowsingError(
            f"Google Safe Browsing returned an unexpected error (HTTP {resp.status_code})."
        )

    matches = resp.json().get("matches", [])
    return sorted({m.get("threatType") for m in matches if m.get("threatType")})
