"""
URL input validation.

A URL a user submits is untrusted input: this module only ever checks
its *shape* (a well-formed http/https URL with a PLAUSIBLE host) - it
never opens, fetches, downloads, or executes anything at the URL.
Whether the URL is actually dangerous is answered entirely by the
VirusTotal threat-intelligence lookup in security/virustotal.py, which
fetches it on VirusTotal's own infrastructure, not ours.

Checking the host is plausible (not just "non-empty") matters: a bare
scheme + non-empty netloc check alone accepts garbage like
"http://Egxnd3abc123xyz" (no dot, not a real domain, not an IP) just
as happily as "http://example.com" - it would sail through validation
and only fail deep inside the VirusTotal API call with a generic,
confusing error, which is exactly the kind of "my input turned into
something unrecognizable" report this stricter check is meant to
prevent at the door instead.
"""
import ipaddress
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048


def _looks_like_a_real_host(hostname: str) -> bool:
    """True for any valid public-looking IPv4/IPv6 literal or anything
    containing a dot (a plausible domain) - false for a single bare
    token with no TLD, which is never a real public website address.
    "localhost" and any private/reserved IP are handled separately by
    _is_private_or_reserved() below, never accepted here, since
    neither is a real PUBLIC address a threat-intel service could
    meaningfully evaluate."""
    if not hostname:
        return False
    if hostname == "localhost":
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    return "." in hostname


def _is_private_or_reserved(hostname: str) -> bool:
    """True for "localhost" or any IP literal in a private/loopback/
    link-local/reserved/multicast range (RFC 1918, RFC 4193, etc.) -
    an internal-only address that public threat-intelligence services
    (VirusTotal, Google Safe Browsing) have no visibility into and
    this app has no legitimate reason to let a user probe for. This is
    a pure string/address-range check - no DNS resolution, so it can't
    be fooled into a slow lookup, but it also can't catch a hostname
    that only RESOLVES to a private address (e.g. via DNS rebinding) -
    out of scope here since this app never itself opens a connection
    to the submitted URL (see this module's own docstring); the actual
    fetch happens entirely on VirusTotal's/Google's infrastructure."""
    if hostname == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def validate_url(raw_url: str):
    """Return (is_valid, cleaned_url) on success, or (False, error_message).

    A pure string-format check - no DNS resolution, no network call -
    but still strict enough to reject something that merely LOOKS like
    it could parse (scheme + non-empty netloc) while obviously not
    being a real website address. The original user-typed text is only
    ever trimmed of whitespace and given a scheme if it was missing -
    nothing here encodes, decodes, or otherwise rewrites the address
    itself, so what gets validated, submitted to VirusTotal, and shown
    back in the UI is always the one same string the user intended.
    """
    url = (raw_url or "").strip()
    if not url:
        return False, "Please enter a URL."
    if len(url) > MAX_URL_LENGTH:
        return False, f"URL is too long (over {MAX_URL_LENGTH} characters)."

    if "://" not in url:
        url = "http://" + url  # allow bare "example.com" style input

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "That doesn't look like a valid URL."

    if parsed.scheme not in ("http", "https"):
        return False, "Only http:// and https:// URLs are supported."
    if not parsed.netloc:
        return False, "URL is missing a host (e.g. example.com)."
    hostname = parsed.hostname or ""
    if _is_private_or_reserved(hostname):
        return False, (
            "Private/internal addresses (localhost, 127.0.0.1, 192.168.x.x, "
            "10.x.x.x, etc.) can't be scanned - public threat-intelligence "
            "services have no visibility into your own network."
        )
    if not _looks_like_a_real_host(hostname):
        return False, (
            "That doesn't look like a real website address - it's missing a "
            "domain (e.g. example.com) or a valid IP address."
        )

    return True, url
