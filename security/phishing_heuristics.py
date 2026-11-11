"""
Local, explainable phishing-URL structure heuristic.

WHY THIS EXISTS: security/url_scanner.py answers "has a real security
vendor (VirusTotal's ~70 engines, Google Safe Browsing) already
confirmed this URL is bad?" - a strong signal, but a lagging one. A URL
used in a phishing campaign launched minutes ago may not be indexed by
any vendor yet. This module answers a different, narrower question -
"does this URL's own STRUCTURE look like a phishing URL?" - using the
same lexical/host-based indicators published phishing-detection
research relies on (IP-literal hosts, the '@' login-redirect trick,
a well-known brand name stapled onto an unrelated domain, free/
disposable TLDs, URL shorteners, sensitive-action keywords, etc.).

HONESTY BOUNDARY (read before wiring this into anything):
  - This is a SECONDARY, SUPPLEMENTARY signal only. It never overrides
    or gets blended into scan_status / risk_score / threat_category -
    VirusTotal/Safe Browsing's verdict (security/url_scanner.py) stays
    the one source of truth for those.
  - Wherever this is shown, it must be labeled "structural analysis" /
    "not a confirmed verdict", never presented as equivalent to a real
    vendor detection.
  - It cannot and must not be tuned to flip a legitimate, well-
    established URL (e.g. a 20-year-old gaming site with an ordinary
    path) into "phishing" just because a dataset or a person expects
    it to be one. If a URL genuinely doesn't exhibit any of these
    structural patterns, this module correctly reports LOW - same
    conclusion an honest reading of VirusTotal's own results would
    reach for that URL.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from ml.risk_scoring import severity_from_risk

# Disposable/free TLDs long associated with high phishing/spam abuse
# rates in published URL-blocklist research - a weak-to-moderate signal
# on its own (plenty of legitimate sites use them too), never decisive
# alone.
_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "zip", "mov", "country", "stream", "men", "loan", "win",
}

# Known URL-shortening services - not inherently malicious, but they
# hide the real destination, which is exactly the property phishing
# campaigns exploit them for.
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly",
}

# Path/query keywords that cluster heavily around credential-harvesting
# pages (login/verify/confirm/update-your-account style phishing).
_SENSITIVE_KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "webscr", "password", "billing", "suspend", "unlock",
)

# A deliberately small, well-known set of frequently-impersonated brand
# names - used ONLY to check whether the brand name appears SOMEWHERE
# in the URL while the ACTUAL registered domain is something else
# entirely (the classic "paypal.com.verify-login.xyz" pattern). Never
# used to flag the brand's own real domain, and never a general-purpose
# keyword blocklist.
_COMMONLY_IMPERSONATED_BRANDS = (
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "bankofamerica", "wellsfargo",
    "chase", "dhl", "fedex", "irs",
)


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registrable_domain(hostname: str) -> str:
    """Best-effort 'last two labels' approximation (e.g.
    "mail.google.com" -> "google.com"). Not a real public-suffix-list
    lookup (no such dependency in this project) - good enough for this
    heuristic's narrow purpose of telling "paypal.com" apart from
    "paypal.com.evil-login.xyz", not a precise registrability check."""
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def analyze_url_structure(url: str) -> dict:
    """Score `url`'s own lexical/host structure for classic phishing-
    URL patterns. Returns a dict with `heuristic_score` (0-100),
    `heuristic_level` (LOW/MEDIUM/HIGH/CRITICAL - the same bands and
    thresholds as every other risk score in this app), and `signals` -
    the list of plain-language reasons that actually fired, so a
    caller can show its work instead of an unexplained number. An
    empty `signals` list means exactly what it says: this URL doesn't
    exhibit any of the structural patterns checked for, not
    "inconclusive"."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    full_url_lower = url.lower()
    path_and_query = f"{parsed.path}{parsed.query}".lower()

    signals: list[tuple[str, int]] = []

    if _is_ip_literal(hostname):
        signals.append(("Hostname is a raw IP address instead of a domain name", 30))

    if "@" in url:
        signals.append(("URL contains '@', a known login-redirect/obfuscation trick", 25))

    if len(url) > 100:
        signals.append(("Unusually long URL (over 100 characters)", 10))
    elif len(url) > 75:
        signals.append(("Long URL (over 75 characters)", 5))

    subdomain_count = max(0, hostname.count(".") - 1)
    if subdomain_count >= 3:
        signals.append((f"Excessive subdomains ({subdomain_count} levels)", 15))

    if hostname.count("-") >= 2:
        signals.append(("Multiple hyphens in the domain name (common brand-spoofing pattern)", 10))

    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in _SUSPICIOUS_TLDS:
        signals.append((f"Uses a free/disposable top-level domain (.{tld})", 15))

    if parsed.scheme == "http":
        signals.append(("No HTTPS encryption", 5))

    registrable_domain = _registrable_domain(hostname)
    for brand in _COMMONLY_IMPERSONATED_BRANDS:
        if brand in full_url_lower and brand not in registrable_domain:
            signals.append((f"Brand name '{brand}' appears in the URL but not in its actual domain", 30))
            break  # one hit is enough signal; don't stack multiple brand matches

    if hostname in _URL_SHORTENERS:
        signals.append(("Uses a known URL-shortening service, which hides the real destination", 15))

    keyword_hits = [kw for kw in _SENSITIVE_KEYWORDS if kw in path_and_query]
    if keyword_hits:
        signals.append((f"Sensitive-action keyword(s) in the URL: {', '.join(keyword_hits[:3])}", 10))

    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        signals.append((f"Non-standard port specified ({port})", 5))

    score = min(100, sum(points for _, points in signals))
    return {
        "heuristic_score": score,
        "heuristic_level": severity_from_risk(score),
        "signals": [reason for reason, _ in signals],
    }
