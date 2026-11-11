"""
URL threat scanner (Step 6).

Orchestrates: validate input -> ask VirusTotal (an existing report
first, falling back to submitting a fresh scan) -> translate
VirusTotal's raw per-engine verdicts into this system's own
SAFE / SUSPICIOUS / MALICIOUS / SCAN_ERROR status and a transparent
0-100 risk score.

VirusTotal's ~70 security engines are the ones actually deciding
whether a URL looks dangerous - this module only aggregates and
labels their verdicts. It never claims VirusTotal "proves" a URL is
malicious, and it never opens, fetches, or executes the submitted URL
itself (that's VirusTotal's job, on their infrastructure).

Risk score formula (deliberately simple and documented, per the FYP
report's requirement that scoring be explainable):

    risk_score = min(100, malicious_count * 4 + suspicious_count * 2)

This is based on the ABSOLUTE number of engines that flagged the URL,
not a percentage of all ~70 engines VirusTotal queries. A percentage-
of-total score would badly understate risk: most generic antivirus
engines simply have no opinion on a given URL (they return
"undetected", not "harmless"), so even a URL a dozen reputable
security vendors have confirmed malicious would only ever reach a
small fraction of all engines and never look urgent by percentage.
Counting detections directly avoids that dilution. Each MALICIOUS
verdict contributes 4 points, each SUSPICIOUS verdict 2 (half as
much, since it's a weaker signal), capped at 100. The 0-100 result is
then bucketed into LOW/MEDIUM/HIGH/CRITICAL using the exact same
thresholds as network threat detection
(ml/risk_scoring.severity_from_risk), so both features report risk on
one consistent scale.
"""
from datetime import datetime, timezone

import config
from ml.risk_scoring import severity_from_risk
from security.phishing_heuristics import analyze_url_structure
from security.safe_browsing import SafeBrowsingError, check_url as check_safe_browsing
from security.validation import validate_url
from security.virustotal import VirusTotalError, get_existing_report, poll_analysis, submit_url

MALICIOUS_WEIGHT = 4
SUSPICIOUS_WEIGHT = 2

# Below this many VirusTotal engines actually weighing in, a SAFE
# result is reported as "Benign (Limited Coverage)" rather than a
# confident "Benign" - requirement: never present an inconclusive
# result as if it were a confirmed-clean verdict. VT typically queries
# ~70 engines for any real scan, so this mostly only ever matters for
# a report that genuinely came back thin.
MIN_ENGINES_FOR_CONFIDENT_VERDICT = 10

# Google Safe Browsing's own threat-type strings, mapped to this
# system's classification taxonomy.
_GSB_CATEGORY_MAP = {
    "SOCIAL_ENGINEERING": "Phishing",
    "MALWARE": "Malware",
    "UNWANTED_SOFTWARE": "Suspicious / Other",
    "POTENTIALLY_HARMFUL_APPLICATION": "Suspicious / Other",
}

# Keyword fragments matched (case-insensitively) against VirusTotal's
# own free-text per-vendor result labels (e.g. "Phishing", "Trojan.
# GenericKD", "Malicious site - defacement") to normalize them into
# this system's fixed 5-category taxonomy. Order matters: checked
# top-to-bottom, first match wins, so a label matching more than one
# fragment (rare) resolves to the earlier, more specific category.
_CATEGORY_KEYWORDS = [
    ("Phishing", ("phish", "credential", "social engineering", "fraud")),
    ("Defacement", ("deface",)),
    ("Malware", ("malware", "trojan", "virus", "worm", "ransomware", "spyware", "exploit", "backdoor")),
]


def _classify_threat_category(engine_results: dict, gsb_threat_types: list) -> str:
    """Normalize VirusTotal's per-vendor free-text labels AND Google
    Safe Browsing's structured threat types into exactly one of this
    system's 5 categories: Phishing, Defacement, Malware,
    Suspicious / Other, Benign. Never invents a category beyond what
    the two real sources actually reported - "Suspicious / Other" is
    the honest fallback for a real detection that doesn't match a more
    specific keyword, not a guess."""
    for threat_type in gsb_threat_types:
        mapped = _GSB_CATEGORY_MAP.get(threat_type)
        if mapped in ("Phishing", "Malware"):
            return mapped  # GSB's own structured verdict is a strong, specific signal

    flagged_labels = [
        (v.get("result") or "")
        for v in engine_results.values()
        if v.get("category") in ("malicious", "suspicious") and v.get("result")
    ]
    for label in flagged_labels:
        lower = label.lower()
        for category, fragments in _CATEGORY_KEYWORDS:
            if any(fragment in lower for fragment in fragments):
                return category

    if flagged_labels or gsb_threat_types:
        return "Suspicious / Other"
    return "Benign"


def scan_url(raw_url: str) -> dict:
    """Validate and scan `raw_url` against every configured threat-
    intel source (VirusTotal always; Google Safe Browsing additionally
    when configured - see config.has_safe_browsing_key()). Always
    returns a result dict and never raises - a failure is represented
    as scan_status=SCAN_ERROR with a human-readable `error`, so callers
    have one code path.

    VirusTotal stays the PRIMARY source (its detailed per-engine
    breakdown and existing-report lookup are what this whole module is
    built around) - Safe Browsing is consulted ADDITIONALLY and purely
    combined into the final verdict; a Safe Browsing failure never
    fails the whole scan, it's just one fewer source consulted (see
    `sources_consulted` on the returned result)."""
    original_url = (raw_url or "").strip()
    is_valid, cleaned_or_error = validate_url(raw_url)
    if not is_valid:
        return _error_result(original_url, cleaned_or_error)

    url = cleaned_or_error
    try:
        report = get_existing_report(url)
        if report is not None:
            stats = report["attributes"]["last_analysis_stats"]
            engine_results = report["attributes"].get("last_analysis_results", {})
            analysis_reference = report.get("id")
        else:
            analysis_id = submit_url(url)
            analysis = poll_analysis(analysis_id)
            if analysis["attributes"]["status"] != "completed":
                return _error_result(
                    original_url,
                    "VirusTotal is still analysing this URL. Please try scanning "
                    "again in about a minute.",
                )
            stats = analysis["attributes"]["stats"]
            engine_results = analysis["attributes"].get("results", {})
            analysis_reference = analysis_id
    except VirusTotalError as e:
        return _error_result(original_url, str(e))
    except Exception as e:
        return _error_result(original_url, f"Unexpected error contacting VirusTotal: {e}")

    sources_consulted = ["VirusTotal"]
    gsb_threat_types = []
    gsb_error = None
    if config.has_safe_browsing_key():
        try:
            gsb_threat_types = check_safe_browsing(url)
            sources_consulted.append("Google Safe Browsing")
        except SafeBrowsingError as e:
            gsb_error = str(e)
        except Exception as e:
            gsb_error = f"Unexpected error contacting Google Safe Browsing: {e}"

    return _build_result(
        url, original_url, stats, engine_results, analysis_reference,
        sources_consulted, gsb_threat_types, gsb_error,
    )


def _build_result(url: str, original_url: str, stats: dict, engine_results: dict, analysis_reference: str,
                   sources_consulted: list, gsb_threat_types: list, gsb_error: str | None) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)
    total_engines = malicious + suspicious + harmless + undetected + timeout

    detection_count = malicious + suspicious

    if malicious > 0 or gsb_threat_types:
        # Google Safe Browsing flags a URL as binary "on a threat list
        # or not" (no malicious/suspicious split like VT's engines) -
        # a real hit there is treated as equivalent to a MALICIOUS
        # VirusTotal verdict, since Safe Browsing only ever lists
        # confirmed, actively-enforced threats.
        scan_status = "MALICIOUS"
    elif suspicious > 0:
        scan_status = "SUSPICIOUS"
    else:
        scan_status = "SAFE"

    raw_score = malicious * MALICIOUS_WEIGHT + suspicious * SUSPICIOUS_WEIGHT
    if gsb_threat_types:
        raw_score += 20  # a confirmed Safe Browsing match is a strong independent signal
    risk_score = min(100, max(0, round(raw_score)))
    risk_level = severity_from_risk(risk_score)

    threat_category = _classify_threat_category(engine_results, gsb_threat_types)
    is_low_confidence = scan_status == "SAFE" and total_engines < MIN_ENGINES_FOR_CONFIDENT_VERDICT

    # Local, explainable URL-structure heuristic (security/
    # phishing_heuristics.py) - a SUPPLEMENTARY signal that can catch a
    # brand-new phishing URL no security vendor has indexed yet. It
    # never touches scan_status/risk_score/threat_category above, which
    # stay driven entirely by VirusTotal/Safe Browsing's real verdict -
    # see that module's own docstring for why this stays a separate,
    # clearly-labeled field rather than being blended in.
    heuristic = analyze_url_structure(url)

    return {
        "url": url,
        "original_url": original_url,
        "scan_status": scan_status,
        "detection_count": detection_count,
        "total_engines": total_engines,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_category": threat_category,
        "vendor_label": _dominant_threat_category(engine_results),
        "engine_breakdown": _curate_engine_results(engine_results),
        "safe_browsing_threats": gsb_threat_types,
        "safe_browsing_error": gsb_error,
        "sources_consulted": sources_consulted,
        "is_low_confidence": is_low_confidence,
        "source": ", ".join(sources_consulted),
        "analysis_reference": analysis_reference,
        "scan_timestamp": datetime.now(timezone.utc),
        "heuristic_score": heuristic["heuristic_score"],
        "heuristic_level": heuristic["heuristic_level"],
        "heuristic_signals": heuristic["signals"],
        "error": None,
    }


def _curate_engine_results(engine_results: dict, limit: int = 8) -> list:
    """A curated subset of VirusTotal's own real per-vendor verdicts -
    every vendor that actually flagged the URL (malicious/suspicious)
    first, then enough undetected/harmless ones to reach `limit` - so
    the UI can show real security-engine results (vendor name,
    category, result label) without listing all ~70 engines VT
    queries. Every field here is read straight from VirusTotal's own
    response, never computed or invented."""
    flagged, clean = [], []
    for vendor, v in engine_results.items():
        entry = {
            "vendor": vendor,
            "category": v.get("category", "undetected"),
            "result": v.get("result"),
        }
        (flagged if entry["category"] in ("malicious", "suspicious") else clean).append(entry)
    return (flagged + clean)[:limit]


def _dominant_threat_category(engine_results: dict):
    """Most common vendor-reported result label (e.g. 'phishing',
    'malware', 'defacement') among engines that flagged the URL as
    malicious OR suspicious, or None if no engine reported one.

    This is VirusTotal's own per-vendor category string, surfaced
    exactly as the vendor wrote it - never a locally computed or
    predicted classification. Considering "suspicious" engines too
    (not just "malicious" ones) means a SUSPICIOUS-status scan can
    also surface a vendor category instead of always showing None."""
    labels = [
        v.get("result")
        for v in engine_results.values()
        if v.get("category") in ("malicious", "suspicious") and v.get("result")
    ]
    if not labels:
        return None
    most_common = max(set(labels), key=labels.count)
    return most_common.title()


def _error_result(url: str, message: str) -> dict:
    return {
        "url": url,
        "original_url": url,
        "scan_status": "SCAN_ERROR",
        "detection_count": None,
        "total_engines": None,
        "risk_score": None,
        "risk_level": None,
        "threat_category": None,
        "vendor_label": None,
        "engine_breakdown": [],
        "safe_browsing_threats": [],
        "safe_browsing_error": None,
        "sources_consulted": [],
        "is_low_confidence": False,
        "source": "VirusTotal",
        "analysis_reference": None,
        "scan_timestamp": datetime.now(timezone.utc),
        "heuristic_score": None,
        "heuristic_level": None,
        "heuristic_signals": [],
        "error": message,
    }
