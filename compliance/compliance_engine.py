"""
Central compliance rule engine (Step 7).

Flow, matching the FYP report exactly:

    Security Event (a threat detection or URL scan already saved to
    the database)
        -> identify event characteristics (build_network_event /
           build_url_event)
        -> each framework module decides independently whether it's
           relevant to THIS event's characteristics (evaluate_event) -
           PDPA/GDPR only fire when personal-data exposure is
           indicated; ISO 27001/NIST fire for every evaluated event
        -> results are persisted to compliance_results
           (database.models.save_compliance_results)
        -> if the event's risk score crosses the alert threshold, an
           alert is created (Step 8), carrying a compliance summary
        -> callers (app_pages/threat_detection.py,
           app_pages/url_scanner.py) write the matching audit log
           entries, since only they know which user triggered this

This module is intentionally Streamlit-free (no `import streamlit`) so
it can be unit-tested directly, the same way ml/*.py stays independent
of the UI layer.

Nothing here ever claims legal compliance or certifies anything - it
only reports predefined prototype rule results, and it never
automatically emits POTENTIAL_VIOLATION (see the framework modules'
own docstrings) - that judgement is left to a human reviewer.
"""
import pandas as pd

from compliance import eu_ai_act_rules, gdpr_rules, iso27001_rules, nist_rules, pdpa_rules
from database.models import create_alert, create_alerts_bulk, save_compliance_results

# Event-driven frameworks (evaluated per detection/scan). EU AI Act is
# evaluated separately via run_ai_system_self_assessment() below - it
# assesses the system itself, not individual events.
FRAMEWORK_MODULES = [pdpa_rules, iso27001_rules, nist_rules, gdpr_rules]

# All static rule catalogs, for seeding compliance_rules.
ALL_RULE_CATALOGS = [m.RULES for m in FRAMEWORK_MODULES] + [eu_ai_act_rules.RULES]

# "Risk Score >= 80" per the FYP report's Alert System section.
ALERT_RISK_THRESHOLD = 80

# Attack categories that indicate an attacker actually reached a
# host/account or exposed data, rather than just probing or disrupting
# availability - the simple, documented heuristic behind
# "potential_data_exposure" for network events. Two vocabularies are
# combined here since the trained model's label set depends on
# whichever dataset it was trained on:
#   - NSL-KDD style: "r2l" (remote-to-login), "u2r" (user-to-root)
#   - CICIDS2017 (see ml/dataset_loader.py): infiltration and bot
#     traffic both indicate a host was actually reached/compromised;
#     Heartbleed is a direct memory-disclosure vulnerability; SQL
#     injection directly targets data; brute-force login attempts
#     (SSH/FTP-Patator, Web Attack - Brute Force) target account
#     access. DoS/DDoS/PortScan are availability/reconnaissance
#     attacks, not data-exposure attacks, so they're deliberately not
#     included here - they still get flagged via severity == "CRITICAL"
#     below when they're actually severe.
DATA_EXPOSURE_ATTACK_TYPES = {
    "r2l", "u2r",
    "infiltration", "bot", "heartbleed",
    "web attack - sql injection", "web attack - brute force",
    "ssh-patator", "ftp-patator",
}


def _clean_optional_text(value):
    """None if `value` represents "no value" under any of pandas' or
    Python's missing-value conventions, else `value` as a plain string
    with its original casing/whitespace untouched.

    ROOT CAUSE this guards against: a BENIGN or binary-model detection
    has no attack type, so ml/prediction.py puts a real `None` there -
    but once that column passes through a pandas DataFrame (results_df
    here, built in ml/prediction.py and round-tripped through
    database.models.insert_threat_detections_bulk/results_df.to_dict()
    for this module), pandas' own default "string" dtype (pandas 3.x)
    represents a missing text value with its own internal marker,
    which commonly re-surfaces as a FLOAT `nan` - not `None` - once
    read back via .to_dict()/.iterrows()/standard indexing. `nan` is
    truthy in Python, so `detection.get("attack_type") or ""` silently
    keeps the float instead of falling back to "", and the very next
    `.strip()` call crashed the whole app with an AttributeError
    (confirmed by reproducing it locally with a binary-class dataset,
    where every row's attack_type is "missing" this way).
    pandas.isna() is the robust, version-proof way to recognise EVERY
    one of pandas'/numpy's "missing" representations (None, float NaN,
    pandas.NA, NaT) in one check, rather than hand-rolling a truthy
    check that only covers the cases seen so far."""
    if pd.isna(value):
        return None
    return str(value)


def build_network_event(detection: dict, user_id: int) -> dict:
    """Build a compliance event from one threat_detections-shaped
    record (as produced by ml/prediction.py and inserted via
    database.models.insert_threat_detections_bulk). `user_id` is the
    owner of this detection - it flows through to every
    compliance_results/alerts row this event produces, so a second
    user can never see it."""
    raw_attack_type = _clean_optional_text(detection.get("attack_type"))
    attack_type = (raw_attack_type or "").strip().lower()
    severity = detection.get("severity")
    flagged = attack_type in DATA_EXPOSURE_ATTACK_TYPES or severity == "CRITICAL"

    return {
        "user_id": user_id,
        "event_type": "NETWORK_THREAT",
        "label": f"network threat detection ({attack_type or 'unknown attack type'})",
        # Original casing preserved for display/alerts (e.g. "DDoS",
        # not "ddos") - `attack_type` above is the lowercased form used
        # only for the DATA_EXPOSURE_ATTACK_TYPES membership check.
        "threat_type": raw_attack_type,
        "severity": severity,
        "risk_score": detection.get("risk_score"),
        "confidence": detection.get("confidence"),
        "potential_data_exposure": flagged,
        "unauthorized_access": flagged,
        "evidence": (
            f"threat_detections.id={detection.get('id')}, "
            f"attack_type={attack_type or 'unknown'}, severity={severity}, "
            f"risk_score={detection.get('risk_score')}"
        ),
        "related_detection_id": detection.get("id"),
        "related_url_scan_id": None,
    }


def build_url_event(scan: dict, user_id: int) -> dict:
    """Build a compliance event from one url_scan_results-shaped
    record (as produced by security/url_scanner.py). `user_id` is the
    owner of this scan - see build_network_event's docstring."""
    flagged = scan.get("scan_status") == "MALICIOUS"

    return {
        "user_id": user_id,
        "event_type": "URL_SCAN",
        "label": f"URL scan ({scan.get('scan_status')})",
        "threat_type": _clean_optional_text(scan.get("threat_category")) or "Malicious URL",
        "severity": scan.get("risk_level"),
        "risk_score": scan.get("risk_score"),
        "confidence": None,
        "scan_status": scan.get("scan_status"),
        "potential_data_exposure": flagged,
        "unauthorized_access": flagged,
        "evidence": (
            f"url_scan_results.id={scan.get('id')}, url={scan.get('url')}, "
            f"status={scan.get('scan_status')}, "
            f"detections={scan.get('detection_count')}/{scan.get('total_engines')}"
        ),
        "related_detection_id": None,
        "related_url_scan_id": scan.get("id"),
    }


def evaluate_event(event: dict) -> list[dict]:
    """Run every event-driven framework module against `event`. A
    module that finds nothing relevant simply contributes no rows -
    "only evaluate rules relevant to the characteristics of the
    event", not every rule for every event."""
    results = []
    for module in FRAMEWORK_MODULES:
        for r in module.evaluate(event):
            r = dict(r)
            r["related_detection_id"] = event.get("related_detection_id")
            r["related_url_scan_id"] = event.get("related_url_scan_id")
            results.append(r)
    return results


def _should_alert(event: dict) -> bool:
    """Alert threshold: risk_score >= ALERT_RISK_THRESHOLD (80, per the
    FYP report), OR a URL scan VirusTotal/Safe Browsing already
    classified MALICIOUS outright. The second clause matters because
    risk_score for a URL scan is based on the ABSOLUTE number of
    engines that flagged it (security/url_scanner.py), not a
    percentage - a URL only 3 of VirusTotal's ~70-90 engines flagged
    is still a confirmed MALICIOUS verdict, but only scores 12/100,
    well under 80. Without this, a confirmed-malicious scan (whose own
    result page already recommends "create a security incident")
    silently never became an alert/incident. Network threat events
    have no "scan_status" key, so this never changes their behavior."""
    if (event.get("risk_score") or 0) >= ALERT_RISK_THRESHOLD:
        return True
    return event.get("event_type") == "URL_SCAN" and event.get("scan_status") == "MALICIOUS"


def process_security_event(event: dict) -> dict:
    """Full per-event pipeline: evaluate -> persist -> maybe alert.
    `event["user_id"]` (set by build_network_event/build_url_event)
    owns every compliance_results/alerts row this produces.

    Returns {"compliance_results": [...], "alert_id": int | None}.
    """
    user_id = event["user_id"]
    results = evaluate_event(event)
    save_compliance_results(results, user_id)

    alert_id = None
    if _should_alert(event):
        alert_id = _create_alert_for_event(event, results)

    return {"compliance_results": results, "alert_id": alert_id}


def process_security_events_bulk(events: list[dict]) -> list[dict]:
    """Batched sibling of process_security_event() for a whole batch of
    events at once (e.g. every HIGH/CRITICAL detection in one Threat
    Detection run) - ONE save_compliance_results() call and ONE
    create_alerts_bulk() call for the ENTIRE batch, instead of up to 2
    DB round trips PER event. This is purely about how many round
    trips happen: every event still runs through the exact same
    evaluate_event() rules and the exact same _should_alert() check
    as calling process_security_event() on each one individually
    - process_security_event() itself is unchanged for every existing
    single-event call site (URL Scanner).

    Returns one {"compliance_results": [...], "alert_id": int | None}
    per input event, same shape and order as process_security_event()."""
    if not events:
        return []

    per_event_results = [evaluate_event(event) for event in events]

    all_results = [r for results in per_event_results for r in results]
    if all_results:
        save_compliance_results(all_results, events[0]["user_id"])

    alert_indices = [i for i, event in enumerate(events) if _should_alert(event)]
    alert_rows = [_alert_row_for_event(events[i], per_event_results[i]) for i in alert_indices]
    alert_ids = create_alerts_bulk(alert_rows) if alert_rows else []

    outcomes = [{"compliance_results": per_event_results[i], "alert_id": None} for i in range(len(events))]
    for i, alert_id in zip(alert_indices, alert_ids):
        outcomes[i]["alert_id"] = alert_id
    return outcomes


def run_ai_system_self_assessment(user_id: int) -> list[dict]:
    """EU AI Act: assessed once for the system itself, not per event -
    but still owned by whichever user clicked the button, so it only
    ever appears in THEIR Compliance Monitoring view. Called on demand
    from the Compliance Monitoring page."""
    results = []
    for r in eu_ai_act_rules.assess_system():
        r = dict(r)
        r["related_detection_id"] = None
        r["related_url_scan_id"] = None
        results.append(r)
    save_compliance_results(results, user_id)
    return results


def _alert_row_for_event(event: dict, compliance_results: list[dict]) -> dict:
    """The exact alert fields for one event + its compliance results -
    shared by _create_alert_for_event() (single-event path) and
    process_security_events_bulk() (batched path), so both produce
    identical alert content regardless of how many DB round trips it
    takes to save them."""
    compliance_summary = "; ".join(
        f"{r['rule_code']}: {r['status']}" for r in compliance_results
    ) or "No applicable compliance rules flagged for this event."

    return {
        "user_id": event["user_id"],
        "event_type": "Network Threat" if event["event_type"] == "NETWORK_THREAT" else "Malicious URL",
        "threat_type": event.get("threat_type"),
        "severity": event.get("severity") or "CRITICAL",
        "risk_score": event.get("risk_score") or 0,
        "confidence": event.get("confidence"),
        "related_detection_id": event.get("related_detection_id"),
        "related_url_scan_id": event.get("related_url_scan_id"),
        "compliance_summary": compliance_summary,
        "recommended_action": _recommended_action_for(event),
    }


def _create_alert_for_event(event: dict, compliance_results: list[dict]) -> int:
    return create_alert(**_alert_row_for_event(event, compliance_results))


def _recommended_action_for(event: dict) -> str:
    """Static, templated recommended actions (per the FYP report's
    Response Actions section) - never AI-generated free text, and
    never a destructive/automated action, only recommendations for a
    human to act on."""
    lines = ["Investigate the source and affected systems.", "Review related security/access logs."]

    if event["event_type"] == "URL_SCAN":
        lines.append("Do not access the flagged URL; treat it as untrusted.")
    if event.get("potential_data_exposure"):
        lines.append("Review any potential personal data exposure.")

    lines.append("Record incident evidence and update this alert's status once reviewed.")
    return "\n".join(f"- {line}" for line in lines)
