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
from compliance import eu_ai_act_rules, gdpr_rules, iso27001_rules, nist_rules, pdpa_rules
from database.models import create_alert, save_compliance_results

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


def build_network_event(detection: dict, user_id: int) -> dict:
    """Build a compliance event from one threat_detections-shaped
    record (as produced by ml/prediction.py and inserted via
    database.models.insert_threat_detections_bulk). `user_id` is the
    owner of this detection - it flows through to every
    compliance_results/alerts row this event produces, so a second
    user can never see it."""
    attack_type = (detection.get("attack_type") or "").strip().lower()
    severity = detection.get("severity")
    flagged = attack_type in DATA_EXPOSURE_ATTACK_TYPES or severity == "CRITICAL"

    return {
        "user_id": user_id,
        "event_type": "NETWORK_THREAT",
        "label": f"network threat detection ({attack_type or 'unknown attack type'})",
        "threat_type": detection.get("attack_type"),
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
        "threat_type": scan.get("threat_category") or "Malicious URL",
        "severity": scan.get("risk_level"),
        "risk_score": scan.get("risk_score"),
        "confidence": None,
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
    if (event.get("risk_score") or 0) >= ALERT_RISK_THRESHOLD:
        alert_id = _create_alert_for_event(event, results)

    return {"compliance_results": results, "alert_id": alert_id}


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


def _create_alert_for_event(event: dict, compliance_results: list[dict]) -> int:
    compliance_summary = "; ".join(
        f"{r['rule_code']}: {r['status']}" for r in compliance_results
    ) or "No applicable compliance rules flagged for this event."

    return create_alert(
        user_id=event["user_id"],
        event_type="Network Threat" if event["event_type"] == "NETWORK_THREAT" else "Malicious URL",
        threat_type=event.get("threat_type"),
        severity=event.get("severity") or "CRITICAL",
        risk_score=event.get("risk_score") or 0,
        confidence=event.get("confidence"),
        related_detection_id=event.get("related_detection_id"),
        related_url_scan_id=event.get("related_url_scan_id"),
        compliance_summary=compliance_summary,
        recommended_action=_recommended_action_for(event),
    )


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
