"""
Prototype NIST Cybersecurity Framework 2.0 monitoring.

Maps each evaluated security event onto three of NIST CSF 2.0's five
functions (IDENTIFY and PROTECT are architectural/preventive and
aren't meaningfully assessed per-event, so only DETECT/RESPOND/RECOVER
are evaluated here):

  DETECT  - the event exists in this system precisely because
            detection already succeeded, so this is always COMPLIANT.
  RESPOND - a recommended response action is generated as part of this
            very evaluation, so this is always COMPLIANT too.
  RECOVER - a freshly detected event has not yet been investigated or
            resolved, so this always starts as NEEDS_REVIEW; resolving
            the linked alert (Alerts & Incidents page) is what this
            check is waiting on.

compliance_results only has one status column per row, so each
function is stored as its own row (NIST-DETECT / NIST-RESPOND /
NIST-RECOVER) rather than packed into one - matching how the FYP
report shows them as three separate lines.
"""

RULES = [
    {
        "rule_code": "NIST-DETECT",
        "framework": "NIST_CSF",
        "title": "Detect",
        "description": "Whether the event was successfully detected by the system.",
        "trigger_condition": "A security event has been detected",
        "recommended_action": "No action needed - detection already completed.",
    },
    {
        "rule_code": "NIST-RESPOND",
        "framework": "NIST_CSF",
        "title": "Respond",
        "description": "Whether a response action has been identified for the event.",
        "trigger_condition": "A recommended response action has been generated",
        "recommended_action": "Carry out the recommended response actions for this event.",
    },
    {
        "rule_code": "NIST-RECOVER",
        "framework": "NIST_CSF",
        "title": "Recover",
        "description": "Whether the incident has been investigated through to resolution.",
        "trigger_condition": "Incident resolution not yet confirmed",
        "recommended_action": "Investigate the related alert/incident, then mark it RESOLVED.",
    },
]


def evaluate(event: dict) -> list[dict]:
    evidence = event.get("evidence", "")
    return [
        {
            "rule_code": "NIST-DETECT",
            "status": "COMPLIANT",
            "reason": "Threat/URL detection completed successfully.",
            "evidence": evidence,
        },
        {
            "rule_code": "NIST-RESPOND",
            "status": "COMPLIANT",
            "reason": "Recommended response actions generated for this event.",
            "evidence": evidence,
        },
        {
            "rule_code": "NIST-RECOVER",
            "status": "NEEDS_REVIEW",
            "reason": "Incident recently detected; recovery/resolution not yet confirmed.",
            "evidence": evidence,
        },
    ]
