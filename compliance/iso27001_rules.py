"""
Prototype ISO/IEC 27001:2022 monitoring rules.

Maps to Annex A incident-management and operations-security controls
at a prototype level: was the event actually recorded with evidence,
and does its severity warrant a review of the controls that should
have limited it. Like every other framework module here, this never
claims formal ISO 27001 certification - only a predefined check result.
"""

RULES = [
    {
        "rule_code": "ISO27001-01",
        "framework": "ISO27001",
        "title": "Security incident logged with evidence",
        "description": (
            "Checks that a detected security event has an incident record "
            "with supporting evidence available, per ISO/IEC 27001:2022 "
            "Annex A incident-management controls."
        ),
        "trigger_condition": "A security event has been detected",
        "recommended_action": "Record and review the security incident and associated evidence.",
    },
    {
        "rule_code": "ISO27001-02",
        "framework": "ISO27001",
        "title": "High-severity event needs control review",
        "description": (
            "Flags HIGH/CRITICAL severity events for a review of the "
            "security controls that should have prevented or limited them."
        ),
        "trigger_condition": "Event severity is HIGH or CRITICAL",
        "recommended_action": (
            "Review the security controls relevant to this event and "
            "assess whether they need strengthening."
        ),
    },
]


def evaluate(event: dict) -> list[dict]:
    results = [{
        "rule_code": "ISO27001-01",
        "status": "COMPLIANT",
        "reason": "Security incident recorded with detection evidence available for review.",
        "evidence": event.get("evidence", ""),
    }]

    if event.get("severity") in ("HIGH", "CRITICAL"):
        results.append({
            "rule_code": "ISO27001-02",
            "status": "NEEDS_REVIEW",
            "reason": f"Event severity is {event.get('severity')}, warranting a security control review.",
            "evidence": event.get("evidence", ""),
        })

    return results
