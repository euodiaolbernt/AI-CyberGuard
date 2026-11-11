"""
Prototype GDPR monitoring rules.

Mirrors pdpa_rules.py's data-exposure check but under GDPR's own
framing (Article 33/34 breach-assessment duties), since the FYP report
treats PDPA and GDPR as parallel personal-data frameworks triggered by
the same event characteristic. Only fires when the event indicates
potential personal data exposure - never for every event, and never
automatically claims GDPR has been violated.
"""

RULES = [
    {
        "rule_code": "GDPR-01",
        "framework": "GDPR",
        "title": "Personal data exposure risk",
        "description": (
            "Flags events whose characteristics suggest personal data may "
            "have been exposed or accessed without authorisation - relevant "
            "to GDPR Article 33/34 breach-assessment duties."
        ),
        "trigger_condition": "Event indicates potential unauthorised access or data exposure",
        "recommended_action": (
            "Assess whether this event constitutes a personal data breach "
            "requiring a GDPR notification review."
        ),
    },
]


def evaluate(event: dict) -> list[dict]:
    if not (event.get("potential_data_exposure") or event.get("unauthorized_access")):
        return []

    return [{
        "rule_code": "GDPR-01",
        "status": "NEEDS_REVIEW",
        "reason": (
            "Potential personal data exposure associated with a detected "
            f"security event ({event.get('label', 'this event')})."
        ),
        "evidence": event.get("evidence", ""),
    }]
