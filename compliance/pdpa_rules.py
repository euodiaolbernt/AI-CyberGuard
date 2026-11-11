"""
Prototype PDPA 2010 (Malaysia Personal Data Protection Act) monitoring
rules.

IMPORTANT: these are predefined PROTOTYPE checks against a security
event's characteristics, not a legal compliance certification. A
NEEDS_REVIEW result means "this event has characteristics that
warrant a human compliance review under PDPA" - never "PDPA has been
violated". Only a human/legal review can determine an actual breach,
so this module never automatically emits POTENTIAL_VIOLATION.
"""

RULES = [
    {
        "rule_code": "PDPA-01",
        "framework": "PDPA",
        "title": "Personal data exposure risk",
        "description": (
            "Flags security events whose characteristics suggest personal "
            "data may have been exposed or accessed without authorisation."
        ),
        "trigger_condition": "Event indicates potential unauthorised access or data exposure",
        "recommended_action": (
            "Review affected systems, access records and incident details "
            "for personal data involvement."
        ),
    },
    {
        "rule_code": "PDPA-02",
        "framework": "PDPA",
        "title": "Security incident recorded",
        "description": (
            "Confirms a detected security event has been logged, which "
            "PDPA's security-safeguard obligations expect for any incident "
            "potentially involving personal data."
        ),
        "trigger_condition": "A security event has been detected and stored",
        "recommended_action": (
            "Retain this incident record and ensure it remains available "
            "for any required PDPA incident review."
        ),
    },
]


def evaluate(event: dict) -> list[dict]:
    """event: see compliance/compliance_engine.py's build_*_event()."""
    results = []

    if event.get("potential_data_exposure") or event.get("unauthorized_access"):
        results.append({
            "rule_code": "PDPA-01",
            "status": "NEEDS_REVIEW",
            "reason": (
                "Potential personal data exposure associated with a "
                f"detected security event ({event.get('label', 'this event')})."
            ),
            "evidence": event.get("evidence", ""),
        })

    # A security incident being "recorded" is always true for events that
    # reach this engine - the triggering detection/scan row is written to
    # the database before compliance is ever evaluated - so this rule
    # simply confirms that already-true fact, not an invented pass.
    results.append({
        "rule_code": "PDPA-02",
        "status": "COMPLIANT",
        "reason": "Security event recorded in the system with detection details retained.",
        "evidence": event.get("evidence", ""),
    })

    return results
