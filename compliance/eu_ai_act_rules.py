"""
Prototype EU AI Act monitoring.

Unlike the other four frameworks, the EU AI Act applies primarily to
the AI SYSTEM ITSELF (per the FYP report), not to individual security
events - so assess_system() is a fixed self-assessment run on demand
from the Compliance Monitoring page, not per detection/scan.

Each status below is an honest, specific claim about THIS codebase,
not an invented score:

  Risk management   - ml/risk_scoring.py and security/url_scanner.py
                       both use a documented, fixed formula (not a
                       black-box model) for turning a prediction into
                       a 0-100 risk score.
  Transparency      - every prediction shown to a user includes the
                       model used, its confidence, and the risk score
                       - never a bare verdict with no explanation.
  Human oversight   - the system only ever RECOMMENDS actions (alerts,
                       response steps); nothing is blocked, deleted, or
                       executed automatically without a person acting
                       on it.
  Auditability      - utils/audit_logger.py records every login, scan,
                       detection, compliance check and alert to
                       audit_logs.
  Risk classification - stays NEEDS_REVIEW: a full formal EU AI Act
                       risk-tier classification and conformity
                       assessment has not been carried out for this
                       prototype, and this system does not claim one.
"""

RULES = [
    {
        "rule_code": "EUAI-RISK-MGMT",
        "framework": "EU_AI_ACT",
        "title": "Risk management",
        "description": "Whether AI-driven risk scoring uses a documented, explainable method.",
        "trigger_condition": "System self-assessment",
        "recommended_action": "Keep the risk-scoring formula documented in code and reviewed as models change.",
    },
    {
        "rule_code": "EUAI-TRANSPARENCY",
        "framework": "EU_AI_ACT",
        "title": "Transparency",
        "description": "Whether AI outputs shown to users include the model, confidence, and basis for the result.",
        "trigger_condition": "System self-assessment",
        "recommended_action": "Continue surfacing model name, confidence and risk score alongside every AI verdict.",
    },
    {
        "rule_code": "EUAI-OVERSIGHT",
        "framework": "EU_AI_ACT",
        "title": "Human oversight",
        "description": "Whether a human reviews and approves actions before they are carried out.",
        "trigger_condition": "System self-assessment",
        "recommended_action": "Keep all response/compliance actions as recommendations for a human to act on, not automated actions.",
    },
    {
        "rule_code": "EUAI-AUDIT",
        "framework": "EU_AI_ACT",
        "title": "Auditability",
        "description": "Whether system actions are logged for later review.",
        "trigger_condition": "System self-assessment",
        "recommended_action": "Keep audit logging enabled for every login, scan, detection, and compliance/alert action.",
    },
    {
        "rule_code": "EUAI-CLASSIFICATION",
        "framework": "EU_AI_ACT",
        "title": "Risk classification",
        "description": "Whether the system has undergone a formal EU AI Act risk-tier classification and conformity assessment.",
        "trigger_condition": "System self-assessment",
        "recommended_action": (
            "Before any real deployment, obtain a formal EU AI Act risk "
            "classification and conformity assessment from a qualified reviewer."
        ),
    },
]


def assess_system() -> list[dict]:
    return [
        {
            "rule_code": "EUAI-RISK-MGMT",
            "status": "COMPLIANT",
            "reason": "Risk scoring (ml/risk_scoring.py, security/url_scanner.py) uses a fixed, documented formula.",
            "evidence": "See ml/risk_scoring.py and security/url_scanner.py docstrings.",
        },
        {
            "rule_code": "EUAI-TRANSPARENCY",
            "status": "COMPLIANT",
            "reason": "Model name, confidence and risk score are shown to users for every AI prediction.",
            "evidence": "Threat Detection and URL Scanner result displays.",
        },
        {
            "rule_code": "EUAI-OVERSIGHT",
            "status": "COMPLIANT",
            "reason": "The system only recommends actions (alerts, response steps); nothing executes automatically.",
            "evidence": "Alerts & Incidents page - all actions are advisory text, not automated blocking.",
        },
        {
            "rule_code": "EUAI-AUDIT",
            "status": "COMPLIANT",
            "reason": "Every login, scan, detection, and compliance/alert action is recorded in audit_logs.",
            "evidence": "utils/audit_logger.py log_action() calls throughout the app.",
        },
        {
            "rule_code": "EUAI-CLASSIFICATION",
            "status": "NEEDS_REVIEW",
            "reason": (
                "A formal EU AI Act risk-tier classification and conformity "
                "assessment has not been performed for this prototype."
            ),
            "evidence": "No such assessment exists in this project.",
        },
    ]
