"""
Transparent risk scoring (FYP report section on risk assessment).

Deliberately a simple, documented formula rather than an opaque or
overly elaborate one, per the report's requirement that the scoring
logic be explainable to a reviewer:

- A MALICIOUS prediction's risk IS the model's confidence in that
  prediction - a confident malicious call is high risk by definition.
- A BENIGN prediction's risk is only the model's *uncertainty*
  (100 - confidence), scaled down (x0.4), since even an uncertain
  benign call is far less concerning than a confident malicious one.
- Isolation Forest is a second, independent (unsupervised) model. If
  it also flags the same record as anomalous, that's a corroborating
  signal from a different method, so a fixed +15 bonus is added,
  capped at 100.
"""

ANOMALY_BONUS = 15


def calculate_risk_score(prediction: str, confidence: float, is_anomaly: bool) -> int:
    """prediction: 'BENIGN' or 'MALICIOUS'. confidence: 0-100, the
    classifier's confidence in `prediction`. is_anomaly: whether
    Isolation Forest independently flagged this record."""
    if prediction == "MALICIOUS":
        risk = confidence
    else:
        risk = (100 - confidence) * 0.4

    if is_anomaly:
        risk += ANOMALY_BONUS

    return int(round(min(100, max(0, risk))))


def severity_from_risk(risk_score: int) -> str:
    """Fixed thresholds from the FYP report: 0-29 LOW, 30-59 MEDIUM,
    60-79 HIGH, 80-100 CRITICAL."""
    if risk_score >= 80:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH"
    if risk_score >= 30:
        return "MEDIUM"
    return "LOW"
