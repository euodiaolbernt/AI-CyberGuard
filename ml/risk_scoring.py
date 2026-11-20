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
import numpy as np

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


def calculate_risk_scores_batch(predictions, confidences, anomaly_flags) -> np.ndarray:
    """Vectorized form of calculate_risk_score() for a whole detection
    run (ml/prediction.py) - the exact same formula applied to entire
    NumPy arrays at once instead of once per row in a Python loop,
    which is what made detection slow on large uploads. `predictions`
    is an array of "BENIGN"/"MALICIOUS" strings, `confidences` 0-100,
    `anomaly_flags` booleans - all the same length, in row order."""
    confidences = np.asarray(confidences, dtype=float)
    anomaly_flags = np.asarray(anomaly_flags, dtype=bool)
    is_malicious = np.asarray(predictions) == "MALICIOUS"

    risk = np.where(is_malicious, confidences, (100 - confidences) * 0.4)
    risk = risk + np.where(anomaly_flags, ANOMALY_BONUS, 0)
    risk = np.clip(risk, 0, 100)
    return np.round(risk).astype(int)


def severities_from_risk_batch(risk_scores) -> np.ndarray:
    """Vectorized form of severity_from_risk() - same fixed
    thresholds, applied to a whole NumPy array at once."""
    risk_scores = np.asarray(risk_scores)
    return np.select(
        [risk_scores >= 80, risk_scores >= 60, risk_scores >= 30],
        ["CRITICAL", "HIGH", "MEDIUM"],
        default="LOW",
    )
