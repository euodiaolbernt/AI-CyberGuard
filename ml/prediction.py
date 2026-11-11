"""
Automatic threat detection on new data using an already-trained model.

The analyst never chooses BENIGN/MALICIOUS - run_detection() calls
straight into the saved classifier's .predict()/.predict_proba() and
reports whatever it returns. The only human choice already made is
*which* trained classifier is "best" (decided once, at training time,
by measured F1 - see ml/train_model.py).
"""
import pandas as pd

from ml.preprocessing import transform_features
from ml.risk_scoring import calculate_risk_score, severity_from_risk

BENIGN_TOKENS = {"benign", "normal"}


def run_detection(raw_feature_df: pd.DataFrame, models: dict, label_encoder,
                   artifacts: dict, best_model_name: str) -> pd.DataFrame:
    """Classify every row of `raw_feature_df` (feature columns only -
    caller must drop any label column first). Returns one row per
    input record with the model's real prediction, confidence, an
    Isolation Forest anomaly flag, and the derived risk score/severity."""
    X = transform_features(raw_feature_df, artifacts)

    classifier = models[best_model_name]
    pred_encoded = classifier.predict(X)
    proba = classifier.predict_proba(X)
    confidence = proba.max(axis=1) * 100
    pred_labels = label_encoder.inverse_transform(pred_encoded)

    anomaly_flags = models["isolation_forest"].predict(X) == -1  # -1 = anomaly

    multi_class = len(label_encoder.classes_) > 2

    records = []
    for i in range(len(X)):
        raw_label = str(pred_labels[i])
        is_benign = raw_label.lower() in BENIGN_TOKENS
        prediction = "BENIGN" if is_benign else "MALICIOUS"
        conf = round(float(confidence[i]), 2)
        is_anomaly = bool(anomaly_flags[i])
        risk = calculate_risk_score(prediction, conf, is_anomaly)

        records.append({
            "record_index": int(X.index[i]),
            "prediction": prediction,
            # Only a genuinely multi-class model (trained on more than
            # BENIGN vs one malicious class) can name a specific attack
            # type - otherwise there is nothing more specific to show.
            "attack_type": raw_label if (multi_class and not is_benign) else None,
            "confidence": conf,
            "is_anomaly": is_anomaly,
            "risk_score": risk,
            "severity": severity_from_risk(risk),
            "model_used": best_model_name,
        })

    return pd.DataFrame(records)
