"""
Automatic threat detection on new data using an already-trained model.

The analyst never chooses BENIGN/MALICIOUS - run_detection() calls
straight into the saved classifier's .predict()/.predict_proba() and
reports whatever it returns. The only human choice already made is
*which* trained classifier is "best" (decided once, at training time,
by measured F1 - see ml/train_model.py).

Every per-record field (prediction/attack type/risk/severity) is
computed with whole-array NumPy/pandas operations, never a Python
`for` loop over rows - on a dataset with hundreds of thousands of
rows (CICIDS2017-scale), a per-row Python loop was measurably the
slowest part of a detection run.
"""
import numpy as np
import pandas as pd

from ml.preprocessing import transform_features
from ml.risk_scoring import calculate_risk_scores_batch, severities_from_risk_batch

BENIGN_TOKENS = {"benign", "normal"}


def _classify_prepared_matrix(X: pd.DataFrame, models: dict, label_encoder,
                               best_model_name: str) -> pd.DataFrame:
    """Shared by run_detection() and run_detection_on_prepared(): given
    an ALREADY preprocessor-transformed feature matrix `X` (same
    column space the models were fit on), run every model and build
    the per-record results DataFrame. Never sanitizes or selects
    columns itself - that's the caller's job - so this one function
    works whether `X` came from transform_features() (a fresh/
    unrelated dataset) or straight from a just-fitted preprocessor's
    own output (the immediately-after-training fast path)."""
    classifier = models[best_model_name]
    pred_encoded = classifier.predict(X)
    proba = classifier.predict_proba(X)
    confidence = proba.max(axis=1) * 100
    pred_labels = np.asarray(label_encoder.inverse_transform(pred_encoded), dtype=str)

    anomaly_flags = models["isolation_forest"].predict(X) == -1  # -1 = anomaly

    multi_class = len(label_encoder.classes_) > 2
    is_benign = np.isin(np.char.lower(pred_labels), list(BENIGN_TOKENS))
    predictions = np.where(is_benign, "BENIGN", "MALICIOUS")
    confidence_rounded = np.round(confidence, 2)

    risk_scores = calculate_risk_scores_batch(predictions, confidence_rounded, anomaly_flags)
    severities = severities_from_risk_batch(risk_scores)

    # Only a genuinely multi-class model (trained on more than BENIGN
    # vs one malicious class) can name a specific attack type -
    # otherwise there is nothing more specific to show. `&`/`~`
    # (elementwise), not `and`/`not`, since is_benign is a NumPy array.
    #
    # np.where(), not pandas' Series.where(): when EVERY row gets
    # replaced (e.g. a binary model, where show_attack_type is all
    # False), pandas' string-dtype Series silently represents the
    # "replaced" rows as float('nan') instead of real None once you
    # call .to_numpy() - and nan is truthy in Python, so downstream
    # code's `detection.get("attack_type") or ""` style checks
    # (compliance/compliance_engine.py) would see a float, not None/
    # "", and crash calling .strip() on it. np.where() with an object
    # array keeps a real None for every row that should show nothing.
    show_attack_type = multi_class & ~is_benign
    attack_type = np.where(show_attack_type, pred_labels, None).astype(object)

    return pd.DataFrame({
        "record_index": X.index.astype(int),
        "prediction": predictions,
        "attack_type": attack_type,
        "confidence": confidence_rounded,
        "is_anomaly": anomaly_flags,
        "risk_score": risk_scores,
        "severity": severities,
        "model_used": best_model_name,
    })


def run_detection(raw_feature_df: pd.DataFrame, models: dict, label_encoder,
                   artifacts: dict, best_model_name: str) -> pd.DataFrame:
    """Classify every row of `raw_feature_df` (feature columns only -
    caller must drop any label column first). Returns one row per
    input record with the model's real prediction, confidence, an
    Isolation Forest anomaly flag, and the derived risk score/severity."""
    X = transform_features(raw_feature_df, artifacts)
    return _classify_prepared_matrix(X, models, label_encoder, best_model_name)


def run_detection_on_prepared(X_prepared: pd.DataFrame, preprocessor, models: dict,
                               label_encoder, best_model_name: str) -> pd.DataFrame:
    """Fast path for "train a new model on this dataset, then
    immediately run detection on that same dataset"
    (app_pages/threat_detection.py's auto-train-and-detect button):
    `X_prepared` is the SAME already-sanitized, already column-
    selected feature matrix train_models() was just fit on
    (ml/preprocessing.py's preprocess_dataset() -> bundle["X"]), and
    `preprocessor` is the freshly-fit pipeline returned alongside it.
    Going straight to `preprocessor.transform()` skips re-running
    sanitize_dataframe() and column selection a second time over data
    that was only just sanitized/selected a moment ago for training -
    what calling run_detection() here would otherwise do, redundantly,
    via transform_features()."""
    X = preprocessor.transform(X_prepared)
    X = pd.DataFrame(X, index=X_prepared.index)
    return _classify_prepared_matrix(X, models, label_encoder, best_model_name)
