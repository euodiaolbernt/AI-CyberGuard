"""
Model evaluation - actual measured metrics only.

Every number here comes from sklearn.metrics run against a real
held-out test split; nothing is invented. If a model hasn't been
trained, the caller (app_pages/threat_detection.py) never calls into
this module at all and shows "Model has not been trained yet." instead.
"""
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def evaluate_classifier(model, X_test, y_test, label_encoder):
    """Return measured accuracy/precision/recall/F1 (as percentages,
    weighted across classes to handle multi-class + class imbalance)
    and the confusion matrix, for one already-fitted classifier."""
    y_pred = model.predict(X_test)
    return {
        "accuracy": round(float(accuracy_score(y_test, y_pred)) * 100, 2),
        "precision": round(
            float(precision_score(y_test, y_pred, average="weighted", zero_division=0)) * 100, 2
        ),
        "recall": round(
            float(recall_score(y_test, y_pred, average="weighted", zero_division=0)) * 100, 2
        ),
        "f1": round(
            float(f1_score(y_test, y_pred, average="weighted", zero_division=0)) * 100, 2
        ),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "class_names": [str(c) for c in label_encoder.classes_],
    }
