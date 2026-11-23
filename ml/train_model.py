"""
Model training and persistence.

Training only happens when the analyst clicks "Train Models" on the
Threat Detection page - never automatically on page load.

LEAKAGE-SAFE ARCHITECTURE: train_test_split happens on the RAW (only
sanitized, not yet imputed/scaled/encoded) feature data FIRST. The
preprocessing pipeline (ml/preprocessing.py's ColumnTransformer -
median/most-frequent imputation, scaling, one-hot encoding) is fit
ONLY on the training split, then reused - never refit - to transform
the test split for evaluation and every future prediction. Fitting on
the full dataset before splitting (the previous architecture) lets the
test split's own distribution leak into the scaler/imputer, which
quietly inflates evaluation metrics; this module never does that.

MODEL SLOTS: each dataset trains into its own named slot under
models/<slug>/, named from the dataset's own name - so training on a
new/different CSV can NEVER accidentally overwrite an existing
dataset's trained model (e.g. CICIDS2017's). Exactly one slot is
"active" at a time (models/active_model.json) - that's the one
load_models() returns for the Threat Detection page's Model Evaluation
and "Run AI Detection" sections. Training a dataset for the first time
makes its slot active automatically; the analyst can switch back to
any previously-trained slot from the UI without retraining.

Two model families are trained together, matching the FYP report:
- Random Forest and XGBoost: supervised classifiers, trained on the
  dataset's own label column (whatever categories it contains -
  binary BENIGN/MALICIOUS or multi-class attack types). Whichever
  scores higher weighted F1 on the held-out test split becomes the
  "best_model" used for live detection.
- Isolation Forest: unsupervised anomaly detection, trained on the
  feature matrix alone (no labels). It contributes an independent
  corroborating signal to risk scoring (see ml/risk_scoring.py) - it
  is not evaluated with accuracy/F1 since it has no ground truth to
  compare against.
"""
import json
import os
import re
import shutil
from datetime import datetime

import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from ml.evaluation import evaluate_classifier
from ml.preprocessing import build_preprocessing_pipeline, check_schema_compatibility
from utils.perf import timed

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
_ACTIVE_POINTER_FILE = os.path.join(MODELS_DIR, "active_model.json")

_MODEL_FILES = {
    "random_forest": "random_forest.pkl",
    "xgboost": "xgboost.pkl",
    "isolation_forest": "isolation_forest.pkl",
}
_LABEL_ENCODER_FILE = "label_encoder.pkl"
_PREPROCESSING_FILE = "preprocessing.pkl"
_META_FILE = "model_meta.json"
_ALL_SLOT_FILES = list(_MODEL_FILES.values()) + [_LABEL_ENCODER_FILE, _PREPROCESSING_FILE, _META_FILE]

BENIGN_TOKENS = {"benign", "normal"}


def slugify(dataset_name: str) -> str:
    """A filesystem-safe folder name derived from the dataset's own
    name - deterministic, so re-training the SAME dataset lands in the
    SAME slot (an intentional retrain/update), while a genuinely
    different dataset name always gets its own separate slot."""
    slug = re.sub(r"[^a-z0-9]+", "_", dataset_name.strip().lower()).strip("_")
    return slug or "dataset"


def _slot_dir(slug: str) -> str:
    return os.path.join(MODELS_DIR, slug)


def _migrate_legacy_flat_model_if_needed():
    """One-time migration for models trained before per-dataset slots
    existed: if models/*.pkl are still sitting at the flat root and no
    active-model pointer exists yet, move them into their OWN named
    slot (derived from their own saved dataset_name) instead of
    leaving them where training a new dataset could collide with them.
    Never deletes anything - uses shutil.move, and is a no-op on every
    later call once the pointer file exists."""
    if os.path.exists(_ACTIVE_POINTER_FILE):
        return
    legacy_meta_path = os.path.join(MODELS_DIR, _META_FILE)
    if not os.path.exists(legacy_meta_path):
        return

    with open(legacy_meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    slug = slugify(meta.get("dataset_name", "legacy_model"))
    slot_dir = _slot_dir(slug)

    if not os.path.exists(slot_dir):
        os.makedirs(slot_dir, exist_ok=True)
        for fname in _ALL_SLOT_FILES:
            src = os.path.join(MODELS_DIR, fname)
            if os.path.exists(src):
                shutil.move(src, os.path.join(slot_dir, fname))
    set_active_slug(slug)


def list_model_slots() -> list[dict]:
    """Every USABLE trained model slot available to switch to, each
    with its own real dataset_name/trained_at/best_model - read
    straight from that slot's own model_meta.json, never inferred.
    A slot saved by a previous version of this codebase (old-format
    preprocessing.pkl, before the ColumnTransformer pipeline existed)
    is deliberately left out here - offering it in the picker would
    just lead to "Model has not been trained yet" the moment it's
    selected (see load_models()); retraining that dataset creates a
    fresh, usable slot with the same name."""
    _migrate_legacy_flat_model_if_needed()
    if not os.path.isdir(MODELS_DIR):
        return []
    slots = []
    for entry in sorted(os.listdir(MODELS_DIR)):
        slot_dir = os.path.join(MODELS_DIR, entry)
        meta_path = os.path.join(slot_dir, _META_FILE)
        prep_path = os.path.join(slot_dir, _PREPROCESSING_FILE)
        if not (os.path.isfile(meta_path) and os.path.isfile(prep_path)):
            continue
        try:
            artifacts = joblib.load(prep_path)
        except Exception:
            continue
        if not isinstance(artifacts, dict) or "preprocessor" not in artifacts:
            continue
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        slots.append({"slug": entry, **meta})
    return slots


def find_model_slot_matches(available_columns, preferred_slug: str | None = None) -> dict:
    """Independent per-dataset model routing: checks `available_columns`
    against EVERY trained slot's own raw_feature_names - never assumes
    whichever slot happens to be active is relevant to a new upload.
    Returns:
      {"compatible": <best-fit slot dict, or None>,
       "closest": <slot dict with the highest match RATIO, for
                   diagnostics only - NEVER loaded or used to run
                   detection; a non-compatible model is never used to
                   force a prediction>}
    Both (when present) carry an extra "_compat" key: that slot's own
    check_schema_compatibility() result against `available_columns`.

    Tie-break when multiple slots are fully compatible: keep
    `preferred_slug` (pass the CURRENT active slug) if it's among
    them, so a dataset that still fits the model already active/picked
    doesn't get silently swapped out from under the analyst on every
    rerun; otherwise falls back to the most recently trained
    compatible slot."""
    slots = list_model_slots()
    if not slots:
        return {"compatible": None, "closest": None}

    scored = [
        {**s, "_compat": check_schema_compatibility(available_columns, s["raw_feature_names"])}
        for s in slots
    ]
    compatible = [s for s in scored if s["_compat"]["compatible"]]
    best_compatible = None
    if compatible:
        preferred = next((s for s in compatible if s["slug"] == preferred_slug), None)
        best_compatible = preferred or max(compatible, key=lambda s: s.get("trained_at", ""))

    closest = max(
        scored, key=lambda s: s["_compat"]["match_count"] / max(s["_compat"]["expected_count"], 1)
    )
    return {"compatible": best_compatible, "closest": closest}


def get_active_slug() -> str | None:
    _migrate_legacy_flat_model_if_needed()
    if not os.path.exists(_ACTIVE_POINTER_FILE):
        return None
    with open(_ACTIVE_POINTER_FILE, encoding="utf-8") as f:
        return json.load(f).get("active_slug")


def set_active_slug(slug: str):
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(_ACTIVE_POINTER_FILE, "w", encoding="utf-8") as f:
        json.dump({"active_slug": slug}, f, indent=2)


def train_models(feature_df, y_raw, numeric_cols, categorical_cols,
                  test_size: float = 0.25, random_state: int = 42, progress_callback=None):
    """Fit a preprocessing pipeline + Random Forest, XGBoost
    (supervised), and Isolation Forest (unsupervised) - all on a
    TRAINING split only (see module docstring on why). Raises
    ValueError if there's no usable label.

    `progress_callback`, if given, is called with a short status string
    before each stage - purely cosmetic, never changes what gets
    trained or how.
    """
    if y_raw is None:
        raise ValueError(
            "Supervised training requires a label column, but this "
            "dataset has none - only Isolation Forest anomaly detection "
            "is possible for unlabeled data."
        )
    if y_raw.nunique(dropna=True) < 2:
        raise ValueError(
            "The label column needs at least two distinct classes to "
            "train a classifier."
        )

    def _report(msg):
        if progress_callback:
            progress_callback(msg)

    _report("Encoding labels...")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_raw.astype(str))

    _report(f"Splitting {len(feature_df):,} rows into train/test "
            f"({int((1 - test_size) * 100)}/{int(test_size * 100)}) before fitting any "
            f"imputer/scaler/encoder, to avoid test-set leakage...")
    try:
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            feature_df, y_encoded, test_size=test_size, random_state=random_state,
            stratify=y_encoded,
        )
    except ValueError:
        # A class with too few members (e.g. 1 sample) makes a
        # stratified split impossible - fall back to a plain random
        # split rather than crash, and say so plainly.
        _report(
            "Warning: at least one class has too few samples to stratify the "
            "split - falling back to a non-stratified random split."
        )
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            feature_df, y_encoded, test_size=test_size, random_state=random_state,
        )

    _report("Fitting the preprocessing pipeline on the training split only...")
    preprocessor = build_preprocessing_pipeline(numeric_cols, categorical_cols)
    X_train = preprocessor.fit_transform(X_train_raw)
    X_test = preprocessor.transform(X_test_raw)

    # n_jobs=-1 (all CPU cores): a performance setting only, not an
    # architecture change - parallelized fitting across trees.
    #
    # n_estimators=100 (was 200): Random Forest is by far the slowest
    # of the three models trained here - measured at ~69s fitting 200
    # trees on an 80k-row x 70-feature table on a typical laptop, well
    # over 10x XGBoost's ~5s on the same data. Benchmarked on a
    # comparable synthetic classification task (60k rows, 70 features,
    # 20 informative) before changing this: 200 trees scored weighted
    # F1 0.9415 in 21.3s, 100 trees scored 0.9379 (-0.36 points, well
    # within normal run-to-run ensemble variance) in 9.2s - more than
    # 2x faster for a difference nowhere near "sacrificing reliability".
    # sklearn's own long-maintained default is 100 for exactly this
    # reason: it's the point past which more trees mostly cost fit
    # time rather than buy meaningfully better accuracy.
    # max_depth=30, max_samples=0.5 (both new): the above n_estimators=100
    # tuning was never the real problem for a genuinely LARGE upload -
    # benchmarked directly against this app's own train_models() on a
    # synthetic 445,909-row dataset (the size of a real large CICIDS-style
    # upload), fitting Random Forest alone took 311s (XGBoost: 14s on the
    # SAME data - over 20x faster for the same job), because sklearn
    # grows each tree to FULL depth by default - confirmed an average
    # actual depth of ~95 on that run. Every split at every one of those
    # ~95 levels re-evaluates across however many rows reached that node,
    # which is what actually dominates fit time at this scale, not tree
    # count. Benchmarked the fix on the trusted 60k-row/70-feature/20-
    # informative synthetic task already used above: uncapped scored
    # F1 0.8495 in 8.15s; max_depth=30 + max_samples=0.5 (each tree
    # bootstrap-sampled from only half the training rows, a standard
    # bagging regularizer - not a data-quality compromise, every row is
    # still eligible, just not every row for every tree) scored F1 0.8206
    # (-2.89 points) in 4.88s - 40% faster for a few points of F1, the
    # trade the user explicitly chose over leaving this uncapped.
    _report(f"Training Random Forest on {len(X_train):,} rows...")
    with timed(f"train_models: fit random_forest ({len(X_train):,} rows)"):
        rf = RandomForestClassifier(
            n_estimators=100, max_depth=30, max_samples=0.5,
            random_state=random_state, n_jobs=-1,
        )
        rf.fit(X_train, y_train)

    _report(f"Training XGBoost on {len(X_train):,} rows...")
    with timed(f"train_models: fit xgboost ({len(X_train):,} rows)"):
        xgb = XGBClassifier(eval_metric="mlogloss", random_state=random_state, n_jobs=-1)
        xgb.fit(X_train, y_train)

    # contamination approximated from the observed proportion of
    # non-benign training labels (clipped to a sane range) - not an
    # arbitrary guess, but also not treated as ground truth since
    # Isolation Forest itself never sees the labels.
    _report("Training Isolation Forest...")
    with timed(f"train_models: fit isolation_forest ({len(X_train):,} rows)"):
        non_benign_ratio = sum(
            1 for v in y_raw.astype(str).str.lower() if v not in BENIGN_TOKENS
        ) / len(y_raw)
        contamination = min(max(non_benign_ratio, 0.01), 0.5)
        iso = IsolationForest(contamination=contamination, random_state=random_state, n_jobs=-1)
        iso.fit(X_train)

    _report("Evaluating models on the held-out test split...")
    with timed(f"train_models: evaluate on test split ({len(X_test):,} rows)"):
        metrics = {
            "random_forest": evaluate_classifier(rf, X_test, y_test, label_encoder),
            "xgboost": evaluate_classifier(xgb, X_test, y_test, label_encoder),
        }
    best_model = max(metrics, key=lambda name: metrics[name]["f1"])

    return {
        "models": {"random_forest": rf, "xgboost": xgb, "isolation_forest": iso},
        "preprocessor": preprocessor,
        "label_encoder": label_encoder,
        "numeric_cols": numeric_cols,
        "categorical_cols": categorical_cols,
        "raw_feature_names": list(feature_df.columns),
        "metrics": metrics,
        "best_model": best_model,
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "test_size": test_size,
        "random_state": random_state,
    }


def save_models(train_result: dict, dataset_name: str, make_active: bool = True) -> str:
    """Persist trained models + the fitted preprocessing pipeline + a
    metadata JSON (metrics, feature schema, timestamps) into this
    dataset's OWN slot (models/<slug>/) - never the flat root, and
    never another dataset's slot. Returns the slug. Setting
    make_active=True (the default, matching the existing "Train
    Models" button's behaviour) also switches load_models() to this
    slot; pass False to train/evaluate a slot without switching the
    live detection model away from whatever is currently active."""
    _migrate_legacy_flat_model_if_needed()
    slug = slugify(dataset_name)
    slot_dir = _slot_dir(slug)
    os.makedirs(slot_dir, exist_ok=True)

    # Version increments across retrains of the SAME slug (same
    # dataset name) - read before this call's own meta overwrites it,
    # so model_meta.json keeps a count of how many times this exact
    # dataset has been (re)trained, not just its latest timestamp.
    version = 1
    existing_meta_path = os.path.join(slot_dir, _META_FILE)
    if os.path.isfile(existing_meta_path):
        try:
            with open(existing_meta_path, encoding="utf-8") as f:
                version = int(json.load(f).get("version", 0)) + 1
        except Exception:
            version = 1

    for name, filename in _MODEL_FILES.items():
        joblib.dump(train_result["models"][name], os.path.join(slot_dir, filename))
    joblib.dump(train_result["label_encoder"], os.path.join(slot_dir, _LABEL_ENCODER_FILE))
    joblib.dump(
        {
            "preprocessor": train_result["preprocessor"],
            "numeric_cols": train_result["numeric_cols"],
            "categorical_cols": train_result["categorical_cols"],
            "raw_feature_names": train_result["raw_feature_names"],
        },
        os.path.join(slot_dir, _PREPROCESSING_FILE),
    )

    meta = {
        "model_id": slug,
        "dataset_name": dataset_name,
        "version": version,
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "raw_feature_names": train_result["raw_feature_names"],
        "numeric_cols": train_result["numeric_cols"],
        "categorical_cols": train_result["categorical_cols"],
        "label_classes": [str(c) for c in train_result["label_encoder"].classes_],
        "best_model": train_result["best_model"],
        "metrics": train_result["metrics"],
        "train_rows": train_result.get("train_rows"),
        "test_rows": train_result.get("test_rows"),
        "training_config": {
            "test_size": train_result.get("test_size"),
            "random_state": train_result.get("random_state"),
        },
    }
    with open(os.path.join(slot_dir, _META_FILE), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    if make_active:
        set_active_slug(slug)
    return slug


def has_trained_model(slug: str | None = None) -> bool:
    _migrate_legacy_flat_model_if_needed()
    slug = slug or get_active_slug()
    if slug is None:
        return False
    slot_dir = _slot_dir(slug)
    return all(os.path.exists(os.path.join(slot_dir, f)) for f in _ALL_SLOT_FILES)


def get_slot_trained_at(slug: str) -> str | None:
    """The 'trained_at' timestamp from `slug`'s own model_meta.json
    ONLY - deliberately never touches that slot's (expensive)
    joblib-pickled model files. Used purely as a cheap cache-
    invalidation key (see app_pages/threat_detection.py's
    st.cache_resource-wrapped model loader) so re-training an EXISTING
    slug (overwriting its files in place) is detected without first
    paying the cost of loading those files."""
    meta_path = os.path.join(_slot_dir(slug), _META_FILE)
    if not os.path.isfile(meta_path):
        return None
    with open(meta_path, encoding="utf-8") as f:
        return json.load(f).get("trained_at")


def load_models(slug: str | None = None):
    """Return (models_dict, label_encoder, preprocessing_artifacts,
    meta_dict) for `slug` (or the currently active slot if not given),
    or None if no trained model exists yet for it - this INCLUDES a
    model saved by a previous version of this codebase, before the
    ColumnTransformer-based pipeline existed. An old-format
    preprocessing.pkl (a plain {encoders, scaler, ...} dict) can't be
    used safely with the current transform_features() - rather than
    crash with a confusing KeyError the first time it's used, treat it
    exactly like "no trained model yet" so the UI's existing
    'Model has not been trained yet' message (which already tells the
    analyst to click Train Models) is what shows, honestly."""
    if not has_trained_model(slug):
        return None
    slug = slug or get_active_slug()
    slot_dir = _slot_dir(slug)

    models = {
        name: joblib.load(os.path.join(slot_dir, filename))
        for name, filename in _MODEL_FILES.items()
    }
    label_encoder = joblib.load(os.path.join(slot_dir, _LABEL_ENCODER_FILE))
    artifacts = joblib.load(os.path.join(slot_dir, _PREPROCESSING_FILE))
    if not isinstance(artifacts, dict) or "preprocessor" not in artifacts or "raw_feature_names" not in artifacts:
        return None
    with open(os.path.join(slot_dir, _META_FILE), encoding="utf-8") as f:
        meta = json.load(f)

    return models, label_encoder, artifacts, meta
