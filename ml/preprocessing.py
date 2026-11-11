"""
Dataset validation and feature preprocessing (Layer 2/3 of the FYP
architecture: ingestion -> processing).

Rewritten to be dataset-agnostic and leakage-safe:

- Any numeric column may contain +-infinity, NaN, numeric-looking
  strings, or a handful of corrupted huge values - sanitize_dataframe()
  is the ONE place that detects and fixes all of these, and it always
  returns a report of exactly what it changed (see its docstring).
  This is what fixes "Input X contains infinity or a value too large
  for dtype('float64')" - the root cause was that infinities were
  never converted to NaN before median-imputation, so they survived
  straight into StandardScaler/the model.
- fit_transform_features()/transform_features() now build and reuse a
  real sklearn ColumnTransformer (SimpleImputer+StandardScaler for
  numeric columns, SimpleImputer+OneHotEncoder for categorical ones)
  instead of a hand-rolled LabelEncoder+StandardScaler pair. This is
  what makes "unseen category at prediction time" a solved problem
  (OneHotEncoder(handle_unknown="ignore") maps it to all-zeros instead
  of a hacky "pretend it's the first known class") and is REUSED
  identically for training, evaluation, and every future prediction -
  see ml/train_model.py for where it gets fit (always on a TRAIN split
  only, never on data that will also be evaluated/used for test
  scoring - that split happens in ml/train_model.py precisely so this
  module is never tempted to fit on data it shouldn't see).
- profile_dataset()/check_schema_compatibility() exist so the UI
  (app_pages/threat_detection.py) can tell the analyst, in plain
  language, whether an uploaded CSV with different column names/order/
  count is compatible with an already-trained model BEFORE attempting
  a prediction that would otherwise fail with a raw exception.
"""
import re

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# Common column names for the ground-truth label in public network
# traffic datasets (NSL-KDD, CICIDS2017, CSE-CIC-IDS2018, common Kaggle
# "malicious URL/traffic" sets, ...). Matched case-insensitively (see
# detect_label_column) so "Label", "label", "LABEL", "Attack Type" all
# match the same candidate without needing every literal casing here.
LABEL_CANDIDATES = [
    "label", "class", "attack_type", "attack type", "attack",
    "target", "outcome", "category", "classification",
]

# Values that mean "not an attack" across common dataset conventions.
# Anything else in the label column is treated as a distinct malicious
# category (used to derive the BENIGN/MALICIOUS binary label).
BENIGN_TOKENS = {"benign", "normal", "0", "no", "false", "legitimate"}

# Column-name fragments that strongly suggest an identifier rather
# than a predictive feature (a row/flow id, an IP address, a raw
# timestamp) - flagged to the analyst, never silently dropped, since a
# false positive here would quietly remove a real feature.
IDENTIFIER_HINTS = ["id", "flow id", "src ip", "dst ip", "source ip",
                     "destination ip", "timestamp"]
# Word-boundary regexes built from IDENTIFIER_HINTS - a bare substring
# match (e.g. "id" inside "Idle Mean") produced false positives on real
# CICIDS2017 data, so each hint only matches as a whole word/token
# (surrounded by start/end-of-string, spaces, or underscores), not as
# a fragment buried inside an unrelated word.
_IDENTIFIER_HINT_PATTERNS = [
    re.compile(r"(?<![a-z0-9])" + re.escape(hint).replace(r"\ ", r"[ _]") + r"(?![a-z0-9])")
    for hint in IDENTIFIER_HINTS
]

# float32's max finite value - genuinely "too large to survive" later
# (XGBoost casts to float32 internally; StandardScaler can itself
# overflow to inf when squaring a value anywhere near float64's own
# max). Nothing below this is ever touched just for being "large" -
# real network-flow values (bytes/s, packet counts, durations) never
# legitimately approach it, so clipping here only ever catches
# corrupted/erroneous values, never valid traffic data.
SAFE_FLOAT_MAX = float(np.finfo(np.float32).max)


def detect_label_column(df: pd.DataFrame, user_override: str | None = None):
    """Return the column to use as the label.

    `user_override`, if given and present in df.columns, always wins -
    this is what lets the analyst manually pick the target column in
    the UI when automatic detection is uncertain or wrong. Otherwise,
    match LABEL_CANDIDATES case-insensitively (so a dataset's own
    "Label"/"ATTACK_TYPE"/"Attack Type" all match without needing
    every literal casing in the candidate list). Returns None if the
    dataset appears unlabeled."""
    if user_override and user_override in df.columns:
        return user_override

    lower_map = {str(c).strip().lower(): c for c in df.columns}
    for candidate in LABEL_CANDIDATES:
        if candidate in lower_map:
            return lower_map[candidate]
    return None


def detect_identifier_columns(df: pd.DataFrame, label_col) -> list[str]:
    """Columns whose NAME suggests an identifier/non-predictive field
    (flow id, IP address, raw timestamp) - returned for the UI to
    display and let the analyst decide whether to exclude them. Never
    dropped automatically - a name match is only a hint, not proof."""
    hits = []
    for c in df.columns:
        if c == label_col:
            continue
        name = str(c).strip().lower()
        if any(pattern.search(name) for pattern in _IDENTIFIER_HINT_PATTERNS):
            hits.append(c)
    return hits


def derive_binary_label(y_raw: pd.Series) -> pd.Series:
    """Collapse a possibly multi-class label column (e.g. 'normal',
    'dos', 'probe', 'r2l') into BENIGN / MALICIOUS."""
    return y_raw.astype(str).str.strip().str.lower().apply(
        lambda v: "BENIGN" if v in BENIGN_TOKENS else "MALICIOUS"
    )


def classify_columns(df: pd.DataFrame, label_col) -> tuple[list[str], list[str]]:
    """Split feature columns into (numeric_cols, categorical_cols).
    A column already stored as a number dtype is numeric; anything
    else is tried as numeric (common for a CSV where numbers were
    read as strings/objects) and classified numeric only if at least
    half of its non-null values actually parse as a number - otherwise
    it's treated as categorical (text), never forced."""
    feature_cols = [c for c in df.columns if c != label_col]
    numeric_cols, categorical_cols = [], []
    for c in feature_cols:
        if pd.api.types.is_numeric_dtype(df[c]):
            numeric_cols.append(c)
            continue
        coerced = pd.to_numeric(df[c], errors="coerce")
        non_null = df[c].notna().sum()
        parses_as_number = non_null > 0 and (coerced.notna().sum() / non_null) >= 0.5
        (numeric_cols if parses_as_number else categorical_cols).append(c)
    return numeric_cols, categorical_cols


def sanitize_dataframe(df: pd.DataFrame, numeric_cols: list[str]) -> tuple[pd.DataFrame, dict]:
    """THE fix for 'Input X contains infinity or a value too large for
    dtype float64'. For every numeric column:
      1. Coerce to numeric (a numeric value stored as text, e.g. "123",
         parses fine; genuinely invalid text becomes NaN - reported).
      2. Replace +-infinity with NaN (reported) - this must happen
         BEFORE any median/imputation step, otherwise the infinity
         simply survives untouched (fillna only ever touches NaN).
      3. Clip any remaining finite value beyond SAFE_FLOAT_MAX (either
         direction) to that bound (reported) - never touches a value
         that was already within a safe range, no matter how "large"
         it looks for ordinary traffic data.
    Returns (sanitized_df, report). report's counts are always real,
    computed numbers - never estimated."""
    working = df.copy()
    report = {
        "invalid_strings_to_nan": {},
        "infinities_replaced": {},
        "values_clipped": {},
        "all_missing_columns": [],
    }

    for c in numeric_cols:
        if c not in working.columns:
            continue
        original = working[c]
        coerced = pd.to_numeric(original, errors="coerce")

        # How many non-null originals failed to parse as a number at all
        # (e.g. "N/A", "unknown", a stray unit suffix).
        invalid_strings = int(((original.notna()) & (coerced.isna())).sum())
        if invalid_strings:
            report["invalid_strings_to_nan"][c] = invalid_strings

        is_inf = np.isinf(coerced.to_numpy(dtype="float64", na_value=0.0)) & coerced.notna()
        n_inf = int(is_inf.sum())
        if n_inf:
            coerced = coerced.mask(is_inf, np.nan)
            report["infinities_replaced"][c] = n_inf

        is_oversized = coerced.abs() > SAFE_FLOAT_MAX
        n_oversized = int(is_oversized.fillna(False).sum())
        if n_oversized:
            coerced = coerced.clip(lower=-SAFE_FLOAT_MAX, upper=SAFE_FLOAT_MAX)
            report["values_clipped"][c] = n_oversized

        if coerced.notna().sum() == 0 and len(coerced) > 0:
            report["all_missing_columns"].append(c)

        working[c] = coerced

    return working, report


def get_dataset_info(df: pd.DataFrame, label_col):
    """Real, computed dataset statistics for the 'Dataset Information'
    panel - never estimated or hard-coded."""
    missing = df.isna().sum()
    numeric_cols, categorical_cols = classify_columns(df, label_col)
    return {
        "rows": len(df),
        "columns": df.shape[1],
        "feature_count": df.shape[1] - (1 if label_col else 0),
        "numeric_feature_count": len(numeric_cols),
        "categorical_feature_count": len(categorical_cols),
        "label_column": label_col,
        "is_labeled": label_col is not None,
        "missing_total": int(missing.sum()),
        "missing_by_column": {c: int(v) for c, v in missing[missing > 0].items()},
        "duplicate_rows": int(df.duplicated().sum()),
        "class_distribution": (
            df[label_col].value_counts().to_dict() if label_col else None
        ),
        "identifier_like_columns": detect_identifier_columns(df, label_col),
    }


def check_schema_compatibility(available_columns, expected_columns) -> dict:
    """Compare a dataset's own raw feature columns against the raw
    feature columns an already-trained model expects (model_meta.json's
    "raw_feature_names" - set once, at that model's own training time).
    Matching is by NAME, never by position/order, and never pretends
    an unrelated column is equivalent to a missing one."""
    available = set(available_columns)
    expected = set(expected_columns)
    matched = sorted(available & expected)
    missing = sorted(expected - available)
    extra = sorted(available - expected)
    return {
        "matched": matched,
        "missing": missing,
        "extra": extra,
        "compatible": len(missing) == 0,
        "match_count": len(matched),
        "expected_count": len(expected),
    }


def validate_dataset(df: pd.DataFrame, label_col):
    """Rule-based checks on the raw upload. Returns (is_valid, messages).
    is_valid=False means training/detection should not proceed."""
    if df.empty:
        return False, ["The uploaded file has no rows."]

    messages = []
    is_valid = True

    if len(df) < 20:
        is_valid = False
        messages.append(
            f"Only {len(df)} row(s) found - at least 20 are recommended so a "
            f"train/test split is meaningful."
        )

    feature_cols = [c for c in df.columns if c != label_col]
    if len(feature_cols) < 2:
        is_valid = False
        messages.append("At least 2 feature columns (besides the label) are required.")

    if label_col is None:
        messages.append(
            "No label column detected (looked for, case-insensitively: "
            + ", ".join(LABEL_CANDIDATES) +
            "). You can pick the target column manually above. Without one, "
            "supervised training (Random Forest, XGBoost) is unavailable - "
            "only unsupervised anomaly detection (Isolation Forest) is possible."
        )
    else:
        n_classes = df[label_col].nunique(dropna=True)
        if n_classes < 2:
            is_valid = False
            messages.append(
                f"Label column '{label_col}' only has {n_classes} unique "
                f"value(s) - at least 2 are needed to train a classifier."
            )
        else:
            class_counts = df[label_col].value_counts(dropna=True)
            rare = class_counts[class_counts < 2]
            if not rare.empty:
                messages.append(
                    "These classes have fewer than 2 samples, so a stratified "
                    "train/test split can't guarantee both splits see them - "
                    "training will automatically fall back to a non-stratified "
                    "split if needed: " + ", ".join(f"{k} ({v})" for k, v in rare.items())
                )

    high_missing_cols = [c for c in df.columns if df[c].isna().mean() > 0.5]
    if high_missing_cols:
        messages.append(
            "These columns are more than 50% missing and will be dropped "
            "during preprocessing: " + ", ".join(high_missing_cols)
        )

    dup_count = int(df.duplicated().sum())
    if dup_count:
        messages.append(
            f"{dup_count:,} duplicate row(s) detected. They are NOT removed "
            f"automatically - review them yourself if that matters for this "
            f"dataset (e.g. re-sampled/exported data can legitimately repeat rows)."
        )

    if is_valid and not messages:
        messages.append("Dataset looks valid.")

    return is_valid, messages


def build_preprocessing_pipeline(numeric_cols: list[str], categorical_cols: list[str]) -> ColumnTransformer:
    """A real sklearn ColumnTransformer - median-impute+scale numeric
    columns, most-frequent-impute+one-hot-encode categorical ones.
    OneHotEncoder(handle_unknown="ignore") is what makes a category
    never seen during training map to all-zeros at prediction time
    instead of crashing or silently pretending it's some other
    category. Returned UNFITTED - ml/train_model.py fits this on the
    training split only, then reuses the same fitted object for the
    test split and every future prediction (see that module)."""
    numeric_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])
    categorical_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])
    transformers = []
    if numeric_cols:
        transformers.append(("num", numeric_pipeline, numeric_cols))
    if categorical_cols:
        transformers.append(("cat", categorical_pipeline, categorical_cols))
    return ColumnTransformer(transformers, remainder="drop")


def transform_features(feature_df: pd.DataFrame, artifacts: dict) -> pd.DataFrame:
    """Apply an ALREADY-FITTED preprocessing pipeline (detection time,
    or test-split evaluation time) - never fits anything itself.
    Raises ValueError (with a clear, structured reason) if `feature_df`
    is missing columns the trained model expects; see
    check_schema_compatibility() for how the UI checks this BEFORE
    ever calling this function, so the analyst sees a clear compatibility
    report instead of this exception in the common case."""
    raw_feature_names = artifacts["raw_feature_names"]
    missing_cols = [c for c in raw_feature_names if c not in feature_df.columns]
    if missing_cols:
        raise ValueError(
            "This dataset is missing column(s) the trained model expects: "
            + ", ".join(missing_cols)
        )

    df = feature_df[raw_feature_names].copy()
    df, _ = sanitize_dataframe(df, artifacts["numeric_cols"])
    for c in artifacts["categorical_cols"]:
        df[c] = df[c].astype(str)

    transformed = artifacts["preprocessor"].transform(df)
    return pd.DataFrame(transformed, index=df.index)


def preprocess_dataset(df: pd.DataFrame, label_col, exclude_cols: list | None = None):
    """Training-time preprocessing: drop analyst-excluded columns
    (e.g. identifier-like columns the analyst chose to remove - see
    detect_identifier_columns()) and very-sparse columns, split off
    the label, classify + SANITIZE the remaining features (inf/NaN/
    oversized-value handling - see sanitize_dataframe()). Deliberately
    does NOT fit any encoder/scaler here - that only happens inside
    ml/train_model.py's train_models(), and only on the training split,
    to avoid the test split ever leaking into a fitted transformer.
    Returns a dict bundle used by both the UI (to show a summary) and
    ml/train_model.py (to train on)."""
    working = df.copy()

    manually_excluded = [c for c in (exclude_cols or []) if c in working.columns and c != label_col]
    if manually_excluded:
        working = working.drop(columns=manually_excluded)

    drop_cols = [
        c for c in working.columns
        if c != label_col and working[c].isna().mean() > 0.5
    ]
    working = working.drop(columns=drop_cols)

    if label_col and label_col in working.columns:
        y_raw = working[label_col]
        feature_df = working.drop(columns=[label_col])
    else:
        y_raw = None
        feature_df = working

    numeric_cols, categorical_cols = classify_columns(feature_df, None)
    feature_df, sanitization_report = sanitize_dataframe(feature_df, numeric_cols)
    for c in categorical_cols:
        feature_df[c] = feature_df[c].fillna("missing").astype(str)

    y_binary = derive_binary_label(y_raw) if y_raw is not None else None

    return {
        "X": feature_df,
        "y_raw": y_raw,
        "y_binary": y_binary,
        "numeric_cols": numeric_cols,
        "categorical_cols": categorical_cols,
        "dropped_columns": drop_cols,
        "manually_excluded_columns": manually_excluded,
        "label_column": label_col,
        "sanitization_report": sanitization_report,
        "duplicate_rows": int(df.duplicated().sum()),
    }
