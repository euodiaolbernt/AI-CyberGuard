"""
CICIDS2017 dataset loading + cleaning.

Kept separate from ml/preprocessing.py deliberately: preprocessing.py's
fit_transform_features()/transform_features() are dataset-agnostic and
used for ANY uploaded CSV, not just CICIDS2017. The issues handled here
(zero-variance columns, physically-impossible negative flow values, a
label-encoding artifact, severe class imbalance) are specific to this
one public dataset's known quirks - confirmed by direct inspection of
the 8 files in data/CICIDS2017/, not assumed. Nothing here is silently
discarded: clean_cicids2017() returns a report dict alongside the
cleaned DataFrame, and app_pages/threat_detection.py surfaces every
entry in it to the analyst.

This module never trains anything and never writes to the database -
it only loads and reports on the raw files, matching the read-only
inspection already performed before this integration was implemented.
"""
from pathlib import Path

import pandas as pd

CICIDS2017_DIR = Path(__file__).resolve().parent.parent / "data" / "CICIDS2017"

# The 8 files confirmed present and schema-identical during inspection.
# Listed explicitly (rather than a bare glob) so a missing file is
# reported by name instead of silently changing the combined dataset.
CICIDS2017_FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Botnet-Friday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
]

LABEL_COLUMN = "Label"

# Columns confirmed (by direct inspection) to have zero variance across
# all 8 files - they carry no signal for any classifier and are dropped
# before training. Detected by name, not blindly assumed: if a future
# copy of the dataset doesn't actually have zero variance in one of
# these, _drop_zero_variance_columns() below only drops what it
# re-verifies live on the loaded data.
KNOWN_ZERO_VARIANCE_COLUMNS = [
    "Bwd PSH Flags", "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
]

# Flow-level fields that can never be legitimately negative - a small
# number of rows in the public dataset have corrupted negative values
# here (confirmed by inspection: Flow Duration min -13, Flow Bytes/s
# min -2.61e8, Flow Packets/s min -2,000,000). Clipped to 0 rather than
# dropped, so already-rare attack classes (e.g. Heartbleed, 11 rows
# total) aren't shrunk further by row deletion.
NON_NEGATIVE_COLUMNS = ["Flow Duration", "Flow Bytes/s", "Flow Packets/s"]

# A class this small makes any train/test split's per-class metrics
# unreliable (e.g. a 25% test split of 11 rows is ~3 rows) - flagged to
# the analyst, never hidden, and never removed from training.
RARE_CLASS_THRESHOLD = 50

# The public dataset's "Web Attack" labels have a mangled separator
# character (U+FFFD, the Unicode replacement character) where an
# en-dash should be - confirmed by inspecting the raw bytes. Normalized
# to a plain hyphen so the label is readable everywhere it's displayed
# (UI, compliance engine, model_meta.json) without changing what
# attack the label actually names.
MOJIBAKE_CHAR = "�"


def check_cicids2017_files_present() -> tuple[bool, list[str]]:
    """Return (all_present, missing_filenames) without loading anything."""
    missing = [f for f in CICIDS2017_FILES if not (CICIDS2017_DIR / f).exists()]
    return not missing, missing


def load_cicids2017_raw(progress_callback=None) -> pd.DataFrame:
    """Read all 8 CICIDS2017 Parquet files and concatenate them.

    `progress_callback`, if given, is called with a short status string
    after each file loads - purely cosmetic (see
    app_pages/threat_detection.py), never affects the returned data.
    Raises FileNotFoundError (naming the missing file) rather than
    silently loading a partial/incomplete combined dataset.
    """
    frames = []
    for filename in CICIDS2017_FILES:
        path = CICIDS2017_DIR / filename
        if not path.exists():
            raise FileNotFoundError(
                f"Expected CICIDS2017 file not found: {path}. "
                f"The original files must not be moved, renamed, or deleted."
            )
        df = pd.read_parquet(path)
        frames.append(df)
        if progress_callback:
            progress_callback(f"Loaded {filename}: {len(df):,} rows")

    combined = pd.concat(frames, ignore_index=True)
    if progress_callback:
        progress_callback(
            f"Combined dataset: {len(combined):,} rows, {combined.shape[1]} columns"
        )
    return combined


def clean_cicids2017(df: pd.DataFrame, progress_callback=None) -> tuple[pd.DataFrame, dict]:
    """Apply the CICIDS2017-specific fixes identified during inspection.

    Returns (cleaned_df, report) - report documents exactly what was
    changed so the caller can show it to the analyst instead of
    silently altering the dataset:
        - dropped_zero_variance_columns: list[str]
        - negative_values_clipped: {column: count_of_rows_clipped}
        - label_encoding_fixed: bool
        - rare_classes: {label: count} for any class below
          RARE_CLASS_THRESHOLD (informational only - never removed)
        - rows_before / rows_after
    """
    working = df.copy()
    report = {
        "rows_before": len(working),
        "dropped_zero_variance_columns": [],
        "negative_values_clipped": {},
        "label_encoding_fixed": False,
        "rare_classes": {},
    }

    # 1. Zero-variance columns: re-verify live rather than trusting the
    # hard-coded list blindly.
    zero_var_cols = [
        c for c in KNOWN_ZERO_VARIANCE_COLUMNS
        if c in working.columns and working[c].nunique(dropna=False) <= 1
    ]
    if zero_var_cols:
        working = working.drop(columns=zero_var_cols)
        report["dropped_zero_variance_columns"] = zero_var_cols
    if progress_callback:
        progress_callback(f"Dropped {len(zero_var_cols)} zero-variance column(s)")

    # 2. Physically-impossible negative values: clip to 0, count how
    # many rows were affected per column (not dropped - see module
    # docstring).
    for col in NON_NEGATIVE_COLUMNS:
        if col not in working.columns:
            continue
        n_negative = int((working[col] < 0).sum())
        if n_negative:
            working[col] = working[col].clip(lower=0)
            report["negative_values_clipped"][col] = n_negative
    if progress_callback:
        total_clipped = sum(report["negative_values_clipped"].values())
        progress_callback(f"Clipped {total_clipped:,} impossible negative value(s)")

    # 3. Label mojibake fix: normalize the replacement character to a
    # plain hyphen so it's readable everywhere downstream.
    if LABEL_COLUMN in working.columns:
        labels = working[LABEL_COLUMN].astype(str)
        if labels.str.contains(MOJIBAKE_CHAR, regex=False).any():
            fixed = labels.str.replace(f" {MOJIBAKE_CHAR} ", " - ", regex=False)
            working[LABEL_COLUMN] = fixed.astype("category")
            report["label_encoding_fixed"] = True
    if progress_callback:
        progress_callback("Fixed Web Attack label encoding artifact" if report["label_encoding_fixed"]
                           else "No label encoding artifact found")

    # 4. Severe class imbalance: report, never remove.
    if LABEL_COLUMN in working.columns:
        counts = working[LABEL_COLUMN].value_counts()
        rare = counts[counts < RARE_CLASS_THRESHOLD]
        report["rare_classes"] = {str(k): int(v) for k, v in rare.items()}
    if progress_callback and report["rare_classes"]:
        progress_callback(
            f"Warning: {len(report['rare_classes'])} class(es) have fewer than "
            f"{RARE_CLASS_THRESHOLD} samples - their evaluation metrics will be unreliable"
        )

    report["rows_after"] = len(working)
    return working, report


def load_and_clean_cicids2017(progress_callback=None) -> tuple[pd.DataFrame, dict]:
    """Convenience wrapper: load_cicids2017_raw() + clean_cicids2017()."""
    raw = load_cicids2017_raw(progress_callback)
    return clean_cicids2017(raw, progress_callback)
