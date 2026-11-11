"""
Generic, format-agnostic uploaded-dataset loader for Threat Detection's
"Multi-Format Upload" tab.

Kept separate from ml/dataset_loader.py (CICIDS2017-specific cleaning)
and ml/preprocessing.py (dataset-agnostic validation/preprocessing,
already used identically regardless of which tab populated
st.session_state["td_df"]) - this module's only job is turning an
uploaded file of ANY supported format into a plain pandas DataFrame, so
every stage downstream (Dataset Information, Validation, Preprocessing,
Training, Evaluation, Detection) runs through the exact same code no
matter which tab the file came from. No format-specific ML logic lives
here, and nothing here writes to the database.

SECURITY: Pickle (.pkl/.pickle) deserializes arbitrary Python objects
and can execute attacker-controlled code during unpickling - a real,
well-known risk, not a theoretical one. load_uploaded_dataset() never
reads a pickle file unless the caller explicitly passes
allow_pickle=True, which app_pages/threat_detection.py only ever sets
after the analyst has checked an explicit "I trust this file" box.
"""
import io
import json
from pathlib import Path

import pandas as pd

# Extension (lowercased, no leading dot) -> (format key, human label).
SUPPORTED_FORMATS = {
    "csv": ("csv", "CSV"),
    "tsv": ("tsv", "TSV"),
    "txt": ("txt", "Delimited text"),
    "xlsx": ("excel", "Excel (.xlsx)"),
    "xls": ("excel_legacy", "Excel (.xls, legacy)"),
    "parquet": ("parquet", "Parquet"),
    "json": ("json", "JSON"),
    "jsonl": ("jsonl", "JSON Lines"),
    "ndjson": ("jsonl", "JSON Lines"),
    "feather": ("feather", "Feather"),
    "orc": ("orc", "Apache ORC"),
    "pkl": ("pickle", "Pickle"),
    "pickle": ("pickle", "Pickle"),
}

ALL_EXTENSIONS = sorted(SUPPORTED_FORMATS.keys())

# Shown as badges in the UI - grouped by real underlying format, not
# duplicated per filename synonym (jsonl/ndjson are the same reader).
FORMAT_BADGES = [
    "CSV", "TSV", "TXT", "XLSX", "XLS", "Parquet", "JSON",
    "JSONL / NDJSON", "Feather", "ORC", "Pickle (opt-in)",
]

# Lightweight magic-byte checks for binary formats with a known,
# fixed signature - catches "renamed extension, wrong actual file"
# early with a clear message instead of a confusing reader-library
# exception three layers down. Formats with no reliable fixed
# signature (csv/tsv/txt/json/jsonl/legacy .xls/pickle) are validated
# by successfully parsing instead - never by guessing a signature.
_SIGNATURES = {
    "excel": (b"PK\x03\x04",),   # .xlsx is a zip container
    "parquet": (b"PAR1",),
    "feather": (b"ARROW1",),
    "orc": (b"ORC",),
}


class DatasetLoadError(Exception):
    """Raised for any uploaded-file problem the UI should show as a
    plain, friendly message - text only, never a raw traceback or
    server file path."""


def detect_format(filename: str):
    """('csv', 'CSV') for 'traffic.csv', None for an unrecognised
    extension. Extension alone is never trusted for a binary format -
    see _check_signature()."""
    ext = Path(filename).suffix.lower().lstrip(".")
    return SUPPORTED_FORMATS.get(ext)


def _check_signature(format_key: str, raw: bytes, filename: str):
    signatures = _SIGNATURES.get(format_key)
    if not signatures:
        return
    if not any(raw.startswith(sig) for sig in signatures):
        ext = Path(filename).suffix.lstrip(".")
        raise DatasetLoadError(
            f"'{filename}' has a .{ext} extension, but its contents don't "
            f"match the expected file signature for that format. The file "
            f"may be corrupted, empty, or actually saved as something else."
        )


def _require_nonempty(df: pd.DataFrame, filename: str) -> pd.DataFrame:
    if df is None or df.shape[1] == 0:
        raise DatasetLoadError(f"'{filename}' has no usable columns once parsed.")
    if df.shape[0] == 0:
        raise DatasetLoadError(
            f"'{filename}' parsed successfully but contains zero rows - an "
            f"empty dataset is never treated as a valid upload."
        )
    return df


def _parse_csv(raw: bytes, filename: str) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(raw))


def _parse_tsv(raw: bytes, filename: str) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(raw), sep="\t")


def _parse_txt(raw: bytes, filename: str) -> pd.DataFrame:
    # Auto-detect the delimiter (comma/tab/semicolon/pipe/...) via
    # pandas' own csv.Sniffer-backed engine - a plain .txt export can
    # legitimately use any of these, and guessing wrong silently would
    # produce a 1-column garbage DataFrame instead of a clear error.
    try:
        df = pd.read_csv(io.BytesIO(raw), sep=None, engine="python")
    except Exception as e:
        raise DatasetLoadError(
            f"'{filename}' doesn't look like a delimited text file pandas "
            f"can parse (tried auto-detecting comma/tab/semicolon/pipe "
            f"separators)."
        ) from e
    if df.shape[1] <= 1:
        raise DatasetLoadError(
            f"'{filename}' could not be split into multiple columns - "
            f"delimiter auto-detection found only one column, which usually "
            f"means this isn't a structured delimited file."
        )
    return df


def _parse_excel(raw: bytes, filename: str) -> pd.DataFrame:
    return pd.read_excel(io.BytesIO(raw), engine="openpyxl")


def _parse_excel_legacy(raw: bytes, filename: str) -> pd.DataFrame:
    return pd.read_excel(io.BytesIO(raw), engine="xlrd")


def _parse_parquet(raw: bytes, filename: str) -> pd.DataFrame:
    return pd.read_parquet(io.BytesIO(raw), engine="pyarrow")


def _parse_json(raw: bytes, filename: str) -> pd.DataFrame:
    try:
        return pd.read_json(io.BytesIO(raw))
    except ValueError:
        # Not a list-of-records JSON array - try a single JSON object,
        # normalised into a one-row DataFrame, before giving up.
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict):
            return pd.json_normalize(obj)
        raise


def _parse_jsonl(raw: bytes, filename: str) -> pd.DataFrame:
    return pd.read_json(io.BytesIO(raw), lines=True)


def _parse_feather(raw: bytes, filename: str) -> pd.DataFrame:
    return pd.read_feather(io.BytesIO(raw))


def _parse_orc(raw: bytes, filename: str) -> pd.DataFrame:
    return pd.read_orc(io.BytesIO(raw))


def _parse_pickle(raw: bytes, filename: str) -> pd.DataFrame:
    obj = pd.read_pickle(io.BytesIO(raw))
    if not isinstance(obj, pd.DataFrame):
        raise DatasetLoadError(
            f"'{filename}' unpickled successfully but doesn't contain a "
            f"pandas DataFrame (got {type(obj).__name__})."
        )
    return obj


_PARSERS = {
    "csv": _parse_csv,
    "tsv": _parse_tsv,
    "txt": _parse_txt,
    "excel": _parse_excel,
    "excel_legacy": _parse_excel_legacy,
    "parquet": _parse_parquet,
    "json": _parse_json,
    "jsonl": _parse_jsonl,
    "feather": _parse_feather,
    "orc": _parse_orc,
    "pickle": _parse_pickle,
}


def load_uploaded_dataset(uploaded_file, allow_pickle: bool = False):
    """Detect `uploaded_file`'s real format and parse it into a plain
    DataFrame. Returns (df, meta). Raises DatasetLoadError - a plain,
    user-safe message, never a raw stack trace or server path - for an
    unsupported extension, a signature mismatch, a missing optional
    reader dependency, corrupt/malformed content, or an empty result.
    A caller can show str(exc) to the analyst directly.

    Pickle files are never read unless allow_pickle=True (see this
    module's own docstring)."""
    filename = uploaded_file.name
    detected = detect_format(filename)
    if detected is None:
        ext = Path(filename).suffix or "(none)"
        raise DatasetLoadError(
            f"Unsupported file extension '{ext}'. Supported formats: "
            + ", ".join(FORMAT_BADGES) + "."
        )
    format_key, format_label = detected

    if format_key == "pickle" and not allow_pickle:
        raise DatasetLoadError(
            "Pickle files can execute arbitrary code when loaded, so they "
            "are never read automatically. Check \"I trust this Pickle "
            "file\" above and upload it again to proceed."
        )

    raw = uploaded_file.getvalue()
    if not raw:
        raise DatasetLoadError(f"'{filename}' is empty (0 bytes).")

    _check_signature(format_key, raw, filename)

    try:
        df = _PARSERS[format_key](raw, filename)
    except DatasetLoadError:
        raise
    except ImportError as e:
        raise DatasetLoadError(
            f"Reading {format_label} files requires an optional package "
            f"that isn't installed in this environment "
            f"({getattr(e, 'name', None) or 'unknown dependency'}). Ask "
            f"your administrator to install it, or use a different format."
        ) from e
    except (pd.errors.ParserError, pd.errors.EmptyDataError,
            UnicodeDecodeError, ValueError, json.JSONDecodeError) as e:
        raise DatasetLoadError(
            f"Could not read '{filename}' as {format_label}: {e}"
        ) from e
    except Exception:
        # Deliberately generic for any error type not already covered
        # above - never leaks an unanticipated exception's own repr
        # (which can include server file paths) to the browser.
        raise DatasetLoadError(
            f"Could not read '{filename}' as {format_label} - the file may "
            f"be corrupted or malformed."
        )

    df = _require_nonempty(df, filename)

    meta = {
        "filename": filename,
        "format_key": format_key,
        "format_label": format_label,
        "size_bytes": len(raw),
        "rows": len(df),
        "columns": df.shape[1],
    }
    return df, meta
