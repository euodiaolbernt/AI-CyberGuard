"""
Threat Detection page (Step 3 / Spiral Model Iteration 3).

Pipeline implemented across ml/*:

    Dataset (CSV upload OR the bundled CICIDS2017 Parquet files - see
    ml/dataset_loader.py) -> validate -> preprocess (ml/preprocessing.py)
        -> train Random Forest + XGBoost + Isolation Forest
           (ml/train_model.py), evaluated with real metrics
           (ml/evaluation.py)
        -> save models to models/ (joblib) so they are NOT retrained
           on every page load
        -> "Run AI Detection" loads the saved models and classifies
           new data (ml/prediction.py), deriving a transparent risk
           score/severity (ml/risk_scoring.py)
        -> results are written to network_traffic + threat_detections
           in MySQL, which is exactly what the Step 2 Dashboard already
           reads - so real detections now flow straight into its KPIs,
           charts and "Recent Threats" table with no Dashboard changes.

The user never chooses BENIGN/MALICIOUS themselves - every verdict
below comes from a trained model's .predict()/.predict_proba().

CICIDS2017 note: loading it (via "Load CICIDS2017 Dataset" below) only
reads files and cleans known data-quality issues (see
ml/dataset_loader.py) - it never trains anything on its own. Training
only ever happens when the analyst clicks "Train Models" further down,
same as for any CSV upload.
"""
import io
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import config
from auth.rate_limit import check_and_bump_cooldown
from compliance.compliance_engine import build_network_event, process_security_events_bulk
from database.models import (
    delete_network_traffic,
    get_threat_detections_in_range,
    insert_network_traffic,
    insert_threat_detections_bulk,
)
from ml.dataset_loader import (
    CICIDS2017_DIR,
    RARE_CLASS_THRESHOLD,
    check_cicids2017_files_present,
    load_and_clean_cicids2017,
)
from ml.file_loader import FORMAT_BADGES, DatasetLoadError, load_uploaded_dataset
from ml.prediction import run_detection, run_detection_on_prepared
from ml.preprocessing import (
    derive_binary_label,
    detect_identifier_columns,
    detect_label_column,
    get_dataset_info,
    preprocess_dataset,
    validate_dataset,
)
from ml.train_model import (
    find_model_slot_matches,
    get_active_slug,
    get_slot_trained_at,
    list_model_slots,
    load_models,
    save_models,
    set_active_slug,
    train_models,
)
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from utils.audit_logger import log_action, log_actions_bulk
from utils.design_tokens import SEVERITY_COLORS
from utils.illustrations import place as _illustration
from utils.illustrations import (
    BANNER_ICON_ACTIVITY,
    BANNER_ICON_CHIP,
    BANNER_ICON_SHIELD_CHECK,
    render_photo,
    render_premium_banner,
)
from utils.page_ui import render_empty_state
from utils.perf import timed
from utils.time_navigator import get_active_range

# Compliance/alert evaluation (Steps 7-8) only runs for detections this
# severe - a single CSV upload can produce hundreds of MALICIOUS rows,
# and running 4-8 rule checks per row for every one of them would be
# both impractical for a live page and noisy for the Compliance/Alerts
# pages. HIGH/CRITICAL already matches "worth a human's attention",
# the same bar the Dashboard and Alerts system use elsewhere.
COMPLIANCE_SEVERITY_THRESHOLD = {"HIGH", "CRITICAL"}


# ---------------------------------------------------------------
# Cached model loading - ml.train_model.load_models() joblib-loads 2
# full sklearn ensembles (Random Forest + XGBoost), an Isolation
# Forest, a label encoder, and a fitted ColumnTransformer from disk on
# every call. Before this cache, Model Evaluation and Automatic Threat
# Detection each called it independently - 2 full disk loads on EVERY
# single Threat Detection page render, even when nothing changed.
# st.cache_resource (not cache_data - these are live sklearn objects,
# not serializable data) keeps them in memory per (slug, trained_at),
# so switching pages or re-rendering costs nothing until the active
# slot or its own training timestamp actually changes.
# ---------------------------------------------------------------

@st.cache_resource(show_spinner=False)
def _cached_load_models(slug: str, trained_at: str):
    with timed(f"load_models (cache miss, slug={slug})"):
        return load_models(slug)


def _load_models_for_slug(slug: str | None):
    """Cached equivalent of ml.train_model.load_models(slug) - resolves
    `slug` (None meaning "the active slot") and that slot's real
    trained_at OUTSIDE the cache boundary, so the cache key always
    reflects the CURRENT active slot/training timestamp rather than a
    stale "None" that would never change across reruns."""
    resolved_slug = slug or get_active_slug()
    if resolved_slug is None:
        return None
    trained_at = get_slot_trained_at(resolved_slug)
    if trained_at is None:
        return None
    return _cached_load_models(resolved_slug, trained_at)


@st.cache_data(show_spinner=False)
def _cached_load_and_clean_cicids2017(_progress_callback=None):
    """Cached so repeated 'Load CICIDS2017 Dataset' clicks in the same
    process don't re-read ~260MB of Parquet from disk every time. This
    is the static reference dataset, not per-user data, so a
    process-wide cache (rather than per-session state) is correct here
    - unlike every detection RESULT downstream, which stays scoped to
    user_id all the way through the database writes below.
    The leading underscore on _progress_callback tells Streamlit not to
    hash it as a cache key (functions aren't hashable) - it still runs
    normally on a cache miss."""
    return load_and_clean_cicids2017(_progress_callback)


def render_threat_detection_page():
    with st.container(key="td_premium_banner"):
        render_premium_banner(
            badge_text="AI CYBERGUARD &bull; THREAT ENGINE",
            heading_main="Detect Smarter.", heading_accent="Respond Faster.",
            description="Every upload runs through trained AI models that classify "
                        "traffic and surface real risk - nothing here is guessed.",
            features=[
                (BANNER_ICON_ACTIVITY, "Real-time Analysis", "cyan"),
                (BANNER_ICON_CHIP, "Model-Driven Accuracy", "violet"),
                (BANNER_ICON_SHIELD_CHECK, "Transparent Risk Scoring", "teal"),
            ],
        )

    with st.container(key="td_page_wrapper"):
        _render_header_card()

        _render_upload_section()

        df = st.session_state.get("td_df")
        if df is not None:
            _sync_model_match_for_dataset(df)
            _render_active_dataset_bar()
            label_col = _render_label_column_picker(df)
            _render_dataset_info(df, label_col)
            _render_pipeline_controls(df, label_col)

        st.divider()
        st.subheader("Model Evaluation", icon=":material/model_training:")
        _render_model_evaluation()

        st.divider()
        st.subheader("Automatic Threat Detection", icon=":material/radar:")
        _render_detection_section(df)

        st.divider()
        st.subheader("Detection History", icon=":material/history:")
        _render_detection_history()


def _render_detection_history():
    """Saved detections (threat_detections rows, by their real
    detected_at timestamp - when the analysis ran, never the original
    timestamps inside an uploaded dataset) for the Global Cyber Time
    Navigator's active period - reuses get_threat_detections_in_range(),
    the same function the Reports page's CSV export already uses, so
    this is a second view over real saved records, not a new query
    path."""
    user_id = st.session_state["user_id"]
    start, end, _ = get_active_range()

    rows = get_threat_detections_in_range(user_id, start, end, limit=50)
    if not rows:
        render_empty_state(
            "No saved detections for the selected period.", "timeline_shield",
        )
        return

    st.caption(f"Most recent {len(rows)} saved detection(s) in the selected period (newest first).")
    df = pd.DataFrame([
        {
            "Time": r["detected_at"],
            "Prediction": r["prediction"],
            "Attack type": r["attack_type"] or "N/A",
            "Severity": r["severity"] or "-",
            "Risk score": r["risk_score"],
            "Model": r["model_used"] or "-",
        }
        for r in rows
    ])

    def _severity_cell(value):
        color = SEVERITY_COLORS.get(value)
        return f"color: {color}; font-weight: 600;" if color else ""

    st.dataframe(
        df.style.map(_severity_cell, subset=["Severity"]),
        width="stretch", hide_index=True,
    )


_ENGINE_STAGES = (
    ("1", "td-stage-cyan", "Data Preprocessing", "Clean, validate, and prepare uploaded traffic data."),
    ("2", "td-stage-blue", "Feature Analysis", "Identify numeric/categorical features and the target column."),
    ("3", "td-stage-violet", "AI Model Prediction", "A trained Random Forest/XGBoost model classifies each record."),
    ("4", "td-stage-green", "Result Generation", "Risk scores, severity, and results are saved for review."),
)


def _render_header_card():
    """The "how detection works" explainer, standing alone full-width.

    This used to be paired in a 2-column card with this page's own
    icon/title/subtitle - that content now lives in the ONE global
    header (utils/page_ui.py's render_top_bar(), rendered once from
    app.py for every page), so repeating it here would be exactly the
    duplicate-title/double-header look that was explicitly reported
    and asked to be removed.

    The 4-stage list is a purely descriptive explainer of the REAL
    pipeline stages this page implements (see the module docstring) -
    deliberately NOT styled with checkmarks as if already complete:
    this renders before any dataset is necessarily uploaded, so it's a
    one-time explanation of how detection works, never a live status."""
    with st.container(key="td_header_card", border=True):
        text_col, art_col = st.columns([4, 1], vertical_alignment="center")
        with text_col:
            st.markdown("#### :material/memory: Detection Engine")
            st.caption(
                "Upload network traffic data below - AI models automatically classify "
                "each record as BENIGN or MALICIOUS (there is no manual override), "
                "end to end:"
            )
        with art_col:
            render_photo("robot_laptop", width=120)
        stages_html = ""
        for num, accent_class, title, desc in _ENGINE_STAGES:
            stages_html += (
                '<div class="td-stage-row">'
                f'<span class="td-stage-badge {accent_class}">{num}</span>'
                f'<div><div class="td-stage-title">{title}</div>'
                f'<div class="td-stage-desc">{desc}</div></div>'
                '</div>'
            )
        st.markdown(stages_html, unsafe_allow_html=True)


# ---------------------------------------------------------------
# Upload / dataset selection
# ---------------------------------------------------------------

CICIDS2017_DATASET_NAME = "CICIDS2017 (combined, 8 files)"


def _set_active_dataset(df: pd.DataFrame, dataset_name: str):
    """Shared by every upload source (CSV / CICIDS2017 / Multi-Format):
    point the rest of the page's pipeline (validate/preprocess/train/
    detect) at `df`, clearing any stale validation/preprocessing/
    detection state left over from a previously loaded dataset so it
    can never leak across datasets - a detection RESULT (and its
    ground-truth evaluation, if any) answers a question about a
    SPECIFIC dataset and must disappear the moment that dataset is
    replaced by a different one, not linger looking like it still
    describes the newly loaded data.

    Column names are stripped of leading/trailing whitespace here, in
    this one shared choke point, because the original CICIDS2017 CSV
    export (and similarly-exported files) is well known to pad most
    header names with a stray leading space. Left unstripped, a column
    that is genuinely the same feature as one of the active model's
    raw_feature_names (e.g. "Bwd Packets/s" vs " Bwd Packets/s") would
    fail the exact-name match in check_schema_compatibility() and get
    listed as BOTH missing and extra - the two entries render
    identically once Markdown/HTML collapses the leading space, which
    is confusing and makes genuinely-compatible datasets look far more
    mismatched than they are."""
    if dataset_name != st.session_state.get("td_dataset_name"):
        for key in ("td_validation", "td_bundle", "td_detection_results",
                    "td_detection_ground_truth_eval", "td_auto_attempted_for",
                    "td_auto_train_error", "td_dataset_info"):
            st.session_state.pop(key, None)

    df.columns = [str(c).strip() for c in df.columns]
    st.session_state["td_df"] = df
    st.session_state["td_dataset_name"] = dataset_name


def _sync_model_match_for_dataset(df: pd.DataFrame):
    """Independent per-dataset model routing - runs BEFORE Model
    Evaluation/Automatic Threat Detection below, every render, so both
    sections agree on which model applies to THIS dataset within the
    SAME render (no page reordering, no one-rerun lag: the active
    pointer is already correct by the time Model Evaluation reads it
    further down). Checks this dataset's columns against EVERY trained
    model slot (find_model_slot_matches()), never just whichever slot
    happened to be active from a previous, unrelated dataset - and
    only switches the active pointer when the currently active slug
    isn't itself still a fit for this dataset (see that function's
    `preferred_slug` tie-break). Never trains anything here - that
    only ever happens from _render_incompatible_schema_fallback when
    nothing existing matches."""
    label_col = detect_label_column(df)
    available_cols = [c for c in df.columns if c != label_col]
    matches = find_model_slot_matches(available_cols, preferred_slug=get_active_slug())
    st.session_state["td_model_match"] = matches

    compatible = matches["compatible"]
    if compatible is not None and compatible["slug"] != get_active_slug():
        set_active_slug(compatible["slug"])


def _render_upload_section():
    # The CICIDS2017 Parquet files are ~258MB and deliberately not
    # shipped with the public repo/cloud deployment (see .gitignore) -
    # a pre-trained model is bundled instead, so retraining from this
    # raw dataset was never required for the live demo. Showing this
    # tab only when the files actually exist (e.g. local dev with the
    # dataset downloaded separately) avoids presenting a dead option
    # that always errors on the public deployment.
    cicids_present, _ = check_cicids2017_files_present()
    tab_labels = ["Upload CSV"]
    if cicids_present:
        tab_labels.append("Use CICIDS2017 Dataset")
    tab_labels.append("Multi-Format Upload")
    tabs = st.tabs(tab_labels)
    tab_upload = tabs[0]
    tab_cicids = tabs[1] if cicids_present else None
    tab_multiformat = tabs[-1]

    with tab_upload, st.container(key="td_upload_card", border=True):
        st.markdown(
            _illustration("cloud_upload_csv", width="175px", height="105px", opacity=0.95),
            unsafe_allow_html=True,
        )
        st.caption(
            f"Up to {config.MAX_UPLOAD_SIZE_MB} MB and "
            f"{config.MAX_UPLOAD_ROWS:,} rows per file."
        )
        uploaded_file = st.file_uploader("Upload Network Traffic CSV", type=["csv"])
        if uploaded_file is not None:
            _handle_csv_upload(uploaded_file)

    if tab_cicids is not None:
        with tab_cicids:
            _render_cicids2017_loader()

    with tab_multiformat:
        _render_multiformat_upload_section()

    if st.session_state.get("td_dataset_name") == CICIDS2017_DATASET_NAME:
        report = st.session_state.get("td_cicids_report")
        if report:
            _render_cicids2017_report(report)


def _handle_csv_upload(uploaded_file):
    """Validate an uploaded file BEFORE it's trusted anywhere else on
    the page: size is checked against uploaded_file.size (no read()
    needed) before pandas touches a single byte, content is checked by
    actually attempting to parse it as CSV, and the parsed row count is
    checked against a generous cap so a hostile/corrupt file can't
    exhaust memory. Nothing here executes the file's contents or
    trusts its name for anything beyond a display label - the
    filename is never used as a filesystem path.

    st.file_uploader() keeps returning the SAME UploadedFile on every
    rerun for as long as it stays attached to the widget - not just
    once at upload time. Without this guard, this function (and its
    full pd.read_csv() of a possibly hundreds-of-thousands-of-rows
    file) ran again on every single click anywhere on the page, for as
    long as the file stayed uploaded - the single biggest cost behind
    "everything feels stuck loading", far bigger than any one page
    computation. uploaded_file.file_id is a stable id Streamlit assigns
    per upload (confirmed via UploadedFile's own __init__/__eq__/__hash__
    in streamlit.runtime.uploaded_file_manager - it's what the class
    itself uses for equality), unchanged across reruns of the same
    attached file and different for a genuinely new upload - even one
    with the same filename. Gated on td_df also still being populated
    so "Clear dataset" (which pops td_df but can't reach into this
    widget's own state) still reloads exactly as it did before this
    guard existed, rather than silently refusing to."""
    if (st.session_state.get("td_df") is not None
            and st.session_state.get("td_csv_loaded_file_id") == uploaded_file.file_id):
        return

    max_bytes = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if uploaded_file.size > max_bytes:
        st.error(
            f"This file is {uploaded_file.size / (1024 * 1024):.1f} MB, which is "
            f"over the {config.MAX_UPLOAD_SIZE_MB} MB limit. Please upload a smaller file."
        )
        return

    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Could not read this file as CSV: {e}")
        return

    if df.empty or df.shape[1] == 0:
        st.error("This file has no usable rows/columns once parsed as CSV.")
        return

    if len(df) > config.MAX_UPLOAD_ROWS:
        st.error(
            f"This file has {len(df):,} rows, which is over the "
            f"{config.MAX_UPLOAD_ROWS:,}-row limit for a single upload. "
            "Please split it into smaller files."
        )
        return

    _set_active_dataset(df, uploaded_file.name)
    st.session_state["td_csv_loaded_file_id"] = uploaded_file.file_id


# ---------------------------------------------------------------
# Multi-Format Upload (CSV/TSV/TXT/Excel/Parquet/JSON/JSONL/Feather/
# ORC/Pickle) - a second entry point into the SAME pipeline the
# "Upload CSV" and "Use CICIDS2017 Dataset" tabs already use. Once
# ml/file_loader.py has turned the file into a plain DataFrame, this
# calls the exact same _set_active_dataset() they call - so Dataset
# Information, Validation, Preprocessing, Training, Evaluation, and
# Detection below all run through identical, unduplicated code
# regardless of which tab the data came from.
# ---------------------------------------------------------------

_MULTIFORMAT_EXTENSIONS = [
    "csv", "tsv", "txt", "xlsx", "xls", "parquet",
    "json", "jsonl", "ndjson", "feather", "orc", "pkl", "pickle",
]


def _render_multiformat_upload_section():
    with st.container(key="td_multiformat_card", border=True):
        st.markdown("**Multi-Format Threat Detection**")
        st.caption(
            "Upload network traffic datasets in CSV, Excel, Parquet, JSON, and "
            "other supported formats. AI CyberGuard will inspect, validate, "
            "preprocess, and evaluate the data before performing threat "
            "detection - the same pipeline as the other two tabs."
        )
        st.markdown(
            " ".join(f":blue-badge[{b}]" for b in FORMAT_BADGES),
        )
        st.caption(
            f"Up to {config.MAX_UPLOAD_SIZE_MB} MB and "
            f"{config.MAX_UPLOAD_ROWS:,} rows per file."
        )

        uploaded_file = st.file_uploader(
            "Upload a dataset in any supported format",
            type=_MULTIFORMAT_EXTENSIONS,
            key="td_multiformat_uploader",
        )

        trust_pickle = False
        if uploaded_file is not None and uploaded_file.name.lower().endswith((".pkl", ".pickle")):
            st.warning(
                ":material/warning: Pickle files can execute arbitrary code when "
                "loaded. Only load a Pickle file you created yourself or fully "
                "trust the source of."
            )
            trust_pickle = st.checkbox(
                "I trust this Pickle file and want to load it.",
                key="td_multiformat_trust_pickle",
            )

        if uploaded_file is not None:
            _handle_multiformat_upload(uploaded_file, trust_pickle)


def _handle_multiformat_upload(uploaded_file, trust_pickle: bool):
    """Same two hard limits _handle_csv_upload() enforces (size before
    parsing, row count after), plus format detection/parsing itself
    delegated to ml/file_loader.py. Every failure path shows a plain
    st.error() and returns without touching session state - a failed
    upload never silently becomes an "empty" active dataset.

    Same same-file-every-rerun guard as _handle_csv_upload() (see its
    docstring) - a separate td_multiformat_loaded_file_id key since
    this is a second, independent st.file_uploader widget that can
    hold its own file regardless of what the CSV tab's uploader holds."""
    if (st.session_state.get("td_df") is not None
            and st.session_state.get("td_multiformat_loaded_file_id") == uploaded_file.file_id):
        return

    max_bytes = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if uploaded_file.size > max_bytes:
        st.error(
            f"This file is {uploaded_file.size / (1024 * 1024):.1f} MB, which is "
            f"over the {config.MAX_UPLOAD_SIZE_MB} MB limit. Please upload a smaller file."
        )
        return

    is_pickle = uploaded_file.name.lower().endswith((".pkl", ".pickle"))
    if is_pickle and not trust_pickle:
        st.info("Check \"I trust this Pickle file\" above to load it.")
        return

    try:
        df, meta = load_uploaded_dataset(uploaded_file, allow_pickle=trust_pickle)
    except DatasetLoadError as e:
        st.error(str(e))
        return

    if len(df) > config.MAX_UPLOAD_ROWS:
        st.error(
            f"This file has {len(df):,} rows, which is over the "
            f"{config.MAX_UPLOAD_ROWS:,}-row limit for a single upload. "
            "Please split it into smaller files."
        )
        return

    _set_active_dataset(df, uploaded_file.name)
    st.session_state["td_multiformat_loaded_file_id"] = uploaded_file.file_id
    st.success(
        f":material/check_circle: Loaded **{meta['filename']}** as "
        f"{meta['format_label']} - {meta['size_bytes'] / 1024:.1f} KB, "
        f"{meta['rows']:,} rows x {meta['columns']} columns."
    )


def _render_active_dataset_bar():
    """A small, shared status bar shown once a dataset is active -
    whichever of the 3 upload tabs populated it - with a real "Clear
    dataset" control (section 7's reset requirement). Clears only this
    page's own transient per-upload state (the dataframe itself,
    validation/preprocessing results, last detection run) - never a
    permanently saved trained model (models/ on disk) and never any
    other page's data, so switching datasets can't leave stale
    validation/preprocessing/detection results from a PREVIOUS upload
    displayed against a newly loaded one."""
    dataset_name = st.session_state.get("td_dataset_name", "")
    df = st.session_state.get("td_df")
    if df is None:
        return

    with st.container(key="td_active_dataset_bar"):
        cols = st.columns([3, 1])
        with cols[0]:
            st.caption(
                f":material/table_chart: Active dataset: **{dataset_name}** "
                f"({len(df):,} rows x {df.shape[1]} columns)"
            )
        with cols[1]:
            if st.button(
                "Clear dataset", icon=":material/close:", key="td_clear_dataset",
                width="stretch",
            ):
                for key in (
                    "td_df", "td_dataset_name", "td_validation", "td_bundle",
                    "td_detection_results", "td_detection_ground_truth_eval", "td_cicids_report",
                    "td_dataset_info",
                ):
                    st.session_state.pop(key, None)
                st.rerun()


def _render_cicids2017_loader():
    present, missing = check_cicids2017_files_present()
    if not present:
        st.error(
            "One or more CICIDS2017 files are missing: " + ", ".join(missing) +
            f" (expected inside {CICIDS2017_DIR})."
        )
        return

    st.caption(
        "Loads all 8 Parquet files from `data/CICIDS2017/` automatically - "
        "no manual upload needed (~2.3 million rows combined). The original "
        "files are only read, never modified or deleted."
    )
    if st.button("Load CICIDS2017 Dataset", width="stretch", icon=":material/database:"):
        _load_cicids2017_dataset()


def _load_cicids2017_dataset():
    status = st.status("Loading CICIDS2017 dataset...", expanded=True)
    with status:
        def _report_progress(msg: str):
            st.write(msg)

        try:
            df, report = _cached_load_and_clean_cicids2017(_progress_callback=_report_progress)
        except FileNotFoundError as e:
            status.update(label="Failed to load CICIDS2017 dataset", state="error")
            st.error(str(e))
            return

        status.update(
            label=f"CICIDS2017 dataset ready: {len(df):,} rows, {df.shape[1]} columns",
            state="complete",
        )

    st.session_state["td_cicids_report"] = report
    _set_active_dataset(df, CICIDS2017_DATASET_NAME)
    st.rerun()


def _render_cicids2017_report(report: dict):
    with st.expander("CICIDS2017 data-quality adjustments (nothing hidden)", expanded=True):
        st.caption(
            f"Rows before cleaning: {report['rows_before']:,} -> after: "
            f"{report['rows_after']:,} (cleaning only clips values or drops "
            f"zero-variance columns - it never removes rows)."
        )
        if report["dropped_zero_variance_columns"]:
            st.write(
                f"Dropped {len(report['dropped_zero_variance_columns'])} zero-variance "
                f"column(s) (no predictive value): "
                + ", ".join(report["dropped_zero_variance_columns"])
            )
        if report["negative_values_clipped"]:
            for col, n in report["negative_values_clipped"].items():
                st.write(f"Clipped {n:,} physically-impossible negative value(s) in **{col}** to 0.")
        if report["label_encoding_fixed"]:
            st.write(
                "Fixed a label-encoding artifact in the 'Web Attack' categories "
                "(a corrupted separator character was normalized to a hyphen)."
            )
        if report["rare_classes"]:
            st.warning(
                "Severe class imbalance - these classes have fewer than "
                f"{RARE_CLASS_THRESHOLD} samples, so their precision/recall/F1 in the "
                "evaluation below will be statistically unreliable. They are kept in "
                "training and detection, not removed: "
                + ", ".join(f"{k} ({v})" for k, v in report["rare_classes"].items())
            )


# ---------------------------------------------------------------
# Target column selection + dataset information
# ---------------------------------------------------------------

def _render_label_column_picker(df: pd.DataFrame):
    """Automatic detection (case-insensitive match against common
    names: Label, class, attack_type, Attack Type, target, ...) is
    the default - the dropdown only exists so the analyst can override
    it when detection is uncertain or wrong for a dataset that uses an
    unusual column name. The override is remembered per dataset name
    so switching datasets doesn't carry a stale choice over."""
    auto_detected = detect_label_column(df)
    dataset_name = st.session_state.get("td_dataset_name", "")
    override_key = f"td_label_override_{dataset_name}"

    options = ["Auto-detect" + (f" ({auto_detected})" if auto_detected else " (none found)")] + list(df.columns)
    chosen = st.selectbox(
        "Target column", options,
        index=0,
        key=override_key,
        help="Leave on auto-detect unless it picked the wrong column (or none at all).",
    )
    return auto_detected if chosen.startswith("Auto-detect") else chosen


def _cached_dataset_info(df: pd.DataFrame, label_col):
    """get_dataset_info() scans the WHOLE uploaded dataframe (isna(),
    duplicated(), identifier-name detection) - for a large upload
    (CICIDS2017-sized files run into the hundreds of thousands of rows)
    that's real work, and both _render_dataset_info() and
    _render_pipeline_controls() call it, unconditionally, on EVERY
    single script rerun of this page - any button/widget interaction
    anywhere on the page, not just right after upload, since Streamlit
    reruns the whole page top to bottom on every interaction. Without
    caching, that's this full-dataframe scan running TWICE per rerun,
    on every single click, for as long as this dataset stays loaded -
    exactly the "feels stuck loading" cost _load_models_for_slug()
    above was already built to avoid for model loading, just never
    applied here too. Cached by label_col alone: _set_active_dataset()
    already clears this same slot whenever the dataset itself changes,
    so a genuinely new upload never sees a stale cached value."""
    cached = st.session_state.get("td_dataset_info")
    if cached is not None and cached[0] == label_col:
        return cached[1]
    info = get_dataset_info(df, label_col)
    st.session_state["td_dataset_info"] = (label_col, info)
    return info


def _render_dataset_info(df: pd.DataFrame, label_col):
    st.subheader("Dataset Information", icon=":material/table_chart:")
    info = _cached_dataset_info(df, label_col)

    # Blue/cyan/teal rotation only (per request) - colour is purely
    # decorative grouping, every value is still the exact real
    # statistic from ml/preprocessing.py:get_dataset_info().
    stats_row1 = [
        ("td_stat_blue", "Rows", f"{info['rows']:,}"),
        ("td_stat_cyan", "Columns", f"{info['columns']:,}"),
        ("td_stat_teal", "Numeric Features", f"{info['numeric_feature_count']:,}"),
        ("td_stat_blue", "Categorical Features", f"{info['categorical_feature_count']:,}"),
    ]
    stats_row2 = [
        ("td_stat_cyan", "Missing Values", f"{info['missing_total']:,}"),
        ("td_stat_teal", "Duplicate Rows", f"{info['duplicate_rows']:,}"),
        ("td_stat_blue", "Labelled", "Yes" if info["is_labeled"] else "No"),
        ("td_stat_cyan", "Classes", f"{len(info['class_distribution']):,}" if info["class_distribution"] else "—"),
    ]
    for row in (stats_row1, stats_row2):
        cols = st.columns(4)
        for col, (card_key, label, value) in zip(cols, row):
            # Each card needs its OWN unique key= (Streamlit requires
            # unique keys within a page) - utils/theme.py matches these
            # by class SUBSTRING (same convention as page_panel_blue/
            # purple elsewhere in this file), so every "td_stat_blue_*"
            # card still gets the identical blue styling regardless of
            # its unique suffix.
            slug = label.lower().replace(" ", "_")
            with col, st.container(key=f"{card_key}_{slug}", border=True):
                st.metric(label, value)

    if info["label_column"]:
        st.caption(f"Target column: **{info['label_column']}**")
        st.caption(f"Class distribution: {info['class_distribution']}")
    else:
        st.warning(
            "No label column detected and none selected above - this dataset "
            "will be treated as unlabeled (Isolation Forest anomaly detection "
            "only; Random Forest/XGBoost need a target column)."
        )

    if info["identifier_like_columns"]:
        st.caption(
            ":material/info: These column names look like identifiers, not "
            "predictive features (not removed automatically - review and drop "
            "them yourself with Preprocess Data's column choices if appropriate): "
            + ", ".join(info["identifier_like_columns"])
        )

    with st.expander("Preview first 10 rows", icon=":material/table_rows:", key="td_expander_preview"):
        st.dataframe(df.head(10), width="stretch")

    if info["missing_by_column"]:
        with st.expander("Missing values by column", icon=":material/report:", key="td_expander_missing"):
            st.write(info["missing_by_column"])


# ---------------------------------------------------------------
# Validate / Preprocess / Train
# ---------------------------------------------------------------

def _render_pipeline_controls(df: pd.DataFrame, label_col):
    info = _cached_dataset_info(df, label_col)
    if info["identifier_like_columns"]:
        exclude_cols = st.multiselect(
            "Exclude identifier/non-predictive columns before preprocessing "
            "(pre-selected from name-based detection above - remove any you "
            "disagree with, or add more)",
            options=[c for c in df.columns if c != label_col],
            default=info["identifier_like_columns"],
            key=f"td_exclude_{st.session_state.get('td_dataset_name', '')}",
        )
    else:
        exclude_cols = []

    col1, col2, col3 = st.columns(3)
    with col1, st.container(key="td_action_validate"):
        validate_clicked = st.button("Validate Dataset", width="stretch", icon=":material/rule:")
    with col2, st.container(key="td_action_preprocess"):
        preprocess_clicked = st.button("Preprocess Data", width="stretch", icon=":material/cleaning_services:")
    with col3, st.container(key="td_action_train"):
        train_clicked = st.button(
            "Train Models", width="stretch", icon=":material/model_training:",
            disabled=st.session_state.get("td_train_running", False),
        )

    if validate_clicked:
        st.session_state["td_validation"] = validate_dataset(df, label_col)

    if "td_validation" in st.session_state:
        is_valid, messages = st.session_state["td_validation"]
        box = st.success if is_valid else st.warning
        for m in messages:
            box(m)

    if preprocess_clicked:
        with st.spinner(f"Preprocessing {len(df):,} rows..."):
            try:
                st.session_state["td_bundle"] = preprocess_dataset(df, label_col, exclude_cols)
            except Exception as e:
                st.error(f"Preprocessing failed: {e}")
            else:
                st.success("Preprocessing Successful.")

    bundle = st.session_state.get("td_bundle")
    if bundle is not None:
        _render_preprocessing_summary(bundle)

    if train_clicked and _check_ml_cooldown():
        st.session_state["td_train_running"] = True
        try:
            _handle_train(bundle, st.session_state.get("td_dataset_name", "uploaded.csv"))
        finally:
            st.session_state["td_train_running"] = False


def _render_preprocessing_summary(bundle: dict):
    report = bundle["sanitization_report"]
    any_corrections = any(report.values())

    with st.expander("Preprocessing summary", expanded=False):
        st.write(f"Numeric features: {len(bundle['numeric_cols'])}  \n"
                 f"Categorical features: {len(bundle['categorical_cols'])}")
        if bundle["manually_excluded_columns"]:
            st.write(f"Manually excluded columns: {bundle['manually_excluded_columns']}")
        if bundle["dropped_columns"]:
            st.write(f"Columns dropped (>50% missing): {bundle['dropped_columns']}")
        if bundle["duplicate_rows"]:
            st.caption(
                f":material/content_copy: {bundle['duplicate_rows']:,} duplicate row(s) "
                f"detected in the original upload - kept as-is, not removed."
            )

        st.markdown("**Invalid-value corrections made (reported, nothing silent):**")
        if not any_corrections:
            st.caption("No infinities, oversized values, or unparseable numeric "
                       "strings were found - the data was already clean.")
        else:
            if report["infinities_replaced"]:
                st.write("Infinite values replaced with missing (then imputed): "
                         + ", ".join(f"{c} ({n:,})" for c, n in report["infinities_replaced"].items()))
            if report["values_clipped"]:
                st.write("Values beyond a safe numerical range were clipped to it "
                         "(genuinely large but ordinary traffic values were NOT touched): "
                         + ", ".join(f"{c} ({n:,})" for c, n in report["values_clipped"].items()))
            if report["invalid_strings_to_nan"]:
                st.write("Non-numeric text in a numeric column treated as missing: "
                         + ", ".join(f"{c} ({n:,})" for c, n in report["invalid_strings_to_nan"].items()))
            if report["all_missing_columns"]:
                st.warning(
                    "These columns had NO usable values at all (every value was "
                    "missing/invalid) - they will contribute no signal to the model: "
                    + ", ".join(report["all_missing_columns"])
                )

        st.dataframe(bundle["X"].head(5), width="stretch")


def _check_ml_cooldown() -> bool:
    """Per-user server-side cooldown shared by Train Models, Run AI
    Detection, and Train New Model & Run Detection - the disable-while-
    running button guards only stop a double-click DURING one run; this
    is what stops the same user from re-triggering another expensive
    training/bulk-detection run back-to-back immediately after one
    finishes, against the shared TiDB backend. Same mechanism as
    url_scanner.py's own cooldown (auth/rate_limit.py), just a longer
    window via config.ML_ACTION_COOLDOWN_SECONDS."""
    user_id = st.session_state.get("user_id")
    allowed, retry_after = check_and_bump_cooldown(
        "ML_ACTION_USER", str(user_id), config.ML_ACTION_COOLDOWN_SECONDS
    )
    if not allowed:
        st.warning(f"Please wait {retry_after} second(s) before starting another training/detection run.")
    return allowed


def _handle_train(bundle, dataset_name):
    if bundle is None:
        st.warning("Preprocess the data before training.")
        return
    if bundle["y_raw"] is None:
        st.warning(
            "This dataset has no detected label column, so supervised "
            "models (Random Forest, XGBoost) cannot be trained on it. "
            "Upload a labeled dataset to train classifiers."
        )
        return

    status = st.status(
        f"Training on {len(bundle['X']):,} rows - this can take a while for large datasets...",
        expanded=True,
    )
    with status:
        def _report_progress(msg: str):
            st.write(msg)

        try:
            result = train_models(
                bundle["X"], bundle["y_raw"], bundle["numeric_cols"], bundle["categorical_cols"],
                progress_callback=_report_progress,
            )
            st.write(f"Saving to models/{dataset_name!r}'s own slot...")
            slug = save_models(result, dataset_name)
        except ValueError as e:
            status.update(label="Training failed", state="error")
            st.error(str(e))
            return
        except Exception as e:
            status.update(label="Training failed", state="error")
            st.error(f"Training failed: {e}")
            return
        status.update(label="Training complete", state="complete")

    st.success(
        f"Training complete on {result['train_rows']:,} training / "
        f"{result['test_rows']:,} test rows (split BEFORE any imputer/scaler/"
        f"encoder was fit, to avoid test-set leakage). Best model: "
        f"**{result['best_model']}** (F1 = {result['metrics'][result['best_model']]['f1']}%). "
        f"Saved to its own slot (`models/{slug}/`) and set as the active model - "
        f"this never touches any other dataset's previously trained model."
    )
    log_action(
        st.session_state.get("username", "?"), "MODEL_TRAINED", "THREAT_DETECTION",
        f"Trained on '{dataset_name}' (slot '{slug}'). Best model: {result['best_model']}.",
    )


# ---------------------------------------------------------------
# Model evaluation (always visible, independent of a fresh upload)
# ---------------------------------------------------------------

# Fixed per-model identity (colour comes from utils/theme.py's
# .st-key-model_panel_rf/xgb; everything else here is just labelling).
_MODEL_THEMES = {
    "random_forest": {
        "key": "model_panel_rf", "label": "Random Forest", "icon": ":material/account_tree:",
        "illustration": "network_nodes", "illustration_color": "#0EA5E9",
    },
    "xgboost": {
        "key": "model_panel_xgb", "label": "XGBoost", "icon": ":material/bolt:",
        "illustration": "analytics_chart", "illustration_color": "#8B5CF6",
    },
}

# Different-but-coordinated identity colour per metric TYPE (applies
# regardless of model) - overridden to green below ONLY when that
# metric's REAL measured value is already strong, never the reverse.
_METRIC_ACCENTS = {
    "accuracy": ("Accuracy", "#22D3EE"),
    "precision": ("Precision", "#3B82F6"),
    "recall": ("Recall", "#8B5CF6"),
    "f1": ("F1 Score", "#A855F7"),
}
_STRONG_RESULT_THRESHOLD = 90  # % - at/above this, the card is coloured green/cyan


def _render_model_slot_picker():
    """Only shown once a second dataset has actually been trained -
    each trained dataset gets its OWN slot (ml/train_model.py never
    overwrites a different dataset's model), so switching here just
    changes which already-trained slot is active; it never retrains
    or deletes anything."""
    slots = list_model_slots()
    if len(slots) < 2:
        return
    active = get_active_slug()
    labels = [f"{s['dataset_name']} (trained {s['trained_at']})" for s in slots]
    slugs = [s["slug"] for s in slots]
    current_index = slugs.index(active) if active in slugs else 0
    chosen_index = st.selectbox(
        "Active model (for the evaluation metrics below - Automatic Threat "
        "Detection independently matches its own model per dataset, see that "
        "section further down)",
        range(len(slots)), index=current_index, format_func=lambda i: labels[i],
        key="td_model_slot_picker",
    )
    if slugs[chosen_index] != active:
        set_active_slug(slugs[chosen_index])
        st.rerun()


def _render_model_evaluation():
    _render_model_slot_picker()
    loaded = _load_models_for_slug(None)
    if loaded is None:
        st.info("Model has not been trained yet.")
        return

    _, _, _, meta = loaded
    st.caption(
        f"Trained on **{meta['dataset_name']}** at {meta['trained_at']}. "
        f"Best model in use for detection: **{meta['best_model']}**."
    )

    panel_cols = st.columns(2)
    for col, model_key in zip(panel_cols, ["random_forest", "xgboost"]):
        theme = _MODEL_THEMES[model_key]
        m = meta["metrics"][model_key]
        is_best = model_key == meta["best_model"]
        with col, st.container(key=theme["key"], border=True):
            st.markdown(
                _illustration(theme["illustration"], color=theme["illustration_color"],
                               width="90px", height="75px", opacity=0.9),
                unsafe_allow_html=True,
            )
            st.markdown(
                f"#### {theme['icon']} {theme['label']}"
                + (" &nbsp; :orange[:material/military_tech:] **BEST MODEL**" if is_best else "")
            )
            st.markdown(_metric_grid_html(model_key, m), unsafe_allow_html=True)
            expander_key = f"td_cm_expander_{model_key}"
            with st.expander("Confusion Matrix", icon=":material/grid_on:", key=expander_key):
                # Only builds the Plotly heatmap when actually expanded -
                # an expander's body still executes even while collapsed
                # (Streamlit renders it, just hides it), so without this
                # check both models' heatmaps were recomputed on EVERY
                # single rerun of this page (every widget click anywhere
                # on the page), never just when someone opens them.
                if st.session_state.get(expander_key):
                    _render_confusion_matrix_heatmap(m["confusion_matrix"], m["class_names"], key=f"cm_{model_key}")


def _metric_grid_html(model_key: str, m: dict) -> str:
    """ONE self-contained HTML block (a plain CSS grid, no nested
    st.columns()/st.container() at all) for the 4 metric tiles.

    A nested st.columns(2) row here - one for Accuracy/Precision, one
    for Recall/F1 - was itself picking up the app-wide default "card"
    box that st.container(border=True) elements get (see theme.py's
    bare [data-testid="stLayoutWrapper"] rule), which stacked a THIRD
    box (the row) around a FOURTH box (the tile) inside the model
    card's own border/background - exactly the "boxes inside boxes"
    look reported, and immune to simply removing the tile's own
    border/shadow since the row itself still picked up the box.
    Raw HTML has no such layout-engine side effects: every tag opened
    here is closed in the same string, so the model card's one border
    is the only outline - these 4 cells are just a light background
    wash, exactly like the proven-working compliance cards elsewhere
    in this app (see utils/compliance_ui.py)."""
    tile_bg = "rgba(14, 165, 233, 0.14)" if model_key == "random_forest" else "rgba(139, 92, 246, 0.14)"
    cells = ""
    for metric_name, (label, base_accent) in _METRIC_ACCENTS.items():
        value = m[metric_name]
        accent = "#22C55E" if value >= _STRONG_RESULT_THRESHOLD else base_accent
        cells += (
            f'<div style="background:{tile_bg}; border-radius:10px; padding:12px 14px;">'
            f'<div style="color:#475569; font-size:0.8rem; font-weight:600;">{label}</div>'
            f'<div style="color:{accent}; font-size:1.5rem; font-weight:700; margin-top:0.15rem;">{value}%</div>'
            "</div>"
        )
    return (
        '<div style="display:grid; grid-template-columns:1fr 1fr; gap:0.6rem; '
        f'margin:0.5rem 0 0.75rem;">{cells}</div>'
    )


def _render_confusion_matrix_heatmap(cm: list, class_names: list, key: str):
    """Real confusion-matrix values only - cm/class_names come straight
    from ml/evaluation.py's sklearn-computed output stored in
    models/model_meta.json; nothing here invents or recomputes a
    number. The diagonal (correct predictions) is outlined in green -
    a structural fact about ANY confusion matrix (diagonal = actual
    matches predicted), not a derived/invented value."""
    n = len(class_names)
    fig = go.Figure(data=go.Heatmap(
        z=cm,
        x=[f"Pred: {c}" for c in class_names],
        y=[f"Actual: {c}" for c in class_names],
        colorscale="Blues",
        text=cm,
        texttemplate="%{text}",
        textfont={"size": 11, "color": "#0F172A"},
        colorbar=dict(title="Count"),
        hovertemplate="Actual: %{y}<br>Predicted: %{x}<br>Count: %{z}<extra></extra>",
    ))
    fig.update_layout(
        shapes=[
            dict(
                type="rect", x0=i - 0.5, x1=i + 0.5, y0=i - 0.5, y1=i + 0.5,
                line=dict(color="#22C55E", width=3), fillcolor="rgba(0,0,0,0)",
            )
            for i in range(n)
        ],
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#0F172A"),
        yaxis=dict(autorange="reversed"),
        height=max(340, 36 * n),
    )
    st.caption(":material/check_circle: Green outline = correct predictions (diagonal). Everything else is a misclassification.")
    st.plotly_chart(fig, width="stretch", key=key)


# ---------------------------------------------------------------
# Automatic detection
# ---------------------------------------------------------------

def _render_detection_section(df):
    with st.container(key="detection_panel", border=True):
        st.markdown(
            _illustration("server_shield", width="140px", height="85px", opacity=0.9),
            unsafe_allow_html=True,
        )

        if df is None:
            st.info(
                "Upload a CSV, or load the CICIDS2017 dataset, above to run "
                "detection with a matching trained model."
            )
            return

        # Independent per-dataset model routing - computed once per
        # render by _sync_model_match_for_dataset() (called earlier in
        # render_threat_detection_page(), before Model Evaluation),
        # never a direct compatibility check against "the active
        # model": this dataset was already checked against EVERY
        # trained slot, and this is whichever one actually fit (or
        # None, if nothing did).
        matches = st.session_state.get("td_model_match") or {"compatible": None, "closest": None}
        compatible = matches["compatible"]
        label_col = detect_label_column(df)

        if compatible is None:
            _render_incompatible_schema_fallback(df, label_col, matches["closest"])
            results = st.session_state.get("td_detection_results")
            if results is not None:
                _render_detection_results(results)
            return

        loaded = _load_models_for_slug(compatible["slug"])
        if loaded is None:
            st.info("Model has not been trained yet.")
            return

        _, _, artifacts, meta = loaded
        _render_compatibility_summary(compatible["_compat"], meta)

        # Runs automatically, exactly ONCE per distinct uploaded dataset
        # (td_auto_attempted_for is reset by _set_active_dataset() the
        # moment a NEW dataset replaces this one) - "Automatic Threat
        # Detection" no longer needs a manual click on the happy path.
        # "Re-run Detection" below stays available for a deliberate
        # manual re-run, gated by the same cooldown a repeated click
        # should go through.
        dataset_name = st.session_state.get("td_dataset_name")
        if st.session_state.get("td_auto_attempted_for") != dataset_name:
            st.session_state["td_auto_attempted_for"] = dataset_name
            st.success("Found a matching existing model - running detection automatically...")
            with st.spinner(f"Running AI detection on {len(df):,} record(s)..."):
                _run_detection(df, loaded)
        else:
            st.success("Using the existing model matched to this dataset.")

        results = st.session_state.get("td_detection_results")
        if results is not None:
            _render_detection_results(results)

        if st.button(
            "Re-run Detection", icon=":material/refresh:", width="stretch",
            disabled=st.session_state.get("td_detect_running", False), key="td_rerun_detect_btn",
        ) and _check_ml_cooldown():
            st.session_state["td_detect_running"] = True
            try:
                with st.spinner(f"Running AI detection on {len(df):,} record(s)..."):
                    _run_detection(df, loaded)
            finally:
                st.session_state["td_detect_running"] = False


def _render_incompatible_schema_fallback(df: pd.DataFrame, label_col, closest_match: dict | None):
    """What happens when NO existing trained model's schema fits this
    dataset (every slot was checked independently - see
    find_model_slot_matches()) - a real, working alternative instead
    of a dead end. `closest_match`, if given, is the single slot with
    the highest column-overlap RATIO against this dataset, purely for
    explaining why nothing auto-matched - it is NEVER loaded or used
    to run detection; a non-compatible model is never used to force a
    prediction.

    If this dataset has a usable label column (>= 2 classes),
    AUTOMATICALLY trains a NEW model on its own schema - reusing the
    EXACT same preprocess_dataset()/train_models()/save_models()
    pipeline the manual "Train Models" button above already uses
    (Workflow B) - and runs detection with it immediately, with no
    click required (every upload should always result in a trained
    model and a detection run, not a dead end requiring a click the
    analyst has to know to make). Runs exactly ONCE per distinct
    uploaded dataset (td_auto_attempted_for, reset by
    _set_active_dataset() the moment a different dataset is loaded) -
    never silently retrains again on an unrelated rerun of this page.
    Without a usable label column, explains why automatic training
    isn't possible rather than attempting it and failing - a hard ML
    constraint (no labels, no supervised model), not a UX choice."""
    if closest_match is not None:
        missing = closest_match["_compat"]["missing"]
        shown = ", ".join(missing[:12]) + ("..." if len(missing) > 12 else "")
        st.caption(
            ":material/info: No existing trained model's schema fully matches "
            f"this dataset's columns. The closest existing model (trained on "
            f"**{closest_match['dataset_name']}**) is still missing: {shown}"
        )
    else:
        st.caption(":material/info: No trained model exists yet for any dataset.")

    if label_col is None:
        st.warning(
            "This dataset has no detected target/label column, so a new "
            "supervised model can't be trained on it either. Automatic "
            "detection needs one of: a dataset whose features match an "
            "already-trained model (see the compatibility summary above), or "
            "a labeled dataset so a new model can be trained on its own schema."
        )
        return

    n_classes = int(df[label_col].nunique(dropna=True))
    if n_classes < 2:
        st.warning(
            f"This dataset's label column ('{label_col}') only has {n_classes} "
            "distinct value(s) - at least 2 are needed to train a classifier, "
            "so a new model can't be trained on it automatically."
        )
        return

    dataset_name = st.session_state.get("td_dataset_name")
    already_attempted = st.session_state.get("td_auto_attempted_for") == dataset_name

    if not already_attempted:
        st.info(
            f"This dataset has a usable label column (**{label_col}**, {n_classes} "
            "classes) but no existing trained model's schema fits it - "
            "training a new model on its own schema automatically and running "
            "detection with it right away. Every other dataset's own trained "
            "model is left untouched unless this succeeds."
        )
        st.session_state["td_auto_attempted_for"] = dataset_name
        _train_and_detect_for_incompatible_schema(df, label_col)
        return

    if st.session_state.get("td_detection_results") is not None:
        return  # already succeeded - its own st.success() already ran once

    # The actual failure reason was only ever shown during the ORIGINAL
    # run that hit it - a plain st.error() inside a function call is not
    # preserved across the rerun that got us here, so without this the
    # reader has no way to tell why it failed. _train_and_detect_for_
    # incompatible_schema() persists the real reason to this key right
    # before every one of its own early returns.
    reason = st.session_state.get("td_auto_train_error")
    st.warning(
        f"Automatic training on **{dataset_name}** didn't complete successfully"
        + (f": {reason}" if reason else " (no error detail was recorded - this "
           "itself is unexpected; please retry and report this if it keeps happening).")
    )
    if st.button(
        "Retry Training & Detection", icon=":material/model_training:", width="stretch",
        key="td_retry_auto_train", disabled=st.session_state.get("td_auto_train_running", False),
    ) and _check_ml_cooldown():
        st.session_state["td_auto_train_running"] = True
        try:
            _train_and_detect_for_incompatible_schema(df, label_col)
        finally:
            st.session_state["td_auto_train_running"] = False


def _train_and_detect_for_incompatible_schema(df: pd.DataFrame, label_col):
    dataset_name = st.session_state.get("td_dataset_name", "uploaded.csv")
    # Cleared on every attempt, then re-set at whichever return point
    # this run actually hits (or left cleared, on success) - a plain
    # st.error()/st.warning() call here is only ever visible during
    # THIS run; without persisting the real reason, a later rerun (the
    # "didn't complete successfully" fallback above) has no way to show
    # WHY it failed, which is exactly what made that message useless.
    st.session_state.pop("td_auto_train_error", None)

    with timed("auto_train_and_detect: total"):
        # Stage 1/6: Validating Dataset - the same rule-based checks the
        # manual "Validate Dataset" button runs (ml/preprocessing.py's
        # validate_dataset()), just run automatically here so a clearly
        # untrainable upload (too few rows, no usable label, a single
        # class) is rejected with a real reason before any model
        # actually starts training on it.
        with timed("auto_train_and_detect: validate_dataset"):
            is_valid, messages = validate_dataset(df, label_col)
        if not is_valid:
            for m in messages:
                st.error(m)
            st.session_state["td_auto_train_error"] = " / ".join(messages)
            return

        identifier_cols = detect_identifier_columns(df, label_col)

        status = st.status("Validating dataset...", expanded=True)
        with status:
            def _report_progress(msg: str):
                st.write(msg)

            for m in messages:
                st.caption(m)

            # Stage 2/6: Preparing Features
            status.update(label="Preparing features...")
            try:
                with timed("auto_train_and_detect: preprocess_dataset"):
                    bundle = preprocess_dataset(df, label_col, identifier_cols)
                if bundle["y_raw"] is None:
                    status.update(label="Training failed", state="error")
                    st.error("No usable label column remained after preprocessing.")
                    st.session_state["td_auto_train_error"] = (
                        "No usable label column remained after preprocessing."
                    )
                    return
                st.write(
                    f"Prepared {len(bundle['X']):,} row(s) x {bundle['X'].shape[1]} "
                    f"feature(s) ({len(bundle['numeric_cols'])} numeric, "
                    f"{len(bundle['categorical_cols'])} categorical)."
                )

                # Stage 3/6: Training Machine Learning Model (stage 4,
                # Evaluating Model Performance, happens inside the same
                # train_models() call - see ml/train_model.py, which
                # fits Random Forest/XGBoost/Isolation Forest THEN
                # scores the two classifiers on the held-out test
                # split in one real, measured pass; splitting that
                # into two separate UI stages here would mean either a
                # second pass over the data or a fake intermediate
                # label, neither of which reflects real work).
                status.update(label="Training machine learning model...")
                with timed("auto_train_and_detect: train_models"):
                    result = train_models(
                        bundle["X"], bundle["y_raw"], bundle["numeric_cols"], bundle["categorical_cols"],
                        progress_callback=_report_progress,
                    )
                status.update(label="Evaluating model performance...")
                st.write(
                    f"Best model: {result['best_model']} - F1 = "
                    f"{result['metrics'][result['best_model']]['f1']}% on its own held-out test split."
                )
                st.write(f"Saving to models/{dataset_name!r}'s own slot and activating it...")
                slug = save_models(result, dataset_name)
            except ValueError as e:
                status.update(label="Training failed", state="error")
                st.error(str(e))
                st.session_state["td_auto_train_error"] = str(e)
                return
            except Exception as e:
                status.update(label="Training failed", state="error")
                st.error(f"Training failed: {e}")
                st.session_state["td_auto_train_error"] = f"Training failed: {e}"
                return

            # Stage 5/6: Running Threat Detection. Reuses bundle["X"]
            # (this exact dataset's own already-sanitized, already
            # column-selected feature matrix) and the preprocessor
            # train_models() just fit, via run_detection_on_prepared()
            # (ml/prediction.py) - skips re-sanitizing/re-selecting
            # columns over the same rows a second time, which is what
            # the generic run_detection() path would otherwise do.
            status.update(label="Running threat detection...")
            loaded = _load_models_for_slug(slug)
            if loaded is None:
                status.update(label="Training succeeded but the new model could not be reloaded", state="error")
                st.error("Training succeeded, but the newly saved model could not be reloaded for detection.")
                st.session_state["td_auto_train_error"] = (
                    "Training succeeded, but the newly saved model could not be "
                    "reloaded for detection."
                )
                return

            # Stage 6/6: Generating Detection Results (scoring, risk/
            # severity, DB persistence, alerts - all inside _run_detection()).
            with timed("auto_train_and_detect: run_detection"):
                _run_detection(df, loaded, prepared=(bundle["X"], result["preprocessor"]))
            if st.session_state.get("td_detection_results") is None:
                # _run_detection() already showed its own specific
                # st.error() above (it never raises) - that message
                # doesn't survive the rerun either, so record that
                # training succeeded but detection itself didn't.
                st.session_state["td_auto_train_error"] = (
                    "The new model trained successfully, but running detection "
                    "with it failed (see the error shown when it ran)."
                )
            status.update(label="Training and detection complete", state="complete")

    st.success(
        f"Trained a new model on **{dataset_name}** (best model: "
        f"**{result['best_model']}**, F1 = {result['metrics'][result['best_model']]['f1']}% on its own "
        f"held-out test split) and ran detection with it. This dataset's model is now the active model "
        f"(`models/{slug}/`) - any other dataset's previously trained model is untouched."
    )
    log_action(
        st.session_state.get("username", "?"), "MODEL_TRAINED", "THREAT_DETECTION",
        f"Auto-trained on '{dataset_name}' (slot '{slug}') after a schema mismatch, then ran "
        f"detection immediately. Best model: {result['best_model']}.",
    )


def _render_compatibility_summary(compat: dict, meta: dict):
    """Only ever called once an independently-matched compatible model
    has already been found (see find_model_slot_matches() /
    _render_detection_section()) - this dataset was checked against
    EVERY trained model, not defaulted to whichever one happened to
    be active, and `meta["dataset_name"]` is the one that actually
    fit. compat["missing"] is therefore always empty here by
    construction (that's the definition of "compatible")."""
    uploaded_name = st.session_state.get("td_dataset_name", "your upload")
    with st.expander(
        f"Schema check: {uploaded_name} vs. matched model (trained on {meta['dataset_name']})",
        expanded=False, icon=":material/compare_arrows:",
    ):
        st.caption(
            f"**{uploaded_name}** was checked independently against every "
            f"existing trained model - the one trained on "
            f"**{meta['dataset_name']}** is the one whose schema actually fits "
            "(not a default/fallback comparison)."
        )
        st.write(f"Matched features: {compat['match_count']} / {compat['expected_count']} expected")
        if compat["extra"]:
            st.caption("Additional columns in this dataset, not used by the model: "
                       + ", ".join(compat["extra"]))
        else:
            st.caption("Exact schema match.")


def _run_detection(df: pd.DataFrame, loaded, prepared: tuple | None = None):
    """`prepared`, if given, is (X_prepared, preprocessor) from a
    dataset that was JUST preprocessed for training this exact
    `loaded` model (see _train_and_detect_for_incompatible_schema) -
    runs the fast run_detection_on_prepared() path instead of
    re-sanitizing `df` from scratch via the generic run_detection()."""
    models, label_encoder, artifacts, meta = loaded
    label_col = detect_label_column(df)
    feature_df = df.drop(columns=[label_col]) if label_col else df.copy()

    try:
        if prepared is not None:
            X_prepared, preprocessor = prepared
            results_df = run_detection_on_prepared(
                X_prepared, preprocessor, models, label_encoder, meta["best_model"],
            )
        else:
            results_df = run_detection(feature_df, models, label_encoder, artifacts, meta["best_model"])
    except ValueError as e:
        st.error(str(e))
        return
    except Exception as e:
        st.error(f"Detection failed: {e}")
        return

    user_id = st.session_state.get("user_id")
    dataset_name = st.session_state.get("td_dataset_name", "uploaded.csv")
    try:
        traffic_id = insert_network_traffic(
            dataset_name=dataset_name,
            uploaded_by=user_id,
            row_count=len(df),
            column_count=df.shape[1],
            status="PROCESSED",
        )
    except Exception as e:
        st.error(
            f"Detection ran, but recording this dataset in the database failed: {e}\n\n"
            "Nothing was saved - no results were added to Recent Threats or the Dashboard. "
            "Please try again."
        )
        return

    try:
        detection_ids = insert_threat_detections_bulk(traffic_id, results_df, user_id)
    except Exception as e:
        # The traffic row above already committed on its own connection -
        # without this, a failed detections insert leaves it dangling
        # (a traffic record with zero detections attached). Clean it up
        # so a failed run never leaves inconsistent state behind.
        try:
            delete_network_traffic(traffic_id)
        except Exception:
            pass
        st.error(
            f"Detection ran, but saving the {len(results_df):,} result(s) to the database "
            f"failed: {e}\n\nNone of this run's results were saved - nothing was added to "
            "Recent Threats or the Dashboard. Please try again."
        )
        return

    malicious_count = int((results_df["prediction"] == "MALICIOUS").sum())
    log_action(
        st.session_state.get("username", "?"), "AI_DETECTION", "THREAT_DETECTION",
        f"Ran {meta['best_model']} on '{dataset_name}' "
        f"({len(results_df)} records, {malicious_count} malicious).",
    )

    alerts_created = _run_compliance_for_significant_detections(results_df, detection_ids, user_id)

    st.session_state["td_detection_results"] = results_df
    st.session_state["td_detection_ground_truth_eval"] = _compute_detection_ground_truth_eval(
        df, label_col, results_df,
    )
    st.success(
        f"Detection complete: {len(results_df)} record(s) analysed and saved. "
        f"{malicious_count} flagged MALICIOUS."
    )
    if alerts_created:
        st.warning(
            f"{alerts_created} high-risk alert(s) created - see Alerts & Incidents."
        )


def _compute_detection_ground_truth_eval(df: pd.DataFrame, label_col, results_df: pd.DataFrame):
    """If the uploaded dataset carries its own label column, compare
    THIS detection run's real predictions against those real labels -
    collapsed to binary BENIGN/MALICIOUS via the exact same
    derive_binary_label() ml/preprocessing.py already uses for
    training, so "MALICIOUS" means the same thing on both sides.
    Returns None when there's no label to compare against - never a
    fabricated metric.

    INDEPENDENT of the active model's own training-time metrics (Model
    Evaluation above, trained on a DIFFERENT split of possibly a
    DIFFERENT dataset) - this measures how well THIS run's predictions
    match THIS dataset's own labels, whichever model produced them."""
    if label_col is None or label_col not in df.columns:
        return None

    true_binary = derive_binary_label(df[label_col])
    aligned_true = true_binary.loc[results_df["record_index"]].reset_index(drop=True)
    pred = results_df["prediction"].reset_index(drop=True)
    if aligned_true.nunique() < 2:
        return None  # a single true class can't support a meaningful precision/recall

    return {
        "n": len(aligned_true),
        "accuracy": round(float(accuracy_score(aligned_true, pred)) * 100, 2),
        "precision": round(float(precision_score(
            aligned_true, pred, pos_label="MALICIOUS", average="binary", zero_division=0,
        )) * 100, 2),
        "recall": round(float(recall_score(
            aligned_true, pred, pos_label="MALICIOUS", average="binary", zero_division=0,
        )) * 100, 2),
        "f1": round(float(f1_score(
            aligned_true, pred, pos_label="MALICIOUS", average="binary", zero_division=0,
        )) * 100, 2),
    }


def _run_compliance_for_significant_detections(results_df: pd.DataFrame, detection_ids: list[int], user_id: int) -> int:
    """Evaluate compliance (Step 7) and create alerts (Step 8) for
    every HIGH/CRITICAL detection in this batch, all owned by
    `user_id`. `detection_ids[i]` is row i's REAL threat_detections.id
    (see insert_threat_detections_bulk's docstring) - fetched with a
    follow-up SELECT rather than guessed from an offset, which is
    required for correctness on TiDB (auto-increment ids aren't
    guaranteed contiguous within one bulk insert there).

    Uses process_security_events_bulk() / log_actions_bulk() - a
    constant handful of DB round trips for the WHOLE batch, rather
    than up to 3 PER significant row (compliance insert, alert
    insert+update, audit log insert) - which, against a remote
    database, is what made a detection run with thousands of
    HIGH/CRITICAL rows feel like it had hung. Every rule/threshold
    decision is identical to before; only how many round trips it
    takes to save the results has changed."""
    events = []
    for offset, row in enumerate(results_df.to_dict("records")):
        if row["severity"] not in COMPLIANCE_SEVERITY_THRESHOLD:
            continue
        detection = dict(row)
        detection["id"] = detection_ids[offset]
        events.append(build_network_event(detection, user_id))

    if not events:
        return 0

    outcomes = process_security_events_bulk(events)

    username = st.session_state.get("username", "?")
    log_entries = []
    alerts_created = 0
    for event, outcome in zip(events, outcomes):
        if outcome["alert_id"] is not None:
            alerts_created += 1
            log_entries.append((
                username, "ALERT_CREATED", "ALERTS",
                f"Alert created for detection id={event['related_detection_id']} "
                f"({event['threat_type']}, {event['severity']}, risk={event['risk_score']}).",
            ))

    log_entries.append((
        username, "COMPLIANCE_CHECK", "COMPLIANCE",
        f"Evaluated compliance rules for {len(events)} HIGH/CRITICAL "
        f"detection(s); {alerts_created} alert(s) created.",
    ))
    log_actions_bulk(log_entries)
    return alerts_created


def _render_ground_truth_eval_panel():
    """Real accuracy/precision/recall/F1 for THIS detection run against
    THIS dataset's own label column (see _compute_detection_ground_truth_eval) -
    shown only when the uploaded dataset actually had one; never
    fabricated or shown as a stand-in for the training-time metrics in
    Model Evaluation above (different data, explicitly labeled as such)."""
    eval_result = st.session_state.get("td_detection_ground_truth_eval")
    if eval_result is None:
        return
    st.markdown("**Evaluation against this dataset's own labels**")
    st.caption(
        f"This uploaded dataset included its own label column - comparing this run's "
        f"{eval_result['n']:,} real prediction(s) against those real labels (BENIGN vs "
        f"MALICIOUS). Independent of the active model's training-time metrics above."
    )
    cols = st.columns(4)
    for col, metric_name in zip(cols, ("accuracy", "precision", "recall", "f1")):
        col.metric(metric_name.capitalize(), f"{eval_result[metric_name]}%")


def _render_detection_results(results_df: pd.DataFrame):
    st.subheader("Detection Summary", icon=":material/fact_check:")

    total = len(results_df)
    malicious = int((results_df["prediction"] == "MALICIOUS").sum())
    benign = total - malicious
    critical = int((results_df["severity"] == "CRITICAL").sum())
    malicious_pct = (malicious / total * 100) if total else 0.0
    cols = st.columns(3)
    # Reusing the exact same coloured-card keys the Dashboard's KPI row
    # uses (see utils/theme.py) - blue/red/crimson - so the same number
    # means the same colour everywhere in the app, not a page-local
    # one-off palette.
    with cols[0], st.container(key="kpi_traffic"):
        st.metric("Records Analysed", f"{total:,}")
        st.caption(f"{benign:,} benign")
    with cols[1], st.container(key="kpi_threats"):
        st.metric("Malicious", f"{malicious:,}")
        st.caption(f"{malicious_pct:.1f}% of analysed records")
    with cols[2], st.container(key="kpi_critical"):
        st.metric("Critical Severity", f"{critical:,}")

    _render_ground_truth_eval_panel()

    top_risk = results_df.sort_values("risk_score", ascending=False).head(3)
    if not top_risk.empty and top_risk.iloc[0]["risk_score"] > 0:
        st.markdown("**Highest-risk detections**")
        for _, row in top_risk.iterrows():
            status_icon = ":red[:material/gpp_bad:]" if row["prediction"] == "MALICIOUS" else ":green[:material/check_circle:]"
            # SEVERITY_COLORS (utils/design_tokens.py - the single shared
            # palette) only ever has the four severities ml/risk_scoring.py
            # actually produces -
            # the grey fallback below is purely defensive, never a
            # fabricated fifth severity.
            severity = row["severity"]
            severity_color = SEVERITY_COLORS.get(severity, "#94A3B8")
            with st.container(border=True):
                st.markdown(f"{status_icon} **Status:** {row['prediction']}")
                st.write(f"Attack Type: {row['attack_type'] or 'N/A'}")
                st.write(f"Confidence: {row['confidence']}%")
                st.write(f"Risk Score: {row['risk_score']}/100")
                st.markdown(
                    f"Severity: <span style='color:{severity_color};font-weight:700;'>{severity}</span>",
                    unsafe_allow_html=True,
                )
                st.write(f"Model: {row['model_used']}")

    st.markdown("**Full detection table**")
    _DETECTION_TABLE_PREVIEW_ROWS = 500
    if len(results_df) > _DETECTION_TABLE_PREVIEW_ROWS:
        st.caption(
            f"Showing the first {_DETECTION_TABLE_PREVIEW_ROWS:,} of {len(results_df):,} "
            "record(s) - use the export buttons below for the complete set."
        )
    preview_df = results_df.head(_DETECTION_TABLE_PREVIEW_ROWS)
    st.dataframe(_detection_table_style(preview_df), width="stretch", hide_index=True)

    _render_results_export(results_df)


def _render_results_export(results_df: pd.DataFrame):
    """Download THIS run's real predictions directly - CSV/JSON/Excel.
    A full PDF across any date range already exists on the Reports
    page (utils/report_generator.py), built from the SAVED
    threat_detections rows in the database rather than this transient
    in-session DataFrame - not duplicated here."""
    st.caption("Export this run's results:")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    cols = st.columns(3)
    with cols[0]:
        st.download_button(
            "CSV", data=results_df.to_csv(index=False).encode("utf-8"),
            file_name=f"detection_results_{timestamp}.csv", mime="text/csv",
            icon=":material/download:", width="stretch", key="td_export_csv",
        )
    with cols[1]:
        st.download_button(
            "JSON", data=results_df.to_json(orient="records", indent=2).encode("utf-8"),
            file_name=f"detection_results_{timestamp}.json", mime="application/json",
            icon=":material/download:", width="stretch", key="td_export_json",
        )
    with cols[2]:
        buf = io.BytesIO()
        results_df.to_excel(buf, index=False, engine="openpyxl")
        st.download_button(
            "Excel", data=buf.getvalue(),
            file_name=f"detection_results_{timestamp}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            icon=":material/download:", width="stretch", key="td_export_xlsx",
        )


_PREDICTION_COLORS = {"MALICIOUS": "#DC2626", "BENIGN": "#16A34A"}


def _detection_table_style(df: pd.DataFrame):
    """Colour-code the Prediction and Severity columns (a real pandas
    Styler, honored by st.dataframe) so BENIGN/MALICIOUS and each
    severity level are visually distinct at a glance in the full
    table, not just in the "Highest-risk detections" cards above -
    same colour maps used there and on the Dashboard, never a
    page-local one-off palette."""
    def _pred_color(val):
        c = _PREDICTION_COLORS.get(val)
        return f"background-color: {c}22; color: {c}; font-weight: 700;" if c else ""

    def _sev_color(val):
        c = SEVERITY_COLORS.get(val)
        return f"background-color: {c}22; color: {c}; font-weight: 700;" if c else ""

    styler = df.style
    if "prediction" in df.columns:
        styler = styler.map(_pred_color, subset=["prediction"])
    if "severity" in df.columns:
        styler = styler.map(_sev_color, subset=["severity"])
    return styler
