"""
Data-access functions ("model" layer), grouped by table.

Keeping every raw SQL statement here - instead of scattered inline
across Streamlit pages - means each page reuses the same,
already-parameterised query instead of writing SQL by hand. All
queries use %s placeholders (never f-string/format-built SQL), which
is what prevents SQL injection.

MULTI-TENANT DATA ISOLATION: every function that reads or writes
user-generated data (network_traffic, threat_detections,
url_scan_results, compliance_results, alerts) takes a mandatory
`user_id` (or `username` for audit_logs, which has no user_id column)
parameter and filters/stamps every row by it - there is deliberately
NO way to call these functions without specifying whose data you want,
so a page can't accidentally leak another user's records by forgetting
a filter. `users` (the identity table) and `compliance_rules` (the
static, shared rule-definition catalog - not user data) are the only
tables without per-user scoping, by design.

Functions are grouped by table, in the order each table was brought
online: users, network_traffic, threat_detections, url_scan_results,
compliance_rules/compliance_results, alerts, audit_logs, reports.
"""
import math
import uuid

import streamlit as st

from database.connection import get_connection
from utils.timezone import now_myt

# Every read-only aggregate/list query below is wrapped in
# st.cache_data(ttl=CACHE_TTL_SECONDS). Streamlit reruns this ENTIRE
# script on every single widget interaction anywhere on a page - a
# dashboard with 9 of these queries was re-querying MySQL 9 times for
# every unrelated click (toggling an expander, switching a tab) before
# this change, which is what made the whole app feel slow/laggy on
# every interaction, not just real navigation. A short TTL means
# repeat renders within that window are served from memory instead of
# round-tripping to MySQL, while still refreshing automatically soon
# after. Each write function below that can make one of these results
# stale calls that getter's own `.clear()` right after commit, so a
# user never has to wait out the TTL to see their own just-completed
# action (upload, scan, alert) reflected - invalidation is immediate,
# the TTL only bounds staleness from OTHER causes (e.g. another
# browser tab/session writing data).
CACHE_TTL_SECONDS = 15


def _sql_null_safe(value):
    """Convert a pandas/numpy NaN to a real Python None.

    ml/prediction.py sets attack_type=None for BENIGN rows. Once that
    column sits in a DataFrame alongside string attack types for
    MALICIOUS rows, pandas silently represents the None entries as a
    float NaN instead - and mysql-connector's C extension renders a
    NaN parameter as the bare unquoted token `nan` in the query rather
    than binding it, which MySQL then rejects as an unknown column
    name. Any mixed BENIGN+MALICIOUS batch hits this, so every field
    coming from a DataFrame that might carry a NaN needs this guard,
    not just attack_type."""
    if isinstance(value, float) and math.isnan(value):
        return None
    return value


# ---------------------------------------------------------------
# users (the identity table itself - no ownership scoping applies)
# ---------------------------------------------------------------

def get_user_by_username(username: str):
    """Return the user row (as a dict) matching `username`, or None
    if no such user exists."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, email, password_hash, role, auth_provider, full_name, is_active "
            "FROM users WHERE username = %s",
            (username,),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def get_user_by_email(email: str):
    """Return the user row (as a dict) matching `email`, or None if no
    such account exists. Used for the manual-signup duplicate-email
    check and to look up an existing account on Google login. Legacy
    accounts created before email login existed (e.g. the original
    'admin' account) have email=NULL and will never match here - they
    still log in fine via get_user_by_username()."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, email, password_hash, role, auth_provider, full_name, is_active "
            "FROM users WHERE email = %s",
            (email,),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def get_user_by_id(user_id: int):
    """Return the user row (as a dict) matching `user_id`, or None.
    Used by the Settings page's 'My Account' section (available to
    every role) to show the current user's own profile."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, email, role, auth_provider, full_name, is_active, "
            "last_login, created_at FROM users WHERE id = %s",
            (user_id,),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def username_exists(username: str) -> bool:
    return get_user_by_username(username) is not None


def create_user(username: str, password_hash, role: str, full_name: str = "",
                 email: str = None, auth_provider: str = "local"):
    """Insert a new user. `password_hash` must already be a bcrypt
    hash (see auth/password.py) - this function never receives or
    stores a plain-text password. `password_hash=None` is only valid
    for auth_provider='google' (a Google-only account has no local
    password - see database/schema.sql's comment on this column)."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role, full_name, auth_provider, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (username, email, password_hash, role, full_name, auth_provider, now_myt()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def update_last_login(user_id: int):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = %s WHERE id = %s", (now_myt(), user_id))
        conn.commit()
    finally:
        conn.close()


def update_user_full_name(user_id: int, full_name: str):
    """Update only the full_name column for one user. Called from the
    Settings -> My Account -> Edit Profile form, the one field that
    page actually lets a user change about themselves - username,
    email, and role stay read-only there (see settings.py's own
    docstring on why)."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET full_name = %s WHERE id = %s", (full_name, user_id))
        conn.commit()
    finally:
        conn.close()


def list_users():
    """Return every user (never including password_hash) ordered by id.
    ADMIN-ONLY by convention (enforced in app_pages/settings.py, not
    here) - this is the one deliberate cross-user read in this module,
    needed for account administration itself."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, role, full_name, is_active, last_login, created_at "
            "FROM users ORDER BY id"
        )
        return cursor.fetchall()
    finally:
        conn.close()


def set_user_active(user_id: int, is_active: bool):
    """Enable/disable an account without deleting it. A disabled
    account fails login via authenticate_user()'s is_active check.
    ADMIN-ONLY by convention (enforced in app_pages/settings.py)."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET is_active = %s WHERE id = %s",
            (1 if is_active else 0, user_id),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------
# network_traffic - owned via uploaded_by
# ---------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_traffic_summary(user_id: int, start_date=None, end_date=None):
    """Return {dataset_count, total_rows} across datasets `user_id`
    uploaded, optionally restricted to [start_date, end_date]."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT COUNT(*) AS dataset_count, "
            "COALESCE(SUM(row_count), 0) AS total_rows "
            "FROM network_traffic WHERE uploaded_by = %s "
        )
        params = [user_id]
        if start_date:
            query += "AND uploaded_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND uploaded_at <= %s "
            params.append(end_date)
        cursor.execute(query, tuple(params))
        return cursor.fetchone()
    finally:
        conn.close()


def insert_network_traffic(dataset_name: str, uploaded_by, row_count: int,
                            column_count: int, status: str = "PROCESSED") -> int:
    """Record one uploaded/analysed dataset, owned by `uploaded_by`.
    Called once per completed 'Run AI Detection' pass on the Threat
    Detection page."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO network_traffic (dataset_name, uploaded_by, row_count, column_count, status, uploaded_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (dataset_name, uploaded_by, row_count, column_count, status, now_myt()),
        )
        conn.commit()
        get_traffic_summary.clear()
        return cursor.lastrowid
    finally:
        conn.close()


# ---------------------------------------------------------------
# threat_detections - owned via user_id (added for multi-tenant isolation)
# ---------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_threat_summary(user_id: int, start_date=None, end_date=None, predictions=None):
    """Return {total, critical} counts of AI threat predictions owned
    by `user_id`, optionally restricted to [start_date, end_date] and to a
    set of prediction labels.

    `predictions` was added because `total` counts EVERY classified row -
    BENIGN included - and was previously rendered as "Threats Detected",
    which overstated threats by an amount equal to the benign traffic. A
    caller that means "threats" now passes predictions=("MALICIOUS",); one
    that means "records analysed" passes nothing and gets the full count.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(severity = 'CRITICAL'), 0) AS critical "
            "FROM threat_detections WHERE user_id = %s "
        )
        params = [user_id]
        if predictions:
            placeholders = ", ".join(["%s"] * len(predictions))
            query += f"AND prediction IN ({placeholders}) "
            params.extend(predictions)
        if start_date:
            query += "AND detected_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND detected_at <= %s "
            params.append(end_date)
        cursor.execute(query, tuple(params))
        return cursor.fetchone()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_severity_distribution(user_id: int, start_date=None, end_date=None, predictions=None):
    """Return [{severity, count}, ...] for `user_id`'s own detections,
    optionally restricted to [start_date, end_date] and to a set of
    prediction labels (see get_threat_summary for why that filter exists -
    BENIGN rows also carry a severity, so an unfiltered distribution would
    include them in a chart titled "threats by severity")."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT severity, COUNT(*) AS count FROM threat_detections "
            "WHERE user_id = %s AND severity IS NOT NULL "
        )
        params = [user_id]
        if predictions:
            placeholders = ", ".join(["%s"] * len(predictions))
            query += f"AND prediction IN ({placeholders}) "
            params.extend(predictions)
        if start_date:
            query += "AND detected_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND detected_at <= %s "
            params.append(end_date)
        query += "GROUP BY severity"
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_attack_type_distribution(user_id: int, start_date=None, end_date=None):
    """Return [{attack_type, count}, ...] for `user_id`'s own MALICIOUS
    detections with a known attack_type (multi-class models only - see
    ml/prediction.py), optionally restricted to [start_date, end_date]."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT attack_type, COUNT(*) AS count FROM threat_detections "
            "WHERE user_id = %s AND attack_type IS NOT NULL "
        )
        params = [user_id]
        if start_date:
            query += "AND detected_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND detected_at <= %s "
            params.append(end_date)
        query += "GROUP BY attack_type ORDER BY count DESC"
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_threat_detections_in_range(user_id: int, start_date=None, end_date=None, limit: int = 5000):
    """Return `user_id`'s own full threat_detections rows in
    [start_date, end_date], for the Reports page's CSV export."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT id, traffic_id, record_index, prediction, attack_type, confidence, "
            "risk_score, severity, model_used, detected_at FROM threat_detections "
            "WHERE user_id = %s "
        )
        params = [user_id]
        if start_date:
            query += "AND detected_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND detected_at <= %s "
            params.append(end_date)
        query += "ORDER BY detected_at DESC LIMIT %s"
        params.append(limit)
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_detection_trend(user_id: int, days: int = 14, predictions=None,
                         start_date=None, end_date=None):
    """Per-day counts of `user_id`'s own detections, for the trend
    chart. Either pass `start_date`/`end_date` (the Global Cyber Time
    Navigator's active range - see utils/time_navigator.py) to scope
    to an exact range, or leave them unset to fall back to the last
    `days` days (the original, still-supported behaviour).

    `predictions` filters to a set of labels - the Dashboard plots MALICIOUS
    only, so its line and its severity doughnut describe the same records.
    Days with no rows are simply absent from the result; the caller
    (app_pages/dashboard.py) fills those in as a real 0 rather than
    letting Plotly draw a straight line across missing calendar days.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT DATE(detected_at) AS day, COUNT(*) AS count FROM threat_detections WHERE user_id = %s "
        params = [user_id]
        if start_date is not None and end_date is not None:
            query += "AND detected_at >= %s AND detected_at <= %s "
            params += [start_date, end_date]
        elif start_date is None and end_date is None and days is not None:
            query += "AND detected_at >= (NOW() - INTERVAL %s DAY) "
            params.append(days)
        if predictions:
            placeholders = ", ".join(["%s"] * len(predictions))
            query += f"AND prediction IN ({placeholders}) "
            params.extend(predictions)
        query += "GROUP BY DATE(detected_at) ORDER BY day"
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_recent_threats(user_id: int, limit: int = 10, start_date=None, end_date=None):
    """Return `user_id`'s own most recent MALICIOUS detections (never
    BENIGN - this feeds the Dashboard's "Recent Threats" section, which
    is specifically about threats, not every classified record),
    optionally restricted to [start_date, end_date] on detected_at."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT id, prediction, attack_type, confidence, risk_score, "
            "severity, model_used, detected_at FROM threat_detections "
            "WHERE user_id = %s AND prediction = 'MALICIOUS' "
        )
        params = [user_id]
        if start_date:
            query += "AND detected_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND detected_at <= %s "
            params.append(end_date)
        query += "ORDER BY detected_at DESC LIMIT %s"
        params.append(limit)
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


# mysql-connector-python's executemany() rewrites a multi-row INSERT
# into ONE multi-VALUES statement for efficiency - great for a handful
# of rows, but for a large detection batch (the bundled CICIDS2017
# dataset is 225,745 rows) that single statement can easily exceed the
# server's max_allowed_packet (MySQL error 1153) and the whole insert
# fails - which is exactly what left threat_detections empty for every
# past attempt at the full dataset. Chunking keeps each statement small
# regardless of how small a server's max_allowed_packet is configured.
#
# 10,000 (was 2,000): this table's live TiDB Cloud connection measured
# at ~84ms round-trip per query (a remote connection, not localhost) -
# every chunk pays that latency regardless of its size, so fewer,
# bigger chunks win. Benchmarked directly against this project's own
# TiDB connection with a real 191,033-row insert (rolled back
# afterwards, nothing persisted): 2,000/chunk took 19.2s (96 round
# trips), 10,000/chunk took 12.6s (20 round trips) - a real ~35%
# reduction, with 20,000/chunk only saving another ~0.7s past this
# point (diminishing returns). The server's actual max_allowed_packet
# is 64MB (confirmed via SHOW VARIABLES) - a 10,000-row chunk of this
# table is well under 1MB, nowhere near that ceiling.
THREAT_DETECTION_INSERT_BATCH_SIZE = 10000


def insert_threat_detections_bulk(traffic_id: int, results_df, user_id: int) -> list[int]:
    """Bulk-insert one row per AI prediction, all owned by `user_id`
    (the analyst who uploaded/ran this batch). `results_df` must come
    from ml/prediction.py:run_detection() - real model output only,
    never manually-entered or invented results.

    Inserted in chunks of THREAT_DETECTION_INSERT_BATCH_SIZE rows (see
    its comment for why), all within ONE transaction - if any chunk
    fails, every chunk already sent in this call is rolled back, so a
    failure never leaves a partial batch (some rows saved, the rest
    silently missing) sitting in the table. Raises back to the caller
    on failure - it never swallows an error and pretends success.

    Returns every inserted row's REAL id, in the same order as
    `results_df`, fetched with a follow-up SELECT scoped to
    `traffic_id` - a fresh network_traffic row exists per detection
    run (see insert_network_traffic), so traffic_id alone unambiguously
    selects exactly this call's own rows, and ORDER BY id preserves
    insertion order (auto-increment is always assigned in insertion
    order, even when the values themselves aren't contiguous).

    PREVIOUSLY this returned only the first row's id and every other
    row's id was GUESSED as first_id + offset, relying on MySQL's
    single-node auto-increment being gapless within one executemany()
    batch. That guess is not safe on TiDB, whose distributed
    AUTO_ID_CACHE allocator can leave gaps within one batch - a guessed
    id could point at a row that was never actually inserted, and the
    compliance engine (Step 7) writing that guessed id as
    compliance_results.related_detection_id then failed with a foreign
    key violation (error 1452) for a detection that was, in fact, saved
    correctly under a different real id. Fetching the real ids here
    removes the guess entirely, on both MySQL and TiDB."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        # One shared timestamp for the whole batch (same detection run),
        # explicit Malaysia time - not the table's own DEFAULT
        # CURRENT_TIMESTAMP, which is the shared TiDB Cloud cluster's
        # clock (UTC), not the user's own local time (see
        # utils/timezone.py).
        detected_at = now_myt()
        rows = [
            (
                user_id,
                traffic_id,
                int(r["record_index"]),
                r["prediction"],
                _sql_null_safe(r["attack_type"]),
                r["confidence"],
                r["risk_score"],
                r["severity"],
                r["model_used"],
                detected_at,
            )
            for r in results_df.to_dict("records")
        ]

        insert_sql = (
            "INSERT INTO threat_detections "
            "(user_id, traffic_id, record_index, prediction, attack_type, confidence, risk_score, severity, model_used, detected_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        )
        for start in range(0, len(rows), THREAT_DETECTION_INSERT_BATCH_SIZE):
            chunk = rows[start:start + THREAT_DETECTION_INSERT_BATCH_SIZE]
            cursor.executemany(insert_sql, chunk)

        cursor.execute(
            "SELECT id FROM threat_detections WHERE traffic_id = %s ORDER BY id",
            (traffic_id,),
        )
        detection_ids = [row[0] for row in cursor.fetchall()]
        if len(detection_ids) != len(rows):
            raise RuntimeError(
                f"Inserted {len(rows)} threat_detections row(s) for traffic_id={traffic_id} "
                f"but only found {len(detection_ids)} on read-back - refusing to guess ids."
            )

        conn.commit()
        get_threat_summary.clear()
        get_severity_distribution.clear()
        get_attack_type_distribution.clear()
        get_threat_detections_in_range.clear()
        get_detection_trend.clear()
        get_recent_threats.clear()
        return detection_ids
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_network_traffic(traffic_id: int) -> None:
    """Remove one network_traffic row - used ONLY to clean up after a
    detection run whose threat_detections insert failed partway
    (see app_pages/threat_detection.py's _run_detection()), so a failed
    run doesn't leave a dangling traffic record with no detections
    attached to it. Safe unconditionally: a row this function is ever
    called for has, by construction, zero threat_detections pointing at
    it yet (the detections insert is what just failed)."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM network_traffic WHERE id = %s", (traffic_id,))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------
# url_scan_results - owned via scanned_by
# ---------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_url_scan_summary(user_id: int, start_date=None, end_date=None):
    """Return {total, high_risk} counts of `user_id`'s own URL
    threat-intel scans, optionally restricted to [start_date, end_date]."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(risk_level IN ('HIGH', 'CRITICAL')), 0) AS high_risk "
            "FROM url_scan_results WHERE scanned_by = %s "
        )
        params = [user_id]
        if start_date:
            query += "AND scan_timestamp >= %s "
            params.append(start_date)
        if end_date:
            query += "AND scan_timestamp <= %s "
            params.append(end_date)
        cursor.execute(query, tuple(params))
        return cursor.fetchone()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_url_scan_status_counts(user_id: int, start_date=None, end_date=None):
    """Return [{scan_status, count}, ...] for `user_id`'s own scans
    (SAFE/SUSPICIOUS/MALICIOUS/SCAN_ERROR), optionally restricted to
    [start_date, end_date]."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT scan_status, COUNT(*) AS count FROM url_scan_results WHERE scanned_by = %s "
        params = [user_id]
        if start_date:
            query += "AND scan_timestamp >= %s "
            params.append(start_date)
        if end_date:
            query += "AND scan_timestamp <= %s "
            params.append(end_date)
        query += "GROUP BY scan_status"
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_url_scans_in_range(user_id: int, start_date=None, end_date=None, limit: int = 5000):
    """Return `user_id`'s own full url_scan_results rows in
    [start_date, end_date], for the Reports page's CSV export."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT id, url, scan_status, threat_category, detection_count, total_engines, "
            "risk_score, risk_level, source, scan_timestamp FROM url_scan_results "
            "WHERE scanned_by = %s "
        )
        params = [user_id]
        if start_date:
            query += "AND scan_timestamp >= %s "
            params.append(start_date)
        if end_date:
            query += "AND scan_timestamp <= %s "
            params.append(end_date)
        query += "ORDER BY scan_timestamp DESC LIMIT %s"
        params.append(limit)
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


def insert_url_scan_result(url: str, scanned_by, scan_status: str, threat_category,
                            detection_count, total_engines, risk_score, risk_level,
                            source: str = "VirusTotal", analysis_reference=None) -> int:
    """Record one completed URL scan, owned by `scanned_by`
    (security/url_scanner.py output only - never a manually-entered
    result)."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO url_scan_results "
            "(url, scanned_by, scan_status, threat_category, detection_count, "
            "total_engines, risk_score, risk_level, source, analysis_reference, scan_timestamp) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (url, scanned_by, scan_status, threat_category, detection_count,
             total_engines, risk_score, risk_level, source, analysis_reference, now_myt()),
        )
        conn.commit()
        get_url_scan_summary.clear()
        get_url_scan_status_counts.clear()
        get_url_scans_in_range.clear()
        get_recent_url_scans.clear()
        return cursor.lastrowid
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_recent_url_scans(user_id: int, limit: int = 10):
    """Return `user_id`'s own most recent URL scans, newest first."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, url, scan_status, threat_category, detection_count, "
            "total_engines, risk_level, scan_timestamp FROM url_scan_results "
            "WHERE scanned_by = %s ORDER BY scan_timestamp DESC LIMIT %s",
            (user_id, limit),
        )
        return cursor.fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------
# compliance_rules (shared, static rule catalog - NOT user data,
# deliberately has no owner) / compliance_results (owned via user_id)
# ---------------------------------------------------------------

# The five frameworks are fixed by the FYP report and the schema's
# ENUM - not data, so listing them here (rather than only ever reading
# them back from an as-yet-empty table) is how the Dashboard can show
# all five with "Not yet assessed" before the compliance engine exists.
COMPLIANCE_FRAMEWORKS = [
    ("PDPA", "PDPA 2010"),
    ("ISO27001", "ISO/IEC 27001:2022"),
    ("NIST_CSF", "NIST CSF 2.0"),
    ("GDPR", "GDPR"),
    ("EU_AI_ACT", "EU AI Act"),
]


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_compliance_overview(user_id: int, start_date=None, end_date=None):
    """Return {framework_code: {compliant, needs_review, violation,
    last_checked}} for every framework with at least one recorded
    compliance_results row OWNED BY `user_id` (optionally restricted
    to [start_date, end_date] on checked_at). A framework absent from
    the returned dict has never been assessed by this user (or none in
    range)."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT cr.framework AS framework, "
            "SUM(cres.status = 'COMPLIANT') AS compliant, "
            "SUM(cres.status = 'NEEDS_REVIEW') AS needs_review, "
            "SUM(cres.status = 'POTENTIAL_VIOLATION') AS violation, "
            "MAX(cres.checked_at) AS last_checked "
            "FROM compliance_results cres "
            "JOIN compliance_rules cr ON cr.id = cres.rule_id "
            "WHERE cres.user_id = %s "
        )
        params = [user_id]
        if start_date:
            query += "AND cres.checked_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND cres.checked_at <= %s "
            params.append(end_date)
        query += "GROUP BY cr.framework"
        cursor.execute(query, tuple(params))
        return {row["framework"]: row for row in cursor.fetchall()}
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_recent_compliance_issues(user_id: int, limit: int = 10, start_date=None, end_date=None):
    """Return `user_id`'s own most recent NEEDS_REVIEW/
    POTENTIAL_VIOLATION results (compliant results aren't 'issues'),
    optionally restricted to [start_date, end_date] on checked_at."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT cres.id, cr.framework, cr.title, cres.status, "
            "cres.reason, cres.recommended_action, cres.checked_at "
            "FROM compliance_results cres "
            "JOIN compliance_rules cr ON cr.id = cres.rule_id "
            "WHERE cres.user_id = %s AND cres.status != 'COMPLIANT' "
        )
        params = [user_id]
        if start_date:
            query += "AND cres.checked_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND cres.checked_at <= %s "
            params.append(end_date)
        query += "ORDER BY cres.checked_at DESC LIMIT %s"
        params.append(limit)
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


def seed_compliance_rules(rule_defs: list):
    """Idempotently insert/update the static, SHARED rule catalog
    (rule_code, framework, title, description, trigger_condition,
    recommended_action). These are fixed reference definitions from
    the FYP report (compliance/*_rules.py's RULES lists) - the same
    for every user, not user data, so there is no user_id here."""
    if not rule_defs:
        return
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.executemany(
            "INSERT INTO compliance_rules "
            "(framework, rule_code, title, description, trigger_condition, recommended_action) "
            "VALUES (%(framework)s, %(rule_code)s, %(title)s, %(description)s, "
            "%(trigger_condition)s, %(recommended_action)s) "
            "ON DUPLICATE KEY UPDATE "
            "title = VALUES(title), description = VALUES(description), "
            "trigger_condition = VALUES(trigger_condition), "
            "recommended_action = VALUES(recommended_action)",
            rule_defs,
        )
        conn.commit()
        get_compliance_rule_lookup.clear()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_compliance_rule_lookup() -> dict:
    """{rule_code: {id, recommended_action}} for the whole static
    compliance_rules catalog - small and rarely-changing (only
    seed_compliance_rules() above writes to it, which clears this
    cache), so this is a correctness-safe win: save_compliance_results()
    below used to run this exact SELECT fresh on every single call,
    and _run_compliance_for_significant_detections()
    (app_pages/threat_detection.py) calls that once per HIGH/CRITICAL
    detection row - thousands of redundant identical queries for one
    detection run on a dataset with many high-risk rows."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, rule_code, recommended_action FROM compliance_rules")
        return {r["rule_code"]: r for r in cursor.fetchall()}
    finally:
        conn.close()


def save_compliance_results(results: list, user_id: int):
    """Persist compliance_engine.py's evaluation output, all owned by
    `user_id` (the same person who triggered the underlying detection/
    scan, or who clicked 'Run AI System Self-Assessment'). Each result
    dict needs: rule_code, status, reason, evidence,
    related_detection_id, related_url_scan_id. The rule's canonical
    recommended_action is looked up from compliance_rules (defined
    once per rule there, not re-typed per result), via the cached
    get_compliance_rule_lookup() above rather than a fresh query every
    call."""
    if not results:
        return
    conn = get_connection()
    try:
        rule_lookup = get_compliance_rule_lookup()

        checked_at = now_myt()
        rows = []
        for r in results:
            rule = rule_lookup.get(r["rule_code"])
            if rule is None:
                continue  # rule not seeded yet - skip rather than crash
            rows.append((
                user_id, rule["id"], r.get("related_detection_id"), r.get("related_url_scan_id"),
                r["status"], r.get("reason"), r.get("evidence"), rule["recommended_action"], checked_at,
            ))
        if not rows:
            return

        cursor = conn.cursor()
        cursor.executemany(
            "INSERT INTO compliance_results "
            "(user_id, rule_id, related_detection_id, related_url_scan_id, status, reason, evidence, recommended_action, checked_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            rows,
        )
        conn.commit()
        get_compliance_overview.clear()
        get_recent_compliance_issues.clear()
        get_compliance_results_detail.clear()
        get_compliance_results_for_event.clear()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_compliance_results_detail(user_id: int, framework=None, limit: int = 100,
                                   start_date=None, end_date=None):
    """Return `user_id`'s own individual compliance_results rows
    (rule-by-rule), most recent first, optionally filtered to one
    framework and/or [start_date, end_date] - used by the Compliance
    Monitoring page's detail table and, with a higher limit, by the
    Reports page's compliance CSV export."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT cres.id, cr.framework, cr.rule_code, cr.title, cres.status, "
            "cres.reason, cres.evidence, cres.recommended_action, cres.related_detection_id, "
            "cres.related_url_scan_id, cres.checked_at "
            "FROM compliance_results cres "
            "JOIN compliance_rules cr ON cr.id = cres.rule_id "
            "WHERE cres.user_id = %s "
        )
        params = [user_id]
        if framework:
            query += "AND cr.framework = %s "
            params.append(framework)
        if start_date:
            query += "AND cres.checked_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND cres.checked_at <= %s "
            params.append(end_date)
        query += "ORDER BY cres.checked_at DESC LIMIT %s"
        params.append(limit)
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------
# alerts - owned via user_id (added for multi-tenant isolation)
# ---------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_alert_count(user_id: int, start_date=None, end_date=None):
    """Return the total number of alerts owned by `user_id` (each
    alert already represents a high-risk event of THEIRS - see
    compliance/ + Step 8's creation rule), optionally restricted to
    [start_date, end_date] on created_at."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT COUNT(*) AS total FROM alerts WHERE user_id = %s "
        params = [user_id]
        if start_date:
            query += "AND created_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND created_at <= %s "
            params.append(end_date)
        cursor.execute(query, tuple(params))
        return cursor.fetchone()["total"]
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_new_alert_count(user_id: int) -> int:
    """Count of `user_id`'s own alerts still in status NEW - i.e. not
    yet investigated or resolved. Backs the top bar's notification
    badge (utils/page_ui.py) with a real, current number, never a
    placeholder."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE user_id = %s AND status = 'NEW'",
            (user_id,),
        )
        return cursor.fetchone()[0]
    finally:
        conn.close()


def create_alert(user_id: int, event_type: str, threat_type, severity: str, risk_score: int,
                  confidence, related_detection_id, related_url_scan_id,
                  compliance_summary: str, recommended_action: str) -> int:
    """Insert a new alert owned by `user_id` (the same person whose
    detection/scan triggered it). Only ever called from
    compliance_engine.py._create_alert_for_event() when an event's
    risk_score crosses ALERT_RISK_THRESHOLD - never manually invented.
    threat_ref (e.g. "THR-0021") is generated from the row's own
    auto-increment id, via a two-step insert-then-update so the
    UNIQUE constraint is satisfied without a separate id sequence."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        placeholder_ref = f"PENDING-{uuid.uuid4().hex[:12]}"
        cursor.execute(
            "INSERT INTO alerts (user_id, threat_ref, event_type, threat_type, severity, "
            "risk_score, confidence, related_detection_id, related_url_scan_id, "
            "compliance_summary, recommended_action, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (user_id, placeholder_ref, event_type, threat_type, severity, risk_score, confidence,
             related_detection_id, related_url_scan_id, compliance_summary, recommended_action, now_myt()),
        )
        alert_id = cursor.lastrowid
        cursor.execute(
            "UPDATE alerts SET threat_ref = %s WHERE id = %s",
            (f"THR-{alert_id:04d}", alert_id),
        )
        conn.commit()
        get_alert_count.clear()
        get_new_alert_count.clear()
        get_alerts.clear()
        get_alert_status_counts.clear()
        get_alert_severity_counts.clear()
        return alert_id
    finally:
        conn.close()


def create_alerts_bulk(alerts: list[dict]) -> list[int]:
    """Bulk sibling of create_alert() - for a whole batch of alerts
    (e.g. every HIGH/CRITICAL detection in one Threat Detection run),
    this is a small constant number of round trips total instead of 2
    PER alert (insert-then-update, each its own connection checkout),
    which is what made a large detection run with thousands of
    significant rows slow against a remote database. create_alert()
    itself is unchanged - URL Scanner's single-event call site keeps
    using it exactly as before.

    Each dict needs the same keys as create_alert()'s parameters
    (user_id, event_type, threat_type, severity, risk_score,
    confidence, related_detection_id, related_url_scan_id,
    compliance_summary, recommended_action). Returns the new alert ids
    in the same order as `alerts`."""
    if not alerts:
        return []
    conn = get_connection()
    try:
        cursor = conn.cursor()
        placeholder_refs = [f"PENDING-{uuid.uuid4().hex[:12]}" for _ in alerts]
        created_at = now_myt()
        rows = [
            (a["user_id"], placeholder_refs[i], a["event_type"], a["threat_type"], a["severity"],
             a["risk_score"], a["confidence"], a["related_detection_id"], a["related_url_scan_id"],
             a["compliance_summary"], a["recommended_action"], created_at)
            for i, a in enumerate(alerts)
        ]
        cursor.executemany(
            "INSERT INTO alerts (user_id, threat_ref, event_type, threat_type, severity, "
            "risk_score, confidence, related_detection_id, related_url_scan_id, "
            "compliance_summary, recommended_action, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            rows,
        )
        conn.commit()

        # executemany()'s own lastrowid only ever gives the FIRST row's
        # id - map placeholder_ref -> real id via one SELECT instead of
        # assuming the ids are contiguous.
        fmt = ", ".join(["%s"] * len(placeholder_refs))
        cursor.execute(f"SELECT id, threat_ref FROM alerts WHERE threat_ref IN ({fmt})", placeholder_refs)
        id_by_ref = {ref: row_id for row_id, ref in cursor.fetchall()}
        ordered_ids = [id_by_ref[ref] for ref in placeholder_refs]

        # A single CASE-based UPDATE instead of executemany() here -
        # mysql-connector-python only rewrites an INSERT's executemany()
        # into one multi-row statement; for UPDATE it silently falls
        # back to one execute() per row, which would put the N we just
        # removed from the insert/alert-creation step right back in on
        # this one. Every id in `ordered_ids` is covered by its own WHEN
        # branch and the WHERE clause only ever matches those same ids,
        # so no row can fall through without a match (no ELSE needed).
        case_clauses = " ".join("WHEN %s THEN %s" for _ in ordered_ids)
        case_params = []
        for alert_id in ordered_ids:
            case_params.extend([alert_id, f"THR-{alert_id:04d}"])
        id_fmt = ", ".join(["%s"] * len(ordered_ids))
        cursor.execute(
            f"UPDATE alerts SET threat_ref = CASE id {case_clauses} END WHERE id IN ({id_fmt})",
            case_params + ordered_ids,
        )
        conn.commit()

        get_alert_count.clear()
        get_new_alert_count.clear()
        get_alerts.clear()
        get_alert_status_counts.clear()
        get_alert_severity_counts.clear()
        return ordered_ids
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_alerts(user_id: int, status=None, severities=None, event_type=None, limit: int = 100,
                start_date=None, end_date=None):
    """Return `user_id`'s own alerts, most recent first, optionally
    filtered by status (NEW / INVESTIGATING / RESOLVED), a list of
    severities (LOW/MEDIUM/HIGH/CRITICAL), event_type ("Network
    Threat" / "Malicious URL"), and/or [start_date, end_date] on
    created_at. `related_detection_id`/`related_url_scan_id` are
    included so the Alerts & Incidents page's detail panel can look up
    the underlying detection/scan record."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = (
            "SELECT id, threat_ref, event_type, threat_type, severity, risk_score, "
            "confidence, related_detection_id, related_url_scan_id, compliance_summary, "
            "recommended_action, status, created_at, updated_at FROM alerts WHERE user_id = %s "
        )
        params = [user_id]
        if status:
            query += "AND status = %s "
            params.append(status)
        if severities:
            query += f"AND severity IN ({','.join(['%s'] * len(severities))}) "
            params.extend(severities)
        if event_type:
            query += "AND event_type = %s "
            params.append(event_type)
        if start_date:
            query += "AND created_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND created_at <= %s "
            params.append(end_date)
        query += "ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_alert_status_counts(user_id: int, start_date=None, end_date=None):
    """Return [{status, count}, ...] (NEW/INVESTIGATING/RESOLVED) for
    `user_id`'s own alerts, optionally restricted to [start_date,
    end_date] - for the Reports page's Incident Summary chart."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT status, COUNT(*) AS count FROM alerts WHERE user_id = %s "
        params = [user_id]
        if start_date:
            query += "AND created_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND created_at <= %s "
            params.append(end_date)
        query += "GROUP BY status"
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_alert_severity_counts(user_id: int, start_date=None, end_date=None):
    """Return [{severity, count}, ...] (LOW/MEDIUM/HIGH/CRITICAL) for
    `user_id`'s own alerts, optionally restricted to [start_date,
    end_date] - backs the Alerts & Incidents page's severity summary
    cards. Only severities with at least one real alert are returned."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT severity, COUNT(*) AS count FROM alerts WHERE user_id = %s "
        params = [user_id]
        if start_date:
            query += "AND created_at >= %s "
            params.append(start_date)
        if end_date:
            query += "AND created_at <= %s "
            params.append(end_date)
        query += "GROUP BY severity"
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


def update_alert_status(alert_id: int, status: str, user_id: int):
    """Move an alert through NEW -> INVESTIGATING -> RESOLVED.

    `user_id` is included directly in the WHERE clause (not just
    checked beforehand) - defense in depth: even if a request for a
    foreign alert_id somehow reached this function, the UPDATE simply
    matches zero rows instead of mutating another user's alert."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        # updated_at set explicitly (Malaysia time, see utils/timezone.py)
        # rather than left to the column's own ON UPDATE CURRENT_TIMESTAMP -
        # that trigger fires on the shared TiDB Cloud cluster's own clock
        # (UTC), the same mismatch commit 1019fff already fixed for every
        # INSERT-time timestamp column; this UPDATE was the one write path
        # still relying on the database server's own clock.
        cursor.execute(
            "UPDATE alerts SET status = %s, updated_at = %s WHERE id = %s AND user_id = %s",
            (status, now_myt(), alert_id, user_id),
        )
        conn.commit()
        get_alert_count.clear()
        get_new_alert_count.clear()
        get_alerts.clear()
        get_alert_status_counts.clear()
        get_alert_severity_counts.clear()
        return cursor.rowcount > 0
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_threat_detection_by_id(detection_id: int, user_id: int):
    """Return one threat_detections row (scoped to `user_id`), for the
    Alerts & Incidents page's incident detail panel when an alert's
    related_detection_id is set. None if not found or not owned by
    this user."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, traffic_id, record_index, prediction, attack_type, confidence, "
            "risk_score, severity, model_used, detected_at FROM threat_detections "
            "WHERE id = %s AND user_id = %s",
            (detection_id, user_id),
        )
        return cursor.fetchone()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_url_scan_by_id(scan_id: int, user_id: int):
    """Return one url_scan_results row (scoped to `user_id`), for the
    Alerts & Incidents page's incident detail panel when an alert's
    related_url_scan_id is set. None if not found or not owned by
    this user."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, url, scan_timestamp, scan_status, threat_category, detection_count, "
            "total_engines, risk_score, risk_level, source, analysis_reference "
            "FROM url_scan_results WHERE id = %s AND scanned_by = %s",
            (scan_id, user_id),
        )
        return cursor.fetchone()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_compliance_results_for_event(user_id: int, related_detection_id=None, related_url_scan_id=None):
    """Return the real compliance_results rows (with their framework,
    status, reason, evidence) that were generated FROM the same
    detection/URL-scan event that triggered a given alert - used by
    the Alerts & Incidents detail panel to show supporting evidence
    without inventing any. Returns [] if neither id is set."""
    if not related_detection_id and not related_url_scan_id:
        return []
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        if related_detection_id:
            cursor.execute(
                "SELECT cr.framework, cr.title, cres.status, cres.reason, cres.evidence "
                "FROM compliance_results cres JOIN compliance_rules cr ON cr.id = cres.rule_id "
                "WHERE cres.user_id = %s AND cres.related_detection_id = %s",
                (user_id, related_detection_id),
            )
        else:
            cursor.execute(
                "SELECT cr.framework, cr.title, cres.status, cres.reason, cres.evidence "
                "FROM compliance_results cres JOIN compliance_rules cr ON cr.id = cres.rule_id "
                "WHERE cres.user_id = %s AND cres.related_url_scan_id = %s",
                (user_id, related_url_scan_id),
            )
        return cursor.fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------
# audit_logs (write side lives in utils/audit_logger.py; these are
# the read-side queries for the Audit Logs page). audit_logs has no
# user_id column (it predates ownership tracking and already has a
# stable `username`), so scoping here is by username instead.
# ---------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_audit_logs(username, limit: int = 200, action=None, start_date=None, end_date=None):
    """Return audit log entries, most recent first, optionally
    filtered by action type and/or [start_date, end_date] on
    timestamp.

    `username=None` returns entries for EVERY user - app_pages/
    audit_logs.py only ever passes None for an admin who has
    explicitly opted into the 'All users' view; every other caller
    (and every non-admin user) always passes their own username."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT id, username, action, event_type, description, timestamp FROM audit_logs WHERE 1=1 "
        params = []
        if username:
            query += "AND username = %s "
            params.append(username)
        if action:
            query += "AND action = %s "
            params.append(action)
        if start_date:
            query += "AND timestamp >= %s "
            params.append(start_date)
        if end_date:
            query += "AND timestamp <= %s "
            params.append(end_date)
        query += "ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_audit_log_actions():
    """Return the distinct action values seen so far, for the Audit
    Logs page's filter dropdown. Just a list of action-type labels
    (e.g. 'LOGIN', 'URL_SCAN') - not user data, so this stays global."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT action FROM audit_logs ORDER BY action")
        return [r[0] for r in cursor.fetchall()]
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_audit_action_counts(username, start_date=None, end_date=None):
    """Return [{action, count}, ...] for one user's own activity
    (`username=None` = every user, admin-only view), optionally
    restricted to [start_date, end_date] - for the Reports page's
    Audit Summary."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT action, COUNT(*) AS count FROM audit_logs WHERE 1=1 "
        params = []
        if username:
            query += "AND username = %s "
            params.append(username)
        if start_date:
            query += "AND timestamp >= %s "
            params.append(start_date)
        if end_date:
            query += "AND timestamp <= %s "
            params.append(end_date)
        query += "GROUP BY action ORDER BY count DESC"
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------
# reports (populated starting Step 10 - Reports page)
# ---------------------------------------------------------------

def record_report(generated_by, report_type: str, file_format: str):
    """Record that a report was generated (who, what kind, which
    format) - the file itself is generated in-memory and streamed to
    the browser via st.download_button, never written to disk, so
    file_path stays NULL. This is purely an audit trail row matching
    the `reports` table schema's own purpose."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO reports (generated_by, report_type, file_format, file_path, generated_at) "
            "VALUES (%s, %s, %s, NULL, %s)",
            (generated_by, report_type, file_format, now_myt()),
        )
        conn.commit()
        get_report_history.clear()
        return cursor.lastrowid
    finally:
        conn.close()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_report_history(generated_by: int, limit: int = 50):
    """Return `generated_by`'s own report-generation history, most
    recent first - real rows from the `reports` audit table, one per
    past download. The actual file bytes were never persisted (see
    record_report's docstring), so this is metadata only: id,
    report_type, file_format, generated_at, plus the generating
    username (joined from users, 'Unknown user' if that account was
    since deleted - generated_by is ON DELETE SET NULL)."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT r.id, r.report_type, r.file_format, r.generated_at, "
            "COALESCE(u.username, 'Unknown user') AS generated_by_username "
            "FROM reports r LEFT JOIN users u ON u.id = r.generated_by "
            "WHERE r.generated_by = %s ORDER BY r.generated_at DESC LIMIT %s",
            (generated_by, limit),
        )
        return cursor.fetchall()
    finally:
        conn.close()
