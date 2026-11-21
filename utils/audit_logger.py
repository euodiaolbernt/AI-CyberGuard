"""
Audit logging (Layer 6 / accountability).

Every security-relevant action across the whole system (login,
logout, dataset upload, AI prediction, URL scan, compliance check,
alert creation, incident update, report generation, ...) is written
through this single log_action() function, so there is exactly one
code path that produces the trail shown later on the Audit Logs page.
"""
from database.connection import get_connection
from utils.timezone import now_myt


def log_action(user: str, action: str, event_type: str, description: str = ""):
    """Insert one row into audit_logs.

    Deliberately never raises: a failure to write an audit log must
    not crash the feature that triggered it (e.g. a login should still
    succeed even if the audit write fails). The failure is only
    printed to the console for developer visibility.
    """
    try:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO audit_logs (username, action, event_type, description, timestamp) "
                "VALUES (%s, %s, %s, %s, %s)",
                (user, action, event_type, description, now_myt()),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[audit_logger] Failed to write audit log: {e}")


def log_actions_bulk(entries: list[tuple[str, str, str, str]]):
    """Bulk sibling of log_action() - one INSERT round trip for many
    rows (user, action, event_type, description) at once, instead of
    one round trip PER row. Only for call sites that legitimately
    produce many audit rows from a single operation (e.g. one
    ALERT_CREATED row per significant detection in a single Threat
    Detection run) - log_action() itself is unchanged for every
    existing single-event call site. Same never-raises contract."""
    if not entries:
        return
    try:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            timestamp = now_myt()
            entries = [(*entry, timestamp) for entry in entries]
            cursor.executemany(
                "INSERT INTO audit_logs (username, action, event_type, description, timestamp) "
                "VALUES (%s, %s, %s, %s, %s)",
                entries,
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[audit_logger] Failed to write audit log batch: {e}")
