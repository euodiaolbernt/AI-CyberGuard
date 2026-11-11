"""
Audit logging (Layer 6 / accountability).

Every security-relevant action across the whole system (login,
logout, dataset upload, AI prediction, URL scan, compliance check,
alert creation, incident update, report generation, ...) is written
through this single log_action() function, so there is exactly one
code path that produces the trail shown later on the Audit Logs page.
"""
from database.connection import get_connection


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
                "INSERT INTO audit_logs (username, action, event_type, description) "
                "VALUES (%s, %s, %s, %s)",
                (user, action, event_type, description),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[audit_logger] Failed to write audit log: {e}")
