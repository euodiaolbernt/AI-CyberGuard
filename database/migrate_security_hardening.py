"""
One-time migration for the security-hardening update.

Safe to run more than once - every change checks INFORMATION_SCHEMA (or
uses CREATE TABLE IF NOT EXISTS) first. Does NOT delete or modify any
existing row's data.

Two changes:

1. Widens `users.username` and `audit_logs.username` from VARCHAR(50)
   to VARCHAR(255). Self-registered accounts (local or Google) store
   their email address AS their username (see
   auth/authentication.py's register_user()/handle_google_login()),
   but `email` has always been VARCHAR(255) while `username` was still
   VARCHAR(50) - an email longer than 50 characters would fail the
   INSERT (or be silently truncated, depending on the server's SQL
   mode). This widens username to match email exactly; no data is
   rewritten, no existing value is long enough to be affected.

2. Creates `rate_limit_counters`, a new table backing
   auth/rate_limit.py's login throttling and security/url_scanner.py's
   per-user scan cooldown. Nothing is removed or altered on any
   existing table for this part - it's a brand-new, empty table.

This script only ever ALTERs/CREATEs schema - it never runs against
or deletes application data, and the Streamlit app never calls it
automatically. Run it once, deliberately:

    python database/migrate_security_hardening.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.connection import get_connection

COLUMN_WIDEN_STATEMENTS = [
    ("users.username -> VARCHAR(255)",
     "SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
     "AND TABLE_NAME = 'users' AND COLUMN_NAME = 'username'",
     "ALTER TABLE users MODIFY COLUMN username VARCHAR(255) NOT NULL"),
    ("audit_logs.username -> VARCHAR(255)",
     "SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
     "AND TABLE_NAME = 'audit_logs' AND COLUMN_NAME = 'username'",
     "ALTER TABLE audit_logs MODIFY COLUMN username VARCHAR(255) NOT NULL"),
]

CREATE_RATE_LIMIT_TABLE = """
CREATE TABLE IF NOT EXISTS rate_limit_counters (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scope           VARCHAR(20) NOT NULL,   -- e.g. 'LOGIN_ACCOUNT', 'LOGIN_SOURCE', 'URL_SCAN_USER'
    identifier       VARCHAR(255) NOT NULL,  -- normalized account identifier, source IP, or user id
    attempt_count    INT NOT NULL DEFAULT 1,
    window_start     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_attempt_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_until     DATETIME NULL,
    UNIQUE KEY uq_rate_limit_scope_identifier (scope, identifier)
)
"""


def main():
    conn = get_connection()
    try:
        cursor = conn.cursor()

        for label, check_sql, fix_sql in COLUMN_WIDEN_STATEMENTS:
            cursor.execute(check_sql)
            current_length = cursor.fetchone()[0]
            if current_length is not None and current_length >= 255:
                print(f"[skip] {label} already wide enough")
            else:
                cursor.execute(fix_sql)
                print(f"[done] {label}")
        conn.commit()

        cursor.execute(CREATE_RATE_LIMIT_TABLE)
        conn.commit()
        print("[done] rate_limit_counters table present")

        print("\nMigration complete. No existing rows were deleted or had "
              "their content changed.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
