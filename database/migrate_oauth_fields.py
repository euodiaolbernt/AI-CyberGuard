"""
One-time migration: add the columns the Google OAuth / email login
update needs to an EXISTING `users` table, without touching any
existing row.

Safe to run more than once - it checks INFORMATION_SCHEMA before
making each change, so it only ever does the parts that are still
missing. A brand-new database created from database/schema.sql
already has the final shape and does not need this script; it exists
for a database that was created before this update.

Run once:

    python database/migrate_oauth_fields.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.connection import get_connection

STATEMENTS = [
    (
        "email column",
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'email'",
        "ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL UNIQUE AFTER username",
    ),
    (
        "auth_provider column",
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'auth_provider'",
        "ALTER TABLE users ADD COLUMN auth_provider ENUM('local','google') NOT NULL DEFAULT 'local' AFTER role",
    ),
]

NULLABLE_PASSWORD_CHECK = (
    "SELECT IS_NULLABLE FROM information_schema.COLUMNS "
    "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'password_hash'"
)
NULLABLE_PASSWORD_FIX = "ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NULL"

ROLE_ENUM_CHECK = (
    "SELECT COLUMN_TYPE FROM information_schema.COLUMNS "
    "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'role'"
)
ROLE_ENUM_FIX = (
    "ALTER TABLE users MODIFY COLUMN role "
    "ENUM('ADMIN','SOC ANALYST','COMPLIANCE OFFICER','AUDITOR','USER') NOT NULL DEFAULT 'USER'"
)


def main():
    conn = get_connection()
    try:
        cursor = conn.cursor()

        for label, check_sql, fix_sql in STATEMENTS:
            cursor.execute(check_sql)
            exists = cursor.fetchone()[0] > 0
            if exists:
                print(f"[skip] {label} already present")
            else:
                cursor.execute(fix_sql)
                print(f"[done] added {label}")

        cursor.execute(NULLABLE_PASSWORD_CHECK)
        is_nullable = cursor.fetchone()[0]
        if is_nullable == "YES":
            print("[skip] password_hash already nullable")
        else:
            cursor.execute(NULLABLE_PASSWORD_FIX)
            print("[done] password_hash is now nullable (for Google-only accounts)")

        cursor.execute(ROLE_ENUM_CHECK)
        role_type = cursor.fetchone()[0]
        if "'USER'" in role_type:
            print("[skip] role ENUM already includes 'USER'")
        else:
            cursor.execute(ROLE_ENUM_FIX)
            print("[done] role ENUM now includes 'USER'")

        conn.commit()
        print("\nMigration complete. No existing rows were modified.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
