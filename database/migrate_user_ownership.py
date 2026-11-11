"""
One-time migration: add per-user ownership (`user_id`) to the tables
that hold user-generated security data, for the multi-tenant data-
isolation update.

Safe to run more than once - checks INFORMATION_SCHEMA before each
change. Does NOT delete or modify any existing row's data (per the
requirement not to lose data); it only ADDS a nullable column and then
best-effort BACKFILLS it from relationships that already exist
(network_traffic.uploaded_by, url_scan_results.scanned_by). Any row
where ownership genuinely can't be determined (e.g. very early test
data with no uploader recorded) is left with user_id=NULL - it will
simply no longer appear in any user's filtered view, but the row
itself is preserved.

`compliance_rules` is NOT touched - it's the shared, static rule
catalog (title/description/recommended_action text), not user data.

Run once:

    python database/migrate_user_ownership.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.connection import get_connection

ADD_COLUMN_STATEMENTS = [
    ("threat_detections.user_id",
     "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
     "AND TABLE_NAME = 'threat_detections' AND COLUMN_NAME = 'user_id'",
     "ALTER TABLE threat_detections ADD COLUMN user_id INT NULL AFTER id, "
     "ADD CONSTRAINT fk_threat_detections_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL"),
    ("compliance_results.user_id",
     "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
     "AND TABLE_NAME = 'compliance_results' AND COLUMN_NAME = 'user_id'",
     "ALTER TABLE compliance_results ADD COLUMN user_id INT NULL AFTER id, "
     "ADD CONSTRAINT fk_compliance_results_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL"),
    ("alerts.user_id",
     "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
     "AND TABLE_NAME = 'alerts' AND COLUMN_NAME = 'user_id'",
     "ALTER TABLE alerts ADD COLUMN user_id INT NULL AFTER id, "
     "ADD CONSTRAINT fk_alerts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL"),
]

BACKFILL_STATEMENTS = [
    ("threat_detections <- network_traffic.uploaded_by",
     "UPDATE threat_detections td JOIN network_traffic nt ON td.traffic_id = nt.id "
     "SET td.user_id = nt.uploaded_by WHERE td.user_id IS NULL AND nt.uploaded_by IS NOT NULL"),
    ("compliance_results <- threat_detections.user_id",
     "UPDATE compliance_results cr JOIN threat_detections td ON cr.related_detection_id = td.id "
     "SET cr.user_id = td.user_id WHERE cr.user_id IS NULL AND td.user_id IS NOT NULL"),
    ("compliance_results <- url_scan_results.scanned_by",
     "UPDATE compliance_results cr JOIN url_scan_results u ON cr.related_url_scan_id = u.id "
     "SET cr.user_id = u.scanned_by WHERE cr.user_id IS NULL AND u.scanned_by IS NOT NULL"),
    ("alerts <- threat_detections.user_id",
     "UPDATE alerts a JOIN threat_detections td ON a.related_detection_id = td.id "
     "SET a.user_id = td.user_id WHERE a.user_id IS NULL AND td.user_id IS NOT NULL"),
    ("alerts <- url_scan_results.scanned_by",
     "UPDATE alerts a JOIN url_scan_results u ON a.related_url_scan_id = u.id "
     "SET a.user_id = u.scanned_by WHERE a.user_id IS NULL AND u.scanned_by IS NOT NULL"),
]


def main():
    conn = get_connection()
    try:
        cursor = conn.cursor()

        for label, check_sql, fix_sql in ADD_COLUMN_STATEMENTS:
            cursor.execute(check_sql)
            if cursor.fetchone()[0] > 0:
                print(f"[skip] {label} already present")
            else:
                cursor.execute(fix_sql)
                print(f"[done] added {label}")
        conn.commit()

        for label, sql in BACKFILL_STATEMENTS:
            cursor.execute(sql)
            print(f"[backfill] {label}: {cursor.rowcount} row(s) updated")
        conn.commit()

        print("\nMigration complete. No existing rows were deleted or had their content changed - "
              "only user_id was added/backfilled where determinable.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
