"""
One-way, safely-repeatable data migration: copy local XAMPP MySQL's
application data into TiDB Cloud (the same database Streamlit Cloud
uses), without ever deleting or modifying anything on the local side,
and without ever overwriting an existing TiDB row.

DRY RUN BY DEFAULT - reports exactly what would change, writes
nothing. Pass --apply (and confirm the typed prompt, or pass --yes to
skip it) to actually write.

Always connects using LOCAL_DB_* / TIDB_DB_* directly from the
environment - independent of whatever DB_PROFILE config.py is
currently resolving to, since this script needs BOTH databases open
at once, which config.py's single active profile was never designed
for (see its own DB_PROFILE docstring). This also means it never goes
through database/connection.py's pooled get_connection() - each side
gets its own plain, short-lived connection instead.

Idempotency: a small bookkeeping table, `_migration_xref`, created on
TiDB only, records (source_table, source_id) -> target_id for every
row this script has ever migrated. Re-running - including a partial
run restricted with --tables - always skips what is already recorded
there and only picks up genuinely new local rows. The leading
underscore keeps it unambiguously a tooling table, never confused with
an application table and never touched by database/models.py.

Usage:
    python database/migrate_local_data_to_tidb.py                        # dry run, all tables
    python database/migrate_local_data_to_tidb.py --apply                 # writes, after a typed "yes"
    python database/migrate_local_data_to_tidb.py --apply --yes           # skip the typed confirmation
    python database/migrate_local_data_to_tidb.py --tables users,alerts   # restrict to a subset (still correct order)
    python database/migrate_local_data_to_tidb.py --limit 50              # cap rows considered per table (smoke test)
    python database/migrate_local_data_to_tidb.py --include-reports --include-rate-limits --apply
    python database/migrate_local_data_to_tidb.py --verbose               # per-row skip reasons
"""
import argparse
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mysql.connector
from dotenv import load_dotenv

load_dotenv()

TABLE_ORDER = [
    "users", "network_traffic", "url_scan_results", "threat_detections",
    "compliance_results", "alerts", "audit_logs",
]
OPT_IN_TABLES = ["rate_limit_counters", "reports"]
INSERT_BATCH_SIZE = 2000


# ---------------------------------------------------------------
# Connections - deliberately independent of config.py/DB_PROFILE
# ---------------------------------------------------------------

def _env(prefix: str, name: str, default: str = "") -> str:
    return os.environ.get(f"{prefix}_DB_{name}", default)


def _ssl_kwargs(prefix: str) -> dict:
    mode = _env(prefix, "SSL_MODE", "DISABLED").strip().upper()
    if mode == "DISABLED":
        return {"ssl_disabled": True}
    kwargs = {"ssl_disabled": False}
    ca = _env(prefix, "SSL_CA", "").strip()
    if mode in ("VERIFY_CA", "VERIFY_IDENTITY"):
        if not ca:
            raise RuntimeError(f"{prefix}_DB_SSL_MODE={mode} requires {prefix}_DB_SSL_CA to be set.")
        kwargs["ssl_ca"] = ca
        kwargs["ssl_verify_cert"] = True
        if mode == "VERIFY_IDENTITY":
            kwargs["ssl_verify_identity"] = True
    return kwargs


def connect(prefix: str, read_only: bool = False):
    host = _env(prefix, "HOST", "localhost" if prefix == "LOCAL" else "")
    port = int(_env(prefix, "PORT", "3306"))
    user = _env(prefix, "USER", "root" if prefix == "LOCAL" else "")
    password = _env(prefix, "PASSWORD", "")
    database = _env(prefix, "NAME", "ai_cyberguard")
    if not host or not user:
        raise RuntimeError(
            f"{prefix}_DB_HOST/{prefix}_DB_USER are not set - fill in the {prefix}_DB_* "
            "block in .env before running this script."
        )
    print(f"  {prefix}: connecting to {user}@{host}:{port}/{database} "
          f"(ssl={_env(prefix, 'SSL_MODE', 'DISABLED')})")
    conn = mysql.connector.connect(
        host=host, port=port, user=user, password=password, database=database,
        **_ssl_kwargs(prefix),
    )
    if read_only:
        cur = conn.cursor()
        cur.execute("SET SESSION TRANSACTION READ ONLY")
        cur.close()
    return conn


# ---------------------------------------------------------------
# Migration cross-reference (idempotency)
# ---------------------------------------------------------------

def ensure_xref_table(tidb_conn, apply_: bool):
    cur = tidb_conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '_migration_xref'"
    )
    exists = cur.fetchone()[0] > 0
    if exists:
        return
    if not apply_:
        return  # dry run: treat "doesn't exist yet" as "nothing migrated yet", below
    cur.execute(
        "CREATE TABLE _migration_xref ("
        "  source_table VARCHAR(64) NOT NULL,"
        "  source_id INT NOT NULL,"
        "  target_id INT NULL,"
        "  migrated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (source_table, source_id)"
        ")"
    )
    tidb_conn.commit()


def load_xref(tidb_conn, table: str) -> dict:
    """{source_id: target_id} for everything already migrated for
    `table` - empty if the xref table doesn't exist yet (first run,
    dry-run-only so far)."""
    cur = tidb_conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '_migration_xref'"
    )
    if cur.fetchone()[0] == 0:
        return {}
    cur.execute("SELECT source_id, target_id FROM _migration_xref WHERE source_table = %s", (table,))
    return {row[0]: row[1] for row in cur.fetchall()}


def record_xref(cur, table: str, pairs: list[tuple[int, int | None]]):
    if not pairs:
        return
    cur.executemany(
        "INSERT INTO _migration_xref (source_table, source_id, target_id) VALUES (%s, %s, %s) "
        "ON DUPLICATE KEY UPDATE target_id = VALUES(target_id)",
        [(table, sid, tid) for sid, tid in pairs],
    )


# ---------------------------------------------------------------
# Report
# ---------------------------------------------------------------

class TableReport:
    def __init__(self, name: str):
        self.name = name
        self.considered = 0
        self.already_present = 0
        self.migrated = 0
        self.skipped_unresolved = 0
        self.before = None
        self.after = None

    def line(self) -> str:
        after = "projected" if self.after is None else str(self.after)
        return (
            f"{self.name:22s} considered={self.considered:<7} already={self.already_present:<7} "
            f"migrated={self.migrated:<7} skipped={self.skipped_unresolved:<7} "
            f"before={self.before} after={after}"
        )


def row_count(conn, table: str, limit: int | None = None) -> int:
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    n = cur.fetchone()[0]
    return min(n, limit) if limit else n


# ---------------------------------------------------------------
# Table migrations
# ---------------------------------------------------------------

def migrate_users(local_conn, tidb_conn, apply_: bool, limit, verbose) -> tuple[TableReport, dict]:
    rep = TableReport("users")
    id_map: dict[int, int] = {}
    rep.before = row_count(tidb_conn, "users")

    lcur = local_conn.cursor(dictionary=True)
    lcur.execute(
        "SELECT id, username, email, password_hash, role, auth_provider, full_name, "
        "is_active, last_login, created_at FROM users ORDER BY id"
        + (f" LIMIT {int(limit)}" if limit else "")
    )
    local_rows = lcur.fetchall()
    rep.considered = len(local_rows)

    tcur = tidb_conn.cursor()
    inserts = []
    for r in local_rows:
        tcur.execute(
            "SELECT id FROM users WHERE username = %s OR (email IS NOT NULL AND email = %s) LIMIT 1",
            (r["username"], r["email"]),
        )
        hit = tcur.fetchone()
        if hit:
            id_map[r["id"]] = hit[0]
            rep.already_present += 1
            if verbose:
                print(f"    [users] {r['username']}: matched existing TiDB id={hit[0]}")
            continue
        inserts.append(r)

    if apply_:
        for r in inserts:
            tcur.execute(
                "INSERT INTO users (username, email, password_hash, role, auth_provider, "
                "full_name, is_active, last_login, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (r["username"], r["email"], r["password_hash"], r["role"], r["auth_provider"],
                 r["full_name"], r["is_active"], r["last_login"], r["created_at"]),
            )
            id_map[r["id"]] = tcur.lastrowid
        record_xref(tcur, "users", [(sid, tid) for sid, tid in id_map.items()])
        tidb_conn.commit()
    else:
        # Dry run: we don't know the real future id, but we still need
        # a placeholder so downstream tables can report accurate
        # "would migrate" counts without crashing on a missing key.
        for r in inserts:
            id_map[r["id"]] = -1

    rep.migrated = len(inserts)
    rep.after = rep.before + rep.migrated if apply_ else None
    return rep, id_map


def migrate_simple_table(
    local_conn, tidb_conn, apply_: bool, limit, verbose,
    table: str, select_cols: list[str], insert_cols: list[str],
    fk_remap: dict[str, dict],
) -> tuple[TableReport, dict]:
    """Single-row-insert tables with no natural dedup key - users-style
    xref is the only dedup mechanism. `fk_remap` maps a column name to
    an already-built {local_id: tidb_id} map for that FK."""
    rep = TableReport(table)
    id_map: dict[int, int] = {}
    rep.before = row_count(tidb_conn, table)
    already = load_xref(tidb_conn, table)

    lcur = local_conn.cursor(dictionary=True)
    lcur.execute(
        f"SELECT {', '.join(select_cols)} FROM {table} ORDER BY id" + (f" LIMIT {int(limit)}" if limit else "")
    )
    local_rows = lcur.fetchall()
    rep.considered = len(local_rows)

    tcur = tidb_conn.cursor()
    new_pairs = []
    for r in local_rows:
        if r["id"] in already:
            id_map[r["id"]] = already[r["id"]]
            rep.already_present += 1
            continue

        values = []
        unresolved = False
        for col in insert_cols:
            v = r[col]
            if col in fk_remap and v is not None:
                mapped = fk_remap[col].get(v)
                if mapped is None:
                    unresolved = True
                    break
                v = mapped
            values.append(v)
        if unresolved:
            rep.skipped_unresolved += 1
            if verbose:
                print(f"    [{table}] source id={r['id']}: skipped, unresolved FK")
            continue

        if apply_:
            placeholders = ", ".join(["%s"] * len(insert_cols))
            tcur.execute(f"INSERT INTO {table} ({', '.join(insert_cols)}) VALUES ({placeholders})", values)
            new_id = tcur.lastrowid
        else:
            new_id = -1
        id_map[r["id"]] = new_id
        new_pairs.append((r["id"], new_id if apply_ else None))
        rep.migrated += 1

    if apply_:
        record_xref(tcur, table, new_pairs)
        tidb_conn.commit()
    rep.after = rep.before + rep.migrated if apply_ else None
    return rep, id_map


def migrate_threat_detections(local_conn, tidb_conn, apply_: bool, limit, verbose,
                               traffic_id_map: dict, user_id_map: dict) -> tuple[TableReport, dict]:
    """Grouped per local traffic_id so the real new ids can be read
    back with one ORDER BY id SELECT per group afterwards - the same
    technique as the application's own insert_threat_detections_bulk()
    fix, which sidesteps relying on contiguous auto-increment values
    (not guaranteed on TiDB) entirely."""
    rep = TableReport("threat_detections")
    id_map: dict[int, int] = {}
    rep.before = row_count(tidb_conn, "threat_detections")
    already = load_xref(tidb_conn, "threat_detections")

    lcur = local_conn.cursor(dictionary=True)
    lcur.execute(
        "SELECT id, user_id, traffic_id, record_index, prediction, attack_type, confidence, "
        "risk_score, severity, model_used, detected_at FROM threat_detections ORDER BY traffic_id, id"
        + (f" LIMIT {int(limit)}" if limit else "")
    )
    local_rows = lcur.fetchall()
    rep.considered = len(local_rows)

    pending = [r for r in local_rows if r["id"] not in already]
    rep.already_present = len(local_rows) - len(pending)
    for r in local_rows:
        if r["id"] in already:
            id_map[r["id"]] = already[r["id"]]

    tcur = tidb_conn.cursor()
    insert_sql = (
        "INSERT INTO threat_detections (user_id, traffic_id, record_index, prediction, "
        "attack_type, confidence, risk_score, severity, model_used, detected_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    )
    new_pairs = []

    # Group pending rows by their LOCAL traffic_id, preserving order.
    groups: dict[int | None, list] = {}
    for r in pending:
        groups.setdefault(r["traffic_id"], []).append(r)

    for local_traffic_id, group_rows in groups.items():
        target_traffic_id = None
        if local_traffic_id is not None:
            target_traffic_id = traffic_id_map.get(local_traffic_id)
            # None means truly unresolved (e.g. network_traffic wasn't
            # processed this run - a --tables subset). -1 is the
            # dry-run placeholder for "would be migrated" and is NOT
            # an error - only guard the real INSERT path below against
            # it ever being used as a literal id.
            if target_traffic_id is None:
                rep.skipped_unresolved += len(group_rows)
                if verbose:
                    print(f"    [threat_detections] traffic_id={local_traffic_id}: "
                          f"skipped {len(group_rows)} row(s), unresolved traffic_id")
                continue

        if not apply_:
            rep.migrated += len(group_rows)
            for r in group_rows:
                id_map[r["id"]] = -1
            continue

        rows_to_insert = [
            (user_id_map.get(r["user_id"]) if r["user_id"] is not None else None,
             target_traffic_id, r["record_index"], r["prediction"], r["attack_type"],
             r["confidence"], r["risk_score"], r["severity"], r["model_used"], r["detected_at"])
            for r in group_rows
        ]
        for start in range(0, len(rows_to_insert), INSERT_BATCH_SIZE):
            tcur.executemany(insert_sql, rows_to_insert[start:start + INSERT_BATCH_SIZE])

        if target_traffic_id is not None:
            tcur.execute(
                "SELECT id FROM threat_detections WHERE traffic_id = %s ORDER BY id",
                (target_traffic_id,),
            )
            new_ids = [row[0] for row in tcur.fetchall()]
            # Only the ids for THIS group - the tail of that list, same
            # length as what we just inserted for this traffic_id.
            new_ids = new_ids[-len(group_rows):]
        else:
            # traffic_id IS NULL locally too - lastrowid is reliable
            # here since these are inserted one at a time below instead.
            new_ids = []
            for row in rows_to_insert:
                tcur.execute(insert_sql, row)
                new_ids.append(tcur.lastrowid)

        for r, new_id in zip(group_rows, new_ids):
            id_map[r["id"]] = new_id
            new_pairs.append((r["id"], new_id))
        rep.migrated += len(group_rows)

    if apply_:
        record_xref(tcur, "threat_detections", new_pairs)
        tidb_conn.commit()
    rep.after = rep.before + rep.migrated if apply_ else None
    return rep, id_map


def build_rule_id_map(local_conn, tidb_conn, apply_: bool) -> dict[int, int]:
    """compliance_rules.id differs between the two databases even
    though both seed the SAME rule_codes (each database's own
    auto-increment order is independent) - join on rule_code, never
    copy the numeric id directly.

    In dry-run mode, seed_compliance_rules_on_tidb() hasn't actually
    inserted anything yet (nothing has, by definition), so a rule_code
    genuinely missing from the target right now would otherwise make
    every compliance_results row relying on it look "unresolved" even
    though --apply would seed it moments before migrating results.
    Map it to the same -1 placeholder convention used elsewhere for
    "will exist after --apply", since no real id is ever used in a
    dry run anyway."""
    lcur = local_conn.cursor()
    lcur.execute("SELECT id, rule_code FROM compliance_rules")
    local_by_code = {code: rid for rid, code in lcur.fetchall()}

    tcur = tidb_conn.cursor()
    tcur.execute("SELECT id, rule_code FROM compliance_rules")
    tidb_by_code = {code: rid for rid, code in tcur.fetchall()}

    result = {}
    for code, local_id in local_by_code.items():
        if code in tidb_by_code:
            result[local_id] = tidb_by_code[code]
        elif not apply_:
            result[local_id] = -1
    return result


def migrate_alerts(local_conn, tidb_conn, apply_: bool, limit, verbose,
                    user_id_map: dict, detection_id_map: dict, scan_id_map: dict) -> tuple[TableReport, dict]:
    """threat_ref is NEVER copied from source - it's derived from each
    database's own independent id sequence (THR-{id:04d}), so a local
    THR-0021 and an unrelated existing TiDB THR-0021 only coincidentally
    share a label. Regenerated via the same two-step insert-then-update
    pattern database/models.py's create_alert() already uses."""
    rep = TableReport("alerts")
    id_map: dict[int, int] = {}
    rep.before = row_count(tidb_conn, "alerts")
    already = load_xref(tidb_conn, "alerts")

    lcur = local_conn.cursor(dictionary=True)
    lcur.execute(
        "SELECT id, user_id, threat_ref, event_type, threat_type, severity, risk_score, "
        "confidence, related_detection_id, related_url_scan_id, compliance_summary, "
        "recommended_action, status, created_at, updated_at FROM alerts ORDER BY id"
        + (f" LIMIT {int(limit)}" if limit else "")
    )
    local_rows = lcur.fetchall()
    rep.considered = len(local_rows)

    tcur = tidb_conn.cursor()
    new_pairs = []
    for r in local_rows:
        if r["id"] in already:
            id_map[r["id"]] = already[r["id"]]
            rep.already_present += 1
            continue

        new_user_id = user_id_map.get(r["user_id"]) if r["user_id"] is not None else None
        new_detection_id = None
        if r["related_detection_id"] is not None:
            new_detection_id = detection_id_map.get(r["related_detection_id"])
            if new_detection_id is None:
                rep.skipped_unresolved += 1
                if verbose:
                    print(f"    [alerts] source id={r['id']}: skipped, unresolved related_detection_id")
                continue
        new_scan_id = None
        if r["related_url_scan_id"] is not None:
            new_scan_id = scan_id_map.get(r["related_url_scan_id"])
            if new_scan_id is None:
                rep.skipped_unresolved += 1
                if verbose:
                    print(f"    [alerts] source id={r['id']}: skipped, unresolved related_url_scan_id")
                continue

        if not apply_:
            id_map[r["id"]] = -1
            rep.migrated += 1
            continue

        placeholder_ref = f"PENDING-{uuid.uuid4().hex[:12]}"
        tcur.execute(
            "INSERT INTO alerts (user_id, threat_ref, event_type, threat_type, severity, "
            "risk_score, confidence, related_detection_id, related_url_scan_id, "
            "compliance_summary, recommended_action, status, created_at, updated_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (new_user_id, placeholder_ref, r["event_type"], r["threat_type"], r["severity"],
             r["risk_score"], r["confidence"], new_detection_id, new_scan_id,
             r["compliance_summary"], r["recommended_action"], r["status"],
             r["created_at"], r["updated_at"]),
        )
        new_id = tcur.lastrowid
        tcur.execute("UPDATE alerts SET threat_ref = %s WHERE id = %s", (f"THR-{new_id:04d}", new_id))
        id_map[r["id"]] = new_id
        new_pairs.append((r["id"], new_id))
        rep.migrated += 1

    if apply_:
        record_xref(tcur, "alerts", new_pairs)
        tidb_conn.commit()
    rep.after = rep.before + rep.migrated if apply_ else None
    return rep, id_map


def migrate_compliance_results(local_conn, tidb_conn, apply_: bool, limit, verbose,
                                user_id_map: dict, detection_id_map: dict, scan_id_map: dict,
                                rule_id_map: dict) -> tuple[TableReport, dict]:
    rep = TableReport("compliance_results")
    id_map: dict[int, int] = {}
    rep.before = row_count(tidb_conn, "compliance_results")
    already = load_xref(tidb_conn, "compliance_results")

    lcur = local_conn.cursor(dictionary=True)
    lcur.execute(
        "SELECT id, user_id, rule_id, related_detection_id, related_url_scan_id, status, "
        "reason, evidence, recommended_action, checked_at FROM compliance_results ORDER BY id"
        + (f" LIMIT {int(limit)}" if limit else "")
    )
    local_rows = lcur.fetchall()
    rep.considered = len(local_rows)

    tcur = tidb_conn.cursor()
    new_pairs = []
    for r in local_rows:
        if r["id"] in already:
            id_map[r["id"]] = already[r["id"]]
            rep.already_present += 1
            continue

        new_rule_id = rule_id_map.get(r["rule_id"])
        if new_rule_id is None:
            rep.skipped_unresolved += 1
            if verbose:
                print(f"    [compliance_results] source id={r['id']}: skipped, unresolved rule_code")
            continue

        new_user_id = user_id_map.get(r["user_id"]) if r["user_id"] is not None else None
        new_detection_id = (detection_id_map.get(r["related_detection_id"])
                             if r["related_detection_id"] is not None else None)
        new_scan_id = (scan_id_map.get(r["related_url_scan_id"])
                        if r["related_url_scan_id"] is not None else None)
        # A reference that existed locally but can't be resolved (e.g.
        # a --tables subset run skipped its source table) degrades to
        # NULL rather than blocking the whole row or guessing an id.
        if r["related_detection_id"] is not None and new_detection_id is None and verbose:
            print(f"    [compliance_results] source id={r['id']}: related_detection_id -> NULL (unresolved)")
        if r["related_url_scan_id"] is not None and new_scan_id is None and verbose:
            print(f"    [compliance_results] source id={r['id']}: related_url_scan_id -> NULL (unresolved)")

        if not apply_:
            id_map[r["id"]] = -1
            rep.migrated += 1
            continue

        tcur.execute(
            "INSERT INTO compliance_results (user_id, rule_id, related_detection_id, "
            "related_url_scan_id, status, reason, evidence, recommended_action, checked_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (new_user_id, new_rule_id, new_detection_id, new_scan_id, r["status"],
             r["reason"], r["evidence"], r["recommended_action"], r["checked_at"]),
        )
        id_map[r["id"]] = tcur.lastrowid
        new_pairs.append((r["id"], tcur.lastrowid))
        rep.migrated += 1

    if apply_:
        record_xref(tcur, "compliance_results", new_pairs)
        tidb_conn.commit()
    rep.after = rep.before + rep.migrated if apply_ else None
    return rep, id_map


def migrate_audit_logs(local_conn, tidb_conn, apply_: bool, limit, verbose) -> TableReport:
    rep = TableReport("audit_logs")
    rep.before = row_count(tidb_conn, "audit_logs")
    already = load_xref(tidb_conn, "audit_logs")

    lcur = local_conn.cursor(dictionary=True)
    lcur.execute(
        "SELECT id, username, action, event_type, description, timestamp FROM audit_logs ORDER BY id"
        + (f" LIMIT {int(limit)}" if limit else "")
    )
    local_rows = lcur.fetchall()
    rep.considered = len(local_rows)
    pending = [r for r in local_rows if r["id"] not in already]
    rep.already_present = len(local_rows) - len(pending)
    rep.migrated = len(pending)

    if apply_ and pending:
        tcur = tidb_conn.cursor()
        insert_sql = (
            "INSERT INTO audit_logs (username, action, event_type, description, timestamp) "
            "VALUES (%s,%s,%s,%s,%s)"
        )
        rows = [(r["username"], r["action"], r["event_type"], r["description"], r["timestamp"]) for r in pending]
        for start in range(0, len(rows), INSERT_BATCH_SIZE):
            tcur.executemany(insert_sql, rows[start:start + INSERT_BATCH_SIZE])
        # audit_logs has no downstream FK references, so target_id isn't
        # load-bearing - record NULL, dedup-only.
        record_xref(tcur, "audit_logs", [(r["id"], None) for r in pending])
        tidb_conn.commit()

    rep.after = rep.before + rep.migrated if apply_ else None
    return rep


def seed_compliance_rules_on_tidb(tidb_conn, apply_: bool):
    """compliance_rules is never migrated row-by-row - both databases
    already self-seed it idempotently (app_pages/compliance.py calls
    database.models.seed_compliance_rules() on every page load). This
    just runs that exact same idempotent upsert directly against this
    script's own TiDB connection, so a viva rehearsal doesn't depend
    on remembering to open the Compliance page first."""
    from compliance.compliance_engine import ALL_RULE_CATALOGS
    rule_defs = [rule for catalog in ALL_RULE_CATALOGS for rule in catalog]
    if not apply_:
        print(f"  compliance_rules: {len(rule_defs)} rule(s) in the app's own catalog "
              f"(would upsert on --apply; not migrated from local, self-seeded identically on both sides)")
        return
    cur = tidb_conn.cursor()
    cur.executemany(
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
    tidb_conn.commit()
    print(f"  compliance_rules: upserted {len(rule_defs)} rule(s)")


# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="Actually write to TiDB (default: dry run only).")
    parser.add_argument("--yes", action="store_true", help="Skip the typed 'yes' confirmation before --apply writes.")
    parser.add_argument("--tables", type=str, default=None,
                         help="Comma-separated subset of tables to process (still in correct dependency order).")
    parser.add_argument("--limit", type=int, default=None, help="Cap rows considered per table (smoke test).")
    parser.add_argument("--include-reports", action="store_true", help="Also migrate reports metadata rows.")
    parser.add_argument("--include-rate-limits", action="store_true",
                         help="Also migrate rate_limit_counters (NOT recommended - ephemeral security-control state).")
    parser.add_argument("--verbose", action="store_true", help="Print per-row skip reasons.")
    args = parser.parse_args()

    wanted = set(args.tables.split(",")) if args.tables else None
    tables = [t for t in TABLE_ORDER if wanted is None or t in wanted]
    if args.include_reports or (wanted and "reports" in wanted):
        tables.append("reports")
    if args.include_rate_limits or (wanted and "rate_limit_counters" in wanted):
        tables.append("rate_limit_counters")

    print(f"{'APPLYING CHANGES' if args.apply else 'DRY RUN (no writes)'} - tables: {', '.join(tables)}\n")
    print("Connecting:")
    local_conn = connect("LOCAL", read_only=True)
    tidb_conn = connect("TIDB", read_only=False)
    print()

    if args.apply and not args.yes:
        confirm = input(
            f"This will WRITE real rows into your TiDB database ({_env('TIDB', 'HOST')}). "
            f"Type 'yes' to continue: "
        )
        if confirm.strip().lower() != "yes":
            print("Aborted - nothing was written.")
            return

    ensure_xref_table(tidb_conn, args.apply)

    reports: list[TableReport] = []
    user_id_map: dict = {}
    traffic_id_map: dict = {}
    scan_id_map: dict = {}
    detection_id_map: dict = {}

    if "users" in tables:
        rep, user_id_map = migrate_users(local_conn, tidb_conn, args.apply, args.limit, args.verbose)
        reports.append(rep)

    if "network_traffic" in tables:
        rep, traffic_id_map = migrate_simple_table(
            local_conn, tidb_conn, args.apply, args.limit, args.verbose,
            table="network_traffic",
            select_cols=["id", "dataset_name", "uploaded_by", "row_count", "column_count",
                         "uploaded_at", "status", "storage_path"],
            insert_cols=["dataset_name", "uploaded_by", "row_count", "column_count",
                         "uploaded_at", "status", "storage_path"],
            fk_remap={"uploaded_by": user_id_map},
        )
        reports.append(rep)

    if "url_scan_results" in tables:
        rep, scan_id_map = migrate_simple_table(
            local_conn, tidb_conn, args.apply, args.limit, args.verbose,
            table="url_scan_results",
            select_cols=["id", "url", "scanned_by", "scan_timestamp", "scan_status", "threat_category",
                         "detection_count", "total_engines", "risk_score", "risk_level", "source",
                         "analysis_reference"],
            insert_cols=["url", "scanned_by", "scan_timestamp", "scan_status", "threat_category",
                         "detection_count", "total_engines", "risk_score", "risk_level", "source",
                         "analysis_reference"],
            fk_remap={"scanned_by": user_id_map},
        )
        reports.append(rep)

    if "threat_detections" in tables:
        rep, detection_id_map = migrate_threat_detections(
            local_conn, tidb_conn, args.apply, args.limit, args.verbose, traffic_id_map, user_id_map,
        )
        reports.append(rep)

    print("\ncompliance_rules (reference catalog, self-seeded on both sides - not migrated row-by-row):")
    seed_compliance_rules_on_tidb(tidb_conn, args.apply)
    rule_id_map = build_rule_id_map(local_conn, tidb_conn, args.apply)

    if "compliance_results" in tables:
        rep, _ = migrate_compliance_results(
            local_conn, tidb_conn, args.apply, args.limit, args.verbose,
            user_id_map, detection_id_map, scan_id_map, rule_id_map,
        )
        reports.append(rep)

    if "alerts" in tables:
        rep, _ = migrate_alerts(
            local_conn, tidb_conn, args.apply, args.limit, args.verbose,
            user_id_map, detection_id_map, scan_id_map,
        )
        reports.append(rep)

    if "audit_logs" in tables:
        reports.append(migrate_audit_logs(local_conn, tidb_conn, args.apply, args.limit, args.verbose))

    if "reports" in tables:
        rep, _ = migrate_simple_table(
            local_conn, tidb_conn, args.apply, args.limit, args.verbose,
            table="reports",
            select_cols=["id", "generated_by", "report_type", "file_format", "file_path", "generated_at"],
            insert_cols=["generated_by", "report_type", "file_format", "file_path", "generated_at"],
            fk_remap={"generated_by": user_id_map},
        )
        print("  NOTE: report file bytes are not migrated by this script (reports.file_path is "
              "metadata only today) - this copies the metadata row alone.")
        reports.append(rep)

    if "rate_limit_counters" in tables:
        rep, _ = migrate_simple_table(
            local_conn, tidb_conn, args.apply, args.limit, args.verbose,
            table="rate_limit_counters",
            select_cols=["id", "scope", "identifier", "attempt_count", "window_start",
                         "last_attempt_at", "locked_until"],
            insert_cols=["scope", "identifier", "attempt_count", "window_start",
                         "last_attempt_at", "locked_until"],
            fk_remap={},
        )
        reports.append(rep)

    local_conn.close()
    tidb_conn.close()

    print("\n" + "=" * 100)
    print(f"{'APPLY' if args.apply else 'DRY RUN'} SUMMARY")
    print("=" * 100)
    for rep in reports:
        print(rep.line())
    print("=" * 100)
    if not args.apply:
        print("\nNothing was written. Re-run with --apply (after reviewing the above) to migrate for real.")


if __name__ == "__main__":
    main()
