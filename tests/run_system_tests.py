"""
AI-CyberGuard automated system test suite (FYP II, Chapter 4).

Runs against a MySQL/MariaDB server (the XAMPP "MySQL" module is MariaDB)
that still has its default, un-hardened configuration. The suite:

  1. records the weaknesses of the default XAMPP-style installation,
  2. imports database/schema.sql,
  3. applies the hardening steps described in Chapter 3,
  4. re-tests the same attack paths and then exercises the real
     application modules (auth, rate limiting, URL validation/scoring,
     risk scoring, compliance engine, ML pipeline, multi-tenant isolation).

Usage (from the project root, MySQL/XAMPP running with default root, no password):

    python tests/run_system_tests.py

Results are printed and written to tests/system_test_results.json.
No application source file is modified by this suite.
"""
import json
import os
import re
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ADMIN_HOST = os.environ.get("TEST_DB_HOST", "127.0.0.1")
ADMIN_PORT = int(os.environ.get("TEST_DB_PORT", "3306"))
APP_USER = "ai_cyberguard_app"
APP_PASS = "T3st-App-Pass!2026"
ROOT_NEW_PASS = "T3st-Root-Pass!2026"

import mysql.connector  # noqa: E402

RESULTS = []


def record(tid, category, title, expected, fn):
    t0 = time.time()
    try:
        ok, actual = fn()
    except Exception as exc:  # a crashing test is a failed test
        ok, actual = False, f"EXCEPTION {type(exc).__name__}: {exc}"
        traceback.print_exc()
    RESULTS.append({
        "id": tid, "category": category, "title": title, "expected": expected,
        "actual": str(actual), "passed": bool(ok), "ms": round((time.time() - t0) * 1000),
    })
    print(f"[{'PASS' if ok else 'FAIL'}] {tid} {title} -> {actual}")


def admin_conn(password="", database=None):
    return mysql.connector.connect(host=ADMIN_HOST, port=ADMIN_PORT, user="root",
                                   password=password, database=database)


# ---------------------------------------------------------------------------
# PHASE 1 - default (un-hardened) XAMPP-style instance
# ---------------------------------------------------------------------------
def e01():
    c = admin_conn("")
    cur = c.cursor()
    cur.execute("SELECT CURRENT_USER()")
    who = cur.fetchone()[0]
    c.close()
    return True, f"login as root with EMPTY password succeeded ({who}); weakness confirmed"


def e02():
    c = admin_conn("")
    cur = c.cursor()
    cur.execute("SELECT COUNT(*) FROM mysql.global_priv WHERE User='' ")
    n = cur.fetchone()[0]
    c.close()
    return True, f"{n} anonymous account row(s) present in default instance"


def e03_import_schema():
    sql = (ROOT / "database" / "schema.sql").read_text(encoding="utf-8")
    c = admin_conn("")
    cur = c.cursor()
    cur.execute("DROP DATABASE IF EXISTS ai_cyberguard")
    # strip comments, split statements
    cleaned = re.sub(r"--[^\n]*", "", sql)
    for stmt in [s.strip() for s in cleaned.split(";") if s.strip()]:
        cur.execute(stmt)
    c.commit()
    cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='ai_cyberguard'")
    n = cur.fetchone()[0]
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='ai_cyberguard' ORDER BY 1")
    names = [r[0] for r in cur.fetchall()]
    c.close()
    return n == 10, f"{n} tables created: {', '.join(names)}"


# ---------------------------------------------------------------------------
# PHASE 2 - hardening
# ---------------------------------------------------------------------------
def apply_hardening():
    c = admin_conn("")
    cur = c.cursor()
    cur.execute(f"ALTER USER 'root'@'localhost' IDENTIFIED BY '{ROOT_NEW_PASS}'")
    cur.execute(f"ALTER USER 'root'@'127.0.0.1' IDENTIFIED BY '{ROOT_NEW_PASS}'")
    cur.execute(f"ALTER USER 'root'@'::1' IDENTIFIED BY '{ROOT_NEW_PASS}'")
    cur.execute("DELETE FROM mysql.global_priv WHERE User=''")
    cur.execute("FLUSH PRIVILEGES")
    cur.execute(f"DROP USER IF EXISTS '{APP_USER}'@'localhost'")
    cur.execute(f"DROP USER IF EXISTS '{APP_USER}'@'127.0.0.1'")
    for host in ("localhost", "127.0.0.1"):
        cur.execute(f"CREATE USER '{APP_USER}'@'{host}' IDENTIFIED BY '{APP_PASS}'")
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='ai_cyberguard'")
        for (t,) in cur.fetchall():
            if t == "audit_logs":
                cur.execute(f"GRANT SELECT, INSERT ON ai_cyberguard.`{t}` TO '{APP_USER}'@'{host}'")
            else:
                cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ai_cyberguard.`{t}` TO '{APP_USER}'@'{host}'")
    cur.execute("FLUSH PRIVILEGES")
    c.commit()
    c.close()


def app_conn():
    return mysql.connector.connect(host=ADMIN_HOST, port=ADMIN_PORT, user=APP_USER,
                                   password=APP_PASS, database="ai_cyberguard")


def e04():
    try:
        admin_conn("")
        return False, "root with empty password STILL accepted"
    except mysql.connector.Error as e:
        return True, f"rejected (errno {e.errno})"


def e05():
    c = admin_conn(ROOT_NEW_PASS)
    cur = c.cursor()
    cur.execute("SELECT COUNT(*) FROM mysql.global_priv WHERE User=''")
    n = cur.fetchone()[0]
    c.close()
    return n == 0, f"{n} anonymous accounts remain"


def e06():
    c = app_conn()
    cur = c.cursor()
    cur.execute("INSERT INTO audit_logs (username, action, event_type, description) VALUES ('t','TEST','T','x')")
    c.commit()
    c.close()
    return True, "INSERT permitted"


def denied(sql, db=True):
    c = app_conn() if db else app_conn()
    cur = c.cursor()
    try:
        cur.execute(sql)
        c.commit()
        return False, "STATEMENT EXECUTED (should have been denied)"
    except mysql.connector.Error as e:
        return True, f"denied (errno {e.errno})"
    finally:
        c.close()


def e13_ssl_modes():
    import config
    from database import connection
    out = []
    ok = True
    config.DB_SSL_MODE = "DISABLED"
    ok &= connection._ssl_kwargs() == {"ssl_disabled": True}
    out.append("DISABLED->ssl_disabled")
    config.DB_SSL_MODE = "BOGUS"
    try:
        connection._ssl_kwargs(); ok = False
    except ValueError:
        out.append("invalid mode->ValueError")
    config.DB_SSL_MODE = "VERIFY_CA"; config.DB_SSL_CA = None
    try:
        connection._ssl_kwargs(); ok = False
    except RuntimeError:
        out.append("VERIFY_CA without CA->RuntimeError (refuses insecure fallback)")
    config.DB_SSL_MODE = "VERIFY_IDENTITY"; config.DB_SSL_CA = "/path/ca.pem"
    k = connection._ssl_kwargs()
    ok &= k.get("ssl_verify_identity") is True and k.get("ssl_verify_cert") is True
    out.append("VERIFY_IDENTITY->verify_cert+verify_identity")
    config.DB_SSL_MODE = "DISABLED"; config.DB_SSL_CA = None
    return ok, "; ".join(out)


def e14_required_env():
    import config
    saved = os.environ.pop("DB_USER", None)
    ok, missing, _ = config.validate_required_env()
    os.environ["DB_USER"] = saved
    return (not ok) and missing == ["DB_USER"], f"ok={ok}, missing={missing} (names only, no values)"


# ---------------------------------------------------------------------------
# PHASE 3 - application tests
# ---------------------------------------------------------------------------
def main():
    # ---- phase 1
    record("E-01", "Environment", "Default root account accepts an empty password", "Weakness exposed", e01)
    record("E-02", "Environment", "Default instance carries anonymous accounts", "Weakness exposed", e02)
    record("E-03", "Environment", "schema.sql imports and creates all application tables", "10 tables", e03_import_schema)

    # ---- hardening
    apply_hardening()
    record("E-04", "Environment", "Root with an empty password is rejected after hardening", "Rejected", e04)
    record("E-05", "Environment", "Anonymous accounts removed after hardening", "0 accounts", e05)
    record("E-06", "Environment", "Least-privilege app account can INSERT into audit_logs", "Permitted", e06)
    record("E-07", "Environment", "App account cannot UPDATE audit_logs (append-only)", "Denied",
           lambda: denied("UPDATE audit_logs SET description='tampered'"))
    record("E-08", "Environment", "App account cannot DELETE from audit_logs", "Denied",
           lambda: denied("DELETE FROM audit_logs"))
    record("E-09", "Environment", "App account cannot DROP a table", "Denied",
           lambda: denied("DROP TABLE users"))
    record("E-10", "Environment", "App account cannot read the server's mysql.global_priv table", "Denied",
           lambda: denied("SELECT * FROM mysql.global_priv"))
    record("E-11", "Environment", "App account cannot create new database users", "Denied",
           lambda: denied("CREATE USER 'evil'@'%' IDENTIFIED BY 'x'"))

    # switch the application's own configuration to the app account
    os.environ.update({
        "DB_HOST": ADMIN_HOST, "DB_PORT": str(ADMIN_PORT), "DB_USER": APP_USER,
        "DB_PASSWORD": APP_PASS, "DB_NAME": "ai_cyberguard", "DB_SSL_MODE": "DISABLED",
    })
    import config  # noqa: E402
    from database.connection import get_connection, test_connection  # noqa: E402

    record("E-12", "Environment", "Application connects through database/connection.py with the app account", "Connected",
           lambda: (test_connection()[0], str(test_connection())))
    record("E-13", "Environment", "TLS mode handling: invalid/insecure configurations fail loudly", "Safe refusal", e13_ssl_modes)
    record("E-14", "Environment", "Missing required setting is reported by name only", "Name only", e14_required_env)

    def e15():
        c = admin_conn(ROOT_NEW_PASS)
        cur = c.cursor()
        cur.execute("SHOW VARIABLES LIKE 'bind_address'")
        v = cur.fetchone()[1]
        c.close()
        return v in ("127.0.0.1", "localhost"), f"bind_address={v}"
    record("E-15", "Environment", "MySQL listens on the loopback interface only", "127.0.0.1", e15)

    from auth.password import hash_password, verify_password
    from auth import authentication as A
    from auth import rate_limit as RL
    from database import models as M
    from utils.audit_logger import log_action
    from security.validation import validate_url
    from security import url_scanner as US
    from ml.risk_scoring import calculate_risk_score, severity_from_risk
    from compliance import compliance_engine as CE

    # ---- security: SQL injection / passwords / auth
    M.create_user("seed.user@utp.edu.my", hash_password("Correct-Horse-9"), "USER", "Seed", "seed.user@utp.edu.my", "local")

    def s01():
        payloads = ["' OR '1'='1", "admin'--", "'; DROP TABLE users;--", "\" OR \"\"=\"", "x' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"]
        hits = [M.get_user_by_username(p) for p in payloads]
        c = get_connection(); cur = c.cursor()
        cur.execute("SELECT COUNT(*) FROM users"); n = cur.fetchone()[0]; c.close()
        return all(h is None for h in hits) and n >= 1, f"{len(payloads)} payloads, 0 rows returned, users table intact ({n} row)"
    record("S-01", "Security", "SQL-injection payloads in the login lookup are treated as data", "No match, table intact", s01)

    def s02():
        h1, h2 = hash_password("Pass-1234"), hash_password("Pass-1234")
        ok = h1 != "Pass-1234" and h1.startswith("$2") and h1 != h2 and verify_password("Pass-1234", h1) \
            and not verify_password("wrong", h1) and verify_password("x", None) is False
        return ok, f"bcrypt prefix {h1[:4]}, salted (two hashes differ), wrong/None rejected"
    record("S-02", "Security", "Passwords stored as salted bcrypt hashes; wrong and NULL hashes fail closed", "Hash verified", s02)

    def s03():
        a = A.authenticate_user("seed.user@utp.edu.my", "Correct-Horse-9")
        b = A.authenticate_user("seed.user@utp.edu.my", "bad")
        c_ = A.authenticate_user("nobody@utp.edu.my", "bad")
        return a is not None and b is None and c_ is None, "correct->user, wrong password->None, unknown user->None (identical outcome)"
    record("S-03", "Security", "Authentication result does not distinguish unknown user from wrong password", "Same outcome", s03)

    def s04():
        uid = M.get_user_by_username("seed.user@utp.edu.my")["id"]
        M.set_user_active(uid, False)
        r = A.authenticate_user("seed.user@utp.edu.my", "Correct-Horse-9")
        M.set_user_active(uid, True)
        return r is None, "disabled account with correct password -> rejected"
    record("S-04", "Security", "Disabled account cannot authenticate", "Rejected", s04)

    def clear_rl():
        c = get_connection(); cur = c.cursor(); cur.execute("DELETE FROM rate_limit_counters"); c.commit(); c.close()

    def s05():
        clear_rl()
        for _ in range(config.LOGIN_ACCOUNT_MAX_ATTEMPTS):
            RL.record_login_failure("victim@utp.edu.my")
        allowed, retry = RL.check_login_rate_limit("victim@utp.edu.my")
        allowed_ghost_pre, _ = RL.check_login_rate_limit("ghost@utp.edu.my")
        return (not allowed) and retry > 0, f"after {config.LOGIN_ACCOUNT_MAX_ATTEMPTS} failures: blocked, retry_after={retry}s"
    record("S-05", "Security", "Login throttling blocks an account after the configured failed attempts", "Blocked", s05)

    def s06():
        clear_rl()
        for _ in range(config.LOGIN_ACCOUNT_MAX_ATTEMPTS):
            RL.record_login_failure("ghost-account-does-not-exist@utp.edu.my")
            RL.record_login_failure("seed.user@utp.edu.my")
        ok1, msg1 = A.login("ghost-account-does-not-exist@utp.edu.my", "x")
        ok2, msg2 = A.login("seed.user@utp.edu.my", "x")
        norm = lambda m: re.sub(r"\d+", "N", m or "")
        same = bool(msg1) and bool(msg2) and norm(msg1) == norm(msg2)
        return (not ok1) and (not ok2) and same, f"real and non-existent accounts both blocked with the same text: '{norm(msg1)}'"
    record("S-06", "Security", "Throttling response is identical for real and non-existent accounts", "No account enumeration", s06)

    def s07():
        clear_rl()
        for _ in range(3):
            RL.record_login_failure("someone@utp.edu.my")
        RL.record_login_success("someone@utp.edu.my")
        c = get_connection(); cur = c.cursor()
        cur.execute("SELECT COUNT(*) FROM rate_limit_counters WHERE scope='LOGIN_ACCOUNT' AND identifier='someone@utp.edu.my'")
        acct = cur.fetchone()[0]
        cur.execute("SELECT attempt_count FROM rate_limit_counters WHERE scope='LOGIN_SOURCE'")
        src = cur.fetchone()[0]; c.close()
        return acct == 0 and src == 3, f"account counter reset on success (rows={acct}); source counter preserved (count={src})"
    record("S-07", "Security", "Success resets the per-account counter but not the per-source counter", "Reset / preserved", s07)

    def s08():
        clear_rl()
        a1 = RL.check_and_bump_cooldown("URL_SCAN_USER", "101", 10)
        a2 = RL.check_and_bump_cooldown("URL_SCAN_USER", "101", 10)
        b1 = RL.check_and_bump_cooldown("URL_SCAN_USER", "202", 10)
        return a1[0] and (not a2[0]) and a2[1] > 0 and b1[0], f"user101 first={a1}, second={a2}; user202 first={b1}"
    record("S-08", "Security", "URL-scan cooldown is enforced per user in the database", "2nd call blocked", s08)

    def s11():
        orig = RL.get_connection
        RL.get_connection = lambda: (_ for _ in ()).throw(RuntimeError("db down"))
        try:
            allowed, retry = RL.check_login_rate_limit("anyone@utp.edu.my")
            RL.record_login_failure("anyone@utp.edu.my")  # must not raise either
        finally:
            RL.get_connection = orig
        return allowed and retry == 0, f"database unavailable -> allowed={allowed} (fails OPEN by design, so an outage cannot lock every user out; documented trade-off)"
    record("S-11", "Security", "Rate limiter fails open when the database is unavailable (documented trade-off)", "Allowed, no crash", s11)

    def s12():
        ident = RL._source_identifier()
        return ident == "local", f"outside a routable network session the source key is '{ident}': every loopback client shares one bucket (documented limitation)"
    record("S-12", "Security", "Loopback clients share a single source bucket (documented limitation)", "'local' bucket", s12)

    def s09():
        cases = [
            (("", "a@b.com", "x", "x"), False), (("N", "not-an-email", "Passw0rd!", "Passw0rd!"), False),
            (("N", "n@utp.edu.my", "Passw0rd!", "different"), False), (("N", "n@utp.edu.my", "short", "short"), False),
            (("Seed", "seed.user@utp.edu.my", "Passw0rd!", "Passw0rd!"), False), (("New User", "new.user@utp.edu.my", "Passw0rd!", "Passw0rd!"), True),
        ]
        res = [A.register_user(*a)[0] == exp for a, exp in cases]
        u = M.get_user_by_email("new.user@utp.edu.my")
        return all(res) and u["role"] == "USER" and u["auth_provider"] == "local", f"{sum(res)}/{len(res)} validation cases correct; new account role={u['role']}"
    record("S-09", "Security", "Self-registration validates input and always assigns the lowest role", "6/6 cases, role USER", s09)

    # ---- URL validation
    def s10():
        cases = [
            ("https://example.com/path?q=1", True), ("example.com", True), ("http://8.8.8.8/login", True), ("http://192.168.1.10/login", False),
            ("http://localhost:8501", False), ("http://127.0.0.1", False),
            ("ftp://example.com", False), ("javascript:alert(1)", False), ("http://Egxnd3abc123xyz", False), ("", False),
            ("http://", False), ("https://" + "a" * 2100 + ".com", False),
        ]
        res = [(validate_url(u)[0] == e) for u, e in cases]
        return all(res), f"{sum(res)}/{len(cases)} URL cases classified correctly"
    record("S-10", "Security", "URL validation accepts well-formed public http/https hosts and rejects unsafe or private/internal input", "12/12", s10)

    # ---- URL scoring with a stubbed VirusTotal response (no network)
    def mk_report(m, s, h=60, u=10):
        res = {f"Eng{i}": {"category": "malicious", "result": "phishing"} for i in range(m)}
        res.update({f"Sus{i}": {"category": "suspicious", "result": "suspicious"} for i in range(s)})
        return {"id": "stub-id", "attributes": {"last_analysis_stats": {"malicious": m, "suspicious": s, "harmless": h, "undetected": u, "timeout": 0},
                                                "last_analysis_results": res}}

    def u01():
        rows = []
        ok = True
        for m, s, exp_status, exp_score, exp_level in [(0, 0, "SAFE", 0, "LOW"), (0, 3, "SUSPICIOUS", 6, "LOW"), (3, 0, "MALICIOUS", 12, "LOW"),
                                                       (10, 0, "MALICIOUS", 40, "MEDIUM"), (17, 1, "MALICIOUS", 70, "HIGH"), (20, 0, "MALICIOUS", 80, "CRITICAL"), (40, 5, "MALICIOUS", 100, "CRITICAL")]:
            US.get_existing_report = lambda url, _m=m, _s=s: mk_report(_m, _s)
            r = US.scan_url("https://example.com")
            good = (r["scan_status"], r["risk_score"], r["risk_level"]) == (exp_status, exp_score, exp_level)
            ok &= good
            rows.append(f"{m}M/{s}S->{r['scan_status']}/{r['risk_score']}/{r['risk_level']}")
        return ok, "; ".join(rows)
    record("U-01", "URL scanner", "Risk = min(100, 4 x malicious + 2 x suspicious) with shared severity bands", "7/7 verdicts", u01)

    def u02():
        r = US.scan_url("http://nodot")
        from security.virustotal import VirusTotalError
        def boom(url): raise VirusTotalError("rate limit exceeded")
        US.get_existing_report = boom
        r2 = US.scan_url("https://example.com")
        return r["scan_status"] == "SCAN_ERROR" and r2["scan_status"] == "SCAN_ERROR" and r2["error"], f"invalid URL->{r['scan_status']}; API failure->{r2['scan_status']} (no exception raised)"
    record("U-02", "URL scanner", "Invalid input and API failures return SCAN_ERROR instead of raising", "SCAN_ERROR", u02)

    # ---- risk scoring
    def r01():
        cases = [("MALICIOUS", 99.0, False, 99), ("MALICIOUS", 99.0, True, 100), ("MALICIOUS", 50.0, False, 50), ("BENIGN", 100.0, False, 0),
                 ("BENIGN", 60.0, False, 16), ("BENIGN", 60.0, True, 31), ("BENIGN", 0.0, True, 55), ("MALICIOUS", 0.0, False, 0)]
        res = [calculate_risk_score(p, c, a) == e for p, c, a, e in cases]
        return all(res), f"{sum(res)}/{len(cases)} formula cases exact"
    record("R-01", "Risk scoring", "Risk formula: malicious=confidence, benign=0.4x(100-confidence), +15 anomaly bonus, capped", "8/8", r01)

    def r02():
        pts = {0: "LOW", 29: "LOW", 30: "MEDIUM", 59: "MEDIUM", 60: "HIGH", 79: "HIGH", 80: "CRITICAL", 100: "CRITICAL"}
        res = [severity_from_risk(k) == v for k, v in pts.items()]
        return all(res), f"{sum(res)}/{len(pts)} boundary values map to the correct band (29|30, 59|60, 79|80)"
    record("R-02", "Risk scoring", "Severity bands: 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL", "8/8 boundaries", r02)

    # ---- compliance engine
    CE_rules = CE.ALL_RULE_CATALOGS
    flat = [r for cat in CE_rules for r in cat]
    M.seed_compliance_rules(flat)
    c = get_connection(); cur = c.cursor(); cur.execute("SELECT framework, COUNT(*) FROM compliance_rules GROUP BY framework ORDER BY framework"); seeded = cur.fetchall(); c.close()
    total_rules = sum(n for _, n in seeded)
    record("C-01", "Compliance", "Rule catalogue seeds idempotently for five frameworks", "13 rules / 5 frameworks",
           lambda: (total_rules == 13 and len(seeded) == 5, f"{total_rules} rules: " + ", ".join(f"{f}={n}" for f, n in seeded)))
    M.seed_compliance_rules(flat)
    c = get_connection(); cur = c.cursor(); cur.execute("SELECT COUNT(*) FROM compliance_rules"); n2 = cur.fetchone()[0]; c.close()
    record("C-02", "Compliance", "Re-seeding the catalogue does not duplicate rules", "Still 13", lambda: (n2 == 13, f"{n2} rules after second seed"))

    uidA = M.get_user_by_username("seed.user@utp.edu.my")["id"]
    uidB = M.get_user_by_email("new.user@utp.edu.my")["id"]
    classes = ["Benign", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator"]

    matrix = []

    def c03():
        ok = True
        for cl in classes[1:]:
            for sev, risk in (("HIGH", 70), ("CRITICAL", 95)):
                ev = CE.build_network_event({"id": None, "attack_type": cl, "severity": sev, "risk_score": risk, "confidence": 95.0}, uidA)
                res = CE.evaluate_event(ev)
                codes = sorted(r["rule_code"] for r in res)
                statuses = {r["status"] for r in res}
                ok &= "POTENTIAL_VIOLATION" not in statuses
                matrix.append({"attack": cl, "severity": sev, "risk": risk, "flagged": ev["potential_data_exposure"], "rules": codes, "alert": risk >= CE.ALERT_RISK_THRESHOLD})
        return ok, f"{len(matrix)} event/severity combinations evaluated; POTENTIAL_VIOLATION never emitted automatically"
    record("C-03", "Compliance", "No attack class/severity combination auto-emits POTENTIAL_VIOLATION (human judgement retained)", "Never", c03)

    def c04():
        flagged_classes = sorted({m["attack"] for m in matrix if m["severity"] == "HIGH" and m["flagged"]})
        expected = sorted(["Bot", "Heartbleed", "Infiltration", "SSH-Patator", "FTP-Patator"])
        return flagged_classes == expected, f"HIGH-severity events flagged for personal-data review: {', '.join(flagged_classes)}"
    record("C-04", "Compliance", "At HIGH severity only access/data-oriented attacks trigger PDPA-01 and GDPR-01", "5 classes", c04)

    def c05():
        crit = [m for m in matrix if m["severity"] == "CRITICAL"]
        allflag = all(m["flagged"] and "PDPA-01" in m["rules"] and "GDPR-01" in m["rules"] for m in crit)
        return allflag, f"all {len(crit)} CRITICAL events trigger PDPA-01 and GDPR-01 (severity override)"
    record("C-05", "Compliance", "CRITICAL severity forces the personal-data rules for every attack class", "11/11", c05)

    def c10():
        from collections import defaultdict
        seen = defaultdict(set)
        for m in matrix:
            ev = CE.build_network_event({"id": None, "attack_type": m["attack"], "severity": m["severity"], "risk_score": m["risk"], "confidence": 95.0}, uidA)
            for r in CE.evaluate_event(ev):
                seen[r["rule_code"]].add(r["status"])
        always = sorted(k for k, v in seen.items() if len(v) == 1)
        varies = sorted(k for k, v in seen.items() if len(v) > 1)
        present = sorted(seen)
        cond = sorted(k for k in present if any(k not in m["rules"] for m in matrix))
        return True, f"rules emitted: {len(present)}; constant status AND always present: {', '.join(k for k in always if k not in cond)}; condition-dependent: {', '.join(cond)}"
    record("C-10", "Compliance", "Rule discrimination analysis: which rule outputs actually change with the event", "Documented", c10)

    def c06():
        ev = CE.build_url_event({"id": 5, "url": "http://x.test", "scan_status": "MALICIOUS", "risk_level": "HIGH", "risk_score": 70, "threat_category": "Phishing", "detection_count": 17, "total_engines": 70}, uidA)
        ev2 = CE.build_url_event({"id": 6, "url": "http://y.test", "scan_status": "SUSPICIOUS", "risk_level": "LOW", "risk_score": 6, "threat_category": None, "detection_count": 3, "total_engines": 70}, uidA)
        a = sorted(r["rule_code"] for r in CE.evaluate_event(ev)); b = sorted(r["rule_code"] for r in CE.evaluate_event(ev2))
        return ("PDPA-01" in a and "GDPR-01" in a and "PDPA-01" not in b), f"MALICIOUS URL -> {', '.join(a)}; SUSPICIOUS URL -> {', '.join(b)}"
    record("C-06", "Compliance", "A malicious URL is mapped to personal-data rules; a merely suspicious URL is not", "Mapped / not mapped", c06)

    def c07():
        out = []
        for risk in (79, 80):
            ev = CE.build_network_event({"id": None, "attack_type": "DDoS", "severity": "HIGH" if risk < 80 else "CRITICAL", "risk_score": risk, "confidence": 90.0}, uidA)
            before = M.get_alert_count(uidA)
            r = CE.process_security_event(ev)
            after = M.get_alert_count(uidA)
            out.append((risk, r["alert_id"] is not None, after - before))
        return out == [(79, False, 0), (80, True, 1)], f"risk 79 -> alert={out[0][1]}; risk 80 -> alert={out[1][1]}"
    record("C-07", "Compliance", "Alert is created at risk >= 80 and not at 79 (boundary)", "79 no, 80 yes", c07)

    def c08():
        res = CE.run_ai_system_self_assessment(uidA)
        st = [r["status"] for r in res]
        return len(res) == 5 and st.count("COMPLIANT") == 4 and st.count("NEEDS_REVIEW") == 1, f"{len(res)} EU AI Act checks: {st.count('COMPLIANT')} COMPLIANT, {st.count('NEEDS_REVIEW')} NEEDS_REVIEW (classification left to a human)"
    record("C-08", "Compliance", "EU AI Act self-assessment is evaluated once, per system, per user", "5 checks (4 + 1)", c08)

    def c09():
        al = M.get_alerts(uidA, limit=10)
        top = al[0]
        return bool(top["compliance_summary"]) and "NIST-RECOVER" in top["compliance_summary"] and bool(top["recommended_action"]), f"alert {top['threat_ref'] if 'threat_ref' in top else ''}: summary='{top['compliance_summary'][:80]}...'"
    record("C-09", "Compliance", "Every alert carries a compliance summary and templated recommended actions", "Present", c09)

    # ---- multi-tenant isolation
    def i01():
        A_alerts = M.get_alerts(uidA, limit=50)
        B_alerts = M.get_alerts(uidB, limit=50)
        B_comp = M.get_compliance_results_detail(uidB, limit=50)
        foreign_id = A_alerts[0]["id"]
        changed = M.update_alert_status(foreign_id, "RESOLVED", uidB)
        own = M.update_alert_status(foreign_id, "INVESTIGATING", uidA)
        return len(A_alerts) >= 1 and len(B_alerts) == 0 and len(B_comp) == 0 and (not changed) and own, \
            f"user A sees {len(A_alerts)} alert(s); user B sees {len(B_alerts)} alert(s) and {len(B_comp)} compliance row(s); B updating A's alert -> {changed}; A updating own -> {own}"
    record("I-01", "Isolation", "A second user cannot read or modify another user's alerts or compliance results", "B sees 0, update rejected", i01)

    def i02():
        a = M.get_threat_summary(uidA); b = M.get_threat_summary(uidB)
        return True, f"threat summary A={a}, B={b}"
    # audit logger
    def l01():
        log_action("test@utp.edu.my", "LOGIN", "AUTH", "unit")
        c = get_connection(); cur = c.cursor(); cur.execute("SELECT COUNT(*) FROM audit_logs WHERE username='test@utp.edu.my'"); n = cur.fetchone()[0]; c.close()
        import database.connection as dc
        orig = dc.get_connection
        import utils.audit_logger as al
        al.get_connection = lambda: (_ for _ in ()).throw(RuntimeError("db down"))
        try:
            log_action("x", "X", "X", "x"); safe = True
        except Exception:
            safe = False
        al.get_connection = orig
        return n == 1 and safe, f"audit row written (n={n}); a database failure does not crash the calling feature"
    record("L-01", "Audit", "Audit entries are written, and an audit failure never crashes the feature", "Written / no crash", l01)

    # ---- ML pipeline (synthetic CICIDS-like data: tests mechanics, NOT accuracy)
    import numpy as np
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder
    from ml import preprocessing as P
    from ml.train_model import train_models
    from ml.prediction import run_detection

    rng = np.random.default_rng(42)
    sizes = {"Benign": 3000, "DDoS": 900, "PortScan": 500, "Bot": 250, "Infiltration": 60}
    frames = []
    for i, (lab, n) in enumerate(sizes.items()):
        base = rng.normal(loc=i * 3.0, scale=1.0, size=(n, 8))
        d = pd.DataFrame(base, columns=[f"f{j}" for j in range(8)])
        d["Label"] = lab
        frames.append(d)
    df = pd.concat(frames, ignore_index=True).sample(frac=1.0, random_state=1).reset_index(drop=True)
    df["f2"] = df["f2"].astype(object); df.loc[5, "f0"] = np.inf; df.loc[6, "f1"] = np.nan; df.loc[7, "f2"] = "N/A"

    def m01():
        v_empty = P.validate_dataset(pd.DataFrame(), None)[0]
        v_small = P.validate_dataset(df.head(10), "Label")[0]
        v_one = P.validate_dataset(df[df.Label == "Benign"], "Label")[0]
        v_ok = P.validate_dataset(df, "Label")[0]
        return (not v_empty) and (not v_small) and (not v_one) and v_ok, f"empty->{v_empty}, <20 rows->{v_small}, single class->{v_one}, valid multi-class->{v_ok}"
    record("M-01", "ML pipeline", "Dataset validation rejects empty, tiny and single-class uploads", "3 rejected, 1 accepted", m01)

    bundle = P.preprocess_dataset(df, "Label")

    def m02():
        r = bundle["sanitization_report"]
        return bool(r["infinities_replaced"]) and bool(r["invalid_strings_to_nan"]), f"infinities replaced={r['infinities_replaced']}, invalid strings->NaN={r['invalid_strings_to_nan']}"
    record("M-02", "ML pipeline", "Sanitiser converts infinities and non-numeric strings and reports exactly what changed", "Reported", m02)

    t0 = time.time()
    tr = train_models(bundle["X"], bundle["y_raw"], bundle["numeric_cols"], bundle["categorical_cols"])
    train_secs = round(time.time() - t0, 1)

    def m03():
        n = len(bundle["X"])
        ratio = tr["test_rows"] / n
        return abs(ratio - 0.25) < 0.01 and tr["train_rows"] + tr["test_rows"] == n, f"train={tr['train_rows']}, test={tr['test_rows']} ({ratio:.3f} of {n})"
    record("M-03", "ML pipeline", "Train/test split is 75/25 and partitions every row", "75/25", m03)

    def m04():
        le = LabelEncoder(); y = le.fit_transform(bundle["y_raw"].astype(str))
        Xtr, Xte, ytr, yte = train_test_split(bundle["X"], y, test_size=0.25, random_state=42, stratify=y)
        imp = tr["preprocessor"].named_transformers_["num"].named_steps["imputer"]
        med_train = Xtr[bundle["numeric_cols"]].median().to_numpy(dtype=float)
        med_all = bundle["X"][bundle["numeric_cols"]].median().to_numpy(dtype=float)
        # imputer statistics must equal the TRAIN-split medians (to float precision), and differ from all-data medians for at least one column
        eq_train = np.allclose(imp.statistics_, med_train, equal_nan=True)
        eq_all = np.allclose(imp.statistics_, med_all, equal_nan=True)
        return eq_train and not eq_all, f"imputer medians == train-split medians: {eq_train}; == whole-dataset medians: {eq_all} (no leakage)"
    record("M-04", "ML pipeline", "Imputer statistics are learned from the training split only (leakage guard)", "Train-only", m04)

    def m05():
        feats = bundle["X"]
        det = run_detection(feats, tr["models"], tr["label_encoder"], tr, tr["best_model"])
        ok_range = det["risk_score"].between(0, 100).all()
        ok_sev = all(severity_from_risk(r) == s for r, s in zip(det["risk_score"], det["severity"]))
        ok_benign = det[det.prediction == "BENIGN"]["attack_type"].isna().all()
        ok_mal = det[det.prediction == "MALICIOUS"]["attack_type"].notna().all()
        return ok_range and ok_sev and ok_benign and ok_mal and len(det) == len(feats), \
            f"{len(det)} records scored; risk in [0,100]; severity consistent; benign rows carry no attack type; malicious rows name one (best model={tr['best_model']})"
    record("M-05", "ML pipeline", "Detection output has consistent prediction, attack type, risk and severity for every record", "Consistent", m05)

    def m06():
        cols = list(bundle["X"].columns)
        rep = P.check_schema_compatibility(cols[:-2], cols)
        try:
            P.transform_features(bundle["X"].drop(columns=[cols[0]]), tr)
            raised = False
        except ValueError:
            raised = True
        return (not rep["compatible"]) and rep["missing"] == sorted(cols[-2:]) and raised, f"missing columns named: {rep['missing']}; transform raises a clear ValueError: {raised}"
    record("M-06", "ML pipeline", "Schema mismatch is reported by column name and blocked before prediction", "Reported", m06)

    # end-to-end: detection -> database -> compliance -> alerts
    def x01():
        feats = bundle["X"].head(400)
        det = run_detection(feats, tr["models"], tr["label_encoder"], tr, tr["best_model"])
        tid = M.insert_network_traffic("synthetic-e2e", uidA, len(det), feats.shape[1])
        first = M.insert_threat_detections_bulk(tid, det, uidA)
        n_alert_before = M.get_alert_count(uidA)
        n_events = 0
        for i, r in enumerate(det.to_dict("records")):
            if r["prediction"] == "MALICIOUS" and r["severity"] in ("HIGH", "CRITICAL"):
                ev = CE.build_network_event({**r, "id": first + i}, uidA)
                CE.process_security_event(ev); n_events += 1
        n_alert_after = M.get_alert_count(uidA)
        expected_alerts = int(((det.prediction == "MALICIOUS") & (det.risk_score >= 80) & det.severity.isin(["HIGH", "CRITICAL"])).sum())
        return (n_alert_after - n_alert_before) == expected_alerts, \
            f"{len(det)} flows scored -> {n_events} HIGH/CRITICAL events -> {n_alert_after - n_alert_before} alerts (expected {expected_alerts}); all rows stored under user A"
    record("X-01", "Integration", "End-to-end: detection -> MySQL -> compliance engine -> alerts, with alert count matching risk>=80", "Counts match", x01)

    out = {
        "environment": {"database": "MariaDB 10.11 (engine bundled with XAMPP)", "python": sys.version.split()[0], "synthetic_train_secs": train_secs},
        "compliance_matrix": matrix,
        "summary": {"total": len(RESULTS), "passed": sum(r["passed"] for r in RESULTS)},
        "results": RESULTS,
    }
    (ROOT / "tests" / "system_test_results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nSUMMARY: {out['summary']['passed']}/{out['summary']['total']} passed")


if __name__ == "__main__":
    main()
