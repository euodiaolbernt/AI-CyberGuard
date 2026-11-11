"""
MySQL connection handling.

Every other module (auth, ML pipeline, compliance engine, audit
logger, ...) opens the database through get_connection() below, so
there is exactly one place in the whole codebase that knows the
connection details - and it reads them from config.py, never from
hard-coded values.

POOLED, NOT ONE-CONNECTION-PER-CALL: a Streamlit rerun calls
get_connection() many times in a single page view (database/models.py
has ~40 query functions, each opening/closing its own connection) -
previously a brand new TCP + MySQL auth handshake on every single one
of those, which is the single biggest contributor to this app feeling
slow on every page switch/filter change. mysql-connector's own
connection pool keeps a small set of real connections open and hands
one out per get_connection() call, returned to the pool (not actually
closed) by the caller's existing conn.close() - every one of
database/models.py's ~40 functions already follows a strict
try/finally: conn.close() pattern, so this is a drop-in swap with ZERO
changes needed anywhere else in the codebase.
"""
import mysql.connector
from mysql.connector import Error as MySQLError
from mysql.connector import pooling

import config
from utils.perf import timed

_pool = None


def _get_pool():
    """Created lazily on first use (never at import time, so a
    misconfigured/unreachable DB still fails exactly where it did
    before - inside the existing try/except mysql.connector.Error
    handling in app.py - not at process startup). mysql-connector
    opens `pool_size` real connections up front when the pool is first
    created - a one-time cost paid once per process, not per page
    view, which is the whole point."""
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="ai_cyberguard_pool",
            pool_size=config.DB_POOL_SIZE,
            pool_reset_session=True,
            host=config.DB_HOST,
            port=config.DB_PORT,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME,
            **_ssl_kwargs(),
        )
    return _pool


def _ssl_kwargs() -> dict:
    """Translate config.DB_SSL_MODE into mysql-connector's own ssl_*
    kwargs. DISABLED (the default) reproduces exactly the pre-hardening
    behavior - no TLS, no change for existing local setups. VERIFY_CA/
    VERIFY_IDENTITY fail LOUDLY (raise) if DB_SSL_CA isn't set, rather
    than silently connecting without certificate verification - a
    config mistake should never downgrade to an insecure connection
    without the caller knowing."""
    mode = config.DB_SSL_MODE
    if mode == "DISABLED":
        return {"ssl_disabled": True}

    if mode not in ("REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY"):
        raise ValueError(
            f"Invalid DB_SSL_MODE '{mode}' - expected DISABLED, REQUIRED, "
            "VERIFY_CA, or VERIFY_IDENTITY."
        )

    kwargs = {"ssl_disabled": False}
    if mode in ("VERIFY_CA", "VERIFY_IDENTITY"):
        if not config.DB_SSL_CA:
            raise RuntimeError(
                f"DB_SSL_MODE is '{mode}' but DB_SSL_CA (path to the CA "
                "certificate) is not set - refusing to connect without "
                "certificate verification. Set DB_SSL_CA, or use "
                "DB_SSL_MODE=REQUIRED if encryption without verification "
                "is intentional."
            )
        kwargs["ssl_ca"] = config.DB_SSL_CA
        kwargs["ssl_verify_cert"] = True
        if mode == "VERIFY_IDENTITY":
            kwargs["ssl_verify_identity"] = True
    return kwargs


def get_connection():
    """Return a connection from the pool (see _get_pool()). Every
    existing caller's own `conn.close()` already returns it to the
    pool rather than tearing down the TCP connection - no caller needs
    to change. If the pool is exhausted (more callers mid-query at once
    than DB_POOL_SIZE), mysql-connector raises PoolError - a subclass
    of mysql.connector.Error, so it's already caught by the same
    try/except mysql.connector.Error handling in app.py that a plain
    connection failure was always caught by.
    """
    with timed("get_connection (pool checkout)"):
        return _get_pool().get_connection()


def test_connection():
    """Return (True, None) if MySQL is reachable with the current
    config, else (False, <error message>). Used by Settings/health
    checks so failures show a readable message instead of a traceback.
    """
    try:
        conn = get_connection()
        conn.close()
        return True, None
    except MySQLError as e:
        return False, str(e)
