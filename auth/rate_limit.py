"""
Persistent, atomic rate limiting for login attempts (and, via the same
table, the URL scanner's per-user cooldown - see security/url_scanner.py).

Every counter lives in MySQL (`rate_limit_counters`, created by
database/migrate_security_hardening.py) rather than st.session_state,
so a limit holds across different browser sessions/tabs and survives a
Streamlit rerun - a purely in-memory or per-session counter would let
an attacker simply open a new session to reset it. Counters are
updated with a single INSERT ... ON DUPLICATE KEY UPDATE statement per
call, which MySQL executes atomically under the row's own unique key -
two concurrent failed attempts can't both read a stale count and
under-count each other.

LOGIN THROTTLING USES TWO INDEPENDENT COUNTERS, on purpose:

  - per ACCOUNT (the submitted username/email, lowercased) - a SHORT,
    BOUNDED cooldown that slows repeated guesses against one identity.
    It is deliberately capped (LOGIN_ACCOUNT_LOCKOUT_MAX_SECONDS) and
    reset on that account's own successful login - an attacker who
    only ever fails against someone else's account can inconvenience
    it for at most that cap, never lock it out indefinitely. This is
    what keeps the limiter itself from becoming a denial-of-service
    tool against a legitimate user.
  - per SOURCE (st.context.ip_address, or a shared "local" bucket when
    that's unavailable - e.g. local development) - the real defense
    against credential stuffing, since it only ever throttles the
    actual abusive network source, never a specific account. This
    counter is NOT reset on a successful login, by design: resetting
    it would let an attacker interleave failed guesses against a
    victim's account with their own successful logins from the same
    source to keep refreshing their attempt budget.

Both counters are updated identically regardless of whether the
submitted account actually exists, and the caller (auth/authentication.
py) shows the exact same message either way - that is what keeps a
lockout response from revealing account existence.

Fails OPEN: any database error while checking or recording an attempt
is swallowed and treated as "not rate-limited" - a transient DB problem
here must never lock every user out of the whole application.
"""
import streamlit as st

import config
from database.connection import get_connection


def _source_identifier() -> str:
    """st.context.ip_address returns None for loopback (127.0.0.1/::1)
    - i.e. for ordinary local development - so every local session
    shares one "local" bucket. That's an accepted limitation, not a
    bug: it only matters once the app is actually reachable over a
    network, at which point real client IPs are reported."""
    try:
        ip = st.context.ip_address
    except Exception:
        ip = None
    return ip or "local"


def _get_block_remaining(scope: str, identifier: str) -> int:
    """Read-only: seconds remaining on an existing lockout for
    (scope, identifier), or 0 if not currently locked out."""
    try:
        conn = get_connection()
    except Exception:
        return 0
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT TIMESTAMPDIFF(SECOND, NOW(), locked_until) AS remaining "
            "FROM rate_limit_counters WHERE scope = %s AND identifier = %s "
            "AND locked_until IS NOT NULL",
            (scope, identifier),
        )
        row = cursor.fetchone()
        if row and row["remaining"] and row["remaining"] > 0:
            return int(row["remaining"])
        return 0
    except Exception:
        return 0
    finally:
        conn.close()


def _record_failure(scope: str, identifier: str, window_seconds: int, max_attempts: int,
                     lockout_seconds: int, lockout_max_seconds: int) -> None:
    """Atomically increment (scope, identifier)'s attempt count,
    resetting it first if its window has already expired, then lock it
    out (with a cooldown that grows per extra attempt but never exceeds
    lockout_max_seconds) once max_attempts is exceeded."""
    try:
        conn = get_connection()
    except Exception:
        return
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO rate_limit_counters "
            "(scope, identifier, attempt_count, window_start, last_attempt_at) "
            "VALUES (%s, %s, 1, NOW(), NOW()) "
            "ON DUPLICATE KEY UPDATE "
            "attempt_count = IF(window_start < NOW() - INTERVAL %s SECOND, 1, attempt_count + 1), "
            "window_start = IF(window_start < NOW() - INTERVAL %s SECOND, NOW(), window_start), "
            "locked_until = IF(window_start < NOW() - INTERVAL %s SECOND, NULL, locked_until), "
            "last_attempt_at = NOW()",
            (scope, identifier, window_seconds, window_seconds, window_seconds),
        )
        conn.commit()

        cursor.execute(
            "SELECT attempt_count FROM rate_limit_counters WHERE scope = %s AND identifier = %s",
            (scope, identifier),
        )
        row = cursor.fetchone()
        if row and row[0] >= max_attempts:
            over = row[0] - max_attempts + 1
            cooldown = min(lockout_seconds * over, lockout_max_seconds)
            cursor.execute(
                "UPDATE rate_limit_counters SET locked_until = NOW() + INTERVAL %s SECOND "
                "WHERE scope = %s AND identifier = %s",
                (cooldown, scope, identifier),
            )
            conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def _reset(scope: str, identifier: str) -> None:
    try:
        conn = get_connection()
    except Exception:
        return
    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM rate_limit_counters WHERE scope = %s AND identifier = %s",
            (scope, identifier),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def check_login_rate_limit(account_identifier: str):
    """Call BEFORE verifying credentials. Returns (allowed, retry_after_seconds)."""
    account_identifier = (account_identifier or "").strip().lower()
    remaining_account = _get_block_remaining("LOGIN_ACCOUNT", account_identifier)
    remaining_source = _get_block_remaining("LOGIN_SOURCE", _source_identifier())
    remaining = max(remaining_account, remaining_source)
    return remaining == 0, remaining


def record_login_failure(account_identifier: str) -> None:
    """Call after any failed authentication attempt - unknown username,
    wrong password, or disabled account; the caller doesn't distinguish
    which, by design (see auth/authentication.py's authenticate_user())."""
    account_identifier = (account_identifier or "").strip().lower()
    _record_failure(
        "LOGIN_ACCOUNT", account_identifier,
        config.LOGIN_ACCOUNT_WINDOW_SECONDS, config.LOGIN_ACCOUNT_MAX_ATTEMPTS,
        config.LOGIN_ACCOUNT_LOCKOUT_SECONDS, config.LOGIN_ACCOUNT_LOCKOUT_MAX_SECONDS,
    )
    _record_failure(
        "LOGIN_SOURCE", _source_identifier(),
        config.LOGIN_SOURCE_WINDOW_SECONDS, config.LOGIN_SOURCE_MAX_ATTEMPTS,
        config.LOGIN_SOURCE_LOCKOUT_SECONDS, config.LOGIN_SOURCE_LOCKOUT_SECONDS,
    )


def record_login_success(account_identifier: str) -> None:
    """Call after a successful login - resets only the per-ACCOUNT
    counter (see module docstring for why the per-SOURCE counter is
    deliberately left alone)."""
    _reset("LOGIN_ACCOUNT", (account_identifier or "").strip().lower())


def check_and_bump_cooldown(scope: str, identifier: str, cooldown_seconds: int):
    """Generic per-identifier cooldown for a repeatable action (used by
    security/url_scanner.py for scan submissions) - allowed exactly once
    per `cooldown_seconds`, enforced atomically via row-level locking so
    two near-simultaneous submissions from the same user can't both
    slip through. Returns (allowed, retry_after_seconds).

    Implementation: first try to UPDATE the existing row only if its
    cooldown has already elapsed (the UPDATE's own WHERE clause makes
    this atomic across concurrent callers - only one can win the row
    lock and see the pre-elapsed state). If that matches no row, either
    this is the very first call ever for this identifier (INSERT
    succeeds -> allowed) or a previous call already holds the cooldown
    (INSERT hits the duplicate key, changes nothing -> blocked)."""
    try:
        conn = get_connection()
    except Exception:
        return True, 0
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE rate_limit_counters SET last_attempt_at = NOW(), "
            "attempt_count = attempt_count + 1 "
            "WHERE scope = %s AND identifier = %s "
            "AND last_attempt_at <= NOW() - INTERVAL %s SECOND",
            (scope, identifier, cooldown_seconds),
        )
        conn.commit()
        if cursor.rowcount == 1:
            return True, 0

        cursor.execute(
            "INSERT INTO rate_limit_counters "
            "(scope, identifier, attempt_count, window_start, last_attempt_at) "
            "VALUES (%s, %s, 1, NOW(), NOW()) "
            "ON DUPLICATE KEY UPDATE id = id",
            (scope, identifier),
        )
        conn.commit()
        if cursor.rowcount == 1:  # a genuinely new row was inserted
            return True, 0

        cursor.execute(
            "SELECT TIMESTAMPDIFF(SECOND, NOW(), last_attempt_at + INTERVAL %s SECOND) "
            "FROM rate_limit_counters WHERE scope = %s AND identifier = %s",
            (cooldown_seconds, scope, identifier),
        )
        row = cursor.fetchone()
        remaining = row[0] if row and row[0] else 1
        return False, max(int(remaining), 1)
    except Exception:
        return True, 0
    finally:
        conn.close()
