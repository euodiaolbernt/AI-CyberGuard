"""
Central configuration loader.

Every secret or environment-specific value (database credentials, API
keys, etc.) is read from environment variables via a local ".env"
file (see .env.example for the template). Nothing sensitive is
hard-coded anywhere in this codebase - this is the ONLY file that
reads os.environ directly, so it's the one place to check when
verifying no secret has leaked into source code.
"""
import os
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

load_dotenv()  # reads the ".env" file in the project root into os.environ


def _load_streamlit_secrets_into_env():
    """Streamlit Community Cloud has no .env file to load - secrets
    there are pasted into the platform's own dashboard instead, which
    Streamlit exposes as st.secrets. Mirroring any keys found there
    into os.environ lets every os.getenv() call below keep working
    unchanged on both local (.env) and Community Cloud (st.secrets),
    without needing two separate code paths. Never overwrites a real
    .env value already present, so local dev behaviour is untouched.
    A bare `except Exception` is deliberate here: st.secrets raises
    when no secrets.toml exists at all (the normal case for local dev
    without Google OAuth configured, see sync_streamlit_auth_secrets()
    below) - that's not an error, it just means there's nothing to
    mirror."""
    try:
        for key, value in st.secrets.items():
            if key not in os.environ:
                os.environ[key] = str(value)
    except Exception:
        pass


_load_streamlit_secrets_into_env()

# NOTE: this file only runs once per process - Python caches imported
# modules, so editing .env while `streamlit run app.py` is already
# running has no effect until the process is fully stopped and
# restarted (a Streamlit "rerun" alone re-executes app.py, not this
# already-imported module).

# --- Database (MySQL / TiDB) ---
# DB_PROFILE selects which connection profile below is active for a
# LOCAL run. Streamlit Community Cloud's own Secrets dashboard never
# sets DB_PROFILE or any <PROFILE>_DB_* name - it only ever sets the
# flat DB_HOST/DB_PORT/etc. names directly (bridged into os.environ by
# _load_streamlit_secrets_into_env() above), so _db_env() below always
# falls through to those flat names there, completely unchanged from
# before DB_PROFILE existed. Locally: DB_PROFILE=TIDB (the default)
# points this process at the SAME TiDB Cloud database Streamlit Cloud
# uses, so local dev and the live deployment share one database.
# DB_PROFILE=LOCAL switches back to XAMPP MySQL, kept installed as an
# offline backup. Changing .env needs a full restart of
# `streamlit run app.py` - a Streamlit rerun does not reload it (see
# the note above this section).
DB_PROFILE = os.getenv("DB_PROFILE", "TIDB").strip().upper()
if DB_PROFILE not in ("LOCAL", "TIDB"):
    DB_PROFILE = "TIDB"  # fail safe to the shared database on a typo, never crash


def _db_env(name: str, default: str = "") -> str:
    """Resolve one DB_* setting for the active profile: a
    <DB_PROFILE>_<name> value wins if set (local .env's per-profile
    blocks), otherwise fall through to the flat <name> (Streamlit
    Cloud's Secrets, or an old-style local .env that hasn't adopted
    DB_PROFILE blocks yet)."""
    prefixed = os.environ.get(f"{DB_PROFILE}_{name}")
    return prefixed if prefixed else os.getenv(name, default)


DB_HOST = _db_env("DB_HOST", "localhost")
DB_PORT = int(_db_env("DB_PORT", "3306"))
DB_USER = _db_env("DB_USER", "root")
DB_PASSWORD = _db_env("DB_PASSWORD", "")
DB_NAME = _db_env("DB_NAME", "ai_cyberguard")

# TLS to MySQL/TiDB - opt-in, defaults to today's plain local-dev
# behavior. DISABLED: no encryption (XAMPP's usual local setup).
# REQUIRED: encrypt the connection but don't verify the server's
#   certificate (better than nothing on an untrusted network, but
#   doesn't stop a MITM with its own cert) - TiDB Cloud requires at
#   least this.
# VERIFY_CA / VERIFY_IDENTITY: encrypt AND verify the server certificate
#   against DB_SSL_CA (VERIFY_IDENTITY additionally checks the hostname
#   matches the certificate) - get_connection() in database/connection.py
#   refuses to connect rather than silently falling back to no
#   verification if DB_SSL_CA is missing under either of these two modes.
DB_SSL_MODE = _db_env("DB_SSL_MODE", "DISABLED").strip().upper()
DB_SSL_CA = _db_env("DB_SSL_CA", "").strip() or None

# Connection pool size (database/connection.py) - real connections kept
# open and reused across reruns instead of a fresh TCP+auth handshake
# per query. 10 comfortably covers a handful of concurrent users for
# an FYP-scale deployment without opening excess idle connections.
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))

# --- URL threat intelligence ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
# Optional second threat-intel source (security/safe_browsing.py) - a
# scan still runs on VirusTotal alone if this is unset; when it IS set,
# its verdict is combined with VirusTotal's, never required on its own.
# Get a free key (Safe Browsing API v4) at
# https://developers.google.com/safe-browsing/v4/get-started
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
# Per-user cooldown between URL scan submissions (security/url_scanner.py),
# enforced server-side in the database - not just in st.session_state -
# so it can't be reset by opening a new browser tab/session, and holds
# even if two scans from the same user land concurrently.
URL_SCAN_COOLDOWN_SECONDS = int(os.getenv("URL_SCAN_COOLDOWN_SECONDS", "10"))
# Per-user cooldown between Threat Detection's own expensive actions
# (Train Models, Run AI Detection, Train New Model & Run Detection) -
# same server-side-cooldown mechanism as URL_SCAN_COOLDOWN_SECONDS
# above, just a longer window since these do real model training/bulk
# DB inserts against the shared TiDB backend rather than one API call.
# Today's disable-while-running button guards (app_pages/threat_detection.py)
# only stop a double-click DURING one run - this is what stops a user
# from re-triggering another expensive run back-to-back immediately
# after one finishes.
ML_ACTION_COOLDOWN_SECONDS = int(os.getenv("ML_ACTION_COOLDOWN_SECONDS", "30"))

# --- Google OAuth ("Continue with Google" login) ---
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8501/oauth2callback")
# Signs Streamlit's own identity cookie for st.login() - a separate
# concern from the Google credentials above, but required by
# Streamlit's auth layer for the login to be secure at all. Generate
# one with: python -c "import secrets; print(secrets.token_hex(32))"
AUTH_COOKIE_SECRET = os.getenv("AUTH_COOKIE_SECRET", "")

# --- App-wide constants ---
APP_NAME = "AI CyberGuard"
# Idle timeout: a session with no page activity for this long is
# expired. Absolute timeout: a hard ceiling on session lifetime even
# with continuous activity, so a device left logged in and in
# constant use still can't stay authenticated forever. Both enforced
# in auth/authentication.py's is_authenticated().
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "60"))
SESSION_ABSOLUTE_TIMEOUT_MINUTES = int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_MINUTES", "480"))

# --- Login brute-force throttling (auth/rate_limit.py) ---
# Two independent counters - see auth/rate_limit.py's module docstring
# for why a per-ACCOUNT limit alone would let an attacker lock out a
# legitimate user on purpose, and why per-SOURCE is the real defense.
LOGIN_ACCOUNT_MAX_ATTEMPTS = int(os.getenv("LOGIN_ACCOUNT_MAX_ATTEMPTS", "5"))
LOGIN_ACCOUNT_WINDOW_SECONDS = int(os.getenv("LOGIN_ACCOUNT_WINDOW_SECONDS", "900"))
LOGIN_ACCOUNT_LOCKOUT_SECONDS = int(os.getenv("LOGIN_ACCOUNT_LOCKOUT_SECONDS", "30"))
LOGIN_ACCOUNT_LOCKOUT_MAX_SECONDS = int(os.getenv("LOGIN_ACCOUNT_LOCKOUT_MAX_SECONDS", "900"))
LOGIN_SOURCE_MAX_ATTEMPTS = int(os.getenv("LOGIN_SOURCE_MAX_ATTEMPTS", "20"))
LOGIN_SOURCE_WINDOW_SECONDS = int(os.getenv("LOGIN_SOURCE_WINDOW_SECONDS", "900"))
LOGIN_SOURCE_LOCKOUT_SECONDS = int(os.getenv("LOGIN_SOURCE_LOCKOUT_SECONDS", "900"))

# --- Upload hardening (app_pages/threat_detection.py) ---
# Checked against the UploadedFile's reported size BEFORE pandas reads
# any of it, and against the parsed row count right after - generous
# defaults so the existing ~225k-row CICIDS2017 workflow is unaffected;
# these exist to bound worst-case memory use from a hostile/corrupt
# file, not to limit realistic datasets.
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "300"))
MAX_UPLOAD_ROWS = int(os.getenv("MAX_UPLOAD_ROWS", "3000000"))

# Required for the app to do anything useful at all (every feature
# needs the database). DB_PASSWORD is deliberately excluded - an empty
# password is a common, if weak, local MySQL root setup, not a missing
# setting. Google OAuth and VirusTotal are optional integrations with
# their own has_*_configured() checks, not startup requirements.
#
# Checked against the RESOLVED values (DB_HOST etc., already resolved
# above via _db_env() for whichever DB_PROFILE is active), never the
# raw flat env var names directly - a local DB_PROFILE=TIDB run only
# ever sets TIDB_DB_HOST, not a flat DB_HOST, so checking os.environ
# for the flat name would wrongly report it "missing" even when the
# app would connect fine.
_REQUIRED_DB_SETTINGS = {"DB_HOST": DB_HOST, "DB_USER": DB_USER, "DB_NAME": DB_NAME}


def validate_required_env():
    """Check required configuration is present WITHOUT ever printing or
    returning the actual values - only which variable NAMES are
    missing. Returns (ok, missing_names, warnings); call once at
    startup (see app.py) before anything tries to use the database."""
    missing = [name for name, value in _REQUIRED_DB_SETTINGS.items() if not value]

    warnings = []
    google_vars = (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, AUTH_COOKIE_SECRET)
    set_count = sum(1 for v in google_vars if v)
    if 0 < set_count < len(google_vars):
        warnings.append(
            "Google OAuth is partially configured (only some of "
            "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / AUTH_COOKIE_SECRET "
            "are set) - 'Continue with Google' will stay disabled until "
            "all three are set."
        )
    if DB_SSL_MODE in ("VERIFY_CA", "VERIFY_IDENTITY") and not DB_SSL_CA:
        warnings.append(
            f"DB_SSL_MODE={DB_SSL_MODE} requires DB_SSL_CA (path to a CA "
            "certificate) - the database connection will fail until it's set."
        )
    # Only meaningful for a local run - Streamlit Cloud never sets
    # DB_PROFILE, so this block is always skipped there.
    if os.getenv("DB_PROFILE", "").strip().upper() in ("LOCAL", "TIDB"):
        # DB_PASSWORD excluded, same reasoning as _REQUIRED_DB_SETTINGS
        # above - an empty password is a legitimate, common local MySQL
        # root setup, not a sign the profile is half-configured. A
        # genuinely missing TiDB password still fails loudly, with a
        # clear "Access denied" error, the moment something connects.
        half_set = [
            n for n in ("DB_HOST", "DB_USER", "DB_NAME")
            if not os.environ.get(f"{DB_PROFILE}_{n}")
        ]
        if half_set:
            warnings.append(
                f"DB_PROFILE={DB_PROFILE} but {', '.join(f'{DB_PROFILE}_{n}' for n in half_set)} "
                f"{'is' if len(half_set) == 1 else 'are'} not set in .env - this run may silently mix "
                f"{DB_PROFILE} and the other profile's values. Fill in every "
                f"{DB_PROFILE}_DB_* value before using this profile."
            )

    return not missing, missing, warnings


def has_virustotal_key() -> bool:
    """Used by the URL Scanner page to decide whether to show a
    'missing API key' notice instead of failing."""
    return bool(VIRUSTOTAL_API_KEY)


def has_safe_browsing_key() -> bool:
    """Used by the URL Scanner page to decide whether to show Google
    Safe Browsing as a consulted source, and by security/url_scanner.py
    to decide whether to call it at all - its absence never blocks a
    scan, VirusTotal alone is always sufficient to run one."""
    return bool(GOOGLE_SAFE_BROWSING_API_KEY)


def has_google_oauth_configured() -> bool:
    """Used by the login page to decide whether to show a working
    'Continue with Google' button or a clear setup message instead of
    pretending Google sign-in works."""
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and AUTH_COOKIE_SECRET)


def sync_streamlit_auth_secrets():
    """Streamlit's st.login()/st.user only ever read OAuth config from
    st.secrets (backed by .streamlit/secrets.toml) - there is no
    supported way to point it at plain environment variables directly.
    Per this project's convention (.env is the one place every other
    secret lives), this mirrors the four GOOGLE_*/AUTH_COOKIE_SECRET
    values from .env into secrets.toml on every process start, so
    .env stays the only file anyone actually edits. secrets.toml is
    git-ignored, exactly like .env, and holds the same values, not
    new ones.

    BEST-EFFORT ONLY: a platform that deploys this app from a git
    checkout (e.g. Streamlit Community Cloud) typically mounts that
    checkout read-only at runtime, and ALSO writes its own
    .streamlit/secrets.toml from its own secrets dashboard before the
    app even starts - so on such a platform this write both fails AND
    isn't needed (the real fix there is pasting the [auth]/[auth.google]
    sections directly into that platform's secrets dashboard, not
    relying on this function). A failed write must never crash the
    whole app over a convenience file it couldn't create - local dev
    (where the checkout IS writable) is the only place this ever
    actually needs to succeed."""
    if not has_google_oauth_configured():
        return

    try:
        secrets_dir = Path(__file__).resolve().parent / ".streamlit"
        secrets_dir.mkdir(exist_ok=True)
        secrets_path = secrets_dir / "secrets.toml"
        secrets_path.write_text(
            "[auth]\n"
            f'redirect_uri = "{GOOGLE_REDIRECT_URI}"\n'
            f'cookie_secret = "{AUTH_COOKIE_SECRET}"\n'
            "\n"
            "[auth.google]\n"
            f'client_id = "{GOOGLE_CLIENT_ID}"\n'
            f'client_secret = "{GOOGLE_CLIENT_SECRET}"\n'
            'server_metadata_url = "https://accounts.google.com/.well-known/openid-configuration"\n',
            encoding="utf-8",
        )
    except OSError:
        pass


sync_streamlit_auth_secrets()
