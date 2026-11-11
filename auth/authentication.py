"""
Authentication and session/role management.

Streamlit has no built-in password-gate concept of its own, so this
module implements one on top of `st.session_state`, which is kept only
in server-side memory for the lifetime of the browser session -
nothing sensitive is written to cookies or local storage by this part.

Google sign-in is different: it goes through Streamlit's own real
OIDC layer (st.login()/st.user, backed by a signed identity cookie -
see config.sync_streamlit_auth_secrets()), not a hand-rolled check.
sync_google_session() below is the bridge between that layer and this
module's own st.session_state contract, so every existing page -
which only ever calls is_authenticated()/can_access()/reads
st.session_state["username"] - keeps working unchanged regardless of
which of the three login methods (username/password, email/password,
or Google) was used.

ACCESS MODEL: every authenticated user - any role - sees every
CyberGuard page (ROLE_PERMISSIONS below maps every role to the same
full page set). What differs per user is never PAGE access but DATA:
each page's queries are filtered by the current user's own user_id
(see database/models.py), so two users looking at the same page see
only their own threats/detections/compliance results/alerts/reports/
history - never each other's. The one thing that stays admin-gated is
managing OTHER people's accounts (creating them, enabling/disabling
them) - a real privilege boundary, not a page restriction - guarded by
is_admin() and enforced inside app_pages/settings.py, not by hiding
the Settings page itself.
"""
import time
import uuid

import streamlit as st

import config
from auth.password import hash_password, verify_password
from auth.rate_limit import check_login_rate_limit, record_login_failure, record_login_success
from auth.validation import validate_email_format
from database.models import (
    create_user,
    get_user_by_email,
    get_user_by_username,
    update_last_login,
)
from utils.audit_logger import log_action

# New self-registered accounts (manual or Google) always start here -
# never a role the visitor picked themselves, and never ADMIN. Every
# role sees every page (see ROLE_PERMISSIONS below), so this doesn't
# limit what a self-registered account can DO - it only ever operates
# on its own data, same as everyone else. What USER can never do is
# manage OTHER accounts (see ADMIN_ROLES/is_admin()); an existing
# ADMIN can still raise a specific account's role from Settings.
DEFAULT_SELF_SIGNUP_ROLE = "USER"

ALL_PAGES = {
    "Dashboard", "Threat Detection", "URL Scanner", "Compliance Monitoring",
    "Alerts & Incidents", "Reports", "Audit Logs", "Settings",
}

# Every role maps to the full page set - see the module docstring for
# why: access control here is about DATA ownership (user_id filtering
# in database/models.py), not which pages a role may open. The dict
# stays keyed by role (rather than a flat "every authenticated user
# can access everything") so a future page-level restriction, if ever
# needed again, has one obvious place to add it back.
ROLE_PERMISSIONS = {
    "ADMIN": ALL_PAGES,
    "SOC ANALYST": ALL_PAGES,
    "COMPLIANCE OFFICER": ALL_PAGES,
    "AUDITOR": ALL_PAGES,
    "USER": ALL_PAGES,
}

# Roles allowed to manage OTHER users' accounts (Settings' "User
# Management" section) - the one capability that stays admin-only.
# Not a page restriction: every role still opens Settings, they just
# see different sections inside it (see app_pages/settings.py).
ADMIN_ROLES = {"ADMIN"}


def authenticate_user(username: str, password: str):
    """Verify credentials against the database.

    Returns the user dict on success, or None on any failure
    (unknown username, wrong password, or a disabled account). The
    caller can't distinguish *why* it failed - this avoids leaking
    whether a given username exists (username enumeration).
    """
    user = get_user_by_username(username)
    if user is None:
        return None
    if not user.get("is_active", 1):
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def login(username: str, password: str):
    """Attempt to log in with a username OR an email (new accounts
    store their email as their username too - see
    database/schema.sql - so this one lookup handles both). On
    success, populates st.session_state and writes an audit log entry;
    on failure, only logs the attempt.

    Returns (success: bool, block_message: str | None). `block_message`
    is only ever set when the attempt was rejected by the brute-force
    throttle (auth/rate_limit.py) - the SAME message regardless of
    whether `username` belongs to a real account, so the throttle
    itself can never be used to enumerate accounts. A normal
    wrong-password/unknown-user failure leaves it None; the caller
    (auth/login.py) shows its own generic "invalid credentials" text
    for that case, exactly as before.
    """
    allowed, retry_after = check_login_rate_limit(username)
    if not allowed:
        log_action(username or "(empty)", "LOGIN_BLOCKED", "AUTH",
                   f"Rate-limited; retry after {retry_after}s.")
        return False, f"Too many attempts. Please try again in {retry_after} seconds."

    user = authenticate_user(username, password)
    if user is None:
        record_login_failure(username)
        log_action(username or "(empty)", "LOGIN_FAILED", "AUTH",
                   "Failed login attempt.")
        return False, None

    record_login_success(username)
    _set_session(user)
    update_last_login(user["id"])
    log_action(user["username"], "LOGIN", "AUTH", "User logged in.")
    return True, None


def register_user(full_name: str, email: str, password: str, confirm_password: str):
    """Manual account self-registration (Option 2's 'Create Account').

    Returns (success: bool, message: str). Every new account gets
    DEFAULT_SELF_SIGNUP_ROLE and auth_provider='local' - never a
    role the visitor picked themselves.
    """
    full_name = (full_name or "").strip()
    email = (email or "").strip().lower()

    if not full_name or not email or not password:
        return False, "Full name, email, and password are all required."
    if not validate_email_format(email):
        return False, "Please enter a valid email address."
    if password != confirm_password:
        return False, "Passwords do not match."
    if len(password) < 8:
        return False, "Password should be at least 8 characters."
    if get_user_by_email(email) is not None:
        return False, "An account with this email already exists. Try logging in instead."

    password_hash = hash_password(password)
    create_user(
        username=email, password_hash=password_hash, role=DEFAULT_SELF_SIGNUP_ROLE,
        full_name=full_name, email=email, auth_provider="local",
    )
    log_action(email, "USER_REGISTERED", "AUTH", f"Self-registered account '{email}'.")
    return True, "Account created. You can now log in below."


def handle_google_login(email: str, full_name: str) -> bool:
    """Bridge a successful Streamlit-native Google sign-in (st.user)
    into this module's own session contract. If `email` already
    belongs to an account (local or Google), that account's EXISTING
    role is reused unchanged - Google login never grants or changes a
    role for a pre-existing account. Only a brand-new email gets
    DEFAULT_SELF_SIGNUP_ROLE, exactly like manual sign-up."""
    if not email:
        return False

    user = get_user_by_email(email)
    if user is None:
        user_id = create_user(
            username=email, password_hash=None, role=DEFAULT_SELF_SIGNUP_ROLE,
            full_name=full_name or email, email=email, auth_provider="google",
        )
        log_action(email, "USER_REGISTERED", "AUTH", f"Self-registered account '{email}' via Google.")
        user = get_user_by_email(email)
        if user is None:  # defensive - insert should always be found by its own email
            return False

    if not user.get("is_active", 1):
        log_action(email, "LOGIN_FAILED", "AUTH", "Google login for a disabled account.")
        return False

    _set_session(user)
    update_last_login(user["id"])
    log_action(user["username"], "LOGIN", "AUTH", "User logged in via Google.")
    return True


def start_guest_session() -> bool:
    """Create a fresh, one-off account and log straight into it - the
    "Continue as Guest" entry point on a public demo deployment. Every
    CyberGuard page scopes its data strictly by user_id (see
    database/models.py's module docstring on multi-tenant isolation),
    so a guest still needs a REAL user row to attach anything they do
    to - this keeps a guest's own uploads/scans/detections fully
    isolated from every other guest and every real account, exactly
    like any other account, never shared or faked data. password_hash
    stays NULL (same as a Google-only account): a guest never
    authenticates with a password, and the random generated username
    is never shown to them, so there is deliberately no way back into
    this same account later - each "Continue as Guest" click is a
    brand-new, disposable identity."""
    username = f"guest_{uuid.uuid4().hex[:10]}"
    create_user(
        username=username, password_hash=None, role=DEFAULT_SELF_SIGNUP_ROLE,
        full_name="Guest", email=None, auth_provider="local",
    )
    user = get_user_by_username(username)
    if user is None:  # defensive - insert should always be found by its own username
        return False

    _set_session(user)
    log_action(username, "GUEST_LOGIN", "AUTH", "Started a guest session.")
    return True


def sync_google_session():
    """Call once near the top of app.py, before checking
    is_authenticated(). If Streamlit's own OIDC layer shows a signed-in
    Google identity that this module's session_state doesn't know
    about yet, bridge it in. A no-op whenever Google OAuth isn't
    configured, so it's always safe to call - it never touches
    st.user unless config confirms the [auth] section actually
    exists (accessing st.user without it configured raises)."""
    if is_authenticated() or not config.has_google_oauth_configured():
        return
    if not getattr(st.user, "is_logged_in", False):
        return
    handle_google_login(st.user.email, st.user.get("name") or st.user.email)


SESSION_KEYS = ("authenticated", "user_id", "username", "role", "full_name",
                "login_time", "last_active_at")


def _set_session(user: dict):
    """Populate st.session_state the same way regardless of which
    login method authenticated `user` - every existing page only ever
    reads these same keys. login_time/last_active_at back the idle +
    absolute session-expiration checks in is_authenticated() below."""
    now = time.time()
    st.session_state["authenticated"] = True
    st.session_state["user_id"] = user["id"]
    st.session_state["username"] = user["username"]
    st.session_state["role"] = user["role"]
    st.session_state["full_name"] = user["full_name"]
    st.session_state["login_time"] = now
    st.session_state["last_active_at"] = now


def _clear_session():
    """Pop every session key AND clear Streamlit's own Google identity
    cookie (if any) - without the second part, sync_google_session()
    would just log the same person straight back in on the very next
    run, defeating both logout() and a forced session expiration."""
    for key in SESSION_KEYS:
        st.session_state.pop(key, None)
    if config.has_google_oauth_configured() and getattr(st.user, "is_logged_in", False):
        st.logout()


def logout():
    if st.session_state.get("authenticated"):
        log_action(st.session_state.get("username", "?"), "LOGOUT", "AUTH",
                   "User logged out.")
    _clear_session()


def _expire_session(reason: str):
    """Force-end the current session (idle timeout or absolute
    lifetime reached). Captures the username BEFORE clearing it so the
    audit entry still names who was logged in - never logs a token or
    any other session secret, only the human-readable reason."""
    username = st.session_state.get("username", "?")
    log_action(username, "SESSION_EXPIRED", "AUTH", reason)
    _clear_session()


def is_authenticated() -> bool:
    """True only for a session that is both marked authenticated AND
    still within its idle timeout (config.SESSION_TIMEOUT_MINUTES
    since the last call to this function) and absolute lifetime
    (config.SESSION_ABSOLUTE_TIMEOUT_MINUTES since login) - whichever
    is hit first ends the session. Called on every single page
    render (directly here, and via require_login()), so last_active_at
    is always a true "last seen" timestamp."""
    if not st.session_state.get("authenticated"):
        return False

    now = time.time()
    login_time = st.session_state.get("login_time")
    last_active_at = st.session_state.get("last_active_at")

    if login_time is not None and now - login_time > config.SESSION_ABSOLUTE_TIMEOUT_MINUTES * 60:
        _expire_session(
            f"Session exceeded its maximum lifetime of "
            f"{config.SESSION_ABSOLUTE_TIMEOUT_MINUTES} minutes."
        )
        return False
    if last_active_at is not None and now - last_active_at > config.SESSION_TIMEOUT_MINUTES * 60:
        _expire_session(
            f"Session idle for longer than {config.SESSION_TIMEOUT_MINUTES} minutes."
        )
        return False

    st.session_state["last_active_at"] = now
    return True


def current_role() -> str:
    return st.session_state.get("role", "")


def can_access(page_name: str) -> bool:
    """Role-based access check for a given sidebar page name. Every
    role currently maps to the same full page set (see
    ROLE_PERMISSIONS) - this check stays in place so page-level
    restrictions remain possible to reintroduce later without
    touching app.py."""
    return page_name in ROLE_PERMISSIONS.get(current_role(), set())


def is_admin() -> bool:
    """Whether the current user may manage OTHER users' accounts
    (Settings' 'User Management' section) - the one capability that
    stays admin-only under the per-user data isolation model."""
    return current_role() in ADMIN_ROLES


def require_login():
    """Call at the top of any protected page module. Halts the script
    (via st.stop()) if there is no authenticated user, so a page can
    never render its content to a logged-out visitor."""
    if not is_authenticated():
        st.warning("Please log in to continue.")
        st.stop()
