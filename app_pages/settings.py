"""
Settings page.

Every authenticated user opens this same page and sees "My Account"
(their own profile - read-only, since email/password changes aren't
in scope for this update). Only an ADMIN additionally sees "Create
Account" and "User Management" below it - creating OTHER people's
accounts and enabling/disabling ANY account is a real privilege
boundary (see auth/authentication.py's module docstring and
is_admin()), not something every self-registered user should be able
to do to each other. The page itself is never hidden from anyone;
only that one capability is gated.
"""
import streamlit as st

from auth.authentication import is_admin
from auth.password import hash_password
from database.models import (
    create_user,
    get_user_by_id,
    list_users,
    set_user_active,
    update_user_full_name,
    username_exists,
)
from utils.audit_logger import log_action
from utils.illustrations import (
    BANNER_ICON_HISTORY,
    BANNER_ICON_LOCK,
    BANNER_ICON_SHIELD_CHECK,
    photo_path,
    render_photo,
    render_premium_banner,
)
from utils.page_ui import render_empty_state

# The left-column "account navigation" list. Only "account_details" and
# "security" open a real section built from this app's actual data -
# the other four are genuine, not-yet-built features (no backend for
# notifications/preferences/connected-accounts/privacy exists anywhere
# in this project), so clicking them shows an honest "not available"
# notice instead of a fake working panel. (slug, title, description, icon)
_ACCOUNT_SECTIONS = [
    ("account_details", "Account Details", "View and update your personal information.", ":material/badge:"),
    ("security", "Security", "Manage your password and security settings.", ":material/lock:"),
    ("notifications", "Notifications", "Configure your notification preferences.", ":material/notifications:"),
    ("preferences", "Preferences", "Customise your application preferences.", ":material/tune:"),
    ("connected", "Connected Accounts", "Manage your linked accounts and integrations.", ":material/link:"),
    ("privacy", "Data & Privacy", "Review your data and privacy settings.", ":material/shield_lock:"),
]
_SECTION_META = {slug: (title, desc, icon) for slug, title, desc, icon in _ACCOUNT_SECTIONS}

ROLES = ["ADMIN", "SOC ANALYST", "COMPLIANCE OFFICER", "AUDITOR", "USER"]

# Every ROLES value gets its own accent - purely cosmetic (badge/avatar
# colour), never a second source of truth for permissions (is_admin()
# in auth/authentication.py is still the only thing that gates admin
# capability anywhere in the app).
ROLE_COLORS = {
    "ADMIN": "#DC2626",
    "SOC ANALYST": "#2563EB",
    "COMPLIANCE OFFICER": "#8B5CF6",
    "AUDITOR": "#0D9488",
    "USER": "#16A34A",
}
_ROLE_FALLBACK = "#94A3B8"


def render_settings_page():
    with st.container(key="settings_premium_banner"):
        render_premium_banner(
            badge_text="AI CYBERGUARD &bull; CONTROL CENTER",
            heading_main="Your Account.", heading_accent="Your Rules.",
            description="Manage your own real profile and security preferences - "
                        "nothing here is shared with or visible to other users.",
            features=[
                (BANNER_ICON_LOCK, "Secure Access", "cyan"),
                (BANNER_ICON_SHIELD_CHECK, "Role-Based", "violet"),
                (BANNER_ICON_HISTORY, "Account Activity", "teal"),
            ],
        )
    _render_breadcrumb()
    _render_page_intro()
    _render_my_account()

    if is_admin():
        st.divider()
        with st.container(key="page_panel_purple_create", border=True):
            st.subheader("Create Account (Admin)", icon=":material/person_add:")
            # border=False - this form already sits inside the
            # page_panel_purple_create card above; st.form's own
            # default border would otherwise paint a second, visibly
            # nested box around the fields inside that already-styled
            # panel.
            with st.form("create_user_form", clear_on_submit=True, border=False):
                col1, col2 = st.columns(2)
                with col1:
                    new_username = st.text_input("Username")
                    new_full_name = st.text_input("Full name (optional)")
                with col2:
                    new_role = st.selectbox("Role", ROLES)
                    new_password = st.text_input("Password", type="password")
                confirm_password = st.text_input("Confirm password", type="password")
                submitted = st.form_submit_button("Create Account", icon=":material/person_add:", type="primary")

            if submitted:
                _handle_create_account(new_username, new_full_name, new_role, new_password, confirm_password)

        st.divider()
        with st.container(key="page_panel_blue_users", border=True):
            st.subheader("User Management (Admin)", icon=":material/manage_accounts:")
            st.caption(
                "Every account here has full access to all pages - what differs is "
                "each account only ever sees its OWN data. Disabling an account "
                "blocks it from logging in without deleting its data."
            )
            _render_user_list()


def _role_color(role: str) -> str:
    return ROLE_COLORS.get(role, _ROLE_FALLBACK)


def _avatar_html(label: str, color: str, size: str = "56px") -> str:
    initial = (label or "?").strip()[0].upper()
    return (
        f'<div style="width:{size}; height:{size}; border-radius:50%; '
        f'background: linear-gradient(135deg, {color}, {color}CC); '
        f'display:flex; align-items:center; justify-content:center; '
        f'color:white; font-weight:800; font-size:calc({size} * 0.42); '
        f'box-shadow: 0 4px 14px {color}55;">{initial}</div>'
    )


def _role_badge_html(role: str) -> str:
    color = _role_color(role)
    return (
        f'<span style="display:inline-block; padding:0.25rem 0.75rem; border-radius:999px; '
        f'background:{color}1A; color:{color}; border:1px solid {color}55; '
        f'font-weight:700; font-size:0.78rem; letter-spacing:0.02em;">{role}</span>'
    )


def _render_breadcrumb():
    """Plain text, not links - Home/Settings aren't clickable controls
    here (My Account is the only real destination on this page), so
    they're styled muted rather than link-blue to avoid implying a
    click does something."""
    home_svg = (
        '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/></svg>'
    )
    st.markdown(
        f'<div class="settings-breadcrumb">'
        f'<span class="settings-breadcrumb-icon">{home_svg}</span>'
        f'<span>Home</span><span class="settings-breadcrumb-sep">&rsaquo;</span>'
        f'<span>Settings</span><span class="settings-breadcrumb-sep">&rsaquo;</span>'
        f'<span class="settings-breadcrumb-current">My Account</span>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _render_page_intro():
    st.markdown(
        '<div class="settings-intro">'
        '<span class="settings-intro-icon">'
        '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.5-7 8-7s8 3 8 7"/></svg>'
        '</span>'
        '<span class="settings-intro-text">'
        '<span class="settings-intro-title">My Account</span>'
        '<span class="settings-intro-subtitle">Manage your profile information and account settings.</span>'
        '</span></div>',
        unsafe_allow_html=True,
    )


def _render_my_account():
    user = get_user_by_id(st.session_state["user_id"])
    if user is None:
        render_empty_state("No data available.", "gears_shield")
        return

    section = st.session_state.get("settings_account_section", "account_details")

    left_col, right_col = st.columns([0.42, 0.58], gap="medium")
    with left_col:
        _render_profile_card(user)
        _render_account_nav_card(section)
        _render_activity_card(user)
    with right_col:
        if section == "account_details":
            _render_edit_profile_card(user)
        elif section == "security":
            _render_security_section(user)
        else:
            title, desc, icon = _SECTION_META[section]
            _render_placeholder_section(title, desc, icon)
        _render_security_banner()


def _render_profile_card(user: dict):
    color = _role_color(user["role"])
    has_robot = photo_path("robot_shield") is not None

    with st.container(key="settings_profile_card", border=True):
        avatar_col, name_col, art_col = st.columns([1, 4, 1] if has_robot else [1, 5, 0.001])
        with avatar_col:
            st.markdown(_avatar_html(user["full_name"] or user["username"], color), unsafe_allow_html=True)
        with name_col:
            st.markdown(f"##### {user['full_name'] or user['username']}")
            st.markdown(_role_badge_html(user["role"]), unsafe_allow_html=True)
        if has_robot:
            with art_col:
                render_photo("robot_shield", width=84)
        st.caption("Keep your profile updated for a secure and personalised experience.")


def _render_account_nav_card(active_section: str):
    # One small dynamically-coloured override for whichever row is
    # active THIS run - same convention as the per-row colour
    # injection already used in _render_user_row()/alerts.py, just
    # keyed off session state instead of a DB column.
    st.markdown(
        f'<style>[data-testid="stMain"] .st-key-settings_nav_row_{active_section} {{ '
        f'background: rgba(59, 130, 246, 0.10) !important; '
        f'border-left: 3px solid #3B82F6 !important; }}'
        f'[data-testid="stMain"] .st-key-settings_nav_row_{active_section} button {{ '
        f'color: #1D4ED8 !important; font-weight: 700 !important; }}</style>',
        unsafe_allow_html=True,
    )
    with st.container(key="settings_nav_card", border=True):
        for slug, title, desc, icon in _ACCOUNT_SECTIONS:
            with st.container(key=f"settings_nav_row_{slug}"):
                if st.button(title, icon=icon, key=f"settings_nav_btn_{slug}", width="stretch"):
                    st.session_state["settings_account_section"] = slug
                    st.rerun()
                st.caption(desc)


_ACTIVITY_ICON_SCHEDULE = (
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>'
)
_ACTIVITY_ICON_KEY = (
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="8" cy="15" r="3"/><path d="M10.5 12.5 18 5l2 2-2 2 2 2-2 2"/></svg>'
)
_ACTIVITY_ICON_BADGE = (
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="4" y="4" width="16" height="16" rx="3"/><circle cx="12" cy="10" r="2.3"/>'
    '<path d="M7 18c1-2 3-3 5-3s4 1 5 3"/></svg>'
)
_ACTIVITY_ICON_EVENT = (
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="4" y="5" width="16" height="15" rx="2"/><path d="M4 10h16M8 3v4M16 3v4"/></svg>'
)


def _render_activity_card(user: dict):
    # Hand-authored inline SVGs, not ":material/x:" shorthand - that
    # shorthand only renders through Streamlit's own markdown parser,
    # never inside a raw unsafe_allow_html block (this is exactly what
    # produced the literal ":material_schedule:" text bug).
    rows = [
        (_ACTIVITY_ICON_SCHEDULE, "Last Login", str(user["last_login"]) if user["last_login"] else "Not available"),
        (_ACTIVITY_ICON_KEY, "Sign-in Method", "Google" if user["auth_provider"] == "google" else "Email & Password"),
        (_ACTIVITY_ICON_BADGE, "Account Role", user["role"]),
        (_ACTIVITY_ICON_EVENT, "Account Created", str(user["created_at"]) if user["created_at"] else "Not available"),
    ]
    with st.container(key="settings_activity_card", border=True):
        st.markdown("##### :material/history: Account Activity")
        st.markdown(
            "".join(
                f'<div class="settings-activity-row">'
                f'<span class="settings-activity-icon">{icon}</span>'
                f'<span class="settings-activity-label">{label}</span>'
                f'<span class="settings-activity-value">{value}</span>'
                f"</div>"
                for icon, label, value in rows
            ),
            unsafe_allow_html=True,
        )


def _render_edit_profile_card(user: dict):
    with st.container(key="settings_edit_profile_card", border=True):
        st.markdown("##### :material/edit: Edit Profile")
        st.caption("Update your personal information and account details.")

        with st.form("edit_profile_form", border=False):
            st.text_input("Username", value=user["username"], disabled=True)
            st.text_input("Email", value=user["email"] or "-", disabled=True)
            new_full_name = st.text_input("Full name", value=user["full_name"] or "")
            st.text_input("Role", value=user["role"], disabled=True)

            btn_col = st.columns([3, 1.3])[1]
            with btn_col, st.container(key="settings_update_profile_btn"):
                submitted = st.form_submit_button(
                    "Update Profile", icon=":material/save:", type="primary", width="stretch",
                )

        if submitted:
            _handle_update_profile(user, new_full_name)


def _handle_update_profile(user: dict, new_full_name: str):
    new_full_name = new_full_name.strip()
    if new_full_name == (user["full_name"] or "").strip():
        st.info("No changes to save.")
        return
    update_user_full_name(user["id"], new_full_name)
    st.session_state["full_name"] = new_full_name
    log_action(st.session_state.get("username", "?"), "PROFILE_UPDATED", "AUTH", "Updated full name.")
    st.success("Profile updated.")
    st.rerun()


def _render_security_section(user: dict):
    with st.container(key="settings_edit_profile_card", border=True):
        st.markdown("##### :material/lock: Security")
        st.caption("Manage your password and security settings.")
        st.text_input(
            "Sign-in method",
            value="Google" if user["auth_provider"] == "google" else "Email & Password",
            disabled=True,
        )
        if user["auth_provider"] == "google":
            st.info(
                "This account signs in through Google, so its password is managed by "
                "Google, not AI CyberGuard. There is nothing to change here."
            )
        else:
            st.info("In-app password changes are not available yet.")


def _render_placeholder_section(title: str, desc: str, icon: str):
    with st.container(key="settings_edit_profile_card", border=True):
        st.markdown(f"##### {icon} {title}")
        st.caption(desc)
        st.info("This feature is not available yet in AI CyberGuard.")


def _render_security_banner():
    """A real cyber_lock.png + cyber_shield.png banner - purely
    decorative/informational, not a second settings form (this app
    doesn't implement password/email changes - see the module
    docstring - so this never implies a control that isn't there).
    A real st.container(key=...), not an st.markdown("<div>") opened
    here and closed in a later call - unsafe_allow_html snippets each
    render into their OWN isolated DOM node, so a <div> opened in one
    st.markdown() call never actually wraps a different, later
    st.columns() call; only a real container does that."""
    has_lock = photo_path("lock") is not None
    has_shield = photo_path("shield") is not None
    if not (has_lock or has_shield):
        return

    with st.container(key="settings_security_banner", border=True):
        text_col, art_col = st.columns([3, 1], vertical_alignment="center")
        with text_col:
            st.markdown("##### :material/shield_lock: Keep Your Account Secure")
            st.caption(
                "Ensure your details are up to date and use a strong password to "
                "protect your account."
            )
            if st.button("Go to Security Settings", icon=":material/arrow_forward:", key="settings_goto_security"):
                st.session_state["settings_account_section"] = "security"
                st.rerun()
        with art_col:
            inner_cols = st.columns(2)
            if has_lock:
                with inner_cols[0]:
                    render_photo("lock", width=56)
            if has_shield:
                with inner_cols[1]:
                    render_photo("shield", width=56)


def _handle_create_account(username, full_name, role, password, confirm_password):
    if not username or not password:
        st.error("Username and password are required.")
        return
    if password != confirm_password:
        st.error("Passwords do not match.")
        return
    if len(password) < 8:
        st.error("Password should be at least 8 characters.")
        return
    if username_exists(username):
        st.error(f"Username '{username}' already exists.")
        return

    password_hash = hash_password(password)
    create_user(username, password_hash, role=role, full_name=full_name)
    log_action(
        st.session_state.get("username", "?"),
        "USER_CREATED",
        "ADMIN",
        f"Created account '{username}' with role {role}.",
    )
    st.success(f"Account '{username}' created with role {role}.")
    st.rerun()


def _render_user_list():
    users = list_users()
    if not users:
        render_empty_state("No data available.", "gears_shield")
        return

    _render_user_summary_cards(users)
    st.markdown("")

    current_username = st.session_state.get("username")
    for user in users:
        _render_user_row(user, current_username)


def _render_user_summary_cards(users: list):
    total = len(users)
    active = sum(1 for u in users if u["is_active"])
    disabled = total - active

    cols = st.columns(3)
    with cols[0], st.container(key="kpi_traffic"):
        st.metric(":material/group: Total users", f"{total:,}")
    with cols[1], st.container(key="kpi_compliance_ok"):
        st.metric(":material/check_circle: Active", f"{active:,}")
    with cols[2], st.container(key="kpi_compliance_bad"):
        st.metric(":material/block: Disabled", f"{disabled:,}")


def _render_user_row(user: dict, current_username: str):
    color = _role_color(user["role"])
    row_key = f"user_row_{user['id']}"

    # Role-coloured left border per row, same convention as the Alerts
    # page's per-item style injection (one dynamically-coloured
    # override per real row, keyed by its own unique id).
    st.markdown(
        f'<style>'
        f'[data-testid="stMain"] .st-key-{row_key} [data-testid="stLayoutWrapper"],'
        f'[data-testid="stMain"] .st-key-{row_key}.st-key-{row_key} {{'
        f'border-left: 4px solid {color} !important; '
        f'background: linear-gradient(90deg, {color}0D, transparent 60%) !important;'
        f"}}</style>",
        unsafe_allow_html=True,
    )

    with st.container(key=row_key, border=True):
        cols = st.columns([0.6, 1.6, 1.6, 1.8, 1, 1.6, 1])
        with cols[0]:
            st.markdown(_avatar_html(user["full_name"] or user["username"], color, size="36px"), unsafe_allow_html=True)
        cols[1].write(f"**{user['username']}**")
        with cols[2]:
            st.markdown(_role_badge_html(user["role"]), unsafe_allow_html=True)
        cols[3].write(user["full_name"] or "-")
        if user["is_active"]:
            cols[4].markdown(":green[:material/check_circle:] Active")
        else:
            cols[4].markdown(":red[:material/block:] Disabled")
        cols[5].caption(str(user["last_login"]) if user["last_login"] else "Never logged in")

        if user["username"] == current_username:
            cols[6].caption("(you)")
            return

        toggle_label = "Disable" if user["is_active"] else "Enable"
        toggle_icon = ":material/block:" if user["is_active"] else ":material/check_circle:"
        if cols[6].button(toggle_label, key=f"toggle_user_{user['id']}", icon=toggle_icon, width="stretch"):
            set_user_active(user["id"], not user["is_active"])
            log_action(
                current_username or "?",
                "USER_STATUS_CHANGED",
                "ADMIN",
                f"{'Disabled' if user['is_active'] else 'Enabled'} account '{user['username']}'.",
            )
            st.rerun()
