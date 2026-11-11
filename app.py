"""
Application entry point.

Run with:

    streamlit run app.py

Responsibilities:
  1. If no user is authenticated, show the login page.
  2. Once authenticated, show the sidebar and route to the selected page.
     Every authenticated user - any role - sees every page (see
     auth/authentication.py's ROLE_PERMISSIONS); each page's DATA is what
     is scoped to the current user, not the page itself.

NOTE: page modules live in "app_pages/", not "pages/". Streamlit
auto-generates its OWN navigation sidebar from any .py file inside a folder
literally named "pages/" next to this script - and it runs each of those
files directly, with no way for them to go through the login/role checks
below. Renaming the folder avoids that collision, so this single router is
the only way into any page.
"""
import html

import streamlit as st

import mysql.connector
import config
from auth.authentication import can_access, is_authenticated, sync_google_session
from auth.login import render_login_page
from app_pages.alerts import render_alerts_page
from app_pages.audit_logs import render_audit_logs_page
from app_pages.compliance import render_compliance_page
from app_pages.dashboard import render_dashboard_page
from app_pages.reports import render_reports_page
from app_pages.settings import render_settings_page
from app_pages.threat_detection import render_threat_detection_page
from app_pages.url_scanner import render_url_scanner_page
from utils.illustrations import ILLUSTRATIONS
from utils.page_ui import PAGE_ICONS, consume_pending_nav_jump, jump_to_page, render_top_bar
from utils.theme import inject_global_theme
from utils.time_navigator import render_sidebar_navigator

st.set_page_config(page_title="AI CyberGuard", page_icon="🛡️", layout="wide")

# PAGE_ICONS lives in utils/page_ui.py (shared with jump_to_page()). The
# dict's key order is the canonical page list; NAV_GROUPS decides how those
# pages are grouped in the sidebar.
ALL_PAGES = list(PAGE_ICONS.keys())

# The shield svg deliberately has explicit width/height (not just a
# viewBox) - an <svg> with no size attributes and no CSS constraint
# renders at the browser's own default intrinsic size (historically
# ~300x150px), which is exactly the "giant icon" failure mode this
# project has hit (and fixed) elsewhere. utils/theme.py's
# .sidebar-brand/.sidebar-brand svg rules are the belt-and-braces CSS
# backup; the attributes here are the real fix.
_BRAND_HTML = """
<div class="sidebar-brand">
  <svg width="52" height="52" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M12 2.6 20 5.7v6.1c0 5-3.4 8.5-8 10.3-4.6-1.8-8-5.3-8-10.3V5.7z"
          stroke="url(#cgBrand)" stroke-width="1.7" stroke-linejoin="round"/>
    <path d="M8.7 11.9 11 14.2l4.3-4.4" stroke="#22D3EE" stroke-width="1.9"
          stroke-linecap="round" stroke-linejoin="round"/>
    <defs>
      <linearGradient id="cgBrand" x1="4" y1="2" x2="20" y2="22">
        <stop stop-color="#22D3EE"/><stop offset="1" stop-color="#0EA5E9"/>
      </linearGradient>
    </defs>
  </svg>
  <div class="sidebar-brand-text">
    <span class="sidebar-wordmark">AI CyberGuard</span>
    <p class="sidebar-tagline">Secure &middot; Detect &middot; Comply</p>
  </div>
</div>
"""


def _sidebar_identity_html(name: str, role: str) -> str:
    """Avatar + name + role + a purely decorative chevron (the account
    popover with REAL account details already lives in the top bar via
    utils/page_ui.py's render_top_bar() - this block never claims to
    be its own dropdown, it just echoes the signed-in identity the way
    the reference design places it, right under the logo)."""
    safe_name = html.escape(name or "?")
    initial = html.escape((name or "?").strip()[:1].upper())
    safe_role = html.escape((role or "").title())
    return (
        f'<div class="sidebar-identity">'
        f'<span class="sidebar-avatar">{initial}</span>'
        f'<span class="sidebar-identity-text">'
        f'<span class="sidebar-identity-name">{safe_name}</span>'
        f'<span class="sidebar-identity-role">{safe_role}</span>'
        f'</span>'
        f'<span class="sidebar-chevron">&#x2304;</span>'
        f'</div>'
    )


def _render_database_error(exc: Exception):
    """Shown instead of an unhandled traceback whenever MySQL can't be
    reached. st.stop() halts the script so no page below this point ever
    tries to run against a database that isn't there. Nothing here prints
    credentials - only the library's own host/port message."""
    st.error(
        "**Could not connect to the database.**\n\n"
        "AI CyberGuard needs MySQL running and reachable with the credentials "
        "in your `.env` file before it can show anything that depends on "
        "stored data (including signing in). Common fixes:\n"
        "- Start your MySQL server - e.g. the XAMPP Control Panel's **MySQL** "
        "module, or your MySQL Windows service.\n"
        "- Check that `DB_HOST`/`DB_PORT` in `.env` match where MySQL is "
        "actually listening (default: `localhost:3306`).\n"
        "- Confirm the `ai_cyberguard` database and its tables exist "
        "(see `database/schema.sql`) and that `DB_USER`/`DB_PASSWORD` are "
        "correct for that server.\n\n"
        f"Technical detail: {exc}"
    )
    st.stop()


def render_placeholder(page_name: str):
    st.info(f"{page_name} has not been built yet. It is scheduled for a later development step.")


def _render_page(page_name: str):
    if page_name == "Dashboard":
        render_dashboard_page()
    elif page_name == "Threat Detection":
        render_threat_detection_page()
    elif page_name == "URL Scanner":
        render_url_scanner_page()
    elif page_name == "Compliance Monitoring":
        render_compliance_page()
    elif page_name == "Alerts & Incidents":
        render_alerts_page()
    elif page_name == "Reports":
        render_reports_page()
    elif page_name == "Audit Logs":
        render_audit_logs_page()
    elif page_name == "Settings":
        render_settings_page()
    else:
        render_placeholder(page_name)


def render_app():
    inject_global_theme()

    # Must run BEFORE the sidebar's st.radio(key="sidebar_nav") below:
    # applies a jump_to_page() request queued by the previous run (e.g.
    # a dashboard KPI card's "View details" button), by writing that
    # widget's own session_state value before it is instantiated this
    # run - setting it after would raise
    # StreamlitWidgetAlreadyInstantiatedError.
    consume_pending_nav_jump()

    with st.sidebar:
        st.markdown(ILLUSTRATIONS["sidebar_network_bg"], unsafe_allow_html=True)

        with st.container(key="sidebar_brand"):
            st.markdown(_BRAND_HTML, unsafe_allow_html=True)

        full_name = st.session_state.get("full_name") or st.session_state.get("username", "")
        role = st.session_state.get("role", "")
        with st.container(key="sidebar_user_card"):
            st.markdown(
                _sidebar_identity_html(full_name or st.session_state.get("username", "?"), role),
                unsafe_allow_html=True,
            )

        accessible = [p for p in ALL_PAGES if can_access(p)]
        labels = [f":material/{PAGE_ICONS[p]}: {p}" for p in accessible]
        chosen_label = st.radio(
            "Navigation", labels, label_visibility="collapsed", key="sidebar_nav",
        )
        page_name = accessible[labels.index(chosen_label)] if chosen_label else accessible[0]

        st.divider()
        render_sidebar_navigator(page_name)

        st.divider()
        with st.container(key="logout_btn"):
            if st.button("Logout", icon=":material/logout:", width="stretch"):
                from auth.authentication import logout

                logout()
                st.rerun()

    render_top_bar(page_name, ALL_PAGES, on_jump=jump_to_page)
    _render_page(page_name)


_env_ok, _missing_env, _env_warnings = config.validate_required_env()
if not _env_ok:
    st.error(
        "**AI CyberGuard is missing required configuration.**\n\n"
        "The following setting(s) must be set in your `.env` file before the "
        "app can start:\n\n"
        + "\n".join(f"- `{name}`" for name in _missing_env)
        + "\n\nSee `.env.example` for the expected format. "
        "(Only the missing setting NAMES are shown here - never their values.)"
    )
    st.stop()
for _warning in _env_warnings:
    st.warning(_warning)

try:
    sync_google_session()
except mysql.connector.Error as e:
    _render_database_error(e)

if not is_authenticated():
    render_login_page()
else:
    try:
        render_app()
    except mysql.connector.Error as e:
        _render_database_error(e)
