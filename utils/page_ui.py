"""
Small reusable page-chrome helpers shared by every app_pages/*.py
module, so the "header card + corner illustration" and "empty state
illustration" patterns are written once instead of copy-pasted 8 times.

render_empty_state() is pure presentation and touches nothing but the
display. render_top_bar() is the one exception - it reads real data
(DB connectivity, the current user's own NEW alert count, and for
Alerts & Incidents specifically its own real NEW+INVESTIGATING count)
because a status/notification bar that always just says "All systems
operational" with a static bell icon would be exactly the kind of
"decorative control with no real action" this project's own rules
forbid. Its search box is a real, working page-jump (not a placeholder
either) - see its own docstring.

render_top_bar() is now the SINGLE place a page's own icon/title/
subtitle renders (previously duplicated: a plain top bar here PLUS
each page's own render_page_header() card below it, both printing the
page name). One unified header row avoids that duplicate-title/
duplicate-card look; render_page_header() stays defined for any
future reuse but no page module calls it from here on.
"""
import streamlit as st

from database.connection import test_connection
from database.models import get_alert_status_counts, get_alerts, get_new_alert_count
from utils.illustrations import ILLUSTRATIONS, place

# Canonical page name -> Material Symbols icon name. app.py builds the
# sidebar nav options from this (and defines navigation order), and
# jump_to_page() below uses it to build the exact same label string
# the sidebar radio expects - having one shared source instead of two
# copies is what keeps a page-jump link from any page module (e.g.
# a dashboard KPI card's "View details" button) from ever drifting out
# of sync with app.py's own icon choices.
PAGE_ICONS = {
    "Dashboard": "dashboard",
    "Threat Detection": "security",
    "URL Scanner": "link",
    "Compliance Monitoring": "balance",
    "Alerts & Incidents": "notifications",
    "Reports": "description",
    "Audit Logs": "history",
    "Settings": "settings",
}

# Per-page header content: subtitle (real, static copy - not derived
# from data) and an accent colour (icon box + header's left edge
# stripe). "status_label" is shown ONLY when the real DB health check
# below passes - it is flavour text for a REAL positive state, never
# an override of a real failure (Alerts & Incidents gets None here
# because its status is computed live from real alert counts instead
# of a static string - see render_top_bar()).
PAGE_META = {
    "Dashboard": {
        "subtitle": "Overview of your security posture",
        "accent": "#3B82F6", "status_label": "All Systems Operational",
    },
    "Threat Detection": {
        "subtitle": "Analyse network traffic with AI",
        "accent": "#FB7185", "status_label": "Monitoring for Threats",
    },
    "URL Scanner": {
        "subtitle": "Check URLs for malicious activity",
        "accent": "#14B8A6", "status_label": "Scanner Active",
    },
    "Compliance Monitoring": {
        "subtitle": "Assess security framework compliance",
        "accent": "#8B5CF6", "status_label": "Compliance Monitoring",
    },
    "Alerts & Incidents": {
        "subtitle": "View and manage security incidents",
        "accent": "#F97316", "status_label": None,
    },
    "Reports": {
        "subtitle": "Generate and view security reports",
        "accent": "#6366F1", "status_label": "Reports Ready",
    },
    "Audit Logs": {
        "subtitle": "Track system activity and changes",
        "accent": "#22D3EE", "status_label": "Logging Active",
    },
    "Settings": {
        "subtitle": "Manage your account and preferences",
        "accent": "#8B5CF6", "status_label": "System Configured",
    },
}

# One small inline-SVG line icon per page, for the header's icon box.
# NOT the ":material/x:" shorthand here - that shorthand only renders
# through Streamlit's own markdown parser, not inside a raw HTML
# string, and the icon box below is one single raw HTML block (see
# why in _topbar_identity_html's docstring). stroke="currentColor"
# lets the surrounding .topbar-page-icon's `color` CSS (set per-page,
# from PAGE_META's accent) recolour each one without a second copy
# per colour.
_TOPBAR_ICONS = {
    "Dashboard": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/>'
        '<rect x="3" y="13" width="8" height="8" rx="2"/><rect x="13" y="13" width="8" height="8" rx="2"/></svg>'
    ),
    "Threat Detection": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 3 19 6v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/><path d="M9 12l2 2 4-4"/></svg>'
    ),
    "URL Scanner": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M11 7l2.5-2.5a3.5 3.5 0 0 1 5 5L16 12"/>'
        '<path d="M13 17l-2.5 2.5a3.5 3.5 0 0 1-5-5L8 12"/>'
        '<path d="M9 15l6-6"/></svg>'
    ),
    "Compliance Monitoring": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="5" y="3" width="14" height="18" rx="2"/>'
        '<path d="M8 8h8M8 12h8M8 16h5"/></svg>'
    ),
    "Alerts & Incidents": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 4c-3 0-5 2.5-5 6v3l-2 3h14l-2-3v-3c0-3.5-2-6-5-6z"/>'
        '<path d="M10 18a2 2 0 0 0 4 0"/></svg>'
    ),
    "Reports": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
        'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M4 20V13M10 20V7M16 20v-6"/><path d="M3 20h18" stroke-width="1.6"/></svg>'
    ),
    "Audit Logs": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/></svg>'
    ),
    "Settings": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="12" r="3"/>'
        '<path d="M12 3v3M12 18v3M21 12h-3M6 12H3M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1'
        'M18.4 18.4l-2.1-2.1M7.7 7.7 5.6 5.6"/></svg>'
    ),
}


def _topbar_identity_html(page_name: str, meta: dict) -> str:
    """One self-contained HTML block (icon box + title + subtitle) -
    deliberately NOT a bordered st.container() for the icon: a
    border=True container's box is sized by Streamlit's own layout
    engine (column width + content height), which does not reliably
    respect an exact pixel square via CSS and is what produced the
    earlier "tall narrow icon box" bug. A single raw HTML flex row has
    no such ambiguity - the 44px square is real CSS, not a guess at
    how Streamlit will lay out a nested container."""
    return (
        f'<div class="topbar-page">'
        f'<span class="topbar-page-icon" style="background:linear-gradient(135deg,{meta["accent"]}29,{meta["accent"]}12);'
        f'border:1px solid {meta["accent"]}55;color:{meta["accent"]};">'
        f'{_TOPBAR_ICONS.get(page_name, _TOPBAR_ICONS["Dashboard"])}</span>'
        f'<span class="topbar-page-text">'
        f'<span class="topbar-title">{page_name}</span>'
        f'<span class="topbar-subtitle">{meta["subtitle"]}</span>'
        f'</span></div>'
    )


def jump_to_page(page_name: str):
    """Request a navigation to `page_name` - call this, then st.rerun(),
    from anywhere (a dashboard KPI card's "View details" button, etc.).

    This does NOT write to the sidebar radio's own session_state key
    directly - app.py's sidebar renders BEFORE routed page content, so
    a page module calling this from within its own render function runs
    AFTER that widget is already instantiated for this run, and
    Streamlit forbids writing a widget's key after that
    (StreamlitWidgetAlreadyInstantiatedError). Instead this sets a
    plain, non-widget flag that app.py's render_app() consumes at the
    very top of the NEXT run, before the sidebar is created - safe
    regardless of where the caller sits in the current run."""
    st.session_state["_pending_nav_jump"] = page_name


def consume_pending_nav_jump():
    """Call once, at the very top of app.py's render_app() - before the
    sidebar - to apply a jump_to_page() request queued on the previous
    run. A no-op if nothing is pending."""
    page_name = st.session_state.pop("_pending_nav_jump", None)
    if page_name in PAGE_ICONS:
        st.session_state["sidebar_nav"] = f":material/{PAGE_ICONS[page_name]}: {page_name}"


def render_page_header(title: str, icon: str, caption: str,
                        illustration: str, illustration_color: str = "#0EA5E9"):
    """Wrap a page's st.header()/st.caption() in the shared light
    'page_header_card' panel (see utils/theme.py) with one faint
    corner illustration. Safe to call with the same container key from
    every page module - only one page ever renders per script run."""
    with st.container(key="page_header_card", border=True):
        st.markdown(
            place(illustration, color=illustration_color, width="120px", height="90px"),
            unsafe_allow_html=True,
        )
        st.header(title, icon=icon)
        if caption:
            st.caption(caption)


def render_top_bar(page_name: str, all_pages: list, on_jump):
    """The single header row rendered once from app.py's render_app(),
    above the routed page content - replaces what used to be a plain
    status/search bar here PLUS a second icon+title+caption card each
    page rendered again for itself (render_page_header()). Six real,
    working pieces, nothing decorative-only:

    - Page identity: `page_name` + PAGE_META's real, static subtitle/
      accent/illustration for that page - not derived from data, but
      not duplicated either (this is now the ONE place a page's name
      is printed).
    - Search: a page-name filter. On a single unique substring match
      (committed when the input loses focus / Enter is pressed, same
      as any st.text_input), it calls `on_jump(page_name)` - app.py
      supplies this as a small closure that sets the sidebar nav
      radio's own session_state value and reruns, so "search" actually
      navigates, it doesn't just sit there looking like it might.
    - System status: a real database connectivity check
      (database.connection.test_connection()) each render - the
      per-page "status_label" text only ever appears when that check
      is healthy; a real failure always shows "Database Unreachable"
      regardless of which page it is. Alerts & Incidents overrides
      this with its OWN real figure - its current NEW+INVESTIGATING
      count - since "page is reachable" is less relevant there than
      "how many incidents need attention right now".
    - Notifications: the CURRENT user's own real count of alerts still
      in status NEW (database.models.get_new_alert_count), with the
      popover listing the real most-recent ones
      (database.models.get_alerts(..., status="NEW")) - never a
      fabricated number or example alert.
    - Account: the authenticated session's own full_name/role - never
      hardcoded.
    """
    meta = PAGE_META.get(page_name, PAGE_META["Dashboard"])
    user_id = st.session_state.get("user_id")

    # Deferred clear: a widget's own session_state key can only be
    # written BEFORE that widget is instantiated in a given run - not
    # after (same constraint sidebar_nav runs into in app.py). So a
    # successful jump below doesn't clear "top_bar_search" directly;
    # it sets this flag and reruns, and THIS line, which runs before
    # the text_input is created, is where the actual clear happens -
    # on the NEXT run, before instantiation, where it's allowed.
    # Without this, the matched text would stay in the box forever and
    # re-trigger the same jump+rerun on every future run - an infinite
    # loop, not just a cosmetic leftover.
    if st.session_state.pop("_top_bar_clear_search", False):
        st.session_state["top_bar_search"] = ""

    # One dynamically-coloured override for THIS run's page - real,
    # computed from PAGE_META, not hard-coded per call site. Every
    # other page reuses the exact same "top_bar" key, just re-tinted,
    # so there is still only one header component, not eight
    # near-duplicates. The icon box itself is now plain HTML (see
    # _topbar_identity_html) - no container-key styling needed for it.
    st.markdown(
        f'<style>[data-testid="stMain"] .st-key-top_bar {{ '
        f'border-left: 4px solid {meta["accent"]} !important; }}</style>',
        unsafe_allow_html=True,
    )

    with st.container(key="top_bar"):
        cols = st.columns([2.7, 3.6, 1.35, 0.8, 1.7], vertical_alignment="center")

        with cols[0]:
            st.markdown(_topbar_identity_html(page_name, meta), unsafe_allow_html=True)

        with cols[1]:
            query = st.text_input(
                "Search pages", placeholder="Search threats, URLs, reports, users...",
                label_visibility="collapsed", key="top_bar_search",
            )
            q = query.strip().lower()
            if q:
                matches = [p for p in all_pages if q in p.lower()]
                if len(matches) == 1:
                    on_jump(matches[0])
                    st.session_state["_top_bar_clear_search"] = True
                    st.rerun()
                elif len(matches) > 1:
                    st.caption("Matches: " + ", ".join(matches))
                else:
                    st.caption("No matching page.")

        with cols[2]:
            # A plain CSS dot, not a ":material:" icon glyph - that
            # shorthand only renders through Streamlit's own markdown
            # parser, which this unsafe_allow_html block bypasses
            # entirely (it would otherwise show up as literal text).
            db_ok, _ = test_connection()
            if not db_ok:
                text, css_class = "Database Unreachable", "top-bar-status-bad"
            elif page_name == "Alerts & Incidents":
                active = sum(
                    row["count"] for row in get_alert_status_counts(user_id)
                    if row["status"] in ("NEW", "INVESTIGATING")
                ) if user_id else 0
                text = f"{active} Active" if active else "No Active Incidents"
                css_class = "top-bar-status-bad" if active else "top-bar-status-ok"
            else:
                text, css_class = meta["status_label"], "top-bar-status-ok"
            st.markdown(
                f'<div class="top-bar-status {css_class}">'
                f'<span class="top-bar-status-dot"></span><span>{text}</span></div>',
                unsafe_allow_html=True,
            )

        with cols[3]:
            # No width="stretch" - a popover trigger stretched into a
            # narrow column is what squeezed/clipped the bell icon
            # before; sized to its own (tiny) content, it stays a
            # clean square regardless of how the columns divide up.
            new_count = get_new_alert_count(user_id) if user_id else 0
            bell_label = f":material/notifications: {new_count}" if new_count else ":material/notifications:"
            with st.popover(bell_label):
                st.markdown("**New alerts**")
                if new_count == 0:
                    st.caption("No new alerts.")
                else:
                    for a in get_alerts(user_id, status="NEW", limit=5):
                        st.write(f"**{a['threat_ref']}** - {a['event_type']} ({a['severity']})")
                    if new_count > 5:
                        st.caption(f"+{new_count - 5} more.")
                    st.caption("See Alerts & Incidents for full details.")

        with cols[4]:
            full_name = st.session_state.get("full_name") or st.session_state.get("username", "")
            role = st.session_state.get("role", "")
            first_name = full_name.split()[0] if full_name else "Account"
            with st.popover(f":material/account_circle: {first_name}"):
                st.write(f"**{full_name or st.session_state.get('username', '?')}**")
                st.caption(role)

    # The Global Cyber Time Navigator now lives in the sidebar (see
    # app.py's render_app() -> utils/time_navigator.py's
    # render_sidebar_navigator()) - this header stays exactly the
    # identity/search/status/bell/account row it always was before
    # the navigator was ever added here.


def render_empty_state(message: str, illustration: str, color: str = "#94A3B8"):
    """A centred, faint illustration + the page's own real
    'No data available'-style message - never a fabricated example
    record. Used wherever a page already shows st.info('No data...')
    for an empty query result."""
    svg = ILLUSTRATIONS[illustration]
    st.markdown(
        f'<div class="td-empty-state">'
        f'<div style="width:100px;height:80px;margin:0 auto;color:{color};opacity:0.35;">{svg}</div>'
        f"</div>",
        unsafe_allow_html=True,
    )
    st.info(message)
