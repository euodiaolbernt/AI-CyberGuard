"""
Global Cyber Time Navigator - a shared date-range filter rendered once
per page load, in the sidebar (see app.py's render_app() ->
render_sidebar_navigator()'s own docstring), below the navigation
links. Every feature page's own query code reads the current selection
via get_active_range(), so one shared filter drives Dashboard, Threat
Detection, URL Scanner, Compliance Monitoring, Alerts & Incidents,
Reports, and Audit Logs - not seven page-local copies.

SESSION STATE (the 3 keys the feature spec names):
  cyber_time_period      - one of PERIOD_KEYS, or "custom"
  cyber_time_start_date  - date | None (meaningful only when period == "custom")
  cyber_time_end_date    - date | None (meaningful only when period == "custom")

MALAYSIA LOCAL TIME: every "today"/"this month"/etc. boundary below is
computed from Asia/Kuala_Lumpur wall-clock time, independent of the
host machine's own system timezone - consistent with this project's
existing deployment assumption that the MySQL server's own clock is
also set to Malaysia time (every DATETIME column here is naive,
written via NOW()/CURRENT_TIMESTAMP - see database/schema.sql).

INCLUSIVE END, NOT A DATABASE REWRITE: database/models.py's existing
start_date/end_date query parameters are already proven, parameterized,
and in production use (Reports, Alerts) with an INCLUSIVE `<= end_date`
boundary (e.g. end_date = datetime.combine(day, time.max)). Rather than
rewriting ~15 already-working WHERE clauses to a literal half-open
`< next-day-midnight` form, get_active_range() returns the
mathematically equivalent inclusive end timestamp
(23:59:59.999999 on the last included day) - zero behavioural
difference, zero risk to already-tested queries.

Selecting a period NEVER queries the database, retrains a model, or
reruns detection by itself - it only changes what get_active_range()
returns to whichever page's own code calls it next.
"""
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

import streamlit as st

from utils.illustrations import photo_path

MALAYSIA_TZ = ZoneInfo("Asia/Kuala_Lumpur")

PERIOD_LABELS = {
    "today": "Today",
    "yesterday": "Yesterday",
    "last_7_days": "7 Days Ago",
    "last_month": "Last Month",
    "last_year": "Last Year",
    "all_time": "All Time",
}
PERIOD_KEYS = list(PERIOD_LABELS.keys())

_STATE_PERIOD = "cyber_time_period"
_STATE_START = "cyber_time_start_date"
_STATE_END = "cyber_time_end_date"
_WIDGET_PRESET = "_cyber_time_preset_widget"
_FLAG_RESET = "_cyber_time_reset_pending"
_FLAG_SHOW_CUSTOM = "_cyber_time_show_custom"
_STATE_EXPANDED = "cyber_time_nav_expanded"
# What the preset dropdown was last successfully synced TO - needed
# because _STATE_PERIOD can be "custom", a value the dropdown (options
# are only the 7 presets) can never actually show; comparing the
# dropdown's current value against _STATE_PERIOD directly would see
# "custom" as a mismatch on EVERY render once custom is active and
# incorrectly snap back to a preset - see render_sidebar_navigator()'s
# own comment at its one read site for the full explanation.
_STATE_LAST_SYNC = "_cyber_time_last_widget_sync"

# Pages where a time-based activity filter makes sense - Settings holds
# static account/profile data only (per the feature spec's own
# exclusion), so the navigator row is skipped there rather than shown
# next to controls it would have no effect on.
SUPPORTED_PAGES = {
    "Dashboard", "Threat Detection", "URL Scanner", "Compliance Monitoring",
    "Alerts & Incidents", "Reports", "Audit Logs",
}


def _now_myt() -> datetime:
    """Naive 'now' in Malaysia time - see this module's own docstring
    for why naive (matches the naive DATETIME columns already written
    via MySQL's own NOW())."""
    return datetime.now(MALAYSIA_TZ).replace(tzinfo=None)


def _today_myt() -> date:
    return _now_myt().date()


def _day_bounds(d: date) -> tuple[datetime, datetime]:
    return datetime.combine(d, time.min), datetime.combine(d, time.max)


def compute_date_range(period: str, custom_start: date = None, custom_end: date = None):
    """Return (start_datetime, end_datetime_inclusive, label_text) for
    `period`. Both datetimes are None only for "all_time" (and for an
    incomplete/invalid "custom" selection) - no restriction at all,
    never a fabricated huge range standing in for "all". Every boundary
    is a real calendar computation from Malaysia-local "today", nothing
    estimated or hard-coded."""
    today = _today_myt()

    if period == "today":
        start, end = _day_bounds(today)
        return start, end, "Showing activity for today"

    if period == "yesterday":
        y = today - timedelta(days=1)
        start, end = _day_bounds(y)
        return start, end, "Showing activity for yesterday"

    if period == "last_7_days":
        start, _ = _day_bounds(today - timedelta(days=6))
        _, end = _day_bounds(today)
        return start, end, "Showing activity for the last 7 days"

    if period == "last_month":
        first_this_month = today.replace(day=1)
        last_day_prev_month = first_this_month - timedelta(days=1)
        first_prev_month = last_day_prev_month.replace(day=1)
        start, _ = _day_bounds(first_prev_month)
        _, end = _day_bounds(last_day_prev_month)
        return start, end, f"Showing activity for {first_prev_month:%B %Y}"

    if period == "last_year":
        start, _ = _day_bounds(today - timedelta(days=364))
        _, end = _day_bounds(today)
        return start, end, "Showing activity for the last year"

    if period == "custom" and custom_start and custom_end and custom_start <= custom_end:
        start, _ = _day_bounds(custom_start)
        _, end = _day_bounds(custom_end)
        return start, end, f"Showing activity for {custom_start:%d %b %Y} - {custom_end:%d %b %Y}"

    return None, None, "Showing activity for all time"


def symmetric_prior_window(start: datetime, end: datetime):
    """The immediately-preceding window of the SAME length as
    [start, end] - e.g. for "last_7_days" this is the 7 days before
    that; for "this_month" it's (approximately) last month; for a
    custom range it's an equal-length range right before it. Used for
    "vs previous period" KPI deltas that stay well-defined for ANY
    selected period, not just a hard-coded trailing-7-days comparison.
    Returns (None, None) when there is nothing to compare against
    (start/end is None, i.e. "All Time" is active)."""
    if start is None or end is None:
        return None, None
    duration = end - start
    prev_end = start - timedelta(microseconds=1)
    prev_start = prev_end - duration
    return prev_start, prev_end


def init_time_navigator_state():
    st.session_state.setdefault(_STATE_PERIOD, "today")
    st.session_state.setdefault(_STATE_START, None)
    st.session_state.setdefault(_STATE_END, None)
    st.session_state.setdefault(_STATE_LAST_SYNC, "today")


def get_active_range():
    """(start_datetime, end_datetime_inclusive, label_text) for
    whatever period is CURRENTLY selected - call this from any page's
    own query code, every rerun. A pure read of session_state, never a
    widget and never a database call itself."""
    init_time_navigator_state()
    period = st.session_state[_STATE_PERIOD]
    return compute_date_range(period, st.session_state.get(_STATE_START), st.session_state.get(_STATE_END))


def _consume_pending_reset():
    """Deferred clear, consumed before any of this row's widgets are
    instantiated this run - same pattern already used elsewhere in this
    app (utils/page_ui.py's consume_pending_nav_jump / top-bar search
    clear) to avoid StreamlitWidgetAlreadyInstantiatedError."""
    if st.session_state.pop(_FLAG_RESET, False):
        st.session_state[_STATE_PERIOD] = "today"
        st.session_state.pop(_WIDGET_PRESET, None)
        st.session_state[_STATE_LAST_SYNC] = "today"
        st.session_state[_STATE_START] = None
        st.session_state[_STATE_END] = None
        st.session_state[_FLAG_SHOW_CUSTOM] = False


def _range_badge_text(period: str, start, end) -> str:
    label = PERIOD_LABELS.get(period, "Custom Range")
    if start is None or end is None:
        return "All Time"
    if start.date() == end.date():
        return f"{label} &middot; {start:%d %b %Y}"
    return f"{label} &middot; {start:%d %b} - {end:%d %b %Y}"


def render_sidebar_navigator(page_name: str):
    """The Global Cyber Time Navigator, in the sidebar - a vertical,
    minimalist strip below the navigation links: a small robot +
    active-range badge, a single compact preset dropdown (not a row of
    pills - a sidebar is too narrow for 7 side-by-side buttons), and a
    Custom/Reset pair underneath. A no-op on pages with nothing time-
    based to filter (see SUPPORTED_PAGES).

    Selecting a period, applying a custom range, or resetting all still
    call st.rerun() - a FULL app rerun, not fragment-scoped - since the
    main content area's KPIs/charts (rendered from a completely
    different part of the script) must reflect the new selection too."""
    if page_name not in SUPPORTED_PAGES:
        return

    _consume_pending_reset()
    init_time_navigator_state()

    robot_path = photo_path("robot_time_navigator")
    start, end, _ = get_active_range()
    period = st.session_state[_STATE_PERIOD]

    with st.container(key="sidebar_time_navigator"):
        if robot_path is not None:
            art_col, title_col = st.columns([0.6, 2.2], vertical_alignment="center")
            with art_col:
                st.image(str(robot_path), width=34)
        else:
            title_col = st.container()
        with title_col:
            st.markdown('<div class="sbn-title">TIME NAVIGATOR</div>', unsafe_allow_html=True)

        st.markdown(
            f'<div class="sbn-badge">{_range_badge_text(period, start, end)}</div>',
            unsafe_allow_html=True,
        )

        chosen = st.selectbox(
            "Period", PERIOD_KEYS,
            index=PERIOD_KEYS.index(period) if period in PERIOD_KEYS else 0,
            format_func=lambda k: PERIOD_LABELS[k],
            key=_WIDGET_PRESET, label_visibility="collapsed",
        )

        btn_cols = st.columns(2)
        with btn_cols[0]:
            custom_clicked = st.button(
                "Custom", icon=":material/edit_calendar:", key="cyber_time_custom_toggle", width="stretch",
            )
        with btn_cols[1]:
            reset_clicked = st.button(
                "Reset", icon=":material/restart_alt:", key="cyber_time_reset_btn", width="stretch",
            )

        if custom_clicked:
            st.session_state[_FLAG_SHOW_CUSTOM] = not st.session_state.get(_FLAG_SHOW_CUSTOM, False)
            st.rerun()
        if reset_clicked:
            st.session_state[_FLAG_RESET] = True
            st.rerun()

        # Compared against _STATE_LAST_SYNC, NOT `period` directly:
        # `period` can be "custom" - a value this dropdown can never
        # actually hold (its options are only the 7 presets) - so once
        # custom is active, `chosen` (whatever the dropdown falls back
        # to) would ALWAYS differ from `period`, incorrectly firing
        # this block on every single render and snapping straight back
        # to a preset the instant Apply Range was clicked. A real,
        # caught bug during development - this comment is why the
        # comparison is against _STATE_LAST_SYNC instead.
        last_synced = st.session_state.get(_STATE_LAST_SYNC)
        if chosen is not None and chosen != last_synced and chosen != period:
            st.session_state[_STATE_PERIOD] = chosen
            st.session_state[_STATE_START] = None
            st.session_state[_STATE_END] = None
            st.session_state[_FLAG_SHOW_CUSTOM] = False
            st.session_state[_STATE_LAST_SYNC] = chosen
            st.rerun()

        _render_custom_range_panel()


def _render_custom_range_panel():
    """Stacked (not side-by-side) date inputs + Apply/Close - a narrow
    sidebar has no room for the 4-across layout a wide header panel
    could use."""
    show = st.session_state.get(_FLAG_SHOW_CUSTOM, False) or st.session_state[_STATE_PERIOD] == "custom"
    if not show:
        return

    with st.container(key="ctn_custom_panel", border=True):
        default_start = st.session_state.get(_STATE_START) or _today_myt()
        default_end = st.session_state.get(_STATE_END) or _today_myt()

        start_input = st.date_input("Start date", value=default_start, key="cyber_time_custom_start")
        end_input = st.date_input("End date", value=default_end, key="cyber_time_custom_end")

        cols = st.columns(2)
        with cols[0]:
            apply_clicked = st.button(
                "Apply", icon=":material/check:", key="cyber_time_apply",
                type="primary", width="stretch",
            )
        with cols[1]:
            close_clicked = st.button("Close", icon=":material/close:", key="cyber_time_close_custom", width="stretch")

        if apply_clicked:
            if start_input > end_input:
                st.error("Start date cannot be later than the end date.")
            else:
                st.session_state[_STATE_PERIOD] = "custom"
                st.session_state[_STATE_START] = start_input
                st.session_state[_STATE_END] = end_input
                # Pop the dropdown's OWN stored value so it reinitializes
                # fresh next render (falling back to index=0, "today" -
                # see render_sidebar_navigator()'s own index= fallback),
                # and set _STATE_LAST_SYNC to that SAME "today" so the
                # comparison there sees no mismatch and doesn't instantly
                # overwrite the custom range just applied.
                st.session_state.pop(_WIDGET_PRESET, None)
                st.session_state[_STATE_LAST_SYNC] = "today"
                st.session_state[_FLAG_SHOW_CUSTOM] = False
                st.rerun()
        if close_clicked:
            st.session_state[_FLAG_SHOW_CUSTOM] = False
            st.rerun()
