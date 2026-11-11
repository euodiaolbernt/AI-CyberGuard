"""
Audit Logs page (Step 9).

Read-only view over the audit_logs table. Every write comes from
utils.audit_logger.log_action(), called throughout the app (login/
logout, dataset upload, AI detection, URL scans, compliance checks,
alert creation/updates, user management) - this page never writes to
audit_logs itself, only queries it.

Every user sees their OWN activity by default (audit_logs has no
user_id column, so scoping is by the account's own username - see
database/models.py). Only an ADMIN gets an extra toggle to view every
user's activity, since that's a real oversight capability, not a page
restriction - everyone still opens this same page.

The 7 event_type values coloured below (AUTH/THREAT_DETECTION/
URL_SCANNER/COMPLIANCE/ALERTS/REPORTS/ADMIN) are the exact, only
values utils.audit_logger.log_action() is ever called with across the
codebase (grep-verified) - this page never invents a category. The
summary cards and Event type filter work on the already-fetched,
already-scoped rows (same 200-row window the table itself uses), so
they can never show a number the table disagrees with.
"""
import pandas as pd
import streamlit as st

from auth.authentication import is_admin
from database.models import get_audit_log_actions, get_audit_logs
from utils.illustrations import (
    BANNER_ICON_HISTORY,
    BANNER_ICON_LOCK,
    BANNER_ICON_SEARCH,
    render_intro_banner,
    render_premium_banner,
)
from utils.page_ui import render_empty_state
from utils.time_navigator import get_active_range

EVENT_TYPE_COLORS = {
    "AUTH": ("#2563EB", "kpi_traffic"),
    "THREAT_DETECTION": ("#BE123C", "kpi_critical"),
    "URL_SCANNER": ("#0D9488", "kpi_urls"),
    "COMPLIANCE": ("#8B5CF6", "kpi_violet"),
    "ALERTS": ("#D97706", "kpi_highrisk"),
    "REPORTS": ("#22D3EE", "kpi_cyan"),
    "ADMIN": ("#EF4444", "kpi_threats"),
}
EVENT_TYPE_ICON = {
    "AUTH": ":material/lock_person:",
    "THREAT_DETECTION": ":material/bug_report:",
    "URL_SCANNER": ":material/link:",
    "COMPLIANCE": ":material/balance:",
    "ALERTS": ":material/notifications:",
    "REPORTS": ":material/description:",
    "ADMIN": ":material/admin_panel_settings:",
}
_TOTAL_CARD_KEY = "kpi_compliance_neutral"


def render_audit_logs_page():
    with st.container(key="audit_premium_banner"):
        render_premium_banner(
            badge_text="AI CYBERGUARD &bull; ACTIVITY TRAIL",
            heading_main="Every Action.", heading_accent="Fully Tracked.",
            description="A real, tamper-evident record of logins, scans, detections, "
                        "and changes - nothing here is summarised away.",
            features=[
                (BANNER_ICON_HISTORY, "Full Accountability", "cyan"),
                (BANNER_ICON_LOCK, "Tamper-Evident", "violet"),
                (BANNER_ICON_SEARCH, "Searchable History", "teal"),
            ],
        )
    render_intro_banner(
        "Full activity trail for accountability and oversight - every login, "
        "scan, detection, and configuration change is recorded here.",
        "shield", width=110, accent="#22D3EE",  # matches PAGE_META's Audit Logs accent
    )

    with st.container(key="page_panel_blue_logs", border=True):
        show_all = False
        if is_admin():
            show_all = st.checkbox("Show all users' activity (admin)", value=False)
            st.caption(
                "Your own activity trail." if not show_all
                else "Every user's activity trail (admin view)."
            )
        else:
            st.caption("Your own activity trail.")

        col1, col2, col3 = st.columns(3)
        with col1:
            actions = ["All"] + get_audit_log_actions()
            action_filter = st.selectbox("Filter by action", actions)
        with col2:
            event_type_filter = st.selectbox("Filter by event type", ["All"] + list(EVENT_TYPE_COLORS.keys()))
        with col3:
            if show_all:
                username_filter = st.text_input("Filter by username (exact match)", placeholder="e.g. admin")
            else:
                username_filter = st.session_state["username"]
                st.text_input("Account", value=username_filter, disabled=True)

        start_date, end_date, _ = get_active_range()
        all_rows = get_audit_logs(
            username=None if show_all and not username_filter else username_filter,
            limit=200,
            action=None if action_filter == "All" else action_filter,
            start_date=start_date, end_date=end_date,
        )

        if not all_rows:
            render_empty_state("No data available.", "timeline_shield")
            return

        st.markdown("###### Activity by event type")
        _render_event_type_summary(all_rows)

        rows = all_rows if event_type_filter == "All" else [r for r in all_rows if r["event_type"] == event_type_filter]
        if not rows:
            render_empty_state("No entries match the selected event type.", "timeline_shield")
            return

        st.markdown(f"###### {len(rows):,} entr{'y' if len(rows) == 1 else 'ies'} shown")
        st.dataframe(_styled_audit_table(rows, show_all), width="stretch", hide_index=True)


def _render_event_type_summary(rows: list):
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["event_type"]] = counts.get(r["event_type"], 0) + 1

    # Only real, present categories get a card - never a 0-count filler.
    present = [et for et in EVENT_TYPE_COLORS if et in counts]
    present += [et for et in counts if et not in EVENT_TYPE_COLORS]  # defensive: an unmapped future value

    cards = [(_TOTAL_CARD_KEY, ":material/summarize: Total entries", sum(counts.values()))]
    for et in present:
        _, color_key = EVENT_TYPE_COLORS.get(et, ("#94A3B8", "kpi_compliance_neutral"))
        icon = EVENT_TYPE_ICON.get(et, ":material/bolt:")
        cards.append((color_key, f"{icon} {et.replace('_', ' ').title()}", counts[et]))

    # NOTE: the container key must be EXACTLY one of _KPI_CARD_COLORS'
    # own keys (e.g. "kpi_traffic"), not a prefixed variant - theme.py's
    # _kpi_card_css() matches the exact class `.st-key-kpi_traffic`, not
    # a substring, so a key like "audit_summary_kpi_traffic" silently
    # gets NO colour/border/hover at all (confirmed: this is why these
    # cards were rendering flat white instead of the intended colours).
    cols = st.columns(len(cards))
    for col, (card_key, label, value) in zip(cols, cards):
        with col, st.container(key=card_key):
            st.metric(label, f"{value:,}")


def _event_type_cell_style(value):
    color = EVENT_TYPE_COLORS.get(value, (None,))[0]
    return f"color: {color}; font-weight: 600;" if color else ""


def _styled_audit_table(rows: list, show_all: bool):
    records = []
    for r in rows:
        record = {"Time": r["timestamp"]}
        if show_all:
            record["Username"] = r["username"]
        record["Action"] = r["action"]
        record["Event type"] = r["event_type"]
        record["Description"] = r["description"]
        records.append(record)
    df = pd.DataFrame(records)
    return df.style.map(_event_type_cell_style, subset=["Event type"])
