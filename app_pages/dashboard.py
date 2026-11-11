"""
Dashboard page (Step 2).

6 KPI-adjacent cards (4 security KPIs + the two charts below) plus a
Recent Threats / Compliance Overview pair - every number here is a
live read through database/models.py of THIS user's own recorded
results. Nothing is sampled, estimated, or shared with another user,
and nothing is invented when a query returns zero rows: an empty
result renders the shared render_empty_state(), never a fabricated
value or a fake trend.

DATA HONESTY:
  * get_threat_summary()/get_severity_distribution()/get_detection_trend()
    are all called with predictions=MALICIOUS_ONLY here - an unfiltered
    count would include BENIGN rows and overstate "detections".
  * get_detection_trend() only returns days that actually have rows;
    the missing calendar days are zero-filled below so the line chart
    doesn't draw a false gap-free slope across days with no data.
  * KPI deltas are only shown when the preceding 7-day window actually
    has records - a percentage change from zero is undefined, so it is
    omitted rather than shown as "+100%".

This page only queries and displays; it never writes.
"""
from datetime import datetime, timedelta

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from database.models import (
    get_alert_count,
    get_compliance_overview,
    get_detection_trend,
    get_new_alert_count,
    get_recent_compliance_issues,
    get_recent_threats,
    get_severity_distribution,
    get_threat_summary,
    get_url_scan_summary,
)
from utils.compliance_ui import render_compliance_cards
from utils.design_tokens import SEVERITY_COLORS
from utils.illustrations import (
    BANNER_ICON_ACTIVITY,
    BANNER_ICON_CHIP,
    BANNER_ICON_SHIELD_CHECK,
    photo_path,
    render_photo,
    render_premium_banner,
)
from utils.page_ui import jump_to_page, render_empty_state
from utils.time_navigator import get_active_range, symmetric_prior_window

TREND_DAYS = 14
MAX_CHART_DAYS = 60
RECENT_THREAT_ROWS = 8
RECENT_FINDING_ROWS = 5
MALICIOUS_ONLY = ("MALICIOUS",)

# (label, material icon, target page, accent hex) - every action really
# navigates via jump_to_page(), nothing decorative here.
_QUICK_ACTIONS = [
    ("detect", "Detect Network Threats", ":material/bug_report:", "Threat Detection", "#3B82F6"),
    ("scan", "Scan Suspicious URLs", ":material/link:", "URL Scanner", "#8B5CF6"),
    ("monitor", "Monitor Compliance", ":material/balance:", "Compliance Monitoring", "#EC4899"),
    ("report", "Generate Security Reports", ":material/description:", "Reports", "#F97316"),
]


def render_dashboard_page():
    user_id = st.session_state["user_id"]
    start, end, _ = get_active_range()

    _render_welcome_hero()
    _render_kpi_row(user_id, start, end)

    st.divider()
    _render_charts(user_id, start, end)

    st.divider()
    # Wrapped in its own container key so the alignment fix below
    # (align-items: flex-start) only applies to THIS row, not every
    # st.columns() pair elsewhere in the app - without it, Streamlit's
    # default flex stretch made the shorter Recent Threats card grow
    # to match whatever height the Compliance Overview card happened
    # to reach, leaving a large empty gap under its own content.
    with st.container(key="dashboard_lower_row"):
        cols = st.columns([0.55, 0.45], gap="medium")
        with cols[0]:
            _render_recent_threats(user_id, start, end)
        with cols[1]:
            _render_compliance_overview(user_id, start, end)

    st.divider()
    _render_bottom_banner()


# ---------------------------------------------------------------
# Welcome hero
# ---------------------------------------------------------------

def _render_welcome_hero():
    full_name = st.session_state.get("full_name") or st.session_state.get("username", "")
    first_name = full_name.split()[0] if full_name else "there"
    has_robot = photo_path("robot_dashboard") is not None

    with st.container(key="dashboard_welcome_card", border=True):
        if has_robot:
            text_col, art_col = st.columns([2.2, 1], vertical_alignment="center")
        else:
            text_col, art_col = st.container(), None
        with text_col:
            st.markdown(
                '<div class="dw-greeting-small">Welcome back,</div>'
                f'<div class="dw-greeting-big">{first_name}! \U0001F44B</div>'
                '<p class="dw-subtitle">Here’s an overview of your cybersecurity environment.</p>'
                '<p class="dw-subtitle">AI CyberGuard helps you detect threats, scan malicious URLs, '
                'monitor compliance and stay secure.</p>',
                unsafe_allow_html=True,
            )
            _render_quick_actions()
        if has_robot:
            with art_col, st.container(key="dashboard_hero_art"):
                render_photo("robot_dashboard", width=180)
                st.markdown(
                    '<div class="dw-quote-card">“A safer digital environment starts with '
                    'awareness and proactive monitoring.”</div>',
                    unsafe_allow_html=True,
                )


def _render_quick_actions():
    # st.columns() here (nested inside the welcome card) kept picking
    # up the app-wide default "card" box (background/border/shadow)
    # that st.container(border=True) elements get, no matter how the
    # resulting box was targeted in CSS - a second, unwanted box around
    # the 4 buttons on top of the welcome card's own border. Switching
    # to st.container(horizontal=True) - the modern, non-st.columns()
    # way to lay out a row - avoids that code path entirely instead of
    # fighting it with more CSS. Each button keeps its own
    # accent-coloured border (set directly on the <button> below),
    # which is one level, not a second nested card.
    with st.container(key="dashboard_quick_actions_row", horizontal=True, gap="small", wrap=True):
        for slug, label, icon, target, accent in _QUICK_ACTIONS:
            st.markdown(
                f'<style>[data-testid="stMain"] .st-key-dash_action_{slug} button {{'
                f'border-color: {accent}55 !important; color: {accent} !important; '
                f'background: {accent}14 !important; }}'
                f'[data-testid="stMain"] .st-key-dash_action_{slug} button:hover {{'
                f'background: {accent}26 !important; border-color: {accent} !important; }}</style>',
                unsafe_allow_html=True,
            )
            with st.container(key=f"dash_action_{slug}", width="content"):
                if st.button(label, icon=icon, key=f"dash_action_btn_{slug}"):
                    jump_to_page(target)
                    st.rerun()


# ---------------------------------------------------------------
# KPI row
# ---------------------------------------------------------------

def _trend_delta(current: float, previous: float):
    """None (no delta shown) when the prior window has no records - a
    percentage change from zero is undefined, not "+100%"."""
    if not previous:
        return None
    pct = (current - previous) / previous * 100
    return f"{pct:+.1f}%"


def _render_kpi_row(user_id: int, start, end):
    # "vs previous period" compares against an equal-length window right
    # before the active one (see symmetric_prior_window's docstring) -
    # well-defined for ANY selected period (Today vs Yesterday, Last 30
    # Days vs the 30 days before that, a custom range vs an equal-length
    # range right before it), not just a hard-coded trailing 7 days.
    # No comparison is shown at all when "All Time" is active (start is
    # None) - there is no "previous" window for "all of it".
    prev_start, prev_end = symmetric_prior_window(start, end)

    detections_all = get_threat_summary(user_id, start, end, MALICIOUS_ONLY)
    alerts_total = get_alert_count(user_id, start, end)
    new_alerts = get_new_alert_count(user_id)
    urls = get_url_scan_summary(user_id, start, end)

    if prev_start is not None:
        detections_prev = get_threat_summary(user_id, prev_start, prev_end, MALICIOUS_ONLY)
        urls_prev = get_url_scan_summary(user_id, prev_start, prev_end)
        detections_delta = _trend_delta(detections_all["total"], detections_prev["total"])
        critical_delta = _trend_delta(detections_all["critical"], detections_prev["critical"])
        urls_delta = _trend_delta(urls["total"], urls_prev["total"])
    else:
        detections_delta = critical_delta = urls_delta = None

    cols = st.columns(4)
    with cols[0], st.container(key="kpi_traffic"):
        st.metric("Total Security Detections", f"{detections_all['total']:,}", delta=detections_delta)
        st.caption("Malicious classifications recorded for the selected period.")

    with cols[1], st.container(key="kpi_critical"):
        st.metric(
            "Critical Threats", f"{detections_all['critical']:,}",
            delta=critical_delta, delta_color="inverse",
        )
        st.caption("Detections scored in the CRITICAL severity band.")
        if st.button("View details", key="dash_open_td", width="stretch"):
            jump_to_page("Threat Detection")
            st.rerun()

    with cols[2], st.container(key="kpi_highrisk"):
        st.metric("Alerts Generated", f"{alerts_total:,}")
        st.caption(f"{new_alerts} still marked NEW." if new_alerts else "No alerts currently NEW.")
        if st.button("View details", key="dash_open_alerts", width="stretch"):
            jump_to_page("Alerts & Incidents")
            st.rerun()

    with cols[3], st.container(key="kpi_urls"):
        st.metric("URLs Scanned", f"{urls['total']:,}", delta=urls_delta)
        st.caption(f"{urls['high_risk']} flagged HIGH or CRITICAL risk.")
        if st.button("View details", key="dash_open_urls", width="stretch"):
            jump_to_page("URL Scanner")
            st.rerun()


# ---------------------------------------------------------------
# Charts
# ---------------------------------------------------------------

def _chart_window(start, end):
    """(chart_start, chart_end, day_count, caption) for the trend line -
    the exact active range when it's bounded and reasonably short
    (<= MAX_CHART_DAYS), otherwise just the most recent MAX_CHART_DAYS
    of it (or of "today" when "All Time" is active) - a daily line
    chart spanning years would be both unreadable and expensive to
    zero-fill. The KPI totals above are never capped this way - only
    this one chart's day-by-day view is."""
    today = datetime.now().date()
    if start is None or end is None:
        chart_end = datetime.combine(today, datetime.max.time())
        chart_start = chart_end - timedelta(days=TREND_DAYS - 1)
        return chart_start, chart_end, TREND_DAYS, f"Malicious classifications per day, last {TREND_DAYS} days (of All Time)."

    span_days = (end.date() - start.date()).days + 1
    if span_days <= MAX_CHART_DAYS:
        return start, end, span_days, f"Malicious classifications per day, {start:%d %b} - {end:%d %b %Y}."

    chart_start = end - timedelta(days=MAX_CHART_DAYS - 1)
    return chart_start, end, MAX_CHART_DAYS, (
        f"Malicious classifications per day, most recent {MAX_CHART_DAYS} days of the selected period."
    )


def _render_charts(user_id: int, start, end):
    cols = st.columns([1.7, 1], gap="medium")

    with cols[0], st.container(key="chart_trend_container"):
        st.subheader("Detections by Day", icon=":material/show_chart:")
        chart_start, chart_end, day_count, trend_caption = _chart_window(start, end)
        st.markdown(
            f'<p class="chart-caption-centered">{trend_caption}</p>',
            unsafe_allow_html=True,
        )
        rows = get_detection_trend(
            user_id, predictions=MALICIOUS_ONLY, start_date=chart_start, end_date=chart_end,
        )
        if not rows:
            _render_photo_empty_state(
                "robot_laptop", "analytics_chart",
                "No detection data available yet.",
                "Upload network traffic data in Threat Detection to see results here.",
                "Open Threat Detection", "Threat Detection", "dash_chart_open_td",
            )
        else:
            df = pd.DataFrame(rows)
            df["day"] = pd.to_datetime(df["day"])
            full_range = pd.date_range(start=chart_start.date(), periods=day_count, freq="D")
            df = (
                df.set_index("day").reindex(full_range, fill_value=0)
                .rename_axis("day").reset_index()
            )
            fig = go.Figure(go.Scatter(
                x=df["day"], y=df["count"], mode="lines+markers",
                line=dict(color="#0EA5E9", width=3.5),
                marker=dict(color="#0EA5E9", size=8, line=dict(color="#FFFFFF", width=1.5)),
                fill="tozeroy", fillcolor="rgba(14, 165, 233, 0.18)",
                hovertemplate="<b>%{x|%d %b}</b>: %{y} detection(s)<extra></extra>",
            ))
            fig.update_layout(
                margin=dict(l=10, r=10, t=10, b=10), height=280,
                xaxis_title=None, yaxis_title="Detections",
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#1E293B", size=13, family="Inter, sans-serif"),
                yaxis=dict(
                    rangemode="tozero", tickfont=dict(color="#1E293B", size=12),
                    title_font=dict(color="#0F172A", size=13),
                    gridcolor="rgba(15, 23, 42, 0.12)",
                ),
                xaxis=dict(tickfont=dict(color="#1E293B", size=12)),
                hoverlabel=dict(font=dict(size=13, color="#FFFFFF")),
            )
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    with cols[1], st.container(key="chart_severity_container"):
        st.subheader("Detections by Severity", icon=":material/donut_small:")
        st.markdown(
            '<p class="chart-caption-centered">Distribution across malicious detections for the selected period.</p>',
            unsafe_allow_html=True,
        )
        dist = get_severity_distribution(user_id, start, end, predictions=MALICIOUS_ONLY)
        if not dist:
            render_empty_state("No severity data available yet.", "analytics_chart")
        else:
            df = pd.DataFrame(dist)
            total = int(df["count"].sum())
            fig = go.Figure(go.Pie(
                labels=df["severity"], values=df["count"], hole=0.62,
                marker=dict(
                    colors=[SEVERITY_COLORS.get(s, "#94A3B8") for s in df["severity"]],
                    line=dict(color="#FFFFFF", width=2),
                ),
                textinfo="label+percent",
                textfont=dict(size=13, color="#FFFFFF", family="Inter, sans-serif"),
                insidetextfont=dict(size=13, color="#FFFFFF"),
                outsidetextfont=dict(size=13, color="#0F172A"),
                # automargin=True lets Plotly grow the figure's own margins
                # to fit an "outside" label fully (e.g. a thin slice's
                # percent text near the top edge) instead of clipping it
                # against a fixed, too-tight margin.
                automargin=True,
                sort=False,
            ))
            fig.update_layout(
                margin=dict(l=35, r=35, t=35, b=35), height=300,
                uniformtext=dict(minsize=11, mode="show"),
                annotations=[dict(
                    text=f"<b>{total}</b><br><b>total</b>", x=0.5, y=0.5,
                    font=dict(size=20, color="#0F172A"), showarrow=False,
                )],
                showlegend=True,
                legend=dict(font=dict(size=13, color="#1E293B", family="Inter, sans-serif")),
            )
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


def _render_photo_empty_state(photo_name: str, fallback_svg: str, headline: str,
                               detail: str, button_label: str, target_page: str, button_key: str):
    """A real cyber_*.png illustration when available, falling back to
    the existing hand-drawn SVG empty state otherwise (never both) -
    same pattern already used by url_scanner.py's
    _render_history_empty_state(). The button is a real, working
    jump_to_page() navigation, never a decorative control."""
    path = photo_path(photo_name)
    if path is None:
        render_empty_state(headline, fallback_svg)
        st.caption(detail)
    else:
        cols = st.columns([1, 2], vertical_alignment="center")
        with cols[0]:
            render_photo(photo_name, width=110)
        with cols[1]:
            st.markdown(f"**{headline}**")
            st.caption(detail)
    if st.button(button_label, icon=":material/arrow_forward:", key=button_key, width="stretch"):
        jump_to_page(target_page)
        st.rerun()


# ---------------------------------------------------------------
# Recent threats
# ---------------------------------------------------------------

def _severity_cell_style(value):
    color = SEVERITY_COLORS.get(value)
    return f"color: {color}; font-weight: 600;" if color else ""


def _render_recent_threats(user_id: int, start, end):
    with st.container(key="page_panel_blue_recent_threats", border=True):
        st.subheader("Recent Threats", icon=":material/bug_report:")
        st.caption(f"{RECENT_THREAT_ROWS} most recent malicious detections for the selected period.")

        rows = get_recent_threats(user_id, limit=RECENT_THREAT_ROWS, start_date=start, end_date=end)
        if not rows:
            _render_photo_empty_state(
                "secure_document", "bell_network",
                "No threats recorded yet.",
                "Run an analysis from Threat Detection to populate this table.",
                "Open Threat Detection", "Threat Detection", "dash_threats_empty_open",
            )
            return

        df = pd.DataFrame([
            {
                "Time": r["detected_at"],
                "Threat type": r["attack_type"] or "Unclassified",
                "Severity": r["severity"],
                "Risk score": r["risk_score"],
                "Model": r["model_used"] or "-",
            }
            for r in rows
        ])
        st.dataframe(
            df.style.map(_severity_cell_style, subset=["Severity"]),
            width="stretch", hide_index=True,
        )

        if st.button("Open Threat Detection", key="dash_threats_open",
                     icon=":material/arrow_forward:", width="stretch"):
            jump_to_page("Threat Detection")
            st.rerun()


# ---------------------------------------------------------------
# Compliance overview
# ---------------------------------------------------------------

def _render_compliance_overview(user_id: int, start, end):
    with st.container(key="page_panel_purple_recent_compliance", border=True):
        st.subheader("Compliance Overview", icon=":material/balance:")
        overview = get_compliance_overview(user_id, start, end)

        if not overview:
            render_empty_state(
                "No compliance assessments recorded for the selected period.", "legal_scale",
            )
            st.caption("Run the AI system self-assessment to record your first findings.")
        else:
            render_compliance_cards(overview, cards_per_row=2)

            st.markdown("###### Recent findings")
            findings = get_recent_compliance_issues(user_id, limit=RECENT_FINDING_ROWS, start_date=start, end_date=end)
            if not findings:
                st.caption("Every recorded rule check is currently compliant.")
            else:
                for f in findings:
                    dot, badge = (
                        (":orange[●]", ":orange[NEEDS REVIEW]") if f["status"] == "NEEDS_REVIEW"
                        else (":red[●]", ":red[NON-COMPLIANT]")
                    )
                    st.markdown(f"{dot} **[{f['framework']}] {f['title']}** - {badge}")
                    st.caption(f["reason"] or "No reason recorded.")

        if st.button("Open Compliance Monitoring", key="dash_compliance_open",
                     icon=":material/arrow_forward:", width="stretch"):
            jump_to_page("Compliance Monitoring")
            st.rerun()


# ---------------------------------------------------------------
# Bottom banner
# ---------------------------------------------------------------

def _render_bottom_banner():
    """Real cyber_robot_shield.png + cyber_cloud_shield.png art, purely
    decorative - makes no claims beyond the app's actual capabilities
    (continuous monitoring is real - every page here reads live data on
    every visit; no fabricated live threat counts or status appear here).
    Thin wrapper around the shared utils.illustrations.render_premium_banner()
    - every other feature page's own banner (Threat Detection, URL
    Scanner, etc.) calls the exact same function with its own copy,
    never a duplicated HTML block per page."""
    with st.container(key="dashboard_premium_banner"):
        render_premium_banner(
            badge_text="AI CYBERGUARD &bull; PROTECTION STATUS",
            heading_main="Stay Secure.", heading_accent="Stay Ahead.",
            description="Continuous monitoring keeps your network protected and your "
                        "security posture ready.",
            features=[
                (BANNER_ICON_ACTIVITY, "Real-time Monitoring", "cyan"),
                (BANNER_ICON_CHIP, "AI-Powered Detection", "violet"),
                (BANNER_ICON_SHIELD_CHECK, "Compliance Ready", "teal"),
            ],
        )
