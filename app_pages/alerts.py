"""
Alerts & Incidents page (Step 8).

Alerts are never created from this page - they're generated
automatically by compliance/compliance_engine.py whenever a Threat
Detection or URL Scanner event's risk_score reaches
ALERT_RISK_THRESHOLD (80, per the FYP report). This page only
displays them and lets an analyst move one through the incident
lifecycle: NEW -> INVESTIGATING -> RESOLVED. Nothing here creates,
blocks, deletes, or auto-modifies anything, and the alert-generation
threshold/logic in compliance_engine.py is untouched.
"""
import pandas as pd
import streamlit as st

from database.models import (
    get_alert_severity_counts,
    get_alerts,
    get_compliance_results_for_event,
    get_threat_detection_by_id,
    get_url_scan_by_id,
    update_alert_status,
)
from utils.audit_logger import log_action
from utils.illustrations import (
    BANNER_ICON_ACTIVITY,
    BANNER_ICON_HISTORY,
    BANNER_ICON_SHIELD_CHECK,
    render_intro_banner,
    render_premium_banner,
)
from utils.page_ui import render_empty_state
from utils.time_navigator import get_active_range

STATUS_OPTIONS = ["NEW", "INVESTIGATING", "RESOLVED"]
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
ALERT_TYPE_OPTIONS = ["Network Threat", "Malicious URL"]

SEVERITY_COLORS = {
    "LOW": "#16A34A",
    "MEDIUM": "#B7791F",
    "HIGH": "#C2410C",
    "CRITICAL": "#DC2626",
}
SEVERITY_ICON = {
    "LOW": ":green[:material/circle:]",
    "MEDIUM": ":orange[:material/circle:]",
    "HIGH": ":orange[:material/warning:]",
    "CRITICAL": ":red[:material/error:]",
}
STATUS_COLORS = {
    "NEW": "#2563EB",
    "INVESTIGATING": "#B7791F",
    "RESOLVED": "#16A34A",
}
STATUS_BADGE = {
    "NEW": ":blue[:material/fiber_new:] **NEW**",
    "INVESTIGATING": ":orange[:material/search:] **INVESTIGATING**",
    "RESOLVED": ":green[:material/check_circle:] **RESOLVED**",
}

# (summary card key, label, severity code | None for the total card)
_SUMMARY_CARDS = [
    ("kpi_traffic", "Total alerts", None),
    ("kpi_critical", "Critical", "CRITICAL"),
    ("kpi_highrisk", "High", "HIGH"),
    ("kpi_medium", "Medium", "MEDIUM"),
    ("kpi_low", "Low", "LOW"),
]

_FILTER_KEYS = (
    "alerts_filter_status", "alerts_filter_severity", "alerts_filter_type",
    "alerts_filter_search_id",
)


def render_alerts_page():
    _consume_pending_filter_clear()

    with st.container(key="alerts_premium_banner"):
        render_premium_banner(
            badge_text="AI CYBERGUARD &bull; INCIDENT RESPONSE",
            heading_main="Spot It Fast.", heading_accent="Act With Confidence.",
            description="High-risk detections and scans become real, actionable "
                        "incidents here - nothing is ever auto-blocked or deleted.",
            features=[
                (BANNER_ICON_ACTIVITY, "Risk-Triggered Alerts", "cyan"),
                (BANNER_ICON_HISTORY, "Full Incident Lifecycle", "violet"),
                (BANNER_ICON_SHIELD_CHECK, "Evidence-Linked", "teal"),
            ],
        )
    render_intro_banner(
        "Automatically created when a detected threat or scanned URL reaches "
        "a risk score of 80 or higher. Recommended actions are advisory only - "
        "this system does not block, delete, or modify anything automatically.",
        "cloud_shield", width=110, accent="#F97316",  # matches PAGE_META's Alerts & Incidents accent
    )

    user_id = st.session_state["user_id"]
    start_date, end_date, _ = get_active_range()

    _render_summary_cards(user_id, start_date, end_date)
    st.divider()

    status_filter, severity_filter, type_filter, search_id = _render_filters()
    severities = None if not severity_filter or len(severity_filter) == len(SEVERITY_ORDER) else severity_filter

    alerts = get_alerts(
        user_id,
        status=None if status_filter == "All" else status_filter,
        severities=severities,
        event_type=None if type_filter == "All" else type_filter,
        start_date=start_date, end_date=end_date,
        limit=100,
    )

    # ID search runs over the already-fetched page of alerts (same
    # pattern as compliance.py's search box) rather than a second
    # database query - cheap since the other filters already bounded
    # the result set to at most 100 rows.
    search_id = search_id.strip()
    if search_id:
        alerts = [a for a in alerts if search_id.lower() in (a["threat_ref"] or "").lower()]

    if not alerts:
        render_empty_state("No alerts match the selected filters.", "bell_network")
        return

    with st.container(key="page_panel_blue_detail", border=True):
        st.subheader(f"{len(alerts)} alert(s) found", icon=":material/table_rows:")
        _render_alerts_table(alerts)

    st.divider()
    st.markdown("###### Incident details")
    st.caption("Expand an alert to review its evidence, linked detection/scan source, and update its status.")
    for alert in alerts:
        _render_alert_detail(alert, user_id)


def _consume_pending_filter_clear():
    if st.session_state.pop("_alerts_clear_filters", False):
        for key in _FILTER_KEYS:
            st.session_state.pop(key, None)


def _render_summary_cards(user_id: int, start_date, end_date):
    """Real counts only - straight from get_alert_severity_counts(),
    scoped to the Global Cyber Time Navigator's active period. Shows
    whatever severities actually have alerts; never invents a severity
    with 0 alerts just to fill a card, except the Total card which is
    always shown (even as 0)."""
    counts = {
        row["severity"]: row["count"]
        for row in get_alert_severity_counts(user_id, start_date, end_date)
    }
    total = sum(counts.values())

    cols = st.columns(len(_SUMMARY_CARDS))
    for col, (card_key, label, severity) in zip(cols, _SUMMARY_CARDS):
        value = total if severity is None else counts.get(severity, 0)
        with col, st.container(key=card_key):
            st.metric(label, f"{value:,}")


def _render_filters():
    """Status/Severity/Type only - the date range is no longer a
    page-local filter here; it comes from the Global Cyber Time
    Navigator in the header above (utils/time_navigator.py), the same
    shared selection every other page's own filters now read from."""
    with st.container(key="alerts_filter_bar", border=True):
        st.markdown("**Filters**")
        cols = st.columns([1, 1.4, 1, 1.2, 0.9])
        with cols[0]:
            status_filter = st.selectbox("Status", ["All"] + STATUS_OPTIONS, key="alerts_filter_status")
        with cols[1]:
            severity_filter = st.multiselect(
                "Severity", SEVERITY_ORDER, default=SEVERITY_ORDER, key="alerts_filter_severity",
            )
        with cols[2]:
            type_filter = st.selectbox("Alert type", ["All"] + ALERT_TYPE_OPTIONS, key="alerts_filter_type")
        with cols[3]:
            search_id = st.text_input(
                "Search by ID", placeholder="e.g. ALERT-1024", key="alerts_filter_search_id",
            )
        with cols[4]:
            st.markdown("<div style='height:1.7rem'></div>", unsafe_allow_html=True)
            if st.button("Clear filters", icon=":material/filter_alt_off:", width="stretch"):
                st.session_state["_alerts_clear_filters"] = True
                st.rerun()

    return status_filter, severity_filter, type_filter, search_id


def _status_cell_style(value):
    color = STATUS_COLORS.get(value)
    return f"color: {color}; font-weight: 600;" if color else ""


def _severity_cell_style(value):
    color = SEVERITY_COLORS.get(value)
    return f"color: {color}; font-weight: 600;" if color else ""


def _render_alerts_table(alerts: list):
    table_df = pd.DataFrame([
        {
            "ID": a["threat_ref"],
            "Alert title": a["threat_type"] or a["event_type"],
            "Alert type": a["event_type"],
            "Severity": a["severity"],
            "Risk score": a["risk_score"],
            "Status": a["status"],
            "Created": a["created_at"],
        }
        for a in alerts
    ])
    st.dataframe(
        table_df.style.map(_severity_cell_style, subset=["Severity"])
                       .map(_status_cell_style, subset=["Status"]),
        width="stretch", hide_index=True,
    )


def _render_alert_detail(alert: dict, user_id: int):
    icon = SEVERITY_ICON.get(alert["severity"], ":gray[:material/circle:]")
    label = f"{icon} {alert['threat_ref']} - {alert['threat_type'] or alert['event_type']} ({alert['status']})"
    with st.expander(label):
        badge_cols = st.columns(2)
        badge_cols[0].markdown(f"**Severity:** :{_severity_md_color(alert['severity'])}[{alert['severity']}]")
        badge_cols[1].markdown(STATUS_BADGE.get(alert["status"], f"**{alert['status']}**"))

        cols = st.columns(4)
        cols[0].metric("Risk score", f"{alert['risk_score']}/100")
        cols[1].metric("Confidence", f"{alert['confidence']}%" if alert["confidence"] is not None else "N/A")
        cols[2].caption(f":material/schedule: Created: {alert['created_at']}")
        cols[3].caption(f":material/update: Updated: {alert['updated_at']}")

        st.markdown(f"**Alert type:** {alert['event_type']}")
        st.markdown(f"**Compliance impact:** {alert['compliance_summary'] or 'None recorded.'}")
        st.markdown(f"**Recommended response:** {alert['recommended_action'] or 'None recorded.'}")

        st.markdown("---")
        _render_source_section(alert, user_id)
        _render_evidence_section(alert, user_id)

        st.markdown("---")
        new_status = st.selectbox(
            "Update status", STATUS_OPTIONS,
            index=STATUS_OPTIONS.index(alert["status"]),
            key=f"alert_status_{alert['id']}",
        )
        if new_status != alert["status"]:
            if st.button("Save status", key=f"alert_save_{alert['id']}", icon=":material/save:"):
                update_alert_status(alert["id"], new_status, user_id)
                log_action(
                    st.session_state.get("username", "?"), "INCIDENT_UPDATED", "ALERTS",
                    f"Alert {alert['threat_ref']} status changed from "
                    f"{alert['status']} to {new_status}.",
                )
                st.rerun()


def _severity_md_color(severity: str) -> str:
    return {"LOW": "green", "MEDIUM": "orange", "HIGH": "orange", "CRITICAL": "red"}.get(severity, "gray")


def _render_source_section(alert: dict, user_id: int):
    """Real, looked-up source/detection info - never a fabricated IP,
    hostname, or geolocation (this dataset has none)."""
    st.markdown("**Source / detection information**")
    if alert["related_detection_id"]:
        detection = get_threat_detection_by_id(alert["related_detection_id"], user_id)
        if detection:
            st.markdown(
                f"- Linked threat detection **#{detection['id']}** "
                f"(dataset record #{detection['record_index']})  \n"
                f"- Prediction: **{detection['prediction']}**, attack type: "
                f"**{detection['attack_type'] or 'N/A'}**  \n"
                f"- Model: **{detection['model_used'] or 'N/A'}**, confidence: "
                f"**{detection['confidence']}%**  \n"
                f"- Detected at: {detection['detected_at']}"
            )
        else:
            st.caption("Linked detection record not found (it may have been removed).")
    elif alert["related_url_scan_id"]:
        scan = get_url_scan_by_id(alert["related_url_scan_id"], user_id)
        if scan:
            st.markdown(
                f"- Linked URL scan **#{scan['id']}**: {scan['url']}  \n"
                f"- Scan status: **{scan['scan_status']}**, threat category: "
                f"**{scan['threat_category'] or 'N/A'}**  \n"
                f"- Detections: **{scan['detection_count']}/{scan['total_engines']}** engines "
                f"flagged this URL  \n"
                f"- Intelligence source: **{scan['source']}**"
                + (f" (ref: {scan['analysis_reference']})" if scan["analysis_reference"] else "") + "  \n"
                f"- Scanned at: {scan['scan_timestamp']}"
            )
        else:
            st.caption("Linked URL scan record not found (it may have been removed).")
    else:
        st.caption("No linked detection or URL scan record for this alert.")


def _render_evidence_section(alert: dict, user_id: int):
    """Real compliance findings generated from the SAME underlying
    event as this alert - never invented supporting evidence."""
    st.markdown("**Supporting evidence (linked compliance findings)**")
    findings = get_compliance_results_for_event(
        user_id,
        related_detection_id=alert["related_detection_id"],
        related_url_scan_id=alert["related_url_scan_id"],
    )
    if not findings:
        st.caption("No linked compliance findings recorded for this alert.")
        return
    for f in findings:
        st.markdown(
            f"- **[{f['framework']}] {f['title']}** - {f['status']}  \n"
            f"  Finding: {f['reason'] or 'No finding recorded.'}  \n"
            f"  Evidence: {f['evidence'] or 'No evidence recorded.'}"
        )
