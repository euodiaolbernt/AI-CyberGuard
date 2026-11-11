"""
Reports page (Step 10).

Composes the same summary data the Dashboard, Threat Detection, URL
Scanner, Compliance Monitoring, Alerts & Incidents, and Audit Logs
pages already show - via utils/report_generator.py, which only reads
through database/models.py's existing query functions (each extended
with optional date-range filtering). This page adds a date-range
filter and CSV/PDF export on top; it never computes or displays a
number those other pages wouldn't also show for the same range.

Report files are generated in-memory and streamed straight to the
browser via st.download_button - they are NEVER written to disk (see
database.models.record_report's docstring). The `reports` table is
therefore a metadata-only audit trail (who/what/when), not a file
store: a past "Recent reports" row can't be re-downloaded byte-for-
byte, only regenerated fresh from the real data for a chosen date
range. The page is honest about this instead of faking a working
"re-download" button for rows whose bytes were never kept.

Colours/badges are imported from utils.design_tokens /
utils.compliance_ui rather than redefined here, so a severity or
compliance status always looks the same everywhere in the app.
"""
from datetime import datetime

import pandas as pd
import streamlit as st

from database.models import get_report_history, record_report
from utils.audit_logger import log_action
from utils.compliance_ui import render_compliance_cards
from utils.design_tokens import SEVERITY_COLORS
from utils.illustrations import place as _illustration
from utils.illustrations import (
    BANNER_ICON_CHIP,
    BANNER_ICON_DOCUMENT,
    BANNER_ICON_HISTORY,
    render_intro_banner,
    render_premium_banner,
)
from utils.page_ui import render_empty_state
from utils.time_navigator import get_active_range
from utils.report_generator import (
    build_report_summary,
    dataframe_for_export,
    generate_audit_log_report_pdf,
    generate_compliance_report_pdf,
    generate_pdf_report,
    generate_threat_detection_report_pdf,
    generate_url_scan_report_pdf,
)

_CARD_ACCENT = {"red": "#DC2626", "violet": "#8B5CF6", "teal": "#0D9488", "amber": "#D97706"}

# (accent colour, illustration, title, description, report_type string
# (matches the `reports` table's existing values), CSV export section
# key, per-section PDF generator). Only the 4 report types the user
# asked for - "Incident Summary" and "Full Summary" stay available via
# the detail tabs / the Generate New Report action below, not as a
# 5th/6th card.
REPORT_CARDS = [
    ("red", "shield_laptop", "Threat Detection Report",
     "Detections, severity distribution, and attack types for the selected period.",
     "Threat Detection", "threat_detections", generate_threat_detection_report_pdf),
    ("violet", "legal_scale", "Compliance Report",
     "PDPA, ISO 27001, NIST CSF, GDPR, and EU AI Act assessment results.",
     "Compliance", "compliance", generate_compliance_report_pdf),
    ("teal", "browser_magnifier", "URL Scan Report",
     "VirusTotal-based scan results and risk classifications.",
     "URL Scan", "url_scans", generate_url_scan_report_pdf),
    ("amber", "timeline_shield", "Audit Log Report",
     "A record of actions taken across the application.",
     "Audit Activity", "audit_logs", generate_audit_log_report_pdf),
]

# Maps a past report's (report_type, file_format) back to a real
# generator, for "Regenerate" in the Recent reports section. Every
# combination that can actually appear in the `reports` table is
# listed here (see _log_report_generated call sites below).
_REGEN_CSV_SECTIONS = {
    "Threat Detection": "threat_detections", "URL Scan": "url_scans",
    "Compliance": "compliance", "Audit Activity": "audit_logs",
    "Incident Summary": "alerts",
}
_REGEN_PDF_FUNCS = {
    "Threat Detection": generate_threat_detection_report_pdf,
    "URL Scan": generate_url_scan_report_pdf,
    "Compliance": generate_compliance_report_pdf,
    "Audit Activity": generate_audit_log_report_pdf,
    "Full Summary": generate_pdf_report,
}


def render_reports_page():
    user_id = st.session_state["user_id"]
    username = st.session_state["username"]

    with st.container(key="reports_premium_banner"):
        render_premium_banner(
            badge_text="AI CYBERGUARD &bull; INSIGHT ENGINE",
            heading_main="Turn Data.", heading_accent="Into Decisions.",
            description="Export your own real detections, scans, and compliance "
                        "results as polished CSV or PDF reports, on demand.",
            features=[
                (BANNER_ICON_DOCUMENT, "Real Exports", "cyan"),
                (BANNER_ICON_CHIP, "PDF & CSV", "violet"),
                (BANNER_ICON_HISTORY, "Period Snapshots", "teal"),
            ],
        )
    render_intro_banner(
        "All figures below are your own data only, live from the same database "
        "the Dashboard, Threat Detection, URL Scanner, Compliance, Alerts, and "
        "Audit Logs pages use - nothing here is invented, hard-coded, or shared "
        "with other users.",
        "secure_document", width=120, accent="#6366F1",  # matches PAGE_META's Reports accent
    )

    start_date, end_date = _render_date_filter()
    st.divider()

    _render_generate_new_report_cta(user_id, username, start_date, end_date)

    st.markdown("##### Generate a report")
    st.caption("Each card builds a report from your own real data for the selected period, as CSV or PDF.")
    _render_report_cards(user_id, username, start_date, end_date)

    st.divider()
    with st.container(key="page_panel_blue_detail", border=True):
        st.subheader("Recent reports", icon=":material/history:")
        _render_report_history(user_id, username, start_date, end_date)

    st.divider()
    summary = build_report_summary(user_id, username, start_date, end_date)
    tabs = st.tabs([
        "Threat Detection", "URL Scanning", "Compliance",
        "Incidents", "Audit Activity",
    ])
    with tabs[0]:
        _render_threat_section(summary, user_id, username, start_date, end_date)
    with tabs[1]:
        _render_url_section(summary, user_id, username, start_date, end_date)
    with tabs[2]:
        _render_compliance_section(summary, user_id, username, start_date, end_date)
    with tabs[3]:
        _render_incident_section(summary, user_id, username, start_date, end_date)
    with tabs[4]:
        _render_audit_section(summary, user_id, username, start_date, end_date)


# ---------------------------------------------------------------
# Date range filter
# ---------------------------------------------------------------

def _render_date_filter():
    """The report period is no longer a page-local control - it comes
    from the Global Cyber Time Navigator in the header above
    (utils/time_navigator.py), the same shared selection every other
    page now reads from. This just surfaces the active range as a
    caption so it's unambiguous which period a generated report
    actually covers."""
    start_date, end_date, label = get_active_range()
    if start_date is None:
        st.caption(f"{label} (using the header's Cyber Time Navigator). No date restriction - every record.")
    else:
        st.caption(
            f"{label} (using the header's Cyber Time Navigator) - "
            f"**{start_date:%Y-%m-%d}** to **{end_date:%Y-%m-%d}**."
        )
    return start_date, end_date


# ---------------------------------------------------------------
# Generate New Report (prominent CTA) + the 4 report cards
# ---------------------------------------------------------------

def _render_generate_new_report_cta(user_id, username, start_date, end_date):
    with st.container(key="reports_generate_cta", border=True):
        cols = st.columns([3, 1.3])
        with cols[0]:
            st.markdown("##### :material/auto_awesome: Generate New Report")
            st.caption(
                "A full combined PDF - Threat Detection, URL Scanning, Compliance, "
                "Incidents, and Audit Activity - for the selected period, in one file."
            )
        with cols[1]:
            with st.spinner("Preparing report..."):
                pdf_bytes = generate_pdf_report(user_id, username, start_date, end_date)
            clicked = st.download_button(
                "Export full report", data=pdf_bytes, icon=":material/download:",
                file_name=f"ai_cyberguard_report_{datetime.now():%Y%m%d_%H%M}.pdf",
                mime="application/pdf", type="primary", width="stretch",
                key="reports_full_export",
            )
            if clicked:
                _log_report_generated("Full Summary", "PDF")
                st.rerun()


def _render_report_cards(user_id, username, start_date, end_date):
    cols = st.columns(4)
    for col, (color, illustration, title, desc, report_type, csv_section, pdf_func) in zip(cols, REPORT_CARDS):
        slug = title.lower().replace(" ", "_")
        with col, st.container(key=f"report_card_{color}_{slug}", border=True):
            st.markdown(
                _illustration(illustration, width="52px", height="40px", color=_CARD_ACCENT[color], opacity=0.9),
                unsafe_allow_html=True,
            )
            st.markdown(f"**{title}**")
            st.caption(desc)
            fmt = st.radio(
                "Format", ["CSV", "PDF"], key=f"report_format_{slug}",
                horizontal=True, label_visibility="collapsed",
            )
            _render_card_generate_button(
                slug, fmt, report_type, csv_section, pdf_func, user_id, username, start_date, end_date,
            )


def _render_card_generate_button(slug, fmt, report_type, csv_section, pdf_func, user_id, username, start_date, end_date):
    if fmt == "CSV":
        df = dataframe_for_export(csv_section, user_id, username, start_date, end_date)
        if df.empty:
            st.button(
                "Generate", key=f"report_gen_{slug}_empty", width="stretch", disabled=True,
                help="No data available for the selected period.",
            )
            return
        data = df.to_csv(index=False).encode("utf-8")
        clicked = st.download_button(
            "Generate", data=data, icon=":material/download:",
            file_name=f"{csv_section}_{datetime.now():%Y%m%d_%H%M}.csv",
            mime="text/csv", key=f"report_gen_{slug}_csv", width="stretch",
        )
        if clicked:
            _log_report_generated(report_type, "CSV")
            st.rerun()
    else:
        pdf_bytes = pdf_func(user_id, username, start_date, end_date)
        clicked = st.download_button(
            "Generate", data=pdf_bytes, icon=":material/download:",
            file_name=f"{csv_section}_{datetime.now():%Y%m%d_%H%M}.pdf",
            mime="application/pdf", key=f"report_gen_{slug}_pdf", width="stretch",
        )
        if clicked:
            _log_report_generated(report_type, "PDF")
            st.rerun()


def _log_report_generated(report_type: str, file_format: str):
    record_report(generated_by=st.session_state.get("user_id"), report_type=report_type, file_format=file_format)
    log_action(
        st.session_state.get("username", "?"), "REPORT_GENERATED", "REPORTS",
        f"Generated {report_type} report ({file_format}).",
    )


# ---------------------------------------------------------------
# Recent reports
# ---------------------------------------------------------------

def _render_report_history(user_id, username, start_date, end_date):
    rows = get_report_history(user_id, limit=50)
    if not rows:
        render_empty_state("No reports generated yet - use a card above to create your first one.", "report_chart")
        return

    table_df = pd.DataFrame([
        {
            "Report ID": f"RPT-{r['id']:04d}",
            "Report name": r["report_type"],
            "Format": r["file_format"],
            "Generated by": r["generated_by_username"],
            "Date": r["generated_at"],
            "Status": "Generated",
            "Action": "Regenerate below",
        }
        for r in rows
    ])
    st.dataframe(table_df, width="stretch", hide_index=True)
    st.caption(
        "Report files are streamed straight to your browser and aren't stored on the server, "
        "so a past entry can't be re-downloaded byte-for-byte. Pick one below to regenerate it "
        "fresh from your current data for the date range selected above."
    )

    options = {f"{r['report_type']} ({r['file_format']}) - RPT-{r['id']:04d}, {r['generated_at']:%Y-%m-%d %H:%M}": r for r in rows}
    choice = st.selectbox("Regenerate a past report", list(options.keys()), key="reports_regen_choice")
    chosen = options[choice]
    _render_regenerate_button(chosen, user_id, username, start_date, end_date)


def _render_regenerate_button(row, user_id, username, start_date, end_date):
    report_type, file_format = row["report_type"], row["file_format"]

    if file_format == "CSV":
        section = _REGEN_CSV_SECTIONS.get(report_type)
        if section is None:
            st.button("Regenerate & download", disabled=True, key="reports_regen_btn",
                       help="This report type can no longer be regenerated.")
            return
        df = dataframe_for_export(section, user_id, username, start_date, end_date)
        if df.empty:
            st.button("Regenerate & download", disabled=True, key="reports_regen_btn",
                       help="No data available for the selected period.")
            return
        data = df.to_csv(index=False).encode("utf-8")
        clicked = st.download_button(
            "Regenerate & download", data=data, icon=":material/refresh:",
            file_name=f"{section}_{datetime.now():%Y%m%d_%H%M}.csv",
            mime="text/csv", key="reports_regen_btn",
        )
    else:
        pdf_func = _REGEN_PDF_FUNCS.get(report_type)
        if pdf_func is None:
            st.button("Regenerate & download", disabled=True, key="reports_regen_btn",
                       help="This report type can no longer be regenerated.")
            return
        pdf_bytes = pdf_func(user_id, username, start_date, end_date)
        clicked = st.download_button(
            "Regenerate & download", data=pdf_bytes, icon=":material/refresh:",
            file_name=f"{report_type.lower().replace(' ', '_')}_{datetime.now():%Y%m%d_%H%M}.pdf",
            mime="application/pdf", key="reports_regen_btn",
        )

    if clicked:
        _log_report_generated(report_type, file_format)
        st.rerun()


# ---------------------------------------------------------------
# Export (per-tab CSV helper, unchanged)
# ---------------------------------------------------------------

def _csv_download(label: str, section: str, user_id, username, start_date, end_date, report_type: str):
    df = dataframe_for_export(section, user_id, username, start_date, end_date)
    if df.empty:
        st.info("No data available.")
        return
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    if st.download_button(
        label, data=csv_bytes,
        icon=":material/download:",
        file_name=f"{section}_{datetime.now():%Y%m%d_%H%M}.csv",
        mime="text/csv", key=f"csv_{section}",
    ):
        _log_report_generated(report_type, "CSV")
    st.dataframe(df, width="stretch", hide_index=True)


# ---------------------------------------------------------------
# Threat Detection
# ---------------------------------------------------------------

def _render_threat_section(summary, user_id, username, start_date, end_date):
    st.subheader("Threat Detection Summary")
    traffic, threats = summary["traffic"], summary["threats"]
    cols = st.columns(3)
    cols[0].metric("Traffic analysed", f"{traffic['total_rows']:,}",
                    help=f"{traffic['dataset_count']} dataset(s)")
    cols[1].metric("Total detections", f"{threats['total']:,}")
    cols[2].metric("Critical severity", f"{threats['critical']:,}")

    st.markdown("**Risk / Severity Distribution**")
    rows = summary["severity_distribution"]
    if not rows:
        st.info("No data available.")
    else:
        import plotly.express as px
        df = pd.DataFrame(rows)
        fig = px.bar(df, x="severity", y="count", color="severity",
                     color_discrete_map=SEVERITY_COLORS,
                     category_orders={"severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]})
        fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), showlegend=False)
        st.plotly_chart(fig, width="stretch")

    st.markdown("**Attack Type Distribution**")
    attack_rows = summary["attack_type_distribution"]
    if not attack_rows:
        st.info("No data available.")
    else:
        st.dataframe(pd.DataFrame(attack_rows), width="stretch", hide_index=True)

    st.markdown("**Export detection records**")
    _csv_download("Download CSV", "threat_detections", user_id, username, start_date, end_date, "Threat Detection")


# ---------------------------------------------------------------
# URL Scanning
# ---------------------------------------------------------------

def _render_url_section(summary, user_id, username, start_date, end_date):
    st.subheader("URL Scan Summary")
    urls = summary["url_scans"]
    cols = st.columns(2)
    cols[0].metric("URLs scanned", f"{urls['total']:,}")
    cols[1].metric("High/Critical risk", f"{urls['high_risk']:,}")

    st.markdown("**Status breakdown**")
    rows = summary["url_status_counts"]
    if not rows:
        st.info("No data available.")
    else:
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

    st.markdown("**Export scan records**")
    _csv_download("Download CSV", "url_scans", user_id, username, start_date, end_date, "URL Scan")


# ---------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------

def _render_compliance_section(summary, user_id, username, start_date, end_date):
    st.subheader("Compliance Summary", icon=":material/balance:")
    st.caption("Prototype assessment based on predefined rules - not legal advice.")

    render_compliance_cards(summary["compliance_overview"])

    st.markdown("**Export compliance results**")
    _csv_download("Download CSV", "compliance", user_id, username, start_date, end_date, "Compliance")


# ---------------------------------------------------------------
# Incidents (Alerts)
# ---------------------------------------------------------------

def _render_incident_section(summary, user_id, username, start_date, end_date):
    st.subheader("Incident Summary")
    rows = summary["alert_status_counts"]
    if not rows:
        st.info("No data available.")
    else:
        cols = st.columns(len(rows))
        for col, row in zip(cols, rows):
            col.metric(row["status"], row["count"])

    st.markdown("**Export alerts**")
    _csv_download("Download CSV", "alerts", user_id, username, start_date, end_date, "Incident Summary")


# ---------------------------------------------------------------
# Audit Activity
# ---------------------------------------------------------------

def _render_audit_section(summary, user_id, username, start_date, end_date):
    st.subheader("Audit Summary")
    rows = summary["audit_action_counts"]
    if not rows:
        st.info("No data available.")
    else:
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

    st.markdown("**Export audit log**")
    _csv_download("Download CSV", "audit_logs", user_id, username, start_date, end_date, "Audit Activity")
