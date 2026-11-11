"""
Report data assembly + export (Step 10).

Every function here only reads through database/models.py's existing
query functions (each extended with optional start_date/end_date
filtering, backward-compatible with every page that already called
them without dates) - so a Reports export can never show a different
number than the Dashboard, Threat Detection, URL Scanner, Compliance,
Alerts, or Audit Logs pages it summarises, and never invents a result.
Severity/risk figures come from the exact same rows those pages read,
via the same ml/risk_scoring.py-derived values already stored in the
database - nothing is recalculated differently here.

CSV export uses pandas (already a dependency). PDF export uses fpdf2
(already a dependency since Step 1, unused until now) - no new
package was added for this feature.
"""
from datetime import datetime

import pandas as pd
from fpdf import FPDF

from database.models import (
    COMPLIANCE_FRAMEWORKS,
    get_alert_status_counts,
    get_alerts,
    get_attack_type_distribution,
    get_audit_action_counts,
    get_audit_logs,
    get_compliance_overview,
    get_compliance_results_detail,
    get_severity_distribution,
    get_threat_detections_in_range,
    get_threat_summary,
    get_traffic_summary,
    get_url_scan_status_counts,
    get_url_scan_summary,
    get_url_scans_in_range,
)

EXPORT_ROW_LIMIT = 5000  # generous cap for an FYP-scale dataset, not a hard product limit


def build_report_summary(user_id: int, username: str, start_date=None, end_date=None) -> dict:
    """Gather every summary section's real, current data for THIS
    user only, in one dict. Used for BOTH the on-page display and the
    PDF export, so the two can never disagree with each other, and
    never with another user's report."""
    return {
        "generated_at": datetime.now(),
        "start_date": start_date,
        "end_date": end_date,
        "traffic": get_traffic_summary(user_id, start_date, end_date),
        "threats": get_threat_summary(user_id, start_date, end_date),
        "severity_distribution": get_severity_distribution(user_id, start_date, end_date),
        "attack_type_distribution": get_attack_type_distribution(user_id, start_date, end_date),
        "url_scans": get_url_scan_summary(user_id, start_date, end_date),
        "url_status_counts": get_url_scan_status_counts(user_id, start_date, end_date),
        "compliance_overview": get_compliance_overview(user_id, start_date, end_date),
        "alert_status_counts": get_alert_status_counts(user_id, start_date, end_date),
        "audit_action_counts": get_audit_action_counts(username, start_date, end_date),
    }


def dataframe_for_export(section: str, user_id: int, username: str, start_date=None, end_date=None) -> pd.DataFrame:
    """Return the full detail rows for one report section as a
    DataFrame, scoped to THIS user only, ready for CSV export - the
    same query each page's on-screen table uses, just with a higher
    row limit."""
    if section == "threat_detections":
        rows = get_threat_detections_in_range(user_id, start_date, end_date, EXPORT_ROW_LIMIT)
    elif section == "url_scans":
        rows = get_url_scans_in_range(user_id, start_date, end_date, EXPORT_ROW_LIMIT)
    elif section == "compliance":
        rows = get_compliance_results_detail(user_id, limit=EXPORT_ROW_LIMIT, start_date=start_date, end_date=end_date)
    elif section == "alerts":
        rows = get_alerts(user_id, limit=EXPORT_ROW_LIMIT, start_date=start_date, end_date=end_date)
    elif section == "audit_logs":
        rows = get_audit_logs(username, limit=EXPORT_ROW_LIMIT, start_date=start_date, end_date=end_date)
    else:
        raise ValueError(f"Unknown report section: {section}")
    return pd.DataFrame(rows)


def generate_pdf_report(user_id: int, username: str, start_date=None, end_date=None) -> bytes:
    """Build a simple, honest PDF summary report for THIS user only,
    covering every section. Every figure comes from
    build_report_summary() - nothing is typed into this function
    directly."""
    summary = build_report_summary(user_id, username, start_date, end_date)
    pdf = _new_pdf("AI CyberGuard - Security & Compliance Report", summary, start_date, end_date)

    _render_threat_detection_pdf(pdf, summary)
    _render_url_scan_pdf(pdf, summary)
    _render_compliance_pdf(pdf, summary)
    _pdf_table(pdf, "Incident Summary (alerts by status)", ["Status", "Count"],
               [[r["status"], r["count"]] for r in summary["alert_status_counts"]])
    _render_audit_log_pdf(pdf, summary)

    return bytes(pdf.output())


def generate_threat_detection_report_pdf(user_id: int, username: str, start_date=None, end_date=None) -> bytes:
    """One of the 4 Reports-page 'Generate' card formats - same real
    data as the Threat Detection tab/section, just this one section on
    its own instead of the full combined report."""
    summary = build_report_summary(user_id, username, start_date, end_date)
    pdf = _new_pdf("AI CyberGuard - Threat Detection Report", summary, start_date, end_date)
    _render_threat_detection_pdf(pdf, summary)
    return bytes(pdf.output())


def generate_url_scan_report_pdf(user_id: int, username: str, start_date=None, end_date=None) -> bytes:
    """One of the 4 Reports-page 'Generate' card formats."""
    summary = build_report_summary(user_id, username, start_date, end_date)
    pdf = _new_pdf("AI CyberGuard - URL Scan Report", summary, start_date, end_date)
    _render_url_scan_pdf(pdf, summary)
    return bytes(pdf.output())


def generate_compliance_report_pdf(user_id: int, username: str, start_date=None, end_date=None) -> bytes:
    """One of the 4 Reports-page 'Generate' card formats."""
    summary = build_report_summary(user_id, username, start_date, end_date)
    pdf = _new_pdf("AI CyberGuard - Compliance Report", summary, start_date, end_date)
    _render_compliance_pdf(pdf, summary)
    return bytes(pdf.output())


def generate_audit_log_report_pdf(user_id: int, username: str, start_date=None, end_date=None) -> bytes:
    """One of the 4 Reports-page 'Generate' card formats."""
    summary = build_report_summary(user_id, username, start_date, end_date)
    pdf = _new_pdf("AI CyberGuard - Audit Log Report", summary, start_date, end_date)
    _render_audit_log_pdf(pdf, summary)
    return bytes(pdf.output())


def _new_pdf(title: str, summary: dict, start_date, end_date) -> FPDF:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, title)
    pdf.ln(12)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Generated: {summary['generated_at']:%Y-%m-%d %H:%M}")
    pdf.ln(6)
    pdf.cell(0, 6, f"Report period: {_format_range(start_date, end_date)}")
    pdf.ln(10)

    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(
        0, 5,
        "This report reflects only data actually recorded by the system. "
        "It is a prototype compliance assessment, not legal advice, and does "
        "not certify legal compliance."
    )
    pdf.ln(4)
    return pdf


def _render_threat_detection_pdf(pdf: FPDF, summary: dict):
    _pdf_section(pdf, "Threat Detection Summary", [
        f"Total traffic analysed: {summary['traffic']['total_rows']} row(s) "
        f"across {summary['traffic']['dataset_count']} dataset(s)",
        f"Total detections: {summary['threats']['total']}",
        f"Critical severity: {summary['threats']['critical']}",
    ])
    _pdf_table(pdf, "Severity distribution", ["Severity", "Count"],
               [[r["severity"], r["count"]] for r in summary["severity_distribution"]])
    _pdf_table(pdf, "Attack type distribution", ["Attack type", "Count"],
               [[r["attack_type"], r["count"]] for r in summary["attack_type_distribution"]])


def _render_url_scan_pdf(pdf: FPDF, summary: dict):
    _pdf_section(pdf, "URL Scan Summary", [
        f"Total URLs scanned: {summary['url_scans']['total']}",
        f"High/Critical risk: {summary['url_scans']['high_risk']}",
    ])
    _pdf_table(pdf, "Scan status breakdown", ["Status", "Count"],
               [[r["scan_status"], r["count"]] for r in summary["url_status_counts"]])


def _render_compliance_pdf(pdf: FPDF, summary: dict):
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Compliance Summary")
    pdf.ln(8)
    compliance_rows = []
    for code, name in COMPLIANCE_FRAMEWORKS:
        row = summary["compliance_overview"].get(code)
        if row:
            compliance_rows.append([name, int(row["compliant"]), int(row["needs_review"]), int(row["violation"])])
        else:
            compliance_rows.append([name, "-", "-", "-"])
    _pdf_table(pdf, None, ["Framework", "Compliant", "Needs review", "Issues"], compliance_rows)


def _render_audit_log_pdf(pdf: FPDF, summary: dict):
    _pdf_table(pdf, "Audit Summary (actions)", ["Action", "Count"],
               [[r["action"], r["count"]] for r in summary["audit_action_counts"]])


def _format_range(start_date, end_date) -> str:
    if not start_date and not end_date:
        return "All time"
    start_str = start_date.strftime("%Y-%m-%d") if start_date else "the beginning"
    end_str = end_date.strftime("%Y-%m-%d") if end_date else "now"
    return f"{start_str} to {end_str}"


def _pdf_section(pdf: FPDF, title: str, lines: list):
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, title)
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 10)
    for line in lines:
        pdf.cell(0, 6, line)
        pdf.ln(6)
    pdf.ln(2)


def _pdf_table(pdf: FPDF, title, headers: list, rows: list):
    if title:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 7, title)
        pdf.ln(7)

    if not rows:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "No data available.")
        pdf.ln(8)
        return

    col_width = 190 / len(headers)
    pdf.set_font("Helvetica", "B", 9)
    for h in headers:
        pdf.cell(col_width, 6, str(h), border=1)
    pdf.ln()

    pdf.set_font("Helvetica", "", 9)
    for row in rows:
        for val in row:
            pdf.cell(col_width, 6, str(val), border=1)
        pdf.ln()
    pdf.ln(4)
