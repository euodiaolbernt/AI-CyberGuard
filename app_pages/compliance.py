"""
Compliance Monitoring page (Step 7).

Shows the five frameworks from the FYP report (PDPA, ISO/IEC 27001,
NIST CSF, GDPR, EU AI Act), each backed by real rows in
compliance_results - written by compliance/compliance_engine.py
whenever a Threat Detection or URL Scanner event is evaluated (PDPA/
GDPR/ISO27001/NIST), or by the "Run AI System Self-Assessment" button
below (EU AI Act, which the FYP report says applies to the AI system
itself, not individual events).

This page - and every rule in compliance/ - is a predefined PROTOTYPE
assessment. It never claims legal compliance and never provides legal
advice; see the disclaimer directly under the page header.
"""
import pandas as pd
import streamlit as st

from compliance.compliance_engine import ALL_RULE_CATALOGS, run_ai_system_self_assessment
from database.models import (
    COMPLIANCE_FRAMEWORKS,
    get_compliance_overview,
    get_compliance_results_detail,
    seed_compliance_rules,
)
from utils.audit_logger import log_action
from utils.compliance_ui import STATUS_STYLE, render_compliance_cards
from utils.illustrations import (
    BANNER_ICON_DOCUMENT,
    BANNER_ICON_SCALE,
    BANNER_ICON_SHIELD_CHECK,
    render_intro_banner,
    render_premium_banner,
)
from utils.page_ui import render_empty_state
from utils.time_navigator import get_active_range

# Display labels for the 3 statuses a compliance_results ROW can
# actually hold (NOT_ASSESSED only ever applies at the framework-card
# level, never to an individual recorded check).
_STATUS_LABELS = {
    "COMPLIANT": "Compliant",
    "NEEDS_REVIEW": "Needs review",
    "POTENTIAL_VIOLATION": "Non-compliant",
}
_STATUS_LABEL_COLORS = {
    "Compliant": STATUS_STYLE["COMPLIANT"]["accent"],
    "Needs review": STATUS_STYLE["NEEDS_REVIEW"]["accent"],
    "Non-compliant": STATUS_STYLE["POTENTIAL_VIOLATION"]["accent"],
}


def render_compliance_page():
    # Idempotent - upserts the ~13 static rule definitions by rule_code.
    # Cheap enough to run on every page load, and guarantees the rule
    # catalog exists even on a database that has never seen this page.
    for catalog in ALL_RULE_CATALOGS:
        seed_compliance_rules(catalog)

    with st.container(key="compliance_premium_banner"):
        render_premium_banner(
            badge_text="AI CYBERGUARD &bull; COMPLIANCE CORE",
            heading_main="Stay Aligned.", heading_accent="Stay Audit-Ready.",
            description="A prototype assessment engine checks your real recorded "
                        "activity against today's leading security frameworks.",
            features=[
                (BANNER_ICON_SCALE, "PDPA & GDPR", "cyan"),
                (BANNER_ICON_SHIELD_CHECK, "ISO 27001", "violet"),
                (BANNER_ICON_DOCUMENT, "NIST CSF", "teal"),
            ],
        )
    render_intro_banner(
        "Compliance assessment based on predefined prototype rules. This is "
        "not legal advice and does not certify legal compliance - results "
        "indicate where a human review may be warranted.",
        "robot_security_panel", width=130, accent="#8B5CF6",  # matches PAGE_META's Compliance Monitoring accent
    )

    user_id = st.session_state["user_id"]

    with st.container(key="compliance_assessment_cta", border=True):
        cols = st.columns([3, 1])
        with cols[0]:
            st.markdown("##### :material/smart_toy: Run AI System Self-Assessment")
            st.caption(
                "Evaluates this AI system itself (EU AI Act) against the predefined "
                "prototype checklist - not an individual network event or URL scan."
            )
        with cols[1]:
            run_clicked = st.button(
                "Run assessment", type="primary", icon=":material/play_circle:",
                width="stretch",
            )

        if run_clicked:
            with st.spinner("Running AI system self-assessment..."):
                results = run_ai_system_self_assessment(user_id)
                log_action(
                    st.session_state.get("username", "?"), "COMPLIANCE_CHECK", "COMPLIANCE",
                    f"Ran EU AI Act self-assessment ({len(results)} checks).",
                )

            compliant = sum(1 for r in results if r["status"] == "COMPLIANT")
            needs_review = sum(1 for r in results if r["status"] == "NEEDS_REVIEW")
            violation = sum(1 for r in results if r["status"] == "POTENTIAL_VIOLATION")
            st.success(
                f"Self-assessment complete: {len(results)} check(s) recorded - "
                f":green[{compliant} compliant], :orange[{needs_review} needs review], "
                f":red[{violation} non-compliant]."
            )

    start, end, _ = get_active_range()

    st.divider()
    render_compliance_cards(get_compliance_overview(user_id, start, end))

    st.divider()
    with st.container(key="page_panel_blue_detail", border=True):
        st.subheader("Rule-by-rule detail", icon=":material/fact_check:")
        _render_detail_table(user_id, start, end)


def _status_cell_style(value):
    color = _STATUS_LABEL_COLORS.get(value)
    return f"color: {color}; font-weight: 600;" if color else ""


_FINDING_ICONS = {
    "COMPLIANT": ":material/check_circle:",
    "NEEDS_REVIEW": ":material/warning:",
    "POTENTIAL_VIOLATION": ":material/cancel:",
}


def _render_detail_table(user_id: int, start, end):
    filter_cols = st.columns([1.1, 1.9])
    with filter_cols[0]:
        framework_options = ["All"] + [code for code, _ in COMPLIANCE_FRAMEWORKS]
        chosen = st.selectbox("Filter by framework", framework_options)
    with filter_cols[1]:
        search_query = st.text_input(
            "Search findings", placeholder="Search by check, status, or recommendation...",
            icon=":material/search:",
        )
    framework_filter = None if chosen == "All" else chosen

    rows = get_compliance_results_detail(
        user_id, framework=framework_filter, limit=100, start_date=start, end_date=end,
    )
    if not rows:
        render_empty_state("No data available.", "legal_scale")
        return

    # Real text search over the already-fetched rows - never a second
    # database query, so it can never disagree with the table above.
    q = search_query.strip().lower()
    if q:
        rows = [
            r for r in rows
            if q in (r["title"] or "").lower()
            or q in (r["framework"] or "").lower()
            or q in _STATUS_LABELS.get(r["status"], r["status"]).lower()
            or q in (r.get("recommended_action") or "").lower()
            or q in (r.get("reason") or "").lower()
        ]
        if not rows:
            render_empty_state(f"No findings match \"{search_query}\".", "legal_scale")
            return

    # "Risk level" from the reference design has no backing column in
    # compliance_results and is intentionally omitted rather than
    # invented - only real columns are shown here.
    table_df = pd.DataFrame([
        {
            "Framework": r["framework"],
            "Check": r["title"],
            "Status": _STATUS_LABELS.get(r["status"], r["status"]),
            "Last checked": r["checked_at"],
            "Recommendation": r.get("recommended_action") or "-",
        }
        for r in rows
    ])
    st.dataframe(
        table_df.style.map(_status_cell_style, subset=["Status"]),
        width="stretch", hide_index=True,
    )

    st.markdown("###### Check-by-check findings")
    st.caption(
        "Click a check to expand its recorded finding, supporting evidence, and "
        "recommended action - exactly as stored by the assessment, nothing inferred. "
        "Colour and icon match its real status."
    )
    for i, r in enumerate(rows):
        style = STATUS_STYLE.get(r["status"], STATUS_STYLE["NOT_ASSESSED"])
        label = _STATUS_LABELS.get(r["status"], r["status"])
        icon = _FINDING_ICONS.get(r["status"], ":material/help:")
        status_slug = r["status"].lower()
        with st.expander(
            f"{r['framework']} - {r['title']} ({label})",
            icon=icon, key=f"compliance_exp_{status_slug}_{i}",
        ):
            st.markdown(style["badge"])
            st.markdown(f"**Finding:** {r.get('reason') or 'No finding recorded.'}")
            st.markdown(f"**Supporting evidence:** {r.get('evidence') or 'No evidence recorded.'}")
            st.markdown(f"**Recommended action:** {r.get('recommended_action') or 'None recorded.'}")
            st.caption(f":material/schedule: Checked at {r['checked_at']}")
