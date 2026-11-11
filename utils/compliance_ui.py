"""
Shared compliance-framework card rendering, used by BOTH
app_pages/dashboard.py's "Compliance Overview" section and
app_pages/compliance.py's "Compliance Monitoring" page, so the same
status -> colour -> badge mapping and the same card layout are defined
in exactly one place instead of twice.

Every colour/badge is picked from REAL compliance_results data (see
status_for_row()) - this module never invents a status, a count, or a
"last checked" timestamp.

Each card is ONE self-contained raw HTML block (st.markdown(...,
unsafe_allow_html=True)) with every colour as an INLINE style, not a
st.container(key=...) + external CSS-class override. That container-
key approach was tried twice here and never actually painted a visible
colour in this installed Streamlit version - the external stylesheet
rule relies on exactly where Streamlit places the "st-key-X" class
relative to the element it visibly paints, which this version does not
appear to expose the way the rest of this file's cards assume. An
inline `style="..."` attribute has no such dependency: it is the
computed style of that exact element, period. This same inline-style
technique is what already renders correctly elsewhere in this project
(e.g. Settings' Account Activity rows, the Dashboard welcome banner's
quote card), so it is the proven-working approach, not a new risk.
Because the whole card - icon, badge, metrics, the breakdown bar - is
one HTML string built from a single st.markdown() call, there is no
"div opened in one call, closed in a later one" risk either; every tag
opened here is closed in the same string.
"""
import streamlit as st

from database.models import COMPLIANCE_FRAMEWORKS

# Hand-authored inline SVGs (stroke=currentColor, 24x24 viewBox) instead
# of ":material/x:" shorthand - that shorthand only renders through
# Streamlit's own markdown parser, never inside a raw unsafe_allow_html
# block (confirmed the hard way earlier in this project - see
# app_pages/settings.py's _render_activity_card). Deliberately plain
# line icons, not certification-seal imagery - a circular "badge"
# graphic next to a framework name could read as an actual
# certification mark, implying a status this prototype never claims.
_ICON_SHIELD_FLAG = (
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3 19 6v6c0 5-3 8-7 9-4-1-7-4-7-9V6z"/><path d="M12 8v4"/>'
    '<circle cx="12" cy="15.3" r="0.6" fill="currentColor" stroke="none"/></svg>'
)
_ICON_SHIELD_CHECK = (
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3 19 6v6c0 5-3 8-7 9-4-1-7-4-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'
)
_ICON_SHIELD = (
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3 19 6v6c0 5-3 8-7 9-4-1-7-4-7-9V6z"/></svg>'
)
_ICON_DOCUMENT = (
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>'
)
_ICON_ROBOT = (
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="5" y="8" width="14" height="10" rx="2"/><circle cx="9" cy="13" r="1.1" fill="currentColor" stroke="none"/>'
    '<circle cx="15" cy="13" r="1.1" fill="currentColor" stroke="none"/><path d="M12 8V5M9.5 5h5"/></svg>'
)

FRAMEWORK_ICONS = {
    "PDPA": _ICON_SHIELD_FLAG,
    "ISO27001": _ICON_SHIELD_CHECK,
    "NIST_CSF": _ICON_SHIELD,
    "GDPR": _ICON_DOCUMENT,
    "EU_AI_ACT": _ICON_ROBOT,
}

# A visibly-tinted background + a matching darker accent per status -
# the ONLY 4 colour sets that exist. status_for_row() is what picks
# which one applies to a given framework, always from real data.
# "badge" is plain Streamlit markdown (":color[...]" + ":material/x:"
# shorthand) for use in an ordinary st.markdown() call elsewhere in the
# app (e.g. app_pages/compliance.py's per-check expanders) - NOT inside
# a raw unsafe_allow_html block, where that shorthand never renders.
STATUS_STYLE = {
    "COMPLIANT": {"bg_from": "rgba(34, 197, 94, 0.22)", "bg_to": "rgba(34, 197, 94, 0.06)",
                  "accent": "#16A34A", "label": "COMPLIANT", "dot": "●",
                  "badge": ":green[:material/check_circle:] **COMPLIANT**"},
    "NEEDS_REVIEW": {"bg_from": "rgba(245, 158, 11, 0.24)", "bg_to": "rgba(245, 158, 11, 0.07)",
                      "accent": "#B45309", "label": "NEEDS REVIEW", "dot": "▲",
                      "badge": ":orange[:material/warning:] **NEEDS REVIEW**"},
    "POTENTIAL_VIOLATION": {"bg_from": "rgba(220, 38, 38, 0.22)", "bg_to": "rgba(220, 38, 38, 0.06)",
                             "accent": "#DC2626", "label": "NON-COMPLIANT", "dot": "●",
                             "badge": ":red[:material/cancel:] **NON-COMPLIANT**"},
    "NOT_ASSESSED": {"bg_from": "rgba(148, 163, 184, 0.22)", "bg_to": "rgba(148, 163, 184, 0.06)",
                      "accent": "#475569", "label": "NOT YET ASSESSED", "dot": "○",
                      "badge": ":gray[:material/help:] **NOT YET ASSESSED**"},
}

_PASSED_COLOR = "#16A34A"
_REVIEW_COLOR = "#D97706"
_ISSUE_COLOR = "#DC2626"


def status_for_row(row) -> str:
    """No row at all means never-assessed; a recorded violation
    outranks needs-review; otherwise compliant. Never invents a status
    beyond what compliance_results actually contains."""
    if row is None:
        return "NOT_ASSESSED"
    if row["violation"] > 0:
        return "POTENTIAL_VIOLATION"
    if row["needs_review"] > 0:
        return "NEEDS_REVIEW"
    return "COMPLIANT"


def render_compliance_cards(overview: dict, cards_per_row: int = 3):
    """Render all 5 framework cards from a real
    get_compliance_overview(user_id) result, `cards_per_row` wide per
    row (3 on row one + 2 on row two by default). Used by both the
    Compliance Monitoring page (full page width - default 3/row) and
    the Dashboard's narrower Compliance Overview column (passes
    cards_per_row=2, since 3 cards squeezed into ~45% of the dashboard
    width wrapped every framework name and stretched each card tall)."""
    frameworks = list(COMPLIANCE_FRAMEWORKS)
    cols = []
    for i in range(0, len(frameworks), cards_per_row):
        row_count = min(cards_per_row, len(frameworks) - i)
        cols.extend(st.columns(row_count))
    for col, (code, display_name) in zip(cols, frameworks):
        with col:
            row = overview.get(code)
            _render_card(code, display_name, row, status_for_row(row))


def _breakdown_bar_html(passed: int, needs_review: int, issues: int) -> str:
    """A small 3-colour stacked bar (green/orange/red, proportional to
    real counts) in place of a single-colour progress bar - doubles as
    a compact "at a glance" chart of the pass/review/issue split,
    without pulling in a full chart library for a strip this small.
    Never shown with fabricated proportions: called only when total>0."""
    total = passed + needs_review + issues
    passed_pct = passed / total * 100
    review_pct = needs_review / total * 100
    issue_pct = issues / total * 100
    segments = ""
    if passed_pct > 0:
        segments += f'<div style="width:{passed_pct:.2f}%; background:{_PASSED_COLOR};"></div>'
    if review_pct > 0:
        segments += f'<div style="width:{review_pct:.2f}%; background:{_REVIEW_COLOR};"></div>'
    if issue_pct > 0:
        segments += f'<div style="width:{issue_pct:.2f}%; background:{_ISSUE_COLOR};"></div>'
    return (
        '<div style="display:flex; width:100%; height:8px; border-radius:999px; '
        'overflow:hidden; background:rgba(15,23,42,0.08); margin-top:0.5rem;">'
        f"{segments}</div>"
    )


def _render_card(code: str, display_name: str, row, status: str):
    style = STATUS_STYLE[status]
    icon = FRAMEWORK_ICONS.get(code, _ICON_SHIELD)
    accent = style["accent"]

    if row is None:
        body = (
            '<p class="compliance-card-note">No compliance checks have run for this framework yet.</p>'
            '<div class="compliance-card-metrics">'
            f'<span><b style="color:{_PASSED_COLOR}">—</b> Passed</span>'
            f'<span><b style="color:{_REVIEW_COLOR}">—</b> Needs review</span>'
            f'<span><b style="color:{_ISSUE_COLOR}">—</b> Issues</span>'
            "</div>"
            '<p class="compliance-card-note">Last checked: —</p>'
        )
    else:
        passed = int(row["compliant"])
        needs_review = int(row["needs_review"])
        issues = int(row["violation"])
        total = passed + needs_review + issues
        bar = _breakdown_bar_html(passed, needs_review, issues) if total > 0 else ""
        pct_line = (
            f'<p class="compliance-card-note">{passed}/{total} checks passed '
            f"({round(passed / total * 100)}%) - not a legal compliance guarantee</p>{bar}"
            if total > 0 else ""
        )
        body = (
            '<div class="compliance-card-metrics">'
            f'<span><b style="color:{_PASSED_COLOR}">{passed}</b> Passed</span>'
            f'<span><b style="color:{_REVIEW_COLOR}">{needs_review}</b> Needs review</span>'
            f'<span><b style="color:{_ISSUE_COLOR}">{issues}</b> Issues</span>'
            "</div>"
            f'<p class="compliance-card-note">Last checked: {row["last_checked"] or "—"}</p>'
            f"{pct_line}"
        )

    st.markdown(
        '<div class="compliance-card" style="'
        f'background: linear-gradient(160deg, {style["bg_from"]}, {style["bg_to"]}); '
        f'border: 1px solid {accent}55; border-left: 4px solid {accent};">'
        '<div class="compliance-card-head">'
        f'<span class="compliance-card-icon" style="color:{accent};">{icon}</span>'
        f'<span class="compliance-card-title">{display_name}</span>'
        "</div>"
        f'<span class="compliance-card-badge" style="color:{accent}; background:{accent}1F; border:1px solid {accent}55;">'
        f'{style["dot"]} {style["label"]}</span>'
        f"{body}"
        "</div>",
        unsafe_allow_html=True,
    )
