"""
Single source of truth for every colour, type step and semantic label
used across AI CyberGuard's UI.

Why this module exists: before the redesign, the same severity palette
was declared twice with different values (app_pages/dashboard.py's
SEVERITY_COLORS vs app_pages/alerts.py's SEVERITY_COLORS), so a HIGH
threat was orange on one page and burnt-orange on another. Adding a
colour meant editing CSS strings in several files. Everything visual
now resolves through here, and utils/theme.py + utils/ui_kit.py read
from it instead of hard-coding hex values.

Rules encoded here (see the design system canvas for the full rationale):
  * Severity is ONE palette, identical on every page.
  * Severity text colour is darker than its dot/marker colour, so the
    label clears WCAG AA on white - colour alone never carries meaning.
  * Status (compliant / needs review / non-compliant / not assessed)
    is an ASSESSMENT vocabulary, deliberately distinct from severity.
  * Framework names are spelled exactly as the regulations are cited.
"""

# ---------------------------------------------------------------------
# Core surfaces and text
# ---------------------------------------------------------------------
INK = "#0F172A"            # headings and primary numbers
BODY = "#475569"           # body copy
MUTED = "#64748B"          # secondary labels, table headers
FAINT = "#94A3B8"          # disabled, decorative

PRIMARY = "#0EA5E9"        # sky-500 - the one accent used for actions
PRIMARY_DEEP = "#0369A1"   # links / gradient text end
CYAN = "#22D3EE"
VIOLET = "#8B5CF6"

PAGE_BG = "#F0F9FF"
SURFACE = "#FFFFFF"
SURFACE_TINT = "#F8FBFF"

BORDER = "rgba(15, 23, 42, 0.08)"
BORDER_STRONG = "rgba(15, 23, 42, 0.14)"

SIDEBAR_TOP = "#0B1220"
SIDEBAR_MID = "#111827"
SIDEBAR_TEXT = "#CBD5E1"
SIDEBAR_MUTED = "#94A3B8"

# Login page only - deliberately dark, as the contrast to the light app.
DARK_DEEP = "#020B18"
DARK_NAVY = "#06172B"
DARK_BLUE = "#087CFF"
DARK_CYAN = "#00D9FF"
DARK_TEXT = "#F5FAFF"
DARK_MUTED = "#A9C7E8"

# ---------------------------------------------------------------------
# Severity - the single palette (was duplicated with different values)
# ---------------------------------------------------------------------
SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

SEVERITY_COLORS = {
    "LOW": "#22C55E",
    "MEDIUM": "#F2C94C",
    "HIGH": "#F97316",
    "CRITICAL": "#DC2626",
}

# Darker companion for text on white - the marker hues above are too
# light to read as a word.
SEVERITY_TEXT = {
    "LOW": "#15803D",
    "MEDIUM": "#8A6A00",
    "HIGH": "#C2410C",
    "CRITICAL": "#B91C1C",
}

SEVERITY_TINTS = {
    "LOW": "rgba(34, 197, 94, 0.10)",
    "MEDIUM": "rgba(242, 201, 76, 0.16)",
    "HIGH": "rgba(249, 115, 22, 0.10)",
    "CRITICAL": "rgba(220, 38, 38, 0.09)",
}

# Risk-score bands from ml/risk_scoring.py - the UI states them in words
# next to every risk number rather than relying on a colour alone.
RISK_BANDS = ((29, "LOW"), (59, "MEDIUM"), (79, "HIGH"), (100, "CRITICAL"))


def severity_for_risk(risk_score) -> str:
    """Mirror of ml/risk_scoring.py's banding, for UI labelling only."""
    try:
        value = float(risk_score)
    except (TypeError, ValueError):
        return "LOW"
    for ceiling, label in RISK_BANDS:
        if value <= ceiling:
            return label
    return "CRITICAL"


# ---------------------------------------------------------------------
# Assessment status - NOT the same vocabulary as severity
# ---------------------------------------------------------------------
STATUS_LABELS = {
    "COMPLIANT": "Compliant",
    "NEEDS_REVIEW": "Needs review",
    "POTENTIAL_VIOLATION": "Potential violation",
    "NOT_ASSESSED": "Not assessed",
}

STATUS_COLORS = {
    "COMPLIANT": ("#15803D", "#ECFDF5"),
    "NEEDS_REVIEW": ("#B45309", "#FFFBEB"),
    "POTENTIAL_VIOLATION": ("#B91C1C", "#FEF2F2"),
    "NOT_ASSESSED": ("#64748B", "#F1F5F9"),
}

# Alert lifecycle (alerts.status enum)
ALERT_STATUS_COLORS = {
    "NEW": ("#1D4ED8", "#EFF6FF"),
    "INVESTIGATING": ("#B45309", "#FFFBEB"),
    "RESOLVED": ("#15803D", "#ECFDF5"),
}

# URL scan outcomes (url_scan_results.scan_status enum)
URL_STATUS_COLORS = {
    "SAFE": ("#15803D", "#ECFDF5"),
    "SUSPICIOUS": ("#B45309", "#FFFBEB"),
    "MALICIOUS": ("#B91C1C", "#FEF2F2"),
    "SCAN_ERROR": ("#64748B", "#F1F5F9"),
}

ROLE_COLORS = {
    "ADMIN": "#DC2626",
    "SOC ANALYST": "#2563EB",
    "COMPLIANCE OFFICER": "#8B5CF6",
    "AUDITOR": "#0D9488",
    "USER": "#16A34A",
}

# ---------------------------------------------------------------------
# Framework display names - cited exactly, never abbreviated ad hoc
# ---------------------------------------------------------------------
FRAMEWORK_NAMES = {
    "PDPA": "PDPA 2010",
    "ISO27001": "ISO/IEC 27001:2022",
    "NIST_CSF": "NIST CSF 2.0",
    "GDPR": "GDPR",
    "EU_AI_ACT": "EU AI Act",
}

FRAMEWORK_ORDER = ("PDPA", "ISO27001", "NIST_CSF", "GDPR", "EU_AI_ACT")


def framework_name(code: str) -> str:
    """'ISO27001' -> 'ISO/IEC 27001:2022'. Unknown codes pass through
    rather than being hidden, so a new framework is never silently
    dropped from a table."""
    return FRAMEWORK_NAMES.get(code, code)


# ---------------------------------------------------------------------
# Type scale and chart styling
# ---------------------------------------------------------------------
FONT_STACK = "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
MONO_STACK = "'JetBrains Mono', ui-monospace, 'SFMono-Regular', Menlo, monospace"

CHART_FONT = dict(family="Inter, sans-serif", size=12, color=MUTED)
CHART_LINE = PRIMARY
CHART_GRID = "rgba(15, 23, 42, 0.07)"
