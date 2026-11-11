"""
Global visual theme for the authenticated application (top bar +
sidebar + every page's headers/cards/buttons/inputs/tables/tabs/alerts).

VISUAL ONLY: this module never touches session_state, routing, auth,
the database, or ML - it only injects CSS (plus wraps a few existing
sidebar elements in st.container(key=...) purely so they have a stable
class to style). inject_global_theme() must only ever be called from
app.py's render_app() - i.e. only AFTER authentication - so none of
this can ever apply to, or conflict with, auth/login.py's own
completely separate background/glassmorphism CSS, which keeps styling
its own page independently.

LIGHT THEME, DELIBERATELY: a full dark-navy main-content pass was
tried and explicitly reverted ("don't make it dark, make it more
colorful but professional") - .streamlit/config.toml's [theme] is
back to base = "light" to match, which is what makes NATIVE components
this CSS can't reach at all (most importantly st.dataframe's grid,
rendered via WebGL/canvas) render light/correct automatically. "More
colorful" here means richer, more varied accent saturation across the
KPI/panel/chart system below - not a hue shift to dark. The sidebar
stays its own separate dark navy (unchanged, and never the part any
feedback objected to) so the product still has one confident dark
accent instead of being uniformly pastel everywhere.

Every selector below is one of two kinds, never a guessed/unstable one:
  1. A real data-testid confirmed by reading this exact installed
     Streamlit version's own frontend bundle (venv/.../streamlit/static),
     e.g. stSidebar, stRadioOption, stLayoutWrapper, stMetric, stButton,
     stTextInput, stSelectbox, stDataFrame, stAlert, stHeading, stTabs,
     stPopover.
  2. Streamlit's own official, version-stable key=-generated
     `.st-key-<name>` class (see theme.md in the developing-with-
     streamlit skill) - used for the handful of elements (sidebar
     brand block, user card, nav radio, logout button, top bar) that
     app.py wraps/keys specifically for this theme.

The one deliberately "clever" selector is the sidebar's active-nav-item
highlight: `.st-key-sidebar_nav [data-testid="stRadioOption"]:has(input
:checked)`. Streamlit's radio option renders a real native
<input type="radio" checked> under the hood for accessibility (confirmed
in the bundle - it's a standard React-Aria radio, not an emotion-only
visual state), so :checked is a genuine, spec-standard CSS pseudo-class
here, not a guessed internal - and :has() is a normal, spec-standard
selector in every current browser. If a future Streamlit version ever
changes this internal structure, the only failure mode is that specific
highlight silently not applying (a harmless no-op) - it cannot break
navigation, since the underlying st.radio widget and its value are
completely untouched.

Every rule in the REUSABLE PAGE-LEVEL CARDS / THREAT DETECTION / URL
SCANNER / REPORTS / SETTINGS sections below follows one rule, proven
correct the hard way (this file used to paint backgrounds/borders
directly on a border=True container's OUTER `.st-key-X` class, which
combined with Streamlit's own native box on an INNER
[data-testid="stLayoutWrapper"] element to paint two independent,
visibly stacked boxes per card - the app-wide "duplicate panel" bug):
a border=True container's visible box is always painted by Streamlit
on that inner stLayoutWrapper, never the outer div - so every outer
class below is explicitly reset to invisible (no border/background/
shadow of its own) and all real visual styling lives on
`.st-key-X [data-testid="stLayoutWrapper"]` instead.
"""
from pathlib import Path

import streamlit as st

# Sidebar stays dark navy - unchanged and never the part any feedback
# objected to (the login page shares this same dark palette too, via
# its own CSS custom properties).
_NAVY_DARK = "#0B1220"
_NAVY_MID = "#111827"
_MUTED_LIGHT = "#94A3B8"
_MUTED_ON_DARK = "#CBD5E1"

# Global background photo (main content area only, never the sidebar -
# see GLOBAL BACKGROUND below). Served from static/ - the one folder
# Streamlit's own "app static file serving" feature exposes at the URL
# "app/static/<file>" (enableStaticServing = true in .streamlit/
# config.toml) - rather than assets/ (the canonical source copy also
# used for the illustrations in utils/illustrations.py), because
# Streamlit does not expose arbitrary folders as URLs, only one
# literally named "static" next to app.py. Resolved via __file__ (not
# the process's CWD, which has drifted before in this project) so this
# works regardless of where `streamlit run` is launched from.
_BACKGROUND_IMAGE_PATH = Path(__file__).resolve().parent.parent / "static" / "cyberguard_background.png"

# Same mechanism, for the shared top_bar header specifically (see
# render_top_bar() in utils/page_ui.py - the one container every page
# renders its header through).
_HEADER_BACKGROUND_IMAGE_PATH = Path(__file__).resolve().parent.parent / "static" / "cyberguard_header_background.png"

# Main content: light theme, dark slate text, cyan/blue primary accent.
_SLATE_TEXT = "#0F172A"
# Darkened from the original #64748B (slate-500) - that read as too
# pale/low-contrast for captions, metric labels, and empty-state detail
# text on this app's light-blue/white card backgrounds (reported
# directly: "the small word tht color grey ... change to color dark
# grey"). #475569 (slate-600) is the single shared "muted/secondary
# text" token used across the whole site, so darkening it here fixes
# every caption/label at once rather than patching each one.
_SLATE_MUTED = "#475569"
_BODY_TEXT = "#334155"
_INPUT_TEXT = "#1E293B"
# Section headings (st.subheader()/h3 - "Model Evaluation", "Recent
# Threats", etc.) get their own distinct dark navy, one step apart from
# h1/h2's _SLATE_TEXT, so the two heading levels read as a hierarchy
# rather than identical weight/colour at different sizes.
_SECTION_HEADING = "#172554"
# st.caption()'s own colour - distinct from _SLATE_MUTED (used for
# "subtitle"-style secondary text like .dw-subtitle/.td-stage-desc),
# per an explicit two-tier request: captions/helper text a hair
# lighter than secondary subtitles, both comfortably dark enough to
# read.
_CAPTION_TEXT = "#52647A"
# Genuinely secondary states ONLY - disabled fields and placeholder
# text, which should read a step lighter than real content so the
# difference between "disabled/empty" and "filled in" stays visible at
# a glance. Never used for normal captions/labels/body text (those all
# use a darker token above).
_PLACEHOLDER_TEXT = "#64748B"
_LINK_TEXT = "#0369A1"
_CYAN = "#22D3EE"
_BLUE = "#0EA5E9"
_BLUE_DARK = "#0891B2"
_GREEN = "#16A34A"
_RED = "#DC2626"

# Dashboard KPI cards (app_pages/dashboard.py wraps each st.metric in
# st.container(key=<one of these>)) - (accent hex, accent "r, g, b" for
# use in rgba()). Kept as one small table rather than nine near-
# duplicate hand-written CSS blocks, so every card's colour, border and
# glow stay derived from a single source instead of drifting apart.
# Colours are semantic, not decorative: compliance's three status keys
# are only ever chosen by app_pages/dashboard.py from REAL compliance
# data (see its docstring there) - never hard-coded to one colour.
# Tints are a bit richer than a first pass (0.16/0.06 vs 0.12/0.04) -
# the "more colorful" half of the feedback that kept this light.
_KPI_CARD_COLORS = {
    "kpi_traffic": ("#3B82F6", "59, 130, 246"),             # soft blue
    "kpi_threats": ("#EF4444", "239, 68, 68"),              # red
    "kpi_critical": ("#BE123C", "190, 18, 60"),             # deep crimson
    "kpi_urls": ("#0D9488", "13, 148, 136"),                # teal
    "kpi_highrisk": ("#D97706", "217, 119, 6"),             # amber/orange
    "kpi_compliance_ok": ("#16A34A", "22, 163, 74"),        # green - fully compliant
    "kpi_compliance_warn": ("#D97706", "217, 119, 6"),      # amber - needs review
    "kpi_compliance_bad": ("#DC2626", "220, 38, 38"),       # red - potential violation
    "kpi_compliance_neutral": ("#94A3B8", "148, 163, 184"), # grey/blue - no data yet
    "kpi_medium": ("#F2C94C", "242, 201, 76"),              # gold - alerts' MEDIUM severity
    "kpi_low": ("#22C55E", "34, 197, 94"),                  # green - alerts' LOW severity
    "kpi_violet": ("#8B5CF6", "139, 92, 246"),              # generic violet (e.g. Audit Logs' COMPLIANCE)
    "kpi_cyan": ("#22D3EE", "34, 211, 238"),                # generic cyan (e.g. Audit Logs' REPORTS)
}


def _kpi_card_css() -> str:
    """Note: the class is repeated 3x in every selector below
    (`.st-key-X.st-key-X.st-key-X`) purely to raise CSS specificity -
    it still matches the exact same single element, but this lets
    these colours keep winning even when a card is reused somewhere
    that ALSO nests inside a more deeply-scoped descendant rule (e.g.
    app_pages/threat_detection.py reuses these same keys inside its
    own .st-key-td_page_wrapper panel, whose own descendant selector
    would otherwise outrank a plain single-class rule)."""
    blocks = []
    for key, (accent, rgb) in _KPI_CARD_COLORS.items():
        sel = f".st-key-{key}.st-key-{key}.st-key-{key}"
        blocks.append(f"""
        [data-testid="stMain"] {sel} {{
            background: linear-gradient(135deg, rgba({rgb}, 0.24), rgba({rgb}, 0.08)) !important;
            border: 1px solid rgba({rgb}, 0.50) !important;
            border-top: 4px solid {accent} !important;
            border-radius: 14px !important;
            box-shadow: 0 4px 16px rgba({rgb}, 0.22) !important;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }}
        [data-testid="stMain"] {sel}:hover {{
            transform: translateY(-3px);
            box-shadow: 0 10px 24px rgba({rgb}, 0.38) !important;
        }}
        [data-testid="stMain"] {sel} [data-testid="stMetric"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] {sel} [data-testid="stMetricValue"] {{
            color: {accent} !important;
        }}
        /* A KPI card's own "View details" link (only present on cards
           that have a single, meaningful destination page - see
           app_pages/dashboard.py) - small and ghost-styled so it reads
           as a quiet link under the number, not a second full button
           competing with the metric itself. */
        [data-testid="stMain"] {sel} [data-testid="stButton"] button {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            color: {accent} !important;
            font-size: 0.78rem !important;
            font-weight: 600 !important;
            padding: 0.1rem 0 !important;
            text-align: left !important;
            justify-content: flex-start !important;
        }}
        [data-testid="stMain"] {sel} [data-testid="stButton"] button:hover {{
            text-decoration: underline;
        }}""")
    blocks.append(_KPI_CARD_LAYOUT_CSS)
    # Belt-and-suspenders, appended LAST (after every rule above,
    # including _KPI_CARD_LAYOUT_CSS): a second colour rule per card
    # using the same substring [class*="st-key-X"] selector
    # _KPI_CARD_LAYOUT_CSS itself already relies on, instead of the
    # exact tripled-class selector above - reported directly (a
    # screenshot of Alerts & Incidents' 5 severity cards showing every
    # "0" the same plain dark navy, not each card's own accent colour,
    # despite the !important rule above). Two independently-matching
    # roads to the same !important colour is cheap insurance against
    # whichever selector form Streamlit's actual rendered markup
    # doesn't happen to match.
    for key, (accent, _rgb) in _KPI_CARD_COLORS.items():
        blocks.append(f"""
        [data-testid="stMain"] [class*="st-key-{key}"] [data-testid="stMetricValue"] {{
            color: {accent} !important;
        }}""")
    return "\n".join(blocks)


# Shared internal layout for EVERY kpi_* card (Dashboard, Settings'
# user-count cards, Audit Logs' event-type cards, Alerts' severity
# cards all reuse these same keys) - one rule set instead of per-card
# spacing hacks, per the explicit request to fix the shared mechanism.
# Streamlit's own vertical block inside a plain (non-border=True)
# st.container(key=...) is already a flex column by default; this only
# tunes its gap/min-height/typography so every card lines up - title
# top-left, a consistently-sized number under it, an optional delta
# shown inline by st.metric itself, then the description, with the
# "View details" button (when a card has one) pinned to the card's
# bottom edge via margin-top:auto rather than drifting to wherever the
# text above it happens to end.
_KPI_CARD_LAYOUT_CSS = """
[data-testid="stMain"] [class*="st-key-kpi_"] {
    padding: 22px !important;
    min-height: 190px !important;
}
[data-testid="stMain"] [class*="st-key-kpi_"] [data-testid="stVerticalBlock"] {
    gap: 0.5rem !important;
}
[data-testid="stMain"] [class*="st-key-kpi_"] [data-testid="stMetricLabel"] p {
    font-size: 13px !important;
    font-weight: 600 !important;
    line-height: 1.3 !important;
}
[data-testid="stMain"] [class*="st-key-kpi_"] [data-testid="stMetricValue"] {
    font-size: 34px !important;
    font-weight: 800 !important;
    line-height: 1.15 !important;
}
[data-testid="stMain"] [class*="st-key-kpi_"] [data-testid="stMetricDelta"] {
    font-size: 12.5px !important;
}
[data-testid="stMain"] [class*="st-key-kpi_"] [data-testid="stCaptionContainer"] p {
    font-size: 12.5px !important;
    line-height: 1.5 !important;
    margin: 0 !important;
    color: rgba(0, 0, 0, 0.70) !important;
    font-weight: 700 !important;
}
[data-testid="stMain"] [class*="st-key-kpi_"] [data-testid="stButton"] {
    margin-top: auto !important;
    padding-top: 0.4rem !important;
}
"""


def inject_global_theme():
    # Skipped entirely (not even an empty background-image: none) when
    # the file genuinely isn't there - the app just keeps its plain
    # light background from .streamlit/config.toml, no broken-image
    # icon, no error. This is the ONE place the background is set, for
    # all 8 authenticated pages (this function is called once from
    # app.py's render_app(), above _render_page()) - no per-page CSS.
    _background_css = (
        f"""
        /* =========================================================
           GLOBAL BACKGROUND - cyberguard_background.png behind every
           authenticated page's MAIN content (never the sidebar, which
           stays its own solid dark navy below, and never the login
           page - inject_global_theme() is only ever called after
           authentication, see this module's own docstring).
           Two layers in one background-image: a translucent white/
           icy-blue wash OVER the photo (keeps every card, table, chart
           and status badge just as readable as before) and the photo
           itself underneath, sized to always fully cover the viewport
           without stretching/distorting it (background-size: cover
           preserves the image's own aspect ratio, cropping instead of
           squashing). background-attachment: fixed keeps the image
           visually stable while page content scrolls.
        ========================================================= */
        [data-testid="stAppViewContainer"] {{
            background-color: #EEF6FD !important;
        }}
        /* !important on every property here, matching this file's own
           established convention everywhere else - Streamlit's base
           theme CSS (.streamlit/config.toml's backgroundColor) was
           otherwise winning the cascade and painting this element
           fully opaque white, hiding the image completely (reported:
           "why no background come out"). The wash is also lighter
           than the first attempt (0.42/0.30 instead of 0.74/0.70) so
           the photo is actually visible, not washed out to near-white
           on top of an already pale image. */
        [data-testid="stMain"] {{
            background-image:
                linear-gradient(180deg, rgba(255, 255, 255, 0.42), rgba(240, 249, 255, 0.30)),
                url("app/static/cyberguard_background.png") !important;
            background-size: cover, cover !important;
            background-position: center, center !important;
            background-repeat: no-repeat, no-repeat !important;
            background-attachment: fixed, fixed !important;
        }}
        /* Belt-and-suspenders: if Streamlit's own block-container
           (the padded wrapper directly inside stMain that every page's
           content actually sits in) also carries an opaque background
           of its own, it would sit on top of stMain's background and
           hide it just as completely - make it explicitly transparent
           so stMain's image is never covered by an invisible opaque
           layer directly behind the content. */
        [data-testid="stMainBlockContainer"],
        [data-testid="stMain"] > div {{
            background: transparent !important;
        }}
        /* iOS Safari in particular does not support a fixed background
           on a scrolling element at narrow widths - falls back to a
           normal scrolling background there instead of the image
           disappearing/glitching. */
        @media (max-width: 768px) {{
            [data-testid="stMain"] {{
                background-attachment: scroll, scroll !important;
            }}
        }}
        """
        if _BACKGROUND_IMAGE_PATH.is_file() else ""
    )

    # Same idea, scoped to the shared top_bar header only (see the
    # .st-key-top_bar rule below). The existing white/icy gradient wash
    # IS the "subtle white overlay" the header already needed for text
    # contrast - reused as the top background-image layer instead of
    # adding a second, separate overlay element, so this is still only
    # one background declaration on the existing header box, not an
    # extra layer/card/pseudo-element. Falls back to that exact same
    # gradient alone (today's look, unchanged) if the file is missing.
    _header_bg_declaration = (
        f'background-image: linear-gradient(135deg, rgba(255, 255, 255, 0.92), '
        f'rgba(224, 242, 254, 0.55)), url("app/static/cyberguard_header_background.png") !important; '
        f'background-size: cover, cover !important; '
        f'background-position: center, center !important; '
        f'background-repeat: no-repeat, no-repeat !important;'
        if _HEADER_BACKGROUND_IMAGE_PATH.is_file() else
        'background: linear-gradient(135deg, rgba(255, 255, 255, 0.92), rgba(224, 242, 254, 0.55)) !important;'
    )

    st.markdown(
        f"""
        <style>
        {_background_css}
        /* =========================================================
           SIDEBAR - dark navy/cyan glass, replacing the plain grey
           default. Scoped entirely to [data-testid="stSidebar"], so
           none of this can leak onto main-content pages or the login
           screen (which never renders a sidebar at all).
        ========================================================= */
        [data-testid="stSidebar"] {{
            background: linear-gradient(165deg, #061323 0%, #0B1728 55%, #061323 100%);
            border-right: 1px solid rgba(34, 211, 238, 0.15);
            box-shadow: 4px 0 24px rgba(0, 0, 0, 0.25);
            width: 280px !important;
            min-width: 280px !important;
            position: relative;
            overflow: hidden;
        }}
        /* Soft cyan glow along the sidebar's right edge, a second
           layer on top of the corner glow below - a thin vertical
           gradient strip, not a hard line. */
        [data-testid="stSidebar"]::after {{
            content: "";
            position: absolute;
            top: 0; right: 0; bottom: 0;
            width: 90px;
            background: linear-gradient(90deg, rgba(34, 211, 238, 0) 0%, rgba(34, 211, 238, 0.07) 100%);
            pointer-events: none;
            z-index: 0;
        }}
        [data-testid="stSidebarContent"] {{
            position: relative;
            z-index: 1;
            padding: 1.1rem 1.3rem !important;
        }}
        [data-testid="stSidebarContent"]::before {{
            content: "";
            position: absolute;
            top: -80px;
            right: -100px;
            width: 260px;
            height: 260px;
            background: radial-gradient(circle, rgba(34, 211, 238, 0.16) 0%, rgba(34, 211, 238, 0) 70%);
            pointer-events: none;
            z-index: -1;
        }}
        /* Decorative network/particle layer (utils/illustrations.py's
           sidebar_network_bg, rendered once from app.py as the FIRST
           thing inside `with st.sidebar:`) - position:absolute takes
           it out of document flow entirely, so where it sits in the
           DOM doesn't matter, only this positioning does. Clipped to
           the sidebar's own bounds (overflow:hidden on the sidebar
           itself, set below) so it can never bleed into main content,
           and pointer-events:none so it can never intercept a click. */
        .sidebar-network-bg {{
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            z-index: -1;
            pointer-events: none;
        }}
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] span,
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] div {{
            color: {_MUTED_ON_DARK};
        }}
        [data-testid="stSidebar"] hr {{
            border-color: rgba(148, 163, 184, 0.18);
            margin: 0.5rem 0 !important;
        }}

        .st-key-sidebar_brand {{
            padding: 0.4rem 0 0.9rem 0;
        }}
        .sidebar-brand {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .sidebar-brand svg {{
            width: 52px;
            height: 52px;
            flex-shrink: 0;
        }}
        .sidebar-brand-text {{
            display: flex;
            flex-direction: column;
            gap: 0.15rem;
            min-width: 0;
        }}
        .sidebar-wordmark {{
            font-size: 1.3rem;
            font-weight: 800;
            letter-spacing: 0.01em;
            color: #FFFFFF;
            line-height: 1.1;
        }}
        .sidebar-tagline {{
            font-size: 0.66rem;
            font-weight: 600;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            color: {_MUTED_LIGHT};
            margin: 0;
        }}

        .st-key-sidebar_user_card {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 12px;
            padding: 0.85rem 1.1rem;
            margin-bottom: 0.75rem;
        }}
        .sidebar-identity {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .sidebar-avatar {{
            flex: 0 0 auto;
            width: 38px;
            height: 38px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, rgba(34, 211, 238, 0.22), rgba(14, 165, 233, 0.12));
            border: 1px solid rgba(34, 211, 238, 0.45);
            color: {_CYAN};
            font-weight: 700;
            font-size: 0.95rem;
        }}
        .sidebar-identity-text {{
            display: flex;
            flex-direction: column;
            min-width: 0;
            flex: 1 1 auto;
        }}
        .sidebar-identity-name {{
            color: #FFFFFF;
            font-weight: 700;
            font-size: 0.88rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .sidebar-identity-role {{
            color: {_MUTED_LIGHT};
            font-size: 0.75rem;
        }}
        .sidebar-chevron {{
            flex: 0 0 auto;
            color: {_MUTED_LIGHT};
            font-size: 1.1rem;
            line-height: 1;
            margin-left: 0.5rem;
        }}

        /* =========================================================
           Global Cyber Time Navigator - sidebar (utils/time_navigator
           .py's render_sidebar_navigator()). Minimalist: the same
           subtle translucent-white-on-navy card convention this
           sidebar already uses for sidebar_user_card, a small gradient
           badge for personality, one compact dropdown instead of a
           row of pills (no room for those here), Custom/Reset below.
        ========================================================= */
        [data-testid="stSidebar"] .st-key-sidebar_time_navigator,
        [data-testid="stSidebar"] .st-key-sidebar_time_navigator [data-testid="stElementContainer"],
        [data-testid="stSidebar"] .st-key-sidebar_time_navigator [data-testid="stHorizontalBlock"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }}
        [data-testid="stSidebar"] .st-key-sidebar_time_navigator {{
            background: rgba(255, 255, 255, 0.05) !important;
            border: 1px solid rgba(34, 211, 238, 0.22) !important;
            border-radius: 12px !important;
            padding: 0.6rem 0.75rem !important;
            margin-top: -0.3rem !important;
            margin-bottom: 0.4rem !important;
        }}
        [data-testid="stSidebar"] .sbn-title {{
            font-size: 0.72rem;
            font-weight: 800;
            letter-spacing: 0.06em;
            color: #67E8F9;
            margin: 0;
        }}
        [data-testid="stSidebar"] .sbn-badge {{
            display: block;
            text-align: center;
            font-size: 0.7rem;
            font-weight: 800;
            color: #FFFFFF;
            background: linear-gradient(135deg, #22D3EE, #0EA5E9 55%, #8B5CF6);
            border-radius: 999px;
            padding: 0.3rem 0.5rem;
            margin: 0.45rem 0 0.55rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        [data-testid="stSidebar"] .st-key-sidebar_time_navigator [data-testid="stSelectbox"] > div,
        [data-testid="stSidebar"] .st-key-sidebar_time_navigator [data-testid="stDateInputField"] {{
            background: rgba(255, 255, 255, 0.07) !important;
            border-radius: 8px !important;
        }}
        [data-testid="stSidebar"] .st-key-sidebar_time_navigator [data-testid="stSelectbox"] label,
        [data-testid="stSidebar"] .st-key-sidebar_time_navigator [data-testid="stWidgetLabel"] p {{
            color: {_MUTED_LIGHT} !important;
        }}
        [data-testid="stSidebar"] .st-key-cyber_time_custom_toggle button,
        [data-testid="stSidebar"] .st-key-cyber_time_reset_btn button {{
            border-radius: 999px !important;
            font-size: 0.76rem !important;
            min-height: 2rem !important;
            padding: 0.25rem 0.4rem !important;
            border: 1px solid rgba(139, 92, 246, 0.35) !important;
            color: #C4B5FD !important;
            background: rgba(139, 92, 246, 0.12) !important;
        }}
        [data-testid="stSidebar"] .st-key-cyber_time_custom_toggle button:hover,
        [data-testid="stSidebar"] .st-key-cyber_time_reset_btn button:hover {{
            background: rgba(139, 92, 246, 0.24) !important;
            border-color: #8B5CF6 !important;
        }}
        [data-testid="stSidebar"] .st-key-ctn_custom_panel,
        [data-testid="stSidebar"] .st-key-ctn_custom_panel [data-testid="stLayoutWrapper"] {{
            background: rgba(14, 165, 233, 0.08) !important;
            border: 1px solid rgba(14, 165, 233, 0.25) !important;
            border-radius: 10px !important;
            margin-top: 0.5rem !important;
            padding: 0.5rem 0.6rem !important;
        }}

        .st-key-sidebar_nav [data-testid="stRadioOption"] {{
            border-radius: 12px;
            padding: 0.5rem 0.85rem;
            margin-bottom: 0.18rem;
            transition: background-color 0.15s ease, transform 0.15s ease;
        }}
        .st-key-sidebar_nav [data-testid="stRadioOption"]:hover {{
            background: rgba(34, 211, 238, 0.08);
        }}
        .st-key-sidebar_nav [data-testid="stRadioOption"] p {{
            color: {_MUTED_LIGHT};
            font-weight: 600;
            font-size: 0.92rem;
        }}
        .st-key-sidebar_nav [data-testid="stRadioOption"] svg {{
            color: {_MUTED_LIGHT};
            width: 20px;
            height: 20px;
        }}
        /* The active item - a filled cyan-to-blue gradient pill with a
           glow, matching the reference's Dashboard button, not just a
           left-border accent. */
        .st-key-sidebar_nav [data-testid="stRadioOption"]:has(input:checked) {{
            background: linear-gradient(90deg, {_CYAN}, {_BLUE}) !important;
            border: 1px solid rgba(34, 211, 238, 0.55);
            box-shadow: 0 0 18px rgba(34, 211, 238, 0.35), 0 4px 14px rgba(14, 165, 233, 0.28);
        }}
        .st-key-sidebar_nav [data-testid="stRadioOption"]:has(input:checked) p {{
            color: #FFFFFF;
            font-weight: 700;
        }}
        .st-key-sidebar_nav [data-testid="stRadioOption"]:has(input:checked) svg {{
            color: #FFFFFF;
        }}

        .st-key-logout_btn {{
            margin-top: 0.75rem;
        }}
        .st-key-logout_btn button {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(148, 163, 184, 0.25);
            color: {_MUTED_ON_DARK};
            border-radius: 12px;
            font-weight: 600;
        }}
        .st-key-logout_btn button:hover {{
            border-color: {_CYAN};
            color: #FFFFFF;
            background: rgba(34, 211, 238, 0.08);
            box-shadow: 0 0 14px rgba(34, 211, 238, 0.22);
        }}

        /* =========================================================
           TOP BAR - the single header row rendered once from app.py
           via utils/page_ui.py's render_top_bar(), above the routed
           page content. Every piece in it reflects real state (DB
           connectivity, the current user's own alert count, and for
           Alerts & Incidents its own real NEW+INVESTIGATING count) -
           see that function's own docstring. NOT border=True, so
           there is no inner stLayoutWrapper here - styling the outer
           .st-key-top_bar class directly is correct.

           The icon + title + subtitle block (.topbar-page and its
           children) is ONE plain HTML element built by
           utils/page_ui.py's _topbar_identity_html() - not a second
           nested Streamlit container. A border=True container's box
           is sized by Streamlit's own column/content layout, which
           does not reliably hold to an exact pixel square; that
           mismatch is what produced the earlier "tall, narrow icon
           box" bug. Plain HTML + flexbox has no such ambiguity.
        ========================================================= */
        [data-testid="stMain"] .st-key-top_bar {{
            {_header_bg_declaration}
            border: 1px solid rgba(14, 165, 233, 0.20) !important;
            border-radius: 14px !important;
            box-shadow: 0 4px 18px rgba(14, 165, 233, 0.08) !important;
            padding: 0.55rem 1rem !important;
            margin-bottom: 0.7rem !important;
        }}
        .topbar-page {{
            display: flex;
            align-items: center;
            gap: 0.55rem;
            min-width: 0;
        }}
        .topbar-page-icon {{
            flex: 0 0 auto;
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .topbar-page-icon svg {{
            width: 18px;
            height: 18px;
            display: block;
        }}
        .topbar-page-text {{
            display: flex;
            flex-direction: column;
            gap: 0.05rem;
            min-width: 0;
        }}
        .topbar-title {{
            font-size: 1.08rem;
            font-weight: 700;
            color: {_SLATE_TEXT};
            line-height: 1.15;
            margin: 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .topbar-subtitle {{
            font-size: 0.72rem;
            font-weight: 500;
            color: {_SLATE_MUTED};
            line-height: 1.2;
            margin: 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .top-bar-status {{
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.3rem 0.65rem;
            border-radius: 999px;
            white-space: nowrap;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .top-bar-status-dot {{
            width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto;
        }}
        .top-bar-status-ok {{
            color: #15803D;
            background: rgba(34, 197, 94, 0.14);
            border: 1px solid rgba(34, 197, 94, 0.30);
        }}
        .top-bar-status-ok .top-bar-status-dot {{
            background: {_GREEN};
            box-shadow: 0 0 6px {_GREEN};
        }}
        .top-bar-status-bad {{
            color: #B91C1C;
            background: rgba(220, 38, 38, 0.12);
            border: 1px solid rgba(220, 38, 38, 0.30);
        }}
        .top-bar-status-bad .top-bar-status-dot {{
            background: {_RED};
            box-shadow: 0 0 6px {_RED};
        }}
        [data-testid="stMain"] .st-key-top_bar [data-testid="stPopover"] button {{
            border: 1px solid rgba(14, 165, 233, 0.30) !important;
            color: {_SLATE_TEXT} !important;
            border-radius: 999px !important;
            background: rgba(255, 255, 255, 0.7) !important;
            min-height: 32px !important;
            font-size: 0.82rem !important;
            padding: 0.25rem 0.7rem !important;
        }}
        [data-testid="stMain"] .st-key-top_bar [data-testid="stPopover"] button:hover {{
            border-color: {_CYAN} !important;
            box-shadow: 0 0 10px rgba(34, 211, 238, 0.20);
        }}
        [data-testid="stMain"] .st-key-top_bar [data-testid="stTextInputRootElement"] {{
            min-height: 32px !important;
        }}
        [data-testid="stMain"] .st-key-top_bar [data-testid="stTextInput"] input {{
            font-size: 0.82rem !important;
            padding-top: 0.3rem !important;
            padding-bottom: 0.3rem !important;
        }}

        /* =========================================================
           GLOBAL CYBER TIME NAVIGATOR - the header's second row,
           rendered from utils/time_navigator.py INSIDE the same
           .st-key-top_bar container row 1 renders into (see that
           module's own docstring) - a thin divider separates the two
           rows, but there is only ever ONE outer header box, never a
           second independent header card.
        ========================================================= */
        .ctn-divider {{
            height: 1px;
            margin: 0.4rem 0 0.35rem;
            background: linear-gradient(90deg, rgba(14, 165, 233, 0.03),
                rgba(14, 165, 233, 0.35), rgba(139, 92, 246, 0.25), rgba(14, 165, 233, 0.03));
        }}
        /* The collapsible bar itself - a vivid cyan/sky-to-violet wash
           (not a flat/plain white strip) with a thin cyan border, so it
           reads as its own distinct, colourful control rather than
           blending into the rest of the header. Rounded corners +
           glow-shadow on both the collapsed slim bar and the taller
           expanded panel. */
        [data-testid="stMain"] .st-key-cyber_time_navigator_row,
        [data-testid="stMain"] .st-key-cyber_time_navigator_row_expanded {{
            background: linear-gradient(120deg, rgba(34, 211, 238, 0.16) 0%,
                rgba(14, 165, 233, 0.12) 45%, rgba(139, 92, 246, 0.14) 100%) !important;
            border: 1.5px solid rgba(14, 165, 233, 0.45) !important;
            border-radius: 12px !important;
            box-shadow: 0 4px 16px rgba(14, 165, 233, 0.16) !important;
            padding: 0.4rem 0.7rem !important;
        }}
        @keyframes ai-panel-fade-in {{
            from {{ opacity: 0; transform: translateY(-4px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        [data-testid="stMain"] .st-key-cyber_time_navigator_row_expanded {{
            animation: ai-panel-fade-in 0.18s ease-out;
        }}
        @media (prefers-reduced-motion: reduce) {{
            [data-testid="stMain"] .st-key-cyber_time_navigator_row_expanded {{
                animation: none !important;
            }}
        }}
        /* Every element INSIDE the navigator card that is itself a
           keyed st.container() (the pills row, the custom-toggle/reset
           button wrappers) was picking up Streamlit's own default
           bordered-card paint as an unwanted SECOND box nested inside
           this one's border - reported from a screenshot showing 3
           stacked boxes. Only ONE of these (ctn_custom_panel, the
           date-picker sub-panel) is MEANT to look like its own inset
           card; every other keyed container in here is reset flat. */
        [data-testid="stMain"] .st-key-cyber_time_navigator_row_expanded [data-testid="stElementContainer"],
        [data-testid="stMain"] .st-key-cyber_time_navigator_row_expanded [data-testid="stHorizontalBlock"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-cyber_time_navigator_row_expanded {{
            border-color: rgba(139, 92, 246, 0.55) !important;
            box-shadow: 0 6px 22px rgba(139, 92, 246, 0.18) !important;
        }}
        /* Title: plain block-level markdown (see time_navigator.py's
           own comment on why this is deliberately NOT a styled
           st.button) - bold, colourful gradient text, left-aligned by
           default since it's just a normal <div>, flush with the
           badge/subtitle line below it and close to the robot image
           beside it, with none of a button's own internal padding to
           cause a mismatched left edge or unwanted centring. */
        .ctn-title {{
            font-size: 0.95rem;
            font-weight: 800;
            letter-spacing: 0.02em;
            line-height: 1.15;
            margin: 0;
            background-image: linear-gradient(90deg, #0369A1, #7C3AED);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .ctn-collapsed-sub {{
            font-size: 0.72rem;
            font-weight: 600;
            color: {_SLATE_MUTED};
            margin: 0.1rem 0 0 !important;
        }}
        .ctn-range-badge {{
            display: inline-block;
            font-size: 0.74rem;
            font-weight: 800;
            color: #FFFFFF;
            background: linear-gradient(135deg, #22D3EE, #0EA5E9 55%, #8B5CF6);
            border-radius: 999px;
            padding: 0.2rem 0.65rem;
            white-space: nowrap;
        }}
        /* Compact cell (utils/time_navigator.py's
           render_time_navigator_compact()) - sits side by side with
           the identity/search/status/bell/account cells in the SAME
           header row, so it gets the same small-pill treatment those
           neighbours already have, rather than its own separate boxed
           panel. */
        [data-testid="stMain"] .st-key-ctn_compact_cell [data-testid="stImage"] img {{
            border-radius: 50%;
        }}
        .ctn-compact-badge {{
            display: inline-block;
            font-size: 0.68rem;
            font-weight: 800;
            color: #FFFFFF;
            background: linear-gradient(135deg, #22D3EE, #0EA5E9 55%, #8B5CF6);
            border-radius: 999px;
            padding: 0.3rem 0.6rem;
            white-space: nowrap;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        /* Chevron toggle: a round, colourful accent button pinned to
           the bar's right edge. */
        [data-testid="stMain"] .st-key-ctn_toggle_chevron button {{
            border-radius: 50% !important;
            width: 2rem !important;
            height: 2rem !important;
            min-height: 2rem !important;
            padding: 0 !important;
            border: 1.5px solid rgba(139, 92, 246, 0.45) !important;
            background: linear-gradient(135deg, rgba(34, 211, 238, 0.20), rgba(139, 92, 246, 0.20)) !important;
            color: #6D28D9 !important;
        }}
        [data-testid="stMain"] .st-key-ctn_toggle_chevron button:hover {{
            background: linear-gradient(135deg, rgba(34, 211, 238, 0.35), rgba(139, 92, 246, 0.35)) !important;
            box-shadow: 0 0 12px rgba(139, 92, 246, 0.35);
        }}
        .ctn-expanded-divider {{
            height: 1px;
            margin: 0.5rem 0 0.4rem;
            background: rgba(139, 92, 246, 0.25);
        }}
        [data-testid="stMain"] .st-key-ctn_pills_row {{
            margin-top: 0.1rem !important;
            row-gap: 0.35rem !important;
        }}
        /* Segmented-control pills: rounded, cyan hover glow, compact
           height/padding (Streamlit's own default button sizing is
           noticeably taller than this toolbar needs). The selected
           pill's bright-cyan fill already comes from .streamlit/
           config.toml's primaryColor (#0EA5E9) - Streamlit's own
           native selected-state styling for this widget - so only
           shape/hover/size is added here, not a second colour system. */
        [data-testid="stMain"] .st-key-ctn_pills_row [data-testid="stSegmentedControl"] button,
        [data-testid="stMain"] .st-key-ctn_custom_toggle_wrap button,
        [data-testid="stMain"] .st-key-cyber_time_reset_btn button {{
            border-radius: 999px !important;
            font-weight: 600 !important;
            font-size: 0.8rem !important;
            min-height: 2rem !important;
            padding: 0.25rem 0.7rem !important;
        }}
        [data-testid="stMain"] .st-key-ctn_pills_row [data-testid="stSegmentedControl"] button:hover {{
            box-shadow: 0 0 10px rgba(34, 211, 238, 0.30);
        }}
        [data-testid="stMain"] .st-key-ctn_custom_toggle_wrap button,
        [data-testid="stMain"] .st-key-cyber_time_reset_btn button {{
            border: 1px solid rgba(139, 92, 246, 0.40) !important;
            color: #6D28D9 !important;
            background: rgba(139, 92, 246, 0.08) !important;
        }}
        [data-testid="stMain"] .st-key-ctn_custom_toggle_wrap button:hover,
        [data-testid="stMain"] .st-key-cyber_time_reset_btn button:hover {{
            background: rgba(139, 92, 246, 0.18) !important;
            border-color: #8B5CF6 !important;
        }}
        [data-testid="stMain"] .st-key-ctn_custom_panel,
        [data-testid="stMain"] .st-key-ctn_custom_panel [data-testid="stLayoutWrapper"] {{
            background: rgba(14, 165, 233, 0.06) !important;
            border: 1px solid rgba(14, 165, 233, 0.22) !important;
            border-radius: 10px !important;
            margin-top: 0.3rem !important;
            padding: 0.4rem 0.6rem !important;
        }}
        [data-testid="stMain"] .st-key-ctn_custom_panel [data-testid="stDateInputField"],
        [data-testid="stMain"] .st-key-ctn_custom_panel button {{
            min-height: 2.1rem !important;
        }}
        @media (max-width: 900px) {{
            [data-testid="stMain"] .st-key-ctn_pills_row {{
                overflow-x: auto !important;
                flex-wrap: nowrap !important;
            }}
        }}

        /* =========================================================
           MAIN CONTENT - consistent cards/headers/inputs/tables
           across every page. Scoped to [data-testid="stMain"] only.
        ========================================================= */

        /* Type scale: st.header()/st.title() (h1/h2, used once per
           page for the page's own title) get the heavier bordered
           treatment already proven here; st.subheader() (h3, used for
           EVERY section heading - "Model Evaluation", "Recent
           Threats", "Detections by Day", etc. across every page) had
           no rule at all until now and fell back to the browser's
           bare default - the single biggest unstyled, "plain-looking"
           gap in the app's type scale. */
        [data-testid="stMain"] [data-testid="stHeading"] h1,
        [data-testid="stMain"] [data-testid="stHeading"] h2 {{
            font-size: 1.85rem;
            font-weight: 700;
            letter-spacing: -0.01em;
            color: {_SLATE_TEXT};
            padding-bottom: 0.4rem;
            border-bottom: 2px solid rgba(14, 165, 233, 0.25);
        }}
        [data-testid="stMain"] [data-testid="stHeading"] h3 {{
            font-size: 1.3rem;
            font-weight: 650;
            letter-spacing: -0.005em;
            color: {_SECTION_HEADING};
            margin-top: 0.2rem;
            margin-bottom: 0.1rem;
        }}
        [data-testid="stMain"] [data-testid="stHeadingIconWrapper"] svg {{
            color: {_BLUE};
        }}
        /* Global text-contrast pass: every one of these was previously
           either unstyled (inheriting whatever a nested gradient card
           happened to leave it at) or coloured but not weighted, which
           together is what made captions/labels/body copy read as
           faded across every page - never fixed card-by-card, fixed
           once here so it applies everywhere at once. */
        [data-testid="stMain"] [data-testid="stCaptionContainer"] p {{
            font-size: 0.82rem;
            font-weight: 500;
            line-height: 1.5;
            color: {_CAPTION_TEXT} !important;
        }}
        [data-testid="stMain"] [data-testid="stMarkdownContainer"] p,
        [data-testid="stMain"] [data-testid="stMarkdownContainer"] li {{
            font-weight: 480;
            line-height: 1.55;
            color: {_BODY_TEXT};
        }}
        /* Page-intro description line (utils/illustrations.py's
           render_intro_banner(), used by every page below the global
           header) - a dedicated class instead of st.caption(), since
           relying on the generic caption rule above still read as too
           pale/thin at the top of a page. */
        [data-testid="stMain"] .page-intro-text {{
            color: #334155 !important;
            font-weight: 600 !important;
            font-size: 0.92rem !important;
            line-height: 1.5;
            margin: 0;
        }}
        /* Intro card's small circular status badge (utils/illustrations
           .py's render_intro_banner()) - a soft colour wash in the
           page's OWN accent colour (set dynamically per call, see that
           function) with a gentle pulsing ring, giving each of the 5
           pages that use this card a distinct, "live" identity instead
           of one flat generic strip for all five. */
        [data-testid="stMain"] .page-intro-badge-wrap {{
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 0.2rem;
        }}
        [data-testid="stMain"] .page-intro-badge {{
            display: flex;
            align-items: center;
            justify-content: center;
            width: 56px;
            height: 56px;
            border-radius: 50%;
            border: 2px solid;
            flex: 0 0 auto;
            animation: ai-badge-pulse-ring 2.6s ease-out infinite;
        }}
        [data-testid="stMain"] .page-intro-badge svg {{
            width: 28px;
            height: 28px;
        }}
        @keyframes ai-badge-pulse-ring {{
            0% {{ box-shadow: 0 0 0 0 rgba(14, 165, 233, 0.30); }}
            70% {{ box-shadow: 0 0 0 8px rgba(14, 165, 233, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(14, 165, 233, 0); }}
        }}
        @media (prefers-reduced-motion: reduce) {{
            [data-testid="stMain"] .page-intro-badge {{
                animation: none !important;
            }}
        }}
        /* Compliance framework cards (utils/compliance_ui.py) - one
           self-contained inline-styled HTML block per card, not a
           st.container(key=...) + external CSS override (that
           approach never painted a visible colour for these cards in
           this installed Streamlit version - see that module's own
           docstring). Only structural/typographic rules live here;
           every colour is inline per-card since it depends on that
           framework's real status. */
        .compliance-card {{
            border-radius: 14px;
            padding: 16px 18px;
            margin-bottom: 14px;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.06);
        }}
        .compliance-card-head {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }}
        .compliance-card-icon {{
            flex: 0 0 auto;
            display: inline-flex;
        }}
        .compliance-card-title {{
            font-size: 0.98rem;
            font-weight: 700;
            color: {_SLATE_TEXT};
        }}
        .compliance-card-badge {{
            display: inline-block;
            padding: 0.25rem 0.7rem;
            border-radius: 999px;
            font-size: 0.72rem;
            font-weight: 800;
            letter-spacing: 0.02em;
            margin-bottom: 0.65rem;
        }}
        .compliance-card-metrics {{
            display: flex;
            flex-direction: column;
            gap: 0.2rem;
            font-size: 0.85rem;
            font-weight: 600;
            color: {_SLATE_TEXT};
            margin-bottom: 0.4rem;
        }}
        .compliance-card-note {{
            font-size: 0.78rem;
            font-weight: 500;
            color: #475569;
            margin: 0.15rem 0;
        }}
        [data-testid="stMain"] [data-testid="stWidgetLabel"] p {{
            font-size: 0.85rem;
            font-weight: 600;
            color: {_BODY_TEXT};
        }}
        [data-testid="stMain"] [data-testid="stWidgetLabel"][disabled] p {{
            color: {_PLACEHOLDER_TEXT};
        }}
        /* Native <input>/<textarea> text - explicit colour AND
           -webkit-text-fill-color, because WebKit/Chromium apply their
           own low-contrast text colour to disabled/read-only form
           controls via the user-agent stylesheet, which a plain
           `color` rule alone does not always override. This is what
           made every disabled "read-only" field across Settings, My
           Account, and Audit Logs' account filter look washed out. */
        [data-testid="stMain"] input,
        [data-testid="stMain"] textarea {{
            color: {_INPUT_TEXT} !important;
            -webkit-text-fill-color: {_INPUT_TEXT} !important;
            opacity: 1 !important;
            font-weight: 500 !important;
        }}
        [data-testid="stMain"] input:disabled,
        [data-testid="stMain"] textarea:disabled {{
            color: {_PLACEHOLDER_TEXT} !important;
            -webkit-text-fill-color: {_PLACEHOLDER_TEXT} !important;
            opacity: 1 !important;
        }}
        [data-testid="stMain"] input::placeholder,
        [data-testid="stMain"] textarea::placeholder {{
            color: {_PLACEHOLDER_TEXT} !important;
            opacity: 1 !important;
        }}
        /* Markdown links (st.markdown's [text](url) syntax) - never
           styled before, so any link fell back to the browser's
           default blue, inconsistent with the rest of this palette. */
        [data-testid="stMain"] [data-testid="stMarkdownContainer"] a {{
            color: {_LINK_TEXT};
            font-weight: 600;
            text-decoration: underline;
            text-underline-offset: 2px;
        }}
        [data-testid="stMain"] [data-testid="stMarkdownContainer"] a:hover {{
            color: {_BLUE_DARK};
        }}
        [data-testid="stMain"] [data-baseweb="select"] > div {{
            color: {_INPUT_TEXT} !important;
            font-weight: 500 !important;
        }}
        /* Metric value/label outside the KPI card system (e.g. Alerts'
           per-incident risk-score/confidence metrics, Settings' user
           summary cards) - the KPI-prefixed cards already set their
           own weight/size via _KPI_CARD_LAYOUT_CSS above; this covers
           every other st.metric() on the site. */
        [data-testid="stMain"] [data-testid="stMetricValue"] {{
            font-weight: 700;
        }}
        [data-testid="stMain"] [data-testid="stMetricLabel"] p {{
            font-weight: 600;
        }}

        /* =========================================================
           DASHBOARD WELCOME HEADER - its own card (dashboard_welcome_
           card, not the shared page_header_card every other page
           uses), deliberately bigger and more colorful than a normal
           page header per explicit request - a bold 3-colour top
           stripe, gradient-text heading, and pill-shaped status/date
           chips instead of plain inline text.
        ========================================================= */
        [data-testid="stMain"] .st-key-dashboard_welcome_card {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-dashboard_welcome_card.st-key-dashboard_welcome_card {{
            background: linear-gradient(120deg,
                rgba(219, 234, 254, 0.92) 0%,
                rgba(207, 250, 254, 0.88) 45%,
                rgba(237, 233, 254, 0.88) 100%) !important;
            border: 1px solid rgba(14, 165, 233, 0.30) !important;
            border-radius: 20px !important;
            box-shadow: 0 10px 30px rgba(14, 165, 233, 0.16) !important;
            padding: 2rem 2.25rem !important;
            position: relative !important;
            overflow: hidden !important;
        }}
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stLayoutWrapper"]::before,
        [data-testid="stMain"] .st-key-dashboard_welcome_card.st-key-dashboard_welcome_card::before {{
            content: "";
            position: absolute; top: 0; left: 0; right: 0; height: 5px;
            background: linear-gradient(90deg, #0EA5E9, #22D3EE, #8B5CF6);
        }}
        /* The rule above is a plain descendant selector - it matches
           ANY [data-testid="stLayoutWrapper"] anywhere inside this
           card, not just its own outer box. The nested
           st.columns(..., vertical_alignment="center") just below
           (text_col/art_col) generates its OWN such element to
           implement the vertical centering, which was ALSO getting
           the full card look (background/border/shadow/top-stripe)
           painted onto it - a second, visibly nested card. This reset
           (placed after, so it wins ties) strips that back to nothing
           for anything living inside a stHorizontalBlock (a columns
           row) in this card - the row itself is layout only, never a
           card of its own. */
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stHorizontalBlock"],
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stHorizontalBlock"] [data-testid="stLayoutWrapper"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0 !important;
        }}
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stHorizontalBlock"]::before,
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stHorizontalBlock"] [data-testid="stLayoutWrapper"]::before {{
            content: none !important;
        }}
        /* The actual "double box" reported here: st.columns() doesn't
           just produce a stHorizontalBlock - Streamlit wraps THAT row
           in its OWN stLayoutWrapper too, as the row's PARENT, not a
           child/descendant of stHorizontalBlock. The reset just above
           only catches stLayoutWrappers NESTED INSIDE stHorizontalBlock
           (per-column ones) - it can never match a wrapper that
           CONTAINS stHorizontalBlock as its own direct child, so that
           wrapper still matched the broad card-paint rule above and
           rendered a second, visibly inset card behind the first.
           :has(> ...) targets exactly that one wrapper (a stLayoutWrapper
           whose direct child is the row) without touching the real
           outer card, which contains stHorizontalBlock only as a much
           deeper descendant, never a direct child. */
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stLayoutWrapper"]:has(> [data-testid="stHorizontalBlock"]) {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0 !important;
        }}
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stLayoutWrapper"]:has(> [data-testid="stHorizontalBlock"])::before {{
            content: none !important;
        }}
        /* Same bug, different child (same family already fixed for
           Detection Engine's stage list and the premium banners): each
           individual element's own per-slot wrapper (stElementContainer)
           was ALSO matching the broad card-paint rule above, producing
           a visible second box behind the real content - this is what
           the screenshot showed. Resetting it is safe here for the
           same reason as everywhere else it's used: it only ever wraps
           ONE individual element, never the outer card's own border. */
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stElementContainer"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-dashboard_welcome_card [data-testid="stHeading"] h1 {{
            font-size: 2.1rem !important;
            font-weight: 800 !important;
            border-bottom: none !important;
            padding-bottom: 0 !important;
            margin-bottom: 0.3rem !important;
            background: linear-gradient(135deg, #0F172A, #0369A1);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .dw-subtitle {{
            color: #475569;
            font-weight: 500;
            font-size: 1.02rem;
            margin: 0;
        }}
        .dw-label {{
            color: {_SLATE_MUTED};
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.07em;
            margin-bottom: 0.45rem;
        }}
        .dw-status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1.05rem;
            border-radius: 999px;
            font-weight: 700;
            font-size: 0.95rem;
        }}
        .dw-status-dot {{
            width: 10px; height: 10px; border-radius: 50%; flex: 0 0 auto;
        }}
        .dw-status-ok {{
            background: rgba(34, 197, 94, 0.14);
            color: #16A34A;
            border: 1px solid rgba(34, 197, 94, 0.32);
        }}
        .dw-status-ok .dw-status-dot {{ background: #16A34A; box-shadow: 0 0 8px #16A34A; }}
        .dw-status-bad {{
            background: rgba(220, 38, 38, 0.14);
            color: #DC2626;
            border: 1px solid rgba(220, 38, 38, 0.32);
        }}
        .dw-status-bad .dw-status-dot {{ background: #DC2626; box-shadow: 0 0 8px #DC2626; }}
        .dw-date-chip {{
            display: inline-block;
            padding: 0.5rem 1.05rem;
            border-radius: 999px;
            background: rgba(139, 92, 246, 0.10);
            border: 1px solid rgba(139, 92, 246, 0.28);
            color: #6D28D9;
            font-weight: 600;
            font-size: 0.9rem;
            white-space: nowrap;
        }}
        .dw-greeting-small {{
            font-size: 1.05rem;
            font-weight: 600;
            color: #475569;
            margin: 0;
        }}
        .dw-greeting-big {{
            font-size: 2.3rem;
            font-weight: 800;
            line-height: 1.15;
            margin: 0 0 0.5rem 0;
            background: linear-gradient(100deg, #0EA5E9, #22D3EE 45%, #8B5CF6 85%);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .dw-quote-card {{
            margin-top: 0.9rem;
            padding: 0.85rem 1.1rem;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.55);
            border: 1px solid rgba(139, 92, 246, 0.22);
            color: #475569;
            font-style: italic;
            font-size: 0.85rem;
            text-align: center;
        }}
        /* The robot illustration (st.image, left-aligned by default) sat
           flush to the left of its column with a lot of empty space to
           its right, next to the already-centered quote card below it -
           this centers the image itself (and keeps the quote card
           centered) so the whole art column reads as one centered
           column instead of a left-aligned image over a centered box. */
        [data-testid="stMain"] .st-key-dashboard_hero_art {{
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        [data-testid="stMain"] .st-key-dashboard_hero_art [data-testid="stImage"] {{
            display: flex;
            justify-content: center;
            width: 100%;
        }}
        /* Both the whole row (dashboard_quick_actions_row) and each
           individual button's own wrapper (dash_action_*) are reset to
           fully flat/borderless here, on BOTH the class itself and its
           possible [data-testid="stLayoutWrapper"] descendant (same
           dual-selector defence used elsewhere in this file) - this is
           what actually removes the extra "row box" nested inside the
           welcome card, regardless of which DOM node the generic
           default card styling (see the bare stLayoutWrapper rule
           above) ends up landing on. Each button's own accent-coloured
           border (set directly on the <button> element by
           dashboard.py) is the only remaining outline - one level, not
           a card inside a card. */
        [data-testid="stMain"] .st-key-dashboard_quick_actions_row,
        [data-testid="stMain"] .st-key-dashboard_quick_actions_row [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-dashboard_quick_actions_row.st-key-dashboard_quick_actions_row,
        [data-testid="stMain"] [class*="st-key-dash_action_"],
        [data-testid="stMain"] [class*="st-key-dash_action_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-dash_action_"][class*="st-key-dash_action_"] {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
            padding: 0 !important;
        }}
        /* The gradient top-stripe is a SEPARATE ::before pseudo-element
           (see dashboard_welcome_card's own ::before above) - resetting
           border/background/box-shadow above does not remove it, since
           its content/background are set independently. This is what
           was still showing as a lone floating stripe above the button
           row after the border/shadow/background reset above landed. */
        [data-testid="stMain"] .st-key-dashboard_quick_actions_row::before,
        [data-testid="stMain"] .st-key-dashboard_quick_actions_row [data-testid="stLayoutWrapper"]::before,
        [data-testid="stMain"] [class*="st-key-dash_action_"]::before,
        [data-testid="stMain"] [class*="st-key-dash_action_"] [data-testid="stLayoutWrapper"]::before {{
            content: none !important;
        }}
        [data-testid="stMain"] .st-key-dashboard_quick_actions_row {{
            margin-top: 0.6rem !important;
        }}
        [data-testid="stMain"] [class*="st-key-dash_action_"] [data-testid="stButton"] button {{
            border-radius: 10px !important;
            font-weight: 600 !important;
        }}
        /* Shared "premium banner" wrapper (utils/illustrations.py's
           render_premium_banner(), used by Dashboard's "Stay Secure.
           Stay Ahead." and every other feature page's own banner) -
           the Streamlit container itself stays fully transparent/
           borderless; every visible pixel of the banner (gradient
           glass panel, border, shadow, glows) lives on the ONE HTML
           <div class="cgb-banner"> that function renders, never on a
           Streamlit-generated wrapper - which is what guarantees there
           is only ever ONE visible box, not two (a previous
           st.columns()-based layout repeatedly let a nested row pick
           up this app's own default card paint as an unwanted second
           box, reported twice; removing the columns removes that
           failure mode at the root). Matched by SUBSTRING
           ("_premium_banner" key suffix - see each page's own call)
           so every page's own uniquely-keyed container gets this reset
           without a new copy of this rule per page. */
        [data-testid="stMain"] [class*="_premium_banner"],
        [data-testid="stMain"] [class*="_premium_banner"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="_premium_banner"] [data-testid="stElementContainer"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0 !important;
        }}
        .cgb-banner {{
            position: relative;
            display: flex;
            align-items: center;
            gap: 1.75rem;
            overflow: hidden;
            border-radius: 28px;
            padding: 1.9rem 2.4rem;
            min-height: 280px;
            background: linear-gradient(135deg, rgba(219, 234, 254, 0.75) 0%,
                rgba(240, 249, 255, 0.85) 45%, rgba(237, 233, 254, 0.80) 100%);
            border: 1px solid rgba(255, 255, 255, 0.65);
            box-shadow: 0 10px 40px rgba(59, 130, 246, 0.14), inset 0 1px 0 rgba(255, 255, 255, 0.5);
        }}
        .cgb-glow {{
            position: absolute;
            width: 280px; height: 280px;
            border-radius: 50%;
            filter: blur(60px);
            pointer-events: none;
            z-index: 0;
        }}
        .cgb-glow-left {{ left: -70px; top: 50%; transform: translateY(-50%); background: rgba(34, 211, 238, 0.35); }}
        .cgb-glow-right {{ right: -70px; top: 50%; transform: translateY(-50%); background: rgba(139, 92, 246, 0.30); }}
        .cgb-art {{
            position: relative; z-index: 1; flex: 0 0 auto;
            display: flex; align-items: center; justify-content: center;
        }}
        .cgb-art img {{ width: 100%; height: auto; max-width: 170px; object-fit: contain; display: block; }}
        .cgb-art-left img {{ animation: cgb-float 5s ease-in-out infinite; }}
        .cgb-art-right img {{ filter: drop-shadow(0 0 18px rgba(99, 102, 241, 0.35)); }}
        @keyframes cgb-float {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-8px); }}
        }}
        @media (prefers-reduced-motion: reduce) {{
            .cgb-art-left img {{ animation: none; }}
        }}
        .cgb-content {{ position: relative; z-index: 1; flex: 1 1 auto; min-width: 0; }}
        .cgb-badge {{
            display: inline-flex; align-items: center; gap: 0.4rem;
            font-size: 0.7rem; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase;
            color: #0369A1; background: rgba(224, 242, 254, 0.92);
            border: 1px solid rgba(14, 165, 233, 0.35); border-radius: 999px;
            padding: 0.35rem 0.9rem;
            box-shadow: 0 2px 8px rgba(14, 165, 233, 0.15);
        }}
        .cgb-heading {{
            margin: 0.65rem 0 0.4rem;
            font-weight: 800; line-height: 1.12;
            font-size: clamp(1.5rem, 1.1rem + 1.6vw, 2.3rem);
            letter-spacing: -0.01em;
        }}
        .cgb-heading-navy {{ color: {_SLATE_TEXT}; }}
        .cgb-heading-blue {{ color: {_BLUE}; }}
        .cgb-desc {{
            margin: 0 0 1.1rem;
            color: {_BODY_TEXT};
            font-size: 0.95rem; line-height: 1.55;
            max-width: 520px;
        }}
        .cgb-badges {{ display: flex; flex-wrap: wrap; gap: 0.7rem; }}
        .cgb-feature {{
            display: inline-flex; align-items: center; gap: 0.5rem;
            font-size: 0.82rem; font-weight: 600; color: #1E293B;
            background: rgba(255, 255, 255, 0.70);
            border-radius: 999px;
            padding: 0.42rem 0.9rem 0.42rem 0.42rem;
            border: 1px solid rgba(15, 23, 42, 0.08);
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.06);
        }}
        .cgb-feature-icon {{
            display: inline-flex; align-items: center; justify-content: center;
            width: 26px; height: 26px; border-radius: 50%; flex: 0 0 auto;
        }}
        .cgb-feature-cyan .cgb-feature-icon {{ background: rgba(34, 211, 238, 0.20); color: #0891B2; }}
        .cgb-feature-violet .cgb-feature-icon {{ background: rgba(139, 92, 246, 0.20); color: #7C3AED; }}
        .cgb-feature-teal .cgb-feature-icon {{ background: rgba(20, 184, 166, 0.20); color: #0D9488; }}
        @media (max-width: 900px) {{
            .cgb-banner {{ padding: 1.5rem; min-height: unset; }}
            .cgb-art-right {{ display: none; }}
            .cgb-art img {{ max-width: 110px; }}
        }}
        @media (max-width: 600px) {{
            .cgb-banner {{ flex-direction: column; align-items: flex-start; gap: 1rem; }}
            .cgb-glow {{ display: none; }}
            .cgb-art-left {{ align-self: center; }}
            .cgb-badges {{ flex-direction: column; align-items: stretch; width: 100%; }}
        }}
        /* Recent Threats / Compliance Overview row - stop the shorter
           card from stretching to match the taller one's height (see
           dashboard.py's own comment on this container key). */
        [data-testid="stMain"] .st-key-dashboard_lower_row [data-testid="stHorizontalBlock"] {{
            align-items: flex-start !important;
        }}

        /* =========================================================
           REUSABLE PAGE-LEVEL CARDS - shared across all 8 pages
           (app_pages/*.py), not just one. Safe to reuse the same key
           on every page module since only one page ever renders in a
           given script run (app.py's if/elif dispatch).
        ========================================================= */
        [data-testid="stMain"] .st-key-page_header_card,
        [data-testid="stMain"] [class*="st-key-page_panel_blue"],
        [data-testid="stMain"] [class*="st-key-page_panel_purple"] {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-page_header_card [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-page_header_card.st-key-page_header_card {{
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.85), rgba(224, 242, 254, 0.60)) !important;
            border: 1px solid rgba(14, 165, 233, 0.20) !important;
            box-shadow: 0 4px 18px rgba(14, 165, 233, 0.08) !important;
            position: relative !important;
            overflow: hidden !important;
        }}
        [data-testid="stMain"] .st-key-page_header_card [data-testid="stHeading"] h1,
        [data-testid="stMain"] .st-key-page_header_card [data-testid="stHeading"] h2 {{
            border-bottom: none;
            padding-bottom: 0;
        }}
        [data-testid="stMain"] [class*="st-key-page_panel_blue"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-page_panel_blue"][class*="st-key-page_panel_blue"] {{
            background: linear-gradient(160deg, rgba(255, 255, 255, 0.80), rgba(219, 234, 254, 0.55)) !important;
            border: 1px solid rgba(59, 130, 246, 0.22) !important;
            box-shadow: 0 4px 18px rgba(59, 130, 246, 0.08) !important;
            position: relative !important;
            overflow: hidden !important;
        }}
        [data-testid="stMain"] [class*="st-key-page_panel_purple"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-page_panel_purple"][class*="st-key-page_panel_purple"] {{
            background: linear-gradient(160deg, rgba(255, 255, 255, 0.80), rgba(237, 233, 254, 0.55)) !important;
            border: 1px solid rgba(139, 92, 246, 0.22) !important;
            box-shadow: 0 4px 18px rgba(139, 92, 246, 0.08) !important;
            position: relative !important;
            overflow: hidden !important;
        }}
        /* Shared horizontal "illustration + text" intro card
           (utils/illustrations.py's render_intro_banner()) - used by
           Alerts & Incidents, Reports, Compliance Monitoring, Audit
           Logs, and URL Scanner. Same proven 3-selector pattern as
           every other card in this file (plain class = reset, then
           [data-testid="stLayoutWrapper"] + the doubled class = where
           the real paint goes), PLUS a reset for the nested
           st.columns() row's own stHorizontalBlock AND every individual
           stElementContainer inside it - omitting either one is
           exactly what produced the "second box" bugs already fixed
           twice elsewhere in this file (Detection Engine's stage list,
           the Stay Secure banner) - applied here from the start instead
           of waiting for a third report of the same bug. */
        [data-testid="stMain"] .st-key-page_intro_card {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-page_intro_card [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-page_intro_card.st-key-page_intro_card {{
            background: linear-gradient(120deg, rgba(255, 255, 255, 0.88), rgba(224, 242, 254, 0.55)) !important;
            border: 1px solid transparent !important;
            background-image:
                linear-gradient(120deg, rgba(255, 255, 255, 0.88), rgba(224, 242, 254, 0.55)),
                linear-gradient(120deg, #22D3EE, #8B5CF6) !important;
            background-origin: border-box !important;
            background-clip: padding-box, border-box !important;
            border-radius: 16px !important;
            box-shadow: 0 4px 18px rgba(14, 165, 233, 0.10) !important;
            padding: 1rem 1.2rem !important;
            transition: box-shadow 0.2s ease, transform 0.2s ease;
        }}
        [data-testid="stMain"] .st-key-page_intro_card:hover [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-page_intro_card.st-key-page_intro_card:hover {{
            box-shadow: 0 8px 26px rgba(14, 165, 233, 0.18) !important;
            transform: translateY(-2px);
        }}
        [data-testid="stMain"] .st-key-page_intro_card [data-testid="stHorizontalBlock"],
        [data-testid="stMain"] .st-key-page_intro_card [data-testid="stElementContainer"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }}

        /* =========================================================
           SHARED ANIMATION SYSTEM - gentle, professional, never
           distracting. Applied through the ALREADY-shared image/icon
           helpers (utils/illustrations.py's render_photo()/place()),
           so every robot/shield/lock illustration across every page
           animates consistently from this ONE place, with no per-page
           changes needed. Fully disabled under prefers-reduced-motion.
        ========================================================= */
        @keyframes ai-float {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-7px); }}
        }}
        @keyframes ai-pulse-glow {{
            0%, 100% {{ filter: drop-shadow(0 0 2px rgba(34, 211, 238, 0.25)); }}
            50% {{ filter: drop-shadow(0 0 9px rgba(34, 211, 238, 0.6)); }}
        }}
        /* Every real illustration photo (robot/shield/lock PNGs) in
           the app's main content gets a slow, gentle float - the ONLY
           kind of st.image() this app ever renders (decorative
           illustrations, never a data screenshot or user photo), so a
           single broad selector is safe here, not overreaching. */
        [data-testid="stMain"] [data-testid="stImage"] img {{
            animation: ai-float 5.5s ease-in-out infinite;
        }}
        /* Hand-authored decorative SVG icons (utils/illustrations.py's
           place()) get a soft pulse-glow instead of floating - they're
           absolutely positioned corner accents, not a centred
           character, so a vertical float would look like a glitch. */
        .ai-icon-pulse {{
            animation: ai-pulse-glow 3.2s ease-in-out infinite;
        }}
        /* Small interactive icon/badge elements across the app get a
           subtle lift+scale on hover - stage badges, feature-card
           icons - never applied to buttons/inputs themselves, so it
           never interferes with clicking or typing. */
        [data-testid="stMain"] .td-stage-badge,
        [data-testid="stMain"] [class*="url-feature-"] [data-testid="stImage"] img {{
            transition: transform 0.2s ease;
        }}
        [data-testid="stMain"] .td-stage-badge:hover {{
            transform: scale(1.12);
        }}
        @media (prefers-reduced-motion: reduce) {{
            [data-testid="stMain"] [data-testid="stImage"] img,
            .ai-icon-pulse,
            .cgb-art-left img {{
                animation: none !important;
            }}
            [data-testid="stMain"] .st-key-page_intro_card:hover [data-testid="stLayoutWrapper"],
            [data-testid="stMain"] .st-key-page_intro_card.st-key-page_intro_card:hover,
            [data-testid="stMain"] .td-stage-badge:hover {{
                transform: none !important;
            }}
        }}

        .td-empty-state {{
            text-align: center;
            padding: 1.5rem 0 0.5rem 0;
        }}
        .td-empty-state svg {{
            margin: 0 auto 0.25rem auto;
            display: block;
        }}

        [data-testid="stMain"] [data-testid="stLayoutWrapper"] {{
            background: rgba(255, 255, 255, 0.72);
            border-radius: 14px;
            border: 1px solid rgba(15, 23, 42, 0.06);
            box-shadow: 0 4px 18px rgba(15, 23, 42, 0.06);
            padding: 22px;
        }}

        [data-testid="stMain"] [data-testid="stMetric"] {{
            background: rgba(255, 255, 255, 0.75);
            border: 1px solid rgba(15, 23, 42, 0.06);
            border-radius: 12px;
            padding: 0.75rem 1rem;
            box-shadow: 0 2px 10px rgba(15, 23, 42, 0.05);
        }}
        [data-testid="stMain"] [data-testid="stMetricValue"] {{
            color: {_SLATE_TEXT};
        }}
        [data-testid="stMain"] [data-testid="stMetricLabel"] {{
            color: {_SLATE_MUTED};
        }}

        {_kpi_card_css()}

        [data-testid="stMain"] .st-key-chart_trend_container,
        [data-testid="stMain"] .st-key-chart_severity_container {{
            background: linear-gradient(135deg, rgba(219, 234, 254, 0.55), rgba(224, 247, 250, 0.45)) !important;
            border: 1px solid rgba(59, 130, 246, 0.18) !important;
            border-radius: 14px !important;
            box-shadow: 0 4px 16px rgba(59, 130, 246, 0.08) !important;
        }}
        /* Both chart titles centred, and both share the same violet
           accent (icon + text) so "Detections by Day" and "Detections
           by Severity" read as one matched pair, not two differently
           coloured headings. */
        [data-testid="stMain"] .st-key-chart_trend_container [data-testid="stHeading"],
        [data-testid="stMain"] .st-key-chart_severity_container [data-testid="stHeading"] {{
            justify-content: center !important;
            text-align: center !important;
        }}
        [data-testid="stMain"] .st-key-chart_trend_container [data-testid="stHeading"] h3,
        [data-testid="stMain"] .st-key-chart_severity_container [data-testid="stHeading"] h3 {{
            color: #7C3AED !important;
        }}
        [data-testid="stMain"] .st-key-chart_trend_container [data-testid="stHeadingIconWrapper"] svg,
        [data-testid="stMain"] .st-key-chart_severity_container [data-testid="stHeadingIconWrapper"] svg {{
            color: #7C3AED !important;
        }}
        /* Both charts' descriptive line ("Malicious classifications per
           day..." / "Distribution across all recorded...") centred and
           bold, so it reads as a proper subtitle under the centred
           title above it rather than a left-aligned caption. */
        [data-testid="stMain"] .chart-caption-centered {{
            text-align: center !important;
            font-weight: 700 !important;
            color: {_SLATE_TEXT} !important;
            font-size: 0.85rem !important;
            margin: 0 0 0.3rem !important;
        }}

        [data-testid="stMain"] [data-testid="stButton"] button,
        [data-testid="stMain"] [data-testid="stDownloadButton"] button,
        [data-testid="stMain"] [data-testid="stFormSubmitButton"] button {{
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.08);
        }}
        [data-testid="stMain"] [data-testid="stButton"] button[kind="secondary"],
        [data-testid="stMain"] [data-testid="stDownloadButton"] button {{
            border: 1px solid rgba(14, 165, 233, 0.35);
        }}

        [data-testid="stMain"] [data-testid="stTextInputRootElement"],
        [data-testid="stMain"] [data-baseweb="select"] > div {{
            border-radius: 10px !important;
            border-color: rgba(15, 23, 42, 0.15) !important;
        }}
        [data-testid="stMain"] [data-testid="stTextInputRootElement"]:focus-within,
        [data-testid="stMain"] [data-baseweb="select"]:focus-within > div {{
            border-color: {_CYAN} !important;
            box-shadow: 0 0 0 1px {_CYAN} !important;
        }}

        [data-testid="stMain"] [data-testid="stDataFrame"] {{
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid rgba(15, 23, 42, 0.08);
            box-shadow: 0 2px 10px rgba(15, 23, 42, 0.05);
        }}

        [data-testid="stMain"] [data-testid="stTabs"] [role="tab"] {{
            color: {_SLATE_MUTED};
            font-weight: 500;
        }}
        [data-testid="stMain"] [data-testid="stTabs"] [role="tab"][aria-selected="true"] {{
            color: {_BLUE_DARK};
            font-weight: 700;
        }}
        [data-testid="stMain"] [data-testid="stTabs"] [data-baseweb="tab-highlight"] {{
            background-color: {_CYAN};
        }}

        [data-testid="stMain"] [data-testid="stAlert"],
        [data-testid="stMain"] [data-testid="stExpander"] {{
            border-radius: 12px;
        }}

        [data-testid="stMain"] hr {{
            border: none;
            height: 1px;
            background: linear-gradient(90deg, rgba(14, 165, 233, 0.35), rgba(34, 211, 238, 0.05));
        }}

        /* =========================================================
           THREAT DETECTION PAGE - bright light-blue/white/cyan
           "premium enterprise cybersecurity" treatment. Everything
           here is scoped under .st-key-td_page_wrapper (the single
           outer container app_pages/threat_detection.py wraps its
           whole page in), so none of it leaks onto any other page.
        ========================================================= */
        /* No border/shadow here on purpose - this wrapper used to paint
           its own full card (border + shadow) around the ENTIRE page,
           which meant every section inside it (Detection Engine, each
           model panel, the detection panel) was a SECOND, visibly
           nested box inside this one - reported as "boxes inside
           boxes". It now only gives the page a soft background tint;
           each section below still owns exactly one border/card of
           its own (td_header_card, model_panel_rf/xgb, td_upload_card,
           detection_panel).
           Targeted on all 3 forms (plain class, descendant
           stLayoutWrapper, and the class doubled onto that same
           element) because this container has no border=True, yet the
           first fix here (plain class only) visibly did nothing - the
           app-wide default card rule (the bare [data-testid=
           "stLayoutWrapper"] rule further up this file: white
           background + border + shadow + 22px padding) was still
           winning on whichever node actually paints this wrapper. The
           dual/triple selector guarantees OUR flat background wins
           regardless of which node that turns out to be. */
        [data-testid="stMain"] .st-key-td_page_wrapper,
        [data-testid="stMain"] .st-key-td_page_wrapper [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-td_page_wrapper.st-key-td_page_wrapper {{
            background: linear-gradient(160deg,
                rgba(255, 255, 255, 0.80) 0%,
                rgba(240, 249, 255, 0.78) 50%,
                rgba(224, 242, 254, 0.75) 100%) !important;
            border: none !important;
            box-shadow: none !important;
            border-radius: 20px !important;
            padding: 1.75rem !important;
        }}
        [data-testid="stMain"] .st-key-td_page_wrapper h1,
        [data-testid="stMain"] .st-key-td_page_wrapper h2,
        [data-testid="stMain"] .st-key-td_page_wrapper h3,
        [data-testid="stMain"] .st-key-td_page_wrapper h4 {{
            color: {_SLATE_TEXT} !important;
            border-bottom-color: rgba(14, 165, 233, 0.30) !important;
        }}
        [data-testid="stMain"] .st-key-td_page_wrapper [data-testid="stCaptionContainer"],
        [data-testid="stMain"] .st-key-td_page_wrapper [data-testid="stCaptionContainer"] p {{
            color: {_SLATE_TEXT} !important;
            font-weight: 600 !important;
        }}
        [data-testid="stMain"] .st-key-td_upload_card,
        [data-testid="stMain"] .st-key-td_header_card,
        [data-testid="stMain"] .st-key-td_multiformat_card {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-td_upload_card.st-key-td_upload_card,
        [data-testid="stMain"] .st-key-td_multiformat_card [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-td_multiformat_card.st-key-td_multiformat_card {{
            background: linear-gradient(135deg, rgba(224, 242, 254, 0.9), rgba(199, 236, 254, 0.55)) !important;
            border: 1px solid rgba(14, 165, 233, 0.35) !important;
            box-shadow: 0 8px 26px rgba(14, 165, 233, 0.14) !important;
            padding: 1.6rem !important;
            position: relative !important;
            overflow: hidden !important;
        }}
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stLayoutWrapper"]::before,
        [data-testid="stMain"] .st-key-td_upload_card.st-key-td_upload_card::before {{
            content: "";
            position: absolute; top: 0; left: 0; right: 0; height: 5px;
            background: linear-gradient(90deg, #0EA5E9, #22D3EE, #8B5CF6);
        }}
        /* Bigger, bolder "Up to 300 MB and 3,000,000 rows" caption and
           the "Upload Network Traffic CSV" label above the dropzone -
           previously plain grey text that disappeared against the
           pale card background ("can see the upload" complaint). */
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stCaptionContainer"],
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stCaptionContainer"] p {{
            color: #0369A1 !important;
            font-weight: 700 !important;
            font-size: 0.92rem !important;
        }}
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stWidgetLabel"] p {{
            color: #0F172A !important;
            font-weight: 800 !important;
            font-size: 1.02rem !important;
        }}
        /* The dropzone itself - bigger (taller), vivid dashed cyan/violet
           border with a soft glow, instead of the barely-visible pale
           box it was. */
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stFileUploaderDropzone"] {{
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.9), rgba(224, 242, 254, 0.75)) !important;
            border: 3px dashed #0EA5E9 !important;
            border-radius: 16px !important;
            min-height: 120px !important;
            padding: 1.25rem !important;
            box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.08), 0 6px 18px rgba(14, 165, 233, 0.14) !important;
            transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
            display: flex !important;
            flex-wrap: wrap !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 0.6rem 1rem !important;
            text-align: center !important;
        }}
        /* The icon/instructions/button row Streamlit nests one level
           inside the dropzone was its own flex child still left-aligned
           on its own axis even once the dropzone itself was centered -
           without this it only pulled the WHOLE group to the middle,
           not the button+text pairing within that group ("put the
           upload on center"). */
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stFileUploaderDropzone"] > div {{
            display: flex !important;
            flex-wrap: wrap !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 0.6rem 1rem !important;
            width: auto !important;
        }}
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stFileUploaderDropzone"]:hover {{
            border-color: #8B5CF6 !important;
            box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.12), 0 8px 22px rgba(139, 92, 246, 0.18) !important;
        }}
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stFileUploaderDropzoneInstructions"] {{
            color: #0F172A !important;
            font-weight: 700 !important;
            font-size: 0.95rem !important;
        }}
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stFileUploaderDropzoneInstructions"] span {{
            color: #0369A1 !important;
        }}
        /* The "Upload"/"Browse files" button inside the dropzone - was
           flat white-on-white and nearly invisible; now a solid
           cyan-to-violet gradient pill that matches the rest of the
           page's accent colours and is obviously clickable. */
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stFileUploaderDropzone"] button {{
            background: linear-gradient(135deg, #0EA5E9, #8B5CF6) !important;
            color: #FFFFFF !important;
            border: none !important;
            border-radius: 999px !important;
            font-weight: 800 !important;
            padding: 0.5rem 1.3rem !important;
            box-shadow: 0 4px 14px rgba(14, 165, 233, 0.35) !important;
        }}
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stFileUploaderDropzone"] button:hover {{
            box-shadow: 0 6px 18px rgba(139, 92, 246, 0.45) !important;
            transform: translateY(-1px);
        }}
        [data-testid="stMain"] .st-key-td_upload_card [data-testid="stFileUploaderDropzone"] svg {{
            color: #0EA5E9 !important;
            width: 28px !important;
            height: 28px !important;
        }}
        /* Active-dataset status bar (shared across all 3 upload tabs) -
           a slim, low-emphasis strip, deliberately NOT another full
           card (no border/shadow of its own) so it doesn't add a
           4th box on top of the upload card / dataset info panels
           already stacked above and below it. */
        [data-testid="stMain"] .st-key-td_active_dataset_bar {{
            background: rgba(14, 165, 233, 0.08) !important;
            border: 1px solid rgba(14, 165, 233, 0.18) !important;
            border-radius: 10px !important;
            padding: 0.5rem 0.9rem !important;
            margin: 0.4rem 0 1rem !important;
        }}
        /* Header card: richer than a normal section card (this is the
           page's main title block), with the same blue-cyan-violet top
           accent stripe used elsewhere for a prominent header. */
        [data-testid="stMain"] .st-key-td_header_card [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-td_header_card.st-key-td_header_card {{
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.88), rgba(219, 234, 254, 0.70)) !important;
            border: 1px solid rgba(14, 165, 233, 0.26) !important;
            border-radius: 18px !important;
            box-shadow: 0 8px 26px rgba(14, 165, 233, 0.12) !important;
            padding-top: 0.25rem !important;
            position: relative !important;
        }}
        /* The illustration inside cols[0] (see _render_header_card())
           needs ITS OWN position:relative ancestor - without this, its
           default top/right anchors to td_header_card above (the
           WHOLE two-column card), landing it near the middle where
           the columns meet instead of inside this left section. */
        [data-testid="stMain"] .st-key-td_header_left {{
            position: relative !important;
        }}
        [data-testid="stMain"] .st-key-td_header_card [data-testid="stLayoutWrapper"]::before,
        [data-testid="stMain"] .st-key-td_header_card.st-key-td_header_card::before {{
            content: "";
            position: absolute; top: 0; left: 0; right: 0; height: 5px;
            background: linear-gradient(90deg, #0EA5E9, #22D3EE, #8B5CF6);
        }}
        /* Same fix as dashboard_welcome_card above - the nested
           st.columns(..., vertical_alignment="center") (text_col/
           art_col) was also getting the full card look (background/
           border/shadow/top-stripe) painted onto its own row, a
           second card nested inside this one. */
        [data-testid="stMain"] .st-key-td_header_card [data-testid="stHorizontalBlock"],
        [data-testid="stMain"] .st-key-td_header_card [data-testid="stHorizontalBlock"] [data-testid="stLayoutWrapper"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0 !important;
        }}
        [data-testid="stMain"] .st-key-td_header_card [data-testid="stHorizontalBlock"]::before,
        [data-testid="stMain"] .st-key-td_header_card [data-testid="stHorizontalBlock"] [data-testid="stLayoutWrapper"]::before {{
            content: none !important;
        }}
        /* Same bug, different child: the 4-stage list is rendered via
           ONE st.markdown() call sitting directly below the title/
           robot columns, inside this SAME card - but its own individual
           element wrapper (stElementContainer, the standard per-element
           wrapper Streamlit gives every single element, distinct from
           the block-level wrapper above that legitimately owns this
           card's paint) was ALSO matching the broad [data-testid=
           "stLayoutWrapper"] card-paint rule, producing a SECOND
           visibly bordered/gradient box stacked directly under the
           first one - reported as "extra layout boxes". Resetting
           every stElementContainer inside this card is safe: it only
           ever wraps ONE individual element at a time, never the
           outer multi-element block this card's real border belongs to. */
        [data-testid="stMain"] .st-key-td_header_card [data-testid="stElementContainer"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }}
        /* Dataset Information stat cards (8 of them - Rows/Columns/
           Numeric/Categorical/Missing/Duplicate/Labelled/Classes) -
           a blue/cyan/teal rotation, per request ("subtle blue, cyan,
           and teal accents"), never a wider rainbow. Values themselves
           are real dataset statistics computed by
           ml/preprocessing.py:get_dataset_info() - this only adds
           colour, never touches a number. */
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_blue"],
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_cyan"],
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_teal"] {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_blue"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_blue"][class*="st-key-td_stat_blue"] {{
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.34), rgba(59, 130, 246, 0.14)) !important;
            border: 1px solid rgba(59, 130, 246, 0.55) !important;
            border-top: 4px solid #3B82F6 !important;
            border-radius: 12px !important;
        }}
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_cyan"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_cyan"][class*="st-key-td_stat_cyan"] {{
            background: linear-gradient(135deg, rgba(34, 211, 238, 0.34), rgba(34, 211, 238, 0.14)) !important;
            border: 1px solid rgba(34, 211, 238, 0.55) !important;
            border-top: 4px solid #22D3EE !important;
            border-radius: 12px !important;
        }}
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_teal"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-td_page_wrapper [class*="st-key-td_stat_teal"][class*="st-key-td_stat_teal"] {{
            background: linear-gradient(135deg, rgba(20, 184, 166, 0.34), rgba(20, 184, 166, 0.14)) !important;
            border: 1px solid rgba(20, 184, 166, 0.55) !important;
            border-top: 4px solid #14B8A6 !important;
            border-radius: 12px !important;
        }}
        /* "Detection Engine" stage badges (inside the unified header
           card, see _render_header_card()) - cyan/blue/violet/green,
           one colour per stage, purely a grouping accent (the stage
           TEXT itself is the real, already-implemented pipeline -
           never a live status, see that function's own docstring). */
        .td-stage-row {{
            display: flex; align-items: flex-start; gap: 0.7rem;
            margin-bottom: 0.85rem;
        }}
        .td-stage-badge {{
            flex: 0 0 auto;
            width: 26px; height: 26px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-weight: 800; font-size: 0.85rem; color: #FFFFFF;
        }}
        .td-stage-cyan {{ background: #22D3EE; box-shadow: 0 0 10px rgba(34, 211, 238, 0.5); }}
        .td-stage-blue {{ background: #0EA5E9; box-shadow: 0 0 10px rgba(14, 165, 233, 0.5); }}
        .td-stage-violet {{ background: #8B5CF6; box-shadow: 0 0 10px rgba(139, 92, 246, 0.5); }}
        .td-stage-green {{ background: #22C55E; box-shadow: 0 0 10px rgba(34, 197, 94, 0.5); }}
        .td-stage-title {{ color: #0F172A; font-weight: 700; font-size: 0.92rem; }}
        .td-stage-desc {{ color: {_SLATE_MUTED}; font-size: 0.8rem; margin-top: 0.1rem; }}
        /* 3 capability pills under the header's title/caption
           (app_pages/threat_detection.py's _render_capability_pills) -
           fills the space the old blank gap left, and gives the
           header card its "more interactive" hover micro-motion. */
        .td-pill-row {{
            display: flex; flex-wrap: wrap; gap: 0.5rem;
            margin: 0.6rem 0 0.9rem;
        }}
        .td-pill {{
            display: inline-block;
            padding: 0.32rem 0.85rem;
            border-radius: 999px;
            border: 1px solid;
            font-weight: 700;
            font-size: 0.78rem;
            letter-spacing: 0.01em;
            transition: transform 0.15s ease;
        }}
        .td-pill:hover {{
            transform: translateY(-2px);
        }}
        [data-testid="stMain"] .st-key-td_page_wrapper [data-testid="stFileUploaderDropzone"] {{
            background: linear-gradient(135deg, rgba(224, 242, 254, 0.7), rgba(240, 249, 255, 0.5)) !important;
            border: 2px dashed rgba(14, 165, 233, 0.45) !important;
            border-radius: 14px !important;
        }}
        [data-testid="stMain"] .st-key-td_page_wrapper [data-testid="stFileUploaderDropzoneInstructions"] {{
            color: #475569 !important;
        }}
        [data-testid="stMain"] .st-key-td_page_wrapper [data-testid="stTabs"] [role="tab"][aria-selected="true"] {{
            color: {_BLUE_DARK} !important;
        }}
        /* Dataset Information's two expanders (Preview first 10 rows /
           Missing values by column) and the Validate/Preprocess/Train
           action row below it - previously flat white/grey like every
           other expander and secondary button on the page, reported
           directly as needing colour. One accent per expander (cyan =
           neutral preview, amber = a flag worth a second look), and
           one accent per pipeline step, reusing the exact cyan/blue/
           violet already established by this page's own Detection
           Engine stage badges above instead of inventing a new
           palette. */
        [data-testid="stMain"] .st-key-td_expander_preview,
        [data-testid="stMain"] .st-key-td_expander_preview [data-testid="stExpander"] {{
            border: 1px solid rgba(34, 211, 238, 0.40) !important;
            border-left: 4px solid #22D3EE !important;
            border-radius: 10px !important;
            background: rgba(34, 211, 238, 0.07) !important;
        }}
        [data-testid="stMain"] .st-key-td_expander_missing,
        [data-testid="stMain"] .st-key-td_expander_missing [data-testid="stExpander"] {{
            border: 1px solid rgba(249, 115, 22, 0.40) !important;
            border-left: 4px solid #F97316 !important;
            border-radius: 10px !important;
            background: rgba(249, 115, 22, 0.07) !important;
        }}
        /* Compliance Monitoring's "Check-by-check findings" - one
           expander per real compliance_results row, coloured/left-
           bordered by its ACTUAL status (green/amber/red), same
           substring-key technique as the Threat Detection stat cards
           above (each row's key ends in a unique "_<index>" suffix, so
           [class*=...] matches every row of that status regardless of
           index). Also a visible hover lift, so the already-real
           click-to-expand affordance reads clearly as interactive. */
        [data-testid="stMain"] [class*="st-key-compliance_exp_compliant_"],
        [data-testid="stMain"] [class*="st-key-compliance_exp_compliant_"] [data-testid="stExpander"] {{
            border: 1px solid rgba(34, 197, 94, 0.40) !important;
            border-left: 4px solid #16A34A !important;
            border-radius: 10px !important;
            background: rgba(34, 197, 94, 0.07) !important;
        }}
        [data-testid="stMain"] [class*="st-key-compliance_exp_needs_review_"],
        [data-testid="stMain"] [class*="st-key-compliance_exp_needs_review_"] [data-testid="stExpander"] {{
            border: 1px solid rgba(245, 158, 11, 0.45) !important;
            border-left: 4px solid #B45309 !important;
            border-radius: 10px !important;
            background: rgba(245, 158, 11, 0.08) !important;
        }}
        [data-testid="stMain"] [class*="st-key-compliance_exp_potential_violation_"],
        [data-testid="stMain"] [class*="st-key-compliance_exp_potential_violation_"] [data-testid="stExpander"] {{
            border: 1px solid rgba(220, 38, 38, 0.45) !important;
            border-left: 4px solid #DC2626 !important;
            border-radius: 10px !important;
            background: rgba(220, 38, 38, 0.07) !important;
        }}
        [data-testid="stMain"] [class*="st-key-compliance_exp_"] {{
            margin-bottom: 0.5rem !important;
            transition: box-shadow 0.15s ease, transform 0.15s ease;
        }}
        [data-testid="stMain"] [class*="st-key-compliance_exp_"]:hover {{
            box-shadow: 0 4px 14px rgba(14, 165, 233, 0.18) !important;
            transform: translateY(-1px);
        }}
        [data-testid="stMain"] [class*="st-key-compliance_exp_"] summary {{
            cursor: pointer !important;
            font-weight: 700 !important;
        }}
        [data-testid="stMain"] .st-key-td_action_validate button {{
            border: 1px solid rgba(34, 211, 238, 0.55) !important;
            color: #0E7490 !important;
            background: rgba(34, 211, 238, 0.12) !important;
            font-weight: 700 !important;
        }}
        [data-testid="stMain"] .st-key-td_action_validate button:hover {{
            background: rgba(34, 211, 238, 0.22) !important;
            border-color: #22D3EE !important;
        }}
        [data-testid="stMain"] .st-key-td_action_preprocess button {{
            border: 1px solid rgba(14, 165, 233, 0.55) !important;
            color: #0369A1 !important;
            background: rgba(14, 165, 233, 0.12) !important;
            font-weight: 700 !important;
        }}
        [data-testid="stMain"] .st-key-td_action_preprocess button:hover {{
            background: rgba(14, 165, 233, 0.22) !important;
            border-color: #0EA5E9 !important;
        }}
        [data-testid="stMain"] .st-key-td_action_train button {{
            border: 1px solid rgba(139, 92, 246, 0.55) !important;
            color: #6D28D9 !important;
            background: rgba(139, 92, 246, 0.12) !important;
            font-weight: 700 !important;
        }}
        [data-testid="stMain"] .st-key-td_action_train button:hover {{
            background: rgba(139, 92, 246, 0.22) !important;
            border-color: #8B5CF6 !important;
        }}

        [data-testid="stMain"] .st-key-model_panel_rf,
        [data-testid="stMain"] .st-key-model_panel_xgb,
        [data-testid="stMain"] .st-key-detection_panel {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-model_panel_rf [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-model_panel_rf.st-key-model_panel_rf {{
            background: linear-gradient(145deg, rgba(14, 165, 233, 0.20), rgba(224, 242, 254, 0.60)) !important;
            border: 1px solid rgba(14, 165, 233, 0.45) !important;
            border-top: 4px solid #0EA5E9 !important;
            box-shadow: 0 0 20px rgba(14, 165, 233, 0.10), 0 6px 18px rgba(15, 23, 42, 0.06) !important;
            position: relative !important;
            overflow: hidden !important;
        }}
        [data-testid="stMain"] .st-key-model_panel_xgb [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-model_panel_xgb.st-key-model_panel_xgb {{
            background: linear-gradient(145deg, rgba(139, 92, 246, 0.18), rgba(237, 233, 254, 0.60)) !important;
            border: 1px solid rgba(139, 92, 246, 0.42) !important;
            border-top: 4px solid #8B5CF6 !important;
            box-shadow: 0 0 20px rgba(139, 92, 246, 0.10), 0 6px 18px rgba(15, 23, 42, 0.06) !important;
            position: relative !important;
            overflow: hidden !important;
        }}

        [data-testid="stMain"] .st-key-detection_panel [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-detection_panel.st-key-detection_panel {{
            background: linear-gradient(160deg, rgba(255, 255, 255, 0.82), rgba(240, 249, 255, 0.72)) !important;
            border: 1px solid rgba(14, 165, 233, 0.26) !important;
            box-shadow: 0 0 24px rgba(14, 165, 233, 0.08) !important;
            position: relative !important;
            overflow: hidden !important;
        }}

        /* =========================================================
           URL SCANNER - feature cards, result status badge, and
           per-engine result rows (app_pages/url_scanner.py). The
           existing page_panel_blue/purple cards already cover the
           scan-input and history panels via the generic rules above.
        ========================================================= */
        /* 4-colour rotation (blue/cyan/violet/green), matching
           _render_feature_cards()'s own FEATURES list - each card's
           key encodes which accent it wants (e.g. "url_feature_blue_
           real-time_url_analysis"), matched here by class substring -
           same convention as Threat Detection's td_stat_* cards. */
        [data-testid="stMain"] [class*="st-key-url_feature_blue_"],
        [data-testid="stMain"] [class*="st-key-url_feature_cyan_"],
        [data-testid="stMain"] [class*="st-key-url_feature_violet_"],
        [data-testid="stMain"] [class*="st-key-url_feature_green_"],
        [data-testid="stMain"] [class*="st-key-report_card_red_"],
        [data-testid="stMain"] [class*="st-key-report_card_violet_"],
        [data-testid="stMain"] [class*="st-key-report_card_teal_"],
        [data-testid="stMain"] [class*="st-key-report_card_amber_"] {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] [class*="st-key-url_feature_blue_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-url_feature_cyan_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-url_feature_violet_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-url_feature_green_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-report_card_red_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-report_card_violet_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-report_card_teal_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-report_card_amber_"] [data-testid="stLayoutWrapper"] {{
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }}
        [data-testid="stMain"] [class*="st-key-url_feature_blue_"] [data-testid="stLayoutWrapper"]:hover,
        [data-testid="stMain"] [class*="st-key-url_feature_cyan_"] [data-testid="stLayoutWrapper"]:hover,
        [data-testid="stMain"] [class*="st-key-url_feature_violet_"] [data-testid="stLayoutWrapper"]:hover,
        [data-testid="stMain"] [class*="st-key-url_feature_green_"] [data-testid="stLayoutWrapper"]:hover,
        [data-testid="stMain"] [class*="st-key-report_card_red_"] [data-testid="stLayoutWrapper"]:hover,
        [data-testid="stMain"] [class*="st-key-report_card_violet_"] [data-testid="stLayoutWrapper"]:hover,
        [data-testid="stMain"] [class*="st-key-report_card_teal_"] [data-testid="stLayoutWrapper"]:hover,
        [data-testid="stMain"] [class*="st-key-report_card_amber_"] [data-testid="stLayoutWrapper"]:hover {{
            transform: translateY(-3px);
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.14);
        }}
        /* Two selectors per rule, not one: this installed Streamlit
           version (1.64.0) puts the "st-key-X" class directly ON the
           element that also carries data-testid="stLayoutWrapper" -
           confirmed by reading the frontend bundle's own element
           builder (im(...) component - both className and the
           stLayoutWrapper test-id are set on that SAME node), not on
           a separate outer ancestor as the rest of this file assumed.
           The descendant form `.st-key-X [data-testid="stLayoutWrapper"]`
           therefore never matches anything for THESE cards - it was
           silently a no-op, which is why they kept rendering as plain
           white boxes no matter how the gradient/border was tuned.
           The second, non-descendant selector (class directly on the
           stLayoutWrapper element) is the one that actually applies;
           the first is kept as a harmless no-op in case a future
           Streamlit version restores the outer-wrapper structure. */
        [data-testid="stMain"] [class*="st-key-url_feature_blue_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-url_feature_blue_"][class*="st-key-url_feature_blue_"] {{
            background: linear-gradient(160deg, rgba(14, 165, 233, 0.34), rgba(14, 165, 233, 0.14)) !important;
            border: 1px solid rgba(14, 165, 233, 0.55) !important;
            border-top: 4px solid #0EA5E9 !important;
            border-radius: 12px !important;
            text-align: center;
        }}
        [data-testid="stMain"] [class*="st-key-url_feature_cyan_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-url_feature_cyan_"][class*="st-key-url_feature_cyan_"] {{
            background: linear-gradient(160deg, rgba(34, 211, 238, 0.34), rgba(34, 211, 238, 0.14)) !important;
            border: 1px solid rgba(34, 211, 238, 0.55) !important;
            border-top: 4px solid #22D3EE !important;
            border-radius: 12px !important;
            text-align: center;
        }}
        [data-testid="stMain"] [class*="st-key-url_feature_violet_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-url_feature_violet_"][class*="st-key-url_feature_violet_"] {{
            background: linear-gradient(160deg, rgba(139, 92, 246, 0.34), rgba(139, 92, 246, 0.14)) !important;
            border: 1px solid rgba(139, 92, 246, 0.55) !important;
            border-top: 4px solid #8B5CF6 !important;
            border-radius: 12px !important;
            text-align: center;
        }}
        [data-testid="stMain"] [class*="st-key-url_feature_green_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-url_feature_green_"][class*="st-key-url_feature_green_"] {{
            background: linear-gradient(160deg, rgba(34, 197, 94, 0.34), rgba(34, 197, 94, 0.14)) !important;
            border: 1px solid rgba(34, 197, 94, 0.55) !important;
            border-top: 4px solid #22C55E !important;
            border-radius: 12px !important;
            text-align: center;
        }}
        /* Title/description inside these "icon + title + description"
           feature cards (url_feature_*, report_card_*, td_stat_*) -
           darker and a touch heavier than the sitewide caption/body
           default, since a tinted gradient card needs more contrast
           than a plain white one to keep small text from reading as
           faded (the exact complaint these cards got). */
        [data-testid="stMain"] [class*="st-key-url_feature_"] [data-testid="stMarkdownContainer"] p,
        [data-testid="stMain"] [class*="st-key-report_card_"] [data-testid="stMarkdownContainer"] p {{
            font-weight: 700 !important;
            color: {_SLATE_TEXT} !important;
            font-size: 0.95rem !important;
        }}
        [data-testid="stMain"] [class*="st-key-url_feature_"] [data-testid="stCaptionContainer"] p,
        [data-testid="stMain"] [class*="st-key-report_card_"] [data-testid="stCaptionContainer"] p {{
            font-weight: 600 !important;
            color: #334155 !important;
        }}
        .url-status-badge {{
            display: inline-block;
            padding: 0.5rem 1.1rem;
            border-radius: 999px;
            font-weight: 800;
            font-size: 0.85rem;
            letter-spacing: 0.03em;
            text-align: center;
            width: 100%;
        }}
        .url-engine-row {{
            display: flex;
            align-items: center;
            gap: 0.6rem;
            padding: 0.4rem 0;
            border-bottom: 1px solid rgba(15, 23, 42, 0.06);
            font-size: 0.85rem;
        }}
        .url-engine-dot {{
            width: 8px; height: 8px; border-radius: 50%; flex: 0 0 auto;
        }}
        .url-engine-vendor {{
            flex: 1 1 auto;
            color: #0F172A;
            font-weight: 600;
        }}
        .url-engine-result {{
            font-weight: 700;
            text-transform: capitalize;
        }}

        /* =========================================================
           REPORTS - the 4 "generate a report" cards
           (app_pages/reports.py's REPORT_CARDS / _render_report_cards).
           Left-aligned (icon + title + description + controls stack
           vertically), unlike URL Scanner's centred feature cards -
           same class-substring-match convention otherwise.
        ========================================================= */
        [data-testid="stMain"] [class*="st-key-report_card_red_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-report_card_red_"][class*="st-key-report_card_red_"] {{
            background: linear-gradient(160deg, rgba(220, 38, 38, 0.32), rgba(220, 38, 38, 0.12)) !important;
            border: 1px solid rgba(220, 38, 38, 0.55) !important;
            border-top: 4px solid #DC2626 !important;
            border-radius: 12px !important;
        }}
        [data-testid="stMain"] [class*="st-key-report_card_violet_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-report_card_violet_"][class*="st-key-report_card_violet_"] {{
            background: linear-gradient(160deg, rgba(139, 92, 246, 0.32), rgba(139, 92, 246, 0.12)) !important;
            border: 1px solid rgba(139, 92, 246, 0.55) !important;
            border-top: 4px solid #8B5CF6 !important;
            border-radius: 12px !important;
        }}
        [data-testid="stMain"] [class*="st-key-report_card_teal_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-report_card_teal_"][class*="st-key-report_card_teal_"] {{
            background: linear-gradient(160deg, rgba(13, 148, 136, 0.32), rgba(13, 148, 136, 0.12)) !important;
            border: 1px solid rgba(13, 148, 136, 0.55) !important;
            border-top: 4px solid #0D9488 !important;
            border-radius: 12px !important;
        }}
        [data-testid="stMain"] [class*="st-key-report_card_amber_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-report_card_amber_"][class*="st-key-report_card_amber_"] {{
            background: linear-gradient(160deg, rgba(217, 119, 6, 0.32), rgba(217, 119, 6, 0.12)) !important;
            border: 1px solid rgba(217, 119, 6, 0.55) !important;
            border-top: 4px solid #D97706 !important;
            border-radius: 12px !important;
        }}
        /* =========================================================
           SETTINGS - per-user row cards (app_pages/settings.py's
           _render_user_row). Colour/border come from that function's
           own per-row style injection (role accent); this just adds
           the hover lift, same convention as every other card.
        ========================================================= */
        [data-testid="stMain"] [class*="st-key-user_row_"] [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] [class*="st-key-user_row_"][class*="st-key-user_row_"] {{
            border-radius: 10px !important;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }}
        [data-testid="stMain"] [class*="st-key-user_row_"] [data-testid="stLayoutWrapper"]:hover,
        [data-testid="stMain"] [class*="st-key-user_row_"][class*="st-key-user_row_"]:hover {{
            transform: translateX(3px);
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.10);
        }}
        /* Account-security banner (app_pages/settings.py's
           _render_security_banner) - light-blue-to-lavender gradient
           card with the real cyber_lock.png/cyber_shield.png
           illustrations, per request. */
        [data-testid="stMain"] .st-key-settings_security_banner {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-settings_security_banner [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-settings_security_banner.st-key-settings_security_banner {{
            background: linear-gradient(120deg, rgba(219, 234, 254, 0.85), rgba(237, 233, 254, 0.75)) !important;
            border: 1px solid rgba(139, 92, 246, 0.28) !important;
            border-radius: 16px !important;
            box-shadow: 0 4px 16px rgba(139, 92, 246, 0.10) !important;
        }}
        /* Same fix as dashboard_welcome_card above - this banner's own
           st.columns(..., vertical_alignment="center") (text_col/
           art_col) was also getting the full card look painted onto
           its row. */
        [data-testid="stMain"] .st-key-settings_security_banner [data-testid="stHorizontalBlock"],
        [data-testid="stMain"] .st-key-settings_security_banner [data-testid="stHorizontalBlock"] [data-testid="stLayoutWrapper"] {{
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0 !important;
        }}

        /* =========================================================
           SETTINGS - My Account page redesign (breadcrumb, page
           intro, profile card, account navigation list, activity
           card). Scoped to plain classes (not .st-key-) for the
           breadcrumb/intro/activity rows since those are single
           literal-HTML blocks, not separate Streamlit containers.
        ========================================================= */
        .settings-breadcrumb {{
            display: flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.82rem;
            color: {_SLATE_MUTED};
            margin: 0 0 0.6rem 0;
        }}
        .settings-breadcrumb-icon {{
            display: inline-flex;
            align-items: center;
            color: {_SLATE_MUTED};
        }}
        .settings-breadcrumb-sep {{
            color: rgba(100, 116, 139, 0.5);
        }}
        .settings-breadcrumb-current {{
            color: {_SLATE_TEXT};
            font-weight: 700;
        }}
        .settings-intro {{
            display: flex;
            align-items: center;
            gap: 0.9rem;
            margin: 0 0 1.1rem 0;
        }}
        .settings-intro-icon {{
            flex: 0 0 auto;
            width: 56px;
            height: 56px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.16), rgba(34, 211, 238, 0.10));
            border: 1px solid rgba(59, 130, 246, 0.25);
            color: #2563EB;
        }}
        .settings-intro-text {{
            display: flex;
            flex-direction: column;
            gap: 0.15rem;
        }}
        .settings-intro-title {{
            font-size: 1.6rem;
            font-weight: 800;
            color: {_SLATE_TEXT};
            line-height: 1.2;
        }}
        .settings-intro-subtitle {{
            font-size: 0.9rem;
            font-weight: 500;
            color: {_SLATE_MUTED};
        }}
        [data-testid="stMain"] .st-key-settings_profile_card {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-settings_profile_card [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-settings_profile_card.st-key-settings_profile_card {{
            background: linear-gradient(120deg, rgba(219, 234, 254, 0.85), rgba(224, 247, 250, 0.70)) !important;
            border: 1px solid rgba(59, 130, 246, 0.25) !important;
            border-radius: 16px !important;
            box-shadow: 0 4px 16px rgba(59, 130, 246, 0.10) !important;
        }}
        [data-testid="stMain"] .st-key-settings_nav_row_account_details,
        [data-testid="stMain"] .st-key-settings_nav_row_security,
        [data-testid="stMain"] .st-key-settings_nav_row_notifications,
        [data-testid="stMain"] .st-key-settings_nav_row_preferences,
        [data-testid="stMain"] .st-key-settings_nav_row_connected,
        [data-testid="stMain"] .st-key-settings_nav_row_privacy {{
            border-radius: 10px;
            padding: 0.15rem 0.3rem;
            margin-bottom: 0.15rem;
            border-left: 3px solid transparent;
            transition: background 0.15s ease;
        }}
        [data-testid="stMain"] [class*="st-key-settings_nav_row_"] [data-testid="stButton"] button {{
            justify-content: flex-start !important;
            text-align: left !important;
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0.4rem 1.6rem 0 0.2rem !important;
            position: relative;
        }}
        [data-testid="stMain"] [class*="st-key-settings_nav_row_"] [data-testid="stButton"] button::after {{
            content: "\\203A";
            position: absolute;
            right: 0.4rem;
            top: 50%;
            transform: translateY(-50%);
            color: {_MUTED_LIGHT};
            font-size: 1.1rem;
        }}
        [data-testid="stMain"] [class*="st-key-settings_nav_row_"] [data-testid="stCaptionContainer"] {{
            padding: 0 0.2rem 0.5rem 2.9rem;
            margin-top: -0.4rem;
        }}
        .settings-activity-row {{
            display: flex;
            align-items: center;
            gap: 0.7rem;
            padding: 0.55rem 0;
            border-bottom: 1px solid rgba(15, 23, 42, 0.06);
            font-size: 0.86rem;
        }}
        .settings-activity-row:last-child {{
            border-bottom: none;
        }}
        .settings-activity-icon {{
            flex: 0 0 auto;
            width: 30px;
            height: 30px;
            border-radius: 8px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: rgba(139, 92, 246, 0.12);
            color: #7C3AED;
        }}
        .settings-activity-label {{
            color: {_SLATE_MUTED};
            flex: 1 1 auto;
        }}
        .settings-activity-value {{
            color: {_SLATE_TEXT};
            font-weight: 600;
            text-align: right;
        }}
        [data-testid="stMain"] .st-key-settings_update_profile_btn button[kind="primary"] {{
            background: linear-gradient(135deg, #3B82F6, {_CYAN}) !important;
            border: none !important;
            color: white !important;
            font-weight: 700 !important;
        }}
        [data-testid="stMain"] .st-key-settings_update_profile_btn button[kind="primary"]:hover {{
            box-shadow: 0 4px 14px rgba(59, 130, 246, 0.35) !important;
        }}

        [data-testid="stMain"] .st-key-reports_generate_cta {{
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }}
        [data-testid="stMain"] .st-key-reports_generate_cta [data-testid="stLayoutWrapper"],
        [data-testid="stMain"] .st-key-reports_generate_cta.st-key-reports_generate_cta {{
            background: linear-gradient(135deg, rgba(14, 165, 233, 0.14), rgba(14, 165, 233, 0.04)) !important;
            border: 1px solid rgba(14, 165, 233, 0.30) !important;
            border-radius: 14px !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )
