"""
Lightweight, local, inline SVG line-art decorations shared across every
page (app_pages/*.py).

Every SVG below is hand-authored directly in this file - no external
image URLs (nothing to break if the site is ever run offline), no new
dependency, no binary asset to manage. Each one uses only simple
primitives (rect/circle/line/path) with a thin stroke and no fill
(or a near-transparent one), matching the requested "thin outline,
nearly monochromatic" style rather than a colourful decorative image.

place() wraps an SVG in a position:absolute, pointer-events:none div
so it can only ever sit decoratively in a card's corner - it can never
intercept a click or sit on top of real content in a way that matters,
since it's also always low-opacity and placed away from where text/
buttons/metrics actually render.

Each page uses a different illustration (or two) so the 8 pages don't
look like copies of each other, while all sharing the same thin-line,
low-opacity, blue/cyan/purple style via the one place() helper.

PHOTO_ILLUSTRATIONS / photo_path() / render_photo() below are a SEPARATE
system: real transparent PNG files the user supplied in
assets/illustrations/, not hand-authored SVGs. photo_path() resolves
each one relative to THIS file's own location (so it finds the right
file regardless of the process's current working directory, which has
drifted before in this project - see app.py's own docstring), and
returns None - never a fabricated path - if a file genuinely isn't on
disk. render_photo() only ever calls st.image() on a path that
photo_path() has already confirmed exists; it silently renders nothing
(not a substitute emoji, not a broken path) when a name is unknown or
missing, so a caller can safely fall back to its own plain text.
"""
from pathlib import Path

import streamlit as st

_ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets" / "illustrations"
_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

PHOTO_ILLUSTRATIONS = {
    "robot_shield": "cyber_robot_shield.png",
    "robot_laptop": "cyber_robot_laptop.png",
    "robot_scanner": "cyber_robot_scanner.png",
    "robot_security_panel": "cyber_robot_security_panel.png",
    "robot_dashboard": "cyber_robot_dashboard.png",
    "shield": "cyber_shield.png",
    "lock": "cyber_lock.png",
    "cloud_shield": "cyber_cloud_shield.png",
    "secure_document": "cyber_secure_document.png",
    "url_scanner_photo": "cyber_url_scanner.png",
    "robot_time_navigator": "cyber_robot_time_navigator.png",
}


def photo_path(name: str) -> "Path | None":
    """Resolve a PHOTO_ILLUSTRATIONS name to its real file on disk, or
    None if the name is unknown or the file genuinely isn't there -
    never a guessed/fabricated path."""
    filename = PHOTO_ILLUSTRATIONS.get(name)
    if not filename:
        return None
    path = _ASSETS_DIR / filename
    return path if path.is_file() else None


def render_photo(name: str, width: int = 140) -> bool:
    """Render a real illustration PNG via st.image() (which preserves
    its transparent background and aspect ratio natively - no CSS
    needed for either). Returns True if it actually rendered something,
    False if the file was missing, so a caller can fall back to plain
    text instead of leaving an unexplained gap or faking a substitute."""
    path = photo_path(name)
    if path is None:
        return False
    st.image(str(path), width=width)
    return True


_INTRO_ICON_PULSE = (
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" '
    'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3 19 6v6c0 5-3 8-7 9-4-1-7-4-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'
)


def render_intro_banner(caption: str, photo: str, *, width: int = 120, accent: str = "#0EA5E9"):
    """A page's existing real caption line, with a small real
    illustration placed beside it, inside one elegant horizontal card
    (gradient border, soft shadow, hover lift - see utils/theme.py's
    .st-key-page_intro_card rule) - used in place of a bare
    st.caption() call on pages whose page-identity title already lives
    in the global header (utils/page_ui.py's render_top_bar()), so
    this never reintroduces a second title/heading. Degrades to the
    exact same plain caption (no card) if the photo is missing, rather
    than showing an empty frame around nothing.

    `accent` colours this card to match the CALLING page's own real
    identity colour (the same one utils/page_ui.py's PAGE_META already
    assigns that page's header icon/border) - not imported directly
    here to avoid a circular import (page_ui.py already imports FROM
    this module), so each of the 5 call sites passes its own page's
    accent literally. A small pulsing status-shield badge on the left
    gives every card the same "live, real intelligence" identity
    without inventing a fake live counter.

    Shared by Alerts & Incidents, Reports, Compliance Monitoring, Audit
    Logs, and URL Scanner - upgrading this ONE function is what gives
    all 5 pages the same polished horizontal illustration+text card at
    once, instead of five separate near-duplicate layouts."""
    path = photo_path(photo)
    if path is None:
        st.markdown(f'<p class="page-intro-text">{caption}</p>', unsafe_allow_html=True)
        return
    st.markdown(
        f'<style>[data-testid="stMain"] .st-key-page_intro_card,'
        f'[data-testid="stMain"] .st-key-page_intro_card.st-key-page_intro_card {{'
        f'background-image: linear-gradient(120deg, rgba(255,255,255,0.90), {accent}1A 55%, rgba(139,92,246,0.12)),'
        f'linear-gradient(120deg, {accent}, #8B5CF6) !important;'
        f'}}'
        f'[data-testid="stMain"] .st-key-page_intro_card .page-intro-badge {{'
        f'color:{accent} !important; background:{accent}1F !important; border-color:{accent}55 !important;'
        f'}}</style>',
        unsafe_allow_html=True,
    )
    with st.container(key="page_intro_card"):
        cols = st.columns([0.7, 3.3, 1], vertical_alignment="center")
        with cols[0]:
            st.markdown(
                f'<div class="page-intro-badge-wrap"><div class="page-intro-badge">{_INTRO_ICON_PULSE}</div></div>',
                unsafe_allow_html=True,
            )
        with cols[1]:
            st.markdown(f'<p class="page-intro-text">{caption}</p>', unsafe_allow_html=True)
        with cols[2]:
            st.image(str(path), width=width)

_SHIELD_LAPTOP = """
<svg viewBox="0 0 140 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="20" y="10" width="100" height="65" rx="6" stroke="currentColor" stroke-width="2"/>
  <path d="M8 85 L132 85 L122 95 L18 95 Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
  <path d="M70 22 L88 29 V45 C88 56 80 63 70 67 C60 63 52 56 52 45 V29 Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
  <path d="M63 45 L68 51 L79 38" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

_CLOUD_UPLOAD_CSV = """
<svg viewBox="0 0 160 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M45 60 C34 60 27 52 27 42 C27 32 35 25 45 26 C47 16 57 9 68 11 C78 13 85 22 84 32 C92 32 98 38 98 46 C98 54 91 60 83 60 Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
  <path d="M62 48 L62 70 M62 48 L53 57 M62 48 L71 57" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  <rect x="104" y="28" width="44" height="56" rx="4" stroke="currentColor" stroke-width="2"/>
  <line x1="113" y1="42" x2="139" y2="42" stroke="currentColor" stroke-width="1.5"/>
  <line x1="113" y1="52" x2="139" y2="52" stroke="currentColor" stroke-width="1.5"/>
  <line x1="113" y1="62" x2="131" y2="62" stroke="currentColor" stroke-width="1.5"/>
  <line x1="113" y1="72" x2="135" y2="72" stroke="currentColor" stroke-width="1.5"/>
</svg>
"""

_NETWORK_NODES = """
<svg viewBox="0 0 120 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <circle cx="60" cy="18" r="7" stroke="currentColor" stroke-width="2"/>
  <circle cx="18" cy="58" r="7" stroke="currentColor" stroke-width="2"/>
  <circle cx="102" cy="52" r="7" stroke="currentColor" stroke-width="2"/>
  <circle cx="52" cy="90" r="7" stroke="currentColor" stroke-width="2"/>
  <line x1="60" y1="25" x2="22" y2="53" stroke="currentColor" stroke-width="1.5"/>
  <line x1="60" y1="25" x2="98" y2="49" stroke="currentColor" stroke-width="1.5"/>
  <line x1="22" y1="63" x2="49" y2="86" stroke="currentColor" stroke-width="1.5"/>
  <line x1="98" y1="56" x2="55" y2="86" stroke="currentColor" stroke-width="1.5"/>
</svg>
"""

_ANALYTICS_CHART = """
<svg viewBox="0 0 120 90" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M8 82 L8 8" stroke="currentColor" stroke-width="1.5"/>
  <path d="M8 82 L112 82" stroke="currentColor" stroke-width="1.5"/>
  <polyline points="16,65 38,48 58,58 80,28 104,38" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="38" cy="48" r="3" stroke="currentColor" stroke-width="2"/>
  <circle cx="80" cy="28" r="3" stroke="currentColor" stroke-width="2"/>
</svg>
"""

_SERVER_SHIELD = """
<svg viewBox="0 0 160 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="10" y="15" width="55" height="18" rx="3" stroke="currentColor" stroke-width="2"/>
  <rect x="10" y="38" width="55" height="18" rx="3" stroke="currentColor" stroke-width="2"/>
  <rect x="10" y="61" width="55" height="18" rx="3" stroke="currentColor" stroke-width="2"/>
  <circle cx="20" cy="24" r="2" fill="currentColor"/>
  <circle cx="20" cy="47" r="2" fill="currentColor"/>
  <circle cx="20" cy="70" r="2" fill="currentColor"/>
  <line x1="65" y1="47" x2="95" y2="47" stroke="currentColor" stroke-width="1.5" stroke-dasharray="4 3"/>
  <path d="M120 20 L140 28 V46 C140 58 131 66 120 70 C109 66 100 58 100 46 V28 Z" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
  <path d="M112 46 L118 52 L130 38" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

_BROWSER_MAGNIFIER = """
<svg viewBox="0 0 140 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="8" y="8" width="90" height="65" rx="5" stroke="currentColor" stroke-width="2"/>
  <line x1="8" y1="22" x2="98" y2="22" stroke="currentColor" stroke-width="1.5"/>
  <circle cx="16" cy="15" r="2" fill="currentColor"/>
  <circle cx="24" cy="15" r="2" fill="currentColor"/>
  <circle cx="32" cy="15" r="2" fill="currentColor"/>
  <line x1="18" y1="35" x2="70" y2="35" stroke="currentColor" stroke-width="1.5"/>
  <line x1="18" y1="45" x2="85" y2="45" stroke="currentColor" stroke-width="1.5"/>
  <line x1="18" y1="55" x2="60" y2="55" stroke="currentColor" stroke-width="1.5"/>
  <circle cx="100" cy="62" r="18" stroke="currentColor" stroke-width="2.5"/>
  <line x1="113" y1="75" x2="128" y2="90" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
</svg>
"""

_LEGAL_SCALE = """
<svg viewBox="0 0 140 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <line x1="70" y1="15" x2="70" y2="80" stroke="currentColor" stroke-width="2"/>
  <line x1="30" y1="25" x2="110" y2="25" stroke="currentColor" stroke-width="2"/>
  <line x1="40" y1="25" x2="30" y2="50" stroke="currentColor" stroke-width="1.5"/>
  <line x1="40" y1="25" x2="50" y2="50" stroke="currentColor" stroke-width="1.5"/>
  <path d="M30 50 A10 8 0 0 0 50 50" stroke="currentColor" stroke-width="1.5"/>
  <line x1="100" y1="25" x2="90" y2="50" stroke="currentColor" stroke-width="1.5"/>
  <line x1="100" y1="25" x2="110" y2="50" stroke="currentColor" stroke-width="1.5"/>
  <path d="M90 50 A10 8 0 0 0 110 50" stroke="currentColor" stroke-width="1.5"/>
  <line x1="55" y1="82" x2="85" y2="82" stroke="currentColor" stroke-width="2"/>
  <rect x="5" y="55" width="26" height="34" rx="2" stroke="currentColor" stroke-width="1.5"/>
  <line x1="10" y1="63" x2="26" y2="63" stroke="currentColor" stroke-width="1.2"/>
  <line x1="10" y1="70" x2="26" y2="70" stroke="currentColor" stroke-width="1.2"/>
  <line x1="10" y1="77" x2="22" y2="77" stroke="currentColor" stroke-width="1.2"/>
</svg>
"""

_BELL_NETWORK = """
<svg viewBox="0 0 140 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M60 20 C60 12 68 6 76 6 C84 6 92 12 92 20 C92 42 100 50 100 55 L52 55 C52 50 60 42 60 20 Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
  <path d="M68 60 a8 6 0 0 0 16 0" stroke="currentColor" stroke-width="2"/>
  <line x1="76" y1="22" x2="76" y2="36" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="76" cy="43" r="1.6" fill="currentColor"/>
  <circle cx="20" cy="30" r="5" stroke="currentColor" stroke-width="1.8"/>
  <circle cx="15" cy="60" r="5" stroke="currentColor" stroke-width="1.8"/>
  <circle cx="35" cy="75" r="5" stroke="currentColor" stroke-width="1.8"/>
  <line x1="22" y1="34" x2="17" y2="56" stroke="currentColor" stroke-width="1.3"/>
  <line x1="18" y1="64" x2="32" y2="73" stroke="currentColor" stroke-width="1.3"/>
</svg>
"""

_REPORT_CHART = """
<svg viewBox="0 0 140 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="10" y="8" width="60" height="80" rx="4" stroke="currentColor" stroke-width="2"/>
  <line x1="18" y1="22" x2="62" y2="22" stroke="currentColor" stroke-width="1.5"/>
  <line x1="18" y1="30" x2="62" y2="30" stroke="currentColor" stroke-width="1.5"/>
  <line x1="18" y1="38" x2="48" y2="38" stroke="currentColor" stroke-width="1.5"/>
  <line x1="22" y1="78" x2="22" y2="55" stroke="currentColor" stroke-width="4"/>
  <line x1="32" y1="78" x2="32" y2="62" stroke="currentColor" stroke-width="4"/>
  <line x1="42" y1="78" x2="42" y2="48" stroke="currentColor" stroke-width="4"/>
  <line x1="52" y1="78" x2="52" y2="68" stroke="currentColor" stroke-width="4"/>
  <circle cx="105" cy="45" r="24" stroke="currentColor" stroke-width="2"/>
  <path d="M105 21 A24 24 0 0 1 127 55" stroke="currentColor" stroke-width="2.5"/>
</svg>
"""

_TIMELINE_SHIELD = """
<svg viewBox="0 0 140 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <line x1="15" y1="15" x2="15" y2="85" stroke="currentColor" stroke-width="2"/>
  <circle cx="15" cy="20" r="4" fill="currentColor"/>
  <circle cx="15" cy="45" r="4" fill="currentColor"/>
  <circle cx="15" cy="70" r="4" fill="currentColor"/>
  <line x1="25" y1="20" x2="70" y2="20" stroke="currentColor" stroke-width="1.5"/>
  <line x1="25" y1="45" x2="80" y2="45" stroke="currentColor" stroke-width="1.5"/>
  <line x1="25" y1="70" x2="65" y2="70" stroke="currentColor" stroke-width="1.5"/>
  <path d="M105 15 L125 22 V40 C125 52 116 60 105 64 C94 60 85 52 85 40 V22 Z" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
  <path d="M97 40 L103 46 L114 33" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

_GEARS_SHIELD = """
<svg viewBox="0 0 140 100" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <circle cx="40" cy="45" r="18" stroke="currentColor" stroke-width="2"/>
  <circle cx="40" cy="45" r="6" stroke="currentColor" stroke-width="1.8"/>
  <g stroke="currentColor" stroke-width="2">
    <line x1="40" y1="24" x2="40" y2="17"/>
    <line x1="40" y1="66" x2="40" y2="73"/>
    <line x1="19" y1="45" x2="12" y2="45"/>
    <line x1="61" y1="45" x2="68" y2="45"/>
    <line x1="25" y1="30" x2="20" y2="25"/>
    <line x1="55" y1="60" x2="60" y2="65"/>
    <line x1="55" y1="30" x2="60" y2="25"/>
    <line x1="25" y1="60" x2="20" y2="65"/>
  </g>
  <circle cx="78" cy="68" r="11" stroke="currentColor" stroke-width="1.8"/>
  <circle cx="78" cy="68" r="4" stroke="currentColor" stroke-width="1.5"/>
  <path d="M105 15 L123 22 V38 C123 49 115 56 105 60 C95 56 87 49 87 38 V22 Z" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
  <path d="M98 37 L103 43 L113 31" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

# A fuller-colour "hero" illustration (not the thin-line/monochrome
# style above) - a radar sweep scanning a small network, catching one
# flagged node, with a shield at the centre. Used inline (own fixed
# colours, normal document flow) rather than through place(), for a
# page section that wants a real, prominent picture instead of a
# faint decorative corner accent - see RADAR_SCAN_HERO's docstring
# at its one call site (app_pages/threat_detection.py's header).
_RADAR_SCAN_HERO = """
<svg viewBox="0 0 260 200" width="100%" height="100%" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="tdShieldGrad" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0EA5E9"/>
      <stop offset="100%" stop-color="#22D3EE"/>
    </linearGradient>
    <radialGradient id="tdRadarGrad" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#8B5CF6" stop-opacity="0.20"/>
      <stop offset="100%" stop-color="#8B5CF6" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <circle cx="130" cy="100" r="85" fill="url(#tdRadarGrad)"/>
  <circle cx="130" cy="100" r="85" stroke="#8B5CF6" stroke-width="1.5" stroke-dasharray="4 5" opacity="0.45"/>
  <circle cx="130" cy="100" r="60" stroke="#22D3EE" stroke-width="1.5" stroke-dasharray="3 5" opacity="0.40"/>
  <circle cx="130" cy="100" r="35" stroke="#0EA5E9" stroke-width="1.5" opacity="0.35"/>

  <path d="M130 100 L130 15 A85 85 0 0 1 203.6 57.5 Z" fill="#22D3EE" opacity="0.16"/>

  <g stroke="#94A3B8" stroke-width="1.2" opacity="0.55">
    <line x1="130" y1="100" x2="130" y2="28"/>
    <line x1="130" y1="100" x2="205" y2="100"/>
    <line x1="130" y1="100" x2="80" y2="155"/>
    <line x1="130" y1="100" x2="185" y2="155"/>
  </g>

  <circle cx="130" cy="28" r="6" fill="#0EA5E9"/>
  <circle cx="80" cy="155" r="6" fill="#8B5CF6"/>
  <circle cx="185" cy="155" r="6" fill="#22D3EE"/>

  <circle cx="205" cy="100" r="6" fill="#22D3EE"/>
  <circle cx="205" cy="100" r="12" fill="none" stroke="#DC2626" stroke-width="1.6" opacity="0.85"/>
  <path d="M200.5 95.5 L209.5 104.5 M209.5 95.5 L200.5 104.5" stroke="#DC2626" stroke-width="1.8" stroke-linecap="round"/>

  <g transform="translate(25,63)">
    <path d="M105 15 L123 22 V38 C123 49 115 56 105 60 C95 56 87 49 87 38 V22 Z" fill="url(#tdShieldGrad)" stroke="#0EA5E9" stroke-width="1.5" stroke-linejoin="round"/>
    <path d="M98 37 L103 43 L113 31" stroke="#FFFFFF" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
  </g>
</svg>
"""

# Decorative background layer for the dark sidebar (app.py renders
# this once, absolutely positioned behind the nav via
# utils/theme.py's .sidebar-network-bg rule) - a few glowing particles
# plus thin circuit-style lines near the top and flowing curves near
# the bottom, echoing the reference design's network motif. Deliberately
# low-opacity and stroke-only (never a filled shape over real content)
# so nav text/icons stay fully readable above it; `preserveAspectRatio
# ="none"` lets it stretch to the sidebar's actual rendered height
# instead of needing to match one fixed viewport size.
_SIDEBAR_NETWORK_BG = """
<svg class="sidebar-network-bg" viewBox="0 0 300 760" preserveAspectRatio="none"
     fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <g stroke="#22D3EE" stroke-width="1.2" opacity="0.30" stroke-linecap="round">
    <path d="M300 36 L255 36 L255 84 L222 84"/>
    <path d="M300 108 L272 108 L272 150"/>
  </g>
  <g fill="#22D3EE">
    <circle cx="280" cy="18" r="2.6" opacity="0.75"/>
    <circle cx="252" cy="80" r="2" opacity="0.55"/>
    <circle cx="296" cy="168" r="2.2" opacity="0.5"/>
    <circle cx="150" cy="420" r="2" opacity="0.45"/>
    <circle cx="208" cy="470" r="2.4" opacity="0.6"/>
    <circle cx="256" cy="566" r="2" opacity="0.5"/>
    <circle cx="188" cy="648" r="2.6" opacity="0.7"/>
    <circle cx="96" cy="700" r="2" opacity="0.45"/>
  </g>
  <g fill="none" stroke-linecap="round" opacity="0.40">
    <path d="M30 760 C 85 672, 145 698, 185 624 S 258 536, 300 552" stroke="#22D3EE" stroke-width="1.6"/>
    <path d="M0 760 C 65 712, 118 736, 165 676 S 248 592, 300 600" stroke="#0EA5E9" stroke-width="1.2"/>
  </g>
</svg>
"""

ILLUSTRATIONS = {
    "shield_laptop": _SHIELD_LAPTOP,
    "cloud_upload_csv": _CLOUD_UPLOAD_CSV,
    "network_nodes": _NETWORK_NODES,
    "analytics_chart": _ANALYTICS_CHART,
    "server_shield": _SERVER_SHIELD,
    "browser_magnifier": _BROWSER_MAGNIFIER,
    "legal_scale": _LEGAL_SCALE,
    "bell_network": _BELL_NETWORK,
    "report_chart": _REPORT_CHART,
    "timeline_shield": _TIMELINE_SHIELD,
    "gears_shield": _GEARS_SHIELD,
    "radar_scan_hero": _RADAR_SCAN_HERO,
    "sidebar_network_bg": _SIDEBAR_NETWORK_BG,
}


def place(name: str, *, top: str = "8px", right: str = "10px",
          width: str = "100px", height: str = "80px",
          color: str = "#0EA5E9", opacity: float = 0.38) -> str:
    """Return the HTML for one decorative illustration, absolutely
    positioned inside whichever container renders it (that container
    needs position:relative - see utils/theme.py's
    .st-key-td_* rules). `color`/`opacity` keep every illustration a
    clearly-visible but still secondary accent - never a bold
    foreground image that competes with the real content next to it.
    (0.38, not the original 0.16 - the lower value read as "barely
    there" on every page header once actually looked at on screen.)
    The "ai-icon-pulse" class (utils/theme.py) gives it a slow,
    subtle drop-shadow glow pulse - never animates opacity, which
    would otherwise fight the tuned `opacity` value above - and is a
    no-op under prefers-reduced-motion."""
    svg = ILLUSTRATIONS[name]
    return (
        f'<div class="ai-icon-pulse" style="position:absolute; top:{top}; right:{right}; '
        f'width:{width}; height:{height}; color:{color}; opacity:{opacity}; '
        f'pointer-events:none; z-index:0;">{svg}</div>'
    )


# ---------------------------------------------------------------
# Premium feature banner - the "Stay Secure. Stay Ahead." style card
# originally built one-off for the Dashboard (app_pages/dashboard.py's
# _render_bottom_banner(), which now just calls render_premium_banner()
# below). Generalized here so every other page can reuse the exact same
# CSS (.cgb-* classes, utils/theme.py) and HTML structure with its own
# badge text, two-tone heading, description, and 3 feature chips -
# never duplicating the markup per page.
# ---------------------------------------------------------------

def static_asset_url(filename: str):
    """A real 'app/static/<file>' browser-fetchable URL for `filename`
    (served per .streamlit/config.toml's enableStaticServing=true), or
    None if the file genuinely isn't in static/ - never a guessed/
    fabricated path."""
    return f"app/static/{filename}" if (_STATIC_DIR / filename).is_file() else None


BANNER_ICON_SHIELD_CHECK = (
    '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" '
    'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3 19 6v6c0 5-3 8-7 9-4-1-7-4-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'
)
BANNER_ICON_ACTIVITY = (
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
    'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>'
)
BANNER_ICON_CHIP = (
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
    'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="6" y="6" width="12" height="12" rx="2"/>'
    '<path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/></svg>'
)
BANNER_ICON_SEARCH = (
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
    'stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.35-4.35"/></svg>'
)
BANNER_ICON_DOCUMENT = (
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
    'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>'
)
BANNER_ICON_HISTORY = (
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
    'stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/></svg>'
)
BANNER_ICON_SCALE = (
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3v18M5 7l-3 6a3.5 3 0 0 0 6 0zM19 7l-3 6a3.5 3 0 0 0 6 0zM5 7h14M9 3h6"/></svg>'
)
BANNER_ICON_LOCK = (
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
    'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>'
)


def render_premium_banner(*, badge_text: str, heading_main: str, heading_accent: str,
                           description: str, features: list,
                           robot_file: str = "cyber_robot_shield.png",
                           shield_file: str = "cyber_cloud_shield.png"):
    """The shared "Stay Secure. Stay Ahead." style premium banner -
    robot art on the left, a status badge + two-tone heading +
    description + 3 feature chips in the middle, shield art on the
    right - all ONE self-contained HTML block (see
    app_pages/dashboard.py's original _render_bottom_banner() for why:
    a nested st.columns() row here previously picked up this app's own
    default card paint as an unwanted second box).

    `features` is a list of up to 3 (icon_svg, label, accent_class)
    tuples - accent_class is one of "cyan"/"violet"/"teal" (utils/
    theme.py's .cgb-feature-* classes). Silently renders nothing if
    neither image file is in static/ - never a broken image reference."""
    robot_url = static_asset_url(robot_file)
    shield_url = static_asset_url(shield_file)
    if not (robot_url or shield_url):
        return

    robot_html = (
        f'<div class="cgb-art cgb-art-left"><img src="{robot_url}" '
        'alt="AI CyberGuard illustration" /></div>' if robot_url else ""
    )
    shield_html = (
        f'<div class="cgb-art cgb-art-right"><img src="{shield_url}" '
        'alt="AI CyberGuard illustration" /></div>' if shield_url else ""
    )
    badges_html = "".join(
        f'<span class="cgb-feature cgb-feature-{accent}"><span class="cgb-feature-icon">{icon}</span>{label}</span>'
        for icon, label, accent in features
    )

    st.markdown(
        '<div class="cgb-banner">'
        '<div class="cgb-glow cgb-glow-left"></div>'
        '<div class="cgb-glow cgb-glow-right"></div>'
        f"{robot_html}"
        '<div class="cgb-content">'
        f'<span class="cgb-badge">{BANNER_ICON_SHIELD_CHECK} {badge_text}</span>'
        '<h2 class="cgb-heading">'
        f'<span class="cgb-heading-navy">{heading_main}</span> '
        f'<span class="cgb-heading-blue">{heading_accent}</span>'
        '</h2>'
        f'<p class="cgb-desc">{description}</p>'
        f'<div class="cgb-badges">{badges_html}</div>'
        '</div>'
        f"{shield_html}"
        '</div>',
        unsafe_allow_html=True,
    )
