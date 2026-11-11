"""
Login page - "single scene, glass card" (Direction 3).

app.py renders this whenever there is no authenticated user in
st.session_state (after sync_google_session() has already had a chance to
bridge in a Google identity - see auth/authentication.py). On a successful
manual login it calls st.rerun(), which re-executes app.py from the top -
this time is_authenticated() is True, so app.py shows the application
instead of this form. A successful Google login instead triggers
Streamlit's own redirect flow (st.login()); the bridging happens on the run
after the user comes back.

AN EARLIER VERSION of this page put four capability "HUD" cards, a
three-feature row and a decorative traffic chart around the form, then
removed all of it down to two bare lines of text (see git-less history:
there is no repo here, so nothing to literally restore) because the chart
implied "live" numbers it didn't have and needed a "DEMO DATA" badge to
say so. The four cards and the three-feature row are back below, rebuilt
from real app content - the exact same page names/colors _QUICK_ACTIONS
uses on the Dashboard (app_pages/dashboard.py), so "what this app does" on
the login screen and inside it never disagree. The chart is NOT back at
all - a prior pass replaced it with the real 4-stage detection pipeline
(app_pages/threat_detection.py's own _ENGINE_STAGES) as a plain stage
list, which was later removed by request, leaving the robot hero art as
the aside's only decorative element.

Two authentication paths, both landing in the same st.session_state
contract every page relies on:
  - "Continue with Google" - real OIDC via st.login(), never a fake gate
  - Email/username + password - this project's own bcrypt-backed login,
    either an existing account or a new one created in the second tab

No "Remember me" or "Forgot password" controls: neither has a real backing
implementation, and faking either would be fake functionality.

Both tabs render their own heading so the heading can never disagree with
the visible tab.

ACCESSIBILITY / LAYOUT
  Every field keeps a visible label above it (placeholders are format
  examples only). The form column is first in DOM order, so on a narrow
  screen the form comes before the decorative field; on wide screens CSS
  visually reverses the pair so the card sits right of the artwork.
"""
import base64
from pathlib import Path

import streamlit as st

import config
from auth.authentication import login, register_user
from utils.illustrations import static_asset_url

_ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"
# The new cinematic scene, with the previous photographic background kept as
# a fallback so this page still renders if only the old asset is present.
_BACKGROUND_CANDIDATES = (
    _ASSETS_DIR / "login_cyberguard.jpg",
    _ASSETS_DIR / "Background_login.png",
)

_ICON_SHIELD = (
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
    '<path d="M12 2.6 20 5.7v6.1c0 5-3.4 8.5-8 10.3-4.6-1.8-8-5.3-8-10.3V5.7z" '
    'stroke="url(#loginShield)" stroke-width="1.7" stroke-linejoin="round"/>'
    '<path d="M8.7 11.9 11 14.2l4.3-4.4" stroke="#00D9FF" stroke-width="1.9" '
    'stroke-linecap="round" stroke-linejoin="round"/>'
    '<defs><linearGradient id="loginShield" x1="4" y1="2" x2="20" y2="22">'
    '<stop stop-color="#00D9FF"/><stop offset="1" stop-color="#087CFF"/>'
    '</linearGradient></defs></svg>'
)

# Google's standard four-colour "G", used as the sign-in button's brand mark.
_GOOGLE_G = (
    "data:image/svg+xml;utf8,"
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20'>"
    "<path fill='%234285F4' d='M19.6 10.23c0-.68-.06-1.33-.17-1.96H10v3.71h5.4a4.62 4.62 0 0 1-2 3.03v2.52"
    "h3.24c1.9-1.75 2.96-4.33 2.96-7.3z'/>"
    "<path fill='%2334A853' d='M10 20c2.7 0 4.96-.89 6.62-2.42l-3.24-2.52c-.9.6-2.05.96-3.38.96-2.6 0-4.8-1.76"
    "-5.59-4.12H1.07v2.6A10 10 0 0 0 10 20z'/>"
    "<path fill='%23FBBC05' d='M4.41 11.9A5.99 5.99 0 0 1 4.09 10c0-.66.11-1.3.32-1.9V5.49H1.07A10 10 0 0 0 0 10"
    "c0 1.61.39 3.14 1.07 4.51l3.34-2.61z'/>"
    "<path fill='%23EA4335' d='M10 3.98c1.47 0 2.79.5 3.82 1.49l2.87-2.87C14.95.99 12.7 0 10 0A10 10 0 0 0 1.07 "
    "5.49l3.34 2.6C5.2 5.73 7.4 3.98 10 3.98z'/></svg>"
)

# Capability-card icons, single-stroke "currentColor" so each card can tint
# its own icon via a wrapper style= instead of needing 4 separate <svg>
# constants - one shape per real feature, matching PAGE_ICONS'
# (utils/page_ui.py) Material icon choices for the same 4 pages, just
# redrawn as plain stroke SVG since this file renders outside Streamlit's
# own icon font.
_ICON_SHIELD_CHECK = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M12 3 19 6v5c0 5-3 8-7 9-4-1-7-4-7-9V6z"/><path d="M9.2 12l1.8 1.8L15 9.8"/></svg>'
)
_ICON_LINK = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M9 15 15 9"/><path d="M10.3 6.3 12 4.6a3.6 3.6 0 0 1 5.1 5.1L15.4 11.5"/>'
    '<path d="M13.7 17.7 12 19.4a3.6 3.6 0 0 1-5.1-5.1l1.7-1.7"/></svg>'
)
_ICON_SCALE = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M12 3v18M4 21h16M9 3h6"/>'
    '<path d="M7 7l-3.5 6.5a3.5 3.5 0 0 0 7 0L7 7zM17 7l-3.5 6.5a3.5 3.5 0 0 0 7 0L17 7z"/></svg>'
)
_ICON_DOC = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/><path d="M9.5 13h5M9.5 16.5h5"/></svg>'
)

# (title, accent hex, icon, one honest sentence) - same 4 pages, same accent
# colors, as dashboard.py's _QUICK_ACTIONS, so this screen never claims a
# capability the app doesn't have or describes it differently in two places.
_CAPABILITY_CARDS = (
    ("Threat Detection", "#3B82F6", _ICON_SHIELD_CHECK,
     "Classifies uploaded network traffic as benign or malicious with a trained ML model."),
    ("URL Scanner", "#8B5CF6", _ICON_LINK,
     "Checks a submitted URL against VirusTotal and flags it by risk category."),
    ("Compliance Monitoring", "#EC4899", _ICON_SCALE,
     "Runs rule-based checks against your data and reports pass/fail findings."),
    ("Reports & Audit Logs", "#F97316", _ICON_DOC,
     "Exportable summaries plus a full audit trail of what ran, and when."),
)


@st.cache_data
def _load_background_base64() -> str | None:
    """Read+base64-encode the background once per process, not once per
    rerun - Streamlit CSS can't reference a local filesystem path."""
    for path in _BACKGROUND_CANDIDATES:
        if path.exists():
            return base64.b64encode(path.read_bytes()).decode("utf-8")
    return None


_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

:root {
    --cg-deep: #020B18;
    --cg-navy: #06172B;
    --cg-blue: #087CFF;
    --cg-cyan: #00D9FF;
    --cg-text: #F5FAFF;
    --cg-muted: #A9C7E8;
}

/* ---------- background scene ---------- */
#login-scene {
    position: fixed;
    inset: 0;
    background-size: cover;
    background-position: center;
    z-index: -2;
    pointer-events: none;
}
/* Heavier on the left where the copy sits, lighter through the middle so
   the city detail stays visible behind the card. Lightened twice now
   from the original 0.92/0.80/0.58/0.74 - still read as too dark after
   the first pass, so this is a much bigger cut, not an incremental one.
   The content surfaces below (cards/text) got their own contrast
   bumped to compensate, since a much brighter city behind them would
   otherwise wash them out. */
#login-scene::after {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(
        100deg,
        rgba(2, 11, 24, 0.52) 0%,
        rgba(2, 11, 24, 0.38) 34%,
        rgba(2, 11, 24, 0.22) 62%,
        rgba(2, 11, 24, 0.36) 100%
    );
}
[data-testid="stAppViewContainer"], [data-testid="stApp"],
[data-testid="stMain"], [data-testid="stHeader"] {
    background: transparent !important;
}
[data-testid="stMain"] .block-container {
    max-width: 1220px;
    padding: 7vh 2rem 3rem 2rem;
}
html, body, [data-testid="stAppViewContainer"], .stMarkdown p, label, input, button {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}

/* Form column is first in the DOM so narrow screens get the form first;
   wide screens reverse the pair so the card sits right of the artwork. */
[data-testid="stMain"] [data-testid="stHorizontalBlock"]:has(.st-key-login_card) {
    flex-direction: row-reverse;
    align-items: center;
    gap: 3.5rem;
}

/* ---------- left field: statements + capability cards ---------- */
.login-aside { max-width: 560px; }
.login-aside-rule {
    width: 100%;
    height: 1px;
    background: rgba(199, 219, 240, 0.30);
    margin-bottom: 1.15rem;
}
.login-aside-lead {
    font-size: 2.6rem;
    font-weight: 300;
    line-height: 1.12;
    letter-spacing: -0.02em;
    margin: 0;
    background: linear-gradient(100deg, #FFFFFF 0%, #7DE6FF 55%, #B9A3FF 100%);
    background-clip: text;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 2px 18px rgba(0, 217, 255, 0.22)) drop-shadow(0 2px 10px rgba(2, 11, 24, 0.55));
}
.login-aside-lead strong {
    font-weight: 700;
}
.login-aside-sub {
    font-size: 1.05rem;
    font-weight: 300;
    line-height: 1.5;
    letter-spacing: -0.005em;
    color: #C7DBF0;
    margin: 0.65rem 0 0.1rem;
    text-shadow: 0 1px 8px rgba(2, 11, 24, 0.85);
}

/* ---------- hero robot: the hand-off between the statement text and
   the rest of the aside. A pulsing radial glow + a slow dashed orbit
   ring behind a gently floating robot - all motion is slow (3.4s+,
   never a bounce/spin that reads as a toy) and fully disabled under
   prefers-reduced-motion, same convention utils/theme.py's own
   ai-float/ai-icon-pulse animations use everywhere else in the app. ---------- */
.login-hero-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.25rem;
    margin-bottom: 0.3rem;
}
.login-hero-text { flex: 1 1 auto; min-width: 0; }
.login-hero-art {
    position: relative;
    flex: 0 0 auto;
    width: 136px;
    height: 136px;
    display: flex;
    align-items: center;
    justify-content: center;
}
.login-hero-glow {
    position: absolute;
    inset: 6px;
    border-radius: 50%;
    background: radial-gradient(circle,
        rgba(0, 217, 255, 0.30) 0%, rgba(0, 217, 255, 0.10) 45%, transparent 72%);
    animation: cg-pulse-glow 3.4s ease-in-out infinite;
}
.login-hero-orbit {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    border: 1px dashed rgba(139, 92, 246, 0.38);
    animation: cg-spin-orbit 16s linear infinite;
}
.login-hero-orbit::before, .login-hero-orbit::after {
    content: "";
    position: absolute;
    width: 5px; height: 5px;
    border-radius: 50%;
    background: var(--cg-cyan);
    box-shadow: 0 0 8px 1px rgba(0, 217, 255, 0.7);
}
.login-hero-orbit::before { top: -2.5px; left: calc(50% - 2.5px); }
.login-hero-orbit::after { bottom: 6px; right: 2px; background: #8B5CF6; box-shadow: 0 0 8px 1px rgba(139, 92, 246, 0.7); }
.login-hero-robot {
    position: relative;
    width: 108px;
    height: auto;
    filter: drop-shadow(0 10px 22px rgba(0, 217, 255, 0.32));
    animation: cg-float-robot 4.6s ease-in-out infinite;
}
@keyframes cg-pulse-glow {
    0%, 100% { transform: scale(0.9); opacity: 0.7; }
    50% { transform: scale(1.08); opacity: 1; }
}
@keyframes cg-spin-orbit {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}
@keyframes cg-float-robot {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-10px); }
}
@media (prefers-reduced-motion: reduce) {
    .login-hero-glow, .login-hero-orbit, .login-hero-robot { animation: none !important; }
}
@media (max-width: 1100px) {
    .login-hero-art { width: 108px; height: 108px; }
    .login-hero-robot { width: 86px; }
}

/* Three-feature row - the same "Secure / Detect / Comply" tagline used in
   the authenticated sidebar (app.py's _BRAND_HTML), so the brand line
   reads the same before and after login. */
.login-feature-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 1.1rem 0 1.5rem;
}
.login-feature-pill {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.32rem 0.75rem;
    border-radius: 999px;
    border: 1px solid rgba(169, 199, 232, 0.32);
    background: rgba(6, 23, 43, 0.55);
    backdrop-filter: blur(6px);
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: #C7DBF0;
}
.login-feature-pill-dot {
    width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto;
}

/* Four capability cards - real features, real accent colors (same hexes
   dashboard.py's _QUICK_ACTIONS uses for these same 4 pages). */
.login-capability-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.7rem;
    margin-bottom: 1.5rem;
}
.login-cap-card {
    background: rgba(6, 23, 43, 0.58);
    border: 1px solid rgba(169, 199, 232, 0.22);
    border-radius: 12px;
    padding: 0.8rem 0.9rem;
    backdrop-filter: blur(6px);
}
.login-cap-card-icon {
    width: 30px; height: 30px; border-radius: 9px;
    display: flex; align-items: center; justify-content: center;
    margin-bottom: 0.55rem;
}
.login-cap-card-icon svg { width: 17px; height: 17px; }
.login-cap-title {
    font-size: 0.84rem; font-weight: 700; color: var(--cg-text); margin: 0 0 0.2rem;
}
.login-cap-desc {
    font-size: 0.72rem; line-height: 1.45; color: #9FB8D4; margin: 0;
}

/* ---------- glass card ---------- */
.st-key-login_card {
    background: linear-gradient(160deg, rgba(18, 45, 76, 0.90) 0%, rgba(6, 23, 43, 0.95) 100%) !important;
    border: 1px solid rgba(0, 217, 255, 0.28) !important;
    border-radius: 20px !important;
    box-shadow: 0 10px 46px rgba(0, 0, 0, 0.55);
    padding: 2.1rem 2.3rem 1.9rem !important;
    max-width: 520px;
    margin-left: auto;
}
.cg-brand { display: flex; align-items: center; gap: 11px; }
.cg-brand svg { width: 32px; height: 32px; flex: 0 0 32px; }
.cg-brand-name {
    font-size: 18px; font-weight: 700; letter-spacing: -0.01em;
    color: var(--cg-text); margin: 0;
}
.cg-heading {
    font-size: 1.6rem; font-weight: 600; letter-spacing: -0.015em;
    color: var(--cg-text); margin: 1.3rem 0 0.3rem;
}
.cg-heading-sub {
    font-size: 0.94rem; color: #8FAAC6; margin: 0 0 0.5rem; line-height: 1.5;
}

/* Tabs */
.st-key-login_tabs [data-baseweb="tab-list"] {
    gap: 1.6rem;
    border-bottom: 1px solid rgba(169, 199, 232, 0.18);
    margin-top: 1rem;
}
.st-key-login_tabs [role="tab"] {
    padding: 0.3rem 0 0.55rem;
    color: #8FAAC6 !important;
    font-size: 0.98rem; font-weight: 500 !important;
}
.st-key-login_tabs [role="tab"][aria-selected="true"] { color: var(--cg-text) !important; font-weight: 600 !important; }
.st-key-login_tabs [data-baseweb="tab-highlight"] { background-color: var(--cg-cyan) !important; height: 2px; }
.st-key-login_tabs [data-baseweb="tab-panel"] { padding-top: 1.1rem; }

/* Labels sit above inputs, always visible. */
.st-key-login_card label p {
    color: #C7DBF0 !important;
    font-size: 0.88rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.01em;
}
.st-key-login_card [data-testid="stTooltipIcon"] { display: none; }

/* Inputs */
.st-key-login_card input {
    background-color: rgba(2, 11, 24, 0.55) !important;
    color: var(--cg-text) !important;
    border: 1px solid rgba(169, 199, 232, 0.22) !important;
    border-radius: 10px !important;
    font-size: 1rem !important;
    height: 3rem !important;
}
.st-key-login_card input::placeholder { color: #6B88A8 !important; }
.st-key-login_card input:focus {
    border-color: var(--cg-cyan) !important;
    box-shadow: 0 0 0 1px var(--cg-cyan) !important;
}
.st-key-login_card [data-testid="stTextInputRootElement"] {
    background: transparent !important;
    border: 0 !important;
}
.st-key-login_card svg { fill: #8FAAC6 !important; }

/* Primary action */
.st-key-login_submit button, .st-key-create_submit button {
    background: linear-gradient(135deg, var(--cg-cyan), var(--cg-blue)) !important;
    color: #04111F !important;
    font-weight: 600 !important;
    font-size: 1rem !important;
    border: 0 !important;
    border-radius: 10px !important;
    box-shadow: 0 4px 18px rgba(0, 217, 255, 0.28);
    height: 3rem;
}
.st-key-login_submit button:hover, .st-key-create_submit button:hover { filter: brightness(1.07); }
.st-key-login_submit button:disabled, .st-key-create_submit button:disabled {
    opacity: 0.55; cursor: not-allowed; box-shadow: none; filter: none;
}

/* Google option: white provider button, above the password fields */
.st-key-google_login_btn button, .st-key-google_create_btn button {
    background-color: #FFFFFF !important;
    background-image: url("__GOOGLE_G__");
    background-repeat: no-repeat;
    background-position: 18px center;
    background-size: 19px 19px;
    color: #1F2937 !important;
    border: 1px solid #DADCE0 !important;
    border-radius: 10px !important;
    font-weight: 500 !important;
    font-size: 0.96rem !important;
    height: 2.8rem;
    padding-left: 48px !important;
    justify-content: center;
}
.st-key-google_login_btn button:hover, .st-key-google_create_btn button:hover {
    background-color: #F8F9FA !important;
}
.st-key-google_login_btn button:disabled, .st-key-google_create_btn button:disabled {
    background-color: #E2E8F0 !important; color: #64748B !important;
    background-image: none;
}

.cg-separator {
    display: flex; align-items: center; gap: 0.7rem;
    color: #7C96B4; font-size: 0.78rem; letter-spacing: 0.05em;
    margin: 1.1rem 0 0.7rem;
}
.cg-separator::before, .cg-separator::after {
    content: ""; flex: 1; height: 1px; background: rgba(169, 199, 232, 0.20);
}
.cg-helper {
    font-size: 0.8rem; line-height: 1.55; color: #7C96B4;
    margin: 0.9rem 0 0;
    padding-top: 0.8rem;
    border-top: 1px solid rgba(169, 199, 232, 0.14);
}
/* Alerts inside the dark card */
.st-key-login_card [data-testid="stAlert"] {
    background: rgba(220, 38, 38, 0.12) !important;
    border: 1px solid rgba(248, 113, 113, 0.35) !important;
    border-radius: 9px;
}
.st-key-login_card [data-testid="stAlert"] p {
    color: #FCA5A5 !important; font-size: 0.78rem !important;
}
.st-key-login_card [data-testid="stAlert"]:has(svg[data-testid="stAlertContentSuccess"]) p,
.st-key-login_card [data-testid="stAlertContainer"] [data-testid="stAlertContentSuccess"] p {
    color: #86EFAC !important;
}

/* Focus rings must survive the custom borders */
.st-key-login_card button:focus-visible,
.st-key-login_card input:focus-visible,
.st-key-login_tabs [role="tab"]:focus-visible {
    outline: 2px solid var(--cg-cyan) !important;
    outline-offset: 2px;
}

@media (prefers-reduced-motion: no-preference) {
    @keyframes cg-fade { from { opacity: 0; } to { opacity: 1; } }
    .st-key-login_card { animation: cg-fade 460ms ease-out both; }
    .login-aside { animation: cg-fade 560ms ease-out both; }
}

/* Base (hidden) state for the compact mobile-robot stand-in - this MUST
   come BEFORE the @media block below that turns it on. Both rules
   target the same .login-mobile-robot selector with equal specificity,
   so CSS resolves the tie by source order, not by which media query
   "sounds" more specific - defining the unconditional display:none
   AFTER the conditional display:flex silently made the override always
   win, so the robot never actually appeared regardless of window width
   (the bug behind "why it still the same"). */
.login-mobile-robot {
    display: none;
    flex-direction: column;
    align-items: center;
    gap: 0.6rem;
    text-align: center;
    margin-bottom: 0.3rem;
}
.login-mobile-robot .login-hero-art { width: 168px; height: 168px; }
.login-mobile-robot .login-hero-robot { width: 132px; }
.login-mobile-robot-text {
    font-size: 2rem;
    font-weight: 300;
    letter-spacing: -0.02em;
    line-height: 1.15;
    margin: 0;
    background: linear-gradient(100deg, #FFFFFF 0%, #7DE6FF 55%, #B9A3FF 100%);
    background-clip: text;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 2px 16px rgba(0, 217, 255, 0.28));
}
.login-mobile-robot-text strong { font-weight: 700; }
.login-mobile-robot-sub {
    font-size: 0.95rem;
    font-weight: 300;
    color: #C7DBF0;
    margin: 0;
    text-shadow: 0 1px 8px rgba(2, 11, 24, 0.85);
}

@media (max-width: 640px) {
    .login-mobile-robot .login-hero-art { width: 120px; height: 120px; }
    .login-mobile-robot .login-hero-robot { width: 94px; }
    .login-mobile-robot-text { font-size: 1.5rem; }
}

/* Below 900px the full aside (headline + pills + 4 cards) genuinely
   doesn't fit, so it still hides - but hiding it left a big
   empty stretch beside a narrow, off-center card ("make this part
   longer... doesn't look empty"). Two fixes: the card itself is now
   wider and actually centered (it was flush-left with max-width:none,
   which - combined with align-items:center still applying from the
   desktop rule above - left it shrink-wrapped off to one side instead
   of using the space), and the compact standalone robot + tagline
   above now fills the space above it down to 480px, where it hides
   again rather than cramming onto a true phone screen. */
@media (max-width: 900px) {
    [data-testid="stMain"] .block-container { padding: 1.5rem 1rem 2.5rem; }
    [data-testid="stMain"] [data-testid="stHorizontalBlock"]:has(.st-key-login_card) {
        flex-direction: column;
        align-items: center;
        gap: 1.25rem;
    }
    .st-key-login_card { max-width: 680px; width: 100%; margin: 0 auto; }
    .login-aside { display: none; }
    .login-mobile-robot { display: flex; }
}

@media (max-width: 480px) {
    .login-mobile-robot { display: none; }
}
</style>
"""


def _inject_styles():
    encoded = _load_background_base64()
    scene_css = (
        f"<style>#login-scene {{ background-image: url('data:image/jpeg;base64,{encoded}'); }}</style>"
        if encoded else ""
    )
    scene_div = '<div id="login-scene"></div>' if encoded else ""
    st.markdown(
        _CSS.replace("__GOOGLE_G__", _GOOGLE_G) + scene_css + scene_div,
        unsafe_allow_html=True,
    )


def render_login_page():
    _inject_styles()

    form_col, aside_col = st.columns([0.8, 1.2], gap="large")

    with form_col:
        st.markdown(_render_mobile_robot_html(), unsafe_allow_html=True)
        with st.container(key="login_card"):
            st.markdown(
                f'<div class="cg-brand">{_ICON_SHIELD}'
                f'<p class="cg-brand-name">AI CyberGuard</p></div>',
                unsafe_allow_html=True,
            )
            tab_login, tab_create = st.tabs(["Login", "Create account"], key="login_tabs")
            with tab_login:
                _render_login_tab()
            with tab_create:
                _render_create_tab()

    with aside_col:
        st.markdown(_render_aside_html(), unsafe_allow_html=True)


# ---------------------------------------------------------------
# Aside content - 3 brand pills, 4 real capability cards. See this
# module's own docstring for why.
# ---------------------------------------------------------------

_FEATURE_PILLS = (("Secure", "#22D3EE"), ("Detect", "#0EA5E9"), ("Comply", "#8B5CF6"))


def _render_aside_html() -> str:
    pills = "".join(
        f'<span class="login-feature-pill">'
        f'<span class="login-feature-pill-dot" style="background:{color}"></span>{label}</span>'
        for label, color in _FEATURE_PILLS
    )
    cards = "".join(
        f'<div class="login-cap-card">'
        f'<div class="login-cap-card-icon" style="background:{accent}1F; color:{accent}">{icon}</div>'
        f'<p class="login-cap-title">{title}</p>'
        f'<p class="login-cap-desc">{desc}</p>'
        f'</div>'
        for title, accent, icon, desc in _CAPABILITY_CARDS
    )
    robot_url = static_asset_url("cyber_robot_shield.png")
    hero_art = (
        f'<div class="login-hero-art">'
        f'<div class="login-hero-glow"></div>'
        f'<div class="login-hero-orbit"></div>'
        f'<img class="login-hero-robot" src="{robot_url}" '
        f'alt="AI CyberGuard robot" /></div>'
    ) if robot_url else ""
    return (
        '<div class="login-aside">'
        '<div class="login-hero-row">'
        '<div class="login-hero-text">'
        '<div class="login-aside-rule"></div>'
        '<p class="login-aside-lead">Stay <strong>Ahead</strong> of Every Threat.</p>'
        '<p class="login-aside-sub">AI-powered detection. Real compliance checks.</p>'
        '</div>'
        f'{hero_art}'
        '</div>'
        f'<div class="login-feature-row">{pills}</div>'
        f'<div class="login-capability-grid">{cards}</div>'
        '</div>'
    )


def _render_mobile_robot_html() -> str:
    """Compact stand-in for the full aside (CSS-hidden below 900px, see
    .login-mobile-robot) - the same floating/glow/orbit robot and a
    short tagline, without the 4 capability cards, which need real
    width to not look cramped. Fills the empty space a hidden aside
    otherwise left above the card on a narrower window."""
    robot_url = static_asset_url("cyber_robot_shield.png")
    if not robot_url:
        return ""
    return (
        '<div class="login-mobile-robot">'
        '<div class="login-hero-art">'
        '<div class="login-hero-glow"></div>'
        '<div class="login-hero-orbit"></div>'
        f'<img class="login-hero-robot" src="{robot_url}" alt="AI CyberGuard robot" />'
        '</div>'
        '<p class="login-mobile-robot-text">Stay <strong>Ahead</strong> of Every Threat.</p>'
        '<p class="login-mobile-robot-sub">AI-powered detection. Real-time defense.</p>'
        '</div>'
    )


def _heading(title: str, subtitle: str):
    st.markdown(
        f'<p class="cg-heading">{title}</p>'
        f'<p class="cg-heading-sub">{subtitle}</p>',
        unsafe_allow_html=True,
    )


def _render_google_option(key: str) -> bool:
    """Real OIDC entry point. Returns False (renders nothing at all) when
    Google sign-in isn't configured - a public deployment without OAuth
    set up shouldn't show a dead button or explain internal env var names
    to anonymous visitors; the email/username + password path still works
    either way, so there's nothing broken to call out here. Returns True
    when it actually rendered a usable button, so the caller knows
    whether a separator below it still makes sense."""
    if not config.has_google_oauth_configured():
        return False
    if st.button("Continue with Google", width="stretch", key=key):
        st.login("google")
    return True


def _separator():
    st.markdown('<p class="cg-separator">or use your account</p>', unsafe_allow_html=True)


# ---------------------------------------------------------------
# Login tab
# ---------------------------------------------------------------

def _render_login_tab():
    _heading("Login to your workspace", "Accounts are issued by an administrator.")

    if _render_google_option("google_login_btn"):
        _separator()

    with st.form("login_form"):
        identifier = st.text_input(
            "Email or username",
            placeholder="admin or you@example.com",
            autocomplete="username",
        )
        password = st.text_input(
            "Password",
            type="password",
            autocomplete="current-password",
            placeholder="",
        )
        submitted = st.form_submit_button(
            "Login", width="stretch", key="login_submit"
        )

    if submitted:
        if not identifier or not password:
            st.error("Please enter both your email/username and password.")
            return

        db_error = None
        success = False
        block_message = None
        try:
            success, block_message = login(identifier, password)
        except Exception:
            db_error = (
                "Could not connect to the database. Make sure MySQL is running "
                "and your .env settings are correct."
            )

        if success:
            st.success("Login successful.")
            st.rerun()
        elif db_error:
            st.error(db_error)
        elif block_message:
            st.error(block_message)
        else:
            st.error("Invalid email/username or password.")

    st.markdown(
        '<p class="cg-helper">Sessions expire after 60 minutes of inactivity. '
        'Repeated failed attempts from the same account or address are rate-limited.</p>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------
# Create-account tab
# ---------------------------------------------------------------

def _render_create_tab():
    _heading("Create an account",
             "New accounts start with the USER role and see only their own data.")

    if _render_google_option("google_create_btn"):
        _separator()

    with st.form("create_account_form", clear_on_submit=True):
        full_name = st.text_input("Full name", placeholder="Your full name",
                                  autocomplete="name")
        email = st.text_input("Email", placeholder="you@example.com",
                              autocomplete="email")
        password = st.text_input(
            "Password",
            type="password",
            placeholder="At least 8 characters",
            autocomplete="new-password",
        )
        confirm_password = st.text_input(
            "Confirm password",
            type="password",
            placeholder="Re-enter your password",
            autocomplete="new-password",
        )
        submitted = st.form_submit_button(
            "Create account", width="stretch", key="create_submit"
        )

    if submitted:
        try:
            success, message = register_user(full_name, email, password, confirm_password)
        except Exception:
            success, message = False, (
                "Could not connect to the database. Make sure MySQL is running "
                "and your .env settings are correct."
            )

        if success:
            st.success(message)
        else:
            st.error(message)

    st.markdown(
        '<p class="cg-helper">Passwords are stored as bcrypt hashes. An administrator '
        'can change your role after you register.</p>',
        unsafe_allow_html=True,
    )
