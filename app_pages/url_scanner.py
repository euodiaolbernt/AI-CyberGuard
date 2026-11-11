"""
URL Scanner page (Step 6).

Interface: enter a URL, click "SCAN URL", see a VirusTotal-based
threat-intelligence result. This page never opens, browses, downloads,
or executes the submitted URL - it only ever hands the URL string to
security/url_scanner.py, which in turn only ever talks to the
VirusTotal API (never the URL itself).

Every completed scan is written to url_scan_results (which is what
feeds the Dashboard's "URLs Scanned" / "High Risk Events" KPIs), is
evaluated by the compliance engine (Step 7 - ISO27001/NIST always run,
PDPA/GDPR only when the scan is MALICIOUS), can create an alert (Step
8 - risk_score >= 80), and is written to the audit log.

WHAT THIS PAGE DOES NOT SHOW, AND WHY: a common URL-scanner reference
design includes a "Technical Details" panel (domain WHOIS, IP address,
country, SSL certificate chain) and a named "Security Sources" list
(Google Safe Browsing, PhishTank, SSL Analysis, Domain Reputation as
separate checks). This app only ever calls VirusTotal's /urls and
/analyses endpoints (security/virustotal.py) - it never performs WHOIS,
DNS, or certificate lookups, and VirusTotal's response here doesn't
include that data either. Faking it would violate this project's own
"never invent data" rule, so it's simply not shown. What IS real and
IS shown: VirusTotal's own per-vendor engine verdicts (many of VT's
~70 engines ARE named security vendors, e.g. "Google Safebrowsing",
"Kaspersky", "PhishTank" among them - see _ENGINE_BADGE below), which
is the closest honest equivalent to a "security sources" breakdown.

RISK, NOT "SAFETY": this page shows a Risk Score (0-100, higher = MORE
dangerous) with LOW/MEDIUM/HIGH/CRITICAL bands, the same scale and
colours as the rest of the app (Dashboard, Threat Detection, Alerts).
A reference design's inverted "0-10 Safety Score" (higher = safer)
would mean a single widget speaks a different, backwards vocabulary
from every other page - confusing, and risks a HIGH risk_score being
misread as a HIGH safety score. Kept consistent instead.
"""
from datetime import timezone

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import config
from auth.rate_limit import check_and_bump_cooldown
from compliance.compliance_engine import build_url_event, process_security_event
from database.models import get_url_scans_in_range, insert_url_scan_result
from security.url_scanner import scan_url
from utils.audit_logger import log_action
from utils.illustrations import place as _illustration
from utils.illustrations import (
    BANNER_ICON_ACTIVITY,
    BANNER_ICON_SEARCH,
    BANNER_ICON_SHIELD_CHECK,
    photo_path,
    render_intro_banner,
    render_premium_banner,
)
from utils.page_ui import render_empty_state
from utils.time_navigator import get_active_range

# Real backend states (security/url_scanner.py's scan_status) plus the
# page-level PENDING/FAILED/UNAVAILABLE distinctions _display_status()
# derives from a SCAN_ERROR's own error text - never a new backend
# state, purely a richer UI label for the one "error" bucket the
# backend already returns (requirement: "Scan status: pending,
# completed, failed, or unavailable").
STATUS_DISPLAY = {
    "SAFE": (":material/check_circle:", "SAFE", "#22C55E", "#ECFDF5"),
    "SUSPICIOUS": (":material/warning:", "SUSPICIOUS", "#F59E0B", "#FFFBEB"),
    "MALICIOUS": (":material/gpp_bad:", "POTENTIAL MALICIOUS URL", "#DC2626", "#FEF2F2"),
    "PENDING": (":material/hourglass_top:", "ANALYSIS PENDING", "#0EA5E9", "#EFF6FF"),
    "UNAVAILABLE": (":material/cloud_off:", "SCANNER UNAVAILABLE", "#94A3B8", "#F1F5F9"),
    "FAILED": (":material/error:", "SCAN FAILED", "#94A3B8", "#F1F5F9"),
}

RISK_BAND_COLORS = {"LOW": "#22C55E", "MEDIUM": "#F2C94C", "HIGH": "#F97316", "CRITICAL": "#DC2626"}

_ENGINE_CATEGORY_COLORS = {
    "malicious": "#DC2626", "suspicious": "#F59E0B",
    "harmless": "#22C55E", "undetected": "#94A3B8",
}

# One distinct accent per card (blue/cyan/violet/green - the same
# 4-colour rotation already used for Threat Detection's pipeline-stage
# badges, kept consistent app-wide rather than inventing a new palette
# here) - accent_class drives the card's border/background (utils/
# theme.py), accent_hex recolours its own illustration to match.
FEATURES = [
    ("browser_magnifier", "Real-Time URL Analysis", "Checked live against VirusTotal's ~70 security engines.",
     "url-feature-blue", "#0EA5E9"),
    ("analytics_chart", "Risk Classification", "A transparent 0-100 risk score with LOW-CRITICAL bands.",
     "url-feature-cyan", "#22D3EE"),
    ("report_chart", "Detailed Results", "Per-engine verdicts and vendor-reported threat categories.",
     "url-feature-violet", "#8B5CF6"),
    ("timeline_shield", "History Tracking", "Every scan you run is kept in Recent Scans below.",
     "url-feature-green", "#22C55E"),
]


def render_url_scanner_page():
    with st.container(key="url_premium_banner"):
        render_premium_banner(
            badge_text="AI CYBERGUARD &bull; LINK DEFENSE",
            heading_main="Scan Before.", heading_accent="You Click.",
            description="Every URL is checked against real threat intelligence before "
                        "you ever decide whether to trust it.",
            features=[
                (BANNER_ICON_SHIELD_CHECK, "VirusTotal Verified", "cyan"),
                (BANNER_ICON_SEARCH, "Safe Browsing Checked", "violet"),
                (BANNER_ICON_ACTIVITY, "Instant Verdicts", "teal"),
            ],
        )
    render_intro_banner(
        "Threat-intelligence lookup via VirusTotal API v3"
        + (" and Google Safe Browsing" if config.has_safe_browsing_key() else "")
        + ". Submitted URLs are never opened, browsed, or executed by this "
        "application - only checked against real security engines.",
        "robot_scanner", width=130, accent="#14B8A6",  # matches PAGE_META's URL Scanner accent
    )
    _render_scanner_fragment()


@st.fragment
def _render_scanner_fragment():
    """Everything interactive on this page - the scan form, its result,
    and Recent Scans - in ONE fragment, so clicking SCAN URL reruns
    only this section (requirement: "display results without
    unnecessarily rerunning the entire Streamlit application"), not the
    page header, sidebar, or global Cyber Time Navigator above it. A
    scan's own DB writes (insert_url_scan_result, compliance/alert
    evaluation, audit log) still happen for real on every click - a
    fragment only changes WHICH PART of the page redraws afterward,
    never what gets persisted."""
    with st.container(key="page_panel_blue_scan", border=True):
        if not config.has_virustotal_key():
            st.warning(
                "VIRUSTOTAL_API_KEY is not set in your .env file. Get a free key at "
                "virustotal.com/gui/my-apikey to enable scanning."
            )
        elif not config.has_safe_browsing_key():
            st.caption(
                ":material/info: Scanning with VirusTotal only. Add "
                "GOOGLE_SAFE_BROWSING_API_KEY to your .env file to also consult Google "
                "Safe Browsing on every scan."
            )

        url_input = st.text_input(
            ":material/link: Enter a URL to scan", placeholder="https://example.com",
        )
        scan_clicked = st.button(
            "SCAN URL", type="primary", icon=":material/radar:", width="stretch",
            disabled=not config.has_virustotal_key(),
        )

    if scan_clicked:
        _handle_scan(url_input)

    _render_feature_cards()

    result = st.session_state.get("last_url_scan")
    if result is not None:
        _render_result(result)

    st.divider()
    with st.container(key="page_panel_purple_history", border=True):
        st.subheader("Recent Scans", icon=":material/history:")
        _render_history()


def _render_feature_cards():
    cols = st.columns(4)
    for col, (illustration, title, desc, accent_class, accent_hex) in zip(cols, FEATURES):
        # Card key encodes the accent (e.g. "url_feature_blue_...") so
        # utils/theme.py can match it by class SUBSTRING - same
        # convention as the Threat Detection stat cards (td_stat_*) -
        # since every card still needs its OWN unique key.
        slug = title.lower().replace(" ", "_")
        color_name = accent_class.rsplit("-", 1)[-1]
        with col, st.container(key=f"url_feature_{color_name}_{slug}", border=True):
            st.markdown(
                _illustration(illustration, width="60px", height="48px", color=accent_hex, opacity=0.9),
                unsafe_allow_html=True,
            )
            st.markdown(f"**{title}**")
            st.caption(desc)


def _handle_scan(url_input: str):
    # Server-side, database-backed cooldown (not st.session_state) so it
    # can't be reset by opening a new tab, and holds even if two scans
    # from the same user land at nearly the same moment - this is what
    # actually bounds how fast one account can burn through the shared
    # VirusTotal quota, AND what prevents a duplicate double-click
    # submission (the second click always lands inside the cooldown
    # window of the first, so it's rejected the same way).
    user_id = st.session_state.get("user_id")
    allowed, retry_after = check_and_bump_cooldown(
        "URL_SCAN_USER", str(user_id), config.URL_SCAN_COOLDOWN_SECONDS
    )
    if not allowed:
        st.warning(f"Please wait {retry_after} second(s) before scanning another URL.")
        return

    with st.spinner("Checking URL against VirusTotal..."):
        result = scan_url(url_input)

    if result["scan_status"] != "SCAN_ERROR":
        scan_id = insert_url_scan_result(
            url=result["url"],
            scanned_by=st.session_state.get("user_id"),
            scan_status=result["scan_status"],
            threat_category=result["threat_category"],
            detection_count=result["detection_count"],
            total_engines=result["total_engines"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            analysis_reference=result["analysis_reference"],
        )
        log_action(
            st.session_state.get("username", "?"), "URL_SCAN", "URL_SCANNER",
            f"Scanned '{result['url']}' -> {result['scan_status']} "
            f"({result['detection_count']}/{result['total_engines']}).",
        )

        scan_row = dict(result)
        scan_row["id"] = scan_id
        event = build_url_event(scan_row, st.session_state.get("user_id"))
        outcome = process_security_event(event)
        log_action(
            st.session_state.get("username", "?"), "COMPLIANCE_CHECK", "COMPLIANCE",
            f"Evaluated compliance rules for URL scan id={scan_id} "
            f"({len(outcome['compliance_results'])} rule(s) applicable).",
        )
        if outcome["alert_id"] is not None:
            log_action(
                st.session_state.get("username", "?"), "ALERT_CREATED", "ALERTS",
                f"Alert created for URL scan id={scan_id} "
                f"(risk={event['risk_score']}).",
            )
        st.session_state["last_url_scan_alert_id"] = outcome["alert_id"]
    else:
        log_action(
            st.session_state.get("username", "?"), "URL_SCAN_ERROR", "URL_SCANNER",
            f"Scan failed for '{result['url']}': {result['error']}",
        )

    st.session_state["last_url_scan"] = result


def _display_status(result: dict):
    """Map the real backend scan_status (+ its error text, for
    SCAN_ERROR) to the richer pending/failed/unavailable distinction -
    a page-level interpretation only; security/url_scanner.py's own
    4 real states are never changed by this."""
    status = result["scan_status"]
    if status != "SCAN_ERROR":
        return status
    error = (result.get("error") or "").lower()
    if "still analysing" in error or "still analyzing" in error:
        return "PENDING"
    if "not configured" in error:
        return "UNAVAILABLE"
    return "FAILED"


def _truncate_url(url: str, max_len: int = 70) -> str:
    return url if len(url) <= max_len else url[: max_len - 1] + "…"


def _render_result(result: dict):
    st.divider()
    display_status = _display_status(result)
    icon, label, accent, bg = STATUS_DISPLAY[display_status]

    # One dynamically-coloured override for the single result card -
    # a fixed key is safe here since only one result ever renders at
    # a time (st.session_state["last_url_scan"] holds just the most
    # recent scan), so there's no risk of two differently-coloured
    # cards needing the same key in one script run.
    st.markdown(
        f'<style>[data-testid="stMain"] .st-key-url_result_card {{'
        f'background: {bg} !important;'
        f'border-color: {accent}66 !important;'
        f'border-left: 4px solid {accent} !important;'
        f"}}</style>",
        unsafe_allow_html=True,
    )

    with st.container(key="url_result_card", border=True):
        header_cols = st.columns([3, 1.3])
        with header_cols[0]:
            st.subheader("Scan Results", icon=":material/radar:")
            url = result["url"]
            if len(url) > 70:
                st.write(f":material/public: {_truncate_url(url)}")
                with st.expander("Show full URL"):
                    st.code(url, language=None)
            else:
                st.write(f":material/public: {url}")
        with header_cols[1]:
            st.markdown(
                f'<div class="url-status-badge" style="background:{accent}1A;color:{accent};'
                f'border:1px solid {accent}55;">{label}</div>',
                unsafe_allow_html=True,
            )

        if display_status in ("PENDING", "UNAVAILABLE", "FAILED"):
            st.error(result["error"]) if display_status == "FAILED" else st.warning(result["error"])
            return

        _render_result_details(result)


_CATEGORY_ACCENT = {
    "Phishing": "#DC2626", "Defacement": "#B45309", "Malware": "#7C3AED",
    "Suspicious / Other": "#F59E0B", "Benign": "#16A34A",
}


def _explain_verdict(result: dict) -> str:
    """One plain-language sentence grounded entirely in the real
    numbers already in `result` - never a generic canned line that
    doesn't actually reflect this scan's own evidence."""
    malicious_n = result["detection_count"] or 0
    total = result["total_engines"] or 0
    gsb_hits = result.get("safe_browsing_threats") or []
    parts = []
    if result["scan_status"] == "MALICIOUS":
        if gsb_hits:
            parts.append(f"Google Safe Browsing lists this URL for: {', '.join(t.replace('_', ' ').title() for t in gsb_hits)}.")
        if malicious_n:
            parts.append(f"{malicious_n} of {total} VirusTotal engines flagged it as malicious.")
    elif result["scan_status"] == "SUSPICIOUS":
        parts.append(f"{malicious_n} of {total} VirusTotal engines flagged it as suspicious (none as outright malicious).")
    else:
        parts.append(f"None of the {total} VirusTotal engines queried flagged this URL, and Google Safe Browsing reported no match." if "Google Safe Browsing" in result.get("sources_consulted", []) else f"None of the {total} VirusTotal engines queried flagged this URL.")
    return " ".join(parts)


def _render_result_details(result: dict):
    category = result.get("threat_category")
    detail_cols = st.columns([1, 1.6])
    with detail_cols[0]:
        _render_risk_gauge(result["risk_score"], result["risk_level"])
    with detail_cols[1]:
        st.metric(
            "Detection",
            f"{result['detection_count']} / {result['total_engines']}",
            help="Security engines that flagged this URL, out of all engines VirusTotal queried.",
        )
        st.write(f"**Risk Level:** :blue[{result['risk_level']}] ({result['risk_score']}/100)")

        if category:
            accent = _CATEGORY_ACCENT.get(category, "#64748B")
            st.markdown(
                f'<div class="url-status-badge" style="background:{accent}1A;color:{accent};'
                f'border:1px solid {accent}55;margin-bottom:0.4rem;">Classification: {category}</div>',
                unsafe_allow_html=True,
            )
        if result.get("is_low_confidence"):
            st.caption(
                ":material/info: Low engine coverage for this report - treat this as "
                "**inconclusive** rather than a confirmed-benign result."
            )

        sources = result.get("sources_consulted") or []
        if sources:
            st.caption(f":material/travel_explore: Sources consulted: {', '.join(sources)}.")
        if result.get("safe_browsing_error"):
            st.caption(f":material/warning: Google Safe Browsing could not be consulted: {result['safe_browsing_error']}")

        if result.get("vendor_label"):
            st.caption(f":material/label: Vendor-reported label: \"{result['vendor_label']}\" (VirusTotal, not a local prediction).")

        if st.session_state.get("last_url_scan_alert_id") is not None:
            st.warning("A high-risk alert was created for this scan - see Alerts & Incidents.")

    st.info(f":material/psychology: **Why this verdict:** {_explain_verdict(result)}")
    st.caption(
        "Threat intelligence indicates how security engines classified this URL. "
        "An absence of detections does not prove the URL is safe, and a detection "
        "does not prove it is malicious - this is not a substitute for further "
        "investigation."
    )

    if result["scan_status"] == "MALICIOUS":
        st.error(
            "**Recommended Action**\n"
            "- Do not access this URL.\n"
            "- Investigate the source it was received from.\n"
            "- Create a security incident and record this scan as evidence.\n"
            "- Review any potential data/security impact."
        )
    elif result["scan_status"] == "SUSPICIOUS":
        st.warning(
            "**Recommended Action:** Treat this URL with caution and "
            "investigate further before accessing it."
        )
    elif result.get("is_low_confidence"):
        st.warning(
            "No engines flagged this URL, but coverage was limited - treat as "
            "inconclusive rather than confirmed-safe."
        )
    else:
        st.success("No engines flagged this URL as malicious or suspicious.")

    _render_heuristic_signal(result)

    if result.get("engine_breakdown"):
        _render_engine_breakdown(result["engine_breakdown"])

    _render_scan_details(result)


def _render_risk_gauge(risk_score: int, risk_level: str):
    """A real 0-100 Plotly gauge, coloured by the SAME LOW/MEDIUM/HIGH/
    CRITICAL thresholds ml/risk_scoring.py uses everywhere else in the
    app (0-29/30-59/60-79/80-100) - this is a RISK gauge (fills toward
    red as danger increases), not an inverted "safety score" - see
    this module's own docstring for why that distinction matters."""
    accent = RISK_BAND_COLORS.get(risk_level, "#94A3B8")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        number={"suffix": "", "font": {"color": accent, "size": 34}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": accent},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 30], "color": "rgba(34, 197, 94, 0.15)"},
                {"range": [30, 60], "color": "rgba(242, 201, 76, 0.15)"},
                {"range": [60, 80], "color": "rgba(249, 115, 22, 0.15)"},
                {"range": [80, 100], "color": "rgba(220, 38, 38, 0.15)"},
            ],
        },
    ))
    fig.update_layout(
        height=190, margin=dict(l=20, r=20, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, width="stretch")
    st.markdown(f"<p style='text-align:center;color:{accent};font-weight:700;'>Risk Score</p>", unsafe_allow_html=True)


def _render_heuristic_signal(result: dict):
    """Local URL-structure analysis (security/phishing_heuristics.py) -
    a SUPPLEMENTARY signal, never blended into the real scan_status/
    risk_score above. It exists to catch a brand-new phishing URL no
    security vendor has indexed yet, which VirusTotal/Safe Browsing
    alone would report as a clean SAFE result. Always labeled as a
    heuristic, never shown as if it were a confirmed vendor verdict -
    see that module's own docstring for the full reasoning.

    Shown as a prominent warning only when it actively DISAGREES with
    the confirmed verdict (HIGH/CRITICAL structure on a SAFE result) -
    that's the one case genuinely worth interrupting the reader for.
    Otherwise it's a quiet, collapsed expander: agreeing with an
    already-dangerous verdict, or confirming a genuinely clean URL
    simply has no suspicious structure either, isn't new information."""
    score = result.get("heuristic_score")
    if score is None:
        return
    level = result["heuristic_level"]
    signals = result.get("heuristic_signals") or []

    disagrees_with_safe = result["scan_status"] == "SAFE" and level in ("HIGH", "CRITICAL")
    if disagrees_with_safe:
        reasons = "; ".join(signals)
        st.warning(
            f":material/policy: **Local structural analysis flags this URL as {level} risk** "
            f"({score}/100), even though no security vendor has confirmed it yet - "
            "this is common for brand-new phishing URLs vendors haven't indexed. "
            f"Reasons: {reasons}. **This is not a confirmed verdict** - treat it as a reason "
            "for extra caution, not proof."
        )
        return

    with st.expander(
        f"Local URL-structure analysis - {level} ({score}/100, heuristic, not a confirmed verdict)",
        icon=":material/policy:",
    ):
        st.caption(
            "A local, explainable check of this URL's own structure (host, length, "
            "keywords, known brand-spoofing/shortener patterns) - a supplementary "
            "signal only, separate from VirusTotal/Safe Browsing's real verdict above."
        )
        if signals:
            for reason in signals:
                st.write(f"- {reason}")
        else:
            st.write("No structural red flags detected in this URL.")


def _render_engine_breakdown(engine_breakdown: list):
    """Real per-vendor VirusTotal verdicts (security/url_scanner.py's
    _curate_engine_results()) - flagged vendors first, then enough
    clean ones to fill the list. Every vendor name/category/result
    shown here is exactly what VirusTotal returned, never invented."""
    with st.expander(f"Security engine results ({len(engine_breakdown)} shown)", icon=":material/shield:"):
        for entry in engine_breakdown:
            color = _ENGINE_CATEGORY_COLORS.get(entry["category"], "#94A3B8")
            result_text = entry["result"] or entry["category"].title()
            st.markdown(
                f'<div class="url-engine-row">'
                f'<span class="url-engine-dot" style="background:{color};"></span>'
                f'<span class="url-engine-vendor">{entry["vendor"]}</span>'
                f'<span class="url-engine-result" style="color:{color};">{result_text}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )


def _render_scan_details(result: dict):
    """What we ACTUALLY have, real and unaltered - not the fabricated
    domain/IP/SSL-certificate "Technical Details" a reference design
    might show, which would need WHOIS/DNS/certificate lookups this
    app never performs (see this module's own docstring)."""
    with st.expander("Scan details", icon=":material/info:"):
        ts = result["scan_timestamp"]
        ts_str = ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else "—"
        original = result.get("original_url")
        if original and original != result["url"]:
            st.write(f"**Original URL (as entered):** {original}")
            st.write(f"**Normalized URL (as scanned):** {result['url']}")
        else:
            st.write(f"**Scanned URL:** {result['url']}")
        st.write(f"**Scan timestamp:** {ts_str}")
        st.write(f"**Source:** {result['source']}")
        if result.get("analysis_reference"):
            st.caption(f"VirusTotal analysis reference: `{result['analysis_reference']}`")


def _render_history():
    start, end, _ = get_active_range()
    rows = get_url_scans_in_range(st.session_state.get("user_id"), start, end, limit=10)
    if not rows:
        _render_history_empty_state()
        return
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def _render_history_empty_state():
    """The real cyber_url_scanner.png illustration when it's
    available, falling back to the existing hand-drawn SVG empty state
    otherwise (never both). This IS a genuinely empty result (zero
    scan rows for this account), not a placeholder for data that
    exists but failed to load."""
    path = photo_path("url_scanner_photo")
    if path is None:
        render_empty_state("No data available.", "browser_magnifier")
        return
    cols = st.columns([1, 2], vertical_alignment="center")
    with cols[0]:
        st.image(str(path), width=150)
    with cols[1]:
        st.info("No data available.")
