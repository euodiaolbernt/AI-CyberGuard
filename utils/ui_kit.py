"""
Reusable HTML building blocks for every page.

Streamlit's own widgets (st.metric, st.dataframe, st.info) can't carry the
design system's typography, severity chips or table alignment, and the
previous build worked around that by re-boxing each widget in CSS - which
is exactly what produced three nested cards on one screen. So presentation
moved here: small, tested functions that return one HTML fragment each,
styled by utils/theme.py's .uik-* rules. Pages compose them; no page module
writes raw layout markup of its own.

Everything that displays a stored value runs through esc() unless the
caller passes an explicit {"html": ...} cell, so model output or a scanned
URL can never inject markup into the page.
"""
from __future__ import annotations

import html as _html
from datetime import datetime

import streamlit as st

import utils.design_tokens as t

# ---------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------


def esc(value) -> str:
    """Escape any stored/user-supplied value for safe interpolation."""
    if value is None:
        return ""
    return _html.escape(str(value), quote=True)


def render(fragment: str) -> None:
    st.markdown(fragment, unsafe_allow_html=True)


def spacer(height: str = "0.5rem") -> None:
    render(f'<div style="height:{height}"></div>')


def note(text: str, tone: str = "muted") -> None:
    """One-line explanation under a section. `tone` is muted | warn | danger."""
    render(f'<p class="uik-note uik-note--{tone}">{text}</p>')


def section(title: str, meta: str = "", hint: str = "") -> None:
    """A section heading row: title left, scope/period note right.

    `meta` is where the period or scope belongs ("13-26 Oct", "all time"),
    so a number can never appear without saying what it counts.
    """
    meta_html = f'<span class="uik-section-meta">{meta}</span>' if meta else ""
    hint_html = f'<p class="uik-section-hint">{hint}</p>' if hint else ""
    render(
        f'<div class="uik-section"><div class="uik-section-head">'
        f'<h2 class="uik-section-title">{title}</h2>{meta_html}</div>{hint_html}</div>'
    )


# ---------------------------------------------------------------------
# Chips
# ---------------------------------------------------------------------


def chip(text: str, fg: str = "#334155", bg: str = "rgba(148,163,184,0.14)",
         dot: str | None = None) -> dict:
    """Return a chip cell. Colour is never the only signal - the label
    text always says the state in words, and a dot carries the hue."""
    dot_html = f'<span class="uik-chip-dot" style="background:{dot}"></span>' if dot else ""
    return {"html": (
        f'<span class="uik-chip" style="color:{fg};background:{bg}">'
        f'{dot_html}{esc(text)}</span>'
    )}


def severity_chip(severity: str) -> dict:
    key = (severity or "").upper()
    return chip(
        key or "UNKNOWN",
        fg=t.SEVERITY_TEXT.get(key, t.MUTED),
        bg=t.SEVERITY_TINTS.get(key, "rgba(148,163,184,0.14)"),
        dot=t.SEVERITY_COLORS.get(key),
    )


def status_chip(status: str) -> dict:
    key = (status or "").upper()
    fg, bg = t.STATUS_COLORS.get(key, t.STATUS_COLORS["NOT_ASSESSED"])
    return chip(t.STATUS_LABELS.get(key, key), fg=fg, bg=bg,
                dot=fg if key in ("COMPLIANT", "NEEDS_REVIEW", "POTENTIAL_VIOLATION") else None)


def alert_status_chip(status: str) -> dict:
    key = (status or "").upper()
    fg, bg = t.ALERT_STATUS_COLORS.get(key, ("#64748B", "#F1F5F9"))
    return chip(key.title() if key else "Unknown", fg=fg, bg=bg, dot=fg)


def url_status_chip(status: str) -> dict:
    key = (status or "").upper()
    label = {"SAFE": "Safe", "SUSPICIOUS": "Suspicious", "MALICIOUS": "Malicious",
             "SCAN_ERROR": "Scan failed"}.get(key, key.title() or "Unknown")
    fg, bg = t.URL_STATUS_COLORS.get(key, ("#64748B", "#F1F5F9"))
    return chip(label, fg=fg, bg=bg, dot=fg)


def mono(value) -> dict:
    """A recorded value - timestamps, IDs, scores. Monospaced + tabular so
    columns line up digit for digit."""
    return {"html": f'<span class="uik-mono">{esc(value)}</span>'}


def muted(value) -> dict:
    return {"html": f'<span class="uik-muted">{esc(value)}</span>'}


# ---------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------


def metric(label: str, value: str, *, scope: str = "", delta: str | None = None,
           delta_good: bool | None = None, size: str = "md", warn: str = "") -> str:
    """One metric block. Returns HTML so a page can place several of them in
    a single row without each becoming its own card.

    `delta_good` says whether the movement is good news: a *fall* in
    critical threats is good (green arrow down), a *rise* in detections is
    bad (red arrow up). `None` renders no delta at all - which is what an
    undefined comparison (prior period had zero records) must show.
    """
    delta_html = ""
    if delta:
        arrow = "↑" if delta.strip().startswith("+") else "↓"
        tone = "flat" if delta_good is None else ("good" if delta_good else "bad")
        delta_html = (
            f'<span class="uik-delta uik-delta--{tone}">{arrow}{esc(delta.lstrip("+-"))}</span>'
        )
    warn_html = f'<span class="uik-metric-warn">{warn}</span>' if warn else ""
    scope_html = f'<p class="uik-metric-scope">{scope}</p>' if scope else ""
    return (
        f'<div class="uik-metric uik-metric--{size}">'
        f'<p class="uik-metric-label">{label}</p>'
        f'<p class="uik-metric-value">{value}{delta_html}{warn_html}</p>'
        f'{scope_html}</div>'
    )


def metric_strip(items: list[str]) -> None:
    """Lay several metric() blocks in one hairline-divided row. Children are
    separated by rules, not by becoming separate cards."""
    cells = "".join(f'<div class="uik-metric-cell">{item}</div>' for item in items)
    render(f'<div class="uik-metric-strip">{cells}</div>')


def segments(filled: int, total: int, *, label: str = "") -> str:
    """A real-denominator indicator: `total` segments, `filled` of them
    filled. Only used where a genuine fraction exists (frameworks
    compliant), never as decoration."""
    total = max(int(total), 0)
    filled = max(min(int(filled), total), 0)
    bars = "".join(
        f'<span class="uik-seg{" uik-seg--on" if i < filled else ""}"></span>'
        for i in range(total)
    )
    aria = label or f"{filled} of {total}"
    return f'<div class="uik-segments" role="img" aria-label="{esc(aria)}">{bars}</div>'


# ---------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------


def table(columns: list[dict], rows: list[list], *, max_height: str = "",
          first_col_strong: bool = False) -> None:
    """Render a record table.

    columns: [{"label": "Time", "align": "left"|"right", "kind": "mono",
               "width": "90px"}]
    rows:    list of rows; each cell is a str (escaped) or {"html": ...}.

    Repeated records belong in one table with shared columns - never a
    column of rounded cards.
    """
    head_cells = []
    for col in columns:
        align = col.get("align", "left")
        width = col.get("width", "")
        style = f' style="width:{width}"' if width else ""
        head_cells.append(
            f'<th scope="col" class="uik-th uik-al-{align}"{style}>{esc(col["label"])}</th>'
        )

    body_rows = []
    for row in rows:
        cells = []
        for c_index, raw in enumerate(row):
            col = columns[c_index] if c_index < len(columns) else {}
            align = col.get("align", "left")
            kind = col.get("kind", "")
            if isinstance(raw, dict) and "html" in raw:
                inner = raw["html"]
            else:
                inner = esc(raw)
            extra = ""
            if kind == "mono" and not isinstance(raw, dict):
                extra = " uik-mono"
            if first_col_strong and c_index == 0 and not isinstance(raw, dict):
                extra += " uik-cell-strong"
            cells.append(f'<td class="uik-td uik-al-{align}{extra}">{inner}</td>')
        body_rows.append(f'<tr class="uik-tr">{"".join(cells)}</tr>')

    height_style = f' style="max-height:{max_height}"' if max_height else ""
    render(
        f'<div class="uik-table-wrap"{height_style}>'
        f'<table class="uik-table"><thead><tr>{"".join(head_cells)}</tr></thead>'
        f'<tbody>{"".join(body_rows)}</tbody></table></div>'
    )


# ---------------------------------------------------------------------
# Empty / unavailable states
# ---------------------------------------------------------------------


_EMPTY_ICONS = {
    "radar": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/>'
             '<path d="M12 12 18 7"/>',
    "document": '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9 13h6M9 17h4"/>',
    "shield": '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/>',
    "bell": '<path d="M6 9a6 6 0 1112 0c0 4 1.5 5.5 1.5 5.5h-15S6 13 6 9z"/>'
            '<path d="M10 18a2 2 0 004 0"/>',
    "link": '<path d="M10 13a5 5 0 007 0l2-2a5 5 0 00-7-7l-1 1"/>'
            '<path d="M14 11a5 5 0 00-7 0l-2 2a5 5 0 007 7l1-1"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
}


def empty_state(title: str, body: str = "", icon: str = "radar") -> None:
    """Name the state, then the next action. Never a fabricated example
    record, never a full-page takeover."""
    body_html = f'<p class="uik-empty-body">{body}</p>' if body else ""
    svg = _EMPTY_ICONS.get(icon, _EMPTY_ICONS["radar"])
    render(
        f'<div class="uik-empty">'
        f'<span class="uik-empty-icon" aria-hidden="true">'
        f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" '
        f'stroke-linecap="round" stroke-linejoin="round">{svg}</svg></span>'
        f'<p class="uik-empty-title">{title}</p>{body_html}</div>'
    )


def unavailable(message: str) -> None:
    """Distinct from empty: the query itself could not be answered."""
    render(f'<div class="uik-unavailable">{message}</div>')


# ---------------------------------------------------------------------
# Chart helpers - one visual language for every Plotly figure
# ---------------------------------------------------------------------


def style_figure(fig, *, height: int = 260, show_legend: bool = False):
    """Apply the shared chart theme. Axes stay visible and labelled: a
    chart without units is not evidence."""
    fig.update_layout(
        height=height,
        margin=dict(l=6, r=6, t=8, b=6),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=t.CHART_FONT,
        showlegend=show_legend,
        hoverlabel=dict(
            bgcolor="#FFFFFF",
            bordercolor=t.BORDER_STRONG,
            font=dict(family="Inter, sans-serif", size=12, color=t.INK),
        ),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
    )
    fig.update_xaxes(
        showgrid=False, zeroline=False,
        linecolor=t.BORDER_STRONG, linewidth=1,
        tickfont=dict(size=11, color=t.MUTED),
        title_font=dict(size=11, color=t.FAINT),
    )
    fig.update_yaxes(
        showgrid=True, gridcolor=t.CHART_GRID, zeroline=False,
        linecolor="rgba(0,0,0,0)",
        tickfont=dict(size=11, color=t.MUTED),
        title_font=dict(size=11, color=t.FAINT),
    )
    return fig


def trend_figure(rows, *, days: int = 14, colour: str | None = None):
    """Daily detection counts as a dated line with a labelled axis.

    Days with no detections are filled with a real 0 rather than skipped:
    an absent calendar day in this range is a measured zero, and letting
    Plotly bridge the gap would draw a trend that never happened.
    """
    import pandas as pd
    import plotly.graph_objects as go

    today = datetime.now().date()
    counts: dict = {}
    for row in rows:
        day = row["day"]
        key = day.date() if hasattr(day, "date") else day
        counts[key] = int(row["count"])

    dates = [today - pd.Timedelta(days=offset) for offset in range(days - 1, -1, -1)]
    values = [counts.get(d, 0) for d in dates]
    labels = [d.strftime("%d %b") for d in dates]

    fig = go.Figure(go.Scatter(
        x=labels, y=values, mode="lines+markers", name="Detections",
        line=dict(color=colour or t.CHART_LINE, width=2.4),
        marker=dict(color=colour or t.CHART_LINE, size=5),
        fill="tozeroy", fillcolor="rgba(14, 165, 233, 0.10)",
        hovertemplate="%{x}<br>%{y} detections<extra></extra>",
    ))
    style_figure(fig)
    fig.update_xaxes(title_text="Date", nticks=8)
    fig.update_yaxes(title_text="Detections", rangemode="tozero",
                     tickformat="d", nticks=5)
    return fig


def severity_legend(rows, *, total: int | None = None) -> None:
    """A readable severity legend: label, count and share as text.

    Deliberately not Plotly's own legend - it can't show the real counts in
    the design's type scale, and a legend that only shows a label leaves the
    reader estimating from arc length.
    """
    lookup = {(r["severity"] or "").upper(): int(r["count"]) for r in rows}
    values = [lookup.get(key, 0) for key in t.SEVERITY_ORDER]
    sum_total = total if total is not None else sum(values)
    items = []
    for key, value in zip(t.SEVERITY_ORDER, values):
        share = f"{value / sum_total * 100:.0f}%" if sum_total else "—"
        items.append(
            f'<li><span class="uik-legend-dot" style="background:{t.SEVERITY_COLORS[key]}"></span>'
            f'<span class="uik-legend-label">{key.title()}</span>'
            f'<span class="uik-legend-value">{value:,}</span>'
            f'<span class="uik-legend-pct">{share}</span></li>'
        )
    render(f'<ul class="uik-legend">{"".join(items)}</ul>')


def severity_figure(rows, *, total: int | None = None, show_legend: bool = False):
    """Severity mix as a doughnut, or None when there is nothing to plot."""
    import plotly.graph_objects as go

    lookup = {(r["severity"] or "").upper(): int(r["count"]) for r in rows}
    values = [lookup.get(key, 0) for key in t.SEVERITY_ORDER]
    if not any(values):
        return None
    sum_total = total if total is not None else sum(values)
    fig = go.Figure(go.Pie(
        labels=[key.title() for key in t.SEVERITY_ORDER],
        values=values,
        hole=0.68,
        sort=False,
        direction="clockwise",
        marker=dict(colors=[t.SEVERITY_COLORS[k] for k in t.SEVERITY_ORDER],
                    line=dict(color="#FFFFFF", width=2)),
        textinfo="none",
        hovertemplate="%{label}<br>%{value} detections<extra></extra>",
    ))
    style_figure(fig, height=260, show_legend=show_legend)
    fig.update_layout(
        annotations=[dict(
            text=f'<b>{sum_total:,}</b><br><span style="font-size:10px;color:{t.MUTED}">'
                 f'DETECTIONS</span>',
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20, color=t.INK, family="Inter, sans-serif"),
        )],
        legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.02),
        margin=dict(l=6, r=6, t=8, b=8),
    )
    return fig


def bar_figure(labels, values, *, colour: str | None = None, horizontal: bool = False,
               x_title: str = "", y_title: str = "", height: int = 280):
    """Discrete comparison - bars, not a line."""
    import plotly.graph_objects as go

    colours = colour or t.CHART_LINE
    if horizontal:
        fig = go.Figure(go.Bar(
            x=values, y=labels, orientation="h",
            marker=dict(color=colours, line=dict(width=0)),
            hovertemplate="%{y}<br>%{x}<extra></extra>",
        ))
    else:
        fig = go.Figure(go.Bar(
            x=labels, y=values,
            marker=dict(color=colours, line=dict(width=0)),
            hovertemplate="%{x}<br>%{y}<extra></extra>",
        ))
    style_figure(fig, height=height)
    if x_title:
        fig.update_xaxes(title_text=x_title)
    if y_title:
        fig.update_yaxes(title_text=y_title)
    return fig


def confusion_matrix_figure(matrix, class_names, *, height: int = 340):
    """Confusion matrix with the diagonal (correct predictions) readable at
    a glance. Counts are printed in each cell - the colour is a second
    channel, not the only one."""
    import plotly.graph_objects as go

    fig = go.Figure(go.Heatmap(
        z=matrix,
        x=[f"Pred: {c}" for c in class_names],
        y=[f"Actual: {c}" for c in class_names],
        colorscale=[[0, "#F8FBFF"], [0.5, "#BAE6FD"], [1, "#0369A1"]],
        text=matrix,
        texttemplate="%{text}",
        textfont=dict(size=11, color=t.INK),
        hovertemplate="%{y} → %{x}<br>%{z} records<extra></extra>",
        showscale=True,
        colorbar=dict(title=dict(text="Count", font=dict(size=11, color=t.MUTED)),
                      thickness=10, outlinewidth=0,
                      tickfont=dict(size=10, color=t.MUTED)),
        xgap=2, ygap=2,
    ))
    style_figure(fig, height=height)
    fig.update_xaxes(showgrid=False, side="bottom")
    fig.update_yaxes(showgrid=False, autorange="reversed")
    return fig


def risk_gauge_figure(score: int, level: str, *, height: int = 240):
    """URL risk score 0-100 with the band boundaries drawn in, so the number
    is anchored to the same thresholds ml/risk_scoring.py uses."""
    import plotly.graph_objects as go

    colour = t.SEVERITY_COLORS.get((level or "").upper(), t.MUTED)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=float(score),
        number=dict(font=dict(size=34, color=colour, family="Inter, sans-serif")),
        gauge=dict(
            axis=dict(range=[0, 100], tickwidth=1, tickcolor=t.BORDER_STRONG,
                      tickfont=dict(size=10, color=t.MUTED)),
            bar=dict(color=colour, thickness=0.32),
            bgcolor="rgba(0,0,0,0)",
            borderwidth=0,
            steps=[
                dict(range=[0, 30], color="rgba(34, 197, 94, 0.12)"),
                dict(range=[30, 60], color="rgba(242, 201, 76, 0.14)"),
                dict(range=[60, 80], color="rgba(249, 115, 22, 0.12)"),
                dict(range=[80, 100], color="rgba(220, 38, 38, 0.12)"),
            ],
        ),
    ))
    fig.update_layout(
        height=height,
        margin=dict(l=18, r=18, t=18, b=6),
        paper_bgcolor="rgba(0,0,0,0)",
        font=t.CHART_FONT,
    )
    return fig
