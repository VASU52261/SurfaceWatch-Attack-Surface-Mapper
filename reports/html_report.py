"""
reports/html_report.py
----------------------
Renders a scan as a single self-contained HTML page.

This is what ``surfacewatch report --format html`` produces. It exists because a
web page is often the easiest thing to share: it opens on any phone or
computer with no PDF reader, and it can be emailed or dropped straight into
the Flask dashboard.

The output is one file with no external stylesheets, scripts, fonts or images,
so it works offline and cannot leak anything about the business to a third
party by loading a remote asset.

Wording comes from exactly the same engines as the PDF, the terminal and the
alert emails, so a business owner reads identical language everywhere.

Usage::

    from reports.html_report import generate_html
    generate_html(graph, "report.html")
"""

from __future__ import annotations

import html
import logging
import os
from datetime import datetime
from typing import Any, Optional

from reports.attack_story import generate_stories
from reports.plain_english import (
    Severity,
    friendly_name,
    generate_report,
    risk_score_words,
)

log = logging.getLogger(__name__)


def _esc(value: Any) -> str:
    """Escape anything going into the page."""
    return html.escape(str(value if value is not None else ""))


def _format_date(raw: Any) -> str:
    try:
        return datetime.fromisoformat(str(raw)).strftime("%d %B %Y at %H:%M")
    except (TypeError, ValueError):
        return datetime.now().strftime("%d %B %Y at %H:%M")


# ===========================================================================
# Sections
# ===========================================================================

def _summary_section(report: dict) -> str:
    level  = report.get("overall_risk", Severity.LOW)
    score  = float(report.get("risk_score", 0) or 0)
    colour = Severity.COLORS.get(level, "#7f8c8d")
    counts = report.get("severity_counts", {})

    chips = "".join(
        f'<div class="stat"><span class="num" style="color:{Severity.COLORS[key]}">'
        f'{counts.get(key, 0)}</span><span class="lbl">{label}</span></div>'
        for key, label in (
            (Severity.CRITICAL, "Urgent"),
            (Severity.HIGH,     "Serious"),
            (Severity.MEDIUM,   "Moderate"),
            (Severity.LOW,      "Minor"),
        )
    )

    actions = report.get("top_actions") or []
    action_html = "".join(
        f'<li>{_esc(action)}</li>' for action in actions
    ) or "<li>Nothing urgent needs your attention right now.</li>"

    return f"""
    <section class="card">
      <div class="verdict" style="background:{colour}">
        <div class="verdict-level">{_esc(level)}</div>
      </div>
      <div class="verdict-body">
        <p class="headline">{_esc(report.get('headline', ''))}</p>
        <p class="muted">{_esc(Severity.MEANING.get(level, ''))}</p>
      </div>
    </section>

    <section class="card pad">
      <h2>How exposed is your business?</h2>
      <div class="meter"><div class="meter-fill"
           style="width:{score:.0f}%;background:{colour}"></div></div>
      <p class="muted">Overall, your business is
         <strong>{_esc(risk_score_words(score))}</strong> &mdash;
         {score:.0f} out of 100. Watch this fall as you work through the actions below.</p>
      <div class="stats">{chips}
        <div class="stat"><span class="num">{(report.get('inventory') or {}).get('total', 0)}</span>
        <span class="lbl">Things found</span></div>
      </div>
    </section>

    <section class="card pad">
      <h2>The three things to fix first</h2>
      <ol class="actions">{action_html}</ol>
    </section>"""


def _findings_section(report: dict) -> str:
    findings = report.get("findings") or []
    if not findings:
        return ('<section class="card pad"><h2>What we found</h2>'
                '<p>Nothing needs your attention right now.</p></section>')

    blocks = []
    for index, finding in enumerate(findings, 1):
        severity = finding.get("severity", Severity.MEDIUM)
        colour   = Severity.COLORS.get(severity, "#7f8c8d")
        evidence = finding.get("evidence") or []

        evidence_html = (
            f'<p class="tech">For your IT person: '
            f'{_esc("; ".join(str(e) for e in evidence[:6]))}</p>'
            if evidence else ""
        )

        blocks.append(f"""
        <article class="finding" style="border-left-color:{colour}">
          <div class="finding-head">
            <span class="badge" style="background:{colour}">{_esc(severity)}</span>
            <h3>{_esc(finding.get('what_is_exposed', ''))}</h3>
          </div>
          <dl>
            <dt>Why it matters</dt><dd>{_esc(finding.get('why_it_matters', ''))}</dd>
            <dt>How an attacker uses it</dt><dd>{_esc(finding.get('how_attacker_uses_it', ''))}</dd>
            <dt>What to do</dt><dd class="action">{_esc(finding.get('recommended_action', ''))}</dd>
          </dl>
          {evidence_html}
        </article>""")

    return (f'<section class="card pad"><h2>Everything we found '
            f'({len(findings)})</h2>{"".join(blocks)}</section>')


def _stories_section(stories: list) -> str:
    if not stories:
        return ('<section class="card pad"><h2>How someone could break in</h2>'
                '<p>We could not trace a complete route into your systems from this '
                'scan. That is a good sign, though it is not a guarantee.</p></section>')

    blocks = []
    for index, story in enumerate(stories, 1):
        severity = story.get("severity", Severity.MEDIUM)
        colour   = Severity.COLORS.get(severity, "#7f8c8d")

        steps = "".join(
            f'<li><span style="color:{colour}"><strong>Step '
            f'{_esc(step.get("number", ""))}:</strong></span> {_esc(step.get("text", ""))}</li>'
            for step in story.get("steps", [])
        )
        prevention = "".join(
            f"<li>{_esc(action)}</li>" for action in story.get("prevention_steps", [])
        )

        blocks.append(f"""
        <article class="route" style="border-left-color:{colour}">
          <div class="finding-head">
            <span class="badge" style="background:{colour}">ROUTE {index}</span>
            <h3>{_esc(story.get('title', ''))}</h3>
          </div>
          <p class="muted">Chance of this working:
             <strong>{_esc(story.get('breach_probability', ''))}</strong>
             &mdash; {_esc(story.get('probability_reason', ''))}</p>
          <ol class="steps">{steps}</ol>
          <h4>How to stop this route</h4>
          <ol class="actions">{prevention}</ol>
        </article>""")

    return (f'<section class="card pad"><h2>How someone could break in</h2>'
            f'{"".join(blocks)}</section>')


def _inventory_section(graph, report: dict) -> str:
    inventory = (report.get("inventory") or {}).get("friendly", {}) or {}
    counts = "".join(
        f"<tr><td>{_esc(str(name).capitalize())}</td><td>{_esc(count)}</td></tr>"
        for name, count in inventory.items()
    )

    rows = []
    try:
        nodes = sorted(graph.G.nodes(data=True), key=lambda item: str(item[0]))
    except Exception as exc:
        log.error("Could not read the graph for the inventory: %s", exc)
        nodes = []

    for node_id, attrs in nodes:
        if attrs.get("node_type") == "cve":
            continue          # weaknesses are listed above, in plain English
        rows.append(
            f"<tr><td>{_esc(attrs.get('label', node_id))}</td>"
            f"<td>{_esc(friendly_name(graph, node_id))}</td>"
            f"<td>{'yes' if attrs.get('exposed') else 'no'}</td></tr>"
        )

    return f"""
    <section class="card pad">
      <h2>What you have exposed to the internet</h2>
      <table class="tbl"><thead><tr><th>What</th><th>How many</th></tr></thead>
        <tbody>{counts}</tbody></table>

      <h3>Everything we found</h3>
      <table class="tbl"><thead><tr><th>Name</th><th>In plain English</th>
        <th>Public?</th></tr></thead>
        <tbody>{"".join(rows)}</tbody></table>
    </section>"""


# ===========================================================================
# Page
# ===========================================================================

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; background:#eef1f5; color:#1f2933;
       font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif; }
.wrap { max-width:900px; margin:0 auto; padding:28px 16px 60px; }
header.top { padding:8px 0 20px; }
header.top h1 { margin:0; font-size:26px; }
header.top .sub { color:#6b7684; font-size:14px; }
.card { background:#fff; border-radius:10px; margin-bottom:18px;
        box-shadow:0 1px 3px rgba(16,24,40,.08); overflow:hidden;
        display:flex; flex-wrap:wrap; }
.card.pad { display:block; padding:22px 24px; }
.verdict { flex:0 0 150px; display:flex; align-items:center; justify-content:center;
           padding:26px 16px; }
.verdict-level { color:#fff; font-size:24px; font-weight:700; letter-spacing:.02em; }
.verdict-body { flex:1 1 320px; padding:22px 24px; }
.headline { font-size:17px; font-weight:600; margin:0 0 6px; }
.muted { color:#6b7684; font-size:14px; }
h2 { font-size:18px; margin:0 0 14px; }
h3 { font-size:15px; margin:18px 0 8px; }
h4 { font-size:14px; margin:14px 0 6px; }
.meter { height:16px; border-radius:8px; background:#e4e7eb; overflow:hidden; margin:6px 0 10px; }
.meter-fill { height:100%; }
.stats { display:flex; flex-wrap:wrap; gap:10px; margin-top:16px; }
.stat { flex:1 1 90px; text-align:center; border:1px solid #e4e7eb;
        border-radius:8px; padding:12px 6px; }
.stat .num { display:block; font-size:22px; font-weight:700; }
.stat .lbl { display:block; font-size:12px; color:#6b7684; }
ol.actions { padding-left:20px; } ol.actions li { margin-bottom:8px; }
.finding, .route { border-left:4px solid #ccc; background:#fbfbfc;
                   border-radius:0 8px 8px 0; padding:14px 18px; margin-bottom:16px; }
.finding-head { display:flex; align-items:flex-start; gap:10px; flex-wrap:wrap; }
.finding-head h3 { margin:2px 0 8px; font-size:15px; flex:1 1 260px; }
.badge { color:#fff; font-size:11px; font-weight:700; padding:3px 9px;
         border-radius:4px; white-space:nowrap; }
dl { margin:6px 0 0; } dt { font-weight:600; font-size:13px; margin-top:8px; }
dd { margin:2px 0 0; font-size:14px; color:#3e4c59; }
dd.action { font-weight:600; color:#1f2933; }
.tech { margin-top:10px; font-size:12px; color:#8a94a0; }
ol.steps { padding-left:20px; } ol.steps li { margin-bottom:7px; }
table.tbl { width:100%; border-collapse:collapse; font-size:14px; margin-bottom:10px; }
table.tbl th { background:#2c5282; color:#fff; text-align:left; padding:8px 10px; font-size:13px; }
table.tbl td { padding:7px 10px; border-bottom:1px solid #eceff2; }
table.tbl tr:nth-child(even) td { background:#f8f9fb; }
footer { color:#8a94a0; font-size:12px; text-align:center; padding-top:10px; }
@media print { body { background:#fff; } .card { box-shadow:none; border:1px solid #e4e7eb; } }
@media (prefers-color-scheme: dark) {
  body { background:#11161c; color:#e6e9ee; }
  .card, .finding, .route { background:#1a212a; }
  .stat { border-color:#2a3441; } .muted, .stat .lbl { color:#9aa5b1; }
  dd { color:#c3ccd6; } dd.action { color:#e6e9ee; }
  table.tbl td { border-color:#2a3441; }
  table.tbl tr:nth-child(even) td { background:#161d25; }
  .meter { background:#2a3441; }
}
"""


def build_html(report: dict, stories: list, graph) -> str:
    """Assemble the complete page as a single string."""
    target = report.get("target", "your business")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SurfaceWatch Security Report - {_esc(target)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1>Your Security Report</h1>
    <div class="sub">{_esc(target)} &middot; {_esc(_format_date(report.get('generated_at')))}</div>
  </header>

  {_summary_section(report)}
  {_findings_section(report)}
  {_stories_section(stories)}
  {_inventory_section(graph, report)}

  <footer>
    Generated by SurfaceWatch &mdash; free, open source attack surface monitoring.<br>
    This report is written to be read by anyone. If something is unclear, send it
    to whoever looks after your computers.
  </footer>
</div>
</body>
</html>"""


def generate_html(graph,
                  output_path: str = "surfacewatch_report.html",
                  report: Optional[dict] = None,
                  stories: Optional[list] = None) -> Optional[str]:
    """
    Write the HTML report to a file.

    Returns the path written, or ``None`` on failure. Never raises, so a
    failed report cannot bring down a scheduled scan.
    """
    try:
        report = report if report is not None else generate_report(graph)
        raw    = stories if stories is not None else generate_stories(graph, top_n=3)
        story_dicts = [s if isinstance(s, dict) else s.to_dict() for s in raw]

        page = build_html(report, story_dicts, graph)

        directory = os.path.dirname(os.path.abspath(output_path))
        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(page)

        log.info("HTML report written to %s", output_path)
        return output_path

    except Exception as exc:
        log.error("Could not create the HTML report: %s", exc)
        return None
