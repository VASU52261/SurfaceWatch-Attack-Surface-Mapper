"""
reports/pdf_generator.py
------------------------
Turns a scan into a professional PDF a business owner can act on - and, just
as importantly, can hand to their IT person or show to an insurer.

The document is deliberately structured the way a non-technical reader takes
it in:

    Page 1  Executive summary   - am I safe, and what do I fix first?
    Page 2  Attack surface      - what do I actually have out there?
    Page 3  Top vulnerabilities - the serious problems, in plain English
    Page 4  Attack paths        - how someone would really break in
    Page 5  Full inventory      - everything we found, for the IT person
    Page 6  Screenshots         - only when Phase 4 captured any

Colour is used consistently throughout, and only to mean severity:
red = critical, orange = high, yellow = medium, green = low.

Everything on the page comes from the earlier phases, so the wording in the
PDF is identical to the wording in the terminal, the web dashboard and the
alert emails.

Usage::

    from graph.builder import AttackSurfaceGraph
    from reports.pdf_generator import generate_pdf

    graph = AttackSurfaceGraph.load("attack_surface.json")
    generate_pdf(graph, "acme-security-report.pdf")

Requires reportlab::

    pip install reportlab
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Optional
from xml.sax.saxutils import escape

from reports.attack_story import generate_stories
from reports.plain_english import (
    Severity,
    friendly_name,
    generate_report,
    risk_score_words,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# reportlab is an optional dependency: everything else in SurfaceWatch works
# without it, so we fail with one clear instruction instead of a traceback.
# ---------------------------------------------------------------------------
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import (
        Flowable,
        Image,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:                                # pragma: no cover
    REPORTLAB_AVAILABLE = False


# ===========================================================================
# Palette
# ===========================================================================

INK        = "#1f2933"     # main text
MUTED      = "#6b7684"     # secondary text
HAIRLINE   = "#dfe3e8"     # table borders
PANEL      = "#f5f7f9"     # panel fill
BRAND      = "#2c5282"     # SurfaceWatch blue

PAGE_MARGIN = 18 * mm if REPORTLAB_AVAILABLE else 0


def severity_colour(severity: str):
    """reportlab colour for a severity level."""
    return colors.HexColor(Severity.COLORS.get(severity, MUTED))


# ===========================================================================
# Custom drawing elements
# ===========================================================================

if REPORTLAB_AVAILABLE:

    class LogoBlock(Flowable):
        """
        The masthead: a logo placeholder plus the product name.

        Pass ``logo_path`` to drop a real logo in; otherwise a clean shield
        placeholder is drawn, so the report never looks unfinished.
        """

        def __init__(self, width: float, logo_path: Optional[str] = None,
                     height: float = 20 * mm):
            super().__init__()
            self.width     = width
            self.height    = height
            self.logo_path = logo_path if logo_path and os.path.exists(logo_path) else None

        def wrap(self, available_width, available_height):
            return self.width, self.height

        def draw(self):
            canvas = self.canv
            size   = self.height

            if self.logo_path:
                try:
                    canvas.drawImage(self.logo_path, 0, 0, width=size, height=size,
                                     preserveAspectRatio=True, mask="auto")
                except Exception as exc:
                    log.debug("Could not draw the logo: %s", exc)
                    self._draw_placeholder(canvas, size)
            else:
                self._draw_placeholder(canvas, size)

            canvas.setFillColor(colors.HexColor(INK))
            canvas.setFont("Helvetica-Bold", 15)
            canvas.drawString(size + 8, size - 12, "SurfaceWatch")

            canvas.setFillColor(colors.HexColor(MUTED))
            canvas.setFont("Helvetica", 8.5)
            canvas.drawString(size + 8, size - 22, "Attack Surface Report")

        def _draw_placeholder(self, canvas, size: float) -> None:
            """A simple shield mark, used until a real logo is supplied."""
            canvas.setFillColor(colors.HexColor(BRAND))
            canvas.roundRect(0, 0, size, size, 3 * mm, stroke=0, fill=1)
            canvas.setFillColor(colors.white)
            canvas.setFont("Helvetica-Bold", size * 0.55)
            canvas.drawCentredString(size / 2, size * 0.30, "W")

    class RiskMeter(Flowable):
        """
        A horizontal 0-100 exposure bar with a marker at the current score.

        Gives the reader an immediate sense of scale before they read a single
        word, which matters when the audience is not technical.
        """

        def __init__(self, width: float, score: float, level: str,
                     height: float = 26 * mm):
            super().__init__()
            self.width  = width
            self.height = height
            self.score  = max(0.0, min(float(score or 0), 100.0))
            self.level  = level

        def wrap(self, available_width, available_height):
            return self.width, self.height

        def draw(self):
            canvas     = self.canv
            bar_height = 9 * mm
            bar_y      = 6 * mm
            accent     = severity_colour(self.level)

            # Four bands, left (safe) to right (critical).
            bands = [
                (Severity.LOW,      0.00, 0.15),
                (Severity.MEDIUM,   0.15, 0.40),
                (Severity.HIGH,     0.40, 0.70),
                (Severity.CRITICAL, 0.70, 1.00),
            ]
            for band_level, start, end in bands:
                colour = severity_colour(band_level)
                canvas.setFillColor(colour)
                canvas.setFillAlpha(0.30)
                canvas.rect(self.width * start, bar_y,
                            self.width * (end - start), bar_height,
                            stroke=0, fill=1)
            canvas.setFillAlpha(1)

            # Marker
            marker_x = self.width * (self.score / 100.0)
            canvas.setFillColor(accent)
            canvas.rect(max(0.0, marker_x - 1.2), bar_y - 2 * mm,
                        2.4, bar_height + 4 * mm, stroke=0, fill=1)

            # Keep the score label inside the bar at both extremes: left
            # aligned near 0, right aligned near 100, centred in between.
            canvas.setFont("Helvetica-Bold", 10)
            label  = f"{self.score:.0f} / 100"
            text_y = bar_y + bar_height + 3 * mm
            if marker_x > self.width - 20 * mm:
                canvas.drawRightString(self.width, text_y, label)
            elif marker_x < 20 * mm:
                canvas.drawString(0, text_y, label)
            else:
                canvas.drawCentredString(marker_x, text_y, label)

            canvas.setFillColor(colors.HexColor(MUTED))
            canvas.setFont("Helvetica", 8)
            canvas.drawString(0, 1 * mm, "Well protected")
            canvas.drawRightString(self.width, 1 * mm, "Very exposed")


# ===========================================================================
# Styles
# ===========================================================================

def _build_styles() -> dict:
    """Paragraph styles used across the document."""
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "wdTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=22, leading=26, textColor=colors.HexColor(INK),
            alignment=TA_LEFT, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "wdSubtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=10.5, leading=15, textColor=colors.HexColor(MUTED),
            spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "wdH2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=14, leading=18, textColor=colors.HexColor(INK),
            spaceBefore=12, spaceAfter=8,
        ),
        "h3": ParagraphStyle(
            "wdH3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=10.5, leading=14, textColor=colors.HexColor(INK),
            spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "wdBody", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=14, textColor=colors.HexColor(INK),
            spaceAfter=6,
        ),
        "muted": ParagraphStyle(
            "wdMuted", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=12, textColor=colors.HexColor(MUTED),
            spaceAfter=4,
        ),
        "cell": ParagraphStyle(
            "wdCell", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11.5, textColor=colors.HexColor(INK),
        ),
        "cellBold": ParagraphStyle(
            "wdCellBold", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8.5, leading=11.5, textColor=colors.HexColor(INK),
        ),
        "headline": ParagraphStyle(
            "wdHeadline", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=12.5, leading=17, textColor=colors.HexColor(INK),
            spaceAfter=8,
        ),
        "step": ParagraphStyle(
            "wdStep", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=13.5, textColor=colors.HexColor(INK),
            leftIndent=14, spaceAfter=5,
        ),
    }


def _p(text: Any, style) -> "Paragraph":
    """Escaped paragraph - report text can contain & and < from real hostnames."""
    return Paragraph(escape(str(text or "")), style)


# ===========================================================================
# Page furniture
# ===========================================================================

def _page_decorations(canvas, doc) -> None:
    """Footer with the page number, drawn on every page."""
    canvas.saveState()
    width, _height = A4

    canvas.setStrokeColor(colors.HexColor(HAIRLINE))
    canvas.setLineWidth(0.5)
    canvas.line(PAGE_MARGIN, 13 * mm, width - PAGE_MARGIN, 13 * mm)

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor(MUTED))
    canvas.drawString(PAGE_MARGIN, 8.5 * mm,
                      "SurfaceWatch - Attack Surface Report - Confidential")
    canvas.drawRightString(width - PAGE_MARGIN, 8.5 * mm, f"Page {canvas.getPageNumber()}")

    canvas.restoreState()


def _severity_chip(severity: str, styles) -> "Table":
    """A small coloured severity badge."""
    chip = Table(
        [[Paragraph(f'<font color="white"><b>{escape(severity)}</b></font>',
                    styles["cell"])]],
        colWidths=[24 * mm],
    )
    chip.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), severity_colour(severity)),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return chip


def _section_header(number: int, title: str, styles) -> list:
    """Consistent numbered section heading."""
    return [
        _p(f"{number}. {title}", styles["h2"]),
        _hairline(),
        Spacer(1, 6),
    ]


def _hairline(width_ratio: float = 1.0) -> "Table":
    """A thin horizontal rule."""
    available = A4[0] - 2 * PAGE_MARGIN
    rule = Table([[""]], colWidths=[available * width_ratio], rowHeights=[0.6])
    rule.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(HAIRLINE)),
    ]))
    return rule


def _table_style(header_colour: str = BRAND) -> "TableStyle":
    """The house table style: clean, alternating rows, no heavy grid."""
    return TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor(header_colour)),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, 0), 8.5),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor(PANEL)]),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.4, colors.HexColor(HAIRLINE)),
    ])


# ===========================================================================
# Page 1 - Executive summary
# ===========================================================================

def _page_executive_summary(report: dict, styles,
                            logo_path: Optional[str], content_width: float) -> list:
    """The page the business owner actually reads."""
    story: list = []

    story.append(LogoBlock(content_width, logo_path))
    story.append(Spacer(1, 10))

    story.append(_p("Your Security Report", styles["title"]))
    story.append(_p(
        f"{report.get('target', 'your business')}  |  "
        f"{_format_date(report.get('generated_at'))}",
        styles["subtitle"],
    ))
    story.append(_hairline())
    story.append(Spacer(1, 12))

    # --- overall verdict -------------------------------------------------
    level  = report.get("overall_risk", Severity.LOW)
    score  = float(report.get("risk_score", 0) or 0)
    colour = severity_colour(level)

    verdict = Table(
        [[Paragraph(f'<font color="white" size="19"><b>{escape(level)}</b></font>',
                    styles["cell"]),
          Paragraph(
              f'<b>{escape(report.get("headline", ""))}</b><br/><br/>'
              f'<font color="{MUTED}">{escape(Severity.MEANING.get(level, ""))}</font>',
              styles["body"])]],
        colWidths=[38 * mm, content_width - 38 * mm],
    )
    verdict.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), colour),
        ("BACKGROUND",    (1, 0), (1, 0), colors.HexColor(PANEL)),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (0, 0), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (1, 0), (1, 0), 12),
        ("RIGHTPADDING",  (1, 0), (1, 0), 12),
    ]))
    story.append(verdict)
    story.append(Spacer(1, 14))

    # --- exposure meter --------------------------------------------------
    story.append(_p("How exposed is your business?", styles["h3"]))
    story.append(RiskMeter(content_width, score, level))
    story.append(_p(
        f"Overall, your business is {risk_score_words(score)}. This score is a "
        f"way to track progress: watch it fall as you work through the actions "
        f"below.", styles["muted"],
    ))
    story.append(Spacer(1, 12))

    # --- top three actions ------------------------------------------------
    story.append(_p("The three things to fix first", styles["h3"]))

    actions = report.get("top_actions") or []
    if actions:
        rows = [[
            Paragraph(f'<font color="white"><b>{i}</b></font>', styles["cellBold"]),
            _p(action, styles["cell"]),
        ] for i, action in enumerate(actions, 1)]

        action_table = Table(rows, colWidths=[10 * mm, content_width - 10 * mm])
        action_table.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (0, -1), colour),
            ("ALIGN",          (0, 0), (0, -1), "CENTER"),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",     (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 8),
            ("LEFTPADDING",    (1, 0), (1, -1), 10),
            ("ROWBACKGROUNDS", (1, 0), (1, -1),
             [colors.white, colors.HexColor(PANEL)]),
            ("LINEBELOW",      (0, 0), (-1, -1), 0.4, colors.HexColor(HAIRLINE)),
        ]))
        story.append(action_table)
    else:
        story.append(_p("Nothing urgent needs your attention right now.", styles["body"]))

    story.append(Spacer(1, 14))

    # --- counts -----------------------------------------------------------
    counts    = report.get("severity_counts", {})
    inventory = report.get("inventory", {}) or {}

    summary_row = [[
        _stat_cell("Urgent",   counts.get(Severity.CRITICAL, 0), Severity.CRITICAL, styles),
        _stat_cell("Serious",  counts.get(Severity.HIGH, 0),     Severity.HIGH, styles),
        _stat_cell("Moderate", counts.get(Severity.MEDIUM, 0),   Severity.MEDIUM, styles),
        _stat_cell("Minor",    counts.get(Severity.LOW, 0),      Severity.LOW, styles),
        _stat_cell("Things found", inventory.get("total", 0), None, styles),
    ]]
    stats = Table(summary_row, colWidths=[content_width / 5.0] * 5)
    stats.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("BOX",          (0, 0), (-1, -1), 0.5, colors.HexColor(HAIRLINE)),
        ("INNERGRID",    (0, 0), (-1, -1), 0.5, colors.HexColor(HAIRLINE)),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(stats)

    story.append(Spacer(1, 12))
    story.append(_p(
        "This report is written to be read by anyone, not just an IT specialist. "
        "If you have someone who looks after your computers, give them this "
        "document - the technical detail they need is included further on.",
        styles["muted"],
    ))

    return story


def _stat_cell(label: str, value: Any, severity: Optional[str], styles) -> "Paragraph":
    """One number in the summary strip."""
    colour = Severity.COLORS.get(severity, BRAND) if severity else BRAND
    return Paragraph(
        f'<para align="center"><font color="{colour}" size="17"><b>{escape(str(value))}</b></font>'
        f'<br/><font color="{MUTED}" size="8">{escape(label)}</font></para>',
        styles["cell"],
    )


# ===========================================================================
# Page 2 - Attack surface overview
# ===========================================================================

def _page_attack_surface(graph, report: dict, styles, content_width: float) -> list:
    """What the business has exposed, and how risky each part is."""
    story: list = []
    story += _section_header(2, "What you have exposed to the internet", styles)

    story.append(_p(
        "Everything below was found from the outside, using only public "
        "information - exactly what an attacker would start with.",
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    # --- counts by type --------------------------------------------------
    inventory = (report.get("inventory") or {}).get("friendly", {}) or {}
    if inventory:
        rows = [["What", "How many"]]
        rows += [[_p(name.capitalize(), styles["cell"]),
                  _p(str(count), styles["cell"])] for name, count in inventory.items()]

        table = Table(rows, colWidths=[content_width * 0.7, content_width * 0.3])
        table.setStyle(_table_style())
        story.append(table)
        story.append(Spacer(1, 14))

    # --- riskiest assets --------------------------------------------------
    story.append(_p("Your most important assets, ranked by risk", styles["h3"]))
    story.append(_p(
        "These are the parts of your setup that matter most - either because "
        "they are the most exposed, or because most of your other systems "
        "depend on them.", styles["muted"],
    ))
    story.append(Spacer(1, 6))

    rows = [["Asset", "What it is", "Risk"]]
    try:
        top_nodes = graph.top_risk_nodes(top_n=60)
    except Exception as exc:
        log.error("Could not rank assets: %s", exc)
        top_nodes = []

    # A weakness is not an asset. CVE nodes rank highly here because
    # top_risk_nodes() folds their severity into the score, but listing them
    # on this page would show raw CVE identifiers to a business owner and
    # duplicate the next page. They are excluded.
    assets = [n for n in top_nodes if n.get("node_type") != "cve"]

    # Severity comes from the findings, not from the topology score, so this
    # page agrees with the rest of the report. Without this, a wide open
    # database door scores near zero on topology alone and would be printed as
    # LOW here while page 3 correctly calls it CRITICAL.
    finding_severity = _worst_severity_by_node(report)

    for node in assets:
        node["display_severity"] = finding_severity.get(
            node.get("node_id", ""), _risk_words(float(node.get("combined") or 0))
        )

    assets.sort(key=lambda n: (Severity.sort_key(n["display_severity"]),
                               -float(n.get("combined") or 0)))

    for node in assets[:14]:
        node_id = node.get("node_id", "")
        level   = node["display_severity"]

        rows.append([
            _p(node.get("label", node_id), styles["cell"]),
            _p(friendly_name(graph, node_id), styles["cell"]),
            Paragraph(
                f'<font color="{Severity.COLORS.get(level, MUTED)}"><b>{escape(level)}</b></font>',
                styles["cell"],
            ),
        ])

    if len(rows) == 1:
        rows.append([_p("Nothing discovered yet.", styles["cell"]), "", ""])

    table = Table(rows, colWidths=[content_width * 0.34, content_width * 0.48,
                                   content_width * 0.18], repeatRows=1)
    table.setStyle(_table_style())
    story.append(table)

    return story


def _worst_severity_by_node(report: dict) -> dict[str, str]:
    """
    Map each asset to the worst severity reported against it.

    Findings already carry the node they relate to, so this is what keeps the
    asset table on page 2 consistent with the detailed findings on page 3.
    """
    worst: dict[str, str] = {}

    for finding in report.get("findings") or []:
        node_id  = finding.get("node_id")
        severity = finding.get("severity")
        if not node_id or not severity:
            continue
        if (node_id not in worst
                or Severity.sort_key(severity) < Severity.sort_key(worst[node_id])):
            worst[node_id] = severity

    return worst


def _risk_words(combined_score: float) -> str:
    """
    Turn the graph's combined risk number into a severity word.

    ``top_risk_nodes()`` blends the node's own risk with its topological
    importance, so the numbers are small; these thresholds map that range onto
    language a business owner already understands from the rest of the report.
    """
    if combined_score >= 4.5:
        return Severity.CRITICAL
    if combined_score >= 3.0:
        return Severity.HIGH
    if combined_score >= 1.0:
        return Severity.MEDIUM
    return Severity.LOW


# ===========================================================================
# Page 3 - Top vulnerabilities
# ===========================================================================

def _page_vulnerabilities(report: dict, styles, content_width: float) -> list:
    """Every critical and high finding, in the standard five-field format."""
    story: list = []
    story += _section_header(3, "The most serious problems we found", styles)

    findings = [
        f for f in (report.get("findings") or [])
        if f.get("severity") in (Severity.CRITICAL, Severity.HIGH)
    ]

    if not findings:
        story.append(_p(
            "Good news: we did not find any urgent or serious problems in this "
            "scan. The full list of smaller items is on the following pages.",
            styles["body"],
        ))
        return story

    story.append(_p(
        f"{len(findings)} problem{'s' if len(findings) != 1 else ''} need"
        f"{'' if len(findings) != 1 else 's'} attention, most urgent first. "
        f"Each one explains what it means for your business and exactly what to do.",
        styles["body"],
    ))
    story.append(Spacer(1, 10))

    for index, finding in enumerate(findings, 1):
        story.append(KeepTogether(_finding_block(index, finding, styles, content_width)))
        story.append(Spacer(1, 10))

    return story


def _finding_block(index: int, finding: dict, styles, content_width: float) -> list:
    """One finding, rendered as a bordered panel with a coloured severity edge."""
    severity = finding.get("severity", Severity.MEDIUM)
    colour   = severity_colour(severity)

    label_width = 46 * mm
    rows = [
        [Paragraph(f'<font color="white"><b>{escape(severity)}</b></font>', styles["cellBold"]),
         _p(finding.get("what_is_exposed", ""), styles["cellBold"])],
        [_p("Why it matters", styles["cellBold"]),
         _p(finding.get("why_it_matters", ""), styles["cell"])],
        [_p("How an attacker uses it", styles["cellBold"]),
         _p(finding.get("how_attacker_uses_it", ""), styles["cell"])],
        [_p("What to do", styles["cellBold"]),
         _p(finding.get("recommended_action", ""), styles["cell"])],
    ]

    table = Table(rows, colWidths=[label_width, content_width - label_width])
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), colour),
        ("BACKGROUND",    (1, 0), (1, 0), colors.HexColor(PANEL)),
        ("BACKGROUND",    (0, 1), (0, -1), colors.HexColor(PANEL)),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (0, 0), (0, 0), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 7),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor(HAIRLINE)),
        ("INNERGRID",     (0, 0), (-1, -1), 0.4, colors.HexColor(HAIRLINE)),
        ("LINEBEFORE",    (0, 0), (0, -1), 2.5, colour),
    ]))

    block = [_p(f"Problem {index}", styles["h3"]), table]

    # Technical detail, kept small and clearly separated for the IT person.
    evidence = finding.get("evidence") or []
    if evidence:
        block.append(_p("For your IT person: " + "; ".join(str(e) for e in evidence[:6]),
                        styles["muted"]))

    return block


# ===========================================================================
# Page 4 - Attack path narratives
# ===========================================================================

def _page_attack_paths(stories: list, styles, content_width: float) -> list:
    """The Phase 2 stories, laid out as numbered steps."""
    story: list = []
    story += _section_header(4, "How someone could break in", styles)

    if not stories:
        story.append(_p(
            "We could not trace a complete route into your systems from this "
            "scan. That is a good sign, though it is not a guarantee - it may "
            "also mean the scan could not see far enough to find one.",
            styles["body"],
        ))
        return story

    story.append(_p(
        "These are real routes through the systems we found, written out step "
        "by step. Breaking any single step in a route stops the whole attack.",
        styles["body"],
    ))
    story.append(Spacer(1, 10))

    for index, attack in enumerate(stories, 1):
        severity    = attack.get("severity", Severity.MEDIUM)
        colour      = severity_colour(severity)
        probability = attack.get("breach_probability", "Low")

        header = Table(
            [[Paragraph(
                f'<font color="white"><b>ROUTE {index}</b></font>', styles["cellBold"]),
              Paragraph(
                  f'<b>{escape(attack.get("title", ""))}</b><br/>'
                  f'<font color="{MUTED}" size="8">Chance of this working: '
                  f'{escape(probability)} - {escape(attack.get("probability_reason", ""))}</font>',
                  styles["cell"])]],
            colWidths=[26 * mm, content_width - 26 * mm],
        )
        header.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), colour),
            ("BACKGROUND",    (1, 0), (1, 0), colors.HexColor(PANEL)),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (0, 0), (0, 0), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (1, 0), (1, 0), 9),
        ]))

        block = [header, Spacer(1, 6)]

        for step in attack.get("steps", []):
            block.append(Paragraph(
                f'<font color="{Severity.COLORS.get(severity, BRAND)}"><b>'
                f'Step {escape(str(step.get("number", "")))}:</b></font> '
                f'{escape(step.get("text", ""))}',
                styles["step"],
            ))

        prevention = attack.get("prevention_steps") or []
        if prevention:
            block.append(Spacer(1, 4))
            block.append(_p("How to stop this route", styles["h3"]))
            for i, action in enumerate(prevention, 1):
                block.append(Paragraph(
                    f'<b>{i}.</b> {escape(action)}', styles["step"]))

        story.append(KeepTogether(block))
        story.append(Spacer(1, 14))

    return story


# ===========================================================================
# Page 5 - Full inventory
# ===========================================================================

def _page_inventory(graph, styles, content_width: float) -> list:
    """Everything discovered, for whoever maintains the systems."""
    story: list = []
    story += _section_header(5, "Everything we found", styles)

    story.append(_p(
        "The complete list of what is visible from the internet. This page is "
        "mainly for whoever looks after your computers.",
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    groups = [
        ("domain",     "Your domain"),
        ("subdomain",  "Web addresses"),
        ("ip",         "Servers"),
        ("port",       "Open doors"),
        ("service",    "Running software"),
        ("technology", "Technologies in use"),
        ("cve",        "Known weaknesses"),
    ]

    try:
        nodes = list(graph.G.nodes(data=True))
    except Exception as exc:
        log.error("Could not read the graph for the inventory: %s", exc)
        nodes = []

    for node_type, heading in groups:
        matching = [(n, d) for n, d in nodes if d.get("node_type") == node_type]
        if not matching:
            continue

        story.append(_p(f"{heading} ({len(matching)})", styles["h3"]))

        rows = [["Name", "In plain English", "Detail"]]
        for node_id, attrs in sorted(matching, key=lambda item: str(item[0]))[:60]:
            meta = attrs.get("meta") if isinstance(attrs.get("meta"), dict) else {}
            detail_bits = []

            if meta.get("version"):
                detail_bits.append(f"version {meta['version']}")
            if meta.get("cvss"):
                detail_bits.append(f"severity score {meta['cvss']}")
            if meta.get("organization"):
                detail_bits.append(str(meta["organization"]))
            if meta.get("country"):
                detail_bits.append(str(meta["country"]))
            if meta.get("outdated"):
                detail_bits.append("out of date")
            if attrs.get("exposed"):
                detail_bits.append("reachable from the internet")

            rows.append([
                _p(attrs.get("label", node_id), styles["cell"]),
                _p(friendly_name(graph, node_id), styles["cell"]),
                _p(", ".join(detail_bits), styles["cell"]),
            ])

        if len(matching) > 60:
            rows.append([_p(f"... and {len(matching) - 60} more", styles["cell"]), "", ""])

        table = Table(rows, colWidths=[content_width * 0.30, content_width * 0.42,
                                       content_width * 0.28], repeatRows=1)
        table.setStyle(_table_style())
        story.append(table)
        story.append(Spacer(1, 12))

    return story


# ===========================================================================
# Optional page - screenshots
# ===========================================================================

def _page_screenshots(graph, styles, content_width: float) -> list:
    """
    Thumbnails of the sites that were photographed.

    Only produced when Phase 4's screenshot scanner actually captured
    something, so the page never appears empty. This is often the part a
    business owner reacts to most strongly - seeing a forgotten staging copy of
    their own shop makes the risk immediate in a way no table does.
    """
    try:
        from scanners.screenshot import screenshots_in_graph
        shots = screenshots_in_graph(graph)
    except Exception as exc:
        log.debug("No screenshots available: %s", exc)
        return []

    existing = {host: path for host, path in shots.items() if os.path.exists(path)}
    if not existing:
        return []

    story: list = [PageBreak()]
    story += _section_header(6, "What your websites look like", styles)
    story.append(_p(
        "These are the pages anyone on the internet sees when they visit the "
        "addresses we found. Look for anything you do not recognise, or "
        "anything that should not be public.",
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    thumb_width  = (content_width - 8 * mm) / 2.0
    thumb_height = thumb_width * 0.56          # 16:9-ish, matches the browser size

    cells: list = []
    for host, path in sorted(existing.items()):
        try:
            image = Image(path, width=thumb_width, height=thumb_height, kind="proportional")
        except Exception as exc:
            log.debug("Could not place the screenshot for %s: %s", host, exc)
            continue

        cells.append([image, _p(host, styles["muted"])])

    # Two per row.
    for start in range(0, len(cells), 2):
        pair = cells[start:start + 2]
        row  = [_stack(cell) for cell in pair]
        while len(row) < 2:
            row.append("")

        grid = Table([row], colWidths=[thumb_width + 4 * mm] * 2)
        grid.setStyle(TableStyle([
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(grid)

    return story


def _stack(parts: list) -> "Table":
    """Stack flowables vertically inside a single table cell."""
    stacked = Table([[part] for part in parts])
    stacked.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return stacked


# ===========================================================================
# Public API
# ===========================================================================

def _format_date(raw: Any) -> str:
    """``2026-08-03T06:55:11`` -> ``03 August 2026 at 06:55``."""
    text = str(raw or "")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed.strftime("%d %B %Y at %H:%M")
    except (TypeError, ValueError):
        return datetime.now().strftime("%d %B %Y at %H:%M")


def generate_pdf(graph,
                 output_path: str = "surfacewatch_report.pdf",
                 logo_path: Optional[str] = None,
                 report: Optional[dict] = None,
                 stories: Optional[list] = None,
                 include_screenshots: bool = True) -> Optional[str]:
    """
    Build the full PDF report for a scanned graph.

    Args:
        graph               : an :class:`~graph.builder.AttackSurfaceGraph`
        output_path         : where to write the PDF
        logo_path           : optional image to use instead of the placeholder
        report              : a pre-built report dict, to avoid recomputing
        stories             : pre-built attack stories, to avoid recomputing
        include_screenshots : add the screenshot page when images exist

    Returns the path written, or ``None`` if the PDF could not be produced.
    Never raises - a failed report should not bring down a scheduled scan.
    """
    if not REPORTLAB_AVAILABLE:
        log.error(
            "Cannot create the PDF - reportlab is not installed. "
            "Install it with:  pip install reportlab"
        )
        return None

    try:
        report  = report if report is not None else generate_report(graph)
        raw_stories = stories if stories is not None else generate_stories(graph, top_n=3)
        story_dicts = [
            s if isinstance(s, dict) else s.to_dict() for s in raw_stories
        ]
    except Exception as exc:
        log.error("Could not prepare the report contents: %s", exc)
        return None

    try:
        directory = os.path.dirname(os.path.abspath(output_path))
        if directory:
            os.makedirs(directory, exist_ok=True)

        target = report.get("target", "") or getattr(graph, "target", "")

        document = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=PAGE_MARGIN, rightMargin=PAGE_MARGIN,
            topMargin=PAGE_MARGIN, bottomMargin=PAGE_MARGIN + 6 * mm,
            title=f"SurfaceWatch Security Report - {target}",
            author="SurfaceWatch",
            subject="Attack surface report",
        )

        styles        = _build_styles()
        content_width = document.width

        flowables: list = []
        flowables += _page_executive_summary(report, styles, logo_path, content_width)
        flowables.append(PageBreak())
        flowables += _page_attack_surface(graph, report, styles, content_width)
        flowables.append(PageBreak())
        flowables += _page_vulnerabilities(report, styles, content_width)
        flowables.append(PageBreak())
        flowables += _page_attack_paths(story_dicts, styles, content_width)
        flowables.append(PageBreak())
        flowables += _page_inventory(graph, styles, content_width)

        if include_screenshots:
            flowables += _page_screenshots(graph, styles, content_width)

        document.build(flowables,
                       onFirstPage=_page_decorations,
                       onLaterPages=_page_decorations)

        log.info("PDF report written to %s", output_path)
        return output_path

    except Exception as exc:
        log.error("Could not create the PDF report: %s", exc)
        return None


def generate_pdf_from_scan(scan_file: str,
                           output_path: str = "surfacewatch_report.pdf",
                           **kwargs) -> Optional[str]:
    """Convenience: load a saved scan JSON and produce the PDF from it."""
    from graph.builder import AttackSurfaceGraph

    try:
        graph = AttackSurfaceGraph.load(scan_file)
    except FileNotFoundError:
        log.error("Scan file not found: %s", scan_file)
        return None
    except Exception as exc:
        log.error("Could not read the scan file %s: %s", scan_file, exc)
        return None

    return generate_pdf(graph, output_path=output_path, **kwargs)


# ===========================================================================
# CLI:  python -m reports.pdf_generator attack_surface.json -o report.pdf
# ===========================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(
        description="Create a PDF security report from a SurfaceWatch scan."
    )
    parser.add_argument("scan_file", nargs="?", default="attack_surface.json",
                        help="Path to a saved scan JSON file")
    parser.add_argument("-o", "--output", default="surfacewatch_report.pdf",
                        help="Where to write the PDF")
    parser.add_argument("--logo", default=None,
                        help="Optional logo image to use instead of the placeholder")
    parser.add_argument("--no-screenshots", action="store_true",
                        help="Leave out the website screenshots page")
    args = parser.parse_args()

    written = generate_pdf_from_scan(
        args.scan_file,
        output_path=args.output,
        logo_path=args.logo,
        include_screenshots=not args.no_screenshots,
    )

    if not written:
        raise SystemExit("The report could not be created. See the messages above.")
    print(f"Report written to {written}")
