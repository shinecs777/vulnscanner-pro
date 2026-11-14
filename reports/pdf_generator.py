"""PDF report generation for assessments.

The generator reads an assessment, its findings (joined with assets), and any
correlated CVEs, then renders a paginated PDF with reportlab's platypus
framework. All user-supplied strings are rendered as Paragraph flowables so
that long evidence blobs and descriptions wrap instead of overflowing the page.
The report is built entirely in memory and returned as a Flask Response; no
file is written to disk.
"""

import io
import json
import logging
from xml.sax.saxutils import escape

from flask import make_response
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core.models import get_db

logger = logging.getLogger(__name__)

RISK_COLORS = {
    "Critical": colors.HexColor("#FF0050"),
    "High": colors.HexColor("#FF4757"),
    "Medium": colors.HexColor("#FFA502"),
    "Low": colors.HexColor("#2ED573"),
    "Info": colors.HexColor("#70A1FF"),
}

RISK_TEXT_COLORS = {
    "Critical": colors.white,
    "High": colors.white,
    "Medium": colors.black,
    "Low": colors.black,
    "Info": colors.black,
}

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

GREY_BG = colors.HexColor("#F2F2F2")
GRID_COLOR = colors.HexColor("#B0B0B0")


def _esc(value) -> str:
    """Escape a value for safe inclusion in a reportlab Paragraph."""
    if value is None:
        return ""
    return escape(str(value)).replace("\n", "<br/>")


def _trunc(value, limit: int):
    """Truncate raw text to `limit` characters, adding an ellipsis."""
    if value is None:
        return None
    text = str(value)
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _trunc_esc(value, limit: int) -> str:
    return _esc(_trunc(value, limit))


def _parse_references(raw) -> list:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if isinstance(data, list):
        return [str(url) for url in data if url]
    return []


def _fetch_data(assessment_id: int):
    """Return (assessment_dict, items) or None when the assessment is absent."""
    with get_db() as connection:
        assessment_row = connection.execute(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()
        if assessment_row is None:
            return None

        rows = connection.execute(
            """
            SELECT
                f.*,
                a.id AS asset_row_id,
                a.host AS asset_host,
                a.port AS asset_port,
                a.protocol AS asset_protocol,
                a.service AS asset_service,
                a.product AS asset_product,
                a.version AS asset_version
            FROM findings f
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.assessment_id = ?
            """,
            (assessment_id,),
        ).fetchall()

        items = []
        for row in rows:
            record = dict(row)
            asset = None
            if record.get("asset_row_id") is not None:
                asset = {
                    "id": record["asset_row_id"],
                    "host": record.get("asset_host"),
                    "port": record.get("asset_port"),
                    "protocol": record.get("asset_protocol"),
                    "service": record.get("asset_service"),
                    "product": record.get("asset_product"),
                    "version": record.get("asset_version"),
                }

            cve_rows = connection.execute(
                """
                SELECT c.cve_id, c.cvss_score, c.cvss_severity,
                       c.description, c.references_json
                FROM finding_cves fc
                JOIN cve_records c ON c.cve_id = fc.cve_id
                WHERE fc.finding_id = ?
                """,
                (record["id"],),
            ).fetchall()

            items.append(
                {
                    "finding": record,
                    "asset": asset,
                    "cves": [dict(cve) for cve in cve_rows],
                }
            )

    return dict(assessment_row), items


def _sort_items(items: list) -> list:
    def sort_key(item):
        finding = item["finding"]
        risk = RISK_ORDER.get(finding.get("risk_level"), 5)
        informational = 1 if finding.get("finding_type") == "informational" else 0
        return (risk, informational, finding.get("id", 0))

    return sorted(items, key=sort_key)


def _severity_counts(items: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in items:
        risk = item["finding"].get("risk_level")
        if risk in counts:
            counts[risk] += 1
    return counts


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=22,
            leading=26,
            spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=12,
            textColor=colors.HexColor("#555555"),
            spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "SectionHeading",
            parent=base["Heading2"],
            fontSize=14,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=9.5,
            leading=13,
        ),
        "body_bold": ParagraphStyle(
            "BodyBold",
            parent=base["Normal"],
            fontSize=9.5,
            leading=13,
            fontName="Helvetica-Bold",
        ),
        "detail_title": ParagraphStyle(
            "DetailTitle",
            parent=base["Normal"],
            fontSize=11,
            leading=14,
            fontName="Helvetica-Bold",
            spaceBefore=4,
            spaceAfter=2,
        ),
        "small": ParagraphStyle(
            "Small",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#555555"),
        ),
        "cell": ParagraphStyle(
            "Cell",
            parent=base["Normal"],
            fontSize=8.5,
            leading=11,
        ),
        "cell_header": ParagraphStyle(
            "CellHeader",
            parent=base["Normal"],
            fontSize=8.5,
            leading=11,
            fontName="Helvetica-Bold",
            textColor=colors.white,
        ),
    }


def _metadata_table(assessment: dict, width: float, styles: dict) -> Table:
    completed = assessment.get("completed_at") or "in progress"
    rows = [
        ["Target", assessment.get("target") or "N/A"],
        ["Type", assessment.get("scan_type") or "N/A"],
        ["Status", assessment.get("status") or "N/A"],
        ["Started", assessment.get("started_at") or "N/A"],
        ["Completed", completed],
    ]
    data = [
        [
            Paragraph(_esc(label), styles["body_bold"]),
            Paragraph(_esc(value), styles["body"]),
        ]
        for label, value in rows
    ]
    table = Table(data, colWidths=[width * 0.25, width * 0.75])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
                ("BACKGROUND", (0, 0), (0, -1), GREY_BG),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _summary_table(counts: dict, total: int, width: float, styles: dict) -> Table:
    labels = ["Total", "Critical", "High", "Medium", "Low", "Info"]
    values = [
        total,
        counts["Critical"],
        counts["High"],
        counts["Medium"],
        counts["Low"],
        counts["Info"],
    ]
    data = [
        [Paragraph(label, styles["cell_header"]) for label in labels],
        [Paragraph(str(value), styles["body_bold"]) for value in values],
    ]
    table = Table(data, colWidths=[width / 6.0] * 6)
    style = [
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#555555")),
        ("BACKGROUND", (1, 0), (1, 0), RISK_COLORS["Critical"]),
        ("BACKGROUND", (2, 0), (2, 0), RISK_COLORS["High"]),
        ("BACKGROUND", (3, 0), (3, 0), RISK_COLORS["Medium"]),
        ("BACKGROUND", (4, 0), (4, 0), RISK_COLORS["Low"]),
        ("BACKGROUND", (5, 0), (5, 0), RISK_COLORS["Info"]),
        ("BACKGROUND", (0, 1), (0, 1), GREY_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for column, risk in enumerate(
        ["Critical", "High", "Medium", "Low", "Info"], start=1
    ):
        style.append(
            (
                "TEXTCOLOR",
                (column, 0),
                (column, 0),
                RISK_TEXT_COLORS[risk],
            )
        )
    table.setStyle(TableStyle(style))
    return table


def _cve_cell_text(cves: list) -> str:
    parts = []
    for cve in cves:
        score = cve.get("cvss_score")
        score_text = "N/A" if score is None else score
        parts.append(f"{cve.get('cve_id')} (CVSS {score_text})")
    return _esc(", ".join(parts))


def _findings_table(items: list, width: float, styles: dict) -> Table:
    header = ["#", "Title", "Type", "Risk", "Confidence", "CVE(s)"]
    data = [[Paragraph(text, styles["cell_header"]) for text in header]]

    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]

    for index, item in enumerate(items, start=1):
        finding = item["finding"]
        risk = finding.get("risk_level")
        title = finding.get("title") or ""
        if finding.get("requires_verification"):
            title = f"\u26a0 {title}"
        risk_style = ParagraphStyle(
            f"Risk{index}",
            parent=styles["cell"],
            fontName="Helvetica-Bold",
            textColor=RISK_TEXT_COLORS.get(risk, colors.black),
        )
        data.append(
            [
                Paragraph(str(index), styles["cell"]),
                Paragraph(_esc(title), styles["cell"]),
                Paragraph(_esc(finding.get("finding_type")), styles["cell"]),
                Paragraph(_esc(risk), risk_style),
                Paragraph(_esc(finding.get("confidence")), styles["cell"]),
                Paragraph(_cve_cell_text(item["cves"]), styles["cell"]),
            ]
        )
        if risk in RISK_COLORS:
            style.append(("BACKGROUND", (3, index), (3, index), RISK_COLORS[risk]))

    table = Table(
        data,
        colWidths=[
            width * 0.05,
            width * 0.33,
            width * 0.15,
            width * 0.10,
            width * 0.12,
            width * 0.25,
        ],
        repeatRows=1,
    )
    table.setStyle(TableStyle(style))
    return table


def _limitations_flowable(assessment: dict, width: float, styles: dict) -> Table:
    text = assessment.get("limitations") or "Not specified."
    paragraph = Paragraph(f"<b>Limitations:</b> {_esc(text)}", styles["body"])
    table = Table([[paragraph]], colWidths=[width])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), GREY_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, GRID_COLOR),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _detail_flowables(items: list, styles: dict) -> list:
    flowables = []
    for index, item in enumerate(items, start=1):
        finding = item["finding"]
        title = finding.get("title") or ""
        if finding.get("requires_verification"):
            title = f"\u26a0 {title}"
        flowables.append(Paragraph(f"#{index} \u2014 {_esc(title)}", styles["detail_title"]))
        flowables.append(
            Paragraph(
                f"Type: {_esc(finding.get('finding_type'))} | "
                f"Risk: {_esc(finding.get('risk_level'))} | "
                f"Confidence: {_esc(finding.get('confidence'))}",
                styles["body"],
            )
        )
        flowables.append(
            Paragraph(f"Evidence: {_esc(finding.get('evidence')) or 'N/A'}", styles["body"])
        )
        flowables.append(
            Paragraph(
                f"Description: {_trunc_esc(finding.get('description'), 500) or 'N/A'}",
                styles["body"],
            )
        )
        flowables.append(
            Paragraph(
                f"Risk rationale: {_esc(finding.get('risk_reasoning')) or 'N/A'}",
                styles["body"],
            )
        )
        flowables.append(
            Paragraph(
                f"Recommendation: {_esc(finding.get('recommendation')) or 'N/A'}",
                styles["body"],
            )
        )

        if item["cves"]:
            flowables.append(Paragraph("Referenced CVEs:", styles["body_bold"]))
            for cve in item["cves"]:
                score = cve.get("cvss_score")
                score_text = "N/A" if score is None else score
                severity = cve.get("cvss_severity") or "N/A"
                flowables.append(
                    Paragraph(
                        f"\u2022 {_esc(cve.get('cve_id'))} "
                        f"(CVSS {score_text}: {_esc(severity)})",
                        styles["body"],
                    )
                )
                flowables.append(
                    Paragraph(
                        f"&nbsp;&nbsp;{_trunc_esc(cve.get('description'), 400) or 'No description available.'}",
                        styles["body"],
                    )
                )
                references = _parse_references(cve.get("references_json"))
                if references:
                    flowables.append(
                        Paragraph(f"&nbsp;&nbsp;{_esc(references[0])}", styles["body"])
                    )

        flowables.append(Spacer(1, 12))

    return flowables


def _build_story(assessment: dict, items: list, width: float) -> list:
    styles = _build_styles()
    counts = _severity_counts(items)
    total = len(items)

    story = [
        Paragraph("Vulnerability Assessment Report", styles["title"]),
        Paragraph(f"Assessment #{assessment.get('id')}", styles["subtitle"]),
        _metadata_table(assessment, width, styles),
        Paragraph("Severity Summary", styles["h2"]),
        _summary_table(counts, total, width, styles),
        Paragraph("Limitations", styles["h2"]),
        _limitations_flowable(assessment, width, styles),
        Paragraph("Findings", styles["h2"]),
    ]

    if items:
        story.append(_findings_table(items, width, styles))
    else:
        story.append(
            Paragraph("No findings recorded for this assessment.", styles["body"])
        )

    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", styles["h2"]))

    if items:
        story.extend(_detail_flowables(items, styles))
    else:
        story.append(
            Paragraph("No findings recorded for this assessment.", styles["body"])
        )

    return story


def generate_pdf(assessment_id: int):
    """Build a PDF report for the given assessment and return a Flask Response.

    Raises ValueError if the assessment does not exist.
    """
    data = _fetch_data(assessment_id)
    if data is None:
        logger.warning("Assessment %s not found for PDF report", assessment_id)
        raise ValueError(f"Assessment {assessment_id} not found")

    assessment, raw_items = data
    items = _sort_items(raw_items)

    margin = 0.75 * inch
    width = letter[0] - 2 * margin

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin,
        bottomMargin=margin,
        title=f"Vulnerability Assessment Report #{assessment_id}",
        author="VulnScanner Pro",
    )

    story = _build_story(assessment, items, width)
    document.build(story)
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="vulnerability_report_'
        f'assessment_{assessment_id}.pdf"'
    )

    logger.info(
        "Generated PDF for assessment %s (%d findings)",
        assessment_id,
        len(items),
    )
    return response
