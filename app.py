"""Flask routes for VulnScanner Pro.

Route handlers stay thin: validation, persistence, and scanning live in the
core and scanner packages. No findings are synthesized here.
"""

import logging

from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFProtect

from config import Config
from core.database import get_db
from core.logger import setup_logging
from core.models import init_db
from core.validator import ValidationError, validate_scan_request
from reports.pdf_generator import generate_pdf
from scanners.network_scanner import scan_network
from scanners.web_scanner import scan_web

setup_logging()
init_db()

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=Config.SECRET_KEY,
    DEBUG=Config.DEBUG,
    WTF_CSRF_ENABLED=True,
)
csrf = CSRFProtect(app)


@app.after_request
def add_security_headers(response):
    """Apply conservative browser security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.route("/")
def index():
    """Show the scan form and the most recent assessments."""
    with get_db() as connection:
        rows = connection.execute(
            """
            SELECT id, scan_type, target, status, started_at
            FROM assessments
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()
    assessments = [dict(row) for row in rows]
    return render_template("index.html", assessments=assessments)


@app.route("/scan", methods=["POST"])
def scan():
    """Validate a target, record the assessment, and dispatch the scanner."""
    scan_type = (request.form.get("scan_type") or "").strip().lower()
    target = (request.form.get("target") or "").strip()

    try:
        validated_target = validate_scan_request(scan_type, target)
    except ValidationError as exc:
        logger.warning("Rejected scan request: %s", exc)
        flash(str(exc), "error")
        return redirect(url_for("index"))

    with get_db() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assessments (scan_type, target, status)
            VALUES (?, ?, ?)
            """,
            (scan_type, validated_target, "pending"),
        )
        assessment_id = cursor.lastrowid

    runner = scan_network if scan_type == "network" else scan_web

    try:
        result = runner(assessment_id, validated_target)
    except NotImplementedError as exc:
        logger.warning(
            "Scanner for assessment %s is not implemented: %s",
            assessment_id,
            exc,
        )
        with get_db() as connection:
            connection.execute(
                """
                UPDATE assessments
                SET status = ?, completed_at = datetime('now'), limitations = ?
                WHERE id = ?
                """,
                ("not_implemented", str(exc), assessment_id),
            )
        flash(
            f"Scan request recorded, but scanning is not implemented yet: {exc}",
            "warning",
        )
        return redirect(
            url_for("assessment_detail", assessment_id=assessment_id)
        )
    except Exception:
        logger.exception("Scanner failed for assessment %s", assessment_id)
        with get_db() as connection:
            connection.execute(
                """
                UPDATE assessments
                SET status = ?, completed_at = datetime('now'), limitations = ?
                WHERE id = ?
                """,
                ("failed", "Scanner raised an unexpected error.", assessment_id),
            )
        flash("The scan failed unexpectedly. Check the server log.", "error")
        return redirect(
            url_for("assessment_detail", assessment_id=assessment_id)
        )

    findings_count = result.get("findings", 0)
    limitations = result.get("limitations")
    with get_db() as connection:
        connection.execute(
            """
            UPDATE assessments
            SET status = ?, completed_at = datetime('now'), limitations = ?
            WHERE id = ?
            """,
            ("completed", limitations, assessment_id),
        )
    flash(f"Scan completed with {findings_count} finding(s).", "success")
    return redirect(url_for("assessment_detail", assessment_id=assessment_id))


@app.route("/assessment/<int:assessment_id>")
def assessment_detail(assessment_id: int):
    """Show the findings placeholder for a single assessment."""
    with get_db() as connection:
        row = connection.execute(
            """
            SELECT id, scan_type, target, started_at, completed_at, status,
                   limitations
            FROM assessments
            WHERE id = ?
            """,
            (assessment_id,),
        ).fetchone()
    if row is None:
        abort(404)
    return render_template("findings.html", assessment=dict(row))


@app.route("/assessment/<int:assessment_id>/report")
def assessment_report(assessment_id: int):
    """Return a generated PDF report, or 501 while generation is a stub."""
    with get_db() as connection:
        row = connection.execute(
            "SELECT id FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()
    if row is None:
        abort(404)

    try:
        pdf_bytes = generate_pdf(assessment_id)
    except NotImplementedError as exc:
        logger.warning("PDF generation unavailable: %s", exc)
        return {"error": str(exc)}, 501

    return pdf_bytes, 200, {
        "Content-Type": "application/pdf",
        "Content-Disposition": (
            f'attachment; filename="assessment-{assessment_id}.pdf"'
        ),
    }


@app.route("/comparison")
def comparison():
    """Show the assessment comparison placeholder."""
    return render_template("comparison.html")


if __name__ == "__main__":
    if Config.DEBUG:
        logger.warning(
            "Config.DEBUG is enabled but the development server will still "
            "start with debug=False. Use a proper debugger outside production."
        )
    logger.info("Starting VulnScanner Pro on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
