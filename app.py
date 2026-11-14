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

if not Config.NVD_API_KEY:
    logger.warning(
        "NVD_API_KEY is not set. CVE lookups will be rate-limited "
        "to 6.5s per request. Get a free key at "
        "https://nvd.nist.gov/developers/request-an-api-key and set "
        "the NVD_API_KEY environment variable before running scans."
    )

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
        "base-uri 'self'; "
        "object-src 'none'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
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
        total_scans = connection.execute(
            "SELECT COUNT(*) FROM assessments"
        ).fetchone()[0]
    assessments = [dict(row) for row in rows]
    return render_template(
        "index.html", assessments=assessments, total_scans=total_scans
    )


@app.route("/scan", methods=["POST"])
def scan():
    """Validate a target, record the assessment, and dispatch the scanner."""
    scan_type = (request.form.get("scan_type") or "").strip().lower()
    target = (request.form.get("target") or "").strip()

    try:
        validated_target = validate_scan_request(scan_type, target)
    except ValidationError as exc:
        logger.warning("Rejected scan request: %s", exc)
        flash(str(exc), "danger")
        return redirect(url_for("index"))

    with get_db() as conn:
        recent = conn.execute(
            """
            SELECT id FROM assessments
            WHERE target = ?
              AND scan_type = ?
              AND status IN ('pending', 'running')
              AND started_at > datetime('now', '-120 seconds')
            ORDER BY id DESC
            LIMIT 1
            """,
            (validated_target, scan_type),
        ).fetchone()

    if recent:
        flash(
            f"A scan for {validated_target} is already running "
            f"(assessment #{recent['id']}). Please wait for it to finish.",
            "warning",
        )
        return redirect(
            url_for("assessment_detail", assessment_id=recent["id"])
        )

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
        flash(
            f"Scan request recorded, but scanning is not implemented yet: {exc}",
            "warning",
        )
        return redirect(
            url_for("assessment_detail", assessment_id=assessment_id)
        )
    except Exception:
        logger.exception("Scanner failed for assessment %s", assessment_id)
        flash("The scan failed unexpectedly. Check the server log.", "danger")
        return redirect(
            url_for("assessment_detail", assessment_id=assessment_id)
        )

    if result.get("error"):
        flash(f"Scan failed: {result['error']}", "danger")
    else:
        flash(
            f"Scan complete: {result.get('findings', 0)} finding(s)",
            "info",
        )
    return redirect(url_for("assessment_detail", assessment_id=assessment_id))


@app.route("/assessment/<int:assessment_id>")
def assessment_detail(assessment_id: int):
    """Show an assessment and its findings."""
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
        findings = connection.execute(
            """
            SELECT f.id, f.assessment_id, f.asset_id, f.finding_type,
                   f.title, f.description, f.evidence, f.risk_level,
                   f.confidence, f.risk_reasoning, f.recommendation,
                   f.requires_verification, f.fingerprint,
                   f.remediation_status, f.first_seen, f.last_seen,
                   a.host, a.port, a.service, a.version
            FROM findings f
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.assessment_id = ?
            ORDER BY
                CASE f.risk_level
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                f.id DESC
            """,
            (assessment_id,),
        ).fetchall()
    if row is None:
        abort(404)
    return render_template(
        "findings.html",
        assessment=dict(row),
        findings=[dict(f) for f in findings],
    )


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
