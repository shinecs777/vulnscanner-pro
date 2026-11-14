"""Web scanner: unauthenticated HTTP security-header assessment.

The scanner performs a single GET request with TLS verification enabled and
records missing security headers as ``misconfiguration`` findings. A missing
header is a hardening gap, never a confirmed vulnerability, so every header
finding is marked ``requires_verification=1`` and capped at ``Low`` risk.
Only headers observed on the response are evaluated; no content is crawled,
no authentication is attempted, and no JavaScript is analyzed.
"""

import hashlib
import logging
from urllib.parse import urlsplit

import requests

from config import Config
from core.models import get_db

logger = logging.getLogger(__name__)

LIMITATIONS = (
    "This assessment only inspected HTTP response headers and basic TLS "
    "reachability. No authentication, crawling, injection testing, or "
    "JavaScript analysis was performed. Absence of findings does NOT mean "
    "the site is secure. This is NOT a complete web application assessment."
)

HEADER_CHECKS = {
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy",
        "type": "misconfiguration",
        "risk": "Low",
        "confidence": "high",
        "reason": (
            "Without CSP, the browser has no defense-in-depth against "
            "injected scripts. This is a hardening gap, not a confirmed XSS."
        ),
        "rec": "Define a Content-Security-Policy that restricts script sources.",
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options",
        "type": "misconfiguration",
        "risk": "Low",
        "confidence": "high",
        "reason": (
            "Without this header (or CSP frame-ancestors), the site may be "
            "clickjacked — but only if it has sensitive UI actions."
        ),
        "rec": "Send 'X-Frame-Options: DENY' or use CSP frame-ancestors.",
    },
    "Strict-Transport-Security": {
        "title": "Missing HSTS",
        "type": "misconfiguration",
        "risk": "Low",
        "confidence": "high",
        "reason": (
            "HSTS prevents SSL stripping. Absence means first-visit is "
            "downgrade-vulnerable, but not currently exploited."
        ),
        "rec": "Send 'Strict-Transport-Security: max-age=31536000'.",
    },
}


def _fingerprint(final_url: str, title: str) -> str:
    return hashlib.sha256(
        f"{final_url}|{title}".encode("utf-8")
    ).hexdigest()[:32]


def _error(message: str) -> dict:
    return {"error": message, "findings": 0, "limitations": LIMITATIONS}


def _mark_running(assessment_id: int) -> None:
    with get_db() as connection:
        connection.execute(
            "UPDATE assessments SET status = ? WHERE id = ?",
            ("running", assessment_id),
        )


def _mark_failed(assessment_id: int) -> None:
    with get_db() as connection:
        connection.execute(
            """
            UPDATE assessments
            SET status = ?, completed_at = CURRENT_TIMESTAMP, limitations = ?
            WHERE id = ?
            """,
            ("failed", LIMITATIONS, assessment_id),
        )


def _mark_completed(assessment_id: int) -> None:
    with get_db() as connection:
        connection.execute(
            """
            UPDATE assessments
            SET status = ?, completed_at = CURRENT_TIMESTAMP, limitations = ?
            WHERE id = ?
            """,
            ("completed", LIMITATIONS, assessment_id),
        )


def _insert_finding(
    connection,
    assessment_id: int,
    asset_id: int,
    *,
    finding_type: str,
    title: str,
    description: str,
    evidence: str,
    risk_level: str,
    confidence: str,
    risk_reasoning: str,
    recommendation: str,
    requires_verification: int,
    fingerprint: str,
) -> int | None:
    connection.execute(
        """
        INSERT OR IGNORE INTO findings (
            assessment_id, asset_id, finding_type, title, description, evidence,
            risk_level, confidence, risk_reasoning, recommendation,
            requires_verification, fingerprint
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            assessment_id,
            asset_id,
            finding_type,
            title,
            description,
            evidence,
            risk_level,
            confidence,
            risk_reasoning,
            recommendation,
            requires_verification,
            fingerprint,
        ),
    )
    row = connection.execute(
        """
        SELECT id FROM findings
        WHERE assessment_id = ? AND fingerprint = ?
        """,
        (assessment_id, fingerprint),
    ).fetchone()
    return row["id"] if row is not None else None


def _record_response(assessment_id: int, response) -> int:
    """Persist the asset, reachability finding, and missing-header findings."""
    final_url = response.url
    status_code = response.status_code
    headers = {name.lower(): value for name, value in response.headers.items()}

    parsed = urlsplit(final_url)
    host = parsed.hostname or ""
    port = 443 if final_url.startswith("https://") else 80
    product = headers.get("server", "unknown")

    findings_count = 0

    with get_db() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assets (
                assessment_id, host, port, protocol, service, product, version
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (assessment_id, host, port, "tcp", "http", product, ""),
        )
        asset_id = cursor.lastrowid

        title = "Web Endpoint Reachable"
        _insert_finding(
            connection,
            assessment_id,
            asset_id,
            finding_type="informational",
            title=title,
            description=f"Endpoint responded with HTTP {status_code}.",
            evidence=f"HTTP {status_code} from {final_url}",
            risk_level="Info",
            confidence="high",
            risk_reasoning="Informational — the endpoint is reachable.",
            recommendation="Continue with authenticated application testing.",
            requires_verification=0,
            fingerprint=_fingerprint(final_url, title),
        )
        findings_count += 1

        for header_name, meta in HEADER_CHECKS.items():
            if header_name.lower() in headers:
                continue
            if (
                header_name == "Strict-Transport-Security"
                and not final_url.startswith("https://")
            ):
                continue

            title = meta["title"]
            _insert_finding(
                connection,
                assessment_id,
                asset_id,
                finding_type=meta["type"],
                title=title,
                description=(
                    f"Response from {final_url} did not include {header_name}."
                ),
                evidence=f"Absent header: {header_name}",
                risk_level=meta["risk"],
                confidence=meta["confidence"],
                risk_reasoning=meta["reason"],
                recommendation=meta["rec"],
                requires_verification=1,
                fingerprint=_fingerprint(final_url, title),
            )
            findings_count += 1

    return findings_count


def scan_web(assessment_id: int, target: str) -> dict:
    """Scan a URL for security header misconfigurations.

    Caller is responsible for validating `target` via core.validator.
    """
    logger.info(
        "Starting web scan for assessment %s target=%s",
        assessment_id,
        target,
    )

    try:
        _mark_running(assessment_id)
    except Exception:
        logger.exception(
            "Failed to mark assessment %s as running", assessment_id
        )
        return _error("failed to update assessment status")

    try:
        response = requests.get(
            target,
            timeout=Config.WEB_TIMEOUT,
            allow_redirects=True,
            verify=True,
            headers={"User-Agent": Config.WEB_USER_AGENT},
        )
    except requests.exceptions.SSLError:
        logger.warning("TLS validation failed for assessment %s", assessment_id)
        _mark_failed(assessment_id)
        return _error("TLS certificate validation failed")
    except requests.exceptions.TooManyRedirects:
        logger.warning("Too many redirects for assessment %s", assessment_id)
        _mark_failed(assessment_id)
        return _error("Too many redirects")
    except requests.exceptions.Timeout:
        logger.warning("Request timed out for assessment %s", assessment_id)
        _mark_failed(assessment_id)
        return _error("Request timed out")
    except requests.exceptions.ConnectionError:
        logger.warning("Connection failed for assessment %s", assessment_id)
        _mark_failed(assessment_id)
        return _error("Connection failed")
    except requests.exceptions.RequestException as exc:
        logger.warning(
            "Request failed for assessment %s: %s", assessment_id, exc
        )
        _mark_failed(assessment_id)
        return _error(f"Request failed: {type(exc).__name__}")

    try:
        findings_count = _record_response(assessment_id, response)
        _mark_completed(assessment_id)
    except Exception:
        logger.exception(
            "Failed to process web results for assessment %s", assessment_id
        )
        try:
            _mark_failed(assessment_id)
        except Exception:
            logger.exception(
                "Failed to mark assessment %s as failed", assessment_id
            )
        return _error("failed to process scan results")

    logger.info(
        "Web scan complete: %d findings for %s",
        findings_count,
        response.url,
    )
    return {
        "findings": findings_count,
        "status_code": response.status_code,
        "final_url": response.url,
        "limitations": LIMITATIONS,
    }
