"""Tests for the PDF report generator."""

import pytest
from flask import Flask

from core.models import get_db, init_db
from reports.pdf_generator import generate_pdf


@pytest.fixture(autouse=True)
def app_context():
    app = Flask(__name__)
    with app.app_context():
        yield


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.Config.DATABASE", str(tmp_path / "test.db"))
    init_db()
    yield


@pytest.fixture
def sample_assessment(tmp_db):
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO assessments (scan_type, target, status) "
            "VALUES ('network', '192.168.1.10', 'completed')"
        )
        aid = cur.lastrowid
    return aid


def _insert_finding(assessment_id, **overrides):
    values = {
        "finding_type": "misconfiguration",
        "title": "Test finding",
        "description": "A description",
        "evidence": "Some evidence",
        "risk_level": "Low",
        "confidence": "high",
        "risk_reasoning": "Because reasons",
        "recommendation": "Fix it",
        "requires_verification": 1,
        "fingerprint": "fingerprint-default",
    }
    values.update(overrides)
    with get_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO findings (
                assessment_id, finding_type, title, description, evidence,
                risk_level, confidence, risk_reasoning, recommendation,
                requires_verification, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                values["finding_type"],
                values["title"],
                values["description"],
                values["evidence"],
                values["risk_level"],
                values["confidence"],
                values["risk_reasoning"],
                values["recommendation"],
                values["requires_verification"],
                values["fingerprint"],
            ),
        )
        return cur.lastrowid


def test_generate_pdf_returns_pdf_response(sample_assessment):
    _insert_finding(sample_assessment, fingerprint="fp-single")

    response = generate_pdf(sample_assessment)

    assert response.data[:5] == b"%PDF-"
    assert response.headers["Content-Type"] == "application/pdf"
    assert "attachment" in response.headers["Content-Disposition"]
    assert len(response.data) > 1000


def test_generate_pdf_empty_assessment(sample_assessment):
    response = generate_pdf(sample_assessment)

    assert response.data[:5] == b"%PDF-"
    assert len(response.data) > 1000


def test_generate_pdf_missing_assessment(tmp_db):
    with pytest.raises(ValueError):
        generate_pdf(99999)


def test_generate_pdf_with_multiple_findings(sample_assessment):
    _insert_finding(
        sample_assessment,
        title="Critical issue",
        risk_level="Critical",
        finding_type="potential_vuln",
        fingerprint="fp-critical",
    )
    _insert_finding(
        sample_assessment,
        title="Medium issue",
        risk_level="Medium",
        finding_type="misconfiguration",
        fingerprint="fp-medium",
    )
    _insert_finding(
        sample_assessment,
        title="Low issue",
        risk_level="Low",
        finding_type="informational",
        fingerprint="fp-low",
    )

    response = generate_pdf(sample_assessment)

    assert response.data[:5] == b"%PDF-"
    assert len(response.data) > 2000


def test_generate_pdf_handles_null_fields(sample_assessment):
    _insert_finding(
        sample_assessment,
        title="Null fields finding",
        description=None,
        evidence=None,
        risk_reasoning=None,
        recommendation=None,
        risk_level="Info",
        finding_type="informational",
        fingerprint="fp-null",
    )

    response = generate_pdf(sample_assessment)

    assert response.data[:5] == b"%PDF-"
