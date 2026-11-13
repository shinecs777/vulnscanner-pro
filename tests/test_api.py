"""API-level tests for the Flask application."""

import pytest

from app import app
from config import Config
from core.database import get_db
from core.models import init_db


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "DATABASE", str(tmp_path / "test.db"))
    init_db()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    try:
        with app.test_client() as test_client:
            yield test_client
    finally:
        app.config.update(TESTING=False, WTF_CSRF_ENABLED=True)


def test_index_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"VulnScanner Pro" in response.data


def test_scan_invalid_target_redirects_and_flashes(client):
    response = client.post(
        "/scan",
        data={"scan_type": "network", "target": "127.0.0.1"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Loopback addresses are not allowed" in response.data


def test_scan_shell_metachar_target_rejected(client):
    response = client.post(
        "/scan",
        data={"scan_type": "web", "target": "example.com; rm -rf /"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"shell metacharacters" in response.data.lower()

    with get_db() as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS total FROM assessments"
        ).fetchone()["total"]
    assert count == 0


def test_valid_target_is_recorded_without_fake_findings(client):
    response = client.post(
        "/scan",
        data={"scan_type": "network", "target": "10.0.0.5"},
    )
    assert response.status_code == 302

    with get_db() as connection:
        assessment = connection.execute(
            "SELECT status, limitations FROM assessments"
        ).fetchone()
        findings = connection.execute(
            "SELECT COUNT(*) AS total FROM findings"
        ).fetchone()["total"]

    assert assessment["status"] == "not_implemented"
    assert "not yet implemented" in assessment["limitations"].lower()
    assert findings == 0


def test_csrf_rejection_without_token(client):
    app.config["WTF_CSRF_ENABLED"] = True
    response = client.post(
        "/scan",
        data={"scan_type": "network", "target": "10.0.0.5"},
    )
    assert response.status_code == 400


def test_security_headers_present(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_missing_assessment_returns_404(client):
    assert client.get("/assessment/999999").status_code == 404
