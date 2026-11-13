"""Tests for scanner implementations and still-stubbed scanner boundaries."""

import subprocess

import pytest

import scanners.network_scanner as network_scanner
from config import Config
from core.models import get_db, init_db
from reports.pdf_generator import generate_pdf
from scanners.cve_lookup import search_cves
from scanners.web_scanner import scan_web


def mock_completed(stdout, returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _patch_subprocess(monkeypatch, stdout, returncode=0, stderr=""):
    def fake_run(*args, **kwargs):
        assert kwargs.get("shell") is False
        assert isinstance(args[0], list)
        return mock_completed(stdout, returncode=returncode, stderr=stderr)

    monkeypatch.setattr(network_scanner.subprocess, "run", fake_run)


def _service_xml(port, protocol, name, product="", version=""):
    return (
        f'<port protocol="{protocol}" portid="{port}">'
        '<state state="open"/>'
        f'<service name="{name}" product="{product}" version="{version}"/>'
        "</port>"
    )


def _xml(services):
    ports = "".join(
        _service_xml(
            service["port"],
            service.get("protocol", "tcp"),
            service["name"],
            service.get("product", ""),
            service.get("version", ""),
        )
        for service in services
    )
    return (
        '<?xml version="1.0"?>'
        "<nmaprun>"
        "<host>"
        '<status state="up"/>'
        '<address addr="10.0.0.5" addrtype="ipv4"/>'
        f"<ports>{ports}</ports>"
        "</host>"
        "</nmaprun>"
    )


def _assessment_status(assessment_id):
    with get_db() as connection:
        row = connection.execute(
            "SELECT status FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()
    return row["status"]


def _findings(assessment_id):
    with get_db() as connection:
        rows = connection.execute(
            "SELECT * FROM findings WHERE assessment_id = ?", (assessment_id,)
        ).fetchall()
    return [dict(row) for row in rows]


@pytest.fixture()
def tmp_assessment(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "DATABASE", str(tmp_path / "test.db"))
    init_db()
    with get_db() as connection:
        cursor = connection.execute(
            "INSERT INTO assessments (scan_type, target) VALUES (?, ?)",
            ("network", "10.0.0.5"),
        )
        assessment_id = cursor.lastrowid
    return assessment_id


def test_scan_network_missing_nmap(monkeypatch, tmp_assessment):
    monkeypatch.setattr(Config, "NMAP_PATH", "C:/nonexistent/nmap.exe")

    result = network_scanner.scan_network(tmp_assessment, "10.0.0.5")

    assert "error" in result
    assert "nmap not found" in result["error"].lower()
    assert result["findings"] == 0
    assert _assessment_status(tmp_assessment) == "failed"


def test_scan_network_nmap_nonzero(monkeypatch, tmp_assessment):
    _patch_subprocess(monkeypatch, stdout="", returncode=1, stderr="some error")

    result = network_scanner.scan_network(tmp_assessment, "10.0.0.5")

    assert "error" in result
    assert "nmap exited with 1" in result["error"]
    assert _assessment_status(tmp_assessment) == "failed"


def test_scan_network_xml_parse_error(monkeypatch, tmp_assessment):
    _patch_subprocess(monkeypatch, stdout="not xml", returncode=0, stderr="")

    result = network_scanner.scan_network(tmp_assessment, "10.0.0.5")

    assert "error" in result
    assert "parse" in result["error"].lower()
    assert _assessment_status(tmp_assessment) == "failed"


def test_scan_network_empty_result(monkeypatch, tmp_assessment):
    _patch_subprocess(monkeypatch, stdout=_xml([]), returncode=0, stderr="")

    result = network_scanner.scan_network(tmp_assessment, "10.0.0.5")

    assert result["findings"] == 0
    assert result["hosts"] == 1
    assert result["limitations"] and len(result["limitations"]) > 50
    assert _assessment_status(tmp_assessment) == "completed"


def test_scan_network_telnet_finding(monkeypatch, tmp_assessment):
    _patch_subprocess(
        monkeypatch,
        stdout=_xml(
            [
                {
                    "port": 23,
                    "protocol": "tcp",
                    "name": "telnet",
                    "product": "Linux telnetd",
                    "version": "",
                }
            ]
        ),
    )

    network_scanner.scan_network(tmp_assessment, "10.0.0.5")

    findings = _findings(tmp_assessment)
    confirmed = [
        finding
        for finding in findings
        if finding["finding_type"] == "confirmed_vuln"
    ]
    assert len(confirmed) == 1
    assert confirmed[0]["risk_level"] == "High"
    assert confirmed[0]["requires_verification"] == 0
    assert confirmed[0]["confidence"] == "high"


def test_scan_network_http_is_informational(monkeypatch, tmp_assessment):
    def raise_not_implemented(keyword, max_results=5):
        raise NotImplementedError("CVE lookup is not implemented")

    monkeypatch.setattr(network_scanner, "search_cves", raise_not_implemented)
    _patch_subprocess(
        monkeypatch,
        stdout=_xml(
            [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "name": "http",
                    "product": "nginx",
                    "version": "1.18.0",
                }
            ]
        ),
    )

    network_scanner.scan_network(tmp_assessment, "10.0.0.5")

    findings = _findings(tmp_assessment)
    port_80 = [
        finding
        for finding in findings
        if "port 80/tcp" in (finding["evidence"] or "").lower()
    ]
    assert any(
        finding["finding_type"] == "informational" for finding in port_80
    )
    assert not any(
        finding["finding_type"] == "confirmed_vuln" for finding in port_80
    )
    assert not any(
        finding["risk_level"] in ("High", "Critical") for finding in port_80
    )


def test_scan_network_ssh_not_flagged(monkeypatch, tmp_assessment):
    def raise_not_implemented(keyword, max_results=5):
        raise NotImplementedError("CVE lookup is not implemented")

    monkeypatch.setattr(network_scanner, "search_cves", raise_not_implemented)
    _patch_subprocess(
        monkeypatch,
        stdout=_xml(
            [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "8.9",
                }
            ]
        ),
    )

    network_scanner.scan_network(tmp_assessment, "10.0.0.5")

    findings = _findings(tmp_assessment)
    assert not any(
        finding["finding_type"] == "confirmed_vuln" for finding in findings
    )
    assert any(
        finding["finding_type"] == "informational" for finding in findings
    )


def test_scan_network_cve_lookup_skipped_gracefully(
    monkeypatch, tmp_assessment
):
    def raise_not_implemented(keyword, max_results=5):
        raise NotImplementedError("CVE lookup is not implemented")

    monkeypatch.setattr(network_scanner, "search_cves", raise_not_implemented)
    _patch_subprocess(
        monkeypatch,
        stdout=_xml(
            [
                {
                    "port": 8080,
                    "protocol": "tcp",
                    "name": "http-alt",
                    "product": "nginx",
                    "version": "1.18.0",
                }
            ]
        ),
    )

    result = network_scanner.scan_network(tmp_assessment, "10.0.0.5")

    assert "error" not in result
    assert _assessment_status(tmp_assessment) == "completed"
    findings = _findings(tmp_assessment)
    assert not any(
        finding["finding_type"] == "potential_vuln" for finding in findings
    )


def test_scan_network_cve_creates_potential_finding(
    monkeypatch, tmp_assessment
):
    def fake_search_cves(keyword, max_results=5):
        assert keyword == "Apache 2.4.49"
        assert max_results == 3
        return [
            {
                "cve_id": "CVE-2021-41773",
                "description": "Path traversal in Apache HTTP Server 2.4.49.",
                "cvss_score": 7.5,
                "cvss_severity": "HIGH",
                "published": "2021-10-05",
                "references": [],
            }
        ]

    monkeypatch.setattr(network_scanner, "search_cves", fake_search_cves)
    _patch_subprocess(
        monkeypatch,
        stdout=_xml(
            [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "name": "http",
                    "product": "Apache",
                    "version": "2.4.49",
                }
            ]
        ),
    )

    result = network_scanner.scan_network(tmp_assessment, "10.0.0.5")
    assert "error" not in result

    with get_db() as connection:
        finding = connection.execute(
            """
            SELECT * FROM findings
            WHERE assessment_id = ? AND finding_type = ?
            """,
            (tmp_assessment, "potential_vuln"),
        ).fetchone()
        cve_record = connection.execute(
            "SELECT * FROM cve_records WHERE cve_id = ?",
            ("CVE-2021-41773",),
        ).fetchone()
        link = connection.execute(
            """
            SELECT * FROM finding_cves
            WHERE finding_id = ? AND cve_id = ?
            """,
            (finding["id"], "CVE-2021-41773"),
        ).fetchone()

    assert finding["risk_level"] == "High"
    assert finding["requires_verification"] == 1
    assert finding["confidence"] == "low"
    assert cve_record is not None
    assert link is not None
    assert link["is_confirmed"] == 0


class TestScannerStubs:
    def test_web_scanner_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Phase 3"):
            scan_web(1, "https://example.com")

    def test_cve_lookup_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Phase 4"):
            search_cves("Apache")

    def test_pdf_generator_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Phase 5"):
            generate_pdf(1)
