"""Tests for scanner implementations and still-stubbed scanner boundaries."""

import subprocess

import pytest
import requests

import scanners.network_scanner as network_scanner
import scanners.web_scanner as web_scanner
import scanners.cve_lookup as cve_lookup
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


class FakeResponse:
    def __init__(self, status_code=200, url="https://example.com/", headers=None):
        self.status_code = status_code
        self.url = url
        self.headers = dict(headers or {})


@pytest.fixture()
def web_assessment(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "DATABASE", str(tmp_path / "test_web.db"))
    init_db()
    with get_db() as connection:
        cursor = connection.execute(
            "INSERT INTO assessments (scan_type, target) VALUES (?, ?)",
            ("web", "https://example.com"),
        )
        assessment_id = cursor.lastrowid
    return assessment_id


def _patch_web_get(monkeypatch, response=None, exc=None, captured=None):
    def fake_get(url, **kwargs):
        if captured is not None:
            captured["url"] = url
            captured.update(kwargs)
        if exc is not None:
            raise exc
        return response

    monkeypatch.setattr(web_scanner.requests, "get", fake_get)


def _titles(assessment_id):
    return [finding["title"] for finding in _findings(assessment_id)]


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "DATABASE", str(tmp_path / "test_cve.db"))
    init_db()
    yield


class FakeNvdResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def _patch_nvd(monkeypatch, response=None, exc=None, captured=None):
    def fake_get(url, **kwargs):
        if captured is not None:
            captured["url"] = url
            captured.update(kwargs)
        if exc is not None:
            raise exc
        return response

    monkeypatch.setattr(cve_lookup.requests, "get", fake_get)
    monkeypatch.setattr(cve_lookup.time, "sleep", lambda *args, **kwargs: None)


def _nvd_cve(cve_id, score=7.5, severity="HIGH"):
    cve = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"Description for {cve_id}"}],
        "published": "2020-01-02T03:04:05.000",
        "references": [{"url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}],
    }
    if score is not None or severity is not None:
        cve["metrics"] = {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": score, "baseSeverity": severity}}
            ]
        }
    return {"cve": cve}


def _cve_count():
    with get_db() as connection:
        return connection.execute(
            "SELECT COUNT(*) AS total FROM cve_records"
        ).fetchone()["total"]


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


def test_scan_web_connection_error(monkeypatch, web_assessment):
    _patch_web_get(monkeypatch, exc=requests.exceptions.ConnectionError())

    result = scan_web(web_assessment, "https://example.com")

    assert result["error"] == "Connection failed"
    assert result["findings"] == 0
    assert result["limitations"]
    assert _assessment_status(web_assessment) == "failed"
    assert _findings(web_assessment) == []


def test_scan_web_timeout(monkeypatch, web_assessment):
    _patch_web_get(monkeypatch, exc=requests.exceptions.Timeout())

    result = scan_web(web_assessment, "https://example.com")

    assert result["error"] == "Request timed out"
    assert result["findings"] == 0
    assert result["limitations"]
    assert _assessment_status(web_assessment) == "failed"


def test_scan_web_too_many_redirects(monkeypatch, web_assessment):
    _patch_web_get(monkeypatch, exc=requests.exceptions.TooManyRedirects())

    result = scan_web(web_assessment, "https://example.com")

    assert result["error"] == "Too many redirects"
    assert result["findings"] == 0
    assert result["limitations"]
    assert _assessment_status(web_assessment) == "failed"


def test_scan_web_all_headers_present(monkeypatch, web_assessment):
    response = FakeResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Server": "nginx",
        }
    )
    _patch_web_get(monkeypatch, response=response)

    result = scan_web(web_assessment, "https://example.com")

    assert "error" not in result
    assert result["findings"] == 1
    assert result["status_code"] == 200
    assert result["final_url"] == "https://example.com/"
    assert result["limitations"]
    assert _assessment_status(web_assessment) == "completed"
    findings = _findings(web_assessment)
    assert len(findings) == 1
    assert findings[0]["title"] == "Web Endpoint Reachable"
    assert findings[0]["finding_type"] == "informational"


def test_scan_web_missing_csp(monkeypatch, web_assessment):
    response = FakeResponse(
        headers={
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
        }
    )
    _patch_web_get(monkeypatch, response=response)

    result = scan_web(web_assessment, "https://example.com")

    assert result["findings"] == 2
    csp = [
        finding
        for finding in _findings(web_assessment)
        if finding["title"] == "Missing Content-Security-Policy"
    ]
    assert len(csp) == 1
    assert csp[0]["finding_type"] == "misconfiguration"
    assert csp[0]["risk_level"] == "Low"
    assert csp[0]["confidence"] == "high"
    assert csp[0]["requires_verification"] == 1
    assert csp[0]["evidence"] == "Absent header: Content-Security-Policy"


def test_scan_web_missing_xframe(monkeypatch, web_assessment):
    response = FakeResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
        }
    )
    _patch_web_get(monkeypatch, response=response)

    result = scan_web(web_assessment, "https://example.com")

    assert result["findings"] == 2
    xframe = [
        finding
        for finding in _findings(web_assessment)
        if finding["title"] == "Missing X-Frame-Options"
    ]
    assert len(xframe) == 1
    assert xframe[0]["finding_type"] == "misconfiguration"
    assert xframe[0]["risk_level"] == "Low"
    assert xframe[0]["requires_verification"] == 1
    assert xframe[0]["evidence"] == "Absent header: X-Frame-Options"


def test_scan_web_http_skips_hsts(monkeypatch, web_assessment):
    response = FakeResponse(
        url="http://example.com/",
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        },
    )
    _patch_web_get(monkeypatch, response=response)

    result = scan_web(web_assessment, "http://example.com")

    assert result["findings"] == 1
    assert "Missing HSTS" not in _titles(web_assessment)


def test_scan_web_https_flags_hsts(monkeypatch, web_assessment):
    response = FakeResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        }
    )
    _patch_web_get(monkeypatch, response=response)

    result = scan_web(web_assessment, "https://example.com")

    assert result["findings"] == 2
    hsts = [
        finding
        for finding in _findings(web_assessment)
        if finding["title"] == "Missing HSTS"
    ]
    assert len(hsts) == 1
    assert hsts[0]["finding_type"] == "misconfiguration"
    assert hsts[0]["risk_level"] == "Low"
    assert hsts[0]["requires_verification"] == 1
    assert hsts[0]["evidence"] == "Absent header: Strict-Transport-Security"


def test_scan_web_all_three_missing(monkeypatch, web_assessment):
    _patch_web_get(monkeypatch, response=FakeResponse(headers={}))

    result = scan_web(web_assessment, "https://example.com")

    assert result["findings"] == 4
    titles = _titles(web_assessment)
    assert "Web Endpoint Reachable" in titles
    assert "Missing Content-Security-Policy" in titles
    assert "Missing X-Frame-Options" in titles
    assert "Missing HSTS" in titles
    header_findings = [
        finding
        for finding in _findings(web_assessment)
        if finding["title"] != "Web Endpoint Reachable"
    ]
    assert len(header_findings) == 3
    assert all(
        finding["finding_type"] == "misconfiguration"
        for finding in header_findings
    )
    assert all(finding["risk_level"] == "Low" for finding in header_findings)
    assert all(
        finding["requires_verification"] == 1 for finding in header_findings
    )


def test_scan_web_status_recorded(monkeypatch, web_assessment):
    monkeypatch.setattr(Config, "WEB_USER_AGENT", "TestAgent/1.0", raising=False)
    captured = {}
    response = FakeResponse(status_code=204, headers={"Server": "nginx"})
    _patch_web_get(monkeypatch, response=response, captured=captured)

    result = scan_web(web_assessment, "https://example.com")

    assert result["status_code"] == 204
    assert result["final_url"] == "https://example.com/"
    assert captured["timeout"] == Config.WEB_TIMEOUT
    assert captured["allow_redirects"] is True
    assert captured["verify"] is True
    assert "max_redirects" not in captured
    assert captured["headers"]["User-Agent"] == "TestAgent/1.0"

    with get_db() as connection:
        row = connection.execute(
            """
            SELECT status, completed_at, limitations
            FROM assessments WHERE id = ?
            """,
            (web_assessment,),
        ).fetchone()
    assert row["status"] == "completed"
    assert row["completed_at"] is not None
    assert row["limitations"]


def test_search_cves_success(monkeypatch, tmp_db):
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2011-2523",
                    "descriptions": [
                        {"lang": "en", "value": "vsftpd 2.3.4 backdoor"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "published": "2011-07-01T00:00:00.000",
                    "references": [
                        {
                            "url": (
                                "https://nvd.nist.gov/vuln/detail/"
                                "CVE-2011-2523"
                            )
                        }
                    ],
                }
            }
        ]
    }
    captured = {}
    _patch_nvd(
        monkeypatch,
        response=FakeNvdResponse(200, payload),
        captured=captured,
    )

    results = search_cves("vsftpd 2.3.4", max_results=3)

    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2011-2523"
    assert results[0]["description"] == "vsftpd 2.3.4 backdoor"
    assert results[0]["cvss_score"] == 9.8
    assert results[0]["cvss_severity"] == "CRITICAL"
    assert results[0]["published"] == "2011-07-01"
    assert results[0]["references"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
    ]
    assert captured["params"]["keywordSearch"] == "vsftpd 2.3.4"
    assert captured["params"]["resultsPerPage"] == 3
    assert captured["timeout"] == getattr(Config, "NVD_TIMEOUT", 10)

    with get_db() as connection:
        row = connection.execute(
            "SELECT * FROM cve_records WHERE cve_id = ?",
            ("CVE-2011-2523",),
        ).fetchone()
    assert row is not None
    assert row["cvss_score"] == 9.8
    assert row["cvss_severity"] == "CRITICAL"
    assert row["published"] == "2011-07-01"
    assert "nvd.nist.gov" in row["references_json"]


def test_search_cves_timeout_returns_empty(monkeypatch, tmp_db):
    _patch_nvd(monkeypatch, exc=requests.exceptions.Timeout())

    assert search_cves("anything") == []
    assert _cve_count() == 0


def test_search_cves_403_returns_empty(monkeypatch, tmp_db):
    _patch_nvd(monkeypatch, response=FakeNvdResponse(403))

    assert search_cves("x") == []
    assert _cve_count() == 0


def test_search_cves_500_returns_empty(monkeypatch, tmp_db):
    _patch_nvd(monkeypatch, response=FakeNvdResponse(500))

    assert search_cves("x") == []
    assert _cve_count() == 0


def test_search_cves_empty_response(monkeypatch, tmp_db):
    _patch_nvd(
        monkeypatch,
        response=FakeNvdResponse(200, {"vulnerabilities": []}),
    )

    assert search_cves("anything") == []
    assert _cve_count() == 0


def test_search_cves_malformed_response(monkeypatch, tmp_db):
    _patch_nvd(
        monkeypatch,
        response=FakeNvdResponse(200, {"unexpected": "structure"}),
    )

    assert search_cves("x") == []
    assert _cve_count() == 0


def test_search_cves_respects_max_results(monkeypatch, tmp_db):
    payload = {
        "vulnerabilities": [
            _nvd_cve(f"CVE-2020-000{i}") for i in range(1, 6)
        ]
    }
    _patch_nvd(monkeypatch, response=FakeNvdResponse(200, payload))

    results = search_cves("example", max_results=2)

    assert len(results) == 2
    assert results[0]["cve_id"] == "CVE-2020-0001"
    assert results[1]["cve_id"] == "CVE-2020-0002"


def test_search_cves_no_cvss(monkeypatch, tmp_db):
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2020-9999",
                    "descriptions": [
                        {"lang": "en", "value": "No metrics here"}
                    ],
                    "published": "2020-05-06T00:00:00.000",
                    "references": [],
                }
            }
        ]
    }
    _patch_nvd(monkeypatch, response=FakeNvdResponse(200, payload))

    results = search_cves("example")

    assert len(results) == 1
    assert results[0]["cvss_score"] is None
    assert results[0]["cvss_severity"] is None


def test_search_cves_logs_do_not_crash(monkeypatch, tmp_db):
    _patch_nvd(monkeypatch, exc=Exception("boom"))

    assert search_cves("x") == []
    assert _cve_count() == 0


def test_search_cves_retries_on_503(monkeypatch, tmp_db):
    payload = {
        "vulnerabilities": [_nvd_cve("CVE-2011-2523", 9.8, "CRITICAL")]
    }
    responses = [FakeNvdResponse(503), FakeNvdResponse(200, payload)]
    calls = {"count": 0}

    def fake_get(url, **kwargs):
        calls["count"] += 1
        index = min(calls["count"] - 1, len(responses) - 1)
        return responses[index]

    monkeypatch.setattr(cve_lookup.requests, "get", fake_get)
    monkeypatch.setattr(cve_lookup.time, "sleep", lambda *args, **kwargs: None)

    results = search_cves("vsftpd")

    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2011-2523"
    assert calls["count"] == 2


class TestScannerStubs:
    def test_pdf_generator_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Phase 5"):
            generate_pdf(1)
