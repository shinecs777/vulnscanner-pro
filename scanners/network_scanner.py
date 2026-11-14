"""Nmap-backed network scanner with evidence-based finding classification.

The scanner invokes Nmap with an argument list (never a shell), parses the XML
output with xml.etree.ElementTree, records assets and findings, and leaves CVE
correlation to the NVD lookup boundary. Version-based CVE matches are always
marked as potential findings that require manual verification.
"""

import hashlib
import logging
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import Config
from core.models import get_db
from scanners.cve_lookup import search_cves

logger = logging.getLogger(__name__)

LIMITATIONS = (
    "Scan covered top 100 TCP ports only (nmap -F). UDP and full "
    "65535-port sweeps were NOT performed. Scan used TCP connect (-sT) "
    "which is slightly slower and more detectable than SYN scans, but "
    "works without raw socket privileges. Service version detection is "
    "fingerprint-based and may be inaccurate. This is NOT a complete "
    "vulnerability assessment."
)

RISKY_SERVICES = {
    "telnet": {
        "title": "Unencrypted Telnet Service",
        "type": "confirmed_vuln",
        "risk": "High",
        "confidence": "high",
        "reason": (
            "Telnet transmits credentials and data in cleartext, "
            "exposing them to network eavesdroppers."
        ),
        "rec": "Disable Telnet. Use SSH or a TLS-wrapped alternative.",
    },
    "ftp": {
        "title": "Unencrypted FTP Service",
        "type": "misconfiguration",
        "risk": "Medium",
        "confidence": "high",
        "reason": (
            "FTP transmits credentials in cleartext. Anonymous-login "
            "may additionally expose file contents."
        ),
        "rec": "Replace with SFTP/FTPS or restrict to a management network.",
    },
    "rlogin": {
        "title": "Legacy rlogin Service",
        "type": "confirmed_vuln",
        "risk": "High",
        "confidence": "high",
        "reason": (
            "rlogin trusts host-based authentication without "
            "cryptographic verification."
        ),
        "rec": "Disable rlogin. Use SSH.",
    },
}

INFORMATIONAL_SERVICES = {
    "http",
    "https",
    "ssh",
    "domain",
    "smtp",
    "imap",
    "pop3",
    "http-alt",
}


def MAP_CVSS(severity: str | None) -> str:
    """Map an NVD CVSS severity label to the finding risk scale."""
    if severity is None:
        return "Medium"
    return {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }.get(str(severity).strip().upper(), "Medium")


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _host_fingerprint(ip: str, port: int, protocol: str, title: str) -> str:
    return hashlib.sha256(
        f"{ip}|{port}|{protocol}|{title}".encode("utf-8")
    ).hexdigest()[:32]


def _cve_fingerprint(ip: str, port: int, protocol: str, cve_id: str) -> str:
    return hashlib.sha256(
        f"{ip}|{port}|{protocol}|{cve_id}".encode("utf-8")
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


def _parse_nmap_xml(stdout: str, parse_errors: list[str] | None = None) -> list[dict]:
    """Parse Nmap XML into hosts with their open services.

    Returns an empty list on any parse error. When parse_errors is supplied,
    the parser appends a marker so the caller can distinguish invalid XML from
    valid XML that simply contains no reachable hosts.
    """
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError as exc:
        logger.error("Failed to parse nmap XML output: %s", stdout[:500])
        if parse_errors is not None:
            parse_errors.append(str(exc))
        return []

    hosts = []
    for host_element in root.findall("host"):
        status_element = host_element.find("status")
        if status_element is None:
            continue
        if status_element.get("state", "").lower() != "up":
            continue

        address_element = host_element.find("address")
        ip = address_element.get("addr", "") if address_element is not None else ""

        services = []
        ports_element = host_element.find("ports")
        if ports_element is not None:
            for port_element in ports_element.findall("port"):
                state_element = port_element.find("state")
                if state_element is None:
                    continue
                if state_element.get("state", "").lower() != "open":
                    continue

                try:
                    port = int(port_element.get("portid", ""))
                except (TypeError, ValueError):
                    continue

                protocol = port_element.get("protocol", "tcp").lower()
                service_element = port_element.find("service")
                if service_element is None:
                    name = "unknown"
                    product = ""
                    version = ""
                else:
                    name = (service_element.get("name") or "unknown").lower()
                    product = service_element.get("product") or ""
                    version = service_element.get("version") or ""

                services.append(
                    {
                        "port": port,
                        "protocol": protocol,
                        "name": name,
                        "product": product,
                        "version": version,
                    }
                )

        hosts.append({"ip": ip, "status": "up", "services": services})

    return hosts


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


def _lookup_cves_for_hosts(hosts: list[dict]) -> dict:
    """Run deduplicated NVD lookups in parallel, bounded to 2 workers.

    The NVD rate limiter in cve_lookup is shared across threads, so parallel
    workers still respect the minimum request interval while hiding latency.
    """
    lookups = []
    for host in hosts:
        for svc in host["services"]:
            if svc["product"] and svc["version"]:
                lookups.append((svc["product"], svc["version"]))

    unique_keywords = sorted({f"{p} {v}" for p, v in lookups})

    cve_map: dict[str, list[dict]] = {}
    if unique_keywords:
        with ThreadPoolExecutor(max_workers=2) as pool:
            future_to_kw = {
                pool.submit(search_cves, kw, 3): kw
                for kw in unique_keywords
            }
            for future in as_completed(future_to_kw):
                kw = future_to_kw[future]
                try:
                    cve_map[kw] = future.result(timeout=30)
                except Exception as exc:
                    logger.warning("CVE lookup failed for %s: %s", kw, exc)
                    cve_map[kw] = []

    return cve_map


def _record_findings(
    connection, assessment_id: int, hosts: list[dict], cve_map: dict
) -> int:
    """Persist assets, service findings, and CVE correlation for parsed hosts."""
    findings_count = 0

    for host in hosts:
        ip = host["ip"]
        for service in host["services"]:
            port = service["port"]
            protocol = service["protocol"]
            service_name = service["name"]
            product = service["product"]
            version = service["version"]
            evidence = f"Port {port}/{protocol} open; banner: {product} {version}".strip()

            cursor = connection.execute(
                """
                INSERT INTO assets (
                    assessment_id, host, port, protocol, service, product, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    ip,
                    port,
                    protocol,
                    service_name,
                    product,
                    version,
                ),
            )
            asset_id = cursor.lastrowid

            if service_name in RISKY_SERVICES:
                meta = RISKY_SERVICES[service_name]
                title = meta["title"]
                fingerprint = _host_fingerprint(ip, port, protocol, title)
                _insert_finding(
                    connection,
                    assessment_id,
                    asset_id,
                    finding_type=meta["type"],
                    title=title,
                    description=f"{service_name} detected on port {port}.",
                    evidence=evidence,
                    risk_level=meta["risk"],
                    confidence=meta["confidence"],
                    risk_reasoning=meta["reason"],
                    recommendation=meta["rec"],
                    requires_verification=0,
                    fingerprint=fingerprint,
                )
                findings_count += 1
            elif service_name in INFORMATIONAL_SERVICES:
                title = f"Open Service: {service_name} ({port})"
                fingerprint = _host_fingerprint(ip, port, protocol, title)
                _insert_finding(
                    connection,
                    assessment_id,
                    asset_id,
                    finding_type="informational",
                    title=title,
                    description=(
                        f"Port {port} is open and running {service_name}. "
                        "An open port is not inherently a vulnerability."
                    ),
                    evidence=evidence,
                    risk_level="Info",
                    confidence="high",
                    risk_reasoning=(
                        "Open port observed. Review whether this service is "
                        "required and properly hardened."
                    ),
                    recommendation=(
                        "Confirm the service is patched and access is restricted."
                    ),
                    requires_verification=0,
                    fingerprint=fingerprint,
                )
                findings_count += 1
            else:
                title = f"Open Port: {port}/{protocol}"
                fingerprint = _host_fingerprint(ip, port, protocol, title)
                _insert_finding(
                    connection,
                    assessment_id,
                    asset_id,
                    finding_type="informational",
                    title=title,
                    description=f"Port {port} is open with unidentified service.",
                    evidence=evidence,
                    risk_level="Info",
                    confidence="medium",
                    risk_reasoning=(
                        "Unknown service. Classification requires manual review."
                    ),
                    recommendation=(
                        "Identify the service and review its configuration."
                    ),
                    requires_verification=1,
                    fingerprint=fingerprint,
                )
                findings_count += 1

            if not product or not version:
                continue

            keyword = f"{product} {version}"
            cves = cve_map.get(keyword, [])

            for cve in cves:
                cve_id = cve["cve_id"]
                title = f"Potential {cve_id} \u2014 {keyword}"
                description = cve.get("description", "")[:500]
                cve_evidence = (
                    f"NVD keyword match for '{keyword}'. "
                    f"CVSS {cve.get('cvss_score')} "
                    f"({cve.get('cvss_severity')})."
                )
                fingerprint = _cve_fingerprint(ip, port, protocol, cve_id)
                finding_id = _insert_finding(
                    connection,
                    assessment_id,
                    asset_id,
                    finding_type="potential_vuln",
                    title=title,
                    description=description,
                    evidence=cve_evidence,
                    risk_level=MAP_CVSS(cve.get("cvss_severity")),
                    confidence="low",
                    risk_reasoning=(
                        "Version-based match only; Nmap service fingerprint "
                        "may be inaccurate. Manual verification required."
                    ),
                    recommendation=(
                        f"Verify applicability of {cve_id} and patch if confirmed."
                    ),
                    requires_verification=1,
                    fingerprint=fingerprint,
                )
                findings_count += 1

                connection.execute(
                    """
                    INSERT OR IGNORE INTO cve_records (
                        cve_id, description, cvss_score, cvss_severity, published
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        cve_id,
                        description,
                        cve.get("cvss_score"),
                        cve.get("cvss_severity"),
                        cve.get("published"),
                    ),
                )

                if finding_id is not None:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO finding_cves (
                            finding_id, cve_id, is_confirmed
                        ) VALUES (?, ?, 0)
                        """,
                        (finding_id, cve_id),
                    )

    return findings_count


def scan_network(assessment_id: int, target: str) -> dict:
    """Scan a target with Nmap, record findings, return summary.

    Caller is responsible for validating `target` via core.validator.
    """
    logger.info(
        "Starting network scan for assessment %s target=%s",
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

    command = [
        Config.NMAP_PATH, "-sT", "-T3", "-sV", "-F", "-oX", "-", "--host-timeout", f"{Config.NMAP_TIMEOUT}s", "-Pn", target,
    ]

    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            timeout=Config.NMAP_TIMEOUT + 30,
        )
    except FileNotFoundError:
        logger.error("nmap not found at %s", Config.NMAP_PATH)
        _mark_failed(assessment_id)
        return _error(f"nmap not found at {Config.NMAP_PATH}")
    except subprocess.TimeoutExpired:
        logger.error("nmap timed out for assessment %s", assessment_id)
        _mark_failed(assessment_id)
        return _error("nmap timed out")
    except Exception:
        logger.exception(
            "Failed to execute nmap for assessment %s", assessment_id
        )
        _mark_failed(assessment_id)
        return _error("failed to execute nmap")

    stdout = _as_text(completed.stdout)
    stderr = _as_text(completed.stderr)

    if completed.returncode != 0:
        logger.warning(
            "nmap exited with %s: %s",
            completed.returncode,
            stderr[:200],
        )
        _mark_failed(assessment_id)
        return _error(f"nmap exited with {completed.returncode}")

    try:
        parse_errors: list[str] = []
        hosts = _parse_nmap_xml(stdout, parse_errors)
        if parse_errors:
            _mark_failed(assessment_id)
            return _error("failed to parse nmap XML output")

        cve_map = _lookup_cves_for_hosts(hosts)

        with get_db() as connection:
            findings_count = _record_findings(
                connection, assessment_id, hosts, cve_map
            )

        _mark_completed(assessment_id)
    except Exception:
        logger.exception(
            "Failed to process scan results for assessment %s", assessment_id
        )
        try:
            _mark_failed(assessment_id)
        except Exception:
            logger.exception(
                "Failed to mark assessment %s as failed", assessment_id
            )
        return _error("failed to process scan results")

    logger.info(
        "Scan complete: %d findings across %d hosts",
        findings_count,
        len(hosts),
    )
    return {
        "findings": findings_count,
        "hosts": len(hosts),
        "limitations": LIMITATIONS,
    }
