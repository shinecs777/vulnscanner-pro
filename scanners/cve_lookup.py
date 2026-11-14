"""NVD CVE lookup with rate limiting and local caching.

The lookup queries the NIST NVD 2.0 API by keyword, normalizes each CVE into a
small dict, and caches the normalized records in ``cve_records``. The function
is deliberately total: any network error, rate-limit response, or malformed
payload resolves to an empty list rather than an exception, because the network
scanner treats a version-based CVE match as an optional enrichment and must
never fail a scan because the NVD was unavailable.

A version keyword match is only a *potential* vulnerability; correlation and
confidence handling remain the caller's responsibility.
"""

import json
import logging
import time

import requests

from config import Config
from core.models import get_db

logger = logging.getLogger(__name__)

_last_request_time = 0.0

_DEFAULT_TIMEOUT = 10
_DEFAULT_RATE_LIMIT_NO_KEY = 6.0
_DEFAULT_RATE_LIMIT_WITH_KEY = 0.6


def _api_key() -> str:
    return getattr(Config, "NVD_API_KEY", "") or ""


def _min_interval() -> float:
    if _api_key():
        return float(
            getattr(
                Config,
                "NVD_RATE_LIMIT_WITH_KEY",
                _DEFAULT_RATE_LIMIT_WITH_KEY,
            )
        )
    return float(
        getattr(
            Config, "NVD_RATE_LIMIT_NO_KEY", _DEFAULT_RATE_LIMIT_NO_KEY
        )
    )


def _rate_limit() -> None:
    """Sleep so consecutive NVD requests respect the minimum interval."""
    global _last_request_time
    min_interval = _min_interval()
    elapsed = time.time() - _last_request_time
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _last_request_time = time.time()


def _request(keyword: str, max_results: int):
    _rate_limit()
    api_key = _api_key()
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    return requests.get(
        Config.NVD_API_URL,
        params=params,
        headers=headers,
        timeout=getattr(Config, "NVD_TIMEOUT", _DEFAULT_TIMEOUT),
    )


def _parse_cve(item: dict) -> dict | None:
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    description = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        "No description available",
    )
    description = (description or "No description available")[:500]

    cvss_score = None
    cvss_severity = None
    metrics = cve.get("metrics") or {}
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key) or []
        if metric_list:
            metric_data = metric_list[0].get("cvssData") or {}
            cvss_score = metric_data.get("baseScore")
            cvss_severity = metric_data.get("baseSeverity")
            break

    published = (cve.get("published") or "")[:10]

    references = [
        reference.get("url")
        for reference in (cve.get("references") or [])
        if reference.get("url")
    ][:3]

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "published": published,
        "references": references,
    }


def _cache_results(results: list[dict]) -> None:
    with get_db() as connection:
        for item in results:
            connection.execute(
                """
                INSERT OR REPLACE INTO cve_records (
                    cve_id, description, cvss_score, cvss_severity,
                    published, references_json, fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    item["cve_id"],
                    item["description"],
                    item["cvss_score"],
                    item["cvss_severity"],
                    item["published"],
                    json.dumps(item["references"]),
                ),
            )


def _handle_response(keyword: str, max_results: int, response) -> list[dict]:
    status = response.status_code

    if status == 403:
        logger.warning("NVD rate limit reached for %r", keyword)
        return []
    if status == 404:
        return []
    if status == 429:
        logger.warning("NVD rate limit (429) for %r", keyword)
        return []
    if status >= 500:
        logger.warning("NVD server error %s for %r", status, keyword)
        return []
    if status != 200:
        logger.warning("NVD request failed with status %s for %r", status, keyword)
        return []

    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", []) or []

    results: list[dict] = []
    for item in vulnerabilities:
        parsed = _parse_cve(item)
        if parsed is None:
            continue
        results.append(parsed)
        if len(results) >= max_results:
            break

    if results:
        _cache_results(results)
        logger.info(
            "NVD lookup for '%s' returned %d CVEs", keyword, len(results)
        )

    return results


def search_cves(keyword: str, max_results: int = 5) -> list[dict]:
    """Search NVD for CVEs matching a product + version keyword.

    Returns [] on ANY failure (network error, rate limit, malformed response).
    Never raises. Results are cached in cve_records for reporting stability.
    """
    try:
        response = _request(keyword, max_results)
        if response.status_code in (503, 429):
            logger.warning(
                "NVD server error %s for '%s', retrying in 3s",
                response.status_code,
                keyword,
            )
            time.sleep(3)
            response = _request(keyword, max_results)
            if response.status_code in (503, 429):
                logger.warning(
                    "NVD server error %s for '%s' persisted after retry",
                    response.status_code,
                    keyword,
                )
                return []
        return _handle_response(keyword, max_results, response)
    except requests.exceptions.Timeout:
        logger.warning("NVD request timed out for %r", keyword)
        return []
    except requests.exceptions.RequestException as exc:
        logger.warning("NVD request failed for %r: %s", keyword, exc)
        return []
    except Exception as exc:
        logger.warning("NVD lookup failed for %r: %s", keyword, exc)
        return []
