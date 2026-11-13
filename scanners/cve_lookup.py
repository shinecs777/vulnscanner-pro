"""NVD CVE lookup boundary.

Intended Phase 4 implementation:
  * Query Config.NVD_API_URL with optional Config.NVD_API_KEY.
  * Serialize requests and back off using Config.NVD_RATE_LIMIT_NO_KEY when
    no API key is present; otherwise handle HTTP 403/429 with retry jitter.
  * Cache normalized records in cve_records and honor NVD_CACHE_TTL_DAYS.
  * Keep correlation explicit: a matching product/version is a potential
    vulnerability until evidence confirms exploitability.
"""


def search_cves(keyword: str, max_results: int = 5) -> dict:
    """Search the NVD for CVEs matching a keyword.

    Not implemented in this scaffold; no CVE data is fabricated.
    """
    raise NotImplementedError(
        "NVD API lookup and rate-limit handling are not yet implemented. "
        "See Phase 4."
    )
