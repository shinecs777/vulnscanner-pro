"""Web scanner boundary.

Intended Phase 3 implementation:
  * Fetch headers and a small set of unauthenticated responses using
    requests with Config.WEB_TIMEOUT and redirects disabled by default.
  * Classify missing security headers as finding_type='misconfiguration'
    with confidence='high' and risk_level='Low'. A missing header is a
    configuration weakness, not an exploitable vulnerability.
  * Only emit 'potential_vuln' or 'confirmed_vuln' when reproducible evidence
    exists, and mark requires_verification accordingly.
"""


def scan_web(assessment_id: int, target: str) -> dict:
    """Run an unauthenticated web assessment for an authorized target.

    Not implemented in this scaffold; no findings are fabricated.
    """
    raise NotImplementedError(
        "Web header and content checks are not yet implemented. See Phase 3."
    )
