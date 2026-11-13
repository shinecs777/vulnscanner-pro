"""Tests for scanner boundaries.

Scanners are intentional stubs until their implementations land. These tests
assert that no fabricated findings are returned.
"""

import pytest

from reports.pdf_generator import generate_pdf
from scanners.cve_lookup import search_cves
from scanners.network_scanner import scan_network
from scanners.web_scanner import scan_web


class TestScannerStubs:
    def test_network_scanner_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Phase 2"):
            scan_network(1, "10.0.0.5")

    def test_web_scanner_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Phase 3"):
            scan_web(1, "https://example.com")

    def test_cve_lookup_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Phase 4"):
            search_cves("Apache")

    def test_pdf_generator_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Phase 5"):
            generate_pdf(1)


@pytest.mark.skip(
    reason="TODO: remove skip when scan_network returns evidence-backed findings"
)
def test_network_scanner_returns_findings_schema():
    result = scan_network(1, "10.0.0.5")
    assert "findings" in result
    assert "limitations" in result
