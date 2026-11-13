"""Network scanner boundary.

Intended Phase 2 implementation:
  * Validate the target with core.validator before any process launch.
  * Invoke Nmap via subprocess.run([...], shell=False) with argument lists,
    writing XML to stdout using "-oX -".
  * Parse the XML with xml.etree.ElementTree (never with regex).
  * Persist assets and evidence-backed findings within a single assessment.
  * Record coverage limitations such as top-100-port scope and timeout state.
"""


def scan_network(assessment_id: int, target: str) -> dict:
    """Run an Nmap assessment for an authorized target.

    Not implemented in this scaffold; no findings are fabricated.
    """
    raise NotImplementedError(
        "Nmap XML parsing not yet implemented. See Phase 2."
    )
