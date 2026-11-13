"""PDF report generation boundary.

Intended Phase 5 implementation:
  * Use reportlab platypus flowables with explicit page breaks and paragraph
    wrapping for long evidence blobs.
  * Produce a severity summary, per-finding evidence, confidence, risk
    reasoning, remediation status, and a limitations section.
  * Never claim a finding is confirmed unless the stored record says so.
"""


def generate_pdf(assessment_id: int) -> bytes:
    """Generate a PDF report for one assessment.

    Not implemented in this scaffold; no report content is fabricated.
    """
    raise NotImplementedError(
        "PDF report generation is not yet implemented. See Phase 5."
    )
