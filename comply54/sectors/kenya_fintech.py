"""
comply54.sectors.kenya_fintech
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Kenyan fintech compliance sector pack.

Composes:
  - KDPA 2019        — data residency, sensitive data categories, consent
  - OWASP Universal  — PII leakage, prompt injection, tool permissions

Usage:
    from comply54.sectors import KenyaFintechCompliance

    compliance = KenyaFintechCompliance()
    result = compliance.check(
        action="export_customer_data",
        params={"destination_country": "CN", "data_type": "biometric"},
    )
"""

from __future__ import annotations

from ..core.packs import (
    HUMAN_APPROVAL,
    KDPA,
    PII_LEAKAGE,
    PROMPT_INJECTION,
    TOOL_PERMISSIONS,
)
from ._base import SectorCompliance


class KenyaFintechCompliance(SectorCompliance):
    """
    Kenyan fintech compliance pack.

    Covers KDPA 2019 §43 (sensitive data), §48 (cross-border transfers),
    and OWASP Agentic AI top risks.
    """

    name = "Kenya Fintech Compliance"
    jurisdictions = ["KE"]
    regulations = [
        "Kenya Data Protection Act 2019",
        "OWASP Agentic AI",
    ]

    def __init__(self) -> None:
        super().__init__(packs=[
            KDPA,
            PII_LEAKAGE,
            PROMPT_INJECTION,
            TOOL_PERMISSIONS,
            HUMAN_APPROVAL,
        ])
