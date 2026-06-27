"""
comply54.sectors.nigeria_insurance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nigerian insurance compliance sector pack.

Composes:
  - NAICOM 2021/2023      — claims adjudication, underwriting controls, anti-discrimination,
                            fraud escalation, policy modification notification
  - NDPA 2023             — personal data including health/biometric used in underwriting
  - NFIU AML              — large premium / claim AML reporting duty
  - OWASP Universal       — PII leakage, prompt injection, tool permissions, human approval

Covers AI agents operating in:
  - Claims processing systems
  - Automated underwriting engines
  - Fraud detection platforms
  - Policy management systems

Usage:
    from comply54.sectors import NigeriaInsuranceCompliance

    compliance = NigeriaInsuranceCompliance()
    result = compliance.check(
        action="deny_claim",
        params={"claim_id": "CLM-001", "claim_amount": 750000},
        context={"human_adjuster_assigned": False},
    )
    if result.blocked:
        raise ValueError(result.primary_violation.messages[0])
"""

from __future__ import annotations

from ..core.packs import (
    HUMAN_APPROVAL,
    NAICOM,
    NDPA,
    NFIU_AML,
    PII_LEAKAGE,
    PROMPT_INJECTION,
    TOOL_PERMISSIONS,
)
from ._base import SectorCompliance


class NigeriaInsuranceCompliance(SectorCompliance):
    """
    Full Nigerian insurance compliance pack.

    Covers Insurance Act 2003 ss.50/67/70, NAICOM Operational Guidelines 2021
    (Guidelines 12, 15, 18), NAICOM Market Conduct Guidelines 2023 (Rules 6, 11),
    NFIU AML Guidelines (insurance sector), NDPA 2023, and OWASP Agentic AI.
    """

    name = "Nigeria Insurance Compliance"
    jurisdictions = ["NG"]
    regulations = [
        "Insurance Act 2003 (Cap I17 LFN 2004)",
        "NAICOM Operational Guidelines 2021",
        "NAICOM Market Conduct Guidelines 2023",
        "Nigeria Data Protection Act 2023",
        "MLPPA 2022 / NFIU AML Guidelines",
        "OWASP Agentic AI",
    ]

    def __init__(self, strict_mode: bool = False) -> None:
        super().__init__(
            packs=[
                NAICOM,
                NDPA,
                NFIU_AML,
                PII_LEAKAGE,
                PROMPT_INJECTION,
                TOOL_PERMISSIONS,
                HUMAN_APPROVAL,
            ],
            strict_mode=strict_mode,
        )
