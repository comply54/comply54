"""
comply54.sectors.nigeria_insurance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nigerian insurance compliance sector pack.

Composes:
  - NIIRA 2025            — Nigerian Insurance Industry Reform Act 2025 (signed August 2025).
                            Replaces Insurance Act 2003 (Cap I17 LFN 2004). Key provisions:
                            §210 mandatory 60-day claims settlement, §212 Policyholders'
                            Protection Fund, Part V market conduct and anti-discrimination rules.
  - NAICOM 2021/2023      — Claims adjudication thresholds, underwriting controls, fraud
                            escalation (remain in force under NIIRA 2025 pending new guidelines)
  - NDPA 2023             — Personal data including health/biometric used in underwriting
  - NFIU AML              — Large premium / claim AML reporting duty
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

    Covers Nigerian Insurance Industry Reform Act 2025 (NIIRA 2025) §§210, 212, Part V,
    NAICOM Operational Guidelines 2021 (Guidelines 12, 15, 18), NAICOM Market Conduct
    Guidelines 2023 (Rules 6, 11), NFIU AML Guidelines (insurance sector), NDPA 2023,
    and OWASP Agentic AI.

    NIIRA 2025 replaced the Insurance Act 2003 (Cap I17 LFN 2004) in August 2025.
    """

    name = "Nigeria Insurance Compliance"
    jurisdictions = ["NG"]
    regulations = [
        "Nigerian Insurance Industry Reform Act 2025 (NIIRA 2025)",
        "NAICOM Operational Guidelines 2021",
        "NAICOM Market Conduct Guidelines 2023",
        "Nigeria Data Protection Act 2023",
        "MLPPA 2022 / NFIU AML Guidelines",
        "OWASP Agentic AI",
    ]

    def __init__(
        self,
        strict_mode: bool = False,
        signing_key: "bytes | str | None" = None,
    ) -> None:
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
            signing_key=signing_key,
        )
