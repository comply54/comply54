"""
comply54.sectors.nigeria_fintech
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nigerian fintech compliance sector pack.

Composes:
  - NDPA 2023          — data residency, cross-border transfers, PII categories
  - CBN FPR            — transaction limits, tiered KYC, NIP cap (₦10M)
  - BVN/NIN Protection — biometric identity data handling
  - NFIU AML           — suspicious transaction reporting, CTR thresholds
  - OWASP Universal    — PII leakage, prompt injection, tool permissions

One import. Zero Rego knowledge required.

Usage:
    from comply54.sectors import NigeriaFintechCompliance

    compliance = NigeriaFintechCompliance()
    result = compliance.check(
        action="transfer_funds",
        params={"amount": 15_000_000, "currency": "NGN"},
        context={"kyc_tier": 3, "customer_verified": True},
    )
    if result.blocked:
        raise ValueError(result.primary_violation.messages[0])
"""

from __future__ import annotations

from ..core.packs import (
    BVN_NIN,
    CBN,
    HUMAN_APPROVAL,
    NDPA,
    NFIU_AML,
    PII_LEAKAGE,
    PROMPT_INJECTION,
    TOOL_PERMISSIONS,
)
from ._base import SectorCompliance


class NigeriaFintechCompliance(SectorCompliance):
    """
    Full Nigerian fintech compliance pack.

    Covers NDPA 2023 §25/§30, CBN FPR/DIR/GEN/CIR/07/003,
    CBN NIP Framework (₦10M cap), NFIU/MLPPA 2022,
    and OWASP Agentic AI top risks.
    """

    name = "Nigeria Fintech Compliance"
    jurisdictions = ["NG"]
    regulations = [
        "Nigeria Data Protection Act 2023",
        "CBN Transaction Limits & Controls",
        "CBN BVN Framework & NIBSS Rules",
        "MLPPA 2022 / NFIU AML Guidelines",
        "OWASP Agentic AI",
    ]

    def __init__(self, strict_mode: bool = False) -> None:
        super().__init__(
            packs=[
                NDPA,
                CBN,
                BVN_NIN,
                NFIU_AML,
                PII_LEAKAGE,
                PROMPT_INJECTION,
                TOOL_PERMISSIONS,
                HUMAN_APPROVAL,
            ],
            strict_mode=strict_mode,
        )
