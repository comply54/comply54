"""
comply54.sectors.pan_african
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Pan-African fintech compliance sector pack.

The most comprehensive comply54 composition — applies all African
jurisdiction packs + universal safety controls simultaneously.
Use this when your agent operates across multiple African markets
and you want maximum regulatory coverage in a single check.

Jurisdictions covered: NG, KE, ZA, GH, RW, EG, ET, MU, TZ, UG

Usage:
    from comply54.sectors import PanAfricanFintechCompliance

    compliance = PanAfricanFintechCompliance()
    result = compliance.check(
        action="transfer_funds",
        params={"amount": 5_000_000, "currency": "NGN", "destination_country": "CN"},
        context={"kyc_tier": 2},
    )
    for violation in result.violations:
        print(violation)
"""

from __future__ import annotations

from ..core.packs import (
    BVN_NIN,
    CBN,
    EGYPT_PDPL,
    ETHIOPIA_PDP,
    GHANA_DPA,
    HUMAN_APPROVAL,
    KDPA,
    MAURITIUS_DPA,
    MODEL_ROUTING,
    NDPA,
    NFIU_AML,
    PII_LEAKAGE,
    POPIA,
    PROMPT_INJECTION,
    RWANDA_DPA,
    TANZANIA_PDPA,
    TOOL_PERMISSIONS,
    UGANDA_DPPA,
)
from ._base import SectorCompliance


class PanAfricanFintechCompliance(SectorCompliance):
    """
    Pan-African fintech compliance pack.

    Applies all 13 African jurisdiction packs + 5 universal OWASP
    safety controls in a single evaluation call.

    Best for: multi-jurisdiction agents, cross-border payment flows,
    and any AI system that processes data across African markets.
    """

    name = "Pan-African Fintech Compliance"
    jurisdictions = ["NG", "KE", "ZA", "GH", "RW", "EG", "ET", "MU", "TZ", "UG"]
    regulations = [
        "NDPA 2023 (Nigeria)",
        "CBN Transaction Controls (Nigeria)",
        "BVN/NIN Protection (Nigeria)",
        "NFIU AML (Nigeria)",
        "KDPA 2019 (Kenya)",
        "POPIA (South Africa)",
        "Ghana DPA 2012",
        "Rwanda DPA 2021",
        "Egypt PDPL 2020",
        "Ethiopia PDP 2024",
        "Mauritius DPA 2017",
        "Tanzania PDPA 2022",
        "Uganda DPPA 2019",
        "OWASP Agentic AI",
    ]

    def __init__(
        self,
        strict_mode: bool = False,
        signing_key: "bytes | str | None" = None,
    ) -> None:
        super().__init__(
            packs=[
                # Nigeria
                NDPA, CBN, BVN_NIN, NFIU_AML,
                # East Africa
                KDPA, MAURITIUS_DPA, TANZANIA_PDPA, UGANDA_DPPA, RWANDA_DPA, ETHIOPIA_PDP,
                # Southern / West / North Africa
                POPIA, GHANA_DPA, EGYPT_PDPL,
                # Universal safety
                PII_LEAKAGE, PROMPT_INJECTION, TOOL_PERMISSIONS, HUMAN_APPROVAL, MODEL_ROUTING,
            ],
            strict_mode=strict_mode,
            signing_key=signing_key,
        )
