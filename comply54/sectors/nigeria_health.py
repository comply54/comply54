"""
comply54.sectors.nigeria_health
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nigerian healthcare compliance sector pack.

Composes:
  - NHA 2014              — patient consent, clinical confidentiality, cross-border health data
  - NDPA 2023             — special-category health data, data residency, cross-border rules
  - BVN/NIN Protection    — biometric identity (patient ID systems)
  - OWASP Universal       — PII leakage, prompt injection, tool permissions, human approval

Covers AI agents operating in:
  - Electronic Health Record (EHR) systems
  - Clinical decision support tools
  - Telemedicine / remote consultation platforms
  - Health data analytics and research platforms

Usage:
    from comply54.sectors import NigeriaHealthcareCompliance

    compliance = NigeriaHealthcareCompliance()
    result = compliance.check(
        action="access_patient_records",
        params={"patient_id": "P-12345", "record_count": 1},
        context={"consent_documented": True, "purpose": "treatment"},
    )
    if result.blocked:
        raise ValueError(result.primary_violation.messages[0])
"""

from __future__ import annotations

from ..core.packs import (
    BVN_NIN,
    HUMAN_APPROVAL,
    NDPA,
    NHA,
    PII_LEAKAGE,
    PROMPT_INJECTION,
    TOOL_PERMISSIONS,
)
from ._base import SectorCompliance


class NigeriaHealthcareCompliance(SectorCompliance):
    """
    Full Nigerian healthcare compliance pack.

    Covers NHA 2014 ss.26/29/30, NDPA 2023 ss.25/30 (special-category data),
    Medical & Dental Practitioners Act Cap M8 s.16,
    FMOH AI in Healthcare Policy (Draft 2024), and OWASP Agentic AI top risks.
    """

    name = "Nigeria Healthcare Compliance"
    jurisdictions = ["NG"]
    regulations = [
        "Nigeria National Health Act 2014",
        "Nigeria Data Protection Act 2023 (Special-Category Health Data)",
        "Medical and Dental Practitioners Act Cap M8 LFN 2004",
        "FMOH AI in Healthcare Policy Draft 2024",
        "CBN BVN Framework & NIBSS Rules",
        "OWASP Agentic AI",
    ]

    def __init__(self, strict_mode: bool = False) -> None:
        super().__init__(
            packs=[
                NHA,
                NDPA,
                BVN_NIN,
                PII_LEAKAGE,
                PROMPT_INJECTION,
                TOOL_PERMISSIONS,
                HUMAN_APPROVAL,
            ],
            strict_mode=strict_mode,
        )
