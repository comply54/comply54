"""
comply54.core.packs
~~~~~~~~~~~~~~~~~~~
Registry of all bundled policy packs — maps pack IDs to Rego files,
OPA query paths, and regulatory metadata including exact source citations.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from .models import RegulatorySource


_PACKS_DIR = pathlib.Path(__file__).parent.parent / "packs"


@dataclass(frozen=True)
class PackSpec:
    """Specification for a single comply54 policy pack."""

    id: str
    regulation: str
    jurisdiction: str
    authority: str
    rego_path: pathlib.Path
    query_prefix: str  # e.g. "data.agt_policies_nigeria.cbn"
    tags: list[str] = field(default_factory=list)
    sources: list[RegulatorySource] = field(default_factory=list)
    """Exact regulatory documents and sections this pack enforces."""

    @property
    def rego_source(self) -> str:
        return self.rego_path.read_text(encoding="utf-8")

    @property
    def module_name(self) -> str:
        return self.rego_path.name


# ── Nigeria ────────────────────────────────────────────────────────────────────

NDPA = PackSpec(
    id="nigeria/ndpa",
    regulation="Nigeria Data Protection Act 2023",
    jurisdiction="NG",
    authority="NDPC",
    rego_path=_PACKS_DIR / "nigeria" / "ndpa.rego",
    query_prefix="data.agt_policies_nigeria.ndpa",
    tags=["data-protection", "cross-border", "pii", "residency"],
    sources=[
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§24", authority="NDPC", year=2023),
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§25", authority="NDPC", year=2023),
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§30", authority="NDPC", year=2023),
    ],
)

CBN = PackSpec(
    id="nigeria/cbn",
    regulation="CBN Transaction Limits & Controls (FPR/DIR/GEN/CIR/07/003)",
    jurisdiction="NG",
    authority="CBN",
    rego_path=_PACKS_DIR / "nigeria" / "cbn.rego",
    query_prefix="data.agt_policies_nigeria.cbn",
    tags=["fintech", "aml", "transaction-limits", "kyc"],
    sources=[
        RegulatorySource(document="CBN Circular FPR/DIR/GEN/CIR/07/003", section="§3.1", authority="CBN", year=2013),
        RegulatorySource(document="CBN NIP (NIBSS Instant Payment) Framework", section="§4.2", authority="CBN", year=2011),
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§2.4", authority="CBN", year=2014),
        RegulatorySource(document="CBN USSD Banking Circular BSD/DIR/GEN/CIR/07/002", section="§5.2", authority="CBN", year=2019),
    ],
)

BVN_NIN = PackSpec(
    id="nigeria/bvn-nin",
    regulation="CBN BVN Framework & NIBSS BVN Scheme Rules",
    jurisdiction="NG",
    authority="CBN/NIBSS",
    rego_path=_PACKS_DIR / "nigeria" / "bvn_nin.rego",
    query_prefix="data.agt_policies_nigeria.bvn_nin",
    tags=["identity", "biometric", "pii"],
    sources=[
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§6", authority="CBN", year=2014),
        RegulatorySource(document="NIBSS BVN Scheme Rules 2014", section="Rule 4.2", authority="NIBSS", year=2014),
        RegulatorySource(document="NIMC Act Cap N99 LFN 2004 (as amended)", section="§18", authority="NIMC", year=2004),
    ],
)

NFIU_AML = PackSpec(
    id="nigeria/nfiu-aml",
    regulation="Money Laundering (Prevention & Prohibition) Act 2022 / NFIU Guidelines",
    jurisdiction="NG",
    authority="NFIU",
    rego_path=_PACKS_DIR / "nigeria" / "nfiu_aml.rego",
    query_prefix="data.agt_policies_nigeria.nfiu",
    tags=["aml", "cft", "str", "fintech"],
    sources=[
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§10", authority="NFIU", year=2022),
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§11", authority="NFIU", year=2022),
        RegulatorySource(document="NFIU AML/CFT Compliance Framework 2022", section="§3.2", authority="NFIU", year=2022),
    ],
)

NHA = PackSpec(
    id="nigeria/nha",
    regulation="Nigeria National Health Act 2014 / Medical & Dental Practitioners Act Cap M8",
    jurisdiction="NG",
    authority="FMOH / MDCN",
    rego_path=_PACKS_DIR / "nigeria" / "nha.rego",
    query_prefix="data.agt_policies_nigeria.nha",
    tags=["healthcare", "patient-consent", "clinical-safety", "health-data"],
    sources=[
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§26", authority="FMOH", year=2014),
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§29", authority="FMOH", year=2014),
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§30", authority="FMOH", year=2014),
        RegulatorySource(document="Medical and Dental Practitioners Act Cap M8 LFN 2004", section="§16", authority="MDCN", year=2004),
        RegulatorySource(document="FMOH AI in Healthcare Policy (Draft 2024)", section="Guideline 4", authority="FMOH", year=2024),
        RegulatorySource(document="FMOH AI in Healthcare Policy (Draft 2024)", section="Guideline 7", authority="FMOH", year=2024),
    ],
)

NAICOM = PackSpec(
    id="nigeria/naicom",
    regulation="Insurance Act 2003 / NAICOM Operational Guidelines 2021 / Market Conduct Guidelines 2023",
    jurisdiction="NG",
    authority="NAICOM",
    rego_path=_PACKS_DIR / "nigeria" / "naicom.rego",
    query_prefix="data.agt_policies_nigeria.naicom",
    tags=["insurance", "claims", "underwriting", "anti-discrimination"],
    sources=[
        RegulatorySource(document="Insurance Act 2003 (Cap I17 LFN 2004)", section="§50", authority="NAICOM", year=2003),
        RegulatorySource(document="Insurance Act 2003 (Cap I17 LFN 2004)", section="§67", authority="NAICOM", year=2003),
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 12", authority="NAICOM", year=2021),
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 15", authority="NAICOM", year=2021),
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 18", authority="NAICOM", year=2021),
        RegulatorySource(document="NAICOM Market Conduct and Business Practice Guidelines 2023", section="Rule 6", authority="NAICOM", year=2023),
        RegulatorySource(document="NAICOM Market Conduct and Business Practice Guidelines 2023", section="Rule 11", authority="NAICOM", year=2023),
    ],
)

# ── East Africa ────────────────────────────────────────────────────────────────

KDPA = PackSpec(
    id="kenya/kdpa",
    regulation="Kenya Data Protection Act 2019",
    jurisdiction="KE",
    authority="ODPC",
    rego_path=_PACKS_DIR / "africa" / "kdpa.rego",
    query_prefix="data.agt_policies_africa.kdpa",
    tags=["data-protection", "cross-border", "pii"],
    sources=[
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§25", authority="ODPC", year=2019),
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§46", authority="ODPC", year=2019),
    ],
)

MAURITIUS_DPA = PackSpec(
    id="mauritius/dpa",
    regulation="Mauritius Data Protection Act 2017",
    jurisdiction="MU",
    authority="DPC Mauritius",
    rego_path=_PACKS_DIR / "africa" / "mauritius_dpa.rego",
    query_prefix="data.agt_policies_africa.mauritius_dpa",
    tags=["data-protection", "pii"],
    sources=[
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§46", authority="DPC Mauritius", year=2017),
    ],
)

TANZANIA_PDPA = PackSpec(
    id="tanzania/pdpa",
    regulation="Tanzania Personal Data Protection Act 2022",
    jurisdiction="TZ",
    authority="PDPC Tanzania",
    rego_path=_PACKS_DIR / "africa" / "tanzania_pdpa.rego",
    query_prefix="data.agt_policies_africa.tanzania_pdpa",
    tags=["data-protection", "pii"],
    sources=[
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§32", authority="PDPC Tanzania", year=2022),
    ],
)

UGANDA_DPPA = PackSpec(
    id="uganda/dppa",
    regulation="Uganda Data Protection and Privacy Act 2019",
    jurisdiction="UG",
    authority="PDPO Uganda",
    rego_path=_PACKS_DIR / "africa" / "uganda_dppa.rego",
    query_prefix="data.agt_policies_africa.uganda_dppa",
    tags=["data-protection", "pii"],
    sources=[
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§26", authority="PDPO Uganda", year=2019),
    ],
)

RWANDA_DPA = PackSpec(
    id="rwanda/dpa",
    regulation="Rwanda Law No. 058/2021 on Personal Data Protection",
    jurisdiction="RW",
    authority="RISA",
    rego_path=_PACKS_DIR / "africa" / "rwanda_dpa.rego",
    query_prefix="data.agt_policies_africa.rwanda_dpa",
    tags=["data-protection", "pii"],
    sources=[
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 8", authority="RISA", year=2021),
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 22", authority="RISA", year=2021),
    ],
)

ETHIOPIA_PDP = PackSpec(
    id="ethiopia/pdp",
    regulation="Ethiopia Personal Data Protection Proclamation 1321/2024",
    jurisdiction="ET",
    authority="ECA",
    rego_path=_PACKS_DIR / "africa" / "ethiopia_pdp.rego",
    query_prefix="data.agt_policies_africa.ethiopia_pdp",
    tags=["data-protection", "pii"],
    sources=[
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 22", authority="ECA", year=2024),
    ],
)

# ── Southern Africa ────────────────────────────────────────────────────────────

POPIA = PackSpec(
    id="south-africa/popia",
    regulation="Protection of Personal Information Act 4 of 2013 (POPIA)",
    jurisdiction="ZA",
    authority="ICLR / Information Regulator",
    rego_path=_PACKS_DIR / "africa" / "popia.rego",
    query_prefix="data.agt_policies_africa.popia",
    tags=["data-protection", "cross-border", "pii", "special-category"],
    sources=[
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§11", authority="Information Regulator ZA", year=2013),
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§72", authority="Information Regulator ZA", year=2013),
    ],
)

# ── West Africa ────────────────────────────────────────────────────────────────

GHANA_DPA = PackSpec(
    id="ghana/dpa",
    regulation="Ghana Data Protection Act 843 of 2012",
    jurisdiction="GH",
    authority="DPC Ghana",
    rego_path=_PACKS_DIR / "africa" / "ghana_dpa.rego",
    query_prefix="data.agt_policies_africa.ghana_dpa",
    tags=["data-protection", "pii"],
    sources=[
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§17", authority="DPC Ghana", year=2012),
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§33", authority="DPC Ghana", year=2012),
    ],
)

# ── North Africa ───────────────────────────────────────────────────────────────

EGYPT_PDPL = PackSpec(
    id="egypt/pdpl",
    regulation="Egypt Personal Data Protection Law No. 151/2020",
    jurisdiction="EG",
    authority="PDPRL Egypt",
    rego_path=_PACKS_DIR / "africa" / "egypt_pdpl.rego",
    query_prefix="data.agt_policies_africa.egypt_pdpl",
    tags=["data-protection", "pii"],
    sources=[
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 3", authority="PDPRL Egypt", year=2020),
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 24", authority="PDPRL Egypt", year=2020),
    ],
)

# ── Universal Agent Safety ─────────────────────────────────────────────────────

_OWASP_URL = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"

PII_LEAKAGE = PackSpec(
    id="universal/pii-leakage",
    regulation="OWASP Agentic AI LLM06 — Sensitive Information Disclosure",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "pii_leakage.rego",
    query_prefix="data.agt_policies_agent.pii_leakage",
    tags=["owasp", "pii", "safety"],
    sources=[
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM06:2025 — Excessive Agency", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
)

PROMPT_INJECTION = PackSpec(
    id="universal/prompt-injection",
    regulation="OWASP Agentic AI LLM01/ASI01 — Prompt Injection",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "prompt_injection.rego",
    query_prefix="data.agt_policies_agent.prompt_injection",
    tags=["owasp", "security", "safety"],
    sources=[
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM01:2025 — Prompt Injection", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
)

TOOL_PERMISSIONS = PackSpec(
    id="universal/tool-permissions",
    regulation="OWASP Agentic AI LLM08 — Excessive Agency",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "tool_permissions.rego",
    query_prefix="data.agt_policies_agent.tool_permissions",
    tags=["owasp", "safety", "permissions"],
    sources=[
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM08:2025 — Excessive Agency", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
)

HUMAN_APPROVAL = PackSpec(
    id="universal/human-approval",
    regulation="OWASP Agentic AI LLM09 — Overreliance",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "human_approval.rego",
    query_prefix="data.agt_policies_agent.human_approval",
    tags=["owasp", "safety", "human-in-the-loop"],
    sources=[
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM08:2025 — Excessive Agency", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
)

MODEL_ROUTING = PackSpec(
    id="universal/model-routing",
    regulation="OWASP Agentic AI LLM03/LLM05 — Model Selection Controls",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "model_routing.rego",
    query_prefix="data.agt_policies_agent.model_routing",
    tags=["owasp", "safety", "model-governance"],
    sources=[
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM09:2025 — Misinformation", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
)

# ── Registry lookup ────────────────────────────────────────────────────────────

PACK_REGISTRY: dict[str, PackSpec] = {
    p.id: p for p in [
        NDPA, CBN, BVN_NIN, NFIU_AML, NHA, NAICOM,
        KDPA, MAURITIUS_DPA, TANZANIA_PDPA, UGANDA_DPPA, RWANDA_DPA, ETHIOPIA_PDP,
        POPIA,
        GHANA_DPA,
        EGYPT_PDPL,
        PII_LEAKAGE, PROMPT_INJECTION, TOOL_PERMISSIONS, HUMAN_APPROVAL, MODEL_ROUTING,
    ]
}

# Jurisdiction → pack IDs
JURISDICTION_PACKS: dict[str, list[str]] = {
    "NG": ["nigeria/ndpa", "nigeria/cbn", "nigeria/bvn-nin", "nigeria/nfiu-aml", "nigeria/nha", "nigeria/naicom"],
    "KE": ["kenya/kdpa"],
    "ZA": ["south-africa/popia"],
    "GH": ["ghana/dpa"],
    "RW": ["rwanda/dpa"],
    "EG": ["egypt/pdpl"],
    "ET": ["ethiopia/pdp"],
    "MU": ["mauritius/dpa"],
    "TZ": ["tanzania/pdpa"],
    "UG": ["uganda/dppa"],
}

UNIVERSAL_PACKS: list[str] = [
    "universal/pii-leakage",
    "universal/prompt-injection",
    "universal/tool-permissions",
    "universal/human-approval",
    "universal/model-routing",
]


def packs_for_jurisdiction(jurisdiction: str, include_universal: bool = True) -> list[PackSpec]:
    """Return all packs for a jurisdiction code, optionally including universal safety packs."""
    ids = JURISDICTION_PACKS.get(jurisdiction.upper(), [])
    if include_universal:
        ids = ids + UNIVERSAL_PACKS
    return [PACK_REGISTRY[i] for i in ids if i in PACK_REGISTRY]


def packs_for_ids(pack_ids: list[str]) -> list[PackSpec]:
    """Return PackSpec objects for a list of pack IDs."""
    return [PACK_REGISTRY[i] for i in pack_ids if i in PACK_REGISTRY]
