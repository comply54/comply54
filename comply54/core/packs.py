"""
comply54.core.packs
~~~~~~~~~~~~~~~~~~~
Registry of all bundled policy packs — maps pack IDs to Rego files,
OPA query paths, and regulatory metadata.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field


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
)

CBN = PackSpec(
    id="nigeria/cbn",
    regulation="CBN Transaction Limits & Controls (FPR/DIR/GEN/CIR/07/003)",
    jurisdiction="NG",
    authority="CBN",
    rego_path=_PACKS_DIR / "nigeria" / "cbn.rego",
    query_prefix="data.agt_policies_nigeria.cbn",
    tags=["fintech", "aml", "transaction-limits", "kyc"],
)

BVN_NIN = PackSpec(
    id="nigeria/bvn-nin",
    regulation="CBN BVN Framework & NIBSS BVN Scheme Rules",
    jurisdiction="NG",
    authority="CBN/NIBSS",
    rego_path=_PACKS_DIR / "nigeria" / "bvn_nin.rego",
    query_prefix="data.agt_policies_nigeria.bvn_nin",
    tags=["identity", "biometric", "pii"],
)

NFIU_AML = PackSpec(
    id="nigeria/nfiu-aml",
    regulation="Money Laundering (Prevention & Prohibition) Act 2022 / NFIU Guidelines",
    jurisdiction="NG",
    authority="NFIU",
    rego_path=_PACKS_DIR / "nigeria" / "nfiu_aml.rego",
    query_prefix="data.agt_policies_nigeria.nfiu",
    tags=["aml", "cft", "str", "fintech"],
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
)

MAURITIUS_DPA = PackSpec(
    id="mauritius/dpa",
    regulation="Mauritius Data Protection Act 2017",
    jurisdiction="MU",
    authority="DPC Mauritius",
    rego_path=_PACKS_DIR / "africa" / "mauritius_dpa.rego",
    query_prefix="data.agt_policies_africa.mauritius_dpa",
    tags=["data-protection", "pii"],
)

TANZANIA_PDPA = PackSpec(
    id="tanzania/pdpa",
    regulation="Tanzania Personal Data Protection Act 2022",
    jurisdiction="TZ",
    authority="PDPC Tanzania",
    rego_path=_PACKS_DIR / "africa" / "tanzania_pdpa.rego",
    query_prefix="data.agt_policies_africa.tanzania_pdpa",
    tags=["data-protection", "pii"],
)

UGANDA_DPPA = PackSpec(
    id="uganda/dppa",
    regulation="Uganda Data Protection and Privacy Act 2019",
    jurisdiction="UG",
    authority="PDPO Uganda",
    rego_path=_PACKS_DIR / "africa" / "uganda_dppa.rego",
    query_prefix="data.agt_policies_africa.uganda_dppa",
    tags=["data-protection", "pii"],
)

RWANDA_DPA = PackSpec(
    id="rwanda/dpa",
    regulation="Rwanda Law No. 058/2021 on Personal Data Protection",
    jurisdiction="RW",
    authority="RISA",
    rego_path=_PACKS_DIR / "africa" / "rwanda_dpa.rego",
    query_prefix="data.agt_policies_africa.rwanda_dpa",
    tags=["data-protection", "pii"],
)

ETHIOPIA_PDP = PackSpec(
    id="ethiopia/pdp",
    regulation="Ethiopia Personal Data Protection Proclamation 1321/2024",
    jurisdiction="ET",
    authority="ECA",
    rego_path=_PACKS_DIR / "africa" / "ethiopia_pdp.rego",
    query_prefix="data.agt_policies_africa.ethiopia_pdp",
    tags=["data-protection", "pii"],
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
)

# ── Universal Agent Safety ─────────────────────────────────────────────────────

PII_LEAKAGE = PackSpec(
    id="universal/pii-leakage",
    regulation="OWASP Agentic AI LLM06 — Sensitive Information Disclosure",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "pii_leakage.rego",
    query_prefix="data.agt_policies_agent.pii_leakage",
    tags=["owasp", "pii", "safety"],
)

PROMPT_INJECTION = PackSpec(
    id="universal/prompt-injection",
    regulation="OWASP Agentic AI LLM01/ASI01 — Prompt Injection",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "prompt_injection.rego",
    query_prefix="data.agt_policies_agent.prompt_injection",
    tags=["owasp", "security", "safety"],
)

TOOL_PERMISSIONS = PackSpec(
    id="universal/tool-permissions",
    regulation="OWASP Agentic AI LLM08 — Excessive Agency",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "tool_permissions.rego",
    query_prefix="data.agt_policies_agent.tool_permissions",
    tags=["owasp", "safety", "permissions"],
)

HUMAN_APPROVAL = PackSpec(
    id="universal/human-approval",
    regulation="OWASP Agentic AI LLM09 — Overreliance",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "human_approval.rego",
    query_prefix="data.agt_policies_agent.human_approval",
    tags=["owasp", "safety", "human-in-the-loop"],
)

MODEL_ROUTING = PackSpec(
    id="universal/model-routing",
    regulation="OWASP Agentic AI LLM03/LLM05 — Model Selection Controls",
    jurisdiction="universal",
    authority="OWASP",
    rego_path=_PACKS_DIR / "universal" / "model_routing.rego",
    query_prefix="data.agt_policies_agent.model_routing",
    tags=["owasp", "safety", "model-governance"],
)

# ── Registry lookup ────────────────────────────────────────────────────────────

PACK_REGISTRY: dict[str, PackSpec] = {
    p.id: p for p in [
        NDPA, CBN, BVN_NIN, NFIU_AML,
        KDPA, MAURITIUS_DPA, TANZANIA_PDPA, UGANDA_DPPA, RWANDA_DPA, ETHIOPIA_PDP,
        POPIA,
        GHANA_DPA,
        EGYPT_PDPL,
        PII_LEAKAGE, PROMPT_INJECTION, TOOL_PERMISSIONS, HUMAN_APPROVAL, MODEL_ROUTING,
    ]
}

# Jurisdiction → pack IDs
JURISDICTION_PACKS: dict[str, list[str]] = {
    "NG": ["nigeria/ndpa", "nigeria/cbn", "nigeria/bvn-nin", "nigeria/nfiu-aml"],
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
