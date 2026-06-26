"""
comply54
~~~~~~~~
African AI governance compliance — enforcement engine and sector packs.

Quick start:

    from comply54 import NigeriaFintechCompliance

    compliance = NigeriaFintechCompliance()
    result = compliance.check(
        action="transfer_funds",
        params={"amount": 15_000_000, "currency": "NGN"},
        context={"kyc_tier": 3},
    )
    if result.blocked:
        raise ValueError(result.primary_violation.messages[0])

Low-level API:

    from comply54 import evaluate, PACK_REGISTRY

    result = evaluate(
        pack_ids=["nigeria/cbn", "nigeria/ndpa", "universal/pii-leakage"],
        action="export_data",
        params={"destination_country": "CN", "data_type": "pii"},
    )
"""

from __future__ import annotations

from .core.engine import Comply54Engine
from .core.models import Action, ComplianceCertificate, ComplianceResult, EvaluationInput, PolicyDecision
from .core.packs import (
    PACK_REGISTRY,
    PackSpec,
    packs_for_ids,
    packs_for_jurisdiction,
)
from .sectors import (
    KenyaFintechCompliance,
    NigeriaFintechCompliance,
    PanAfricanFintechCompliance,
    SectorCompliance,
)

__version__ = "0.1.0"
__all__ = [
    # Sector packs (recommended entry point)
    "NigeriaFintechCompliance",
    "KenyaFintechCompliance",
    "PanAfricanFintechCompliance",
    "SectorCompliance",
    # Low-level API
    "evaluate",
    "list_packs",
    "Comply54Engine",
    "EvaluationInput",
    "ComplianceResult",
    "ComplianceCertificate",
    "PolicyDecision",
    "Action",
    # Pack registry
    "PACK_REGISTRY",
    "PackSpec",
    "packs_for_jurisdiction",
    "packs_for_ids",
]


def list_packs() -> list[PackSpec]:
    """Return all registered comply54 packs."""
    return list(PACK_REGISTRY.values())


def evaluate(
    pack_ids: list[str],
    action: str,
    params: dict | None = None,
    output: str = "",
    context: dict | None = None,
) -> ComplianceResult:
    """
    Evaluate a set of comply54 packs against an agent action.

    This is the lowest-level public API. Prefer sector packs
    (NigeriaFintechCompliance etc.) for production use.

    Args:
        pack_ids: List of pack IDs from PACK_REGISTRY.
        action:   The tool/action name.
        params:   Structured parameters dict.
        output:   Agent's proposed text output.
        context:  Session context dict.

    Returns:
        ComplianceResult

    Example:
        result = evaluate(
            pack_ids=["nigeria/cbn", "universal/pii-leakage"],
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        )
    """
    packs = packs_for_ids(pack_ids)
    engine = Comply54Engine(packs=packs)
    return engine.check(action=action, params=params or {}, output=output, context=context or {})
