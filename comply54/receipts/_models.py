"""
comply54.receipts._models
~~~~~~~~~~~~~~~~~~~~~~~~~
Data model for a decoded and verified comply54 receipt payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class ReceiptPayload:
    """
    Decoded and verified payload from a comply54 signed receipt token.

    Returned by ``verify_receipt()``. All fields are extracted from the
    JWT claims and have been cryptographically verified against the
    signing key before this object is constructed.
    """

    jti: str
    """Unique receipt identifier — matches ``ComplianceResult.audit_id``."""

    issued_at: int
    """Unix timestamp (UTC) when the receipt was signed."""

    issuer: str
    """Always ``'comply54'``."""

    decision: str
    """The compliance decision: ``'allow'``, ``'deny'``, ``'escalate'``, or ``'audit'``."""

    pack: Optional[str]
    """Primary pack that produced the decision (``None`` for ``'allow'``)."""

    regulation: Optional[str]
    """Primary regulation cited (``None`` for ``'allow'``)."""

    rule_triggered: Optional[str]
    """Specific rule key that triggered the decision (e.g. ``'sanctions_screening_required'``)."""

    messages: List[str]
    """Human-readable violation messages from the primary pack (up to 5)."""

    input_digest: str
    """
    SHA-256 digest of the evaluation input in ``sha256:<hex>`` format.

    Recompute with ``digest_input(action, params, output, context)`` and
    compare to prove the receipt covers the exact input under inspection.
    """

    comply54_version: str
    """Version of comply54 that produced this receipt."""

    packs_evaluated: List[str]
    """All pack IDs evaluated in this check, e.g. ``['nigeria/nfiu-aml', 'nigeria/cbn']``."""

    pack_versions: dict
    """
    Mapping of evaluated pack ID → policy pack version at evaluation time.

    Example::

        {
            "nigeria/cbn":      "1.0.0",
            "nigeria/nfiu-aml": "1.1.0",
            "nigeria/ndpa":     "1.0.0",
        }

    Use this to confirm exactly which version of each regulation was being
    enforced when this receipt was issued.  Empty dict for receipts produced
    before comply54 v0.4.1.
    """

    def __str__(self) -> str:
        status = "✓ ALLOW" if self.decision == "allow" else f"✗ {self.decision.upper()}"
        pack_str = f" [{self.pack}]" if self.pack else ""
        return f"comply54 receipt {status}{pack_str} — {self.regulation or 'no violation'}"
