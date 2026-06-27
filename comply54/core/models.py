"""
comply54.core.models
~~~~~~~~~~~~~~~~~~~~
Standardised data types returned by every comply54 evaluation.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


Action = Literal["allow", "deny", "escalate", "audit"]


class RegulatorySource(BaseModel):
    """A specific regulatory document and section enforced by a policy rule."""

    model_config = ConfigDict(frozen=True)

    document: str
    """Official document name or reference (e.g. 'CBN Circular FPR/DIR/GEN/CIR/07/003')."""
    section: str
    """Section, article, or guideline number (e.g. '§4.1', 'Guideline 4', 'Art. 22')."""
    authority: str
    """Issuing authority (e.g. 'CBN', 'NDPC', 'NAICOM')."""
    year: int
    """Year the document was issued or last amended."""
    url: str = ""
    """Optional URL to the official document text."""


class PolicyDecision(BaseModel):
    """
    The outcome of evaluating a single policy pack against an agent action.

    Severity order: deny > escalate > audit > allow
    """

    pack: str
    regulation: str
    jurisdiction: str
    action: Action
    messages: list[str] = Field(default_factory=list)
    citations: list[RegulatorySource] = Field(default_factory=list)
    rule_triggered: Optional[str] = None
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def passed(self) -> bool:
        return self.action == "allow"

    @property
    def blocked(self) -> bool:
        return self.action in ("deny", "escalate")

    def __str__(self) -> str:
        msg = self.messages[0] if self.messages else "No message"
        return f"[{self.jurisdiction}/{self.pack}] {self.action.upper()}: {msg}"


_SEVERITY: dict[Action, int] = {"allow": 0, "audit": 1, "escalate": 2, "deny": 3}


class ComplianceResult(BaseModel):
    """
    The aggregate outcome of evaluating multiple policy packs in a single call.
    This is what sector packs and adapters return.
    """

    overall: Action
    decisions: list[PolicyDecision]
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def passed(self) -> bool:
        return self.overall == "allow"

    @property
    def blocked(self) -> bool:
        return self.overall in ("deny", "escalate")

    @property
    def violations(self) -> list[PolicyDecision]:
        return [d for d in self.decisions if d.action != "allow"]

    @property
    def primary_violation(self) -> PolicyDecision | None:
        """Returns the most severe violation, if any."""
        blocking = [d for d in self.decisions if d.blocked]
        if blocking:
            return max(blocking, key=lambda d: _SEVERITY[d.action])
        return None

    def to_certificate(
        self,
        sector_pack: str = "comply54",
        jurisdictions: list[str] | None = None,
        regulations: list[str] | None = None,
    ) -> "ComplianceCertificate":
        """
        Generate an auditor-exportable compliance certificate from this result.

        Args:
            sector_pack:   Name of the sector pack that produced this result.
            jurisdictions: Jurisdiction codes covered (e.g. ["NG", "KE"]).
            regulations:   Human-readable regulation names covered.

        Returns:
            ComplianceCertificate — call .to_json() or .to_dict() for export.
        """
        violations_export = [
            {
                "pack": d.pack,
                "regulation": d.regulation,
                "jurisdiction": d.jurisdiction,
                "action": d.action,
                "messages": d.messages,
                "citations": [c.model_dump() for c in d.citations],
            }
            for d in self.violations
        ]
        packs_evaluated = [d.pack for d in self.decisions]

        # Integrity hash: deterministic fingerprint of the decision set
        hash_payload = json.dumps(
            {
                "audit_id": self.audit_id,
                "overall": self.overall,
                "violations": violations_export,
                "packs": packs_evaluated,
            },
            sort_keys=True,
        )
        integrity_hash = hashlib.sha256(hash_payload.encode()).hexdigest()

        return ComplianceCertificate(
            certificate_id=f"cert_{uuid.uuid4().hex[:12]}",
            issued_at=self.evaluated_at,
            sector_pack=sector_pack,
            jurisdictions=jurisdictions or [],
            regulations=regulations or [],
            overall=self.overall,
            passed=self.passed,
            violations=violations_export,
            packs_evaluated=packs_evaluated,
            audit_id=self.audit_id,
            integrity_hash=integrity_hash,
        )

    @classmethod
    def from_decisions(cls, decisions: list[PolicyDecision]) -> "ComplianceResult":
        overall: Action = "allow"
        for d in decisions:
            if _SEVERITY[d.action] > _SEVERITY[overall]:
                overall = d.action
        return cls(overall=overall, decisions=decisions)


class ComplianceCertificate(BaseModel):
    """
    Auditor-exportable compliance certificate for a single evaluation.

    Generated by ComplianceResult.to_certificate() or SectorCompliance.certificate().
    Suitable for inclusion in regulatory audit files, export-control logs,
    and internal compliance records.
    """

    certificate_id: str
    issued_at: datetime
    sector_pack: str
    jurisdictions: list[str]
    regulations: list[str]
    overall: Action
    passed: bool
    violations: list[dict]
    packs_evaluated: list[str]
    audit_id: str
    integrity_hash: str

    def to_json(self, indent: int = 2) -> str:
        """Return the certificate as a formatted JSON string."""
        data = self.model_dump(mode="json")
        return json.dumps(data, indent=indent, default=str)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class EvaluationInput(BaseModel):
    """
    Standardised input schema accepted by every comply54 pack.

    Mirrors the input schema used in agt-policies-nigeria Rego policies.
    """

    action: str = Field(description="The tool/action the agent is about to execute.")
    params: dict = Field(
        default_factory=dict,
        description="Structured parameters for the action (amount, currency, destination, etc.).",
    )
    output: str = Field(
        default="",
        description="The agent's proposed text output (used by PII/prompt-injection packs).",
    )
    context: dict = Field(
        default_factory=dict,
        description="Session context: kyc_tier, user_id, consent flags, etc.",
    )

    def to_rego_input(self) -> dict:
        return self.model_dump()
