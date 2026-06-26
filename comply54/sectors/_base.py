"""
comply54.sectors._base
~~~~~~~~~~~~~~~~~~~~~~
Base class for all comply54 sector packs.
"""

from __future__ import annotations

from ..core.engine import Comply54Engine
from ..core.models import ComplianceCertificate, ComplianceResult, EvaluationInput
from ..core.packs import PackSpec


class SectorCompliance:
    """
    Base class for comply54 sector packs.

    Subclasses declare which packs they compose and optionally override
    default context enrichment (e.g. injecting jurisdiction metadata).
    """

    #: Human-readable name shown in audit logs and error messages.
    name: str = "SectorCompliance"
    #: Regulatory jurisdictions covered, e.g. ["NG", "KE"].
    jurisdictions: list[str] = []
    #: Regulatory frameworks covered, e.g. ["NDPA 2023", "CBN FPR"].
    regulations: list[str] = []

    def __init__(self, packs: list[PackSpec], strict_mode: bool = False) -> None:
        self._engine = Comply54Engine(packs=packs)
        self._strict_mode = strict_mode

    @property
    def strict_mode(self) -> bool:
        """When True, escalate decisions are treated as deny."""
        return self._strict_mode

    @property
    def pack_ids(self) -> list[str]:
        return [p.id for p in self._engine.packs]

    @property
    def packs(self) -> list[PackSpec]:
        return self._engine.packs

    def check(
        self,
        action: str,
        params: dict | None = None,
        output: str = "",
        context: dict | None = None,
    ) -> ComplianceResult:
        """
        Evaluate the agent action against all sector packs.

        Args:
            action:  The tool name / action identifier.
            params:  Structured parameters (amount, currency, destination, etc.).
            output:  The agent's proposed text output.
            context: Session context (kyc_tier, user_id, consent flags, etc.).

        Returns:
            ComplianceResult — check .blocked, .overall, and .violations.
        """
        result = self._engine.check(
            action=action,
            params=params or {},
            output=output,
            context=context or {},
        )
        if self._strict_mode:
            result = self._apply_strict_mode(result)
        return result

    def evaluate(self, input: EvaluationInput | dict) -> ComplianceResult:
        """Direct evaluation with an EvaluationInput object."""
        result = self._engine.evaluate(input)
        if self._strict_mode:
            result = self._apply_strict_mode(result)
        return result

    def certificate(
        self,
        action: str,
        params: dict | None = None,
        output: str = "",
        context: dict | None = None,
    ) -> ComplianceCertificate:
        """
        Run a compliance check and return an auditor-exportable certificate.

        The certificate includes the decision, all violations with messages,
        packs evaluated, regulatory coverage, and a SHA-256 integrity hash.

        Usage:
            cert = compliance.certificate(
                action="transfer_funds",
                params={"amount": 5_000_000, "currency": "NGN"},
            )
            print(cert.to_json())   # export to JSON for auditors
            assert cert.integrity_hash  # tamper-evident fingerprint
        """
        result = self.check(action=action, params=params, output=output, context=context)
        return result.to_certificate(
            sector_pack=self.name,
            jurisdictions=self.jurisdictions,
            regulations=self.regulations,
        )

    @staticmethod
    def _apply_strict_mode(result: ComplianceResult) -> ComplianceResult:
        """Upgrade all 'escalate' decisions to 'deny'."""
        from ..core.models import PolicyDecision
        new_decisions = [
            PolicyDecision(
                pack=d.pack,
                regulation=d.regulation,
                jurisdiction=d.jurisdiction,
                action="deny" if d.action == "escalate" else d.action,
                messages=d.messages,
                rule_triggered=d.rule_triggered,
                audit_id=d.audit_id,
                evaluated_at=d.evaluated_at,
            )
            for d in result.decisions
        ]
        return ComplianceResult.from_decisions(new_decisions)

    def __repr__(self) -> str:
        strict = ", strict_mode=True" if self._strict_mode else ""
        return f"{self.__class__.__name__}(jurisdictions={self.jurisdictions}{strict})"
