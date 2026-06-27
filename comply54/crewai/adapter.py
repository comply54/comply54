"""
comply54.crewai.adapter
~~~~~~~~~~~~~~~~~~~~~~~
CrewAI integration for comply54.

Provides:
  - Comply54CrewTool       — BaseTool agents call explicitly to self-check an action
  - Comply54GuardedTool    — Wraps any CrewAI BaseTool; blocks execution on deny
  - comply54_guard_tools() — Wrap a list of tools and return guarded versions
  - Comply54TaskGuardrail  — CrewAI task guardrail for output-level PII / safety checks

Automatic enforcement pattern (recommended):

    from comply54.crewai import comply54_guard_tools
    from comply54.sectors import NigeriaFintechCompliance

    raw_tools = [TransferFundsTool(), CheckBalanceTool()]
    guarded   = comply54_guard_tools(NigeriaFintechCompliance(), raw_tools,
                                     context={"kyc_tier": 3})

    agent = Agent(
        role="Fintech Agent",
        tools=guarded,
        ...
    )

Output-level guardrail pattern:

    from comply54.crewai import Comply54TaskGuardrail

    guardrail = Comply54TaskGuardrail(NigeriaFintechCompliance())

    task = Task(
        description="Summarise the customer account",
        expected_output="Plain text summary",
        guardrail=guardrail,
        agent=agent,
    )
"""

from __future__ import annotations

import json
from typing import Any, Type

from ..core.models import ComplianceResult
from ..sectors._base import SectorCompliance

try:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field
    _CREWAI = True
except ImportError:
    BaseTool = object  # type: ignore[misc,assignment]
    _CREWAI = False

    class BaseModel:  # type: ignore[no-redef]
        pass

    def Field(*args: Any, **kwargs: Any) -> Any:  # type: ignore[no-redef]
        return None


# ─── Input schemas ────────────────────────────────────────────────────────────

class _ComplianceInput(BaseModel):
    action: str = Field(description="Agent action or tool name to evaluate.")
    params: dict = Field(default_factory=dict, description="Action parameters.")
    output: str = Field(default="", description="Agent's proposed output text.")
    context: dict = Field(default_factory=dict, description="Session context.")


class _FallbackInput(BaseModel):
    """Generic single-string input for tools without a defined args_schema."""
    input: str = Field(default="", description="Tool input.")


# ─── Self-check tool ──────────────────────────────────────────────────────────

class Comply54CrewTool(BaseTool):
    """
    A CrewAI BaseTool that evaluates an action explicitly against a comply54 pack.

    The agent calls this tool to self-check compliance before acting.
    For automatic pre-execution enforcement on existing tools, use
    comply54_guard_tools() or Comply54GuardedTool instead.

    Args:
        compliance: A SectorCompliance instance (e.g. NigeriaFintechCompliance()).

    Usage:
        tool = Comply54CrewTool(compliance=NigeriaFintechCompliance())
        agent = Agent(role="Compliance Agent", tools=[tool], ...)
    """

    name: str = "comply54_compliance_check"
    description: str = (
        "Check whether an agent action complies with applicable African regulatory requirements. "
        "Returns a JSON decision with overall outcome (allow/deny/escalate/audit), "
        "violation details, triggered rule, and exact regulatory citations."
    )
    args_schema: Type[BaseModel] = _ComplianceInput  # type: ignore[assignment]
    compliance: Any = None
    model_config = {"arbitrary_types_allowed": True}

    def __init__(self, compliance: SectorCompliance, **kwargs: Any) -> None:
        if not _CREWAI:
            raise ImportError("crewai is required. Install with: pip install comply54[crewai]")
        super().__init__(
            compliance=compliance,
            name=f"comply54_{compliance.__class__.__name__.lower()}",
            description=(
                f"comply54 compliance check — {compliance.name}. "
                f"Jurisdictions: {', '.join(compliance.jurisdictions)}. "
                "Returns JSON with overall decision (allow/deny/escalate/audit), "
                "triggered rule, and exact regulatory citations."
            ),
            **kwargs,
        )

    def _run(
        self,
        action: str,
        params: dict | None = None,
        output: str = "",
        context: dict | None = None,
    ) -> str:
        result = self.compliance.check(
            action=action, params=params or {}, output=output, context=context or {}
        )
        return json.dumps(_result_to_dict(result))


# ─── Pre-execution guard tool ─────────────────────────────────────────────────

class Comply54GuardedTool(BaseTool):
    """
    Wraps any CrewAI BaseTool with pre-execution comply54 enforcement.

    When the agent calls the guarded tool, comply54 evaluates the action and
    parameters against the configured SectorCompliance pack *before* the inner
    tool executes.  If the decision is "deny" (or "escalate" when
    block_on_escalate is True), the tool returns a structured error JSON
    without executing the inner tool.

    The wrapped tool's original name, description, and args_schema are
    preserved — the agent's interface is unchanged.

    Args:
        inner_tool:        The original CrewAI BaseTool to wrap.
        compliance:        A SectorCompliance instance.
        context:           Default session context (e.g. {"kyc_tier": 3}).
                           Merged with any context present at call time.
        block_on_escalate: Also block "escalate" decisions. Default False —
                           escalate passes through so the agent can surface
                           the escalation reason to the user.

    Usage:
        from comply54.crewai import Comply54GuardedTool
        from comply54.sectors import NigeriaFintechCompliance

        guarded = Comply54GuardedTool(
            TransferFundsTool(),
            NigeriaFintechCompliance(),
            context={"kyc_tier": 3},
        )
        agent = Agent(role="Fintech Agent", tools=[guarded], ...)
    """

    name: str = ""
    description: str = ""
    inner_tool: Any = None
    compliance: Any = None
    guard_context: dict = Field(default_factory=dict)
    block_on_escalate: bool = False
    model_config = {"arbitrary_types_allowed": True}

    def __init__(
        self,
        inner_tool: Any,
        compliance: SectorCompliance,
        context: dict | None = None,
        block_on_escalate: bool = False,
        **kwargs: Any,
    ) -> None:
        if not _CREWAI:
            raise ImportError("crewai is required. Install with: pip install comply54[crewai]")

        inner_schema = getattr(inner_tool, "args_schema", _FallbackInput)

        super().__init__(
            name=inner_tool.name,
            description=(
                f"[comply54 guarded] {inner_tool.description} "
                f"— enforces {compliance.name} "
                f"({', '.join(compliance.jurisdictions)})"
            ),
            inner_tool=inner_tool,
            compliance=compliance,
            guard_context=context or {},
            block_on_escalate=block_on_escalate,
            args_schema=inner_schema,
            **kwargs,
        )

    def _run(self, **kwargs: Any) -> str:
        result = self.compliance.check(
            action=self.inner_tool.name,
            params=kwargs,
            context=self.guard_context,
        )
        is_blocked = result.overall == "deny" or (
            self.block_on_escalate and result.overall == "escalate"
        )

        if is_blocked:
            violation = result.primary_violation
            reason = (
                violation.messages[0]
                if violation and violation.messages
                else "Compliance check failed"
            )
            return json.dumps({
                "blocked": True,
                "decision": result.overall,
                "reason": reason,
                "regulation": violation.regulation if violation else self.compliance.name,
                "rule_triggered": violation.rule_triggered if violation else None,
                "citations": [
                    {
                        "document": c.document,
                        "section": c.section,
                        "authority": c.authority,
                        "year": c.year,
                    }
                    for c in (violation.citations if violation else [])
                ],
                "audit_id": result.audit_id,
                "jurisdictions": self.compliance.jurisdictions,
            })

        # Compliance passed — execute the inner tool.
        return self.inner_tool._run(**kwargs)

    def __repr__(self) -> str:
        return (
            f"Comply54GuardedTool({self.inner_tool!r}, {self.compliance!r}, "
            f"block_on_escalate={self.block_on_escalate})"
        )


# ─── Convenience wrapper ──────────────────────────────────────────────────────

def comply54_guard_tools(
    compliance: SectorCompliance,
    tools: list[Any],
    context: dict | None = None,
    block_on_escalate: bool = False,
) -> list[Comply54GuardedTool]:
    """
    Wrap a list of CrewAI tools with comply54 pre-execution enforcement.

    Each tool in the list is wrapped in a Comply54GuardedTool that checks
    compliance before allowing execution.  The original tool interfaces
    (name, description, args_schema) are preserved.

    Args:
        compliance:        A SectorCompliance instance.
        tools:             List of CrewAI BaseTool instances to guard.
        context:           Default session context applied to every evaluation
                           (e.g. {"kyc_tier": 3, "customer_verified": True}).
        block_on_escalate: Treat "escalate" decisions as blocks. Default False.

    Returns:
        List of Comply54GuardedTool instances, one per input tool.

    Usage:
        from comply54.crewai import comply54_guard_tools
        from comply54.sectors import NigeriaFintechCompliance

        raw_tools = [TransferFundsTool(), GetBalanceTool()]
        guarded   = comply54_guard_tools(
            NigeriaFintechCompliance(), raw_tools, context={"kyc_tier": 3}
        )
        agent = Agent(role="Fintech Agent", tools=guarded, ...)
    """
    return [
        Comply54GuardedTool(
            inner_tool=tool,
            compliance=compliance,
            context=context,
            block_on_escalate=block_on_escalate,
        )
        for tool in tools
    ]


# ─── Output-level task guardrail ──────────────────────────────────────────────

class Comply54TaskGuardrail:
    """
    CrewAI task guardrail that enforces comply54 output-level checks.

    Implements the CrewAI guardrail protocol: a callable that takes a TaskOutput
    and returns ``(True, output)`` on pass or ``(False, error_message)`` on fail.

    Primary use case: detect PII leakage (BVN, NIN, account numbers, medical data)
    and prompt-injection echoes in agent task output *before* it is delivered.

    Args:
        compliance:  A SectorCompliance instance.
        action:      The action name to evaluate output against.
                     Defaults to ``"respond_to_user"`` which triggers the
                     PII-leakage and output-safety packs.
        context:     Default session context.

    Usage:
        from comply54.crewai import Comply54TaskGuardrail
        from comply54.sectors import NigeriaFintechCompliance

        guardrail = Comply54TaskGuardrail(NigeriaFintechCompliance())

        task = Task(
            description="Summarise the customer's transaction history",
            expected_output="Plain text summary",
            guardrail=guardrail,
            agent=agent,
        )
    """

    def __init__(
        self,
        compliance: SectorCompliance,
        action: str = "respond_to_user",
        context: dict | None = None,
    ) -> None:
        self._compliance = compliance
        self._action = action
        self._context = context or {}

    def __call__(self, task_output: Any) -> tuple[bool, Any]:
        output_text = _extract_output_text(task_output)
        result = self._compliance.check(
            action=self._action,
            output=output_text,
            context=self._context,
        )

        if result.blocked:
            violation = result.primary_violation
            reason = (
                violation.messages[0]
                if violation and violation.messages
                else "Output failed compliance check"
            )
            regulation = violation.regulation if violation else self._compliance.name
            rule = f" [{violation.rule_triggered}]" if (violation and violation.rule_triggered) else ""
            return (
                False,
                f"comply54 blocked: [{regulation}]{rule} {reason} (audit_id={result.audit_id})",
            )

        return True, task_output

    def __repr__(self) -> str:
        return f"Comply54TaskGuardrail({self._compliance!r}, action={self._action!r})"


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _extract_output_text(task_output: Any) -> str:
    """Extract plain text from a CrewAI TaskOutput or raw string."""
    if isinstance(task_output, str):
        return task_output
    if hasattr(task_output, "raw"):
        return str(task_output.raw)
    return str(task_output)


def _result_to_dict(result: ComplianceResult) -> dict:
    return {
        "overall": result.overall,
        "blocked": result.blocked,
        "audit_id": result.audit_id,
        "violations": [
            {
                "pack": d.pack,
                "regulation": d.regulation,
                "jurisdiction": d.jurisdiction,
                "action": d.action,
                "messages": d.messages,
                "rule_triggered": d.rule_triggered,
                "citations": [
                    {
                        "document": c.document,
                        "section": c.section,
                        "authority": c.authority,
                        "year": c.year,
                    }
                    for c in d.citations
                ],
            }
            for d in result.violations
        ],
    }
