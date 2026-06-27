"""
comply54.langchain.adapter
~~~~~~~~~~~~~~~~~~~~~~~~~~
LangChain / LangGraph integration for comply54.

Provides:
  - comply54_tool()    — StructuredTool wrapping any SectorCompliance pack
  - Comply54Guard      — LangGraph node that intercepts AIMessage tool_calls
                         and runs comply54 before they execute
  - comply54_route()   — Conditional routing function for the guard node
  - compliance_node()  — Simple state-dict node (legacy, kept for compatibility)

No OPA binary required. No subprocess. Works in serverless environments.

LangGraph guard pattern (recommended):

    from comply54.langchain import Comply54Guard, comply54_route
    from comply54.sectors import NigeriaFintechCompliance

    guard = Comply54Guard(NigeriaFintechCompliance(), context={"kyc_tier": 3})

    graph.add_node("agent", call_model)
    graph.add_node("comply54_guard", guard)
    graph.add_node("tools", tool_node)

    graph.add_conditional_edges("agent", should_continue,
        {"comply54_guard": "comply54_guard", END: END})
    graph.add_conditional_edges("comply54_guard", comply54_route,
        {"tools": "tools", "agent": "agent"})
    graph.add_edge("tools", "agent")
"""

from __future__ import annotations

import json
from typing import Any

from ..core.models import ComplianceResult
from ..sectors._base import SectorCompliance


# ─── LangGraph guard node ─────────────────────────────────────────────────────

class Comply54Guard:
    """
    LangGraph node that intercepts tool calls from an agent node and evaluates
    each one against comply54 compliance packs before execution.

    The guard reads the last AIMessage from state["messages"], evaluates every
    tool_call against the configured SectorCompliance pack, and either:

      - Injects ToolMessage errors for blocked calls and sets
        state["compliance_blocked"] = True  (agent sees the errors and responds)
      - Sets state["compliance_blocked"] = False and passes through so the
        tools node can execute the calls normally.

    Args:
        compliance:       A SectorCompliance instance (e.g. NigeriaFintechCompliance()).
        context:          Default session context applied to every evaluation
                          (e.g. {"kyc_tier": 3, "customer_verified": True}).
                          Per-request overrides via state["compliance_context"].
        block_on_escalate: If True, treat "escalate" decisions as blocks in addition
                          to "deny". Default False — escalate is flagged but allowed
                          through so the agent can explain the escalation to the user.

    Usage:
        guard = Comply54Guard(
            NigeriaFintechCompliance(),
            context={"kyc_tier": 3},
            block_on_escalate=True,
        )
        graph.add_node("comply54_guard", guard)
    """

    def __init__(
        self,
        compliance: SectorCompliance,
        context: dict | None = None,
        block_on_escalate: bool = False,
    ) -> None:
        self._compliance = compliance
        self._default_context = context or {}
        self._block_on_escalate = block_on_escalate

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        try:
            from langchain_core.messages import AIMessage, ToolMessage
        except ImportError as exc:
            raise ImportError(
                "langchain-core is required. Install with: pip install comply54[langgraph]"
            ) from exc

        messages = state.get("messages", [])
        if not messages:
            return {"compliance_blocked": False, "compliance_result": None}

        last_msg = messages[-1]
        if not isinstance(last_msg, AIMessage) or not last_msg.tool_calls:
            return {"compliance_blocked": False, "compliance_result": None}

        # Merge default context with per-request context from state.
        context = {**self._default_context, **state.get("compliance_context", {})}

        blocked_tool_messages: list[ToolMessage] = []
        last_result: ComplianceResult | None = None

        for tool_call in last_msg.tool_calls:
            result = self._compliance.check(
                action=tool_call["name"],
                params=tool_call.get("args", {}),
                context=context,
            )
            last_result = result

            is_blocked = result.overall == "deny" or (
                self._block_on_escalate and result.overall == "escalate"
            )

            if is_blocked:
                violation = result.primary_violation
                reason = (
                    violation.messages[0]
                    if violation and violation.messages
                    else "Compliance check failed"
                )
                regulation = violation.regulation if violation else self._compliance.name

                blocked_tool_messages.append(
                    ToolMessage(
                        content=json.dumps({
                            "blocked": True,
                            "decision": result.overall,
                            "reason": reason,
                            "regulation": regulation,
                            "audit_id": result.audit_id,
                            "jurisdictions": self._compliance.jurisdictions,
                        }),
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                    )
                )

        result_dict = _result_to_dict(last_result) if last_result else None

        if blocked_tool_messages:
            return {
                "messages": blocked_tool_messages,
                "compliance_blocked": True,
                "compliance_result": result_dict,
            }

        return {
            "compliance_blocked": False,
            "compliance_result": result_dict,
        }

    def __repr__(self) -> str:
        return (
            f"Comply54Guard({self._compliance!r}, "
            f"block_on_escalate={self._block_on_escalate})"
        )


def comply54_route(state: dict[str, Any]) -> str:
    """
    Routing function for the conditional edge leaving the comply54_guard node.

    Returns:
        "tools"  — all tool calls passed compliance; proceed to execution.
        "agent"  — one or more calls were blocked; agent receives ToolMessage
                   errors and can respond to the user with an explanation.

    Usage:
        graph.add_conditional_edges(
            "comply54_guard",
            comply54_route,
            {"tools": "tools", "agent": "agent"},
        )
    """
    return "agent" if state.get("compliance_blocked") else "tools"


# ─── LangChain StructuredTool wrapper ─────────────────────────────────────────

def comply54_tool(compliance: SectorCompliance, name: str | None = None):
    """
    Wrap a SectorCompliance pack as a LangChain StructuredTool.

    Useful for giving the agent the ability to self-check before taking an action.
    For automatic pre-execution enforcement use Comply54Guard instead.

    Args:
        compliance: A SectorCompliance instance (e.g. NigeriaFintechCompliance()).
        name: Optional tool name override.

    Returns:
        langchain_core.tools.StructuredTool
    """
    try:
        from langchain_core.tools import StructuredTool
        from pydantic import BaseModel, Field
    except ImportError as exc:
        raise ImportError(
            "langchain-core is required. Install with: pip install comply54[langgraph]"
        ) from exc

    class ComplianceInput(BaseModel):
        action: str = Field(description="The agent action or tool name to evaluate.")
        params: dict = Field(default_factory=dict, description="Action parameters.")
        output: str = Field(default="", description="Agent's proposed output text.")
        context: dict = Field(default_factory=dict, description="Session context.")

    tool_name = name or f"comply54_{compliance.__class__.__name__.lower()}"

    def run_check(
        action: str,
        params: dict | None = None,
        output: str = "",
        context: dict | None = None,
    ) -> str:
        result = compliance.check(
            action=action, params=params or {}, output=output, context=context or {}
        )
        return json.dumps(_result_to_dict(result))

    return StructuredTool.from_function(
        func=run_check,
        name=tool_name,
        description=(
            f"comply54 compliance check — {compliance.name}. "
            f"Jurisdictions: {', '.join(compliance.jurisdictions)}. "
            "Returns JSON with overall decision (allow/deny/escalate/audit) and violation details."
        ),
        args_schema=ComplianceInput,
    )


# ─── Legacy simple node (kept for backward compatibility) ─────────────────────

def compliance_node(compliance: SectorCompliance):
    """
    Build a LangGraph state-graph node that enforces compliance.

    Legacy API: reads action/params/output/context directly from the state dict.
    For message-based ReAct agents use Comply54Guard instead.

    The node reads `action`, `params`, `output`, and `context` from the
    agent state dict and writes back:
      - compliance_result:  ComplianceResult as dict
      - compliance_blocked: bool
      - compliance_message: primary violation message (empty string if passed)
    """
    def _node(state: dict[str, Any]) -> dict[str, Any]:
        result = compliance.check(
            action=state.get("action", ""),
            params=state.get("params", {}),
            output=state.get("output", ""),
            context=state.get("context", {}),
        )
        violation = result.primary_violation
        return {
            **state,
            "compliance_result": _result_to_dict(result),
            "compliance_blocked": result.blocked,
            "compliance_message": (
                violation.messages[0] if violation and violation.messages else ""
            ),
        }

    return _node


# ─── Internal helpers ─────────────────────────────────────────────────────────

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
            }
            for d in result.violations
        ],
    }
