"""
comply54.langchain.adapter
~~~~~~~~~~~~~~~~~~~~~~~~~~
LangChain / LangGraph integration for comply54.

Provides:
  - comply54_tool()       — StructuredTool wrapping any SectorCompliance pack
  - compliance_node()     — LangGraph node that enforces compliance on agent state
  - Comply54CallbackHandler — LangChain callback that intercepts tool calls pre-execution

No OPA binary required. No subprocess. Works in serverless environments.

Usage (LangChain tool):
    from comply54.langchain import comply54_tool
    from comply54 import NigeriaFintechCompliance

    tool = comply54_tool(NigeriaFintechCompliance())
    result = tool.invoke({"action": "transfer_funds", "params": {"amount": 5000000, "currency": "NGN"}})

Usage (LangGraph node):
    from comply54.langchain import compliance_node
    from comply54 import NigeriaFintechCompliance

    graph.add_node("compliance", compliance_node(NigeriaFintechCompliance()))
"""

from __future__ import annotations

import json
from typing import Any

from ..core.models import ComplianceResult
from ..sectors._base import SectorCompliance


def comply54_tool(compliance: SectorCompliance, name: str | None = None):
    """
    Wrap a SectorCompliance pack as a LangChain StructuredTool.

    Args:
        compliance: A SectorCompliance instance (e.g. NigeriaFintechCompliance()).
        name: Optional tool name override.

    Returns:
        langchain_core.tools.StructuredTool
    """
    try:
        from langchain_core.tools import StructuredTool
        from pydantic import BaseModel, Field
    except ImportError as e:
        raise ImportError(
            "langchain-core is required. Install with: pip install comply54[langchain]"
        ) from e

    class ComplianceInput(BaseModel):
        action: str = Field(description="The agent action or tool name to evaluate.")
        params: dict = Field(default_factory=dict, description="Action parameters.")
        output: str = Field(default="", description="Agent's proposed output text.")
        context: dict = Field(default_factory=dict, description="Session context.")

    tool_name = name or f"comply54_{compliance.__class__.__name__.lower()}"

    def run_check(action: str, params: dict | None = None,
                  output: str = "", context: dict | None = None) -> str:
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


def compliance_node(compliance: SectorCompliance):
    """
    Build a LangGraph state-graph node that enforces compliance.

    The node reads `action`, `params`, `output`, and `context` from the
    agent state dict and writes back:
      - compliance_result:  ComplianceResult as dict
      - compliance_blocked: bool
      - compliance_message: primary violation message (empty string if passed)

    Args:
        compliance: A SectorCompliance instance.

    Returns:
        Callable suitable for graph.add_node()
    """
    def _node(state: dict[str, Any]) -> dict[str, Any]:
        result = compliance.check(
            action=state.get("action", ""),
            params=state.get("params", {}),
            output=state.get("output", ""),
            context=state.get("context", {}),
        )
        violation = result.primary_violation
        state["compliance_result"] = _result_to_dict(result)
        state["compliance_blocked"] = result.blocked
        state["compliance_message"] = violation.messages[0] if violation and violation.messages else ""
        return state

    return _node


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
