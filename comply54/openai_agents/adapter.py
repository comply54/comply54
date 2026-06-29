"""
comply54.openai_agents
~~~~~~~~~~~~~~~~~~~~~~
OpenAI Agents SDK integration for comply54.

Wraps comply54's policy evaluation behind the @tool_input_guardrail
decorator so any OpenAI Agents SDK function_tool can be guarded with
pre-execution Nigerian (or African) regulatory compliance checks.

Usage:
    from comply54.sectors import NigeriaFintechCompliance
    from comply54.openai_agents import make_tool_input_guardrail
    from agents import Agent, function_tool

    compliance = NigeriaFintechCompliance()
    guardrail = make_tool_input_guardrail(
        compliance,
        context={"kyc_tier": 3, "customer_verified": True},
    )

    @function_tool
    def transfer_funds(amount: float, recipient_account: str) -> str:
        ...

    transfer_funds.tool_input_guardrails = [guardrail]

    agent = Agent(
        name="Fintech Agent",
        tools=[transfer_funds],
    )
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .._base import SectorCompliance


def make_tool_input_guardrail(
    compliance: "SectorCompliance",
    context: dict[str, Any] | None = None,
):
    """
    Return an OpenAI Agents SDK @tool_input_guardrail backed by comply54.

    The guardrail intercepts every tool call before execution, evaluates it
    against the compliance pack, and rejects blocked calls with a structured
    regulatory message. The model receives the rejection and can explain to
    the user why the action was prevented.

    Args:
        compliance: A comply54 SectorCompliance instance
                    (e.g. NigeriaFintechCompliance, PanAfricanFintechCompliance).
        context:    Static session context passed to every evaluation.
                    Typical keys: ``kyc_tier``, ``customer_verified``.

    Returns:
        A guardrail function ready to attach to any function_tool via
        ``tool.tool_input_guardrails = [guardrail]``.

    Raises:
        ImportError: if ``openai-agents`` is not installed.
    """
    try:
        from agents import (
            ToolGuardrailFunctionOutput,
            ToolInputGuardrailData,
            tool_input_guardrail,
        )
    except ImportError as exc:
        raise ImportError(
            "openai-agents is required. Install with: pip install openai-agents"
        ) from exc

    _context = context or {}

    @tool_input_guardrail
    def _comply54_guardrail(
        data: ToolInputGuardrailData,
    ) -> ToolGuardrailFunctionOutput:
        try:
            params = (
                json.loads(data.context.tool_arguments)
                if data.context.tool_arguments
                else {}
            )
        except (json.JSONDecodeError, TypeError):
            params = {}

        result = compliance.check(
            action=data.context.tool_name,
            params=params,
            context=_context,
        )

        if result.blocked:
            primary = result.primary_violation
            regulation = primary.regulation if primary else "Compliance policy"
            message = (
                primary.messages[0]
                if primary and primary.messages
                else "Action blocked by compliance policy"
            )

            return ToolGuardrailFunctionOutput.reject_content(
                message=f"[comply54] {regulation}: {message}",
                output_info={
                    "blocked": True,
                    "overall": result.overall,
                    "regulation": regulation,
                    "rule_triggered": getattr(primary, "rule_triggered", None),
                    "violations": [
                        {
                            "pack": v.pack,
                            "regulation": v.regulation,
                            "messages": v.messages,
                            "rule_triggered": getattr(v, "rule_triggered", None),
                        }
                        for v in result.violations
                    ],
                },
            )

        return ToolGuardrailFunctionOutput(
            output_info={"blocked": False, "overall": result.overall}
        )

    return _comply54_guardrail
