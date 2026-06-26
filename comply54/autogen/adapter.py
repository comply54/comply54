"""
comply54.autogen.adapter
~~~~~~~~~~~~~~~~~~~~~~~~
Microsoft AutoGen integration for comply54.

Usage:
    from autogen import AssistantAgent
    from comply54.autogen import register_compliance
    from comply54 import NigeriaFintechCompliance

    assistant = AssistantAgent("assistant", llm_config=llm_config)
    register_compliance(assistant, NigeriaFintechCompliance())
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from ..sectors._base import SectorCompliance


def register_compliance(agent: Any, compliance: SectorCompliance) -> None:
    """
    Register a comply54 SectorCompliance pack as a callable function tool on an AutoGen agent.

    Args:
        agent:      An autogen ConversableAgent or AssistantAgent.
        compliance: A SectorCompliance instance.
    """
    def check_compliance(
        action: Annotated[str, "The agent action or tool name to evaluate."],
        params: Annotated[str, "JSON-encoded parameters dict."] = "{}",
        output: Annotated[str, "The agent's proposed output text."] = "",
        context: Annotated[str, "JSON-encoded session context dict."] = "{}",
    ) -> str:
        result = compliance.check(
            action=action,
            params=json.loads(params) if params else {},
            output=output,
            context=json.loads(context) if context else {},
        )
        return json.dumps({
            "overall": result.overall,
            "blocked": result.blocked,
            "violations": [
                {"pack": d.pack, "action": d.action, "messages": d.messages}
                for d in result.violations
            ],
        })

    fn_name = f"comply54_{compliance.__class__.__name__.lower()}"
    check_compliance.__name__ = fn_name
    check_compliance.__doc__ = (
        f"comply54 compliance check: {compliance.name}. "
        f"Jurisdictions: {', '.join(compliance.jurisdictions)}. "
        "Returns JSON with overall decision and violations."
    )

    try:
        agent.register_for_llm(
            name=fn_name,
            description=check_compliance.__doc__,
        )(check_compliance)
    except AttributeError as e:
        raise ImportError(
            "pyautogen is required. Install with: pip install comply54[autogen]"
        ) from e
