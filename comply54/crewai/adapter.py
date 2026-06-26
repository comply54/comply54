"""
comply54.crewai.adapter
~~~~~~~~~~~~~~~~~~~~~~~
CrewAI integration for comply54.

Usage:
    from comply54.crewai import Comply54CrewTool
    from comply54 import NigeriaFintechCompliance

    tool = Comply54CrewTool(compliance=NigeriaFintechCompliance())
    agent = Agent(role="Compliance Agent", tools=[tool], ...)
"""

from __future__ import annotations

import json
from typing import Any, Type

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


class _ComplianceInput(BaseModel):
    action: str = Field(description="Agent action or tool name to evaluate.")
    params: dict = Field(default_factory=dict, description="Action parameters.")
    output: str = Field(default="", description="Agent's proposed output text.")
    context: dict = Field(default_factory=dict, description="Session context.")


class Comply54CrewTool(BaseTool):
    """
    A CrewAI BaseTool that enforces a comply54 SectorCompliance pack.

    Args:
        compliance: A SectorCompliance instance (NigeriaFintechCompliance, etc.)
    """

    name: str = "comply54_compliance_check"
    description: str = (
        "Check whether an agent action complies with applicable African regulatory requirements. "
        "Returns a JSON decision object with overall outcome and any violation details."
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
                f"Jurisdictions: {', '.join(compliance.jurisdictions)}."
            ),
            **kwargs,
        )

    def _run(self, action: str, params: dict | None = None,
             output: str = "", context: dict | None = None) -> str:
        result = self.compliance.check(
            action=action, params=params or {}, output=output, context=context or {}
        )
        return json.dumps({
            "overall": result.overall,
            "blocked": result.blocked,
            "violations": [
                {"pack": d.pack, "action": d.action, "messages": d.messages}
                for d in result.violations
            ],
        })
