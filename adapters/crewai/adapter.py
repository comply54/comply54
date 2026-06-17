"""
Comply54 → CrewAI adapter.

Provides an OPA-based compliance BaseTool for CrewAI agents.

Requires: pip install crewai pyyaml
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from typing import Any

try:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field
except ImportError:
    BaseTool = object  # stub so module can be imported without crewai installed

    class BaseModel:  # type: ignore[no-redef]
        pass

    def Field(*args, **kwargs):  # type: ignore[no-redef]
        return None


class ComplianceCheckInput(BaseModel):
    action: str = Field(description="The action the agent intends to perform")
    output: str = Field(default="", description="The agent's proposed output text")
    context: dict = Field(default_factory=dict, description="Additional context")


class Comply54Tool(BaseTool):
    """
    A CrewAI tool that evaluates one comply54 policy pack via OPA.

    Usage:
        from adapters.crewai.adapter import Comply54Tool
        tool = Comply54Tool(pack_path="packages/nigeria/ndpa")
        agent = Agent(tools=[tool], ...)
    """

    name: str = "comply54_policy_check"
    description: str = "Check agent action and output against a comply54 compliance policy"
    pack_path: str = ""

    model_config = {"arbitrary_types_allowed": True}

    def _run(self, action: str, output: str = "", context: dict | None = None) -> str:
        rego_path = pathlib.Path(self.pack_path) / "policy.rego"
        payload = {"action": action, "output": output, "context": context or {}}

        if not rego_path.exists():
            return json.dumps({"action": "allow", "message": "No Rego policy — pass-through"})

        result = subprocess.run(
            ["opa", "eval", "-d", str(rego_path.parent), "-I",
             "--format", "raw", "data.comply54.decision"],
            input=json.dumps(payload),
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            return json.dumps({"action": "error", "message": result.stderr.strip()})
        try:
            decision = json.loads(result.stdout)
            return json.dumps(decision)
        except json.JSONDecodeError:
            return json.dumps({"action": "error", "message": "OPA returned non-JSON"})


def build_tools_for_jurisdiction(jurisdiction: str,
                                  registry_path: str | pathlib.Path | None = None) -> list:
    """
    Build a list of Comply54Tools covering all packs for a jurisdiction + universal.

    Args:
        jurisdiction: ISO 3166-1 alpha-2 country code (e.g. 'NG')
        registry_path: Path to registry.json. Defaults to repo root.

    Returns:
        list[Comply54Tool]
    """
    if registry_path is None:
        registry_path = pathlib.Path(__file__).parent.parent.parent / "registry.json"

    with pathlib.Path(registry_path).open() as f:
        registry = json.load(f)

    jmap = registry.get("jurisdiction_map", {})
    pack_ids = set(jmap.get(jurisdiction, [])) | set(jmap.get("universal", []))
    root = pathlib.Path(registry_path).parent
    packs_by_id = {p["id"]: p for p in registry["packs"]}

    tools = []
    for pack_id in pack_ids:
        if pack_id in packs_by_id:
            pack = packs_by_id[pack_id]
            tools.append(Comply54Tool(
                name=f"comply54_{pack['id'].replace('-', '_')}",
                description=f"Comply54: {pack['regulation']}",
                pack_path=str(root / pack["path"]),
            ))
    return tools
