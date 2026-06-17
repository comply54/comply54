"""
Comply54 → LangChain adapter.

Provides a LangChain Tool and a runnable compliance check node
for use in LangGraph / LCEL pipelines.

Requires: pip install langchain langgraph pyyaml
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from typing import Any


def _opa_eval(policy_rego: pathlib.Path, input_data: dict) -> dict:
    """Evaluate a Rego policy with OPA and return the decision dict."""
    result = subprocess.run(
        ["opa", "eval", "-d", str(policy_rego.parent), "-I",
         "--format", "raw", "data.comply54.decision"],
        input=json.dumps(input_data),
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return {"action": "error", "message": result.stderr.strip()}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"action": "error", "message": "OPA returned non-JSON output"}


def build_compliance_tool(pack_path: str | pathlib.Path, name: str | None = None):
    """
    Build a LangChain StructuredTool that enforces a comply54 policy pack.

    Args:
        pack_path: Path to a comply54 pack directory.
        name: Optional tool name. Defaults to the pack directory name.

    Returns:
        langchain_core.tools.StructuredTool

    Example:
        from adapters.langchain.adapter import build_compliance_tool
        tool = build_compliance_tool("packages/nigeria/ndpa")
        result = tool.invoke({"action": "export_data", "output": "user@example.com"})
    """
    try:
        from langchain_core.tools import StructuredTool
        from pydantic import BaseModel
    except ImportError as e:
        raise ImportError(
            "langchain-core is not installed. Install with: pip install langchain-core"
        ) from e

    pack_path = pathlib.Path(pack_path)
    tool_name = name or pack_path.name
    rego_path = pack_path / "policy.rego"

    class PolicyInput(BaseModel):
        action: str = ""
        output: str = ""
        input: str = ""
        context: dict = {}

    def run_compliance_check(action: str = "", output: str = "",
                              input: str = "", context: dict | None = None) -> str:
        payload = {"action": action, "output": output,
                   "input": input, "context": context or {}}
        if rego_path.exists():
            decision = _opa_eval(rego_path, payload)
        else:
            decision = {"action": "allow", "message": "No Rego policy — pass-through"}
        return json.dumps(decision)

    return StructuredTool.from_function(
        func=run_compliance_check,
        name=f"comply54_{tool_name}",
        description=f"Comply54 policy check: {tool_name}. Returns JSON with action and message.",
        args_schema=PolicyInput,
    )


def compliance_node(pack_paths: list[str | pathlib.Path]):
    """
    Build a LangGraph node that evaluates a list of comply54 policy packs.

    The node receives the agent state dict and adds a 'compliance_results' key.

    Returns:
        callable suitable for graph.add_node()
    """
    tools = [build_compliance_tool(p) for p in pack_paths]

    def _node(state: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "action": state.get("action", ""),
            "output": state.get("output", ""),
            "input": state.get("input", ""),
            "context": state.get("context", {}),
        }
        results = [json.loads(t.invoke(payload)) for t in tools]
        blocked = [r for r in results if r.get("action") in ("deny", "block")]
        state["compliance_results"] = results
        state["compliance_blocked"] = bool(blocked)
        state["compliance_block_reason"] = blocked[0].get("message", "") if blocked else ""
        return state

    return _node
