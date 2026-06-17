"""
Comply54 → Microsoft AutoGen adapter.

Registers comply54 compliance checks as AutoGen function tools
for use in AssistantAgent / GroupChat workflows.

Requires: pip install pyautogen pyyaml
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from typing import Annotated


def _opa_eval(pack_path: pathlib.Path, action: str, output: str, context: dict) -> dict:
    rego_path = pack_path / "policy.rego"
    if not rego_path.exists():
        return {"action": "allow", "message": "No Rego policy — pass-through"}

    payload = {"action": action, "output": output, "context": context}
    result = subprocess.run(
        ["opa", "eval", "-d", str(rego_path.parent), "-I",
         "--format", "raw", "data.comply54.decision"],
        input=json.dumps(payload),
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return {"action": "error", "message": result.stderr.strip()}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"action": "error", "message": "OPA returned non-JSON"}


def register_compliance_tools(agent, pack_paths: list[str | pathlib.Path]) -> None:
    """
    Register comply54 compliance check functions on an AutoGen ConversableAgent.

    Args:
        agent: An autogen.ConversableAgent or AssistantAgent instance.
        pack_paths: List of comply54 pack directories to register.

    Example:
        from autogen import AssistantAgent
        from adapters.autogen.adapter import register_compliance_tools

        assistant = AssistantAgent("assistant", llm_config=llm_config)
        register_compliance_tools(assistant, ["packages/nigeria/ndpa", "packages/universal/pii-leakage"])
    """
    for path in pack_paths:
        pack_path = pathlib.Path(path)
        pack_name = pack_path.name

        def make_checker(p):
            def check_compliance(
                action: Annotated[str, "The action the agent intends to perform"],
                output: Annotated[str, "The agent's proposed output text"] = "",
                context: Annotated[str, "JSON-encoded context dict"] = "{}",
            ) -> str:
                ctx = json.loads(context) if context else {}
                decision = _opa_eval(p, action, output, ctx)
                return json.dumps(decision)
            check_compliance.__name__ = f"comply54_check_{p.name.replace('-', '_')}"
            check_compliance.__doc__ = f"Comply54 policy check for {p.name}"
            return check_compliance

        agent.register_for_llm(
            name=f"comply54_check_{pack_name.replace('-', '_')}",
            description=f"Check compliance against comply54 pack: {pack_name}",
        )(make_checker(pack_path))


def check_all_packs(
    jurisdiction: str,
    action: str,
    output: str = "",
    context: dict | None = None,
    registry_path: str | pathlib.Path | None = None,
) -> dict:
    """
    Evaluate all packs for a jurisdiction + universal in a single call.

    Returns:
        {
            "overall": "allow" | "block" | "deny" | "audit",
            "results": [{"pack": str, "action": str, "message": str}]
        }
    """
    if registry_path is None:
        registry_path = pathlib.Path(__file__).parent.parent.parent / "registry.json"

    with pathlib.Path(registry_path).open() as f:
        registry = json.load(f)

    jmap = registry.get("jurisdiction_map", {})
    pack_ids = set(jmap.get(jurisdiction, [])) | set(jmap.get("universal", []))
    root = pathlib.Path(registry_path).parent
    packs_by_id = {p["id"]: p["path"] for p in registry["packs"]}

    results = []
    overall = "allow"
    severity = {"allow": 0, "audit": 1, "block": 2, "deny": 3}

    for pack_id in pack_ids:
        if pack_id in packs_by_id:
            pack_path = root / packs_by_id[pack_id]
            decision = _opa_eval(pack_path, action, output, context or {})
            results.append({"pack": pack_id, **decision})
            if severity.get(decision.get("action", "allow"), 0) > severity.get(overall, 0):
                overall = decision.get("action", "allow")

    return {"overall": overall, "results": results}
