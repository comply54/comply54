"""
Comply54 → Microsoft Agent-OS (AGT) adapter.

Loads a comply54 policy.yaml and returns an agent_os PolicyDocument.
Requires: pip install agent-os pyyaml
"""

from __future__ import annotations

import pathlib
import yaml


def load_policy(pack_path: str | pathlib.Path):
    """
    Load a comply54 policy pack into an AGT PolicyDocument.

    Args:
        pack_path: Path to a comply54 pack directory (e.g. packages/nigeria/ndpa)
                   or directly to a policy.yaml file.

    Returns:
        agent_os.policies.schema.PolicyDocument

    Example:
        from adapters.agt.adapter import load_policy
        policy = load_policy("packages/nigeria/ndpa")
        result = policy.evaluate({"action": "export_data", "output": ""})
    """
    try:
        from agent_os.policies.schema import PolicyDocument
    except ImportError as e:
        raise ImportError(
            "agent-os is not installed. Install with: pip install agent-os"
        ) from e

    pack_path = pathlib.Path(pack_path)
    if pack_path.is_dir():
        pack_path = pack_path / "policy.yaml"

    with pack_path.open() as f:
        raw = yaml.safe_load(f)

    return PolicyDocument.model_validate(raw)


def load_jurisdiction(jurisdiction: str, registry_path: str | pathlib.Path | None = None):
    """
    Load all comply54 packs for a given jurisdiction + universal packs.

    Args:
        jurisdiction: ISO 3166-1 alpha-2 country code (e.g. 'NG', 'KE', 'ZA')
        registry_path: Path to registry.json. Defaults to repo root.

    Returns:
        list[agent_os.policies.schema.PolicyDocument]
    """
    import json

    if registry_path is None:
        registry_path = pathlib.Path(__file__).parent.parent.parent / "registry.json"

    with pathlib.Path(registry_path).open() as f:
        registry = json.load(f)

    jmap = registry.get("jurisdiction_map", {})
    pack_ids = set(jmap.get(jurisdiction, [])) | set(jmap.get("universal", []))

    root = pathlib.Path(registry_path).parent
    packs_by_id = {p["id"]: p["path"] for p in registry["packs"]}

    policies = []
    for pack_id in pack_ids:
        if pack_id in packs_by_id:
            policies.append(load_policy(root / packs_by_id[pack_id]))

    return policies
