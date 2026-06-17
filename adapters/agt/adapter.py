"""
Comply54 → Microsoft Agent-OS (AGT) adapter.

Loads comply54 policy packs (from local path or remote URL) into
agent_os PolicyDocument objects.

Requires: pip install agent-os pyyaml
"""

from __future__ import annotations

import json
import pathlib
import urllib.request

import yaml


def _fetch_yaml(source: str | pathlib.Path) -> dict:
    """Load YAML from a local path or https:// URL."""
    if isinstance(source, str) and (source.startswith("https://") or source.startswith("http://")):
        with urllib.request.urlopen(source, timeout=15) as resp:
            return yaml.safe_load(resp.read().decode())
    with pathlib.Path(source).open() as f:
        return yaml.safe_load(f)


def load_policy(source: str | pathlib.Path):
    """
    Load a policy into an AGT PolicyDocument.

    Args:
        source: One of:
            - Path to a comply54 pack directory  (e.g. "packages/ghana/gdpa")
            - Path to a policy.yaml file
            - https:// URL to a raw YAML file

    Returns:
        agent_os.policies.schema.PolicyDocument

    Example:
        from adapters.agt.adapter import load_policy

        # From agt-policies-nigeria (remote)
        policy = load_policy(
            "https://raw.githubusercontent.com/kingztech2019/"
            "agt-policies-nigeria/main/policies/ndpa-data-residency.yaml"
        )

        # From a local future pack
        policy = load_policy("packages/ghana/gdpa")
    """
    try:
        from agent_os.policies.schema import PolicyDocument
    except ImportError as e:
        raise ImportError(
            "agent-os is not installed. Install with: pip install agent-os"
        ) from e

    source = pathlib.Path(source) if not isinstance(source, str) or not source.startswith("http") else source

    if isinstance(source, pathlib.Path) and source.is_dir():
        source = source / "policy.yaml"

    raw = _fetch_yaml(source)
    return PolicyDocument.model_validate(raw)


def load_jurisdiction(jurisdiction: str, registry_path: str | pathlib.Path | None = None):
    """
    Load all comply54 policy packs for a jurisdiction + universal packs.

    Packs sourced from agt-policies-nigeria are fetched from GitHub.
    Local packs (future community contributions) are loaded from disk.

    Args:
        jurisdiction: ISO 3166-1 alpha-2 country code (e.g. 'NG', 'KE', 'ZA')
        registry_path: Path to comply54's registry.json. Defaults to repo root.

    Returns:
        list[agent_os.policies.schema.PolicyDocument]
    """
    if registry_path is None:
        registry_path = pathlib.Path(__file__).parent.parent.parent / "registry.json"

    with pathlib.Path(registry_path).open() as f:
        registry = json.load(f)

    jmap = registry.get("jurisdiction_map", {})
    pack_ids = set(jmap.get(jurisdiction, [])) | set(jmap.get("universal", []))
    packs_by_id = {p["id"]: p for p in registry["packs"]}
    root = pathlib.Path(registry_path).parent

    policies = []
    for pack_id in pack_ids:
        pack = packs_by_id.get(pack_id)
        if not pack:
            continue

        if pack.get("path"):
            source = root / pack["path"] / "policy.yaml"
        elif pack.get("source_yaml"):
            source = pack["source_yaml"]
        else:
            continue

        policies.append(load_policy(source))

    return policies
