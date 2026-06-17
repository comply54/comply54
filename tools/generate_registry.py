#!/usr/bin/env python3
"""
Comply54 registry generator.

Scans packages/ for NEW local packs and merges them into registry.json,
preserving existing entries (including remote agt-policies-nigeria packs).

Usage:
    python tools/generate_registry.py           # merge local packs into registry
    python tools/generate_registry.py --dry-run # print result without writing
"""

import sys
import json
import pathlib
import argparse
from datetime import date

ROOT = pathlib.Path(__file__).parent.parent
PACKAGES_PATH = ROOT / "packages"
REGISTRY_PATH = ROOT / "registry.json"


def build_entry_from_local(pack_dir: pathlib.Path) -> dict | None:
    """Build a registry entry from a local packages/<j>/<slug>/ directory."""
    meta_path = pack_dir / "meta.json"
    if not meta_path.exists():
        print(f"WARNING: {pack_dir} has no meta.json — skipping", file=sys.stderr)
        return None

    try:
        with meta_path.open() as f:
            meta = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: {meta_path}: {e}", file=sys.stderr)
        return None

    rel_path = str(pack_dir.relative_to(ROOT))
    return {
        "id": meta["id"],
        "source_repo": None,
        "source_yaml": None,
        "source_rego": None,
        "path": rel_path,
        "jurisdiction": meta.get("jurisdiction", "unknown"),
        "regulation": meta.get("regulation", ""),
        "short_name": meta.get("short_name", ""),
        "version": meta.get("version", "0.0.0"),
        "enforcing_authority": meta.get("enforcing_authority", ""),
        "effective_date": meta.get("effective_date", ""),
        "regulatory_source": meta.get("regulatory_source", ""),
        "tags": meta.get("tags", []),
        "agt_compatible": meta.get("agt_compatible", False),
        "rego_tests": meta.get("rego_tests", 0),
    }


def build_jurisdiction_map(packs: list[dict]) -> dict:
    jmap: dict[str, list[str]] = {}
    for pack in packs:
        jur = pack.get("jurisdiction", "universal")
        jmap.setdefault(jur, []).append(pack["id"])
    return jmap


def main():
    parser = argparse.ArgumentParser(
        description="Merge local packs into registry.json (preserves remote entries)"
    )
    parser.add_argument("--dry-run", action="store_true", help="Print result without writing")
    args = parser.parse_args()

    # Load existing registry
    existing: dict = {}
    if REGISTRY_PATH.exists():
        with REGISTRY_PATH.open() as f:
            reg = json.load(f)
        existing = {p["id"]: p for p in reg.get("packs", [])}

    # Discover local packs
    local_meta_files = sorted(PACKAGES_PATH.rglob("meta.json"))
    new_entries = []
    for meta_path in local_meta_files:
        entry = build_entry_from_local(meta_path.parent)
        if entry and entry["id"] not in existing:
            new_entries.append(entry)
            print(f"  + adding local pack: {entry['id']}")

    if not new_entries and existing:
        print("No new local packs found — registry.json is up to date.")
        return

    # Merge: existing first, then new local packs
    all_packs = list(existing.values()) + new_entries

    registry = {
        "$schema": "https://comply54.io/schema/registry.schema.json",
        "version": reg.get("version", "1.0.0") if REGISTRY_PATH.exists() else "1.0.0",
        "last_updated": str(date.today()),
        "total_packs": len(all_packs),
        "packs": all_packs,
        "jurisdiction_map": build_jurisdiction_map(all_packs),
    }

    output = json.dumps(registry, indent=2) + "\n"

    if args.dry_run:
        print(output)
    else:
        REGISTRY_PATH.write_text(output)
        print(f"registry.json updated — {len(all_packs)} total packs "
              f"({len(existing)} existing + {len(new_entries)} new)")


if __name__ == "__main__":
    main()
