#!/usr/bin/env python3
"""
Comply54 registry generator.

Reads every packages/**/meta.json and writes registry.json at the repo root.

Usage:
    python tools/generate_registry.py
    python tools/generate_registry.py --dry-run
"""

import sys
import json
import pathlib
import argparse

ROOT = pathlib.Path(__file__).parent.parent
PACKAGES_PATH = ROOT / "packages"
REGISTRY_PATH = ROOT / "registry.json"


def build_jurisdiction_map(packs: list[dict]) -> dict:
    jmap: dict[str, list[str]] = {}
    for pack in packs:
        jur = pack.get("jurisdiction", "universal")
        jmap.setdefault(jur, []).append(pack["id"])
    return jmap


def main():
    parser = argparse.ArgumentParser(description="Regenerate registry.json from meta.json files")
    parser.add_argument("--dry-run", action="store_true", help="Print registry without writing")
    args = parser.parse_args()

    meta_files = sorted(PACKAGES_PATH.rglob("meta.json"))
    if not meta_files:
        print("No meta.json files found under packages/", file=sys.stderr)
        sys.exit(1)

    packs = []
    for meta_path in meta_files:
        try:
            with meta_path.open() as f:
                meta = json.load(f)
            pack_path = str(meta_path.parent.relative_to(ROOT))
            packs.append({
                "id": meta["id"],
                "path": pack_path,
                "jurisdiction": meta.get("jurisdiction", "unknown"),
                "regulation": meta.get("regulation", ""),
                "short_name": meta.get("short_name", ""),
                "version": meta.get("version", "0.0.0"),
                "enforcing_authority": meta.get("enforcing_authority", ""),
                "tags": meta.get("tags", []),
                "agt_compatible": meta.get("agt_compatible", False),
                "rego_tests": meta.get("rego_tests", 0),
            })
        except (json.JSONDecodeError, KeyError) as e:
            print(f"ERROR reading {meta_path}: {e}", file=sys.stderr)
            sys.exit(1)

    from datetime import date
    registry = {
        "$schema": "https://comply54.io/schema/registry.schema.json",
        "version": "1.0.0",
        "last_updated": str(date.today()),
        "total_packs": len(packs),
        "packs": packs,
        "jurisdiction_map": build_jurisdiction_map(packs),
    }

    output = json.dumps(registry, indent=2)

    if args.dry_run:
        print(output)
    else:
        REGISTRY_PATH.write_text(output + "\n")
        print(f"registry.json updated — {len(packs)} packs indexed")


if __name__ == "__main__":
    main()
