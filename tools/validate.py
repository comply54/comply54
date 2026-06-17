#!/usr/bin/env python3
"""
Comply54 policy validator.

Usage:
    python tools/validate.py                     # validate all packs
    python tools/validate.py packages/nigeria/ndpa  # validate one pack
"""

import sys
import json
import pathlib
import argparse

try:
    import yaml
    import jsonschema
except ImportError:
    print("Missing deps: pip install pyyaml jsonschema", file=sys.stderr)
    sys.exit(1)

ROOT = pathlib.Path(__file__).parent.parent
SCHEMA_PATH = ROOT / "schema" / "policy.schema.json"
PACKAGES_PATH = ROOT / "packages"


def load_schema() -> dict:
    with SCHEMA_PATH.open() as f:
        return json.load(f)


def validate_pack(pack_dir: pathlib.Path, schema: dict) -> list[str]:
    """Return list of error strings; empty = pass."""
    errors = []
    pack_dir = pathlib.Path(pack_dir)

    policy_yaml = pack_dir / "policy.yaml"
    if not policy_yaml.exists():
        errors.append(f"{pack_dir}: missing policy.yaml")
        return errors

    meta_json = pack_dir / "meta.json"
    if not meta_json.exists():
        errors.append(f"{pack_dir}: missing meta.json")

    try:
        with policy_yaml.open() as f:
            doc = yaml.safe_load(f)
        jsonschema.validate(doc, schema)
    except yaml.YAMLError as e:
        errors.append(f"{policy_yaml}: YAML parse error — {e}")
    except jsonschema.ValidationError as e:
        errors.append(f"{policy_yaml}: schema violation — {e.message} at {list(e.path)}")

    if meta_json.exists():
        try:
            with meta_json.open() as f:
                meta = json.load(f)
            required_keys = {"id", "version", "jurisdiction", "regulation", "enforcing_authority", "agt_compatible"}
            missing = required_keys - set(meta.keys())
            if missing:
                errors.append(f"{meta_json}: missing required keys: {missing}")
        except json.JSONDecodeError as e:
            errors.append(f"{meta_json}: JSON parse error — {e}")

    return errors


def discover_packs() -> list[pathlib.Path]:
    """Find all directories containing a policy.yaml."""
    return sorted(p.parent for p in PACKAGES_PATH.rglob("policy.yaml"))


def main():
    parser = argparse.ArgumentParser(description="Comply54 policy schema validator")
    parser.add_argument("pack", nargs="?", help="Path to a specific pack directory")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    schema = load_schema()

    if args.pack:
        packs = [pathlib.Path(args.pack)]
    else:
        packs = discover_packs()

    if not packs:
        print("No policy packs found.", file=sys.stderr)
        sys.exit(1)

    results = []
    total_pass = 0
    total_fail = 0

    for pack in packs:
        errors = validate_pack(pack, schema)
        name = str(pack.relative_to(ROOT))
        if errors:
            total_fail += 1
            results.append({"pack": name, "status": "FAIL", "errors": errors})
        else:
            total_pass += 1
            results.append({"pack": name, "status": "PASS", "errors": []})

    if args.json:
        print(json.dumps({"pass": total_pass, "fail": total_fail, "results": results}, indent=2))
    else:
        for r in results:
            status = "✓" if r["status"] == "PASS" else "✗"
            print(f"  {status}  {r['pack']}")
            for e in r["errors"]:
                print(f"       {e}")

        print(f"\n{total_pass} passed, {total_fail} failed")

    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
