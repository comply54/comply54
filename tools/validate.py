#!/usr/bin/env python3
"""
Comply54 policy validator.

Validates policy.yaml files (local or remote) against schema/policy.schema.json.

Usage:
    python tools/validate.py                      # validate all packs in registry.json
    python tools/validate.py packages/ghana/gdpa  # validate a local pack
    python tools/validate.py --local-only         # skip remote packs (offline)
"""

import sys
import json
import pathlib
import argparse
import urllib.request

try:
    import yaml
    import jsonschema
except ImportError:
    print("Missing deps: pip install pyyaml jsonschema", file=sys.stderr)
    sys.exit(1)

ROOT = pathlib.Path(__file__).parent.parent
SCHEMA_PATH = ROOT / "schema" / "policy.schema.json"
REGISTRY_PATH = ROOT / "registry.json"


def load_schema() -> dict:
    with SCHEMA_PATH.open() as f:
        return json.load(f)


def fetch_yaml(source: str) -> dict:
    """Load YAML from a local path or https:// URL."""
    if source.startswith("https://") or source.startswith("http://"):
        with urllib.request.urlopen(source, timeout=10) as resp:
            return yaml.safe_load(resp.read().decode())
    else:
        with pathlib.Path(source).open() as f:
            return yaml.safe_load(f)


def validate_entry(entry: dict, schema: dict) -> list[str]:
    """Validate one registry entry. Returns list of error strings."""
    errors = []
    pack_id = entry.get("id", "unknown")

    if entry.get("path"):
        source = str(ROOT / entry["path"] / "policy.yaml")
        label = f"local:{entry['path']}"
    elif entry.get("source_yaml"):
        source = entry["source_yaml"]
        label = f"remote:{entry.get('source_repo', '?')}"
    else:
        errors.append(f"{pack_id}: no 'path' or 'source_yaml' in registry entry")
        return errors

    try:
        doc = fetch_yaml(source)
        jsonschema.validate(doc, schema)
    except urllib.error.URLError as e:
        errors.append(f"{pack_id} ({label}): network error — {e}")
    except yaml.YAMLError as e:
        errors.append(f"{pack_id} ({label}): YAML parse error — {e}")
    except jsonschema.ValidationError as e:
        errors.append(f"{pack_id} ({label}): schema violation — {e.message} at {list(e.path)}")

    return errors


def validate_local_pack(pack_dir: pathlib.Path, schema: dict) -> list[str]:
    """Validate a local pack directory directly (without registry.json)."""
    errors = []
    policy_yaml = pack_dir / "policy.yaml"

    if not policy_yaml.exists():
        return [f"{pack_dir}: missing policy.yaml"]

    if not (pack_dir / "meta.json").exists():
        errors.append(f"{pack_dir}: missing meta.json")

    try:
        with policy_yaml.open() as f:
            doc = yaml.safe_load(f)
        jsonschema.validate(doc, schema)
    except yaml.YAMLError as e:
        errors.append(f"{policy_yaml}: YAML parse error — {e}")
    except jsonschema.ValidationError as e:
        errors.append(f"{policy_yaml}: schema violation — {e.message} at {list(e.path)}")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Comply54 policy schema validator")
    parser.add_argument("pack", nargs="?", help="Path to a local pack directory")
    parser.add_argument("--local-only", action="store_true",
                        help="Skip remote packs (useful for offline / CI without network)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    schema = load_schema()
    results = []
    total_pass = 0
    total_fail = 0

    if args.pack:
        errors = validate_local_pack(pathlib.Path(args.pack), schema)
        name = args.pack
        if errors:
            total_fail += 1
            results.append({"pack": name, "status": "FAIL", "errors": errors})
        else:
            total_pass += 1
            results.append({"pack": name, "status": "PASS", "errors": []})
    else:
        with REGISTRY_PATH.open() as f:
            registry = json.load(f)

        for entry in registry.get("packs", []):
            is_remote = entry.get("source_yaml") and not entry.get("path")
            if is_remote and args.local_only:
                results.append({"pack": entry["id"], "status": "SKIP", "errors": []})
                continue

            errors = validate_entry(entry, schema)
            if errors:
                total_fail += 1
                results.append({"pack": entry["id"], "status": "FAIL", "errors": errors})
            else:
                total_pass += 1
                results.append({"pack": entry["id"], "status": "PASS", "errors": []})

    if args.json:
        print(json.dumps({"pass": total_pass, "fail": total_fail, "results": results}, indent=2))
    else:
        for r in results:
            symbol = {"PASS": "✓", "FAIL": "✗", "SKIP": "–"}.get(r["status"], "?")
            print(f"  {symbol}  {r['pack']}")
            for e in r["errors"]:
                print(f"       {e}")

        skipped = sum(1 for r in results if r["status"] == "SKIP")
        print(f"\n{total_pass} passed, {total_fail} failed" +
              (f", {skipped} skipped (--local-only)" if skipped else ""))

    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
