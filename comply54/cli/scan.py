"""Governance scan command implementation."""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from typing import Any

from ..core.engine import Comply54Engine
from ..core.models import ComplianceResult
from ..core.packs import PACK_REGISTRY, packs_for_ids


_EXIT_CODES = {"allow": 0, "audit": 0, "deny": 1, "escalate": 2}


def _json_object(value: str, option: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{option} must be valid JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{option} must be a JSON object")
    return parsed


def _load_input(args) -> tuple[list[str], list[dict[str, Any]]]:
    import yaml

    if args.config:
        if args.action or args.packs:
            raise ValueError("--config cannot be combined with --action or --pack")
        try:
            data = yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {}
        except OSError as exc:
            raise ValueError(f"cannot read config: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid YAML config: {exc}") from exc
        packs = data.get("packs", [])
        scenarios = data.get("scenarios", [])
        if not isinstance(packs, list) or not isinstance(scenarios, list) or not scenarios:
            raise ValueError("config requires non-empty 'scenarios' and a list of 'packs'")
        return packs, scenarios

    if not args.action:
        raise ValueError("--action is required unless --config is used")
    if not args.packs:
        raise ValueError("at least one --pack is required")
    return args.packs, [
        {
            "action": args.action,
            "params": _json_object(args.params, "--params"),
            "context": _json_object(args.context, "--context"),
            "output": args.output,
        }
    ]


def _validate_packs(pack_ids: list[str]) -> None:
    unknown = [pack_id for pack_id in pack_ids if pack_id not in PACK_REGISTRY]
    if unknown:
        raise ValueError(f"unknown policy pack(s): {', '.join(unknown)}")


def _evaluate(pack_ids: list[str], scenario: dict[str, Any]) -> ComplianceResult:
    action = scenario.get("action")
    if not isinstance(action, str) or not action:
        raise ValueError("each scenario requires a non-empty 'action'")
    params = scenario.get("params", {})
    context = scenario.get("context", {})
    output = scenario.get("output", "")
    if not isinstance(params, dict) or not isinstance(context, dict) or not isinstance(output, str):
        raise ValueError("scenario params/context must be objects and output must be a string")
    return Comply54Engine(packs_for_ids(pack_ids)).check(
        action=action,
        params=params,
        context=context,
        output=output,
    )


def _report_data(
    scenarios: list[dict[str, Any]], results: list[ComplianceResult]
) -> dict[str, Any]:
    items = []
    for scenario, result in zip(scenarios, results):
        items.append(
            {
                "action": scenario["action"],
                "params": scenario.get("params", {}),
                "context": scenario.get("context", {}),
                "result": result.model_dump(mode="json"),
            }
        )
    return {"scenario_count": len(items), "scenarios": items}


def _render_table(scenarios: list[dict[str, Any]], results: list[ComplianceResult]) -> None:
    from rich.console import Console
    from rich.table import Table

    table = Table(title="comply54 governance scan")
    table.add_column("#", justify="right")
    table.add_column("Action")
    table.add_column("Decision")
    table.add_column("Violations", justify="right")
    table.add_column("Audit ID")
    styles = {"allow": "green", "audit": "cyan", "escalate": "yellow", "deny": "bold red"}
    for index, (scenario, result) in enumerate(zip(scenarios, results), start=1):
        table.add_row(
            str(index),
            scenario["action"],
            f"[{styles[result.overall]}]{result.overall.upper()}[/]",
            str(len(result.violations)),
            result.audit_id,
        )
    Console().print(table)


def _render_html(data: dict[str, Any]) -> str:
    rows = []
    for item in data["scenarios"]:
        result = item["result"]
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['action'])}</td>"
            f'<td class="{result["overall"]}">{html.escape(result["overall"].upper())}</td>'
            f"<td>{len([d for d in result['decisions'] if d['action'] != 'allow'])}</td>"
            f"<td>{html.escape(result['audit_id'])}</td>"
            "</tr>"
        )
    return (
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>comply54 governance report</title>
<style>body{font-family:system-ui;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:.6rem;text-align:left}.allow{color:#15803d}.audit{color:#0369a1}.escalate{color:#a16207}.deny{color:#b91c1c;font-weight:700}</style>
</head><body><h1>comply54 governance report</h1><table><thead><tr><th>Action</th><th>Decision</th><th>Violations</th><th>Audit ID</th></tr></thead><tbody>"""
        + "".join(rows)
        + "</tbody></table></body></html>"
    )


def run_scan(args) -> int:
    try:
        import yaml  # noqa: F401
        import rich  # noqa: F401
    except ImportError:
        print(
            "error: CLI dependencies not installed. Run: pip install comply54[cli]",
            file=sys.stderr,
        )
        return 2

    try:
        pack_ids, scenarios = _load_input(args)
        _validate_packs(pack_ids)
        results = [_evaluate(pack_ids, scenario) for scenario in scenarios]
    except (TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    data = _report_data(scenarios, results)
    if args.format == "json":
        print(json.dumps(data, indent=2))
    elif args.format == "html":
        report = _render_html(data)
        if args.report:
            Path(args.report).write_text(report, encoding="utf-8")
        else:
            print(report)
    else:
        _render_table(scenarios, results)

    return max((_EXIT_CODES[result.overall] for result in results), default=0)
