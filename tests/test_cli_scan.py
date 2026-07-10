import json

import pytest

from comply54.cli import build_parser
from comply54.cli import scan
from comply54.core.models import ComplianceResult, PolicyDecision


def _result(action="allow"):
    return ComplianceResult(
        overall=action,
        audit_id="audit-test",
        decisions=[
            PolicyDecision(
                pack="nigeria/cbn",
                regulation="CBN",
                jurisdiction="NG",
                action=action,
            )
        ],
    )


@pytest.mark.parametrize(
    "decision,expected", [("allow", 0), ("audit", 0), ("deny", 1), ("escalate", 2)]
)
def test_scan_exit_codes(monkeypatch, capsys, decision, expected):
    monkeypatch.setattr(scan, "_evaluate", lambda packs, scenario: _result(decision))
    args = build_parser().parse_args(["scan", "--action", "read", "--pack", "nigeria/cbn"])

    assert scan.run_scan(args) == expected
    assert decision.upper() in capsys.readouterr().out


def test_scan_json_is_machine_readable(monkeypatch, capsys):
    monkeypatch.setattr(scan, "_evaluate", lambda packs, scenario: _result())
    args = build_parser().parse_args(
        [
            "scan",
            "--action",
            "read",
            "--params",
            '{"record": 1}',
            "--pack",
            "nigeria/cbn",
            "--format",
            "json",
        ]
    )

    assert scan.run_scan(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["scenario_count"] == 1
    assert payload["scenarios"][0]["result"]["overall"] == "allow"
    assert payload["scenarios"][0]["result"]["decisions"][0]["pack"] == "nigeria/cbn"


def test_scan_loads_multiple_yaml_scenarios(monkeypatch, tmp_path, capsys):
    config = tmp_path / "scan.yaml"
    config.write_text(
        "packs:\n  - nigeria/cbn\nscenarios:\n  - action: first\n    params: {}\n  - action: second\n    context: {}\n",
        encoding="utf-8",
    )
    seen = []
    monkeypatch.setattr(
        scan, "_evaluate", lambda packs, scenario: seen.append(scenario["action"]) or _result()
    )
    args = build_parser().parse_args(["scan", "--config", str(config), "--format", "json"])

    assert scan.run_scan(args) == 0
    assert seen == ["first", "second"]
    assert json.loads(capsys.readouterr().out)["scenario_count"] == 2


def test_scan_writes_standalone_html(monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_evaluate", lambda packs, scenario: _result("deny"))
    report = tmp_path / "report.html"
    args = build_parser().parse_args(
        [
            "scan",
            "--action",
            "transfer_funds",
            "--pack",
            "nigeria/cbn",
            "--format",
            "html",
            "--report",
            str(report),
        ]
    )

    assert scan.run_scan(args) == 1
    content = report.read_text(encoding="utf-8")
    assert content.startswith("<!doctype html>")
    assert "transfer_funds" in content
    assert "DENY" in content


def test_scan_rejects_invalid_json(capsys):
    args = build_parser().parse_args(
        ["scan", "--action", "read", "--params", "[1]", "--pack", "nigeria/cbn"]
    )

    assert scan.run_scan(args) == 2
    assert "--params must be a JSON object" in capsys.readouterr().err
