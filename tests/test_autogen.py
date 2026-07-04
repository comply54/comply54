"""
Tests for comply54.autogen — autogen-agentchat ≥ 0.4 adapter.

Uses a lightweight mock SectorCompliance so no policy files or OPA runtime
are required.  Imports autogen_core.tools.FunctionTool directly to verify the
wrapped tool schema and behaviour.
"""

from __future__ import annotations

import asyncio
import json
import warnings
from unittest.mock import MagicMock

import pytest

pytest.importorskip("autogen_agentchat")

from comply54.autogen import (
    Comply54UserProxy,
    comply54_tool,
    comply54_tools,
    compliance_tool,
    register_compliance,
    register_compliance_guard,
)
from comply54.core.models import ComplianceResult, PolicyDecision, RegulatorySource


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_result(overall: str) -> ComplianceResult:
    """Build a minimal ComplianceResult for a given overall decision."""
    if overall == "allow":
        return ComplianceResult.from_decisions([])

    decision = PolicyDecision(
        pack="test_pack",
        regulation="Test Regulation",
        jurisdiction="TEST",
        action=overall,
        messages=["Test message"],
        citations=[
            RegulatorySource(
                document="Test Act 2024",
                section="s.1",
                authority="Test Authority",
                year=2024,
            )
        ],
        rule_triggered="test_rule",
    )
    return ComplianceResult.from_decisions([decision])


def _mock_compliance(overall: str) -> MagicMock:
    mock = MagicMock()
    mock.name = "TestCompliance"
    mock.jurisdictions = ["TEST"]
    mock.__class__.__name__ = "TestCompliance"
    mock.check.return_value = _make_result(overall)
    return mock


async def _transfer(recipient: str, amount: float, currency: str) -> str:
    """Transfer funds between accounts."""
    return json.dumps({"status": "ok", "recipient": recipient, "amount": amount})


def _check_balance(account: str) -> str:
    """Check account balance."""
    return json.dumps({"account": account, "balance": 5000.0})


def _run(coro):
    return asyncio.run(coro)


# ─── comply54_tool ────────────────────────────────────────────────────────────

class TestComply54Tool:
    def test_returns_function_tool(self):
        from autogen_core.tools import FunctionTool
        assert isinstance(comply54_tool(_transfer, _mock_compliance("allow")), FunctionTool)

    def test_preserves_tool_name(self):
        assert comply54_tool(_transfer, _mock_compliance("allow")).name == "_transfer"

    def test_custom_name(self):
        tool = comply54_tool(_transfer, _mock_compliance("allow"), name="transfer_funds")
        assert tool.name == "transfer_funds"

    def test_preserves_schema_parameters(self):
        tool = comply54_tool(_transfer, _mock_compliance("allow"))
        params = tool.schema["parameters"]["properties"]
        assert set(params.keys()) == {"recipient", "amount", "currency"}

    def test_allow_executes_function(self):
        from autogen_core import CancellationToken
        tool = comply54_tool(_transfer, _mock_compliance("allow"))
        result = _run(tool.run_json(
            {"recipient": "ACC123", "amount": 100.0, "currency": "USD"},
            CancellationToken(),
        ))
        assert json.loads(result)["status"] == "ok"

    def test_deny_blocks_execution(self):
        from autogen_core import CancellationToken
        tool = comply54_tool(_transfer, _mock_compliance("deny"))
        result = _run(tool.run_json(
            {"recipient": "ACC123", "amount": 99_000_000.0, "currency": "USD"},
            CancellationToken(),
        ))
        payload = json.loads(result)
        assert payload["blocked"] is True
        assert payload["decision"] == "deny"

    def test_deny_includes_regulation_and_rule(self):
        from autogen_core import CancellationToken
        tool = comply54_tool(_transfer, _mock_compliance("deny"))
        result = _run(tool.run_json(
            {"recipient": "X", "amount": 1.0, "currency": "USD"}, CancellationToken()
        ))
        payload = json.loads(result)
        assert payload["regulation"] == "Test Regulation"
        assert payload["rule_triggered"] == "test_rule"
        assert len(payload["citations"]) == 1

    def test_escalate_allows_by_default(self):
        from autogen_core import CancellationToken
        tool = comply54_tool(_transfer, _mock_compliance("escalate"))
        result = _run(tool.run_json(
            {"recipient": "X", "amount": 1.0, "currency": "USD"}, CancellationToken()
        ))
        # escalate without flag → function executes normally
        assert "blocked" not in result

    def test_escalate_blocks_when_flag_set(self):
        from autogen_core import CancellationToken
        tool = comply54_tool(_transfer, _mock_compliance("escalate"), block_on_escalate=True)
        result = _run(tool.run_json(
            {"recipient": "X", "amount": 1.0, "currency": "USD"}, CancellationToken()
        ))
        assert json.loads(result)["blocked"] is True

    def test_wraps_sync_function(self):
        from autogen_core import CancellationToken
        tool = comply54_tool(_check_balance, _mock_compliance("allow"))
        result = _run(tool.run_json({"account": "ACC999"}, CancellationToken()))
        assert json.loads(result)["account"] == "ACC999"

    def test_context_forwarded_to_compliance(self):
        from autogen_core import CancellationToken
        compliance = _mock_compliance("allow")
        tool = comply54_tool(_transfer, compliance, context={"kyc_tier": 3})
        _run(tool.run_json(
            {"recipient": "X", "amount": 1.0, "currency": "USD"}, CancellationToken()
        ))
        call_kwargs = compliance.check.call_args.kwargs
        assert call_kwargs.get("context", {}).get("kyc_tier") == 3


# ─── comply54_tools ───────────────────────────────────────────────────────────

class TestComply54Tools:
    def test_wraps_multiple_callables(self):
        from autogen_core.tools import FunctionTool
        wrapped = comply54_tools([_transfer, _check_balance], _mock_compliance("allow"))
        assert len(wrapped) == 2
        assert all(isinstance(t, FunctionTool) for t in wrapped)

    def test_wraps_existing_function_tool(self):
        from autogen_core.tools import FunctionTool
        original = FunctionTool(_check_balance, description="Check balance", name="check_balance")
        wrapped = comply54_tools([original], _mock_compliance("allow"))
        assert len(wrapped) == 1
        assert wrapped[0].name == "check_balance"
        assert wrapped[0].description == "Check balance"

    def test_all_tools_blocked_on_deny(self):
        from autogen_core import CancellationToken
        transfer_tool, balance_tool = comply54_tools(
            [_transfer, _check_balance], _mock_compliance("deny")
        )
        r1 = _run(transfer_tool.run_json(
            {"recipient": "X", "amount": 1.0, "currency": "USD"}, CancellationToken()
        ))
        r2 = _run(balance_tool.run_json({"account": "ACC1"}, CancellationToken()))
        assert json.loads(r1)["blocked"] is True
        assert json.loads(r2)["blocked"] is True


# ─── compliance_tool ──────────────────────────────────────────────────────────

class TestComplianceTool:
    def test_returns_function_tool(self):
        from autogen_core.tools import FunctionTool
        assert isinstance(compliance_tool(_mock_compliance("allow")), FunctionTool)

    def test_name_includes_compliance_class(self):
        tool = compliance_tool(_mock_compliance("allow"))
        assert "testcompliance" in tool.name

    def test_allow_returns_json_with_overall(self):
        from autogen_core import CancellationToken
        tool = compliance_tool(_mock_compliance("allow"))
        result = _run(tool.run_json({"action": "transfer_funds"}, CancellationToken()))
        assert json.loads(result)["overall"] == "allow"

    def test_deny_returns_json_with_violations(self):
        from autogen_core import CancellationToken
        tool = compliance_tool(_mock_compliance("deny"))
        result = _run(tool.run_json({"action": "send_pii"}, CancellationToken()))
        payload = json.loads(result)
        assert payload["overall"] == "deny"
        assert payload["blocked"] is True
        assert len(payload["violations"]) > 0


# ─── Deprecated API ───────────────────────────────────────────────────────────

class TestDeprecatedAPI:
    def test_comply54_user_proxy_raises(self):
        with pytest.raises(ImportError, match="Comply54UserProxy"):
            Comply54UserProxy(compliance=_mock_compliance("allow"))

    def test_register_compliance_guard_raises(self):
        with pytest.raises(ImportError, match="register_compliance_guard"):
            register_compliance_guard(MagicMock(), _mock_compliance("allow"))

    def test_register_compliance_emits_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            register_compliance(MagicMock(), _mock_compliance("allow"))
        assert any(issubclass(w.category, DeprecationWarning) for w in caught)

    def test_register_compliance_returns_function_tool(self):
        from autogen_core.tools import FunctionTool
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = register_compliance(MagicMock(), _mock_compliance("allow"))
        assert isinstance(result, FunctionTool)
