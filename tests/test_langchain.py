"""
Tests for comply54.langchain — LangChain / LangGraph integration.

Covers:
  - Comply54Guard: tool call interception, block on deny, pass-through on allow
  - comply54_route: routing based on compliance_blocked state
  - comply54_tool: StructuredTool creation and invocation
  - compliance_node: legacy state-dict node
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

pytest.importorskip("langchain_core")

from langchain_core.messages import AIMessage, ToolMessage

from comply54.core.models import Action, ComplianceResult, PolicyDecision, RegulatorySource
from comply54.langchain.adapter import (
    Comply54Guard,
    comply54_route,
    comply54_tool,
    compliance_node,
)
from comply54.sectors.nigeria_fintech import NigeriaFintechCompliance


# ─── Helpers ──────────────────────────────────────────────────────────────────

_SOURCE = RegulatorySource(
    document="CBN Circular FPR/DIR/GEN/CIR/07/003",
    section="§4.1",
    authority="CBN",
    year=2023,
)


def _make_result(action: Action, message: str = "test violation") -> ComplianceResult:
    decision = PolicyDecision(
        pack="test_pack",
        regulation="Test Regulation",
        jurisdiction="NG",
        action=action,
        messages=[message] if action != "allow" else [],
        citations=[_SOURCE] if action != "allow" else [],
    )
    return ComplianceResult.from_decisions([decision])


def _make_ai_message_with_tool_call(tool_name: str, args: dict) -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[{"id": "call_001", "name": tool_name, "args": args}],
    )


# ─── Comply54Guard ─────────────────────────────────────────────────────────────

class TestComply54Guard:

    def test_blocks_denied_tool_call(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("deny", "CBN NIP cap exceeded")
        mock_compliance.name = "Test"
        mock_compliance.jurisdictions = ["NG"]

        guard = Comply54Guard(mock_compliance)
        state = {
            "messages": [_make_ai_message_with_tool_call("transfer_funds", {"amount": 15_000_000})],
        }
        result = guard(state)

        assert result["compliance_blocked"] is True
        assert len(result["messages"]) == 1
        msg = result["messages"][0]
        assert isinstance(msg, ToolMessage)
        payload = json.loads(msg.content)
        assert payload["blocked"] is True
        assert payload["decision"] == "deny"
        assert "CBN NIP cap exceeded" in payload["reason"]

    def test_passes_through_allowed_tool_call(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("allow")
        mock_compliance.name = "Test"
        mock_compliance.jurisdictions = ["NG"]

        guard = Comply54Guard(mock_compliance)
        state = {
            "messages": [_make_ai_message_with_tool_call("read_user", {})],
        }
        result = guard(state)

        assert result["compliance_blocked"] is False
        assert "messages" not in result

    def test_no_tool_calls_passes_through(self):
        mock_compliance = MagicMock()
        guard = Comply54Guard(mock_compliance)
        state = {"messages": [AIMessage(content="Hello")]}
        result = guard(state)

        assert result["compliance_blocked"] is False
        mock_compliance.check.assert_not_called()

    def test_empty_messages_passes_through(self):
        mock_compliance = MagicMock()
        guard = Comply54Guard(mock_compliance)
        result = guard({"messages": []})
        assert result["compliance_blocked"] is False
        mock_compliance.check.assert_not_called()

    def test_escalate_passes_through_by_default(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("escalate", "high-value transfer")
        mock_compliance.name = "Test"
        mock_compliance.jurisdictions = ["NG"]

        guard = Comply54Guard(mock_compliance)
        state = {
            "messages": [_make_ai_message_with_tool_call("transfer_funds", {"amount": 5_000_000})],
        }
        result = guard(state)

        assert result["compliance_blocked"] is False

    def test_escalate_blocks_when_block_on_escalate_true(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("escalate", "high-value transfer")
        mock_compliance.name = "Test"
        mock_compliance.jurisdictions = ["NG"]

        guard = Comply54Guard(mock_compliance, block_on_escalate=True)
        state = {
            "messages": [_make_ai_message_with_tool_call("transfer_funds", {"amount": 5_000_000})],
        }
        result = guard(state)

        assert result["compliance_blocked"] is True

    def test_context_merged_from_state(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("allow")
        mock_compliance.name = "Test"
        mock_compliance.jurisdictions = ["NG"]

        guard = Comply54Guard(mock_compliance, context={"kyc_tier": 2})
        state = {
            "messages": [_make_ai_message_with_tool_call("read_user", {})],
            "compliance_context": {"customer_verified": True},
        }
        guard(state)

        _, kwargs = mock_compliance.check.call_args
        called_kwargs = mock_compliance.check.call_args.kwargs
        assert called_kwargs.get("context", {}).get("kyc_tier") == 2
        assert called_kwargs.get("context", {}).get("customer_verified") is True

    def test_audit_id_in_blocked_payload(self):
        mock_compliance = MagicMock()
        result = _make_result("deny", "blocked")
        mock_compliance.check.return_value = result
        mock_compliance.name = "Test"
        mock_compliance.jurisdictions = ["NG"]

        guard = Comply54Guard(mock_compliance)
        state = {"messages": [_make_ai_message_with_tool_call("transfer_funds", {})]}
        out = guard(state)

        payload = json.loads(out["messages"][0].content)
        assert "audit_id" in payload
        assert payload["audit_id"] == result.audit_id

    def test_repr(self):
        mock_compliance = MagicMock()
        mock_compliance.__repr__ = lambda self: "MockCompliance()"
        guard = Comply54Guard(mock_compliance)
        assert "Comply54Guard" in repr(guard)


# ─── comply54_route ────────────────────────────────────────────────────────────

class TestComply54Route:

    def test_routes_to_agent_when_blocked(self):
        assert comply54_route({"compliance_blocked": True}) == "agent"

    def test_routes_to_tools_when_not_blocked(self):
        assert comply54_route({"compliance_blocked": False}) == "tools"

    def test_routes_to_tools_when_key_missing(self):
        assert comply54_route({}) == "tools"


# ─── comply54_tool ─────────────────────────────────────────────────────────────

class TestComply54Tool:

    def test_returns_structured_tool(self):
        from langchain_core.tools import StructuredTool

        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("allow")
        mock_compliance.__class__.__name__ = "MockCompliance"

        tool = comply54_tool(mock_compliance)
        assert isinstance(tool, StructuredTool)

    def test_tool_name_defaults_to_class_name(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("allow")
        mock_compliance.__class__.__name__ = "NigeriaFintechCompliance"

        tool = comply54_tool(mock_compliance)
        assert "nigeriafintech" in tool.name.lower() or "comply54" in tool.name.lower()

    def test_tool_name_custom(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("allow")
        mock_compliance.__class__.__name__ = "MockCompliance"

        tool = comply54_tool(mock_compliance, name="nigeria_check")
        assert tool.name == "nigeria_check"

    def test_tool_invoke_returns_json(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("deny", "NIP cap exceeded")
        mock_compliance.__class__.__name__ = "MockCompliance"

        tool = comply54_tool(mock_compliance)
        raw = tool.invoke({"action": "transfer_funds", "params": {"amount": 15_000_000}})
        parsed = json.loads(raw)

        assert parsed["overall"] == "deny"
        assert parsed["blocked"] is True
        assert len(parsed["violations"]) == 1

    def test_tool_invoke_allow_returns_empty_violations(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("allow")
        mock_compliance.__class__.__name__ = "MockCompliance"

        tool = comply54_tool(mock_compliance)
        raw = tool.invoke({"action": "read_profile", "params": {}})
        parsed = json.loads(raw)

        assert parsed["overall"] == "allow"
        assert parsed["blocked"] is False
        assert parsed["violations"] == []


# ─── compliance_node (legacy) ──────────────────────────────────────────────────

class TestComplianceNode:

    def test_blocked_state_on_deny(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("deny", "Access denied")
        mock_compliance.__class__.__name__ = "MockCompliance"

        node = compliance_node(mock_compliance)
        state = {"action": "export_data", "params": {}, "output": "", "context": {}}
        result = node(state)

        assert result["compliance_blocked"] is True
        assert result["compliance_message"] == "Access denied"
        assert result["compliance_result"]["overall"] == "deny"

    def test_passed_state_on_allow(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("allow")
        mock_compliance.__class__.__name__ = "MockCompliance"

        node = compliance_node(mock_compliance)
        state = {"action": "read_user", "params": {}, "output": "", "context": {}}
        result = node(state)

        assert result["compliance_blocked"] is False
        assert result["compliance_message"] == ""

    def test_preserves_state_keys(self):
        mock_compliance = MagicMock()
        mock_compliance.check.return_value = _make_result("allow")
        mock_compliance.__class__.__name__ = "MockCompliance"

        node = compliance_node(mock_compliance)
        state = {"action": "read_user", "params": {}, "output": "", "context": {}, "custom_key": "preserved"}
        result = node(state)

        assert result["custom_key"] == "preserved"


# ─── Integration test with real NigeriaFintechCompliance ──────────────────────

class TestIntegrationWithRealSector:

    def test_guard_blocks_real_nip_violation(self):
        guard = Comply54Guard(NigeriaFintechCompliance())
        state = {
            "messages": [
                _make_ai_message_with_tool_call(
                    "transfer_funds", {"amount": 15_000_000, "currency": "NGN"}
                )
            ],
        }
        result = guard(state)

        assert result["compliance_blocked"] is True
        payload = json.loads(result["messages"][0].content)
        assert payload["blocked"] is True
        assert payload["decision"] == "deny"

    def test_guard_allows_small_transfer(self):
        guard = Comply54Guard(NigeriaFintechCompliance())
        state = {
            "messages": [
                _make_ai_message_with_tool_call(
                    "transfer_funds",
                    {"amount": 50_000, "currency": "NGN"},
                )
            ],
            "compliance_context": {"kyc_tier": 3, "customer_verified": True, "sanctions_screened": True},
        }
        result = guard(state)

        assert result["compliance_blocked"] is False

    def test_comply54_tool_real_denial(self):
        tool = comply54_tool(NigeriaFintechCompliance())
        raw = tool.invoke({
            "action": "transfer_funds",
            "params": {"amount": 15_000_000, "currency": "NGN"},
        })
        parsed = json.loads(raw)
        assert parsed["blocked"] is True
