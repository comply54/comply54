"""
Property-based tests for comply54 using Hypothesis.

These tests verify invariants that must hold across all possible inputs,
not just the specific examples covered by unit tests:

  1. Severity aggregation    — from_decisions() always returns the maximum
                               severity across all decisions (pure model).
  2. CBN amount threshold    — any transfer > ₦10,000,000 is always denied;
                               any transfer <= ₦10,000,000 is never denied.
  3. Certificate determinism — identical ComplianceResults produce identical
                               integrity hashes (idempotent serialisation).
  4. Engine robustness       — arbitrary safe action strings never raise;
                               the engine always returns a ComplianceResult.

Running: pytest tests/test_properties.py -v
"""

from __future__ import annotations

import string
import uuid

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from comply54.core.engine import Comply54Engine
from comply54.core.models import (
    Action,
    ComplianceResult,
    EvaluationInput,
    PolicyDecision,
)
from comply54.core.packs import CBN


# ── Strategies ────────────────────────────────────────────────────────────────

_ACTIONS: list[Action] = ["allow", "deny", "escalate", "audit"]
_SEVERITY: dict[Action, int] = {"allow": 0, "audit": 1, "escalate": 2, "deny": 3}

action_st = st.sampled_from(_ACTIONS)

policy_decision_st = st.builds(
    PolicyDecision,
    pack=st.just("nigeria/cbn"),
    regulation=st.just("CBN NIP Framework"),
    jurisdiction=st.just("NG"),
    action=action_st,
    messages=st.lists(st.text(max_size=80), max_size=3),
    rule_triggered=st.one_of(st.none(), st.text(alphabet=string.ascii_lowercase + "_", max_size=40)),
    audit_id=st.builds(lambda: str(uuid.uuid4())),
)

# Safe action strings: printable ASCII, no shell metacharacters
safe_action_st = st.text(
    alphabet=string.ascii_letters + string.digits + "_-",
    min_size=1,
    max_size=50,
)

# NGN amounts: focus on around the ₦10M cap boundary
over_cap_amount_st = st.integers(min_value=10_000_001, max_value=1_000_000_000)
under_cap_amount_st = st.integers(min_value=0, max_value=10_000_000)


# ── Property 1: Severity aggregation ─────────────────────────────────────────


@given(st.lists(policy_decision_st, min_size=1, max_size=10))
def test_from_decisions_overall_is_max_severity(decisions: list[PolicyDecision]) -> None:
    """ComplianceResult.from_decisions() must always return the maximum severity."""
    result = ComplianceResult.from_decisions(decisions)
    expected_severity = max(_SEVERITY[d.action] for d in decisions)
    assert _SEVERITY[result.overall] == expected_severity, (
        f"overall={result.overall!r} has severity {_SEVERITY[result.overall]}, "
        f"expected {expected_severity}"
    )


@given(st.lists(policy_decision_st, min_size=1, max_size=10))
def test_blocked_iff_deny_or_escalate(decisions: list[PolicyDecision]) -> None:
    """result.blocked must be True exactly when overall is deny or escalate."""
    result = ComplianceResult.from_decisions(decisions)
    assert result.blocked == (result.overall in ("deny", "escalate"))


@given(st.lists(policy_decision_st, min_size=1, max_size=10))
def test_any_deny_means_overall_deny(decisions: list[PolicyDecision]) -> None:
    """If any decision is deny, overall must be deny."""
    result = ComplianceResult.from_decisions(decisions)
    if any(d.action == "deny" for d in decisions):
        assert result.overall == "deny"


@given(st.lists(policy_decision_st.filter(lambda d: d.action != "deny"), min_size=1, max_size=10))
def test_no_deny_means_overall_not_deny(decisions: list[PolicyDecision]) -> None:
    """If no decision is deny, overall must not be deny."""
    result = ComplianceResult.from_decisions(decisions)
    assert result.overall != "deny"


# ── Property 2: CBN amount threshold ─────────────────────────────────────────


@pytest.fixture(scope="module")
def cbn_engine() -> Comply54Engine:
    return Comply54Engine(packs=[CBN])


@given(amount=over_cap_amount_st)
@settings(max_examples=50)
def test_over_cap_transfer_always_denied(amount: int) -> None:
    """Any transfer_funds call with amount > ₦10,000,000 must be denied."""
    engine = Comply54Engine(packs=[CBN])
    result = engine.check(
        action="transfer_funds",
        params={"amount": amount, "currency": "NGN"},
        context={"kyc_tier": 3},
    )
    assert result.overall == "deny", (
        f"Expected deny for ₦{amount:,} but got {result.overall!r}"
    )


@given(amount=under_cap_amount_st)
@settings(max_examples=50)
def test_under_cap_transfer_never_denied(amount: int) -> None:
    """Any transfer_funds call with amount <= ₦10,000,000 must not be denied."""
    engine = Comply54Engine(packs=[CBN])
    result = engine.check(
        action="transfer_funds",
        params={"amount": amount, "currency": "NGN"},
        context={"kyc_tier": 3},
    )
    assert result.overall != "deny", (
        f"Expected non-deny for ₦{amount:,} but got {result.overall!r}"
    )


# ── Property 3: Certificate determinism ───────────────────────────────────────


@given(st.lists(policy_decision_st, min_size=1, max_size=5))
def test_certificate_integrity_hash_is_deterministic(decisions: list[PolicyDecision]) -> None:
    """Calling to_certificate() twice on the same result produces the same hash."""
    result = ComplianceResult.from_decisions(decisions)
    cert_a = result.to_certificate(sector_pack="test", jurisdictions=["NG"])
    cert_b = result.to_certificate(sector_pack="test", jurisdictions=["NG"])
    assert cert_a.integrity_hash == cert_b.integrity_hash


@given(st.lists(policy_decision_st, min_size=1, max_size=5))
def test_certificate_passed_matches_overall(decisions: list[PolicyDecision]) -> None:
    """Certificate.passed must match whether overall == 'allow'."""
    result = ComplianceResult.from_decisions(decisions)
    cert = result.to_certificate()
    assert cert.passed == (result.overall == "allow")


@given(st.lists(policy_decision_st, min_size=1, max_size=5))
def test_certificate_overall_matches_result(decisions: list[PolicyDecision]) -> None:
    """Certificate.overall must equal ComplianceResult.overall."""
    result = ComplianceResult.from_decisions(decisions)
    cert = result.to_certificate()
    assert cert.overall == result.overall


# ── Property 4: Engine robustness ────────────────────────────────────────────


@given(action=safe_action_st)
@settings(max_examples=30)
def test_engine_never_raises_on_arbitrary_action(action: str) -> None:
    """The engine must return a ComplianceResult for any safe action string."""
    engine = Comply54Engine(packs=[CBN])
    result = engine.check(action=action, params={}, context={})
    assert isinstance(result, ComplianceResult)
    assert result.overall in ("allow", "deny", "escalate", "audit")


@given(action=safe_action_st, amount=st.integers(min_value=0, max_value=10**9))
@settings(max_examples=30)
def test_engine_result_always_has_audit_id(action: str, amount: int) -> None:
    """Every ComplianceResult must carry a non-empty audit_id."""
    engine = Comply54Engine(packs=[CBN])
    result = engine.check(
        action=action,
        params={"amount": amount, "currency": "NGN"},
    )
    assert result.audit_id
    assert len(result.audit_id) > 0
