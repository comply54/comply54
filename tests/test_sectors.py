"""
Tests for comply54 sector packs — NigeriaFintechCompliance, KenyaFintechCompliance,
PanAfricanFintechCompliance.
"""

import pytest
from comply54 import NigeriaFintechCompliance, KenyaFintechCompliance, PanAfricanFintechCompliance


# ── NigeriaFintechCompliance ──────────────────────────────────────────────────

class TestNigeriaFintechCompliance:
    compliance = NigeriaFintechCompliance()

    def test_large_transfer_denied(self):
        result = self.compliance.check(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
            context={"kyc_tier": 3},
        )
        assert result.blocked
        assert result.overall == "deny"

    def test_small_transfer_not_denied(self):
        # ₦5,000 should not be outright denied — may audit but not block
        result = self.compliance.check(
            action="transfer_funds",
            params={"amount": 5_000, "currency": "NGN"},
            context={"kyc_tier": 3},
        )
        assert result.overall != "deny"

    def test_bvn_in_output_caught(self):
        result = self.compliance.check(
            action="respond_to_user",
            output="Customer BVN: 12345678901",
        )
        assert result.overall in ("deny", "escalate", "audit")

    def test_primary_violation_has_message(self):
        result = self.compliance.check(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        )
        violation = result.primary_violation
        assert violation is not None
        assert len(violation.messages) > 0

    def test_violations_list_populated_on_block(self):
        result = self.compliance.check(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        )
        assert len(result.violations) > 0

    def test_jurisdictions_correct(self):
        assert "NG" in self.compliance.jurisdictions

    def test_compliance_result_has_audit_id(self):
        result = self.compliance.check(action="get_balance", params={})
        assert result.audit_id
        assert len(result.audit_id) > 0


# ── KenyaFintechCompliance ────────────────────────────────────────────────────

class TestKenyaFintechCompliance:
    compliance = KenyaFintechCompliance()

    def test_biometric_export_blocked(self):
        result = self.compliance.check(
            action="export_data",
            params={"destination_country": "CN", "data_type": "biometric"},
        )
        assert result.overall in ("deny", "escalate", "audit")

    def test_safe_action_passes(self):
        result = self.compliance.check(action="list_accounts", params={})
        assert result.overall == "allow"

    def test_jurisdictions_correct(self):
        assert "KE" in self.compliance.jurisdictions


# ── PanAfricanFintechCompliance ───────────────────────────────────────────────

class TestPanAfricanFintechCompliance:
    compliance = PanAfricanFintechCompliance()

    def test_large_ngn_transfer_denied(self):
        result = self.compliance.check(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        )
        assert result.blocked

    def test_covers_all_jurisdictions(self):
        expected = {"NG", "KE", "ZA", "GH", "RW", "EG", "ET", "MU", "TZ", "UG"}
        actual = set(self.compliance.jurisdictions)
        assert expected == actual

    def test_decisions_include_all_packs(self):
        result = self.compliance.check(action="get_balance", params={})
        pack_ids = {d.pack for d in result.decisions}
        assert "nigeria/cbn" in pack_ids
        assert "kenya/kdpa" in pack_ids
        assert "south-africa/popia" in pack_ids
        assert "ghana/dpa" in pack_ids
        assert "universal/pii-leakage" in pack_ids

    def test_safe_action_passes_all_packs(self):
        result = self.compliance.check(action="list_transactions", params={})
        assert result.overall == "allow"


# ── Public evaluate() API ─────────────────────────────────────────────────────

class TestPublicEvaluateAPI:
    def test_evaluate_with_pack_ids(self):
        from comply54 import evaluate
        result = evaluate(
            pack_ids=["nigeria/cbn", "universal/pii-leakage"],
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        )
        assert result.blocked

    def test_evaluate_cbn_small_amount_not_denied(self):
        from comply54 import evaluate
        result = evaluate(
            pack_ids=["nigeria/cbn"],
            action="transfer_funds",
            params={"amount": 5_000, "currency": "NGN"},
        )
        assert result.overall != "deny"
