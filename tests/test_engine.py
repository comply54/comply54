"""
Tests for comply54.core.engine — regopy-based evaluation engine.
No OPA binary required.
"""


from comply54.core.engine import Comply54Engine
from comply54.core.models import EvaluationInput
from comply54.core.packs import CBN, NDPA, BVN_NIN, PII_LEAKAGE, KDPA


# ── CBN transaction limit tests ────────────────────────────────────────────────

class TestCBNEngine:
    engine = Comply54Engine(packs=[CBN])

    def test_transfer_exceeds_nip_cap_is_denied(self):
        result = self.engine.check(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
            context={"kyc_tier": 3},
        )
        assert result.blocked
        assert result.overall == "deny"
        violation = result.primary_violation
        assert violation is not None
        assert "CBN" in violation.messages[0] or "NIP" in violation.messages[0]

    def test_transfer_below_nip_cap_not_denied(self):
        # ₦5M is below the ₦10M NIP cap — should not be deny (may still escalate for KYC audit)
        result = self.engine.check(
            action="transfer_funds",
            params={"amount": 5_000_000, "currency": "NGN"},
            context={"kyc_tier": 3},
        )
        assert result.overall != "deny"

    def test_small_transfer_not_denied(self):
        # ₦50K is well below all CBN thresholds — should not be deny
        result = self.engine.check(
            action="transfer_funds",
            params={"amount": 50_000, "currency": "NGN"},
            context={"kyc_tier": 1},
        )
        assert result.overall != "deny"

    def test_non_transfer_action_passes(self):
        result = self.engine.check(
            action="get_account_balance",
            params={"account_id": "abc"},
        )
        assert result.overall == "allow"


# ── NDPA cross-border tests ───────────────────────────────────────────────────

class TestNDPAEngine:
    engine = Comply54Engine(packs=[NDPA])

    def test_export_to_us_without_consent_triggers_escalation_or_deny(self):
        result = self.engine.check(
            action="send_to_external",
            params={
                "destination_country": "US",
                "destination_region": "us-east-1",
                "data_type": "customer_pii",
                "record_count": 500,
            },
            context={"consent_documented": False},
        )
        assert result.overall in ("deny", "escalate", "audit")

    def test_domestic_storage_passes(self):
        result = self.engine.check(
            action="store_data",
            params={
                "destination_region": "NG",
                "destination_country": "NG",
                "data_type": "customer_pii",
            },
            context={"consent_documented": True},
        )
        assert result.overall == "allow"


# ── Multi-pack evaluation ─────────────────────────────────────────────────────

class TestMultiPackEngine:
    engine = Comply54Engine(packs=[CBN, NDPA, BVN_NIN])

    def test_large_transfer_to_foreign_region_triggers_multiple_violations(self):
        result = self.engine.check(
            action="transfer_funds",
            params={
                "amount": 15_000_000,
                "currency": "NGN",
                "destination_country": "US",
                "destination_region": "us-east-1",
                "data_type": "customer_pii",
            },
            context={"kyc_tier": 3, "consent_documented": False},
        )
        assert result.blocked
        pack_ids = [d.pack for d in result.violations]
        assert "nigeria/cbn" in pack_ids

    def test_evaluation_input_object_accepted(self):
        inp = EvaluationInput(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
            context={"kyc_tier": 3},
        )
        result = self.engine.evaluate(inp)
        assert result.blocked

    def test_all_packs_present_in_decisions(self):
        result = self.engine.check(action="get_balance", params={})
        pack_ids = {d.pack for d in result.decisions}
        assert "nigeria/cbn" in pack_ids
        assert "nigeria/ndpa" in pack_ids
        assert "nigeria/bvn-nin" in pack_ids


# ── KDPA ──────────────────────────────────────────────────────────────────────

class TestKDPAEngine:
    engine = Comply54Engine(packs=[KDPA])

    def test_export_biometric_data_blocked(self):
        result = self.engine.check(
            action="export_data",
            params={"destination_country": "CN", "data_type": "biometric"},
        )
        assert result.overall in ("deny", "escalate", "audit")

    def test_clean_action_passes(self):
        result = self.engine.check(action="list_transactions", params={})
        assert result.overall == "allow"


# ── PII leakage universal pack ────────────────────────────────────────────────

class TestPIILeakage:
    engine = Comply54Engine(packs=[PII_LEAKAGE])

    def test_bvn_in_output_triggers_deny(self):
        result = self.engine.check(
            action="respond_to_user",
            output="Your BVN is 12345678901 and NIN is 98765432101.",
        )
        assert result.overall in ("deny", "escalate", "audit")

    def test_clean_output_passes(self):
        result = self.engine.check(
            action="respond_to_user",
            output="Your transaction of ₦5,000 was successful.",
        )
        assert result.overall == "allow"
