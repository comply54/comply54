"""
Tests for comply54.core.engine — regopy-based evaluation engine.
No OPA binary required.
"""


from comply54.core.engine import Comply54Engine
from comply54.core.models import EvaluationInput
from comply54.core.packs import CBN, NDPA, BVN_NIN, PII_LEAKAGE, KDPA, NFIU_AML, NAICOM


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


# ── NFIU sanctions screening (regression: scenario 06) ───────────────────────
#
# Before this fix, a ₦8M corporate payment to a sanctioned entity was only
# *escalated* (CTR threshold), not denied. That made the "sanctioned transfer"
# scenario a false demo — it blocked at ₦12M only because of the unrelated NIP
# cap, not because of sanctions screening.
# The fix adds a deny rule: any transfer_action without sanctions_screened == true
# is hard-blocked regardless of amount.

class TestNFIUSanctionsScreening:
    engine = Comply54Engine(packs=[NFIU_AML])

    def test_corporate_payment_without_sanctions_screening_is_denied(self):
        # ₦8M is below the NIP cap (₦10M) — old code only escalated this.
        # New sanctions rule must deny it because sanctions_screened is False.
        result = self.engine.check(
            action="process_corporate_payment",
            params={"amount": 8_000_000, "currency": "NGN"},
            context={"sanctions_screened": False, "aml_check_performed": False},
        )
        assert result.blocked
        assert result.overall == "deny"
        assert "sanctions" in result.primary_violation.messages[0].lower()

    def test_corporate_payment_with_screening_and_under_nip_cap_escalates_for_ctr(self):
        # ₦8M with sanctions screening done → not denied by sanctions rule.
        # Still escalates for CTR (₦5M–₦10M zone). Note: comply54 sets blocked=True for escalate.
        result = self.engine.check(
            action="process_corporate_payment",
            params={"amount": 8_000_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        assert result.overall in ("escalate", "audit")
        assert result.overall != "deny"

    def test_transfer_funds_without_sanctions_screening_is_denied(self):
        # The fix also applies to transfer_funds, not just corporate payments.
        result = self.engine.check(
            action="transfer_funds",
            params={"amount": 3_000_000, "currency": "NGN"},
            context={"sanctions_screened": False},
        )
        assert result.blocked
        assert result.overall == "deny"

    def test_transfer_with_screening_confirmed_is_not_denied_by_sanctions_rule(self):
        result = self.engine.check(
            action="transfer_funds",
            params={"amount": 3_000_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        # May escalate for CTR, but must not be denied by the sanctions rule.
        assert result.overall != "deny" or "NIP" in (result.primary_violation.messages[0] if result.primary_violation else "")


# ── NAICOM discrimination — state_of_origin (regression: scenario 07) ────────
#
# Before this fix, a denial citing only state_of_origin wasn't caught because
# state_of_origin was not in the prohibited_characteristics set.
# Religion WAS in the set, so the scenario fired — but only accidentally.

class TestNAICOMDiscrimination:
    engine = Comply54Engine(packs=[NAICOM])

    def test_underwriting_with_state_of_origin_is_denied(self):
        # Denial citing state_of_origin alone must now be caught.
        result = self.engine.check(
            action="underwrite_policy",
            params={
                "state_of_origin": "Kano",
                "policy_type": "life",
                "underwriting_amount": 3_000_000,
            },
            context={"human_underwriter": True},
        )
        assert result.blocked
        assert result.overall == "deny"
        assert "state_of_origin" in result.primary_violation.messages[0]

    def test_underwriting_with_religion_is_denied(self):
        # Existing behaviour must still hold.
        result = self.engine.check(
            action="underwrite_policy",
            params={"religion": "Islam", "policy_type": "life", "underwriting_amount": 3_000_000},
            context={"human_underwriter": True},
        )
        assert result.blocked
        assert result.overall == "deny"

    def test_underwriting_with_both_religion_and_state_of_origin_is_denied(self):
        # The full scenario 07 params — both fields present.
        result = self.engine.check(
            action="underwrite_policy",
            params={
                "applicant_name": "Amina Bello",
                "state_of_origin": "Kano",
                "religion": "Islam",
                "gender": "female",
                "policy_type": "life",
                "underwriting_amount": 10_000_000,
                "decision": "deny",
            },
            context={},
        )
        assert result.blocked
        assert result.overall == "deny"

    def test_clean_underwriting_without_prohibited_fields_is_not_denied(self):
        result = self.engine.check(
            action="underwrite_policy",
            params={
                "applicant_age": 34,
                "smoker": False,
                "bmi": 22.5,
                "policy_type": "life",
                "underwriting_amount": 3_000_000,
            },
            context={"human_underwriter": True},
        )
        assert result.overall != "deny"


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
