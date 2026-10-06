"""
Rules must key on what a request declares, not only on the action's name.

Packs previously matched actions against closed sets of exact strings, and an
unrecognised name fell through to allow. A caller whose tool was named
`approve_insurance_claim` rather than `approve_claim`, or who sent `amount`
where the rule read `claim_amount`, got no enforcement and no signal that none
had run. These tests pin the cases that silently passed.
"""

import pytest

from comply54.sectors.nigeria_fintech import NigeriaFintechCompliance
from comply54.sectors.nigeria_insurance import NigeriaInsuranceCompliance


def packs_firing(result):
    return {d.pack for d in result.decisions if d.action != "allow"}


class TestSpecialCategoryData:
    """NDPA s.30 applies to health data whatever the tool is called."""

    def test_health_data_logged_without_consent_is_denied(self):
        r = NigeriaInsuranceCompliance().check(
            "log_caller_health_data",
            {"claim_id": "CLM-9920-WEM", "conditions": ["HIV", "Type 2 Diabetes"]},
            "",
            {
                "data_category": "health",
                "special_category": True,
                "consent_given": False,
                "hiv_status": True,
            },
        )
        assert r.blocked
        assert "nigeria/ndpa" in packs_firing(r)

    @pytest.mark.parametrize(
        "signal",
        [
            {"special_category": True},
            {"contains_phi": True},
            {"hiv_status": True},
            {"data_category": "health"},
            {"data_category": "biometric"},
            {"data_category": "genetic"},
        ],
    )
    def test_each_special_category_signal_denies_without_consent(self, signal):
        r = NigeriaInsuranceCompliance().check("any_tool_name", {}, "", signal)
        assert r.blocked, f"{signal} did not block"

    @pytest.mark.parametrize(
        "consent_key",
        ["consent_documented", "consent_provided", "consent_given", "consent_obtained"],
    )
    def test_consent_is_honoured_under_each_spelling(self, consent_key):
        """One accepted spelling of consent would be the same fail-open inverted."""
        r = NigeriaInsuranceCompliance().check(
            "log_caller_health_data", {}, "",
            {"data_category": "health", consent_key: True},
        )
        assert "nigeria/ndpa" not in packs_firing(r)


class TestLawfulBasis:
    """NDPA s.25: a declared-null basis is an absence, not an omission."""

    def test_null_lawful_basis_without_consent_is_denied(self):
        r = NigeriaFintechCompliance().check(
            "bulk_export_customer_records", {"record_count": 50340}, "",
            {"lawful_basis": None, "consent_obtained": False, "cross_border": True},
        )
        assert r.blocked
        assert "nigeria/ndpa" in packs_firing(r)

    def test_absent_lawful_basis_key_does_not_deny(self):
        """Only a declared-empty basis denies; silence is not treated as a claim."""
        r = NigeriaFintechCompliance().check("some_read_action", {}, "", {})
        assert "nigeria/ndpa" not in packs_firing(r)


class TestClaimActionVocabulary:
    """NAICOM thresholds must survive a differently named claim tool."""

    @pytest.mark.parametrize(
        "action",
        [
            "approve_claim",
            "approve_insurance_claim",
            "authorize_claim",
            "approve_payout",
            "disburse_claim",
        ],
    )
    def test_high_value_claim_escalates_under_each_action_name(self, action):
        r = NigeriaInsuranceCompliance().check(
            action, {"claim_amount": 15_000_000}, "", {"senior_approval": False},
        )
        assert r.blocked, f"{action} did not escalate"

    @pytest.mark.parametrize(
        "field", ["claim_amount", "amount", "payout_amount", "settlement_amount"],
    )
    def test_claim_value_is_read_under_each_field_name(self, field):
        r = NigeriaInsuranceCompliance().check(
            "approve_claim", {field: 15_000_000}, "", {"senior_approval": False},
        )
        assert r.blocked, f"{field} was not read as the claim value"


class TestSanctionsScreening:
    """A declared-absent control is evidence, not silence."""

    @pytest.mark.parametrize(
        "action", ["transfer_funds", "process_corporate_payment", "send_payment"],
    )
    def test_unscreened_payment_denies_under_each_action_name(self, action):
        r = NigeriaFintechCompliance().check(
            action, {"amount": 12_000_000, "currency": "NGN"}, "",
            {"sanctions_screened": False, "aml_check_performed": False},
        )
        assert r.blocked, f"{action} was not blocked"
        assert "nigeria/nfiu-aml" in packs_firing(r)

    def test_screened_payment_is_not_denied_by_this_rule(self):
        """A screened transfer still audits, which is normal; the rule must not deny."""
        r = NigeriaFintechCompliance().check(
            "transfer_funds", {"amount": 50_000, "currency": "NGN"}, "",
            {"sanctions_screened": True, "aml_check_performed": True, "kyc_verified": True},
        )
        aml_denials = [
            d for d in r.decisions if d.pack == "nigeria/nfiu-aml" and d.action == "deny"
        ]
        assert aml_denials == [], f"unexpected AML denial: {aml_denials}"
