"""
Tests for Phase 1.3 additions:
  - ComplianceCertificate output
  - SectorCompliance.certificate() method
  - strict_mode on PanAfricanFintechCompliance
"""

import json

from comply54 import NigeriaFintechCompliance, PanAfricanFintechCompliance, ComplianceCertificate


class TestComplianceCertificate:
    compliance = NigeriaFintechCompliance()

    def test_certificate_returned_on_allow(self):
        cert = self.compliance.certificate(action="get_balance", params={})
        assert isinstance(cert, ComplianceCertificate)
        assert cert.overall == "allow"
        assert cert.passed is True

    def test_certificate_returned_on_deny(self):
        cert = self.compliance.certificate(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        )
        assert cert.overall == "deny"
        assert cert.passed is False
        assert len(cert.violations) > 0

    def test_certificate_has_required_fields(self):
        cert = self.compliance.certificate(action="get_balance", params={})
        assert cert.certificate_id.startswith("cert_")
        assert cert.audit_id
        assert cert.issued_at is not None
        assert cert.sector_pack == "Nigeria Fintech Compliance"
        assert "NG" in cert.jurisdictions
        assert len(cert.packs_evaluated) == 8

    def test_certificate_integrity_hash_present(self):
        cert = self.compliance.certificate(action="get_balance", params={})
        assert len(cert.integrity_hash) == 64  # SHA-256 hex

    def test_certificate_integrity_hash_deterministic_for_same_audit_id(self):
        # Two certs from the same result must have the same hash
        result = self.compliance.check(action="get_balance", params={})
        cert1 = result.to_certificate(
            sector_pack="Nigeria Fintech Compliance",
            jurisdictions=["NG"],
        )
        cert2 = result.to_certificate(
            sector_pack="Nigeria Fintech Compliance",
            jurisdictions=["NG"],
        )
        assert cert1.integrity_hash == cert2.integrity_hash

    def test_certificate_to_json_is_valid_json(self):
        cert = self.compliance.certificate(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        )
        json_str = cert.to_json()
        parsed = json.loads(json_str)
        assert parsed["overall"] == "deny"
        assert "violations" in parsed
        assert "integrity_hash" in parsed

    def test_certificate_to_dict_round_trips(self):
        cert = self.compliance.certificate(action="get_balance", params={})
        d = cert.to_dict()
        assert isinstance(d, dict)
        assert d["sector_pack"] == "Nigeria Fintech Compliance"
        assert d["passed"] is True

    def test_certificate_violations_contain_messages(self):
        cert = self.compliance.certificate(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        )
        assert any(len(v["messages"]) > 0 for v in cert.violations)

    def test_certificate_has_regulations_list(self):
        cert = self.compliance.certificate(action="get_balance", params={})
        assert len(cert.regulations) > 0
        assert any("Nigeria Data Protection" in r or "NDPA" in r for r in cert.regulations)


class TestStrictMode:
    def test_strict_mode_off_escalate_is_not_deny(self):
        compliance = PanAfricanFintechCompliance(strict_mode=False)
        result = compliance.check(
            action="transfer_funds",
            params={"amount": 6_000_000, "currency": "NGN"},
            context={"kyc_tier": 3},
        )
        # Should escalate (NFIU CTR) but not deny
        assert result.overall != "deny"
        assert result.overall in ("allow", "audit", "escalate")

    def test_strict_mode_on_escalate_becomes_deny(self):
        compliance = PanAfricanFintechCompliance(strict_mode=True)
        result = compliance.check(
            action="transfer_funds",
            params={"amount": 6_000_000, "currency": "NGN"},
            context={"kyc_tier": 3},
        )
        # In strict mode, escalate → deny
        assert result.overall == "deny"
        assert result.blocked is True

    def test_strict_mode_repr(self):
        compliance = PanAfricanFintechCompliance(strict_mode=True)
        assert "strict_mode=True" in repr(compliance)

    def test_strict_mode_certificate_reflects_upgraded_decision(self):
        compliance = PanAfricanFintechCompliance(strict_mode=True)
        cert = compliance.certificate(
            action="transfer_funds",
            params={"amount": 6_000_000, "currency": "NGN"},
            context={"kyc_tier": 3},
        )
        assert cert.overall == "deny"
        assert cert.passed is False

    def test_pack_ids_property(self):
        compliance = NigeriaFintechCompliance()
        ids = compliance.pack_ids
        assert "nigeria/cbn" in ids
        assert "universal/pii-leakage" in ids
        assert len(ids) == 8

    def test_packs_property_returns_pack_specs(self):
        from comply54.core.packs import PackSpec
        compliance = NigeriaFintechCompliance()
        for p in compliance.packs:
            assert isinstance(p, PackSpec)
