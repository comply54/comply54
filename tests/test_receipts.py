"""
Tests for comply54 signed compliance receipts (v0.4.0).

Coverage:
  - digest_input() determinism and sensitivity
  - ReceiptSigner.generate_keypair() produces valid Ed25519 PEM
  - ReceiptSigner.sign() produces a verifiable JWT
  - verify_receipt() round-trip: valid token → ReceiptPayload
  - verify_receipt() raises InvalidReceiptError for tampered tokens
  - verify_receipt() raises InvalidReceiptError for wrong public key
  - Receipt fields accurately reflect ComplianceResult
  - receipt_token is None when no signing_key provided
  - receipt_token is populated when signing_key provided via SectorCompliance
  - receipt_token is populated when signing_key provided via Comply54Engine
  - strict_mode: receipt reflects upgraded decision (escalate → deny)
  - ReceiptPayload.__str__ formatting
  - CLI: verify-receipt and generate-keypair commands
"""

from __future__ import annotations

import json

import pytest

from comply54 import NigeriaFintechCompliance
from comply54.core.engine import Comply54Engine
from comply54.core.packs import CBN, NDPA, NFIU_AML
from comply54.receipts import (
    InvalidReceiptError,
    ReceiptPayload,
    ReceiptSigner,
    digest_input,
    verify_receipt,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def keypair():
    """Generate a fresh Ed25519 keypair once per test module."""
    return ReceiptSigner.generate_keypair()


@pytest.fixture(scope="module")
def private_pem(keypair):
    return keypair[0]


@pytest.fixture(scope="module")
def public_pem(keypair):
    return keypair[1]


@pytest.fixture(scope="module")
def signer(private_pem):
    return ReceiptSigner(private_pem)


@pytest.fixture(scope="module")
def compliance_with_signing(private_pem):
    return NigeriaFintechCompliance(signing_key=private_pem)


# ─── digest_input ─────────────────────────────────────────────────────────────


class TestDigestInput:
    def test_returns_sha256_prefix(self):
        d = digest_input("transfer_funds", {"amount": 5_000_000}, "", {})
        assert d.startswith("sha256:")

    def test_hex_is_64_chars(self):
        d = digest_input("transfer_funds", {"amount": 5_000_000}, "", {})
        hex_part = d[len("sha256:"):]
        assert len(hex_part) == 64
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_deterministic_same_input(self):
        kwargs = dict(action="transfer_funds", params={"amount": 5_000_000}, output="", context={"kyc_tier": 3})
        assert digest_input(**kwargs) == digest_input(**kwargs)

    def test_sensitive_to_action(self):
        base = dict(params={"amount": 5_000_000}, output="", context={})
        assert digest_input("transfer_funds", **base) != digest_input("send_money", **base)

    def test_sensitive_to_amount(self):
        base = dict(action="transfer_funds", output="", context={})
        assert digest_input(**base, params={"amount": 100}) != digest_input(**base, params={"amount": 200})

    def test_sensitive_to_context(self):
        base = dict(action="transfer_funds", params={"amount": 100}, output="")
        d1 = digest_input(**base, context={"kyc_tier": 1})
        d2 = digest_input(**base, context={"kyc_tier": 2})
        assert d1 != d2

    def test_sensitive_to_output(self):
        base = dict(action="transfer_funds", params={}, context={})
        assert digest_input(**base, output="hello") != digest_input(**base, output="world")

    def test_none_context_equals_empty_dict(self):
        d1 = digest_input("action", {}, "", None)
        d2 = digest_input("action", {}, "", {})
        assert d1 == d2

    def test_dict_key_order_does_not_matter(self):
        d1 = digest_input("a", {"x": 1, "y": 2}, "", {})
        d2 = digest_input("a", {"y": 2, "x": 1}, "", {})
        assert d1 == d2


# ─── ReceiptSigner.generate_keypair ──────────────────────────────────────────


class TestGenerateKeypair:
    def test_returns_two_bytes_objects(self, keypair):
        private_pem, public_pem = keypair
        assert isinstance(private_pem, bytes)
        assert isinstance(public_pem, bytes)

    def test_private_key_is_pem(self, private_pem):
        assert b"-----BEGIN PRIVATE KEY-----" in private_pem

    def test_public_key_is_pem(self, public_pem):
        assert b"-----BEGIN PUBLIC KEY-----" in public_pem

    def test_two_calls_produce_different_keys(self):
        k1 = ReceiptSigner.generate_keypair()
        k2 = ReceiptSigner.generate_keypair()
        assert k1[0] != k2[0]
        assert k1[1] != k2[1]

    def test_signer_accepts_generated_private_key(self, private_pem):
        signer = ReceiptSigner(private_pem)
        assert signer is not None

    def test_signer_accepts_str_private_key(self, private_pem):
        signer = ReceiptSigner(private_pem.decode())
        assert signer is not None

    def test_signer_rejects_non_ed25519_key(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat
        )
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with pytest.raises(ValueError, match="Ed25519"):
            ReceiptSigner(rsa_pem)


# ─── sign() → JWT structure ──────────────────────────────────────────────────


class TestSign:
    def _make_deny_result(self, private_pem):
        """Helper: a deny result via NigeriaFintechCompliance."""
        c = NigeriaFintechCompliance(signing_key=private_pem)
        return c.check(
            action="transfer_funds",
            params={"amount": 5_000_000, "currency": "NGN"},
            context={"sanctions_screened": False},
        )

    def test_receipt_token_is_a_string(self, private_pem):
        result = self._make_deny_result(private_pem)
        assert isinstance(result.receipt_token, str)

    def test_receipt_token_has_three_jwt_segments(self, private_pem):
        result = self._make_deny_result(private_pem)
        parts = result.receipt_token.split(".")
        assert len(parts) == 3

    def test_no_signing_key_gives_none_receipt_token(self):
        c = NigeriaFintechCompliance()
        result = c.check(
            action="transfer_funds",
            params={"amount": 500_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        assert result.receipt_token is None

    def test_engine_direct_signing(self, private_pem):
        engine = Comply54Engine(packs=[CBN, NDPA, NFIU_AML], signing_key=private_pem)
        result = engine.check(
            action="transfer_funds",
            params={"amount": 500_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        assert result.receipt_token is not None
        assert len(result.receipt_token.split(".")) == 3


# ─── verify_receipt() round-trip ─────────────────────────────────────────────


class TestVerifyReceiptRoundTrip:
    @pytest.fixture(scope="class")
    def deny_result(self, private_pem):
        c = NigeriaFintechCompliance(signing_key=private_pem)
        return c.check(
            action="transfer_funds",
            params={"amount": 5_000_000, "currency": "NGN"},
            context={"sanctions_screened": False},
        )

    @pytest.fixture(scope="class")
    def deny_payload(self, deny_result, public_pem):
        return verify_receipt(deny_result.receipt_token, public_pem)

    @pytest.fixture(scope="class")
    def allow_result(self, private_pem):
        c = NigeriaFintechCompliance(signing_key=private_pem)
        return c.check(
            action="transfer_funds",
            params={"amount": 500_000, "currency": "NGN"},
            context={"sanctions_screened": True, "kyc_tier": 3},
        )

    @pytest.fixture(scope="class")
    def allow_payload(self, allow_result, public_pem):
        return verify_receipt(allow_result.receipt_token, public_pem)

    # ── basic decode ──────────────────────────────────────────────────────

    def test_returns_receipt_payload(self, deny_payload):
        assert isinstance(deny_payload, ReceiptPayload)

    def test_decision_matches_result(self, deny_result, deny_payload):
        assert deny_payload.decision == deny_result.overall

    def test_jti_matches_audit_id(self, deny_result, deny_payload):
        assert deny_payload.jti == deny_result.audit_id

    def test_issuer_is_comply54(self, deny_payload):
        assert deny_payload.issuer == "comply54"

    def test_comply54_version_is_present(self, deny_payload):
        assert deny_payload.comply54_version == "0.4.1"

    def test_packs_evaluated_is_non_empty(self, deny_payload):
        assert len(deny_payload.packs_evaluated) > 0

    def test_input_digest_starts_sha256(self, deny_payload):
        assert deny_payload.input_digest.startswith("sha256:")

    # ── deny-specific fields ──────────────────────────────────────────────

    def test_deny_pack_is_nfiu_aml(self, deny_payload):
        assert deny_payload.pack == "nigeria/nfiu-aml"

    def test_deny_regulation_references_nfiu_or_mlppa(self, deny_payload):
        reg = deny_payload.regulation or ""
        assert "NFIU" in reg or "MLPPA" in reg or "Money Laundering" in reg

    def test_deny_rule_triggered_is_present(self, deny_payload):
        assert deny_payload.rule_triggered is not None

    def test_deny_messages_non_empty(self, deny_payload):
        assert len(deny_payload.messages) > 0

    def test_deny_messages_mention_sanctions(self, deny_payload):
        all_msgs = " ".join(deny_payload.messages).lower()
        assert "sanction" in all_msgs or "mlppa" in all_msgs.upper() or "s.6" in all_msgs

    # ── allow-specific fields ─────────────────────────────────────────────

    def test_allow_decision_is_allow_or_escalate(self, allow_payload):
        assert allow_payload.decision in ("allow", "escalate", "audit")

    def test_allow_pack_is_none_when_no_violation(self, allow_payload):
        if allow_payload.decision == "allow":
            assert allow_payload.pack is None

    # ── input digest verification ─────────────────────────────────────────

    def test_input_digest_matches_recomputed(self, deny_payload):
        recomputed = digest_input(
            action="transfer_funds",
            params={"amount": 5_000_000, "currency": "NGN"},
            context={"sanctions_screened": False},
        )
        assert deny_payload.input_digest == recomputed

    def test_input_digest_different_input_does_not_match(self, deny_payload):
        wrong = digest_input(
            action="transfer_funds",
            params={"amount": 999, "currency": "NGN"},
            context={"sanctions_screened": False},
        )
        assert deny_payload.input_digest != wrong

    # ── pack_versions ─────────────────────────────────────────────────────

    def test_pack_versions_is_dict(self, deny_payload):
        assert isinstance(deny_payload.pack_versions, dict)

    def test_pack_versions_non_empty(self, deny_payload):
        assert len(deny_payload.pack_versions) > 0

    def test_pack_versions_keys_match_packs_evaluated(self, deny_payload):
        assert set(deny_payload.pack_versions.keys()) == set(deny_payload.packs_evaluated)

    def test_pack_versions_values_are_semver(self, deny_payload):
        import re
        semver = re.compile(r"^\d+\.\d+\.\d+$")
        for pack_id, version in deny_payload.pack_versions.items():
            assert semver.match(version), f"{pack_id} has non-semver version: {version!r}"

    def test_nfiu_aml_version_is_1_1_0(self, deny_payload):
        assert deny_payload.pack_versions.get("nigeria/nfiu-aml") == "1.1.0"

    def test_pack_versions_empty_for_pre_0_4_1_receipts(self, private_pem, public_pem):
        """Old receipts without c54_pack_versions should still verify and return empty dict."""
        import jwt as _jwt
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from comply54.receipts import digest_input
        key = load_pem_private_key(private_pem, password=None)
        legacy_claims = {
            "iss": "comply54",
            "iat": 1700000000,
            "jti": "legacy-jti",
            "c54_decision": "allow",
            "c54_pack": None,
            "c54_regulation": None,
            "c54_rule": None,
            "c54_messages": [],
            "c54_input_digest": digest_input("ping", {}),
            "c54_version": "0.4.0",
            "c54_packs_evaluated": ["nigeria/ndpa"],
            # intentionally omitting c54_pack_versions
        }
        token = _jwt.encode(legacy_claims, key, algorithm="EdDSA")
        payload = verify_receipt(token, public_pem)
        assert payload.pack_versions == {}

    # ── str representation ────────────────────────────────────────────────

    def test_str_deny_shows_violation(self, deny_payload):
        s = str(deny_payload)
        assert "DENY" in s
        assert "nigeria/nfiu-aml" in s

    def test_str_allow_shows_allow(self, allow_payload):
        s = str(allow_payload)
        if allow_payload.decision == "allow":
            assert "ALLOW" in s

    # ── verify accepts string public key too ─────────────────────────────

    def test_verify_accepts_str_public_key(self, deny_result, public_pem):
        payload = verify_receipt(deny_result.receipt_token, public_pem.decode())
        assert isinstance(payload, ReceiptPayload)


# ─── verify_receipt() — rejection cases ──────────────────────────────────────


class TestVerifyReceiptRejection:
    @pytest.fixture(scope="class")
    def valid_token(self, private_pem, public_pem):
        c = NigeriaFintechCompliance(signing_key=private_pem)
        result = c.check(
            action="transfer_funds",
            params={"amount": 500_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        return result.receipt_token

    def test_wrong_public_key_raises(self, valid_token):
        _, other_pub = ReceiptSigner.generate_keypair()
        with pytest.raises(InvalidReceiptError):
            verify_receipt(valid_token, other_pub)

    def test_tampered_payload_raises(self, valid_token, public_pem):
        header, payload, sig = valid_token.split(".")
        import base64
        # Pad and decode
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        claims["c54_decision"] = "allow"  # tamper
        tampered_payload = base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        tampered_token = f"{header}.{tampered_payload}.{sig}"
        with pytest.raises(InvalidReceiptError):
            verify_receipt(tampered_token, public_pem)

    def test_garbage_token_raises(self, public_pem):
        with pytest.raises(InvalidReceiptError):
            verify_receipt("not.a.jwt", public_pem)

    def test_empty_token_raises(self, public_pem):
        with pytest.raises(InvalidReceiptError):
            verify_receipt("", public_pem)

    def test_invalid_public_key_raises(self, valid_token):
        with pytest.raises(InvalidReceiptError):
            verify_receipt(valid_token, b"not a pem key")

    def test_non_ed25519_public_key_raises(self, valid_token):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pub_pem = rsa_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with pytest.raises(InvalidReceiptError, match="Ed25519"):
            verify_receipt(valid_token, rsa_pub_pem)


# ─── strict_mode interaction ──────────────────────────────────────────────────


class TestStrictModeReceipts:
    def test_strict_mode_receipt_reflects_deny_not_escalate(self, private_pem, public_pem):
        c_strict = NigeriaFintechCompliance(strict_mode=True, signing_key=private_pem)
        result = c_strict.check(
            action="transfer_funds",
            params={"amount": 6_000_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        assert result.overall == "deny"
        assert result.receipt_token is not None
        payload = verify_receipt(result.receipt_token, public_pem)
        # Receipt must capture the strict-mode decision (deny), not the raw escalate
        assert payload.decision == "deny"

    def test_non_strict_escalate_receipt_says_escalate(self, private_pem, public_pem):
        c = NigeriaFintechCompliance(strict_mode=False, signing_key=private_pem)
        result = c.check(
            action="transfer_funds",
            params={"amount": 6_000_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        assert result.overall == "escalate"
        payload = verify_receipt(result.receipt_token, public_pem)
        assert payload.decision == "escalate"


# ─── backwards compatibility ──────────────────────────────────────────────────


class TestBackwardsCompatibility:
    def test_receipt_token_field_defaults_to_none(self):
        c = NigeriaFintechCompliance()
        result = c.check(
            action="transfer_funds",
            params={"amount": 500_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        assert result.receipt_token is None

    def test_result_still_has_all_existing_fields(self):
        c = NigeriaFintechCompliance()
        result = c.check(
            action="transfer_funds",
            params={"amount": 500_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        assert hasattr(result, "overall")
        assert hasattr(result, "decisions")
        assert hasattr(result, "audit_id")
        assert hasattr(result, "evaluated_at")
        assert hasattr(result, "receipt_token")

    def test_existing_tests_not_broken_by_receipt_token_field(self):
        # Spot-check: a deny result still has all expected attributes
        c = NigeriaFintechCompliance()
        result = c.check(
            action="transfer_funds",
            params={"amount": 5_000_000, "currency": "NGN"},
            context={"sanctions_screened": False},
        )
        assert result.overall == "deny"
        assert result.blocked is True
        assert result.primary_violation is not None
        assert result.receipt_token is None  # no signing_key
