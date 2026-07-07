"""
comply54.receipts._signer
~~~~~~~~~~~~~~~~~~~~~~~~~
Ed25519 JWT receipt signer for comply54 compliance results.

Design decisions:
  - Ed25519 (EdDSA): 32-byte keys, 64-byte signatures, ~35x faster than RSA-2048,
    NIST SP 800-186 approved. No RSA/EC key confusion possible (key type is explicit).
  - PyJWT 2.x + cryptography: both are required for Ed25519 support.
  - BYOK (bring-your-own-key): the caller generates their own keypair and passes
    the PEM-encoded private key. comply54 never generates or stores keys on behalf
    of the caller in production code.
  - JWT claims use ``c54_`` prefix to avoid collisions with IANA-registered names.
  - Signing happens AFTER strict_mode is applied in SectorCompliance — the receipt
    reflects the final decision returned to the caller, not the raw engine output.
"""

from __future__ import annotations

from typing import Optional, Union

from .._version import __version__
from ._digest import digest_input

try:
    import jwt as _jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
    )

    _SIGNING_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SIGNING_AVAILABLE = False


_SIGNING_INSTALL_MSG = (
    "Signed receipts require PyJWT and cryptography. "
    "Install with:  pip install 'comply54[signing]'"
)


class ReceiptSigner:
    """
    Signs a ``ComplianceResult`` and returns a compact Ed25519 JWT receipt.

    Instantiate once with your Ed25519 private key (PEM) and call ``sign()``
    after every compliance evaluation.  Pass the companion public key PEM to
    ``verify_receipt()`` to verify receipts offline — no network call needed.

    Generate a keypair with :meth:`generate_keypair` (development / CI only —
    in production, generate and store keys in your secret manager):

    .. code-block:: python

        private_pem, public_pem = ReceiptSigner.generate_keypair()
        signer = ReceiptSigner(private_pem)

        compliance = NigeriaFintechCompliance(signing_key=private_pem)
        result = compliance.check(
            action="transfer_funds",
            params={"amount": 5_000_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        print(result.receipt_token)   # compact JWT

        payload = verify_receipt(result.receipt_token, public_pem)
        assert payload.decision == "escalate"

    The JWT payload structure (all ``c54_*`` claims are custom):

    .. code-block:: json

        {
          "iss": "comply54",
          "iat": 1751234567,
          "jti": "<audit_id>",
          "c54_decision": "deny",
          "c54_pack": "nigeria/nfiu-aml",
          "c54_regulation": "MLPPA 2022",
          "c54_rule": "sanctions_screening_required",
          "c54_messages": ["NFIU / MLPPA 2022 s.6: ..."],
          "c54_input_digest": "sha256:a3f9...",
          "c54_version": "0.4.0",
          "c54_packs_evaluated": ["nigeria/nfiu-aml", "nigeria/cbn"]
        }
    """

    def __init__(self, private_key_pem: Union[str, bytes]) -> None:
        if not _SIGNING_AVAILABLE:  # pragma: no cover
            raise ImportError(_SIGNING_INSTALL_MSG)
        if isinstance(private_key_pem, str):
            private_key_pem = private_key_pem.encode()
        key = load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(
                "comply54 receipts require an Ed25519 private key. "
                "Received a key of type: "
                f"{type(key).__name__}"
            )
        self._private_key: Ed25519PrivateKey = key

    def sign(
        self,
        result: "ComplianceResult",  # type: ignore[name-defined]  # avoid circular import
        action: str,
        params: dict,
        output: str = "",
        context: Optional[dict] = None,
        pack_versions: Optional[dict] = None,
    ) -> str:
        """
        Sign a ``ComplianceResult`` and return a compact JWT receipt token.

        Args:
            result:        The ``ComplianceResult`` to sign — must be the final
                           result after strict_mode is applied.
            action:        The action string passed to ``check()`` / ``evaluate()``.
            params:        The params dict from the same call.
            output:        The output string from the same call.
            context:       The context dict from the same call.
            pack_versions: Mapping of pack ID → policy version for every pack
                           that was evaluated, e.g.
                           ``{"nigeria/cbn": "1.0.0", "nigeria/nfiu-aml": "1.1.0"}``.
                           Embedded as ``c54_pack_versions`` in the JWT so auditors
                           can confirm which version of each regulation was in force.

        Returns:
            Compact JWT string (three base64url-encoded segments).
        """
        pv = result.primary_violation
        ctx = context or {}

        claims: dict = {
            "iss": "comply54",
            "iat": int(result.evaluated_at.timestamp()),
            "jti": result.audit_id,
            "c54_decision": result.overall,
            "c54_pack": pv.pack if pv else None,
            "c54_regulation": pv.regulation if pv else None,
            "c54_rule": pv.rule_triggered if pv else None,
            "c54_messages": pv.messages[:5] if pv else [],
            "c54_input_digest": digest_input(action, params, output, ctx),
            "c54_version": __version__,
            "c54_packs_evaluated": [d.pack for d in result.decisions],
            "c54_pack_versions": pack_versions or {},
        }

        return _jwt.encode(claims, self._private_key, algorithm="EdDSA")

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """
        Generate a new Ed25519 keypair for use with comply54 receipts.

        .. warning::

            This method is intended for development, testing, and CI pipelines.
            In production, generate keys inside your secret manager (AWS KMS,
            HashiCorp Vault, GCP KMS) and never write private keys to disk.

        Returns:
            ``(private_key_pem, public_key_pem)`` — both as PEM-encoded bytes.
            Pass ``private_key_pem`` to :class:`ReceiptSigner`.
            Distribute ``public_key_pem`` to receipt verifiers.
        """
        if not _SIGNING_AVAILABLE:  # pragma: no cover
            raise ImportError(_SIGNING_INSTALL_MSG)
        key = Ed25519PrivateKey.generate()
        private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        public_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return private_pem, public_pem
