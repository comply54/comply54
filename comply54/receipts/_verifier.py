"""
comply54.receipts._verifier
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Offline verification of comply54 signed receipt tokens.

Security note — CVE-2022-29217:
    Always pass ``algorithms=["EdDSA"]`` explicitly to ``jwt.decode()``.
    Omitting the ``algorithms`` parameter allows an attacker to substitute an
    HMAC algorithm and forge tokens using the public key as the HMAC secret.
    comply54 hard-codes ``algorithms=["EdDSA"]`` and will never accept any
    other algorithm in a receipt token.
"""

from __future__ import annotations

from typing import Union

from ._models import ReceiptPayload

try:
    import jwt as _jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    _SIGNING_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SIGNING_AVAILABLE = False


_SIGNING_INSTALL_MSG = (
    "Receipt verification requires PyJWT and cryptography. "
    "Install with:  pip install 'comply54[signing]'"
)


class InvalidReceiptError(Exception):
    """
    Raised when a comply54 receipt token fails verification.

    Common causes:
    - The token signature does not match the provided public key.
    - The token has been tampered with after signing.
    - The token was produced by a different comply54 instance.
    - The ``iss`` claim is not ``"comply54"``.
    - Required claims (``iss``, ``iat``, ``jti``) are missing.
    """


def verify_receipt(
    token: str,
    public_key_pem: Union[str, bytes],
) -> ReceiptPayload:
    """
    Verify a comply54 signed receipt token and return the decoded payload.

    Verification is fully offline — no network call is made. The token carries
    all proof: algorithm, claims, and cryptographic signature. The caller
    supplies the Ed25519 public key that corresponds to the signing key used
    to issue the receipt.

    To confirm the receipt covers the *exact* input under inspection, recompute
    the digest with :func:`~comply54.receipts.digest_input` and compare it to
    ``payload.input_digest``.

    Args:
        token:          The JWT receipt token from
                        ``ComplianceResult.receipt_token``.
        public_key_pem: Ed25519 public key in PEM format (``str`` or ``bytes``).

    Returns:
        :class:`~comply54.receipts.ReceiptPayload` — decoded and
        cryptographically verified claims.

    Raises:
        :class:`InvalidReceiptError`: If the token is invalid, tampered with,
            or does not match the provided public key.
        :exc:`ImportError`: If PyJWT or cryptography are not installed.

    Example:
        .. code-block:: python

            from comply54.receipts import verify_receipt, digest_input

            payload = verify_receipt(result.receipt_token, public_key_pem)
            print(payload.decision)      # "deny"
            print(payload.pack)          # "nigeria/nfiu-aml"

            # Prove the receipt covers the exact input under inspection:
            expected = digest_input(
                action="transfer_funds",
                params={"amount": 5_000_000, "currency": "NGN"},
                context={"sanctions_screened": False},
            )
            assert payload.input_digest == expected, "Input mismatch — receipt is for a different call"
    """
    if not _SIGNING_AVAILABLE:  # pragma: no cover
        raise ImportError(_SIGNING_INSTALL_MSG)

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()

    try:
        pub_key = load_pem_public_key(public_key_pem)
    except Exception as exc:
        raise InvalidReceiptError(f"Invalid public key: {exc}") from exc

    if not isinstance(pub_key, Ed25519PublicKey):
        raise InvalidReceiptError(
            "Public key must be Ed25519. "
            f"Received: {type(pub_key).__name__}"
        )

    try:
        claims: dict = _jwt.decode(
            token,
            pub_key,
            algorithms=["EdDSA"],  # explicit — CVE-2022-29217 mitigation
            options={"require": ["iss", "iat", "jti"]},
        )
    except _jwt.ExpiredSignatureError as exc:
        raise InvalidReceiptError("Receipt token has expired") from exc
    except _jwt.InvalidSignatureError as exc:
        raise InvalidReceiptError("Receipt signature is invalid") from exc
    except _jwt.DecodeError as exc:
        raise InvalidReceiptError(f"Receipt token is malformed: {exc}") from exc
    except _jwt.PyJWTError as exc:
        raise InvalidReceiptError(f"Receipt verification failed: {exc}") from exc

    if claims.get("iss") != "comply54":
        raise InvalidReceiptError(
            f"Receipt issuer must be 'comply54', got: {claims.get('iss')!r}"
        )

    for required_claim in ("c54_decision", "c54_input_digest", "c54_version"):
        if required_claim not in claims:
            raise InvalidReceiptError(
                f"Receipt is missing required claim: '{required_claim}'"
            )

    return ReceiptPayload(
        jti=claims["jti"],
        issued_at=claims["iat"],
        issuer=claims["iss"],
        decision=claims["c54_decision"],
        pack=claims.get("c54_pack"),
        regulation=claims.get("c54_regulation"),
        rule_triggered=claims.get("c54_rule"),
        messages=claims.get("c54_messages", []),
        input_digest=claims["c54_input_digest"],
        comply54_version=claims["c54_version"],
        packs_evaluated=claims.get("c54_packs_evaluated", []),
    )
