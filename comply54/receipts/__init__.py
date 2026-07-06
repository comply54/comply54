"""
comply54.receipts
~~~~~~~~~~~~~~~~~
Signed compliance receipts — tamper-evident JWT proof of every evaluation.

A comply54 receipt is a compact Ed25519-signed JWT that proves:

  1. **What was decided** — the overall decision (allow / deny / escalate / audit)
     and the primary violation pack, regulation, and rule that triggered it.
  2. **What was evaluated** — all pack IDs evaluated in this call.
  3. **What input it covers** — SHA-256 digest of action + params + output + context,
     so the receipt can be tied to an exact call.
  4. **When it was issued** — UTC Unix timestamp (``iat`` claim).
  5. **Which comply54 version produced it** — for reproducibility audits.

The receipt is fully self-contained and verifiable offline — no network call,
no comply54 server, no database lookup.

Quick start::

    from comply54 import NigeriaFintechCompliance
    from comply54.receipts import ReceiptSigner, verify_receipt

    # One-time: generate a keypair (store private key securely)
    private_pem, public_pem = ReceiptSigner.generate_keypair()

    # Pass the private key to the sector pack
    compliance = NigeriaFintechCompliance(signing_key=private_pem)

    result = compliance.check(
        action="transfer_funds",
        params={"amount": 5_000_000, "currency": "NGN"},
        context={"sanctions_screened": True},
    )
    print(result.receipt_token)   # eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...

    # Later, anywhere, with only the public key:
    payload = verify_receipt(result.receipt_token, public_pem)
    print(payload)                # comply54 receipt ✗ ESCALATE [nigeria/nfiu-aml] — MLPPA 2022
    assert payload.decision == "escalate"
    assert payload.pack == "nigeria/nfiu-aml"
"""

from ._digest import digest_input
from ._models import ReceiptPayload
from ._signer import ReceiptSigner
from ._verifier import InvalidReceiptError, verify_receipt

__all__ = [
    "ReceiptSigner",
    "ReceiptPayload",
    "verify_receipt",
    "InvalidReceiptError",
    "digest_input",
]
