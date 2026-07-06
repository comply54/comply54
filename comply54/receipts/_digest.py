"""
comply54.receipts._digest
~~~~~~~~~~~~~~~~~~~~~~~~~
Deterministic SHA-256 digest of a comply54 evaluation input.

The digest ties a signed receipt to the exact input that was evaluated,
allowing offline verification that the receipt covers the input under
inspection — not a different call with the same decision.
"""

from __future__ import annotations

import hashlib
import json


def digest_input(
    action: str,
    params: dict,
    output: str = "",
    context: dict | None = None,
) -> str:
    """
    Return a deterministic SHA-256 digest of a comply54 evaluation input.

    The digest is formatted as ``sha256:<hex>`` so it is self-describing
    and forward-compatible if the hash algorithm ever changes.

    Determinism guarantees:
    - ``json.dumps(..., sort_keys=True)`` — dict key order is normalised.
    - ``separators=(",", ":")`` — no whitespace between tokens.
    - UTF-8 encoding — consistent on all platforms.

    Args:
        action:  The tool/action name passed to ``check()`` or ``evaluate()``.
        params:  The ``params`` dict from the same call.
        output:  The ``output`` string from the same call (default ``""``).
        context: The ``context`` dict from the same call (default ``{}``).

    Returns:
        ``"sha256:<64-char hex>"``

    Example:
        digest = digest_input(
            action="transfer_funds",
            params={"amount": 5_000_000, "currency": "NGN"},
            context={"sanctions_screened": True},
        )
        # "sha256:a3f9c2b1..."
    """
    payload = {
        "action": action,
        "params": params,
        "output": output,
        "context": context or {},
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
