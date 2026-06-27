"""
Mock Nigerian fintech tools for the comply54 LangGraph demo.

These are realistic tool definitions — the agent calls them normally.
comply54 intercepts each call BEFORE execution and blocks anything
that violates CBN, NDPA, or NFIU rules.
"""

from __future__ import annotations

import random
import string
from typing import Optional

from langchain_core.tools import tool


def _txn_ref() -> str:
    return "TXN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))


@tool
def transfer_funds(
    amount: float,
    currency: str,
    recipient_account: str,
    description: str = "",
    destination_country: str = "NG",
) -> str:
    """
    Transfer funds from the customer's account to a recipient.

    Args:
        amount:             Amount to transfer (in the given currency).
        currency:           Currency code, e.g. "NGN", "USD".
        recipient_account:  Recipient's account number or IBAN.
        description:        Optional payment reference/narration.
        destination_country: ISO 3166-1 alpha-2 country code of the recipient.

    Returns:
        Transfer confirmation with transaction reference.
    """
    ref = _txn_ref()
    return (
        f"Transfer confirmed. Reference: {ref}. "
        f"Amount: {currency} {amount:,.2f} → Account {recipient_account} "
        f"({destination_country}). Narration: '{description or 'N/A'}'."
    )


@tool
def check_balance(account_id: str) -> str:
    """
    Retrieve the current account balance for a given account.

    Args:
        account_id: The account number to query.

    Returns:
        Current available and ledger balances.
    """
    return (
        f"Account {account_id}: "
        f"Ledger balance = ₦2,450,000.00 | "
        f"Available balance = ₦2,400,000.00 | "
        f"Currency: NGN | Status: Active"
    )


@tool
def get_account_details(account_id: str) -> str:
    """
    Retrieve KYC and account details for a given account.

    Args:
        account_id: The account number to look up.

    Returns:
        Account holder details including KYC tier.
    """
    return (
        f"Account {account_id}: "
        f"Holder: Emeka Okonkwo | "
        f"KYC Tier: 3 (fully verified) | "
        f"BVN: 2234****789 | "
        f"Account type: Current | "
        f"Opened: 2021-03-15"
    )


@tool
def approve_transfer(transfer_reference: str, approver_notes: str = "") -> str:
    """
    Approve a pending transfer request.

    Args:
        transfer_reference: The TXN reference to approve.
        approver_notes:     Optional notes from the approver.

    Returns:
        Approval confirmation.
    """
    return (
        f"Transfer {transfer_reference} approved. "
        f"Notes: '{approver_notes or 'None'}'. "
        f"Funds will be disbursed in the next settlement window."
    )


@tool
def get_transaction_history(
    account_id: str,
    limit: int = 10,
    from_date: Optional[str] = None,
) -> str:
    """
    Retrieve recent transaction history for an account.

    Args:
        account_id: The account number to query.
        limit:      Maximum number of transactions to return (default 10).
        from_date:  Optional start date filter (YYYY-MM-DD).

    Returns:
        List of recent transactions.
    """
    return (
        f"Last {limit} transactions for account {account_id} "
        f"(from {from_date or 'all time'}): "
        f"[1] 2026-06-20 — Transfer OUT ₦50,000 → ACC-9988776 | "
        f"[2] 2026-06-18 — Transfer IN ₦200,000 ← ACC-1122334 | "
        f"[3] 2026-06-15 — Bill payment ₦15,000 → DSTV"
    )


# Exported tool list for the agent
FINTECH_TOOLS = [
    transfer_funds,
    check_balance,
    get_account_details,
    approve_transfer,
    get_transaction_history,
]
