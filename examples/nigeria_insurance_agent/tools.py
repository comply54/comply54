"""
Mock Nigerian insurance tools for the comply54 LangGraph demo.

These represent tools a claims processing / underwriting AI agent might call.
comply54 intercepts each call BEFORE execution and blocks anything that
violates NAICOM 2021/2023, Insurance Act 2003, NFIU AML, or NDPA 2023.
"""

from __future__ import annotations

import random
import string
from typing import Optional

from langchain_core.tools import tool


def _claim_ref() -> str:
    return "CLM-" + "".join(random.choices(string.digits, k=8))


def _policy_ref() -> str:
    return "POL-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))


@tool
def generate_quote(
    applicant_id: str,
    policy_type: str,
    coverage_amount: float,
    age: Optional[int] = None,
    occupation: Optional[str] = None,
) -> str:
    """
    Generate an insurance premium quote for an applicant.

    Args:
        applicant_id:     Applicant unique identifier.
        policy_type:      "motor", "health", "life", "fire", "marine".
        coverage_amount:  Sum insured in NGN.
        age:              Applicant's age (optional, legitimate underwriting factor).
        occupation:       Applicant's occupation (legitimate underwriting factor).

    Returns:
        Insurance quote with premium and terms.
    """
    base_rate = 0.02
    premium = coverage_amount * base_rate
    ref = _policy_ref()
    return (
        f"Quote {ref}: {policy_type.title()} insurance for {applicant_id}. "
        f"Coverage: ₦{coverage_amount:,.0f}. Annual premium: ₦{premium:,.2f}. "
        f"Valid 30 days. Terms subject to underwriter review."
    )


@tool
def approve_claim(
    claim_id: str,
    claim_amount: float,
    adjuster_notes: str = "",
) -> str:
    """
    Approve and settle an insurance claim.

    Args:
        claim_id:       The claim reference number.
        claim_amount:   Approved settlement amount in NGN.
        adjuster_notes: Notes from the claims adjuster.

    Returns:
        Claim approval confirmation and payment timeline.
    """
    return (
        f"Claim {claim_id} approved. Settlement: ₦{claim_amount:,.2f}. "
        f"Notes: '{adjuster_notes or 'Standard processing'}'. "
        f"Payment will be disbursed within 5 working days per NAICOM Guideline 12."
    )


@tool
def deny_claim(
    claim_id: str,
    claim_amount: float,
    denial_reason: str,
) -> str:
    """
    Deny an insurance claim.

    Args:
        claim_id:       The claim reference number.
        claim_amount:   Claimed amount (for reference).
        denial_reason:  Specific grounds for denial (mandatory under Insurance Act).

    Returns:
        Denial notice with appeal rights.
    """
    return (
        f"Claim {claim_id} (₦{claim_amount:,.0f}) denied. "
        f"Reason: {denial_reason}. "
        f"Policyholder notified with written grounds. "
        f"Appeal window: 30 days (Insurance Act s.70)."
    )


@tool
def flag_fraud(
    claim_id: str,
    fraud_indicators: str,
    fraud_score: float,
) -> str:
    """
    Flag an insurance claim for suspected fraud investigation.

    Args:
        claim_id:          The claim reference number.
        fraud_indicators:  Description of suspicious patterns observed.
        fraud_score:       AI fraud probability score (0.0–1.0).

    Returns:
        Fraud flag confirmation and investigation reference.
    """
    inv_ref = "INV-" + "".join(random.choices(string.digits, k=6))
    return (
        f"Claim {claim_id} flagged for fraud investigation. "
        f"Investigation ref: {inv_ref}. Fraud score: {fraud_score:.2f}. "
        f"Indicators: {fraud_indicators}. "
        f"Assigned to Special Investigations Unit per NAICOM Rule 11."
    )


@tool
def cancel_policy(
    policy_id: str,
    reason: str,
    effective_date: str,
) -> str:
    """
    Cancel an insurance policy.

    Args:
        policy_id:      The policy reference number.
        reason:         Reason for cancellation.
        effective_date: Date cancellation takes effect (YYYY-MM-DD).

    Returns:
        Cancellation confirmation and refund details.
    """
    return (
        f"Policy {policy_id} cancellation initiated. "
        f"Effective: {effective_date}. Reason: {reason}. "
        f"Policyholder notification dispatched. "
        f"Pro-rata refund calculated per Insurance Act s.50."
    )


@tool
def get_claim_status(
    claim_id: str,
) -> str:
    """
    Retrieve the current status and details of an insurance claim.

    Args:
        claim_id: The claim reference number.

    Returns:
        Current claim status, amount, and processing stage.
    """
    return (
        f"Claim {claim_id}: Status — Under Review. "
        f"Submitted: 2026-06-15 | Amount: ₦1,200,000 | "
        f"Policy type: Motor comprehensive | "
        f"Current stage: Adjuster assigned — awaiting site inspection report."
    )


INSURANCE_TOOLS = [
    generate_quote,
    approve_claim,
    deny_claim,
    flag_fraud,
    cancel_policy,
    get_claim_status,
]
