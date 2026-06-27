"""
Mock Nigerian healthcare tools for the comply54 LangGraph demo.

These represent tools an EHR / clinical decision support AI agent might call.
comply54 intercepts each call BEFORE execution and blocks anything that
violates NHA 2014, NDPA 2023 (special-category health data), or FMOH AI Policy.
"""

from __future__ import annotations

import random
import string
from typing import Optional

from langchain_core.tools import tool


def _record_ref() -> str:
    return "EHR-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))


@tool
def access_patient_records(
    patient_id: str,
    record_type: str = "summary",
    purpose: str = "treatment",
) -> str:
    """
    Retrieve a patient's electronic health record.

    Args:
        patient_id:  The unique patient identifier.
        record_type: Type of record — "summary", "full_ehr", "lab_results", "imaging".
        purpose:     Reason for access — "treatment", "research", "audit", "billing".

    Returns:
        Patient health record data.
    """
    return (
        f"Patient {patient_id} — {record_type.replace('_', ' ').title()}: "
        f"DOB: 1985-04-12 | Blood type: O+ | Allergies: Penicillin | "
        f"Last visit: 2026-05-10 | Primary diagnosis: Hypertension (ICD-10: I10) | "
        f"Current medications: Amlodipine 5mg | Access purpose: {purpose}"
    )


@tool
def share_health_data(
    patient_id: str,
    recipient_provider: str,
    data_type: str = "referral_summary",
    destination_country: str = "NG",
) -> str:
    """
    Share patient health data with another healthcare provider or institution.

    Args:
        patient_id:          The patient whose data is being shared.
        recipient_provider:  Name or ID of the receiving healthcare provider.
        data_type:           Type of data being shared ("referral_summary", "full_record", "lab_results").
        destination_country: Country of receiving provider (ISO 3166-1 alpha-2).

    Returns:
        Confirmation of data transfer.
    """
    ref = _record_ref()
    return (
        f"Health data shared. Transfer ref: {ref}. "
        f"Patient {patient_id} — {data_type} sent to {recipient_provider} ({destination_country})."
    )


@tool
def generate_diagnosis(
    patient_id: str,
    symptoms: str,
    clinical_notes: str = "",
) -> str:
    """
    Generate an AI-assisted clinical assessment based on symptoms and notes.

    Args:
        patient_id:     Patient identifier.
        symptoms:       Comma-separated list of presenting symptoms.
        clinical_notes: Additional notes from clinician or triage.

    Returns:
        AI-generated differential diagnosis and recommended next steps.
    """
    return (
        f"AI Clinical Assessment for {patient_id}: "
        f"Presenting symptoms: {symptoms}. "
        f"Differential diagnosis: (1) Hypertensive crisis [HIGH], (2) Anxiety disorder [MEDIUM]. "
        f"Recommended: BP measurement, ECG, refer to cardiologist. "
        f"IMPORTANT: This is AI-assisted only — requires clinician review before communication to patient."
    )


@tool
def prescribe_medication(
    patient_id: str,
    medication: str,
    dosage: str,
    duration_days: int = 7,
) -> str:
    """
    Issue a medication prescription for a patient.

    Args:
        patient_id:    Patient identifier.
        medication:    Medication name.
        dosage:        Dosage instructions (e.g. "5mg once daily").
        duration_days: Duration of prescription in days.

    Returns:
        Prescription confirmation with reference.
    """
    ref = "RX-" + "".join(random.choices(string.digits, k=8))
    return (
        f"Prescription {ref}: {medication} {dosage} for {duration_days} days. "
        f"Patient: {patient_id}. "
        f"Dispensing instructions sent to pharmacy."
    )


@tool
def create_referral(
    patient_id: str,
    referring_to: str,
    referral_reason: str,
    urgency: str = "routine",
) -> str:
    """
    Create a patient referral to another clinician or specialist.

    Args:
        patient_id:      Patient identifier.
        referring_to:    Specialist or facility name.
        referral_reason: Clinical reason for referral.
        urgency:         "routine", "urgent", or "emergency".

    Returns:
        Referral letter reference and next steps.
    """
    ref = "REF-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return (
        f"Referral {ref} created. Patient {patient_id} referred to {referring_to}. "
        f"Reason: {referral_reason}. Urgency: {urgency}. "
        f"Patient will be contacted within 48 hours."
    )


@tool
def get_lab_results(
    patient_id: str,
    test_type: Optional[str] = None,
) -> str:
    """
    Retrieve laboratory test results for a patient.

    Args:
        patient_id: Patient identifier.
        test_type:  Optional specific test type (e.g. "FBC", "LFT", "HbA1c").

    Returns:
        Lab test results.
    """
    return (
        f"Lab results for {patient_id} ({test_type or 'all recent'}): "
        f"FBC — Hb: 13.2 g/dL (Normal) | WBC: 6.4 x10⁹/L (Normal) | "
        f"HbA1c: 7.2% (Elevated — review diabetes management) | "
        f"Creatinine: 88 µmol/L (Normal). Reported: 2026-06-20."
    )


HEALTH_TOOLS = [
    access_patient_records,
    share_health_data,
    generate_diagnosis,
    prescribe_medication,
    create_referral,
    get_lab_results,
]
