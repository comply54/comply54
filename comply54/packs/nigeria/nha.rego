# agt-policies-nigeria
# Nigeria National Health Act 2014 — Healthcare AI Agent Controls (Rego)
#
# Regulatory references:
#   Nigeria National Health Act 2014 (NHA 2014)
#     s.26  — Patient consent required before processing health records
#     s.29  — Confidentiality: health worker must not disclose patient info
#     s.30  — Prohibition on unqualified clinical practice
#   Nigeria Data Protection Act 2023 (NDPA 2023)
#     s.30  — Special-category data: health data requires explicit consent
#     s.25  — Cross-border transfer restrictions apply with added weight
#   Medical and Dental Practitioners Act Cap M8 LFN 2004
#     s.16  — Only registered practitioners may diagnose / prescribe
#   Federal Ministry of Health AI in Healthcare Policy (Draft 2024)
#     Guideline 4 — Human clinician must review AI-generated diagnoses
#     Guideline 7 — No autonomous prescription of controlled substances
#
# Rego advantage over YAML:
#   Checks input.context.consent_documented, input.context.licensed_clinician_approval
#   directly without regex on natural-language output — avoids bypass via rewording.
#
# Input schema expected:
#   {
#     "action":  "access_patient_records",
#     "params":  {
#       "patient_id":          "P-12345",
#       "record_type":         "full_ehr",       // or "summary", "lab_results"
#       "destination_country": "US",              // for cross-border sharing
#       "record_count":        1
#     },
#     "output":  "agent output text",
#     "context": {
#       "consent_documented":         true,
#       "licensed_clinician_approval": false,
#       "human_clinician_oversight":  false,
#       "purpose":                    "treatment"  // or "research", "audit"
#     }
#   }

package agt_policies_nigeria.nha

import rego.v1

# ── Action sets ───────────────────────────────────────────────────

record_access_actions := {
	"access_patient_records", "read_health_record",
	"get_patient_history", "fetch_lab_results",
	"retrieve_ehr", "query_medical_records",
}

data_sharing_actions := {
	"share_health_data", "send_patient_report",
	"export_health_records", "forward_to_provider",
	"upload_clinical_data", "relay_health_info",
}

cross_border_sharing_actions := {
	"share_health_data", "export_health_records",
	"upload_clinical_data", "send_patient_report",
}

diagnosis_actions := {
	"generate_diagnosis", "assess_symptoms",
	"interpret_scan", "read_pathology",
	"produce_clinical_assessment",
}

prescription_actions := {
	"prescribe_medication", "issue_prescription",
	"recommend_dosage", "update_prescription",
}

high_risk_clinical_actions := {
	"approve_surgery", "authorise_procedure",
	"consent_to_intervention", "clear_for_operation",
}

# ── DENY rules ────────────────────────────────────────────────────

# NHA s.26 / NDPA s.30: Accessing health records without documented patient consent is prohibited
deny contains msg if {
	input.action in record_access_actions
	not input.context.consent_documented == true
	msg := "NHA s.26 / NDPA s.30: Access to patient health records requires documented patient consent — consent_documented must be true"
}

# NHA s.29: Sharing patient data with third parties without explicit consent is prohibited
deny contains msg if {
	input.action in data_sharing_actions
	not input.context.consent_documented == true
	msg := "NHA s.29: Health data disclosure to third parties requires explicit patient consent — consent_documented must be true"
}

# NDPA s.25 + NHA s.29: Cross-border health data transfer to non-NG country blocked
# Health data is special-category under NDPA; cross-border requires adequacy assessment + consent
deny contains msg if {
	input.action in cross_border_sharing_actions
	input.params.destination_country != null
	not input.params.destination_country in {"NG", "ng"}
	msg := sprintf(
		"NDPA s.25 + NHA s.29: Cross-border transfer of health data to '%v' is prohibited — special-category data requires adequacy approval",
		[input.params.destination_country],
	)
}

# Medical & Dental Practitioners Act s.16 / FMOH AI Guideline 4:
# AI cannot produce a standalone clinical diagnosis without human clinician oversight
deny contains msg if {
	input.action in diagnosis_actions
	not input.context.human_clinician_oversight == true
	msg := "FMOH AI Guideline 4 / MDP Act s.16: AI-generated diagnosis requires human clinician oversight — set human_clinician_oversight: true"
}

# Medical & Dental Practitioners Act s.16 / FMOH Guideline 7:
# AI cannot prescribe medication — only a licensed, registered practitioner may do so
deny contains msg if {
	input.action in prescription_actions
	not input.context.licensed_clinician_approval == true
	msg := "MDP Act s.16 / FMOH Guideline 7: AI cannot prescribe medication without licensed clinician approval — set licensed_clinician_approval: true"
}

# ── ESCALATE rules ────────────────────────────────────────────────

# FMOH Guideline 4: Any AI-assisted diagnosis must be routed to a clinician for sign-off
escalate contains msg if {
	input.action in diagnosis_actions
	input.context.human_clinician_oversight == true
	msg := "FMOH AI Guideline 4: AI-assisted diagnosis must be reviewed and signed off by a licensed clinician before communication to patient"
}

# NHA s.26: High-risk clinical decisions (surgical consent, procedures) require human doctor
escalate contains msg if {
	input.action in high_risk_clinical_actions
	msg := "NHA s.26 / Clinical Safety: High-risk clinical action requires authorisation by a registered medical practitioner"
}

# NHA: Research use of patient data requires ethics committee review
escalate contains msg if {
	input.action in record_access_actions
	input.context.purpose == "research"
	msg := "NHA 2014 / NDPC Guidelines: Use of patient records for research purpose requires ethics committee review and approval"
}

# Bulk health record access always requires a data protection officer review
escalate contains msg if {
	input.action in record_access_actions
	input.params.record_count > 10
	msg := sprintf(
		"NDPA s.30: Bulk access to %v patient records (special-category data) requires Data Protection Officer review",
		[input.params.record_count],
	)
}

# ── AUDIT rules ───────────────────────────────────────────────────

# NHA s.26 / NDPA: All access to patient health records must be logged
audit contains msg if {
	input.action in record_access_actions
	msg := "NHA s.26 / NDPA Audit: Patient health record access logged — mandatory for NHA compliance and NDPC examination"
}

# All clinical AI decisions must be logged (FMOH AI Policy)
audit contains msg if {
	input.action in diagnosis_actions
	msg := "FMOH AI Policy: AI clinical decision logged — required for regulatory review and medical audit trail"
}

# ── Decision summary ──────────────────────────────────────────────

decision := "deny" if count(deny) > 0

decision := "escalate" if {
	count(deny) == 0
	count(escalate) > 0
}

decision := "audit" if {
	count(deny) == 0
	count(escalate) == 0
	count(audit) > 0
}

decision := "allow" if {
	count(deny) == 0
	count(escalate) == 0
	count(audit) == 0
}
