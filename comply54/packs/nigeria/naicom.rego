# agt-policies-nigeria
# NAICOM — Nigeria Insurance Commission AI Agent Controls (Rego)
#
# Regulatory references:
#   Nigerian Insurance Industry Reform Act 2025 (NIIRA 2025)
#     — Signed into law by President Tinubu, August 2025
#     — Repeals and consolidates Insurance Act 2003 (Cap I17 LFN 2004),
#       Marine Insurance Act Cap M3, Motor Vehicles (Third Party Insurance) Act Cap M22,
#       National Insurance Corporation of Nigeria Act, and Nigerian Reinsurance Corporation Act
#     §210 — Claims settlement: all claims must be settled within 60 days of notification;
#             automated denial of claims ≥ ₦500,000 prohibited without human adjuster
#     §212 — Insurance Policyholders' Protection Fund: consumer protection in insurer insolvency
#     Part V — Market Conduct: prohibition on discriminatory underwriting factors
#             (religion, ethnicity, gender, disability, HIV status, political affiliation);
#             policy modification requires written policyholder notification and consent
#   NAICOM Operational Guidelines 2021
#     (Remain in force under NIIRA 2025 pending updated NAICOM regulations)
#     Guideline 12 — Claims above ₦2,000,000 require senior adjuster review
#     Guideline 15 — Automated denial of claims ≥ ₦500,000 prohibited
#     Guideline 18 — Life assurance underwriting > ₦5M requires human underwriter
#   NAICOM Market Conduct Guidelines 2023
#     (Remain in force under NIIRA 2025 pending updated NAICOM regulations)
#     Rule 6  — AI-generated quotes must not use discriminatory pricing factors
#     Rule 11 — Fraud investigations require human oversight
#   NFIU AML Guidelines (applicable to insurance sector)
#     Threshold — Premiums/claims > ₦5M trigger AML reporting duty
#   Nigeria Data Protection Act 2023 (NDPA 2023)
#     s.30  — Health/biometric data used in underwriting is special-category
#
# Input schema expected:
#   {
#     "action":  "approve_claim",
#     "params":  {
#       "claim_id":            "CLM-00123",
#       "claim_amount":        3500000,
#       "policy_type":         "life",       // "motor", "health", "fire", "marine"
#       "underwriting_amount": 6000000,
#       "fraud_score":         0.72,         // 0.0–1.0; >= 0.65 flagged
#       "discriminatory_field": "religion"   // prohibited characteristic
#     },
#     "output":  "agent output text",
#     "context": {
#       "human_adjuster_assigned": false,
#       "senior_approval":         false,
#       "human_underwriter":       false
#     }
#   }

package agt_policies_nigeria.naicom

import rego.v1

# ── Thresholds ────────────────────────────────────────────────────

# NAICOM Guideline 15: automated denial of claims this size is prohibited
auto_denial_cap := 500000

# NAICOM Guideline 12: claims above this require senior adjuster
senior_review_threshold := 2000000

# NAICOM Guideline 18: life underwriting above this requires human underwriter
life_underwriting_cap := 5000000

# NFIU / Insurance Act: AML reporting threshold
aml_reporting_threshold := 5000000

# Fraud score above this triggers escalation to investigation team
fraud_score_threshold := 0.65

# ── Action sets ───────────────────────────────────────────────────

claim_actions := {
	"approve_claim", "settle_claim",
	"process_claim_payment", "close_claim",
}

claim_denial_actions := {
	"deny_claim", "reject_claim",
	"decline_claim", "void_claim",
}

underwriting_actions := {
	"generate_quote", "calculate_premium",
	"underwrite_policy", "assess_risk",
}

policy_actions := {
	"cancel_policy", "lapse_policy",
	"update_policy", "amend_policy_terms",
}

fraud_actions := {
	"flag_fraud", "submit_fraud_report",
	"initiate_fraud_investigation",
}

# Prohibited characteristics: NIIRA 2025 Part V (Market Conduct) + NAICOM Market Conduct Rule 6
prohibited_characteristics := {
	"religion", "ethnicity", "tribe", "political_affiliation",
	"gender", "disability", "hiv_status",
}

# ── DENY rules ────────────────────────────────────────────────────

# NAICOM Guideline 15: AI cannot autonomously deny a claim of ₦500,000 or more
deny contains msg if {
	input.action in claim_denial_actions
	input.params.claim_amount >= auto_denial_cap
	not input.context.human_adjuster_assigned == true
	msg := sprintf(
		"NAICOM Guideline 15: AI cannot autonomously deny a claim of ₦%v — a human adjuster must be assigned (human_adjuster_assigned: true)",
		[input.params.claim_amount],
	)
}

# NIIRA 2025 Part V (Market Conduct) / NAICOM Market Conduct Rule 6:
# Pricing or underwriting must not use discriminatory characteristics
deny contains msg if {
	input.action in underwriting_actions
	some field in prohibited_characteristics
	input.params[field] != null
	msg := sprintf(
		"NIIRA 2025 Part V / NAICOM Rule 6: Underwriting or quote uses prohibited discriminatory characteristic '%v' — remove this field",
		[field],
	)
}

# NAICOM Guideline 18: Life insurance underwriting > ₦5M cannot be fully automated
deny contains msg if {
	input.action in underwriting_actions
	input.params.policy_type == "life"
	input.params.underwriting_amount > life_underwriting_cap
	not input.context.human_underwriter == true
	msg := sprintf(
		"NAICOM Guideline 18: Life assurance underwriting of ₦%v exceeds ₦5,000,000 — a licensed human underwriter is required (human_underwriter: true)",
		[input.params.underwriting_amount],
	)
}

# ── ESCALATE rules ────────────────────────────────────────────────

# NAICOM Guideline 12: Claims above ₦2M must go to senior adjuster
escalate contains msg if {
	input.action in claim_actions
	input.params.claim_amount > senior_review_threshold
	not input.context.senior_approval == true
	msg := sprintf(
		"NAICOM Guideline 12: Claim of ₦%v exceeds ₦2,000,000 — requires senior adjuster review and approval before settlement",
		[input.params.claim_amount],
	)
}

# NAICOM Market Conduct Rule 11: Fraud investigation must involve a human investigator
escalate contains msg if {
	input.action in fraud_actions
	msg := "NAICOM Rule 11: Fraud investigation must be handled by a human investigator — AI may flag but cannot conclude"
}

# Fraud score threshold: automatically escalate high-fraud-probability claims
escalate contains msg if {
	input.action in claim_actions
	input.params.fraud_score > fraud_score_threshold
	msg := sprintf(
		"NAICOM / Anti-Fraud Controls: Claim fraud score %.2f exceeds threshold %.2f — escalated to fraud investigation team",
		[input.params.fraud_score, fraud_score_threshold],
	)
}

# NIIRA 2025 Part V: Policy cancellation / amendment must be communicated — escalate for human notification
escalate contains msg if {
	input.action in policy_actions
	msg := "NIIRA 2025 Part V: Policy modification requires written policyholder notification and human verification before execution"
}

# NFIU AML: Large premiums/claims above ₦5M trigger AML reporting duty
escalate contains msg if {
	input.action in claim_actions
	input.params.claim_amount > aml_reporting_threshold
	msg := sprintf(
		"NFIU AML Guidelines: Claim of ₦%v exceeds ₦5,000,000 AML reporting threshold — file Suspicious Transaction Report if warranted",
		[input.params.claim_amount],
	)
}

# NAICOM Guideline 15: Even claim amounts below auto_denial_cap should be escalated for first denial
escalate contains msg if {
	input.action in claim_denial_actions
	input.params.claim_amount < auto_denial_cap
	msg := sprintf(
		"NAICOM Fair Claims Practice: Denial of claim (₦%v) escalated for human review — customer must be notified with specific grounds for denial",
		[input.params.claim_amount],
	)
}

# NIIRA 2025 §210: Claims pending beyond 60 days must be escalated — zero-tolerance for delay
escalate contains msg if {
	input.action in claim_actions
	input.params.days_pending > 60
	msg := sprintf(
		"NIIRA 2025 §210: Claim has been pending %v days — 60-day settlement deadline exceeded; escalate to senior adjuster and notify NAICOM",
		[input.params.days_pending],
	)
}

# ── AUDIT rules ───────────────────────────────────────────────────

# NAICOM Records Requirement: All claims decisions must be logged (NIIRA 2025 §210)
audit contains msg if {
	input.action in claim_actions
	msg := "NAICOM Records (NIIRA 2025 §210): Claim settlement decision logged — mandatory for NAICOM examination and consumer protection records"
}

audit contains msg if {
	input.action in claim_denial_actions
	msg := "NAICOM Records (NIIRA 2025 §210): Claim denial logged — policyholder has right to written reasons and appeal under NIIRA 2025"
}

# All underwriting decisions must be logged
audit contains msg if {
	input.action in underwriting_actions
	msg := "NAICOM Records: Underwriting decision logged — required for actuarial review and NAICOM regulatory examination"
}

# ── Citation key sets ─────────────────────────────────────────────

deny_citations contains key if {
	input.action in claim_denial_actions
	input.params.claim_amount >= auto_denial_cap
	not input.context.human_adjuster_assigned == true
	key := "auto_denial_cap"
}

deny_citations contains key if {
	input.action in underwriting_actions
	some field in prohibited_characteristics
	input.params[field] != null
	key := "discrimination"
}

deny_citations contains key if {
	input.action in underwriting_actions
	input.params.policy_type == "life"
	input.params.underwriting_amount > life_underwriting_cap
	not input.context.human_underwriter == true
	key := "life_underwriting_cap"
}

escalate_citations contains key if {
	input.action in claim_actions
	input.params.claim_amount > senior_review_threshold
	not input.context.senior_approval == true
	key := "senior_review"
}

escalate_citations contains key if {
	input.action in fraud_actions
	key := "fraud_human"
}

escalate_citations contains key if {
	input.action in claim_actions
	input.params.fraud_score > fraud_score_threshold
	key := "fraud_score"
}

escalate_citations contains key if {
	input.action in policy_actions
	key := "policy_modification"
}

escalate_citations contains key if {
	input.action in claim_actions
	input.params.claim_amount > aml_reporting_threshold
	key := "aml_threshold"
}

escalate_citations contains key if {
	input.action in claim_denial_actions
	input.params.claim_amount < auto_denial_cap
	key := "sub_cap_denial"
}

escalate_citations contains key if {
	input.action in claim_actions
	input.params.days_pending > 60
	key := "niira_60day_deadline"
}

audit_citations contains key if {
	input.action in claim_actions
	key := "claims_decision"
}

audit_citations contains key if {
	input.action in claim_denial_actions
	key := "claims_denial_log"
}

audit_citations contains key if {
	input.action in underwriting_actions
	key := "underwriting_decision"
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
