# agt-policies-nigeria
# BVN / NIN Data Protection Policy (Rego)
#
# Regulatory references:
#   CBN BVN Policy Framework (2014, updated 2023)
#   NIMC Act 2026 (signed 26 June 2026 — repeals NIMC Act Cap N99 LFN 2004)
#     - Purpose limitation: NIN may only be used for the stated purpose at collection
#     - Illegal data persistence: NIN must not be stored after verification completes
#     - Mandatory NIN: bank accounts, SIM, passports, land, pensions, insurance, credit
#     - Penalties: ₦20 million (corporate) / 5 years min. imprisonment (individual)
#   NDPA 2023 Schedule 1 — biometric data as sensitive personal data
#
# Rego advantage over YAML:
#   Can check structured fields (input.params.bvn_present, input.params.identifier_type)
#   alongside output pattern matching — two-layer enforcement.
#
# Input schema expected:
#   {
#     "action":  "verify_bvn",
#     "params":  { "bvn": "22345678901", "bvn_present": true, "identifier_type": "BVN" },
#     "output":  "agent output text",
#     "context": { "channel": "whatsapp", "purpose": "refund_verification",
#                  "nin_verified": true, "nin_consented_purpose": "account_opening" }
#   }

package agt_policies_nigeria.bvn_nin

import rego.v1

# ── Verification actions ──────────────────────────────────────────
bvn_verification_actions := {
	"verify_bvn", "check_bvn", "validate_bvn",
	"bvn_lookup", "nibss_bvn_verify",
}

nin_verification_actions := {
	"verify_nin", "check_nin", "validate_nin",
	"nin_lookup", "nimc_nin_verify",
}

transmission_actions := {
	"send_bvn", "transmit_bvn", "share_bvn",
	"send_nin", "transmit_nin", "share_nin",
	"post_identity", "relay_kyc",
}

# NIMC Act 2026: illegal data persistence actions
persist_actions := {
	"store_nin", "save_nin_data", "persist_identity",
	"cache_nin", "log_nin", "record_nin", "write_nin_record",
	"store_bvn", "save_bvn_data", "cache_bvn",
}

# NIMC Act 2026: services requiring verified NIN before proceeding
mandatory_nin_service_actions := {
	"open_account", "create_account", "register_voter",
	"apply_passport", "sim_registration", "land_registration",
	"pension_enrollment", "insurance_enrollment", "apply_credit",
	"tax_registration", "apply_government_service",
}

# NIMC Act 2026: bulk NIN / identity data export
bulk_export_actions := {
	"export_nin_data", "bulk_nin_export", "download_nin_records",
	"extract_identity_records", "bulk_identity_export",
}

# ── Deny rules ────────────────────────────────────────────────────

# Block BVN value in agent output (label + digits pattern)
deny contains msg if {
	regex.match(`(?i)(bvn\s+is|bvn:\s*|bvn\s*=|your\s+bvn|the\s+bvn)[\s:]*[0-9]{10,11}`, input.output)
	msg := "BVN Protection: BVN value detected in agent output — blocked (NDPA Schedule 1 biometric data)"
}

# Block contextual BVN pattern in output
deny contains msg if {
	regex.match(`(?i)(bvn|bank\s+verification).{0,20}\b[0-9]{11}\b`, input.output)
	msg := "BVN Protection: BVN pattern detected in agent output — blocked to prevent credential exposure"
}

# Block NIN value in agent output
deny contains msg if {
	regex.match(`(?i)(nin\s+is|nin:\s*|nin\s*=|your\s+nin|the\s+nin)[\s:]*[0-9]{10,11}`, input.output)
	msg := "NIN Protection: NIN value detected in agent output — blocked (NDPA Schedule 1 biometric data)"
}

# Block virtual NIN (vNIN) in output
deny contains msg if {
	regex.match(`(?i)(vnin|virtual\s+nin)[\s:=]+[A-Z0-9]{16}`, input.output)
	msg := "NIN Protection: Virtual NIN (vNIN) detected in agent output — blocked"
}

# Block direct BVN/NIN transmission to external systems
deny contains msg if {
	input.action in transmission_actions
	msg := "BVN/NIN Transmission: Direct BVN/NIN transmission blocked — use NIBSS tokenised verification flow"
}

# Block BVN present in params from being passed externally
deny contains msg if {
	input.params.bvn_present == true
	input.action in transmission_actions
	msg := "BVN/NIN Transmission: BVN detected in params with external transmission action — blocked"
}

# Block BVN disclosure over conversational channels (social engineering)
deny contains msg if {
	regex.match(`(?i)(customer\s+(wants|needs|asked|requested).{0,30}(bvn|nin)|confirm.{0,20}(bvn|nin).{0,20}(over|via|through)\s+(chat|call|whatsapp|email|sms))`, input.output)
	msg := "BVN/NIN Social Engineering: Attempt to disclose BVN/NIN through conversational channel — blocked"
}

# ── Escalate rules ────────────────────────────────────────────────

# BVN verification always requires human approval
escalate contains msg if {
	input.action in bvn_verification_actions
	msg := "BVN Verification: BVN lookup requires human approval — CBN BVN Framework mandates audit trail for all lookups"
}

# NIN verification always requires human approval
escalate contains msg if {
	input.action in nin_verification_actions
	msg := "NIN Verification: NIN lookup requires human approval — NIMC Act requires documented purpose for each lookup"
}

# Escalate if identifier type is BVN/NIN in params
escalate contains msg if {
	input.params.identifier_type in {"BVN", "NIN", "bvn", "nin"}
	not input.action in transmission_actions # transmission is deny, not escalate
	msg := sprintf(
		"BVN/NIN Gate: Action '%v' involves %v identifier — requires human approval before proceeding",
		[input.action, input.params.identifier_type],
	)
}

# ── Audit rules ───────────────────────────────────────────────────

# All identity-related actions must be logged
_action_has_identity_pattern if {
	some pattern in {"bvn", "nin", "kyc", "identity_verify"}
	contains(input.action, pattern)
}

audit contains msg if {
	_action_has_identity_pattern
	msg := "BVN/NIN Audit: Identity-related action logged — NDPA s.30 and CBN BVN audit trail requirement"
}

# ── NIMC Act 2026: New obligations ───────────────────────────────

# Deny: illegal NIN/BVN data persistence (NIMC Act 2026)
deny contains msg if {
	input.action in persist_actions
	msg := "NIMC Act 2026: Storing NIN/BVN data after verification is prohibited — illegal data persistence (₦20M corporate / 5yr individual penalty)"
}

# Deny: illegal NIN/BVN data persistence via params flag
deny contains msg if {
	input.params.persist_nin == true
	msg := "NIMC Act 2026: persist_nin=true flag detected — NIN data may not be stored after verification completes"
}

# Deny: bulk NIN/identity data export (NIMC Act 2026)
deny contains msg if {
	input.action in bulk_export_actions
	msg := "NIMC Act 2026: Bulk NIN/identity data export is prohibited — only individual authorised verifications are permitted"
}

# Deny: bulk export via params flag
deny contains msg if {
	input.params.bulk_identity_export == true
	msg := "NIMC Act 2026: bulk_identity_export=true detected — bulk NIN data extraction is prohibited"
}

# Escalate: NIN/BVN access without a declared purpose (NIMC Act 2026 purpose limitation)
escalate contains msg if {
	input.action in nin_verification_actions
	not input.context.nin_purpose
	msg := "NIMC Act 2026: NIN lookup attempted without a declared purpose — purpose limitation requires stating the reason before each verification"
}

escalate contains msg if {
	input.action in bvn_verification_actions
	not input.context.nin_purpose
	msg := "NIMC Act 2026: BVN/NIN lookup attempted without a declared purpose — purpose limitation requires stating the reason before each verification"
}

# Escalate: NIN used for a purpose that differs from the one consented to
escalate contains msg if {
	input.context.nin_consented_purpose != ""
	input.context.purpose != ""
	input.context.nin_consented_purpose != input.context.purpose
	msg := sprintf(
		"NIMC Act 2026: Purpose mismatch — NIN consent was granted for '%v' but action context declares purpose '%v'",
		[input.context.nin_consented_purpose, input.context.purpose],
	)
}

# Audit: mandatory-NIN service attempted without verified NIN (NIMC Act 2026)
audit contains msg if {
	input.action in mandatory_nin_service_actions
	not input.context.nin_verified
	msg := sprintf(
		"NIMC Act 2026: Action '%v' is a mandatory-NIN service — NIN must be verified before proceeding (bank accounts, SIM, passports, land, pension, insurance, credit)",
		[input.action],
	)
}

# ── Citation key sets ─────────────────────────────────────────────

deny_citations contains key if {
	regex.match(`(?i)(bvn\s+is|bvn:\s*|bvn\s*=|your\s+bvn|the\s+bvn)[\s:]*[0-9]{10,11}`, input.output)
	key := "bvn_label_pattern"
}

deny_citations contains key if {
	regex.match(`(?i)(bvn|bank\s+verification).{0,20}\b[0-9]{11}\b`, input.output)
	key := "bvn_contextual_pattern"
}

deny_citations contains key if {
	regex.match(`(?i)(nin\s+is|nin:\s*|nin\s*=|your\s+nin|the\s+nin)[\s:]*[0-9]{10,11}`, input.output)
	key := "nin_label_pattern"
}

deny_citations contains key if {
	regex.match(`(?i)(vnin|virtual\s+nin)[\s:=]+[A-Z0-9]{16}`, input.output)
	key := "vnin_pattern"
}

deny_citations contains key if {
	input.action in transmission_actions
	key := "bvn_nin_transmission"
}

deny_citations contains key if {
	input.params.bvn_present == true
	input.action in transmission_actions
	key := "bvn_in_params"
}

deny_citations contains key if {
	regex.match(`(?i)(customer\s+(wants|needs|asked|requested).{0,30}(bvn|nin)|confirm.{0,20}(bvn|nin).{0,20}(over|via|through)\s+(chat|call|whatsapp|email|sms))`, input.output)
	key := "bvn_social_engineering"
}

deny_citations contains key if {
	input.action in persist_actions
	key := "nimc_nin_persistence"
}

deny_citations contains key if {
	input.params.persist_nin == true
	key := "nimc_nin_persistence"
}

deny_citations contains key if {
	input.action in bulk_export_actions
	key := "nimc_nin_bulk_export"
}

deny_citations contains key if {
	input.params.bulk_identity_export == true
	key := "nimc_nin_bulk_export"
}

escalate_citations contains key if {
	input.action in bvn_verification_actions
	key := "bvn_verification"
}

escalate_citations contains key if {
	input.action in nin_verification_actions
	key := "nin_verification"
}

escalate_citations contains key if {
	input.params.identifier_type in {"BVN", "NIN", "bvn", "nin"}
	not input.action in transmission_actions
	key := "identifier_gate"
}

escalate_citations contains key if {
	input.action in nin_verification_actions
	not input.context.nin_purpose
	key := "nimc_purpose_limitation"
}

escalate_citations contains key if {
	input.action in bvn_verification_actions
	not input.context.nin_purpose
	key := "nimc_purpose_limitation"
}

escalate_citations contains key if {
	input.context.nin_consented_purpose != ""
	input.context.purpose != ""
	input.context.nin_consented_purpose != input.context.purpose
	key := "nimc_purpose_limitation"
}

audit_citations contains key if {
	_action_has_identity_pattern
	key := "identity_action_log"
}

audit_citations contains key if {
	input.action in mandatory_nin_service_actions
	not input.context.nin_verified
	key := "nimc_mandatory_service"
}

# ── Decision summary ─────────────────────────────────────────────
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
