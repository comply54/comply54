package agt_policies_agent.pii_leakage_test

import data.agt_policies_agent.pii_leakage

import rego.v1

# ── Helper ────────────────────────────────────────────────────────────

_input(action, output) := {"action": action, "params": {}, "output": output, "context": {}}

# ── Deny: BVN/NIN (11-digit) ─────────────────────────────────────────

test_deny_bvn_in_output if {
	result := pii_leakage.decision with input as _input("respond_to_customer", "Your BVN is: 22345678901.")
	result == "deny"
}

test_deny_nin_in_output if {
	result := pii_leakage.decision with input as _input("respond_to_customer", "NIN: 12345678901 confirmed.")
	result == "deny"
}

test_deny_11_digit_bare if {
	result := pii_leakage.decision with input as _input("chat", "ID number: 98765432101")
	result == "deny"
}

# ── Deny: credit card ─────────────────────────────────────────────────

test_deny_visa_card if {
	result := pii_leakage.decision with input as _input("respond_to_customer", "Card ending in 4111111111111111 charged.")
	result == "deny"
}

test_deny_mastercard if {
	result := pii_leakage.decision with input as _input("chat", "5500005555555559 is on file.")
	result == "deny"
}

# ── Deny: South African ID ────────────────────────────────────────────

test_deny_sa_id if {
	result := pii_leakage.decision with input as _input("respond", "Your SA ID: 9001015009087.")
	result == "deny"
}

# ── Escalate: email ───────────────────────────────────────────────────

test_escalate_email_in_output if {
	result := pii_leakage.decision with input as _input("respond_to_customer", "Contact support at user@example.com for help.")
	result == "escalate"
}

test_escalate_email_only if {
	result := pii_leakage.decision with input as _input("chat", "Email: john.doe@bank.co.ng")
	result == "escalate"
}

# ── Escalate: phone number ────────────────────────────────────────────

test_escalate_phone_number if {
	result := pii_leakage.decision with input as _input("respond_to_customer", "Call us on +2348012345678.")
	result == "escalate"
}

# ── Deny beats escalate when both present ────────────────────────────

test_deny_wins_over_email_when_card_present if {
	result := pii_leakage.decision with input as _input("chat", "Card 4111111111111111 for user@example.com")
	result == "deny"
}

# ── Audit: PII-capable action, no PII found ───────────────────────────

test_audit_pii_capable_action_clean if {
	result := pii_leakage.decision with input as _input("respond_to_customer", "Your transaction was processed.")
	result == "audit"
}

test_audit_export_data_no_pii if {
	result := pii_leakage.decision with input as _input("export_data", "Export completed: 500 records.")
	result == "audit"
}

test_audit_read_customer_clean if {
	result := pii_leakage.decision with input as _input("read_customer", "Account status: active.")
	result == "audit"
}

# ── Allow: non-PII-capable action, clean output ───────────────────────

test_allow_clean_non_pii_action if {
	result := pii_leakage.decision with input as _input("calculate_fee", "Fee: ₦500.")
	result == "allow"
}

test_allow_empty_output if {
	result := pii_leakage.decision with input as _input("chat", "")
	result == "allow"
}

# ── Allowed action override ───────────────────────────────────────────

test_allowed_action_permits_email if {
	result := pii_leakage.decision with input as _input("send_kyc_report", "KYC email: officer@compliance.ng")
		with data.config.pii_leakage.allowed_actions as {"send_kyc_report"}
	result == "allow"
}

test_allowed_action_permits_bvn if {
	result := pii_leakage.decision with input as _input("bvn_verification_response", "Verified BVN: 22345678901")
		with data.config.pii_leakage.allowed_actions as {"bvn_verification_response"}
	result == "allow"
}

# ── Custom extra pattern (deployer-configured) ────────────────────────

test_extra_pattern_deny if {
	result := pii_leakage.decision with input as _input("chat", "passport number: A12345678")
		with data.config.pii_leakage.extra_patterns as {`passport number: [A-Z][0-9]{8}`}
	result == "deny"
}
