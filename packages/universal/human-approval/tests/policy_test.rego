package agt_policies_agent.human_approval_test

import data.agt_policies_agent.human_approval

import rego.v1

# ── Helper ────────────────────────────────────────────────────────────

_input(action, params, context) := {"action": action, "params": params, "output": "", "context": context}

# ── Escalate: default approval-required actions ───────────────────────

test_escalate_delete_account if {
	result := human_approval.decision with input as _input("delete_account", {}, {})
	result == "escalate"
}

test_escalate_close_account if {
	result := human_approval.decision with input as _input("close_account", {}, {})
	result == "escalate"
}

test_escalate_bulk_delete if {
	result := human_approval.decision with input as _input("bulk_delete", {}, {})
	result == "escalate"
}

test_escalate_grant_admin if {
	result := human_approval.decision with input as _input("grant_admin", {}, {})
	result == "escalate"
}

test_escalate_revoke_access if {
	result := human_approval.decision with input as _input("revoke_access", {}, {})
	result == "escalate"
}

test_escalate_send_bulk_email if {
	result := human_approval.decision with input as _input("send_bulk_email", {}, {})
	result == "escalate"
}

# ── Escalate: high risk level ─────────────────────────────────────────

test_escalate_high_risk_level if {
	result := human_approval.decision with input as _input("export_data", {}, {"risk_level": "high"})
	result == "escalate"
}

test_escalate_critical_risk_level if {
	result := human_approval.decision with input as _input("process_payment", {}, {"risk_level": "critical"})
	result == "escalate"
}

test_allow_low_risk_level if {
	result := human_approval.decision with input as _input("read_customer", {}, {"risk_level": "low"})
	result == "allow"
}

test_allow_medium_risk_level if {
	result := human_approval.decision with input as _input("read_customer", {}, {"risk_level": "medium"})
	result == "allow"
}

# ── Escalate: amount threshold ────────────────────────────────────────

test_escalate_above_default_threshold if {
	result := human_approval.decision with input as _input("nip_transfer", {"amount": 1500000}, {})
	result == "escalate"
}

test_allow_below_default_threshold if {
	result := human_approval.decision with input as _input("nip_transfer", {"amount": 500000}, {})
	result == "allow"
}

test_allow_at_exact_threshold if {
	result := human_approval.decision with input as _input("nip_transfer", {"amount": 1000000}, {})
	result == "allow"
}

# ── Escalate: bulk record threshold ──────────────────────────────────

test_escalate_above_bulk_threshold if {
	result := human_approval.decision with input as _input("export_data", {"record_count": 600}, {})
	result == "escalate"
}

test_allow_below_bulk_threshold if {
	result := human_approval.decision with input as _input("export_data", {"record_count": 100}, {})
	result == "allow"
}

# ── Config override: custom threshold ────────────────────────────────

test_custom_amount_threshold if {
	result := human_approval.decision with input as _input("nip_transfer", {"amount": 6000000}, {})
		with data.config.human_approval.amount_threshold as 5000000
	result == "escalate"
}

test_custom_threshold_below_amount if {
	result := human_approval.decision with input as _input("nip_transfer", {"amount": 3000000}, {})
		with data.config.human_approval.amount_threshold as 5000000
	result == "allow"
}

# ── Config override: custom required actions ──────────────────────────

test_custom_required_action if {
	result := human_approval.decision with input as _input("run_report", {}, {})
		with data.config.human_approval.required_actions as {"run_report"}
	result == "escalate"
}

# ── Allow: safe action, low risk, small amount ────────────────────────

test_allow_read_customer if {
	result := human_approval.decision with input as _input("read_customer", {"customer_id": "CUS-001"}, {})
	result == "allow"
}

test_allow_no_context if {
	result := human_approval.decision with input as _input("read_balance", {}, {})
	result == "allow"
}
