package agt_policies_agent.model_routing_test

import data.agt_policies_agent.model_routing

import rego.v1

# ── Helper ────────────────────────────────────────────────────────────

_input(action, task_type, model) := {
	"action": action,
	"params": {},
	"output": "",
	"context": {"task_type": task_type, "model": model},
}

# ── Deny: banned model ────────────────────────────────────────────────

test_deny_banned_model if {
	result := model_routing.decision with input as _input("chat", "general", "gpt-3.5-turbo")
		with data.config.model_routing.banned_models as {"gpt-3.5-turbo"}
	result == "deny"
}

test_deny_banned_model_on_sensitive_task if {
	result := model_routing.decision with input as _input("process", "pii_processing", "gpt-3.5-turbo")
		with data.config.model_routing.banned_models as {"gpt-3.5-turbo"}
	result == "deny"
}

# ── Deny: unapproved model on sensitive task ──────────────────────────

test_deny_unapproved_model_pii if {
	result := model_routing.decision with input as _input("process", "pii_processing", "gpt-3.5-turbo")
	result == "deny"
}

test_deny_unapproved_model_financial if {
	result := model_routing.decision with input as _input("decide", "financial_decision", "llama-3")
	result == "deny"
}

test_deny_unapproved_model_fraud if {
	result := model_routing.decision with input as _input("screen", "fraud_detection", "mistral-7b")
	result == "deny"
}

test_deny_unapproved_model_kyc if {
	result := model_routing.decision with input as _input("review", "kyc_review", "unknown-model")
	result == "deny"
}

test_deny_unapproved_model_aml if {
	result := model_routing.decision with input as _input("screen", "aml_screening", "gpt-3.5-turbo")
	result == "deny"
}

# ── Escalate: sensitive task with no model specified ──────────────────

test_escalate_pii_no_model if {
	result := model_routing.decision with input as {
		"action": "process",
		"params": {},
		"output": "",
		"context": {"task_type": "pii_processing"},
	}
	result == "escalate"
}

test_escalate_financial_no_model if {
	result := model_routing.decision with input as {
		"action": "decide",
		"params": {},
		"output": "",
		"context": {"task_type": "financial_decision"},
	}
	result == "escalate"
}

test_escalate_sensitive_empty_model if {
	result := model_routing.decision with input as {
		"action": "screen",
		"params": {},
		"output": "",
		"context": {"task_type": "fraud_detection", "model": ""},
	}
	result == "escalate"
}

# ── Audit: sensitive task with approved model ─────────────────────────

test_audit_pii_approved_model if {
	result := model_routing.decision with input as _input("process", "pii_processing", "claude-sonnet-4-6")
	result == "audit"
}

test_audit_financial_gpt4o if {
	result := model_routing.decision with input as _input("decide", "financial_decision", "gpt-4o")
	result == "audit"
}

test_audit_fraud_opus if {
	result := model_routing.decision with input as _input("screen", "fraud_detection", "claude-opus-4")
	result == "audit"
}

test_audit_kyc_approved if {
	result := model_routing.decision with input as _input("review", "kyc_review", "gpt-4-turbo")
	result == "audit"
}

# ── Allow: non-sensitive task ─────────────────────────────────────────

test_allow_general_task_any_model if {
	result := model_routing.decision with input as _input("chat", "general", "gpt-3.5-turbo")
	result == "allow"
}

test_allow_no_task_type if {
	result := model_routing.decision with input as {
		"action": "chat",
		"params": {},
		"output": "",
		"context": {},
	}
	result == "allow"
}

test_allow_non_sensitive_task_no_model if {
	result := model_routing.decision with input as {
		"action": "read",
		"params": {},
		"output": "",
		"context": {"task_type": "general"},
	}
	result == "allow"
}

# ── Config override ───────────────────────────────────────────────────

test_custom_sensitive_task_type_deny if {
	result := model_routing.decision with input as _input("process", "hr_decision", "gpt-3.5-turbo")
		with data.config.model_routing.sensitive_task_types as {"hr_decision"}
		with data.config.model_routing.approved_sensitive_models as {"gpt-4o"}
	result == "deny"
}

test_custom_approved_model if {
	result := model_routing.decision with input as _input("process", "financial_decision", "internal-model-v2")
		with data.config.model_routing.approved_sensitive_models as {"internal-model-v2"}
	result == "audit"
}
