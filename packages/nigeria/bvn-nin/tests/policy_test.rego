# agt-policies-nigeria
# Tests for BVN / NIN Data Protection policy
# Run: opa test policies/rego/ -v

package agt_policies_nigeria.bvn_nin_test

import data.agt_policies_nigeria.bvn_nin
import rego.v1

# ── Deny: BVN in output ───────────────────────────────────────────

test_deny_bvn_label_plus_digits if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "respond_to_customer",
		"params": {},
		"output": "Your BVN is: 22345678901",
		"context": {},
	}
}

test_deny_bvn_contextual_pattern if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "respond_to_customer",
		"params": {},
		"output": "Bank Verification number: 22345678901",
		"context": {},
	}
}

test_deny_bvn_equals_pattern if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "respond_to_customer",
		"params": {},
		"output": "bvn=22345678901 confirmed",
		"context": {},
	}
}

# ── Deny: NIN in output ───────────────────────────────────────────

test_deny_nin_label_plus_digits if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "respond_to_customer",
		"params": {},
		"output": "Your NIN is: 12345678901",
		"context": {},
	}
}

test_deny_nin_equals_pattern if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "respond_to_customer",
		"params": {},
		"output": "NIN=12345678901",
		"context": {},
	}
}

# ── Deny: vNIN in output ──────────────────────────────────────────

test_deny_vnin_pattern if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "respond_to_customer",
		"params": {},
		"output": "vNIN: ABCD1234EFGH5678",
		"context": {},
	}
}

test_deny_virtual_nin_pattern if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "respond_to_customer",
		"params": {},
		"output": "virtual NIN: WXYZ9876ABCD1234",
		"context": {},
	}
}

# ── Deny: direct transmission actions ────────────────────────────

test_deny_send_bvn_action if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "send_bvn",
		"params": {}, "output": "", "context": {},
	}
}

test_deny_transmit_nin_action if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "transmit_nin",
		"params": {}, "output": "", "context": {},
	}
}

test_deny_relay_kyc_action if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "relay_kyc",
		"params": {}, "output": "", "context": {},
	}
}

# ── Deny: BVN present in params with transmission action ──────────

test_deny_bvn_in_params_with_transmission if {
	count(bvn_nin.deny) > 0 with input as {
		"action": "post_identity",
		"params": {"bvn_present": true},
		"output": "", "context": {},
	}
}

# ── Escalate: BVN verification ────────────────────────────────────

test_escalate_verify_bvn if {
	count(bvn_nin.escalate) > 0 with input as {
		"action": "verify_bvn",
		"params": {}, "output": "", "context": {},
	}
}

test_escalate_bvn_lookup if {
	count(bvn_nin.escalate) > 0 with input as {
		"action": "bvn_lookup",
		"params": {}, "output": "", "context": {},
	}
}

test_escalate_nibss_bvn_verify if {
	count(bvn_nin.escalate) > 0 with input as {
		"action": "nibss_bvn_verify",
		"params": {}, "output": "", "context": {},
	}
}

# ── Escalate: NIN verification ────────────────────────────────────

test_escalate_verify_nin if {
	count(bvn_nin.escalate) > 0 with input as {
		"action": "verify_nin",
		"params": {}, "output": "", "context": {},
	}
}

test_escalate_nimc_nin_verify if {
	count(bvn_nin.escalate) > 0 with input as {
		"action": "nimc_nin_verify",
		"params": {}, "output": "", "context": {},
	}
}

# ── Escalate: identifier_type in params ──────────────────────────

test_escalate_identifier_type_bvn if {
	count(bvn_nin.escalate) > 0 with input as {
		"action": "check_account",
		"params": {"identifier_type": "BVN"},
		"output": "", "context": {},
	}
}

test_escalate_identifier_type_nin if {
	count(bvn_nin.escalate) > 0 with input as {
		"action": "check_account",
		"params": {"identifier_type": "NIN"},
		"output": "", "context": {},
	}
}

test_escalate_identifier_type_lowercase_bvn if {
	count(bvn_nin.escalate) > 0 with input as {
		"action": "check_account",
		"params": {"identifier_type": "bvn"},
		"output": "", "context": {},
	}
}

# ── Audit: identity-related action names ─────────────────────────

test_audit_action_containing_bvn if {
	count(bvn_nin.audit) > 0 with input as {
		"action": "log_bvn_attempt",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_action_containing_kyc if {
	count(bvn_nin.audit) > 0 with input as {
		"action": "kyc_status_check",
		"params": {}, "output": "", "context": {},
	}
}

# ── Allow: no identifier, no sensitive output ─────────────────────

test_allow_normal_customer_lookup if {
	bvn_nin.decision == "allow" with input as {
		"action": "get_account_balance",
		"params": {"account_id": "ACC-123"},
		"output": "Account balance: ₦50,000",
		"context": {},
	}
}

# ── Decision rules ────────────────────────────────────────────────

test_decision_deny_for_bvn_in_output if {
	bvn_nin.decision == "deny" with input as {
		"action": "respond_to_customer",
		"params": {},
		"output": "Your BVN is: 22345678901",
		"context": {},
	}
}

test_decision_deny_for_transmission_action if {
	bvn_nin.decision == "deny" with input as {
		"action": "send_bvn",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_escalate_for_bvn_verification if {
	bvn_nin.decision == "escalate" with input as {
		"action": "verify_bvn",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_escalate_for_identifier_type if {
	bvn_nin.decision == "escalate" with input as {
		"action": "process_request",
		"params": {"identifier_type": "BVN"},
		"output": "", "context": {},
	}
}

test_decision_audit_for_kyc_action if {
	bvn_nin.decision == "audit" with input as {
		"action": "kyc_record_fetch",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_allow_for_unrelated_action if {
	bvn_nin.decision == "allow" with input as {
		"action": "fetch_exchange_rate",
		"params": {}, "output": "", "context": {},
	}
}
