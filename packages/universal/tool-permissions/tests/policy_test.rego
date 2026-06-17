package agt_policies_agent.tool_permissions_test

import data.agt_policies_agent.tool_permissions

import rego.v1

# ── Helper ────────────────────────────────────────────────────────────

_input(action) := {"action": action, "params": {}, "output": "", "context": {}}

# ── Escalate: default restricted tools ───────────────────────────────

test_escalate_delete_record if {
	result := tool_permissions.decision with input as _input("delete_record")
	result == "escalate"
}

test_escalate_send_email if {
	result := tool_permissions.decision with input as _input("send_email")
	result == "escalate"
}

test_escalate_execute_code if {
	result := tool_permissions.decision with input as _input("execute_code")
	result == "escalate"
}

test_escalate_shell_exec if {
	result := tool_permissions.decision with input as _input("shell_exec")
	result == "escalate"
}

test_escalate_file_write if {
	result := tool_permissions.decision with input as _input("file_write")
	result == "escalate"
}

test_escalate_drop_table if {
	result := tool_permissions.decision with input as _input("drop_table")
	result == "escalate"
}

test_escalate_grant_admin if {
	result := tool_permissions.decision with input as _input("grant_admin")
	result == "escalate"
}

# ── Deny: explicit denied list ────────────────────────────────────────

test_deny_blocked_tool if {
	result := tool_permissions.decision with input as _input("wipe_database")
		with data.config.tool_permissions.denied as {"wipe_database"}
	result == "deny"
}

test_deny_blocked_tool_not_in_restricted if {
	result := tool_permissions.decision with input as _input("nuclear_option")
		with data.config.tool_permissions.denied as {"nuclear_option"}
		with data.config.tool_permissions.restricted as set()
	result == "deny"
}

# ── Deny wins over escalate for same tool ────────────────────────────

test_deny_beats_restricted_when_also_denied if {
	result := tool_permissions.decision with input as _input("delete_record")
		with data.config.tool_permissions.denied as {"delete_record"}
	result == "deny"
}

# ── Deny: allowlist mode — tool not in allowed set ────────────────────

test_deny_not_in_allowlist if {
	result := tool_permissions.decision with input as _input("read_customer")
		with data.config.tool_permissions.allowed as {"read_balance", "list_accounts"}
	result == "deny"
}

test_deny_not_in_allowlist_2 if {
	result := tool_permissions.decision with input as _input("delete_record")
		with data.config.tool_permissions.allowed as {"read_balance"}
		with data.config.tool_permissions.denied as set()
	result == "deny"
}

# ── Allow: tool in allowlist ──────────────────────────────────────────

test_allow_in_allowlist if {
	result := tool_permissions.decision with input as _input("read_balance")
		with data.config.tool_permissions.allowed as {"read_balance", "list_accounts"}
	result == "allow"
}

# ── Allow: no config, not in default restricted ───────────────────────

test_allow_safe_tool_no_config if {
	result := tool_permissions.decision with input as _input("read_customer")
	result == "allow"
}

test_allow_read_balance_no_config if {
	result := tool_permissions.decision with input as _input("read_balance")
	result == "allow"
}

test_allow_list_accounts_no_config if {
	result := tool_permissions.decision with input as _input("list_transactions")
	result == "allow"
}

# ── Custom restricted list ────────────────────────────────────────────

test_escalate_custom_restricted if {
	result := tool_permissions.decision with input as _input("export_data")
		with data.config.tool_permissions.restricted as {"export_data"}
	result == "escalate"
}
