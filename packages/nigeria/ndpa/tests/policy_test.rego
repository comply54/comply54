# agt-policies-nigeria
# Tests for NDPA 2023 Data Residency & Privacy policy
# Run: opa test policies/rego/ -v

package agt_policies_nigeria.ndpa_test

import data.agt_policies_nigeria.ndpa
import rego.v1

# ── Deny: non-permitted destination region ────────────────────────

test_deny_us_east_1_region if {
	count(ndpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 10},
		"output": "", "context": {"consent_documented": false},
	}
}

test_deny_eu_west_1_region if {
	count(ndpa.deny) > 0 with input as {
		"action": "upload_to_cloud",
		"params": {"destination_region": "eu-west-1", "destination_country": "IE", "record_count": 5},
		"output": "", "context": {"consent_documented": false},
	}
}

test_deny_ap_southeast_1_region if {
	count(ndpa.deny) > 0 with input as {
		"action": "forward_to",
		"params": {"destination_region": "ap-southeast-1", "destination_country": "SG", "record_count": 1},
		"output": "", "context": {"consent_documented": false},
	}
}

# ── Allow: permitted destination regions ─────────────────────────

test_allow_af_south_1_region if {
	ndpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "af-south-1", "destination_country": "ZA", "record_count": 10},
		"output": "", "context": {"consent_documented": true},
	}
}

test_allow_nigeria_region if {
	ndpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "nigeria", "destination_country": "NG", "record_count": 5},
		"output": "", "context": {},
	}
}

test_allow_ng_country_code if {
	ndpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "ng", "destination_country": "NG", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Deny: non-NG country without consent ─────────────────────────

test_deny_non_ng_country_no_consent if {
	count(ndpa.deny) > 0 with input as {
		"action": "send_to_external",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 1},
		"output": "", "context": {"consent_documented": false},
	}
}

test_deny_uk_country_no_consent if {
	count(ndpa.deny) > 0 with input as {
		"action": "relay_data",
		"params": {"destination_region": "eu-west-2", "destination_country": "GB", "record_count": 1},
		"output": "", "context": {},
	}
}

# ── Deny: bulk export actions ─────────────────────────────────────

test_deny_bulk_export if {
	count(ndpa.deny) > 0 with input as {
		"action": "bulk_export",
		"params": {}, "output": "", "context": {},
	}
}

test_deny_dump_database if {
	count(ndpa.deny) > 0 with input as {
		"action": "dump_database",
		"params": {}, "output": "", "context": {},
	}
}

test_deny_export_all if {
	count(ndpa.deny) > 0 with input as {
		"action": "export_all",
		"params": {}, "output": "", "context": {},
	}
}

# ── Deny: large record count (>1000) ─────────────────────────────

test_deny_record_count_1001 if {
	count(ndpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "record_count": 1001},
		"output": "", "context": {},
	}
}

test_deny_record_count_1500 if {
	count(ndpa.deny) > 0 with input as {
		"action": "upload_to_cloud",
		"params": {"destination_region": "us-east-1", "record_count": 1500},
		"output": "", "context": {},
	}
}

# ── Deny: biometric data in output ───────────────────────────────

test_deny_fingerprint_in_output if {
	count(ndpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer fingerprint template stored successfully.",
		"context": {},
	}
}

test_deny_facial_recognition_in_output if {
	count(ndpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Facial recognition data matched — identity confirmed.",
		"context": {},
	}
}

# ── Deny: breach suppression ──────────────────────────────────────

test_deny_breach_suppression if {
	count(ndpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Don't report this incident to the regulator.",
		"context": {},
	}
}

test_deny_hide_breach if {
	count(ndpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "We should hide the breach from the NDPC.",
		"context": {},
	}
}

# ── Escalate: missing destination metadata ────────────────────────

test_escalate_transfer_no_destination_info if {
	count(ndpa.escalate) > 0 with input as {
		"action": "export_data",
		"params": {"record_count": 10},
		"output": "", "context": {},
	}
}

# ── Escalate: moderate record count (100–1000) ────────────────────

test_escalate_record_count_500 if {
	count(ndpa.escalate) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 500},
		"output": "", "context": {"consent_documented": false},
	}
}

test_escalate_record_count_exactly_1000 if {
	count(ndpa.escalate) > 0 with input as {
		"action": "upload_to_cloud",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 1000},
		"output": "", "context": {"consent_documented": false},
	}
}

test_escalate_record_count_101 if {
	count(ndpa.escalate) > 0 with input as {
		"action": "relay_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 101},
		"output": "", "context": {"consent_documented": false},
	}
}

# ── Escalate: health data in output ──────────────────────────────

test_escalate_health_data_in_output if {
	count(ndpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer medical record shows HIV positive status.",
		"context": {},
	}
}

test_escalate_mental_health_in_output if {
	count(ndpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Mental health condition noted in customer file.",
		"context": {},
	}
}

# ── Escalate: cross-border language in output ─────────────────────

test_escalate_cross_border_language_in_output if {
	count(ndpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Transferring customer records outside Nigeria to our backup.",
		"context": {},
	}
}

# ── Audit: PII access and modification ───────────────────────────

test_audit_read_user_action if {
	count(ndpa.audit) > 0 with input as {
		"action": "read_user",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_get_customer_action if {
	count(ndpa.audit) > 0 with input as {
		"action": "get_customer",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_update_user_action if {
	count(ndpa.audit) > 0 with input as {
		"action": "update_user",
		"params": {}, "output": "", "context": {},
	}
}

# ── Allow: normal operations ──────────────────────────────────────

test_allow_normal_action if {
	ndpa.decision == "allow" with input as {
		"action": "get_product_list",
		"params": {}, "output": "Here are available products.", "context": {},
	}
}

# ── Decision rules ────────────────────────────────────────────────

test_decision_deny_cross_border_non_permitted if {
	ndpa.decision == "deny" with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 10},
		"output": "", "context": {"consent_documented": false},
	}
}

test_decision_deny_bulk_export if {
	ndpa.decision == "deny" with input as {
		"action": "bulk_export",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_deny_large_record_count if {
	ndpa.decision == "deny" with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "record_count": 2000},
		"output": "", "context": {},
	}
}

test_decision_escalate_missing_destination if {
	ndpa.decision == "escalate" with input as {
		"action": "export_data",
		"params": {"record_count": 5},
		"output": "", "context": {},
	}
}

test_decision_audit_for_pii_access if {
	ndpa.decision == "audit" with input as {
		"action": "lookup_account",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_allow_for_unrelated_action if {
	ndpa.decision == "allow" with input as {
		"action": "check_service_status",
		"params": {}, "output": "", "context": {},
	}
}
