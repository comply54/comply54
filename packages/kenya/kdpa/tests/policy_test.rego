# agt-policies-africa
# Tests for Kenya Data Protection Act 2019 policy
# Run: opa test policies/rego/ -v

package agt_policies_africa.kdpa_test

import data.agt_policies_africa.kdpa
import rego.v1

# ── Deny: breach suppression ──────────────────────────────────────

test_deny_breach_suppression if {
	count(kdpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Don't report this incident to the ODPC.",
		"context": {},
	}
}

test_deny_hide_breach if {
	count(kdpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "We should hide the breach from the regulator.",
		"context": {},
	}
}

# ── Deny: cross-border to non-permitted region ────────────────────

test_deny_us_east_1 if {
	count(kdpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 5},
		"output": "", "context": {"consent_documented": false},
	}
}

test_deny_eu_west_1 if {
	count(kdpa.deny) > 0 with input as {
		"action": "upload_to_cloud",
		"params": {"destination_region": "eu-west-1", "destination_country": "IE", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Allow: permitted regions ──────────────────────────────────────

test_allow_kenya_region if {
	kdpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "kenya", "destination_country": "KE", "record_count": 5},
		"output": "", "context": {},
	}
}

test_allow_af_south_1 if {
	kdpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "af-south-1", "destination_country": "KE", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Deny: processing without consent ─────────────────────────────

test_deny_processing_without_consent if {
	count(kdpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "We are sharing this data without consent from the customer.",
		"context": {},
	}
}

# ── Deny: biometric data in output ───────────────────────────────

test_deny_fingerprint_in_output if {
	count(kdpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer fingerprint template stored successfully.",
		"context": {},
	}
}

test_deny_facial_recognition_in_output if {
	count(kdpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Facial recognition confirmed customer identity.",
		"context": {},
	}
}

# ── Deny: national ID / KRA PIN in output ────────────────────────

test_deny_national_id_in_output if {
	count(kdpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "National ID number: 12345678",
		"context": {},
	}
}

# ── Deny: large record count ──────────────────────────────────────

test_deny_record_count_1001 if {
	count(kdpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 1001},
		"output": "", "context": {},
	}
}

# ── Escalate: health/medical data ────────────────────────────────

test_escalate_health_data if {
	count(kdpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer medical record shows HIV positive status.",
		"context": {},
	}
}

test_escalate_mental_health if {
	count(kdpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Mental health condition noted in customer file.",
		"context": {},
	}
}

# ── Escalate: special category data ──────────────────────────────

test_escalate_ethnic_origin if {
	count(kdpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's ethnic origin is Kikuyu.",
		"context": {},
	}
}

test_escalate_religion if {
	count(kdpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's religion is noted as Christian.",
		"context": {},
	}
}

# ── Escalate: cross-border language in output ─────────────────────

test_escalate_cross_border_output if {
	count(kdpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Transferring customer data outside Kenya to our backup server.",
		"context": {},
	}
}

# ── Escalate: missing destination metadata ────────────────────────

test_escalate_missing_destination if {
	count(kdpa.escalate) > 0 with input as {
		"action": "export_data",
		"params": {"record_count": 10},
		"output": "", "context": {},
	}
}

# ── Escalate: moderate record count ──────────────────────────────

test_escalate_record_count_500 if {
	count(kdpa.escalate) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 500},
		"output": "", "context": {},
	}
}

test_escalate_record_count_101 if {
	count(kdpa.escalate) > 0 with input as {
		"action": "relay_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 101},
		"output": "", "context": {},
	}
}

# ── Escalate: bulk export action ─────────────────────────────────

test_escalate_bulk_export if {
	count(kdpa.escalate) > 0 with input as {
		"action": "bulk_export",
		"params": {}, "output": "", "context": {},
	}
}

# ── Audit: PII access ─────────────────────────────────────────────

test_audit_read_user if {
	count(kdpa.audit) > 0 with input as {
		"action": "read_user",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_get_customer if {
	count(kdpa.audit) > 0 with input as {
		"action": "get_customer",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_update_user if {
	count(kdpa.audit) > 0 with input as {
		"action": "update_user",
		"params": {}, "output": "", "context": {},
	}
}

# ── Allow: normal operations ──────────────────────────────────────

test_allow_normal_action if {
	kdpa.decision == "allow" with input as {
		"action": "get_product_list",
		"params": {}, "output": "Here are available products.", "context": {},
	}
}

# ── Decision rules ────────────────────────────────────────────────

test_decision_deny_cross_border if {
	kdpa.decision == "deny" with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 5},
		"output": "", "context": {"consent_documented": false},
	}
}

test_decision_deny_biometric if {
	kdpa.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "Customer fingerprint matched successfully.",
		"context": {},
	}
}

test_decision_escalate_health_data if {
	kdpa.decision == "escalate" with input as {
		"action": "respond",
		"params": {},
		"output": "Customer has a disability noted in their file.",
		"context": {},
	}
}

test_decision_escalate_missing_destination if {
	kdpa.decision == "escalate" with input as {
		"action": "export_data",
		"params": {"record_count": 5},
		"output": "", "context": {},
	}
}

test_decision_audit_pii_access if {
	kdpa.decision == "audit" with input as {
		"action": "lookup_account",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_allow_unrelated_action if {
	kdpa.decision == "allow" with input as {
		"action": "check_service_status",
		"params": {}, "output": "", "context": {},
	}
}
