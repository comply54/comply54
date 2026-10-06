# agt-policies-nigeria
# Nigeria Data Protection Act 2023 — Data Residency & Privacy (Rego)
#
# Regulatory references:
#   Nigeria Data Protection Act 2023 (NDPA 2023)
#   Enforcing authority: Nigeria Data Protection Commission (NDPC)
#
# Rego advantage over YAML:
#   Can check input.params.destination_region directly — no text matching
#   needed to enforce cross-border rules. Structured field checks are
#   unambiguous compared to regex on output strings.
#
# Input schema expected:
#   {
#     "action":  "send_to_external",
#     "params":  {
#       "destination_region": "us-east-1",
#       "destination_country": "US",
#       "data_type": "customer_pii",
#       "record_count": 1500
#     },
#     "output":  "agent output text",
#     "context": { "purpose": "backup", "consent_documented": false }
#   }

package agt_policies_nigeria.ndpa

import rego.v1

# ── Permitted regions (Nigeria-hosted or adequacy-approved) ──────
# Only Nigerian-hosted infrastructure is permitted by default.
# Organisations must explicitly expand this list after conducting
# an adequacy assessment per NDPA s.25.
permitted_regions := {
	"af-south-1", # AWS Africa (Cape Town) — nearest, often used
	"ng-lag-1", # Hypothetical Nigerian region placeholder
	"nigeria",
	"NG",
	"ng",
}

# Cross-border transfer actions
transfer_actions := {
	"send_to_external", "export_data", "upload_to_cloud",
	"forward_to", "relay_data", "sync_to_remote",
}

# Bulk data export actions (NDPA s.24 — data minimisation)
bulk_export_actions := {
	"bulk_export", "export_all", "download_all_records",
	"dump_database", "full_table_export", "batch_download_pii",
}

# ── Special categories (NDPA s.30) ────────────────────────────────
# Declared via context.data_category. Keyed on what the context declares
# rather than on the action name: matching only a closed action vocabulary
# fails open, so a tool named outside the list would process special-category
# data unguarded.
special_category_types := {
	"health", "medical", "biometric", "genetic",
	"sexual_orientation", "religion",
}

# True when the request declares special-category data by any accepted signal.
declares_special_category if input.context.special_category == true

declares_special_category if input.context.contains_phi == true

declares_special_category if input.context.hiv_status == true

declares_special_category if input.context.data_category in special_category_types

# Deployments spell consent differently; accepting one spelling only would be
# the same fail-open in another place.
consent_declared if input.context.consent_documented == true

consent_declared if input.context.consent_provided == true

consent_declared if input.context.consent_given == true

consent_declared if input.context.consent_obtained == true

# ── Deny rules ────────────────────────────────────────────────────

# NDPA s.30: special-category data requires the subject's explicit consent
deny contains msg if {
	declares_special_category
	not consent_declared
	msg := "NDPA s.30: Processing special-category personal data (health, biometric, genetic) requires the explicit consent of the data subject — none was declared"
}

# NDPA s.25: processing requires a lawful basis. An explicitly null basis with
# no consent is a declared absence, not an omission. A reference to a missing
# key is undefined in Rego, so these fire only when the caller actually sent
# the field and left it empty.
deny contains msg if {
	input.context.lawful_basis == null
	not consent_declared
	msg := "NDPA s.25: Processing personal data requires a lawful basis — none was declared and no consent was obtained"
}

deny contains msg if {
	input.context.lawful_basis == ""
	not consent_declared
	msg := "NDPA s.25: Processing personal data requires a lawful basis — none was declared and no consent was obtained"
}

# NDPA s.25: Block transfer to non-permitted region (structured check)
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"NDPA s.25: Cross-border transfer to '%v' blocked — region not in NDPC adequacy-approved list",
		[input.params.destination_region],
	)
}

# NDPA s.25: Block transfer to non-Nigerian country code (structured check)
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "NG"
	not input.context.consent_documented == true
	msg := sprintf(
		"NDPA s.25: Transfer to country '%v' blocked — no documented consent or adequacy basis on file",
		[input.params.destination_country],
	)
}

# NDPA s.24: Block bulk data exports (data minimisation)
deny contains msg if {
	input.action in bulk_export_actions
	msg := "NDPA s.24: Bulk personal data export violates data minimisation principle — not permitted without documented legal basis"
}

# NDPA s.24: Block large record exports (>1000 records presumptively disproportionate)
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"NDPA s.24: Export of %v records is presumptively disproportionate — requires Data Protection Officer review",
		[input.params.record_count],
	)
}

# NDPA Schedule 1: Block biometric data transmission
deny contains msg if {
	regex.match(`(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, lower(input.output))
	msg := "NDPA Schedule 1: Biometric data detected — must not be transmitted by AI agents without documented lawful basis"
}

# NDPA s.22(5): Block breach suppression
deny contains msg if {
	regex.match(`(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, lower(input.output))
	msg := "NDPA s.22(5): Agent cannot suppress breach notifications — 72-hour NDPC reporting obligation applies"
}

# ── Escalate rules ────────────────────────────────────────────────

# NDPA s.25: Cross-border transfer with missing destination info — cannot verify
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "NDPA s.25: Cross-border transfer action with no destination metadata — cannot verify adequacy, requires human review"
}

# NDPA s.25: Detected cross-border language in output (defence-in-depth)
escalate contains msg if {
	regex.match(`(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+nigeria|cross.?border|international\s+transfer|offshore)`, lower(input.output))
	msg := "NDPA s.25: Cross-border data transfer language detected in output — requires NDPC adequacy verification"
}

# NDPA Schedule 1: Health/medical data requires approval before processing
escalate contains msg if {
	regex.match(`(medical\s+record|health\s+(condition|status|data)|hiv|mental\s+health|disability|prescription)`, lower(input.output))
	msg := "NDPA Schedule 1: Health/medical data detected — sensitive personal data requires explicit lawful basis"
}

# NDPA s.24: Moderate record count (100–1000) requires approval
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"NDPA s.24: Export of %v records requires Data Protection Officer approval before execution",
		[input.params.record_count],
	)
}

# ── Audit rules ───────────────────────────────────────────────────

# NDPA s.30: All PII access must be logged for NDPC accountability
audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "NDPA s.30: Personal data access logged — accountability audit trail for NDPC compliance"
}

# NDPA s.30: All PII modifications must be logged
audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal"}
	input.action in pii_update_actions
	msg := "NDPA s.30: Personal data modification logged — accountability audit trail for NDPC compliance"
}

# ── Citation key sets ─────────────────────────────────────────────

deny_citations contains key if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	key := "cross_border_region"
}

deny_citations contains key if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "NG"
	not input.context.consent_documented == true
	key := "cross_border_country"
}

deny_citations contains key if {
	input.action in bulk_export_actions
	key := "bulk_export_action"
}

deny_citations contains key if {
	input.action in transfer_actions
	input.params.record_count > 1000
	key := "large_record_export"
}

deny_citations contains key if {
	regex.match(`(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, lower(input.output))
	key := "biometric_output"
}

deny_citations contains key if {
	regex.match(`(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, lower(input.output))
	key := "breach_suppression"
}

escalate_citations contains key if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	key := "missing_destination"
}

escalate_citations contains key if {
	regex.match(`(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+nigeria|cross.?border|international\s+transfer|offshore)`, lower(input.output))
	key := "cross_border_output_pattern"
}

escalate_citations contains key if {
	regex.match(`(medical\s+record|health\s+(condition|status|data)|hiv|mental\s+health|disability|prescription)`, lower(input.output))
	key := "health_data_output"
}

escalate_citations contains key if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	key := "moderate_record_export"
}

audit_citations contains key if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	key := "pii_access_log"
}

audit_citations contains key if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal"}
	input.action in pii_update_actions
	key := "pii_modification_log"
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
