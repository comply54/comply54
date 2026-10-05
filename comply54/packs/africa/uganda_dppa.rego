# agt-policies-africa
# Uganda Data Protection and Privacy Act 2019 — Data Protection Policy (Rego)
#
# Regulatory reference: Uganda Data Protection and Privacy Act 2019 (DPPA)
# Enforcing authority: Personal Data Protection Office (PDPO) / NITA-U
#
# Input schema expected:
#   {
#     "action":  "export_data",
#     "params":  {
#       "destination_region": "us-east-1",
#       "destination_country": "US",
#       "record_count": 500
#     },
#     "output":  "agent output text",
#     "context": { "consent_documented": false, "legal_basis": "" }
#   }

package agt_policies_africa.uganda_dppa

import rego.v1

# ── Permitted regions (Uganda-hosted or adequacy-approved) ────────
# Update this list following Uganda PDPO adequacy determinations.
permitted_regions := {
	"af-south-1", # AWS Africa (Cape Town) — nearest available
	"af-east-1",  # East Africa region placeholder
	"uganda",
	"UG",
	"ug",
}

# Cross-border transfer actions
transfer_actions := {
	"send_to_external", "export_data", "upload_to_cloud",
	"forward_to", "relay_data", "sync_to_remote",
}

# Bulk export actions (DPPA s.4(e) — data minimisation)
bulk_export_actions := {
	"bulk_export", "export_all", "download_all_records",
	"dump_database", "full_table_export", "batch_download_pii",
}

# ── Deny rules ────────────────────────────────────────────────────

# DPPA s.22: Block breach suppression
deny contains msg if {
	regex.match(`(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, lower(input.output))
	msg := "Uganda DPPA s.22: Agent cannot suppress breach notifications — 72-hour PDPO reporting obligation applies"
}

# DPPA s.13: Block biometric data transmission
deny contains msg if {
	regex.match(`(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, lower(input.output))
	msg := "Uganda DPPA s.13: Biometric data detected — must not be transmitted without documented lawful basis"
}

# DPPA s.19: Block transfer to non-permitted region
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Uganda DPPA s.19: Cross-border transfer to '%v' blocked — region not in PDPO adequacy-approved list",
		[input.params.destination_region],
	)
}

# DPPA s.19: Block transfer to non-UG country without consent
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "UG"
	not input.context.consent_documented == true
	msg := sprintf(
		"Uganda DPPA s.19: Transfer to country '%v' blocked — no documented consent or adequacy basis on file",
		[input.params.destination_country],
	)
}

# DPPA: Block National ID (NIRA) in output
deny contains msg if {
	regex.match(`(national\s+id|nira\s+number|uganda\s+id)[\s:=]{0,5}[a-z]{2}[0-9]{9,12}`, lower(input.output))
	msg := "Uganda DPPA: National ID number (NIRA) detected in agent output — blocked to prevent identity exposure"
}

# DPPA s.4: Block large record exports (>1000 records)
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Uganda DPPA s.4(e): Export of %v records is disproportionate — requires Data Protection Officer review",
		[input.params.record_count],
	)
}

# ── Escalate rules ────────────────────────────────────────────────

# DPPA s.13: Health/medical data requires approval
escalate contains msg if {
	regex.match(`(medical\s+record|health\s+(condition|status|data)|hiv|genetic\s+(data|test)|mental\s+health|disability|prescription)`, lower(input.output))
	msg := "Uganda DPPA s.13: Health/medical sensitive personal data detected — requires explicit consent or documented legal basis"
}

# DPPA s.13: Special category data requires approval
escalate contains msg if {
	regex.match(`(ethnic\s+origin|tribe|political\s+opinion|religious\s+belief|trade\s+union|sexual\s+orientation|criminal\s+conviction)`, lower(input.output))
	msg := "Uganda DPPA s.13: Special category personal data detected — explicit consent or lawful condition required"
}

# DPPA s.13: Financial data requires approval
escalate contains msg if {
	regex.match(`(bank\s+account\s+number|account\s+balance|credit\s+score|loan\s+status|financial\s+(record|data|history))`, lower(input.output))
	msg := "Uganda DPPA s.13: Financial personal data detected — requires documented lawful basis"
}

# DPPA s.19: Cross-border language in output
escalate contains msg if {
	regex.match(`(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+uganda|cross.?border|international\s+transfer|offshore)`, lower(input.output))
	msg := "Uganda DPPA s.19: Cross-border data transfer language detected — requires PDPO adequacy verification"
}

# DPPA s.19: Transfer with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Uganda DPPA s.19: Cross-border transfer with no destination metadata — cannot verify adequacy, requires human review"
}

# DPPA s.4(e): Moderate record exports (100–1000 records)
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Uganda DPPA s.4(e): Export of %v records requires Data Protection Officer approval",
		[input.params.record_count],
	)
}

# DPPA s.4(e): Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Uganda DPPA s.4(e): Bulk personal data export requires documented lawful basis and DPO approval"
}

# ── Audit rules ───────────────────────────────────────────────────

# DPPA s.25: All personal data access must be logged
audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "Uganda DPPA s.25: Personal data access logged — PDPO accountability audit trail requirement"
}

# DPPA s.25: All personal data modifications must be logged
audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal"}
	input.action in pii_update_actions
	msg := "Uganda DPPA s.25: Personal data modification logged — PDPO accountability audit trail requirement"
}

# ── Citation key sets ────────────────────────────────────────────

deny_citations contains key if {
	regex.match(`(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, lower(input.output))
	key := "breach_suppression"
}

deny_citations contains key if {
	regex.match(`(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, lower(input.output))
	key := "biometric_output"
}

deny_citations contains key if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	key := "cross_border_region"
}

deny_citations contains key if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "UG"
	not input.context.consent_documented == true
	key := "cross_border_country"
}

deny_citations contains key if {
	regex.match(`(national\s+id|nira\s+number|uganda\s+id)[\s:=]{0,5}[a-z]{2}[0-9]{9,12}`, lower(input.output))
	key := "national_id_output"
}

deny_citations contains key if {
	input.action in transfer_actions
	input.params.record_count > 1000
	key := "large_record_export"
}

escalate_citations contains key if {
	regex.match(`(medical\s+record|health\s+(condition|status|data)|hiv|genetic\s+(data|test)|mental\s+health|disability|prescription)`, lower(input.output))
	key := "health_data_output"
}

escalate_citations contains key if {
	regex.match(`(ethnic\s+origin|tribe|political\s+opinion|religious\s+belief|trade\s+union|sexual\s+orientation|criminal\s+conviction)`, lower(input.output))
	key := "special_category_output"
}

escalate_citations contains key if {
	regex.match(`(bank\s+account\s+number|account\s+balance|credit\s+score|loan\s+status|financial\s+(record|data|history))`, lower(input.output))
	key := "special_category_output"
}

escalate_citations contains key if {
	regex.match(`(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+uganda|cross.?border|international\s+transfer|offshore)`, lower(input.output))
	key := "cross_border_output_pattern"
}

escalate_citations contains key if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	key := "missing_destination"
}

escalate_citations contains key if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	key := "moderate_record_export"
}

escalate_citations contains key if {
	input.action in bulk_export_actions
	key := "bulk_export_action"
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
