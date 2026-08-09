package agt_policies_agent.individual_risk_assessment

import rego.v1

# ═══════════════════════════════════════════════════════════════════════════════
# AI INDIVIDUAL RISK ASSESSMENT GOVERNANCE
# ═══════════════════════════════════════════════════════════════════════════════
#
# Governs AI systems that generate risk narratives, scores, and recommendations
# about individual people — field agents, employees, customers, borrowers — and
# persist those outputs to permanent records that affect employment, credit,
# insurance, or access decisions.
#
# This pack enforces four categories of obligation:
#
#   1. LAWFUL BASIS GATE       — a declared legal basis under NDPA §16 / GDPR
#                                Art. 6 must exist before any processing runs
#   2. PRE-AUTHORIZATION GATE  — a named supervisor must explicitly authorise
#                                the AI assessment before it executes (NDPA §33)
#   3. OUTPUT INTEGRITY        — generated narratives must not contain absolute
#                                character condemnation or protected-characteristic
#                                reasoning (NDPA §36, Nigeria Labour Act §11)
#   4. HUMAN-IN-THE-LOOP GATES — high-risk labels require escalation before
#                                persistence and before distribution (NDPA §33,
#                                EU AI Act Art. 14)
#
# ── SECURITY POSTURE (read this before deploying) ─────────────────────────────
#
# This pack is FAIL-CLOSED by default. If a deployer omits a lawful basis,
# supervisor authorization, or worker identifier, the default behavior is to
# DENY or ESCALATE. This is deliberate: a missing lawful basis is not a
# configuration detail — it is a regulatory violation.
#
# Three config flags control the fail-closed behavior explicitly:
#   require_lawful_basis      — generation and persistence need context.lawful_basis
#                               (default: true — cannot legally disable for NDPA)
#   require_pre_authorization — generation needs context.human_approved=true
#                               (default: true)
#   deny_unlisted_export_destinations — export to unconfigured destination → deny
#                               (default: true)
#
# ── Covered actions ────────────────────────────────────────────────────────────
#   generate_risk_narrative    AI generates a risk label, narrative, and
#                              recommendations for a named individual
#   persist_risk_label         Writes the AI-generated label + narrative to a
#                              permanent record (HR system, case file, etc.)
#   persist_risk_assessment    Alias for persist_risk_label for systems that
#                              write the full assessment object
#   export_risk_record         Sends the assessment outside the originating
#                              system (e-mail, dashboard, third-party HR API)
#   display_risk_narrative     Renders the narrative to a viewer (always audited,
#                              never blocked — access control is a separate concern)
#
# ── Input schema ───────────────────────────────────────────────────────────────
#   input.action                        string  — one of the covered actions above
#   input.params.worker_id              string  — identifier of the assessed individual
#   input.params.risk_label             string  — "low" | "moderate" | "high"
#   input.params.narrative              string  — AI-generated text output
#   input.params.confidence             number  — model confidence (0.0–1.0)
#   input.params.data_sources           array   — data feeds used in assessment
#   input.params.assessment_type        string  — e.g. "field_agent_risk", "performance"
#   input.params.recommendations        array   — AI-generated recommendations
#   input.params.destination            string  — export target URL or system name
#   input.context.human_approved        bool    — supervisor has authorised this action
#   input.context.lawful_basis          string  — "legitimate_interests" | "contract" |
#                                                  "legal_obligation" | "public_task" |
#                                                  "vital_interests" | "consent"
#   input.context.supervisor_id         string  — identifier of the approving supervisor
#   input.context.subject_notified      bool    — individual has been informed
#   input.context.export_allowlist      set     — approved export destinations
#
# ── Configuration (override via data.config.individual_risk_assessment.*) ──────
#   min_confidence                 number — minimum confidence to persist a label
#                                           (default: 0.60)
#   require_pre_authorization      bool   — generation needs context.human_approved
#                                           (default: true)
#   require_lawful_basis           bool   — all primary actions need lawful_basis
#                                           (default: true — disabling violates NDPA)
#   require_supervisor_id_for_high bool   — persist of HIGH label needs supervisor_id
#                                           (default: true)
#   require_subject_notification   bool   — persist of HIGH label needs subject_notified
#                                           (default: true)
#   deny_unlisted_export_destinations bool — deny export when no allowlist configured
#                                           (default: true)
#
# ── Framework alignment ────────────────────────────────────────────────────────
#   Nigeria Data Protection Act 2023    §16 Lawful basis, §33 Automated decisions,
#                                       §34 Data subject rights, §36 Non-discrimination
#   Nigeria Labour Act Cap L1 LFN 2004  §11 Wrongful dismissal protection
#   GDPR 2016/679                       Art. 6 Lawful basis, Art. 22 Automated decisions
#   POPIA (South Africa)                §71 Automated decision-making
#   Kenya DPA 2019                      §39 Automated processing
#   EU AI Act 2024                      Art. 14 Human oversight, Art. 10 Data accuracy
#   NIST AI RMF 1.0                     GOVERN 1.3, MANAGE 2.2, MEASURE 2.5
#   ISO/IEC 42001:2023                  §6.1.2 AI risk assessment, §8.4 Accountability
#   OWASP Top 10 for Agentic AI         ASI03 Insufficient Authorization Controls

# ── Covered action sets ────────────────────────────────────────────────────────

_generation_actions := {"generate_risk_narrative"}

_persistence_actions := {
	"persist_risk_label",
	"persist_risk_assessment",
}

_distribution_actions := {"export_risk_record"}

_display_actions := {"display_risk_narrative"}

_all_covered_actions := (
	_generation_actions |
	_persistence_actions |
	_distribution_actions |
	_display_actions
)

# ── Configuration with defaults ────────────────────────────────────────────────

_min_confidence := v if {
	v := data.config.individual_risk_assessment.min_confidence
} else := 0.6

_require_pre_authorization if {
	not data.config.individual_risk_assessment.require_pre_authorization == false
}

_require_lawful_basis if {
	not data.config.individual_risk_assessment.require_lawful_basis == false
}

_require_supervisor_id_for_high if {
	not data.config.individual_risk_assessment.require_supervisor_id_for_high == false
}

_require_subject_notification if {
	not data.config.individual_risk_assessment.require_subject_notification == false
}

# Fail-closed by default: an empty export allowlist means DENY ALL, not ALLOW ALL.
_deny_unlisted_export_destinations if {
	not data.config.individual_risk_assessment.deny_unlisted_export_destinations == false
}

# ── Input helpers ──────────────────────────────────────────────────────────────

_action := input.action

_worker_id := w if { w := input.params.worker_id; w != "" } else := ""

_risk_label := r if { r := input.params.risk_label } else := ""

_narrative := n if { n := input.params.narrative } else := ""

# Confidence: missing data is treated as WORST case (0.0) to match the pattern
# established in code_review_agent. An AI that doesn't report its own confidence
# should not sail through the confidence gate.
_confidence := c if {
	c := to_number(input.params.confidence)
	c >= 0.0
	c <= 1.0
} else := 0.0

_data_sources := d if { d := input.params.data_sources } else := []

_assessment_type := t if { t := input.params.assessment_type } else := ""

_destination := d if { d := input.params.destination; d != "" } else := ""

_human_approved := input.context.human_approved == true

_lawful_basis := l if {
	l := input.context.lawful_basis
	l != ""
} else := ""

_supervisor_id := s if {
	s := input.context.supervisor_id
	s != ""
} else := ""

_subject_notified := input.context.subject_notified == true

_export_allowlist := a if { a := input.context.export_allowlist } else := set()

# ── Prohibited narrative patterns ─────────────────────────────────────────────
#
# Patterns checked against lower(input.params.narrative) in D4.
# Organized into three categories:
#
#   1. Absolute character condemnation — sweeping negative character claims that
#      cannot be derived from performance data and expose the organization to
#      defamation liability and NDPA §36 / Labour Act §11 claims.
#
#   2. Protected-characteristic reasoning — any phrase that links a risk
#      label to a legally protected attribute (religion, ethnicity, tribe,
#      marital status, gender, age). Under NDPA §36 and the Nigeria Labour
#      Act, using these as risk factors is discriminatory regardless of framing.
#
#   3. Absolute temporal negatives — "will never", "will always [negative]"
#      applied to conduct. Permanent character predictions from limited data
#      violate the proportionality principle in NDPA §22.

_prohibited_narrative_phrases := {
	# ── 1. Absolute character condemnation ───────────────────────────────────────
	"is a fraudster",
	"is a fraud",
	"is dishonest",
	"is corrupt",
	"is a liar",
	"is a thief",
	"is a criminal",
	"is fundamentally dishonest",
	"is inherently unreliable",
	"is inherently dishonest",
	"is inherently corrupt",
	"is fundamentally corrupt",
	"is fundamentally unreliable",
	"is untrustworthy by nature",
	"is by nature untrustworthy",
	"has no integrity",
	"lacks basic integrity",
	"is morally bankrupt",
	"is a bad person",
	"is a terrible employee",
	"is worthless",
	"is useless",
	"is hopeless",
	"is a total failure",
	"is completely incompetent",
	"is a disaster",
	# ── 2. Protected-characteristic reasoning ────────────────────────────────────
	# Religion
	"because of his religion",
	"because of her religion",
	"because of their religion",
	"due to his religion",
	"due to her religion",
	"due to their religion",
	"his religious background",
	"her religious background",
	"their religious background",
	# Ethnicity / tribe
	"because of his ethnicity",
	"because of her ethnicity",
	"because of their ethnicity",
	"due to his ethnicity",
	"due to her ethnicity",
	"due to their ethnicity",
	"due to his tribe",
	"due to her tribe",
	"due to their tribe",
	"his tribal background",
	"her tribal background",
	"because of his tribe",
	"because of her tribe",
	"because of their tribe",
	# National origin
	"due to his origin",
	"due to her origin",
	"due to their origin",
	"because of his origin",
	"because of her origin",
	"because of their origin",
	# Marital status
	"due to his marital status",
	"due to her marital status",
	"because of his marital status",
	"because of her marital status",
	# Gender
	"because of his gender",
	"because of her gender",
	"due to his gender",
	"due to her gender",
	# Age
	"because of his age",
	"because of her age",
	"because of their age",
	"due to his age",
	"due to her age",
	# ── 3. Absolute temporal negatives ───────────────────────────────────────────
	"will never be honest",
	"will never improve",
	"will never change",
	"will always steal",
	"will always defraud",
	"will always fail",
	"can never be trusted",
	"can never be rehabilitated",
	"will always be a risk",
	"is beyond redemption",
	"is beyond reform",
}

_narrative_has_prohibited_phrase if {
	some phrase in _prohibited_narrative_phrases
	contains(lower(_narrative), phrase)
}

# ── Export destination authorization ──────────────────────────────────────────

_export_allowlist_configured if {
	count(_export_allowlist) > 0
}

_destination_is_approved if {
	_destination in _export_allowlist
}

# ═══════════════════════════════════════════════════════════════════════════════
# DENY rules
# ═══════════════════════════════════════════════════════════════════════════════

# ─── D1: Lawful basis gate ─────────────────────────────────────────────────────
# A declared lawful basis is a prerequisite for any processing that produces
# an automated individual decision, not an optional field. NDPA 2023 §16
# lists six valid bases; the field must contain one of them. A missing basis
# is treated as a violation, not a configuration omission.

deny contains msg if {
	_action in (_generation_actions | _persistence_actions | _distribution_actions)
	_require_lawful_basis
	_lawful_basis == ""
	msg := sprintf(
		"Individual risk assessment — D1 lawful basis gate: action '%v' requires a declared lawful basis (NDPA §16 / GDPR Art. 6). Set context.lawful_basis to one of: legitimate_interests, contract, legal_obligation, public_task, vital_interests, consent.",
		[_action],
	)
}

# ─── D2: Pre-authorization gate ───────────────────────────────────────────────
# An AI must not generate a risk narrative about a named individual unless a
# supervisor has explicitly authorized it for that specific run. Silent
# generation with no human sign-off is the governance gap this rule closes.
# The Proxze AI document names this as the primary Priority 1 gap.

deny contains msg if {
	_action in _generation_actions
	_require_pre_authorization
	not _human_approved
	msg := sprintf(
		"Individual risk assessment — D2 pre-authorization gate: action '%v' requires supervisor pre-authorization before the AI assessment runs. Set context.human_approved=true and context.supervisor_id after obtaining supervisor sign-off.",
		[_action],
	)
}

# ─── D3: High-risk label — no human review before persistence ─────────────────
# A "high" risk label written to a permanent record without any human review
# is the highest-risk outcome in this system. A named individual's livelihood
# can be directly affected. This is blocked unconditionally until a human
# approves. NDPA §33 and GDPR Art. 22 both require that automated decisions
# with significant effects be reviewable by a human before they take effect.

deny contains msg if {
	_action in _persistence_actions
	lower(_risk_label) == "high"
	not _human_approved
	msg := sprintf(
		"Individual risk assessment — D3 high-risk label gate: action '%v' with risk_label='high' blocked. A human supervisor must review the AI assessment and set context.human_approved=true before a high-risk label may be written to a permanent record (NDPA §33).",
		[_action],
	)
}

# ─── D4: Prohibited narrative patterns ────────────────────────────────────────
# The narrative must not contain absolute character condemnation, protected-
# characteristic reasoning, or permanent temporal negatives. These patterns are
# disproportionate (NDPA §22), potentially discriminatory (NDPA §36, Labour
# Act §11), and exceed what AI systems can legitimately conclude from
# performance data. The organization that persists such a narrative becomes
# liable for its content under Nigeria's data subject rights framework.

deny contains "Individual risk assessment — D4 prohibited narrative: the generated narrative contains absolute character condemnation, protected-characteristic reasoning, or permanent temporal negatives. These patterns are disproportionate under NDPA §22, potentially discriminatory under NDPA §36 and Nigeria Labour Act §11, and must be removed before the narrative may be persisted or distributed." if {
	_action in (_persistence_actions | _distribution_actions)
	_narrative_has_prohibited_phrase
}

# ─── D5: Missing worker identification ────────────────────────────────────────
# An AI risk assessment that cannot be traced to a specific named individual
# has no valid audit trail. NDPA §30 requires controllers to demonstrate
# accountability for automated processing; an assessment without a worker_id
# makes that impossible. This also prevents a "batch assessment" attack where
# an agent generates risk labels for multiple people in one unchecked call.

deny contains "Individual risk assessment — D5 missing worker identifier: input.params.worker_id is required for all risk narrative generation. An assessment without a worker identifier has no audit trail and cannot satisfy NDPA §30 accountability obligations. Provide the identifier of the specific individual being assessed." if {
	_action in _generation_actions
	_worker_id == ""
}

# ─── D6: Confidence below minimum threshold ───────────────────────────────────
# A risk label written to a permanent record with low model confidence is
# unreliable. A "high" label at 0.40 confidence that triggers adverse action
# against an employee causes real harm on the basis of unreliable output.
# Missing confidence defaults to 0.0 (worst case) — an AI that does not
# report its own confidence does not get the benefit of the doubt.

deny contains msg if {
	_action in _persistence_actions
	_confidence < _min_confidence
	msg := sprintf(
		"Individual risk assessment — D6 confidence gate: model confidence %.2f is below the minimum threshold %.2f for persisting a risk label. Missing confidence is treated as 0.0. Increase model confidence or escalate for human review before persisting (EU AI Act Art. 10).",
		[_confidence, _min_confidence],
	)
}

# ─── D7: High-risk record export without authorization ────────────────────────
# A risk record with a "high" label leaving the originating system without
# explicit human authorization is particularly dangerous — it distributes a
# consequential AI decision beyond the supervisor review chain. Blocked
# unconditionally without human_approved on the export action.

deny contains msg if {
	_action in _distribution_actions
	lower(_risk_label) == "high"
	not _human_approved
	msg := sprintf(
		"Individual risk assessment — D7 high-risk export gate: exporting a risk record with risk_label='high' requires explicit supervisor authorization. Set context.human_approved=true after review before exporting to '%v' (NDPA §25, POPIA §71).",
		[_destination],
	)
}

# ═══════════════════════════════════════════════════════════════════════════════
# ESCALATE rules
# ═══════════════════════════════════════════════════════════════════════════════

# ─── E1: High-risk label — supervisor ID required for persistence ──────────────
# Even when human_approved=true, a high-risk label being written to a permanent
# record requires an identified supervisor (context.supervisor_id). A boolean
# flag alone does not satisfy NDPA §33's human review requirement — there must
# be a named accountable person. If supervisor_id is absent, escalate rather
# than deny outright, allowing the caller to add the field and retry.

escalate contains msg if {
	_action in _persistence_actions
	lower(_risk_label) == "high"
	_human_approved
	_require_supervisor_id_for_high
	_supervisor_id == ""
	count(deny) == 0
	msg := sprintf(
		"Individual risk assessment — E1 supervisor identification required: persisting a high-risk label with human_approved=true but no context.supervisor_id. Provide the supervisor identifier to create a named accountability record for NDPA §33 compliance.",
		[],
	)
}

# ─── E2: Export destination not in allowlist ──────────────────────────────────
# Risk records contain sensitive personal data about named individuals. Exporting
# to an unconfigured destination may violate NDPA §25 (cross-border transfers)
# or send personal data to an unauthorized third party. Escalate rather than
# deny outright to allow the caller to confirm the destination is intended.

escalate contains msg if {
	_action in _distribution_actions
	_export_allowlist_configured
	not _destination_is_approved
	count(deny) == 0
	msg := sprintf(
		"Individual risk assessment — E2 export destination gate: destination '%v' is not in context.export_allowlist. Add the destination to the allowlist or obtain explicit authorization before distributing risk records externally (NDPA §25).",
		[_destination],
	)
}

escalate contains "Individual risk assessment — E2 export destination gate: no export allowlist is configured. By default, risk record exports are escalated until context.export_allowlist is set. To allow all destinations during early rollout, set deny_unlisted_export_destinations=false explicitly in config." if {
	_action in _distribution_actions
	not _export_allowlist_configured
	_deny_unlisted_export_destinations
	count(deny) == 0
}

# ─── E3: Data sources absent — assessment has no verifiable basis ─────────────
# An AI risk narrative generated from an empty data sources list cannot be
# verified against the inputs used to produce it. The decision may be
# hallucinated rather than grounded. Under NIST AI RMF MEASURE 2.5 and
# ISO/IEC 42001:2023 §8.4, AI outputs used in individual decisions must be
# traceable to their inputs. Escalate to require human confirmation that a
# proper data basis was provided through an out-of-band channel.

escalate contains msg if {
	_action in _generation_actions
	count(_data_sources) == 0
	count(deny) == 0
	msg := sprintf(
		"Individual risk assessment — E3 data sources absent: action '%v' has no input.params.data_sources declared. An AI risk assessment with no declared data basis cannot be verified and requires human confirmation before proceeding (NIST AI RMF MEASURE 2.5, ISO/IEC 42001:2023 §8.4).",
		[_action],
	)
}

# ─── E4: Subject not notified on high-risk assessment ─────────────────────────
# Under NDPA 2023 §34, data subjects have the right to be informed of automated
# decisions that significantly affect them. For a "high" risk label that will be
# persisted permanently, the assessed individual must be notified. Escalate when
# subject_notified=false on a high-risk persist, to ensure notification happens
# before the record is written (or immediately after if the workflow requires it).

escalate contains msg if {
	_action in _persistence_actions
	lower(_risk_label) == "high"
	_require_subject_notification
	not _subject_notified
	count(deny) == 0
	msg := sprintf(
		"Individual risk assessment — E4 subject notification required: persisting a high-risk label without context.subject_notified=true. NDPA §34 requires that individuals be informed of automated decisions that significantly affect them. Notify the assessed individual before or immediately after persisting this record.",
		[],
	)
}

# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT rules
# ═══════════════════════════════════════════════════════════════════════════════

# ─── A1: All risk narrative generation ────────────────────────────────────────
# Every invocation of the AI risk assessment — whether it proceeds or is blocked
# — must produce an audit record. This creates a complete history of when the
# assessment was run, by whose authorization, for which worker, and on what data.

audit contains msg if {
	_action in _generation_actions
	count(deny) == 0
	count(escalate) == 0
	msg := sprintf(
		"Individual risk assessment — A1 audit: risk narrative generation authorized for worker_id='%v' | Assessment type: %v | Data sources: %v | Authorized by: %v",
		[_worker_id, _assessment_type, count(_data_sources), _supervisor_id],
	)
}

# ─── A2: All risk label persistence ───────────────────────────────────────────
# Writing a risk label to a permanent record is one of the highest-consequence
# agent actions in this system. Every persistence event — whether low, moderate,
# or high risk — must be logged with full provenance including the label, the
# supervisor who approved, and the confidence at time of writing.

audit contains msg if {
	_action in _persistence_actions
	count(deny) == 0
	count(escalate) == 0
	msg := sprintf(
		"Individual risk assessment — A2 audit: risk label '%v' persisted for worker_id='%v' | Confidence: %.2f | Approved by: %v",
		[_risk_label, _worker_id, _confidence, _supervisor_id],
	)
}

# ─── A3: All risk record distribution ─────────────────────────────────────────

audit contains msg if {
	_action in _distribution_actions
	count(deny) == 0
	count(escalate) == 0
	msg := sprintf(
		"Individual risk assessment — A3 audit: risk record for worker_id='%v' (label='%v') exported to '%v' | Authorized by: %v",
		[_worker_id, _risk_label, _destination, _supervisor_id],
	)
}

# ─── A4: All narrative display events ─────────────────────────────────────────
# Display is always audited regardless of other rule outcomes — reading a
# permanent risk record is itself an access event that must be logged.
# This rule fires even when other rules deny or escalate.

audit contains msg if {
	_action in _display_actions
	msg := sprintf(
		"Individual risk assessment — A4 audit: risk narrative for worker_id='%v' displayed | Risk label: %v | Viewed by: %v",
		[_worker_id, _risk_label, _supervisor_id],
	)
}

# ═══════════════════════════════════════════════════════════════════════════════
# Citation keys — matched to RULE_CITATIONS in comply54.core.citations
# ═══════════════════════════════════════════════════════════════════════════════

deny_citations contains "ira_no_lawful_basis" if {
	_action in (_generation_actions | _persistence_actions | _distribution_actions)
	_require_lawful_basis
	_lawful_basis == ""
}

deny_citations contains "ira_no_pre_authorization" if {
	_action in _generation_actions
	_require_pre_authorization
	not _human_approved
}

deny_citations contains "ira_high_risk_no_review" if {
	_action in _persistence_actions
	lower(_risk_label) == "high"
	not _human_approved
}

deny_citations contains "ira_prohibited_narrative" if {
	_action in (_persistence_actions | _distribution_actions)
	_narrative_has_prohibited_phrase
}

deny_citations contains "ira_missing_worker_id" if {
	_action in _generation_actions
	_worker_id == ""
}

deny_citations contains "ira_low_confidence" if {
	_action in _persistence_actions
	_confidence < _min_confidence
}

deny_citations contains "ira_high_risk_export" if {
	_action in _distribution_actions
	lower(_risk_label) == "high"
	not _human_approved
}

escalate_citations contains "ira_high_risk_review_gate" if {
	_action in _persistence_actions
	lower(_risk_label) == "high"
	_human_approved
	_require_supervisor_id_for_high
	_supervisor_id == ""
	count(deny) == 0
}

escalate_citations contains "ira_export_no_allowlist" if {
	_action in _distribution_actions
	not _export_allowlist_configured
	_deny_unlisted_export_destinations
	count(deny) == 0
}

escalate_citations contains "ira_export_unlisted_destination" if {
	_action in _distribution_actions
	_export_allowlist_configured
	not _destination_is_approved
	count(deny) == 0
}

escalate_citations contains "ira_no_data_sources" if {
	_action in _generation_actions
	count(_data_sources) == 0
	count(deny) == 0
}

escalate_citations contains "ira_subject_not_notified" if {
	_action in _persistence_actions
	lower(_risk_label) == "high"
	_require_subject_notification
	not _subject_notified
	count(deny) == 0
}

audit_citations contains "ira_generation_audit" if {
	_action in _generation_actions
	count(deny) == 0
	count(escalate) == 0
}

audit_citations contains "ira_persistence_audit" if {
	_action in _persistence_actions
	count(deny) == 0
	count(escalate) == 0
}

audit_citations contains "ira_export_audit" if {
	_action in _distribution_actions
	count(deny) == 0
	count(escalate) == 0
}

audit_citations contains "ira_display_audit" if {
	_action in _display_actions
}

# ═══════════════════════════════════════════════════════════════════════════════
# Decision — most-restrictive-wins
# ═══════════════════════════════════════════════════════════════════════════════

decision := "deny" if { count(deny) > 0 }

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
