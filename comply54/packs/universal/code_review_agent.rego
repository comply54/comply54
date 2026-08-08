package agt_policies_agent.code_review_agent

import rego.v1

# ═══════════════════════════════════════════════════════════════════════════════
# AI CODE REVIEW AGENT GOVERNANCE
# ═══════════════════════════════════════════════════════════════════════════════
#
# Governs autonomous AI agents that review source code, post findings to version
# control systems, probe applications for vulnerabilities, and notify developers.
#
# This pack enforces the three categories of obligation identified in the
# comply54 governance model:
#
#   1. ORGANIZATIONAL POLICIES — confidence gates, finding volume limits,
#      repository scope controls, dismissal audit trail
#   2. SECURITY GUARDRAILS    — probe target validation, destructive payload
#      blocking, PR injection pre-screening, output integrity
#   3. HUMAN-IN-THE-LOOP GATES — high-severity security findings, developer
#      notifications, non-compliant compliance assessments
#
# ── SECURITY POSTURE (read this before deploying) ─────────────────────────────
#
# This pack is FAIL-CLOSED by default. If a deployer forgets to configure an
# allowlist, approval token, or scope restriction, the default behavior is to
# DENY or ESCALATE, never to silently ALLOW. This is a deliberate design choice,
# not an accident of which fields happen to be populated.
#
# Three flags control this explicitly (see Configuration below):
#   require_explicit_authorization   — probes need a verified token, not just
#                                       any non-empty string (default: true)
#   deny_unlisted_notification_domains — if no domain allowlist is configured,
#                                       ALL external notifications are denied,
#                                       not allowed (default: true)
#   deny_unlisted_repos              — if no approved-repo list is configured,
#                                       ALL repo ingestion is denied, not
#                                       allowed (default: true)
#
# A deployer who genuinely wants an open posture during early rollout must set
# these to false explicitly, in writing, in config — not by leaving a list
# empty and getting permissiveness as an accidental side effect.
#
# Covered actions
# ────────────────────────────────────────────────────────────────────────────
#   post_review_finding       Post a single finding/comment to a PR or MR
#   post_review_summary       Post the overall review summary to a PR or MR
#   post_compliance_assessment Post ticket/issue compliance results to a PR
#   run_security_probe        Actively probe a target URL with security payloads
#   send_developer_notification Send email/Teams/Slack notification about a developer
#   ingest_pull_request       Receive a PR diff into the LLM for analysis
#   dismiss_finding            Dismiss a previously raised finding without acting
#
# Input schema
# ────────────────────────────────────────────────────────────────────────────
#   input.action                string  — one of the covered actions above
#   input.params.body           string  — content being posted or processed
#   input.params.confidence     number  — model confidence score (0.0–1.0)
#   input.params.severity       string  — "high" | "medium" | "low"
#   input.params.category       string  — "security" | "bug" | "performance" | "style" | ...
#   input.params.findings_in_batch  int — total findings in this review batch
#   input.params.target_url     string  — URL for security probe
#   input.params.probe_scope    string  — space-separated payload types requested
#   input.params.recipient      string  — notification recipient address
#   input.params.dismissal_reason string — reason for dismissing a finding
#   input.params.repo           string  — "org/repo-name" being reviewed
#   input.params.not_implemented_count  int — requirements not implemented
#   input.params.total_requirements     int — total requirements assessed
#   input.context.human_approved        bool   — operator approved this action
#   input.context.approved_targets      set    — URLs approved for probe testing
#   input.context.authorization_token   string — probe authorization token
#   input.context.verified_tokens       set    — tokens the platform has actually
#                                                 verified as valid for this run
#                                                 (populated by the caller, NOT
#                                                 the agent — see note on D3)
#   input.context.approved_repos        set    — repos this agent may review
#   input.context.recipient_domain_allowlist  set — approved email domains
#
# Configuration (override via data.config.code_review_agent.*)
# ────────────────────────────────────────────────────────────────────────────
#   min_confidence                 number — minimum confidence to post a finding
#                                            (default: 0.75)
#   max_findings_per_batch         int    — max findings before requiring human
#                                            review (default: 30)
#   require_human_for_security     bool   — escalate HIGH+security findings
#                                            (default: true)
#   require_probe_authorization    bool   — probes must have a verified token or
#                                            approved target (default: true)
#   require_explicit_authorization bool   — a probe token must appear in
#                                            context.verified_tokens, not just be
#                                            non-empty (default: true)
#   require_dismissal_reason       bool   — dismissals must include a reason
#                                            (default: true)
#   require_notification_approval  bool   — developer notifications need
#                                            human_approved (default: true)
#   deny_unlisted_notification_domains bool — deny all notifications when no
#                                            allowlist is configured, instead of
#                                            allowing all (default: true)
#   deny_unlisted_repos            bool   — deny all ingestion when no approved
#                                            repo list is configured, instead of
#                                            allowing all (default: true)
#   non_compliance_threshold       number — ratio of not_implemented/total that
#                                            triggers escalation on
#                                            post_compliance_assessment
#                                            (default: 0.5)
#
# Framework alignment
# ────────────────────────────────────────────────────────────────────────────
#   OWASP Top 10 for LLM 2025      LLM08 Excessive Agency
#   OWASP Agentic AI Top 10        ASI01 Agent Behaviour Hijack, ASI02 Tool Misuse,
#                                  ASI09 Human-Agent Trust Exploitation
#   NIST AI RMF                    GOVERN 1.2, GOVERN 1.3, MANAGE 2.2
#   ISO/IEC 42001:2023             §6.1.2 AI risk assessment
#   EU AI Act                      Art. 9 Risk management, Art. 14 Human oversight

# ── Covered actions ────────────────────────────────────────────────────────────

_posting_actions := {
	"post_review_finding",
	"post_review_summary",
	"post_compliance_assessment",
}

_all_covered_actions := _posting_actions | {
	"run_security_probe",
	"send_developer_notification",
	"ingest_pull_request",
	"dismiss_finding",
}

# ── Configuration with defaults ────────────────────────────────────────────────

_min_confidence := v if {
	v := data.config.code_review_agent.min_confidence
} else := 0.75

_max_findings_per_batch := v if {
	v := data.config.code_review_agent.max_findings_per_batch
} else := 30

_require_human_for_security if {
	not data.config.code_review_agent.require_human_for_security == false
}

_require_probe_authorization if {
	not data.config.code_review_agent.require_probe_authorization == false
}

# Fail-closed by default: a bare non-empty token is NOT enough on its own
# unless a deployer explicitly opts out of verification.
_require_explicit_authorization if {
	not data.config.code_review_agent.require_explicit_authorization == false
}

_require_dismissal_reason if {
	not data.config.code_review_agent.require_dismissal_reason == false
}

_require_notification_approval if {
	not data.config.code_review_agent.require_notification_approval == false
}

# Fail-closed by default: an empty allowlist means DENY ALL, not ALLOW ALL.
_deny_unlisted_notification_domains if {
	not data.config.code_review_agent.deny_unlisted_notification_domains == false
}

# Fail-closed by default: an empty approved-repo list means DENY ALL, not
# ALLOW ALL.
_deny_unlisted_repos if {
	not data.config.code_review_agent.deny_unlisted_repos == false
}

_non_compliance_threshold := v if {
	v := data.config.code_review_agent.non_compliance_threshold
} else := 0.5

# ── Convenience helpers ────────────────────────────────────────────────────────

_action := input.action
_body := b if { b := input.params.body } else := ""

# Confidence: missing data is treated as WORST case (0.0), not best case.
# An agent that fails to report its own confidence should not sail through
# the confidence gate by default — that inverts the purpose of the gate.
_confidence := c if {
	c := to_number(input.params.confidence)
	c >= 0.0
	c <= 1.0
} else := 0.0

_severity := s if { s := input.params.severity } else := ""
_category := c if { c := input.params.category } else := ""
_findings_in_batch := n if { n := to_number(input.params.findings_in_batch) } else := 0
_target_url := u if { u := input.params.target_url } else := ""
_probe_scope := p if { p := input.params.probe_scope } else := ""
_recipient := r if { r := input.params.recipient } else := ""
_dismissal_reason := d if { d := input.params.dismissal_reason } else := ""
_repo := r if { r := input.params.repo } else := ""

_not_implemented := n if { n := to_number(input.params.not_implemented_count) } else := 0
_total_reqs := n if { n := to_number(input.params.total_requirements) } else := 0

_human_approved := input.context.human_approved == true
_approved_targets := t if { t := input.context.approved_targets } else := set()
_auth_token := t if { t := input.context.authorization_token; t != "" } else := ""
_verified_tokens := t if { t := input.context.verified_tokens } else := set()
_approved_repos := r if { r := input.context.approved_repos } else := set()
_domain_allowlist := d if { d := input.context.recipient_domain_allowlist } else := set()

# ── Destructive payload keywords ───────────────────────────────────────────────

_destructive_probe_keywords := {
	"drop_table", "drop table",
	"delete_all", "delete all records",
	"truncate", "truncate table",
	"rm -rf", "rm -r",
	"format drive", "mkfs",
	"shutdown", "reboot",
	"destroy_db", "wipe_db",
	"ransomware", "encrypt_files",
	"delete_user_data",
	"drop_database",
	"delete_repository",
}

_probe_scope_has_destructive if {
	some kw in _destructive_probe_keywords
	contains(lower(_probe_scope), kw)
}

# ── Production environment detection ──────────────────────────────────────────
#
# Three-phase detection strategy (fail-safe design):
#
# Phase 1 — context.is_production wins unconditionally:
#   true  → always production, URL heuristics are irrelevant
#   false → never production (explicit operator override)
#
# Phase 2 — Explicit production indicators: well-known prod/prd/live patterns.
#
# Phase 3 — Fail-safe: any non-empty URL with NO recognisable non-production
# marker is treated as production-tier. This catches the most dangerous cases:
# bare apex domains (myapp.io), unlabelled API subdomains (api.myapp.io),
# cloud-platform hostnames (myapp.azurecontainerapps.io), and "prd" abbreviations
# missed by the old positive-match approach.
#
# The original approach of matching known production patterns has an irreducible
# false-negative problem: any production URL that does not fit the pattern
# silently passes through. Inverting the logic — identify the much smaller,
# more stable set of NON-production patterns — and treating everything else as
# production reduces false negatives to near-zero at the cost of a few more
# escalations on genuinely ambiguous URLs.

_non_production_indicators := {
	# Staging
	"staging.", ".staging.", "-staging.", "/staging/",
	"stg.", ".stg.", "-stg.", "/stg/",
	# Development
	"dev.", ".dev.", "-dev.", "/dev/",
	"develop.", "development.",
	# Test / QA
	"test.", ".test.", "-test.", "/test/",
	"qa.", ".qa.", "-qa.", "/qa/",
	"uat.", ".uat.", "-uat.",
	# Sandbox
	"sandbox.", ".sandbox.", "-sandbox.",
	"sbx.", ".sbx.", "-sbx.",
	# Demo / preview / canary
	"demo.", ".demo.", "-demo.",
	"preview.", ".preview.", "-preview.", "/preview/",
	"canary.", ".canary.", "-canary.",
	# Local / loopback / private networks
	"localhost", "127.0.0.1",
	"://192.168.", "://10.", "://172.", "://127.", "://[::1]", "://0.0.0.0",
	# Branch / PR preview deployments (Vercel, Netlify, Render, etc.)
	"feature-", "feat-", "/pr-", "/branch-",
	# Pre-release channels
	"alpha.", "beta.", "rc.",
	"nightly.", "experiment.", "lab.",
	# Non-standard ports — ONLY include ports that are virtually never used in
	# production. 9000 (SonarQube/MinIO), 9090 (Prometheus), 9443 (OpenShift/K8s
	# HTTPS alternate) are legitimately production ports and are excluded here —
	# they fall through to the Phase 3 fail-safe and escalate.
	":8080", ":3000", ":4000", ":5000",
	":8000", ":8888",
}

_explicit_production_indicators := {
	"prod.", "/prod/", "-prod.", ".prod.", "prod-",
	"prd.", "/prd/", "-prd.", ".prd.", "prd-",
	"production.", "/production/",
	"live.", ".live.", "-live.",
	"release.", ".release.", "-release.",
}

_url_has_non_production_marker if {
	some marker in _non_production_indicators
	contains(lower(_target_url), marker)
}

# context.is_production=false is an explicit operator override — skip all URL heuristics.
_is_explicitly_non_production if {
	input.context.is_production == false
}

# Rule 1: explicit flag wins
_target_appears_production if {
	input.context.is_production == true
}

# Rule 2: known production URL patterns
_target_appears_production if {
	not _is_explicitly_non_production
	some indicator in _explicit_production_indicators
	contains(lower(_target_url), indicator)
}

# Rule 3: fail-safe — no non-production marker → treat as production
_target_appears_production if {
	not _is_explicitly_non_production
	_target_url != ""
	not _url_has_non_production_marker
}

# ── Output integrity — injection artifact detection in body ───────────────────

_injection_artifacts := {
	"ignore previous instructions",
	"ignore all previous instructions",
	"your new instructions are",
	"new task:",
	"[system override]",
	"[admin override]",
	"[hidden instruction]",
	"you are now dan",
	"bypass all restrictions",
	"/* ignore previous",
	"# ignore previous",
	"// ignore previous",
}

_body_contains_injection_artifact if {
	some artifact in _injection_artifacts
	contains(lower(_body), artifact)
}

# ── Recipient domain extraction ────────────────────────────────────────────────

_recipient_domain := d if {
	parts := split(_recipient, "@")
	count(parts) == 2
	d := parts[1]
}

_recipient_in_allowlist if {
	count(_domain_allowlist) > 0
	_recipient_domain in _domain_allowlist
}

_allowlist_configured if {
	count(_domain_allowlist) > 0
}

# ── Probe target authorization ─────────────────────────────────────────────────
# A target is only authorized two ways:
#   (a) it's on the pre-approved target list, or
#   (b) a token was supplied AND that token appears in verified_tokens — i.e.
#       something upstream of this policy actually checked it. A bare
#       non-empty string is never sufficient on its own unless a deployer
#       has explicitly disabled require_explicit_authorization.

_target_is_approved if {
	_target_url in _approved_targets
}

_token_is_verified if {
	_auth_token != ""
	_auth_token in _verified_tokens
}

_token_is_present_unverified if {
	_auth_token != ""
	not _require_explicit_authorization
}

_target_is_authorized if {
	_target_is_approved
}

_target_is_authorized if {
	_token_is_verified
}

_target_is_authorized if {
	_token_is_present_unverified
}

# ── Repository authorization ───────────────────────────────────────────────────

_repo_list_configured if {
	count(_approved_repos) > 0
}

_repo_is_approved if {
	_repo in _approved_repos
}

# ── Non-compliance ratio ───────────────────────────────────────────────────────

_non_compliance_ratio := r if {
	_total_reqs > 0
	r := _not_implemented / _total_reqs
} else := 0.0

# ═══════════════════════════════════════════════════════════════════════════════
# DENY rules
# ═══════════════════════════════════════════════════════════════════════════════

# ─── D1: Confidence gate ───────────────────────────────────────────────────────
# A finding posted with confidence below the minimum threshold — or with no
# confidence reported at all — is treated as unreliable. An agent that omits
# its own confidence score does not get the benefit of the doubt.

deny contains msg if {
	_action == "post_review_finding"
	_confidence < _min_confidence
	msg := sprintf(
		"Code review agent — confidence gate: finding confidence %.2f is below the minimum threshold %.2f (missing confidence is treated as 0.0). Increase model confidence, report it explicitly, or suppress this finding.",
		[_confidence, _min_confidence],
	)
}

# ─── D2: Injection artifact in posted content ─────────────────────────────────

deny contains "Code review agent — output integrity: posted content contains a prompt injection artifact. The review model may have been influenced by malicious content in the diff. Review blocked." if {
	_action in _posting_actions
	_body_contains_injection_artifact
}

# ─── D3: Security probe without VERIFIED authorization ────────────────────────
# An AI agent that can fire SQL injection, XSS, SSRF, and JWT attack payloads
# at arbitrary URLs is a dangerous capability. A bare non-empty token string
# is not proof of authorization — it must appear in context.verified_tokens,
# populated by whatever system actually checked it, unless a deployer has
# explicitly disabled require_explicit_authorization.

deny contains msg if {
	_action == "run_security_probe"
	_require_probe_authorization
	not _target_is_authorized
	msg := sprintf(
		"Code review agent — security probe blocked: target URL '%v' is not in the approved targets list and no verified authorization token was provided. Add the target to context.approved_targets or supply a token that appears in context.verified_tokens.",
		[_target_url],
	)
}

# ─── D4: Destructive probe payload ────────────────────────────────────────────

deny contains msg if {
	_action == "run_security_probe"
	_probe_scope_has_destructive
	msg := sprintf(
		"Code review agent — security probe blocked: probe scope '%v' contains destructive payload keywords. Destructive payloads are never permitted in automated probes.",
		[_probe_scope],
	)
}

# ─── D5: Developer notification — fail closed on missing allowlist ────────────
# If no domain allowlist is configured, ALL developer notifications are
# denied by default (deny_unlisted_notification_domains = true). This
# reverses the original permissive default: an empty allowlist used to mean
# "allow everything," which meant the safety of this rule depended on every
# deployer remembering to configure it. A missing config now fails safe.

deny contains msg if {
	_action == "send_developer_notification"
	_allowlist_configured
	not _recipient_in_allowlist
	msg := sprintf(
		"Code review agent — notification blocked: recipient '%v' is not in the approved domain allowlist. Developer notifications must stay within the organization.",
		[_recipient],
	)
}

deny contains "Code review agent — notification blocked: no recipient domain allowlist is configured. By default, developer notifications are denied until context.recipient_domain_allowlist is set. To allow all domains during early rollout, set deny_unlisted_notification_domains=false explicitly in config." if {
	_action == "send_developer_notification"
	not _allowlist_configured
	_deny_unlisted_notification_domains
}

# ─── D6: Dismissal without reason ─────────────────────────────────────────────

deny contains "Code review agent — dismissal blocked: a dismissal reason is required. Provide params.dismissal_reason explaining why this finding is being dismissed." if {
	_action == "dismiss_finding"
	_require_dismissal_reason
	count(trim_space(_dismissal_reason)) == 0
}

# ─── D7: PR ingestion — fail closed on missing approved-repo list ────────────
# If no approved-repo list is configured, ALL ingestion is denied by default
# (deny_unlisted_repos = true), for the same reason as D5: an empty list
# should not silently mean "review anything."

deny contains msg if {
	_action == "ingest_pull_request"
	_repo_list_configured
	not _repo_is_approved
	msg := sprintf(
		"Code review agent — ingestion blocked: repository '%v' is not in the approved repository list. Add it to context.approved_repos to enable review.",
		[_repo],
	)
}

deny contains "Code review agent — ingestion blocked: no approved-repository list is configured. By default, PR ingestion is denied until context.approved_repos is set. To allow all repositories during early rollout, set deny_unlisted_repos=false explicitly in config." if {
	_action == "ingest_pull_request"
	not _repo_list_configured
	_deny_unlisted_repos
}

# ═══════════════════════════════════════════════════════════════════════════════
# ESCALATE rules
# ═══════════════════════════════════════════════════════════════════════════════

# ─── E1: High-severity security finding requires human review before posting ──

escalate contains "Code review agent — human review required: HIGH severity security finding must be reviewed by a human before posting. Set context.human_approved=true after review." if {
	_action == "post_review_finding"
	lower(_severity) == "high"
	lower(_category) == "security"
	_require_human_for_security
	not _human_approved
	count(deny) == 0
}

# ─── E2: Finding volume exceeds batch limit ────────────────────────────────────

escalate contains msg if {
	_action in {"post_review_finding", "post_review_summary"}
	_findings_in_batch > _max_findings_per_batch
	count(deny) == 0
	msg := sprintf(
		"Code review agent — finding volume: batch contains %v findings, exceeding the limit of %v. Route to human triage before posting.",
		[_findings_in_batch, _max_findings_per_batch],
	)
}

# ─── E3: Developer notification requires human approval ───────────────────────

escalate contains "Code review agent — human review required: developer notifications require human approval before sending. Set context.human_approved=true after review." if {
	_action == "send_developer_notification"
	_require_notification_approval
	not _human_approved
	count(deny) == 0
}

# ─── E4: Probe targeting production environment ───────────────────────────────

escalate contains msg if {
	_action == "run_security_probe"
	_target_appears_production
	not _human_approved
	count(deny) == 0
	msg := sprintf(
		"Code review agent — probe escalated: target '%v' appears to be a production environment. Human approval required before probing production systems.",
		[_target_url],
	)
}

# ─── E5: High non-compliance ratio in assessment ──────────────────────────────

escalate contains msg if {
	_action == "post_compliance_assessment"
	_total_reqs > 0
	_non_compliance_ratio > _non_compliance_threshold
	not _human_approved
	count(deny) == 0
	msg := sprintf(
		"Code review agent — compliance assessment escalated: %v of %v requirements not implemented (%.0f%%, threshold %.0f%%). Human review required before posting.",
		[_not_implemented, _total_reqs,
			_non_compliance_ratio * 100, _non_compliance_threshold * 100],
	)
}

# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT rules
# ═══════════════════════════════════════════════════════════════════════════════

# ─── A1: All VCS-posting actions ──────────────────────────────────────────────

audit contains msg if {
	_action in _posting_actions
	msg := sprintf(
		"Code review agent — audit: %v action recorded. Confidence: %.2f | Severity: %v | Category: %v",
		[_action, _confidence, _severity, _category],
	)
}

# ─── A2: Security probe executions — distinguishes authorized vs. escalated ──
# An "authorized and executed" audit line must be literally true — it should
# not fire when the action was escalated pending human approval.

audit contains msg if {
	_action == "run_security_probe"
	count(deny) == 0
	count(escalate) == 0
	msg := sprintf(
		"Code review agent — audit: security probe authorized and executed for target '%v' | Scope: %v",
		[_target_url, _probe_scope],
	)
}

audit contains msg if {
	_action == "run_security_probe"
	count(deny) == 0
	count(escalate) > 0
	msg := sprintf(
		"Code review agent — audit: security probe escalated, NOT yet executed, for target '%v' | Scope: %v | Pending human approval.",
		[_target_url, _probe_scope],
	)
}

# ─── A3: Finding dismissals ────────────────────────────────────────────────────

audit contains msg if {
	_action == "dismiss_finding"
	count(deny) == 0
	msg := sprintf(
		"Code review agent — audit: finding dismissed. Reason recorded: '%v'",
		[_dismissal_reason],
	)
}

# ─── A4: Developer notifications — distinguishes sent vs. escalated ──────────

audit contains msg if {
	_action == "send_developer_notification"
	count(deny) == 0
	count(escalate) == 0
	msg := sprintf(
		"Code review agent — audit: developer notification dispatched to '%v'",
		[_recipient],
	)
}

audit contains msg if {
	_action == "send_developer_notification"
	count(deny) == 0
	count(escalate) > 0
	msg := sprintf(
		"Code review agent — audit: developer notification drafted for '%v', NOT yet sent | Pending human approval.",
		[_recipient],
	)
}

# ═══════════════════════════════════════════════════════════════════════════════
# Citation keys — matched to RULE_CITATIONS in comply54.core.models
# ═══════════════════════════════════════════════════════════════════════════════

deny_citations contains "ai_agent_confidence_gate" if {
	_action == "post_review_finding"
	_confidence < _min_confidence
}

deny_citations contains "ai_agent_output_integrity" if {
	_action in _posting_actions
	_body_contains_injection_artifact
}

deny_citations contains "ai_agent_probe_unauthorized" if {
	_action == "run_security_probe"
	_require_probe_authorization
	not _target_is_authorized
}

deny_citations contains "ai_agent_destructive_probe" if {
	_action == "run_security_probe"
	_probe_scope_has_destructive
}

deny_citations contains "ai_agent_external_notification" if {
	_action == "send_developer_notification"
	_allowlist_configured
	not _recipient_in_allowlist
}

deny_citations contains "ai_agent_notification_no_allowlist" if {
	_action == "send_developer_notification"
	not _allowlist_configured
	_deny_unlisted_notification_domains
}

deny_citations contains "ai_agent_dismissal_no_reason" if {
	_action == "dismiss_finding"
	_require_dismissal_reason
	count(trim_space(_dismissal_reason)) == 0
}

deny_citations contains "ai_agent_unauthorized_repo" if {
	_action == "ingest_pull_request"
	_repo_list_configured
	not _repo_is_approved
}

deny_citations contains "ai_agent_repo_no_allowlist" if {
	_action == "ingest_pull_request"
	not _repo_list_configured
	_deny_unlisted_repos
}

escalate_citations contains "ai_agent_security_human_gate" if {
	_action == "post_review_finding"
	lower(_severity) == "high"
	lower(_category) == "security"
	_require_human_for_security
	not _human_approved
	count(deny) == 0
}

escalate_citations contains "ai_agent_finding_volume" if {
	_action in {"post_review_finding", "post_review_summary"}
	_findings_in_batch > _max_findings_per_batch
	count(deny) == 0
}

escalate_citations contains "ai_agent_notification_approval" if {
	_action == "send_developer_notification"
	_require_notification_approval
	not _human_approved
	count(deny) == 0
}

escalate_citations contains "ai_agent_production_probe" if {
	_action == "run_security_probe"
	_target_appears_production
	not _human_approved
	count(deny) == 0
}

escalate_citations contains "ai_agent_compliance_assessment" if {
	_action == "post_compliance_assessment"
	_total_reqs > 0
	_non_compliance_ratio > _non_compliance_threshold
	not _human_approved
	count(deny) == 0
}

audit_citations contains "ai_agent_posting_audit" if {
	_action in _posting_actions
}

audit_citations contains "ai_agent_probe_audit" if {
	_action == "run_security_probe"
	count(deny) == 0
}

audit_citations contains "ai_agent_dismissal_audit" if {
	_action == "dismiss_finding"
	count(deny) == 0
}

audit_citations contains "ai_agent_notification_audit" if {
	_action == "send_developer_notification"
	count(deny) == 0
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
