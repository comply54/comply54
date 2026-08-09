"""
Tests for universal/individual-risk-assessment pack.

Coverage
─────────────────────────────────────────────────────────
  DENY
    D1  Lawful basis gate — generation, persistence, export
    D2  Pre-authorization gate — generation without supervisor sign-off
    D3  High-risk label written to permanent record without human review
    D4  Prohibited narrative patterns — absolute condemnation, protected
        characteristics, permanent temporal negatives
    D5  Missing worker identifier — no audit trail possible
    D6  Confidence gate — model confidence below minimum threshold
    D7  High-risk export without authorization

  ESCALATE
    E1  Supervisor ID required for high-risk label persistence
    E2  Export destination not in allowlist (also fail-closed case)
    E3  Data sources absent — assessment has no verifiable basis
    E4  Subject not notified for high-risk assessment

  AUDIT
    A1  All authorized risk narrative generation
    A2  All authorized risk label persistence
    A3  All authorized risk record distribution
    A4  All risk narrative display events (always, regardless of other rules)

  ALLOW
    Clean inputs covering every action type

  CONFIGURATION
    Overrides for min_confidence, require_pre_authorization,
    require_lawful_basis, require_supervisor_id_for_high,
    require_subject_notification, deny_unlisted_export_destinations

  CITATION KEYS
    All rule keys present on violations and audit records

  FALSE-POSITIVE SAFETY
    Legitimate qualified language in narratives must not trigger D4
    Covered actions with unknown action must not trigger
"""

import pytest

from comply54.core.engine import Comply54Engine
from comply54.core.packs import INDIVIDUAL_RISK_ASSESSMENT

# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def engine():
    return Comply54Engine(packs=[INDIVIDUAL_RISK_ASSESSMENT])


def _check(engine, action, params=None, output="", context=None):
    return engine.check(
        action=action,
        params=params or {},
        output=output,
        context=context or {},
    )


def _engine_with_config(config: dict) -> Comply54Engine:
    return Comply54Engine(packs=[INDIVIDUAL_RISK_ASSESSMENT], config=config)


# ── Shared valid payloads ──────────────────────────────────────────────────────

_VALID_GENERATION = {
    "params": {
        "worker_id": "agent-00123",
        "assessment_type": "field_agent_risk",
        "data_sources": ["performance_history", "disciplinary_records", "attendance"],
    },
    "context": {
        "human_approved": True,
        "lawful_basis": "legitimate_interests",
        "supervisor_id": "mgr-456",
    },
}

_VALID_PERSISTENCE = {
    "params": {
        "worker_id": "agent-00123",
        "risk_label": "low",
        "narrative": "Based on 12 months of performance records, the agent meets all targets consistently.",
        "confidence": 0.85,
        "recommendations": ["Continue standard monitoring cycle."],
    },
    "context": {
        "human_approved": True,
        "lawful_basis": "legitimate_interests",
        "supervisor_id": "mgr-456",
        "subject_notified": True,
    },
}

_VALID_EXPORT = {
    "params": {
        "worker_id": "agent-00123",
        "risk_label": "low",
        "narrative": "Performance data supports a low-risk classification.",
        "destination": "hr.internal",
    },
    "context": {
        "human_approved": True,
        "lawful_basis": "legitimate_interests",
        "supervisor_id": "mgr-456",
        "export_allowlist": ["hr.internal", "reporting.internal"],
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# ALLOW — clean inputs across every covered action
# ═══════════════════════════════════════════════════════════════════════════════


class TestCleanInputs:
    def test_generate_risk_narrative_clean(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context=_VALID_GENERATION["context"],
        )
        assert result.overall == "audit"  # A1 always produces an audit record

    def test_persist_risk_label_low_clean(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params=_VALID_PERSISTENCE["params"],
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "audit"

    def test_persist_risk_assessment_alias_clean(self, engine):
        # persist_risk_assessment is an alias for persist_risk_label
        result = _check(
            engine,
            action="persist_risk_assessment",
            params=_VALID_PERSISTENCE["params"],
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "audit"

    def test_persist_moderate_risk_clean(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                **_VALID_PERSISTENCE["params"],
                "risk_label": "moderate",
                "narrative": "Performance data indicates moderate reliability concerns based on 3 late submissions in the review period.",
                "confidence": 0.78,
            },
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "audit"

    def test_persist_high_risk_fully_authorized(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00999",
                "risk_label": "high",
                "narrative": "Available records show 7 disciplinary actions and 12 unauthorized absences in the review period. Performance targets not met for 4 consecutive quarters.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-789",
                "subject_notified": True,
            },
        )
        assert result.overall == "audit"

    def test_export_risk_record_clean(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params=_VALID_EXPORT["params"],
            context=_VALID_EXPORT["context"],
        )
        assert result.overall == "audit"

    def test_display_risk_narrative_always_audit(self, engine):
        # display_risk_narrative is always audited — the A4 rule fires unconditionally
        result = _check(
            engine,
            action="display_risk_narrative",
            params={"worker_id": "agent-00123", "risk_label": "low"},
            context={"supervisor_id": "mgr-456"},
        )
        assert result.overall == "audit"

    def test_unknown_action_not_governed(self, engine):
        result = _check(engine, action="fetch_worker_profile")
        assert result.overall == "allow"


# ═══════════════════════════════════════════════════════════════════════════════
# DENY D1 — Lawful basis gate
# ═══════════════════════════════════════════════════════════════════════════════


class TestLawfulBasisGate:
    def test_generate_no_lawful_basis_denied(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context={
                "human_approved": True,
                "supervisor_id": "mgr-456",
                # lawful_basis intentionally absent
            },
        )
        assert result.overall == "deny"

    def test_persist_no_lawful_basis_denied(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params=_VALID_PERSISTENCE["params"],
            context={
                "human_approved": True,
                "supervisor_id": "mgr-456",
                "subject_notified": True,
                # lawful_basis intentionally absent
            },
        )
        assert result.overall == "deny"

    def test_export_no_lawful_basis_denied(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params=_VALID_EXPORT["params"],
            context={
                "human_approved": True,
                "supervisor_id": "mgr-456",
                "export_allowlist": ["hr.internal"],
                # lawful_basis intentionally absent
            },
        )
        assert result.overall == "deny"

    @pytest.mark.parametrize("basis", [
        "legitimate_interests",
        "contract",
        "legal_obligation",
        "public_task",
        "vital_interests",
        "consent",
    ])
    def test_all_valid_lawful_bases_pass(self, engine, basis):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context={
                "human_approved": True,
                "lawful_basis": basis,
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall != "deny", f"Lawful basis '{basis}' should not be denied"

    def test_display_not_subject_to_lawful_basis_gate(self, engine):
        # display_risk_narrative is not in the D1 covered action set
        result = _check(
            engine,
            action="display_risk_narrative",
            params={"worker_id": "agent-00123"},
            context={"supervisor_id": "mgr-456"},
            # no lawful_basis — display is always just audited
        )
        assert result.overall == "audit"

    def test_citation_key_no_lawful_basis(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context={"human_approved": True, "supervisor_id": "mgr-456"},
        )
        assert result.overall == "deny"
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_no_lawful_basis" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# DENY D2 — Pre-authorization gate
# ═══════════════════════════════════════════════════════════════════════════════


class TestPreAuthorizationGate:
    def test_generate_no_approval_denied(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                # human_approved intentionally absent
            },
        )
        assert result.overall == "deny"

    def test_generate_false_approval_denied(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context={
                "human_approved": False,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall == "deny"

    def test_persist_does_not_require_pre_auth_flag(self, engine):
        # D2 only applies to generate_risk_narrative, not to persist
        result = _check(
            engine,
            action="persist_risk_label",
            params=_VALID_PERSISTENCE["params"],
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "subject_notified": True,
                # human_approved absent — but D2 only fires on generation
            },
        )
        # D3 may fire if risk_label is "high"; for "low" label no deny expected
        assert result.overall != "deny" or result.overall == "deny"  # just check D2 not the culprit
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_no_pre_authorization" not in citations

    def test_citation_key_no_pre_authorization(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context={"lawful_basis": "legitimate_interests"},
        )
        assert result.overall == "deny"
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_no_pre_authorization" in citations

    def test_require_pre_authorization_disabled(self):
        e = _engine_with_config({"individual_risk_assessment": {"require_pre_authorization": False}})
        result = _check(
            e,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                # human_approved absent — but D2 is disabled
            },
        )
        # No D2 deny — but D5 might fire if worker_id present, E3 if no data_sources
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_no_pre_authorization" not in citations


# ═══════════════════════════════════════════════════════════════════════════════
# DENY D3 — High-risk label without human review
# ═══════════════════════════════════════════════════════════════════════════════


class TestHighRiskNoReview:
    def test_persist_high_no_approval_denied(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Performance data shows sustained underperformance across all metrics.",
                "confidence": 0.80,
            },
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "subject_notified": True,
                # human_approved intentionally absent
            },
        )
        assert result.overall == "deny"

    def test_persist_assessment_alias_high_no_approval_denied(self, engine):
        result = _check(
            engine,
            action="persist_risk_assessment",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Records indicate significant risk based on documented incidents.",
                "confidence": 0.75,
            },
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "subject_notified": True,
            },
        )
        assert result.overall == "deny"

    def test_persist_low_no_approval_passes(self, engine):
        # D3 only applies to high risk labels, not low or moderate
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "low",
                "narrative": "All performance targets met consistently.",
                "confidence": 0.88,
            },
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "subject_notified": True,
                # human_approved absent — but D3 only fires on "high"
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_high_risk_no_review" not in citations

    def test_persist_high_with_approval_passes_d3(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Available records document persistent reliability failures over 8 months.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-789",
                "subject_notified": True,
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_high_risk_no_review" not in citations

    def test_citation_key_high_risk_no_review(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Risk indicators present across performance data.",
                "confidence": 0.80,
            },
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "subject_notified": True,
            },
        )
        assert result.overall == "deny"
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_high_risk_no_review" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# DENY D4 — Prohibited narrative patterns
# ═══════════════════════════════════════════════════════════════════════════════


class TestProhibitedNarrativePatterns:
    def _persist_with_narrative(self, engine, narrative: str, risk_label: str = "moderate"):
        return _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": risk_label,
                "narrative": narrative,
                "confidence": 0.80,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "subject_notified": True,
            },
        )

    # ── Absolute character condemnation ───────────────────────────────────────

    @pytest.mark.parametrize("phrase", [
        "This agent is a fraudster who has been stealing from customers.",
        "Employee is a fraud and cannot be retained.",
        "Agent is dishonest and cannot be given financial responsibilities.",
        "Record shows the agent is corrupt beyond any doubt.",
        "This individual is a liar who fabricates reports.",
        "Agent is a thief — multiple items missing from stock.",
        "Subject is fundamentally dishonest and poses ongoing risk.",
        "Employee is inherently unreliable and will always underperform.",
        "Agent is inherently corrupt and unfit for duty.",
        "This individual has no integrity and should be terminated.",
        "Employee is morally bankrupt and unfit for public-facing roles.",
        "Agent is completely incompetent and has been since joining.",
        "Subject is a total failure across all performance metrics.",
        "This person is worthless to the organization.",
        "Employee is useless and cannot be rehabilitated.",
    ])
    def test_absolute_condemnation_denied(self, engine, phrase):
        result = self._persist_with_narrative(engine, phrase)
        assert result.overall == "deny", f"Phrase should be denied: {phrase[:60]}"
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_prohibited_narrative" in citations

    # ── Protected-characteristic reasoning ───────────────────────────────────

    @pytest.mark.parametrize("phrase", [
        "The agent is flagged as high risk because of his religion.",
        "Risk elevated due to her tribe and known cultural practices.",
        "Agent's background makes her unreliable — his religious background is a concern.",
        "Risk elevated due to his ethnicity and associated patterns.",
        "Performance concerns are linked to due to her marital status.",
        "Subject assessed as high risk because of his age.",
        "Risk elevated due to his tribe and regional background.",
        "Assessment influenced by her religious background.",
    ])
    def test_protected_characteristic_reasoning_denied(self, engine, phrase):
        result = self._persist_with_narrative(engine, phrase)
        assert result.overall == "deny", f"Protected characteristic phrase should be denied: {phrase[:60]}"

    # ── Permanent temporal negatives ──────────────────────────────────────────

    @pytest.mark.parametrize("phrase", [
        "This agent will never be honest with supervisors.",
        "Employee will never improve regardless of intervention.",
        "Agent will always defraud the company given the opportunity.",
        "This individual will always fail in a supervisory role.",
        "Subject can never be trusted with cash handling.",
    ])
    def test_permanent_temporal_negatives_denied(self, engine, phrase):
        result = self._persist_with_narrative(engine, phrase)
        assert result.overall == "deny", f"Permanent negative phrase should be denied: {phrase[:60]}"

    # ── D4 on export action ───────────────────────────────────────────────────

    def test_prohibited_phrase_in_export_denied(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "moderate",
                "narrative": "Agent is a fraudster — confirmed by multiple incidents.",
                "destination": "hr.internal",
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "export_allowlist": ["hr.internal"],
            },
        )
        assert result.overall == "deny"
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_prohibited_narrative" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# DENY D5 — Missing worker identifier
# ═══════════════════════════════════════════════════════════════════════════════


class TestMissingWorkerId:
    def test_generate_no_worker_id_denied(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params={
                "assessment_type": "field_agent_risk",
                "data_sources": ["performance_history"],
                # worker_id intentionally absent
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall == "deny"

    def test_generate_empty_worker_id_denied(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params={
                "worker_id": "",
                "assessment_type": "field_agent_risk",
                "data_sources": ["performance_history"],
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall == "deny"

    def test_citation_key_missing_worker_id(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params={
                "data_sources": ["performance_history"],
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall == "deny"
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_missing_worker_id" in citations

    def test_persist_without_worker_id_not_subject_to_d5(self, engine):
        # D5 is only enforced on generate_risk_narrative, not persist
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                # worker_id absent
                "risk_label": "low",
                "narrative": "Performance targets consistently met.",
                "confidence": 0.85,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "subject_notified": True,
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_missing_worker_id" not in citations


# ═══════════════════════════════════════════════════════════════════════════════
# DENY D6 — Confidence gate
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfidenceGate:
    @pytest.mark.parametrize("confidence", [0.0, 0.30, 0.50, 0.59, 0.599])
    def test_low_confidence_persist_denied(self, engine, confidence):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                **_VALID_PERSISTENCE["params"],
                "confidence": confidence,
            },
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "deny", f"Confidence {confidence} should be denied on persist"

    def test_missing_confidence_treated_as_zero(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "low",
                "narrative": "Performance targets met.",
                # confidence intentionally absent
            },
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "deny"

    def test_exactly_at_threshold_passes_d6(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                **_VALID_PERSISTENCE["params"],
                "confidence": 0.60,
            },
            context=_VALID_PERSISTENCE["context"],
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_low_confidence" not in citations

    def test_high_confidence_passes(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                **_VALID_PERSISTENCE["params"],
                "confidence": 0.95,
            },
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "audit"

    def test_confidence_gate_custom_threshold(self):
        e = _engine_with_config({"individual_risk_assessment": {"min_confidence": 0.80}})
        result = _check(
            e,
            action="persist_risk_label",
            params={**_VALID_PERSISTENCE["params"], "confidence": 0.75},
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "deny"

    def test_confidence_gate_relaxed(self):
        e = _engine_with_config({"individual_risk_assessment": {"min_confidence": 0.40}})
        result = _check(
            e,
            action="persist_risk_label",
            params={**_VALID_PERSISTENCE["params"], "confidence": 0.50},
            context=_VALID_PERSISTENCE["context"],
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_low_confidence" not in citations

    def test_confidence_gate_only_on_persist_not_generate(self, engine):
        # D6 applies to persistence, not generation
        result = _check(
            engine,
            action="generate_risk_narrative",
            params={
                "worker_id": "agent-00123",
                "confidence": 0.10,
                "data_sources": ["performance_history"],
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_low_confidence" not in citations

    def test_citation_key_low_confidence(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={**_VALID_PERSISTENCE["params"], "confidence": 0.20},
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "deny"
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_low_confidence" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# DENY D7 — High-risk export without authorization
# ═══════════════════════════════════════════════════════════════════════════════


class TestHighRiskExportGate:
    def test_export_high_no_approval_denied(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Performance data supports high-risk classification.",
                "destination": "hr.internal",
            },
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "export_allowlist": ["hr.internal"],
                # human_approved intentionally absent
            },
        )
        assert result.overall == "deny"

    def test_export_low_no_approval_passes_d7(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "low",
                "narrative": "Low risk — all targets met.",
                "destination": "hr.internal",
            },
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "export_allowlist": ["hr.internal"],
                # human_approved absent but D7 only fires on "high"
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_high_risk_export" not in citations

    def test_export_high_with_approval_passes_d7(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Documented performance failures across all metrics in the review period.",
                "destination": "hr.internal",
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "export_allowlist": ["hr.internal"],
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_high_risk_export" not in citations

    def test_citation_key_high_risk_export(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "High risk confirmed.",
                "destination": "hr.internal",
            },
            context={
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "export_allowlist": ["hr.internal"],
            },
        )
        assert result.overall == "deny"
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_high_risk_export" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# ESCALATE E1 — Supervisor ID required for high-risk persistence
# ═══════════════════════════════════════════════════════════════════════════════


class TestHighRiskReviewGate:
    def test_persist_high_approved_no_supervisor_id_escalates(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Available data supports high risk classification across review period.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "subject_notified": True,
                # supervisor_id intentionally absent
            },
        )
        assert result.overall == "escalate"

    def test_persist_high_approved_with_supervisor_id_passes(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Data from review period consistently shows high-risk indicators.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-789",
                "subject_notified": True,
            },
        )
        assert result.overall == "audit"

    def test_persist_low_no_supervisor_id_not_escalated_by_e1(self, engine):
        # E1 only fires on high risk labels
        result = _check(
            engine,
            action="persist_risk_label",
            params={**_VALID_PERSISTENCE["params"]},
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "subject_notified": True,
                # supervisor_id absent — but low risk, so E1 should not fire
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_high_risk_review_gate" not in citations

    def test_require_supervisor_id_disabled(self):
        e = _engine_with_config({
            "individual_risk_assessment": {"require_supervisor_id_for_high": False}
        })
        result = _check(
            e,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Risk indicators documented across review period.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "subject_notified": True,
                # supervisor_id absent but rule disabled
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_high_risk_review_gate" not in citations

    def test_citation_key_high_risk_review_gate(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Risk indicators present throughout review period.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "subject_notified": True,
            },
        )
        assert result.overall == "escalate"
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_high_risk_review_gate" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# ESCALATE E2 — Export destination gate
# ═══════════════════════════════════════════════════════════════════════════════


class TestExportDestinationGate:
    def test_export_unlisted_destination_escalates(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "low",
                "narrative": "Low risk confirmed.",
                "destination": "external-vendor.com",
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "export_allowlist": ["hr.internal"],
            },
        )
        assert result.overall == "escalate"

    def test_export_no_allowlist_configured_escalates(self, engine):
        # Fail-closed: no allowlist configured → escalate
        result = _check(
            engine,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "low",
                "narrative": "Low risk confirmed.",
                "destination": "hr.internal",
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                # export_allowlist intentionally absent
            },
        )
        assert result.overall == "escalate"

    def test_export_allowlist_opt_out(self):
        e = _engine_with_config({
            "individual_risk_assessment": {"deny_unlisted_export_destinations": False}
        })
        result = _check(
            e,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "low",
                "narrative": "Low risk confirmed.",
                "destination": "anywhere.io",
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                # no allowlist, but deny_unlisted_export_destinations=false
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_export_no_allowlist" not in citations

    def test_citation_key_export_no_allowlist(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params={
                "worker_id": "agent-00123",
                "risk_label": "low",
                "destination": "hr.internal",
                "narrative": "Low risk.",
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall == "escalate"
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_export_no_allowlist" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# ESCALATE E3 — Data sources absent
# ═══════════════════════════════════════════════════════════════════════════════


class TestNoDataSources:
    def test_generate_no_data_sources_escalates(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params={
                "worker_id": "agent-00123",
                "assessment_type": "field_agent_risk",
                # data_sources intentionally absent
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall == "escalate"

    def test_generate_empty_data_sources_escalates(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params={
                "worker_id": "agent-00123",
                "assessment_type": "field_agent_risk",
                "data_sources": [],
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall == "escalate"

    def test_generate_with_data_sources_passes_e3(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context=_VALID_GENERATION["context"],
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_no_data_sources" not in citations

    def test_citation_key_no_data_sources(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params={"worker_id": "agent-00123"},
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
            },
        )
        assert result.overall == "escalate"
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_no_data_sources" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# ESCALATE E4 — Subject not notified
# ═══════════════════════════════════════════════════════════════════════════════


class TestSubjectNotNotified:
    def test_persist_high_subject_not_notified_escalates(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Documented performance failures across the review period.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-789",
                "subject_notified": False,
            },
        )
        assert result.overall == "escalate"

    def test_persist_high_subject_not_notified_absent_escalates(self, engine):
        # subject_notified absent is equivalent to False
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Risk indicators present in performance data.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-789",
                # subject_notified absent
            },
        )
        assert result.overall == "escalate"

    def test_persist_low_subject_not_notified_not_escalated(self, engine):
        # E4 only fires for high risk labels
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                **_VALID_PERSISTENCE["params"],
                "subject_notified": False,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-456",
                "subject_notified": False,
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_subject_not_notified" not in citations

    def test_require_subject_notification_disabled(self):
        e = _engine_with_config({
            "individual_risk_assessment": {"require_subject_notification": False}
        })
        result = _check(
            e,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Performance data confirms high risk assessment.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-789",
                # subject_notified absent, but rule disabled
            },
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_subject_not_notified" not in citations

    def test_citation_key_subject_not_notified(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "high",
                "narrative": "Risk indicators documented in performance records.",
                "confidence": 0.82,
            },
            context={
                "human_approved": True,
                "lawful_basis": "legitimate_interests",
                "supervisor_id": "mgr-789",
                "subject_notified": False,
            },
        )
        assert result.overall == "escalate"
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_subject_not_notified" in citations


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT — A1, A2, A3, A4
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuditRules:
    def test_a1_generation_audit_record_present(self, engine):
        result = _check(
            engine,
            action="generate_risk_narrative",
            params=_VALID_GENERATION["params"],
            context=_VALID_GENERATION["context"],
        )
        assert result.overall == "audit"
        audit_decisions = [d for d in result.decisions if d.action == "audit"]
        assert len(audit_decisions) > 0
        msgs = [m for d in audit_decisions for m in d.messages]
        assert any("A1 audit" in m for m in msgs)

    def test_a2_persistence_audit_record_present(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params=_VALID_PERSISTENCE["params"],
            context=_VALID_PERSISTENCE["context"],
        )
        assert result.overall == "audit"
        msgs = [m for d in result.decisions if d.action == "audit" for m in d.messages]
        assert any("A2 audit" in m for m in msgs)

    def test_a2_includes_risk_label_and_supervisor(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params=_VALID_PERSISTENCE["params"],
            context=_VALID_PERSISTENCE["context"],
        )
        msgs = [m for d in result.decisions if d.action == "audit" for m in d.messages]
        audit_msg = next((m for m in msgs if "A2 audit" in m), None)
        assert audit_msg is not None
        assert "agent-00123" in audit_msg
        assert "mgr-456" in audit_msg

    def test_a3_export_audit_record_present(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params=_VALID_EXPORT["params"],
            context=_VALID_EXPORT["context"],
        )
        assert result.overall == "audit"
        msgs = [m for d in result.decisions if d.action == "audit" for m in d.messages]
        assert any("A3 audit" in m for m in msgs)

    def test_a3_includes_destination(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params=_VALID_EXPORT["params"],
            context=_VALID_EXPORT["context"],
        )
        msgs = [m for d in result.decisions if d.action == "audit" for m in d.messages]
        audit_msg = next((m for m in msgs if "A3 audit" in m), None)
        assert audit_msg is not None
        assert "hr.internal" in audit_msg

    def test_a4_display_always_audited_despite_no_auth(self, engine):
        # display is always audited — even with no lawful_basis or human_approved
        result = _check(
            engine,
            action="display_risk_narrative",
            params={"worker_id": "agent-00123", "risk_label": "high"},
            context={},  # no auth at all
        )
        assert result.overall == "audit"
        msgs = [m for d in result.decisions if d.action == "audit" for m in d.messages]
        assert any("A4 audit" in m for m in msgs)

    def test_a4_does_not_fire_for_other_actions(self, engine):
        result = _check(
            engine,
            action="persist_risk_label",
            params=_VALID_PERSISTENCE["params"],
            context=_VALID_PERSISTENCE["context"],
        )
        msgs = [m for d in result.decisions if d.action == "audit" for m in d.messages]
        assert not any("A4 audit" in m for m in msgs)


# ═══════════════════════════════════════════════════════════════════════════════
# FALSE-POSITIVE SAFETY
# ═══════════════════════════════════════════════════════════════════════════════


class TestFalsePositiveSafety:
    """Qualified, factual narratives must not trigger D4 prohibited phrase check."""

    @pytest.mark.parametrize("narrative", [
        # Qualified character assessments are fine
        "Based on available records, the agent appears to have reliability concerns in the review period.",
        "Performance data from the past 12 months indicates consistent failure to meet targets.",
        "According to documented disciplinary records, 4 incidents were recorded this quarter.",
        "The performance history shows a pattern of late submissions across 6 months.",
        # Qualified confidence language is fine
        "The available evidence suggests elevated risk, with 3 unauthorized absences confirmed.",
        "Records indicate the agent may benefit from additional supervision and support.",
        # Data-grounded conclusions are fine
        "Financial discrepancies in agent cash-handling records — 3 incidents over 6 months.",
        "Performance targets not met for 4 consecutive review periods per HR records.",
        # Recommendations that reference risk are fine
        "High risk classification based on documented incidents. Recommend enhanced monitoring.",
    ])
    def test_qualified_narrative_not_prohibited(self, engine, narrative: str):
        result = _check(
            engine,
            action="persist_risk_label",
            params={
                "worker_id": "agent-00123",
                "risk_label": "moderate",
                "narrative": narrative,
                "confidence": 0.80,
            },
            context=_VALID_PERSISTENCE["context"],
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "deny"]
        assert "ira_prohibited_narrative" not in citations, (
            f"Legitimate narrative triggered D4 prohibited phrase check: {narrative[:80]}"
        )

    def test_export_to_allowlisted_destination_not_escalated(self, engine):
        result = _check(
            engine,
            action="export_risk_record",
            params={
                **_VALID_EXPORT["params"],
                "destination": "reporting.internal",
            },
            context=_VALID_EXPORT["context"],
        )
        citations = [v.rule_triggered for v in result.violations if v.action == "escalate"]
        assert "ira_export_unlisted_destination" not in citations
