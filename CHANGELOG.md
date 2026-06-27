# Changelog

All notable changes to comply54 are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] — 2026-06-27

### Added

**Regulatory source traceability**

- `RegulatorySource` model — structured citation type with `document`, `section`, `authority`, `year`, `url` fields.
  Exported from `comply54` (Python) and `@comply54/core` (TypeScript).
- `PolicyDecision.citations: list[RegulatorySource]` — every compliance decision now carries the exact
  regulatory documents and sections that back it. The engine populates this automatically from `PackSpec.sources`.
- `ComplianceCertificate` violations export now includes `citations` per violation for full audit trail.
- `PackSpec.sources: list[RegulatorySource]` — each of the 21 packs now has a machine-readable list
  of exact regulatory citations (document name, section, authority, year).

Citation coverage:
- **Nigeria**: NDPA 2023 §24/25/30; CBN Circular FPR/DIR/GEN/CIR/07/003 §3.1 + NIP Framework §4.2;
  BVN Framework §6 + NIBSS Scheme Rules; MLPPA 2022 §10/11; NHA 2014 §26/29/30;
  MDP Act Cap M8 §16; FMOH AI Policy Guideline 4+7; Insurance Act §50/67;
  NAICOM Operational Guidelines 12/15/18; NAICOM Market Conduct Rules 6/11.
- **Africa**: KDPA §25/46; POPIA §11/72; Ghana DPA §17/33; Rwanda Law No. 058/2021 Art. 8+22;
  Egypt PDPL Art. 3+24; Ethiopia PDP Proclamation Art. 22; Mauritius DPA §46;
  Tanzania PDPA §32; Uganda DPPA §26.
- **Universal**: OWASP LLM Top 10 2025 — LLM01 (Prompt Injection), LLM06 (PII Leakage),
  LLM08 (Excessive Agency), LLM09 (Misinformation).

---

## [0.2.0] — 2026-06-27

### Added

**New Policy Packs**

- `nigeria/nha` — Nigeria National Health Act 2014 + FMOH AI in Healthcare Policy (Draft 2024)
  + Medical and Dental Practitioners Act Cap M8 LFN 2004.
  Rules: patient consent gate (NHA s.26 / NDPA s.30), clinical data confidentiality
  (NHA s.29), AI-only diagnosis block (FMOH Guideline 4), AI prescription block
  (MDP Act s.16 / FMOH Guideline 7), cross-border health data block (NDPA s.25),
  bulk / research access escalation.

- `nigeria/naicom` — Insurance Act 2003 (Cap I17 LFN 2004) + NAICOM Operational
  Guidelines 2021 + NAICOM Market Conduct Guidelines 2023.
  Rules: auto-denial cap ₦500K (Guideline 15), senior adjuster threshold ₦2M
  (Guideline 12), life underwriting cap ₦5M (Guideline 18), anti-discrimination
  (Insurance Act s.67 / Market Conduct Rule 6), fraud escalation (Rule 11),
  policy modification notification (Insurance Act s.50), NFIU AML threshold ₦5M.

**New Sector Classes**

- `NigeriaHealthcareCompliance` — composes `nigeria/nha` + `nigeria/ndpa` (special-category
  health data) + `nigeria/bvn-nin` + universal OWASP safety packs. For EHR agents,
  clinical decision support, and telemedicine platforms.

- `NigeriaInsuranceCompliance` — composes `nigeria/naicom` + `nigeria/ndpa` +
  `nigeria/nfiu-aml` + universal OWASP safety packs. For claims processing,
  underwriting engines, and fraud detection platforms.

**New Example Agents**

- `examples/nigeria_health_agent/` — Complete LangGraph agent demonstrating 7 healthcare
  compliance scenarios: EHR access gating, AI diagnosis oversight, prescription control,
  cross-border health data blocking, research purpose escalation.

- `examples/nigeria_insurance_agent/` — Complete LangGraph agent demonstrating 8 insurance
  compliance scenarios: claims adjudication controls, discriminatory pricing denial,
  life underwriting gate, fraud flagging escalation, policy cancellation notification.

**LangGraph Adapter**

- `Comply54Guard` — LangGraph node that intercepts `AIMessage.tool_calls`, evaluates each
  against a `SectorCompliance` pack in-process, and injects `ToolMessage` errors for
  blocked calls. `state["compliance_blocked"]` and `state["compliance_result"]` written
  back to agent state.

- `comply54_route(state)` — conditional routing function: returns `"tools"` if all calls
  passed compliance, `"agent"` if any were blocked.

- `comply54_tool(compliance)` — wraps a `SectorCompliance` as a `StructuredTool` the agent
  can call to self-check before acting.

- `block_on_escalate` parameter on `Comply54Guard` — when `True`, `escalate` decisions are
  treated as hard blocks (strict mode). Default `False`.

**Other**

- `strict_mode` parameter on all sector `__init__` methods — upgrades all `escalate`
  decisions to `deny` at evaluation time.
- `NigeriaFintechCompliance(strict_mode=True)` now correctly forwards to the base class
  (was silently ignored in v0.1.0).
- `nigeria/nha` and `nigeria/naicom` added to `PACK_REGISTRY` and `JURISDICTION_PACKS["NG"]`.

### Changed

- `pyproject.toml` author email corrected to `ginuxtechacademy@gmail.com`.
- `pyproject.toml` optional dependency group `langgraph` now includes `langchain-anthropic>=0.2.0`.
- `comply54/sectors/__init__.py` exports `NigeriaHealthcareCompliance` and
  `NigeriaInsuranceCompliance`.

---

## [0.1.0] — 2026-05-01

### Added

**Core enforcement engine**

- `Comply54Engine` — in-process Rego evaluation via `regopy` (no OPA binary, no subprocess).
- `ComplianceResult`, `PolicyDecision`, `ComplianceCertificate` models.
- `SectorCompliance` base class with `.check()`, `.evaluate()`, `.certificate()`.

**Policy Packs — Nigerian**

- `nigeria/ndpa` — Nigeria Data Protection Act 2023 (NDPA). Data residency, cross-border
  transfer restrictions, bulk export controls (ss.24–25, 30).
- `nigeria/cbn` — CBN Transaction Limits & Controls (FPR/DIR/GEN/CIR/07/003). NIP ₦10M cap,
  tiered KYC limits (Tier 1/2/3), Maker-Checker, bulk payment escalation.
- `nigeria/bvn-nin` — CBN BVN Framework & NIBSS Scheme Rules. Biometric identity data
  handling and access controls.
- `nigeria/nfiu-aml` — MLPPA 2022 / NFIU AML Guidelines. CTR thresholds, STR triggers,
  cross-border cash movement.

**Policy Packs — East Africa**

- `kenya/kdpa` — Kenya Data Protection Act 2019.
- `mauritius/dpa` — Mauritius Data Protection Act 2017.
- `tanzania/pdpa` — Tanzania Personal Data Protection Act 2022.
- `uganda/dppa` — Uganda Data Protection and Privacy Act 2019.
- `ethiopia/pdp` — Ethiopia Personal Data Protection Proclamation 1321/2024.
- `rwanda/dpa` — Rwanda Law No. 058/2021 on Personal Data Protection.

**Policy Packs — Southern / West / North Africa**

- `south-africa/popia` — POPIA Act 4 of 2013.
- `ghana/dpa` — Ghana Data Protection Act 843 of 2012.
- `egypt/pdpl` — Egypt Personal Data Protection Law No. 151/2020.

**Universal Safety Packs**

- `universal/pii-leakage` — OWASP LLM06 Sensitive Information Disclosure.
- `universal/prompt-injection` — OWASP LLM01/ASI01 Prompt Injection.
- `universal/tool-permissions` — OWASP LLM08 Excessive Agency.
- `universal/human-approval` — OWASP LLM09 Overreliance.
- `universal/model-routing` — OWASP LLM03/LLM05 Model Selection Controls.

**Sector Classes**

- `NigeriaFintechCompliance` — NDPA + CBN + BVN/NIN + NFIU AML + OWASP.
- `KenyaFintechCompliance` — KDPA + OWASP.
- `PanAfricanFintechCompliance` — all 13 African jurisdiction packs + OWASP.

**Framework Adapters**

- `comply54.langchain` — LangChain `StructuredTool` wrapper and legacy `compliance_node`.
- `comply54.crewai` — CrewAI tool integration.
- `comply54.autogen` — AutoGen middleware.
