# Changelog

All notable changes to comply54 are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.4.1] — 2026-07-07

### Added

**Policy pack versioning in signed receipts**

Every signed receipt now embeds a `c54_pack_versions` JWT claim — a map of pack ID to the semantic version of its Rego rules at evaluation time.

```json
"c54_pack_versions": {
  "nigeria/cbn":      "1.0.0",
  "nigeria/nfiu-aml": "1.1.0",
  "nigeria/ndpa":     "1.0.0",
  "universal/pii-leakage": "1.0.0"
}
```

This closes a legal evidence gap: a receipt previously proved *that* a check ran — now it also proves *which version of each regulation* was in force at evaluation time. Auditors can confirm the exact policy pack rules that governed a decision, independent of any subsequent pack updates.

- `ReceiptPayload.pack_versions: dict[str, str]` — new field on the Python model (empty dict for pre-v0.4.1 receipts, fully backwards-compatible).
- `ReceiptPayload.packVersions: Record<string, string>` — TypeScript equivalent.
- `PackSpec.version: str` — new field on `PackSpec` (default `"1.0.0"`). Set this whenever a pack's Rego rules change behaviour.
- `PACK_VERSIONS` dict exported from `@comply54/core` for TypeScript consumers.
- `nigeria/nfiu-aml` bumped to `"1.1.0"` — `sanctions_screening_required` fail-closed rule (MLPPA 2022 s.6).
- `nigeria/naicom` bumped to `"1.1.0"` — `state_of_origin` added to prohibited characteristics (NIIRA 2025 Part V).
- 6 new tests in `tests/test_receipts.py` covering pack_versions content, key–packs alignment, semver format, and backwards-compat with legacy receipts (total: 166 tests).

---

## [0.4.0] — 2026-07-06

### Added

**Signed compliance receipts (`comply54[signing]`)**

Ed25519-signed JWT receipts: tamper-evident, offline-verifiable proof attached to every compliance evaluation. Inspired by the AgenTrust TRACE concept.

```bash
pip install 'comply54[signing]'
```

Key additions:

- `comply54.receipts.ReceiptSigner` — signs a `ComplianceResult` into a compact JWT using Ed25519 (EdDSA). Bring-your-own-key (PEM format).
- `comply54.receipts.verify_receipt(token, public_key_pem)` — verifies a receipt offline. Returns `ReceiptPayload`. Raises `InvalidReceiptError` on any failure.
- `comply54.receipts.digest_input(action, params, output, context)` — deterministic SHA-256 digest of an evaluation input. Ties the receipt to the exact call.
- `comply54.receipts.ReceiptPayload` — frozen dataclass: `jti`, `issued_at`, `issuer`, `decision`, `pack`, `regulation`, `rule_triggered`, `messages`, `input_digest`, `comply54_version`, `packs_evaluated`.
- `comply54.receipts.InvalidReceiptError` — raised by `verify_receipt()` on any verification failure.
- `signing_key` parameter on all sector packs (`NigeriaFintechCompliance`, `NigeriaHealthcareCompliance`, `NigeriaInsuranceCompliance`, `KenyaFintechCompliance`, `PanAfricanFintechCompliance`) and `Comply54Engine`. Signing is applied **after** `strict_mode`, so the receipt accurately reflects the final decision returned to the caller.
- `ComplianceResult.receipt_token: Optional[str] = None` — backwards-compatible new field. `None` when no `signing_key` is provided.
- `comply54 CLI` — new commands:
  - `comply54 verify-receipt <token> --public-key <path>` — verify a receipt and optionally confirm it covers a specific input.
  - `comply54 generate-keypair [--out <dir>]` — generate an Ed25519 keypair for development / CI.
- `comply54/_version.py` — single source of truth for `__version__`, imported by the signer to embed the version in every receipt.
- `[project.scripts]` entry in `pyproject.toml` — installs the `comply54` CLI command.
- `[project.optional-dependencies.signing]` — `PyJWT>=2.4.0`, `cryptography>=41.0.0`.
- `docs/receipt-signing.mdx` — full receipt signing documentation.
- 50 new tests in `tests/test_receipts.py` (total: 160 tests).

**Security details:**
- Algorithm: Ed25519 (EdDSA) — 32-byte keys, 64-byte signatures, ~35× faster than RSA-2048, NIST SP 800-186 approved.
- CVE-2022-29217 mitigation: `algorithms=["EdDSA"]` is always passed explicitly to `jwt.decode()`.
- BYOK: comply54 never generates or stores keys on the caller's behalf in production paths.

### Fixed

- `SectorCompliance._apply_strict_mode()` was silently dropping `citations` from upgraded decisions. `citations=d.citations` is now preserved. [#pre-existing]

### Added

- `funding.json` manifest (fundingjson.org v1.1.0) at repo root — describes project funding channels and plans for FLOSS/fund and other grant programs.

### Fixed

**`nigeria/nfiu-aml` — sanctions screening is now fail-closed (MLPPA 2022 s.6)**

Added a hard-block deny rule: any transfer action without `context.sanctions_screened == true` is blocked before execution, regardless of amount. Previously, a transfer to a sanctioned entity could only be blocked by the ₦10M NIP cap — an unrelated rule. The new rule enforces the actual MLPPA 2022 s.6 requirement that counterparties must be screened against the OFAC SDN list, UN Security Council Consolidated List, and NFIU Designated Persons List before any payment is executed.

Affected actions: `transfer_funds`, `send_money`, `wire_transfer`, `nip_transfer`, `instant_payment`, `disburse_funds`, `process_corporate_payment`, `initiate_wire_transfer`, `send_international_payment`.

**Migration:** add `"sanctions_screened": True` to your compliance context after screening is confirmed.

**`nigeria/naicom` — `state_of_origin` added to prohibited underwriting characteristics**

`state_of_origin` was not in the `prohibited_characteristics` set in `naicom.rego`, meaning an underwriting denial citing only state of origin was not caught. It is now explicitly included, consistent with NIIRA 2025 Part V. A denial citing religion was still caught before this fix, but only by coincidence if both fields were present.

**KDPA docs — pack ID vs. file path caution block added**

Added a `:::caution` block to `docs/policy-reference/east-africa/kdpa.mdx` explaining that `kenya/kdpa` (SDK pack ID) ≠ `africa/kdpa.rego` (file path). The SDK silently returns `allow` with no violations if an unrecognised pack ID is passed.

---

## [0.3.0] — 2026-07-02

### Changed

**AutoGen adapter rewritten for autogen-agentchat ≥ 0.4**

The `comply54.autogen` adapter has been rewritten to target the
`autogen-agentchat / autogen-core ≥ 0.4` API. The `pyautogen ≤ 0.2`
dependency has been replaced with `autogen-agentchat>=0.4,<1.0`.

The `UserProxyAgent.execute_function()` override pattern no longer exists in
autogen v0.4. Compliance enforcement now wraps tools at construction time via
`FunctionTool`, which is the idiomatic v0.4 pattern.

**New public API:**

| Function | Description |
|---|---|
| `comply54_tool(fn, compliance, ...)` | Wrap a single callable. Returns a `FunctionTool` for `AssistantAgent(tools=[...])`. |
| `comply54_tools(tools, compliance, ...)` | Bulk-wrap a list of callables or existing `FunctionTool` instances. |
| `compliance_tool(compliance)` | Create a passive self-check tool the agent can call voluntarily. |

**Deprecated / removed API:**

| Symbol | Status | Migration |
|---|---|---|
| `Comply54UserProxy` | Raises `ImportError` with migration guide | Use `comply54_tools()` |
| `register_compliance_guard()` | Raises `ImportError` with migration guide | Use `comply54_tools()` |
| `register_compliance()` | Emits `DeprecationWarning`, returns `FunctionTool` | Use `compliance_tool()` in `tools=[]` |

**Schema preservation:** The original function's type annotations are forwarded
to `FunctionTool` via `__signature__` assignment, so AutoGen generates the
correct JSON schema for the wrapped tool.

**Tests:** 22 unit tests added (`tests/test_autogen.py`); all pass on
Python 3.9 – 3.14.

---

## [0.2.5] — 2026-06-28

### Changed

**NIIRA 2025 — Nigerian Insurance Industry Reform Act 2025 (replaces Insurance Act 2003)**

President Tinubu signed the **Nigerian Insurance Industry Reform Act 2025 (NIIRA 2025)**
into law in August 2025, repealing and consolidating five legacy statutes including the
Insurance Act 2003 (Cap I17 LFN 2004). The `nigeria/naicom` pack and `NigeriaInsuranceCompliance`
sector pack have been updated accordingly.

**Policy changes in `nigeria/naicom`:**

| Change | Detail |
|---|---|
| Citation update | All `Insurance Act 2003` section references updated to `NIIRA 2025` |
| New rule: `niira_60day_deadline` | Claims pending beyond 60 days must be escalated — NIIRA 2025 §210 mandatory settlement deadline |
| Citation update: s.70 → §210 | Claims settlement cite updated to NIIRA 2025 §210 |
| Citation update: s.67 → Part V | Anti-discrimination cite updated to NIIRA 2025 Part V (Market Conduct) |
| Citation update: s.50 → Part V | Policy modification notification cite updated to NIIRA 2025 Part V |
| Denial message update | All deny/escalate/audit messages now reference `NIIRA 2025` instead of `Insurance Act` |

**`NigeriaInsuranceCompliance.regulations` updated:**

```python
# Before
regulations = ["Insurance Act 2003 (Cap I17 LFN 2004)", ...]

# After
regulations = ["Nigerian Insurance Industry Reform Act 2025 (NIIRA 2025)", ...]
```

NAICOM Operational Guidelines 2021 and Market Conduct Guidelines 2023 remain in force
under NIIRA 2025 pending updated NAICOM subsidiary regulations.

---

## [0.2.4] — 2026-06-27

### Added

**NIMC Act 2026 — Nigeria BVN/NIN pack updated (signed 26 June 2026)**

The NIMC Act 2026 repeals and replaces the NIMC Act Cap N99 LFN 2004. Four new
enforcement rules added to `nigeria/bvn-nin`:

| Rule key | Action | Obligation |
|---|---|---|
| `nimc_nin_persistence` | deny | Storing NIN/BVN data after verification is prohibited — NIMC Act 2026 illegal data persistence clause (₦20M corporate / 5yr individual) |
| `nimc_nin_bulk_export` | deny | Bulk NIN/identity data extraction or export is blocked |
| `nimc_purpose_limitation` | escalate | NIN/BVN lookup without a declared purpose, or use for a purpose other than the one consented to, must be escalated |
| `nimc_mandatory_service` | audit | Bank accounts, SIM registration, passports, land transactions, pension enrollment, insurance enrollment, and consumer credit require verified NIN (`context.nin_verified = true`) |

**Citation updates across `nigeria/bvn-nin`:**

All existing NIN rules (`nin_label_pattern`, `vnin_pattern`, `bvn_nin_transmission`,
`nin_verification`, `identifier_gate`) now cite **NIMC Act 2026** instead of the
repealed NIMC Act Cap N99 LFN 2004.

**Pack metadata updated:**

- `regulation`: `"CBN BVN Framework, NIBSS BVN Scheme Rules & NIMC Act 2026"`
- `authority`: `"CBN/NIBSS/NIMC"`
- Pack-level `sources` updated to reference NIMC Act 2026

**TypeScript (`nigeria.ts`):**

- `BVN_NIN_CITATIONS` updated
- `BVN_NIN_RULE_CITATIONS` extended with 4 new entries
- `evaluateBvnNin` extended with `PERSIST_ACTIONS`, `BULK_EXPORT_ACTIONS`,
  `MANDATORY_NIN_ACTIONS` sets and corresponding return paths
- `regulation` field on the base decision updated

---

## [0.2.3] — 2026-06-27

### Added

**Full CrewAI adapter — pre-execution enforcement and output guardrails**

- `Comply54GuardedTool` — wraps any CrewAI `BaseTool` with comply54 pre-execution
  enforcement. The inner tool's original `name`, `description`, and `args_schema` are
  preserved so the agent's interface is unchanged. Blocked calls return structured JSON
  (`blocked`, `decision`, `reason`, `regulation`, `rule_triggered`, `citations`,
  `audit_id`) without executing the inner tool.
- `comply54_guard_tools(compliance, tools, context, block_on_escalate)` — convenience
  function that wraps a list of tools and returns guarded versions. Drop-in replacement
  at the `Agent(tools=...)` call site.
- `Comply54TaskGuardrail` — implements the CrewAI guardrail protocol
  `(TaskOutput) → (bool, Any)`. Checks task output text for PII leakage, BVN/NIN
  exposure, and other output-level violations before the task result is delivered.
- `Comply54CrewTool` now includes `rule_triggered` and `citations` in its JSON output
  (was missing in v0.2.1).

**Full AutoGen adapter — proxy-level pre-execution enforcement**

- `Comply54UserProxy` — drop-in replacement for `autogen.UserProxyAgent`. Overrides
  `execute_function` to evaluate every function/tool call against comply54 before
  execution. Blocked calls inject a structured error dict into the conversation thread
  without running the function — the assistant sees the error and responds to the user.
- `register_compliance_guard(proxy, compliance, context, block_on_escalate)` — patches
  any existing `UserProxyAgent` in-place when you cannot control proxy construction
  (e.g. third-party scaffolding).
- `register_compliance` now includes `rule_triggered` and `citations` in its JSON output
  (was missing in v0.2.1).

All three adapters now return the same `_result_to_dict` shape:
`overall · blocked · audit_id · violations[pack, regulation, jurisdiction, action,
messages, rule_triggered, citations[document, section, authority, year]]`

---

## [0.2.2] — 2026-06-27

### Added

**Per-rule regulatory source traceability (Phase 2)**

- `PolicyDecision.rule_triggered: str | None` — each decision now names the exact rule that
  fired (e.g. `"nip_cap"`, `"no_consent_access"`, `"ctr_threshold"`). Available on both the
  Python and TypeScript models.
- `PolicyDecision.citations` is now **rule-level**, not pack-level. The engine resolves the
  `rule_triggered` key against `comply54.core.citations.RULE_CITATIONS` and returns only the
  citations directly relevant to the triggered rule. Falls back to `PackSpec.sources` when no
  per-rule entry is registered.
- `comply54.core.citations.RULE_CITATIONS` — internal registry mapping
  `"{pack_id}.{rule_key}"` → `list[RegulatorySource]`. 200+ entries covering all 21 packs.
- All 6 Nigeria Rego packs now emit `deny_citations`, `escalate_citations`, and
  `audit_citations` sets alongside the existing message sets. The engine queries these in Pass 2
  of its two-pass evaluation strategy (no extra round-trip).
- All 5 Universal OWASP packs emit citation key sets (Rego) and per-rule maps (TypeScript).
- All 9 Africa DPA packs emit citation key sets (Rego) and per-rule maps (TypeScript).
- TypeScript packs (`nigeria.ts`, `universal.ts`, `africa.ts`) now carry `RULE_CITATIONS` maps
  and override `citations` on every non-allow return.

**Example output delta (v0.2.1 → v0.2.2):**

```python
# v0.2.1 — pack-level (4 sources for all CBN rules)
decision.citations  # [CBN Circular §3.1, CBN NIP §4.2, CBN BVN §2.4, CBN USSD §5.2]

# v0.2.2 — rule-level (1 source for this specific rule)
decision.rule_triggered  # "nip_cap"
decision.citations  # [CBN NIP Framework §4.2 — Per-Transaction Cap]
```

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
