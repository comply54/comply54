# Comply54 — Product Roadmap

> **North Star:** Comply54 becomes the African AI compliance infrastructure layer —
> embedded in every serious AI agent stack operating in Africa, impossible to remove,
> the way Stripe is impossible to remove from a payments stack.

---

## The Honest Starting Point

Before planning forward, it is important to be clear about where we are today.

**What we have built that is genuinely valuable:**
- `agt-policies-nigeria` — African AI governance policies in OPA/Rego with exact regulatory citations. Referenced by Microsoft AGT. Nothing else like it exists.
- `guardrails-african-pii` and `guardrails-african-compliance` — published on PyPI, installable, covering 6 jurisdictions. Fills a gap Presidio and spaCy ignore.
- `eve-policy` — published on npm, a real policy enforcement engine for the Vercel Eve framework.
- A registry of 19 packs across 10 jurisdictions with real regulatory depth.

**What we have that is still scaffolding:**
- `registry.json` is a bookmark file. It has no runtime value on its own.
- The Python adapters (LangChain, CrewAI, AutoGen, AGT) call `opa eval` via subprocess. Any developer writes this in an afternoon. They are not defensible.
- `@comply54/eve` profiles are valuable content but built on a niche framework.
- None of the adapters are published packages. Nothing is installable via `pip install comply54`.

**The gap:** A developer who wants NDPA compliance in their LangChain agent today still has to: find the Rego file, install OPA, write subprocess glue, and handle errors themselves. Comply54 does not yet remove that friction.

---

## The Flutterwave Lesson Applied Here

Flutterwave's journey from payments API to licensed bank teaches five things that map directly to comply54:

| Flutterwave Lesson | Comply54 Application |
|---|---|
| Start narrow, go deep | Stop adding jurisdictions until one enforcement path is production-grade |
| Build infrastructure, not software | Subprocess adapters are software. A hosted API is infrastructure. |
| Own the value chain | OPA running on the developer's machine is value leaking out. OPA running inside comply54 is value captured. |
| Think systems over features | The question is not "which adapter next?" but "which layer of the compliance stack do we own?" |
| Outcomes over interface | Developers do not care about Rego files. They care that their agent is compliant. Hide the complexity. |

The critical distinction from that article: **"Impressive products win attention. Indispensable products win markets."**

Right now comply54 is impressive to people who understand African AI governance. It is not yet indispensable to any developer's production stack. That is the gap this roadmap closes.

---

## Strategic Direction

Comply54 must own **one specific layer**: the enforcement decision layer.

Not the policy authoring layer (that is agt-policies-nigeria).
Not the framework integration layer (that is adapters).
The layer where an agent action comes in and a compliance decision — allow, deny, escalate, audit — comes out.

That layer, made available as an API, becomes infrastructure. It becomes the thing that enterprise teams build on top of, not around.

```
Agent Action
     │
     ▼
┌─────────────────────────────┐
│   comply54 enforcement API  │  ◄── This is the layer we must own
│   (hosted, no OPA required) │
└─────────────────────────────┘
     │              │
     ▼              ▼
  Decision       Audit Log
(allow/deny/    (tamper-proof,
 escalate)       exportable)
```

---

## Phase 0 — Foundation (COMPLETE)

**Status:** Done. Do not revisit until Phase 2 is shipped.

- [x] OPA Rego policies for Nigeria (NDPA, CBN, BVN/NIN, NFIU, POS geo-fencing)
- [x] East/West/Southern Africa data protection packs (KE, ZA, GH, RW, EG, ET, MU, TZ, UG)
- [x] 5 universal safety packs (prompt injection, PII leakage, tool permissions, human approval, model routing)
- [x] registry.json v1.4.0 (19 packs, 10 jurisdictions)
- [x] Thin adapters for LangChain, CrewAI, AutoGen, AGT, Eve
- [x] `guardrails-african-pii` on PyPI
- [x] `guardrails-african-compliance` on PyPI
- [x] `eve-policy` on npm
- [x] Microsoft AGT citation (agt-policies-nigeria)
- [x] JSON Schema validator + CI tooling

**What Phase 0 proves:** The regulatory research is done. The policies are real. The domain knowledge exists. The foundation is solid.

---

## Phase 0.5 — Sector Packs & LangGraph Adapter (COMPLETE)

**Status:** Done as of v0.2.0.

These items were originally scoped to Phase 1 but shipped early because the
embedded OPA foundation (regopy) was already in place.

- [x] `NigeriaFintechCompliance` composed sector pack (NDPA + CBN + BVN/NIN + NFIU AML + OWASP)
- [x] `KenyaFintechCompliance` composed sector pack
- [x] `PanAfricanFintechCompliance` composed sector pack (all 13 jurisdictions + OWASP)
- [x] `NigeriaHealthcareCompliance` — NHA 2014 + NDPA (special-category) + FMOH AI Policy + OWASP
- [x] `NigeriaInsuranceCompliance` — Insurance Act 2003 + NAICOM 2021/2023 + NFIU AML + OWASP
- [x] `nigeria/nha` Rego pack (National Health Act 2014 + FMOH AI in Healthcare Policy)
- [x] `nigeria/naicom` Rego pack (Insurance Act 2003 + NAICOM Operational & Market Conduct Guidelines)
- [x] `Comply54Guard` — LangGraph node with in-process compliance interception
- [x] `comply54_route` — conditional routing function for guard node
- [x] `comply54_tool` — LangChain StructuredTool wrapper for self-check pattern
- [x] `block_on_escalate` / `strict_mode` support
- [x] Compliance certificate output (JSON, SHA-256 tamper-evident hash)
- [x] Example agents: `nigeria_fintech_agent`, `nigeria_health_agent`, `nigeria_insurance_agent`

---

## Phase 1 — Go Deep Before Going Wide

**Timeline:** 6–10 weeks  
**Theme:** Make one path production-grade. Earn the right to expand.  
**Milestone:** A developer can add NDPA + CBN compliance to a LangChain agent in under 10 minutes with zero OPA knowledge required.

### 1.1 — Embedded OPA (Kill the Subprocess) ✅ DONE

~~The subprocess `opa eval` approach is the single biggest technical debt in comply54.~~

**Done.** `regopy` provides in-process Rego evaluation — no subprocess, no OPA binary,
works in serverless environments. All sector packs evaluate in-process via `Comply54Engine`.
The LangGraph adapter (`Comply54Guard`) is rewritten on top of this.

**Deliverables:**
- [x] `comply54` Python package with embedded evaluation via `regopy` (no subprocess)
- [x] `Comply54Guard` LangGraph adapter rewritten on top of embedded evaluator
- [x] All tests passing against embedded evaluator
- [ ] `@comply54/core` npm package with OPA-WASM evaluation ← still pending
- [ ] Published to PyPI as installable package ← still pending

### 1.2 — Documentation Site (comply54.io)

Right now comply54.io is referenced in the registry schema but nothing is there. The documentation is the product for an infrastructure library. Without it, even good code does not get adopted.

**Deliverables:**
- [ ] comply54.io live (can be Mintlify, Docusaurus, or plain Next.js)
- [ ] Quickstart: "Add NDPA compliance to your LangChain agent in 5 minutes"
- [ ] Policy reference: every pack, every rule, every regulatory article it maps to
- [ ] API reference (even if the hosted API comes in Phase 2, document the interface now)
- [ ] Nigerian fintech compliance guide (the most complete, most cited use case)

### 1.3 — Sector Packs ✅ DONE (Python; TypeScript pending)

**Done** for the Python layer. See Phase 0.5 above for the full list.

```python
from comply54.sectors import NigeriaFintechCompliance

guard = NigeriaFintechCompliance()
# Covers: NDPA + CBN limits + BVN/NIN protection + NFIU AML + OWASP
```

**Deliverables:**
- [x] `NigeriaFintechCompliance` composed pack
- [x] `NigeriaHealthcareCompliance` composed pack
- [x] `NigeriaInsuranceCompliance` composed pack
- [x] `KenyaFintechCompliance` composed pack
- [x] `PanAfricanFintechCompliance` composed pack (all jurisdictions, strict mode)
- [x] Compliance certificate output (JSON, SHA-256 hash, exportable for auditors)
- [ ] TypeScript equivalents ← still pending

### 1.4 — Real Test Coverage

Every pack must have end-to-end tests that run in CI without OPA installed on the runner. This is what makes comply54 trustworthy for an enterprise audit.

**Deliverables:**
- [ ] CI pipeline (GitHub Actions) running all 306+ Rego tests + Python adapter tests + TS adapter tests
- [ ] Coverage badge on README
- [ ] Test against real regulatory scenarios (not just unit tests — integration scenarios like "agent tries to transfer ₦15M without CTR" must fail predictably)

---

## Phase 2 — Own the Enforcement Layer

**Timeline:** 8–14 weeks after Phase 1  
**Theme:** Become infrastructure. A hosted API turns comply54 from a library into a platform.  
**Milestone:** An enterprise team can integrate comply54 without touching OPA, Rego, or any policy file. POST in, decision out.

### 2.1 — Comply54 Enforcement API

This is the most important product decision in the entire roadmap. A hosted REST API that accepts agent actions and returns compliance decisions removes every barrier to adoption.

```http
POST https://api.comply54.io/v1/evaluate
Authorization: Bearer <api_key>

{
  "jurisdiction": "NG",
  "sector": "fintech",
  "action": {
    "tool": "transfer_funds",
    "input": { "amount": 15000000, "currency": "NGN", "recipient": "external" }
  },
  "agent_context": {
    "user_tier": "tier2",
    "session_id": "sess_abc123"
  }
}

→ 200 OK
{
  "decision": "deny",
  "rule_triggered": "cbn_ctr_threshold",
  "regulation": "CBN AML/CFT/CPF Regulations 2023, §12(3)",
  "message": "Transaction exceeds mandatory CTR threshold (₦10,000,000). Report to NFIU required.",
  "audit_id": "aud_xyz789"
}
```

No OPA. No Rego. No subprocess. One HTTP call.

**Deliverables:**
- [ ] `api.comply54.io` live — FastAPI or Hono backend
- [ ] Authentication (API keys, JWT)
- [ ] Rate limiting per tier (free / pro / enterprise)
- [ ] All 19 packs available via the API
- [ ] Decision latency < 50ms p99
- [ ] SDK wrappers: `comply54.evaluate(action)` in Python and TypeScript that call the API
- [ ] OpenAPI spec published

### 2.2 — Audit Trail Infrastructure

Compliance without proof is worthless to a legal or regulatory team. Comply54 must generate tamper-proof audit logs that an enterprise can show to NDPC, CBN, or any African DPA during an investigation.

**Deliverables:**
- [ ] Every API call produces an immutable audit record
- [ ] Audit export: JSON, CSV, PDF report
- [ ] Retention policy (configurable: 90 days / 1 year / 7 years for financial)
- [ ] Audit dashboard at comply54.io/dashboard
- [ ] Signed audit certificates (cryptographically signed, verifiable without comply54)

### 2.3 — Webhook / Event Stream

Enterprise AI pipelines are async. The enforcement API needs a push model, not just request/response.

**Deliverables:**
- [ ] Webhook delivery for deny/escalate decisions
- [ ] Slack integration (escalations routed to compliance officer channel)
- [ ] Severity levels: INFO → WARNING → ESCALATE → BLOCK

---

## Phase 3 — Complete the Library Shelf

**Timeline:** Parallel to Phase 2, ongoing  
**Theme:** No African jurisdiction with an enacted DPA should be missing from comply54.  
**Rule:** Do not ship a jurisdiction pack without: exact regulatory citation, test coverage, and a sector-specific composition.

### 3.1 — Remaining Jurisdictions

Current coverage: 10 jurisdictions. Target: all 30+ African countries with enacted or operational data protection laws.

**Priority queue (by AI agent deployment density):**

| Jurisdiction | Law | Status | Priority |
|---|---|---|---|
| Senegal | Loi n°2008-12 (DPA 2008) | Missing | High |
| Côte d'Ivoire | Loi n°2013-450 | Missing | High |
| Morocco | Law 09-08 | Missing | High |
| Tunisia | Organic Law 2004-63 | Missing | High |
| Cameroon | Law No. 2010/012 | Missing | Medium |
| Zimbabwe | Cyber and Data Protection Act 2021 | Missing | Medium |
| Zambia | Data Protection Act 2021 | Missing | Medium |
| Botswana | Data Protection Act 2018 | Missing | Medium |
| Angola | Lei n.º 22/11 | Missing | Medium |
| Benin | Loi n°2017-20 | Missing | Low |

**Each pack must include:**
- Rego policy with exact article citations
- YAML metadata with enforcing authority, effective date, penalties
- Minimum 15 test cases
- Sector-specific composition (at minimum: fintech + general)

### 3.2 — Sector Packs (Cross-Jurisdiction)

Right now comply54 is jurisdiction-first. Enterprise customers think sector-first. A healthtech company does not think "I need Kenya compliance" — they think "I need African healthtech compliance."

**Progress:** Nigeria-scoped sector packs for health and insurance shipped in v0.2.0.
Pan-African compositions are the next step.

**Deliverables:**
- [x] `NigeriaHealthcareCompliance` — NHA 2014 + NDPA special-category + FMOH AI Policy ✅
- [x] `NigeriaInsuranceCompliance` — Insurance Act 2003 + NAICOM + NFIU AML ✅
- [ ] `AfricanHealthtechCompliance` — extend with KDPA §43 + POPIA §26 + cross-border medical data
- [ ] `AfricanInsuranceCompliance` — extend with IRA Kenya + FSB South Africa + actuary data handling
- [ ] `AfricanTelecomCompliance` — NCC Nigeria + CA Kenya + ICASA South Africa + subscriber data rules
- [ ] `AfricanEcommerceCompliance` — Consumer protection + payment data + cross-border sales rules

### 3.3 — Cross-Border Transfer Matrix

One of the most complex problems for African AI companies: can I send this user's data to this country for model inference? No tool answers this today.

**Deliverable:**
- [ ] Interactive matrix: source country × destination country × data category → decision (permitted / restricted / prohibited / adequate safeguards required)
- [ ] Covers all 54 African countries + major inference destinations (US, EU, China, India)
- [ ] Cites the exact legal basis for each cell
- [ ] Queryable via the enforcement API: `POST /v1/transfer-check`

---

## Phase 4 — Enforcement Intelligence

**Timeline:** 6–12 months from now  
**Theme:** Static policies go stale. Comply54 must track regulatory changes in real time.

### 4.1 — Regulatory Change Monitoring

African regulations change. CBN issues new circulars. NDPC publishes guidance. A compliance system that does not track this becomes a liability, not an asset.

**Deliverables:**
- [ ] Regulatory change feed — monitored sources per jurisdiction (official gazettes, regulator websites)
- [ ] Changelog: every policy version with diff of what changed and why
- [ ] Email/webhook alerts when a pack affecting your deployed jurisdictions changes
- [ ] Semantic versioning of every pack: `ndpa-data-residency@1.0.0` → `1.1.0` when NDPC issues new guidance

### 4.2 — Enforcement Intelligence Dashboard

- [ ] Penalty tracker: recent NDPC enforcement actions, CBN fines, ODPC decisions
- [ ] Jurisdiction risk scores: updated monthly, cites real enforcement activity
- [ ] "What would have triggered a violation in the last 90 days?" — retroactive audit on your logs

---

## Phase 5 — The Platform

**Timeline:** 12–18 months from now  
**Theme:** Comply54 as the de facto standard. Not one of several options — the one that every serious African AI team uses.

### 5.1 — Regulatory Body Partnerships

The path from "good open-source project" to "industry standard" runs through the regulators themselves.

**Targets:**
- [ ] NDPC (Nigeria) — present comply54 as reference implementation for AI agent compliance under NDPA
- [ ] CBN FinTech Unit — position comply54 as the compliance layer for AI-powered financial services
- [ ] Kenya ODPC — present comply54 as reference for AI agents under KDPA
- [ ] AU (African Union) — align with AU AI Continental Strategy 2024 framework

Even one regulator endorsement changes the conversation with every enterprise customer.

### 5.2 — Enterprise Tier

- [ ] SLA-backed API (99.99% uptime, sub-20ms p99)
- [ ] Private deployment (on-premise / VPC for banks that cannot send data to external APIs)
- [ ] Custom pack authoring (enterprise writes internal rules, comply54 enforces them)
- [ ] Dedicated compliance officer dashboard
- [ ] Annual compliance attestation reports (signed, auditor-ready)

### 5.3 — Developer Ecosystem

- [ ] comply54 certified packs — third-party policy packs that pass the comply54 quality bar
- [ ] Community registry — open contributions with maintainer review
- [ ] Comply54 grants program — fund African developers writing packs for underrepresented jurisdictions

---

## What We Do Not Build

Being clear about this is as important as the roadmap itself.

| What we skip | Why |
|---|---|
| A policy authoring IDE or no-code builder | The target user is a developer. Rego is the right interface for them. |
| A general-purpose compliance tool (GDPR, CCPA, etc.) | Competitors already own that. Africa is our moat. Start narrow. |
| Framework-specific features beyond what compliance requires | comply54 is not a LangChain plugin. It is a compliance system that integrates with LangChain. |
| A frontend agent builder or LLM wrapper | Out of scope. Stay in the enforcement layer. |

---

## Metrics That Matter

These are the numbers that determine whether comply54 is becoming infrastructure or staying a library.

| Metric | Phase 1 Target | Phase 2 Target | Phase 3 Target |
|---|---|---|---|
| PyPI weekly downloads | 500 | 5,000 | 50,000 |
| npm weekly downloads | 200 | 2,000 | 20,000 |
| API monthly evaluations | — | 100,000 | 5,000,000 |
| Jurisdictions covered | 10 | 10 | 25 |
| Enterprise customers | 0 | 3 | 20 |
| GitHub stars | — | 500 | 2,000 |
| Regulatory citations (official) | 1 (MS AGT) | 3 | 10 |

---

## The Single Most Important Principle

From the Flutterwave analysis: **"Software gets used. Infrastructure gets embedded."**

Every decision in this roadmap should be evaluated against one question:

> *Does this make comply54 harder to remove, or does it just make it more feature-rich?*

Hosted enforcement API → harder to remove (your audit trail lives there).  
Embedded OPA WASM → harder to remove (no external dependency at all).  
Regulatory change alerts → harder to remove (your team relies on it for awareness).  
Another thin adapter → easier to remove (just a wrapper they can write themselves).

Build what embeds. Skip what impresses.

---

## Immediate Next Actions (This Week)

1. **Kill the subprocess** — rewrite the LangChain adapter with embedded OPA evaluation. This is the single highest-leverage technical change.
2. **Publish `comply54` to PyPI** — even a minimal package that imports the embedded evaluator. Getting on PyPI establishes the name.
3. **Register comply54.io** — the domain must exist before Phase 1 documentation ships.
4. **Design the enforcement API contract** — the request/response schema, before writing a single line of server code. Get the interface right.

---

*Last updated: 2026-06-27*  
*Version: 1.1*  
*Owner: Oluwajuwon Omotayo*
