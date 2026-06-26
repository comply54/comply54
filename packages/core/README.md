# @comply54/core

**African AI governance compliance — enforcement engine and sector packs for TypeScript/JavaScript.**

[![npm](https://img.shields.io/npm/v/@comply54/core.svg)](https://www.npmjs.com/package/@comply54/core)
[![CI](https://github.com/comply54/comply54/actions/workflows/ci.yml/badge.svg)](https://github.com/comply54/comply54/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/comply54/comply54/blob/main/LICENSE)

Evaluate AI agent actions against 13 African regulatory frameworks + OWASP Agentic AI controls — no external API, no OPA binary, pure TypeScript in-process evaluation.

---

## Installation

```bash
npm install @comply54/core
# or
yarn add @comply54/core
# or
pnpm add @comply54/core
```

---

## Quick Start

### Nigeria Fintech (NDPA + CBN + NFIU + OWASP)

```typescript
import { NigeriaFintechCompliance } from "@comply54/core";

const compliance = new NigeriaFintechCompliance();

const result = compliance.check(
  "transfer_funds",
  { amount: 15_000_000, currency: "NGN" },  // params
  "",                                         // output text
  { kyc_tier: 3 }                             // context
);

if (result.blocked) {
  console.error(result.primaryViolation?.messages[0]);
  // "CBN NIP cap exceeded: ₦15,000,000 > ₦10,000,000 limit"
}

console.log(result.overall); // "deny" | "escalate" | "audit" | "allow"
```

### Kenya Fintech (KDPA 2019)

```typescript
import { KenyaFintechCompliance } from "@comply54/core";

const compliance = new KenyaFintechCompliance();

const result = compliance.check(
  "export_data",
  { destination_country: "CN", data_type: "biometric" }
);

console.log(result.overall);   // "deny"
console.log(result.blocked);   // true
```

### Pan-African (13 jurisdictions + OWASP)

```typescript
import { PanAfricanFintechCompliance } from "@comply54/core";

const compliance = new PanAfricanFintechCompliance();

const result = compliance.check(
  "send_to_external",
  { destination_country: "US", data_type: "customer_pii" },
  "",
  { consent_documented: false }
);

// Evaluates 18 packs across NG, KE, ZA, GH, RW, EG, ET, MU, TZ, UG
console.log(result.decisions.length);  // 18
```

---

## Sector Packs

| Class | Packs | Jurisdictions |
|-------|-------|---------------|
| `NigeriaFintechCompliance` | NDPA 2023, CBN Transaction Controls, BVN/NIN Framework, NFIU/MLPPA 2022, OWASP (PII, injection, tools, approval) | NG |
| `KenyaFintechCompliance` | KDPA 2019, OWASP (PII, injection, tools, approval) | KE |
| `PanAfricanFintechCompliance` | All 13 African packs + 5 OWASP universal packs | NG, KE, ZA, GH, RW, EG, ET, MU, TZ, UG |

---

## Regulations Covered

### Nigerian Packs
| Pack | Regulation | Authority |
|------|-----------|----------|
| `evaluateNDPA` | Nigeria Data Protection Act 2023 | NDPC |
| `evaluateCBN` | CBN Transaction Limits & Tiered KYC | CBN |
| `evaluateBvnNin` | CBN BVN Framework; NIBSS Rules | CBN / NIBSS |
| `evaluateNfiu` | MLPPA 2022 / NFIU AML Guidelines | NFIU |

### African Jurisdiction Packs
| Pack | Regulation | Country |
|------|-----------|---------|
| `evaluateKDPA` | Kenya Data Protection Act 2019 | Kenya |
| `evaluatePOPIA` | Protection of Personal Information Act 2013 | South Africa |
| `evaluateGhanaDPA` | Ghana Data Protection Act 2012 | Ghana |
| `evaluateRwandaDPA` | Rwanda DPA 2021 | Rwanda |
| `evaluateEgyptPDPL` | Egypt Personal Data Protection Law 2020 | Egypt |
| `evaluateEthiopiaPDP` | Ethiopia PDP 2024 | Ethiopia |
| `evaluateMauritiusDPA` | Mauritius Data Protection Act 2017 | Mauritius |
| `evaluateTanzaniaPDPA` | Tanzania PDPA 2022 | Tanzania |
| `evaluateUgandaDPPA` | Uganda DPPA 2019 | Uganda |

### Universal Agent Safety Packs (OWASP Agentic AI)
| Pack | OWASP Reference |
|------|----------------|
| `evaluatePiiLeakage` | LLM06 — detects BVN, NIN, card numbers, SSN in output |
| `evaluatePromptInjection` | LLM01 / ASI01 — blocks jailbreak and override attempts |
| `evaluateToolPermissions` | LLM08 — enforces tool use boundaries |
| `evaluateHumanApproval` | LLM09 — flags high-risk actions for human review |
| `evaluateModelRouting` | LLM03 / LLM05 — validates model selection integrity |

---

## API Reference

### `SectorCompliance.check(action, params?, output?, context?)`

```typescript
const result: ComplianceResult = compliance.check(
  "transfer_funds",               // action name (string)
  { amount: 5_000_000 },          // structured params (optional)
  "",                              // agent output text (optional)
  { kyc_tier: 2, is_pep: false }  // session context (optional)
);
```

### `SectorCompliance.evaluate(input)`

```typescript
import { NigeriaFintechCompliance, EvaluationInput } from "@comply54/core";

const input: EvaluationInput = {
  action: "export_data",
  params: { destination_country: "US", data_type: "pii" },
  context: { consent_documented: false },
};

const result = new NigeriaFintechCompliance().evaluate(input);
```

### `SectorCompliance.certificate(action, params?, output?, context?)`

Generate an auditor-exportable compliance certificate with SHA-256 integrity hash.

```typescript
const cert = await compliance.certificate(
  "transfer_funds",
  { amount: 15_000_000, currency: "NGN" },
);

console.log(cert.overall);         // "deny"
console.log(cert.passed);          // false
console.log(cert.integrityHash);   // SHA-256 hex (64 chars)
console.log(cert.packsEvaluated);  // ["nigeria/ndpa", "nigeria/cbn", ...]

// Export for audit log
const json = cert.toJSON();        // formatted JSON string
const obj  = cert.toObject();      // plain object
```

### `ComplianceResult` shape

```typescript
interface ComplianceResult {
  overall: "allow" | "audit" | "escalate" | "deny";
  blocked: boolean;           // true if overall is "deny" or "escalate"
  passed: boolean;            // true if overall is "allow"
  decisions: PolicyDecision[]; // one per pack evaluated
  violations: PolicyDecision[]; // decisions where action !== "allow"
  primaryViolation: PolicyDecision | null; // highest-severity violation
  auditId: string;            // UUID for this evaluation
  evaluatedAt: string;        // ISO 8601 timestamp
}
```

---

## Strict Mode

Upgrades all `escalate` decisions to `deny` — use for maximum enforcement environments.

```typescript
const compliance = new PanAfricanFintechCompliance({ strictMode: true });

const result = compliance.check(
  "transfer_funds",
  { amount: 6_000_000, currency: "NGN" },
  "",
  { kyc_tier: 3 },
);

// NFIU CTR threshold (₦5M) triggers "escalate" in normal mode
// With strictMode: true, it becomes "deny"
console.log(result.overall);  // "deny"
console.log(result.blocked);  // true
```

---

## Low-Level Engine API

Use `Comply54Engine` directly to compose custom pack sets:

```typescript
import { Comply54Engine, evaluateCBN, evaluateNDPA, evaluatePiiLeakage } from "@comply54/core";

const engine = new Comply54Engine([
  evaluateCBN,
  evaluateNDPA,
  evaluatePiiLeakage,
]);

const result = engine.check(
  "transfer_funds",
  { amount: 15_000_000, currency: "NGN" },
);
```

---

## Use in LangChain / LangGraph

```typescript
import { NigeriaFintechCompliance } from "@comply54/core";

const compliance = new NigeriaFintechCompliance();

// As a LangGraph node
function complianceNode(state: AgentState): AgentState {
  const result = compliance.check(
    state.action,
    state.params,
    state.output,
    state.context,
  );

  if (result.blocked) {
    return { ...state, blocked: true, reason: result.primaryViolation?.messages[0] };
  }
  return { ...state, blocked: false };
}
```

---

## Decision Severity

Decisions are ranked: `deny` > `escalate` > `audit` > `allow`

The `overall` on a `ComplianceResult` is the highest severity across all evaluated packs.

| Decision | `blocked` | Meaning |
|----------|-----------|---------|
| `deny` | `true` | Hard block — action must not proceed |
| `escalate` | `true` | Requires human review before proceeding |
| `audit` | `false` | Proceed, but log for compliance audit trail |
| `allow` | `false` | No issues found |

---

## Python SDK

This package is the TypeScript port of the Python `comply54` library.
For Python projects: `pip install comply54`

---

## Links

- [GitHub](https://github.com/comply54/comply54)
- [Python package](https://pypi.org/project/comply54)
- [Policy source: agt-policies-nigeria](https://github.com/kingztech2019/agt-policies-nigeria)

---

## License

MIT © Oluwajuwon Omotayo
