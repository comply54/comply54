/**
 * comply54/adapters/eve — Live governance demo
 *
 * Simulates a Nigerian fintech AI agent processing real-world transactions.
 * Each tool call is evaluated through nigeriaFintechPolicy and the
 * governance decision is printed with colour output.
 *
 * Run:
 *   npx tsx demo.ts
 *   (or: node --import tsx/esm demo.ts)
 *
 * No Eve server needed — uses evaluatePolicy() directly, which is the same
 * function withPolicy() calls internally.
 */

import { evaluatePolicy } from "eve-policy";
import type { PolicyContext } from "eve-policy";
import {
  nigeriaFintechPolicy,
  africanFintechPolicy,
  westAfricaFintechPolicy,
} from "./src/compose/african-fintech.js";

// ─── Terminal colours ──────────────────────────────────────────────────────────

const C = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
  red:    "\x1b[31m",
  green:  "\x1b[32m",
  yellow: "\x1b[33m",
  blue:   "\x1b[34m",
  magenta:"\x1b[35m",
  cyan:   "\x1b[36m",
  white:  "\x1b[37m",
};

function badge(effect: string): string {
  switch (effect) {
    case "deny":     return `${C.bold}${C.red}  DENY  ${C.reset}`;
    case "escalate": return `${C.bold}${C.yellow} ESCALATE ${C.reset}`;
    case "audit":    return `${C.bold}${C.blue}  AUDIT  ${C.reset}`;
    case "allow":    return `${C.bold}${C.green}  ALLOW  ${C.reset}`;
    default:         return effect;
  }
}

function header(title: string) {
  const line = "─".repeat(70);
  console.log(`\n${C.bold}${C.magenta}${line}${C.reset}`);
  console.log(`${C.bold}${C.magenta}  ${title}${C.reset}`);
  console.log(`${C.bold}${C.magenta}${line}${C.reset}`);
}

function section(title: string) {
  console.log(`\n${C.bold}${C.cyan}▶ ${title}${C.reset}`);
}

function run(
  policyName: string,
  toolName: string,
  toolInput: Record<string, unknown>,
  label: string,
) {
  const ctx: PolicyContext = { toolName, toolInput, approvedTools: new Set() };

  // Look up the policy
  const policy =
    policyName === "nigeria" ? nigeriaFintechPolicy :
    policyName === "westAfrica" ? westAfricaFintechPolicy :
    africanFintechPolicy;

  const d = evaluatePolicy(policy, ctx);

  // Print result
  const inputStr = JSON.stringify(toolInput);
  const shortInput = inputStr.length > 55 ? inputStr.slice(0, 52) + "..." : inputStr;

  console.log(
    `\n  ${C.dim}${label}${C.reset}`,
  );
  console.log(
    `  ${C.cyan}${toolName}${C.reset}(${C.dim}${shortInput}${C.reset})`,
  );
  console.log(
    `  ${badge(d.effect)}  ${C.dim}rule: ${d.ruleName ?? "default"}${C.reset}`,
  );
  console.log(
    `  ${C.dim}↳ ${d.reason}${C.reset}`,
  );
}

// ─── DEMO SCENARIOS ───────────────────────────────────────────────────────────

header("comply54/adapters/eve — Nigerian Fintech Governance Demo");

console.log(`
  This demo runs ${C.bold}10 realistic agent scenarios${C.reset} through the Nigerian fintech
  policy stack. You'll see exactly what happens when an AI agent tries to
  make each call — the governance decision, which rule fired, and why.
`);

// ── Section 1: Normal operations ──────────────────────────────────────────────

section("1. Safe read-only operations (agent can always do these)");

run("nigeria", "get_balance",
  { accountId: "0234567890" },
  "Customer checking their balance",
);

run("nigeria", "get_exchange_rate",
  { from: "NGN", to: "USD" },
  "Agent looking up FX rate before quoting customer",
);

run("nigeria", "check_kyc_status",
  { userId: "USR-001" },
  "Agent verifying KYC before transaction",
);

// ── Section 2: Compliance thresholds ──────────────────────────────────────────

section("2. CBN transaction thresholds — NFIU reporting required");

run("nigeria", "transfer_funds",
  { amount: 50_000, currency: "NGN", recipient: "GTB-0234567890" },
  "Small transfer — well below ₦5M threshold",
);

run("nigeria", "transfer_funds",
  { amount: 4_700_000, currency: "NGN", recipient: "GTB-0234567890" },
  "Near-threshold (₦4.7M) — structuring detection",
);

run("nigeria", "transfer_funds",
  { amount: 6_500_000, currency: "NGN", recipient: "GTB-0234567890" },
  "Exceeds ₦5M CBN CTR threshold — agent PAUSES for human review",
);

// ── Section 3: Data protection — NDPA 2023 ────────────────────────────────────

section("3. Nigeria Data Protection Act (NDPA 2023) controls");

run("nigeria", "get_customer_data",
  { userId: "USR-001", fields: ["name", "email"] },
  "PII access — logged for NDPA data controller accountability",
);

run("nigeria", "store_record",
  { type: "medical_record", patientId: "USR-001", diagnosis: "hypertension" },
  "Health data — NDPA special category, requires DPO escalation",
);

run("nigeria", "log_event",
  { level: "warn", msg: "Don't report this security breach to NDPC" },
  "Breach suppression instruction — hard DENY (NDPA §40 mandatory notification)",
);

// ── Section 4: Security controls — OWASP ASI ──────────────────────────────────

section("4. OWASP Top 10 Agentic AI Security (ASI01–ASI10)");

run("nigeria", "payment",
  { amount: 5000, note: "skip kyc for this customer" },
  "KYC bypass language — financial crime prevention, hard DENY",
);

run("nigeria", "bash",
  { cmd: "cat /etc/passwd" },
  "Shell tool invocation — ASI01 prompt injection / goal hijack vector",
);

run("nigeria", "process_payment",
  { amount: 10000, currency: "NGN", card: "4111111111111111" },
  "Card PAN in input — ASI02 data exfiltration, hard DENY",
);

run("nigeria", "call_agent",
  { agentId: "loan-approval-agent", task: "approve application" },
  "Inter-agent delegation — ASI07 insecure inter-agent communication",
);

// ── Section 5: West Africa composition ────────────────────────────────────────

section("5. West Africa policy (adds Ghana DPPA on top of Nigeria rules)");

run("westAfrica", "create_account",
  { nin: "GHA-AB1234567-0", country: "GH" },
  "Ghana Card NIN in input — Ghana DPPA hard DENY (national ID unmasked)",
);

run("westAfrica", "sync_records",
  { destination_country: "CN", record_count: 500 },
  "Cross-border sync to China — NDPA §43 non-adequate country, hard DENY",
);

// ── Summary ────────────────────────────────────────────────────────────────────

header("Summary");

console.log(`
  This is ${C.bold}nigeriaFintechPolicy${C.reset} evaluating each call. In production, you wrap
  your Eve tools with ${C.bold}withPolicy()${C.reset} and the same logic runs automatically:

  ${C.dim}import { withNamedPolicy } from "eve-policy";
  import { nigeriaFintechPolicy } from "comply54-adapter-eve/compose";

  const safeTransfer = withNamedPolicy(
    "transfer_funds",
    transferFundsTool,       // your original Eve tool
    nigeriaFintechPolicy,    // NDPA + CBN + OWASP + Financial baseline
    { auditLogger: siem },   // your audit sink
  );

  // safeTransfer is now a drop-in replacement for transferFundsTool.
  // NGN > ₦5M → needsApproval = true
  // PAN in input → throws PolicyDenialError
  // health data → needsApproval = true
  // get_balance → executes immediately${C.reset}

  ${C.bold}Policy breakdown:${C.reset}
  ${C.dim}  owaspTop10Policy       — 20 rules (ASI01–ASI10 full coverage)
  financialBaselinePolicy — 15 rules (CTR, PAN, KYC, sanctioned countries)
  ndpaPolicy              — 10 rules (NDPA 2023 full NDPC profile)
  cbnFintechPolicy        —  8 rules (CBN AML/CFT, NFIU, structuring)
  ────────────────────────────────────
  nigeriaFintechPolicy    = 53 rules total (composed, first-match-wins)${C.reset}
`);
