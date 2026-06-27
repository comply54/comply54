/**
 * Universal agent safety pack evaluators.
 * Covers: PII leakage, prompt injection, tool permissions, human approval, model routing.
 * Standard: OWASP Top 10 for LLM Applications.
 */

import { makeAuditId, nowIso, hasBvn, hasNin, hasPan, hasPassport } from "../utils.js";
import type { EvaluationInput, PackEvaluatorFn, PolicyDecision, RegulatorySource } from "../types.js";

type Input = Required<EvaluationInput>;

// ── Regulatory citation constants ─────────────────────────────────────────────

const _OWASP_URL = "https://owasp.org/www-project-top-10-for-large-language-model-applications/";

const PII_LEAKAGE_CITATIONS: RegulatorySource[] = [
  { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM06:2025 — Excessive Agency", authority: "OWASP", year: 2025, url: _OWASP_URL },
];

const PROMPT_INJECTION_CITATIONS: RegulatorySource[] = [
  { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM01:2025 — Prompt Injection", authority: "OWASP", year: 2025, url: _OWASP_URL },
];

const TOOL_PERMISSIONS_CITATIONS: RegulatorySource[] = [
  { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM08:2025 — Excessive Agency", authority: "OWASP", year: 2025, url: _OWASP_URL },
];

const HUMAN_APPROVAL_CITATIONS: RegulatorySource[] = [
  { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM08:2025 — Excessive Agency", authority: "OWASP", year: 2025, url: _OWASP_URL },
];

const MODEL_ROUTING_CITATIONS: RegulatorySource[] = [
  { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM09:2025 — Misinformation", authority: "OWASP", year: 2025, url: _OWASP_URL },
];

// ── Per-rule regulatory citation maps ────────────────────────────────────────

const PII_LEAKAGE_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  pii_bvn: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM06:2025 — Sensitive Information Disclosure", authority: "OWASP", year: 2025, url: _OWASP_URL },
    { document: "CBN Regulatory Framework for BVN Operations 2014", section: "§6 — BVN Confidentiality Obligations", authority: "CBN", year: 2014 },
  ],
  pii_nin: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM06:2025 — Sensitive Information Disclosure", authority: "OWASP", year: 2025, url: _OWASP_URL },
    { document: "NIMC Act Cap N99 LFN 2004 (as amended)", section: "§18 — NIN Confidentiality", authority: "NIMC", year: 2004 },
  ],
  pii_pan: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM06:2025 — Sensitive Information Disclosure", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
  pii_passport: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM06:2025 — Sensitive Information Disclosure", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
};

const PROMPT_INJECTION_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  prompt_injection: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM01:2025 — Prompt Injection", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
};

const TOOL_PERMISSIONS_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  tool_out_of_scope: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM08:2025 — Excessive Agency (Scope)", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
  tool_idor: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM08:2025 — Excessive Agency (IDOR)", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
  tool_bulk_read: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM08:2025 — Excessive Agency (Bulk Operations)", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
};

const HUMAN_APPROVAL_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  human_approval_irreversible: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM08:2025 — Excessive Agency (Irreversible Actions)", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
  human_approval_high_value: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM08:2025 — Excessive Agency (High-Value Transfers)", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
  human_approval_bulk: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM08:2025 — Excessive Agency (Bulk Messaging)", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
};

const MODEL_ROUTING_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  model_routing_biometric: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM09:2025 — Misinformation", authority: "OWASP", year: 2025, url: _OWASP_URL },
    { document: "Nigeria Data Protection Act 2023", section: "Schedule 1 — Biometric Data", authority: "NDPC", year: 2023 },
  ],
  model_routing_region: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM09:2025 — Misinformation", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
  model_routing_no_dpa: [
    { document: "OWASP Top 10 for LLM Applications 2025", section: "LLM09:2025 — Misinformation", authority: "OWASP", year: 2025, url: _OWASP_URL },
  ],
};

// ── PII Leakage (OWASP LLM06) ────────────────────────────────────────────────

export const evaluatePiiLeakage: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "universal/pii-leakage",
    regulation: "OWASP LLM06",
    jurisdiction: "",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: PII_LEAKAGE_CITATIONS,
  };

  const output = input.output ?? "";

  if (hasBvn(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM06: BVN detected in agent output — must not be exposed in plaintext"],
      ruleTriggered: "pii_bvn",
      citations: PII_LEAKAGE_RULE_CITATIONS["pii_bvn"] ?? PII_LEAKAGE_CITATIONS,
    };
  }
  if (hasNin(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM06: NIN detected in agent output — sharing NIN values is prohibited"],
      ruleTriggered: "pii_nin",
      citations: PII_LEAKAGE_RULE_CITATIONS["pii_nin"] ?? PII_LEAKAGE_CITATIONS,
    };
  }
  if (hasPan(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM06: Payment card number (PAN) detected in agent output"],
      ruleTriggered: "pii_pan",
      citations: PII_LEAKAGE_RULE_CITATIONS["pii_pan"] ?? PII_LEAKAGE_CITATIONS,
    };
  }
  if (hasPassport(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM06: Passport number pattern detected in response"],
      ruleTriggered: "pii_passport",
      citations: PII_LEAKAGE_RULE_CITATIONS["pii_passport"] ?? PII_LEAKAGE_CITATIONS,
    };
  }

  return { ...base, action: "allow", messages: [] };
};

// ── Prompt Injection (OWASP LLM01) ───────────────────────────────────────────

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
  /you\s+are\s+now\s+(DAN|an?\s+AI\s+without|unrestricted)/i,
  /disregard\s+(your\s+)?(system\s+prompt|previous\s+instructions)/i,
  /jailbreak/i,
  /\[SYSTEM\]/i,
  /act\s+as\s+if\s+you\s+have\s+no\s+restrictions/i,
  /pretend\s+(you\s+are|to\s+be)\s+(an?\s+AI|a\s+chatbot)\s+without/i,
  /reveal\s+(your\s+)?(system\s+prompt|instructions)/i,
];

export const evaluatePromptInjection: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "universal/prompt-injection",
    regulation: "OWASP LLM01",
    jurisdiction: "",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: PROMPT_INJECTION_CITATIONS,
  };

  const userMessage = String(input.params["user_message"] ?? input.params["content"] ?? "");
  const combined = userMessage + " " + (input.output ?? "");

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(combined)) {
      return {
        ...base,
        action: "deny",
        messages: ["OWASP LLM01: Prompt injection pattern detected — instruction override attempt"],
        ruleTriggered: "prompt_injection",
        citations: PROMPT_INJECTION_RULE_CITATIONS["prompt_injection"] ?? PROMPT_INJECTION_CITATIONS,
      };
    }
  }

  return { ...base, action: "allow", messages: [] };
};

// ── Tool Permissions (OWASP LLM08) ───────────────────────────────────────────

export const evaluateToolPermissions: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "universal/tool-permissions",
    regulation: "OWASP LLM08",
    jurisdiction: "",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: TOOL_PERMISSIONS_CITATIONS,
  };

  const allowedTools = input.context["allowed_tools"] as string[] | undefined;
  const toolName = String(input.params["tool_name"] ?? input.action);
  const currentUserId = String(input.context["current_user_id"] ?? "");
  const isAdmin = Boolean(input.context["is_admin"]);

  // Tool not in declared scope
  if (allowedTools && allowedTools.length > 0 && !allowedTools.includes(toolName)) {
    return {
      ...base,
      action: "deny",
      messages: [`OWASP LLM08: Tool '${toolName}' is not in the agent's declared tool scope`],
      ruleTriggered: "tool_out_of_scope",
      citations: TOOL_PERMISSIONS_RULE_CITATIONS["tool_out_of_scope"] ?? TOOL_PERMISSIONS_CITATIONS,
    };
  }

  // IDOR-style check: params reference a different user's resource
  const paramsUserId = String(input.params["user_id"] ?? input.params["account_id"] ?? "");
  if (paramsUserId && currentUserId && paramsUserId !== currentUserId && !isAdmin) {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM08: Tool call references resource owned by a different user — possible IDOR"],
      ruleTriggered: "tool_idor",
      citations: TOOL_PERMISSIONS_RULE_CITATIONS["tool_idor"] ?? TOOL_PERMISSIONS_CITATIONS,
    };
  }

  // Bulk read without admin scope
  const recordCount = Number(input.params["record_count"] ?? 0);
  if (recordCount > 100 && !isAdmin) {
    return {
      ...base,
      action: "escalate",
      messages: [`OWASP LLM08: Bulk read of ${recordCount} records without admin scope — escalation required`],
      ruleTriggered: "tool_bulk_read",
      citations: TOOL_PERMISSIONS_RULE_CITATIONS["tool_bulk_read"] ?? TOOL_PERMISSIONS_CITATIONS,
    };
  }

  return { ...base, action: "allow", messages: [] };
};

// ── Human Approval (OWASP LLM08) ─────────────────────────────────────────────

const HUMAN_APPROVAL_THRESHOLD = 1_000_000;
const IRREVERSIBLE_ACTIONS = new Set([
  "delete_account",
  "close_account",
  "terminate_service",
  "delete_data",
  "revoke_access",
  "send_bulk_message",
]);

export const evaluateHumanApproval: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "universal/human-approval",
    regulation: "OWASP LLM08",
    jurisdiction: "",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: HUMAN_APPROVAL_CITATIONS,
  };

  // Irreversible actions
  if (IRREVERSIBLE_ACTIONS.has(input.action)) {
    return {
      ...base,
      action: "escalate",
      messages: [`OWASP LLM08: '${input.action}' is an irreversible operation — human sign-off required`],
      ruleTriggered: "human_approval_irreversible",
      citations: HUMAN_APPROVAL_RULE_CITATIONS["human_approval_irreversible"] ?? HUMAN_APPROVAL_CITATIONS,
    };
  }

  // High-value transfer
  if (input.action === "transfer_funds") {
    const amount = Number(input.params["amount"] ?? 0);
    if (amount >= HUMAN_APPROVAL_THRESHOLD) {
      return {
        ...base,
        action: "escalate",
        messages: [
          `OWASP LLM08: Transfer of ₦${amount.toLocaleString()} requires human approval before execution`,
        ],
        ruleTriggered: "human_approval_high_value",
        citations: HUMAN_APPROVAL_RULE_CITATIONS["human_approval_high_value"] ?? HUMAN_APPROVAL_CITATIONS,
      };
    }
  }

  // Bulk messaging
  if (input.action === "send_message" || input.action === "send_bulk_message") {
    const recipients = Number(input.params["recipient_count"] ?? 0);
    if (recipients > 100) {
      return {
        ...base,
        action: "escalate",
        messages: [`OWASP LLM08: Bulk message to ${recipients} recipients requires human review`],
        ruleTriggered: "human_approval_bulk",
        citations: HUMAN_APPROVAL_RULE_CITATIONS["human_approval_bulk"] ?? HUMAN_APPROVAL_CITATIONS,
      };
    }
  }

  return { ...base, action: "allow", messages: [] };
};

// ── Model Routing (OWASP LLM09) ──────────────────────────────────────────────

export const evaluateModelRouting: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "universal/model-routing",
    regulation: "OWASP LLM09",
    jurisdiction: "",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: MODEL_ROUTING_CITATIONS,
  };

  if (input.action !== "route_to_model") {
    return { ...base, action: "allow", messages: [] };
  }

  const modelRegion = String(input.params["model_region"] ?? "");
  const dataType = String(input.params["data_type"] ?? "").toLowerCase();
  const approvedRegions = input.context["approved_regions"] as string[] | undefined;

  // Biometric to any external model
  if (dataType === "biometric") {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM09: Biometric data must not be sent to external model APIs"],
      ruleTriggered: "model_routing_biometric",
      citations: MODEL_ROUTING_RULE_CITATIONS["model_routing_biometric"] ?? MODEL_ROUTING_CITATIONS,
    };
  }

  // Not in approved regions
  if (approvedRegions && modelRegion && !approvedRegions.includes(modelRegion)) {
    return {
      ...base,
      action: "deny",
      messages: [`OWASP LLM09: Model region '${modelRegion}' not in approved regions for this data`],
      ruleTriggered: "model_routing_region",
      citations: MODEL_ROUTING_RULE_CITATIONS["model_routing_region"] ?? MODEL_ROUTING_CITATIONS,
    };
  }

  // PII to non-domestic region without DPA
  if (dataType === "customer_pii" || dataType === "pii") {
    const hasDpa = Boolean(input.context["data_processing_agreement"]);
    if (!hasDpa) {
      return {
        ...base,
        action: "escalate",
        messages: ["OWASP LLM09: No data processing agreement recorded for model provider — escalation required"],
        ruleTriggered: "model_routing_no_dpa",
        citations: MODEL_ROUTING_RULE_CITATIONS["model_routing_no_dpa"] ?? MODEL_ROUTING_CITATIONS,
      };
    }
  }

  return { ...base, action: "allow", messages: [] };
};
