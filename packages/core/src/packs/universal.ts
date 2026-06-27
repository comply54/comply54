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
    };
  }
  if (hasNin(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM06: NIN detected in agent output — sharing NIN values is prohibited"],
      ruleTriggered: "pii_nin",
    };
  }
  if (hasPan(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM06: Payment card number (PAN) detected in agent output"],
      ruleTriggered: "pii_pan",
    };
  }
  if (hasPassport(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["OWASP LLM06: Passport number pattern detected in response"],
      ruleTriggered: "pii_passport",
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
    };
  }

  // Not in approved regions
  if (approvedRegions && modelRegion && !approvedRegions.includes(modelRegion)) {
    return {
      ...base,
      action: "deny",
      messages: [`OWASP LLM09: Model region '${modelRegion}' not in approved regions for this data`],
      ruleTriggered: "model_routing_region",
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
      };
    }
  }

  return { ...base, action: "allow", messages: [] };
};
