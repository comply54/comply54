import { definePolicy } from "eve-policy";
import { deny, escalate, audit } from "eve-policy/rules";
import {
  toolNameMatches,
  amountExceeds,
  isSubagentCall,
  and,
} from "eve-policy/rules";

/**
 * Mauritius Data Protection Act (DPA) 2017 — Eve Governance Profile
 *
 * Source: agt-policies-nigeria mauritius-dpa.rego and mauritius-dpa.yaml
 * Enforcer: Data Protection Commissioner (dataprotection.govmu.org)
 * Effective: 15 January 2018 (Act No. 20/2017)
 *
 * Notable characteristics (stricter than GDPR in some areas):
 * - DPO mandatory for ALL controllers (no size threshold — unlike GDPR's 250-employee rule)
 * - Registration with Data Protection Commissioner is mandatory (MUR 200,000/5yr penalty)
 * - 72-hour breach notification (GDPR-aligned)
 * - Automated decision-making transparency requirements
 * - Most GDPR-aligned DPA on the African continent
 * - Mauritius NIC format: [A-Z][0-9]{6,7}
 *
 * @see https://dataprotection.govmu.org/
 * @see kingztech2019/agt-policies-nigeria (policies/mauritius-dpa.yaml)
 */
export const mauritiusDpaPolicy = definePolicy({
  name: "comply54-mauritius-dpa",
  version: "2017.1.0",
  description: "Mauritius DPA 2017 — Data Protection Commissioner enforcement profile for Eve agents",
  defaultEffect: "audit",
  rules: [
    // ── Hard denials ─────────────────────────────────────────────────────────

    deny(
      "mu-dpa-breach-suppression",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(don'?t|do\s+not|never|suppress|delay|hide)\s.{0,40}(breach|security\s+incident|data\s+compromise)/i.test(inputStr);
      },
      "Mauritius DPA (Breach Notification): 72-hour breach notification is mandatory — suppression is prohibited.",
      { riskLevel: "critical", owaspRisks: ["ASI01", "ASI09"] },
    ),

    deny(
      "mu-dpa-biometric-unguarded",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(biometric|fingerprint|iris|facial\s+recognition|retina)\b/i.test(inputStr) &&
          !/\b(consent|authorised|authorized)\b/i.test(inputStr);
      },
      "Mauritius DPA (Special Categories): Biometric data processed without documented consent — prohibited.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "mu-dpa-registration-bypass",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(no\s+need|optional|not\s+required|skip|bypass|ignore)\s.{0,40}(register|registration|commissioner|dpc)/i.test(inputStr);
      },
      "Mauritius DPA (Registration): Registration with the Data Protection Commissioner is mandatory — cannot be skipped.",
      { riskLevel: "critical", owaspRisks: ["ASI09"] },
    ),

    deny(
      "mu-dpa-nic-in-output",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(mauritius\s+(national\s+)?(id|identity|nic)|national\s+(identity\s+)?card|NIC)\s*[:\s]*[A-Z]\d{6,7}\b/.test(inputStr);
      },
      "Mauritius DPA: Mauritius NIC number detected in input — national ID must not be processed without explicit grounds.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "mu-dpa-cross-border-non-permitted",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const dest = String(input["destination_country"] ?? input["destination_region"] ?? "").toUpperCase();
        if (!dest) return false;
        const permittedRegions = new Set(["MU", "MAURITIUS", "AF-SOUTH-1", "AF-SOUTH-2", "AF-EAST-1", "EU", "GB", "ZA", "KE"]);
        return toolNameMatches(/transfer|export|send|cross.?border/i)(ctx) &&
          !permittedRegions.has(dest);
      },
      "Mauritius DPA (Cross-Border Transfers): Transfer to non-permitted jurisdiction requires Data Protection Commissioner approval.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    // ── Escalations ───────────────────────────────────────────────────────────

    escalate(
      "mu-dpa-health-special-categories",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(health|medical|religion|racial|ethnic|criminal|sexual\s+orientation|political\s+opinion)\b/i.test(inputStr);
      },
      "Mauritius DPA (Special Categories): Sensitive data processing requires DPO approval.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "mu-dpa-dpo-bypass",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(skip|bypass|override|ignore)\s.{0,30}(dpo|data\s+protection\s+officer)/i.test(inputStr);
      },
      "Mauritius DPA: DPO is mandatory for ALL controllers — oversight cannot be bypassed.",
      { riskLevel: "high", owaspRisks: ["ASI09"] },
    ),

    escalate(
      "mu-dpa-cross-border-language",
      and(
        toolNameMatches(/transfer|export|send|cross.?border/i),
        (ctx) => {
          const input = ctx.toolInput as Record<string, unknown>;
          return !!input["destination_country"] || !!input["destination_region"];
        },
      ),
      "Mauritius DPA (Cross-Border Transfers): Cross-border transfer requires consent documentation.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "mu-dpa-automated-decisions",
      toolNameMatches(/^(automated_decision|credit_scoring|risk_assessment|profiling|ml_decision)$/i),
      "Mauritius DPA (Automated Decisions): Automated decision-making requires transparency notice and right to review.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "mu-dpa-bulk-export",
      amountExceeds("record_count", 1000),
      "Mauritius DPA: Bulk export >1000 records requires Data Protection Commissioner notification.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "mu-dpa-subagent-pii-write",
      and(isSubagentCall(), toolNameMatches(/update|write|store|save|create|modify/i)),
      "Mauritius DPA: Subagent PII write — principal verification required under processor obligations.",
      { riskLevel: "high", owaspRisks: ["ASI03"] },
    ),

    // ── Audit ─────────────────────────────────────────────────────────────────

    audit(
      "mu-dpa-pii-access",
      toolNameMatches(/customer|user.{0,20}(profile|data|record)|personal.{0,20}data/i),
      "Mauritius DPA: Personal data access logged for data controller accountability.",
      { riskLevel: "medium", owaspRisks: [] },
    ),

    audit(
      "mu-dpa-moderate-export",
      amountExceeds("record_count", 100),
      "Mauritius DPA: Moderate export (100–1000 records) logged for monitoring.",
      { riskLevel: "low", owaspRisks: [] },
    ),

  ],
});
