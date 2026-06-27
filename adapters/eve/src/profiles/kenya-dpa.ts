import { definePolicy } from "eve-policy";
import { deny, escalate, audit, allow } from "eve-policy/rules";
import {
  toolNameMatches,
  amountExceeds,
  isSubagentCall,
  and,
} from "eve-policy/rules";

/**
 * Kenya Data Protection Act (DPA) 2019 — Eve Governance Profile
 *
 * Source: comply54 Kenya DPA Rego policies
 * Enforcer: Office of the Data Protection Commissioner (ODPC)
 *
 * Key provisions:
 * - Data residency: personal data of Kenyans must remain in Kenya
 *   or countries with adequate protection (ODPC whitelist)
 * - Breach notification: 72-hour window (same as GDPR)
 * - Sensitive data: health, biometric, financial, political — heightened rules
 * - DPA registration mandatory for data processors
 * - CBK AML: KSh 1,000,000 threshold for MPESA/banking agents
 *
 * @see https://www.odpc.go.ke/
 * @see comply54/packages/kenya/
 */
export const kenyaDpaPolicy = definePolicy({
  name: "comply54-kenya-dpa",
  version: "2019.1.0",
  description: "Kenya Data Protection Act 2019 — ODPC enforcement profile for Eve agents",
  defaultEffect: "audit",
  rules: [
    // ── Hard denials ─────────────────────────────────────────────────────────

    deny(
      "kdpa-breach-suppression",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(don'?t|do\s+not|never|suppress|delay|hide)\s.{0,40}(breach|incident|data\s+leak|security\s+event)/i.test(inputStr);
      },
      "Kenya DPA §43: Breach suppression instruction detected. 72-hour breach notification is mandatory.",
      { riskLevel: "critical", owaspRisks: ["ASI01", "ASI09"] },
    ),

    deny(
      "kdpa-cross-border-non-adequate",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const dest = String(input["destination_country"] ?? input["destination_region"] ?? "").toUpperCase();
        if (!dest) return false;
        const adequateList = new Set(["KE", "GB", "EU", "ZA", "MU", "GH", "NG", "KENYA", "af-south-1", "africa"]);
        const isTransfer = toolNameMatches(/transfer|export|send|sync|cross.?border/i)(ctx);
        return isTransfer && dest.length > 0 && !adequateList.has(dest);
      },
      "Kenya DPA §48: Cross-border transfer to a country without adequate protection requires ODPC authorisation.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "kdpa-biometric-unguarded",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(biometric|fingerprint|iris|facial\s+recognition|hudhuma|huduma\s+namba)\b/i.test(inputStr) &&
          !/\b(consent|authorised|authorized|approved)\b/i.test(inputStr);
      },
      "Kenya DPA §27: Biometric data (including Huduma Namba) requires explicit consent for processing.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    // ── Escalations ───────────────────────────────────────────────────────────

    escalate(
      "kdpa-ctr-threshold",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const amount = input["amount"];
        const currency = String(input["currency"] ?? "").toUpperCase();
        return (currency === "KES" || currency === "") &&
          typeof amount === "number" && amount > 1_000_000;
      },
      "CBK AML: Transaction exceeds KSh 1,000,000 — Proceeds of Crime and AML Act reporting required.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "kdpa-health-data",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(health|medical|nhif|sha|patient|diagnosis|hiv|tuberculosis|malaria|prescription)\b/i.test(inputStr);
      },
      "Kenya DPA §27: Health and medical data require explicit consent and Data Protection Officer review.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "kdpa-bulk-export",
      amountExceeds("record_count", 1000),
      "Kenya DPA §48: Bulk export of >1000 personal data records requires ODPC prior authorisation.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "kdpa-cross-border-transfer",
      and(
        toolNameMatches(/transfer|export|send|sync|cross.?border/i),
        (ctx) => {
          const input = ctx.toolInput as Record<string, unknown>;
          return !!input["destination_country"] || !!input["destination_region"];
        },
      ),
      "Kenya DPA §48: Cross-border data transfer requires consent documentation.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "kdpa-data-subject-rights",
      toolNameMatches(/^(delete_user|erase_data|data_portability|subject_access|sar_|right_to_erasure)/i),
      "Kenya DPA §26–32: Data subject rights exercise requires DPO oversight and 7-day response tracking.",
      { riskLevel: "medium", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "kdpa-subagent-personal-data-write",
      and(isSubagentCall(), toolNameMatches(/update|write|store|save|create|modify/i)),
      "Kenya DPA: Subagent personal data write — principal verification required.",
      { riskLevel: "high", owaspRisks: ["ASI03"] },
    ),

    // ── Audit ─────────────────────────────────────────────────────────────────

    audit(
      "kdpa-pii-access",
      toolNameMatches(/customer|user.{0,20}(profile|data|record)|personal.{0,20}data|identity/i),
      "Kenya DPA §22: Personal data access logged for data controller accountability.",
      { riskLevel: "medium", owaspRisks: [] },
    ),

    allow(
      "kdpa-read-only",
      toolNameMatches(/^(get_|check_|verify_|list_|search_kra|validate_)/i),
      "Kenya DPA: Read-only operations are permitted without additional controls.",
    ),

  ],
});
