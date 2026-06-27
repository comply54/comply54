import { definePolicy } from "eve-policy";
import { deny, escalate, audit, allow } from "eve-policy/rules";
import {
  toolNameMatches,
  amountExceeds,
  isSubagentCall,
  and,
} from "eve-policy/rules";

/**
 * Ghana Data Protection Act (DPA) 2012 (Act 843) — Eve Governance Profile
 *
 * Enforcer: Data Protection Commission (DPC) Ghana
 * Notable: First comprehensive data protection law in West Africa
 *
 * Key provisions:
 * - Registration mandatory for all data controllers and processors
 * - 8 data protection principles (similar to GDPR)
 * - Sensitive personal data: health, racial/ethnic origin, religion, biometric, political
 * - Data subject rights: access, correction, erasure
 * - Cross-border transfers: only to countries with adequate protection
 * - Ghana Card NIN format: GHA-XXXXXXXXX-X
 *
 * @see https://www.dataprotection.org.gh/
 */
export const ghanaDppaPolicy = definePolicy({
  name: "comply54-ghana-dppa",
  version: "2012.1.0",
  description: "Ghana Data Protection Act 2012 (Act 843) — DPC enforcement profile for Eve agents",
  defaultEffect: "audit",
  rules: [
    // ── Hard denials ─────────────────────────────────────────────────────────

    deny(
      "gh-dppa-breach-suppression",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(don'?t|do\s+not|suppress|delay|hide)\s.{0,40}(breach|security\s+incident|data\s+loss)/i.test(inputStr);
      },
      "Ghana DPA §33: Breach notification to DPC is mandatory — suppression is prohibited.",
      { riskLevel: "critical", owaspRisks: ["ASI01", "ASI09"] },
    ),

    deny(
      "gh-dppa-ghana-card-nin",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\bGHA-[A-Z0-9]{9}-[0-9]\b/.test(inputStr);
      },
      "Ghana DPA: Ghana Card NIN detected in input — national ID must not be processed without documented grounds.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "gh-dppa-sensitive-data-unguarded",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        const isSensitive = /\b(biometric|health\s+record|racial|ethnic|religion|criminal\s+conviction|ghana\s+card)\b/i.test(inputStr);
        const hasConsent = /\b(consent|authorised|authorized|lawful\s+basis)\b/i.test(inputStr);
        return isSensitive && !hasConsent;
      },
      "Ghana DPA §19: Sensitive personal data (biometric, health, racial origin) requires explicit consent.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "gh-dppa-cross-border-non-adequate",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const dest = String(input["destination_country"] ?? "").toUpperCase();
        if (!dest) return false;
        const adequateList = new Set(["GH", "GB", "EU", "ZA", "KE", "MU", "NG", "af-south-1", "af-west-1"]);
        return toolNameMatches(/transfer|export|send|cross.?border/i)(ctx) && !adequateList.has(dest);
      },
      "Ghana DPA §34: Cross-border transfer to country without adequate protection requires DPC authorisation.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    // ── Escalations ───────────────────────────────────────────────────────────

    escalate(
      "gh-dppa-bulk-export",
      amountExceeds("record_count", 1000),
      "Ghana DPA §34: Bulk export of >1000 personal data records requires DPC prior approval.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "gh-dppa-cross-border-transfer",
      and(
        toolNameMatches(/transfer|export|send|cross.?border/i),
        (ctx) => {
          const input = ctx.toolInput as Record<string, unknown>;
          return !!input["destination_country"];
        },
      ),
      "Ghana DPA §34: Cross-border data transfer requires consent and adequacy verification.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "gh-dppa-registration-bypass",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(skip|bypass|no\s+need)\s.{0,30}(register|dpc|data\s+protection\s+commission)/i.test(inputStr);
      },
      "Ghana DPA §17: Registration with DPC is mandatory for all data controllers.",
      { riskLevel: "high", owaspRisks: ["ASI09"] },
    ),

    escalate(
      "gh-dppa-data-subject-rights",
      toolNameMatches(/^(delete_user|erase_data|subject_access|access_request|data_correction)/i),
      "Ghana DPA §24–32: Data subject rights require a designated officer to handle within 21 days.",
      { riskLevel: "medium", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "gh-dppa-subagent-pii-write",
      and(isSubagentCall(), toolNameMatches(/update|write|store|save|create|modify/i)),
      "Ghana DPA: Subagent PII write — controller-level verification required.",
      { riskLevel: "high", owaspRisks: ["ASI03"] },
    ),

    // ── Audit ─────────────────────────────────────────────────────────────────

    audit(
      "gh-dppa-pii-access",
      toolNameMatches(/customer|personal.{0,20}(data|info|record)|user.{0,20}profile/i),
      "Ghana DPA: Personal data access logged for accountability.",
      { riskLevel: "medium", owaspRisks: [] },
    ),

    allow(
      "gh-dppa-read-only",
      toolNameMatches(/^(get_|check_|list_|search_|verify_|query_)/i),
      "Ghana DPA: Read-only operations permitted.",
    ),

  ],
});
