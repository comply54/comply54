import { definePolicy } from "eve-policy";
import { deny, escalate, audit, allow } from "eve-policy/rules";
import {
  toolNameMatches,
  amountExceeds,
  isSubagentCall,
  and,
} from "eve-policy/rules";

/**
 * Protection of Personal Information Act (POPIA) 2013 — Eve Governance Profile
 *
 * Enforcer: Information Regulator of South Africa
 * Effective: 1 July 2021
 *
 * Key provisions:
 * - 8 Conditions for Lawful Processing (Accountability, Processing Limitation,
 *   Purpose Specification, Further Processing Limitation, Information Quality,
 *   Openness, Security Safeguards, Data Subject Participation)
 * - Section 57: Special personal information — prohibition on processing
 *   racial/ethnic origin, religious beliefs, health, biometric data without grounds
 * - Section 72: Prohibition on transfer to countries without adequate protection
 * - Section 22: Mandatory breach notification to Information Regulator AND data subjects
 * - Section 11: Six lawful bases for processing (consent, contract, legal obligation,
 *   legitimate interest, vital interests, public interest)
 * - POPI Act: No retention beyond purpose; mandatory destruction/de-identification
 *
 * @see https://www.inforegulator.org.za/
 */
export const popiaPolicy = definePolicy({
  name: "comply54-south-africa-popia",
  version: "2021.1.0",
  description: "POPIA 2013/2021 — Information Regulator enforcement profile for Eve agents",
  defaultEffect: "audit",
  rules: [
    // ── Hard denials ─────────────────────────────────────────────────────────

    deny(
      "popia-breach-suppression",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(don'?t|do\s+not|never|suppress|delay|hide|conceal)\s.{0,40}(breach|compromise|security\s+incident|data\s+loss|popi)/i.test(inputStr);
      },
      "POPIA §22: Breach notification to the Information Regulator is mandatory. Suppression is prohibited.",
      { riskLevel: "critical", owaspRisks: ["ASI01", "ASI09"] },
    ),

    deny(
      "popia-special-categories-unguarded",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        const isSpecial = /\b(racial|ethnic\s+origin|religion|biometric|health\s+data|sex\s+life|trade\s+union|criminal\s+record|political\s+belief)\b/i.test(inputStr);
        const hasGrounds = /\b(consent|legal\s+obligation|vital\s+interest|research|statistical|historical)\b/i.test(inputStr);
        return isSpecial && !hasGrounds;
      },
      "POPIA §26–27 (Condition 6): Special personal information processed without a lawful ground.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "popia-cross-border-non-adequate",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const dest = String(input["destination_country"] ?? "").toUpperCase();
        if (!dest) return false;
        const adequateCountries = new Set([
          "ZA", "GB", "EU", "DE", "FR", "NL", "MU", "KE", "GH", "NG",
          "ZAF", "eu-west-1", "af-south-1"
        ]);
        return toolNameMatches(/transfer|export|send|sync|cross.?border/i)(ctx) &&
          !adequateCountries.has(dest);
      },
      "POPIA §72: Transfer of personal information to a country without adequate protection is prohibited.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "popia-sa-id-number-in-output",
      (ctx) => {
        const outputStr = JSON.stringify(ctx.toolInput);
        // South African ID: 13 digits starting with YY MM DD GGGGG CRZ
        return /\b(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{7}\b/.test(outputStr);
      },
      "POPIA: South African national ID number detected in tool input — must not be logged or transmitted unmasked.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    // ── Escalations ───────────────────────────────────────────────────────────

    escalate(
      "popia-bulk-export",
      amountExceeds("record_count", 1000),
      "POPIA Condition 7: Bulk personal data export (>1000 records) requires Information Officer review.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "popia-cross-border-transfer",
      and(
        toolNameMatches(/transfer|export|send|sync|cross.?border/i),
        (ctx) => {
          const input = ctx.toolInput as Record<string, unknown>;
          return !!input["destination_country"];
        },
      ),
      "POPIA §72: Cross-border personal information transfer requires documented consent and adequacy assessment.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "popia-data-subject-rights",
      toolNameMatches(/^(delete_user|erase_data|data_portability|subject_access|access_request|correction_request|objection)/i),
      "POPIA §53–73 (Part 3): Data subject rights (access, correction, deletion, objection) require Information Officer.",
      { riskLevel: "medium", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "popia-direct-marketing",
      toolNameMatches(/^(send_marketing|email_campaign|sms_blast|push_notification|newsletter_send)$/i),
      "POPIA §69–70: Electronic marketing to data subjects requires opt-in consent verification.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "popia-subagent-special-data",
      and(isSubagentCall(), toolNameMatches(/health|medical|biometric|racial|criminal/i)),
      "POPIA §26: Subagent processing special personal information — operator-level verification required.",
      { riskLevel: "critical", owaspRisks: ["ASI03"] },
    ),

    // ── Mandatory audit ───────────────────────────────────────────────────────

    audit(
      "popia-pii-access",
      toolNameMatches(/customer|data_subject|personal.{0,20}(data|info|record)|popi/i),
      "POPIA Condition 1: Personal information access logged for data controller accountability.",
      { riskLevel: "medium", owaspRisks: [] },
    ),

    audit(
      "popia-retention-check",
      toolNameMatches(/^(archive|retain|store_long_term|backup_personal)$/i),
      "POPIA Condition 5: Long-term retention logged — ensure purpose limitation compliance.",
      { riskLevel: "low", owaspRisks: [] },
    ),

    allow(
      "popia-read-only",
      toolNameMatches(/^(get_|check_|list_|search_|verify_)/i),
      "POPIA: Read-only data operations permitted with standard audit logging.",
    ),

  ],
});
