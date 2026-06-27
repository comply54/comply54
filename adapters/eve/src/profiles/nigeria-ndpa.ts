import { definePolicy } from "eve-policy";
import { deny, escalate, audit, allow } from "eve-policy/rules";
import {
  toolNameMatches,
  fieldContains,
  amountExceeds,
  isSubagentCall,
  and,
  or,
} from "eve-policy/rules";

/**
 * Nigeria Data Protection Act (NDPA) 2023 — Eve Governance Profile
 *
 * Source: agt-policies-nigeria NDPA Rego policies
 * Enforcer: Nigeria Data Protection Commission (NDPC)
 *
 * Key provisions modeled:
 * - Data residency: personal data of Nigerians must stay in Nigeria or adequacy-listed countries
 * - Breach suppression: agents must never suppress or delay incident notification
 * - Sensitive data: biometric, health, financial — heightened protection
 * - Lawful basis: consent must be documented for cross-border transfers
 * - Data subject rights: erasure/portability tools require human review
 * - Bulk export: >1000 records triggers escalation
 *
 * @see https://ndpc.gov.ng/
 * @see kingztech2019/agt-policies-nigeria (policies/ndpa-data-residency.yaml)
 */
export const ndpaPolicy = definePolicy({
  name: "comply54-nigeria-ndpa",
  version: "2023.1.0",
  description: "Nigeria Data Protection Act 2023 — NDPC enforcement profile for Eve agents",
  defaultEffect: "audit",
  rules: [
    // ── Hard denials ─────────────────────────────────────────────────────────

    deny(
      "ndpa-breach-suppression",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(don'?t|do\s+not|never|suppress|delay|hide|conceal)\s.{0,40}(breach|incident|data\s+leak|security\s+event|compromise)/i.test(inputStr);
      },
      "NDPA §40: Breach suppression instruction detected. Breach notification is mandatory — cannot be overridden by an agent.",
      { riskLevel: "critical", owaspRisks: ["ASI01", "ASI09"] },
    ),

    deny(
      "ndpa-biometric-unguarded",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(biometric|fingerprint|iris|retina|facial\s+recognition|voiceprint|dna\s+sample)\b/i.test(inputStr) &&
          !/\b(authorized|authorised|consent|approved)\b/i.test(inputStr);
      },
      "NDPA §30: Biometric data processed without documented authorisation — prohibited.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "ndpa-cross-border-non-adequate",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const dest = String(input["destination_country"] ?? input["destination_region"] ?? "").toUpperCase();
        if (!dest) return false;
        const adequateCountries = new Set([
          "NG", "GB", "EU", "DE", "FR", "NL", "IE", "ZA", "KE", "GH", "MU",
          "eu-west-1", "af-south-1", "africa", "nigeria", "NG"
        ]);
        return !adequateCountries.has(dest) && (
          toolNameMatches(/transfer|export|send|sync|replicate|cross.?border/i)(ctx)
        );
      },
      "NDPA §43: Cross-border transfer to non-adequacy country without NDPC authorisation is prohibited.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    // ── Escalations ───────────────────────────────────────────────────────────

    escalate(
      "ndpa-bulk-export",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const count = input["record_count"] ?? input["count"] ?? input["limit"];
        return typeof count === "number" && count > 1000;
      },
      "NDPA §43: Bulk export of >1000 records requires Data Protection Officer (DPO) review.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "ndpa-health-data",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(health|medical|diagnosis|prescription|patient|clinical|hiv|mental[\s_]health|psychiatric)/i.test(inputStr);
      },
      "NDPA §30: Health/medical data is a special category — processing requires escalated review.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "ndpa-cross-border-transfer",
      and(
        toolNameMatches(/transfer|export|send|sync|replicate|cross.?border/i),
        (ctx) => {
          const input = ctx.toolInput as Record<string, unknown>;
          const dest = String(input["destination_country"] ?? input["destination_region"] ?? "");
          return dest.length > 0;
        },
      ),
      "NDPA §43: Cross-border data transfer requires consent documentation and DPO review.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "ndpa-data-subject-rights",
      toolNameMatches(/^(delete_user|erase_data|data_erasure|portability|export_my_data|subject_access_request|sar_)$/i),
      "NDPA §34–38: Data subject rights requests (erasure, portability, access) require DPO oversight.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "ndpa-dpo-bypass",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(skip|bypass|override|ignore)\s.{0,30}(dpo|data\s+protection\s+officer|privacy\s+officer|consent)/i.test(inputStr);
      },
      "NDPA §32: DPO oversight cannot be bypassed — escalating for mandatory review.",
      { riskLevel: "high", owaspRisks: ["ASI09"] },
    ),

    escalate(
      "ndpa-subagent-pii-write",
      and(
        isSubagentCall(),
        toolNameMatches(/update|write|store|save|create|insert|modify/i),
      ),
      "NDPA: Subagent attempting PII write — principal verification required.",
      { riskLevel: "high", owaspRisks: ["ASI03"] },
    ),

    // ── Mandatory audit ────────────────────────────────────────────────────────

    audit(
      "ndpa-pii-access",
      toolNameMatches(/customer|user.{0,20}(profile|data|record)|personal.{0,20}data|pii|identity/i),
      "NDPA §22: PII access logged for data controller accountability.",
      { riskLevel: "medium", owaspRisks: ["ASI02"] },
    ),

    audit(
      "ndpa-moderate-export",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const count = input["record_count"] ?? input["count"] ?? input["limit"];
        return typeof count === "number" && count > 100 && count <= 1000;
      },
      "NDPA §43: Moderate bulk operation (100–1000 records) logged for compliance monitoring.",
      { riskLevel: "low", owaspRisks: [] },
    ),

  ],
});

/**
 * CBN Digital Finance Policy Framework — Eve Governance Profile
 *
 * Enforcer: Central Bank of Nigeria (CBN)
 * Covers: AML/CFT, transaction monitoring, mobile money, virtual accounts
 *
 * Key rules:
 * - CTR threshold: ₦5,000,000 per CBN AML/CFT framework
 * - STR: Structured/suspicious transaction patterns
 * - No cash-equivalent transactions without documented KYC
 * - NIBSS virtual account creation requires approval
 */
export const cbnFintechPolicy = definePolicy({
  name: "comply54-nigeria-cbn",
  version: "2024.1.0",
  description: "CBN Digital Finance Policy Framework — AML/CFT and transaction controls for Eve agents",
  defaultEffect: "audit",
  rules: [
    // ── Hard denials ─────────────────────────────────────────────────────────

    deny(
      "cbn-no-kyc-transaction",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /(no\s+kyc|without\s+kyc|skip\s+kyc|kyc.{0,20}(not|skip|waive|bypass|exempt))/i.test(inputStr) &&
          toolNameMatches(/payment|transfer|disburse|wallet|account/i)(ctx);
      },
      "CBN AML/CFT §8: Financial transactions without KYC verification are prohibited.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    deny(
      "cbn-sanctioned-entity",
      (ctx) => {
        const inputStr = JSON.stringify(ctx.toolInput);
        return /\b(ofac|nfiu.{0,20}watch|sanctioned|pep\s+list|politically\s+exposed)\b/i.test(inputStr) &&
          /(match|found|detected|flagged)/i.test(inputStr);
      },
      "CBN AML/CFT: Sanctioned entity or PEP match detected — transaction must be blocked.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    // ── Escalations ───────────────────────────────────────────────────────────

    escalate(
      "cbn-ctr-threshold",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const amount = input["amount"];
        return typeof amount === "number" && amount > 5_000_000;
      },
      "CBN AML/CFT §12: Transaction exceeds ₦5,000,000 CTR threshold — NFIU report required.",
      { riskLevel: "critical", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "cbn-structured-transaction",
      (ctx) => {
        const input = ctx.toolInput as Record<string, unknown>;
        const amount = input["amount"];
        // Near-threshold transactions (structuring detection): ₦4.5M–₦5M
        return typeof amount === "number" && amount >= 4_500_000 && amount < 5_000_000;
      },
      "CBN AML/CFT: Near-threshold transaction (₦4.5M–₦5M) — potential structuring, requires review.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "cbn-virtual-account-creation",
      toolNameMatches(/^(create_virtual_account|generate_account_number|provision_wallet|open_account)$/i),
      "CBN PSB Framework: Virtual/wallet account creation requires regulatory compliance verification.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    escalate(
      "cbn-suspicious-pattern",
      or(
        fieldContains("note", "avoid detection"),
        fieldContains("note", "split payment"),
        (ctx) => {
          const inputStr = JSON.stringify(ctx.toolInput);
          return /(structuring|smurfing|layering|placement|integration).{0,30}(transaction|transfer|payment)/i.test(inputStr);
        },
      ),
      "CBN AML/CFT: Suspicious transaction language detected — escalating for SAR evaluation.",
      { riskLevel: "critical", owaspRisks: ["ASI01", "ASI09"] },
    ),

    escalate(
      "cbn-interbank-transfer",
      and(
        toolNameMatches(/nip|nibss|rtgs|interbank|wire/i),
        amountExceeds("amount", 1_000_000),
      ),
      "CBN RTGS/NIP: Large interbank transfer requires correspondent verification.",
      { riskLevel: "high", owaspRisks: ["ASI02"] },
    ),

    // ── Audit ─────────────────────────────────────────────────────────────────

    audit(
      "cbn-transaction-log",
      toolNameMatches(/payment|transfer|disburse|credit|debit|topup|airtime|utility/i),
      "CBN AML/CFT: All financial transactions logged for regulatory audit trail.",
      { riskLevel: "low", owaspRisks: [] },
    ),

    allow(
      "cbn-balance-inquiry",
      toolNameMatches(/^(get_balance|check_balance|get_statement|transaction_history)$/i),
      "CBN: Balance inquiries and read-only operations are permitted.",
    ),

  ],
});
