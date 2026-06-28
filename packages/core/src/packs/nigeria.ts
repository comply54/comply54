/**
 * Nigerian policy pack evaluators.
 * Covers: NDPA 2023, CBN Transaction Controls, BVN/NIN Framework, NFIU/MLPPA 2022,
 *         NHA 2014 (Healthcare), NAICOM (Insurance).
 */

import { makeAuditId, nowIso, isSanctioned, hasAdequacy, hasBvn, hasNin } from "../utils.js";
import type { EvaluationInput, PackEvaluatorFn, PolicyDecision, RegulatorySource } from "../types.js";

// ── Regulatory citation constants ─────────────────────────────────────────────

const CBN_CITATIONS: RegulatorySource[] = [
  { document: "CBN Circular FPR/DIR/GEN/CIR/07/003", section: "§3.1", authority: "CBN", year: 2013 },
  { document: "CBN NIP (NIBSS Instant Payment) Framework", section: "§4.2", authority: "CBN", year: 2011 },
  { document: "CBN Regulatory Framework for BVN Operations 2014", section: "§2.4", authority: "CBN", year: 2014 },
  { document: "CBN USSD Banking Circular BSD/DIR/GEN/CIR/07/002", section: "§5.2", authority: "CBN", year: 2019 },
];

const NDPA_CITATIONS: RegulatorySource[] = [
  { document: "Nigeria Data Protection Act 2023", section: "§24", authority: "NDPC", year: 2023 },
  { document: "Nigeria Data Protection Act 2023", section: "§25", authority: "NDPC", year: 2023 },
  { document: "Nigeria Data Protection Act 2023", section: "§30", authority: "NDPC", year: 2023 },
];

const BVN_NIN_CITATIONS: RegulatorySource[] = [
  { document: "CBN Regulatory Framework for BVN Operations 2014", section: "§6", authority: "CBN", year: 2014 },
  { document: "NIBSS BVN Scheme Rules 2014", section: "Rule 4.2", authority: "NIBSS", year: 2014 },
  { document: "NIMC Act 2026", section: "Purpose Limitation & Data Persistence Prohibition", authority: "NIMC", year: 2026 },
];

const NFIU_CITATIONS: RegulatorySource[] = [
  { document: "Money Laundering (Prevention and Prohibition) Act 2022", section: "§10", authority: "NFIU", year: 2022 },
  { document: "Money Laundering (Prevention and Prohibition) Act 2022", section: "§11", authority: "NFIU", year: 2022 },
  { document: "NFIU AML/CFT Compliance Framework 2022", section: "§3.2", authority: "NFIU", year: 2022 },
];

const NHA_CITATIONS: RegulatorySource[] = [
  { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§26", authority: "FMOH", year: 2014 },
  { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§29", authority: "FMOH", year: 2014 },
  { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§30", authority: "FMOH", year: 2014 },
  { document: "Medical and Dental Practitioners Act Cap M8 LFN 2004", section: "§16", authority: "MDCN", year: 2004 },
  { document: "FMOH AI in Healthcare Policy (Draft 2024)", section: "Guideline 4", authority: "FMOH", year: 2024 },
  { document: "FMOH AI in Healthcare Policy (Draft 2024)", section: "Guideline 7", authority: "FMOH", year: 2024 },
];

const NAICOM_CITATIONS: RegulatorySource[] = [
  { document: "Insurance Act 2003 (Cap I17 LFN 2004)", section: "§50", authority: "NAICOM", year: 2003 },
  { document: "Insurance Act 2003 (Cap I17 LFN 2004)", section: "§67", authority: "NAICOM", year: 2003 },
  { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 12", authority: "NAICOM", year: 2021 },
  { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 15", authority: "NAICOM", year: 2021 },
  { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 18", authority: "NAICOM", year: 2021 },
  { document: "NAICOM Market Conduct and Business Practice Guidelines 2023", section: "Rule 6", authority: "NAICOM", year: 2023 },
  { document: "NAICOM Market Conduct and Business Practice Guidelines 2023", section: "Rule 11", authority: "NAICOM", year: 2023 },
];

// ── Per-rule citation maps ─────────────────────────────────────────────────────

const CBN_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  cbn_no_kyc: [
    { document: "CBN Circular FPR/DIR/GEN/CIR/07/003", section: "§2.1 — KYC Requirements", authority: "CBN", year: 2013 },
  ],
  cbn_nip_cap: [
    { document: "CBN NIP (NIBSS Instant Payment) Framework", section: "§4.2 — Per-Transaction Cap", authority: "CBN", year: 2011 },
  ],
  cbn_tier_limit: [
    { document: "CBN Circular FPR/DIR/GEN/CIR/07/003", section: "§3.1 — Tiered KYC Limits", authority: "CBN", year: 2013 },
  ],
  cbn_pep: [
    { document: "NFIU AML/CFT Compliance Framework 2022", section: "§5.1 — PEP Enhanced Due Diligence", authority: "NFIU", year: 2022 },
    { document: "CBN Circular FPR/DIR/GEN/CIR/07/003", section: "§4.3 — PEP Controls", authority: "CBN", year: 2013 },
  ],
  cbn_fx: [
    { document: "CBN Foreign Exchange (Monitoring and Miscellaneous Provisions) Act 2004", section: "§3 — FX Compliance", authority: "CBN", year: 2004 },
  ],
};

const NDPA_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  ndpa_biometric_export: [
    { document: "Nigeria Data Protection Act 2023", section: "§25 — Biometric Cross-Border Ban", authority: "NDPC", year: 2023 },
  ],
  ndpa_cross_border_consent: [
    { document: "Nigeria Data Protection Act 2023", section: "§25 — Cross-Border Consent", authority: "NDPC", year: 2023 },
  ],
  ndpa_non_adequate_escalate: [
    { document: "Nigeria Data Protection Act 2023", section: "§25 — Non-Adequate Transfer", authority: "NDPC", year: 2023 },
  ],
  ndpa_non_adequate_deny: [
    { document: "Nigeria Data Protection Act 2023", section: "§25 — Non-Adequate No-Consent", authority: "NDPC", year: 2023 },
  ],
};

const BVN_NIN_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  bvn_in_output: [
    { document: "CBN Regulatory Framework for BVN Operations 2014", section: "§6", authority: "CBN", year: 2014 },
  ],
  nin_in_output: [
    { document: "NIMC Act 2026", section: "Prohibition on Unauthorized NIN Disclosure", authority: "NIMC", year: 2026 },
    { document: "Nigeria Data Protection Act 2023", section: "Schedule 1", authority: "NDPC", year: 2023 },
  ],
  biometric_export: [
    { document: "NIMC Act 2026", section: "Prohibition on Unauthorized NIN Disclosure", authority: "NIMC", year: 2026 },
  ],
  nimc_nin_persistence: [
    { document: "NIMC Act 2026", section: "Prohibition of Illegal Data Persistence", authority: "NIMC", year: 2026 },
    { document: "Nigeria Data Protection Act 2023", section: "§26 — Storage Limitation", authority: "NDPC", year: 2023 },
  ],
  nimc_nin_bulk_export: [
    { document: "NIMC Act 2026", section: "Prohibition on Bulk NIN Data Extraction", authority: "NIMC", year: 2026 },
    { document: "Nigeria Data Protection Act 2023", section: "§25 — Bulk Transfer Controls", authority: "NDPC", year: 2023 },
  ],
  nimc_purpose_limitation: [
    { document: "NIMC Act 2026", section: "Purpose Limitation — NIN Use Restricted to Stated Purpose", authority: "NIMC", year: 2026 },
    { document: "Nigeria Data Protection Act 2023", section: "§24 — Purpose Limitation", authority: "NDPC", year: 2023 },
  ],
  nimc_mandatory_service: [
    { document: "NIMC Act 2026", section: "NIN as Mandatory Prerequisite for Regulated Services", authority: "NIMC", year: 2026 },
  ],
};

const NHA_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  nha_no_consent_access: [
    { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§26", authority: "FMOH", year: 2014 },
    { document: "Nigeria Data Protection Act 2023", section: "§30", authority: "NDPC", year: 2023 },
  ],
  nha_cross_border_health: [
    { document: "Nigeria Data Protection Act 2023", section: "§25", authority: "NDPC", year: 2023 },
    { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§29", authority: "FMOH", year: 2014 },
  ],
  nha_no_consent_share: [
    { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§29", authority: "FMOH", year: 2014 },
  ],
  nha_ai_diagnosis_no_oversight: [
    { document: "FMOH AI in Healthcare Policy (Draft 2024)", section: "Guideline 4", authority: "FMOH", year: 2024 },
    { document: "Medical and Dental Practitioners Act Cap M8 LFN 2004", section: "§16", authority: "MDCN", year: 2004 },
  ],
  nha_ai_prescription: [
    { document: "Medical and Dental Practitioners Act Cap M8 LFN 2004", section: "§16", authority: "MDCN", year: 2004 },
    { document: "FMOH AI in Healthcare Policy (Draft 2024)", section: "Guideline 7", authority: "FMOH", year: 2024 },
  ],
  nha_diagnosis_escalate: [
    { document: "FMOH AI in Healthcare Policy (Draft 2024)", section: "Guideline 4", authority: "FMOH", year: 2024 },
  ],
  nha_high_risk_clinical: [
    { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§26", authority: "FMOH", year: 2014 },
  ],
  nha_research_escalate: [
    { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§26", authority: "FMOH", year: 2014 },
  ],
  nha_bulk_access: [
    { document: "Nigeria Data Protection Act 2023", section: "§30", authority: "NDPC", year: 2023 },
  ],
  nha_audit_access: [
    { document: "National Health Act 2014 (Act No. 8 of 2014)", section: "§26", authority: "FMOH", year: 2014 },
    { document: "Nigeria Data Protection Act 2023", section: "§30", authority: "NDPC", year: 2023 },
  ],
};

const NAICOM_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  naicom_auto_denial_cap: [
    { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 15", authority: "NAICOM", year: 2021 },
  ],
  naicom_discrimination: [
    { document: "Insurance Act 2003 (Cap I17 LFN 2004)", section: "§67", authority: "NAICOM", year: 2003 },
    { document: "NAICOM Market Conduct and Business Practice Guidelines 2023", section: "Rule 6", authority: "NAICOM", year: 2023 },
  ],
  naicom_life_underwriting_cap: [
    { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 18", authority: "NAICOM", year: 2021 },
  ],
  naicom_senior_review: [
    { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 12", authority: "NAICOM", year: 2021 },
  ],
  naicom_aml_threshold: [
    { document: "Money Laundering (Prevention and Prohibition) Act 2022", section: "§10", authority: "NFIU", year: 2022 },
    { document: "NFIU AML/CFT Compliance Framework 2022", section: "§6.1", authority: "NFIU", year: 2022 },
  ],
  naicom_fraud_human: [
    { document: "NAICOM Market Conduct and Business Practice Guidelines 2023", section: "Rule 11", authority: "NAICOM", year: 2023 },
  ],
  naicom_fraud_score: [
    { document: "NAICOM Market Conduct and Business Practice Guidelines 2023", section: "Rule 11", authority: "NAICOM", year: 2023 },
  ],
  naicom_policy_modification: [
    { document: "Insurance Act 2003 (Cap I17 LFN 2004)", section: "§50", authority: "NAICOM", year: 2003 },
  ],
  naicom_sub_cap_denial: [
    { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 15", authority: "NAICOM", year: 2021 },
  ],
  naicom_audit: [
    { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 12", authority: "NAICOM", year: 2021 },
    { document: "Insurance Act 2003 (Cap I17 LFN 2004)", section: "§70", authority: "NAICOM", year: 2003 },
  ],
  naicom_audit_underwriting: [
    { document: "NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section: "Guideline 18", authority: "NAICOM", year: 2021 },
  ],
};

const NFIU_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  nfiu_sanctions: [
    { document: "Money Laundering (Prevention and Prohibition) Act 2022", section: "§10", authority: "NFIU", year: 2022 },
    { document: "Terrorism (Prevention and Prohibition) Act 2022", section: "§16", authority: "NFIU", year: 2022 },
  ],
  nfiu_structuring: [
    { document: "Money Laundering (Prevention and Prohibition) Act 2022", section: "§14", authority: "NFIU", year: 2022 },
  ],
  nfiu_ctr: [
    { document: "Money Laundering (Prevention and Prohibition) Act 2022", section: "§10 — CTR Filing", authority: "NFIU", year: 2022 },
  ],
};

type Input = Required<EvaluationInput>;

// ── CBN Transaction Controls ──────────────────────────────────────────────────

const CBN_NIP_CAP = 10_000_000;

const TIER_LIMITS: Record<number, number> = {
  0: 0,
  1: 200_000,
  2: 2_000_000,
  3: CBN_NIP_CAP,
};

export const evaluateCBN: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "nigeria/cbn",
    regulation: "CBN NIP Framework",
    jurisdiction: "NG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: CBN_CITATIONS,
  };

  if (input.action !== "transfer_funds") {
    return { ...base, action: "allow", messages: [] };
  }

  const amount = Number(input.params["amount"] ?? 0);
  const currency = String(input.params["currency"] ?? "NGN").toUpperCase();
  const kyc = Number(input.context["kyc_tier"] ?? -1);
  const pep = Boolean(input.context["pep_flag"]);

  // No KYC — block entirely
  if (kyc === 0 || kyc < 0) {
    return {
      ...base,
      action: "deny",
      messages: ["CBN KYC Framework: No verified identity — transaction blocked pending KYC"],
      ruleTriggered: "cbn_no_kyc",
      citations: CBN_RULE_CITATIONS["cbn_no_kyc"] ?? CBN_CITATIONS,
    };
  }

  // Exceeds absolute NIP cap
  if (currency === "NGN" && amount > CBN_NIP_CAP) {
    return {
      ...base,
      action: "deny",
      messages: [
        `CBN NIP Framework §4.2: Transaction of ₦${amount.toLocaleString()} exceeds the ₦${CBN_NIP_CAP.toLocaleString()} single-transaction cap`,
      ],
      ruleTriggered: "cbn_nip_cap",
      citations: CBN_RULE_CITATIONS["cbn_nip_cap"] ?? CBN_CITATIONS,
    };
  }

  // Exceeds tier limit
  const tierLimit = TIER_LIMITS[Math.min(kyc, 3)] ?? 0;
  if (currency === "NGN" && amount > tierLimit) {
    return {
      ...base,
      action: "deny",
      messages: [
        `CBN KYC Framework: Tier ${kyc} single-transaction limit is ₦${tierLimit.toLocaleString()} — ₦${amount.toLocaleString()} exceeds limit`,
      ],
      ruleTriggered: "cbn_tier_limit",
      citations: CBN_RULE_CITATIONS["cbn_tier_limit"] ?? CBN_CITATIONS,
    };
  }

  // PEP flag
  if (pep) {
    return {
      ...base,
      action: "escalate",
      messages: ["CBN AML/CFT: PEP flag set — transaction requires compliance officer approval"],
      ruleTriggered: "cbn_pep",
      citations: CBN_RULE_CITATIONS["cbn_pep"] ?? CBN_CITATIONS,
    };
  }

  // Non-NGN
  if (currency !== "NGN") {
    return {
      ...base,
      action: "escalate",
      messages: ["CBN FX Policy: Non-NGN transfer requires CBN FX compliance review"],
      ruleTriggered: "cbn_fx",
      citations: CBN_RULE_CITATIONS["cbn_fx"] ?? CBN_CITATIONS,
    };
  }

  return { ...base, action: "allow", messages: [] };
};

// ── NDPA 2023 ─────────────────────────────────────────────────────────────────

const TRANSFER_ACTIONS = new Set(["send_to_external", "export_data", "store_data"]);

export const evaluateNDPA: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "nigeria/ndpa",
    regulation: "NDPA 2023",
    jurisdiction: "NG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: NDPA_CITATIONS,
  };

  if (!TRANSFER_ACTIONS.has(input.action)) {
    return { ...base, action: "allow", messages: [] };
  }

  const dest = String(input.params["destination_country"] ?? input.params["destination_region"] ?? "NG").toUpperCase();
  const dataType = String(input.params["data_type"] ?? "").toLowerCase();
  const consent = Boolean(input.context["consent_documented"]);

  // Domestic — always allow
  if (dest === "NG") {
    return { ...base, action: "allow", messages: [] };
  }

  // Biometric — always deny cross-border
  if (dataType === "biometric") {
    return {
      ...base,
      action: "deny",
      messages: ["NDPA 2023 §25: Biometric data transfer outside Nigeria is prohibited"],
      ruleTriggered: "ndpa_biometric_export",
      citations: NDPA_RULE_CITATIONS["ndpa_biometric_export"] ?? NDPA_CITATIONS,
    };
  }

  // Adequate destination with consent
  if (hasAdequacy(dest)) {
    if (consent) {
      return { ...base, action: "allow", messages: [] };
    }
    return {
      ...base,
      action: "escalate",
      messages: [
        `NDPA 2023 §25: Cross-border transfer to ${dest} requires explicit consent or adequacy confirmation`,
      ],
      ruleTriggered: "ndpa_cross_border_consent",
      citations: NDPA_RULE_CITATIONS["ndpa_cross_border_consent"] ?? NDPA_CITATIONS,
    };
  }

  // Non-adequate destination
  if (consent) {
    return {
      ...base,
      action: "escalate",
      messages: [
        `NDPA 2023 §25: Transfer to ${dest} — no adequacy. Consent documented but NITDA notification required`,
      ],
      ruleTriggered: "ndpa_non_adequate_escalate",
      citations: NDPA_RULE_CITATIONS["ndpa_non_adequate_escalate"] ?? NDPA_CITATIONS,
    };
  }

  return {
    ...base,
    action: "deny",
    messages: [
      `NDPA 2023 §25: Transfer to ${dest} — no adequacy and no consent. Transfer prohibited`,
    ],
    ruleTriggered: "ndpa_non_adequate_deny",
    citations: NDPA_RULE_CITATIONS["ndpa_non_adequate_deny"] ?? NDPA_CITATIONS,
  };
};

// ── BVN/NIN Framework ─────────────────────────────────────────────────────────

const PERSIST_ACTIONS = new Set([
  "store_nin", "save_nin_data", "persist_identity", "cache_nin", "log_nin",
  "record_nin", "write_nin_record", "store_bvn", "save_bvn_data", "cache_bvn",
]);

const BULK_EXPORT_ACTIONS = new Set([
  "export_nin_data", "bulk_nin_export", "download_nin_records",
  "extract_identity_records", "bulk_identity_export",
]);

const MANDATORY_NIN_ACTIONS = new Set([
  "open_account", "create_account", "register_voter", "apply_passport",
  "sim_registration", "land_registration", "pension_enrollment",
  "insurance_enrollment", "apply_credit", "tax_registration",
  "apply_government_service",
]);

export const evaluateBvnNin: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "nigeria/bvn-nin",
    regulation: "CBN BVN Framework, NIBSS BVN Scheme Rules & NIMC Act 2026",
    jurisdiction: "NG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: BVN_NIN_CITATIONS,
  };

  const output = input.output ?? "";
  const action = input.action ?? "";
  const params = input.params ?? {};
  const context = input.context ?? {};

  // ── Output-level deny ─────────────────────────────────────────────────────
  if (hasBvn(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["BVN/NIN Framework: BVN detected in agent output — must not be exposed in plaintext"],
      ruleTriggered: "bvn_in_output",
      citations: BVN_NIN_RULE_CITATIONS["bvn_in_output"] ?? BVN_NIN_CITATIONS,
    };
  }

  if (hasNin(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["BVN/NIN Framework: NIN detected in agent output — sharing NIN values is prohibited"],
      ruleTriggered: "nin_in_output",
      citations: BVN_NIN_RULE_CITATIONS["nin_in_output"] ?? BVN_NIN_CITATIONS,
    };
  }

  // ── NIMC Act 2026: Biometric export ───────────────────────────────────────
  const dataType = String(params["data_type"] ?? "").toLowerCase();
  const dest = String(params["destination_country"] ?? "NG").toUpperCase();

  if (dataType === "biometric" && dest !== "NG") {
    return {
      ...base,
      action: "deny",
      messages: ["NIMC Act 2026: Biometric/NIN data export outside Nigeria is prohibited"],
      ruleTriggered: "biometric_export",
      citations: BVN_NIN_RULE_CITATIONS["biometric_export"] ?? BVN_NIN_CITATIONS,
    };
  }

  // ── NIMC Act 2026: Illegal data persistence ───────────────────────────────
  if (PERSIST_ACTIONS.has(action) || params["persist_nin"] === true) {
    return {
      ...base,
      action: "deny",
      messages: ["NIMC Act 2026: Storing NIN/BVN data after verification is prohibited — illegal data persistence (₦20M corporate / 5yr individual penalty)"],
      ruleTriggered: "nimc_nin_persistence",
      citations: BVN_NIN_RULE_CITATIONS["nimc_nin_persistence"] ?? BVN_NIN_CITATIONS,
    };
  }

  // ── NIMC Act 2026: Bulk NIN export ────────────────────────────────────────
  if (BULK_EXPORT_ACTIONS.has(action) || params["bulk_identity_export"] === true) {
    return {
      ...base,
      action: "deny",
      messages: ["NIMC Act 2026: Bulk NIN/identity data export is prohibited — only individual authorised verifications are permitted"],
      ruleTriggered: "nimc_nin_bulk_export",
      citations: BVN_NIN_RULE_CITATIONS["nimc_nin_bulk_export"] ?? BVN_NIN_CITATIONS,
    };
  }

  // ── NIMC Act 2026: Purpose limitation ─────────────────────────────────────
  const ninPurpose = context["nin_consented_purpose"] as string | undefined;
  const currentPurpose = context["purpose"] as string | undefined;
  if (ninPurpose && currentPurpose && ninPurpose !== currentPurpose) {
    return {
      ...base,
      action: "escalate",
      messages: [`NIMC Act 2026: Purpose mismatch — NIN consent was for '${ninPurpose}' but current purpose is '${currentPurpose}'`],
      ruleTriggered: "nimc_purpose_limitation",
      citations: BVN_NIN_RULE_CITATIONS["nimc_purpose_limitation"] ?? BVN_NIN_CITATIONS,
    };
  }

  // ── NIMC Act 2026: Mandatory NIN prerequisite ─────────────────────────────
  if (MANDATORY_NIN_ACTIONS.has(action) && !context["nin_verified"]) {
    return {
      ...base,
      action: "audit",
      messages: [`NIMC Act 2026: '${action}' requires verified NIN — bank accounts, SIM, passports, land, pension, insurance, and credit are mandatory-NIN services`],
      ruleTriggered: "nimc_mandatory_service",
      citations: BVN_NIN_RULE_CITATIONS["nimc_mandatory_service"] ?? BVN_NIN_CITATIONS,
    };
  }

  return { ...base, action: "allow", messages: [] };
};

// ── NHA 2014 — Nigeria National Health Act ────────────────────────────────────

const RECORD_ACCESS_ACTIONS = new Set([
  "access_patient_records", "read_health_record", "get_patient_history",
  "fetch_lab_results", "retrieve_ehr", "query_medical_records",
]);

const HEALTH_SHARING_ACTIONS = new Set([
  "share_health_data", "send_patient_report", "export_health_records",
  "forward_to_provider", "upload_clinical_data", "relay_health_info",
]);

const DIAGNOSIS_ACTIONS = new Set([
  "generate_diagnosis", "assess_symptoms", "interpret_scan",
  "read_pathology", "produce_clinical_assessment",
]);

const PRESCRIPTION_ACTIONS = new Set([
  "prescribe_medication", "issue_prescription", "recommend_dosage", "update_prescription",
]);

const HIGH_RISK_CLINICAL_ACTIONS = new Set([
  "approve_surgery", "authorise_procedure", "consent_to_intervention", "clear_for_operation",
]);

export const evaluateNHA: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "nigeria/nha",
    regulation: "Nigeria National Health Act 2014",
    jurisdiction: "NG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: NHA_CITATIONS,
  };

  const consentDocumented = Boolean(input.context["consent_documented"]);
  const humanClinician = Boolean(input.context["human_clinician_oversight"]);
  const clinicianApproval = Boolean(input.context["licensed_clinician_approval"]);
  const purpose = String(input.context["purpose"] ?? "treatment").toLowerCase();
  const destCountry = String(input.params["destination_country"] ?? "NG").toUpperCase();
  const recordCount = Number(input.params["record_count"] ?? 1);

  // NHA s.26 / NDPA s.30: Record access requires documented consent
  if (RECORD_ACCESS_ACTIONS.has(input.action) && !consentDocumented) {
    return {
      ...base,
      action: "deny",
      messages: ["NHA s.26 / NDPA s.30: Access to patient health records requires documented patient consent — consent_documented must be true"],
      ruleTriggered: "nha_no_consent_access",
      citations: NHA_RULE_CITATIONS["nha_no_consent_access"] ?? NHA_CITATIONS,
    };
  }

  // NHA s.29: Cross-border health data sharing blocked
  if (HEALTH_SHARING_ACTIONS.has(input.action) && destCountry !== "NG") {
    return {
      ...base,
      action: "deny",
      messages: [`NDPA s.25 + NHA s.29: Cross-border transfer of health data to '${destCountry}' is prohibited — special-category data requires adequacy approval`],
      ruleTriggered: "nha_cross_border_health",
      citations: NHA_RULE_CITATIONS["nha_cross_border_health"] ?? NHA_CITATIONS,
    };
  }

  // NHA s.29: Sharing without consent
  if (HEALTH_SHARING_ACTIONS.has(input.action) && !consentDocumented) {
    return {
      ...base,
      action: "deny",
      messages: ["NHA s.29: Health data disclosure to third parties requires explicit patient consent — consent_documented must be true"],
      ruleTriggered: "nha_no_consent_share",
      citations: NHA_RULE_CITATIONS["nha_no_consent_share"] ?? NHA_CITATIONS,
    };
  }

  // FMOH Guideline 4 / MDP Act s.16: AI diagnosis without oversight is prohibited
  if (DIAGNOSIS_ACTIONS.has(input.action) && !humanClinician) {
    return {
      ...base,
      action: "deny",
      messages: ["FMOH AI Guideline 4 / MDP Act s.16: AI-generated diagnosis requires human clinician oversight — set human_clinician_oversight: true"],
      ruleTriggered: "nha_ai_diagnosis_no_oversight",
      citations: NHA_RULE_CITATIONS["nha_ai_diagnosis_no_oversight"] ?? NHA_CITATIONS,
    };
  }

  // MDP Act s.16: AI cannot prescribe without licensed clinician approval
  if (PRESCRIPTION_ACTIONS.has(input.action) && !clinicianApproval) {
    return {
      ...base,
      action: "deny",
      messages: ["MDP Act s.16 / FMOH Guideline 7: AI cannot prescribe medication without licensed clinician approval — set licensed_clinician_approval: true"],
      ruleTriggered: "nha_ai_prescription",
      citations: NHA_RULE_CITATIONS["nha_ai_prescription"] ?? NHA_CITATIONS,
    };
  }

  // FMOH Guideline 4: Diagnosis with oversight must be escalated for clinician sign-off
  if (DIAGNOSIS_ACTIONS.has(input.action) && humanClinician) {
    return {
      ...base,
      action: "escalate",
      messages: ["FMOH AI Guideline 4: AI-assisted diagnosis must be reviewed and signed off by a licensed clinician before communication to patient"],
      ruleTriggered: "nha_diagnosis_escalate",
      citations: NHA_RULE_CITATIONS["nha_diagnosis_escalate"] ?? NHA_CITATIONS,
    };
  }

  // NHA s.26: High-risk clinical actions require human authorisation
  if (HIGH_RISK_CLINICAL_ACTIONS.has(input.action)) {
    return {
      ...base,
      action: "escalate",
      messages: ["NHA s.26 / Clinical Safety: High-risk clinical action requires authorisation by a registered medical practitioner"],
      ruleTriggered: "nha_high_risk_clinical",
      citations: NHA_RULE_CITATIONS["nha_high_risk_clinical"] ?? NHA_CITATIONS,
    };
  }

  // NHA: Research purpose requires ethics committee review
  if (RECORD_ACCESS_ACTIONS.has(input.action) && purpose === "research") {
    return {
      ...base,
      action: "escalate",
      messages: ["NHA 2014 / NDPC Guidelines: Use of patient records for research purpose requires ethics committee review and approval"],
      ruleTriggered: "nha_research_escalate",
      citations: NHA_RULE_CITATIONS["nha_research_escalate"] ?? NHA_CITATIONS,
    };
  }

  // NDPA s.30: Bulk record access requires DPO review
  if (RECORD_ACCESS_ACTIONS.has(input.action) && recordCount > 10) {
    return {
      ...base,
      action: "escalate",
      messages: [`NDPA s.30: Bulk access to ${recordCount} patient records (special-category data) requires Data Protection Officer review`],
      ruleTriggered: "nha_bulk_access",
      citations: NHA_RULE_CITATIONS["nha_bulk_access"] ?? NHA_CITATIONS,
    };
  }

  // Audit all record access
  if (RECORD_ACCESS_ACTIONS.has(input.action)) {
    return {
      ...base,
      action: "audit",
      messages: ["NHA s.26 / NDPA Audit: Patient health record access logged — mandatory for NHA compliance and NDPC examination"],
      ruleTriggered: "nha_audit_access",
      citations: NHA_RULE_CITATIONS["nha_audit_access"] ?? NHA_CITATIONS,
    };
  }

  return { ...base, action: "allow", messages: [] };
};

// ── NAICOM — Insurance Act 2003 / NAICOM Guidelines 2021/2023 ─────────────────

const AUTO_DENIAL_CAP = 500_000;
const SENIOR_REVIEW_THRESHOLD = 2_000_000;
const LIFE_UNDERWRITING_CAP = 5_000_000;
const INSURANCE_AML_THRESHOLD = 5_000_000;
const FRAUD_SCORE_THRESHOLD = 0.65;

const CLAIM_APPROVAL_ACTIONS = new Set([
  "approve_claim", "settle_claim", "process_claim_payment", "close_claim",
]);
const CLAIM_DENIAL_ACTIONS = new Set([
  "deny_claim", "reject_claim", "decline_claim", "void_claim",
]);
const UNDERWRITING_ACTIONS = new Set([
  "generate_quote", "calculate_premium", "underwrite_policy", "assess_risk",
]);
const POLICY_MODIFICATION_ACTIONS = new Set([
  "cancel_policy", "lapse_policy", "update_policy", "amend_policy_terms",
]);
const FRAUD_INVESTIGATION_ACTIONS = new Set([
  "flag_fraud", "submit_fraud_report", "initiate_fraud_investigation",
]);

const PROHIBITED_CHARACTERISTICS = new Set([
  "religion", "ethnicity", "tribe", "political_affiliation",
  "gender", "disability", "hiv_status",
]);

export const evaluateNAICOM: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "nigeria/naicom",
    regulation: "Insurance Act 2003 / NAICOM Guidelines",
    jurisdiction: "NG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: NAICOM_CITATIONS,
  };

  const humanAdjuster = Boolean(input.context["human_adjuster_assigned"]);
  const seniorApproval = Boolean(input.context["senior_approval"]);
  const humanUnderwriter = Boolean(input.context["human_underwriter"]);
  const claimAmount = Number(input.params["claim_amount"] ?? 0);
  const policyType = String(input.params["policy_type"] ?? "").toLowerCase();
  const underwritingAmount = Number(input.params["underwriting_amount"] ?? 0);
  const fraudScore = Number(input.params["fraud_score"] ?? 0);

  // NAICOM Guideline 15: AI cannot auto-deny claims >= ₦500K without adjuster
  if (CLAIM_DENIAL_ACTIONS.has(input.action) && claimAmount >= AUTO_DENIAL_CAP && !humanAdjuster) {
    return {
      ...base,
      action: "deny",
      messages: [`NAICOM Guideline 15: AI cannot autonomously deny a claim of ₦${claimAmount.toLocaleString()} — a human adjuster must be assigned (human_adjuster_assigned: true)`],
      ruleTriggered: "naicom_auto_denial_cap",
      citations: NAICOM_RULE_CITATIONS["naicom_auto_denial_cap"] ?? NAICOM_CITATIONS,
    };
  }

  // Insurance Act s.67 / NAICOM Rule 6: Prohibited discriminatory characteristics
  for (const field of PROHIBITED_CHARACTERISTICS) {
    if (UNDERWRITING_ACTIONS.has(input.action) && input.params[field] != null) {
      return {
        ...base,
        action: "deny",
        messages: [`Insurance Act s.67 / NAICOM Rule 6: Underwriting or quote uses prohibited discriminatory characteristic '${field}' — remove this field`],
        ruleTriggered: "naicom_discrimination",
        citations: NAICOM_RULE_CITATIONS["naicom_discrimination"] ?? NAICOM_CITATIONS,
      };
    }
  }

  // NAICOM Guideline 18: Life underwriting > ₦5M requires human underwriter
  if (
    UNDERWRITING_ACTIONS.has(input.action) &&
    policyType === "life" &&
    underwritingAmount > LIFE_UNDERWRITING_CAP &&
    !humanUnderwriter
  ) {
    return {
      ...base,
      action: "deny",
      messages: [`NAICOM Guideline 18: Life assurance underwriting of ₦${underwritingAmount.toLocaleString()} exceeds ₦5,000,000 — a licensed human underwriter is required (human_underwriter: true)`],
      ruleTriggered: "naicom_life_underwriting_cap",
      citations: NAICOM_RULE_CITATIONS["naicom_life_underwriting_cap"] ?? NAICOM_CITATIONS,
    };
  }

  // NAICOM Guideline 12: Claims > ₦2M require senior adjuster
  if (CLAIM_APPROVAL_ACTIONS.has(input.action) && claimAmount > SENIOR_REVIEW_THRESHOLD && !seniorApproval) {
    return {
      ...base,
      action: "escalate",
      messages: [`NAICOM Guideline 12: Claim of ₦${claimAmount.toLocaleString()} exceeds ₦2,000,000 — requires senior adjuster review and approval before settlement`],
      ruleTriggered: "naicom_senior_review",
      citations: NAICOM_RULE_CITATIONS["naicom_senior_review"] ?? NAICOM_CITATIONS,
    };
  }

  // NFIU AML: Claim/premium > ₦5M triggers AML reporting
  if (CLAIM_APPROVAL_ACTIONS.has(input.action) && claimAmount > INSURANCE_AML_THRESHOLD) {
    return {
      ...base,
      action: "escalate",
      messages: [`NFIU AML Guidelines: Claim of ₦${claimAmount.toLocaleString()} exceeds ₦5,000,000 AML reporting threshold — file Suspicious Transaction Report if warranted`],
      ruleTriggered: "naicom_aml_threshold",
      citations: NAICOM_RULE_CITATIONS["naicom_aml_threshold"] ?? NAICOM_CITATIONS,
    };
  }

  // NAICOM Rule 11: Fraud investigations require human oversight
  if (FRAUD_INVESTIGATION_ACTIONS.has(input.action)) {
    return {
      ...base,
      action: "escalate",
      messages: ["NAICOM Rule 11: Fraud investigation must be handled by a human investigator — AI may flag but cannot conclude"],
      ruleTriggered: "naicom_fraud_human",
      citations: NAICOM_RULE_CITATIONS["naicom_fraud_human"] ?? NAICOM_CITATIONS,
    };
  }

  // High fraud score — escalate to investigation team
  if (CLAIM_APPROVAL_ACTIONS.has(input.action) && fraudScore > FRAUD_SCORE_THRESHOLD) {
    return {
      ...base,
      action: "escalate",
      messages: [`NAICOM / Anti-Fraud Controls: Claim fraud score ${fraudScore.toFixed(2)} exceeds threshold ${FRAUD_SCORE_THRESHOLD.toFixed(2)} — escalated to fraud investigation team`],
      ruleTriggered: "naicom_fraud_score",
      citations: NAICOM_RULE_CITATIONS["naicom_fraud_score"] ?? NAICOM_CITATIONS,
    };
  }

  // Insurance Act s.50: Policy modifications require customer notification
  if (POLICY_MODIFICATION_ACTIONS.has(input.action)) {
    return {
      ...base,
      action: "escalate",
      messages: ["Insurance Act s.50: Policy modification requires customer notification and human verification before execution"],
      ruleTriggered: "naicom_policy_modification",
      citations: NAICOM_RULE_CITATIONS["naicom_policy_modification"] ?? NAICOM_CITATIONS,
    };
  }

  // Sub-cap denials still need escalation (fair practice)
  if (CLAIM_DENIAL_ACTIONS.has(input.action) && claimAmount < AUTO_DENIAL_CAP) {
    return {
      ...base,
      action: "escalate",
      messages: [`NAICOM Fair Claims Practice: Denial of claim (₦${claimAmount.toLocaleString()}) escalated for human review — customer must be notified with specific grounds`],
      ruleTriggered: "naicom_sub_cap_denial",
      citations: NAICOM_RULE_CITATIONS["naicom_sub_cap_denial"] ?? NAICOM_CITATIONS,
    };
  }

  // Audit all claims decisions
  if (CLAIM_APPROVAL_ACTIONS.has(input.action) || CLAIM_DENIAL_ACTIONS.has(input.action)) {
    return {
      ...base,
      action: "audit",
      messages: ["NAICOM Records: Claims decision logged — mandatory for NAICOM examination and consumer protection records"],
      ruleTriggered: "naicom_audit",
      citations: NAICOM_RULE_CITATIONS["naicom_audit"] ?? NAICOM_CITATIONS,
    };
  }

  if (UNDERWRITING_ACTIONS.has(input.action)) {
    return {
      ...base,
      action: "audit",
      messages: ["NAICOM Records: Underwriting decision logged — required for actuarial review and NAICOM regulatory examination"],
      ruleTriggered: "naicom_audit_underwriting",
      citations: NAICOM_RULE_CITATIONS["naicom_audit_underwriting"] ?? NAICOM_CITATIONS,
    };
  }

  return { ...base, action: "allow", messages: [] };
};

// ── NFIU / MLPPA 2022 ─────────────────────────────────────────────────────────

const CTR_THRESHOLD = 5_000_000;

export const evaluateNfiu: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "nigeria/nfiu-aml",
    regulation: "NFIU/MLPPA 2022",
    jurisdiction: "NG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: NFIU_CITATIONS,
  };

  if (input.action !== "transfer_funds") {
    return { ...base, action: "allow", messages: [] };
  }

  const amount = Number(input.params["amount"] ?? 0);
  const dest = String(input.params["destination_country"] ?? "NG").toUpperCase();
  const structuring = Boolean(input.context["structuring_detected"]);

  // Sanctioned destination
  if (isSanctioned(dest)) {
    return {
      ...base,
      action: "deny",
      messages: [`NFIU/MLPPA 2022: Transfer to sanctioned jurisdiction (${dest}) — blocked per UN/OFAC sanctions`],
      ruleTriggered: "nfiu_sanctions",
      citations: NFIU_RULE_CITATIONS["nfiu_sanctions"] ?? NFIU_CITATIONS,
    };
  }

  // Structuring (just below CTR threshold intentionally)
  if (structuring) {
    return {
      ...base,
      action: "escalate",
      messages: ["NFIU/MLPPA 2022: STR pattern detected — possible structuring below CTR threshold"],
      ruleTriggered: "nfiu_structuring",
      citations: NFIU_RULE_CITATIONS["nfiu_structuring"] ?? NFIU_CITATIONS,
    };
  }

  // CTR threshold
  if (amount >= CTR_THRESHOLD) {
    return {
      ...base,
      action: "escalate",
      messages: [
        `NFIU/MLPPA 2022: Transaction ₦${amount.toLocaleString()} ≥ ₦${CTR_THRESHOLD.toLocaleString()} — Currency Transaction Report required within 24 hours`,
      ],
      ruleTriggered: "nfiu_ctr",
      citations: NFIU_RULE_CITATIONS["nfiu_ctr"] ?? NFIU_CITATIONS,
    };
  }

  return { ...base, action: "allow", messages: [] };
};
