/**
 * Nigerian policy pack evaluators.
 * Covers: NDPA 2023, CBN Transaction Controls, BVN/NIN Framework, NFIU/MLPPA 2022.
 */

import { makeAuditId, nowIso, isSanctioned, hasAdequacy, hasBvn, hasNin } from "../utils.js";
import type { EvaluationInput, PackEvaluatorFn, PolicyDecision } from "../types.js";

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
    };
  }

  // PEP flag
  if (pep) {
    return {
      ...base,
      action: "escalate",
      messages: ["CBN AML/CFT: PEP flag set — transaction requires compliance officer approval"],
      ruleTriggered: "cbn_pep",
    };
  }

  // Non-NGN
  if (currency !== "NGN") {
    return {
      ...base,
      action: "escalate",
      messages: ["CBN FX Policy: Non-NGN transfer requires CBN FX compliance review"],
      ruleTriggered: "cbn_fx",
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
    };
  }

  return {
    ...base,
    action: "deny",
    messages: [
      `NDPA 2023 §25: Transfer to ${dest} — no adequacy and no consent. Transfer prohibited`,
    ],
    ruleTriggered: "ndpa_non_adequate_deny",
  };
};

// ── BVN/NIN Framework ─────────────────────────────────────────────────────────

export const evaluateBvnNin: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "nigeria/bvn-nin",
    regulation: "BVN/NIN Framework",
    jurisdiction: "NG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
  };

  const output = input.output ?? "";

  if (hasBvn(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["BVN/NIN Framework: BVN detected in agent output — must not be exposed in plaintext"],
      ruleTriggered: "bvn_in_output",
    };
  }

  if (hasNin(output)) {
    return {
      ...base,
      action: "deny",
      messages: ["BVN/NIN Framework: NIN detected in agent output — sharing NIN values is prohibited"],
      ruleTriggered: "nin_in_output",
    };
  }

  const dataType = String(input.params["data_type"] ?? "").toLowerCase();
  const dest = String(input.params["destination_country"] ?? "NG").toUpperCase();

  if (dataType === "biometric" && dest !== "NG") {
    return {
      ...base,
      action: "deny",
      messages: ["BVN/NIN Framework: Biometric data export outside Nigeria is prohibited under NIMC Act"],
      ruleTriggered: "biometric_export",
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
    };
  }

  // Structuring (just below CTR threshold intentionally)
  if (structuring) {
    return {
      ...base,
      action: "escalate",
      messages: ["NFIU/MLPPA 2022: STR pattern detected — possible structuring below CTR threshold"],
      ruleTriggered: "nfiu_structuring",
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
    };
  }

  return { ...base, action: "allow", messages: [] };
};
