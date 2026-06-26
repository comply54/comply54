/**
 * African jurisdiction pack evaluators (non-Nigerian).
 * Covers: KDPA, POPIA, Ghana DPA, Rwanda DPA, Egypt PDPL,
 *         Ethiopia PDP, Mauritius DPA, Tanzania PDPA, Uganda DPPA.
 */

import { makeAuditId, nowIso, hasAdequacy } from "../utils.js";
import type { EvaluationInput, PackEvaluatorFn, PolicyDecision } from "../types.js";

type Input = Required<EvaluationInput>;

const TRANSFER_ACTIONS = new Set(["send_to_external", "export_data", "store_data", "process_data"]);

/** Generic cross-border evaluator — shared logic across most African DPAs */
function evaluateCrossBorder(
  input: Input,
  pack: string,
  regulation: string,
  jurisdiction: string,
  options: {
    domesticCountry: string;
    biometricRule?: "deny" | "escalate";
    adequatePartners?: Set<string>;
  }
): PolicyDecision {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack,
    regulation,
    jurisdiction,
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
  };

  if (!TRANSFER_ACTIONS.has(input.action)) {
    return { ...base, action: "allow", messages: [] };
  }

  const dest = String(input.params["destination_country"] ?? options.domesticCountry).toUpperCase();
  const dataType = String(input.params["data_type"] ?? "").toLowerCase();
  const consent = Boolean(input.context["consent_documented"]);

  // Domestic — allow
  if (dest === options.domesticCountry) {
    return { ...base, action: "allow", messages: [] };
  }

  // Biometric always deny
  if (dataType === "biometric" || dataType === "health") {
    const biometricAction = options.biometricRule ?? "deny";
    return {
      ...base,
      action: biometricAction,
      messages: [`${regulation}: Biometric/sensitive data cross-border transfer prohibited`],
      ruleTriggered: "biometric_export",
    };
  }

  // Adequate destination
  const isAdequate =
    options.adequatePartners?.has(dest) || hasAdequacy(dest);

  if (isAdequate && consent) {
    return { ...base, action: "allow", messages: [] };
  }
  if (isAdequate && !consent) {
    return {
      ...base,
      action: "escalate",
      messages: [`${regulation}: Cross-border transfer to ${dest} requires consent or adequacy confirmation`],
      ruleTriggered: "cross_border_consent",
    };
  }

  // Non-adequate destination
  if (consent) {
    return {
      ...base,
      action: "escalate",
      messages: [`${regulation}: Transfer to ${dest} — no adequacy. Consent documented but regulator notification required`],
      ruleTriggered: "non_adequate_escalate",
    };
  }

  return {
    ...base,
    action: "deny",
    messages: [`${regulation}: Transfer to ${dest} — no adequacy and no consent. Transfer prohibited`],
    ruleTriggered: "non_adequate_deny",
  };
}

// ── KDPA 2019 (Kenya) ─────────────────────────────────────────────────────────

export const evaluateKDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "kenya/kdpa", "KDPA 2019", "KE", { domesticCountry: "KE" });

// ── POPIA (South Africa) ──────────────────────────────────────────────────────

export const evaluatePOPIA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "south-africa/popia", "POPIA", "ZA", { domesticCountry: "ZA" });

// ── Ghana DPA 2012 ────────────────────────────────────────────────────────────

export const evaluateGhanaDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "ghana/dpa", "Ghana DPA 2012", "GH", { domesticCountry: "GH" });

// ── Rwanda DPA 2021 ───────────────────────────────────────────────────────────

export const evaluateRwandaDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "rwanda/dpa", "Rwanda Law No. 058/2021", "RW", { domesticCountry: "RW" });

// ── Egypt PDPL 2020 ───────────────────────────────────────────────────────────

export const evaluateEgyptPDPL: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "egypt/pdpl",
    regulation: "Egypt PDPL No. 151/2020",
    jurisdiction: "EG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
  };

  if (!TRANSFER_ACTIONS.has(input.action)) {
    return { ...base, action: "allow", messages: [] };
  }

  const dest = String(input.params["destination_country"] ?? input.params["destination_region"] ?? "EG").toUpperCase();
  const dataType = String(input.params["data_type"] ?? "").toLowerCase();

  // Egypt data localisation: financial data must stay in Egypt
  if (dataType === "financial" && dest !== "EG") {
    return {
      ...base,
      action: "deny",
      messages: ["Egypt PDPL No. 151/2020: Financial data must be stored within Egypt (data localisation)"],
      ruleTriggered: "egypt_localisation",
    };
  }

  return evaluateCrossBorder(input, "egypt/pdpl", "Egypt PDPL No. 151/2020", "EG", { domesticCountry: "EG" });
};

// ── Ethiopia PDP 2024 ─────────────────────────────────────────────────────────

export const evaluateEthiopiaPDP: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "ethiopia/pdp", "Ethiopia PDP Proclamation 1321/2024", "ET", { domesticCountry: "ET" });

// ── Mauritius DPA 2017 ────────────────────────────────────────────────────────

export const evaluateMauritiusDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "mauritius/dpa", "Mauritius DPA 2017", "MU", { domesticCountry: "MU" });

// ── Tanzania PDPA 2022 ────────────────────────────────────────────────────────

export const evaluateTanzaniaPDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "tanzania/pdpa", "Tanzania PDPA 2022", "TZ", { domesticCountry: "TZ" });

// ── Uganda DPPA 2019 ──────────────────────────────────────────────────────────

export const evaluateUgandaDPPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "uganda/dppa", "Uganda DPPA 2019", "UG", { domesticCountry: "UG" });
