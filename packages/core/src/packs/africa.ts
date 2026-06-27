/**
 * African jurisdiction pack evaluators (non-Nigerian).
 * Covers: KDPA, POPIA, Ghana DPA, Rwanda DPA, Egypt PDPL,
 *         Ethiopia PDP, Mauritius DPA, Tanzania PDPA, Uganda DPPA.
 */

import { makeAuditId, nowIso, hasAdequacy } from "../utils.js";
import type { EvaluationInput, PackEvaluatorFn, PolicyDecision, RegulatorySource } from "../types.js";

type Input = Required<EvaluationInput>;

const TRANSFER_ACTIONS = new Set(["send_to_external", "export_data", "store_data", "process_data"]);

// ── Regulatory citation constants ─────────────────────────────────────────────

const KDPA_CITATIONS: RegulatorySource[] = [
  { document: "Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section: "§25", authority: "ODPC", year: 2019 },
  { document: "Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section: "§46", authority: "ODPC", year: 2019 },
];

const POPIA_CITATIONS: RegulatorySource[] = [
  { document: "Protection of Personal Information Act 4 of 2013 (POPIA)", section: "§11", authority: "Information Regulator ZA", year: 2013 },
  { document: "Protection of Personal Information Act 4 of 2013 (POPIA)", section: "§72", authority: "Information Regulator ZA", year: 2013 },
];

const GHANA_DPA_CITATIONS: RegulatorySource[] = [
  { document: "Ghana Data Protection Act 2012 (Act 843)", section: "§17", authority: "DPC Ghana", year: 2012 },
  { document: "Ghana Data Protection Act 2012 (Act 843)", section: "§33", authority: "DPC Ghana", year: 2012 },
];

const RWANDA_DPA_CITATIONS: RegulatorySource[] = [
  { document: "Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section: "Art. 8", authority: "RISA", year: 2021 },
  { document: "Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section: "Art. 22", authority: "RISA", year: 2021 },
];

const EGYPT_PDPL_CITATIONS: RegulatorySource[] = [
  { document: "Personal Data Protection Law No. 151 of 2020", section: "Art. 3", authority: "PDPRL Egypt", year: 2020 },
  { document: "Personal Data Protection Law No. 151 of 2020", section: "Art. 24", authority: "PDPRL Egypt", year: 2020 },
];

const EGYPT_RULE_CITATIONS: Record<string, RegulatorySource[]> = {
  egypt_localisation: [
    { document: "Personal Data Protection Law No. 151 of 2020", section: "Art. 3 — Data Localisation for Financial Data", authority: "PDPRL Egypt", year: 2020 },
  ],
  biometric_export: [
    { document: "Personal Data Protection Law No. 151 of 2020", section: "Art. 24 — Sensitive Data Cross-Border Ban", authority: "PDPRL Egypt", year: 2020 },
  ],
  cross_border_consent: [
    { document: "Personal Data Protection Law No. 151 of 2020", section: "Art. 3 — Consent", authority: "PDPRL Egypt", year: 2020 },
    { document: "Personal Data Protection Law No. 151 of 2020", section: "Art. 24 — Cross-Border Transfer", authority: "PDPRL Egypt", year: 2020 },
  ],
  non_adequate_escalate: [
    { document: "Personal Data Protection Law No. 151 of 2020", section: "Art. 24 — Cross-Border Safeguards", authority: "PDPRL Egypt", year: 2020 },
  ],
  non_adequate_deny: [
    { document: "Personal Data Protection Law No. 151 of 2020", section: "Art. 24 — Cross-Border Safeguards", authority: "PDPRL Egypt", year: 2020 },
  ],
};

const ETHIOPIA_PDP_CITATIONS: RegulatorySource[] = [
  { document: "Personal Data Protection Proclamation No. 1321/2024", section: "Art. 22", authority: "ECA", year: 2024 },
];

const MAURITIUS_DPA_CITATIONS: RegulatorySource[] = [
  { document: "Data Protection Act 2017 (Act 20 of 2017)", section: "§46", authority: "DPC Mauritius", year: 2017 },
];

const TANZANIA_PDPA_CITATIONS: RegulatorySource[] = [
  { document: "Personal Data Protection Act No. 11 of 2022", section: "§32", authority: "PDPC Tanzania", year: 2022 },
];

const UGANDA_DPPA_CITATIONS: RegulatorySource[] = [
  { document: "Data Protection and Privacy Act 2019 (Act 9 of 2019)", section: "§26", authority: "PDPO Uganda", year: 2019 },
];

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
    citations?: RegulatorySource[];
    ruleCitations?: Record<string, RegulatorySource[]>;
  }
): PolicyDecision {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack,
    regulation,
    jurisdiction,
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: options.citations ?? [],
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
      citations: options.ruleCitations?.["biometric_export"] ?? base.citations,
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
      citations: options.ruleCitations?.["cross_border_consent"] ?? base.citations,
    };
  }

  // Non-adequate destination
  if (consent) {
    return {
      ...base,
      action: "escalate",
      messages: [`${regulation}: Transfer to ${dest} — no adequacy. Consent documented but regulator notification required`],
      ruleTriggered: "non_adequate_escalate",
      citations: options.ruleCitations?.["non_adequate_escalate"] ?? base.citations,
    };
  }

  return {
    ...base,
    action: "deny",
    messages: [`${regulation}: Transfer to ${dest} — no adequacy and no consent. Transfer prohibited`],
    ruleTriggered: "non_adequate_deny",
    citations: options.ruleCitations?.["non_adequate_deny"] ?? base.citations,
  };
}

// ── KDPA 2019 (Kenya) ─────────────────────────────────────────────────────────

export const evaluateKDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "kenya/kdpa", "KDPA 2019", "KE", { domesticCountry: "KE", citations: KDPA_CITATIONS });

// ── POPIA (South Africa) ──────────────────────────────────────────────────────

export const evaluatePOPIA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "south-africa/popia", "POPIA", "ZA", { domesticCountry: "ZA", citations: POPIA_CITATIONS });

// ── Ghana DPA 2012 ────────────────────────────────────────────────────────────

export const evaluateGhanaDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "ghana/dpa", "Ghana DPA 2012", "GH", { domesticCountry: "GH", citations: GHANA_DPA_CITATIONS });

// ── Rwanda DPA 2021 ───────────────────────────────────────────────────────────

export const evaluateRwandaDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "rwanda/dpa", "Rwanda Law No. 058/2021", "RW", { domesticCountry: "RW", citations: RWANDA_DPA_CITATIONS });

// ── Egypt PDPL 2020 ───────────────────────────────────────────────────────────

export const evaluateEgyptPDPL: PackEvaluatorFn = (input: Input): PolicyDecision => {
  const base: Omit<PolicyDecision, "action" | "messages" | "ruleTriggered"> = {
    pack: "egypt/pdpl",
    regulation: "Egypt PDPL No. 151/2020",
    jurisdiction: "EG",
    auditId: makeAuditId(),
    evaluatedAt: nowIso(),
    citations: EGYPT_PDPL_CITATIONS,
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
      citations: EGYPT_RULE_CITATIONS["egypt_localisation"] ?? EGYPT_PDPL_CITATIONS,
    };
  }

  return evaluateCrossBorder(input, "egypt/pdpl", "Egypt PDPL No. 151/2020", "EG", { domesticCountry: "EG", citations: EGYPT_PDPL_CITATIONS, ruleCitations: EGYPT_RULE_CITATIONS });
};

// ── Ethiopia PDP 2024 ─────────────────────────────────────────────────────────

export const evaluateEthiopiaPDP: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "ethiopia/pdp", "Ethiopia PDP Proclamation 1321/2024", "ET", { domesticCountry: "ET", citations: ETHIOPIA_PDP_CITATIONS });

// ── Mauritius DPA 2017 ────────────────────────────────────────────────────────

export const evaluateMauritiusDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "mauritius/dpa", "Mauritius DPA 2017", "MU", { domesticCountry: "MU", citations: MAURITIUS_DPA_CITATIONS });

// ── Tanzania PDPA 2022 ────────────────────────────────────────────────────────

export const evaluateTanzaniaPDPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "tanzania/pdpa", "Tanzania PDPA 2022", "TZ", { domesticCountry: "TZ", citations: TANZANIA_PDPA_CITATIONS });

// ── Uganda DPPA 2019 ──────────────────────────────────────────────────────────

export const evaluateUgandaDPPA: PackEvaluatorFn = (input: Input): PolicyDecision =>
  evaluateCrossBorder(input, "uganda/dppa", "Uganda DPPA 2019", "UG", { domesticCountry: "UG", citations: UGANDA_DPPA_CITATIONS });
