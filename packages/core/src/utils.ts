import type { Action, ComplianceResult, PolicyDecision } from "./types.js";

const SEVERITY: Record<Action, number> = {
  allow: 0,
  audit: 1,
  escalate: 2,
  deny: 3,
};

export function severityOf(action: Action): number {
  return SEVERITY[action];
}

export function maxAction(a: Action, b: Action): Action {
  return severityOf(a) >= severityOf(b) ? a : b;
}

export function makeAuditId(): string {
  return `aud_${Math.random().toString(36).slice(2, 14)}`;
}

export function makeCertificateId(): string {
  return `cert_${Math.random().toString(36).slice(2, 14)}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function buildResult(decisions: PolicyDecision[]): ComplianceResult {
  let overall: Action = "allow";
  for (const d of decisions) {
    if (severityOf(d.action) > severityOf(overall)) {
      overall = d.action;
    }
  }
  const violations = decisions.filter((d) => d.action !== "allow");
  const blocking = violations.filter((d) => d.action === "deny" || d.action === "escalate");
  const primaryViolation =
    blocking.length > 0
      ? blocking.reduce((a, b) => (severityOf(a.action) >= severityOf(b.action) ? a : b))
      : null;

  return {
    overall,
    decisions,
    auditId: decisions[0]?.auditId ?? makeAuditId(),
    evaluatedAt: decisions[0]?.evaluatedAt ?? nowIso(),
    blocked: overall === "deny" || overall === "escalate",
    passed: overall === "allow",
    violations,
    primaryViolation,
  };
}

/** Detect BVN (11-digit) near a BVN label in text */
export function hasBvn(text: string): boolean {
  return /\bBVN\s*:?\s*\d{11}\b/i.test(text) || /\b\d{11}\b/.test(text) && /BVN/i.test(text);
}

/** Detect NIN (11-digit) near a NIN label in text */
export function hasNin(text: string): boolean {
  return /\bNIN\s*:?\s*\d{11}\b/i.test(text) || /\b\d{11}\b/.test(text) && /NIN/i.test(text);
}

/** Detect payment card numbers (15-16 digits) */
export function hasPan(text: string): boolean {
  return /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/.test(text);
}

/** Detect passport number patterns */
export function hasPassport(text: string): boolean {
  return /\b[A-Z]{1,2}\d{7,9}\b/.test(text);
}

/** Detect KRA PIN (Kenya) */
export function hasKraPin(text: string): boolean {
  return /\bA\d{9}[A-Z]\b/.test(text) && /KRA/i.test(text);
}

const SANCTIONED_COUNTRIES = new Set(["IR", "KP", "SY", "CU", "VE"]);
const AU_ECOWAS_ADEQUACY = new Set([
  "NG", "GH", "SN", "CI", "CM", "ML", "BJ", "TG", "BF",
  "KE", "UG", "TZ", "RW", "ET", "MU", "MG",
  "ZA", "ZW", "ZM", "BW", "NA", "LS", "SZ", "MW", "MZ", "AO",
  "EG", "MA", "TN", "LY", "DZ",
  // EU — adequacy decision
  "DE", "FR", "GB", "IT", "ES", "NL", "SE", "NO", "CH",
]);

export function isSanctioned(country: string): boolean {
  return SANCTIONED_COUNTRIES.has(country.toUpperCase());
}

export function hasAdequacy(country: string): boolean {
  return AU_ECOWAS_ADEQUACY.has(country.toUpperCase());
}
