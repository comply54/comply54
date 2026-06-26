/**
 * Core type definitions for @comply54/core.
 * Mirrors the Python comply54 models exactly.
 */

export type Action = "allow" | "audit" | "escalate" | "deny";

export interface PolicyDecision {
  pack: string;
  regulation: string;
  jurisdiction: string;
  action: Action;
  messages: string[];
  ruleTriggered?: string;
  auditId: string;
  evaluatedAt: string; // ISO 8601
}

export interface ComplianceResult {
  overall: Action;
  decisions: PolicyDecision[];
  auditId: string;
  evaluatedAt: string;
  /** True if overall is "deny" or "escalate" */
  blocked: boolean;
  /** True if overall is "allow" */
  passed: boolean;
  /** Decisions where action !== "allow" */
  violations: PolicyDecision[];
  /** Highest-severity violation, or null */
  primaryViolation: PolicyDecision | null;
}

export interface EvaluationInput {
  action: string;
  params?: Record<string, unknown>;
  output?: string;
  context?: Record<string, unknown>;
}

export interface CertificateViolation {
  pack: string;
  regulation: string;
  jurisdiction: string;
  action: Action;
  messages: string[];
}

export interface ComplianceCertificate {
  certificateId: string;
  issuedAt: string;
  sectorPack: string;
  jurisdictions: string[];
  regulations: string[];
  overall: Action;
  passed: boolean;
  violations: CertificateViolation[];
  packsEvaluated: string[];
  auditId: string;
  integrityHash: string;
  toJSON(): string;
  toObject(): Record<string, unknown>;
}

export type PackEvaluatorFn = (input: Required<EvaluationInput>) => PolicyDecision;
