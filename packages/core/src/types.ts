/**
 * Core type definitions for @comply54/core.
 * Mirrors the Python comply54 models exactly.
 */

export type Action = "allow" | "audit" | "escalate" | "deny";

export interface RegulatorySource {
  /** Official document name or reference (e.g. "CBN Circular FPR/DIR/GEN/CIR/07/003") */
  document: string;
  /** Section, article, or guideline number (e.g. "§4.1", "Guideline 4", "Art. 22") */
  section: string;
  /** Issuing authority (e.g. "CBN", "NDPC", "NAICOM") */
  authority: string;
  /** Year the document was issued or last amended */
  year: number;
  /** Optional URL to the official document text */
  url?: string;
}

export interface PolicyDecision {
  pack: string;
  regulation: string;
  jurisdiction: string;
  action: Action;
  messages: string[];
  /** Regulatory documents and sections this decision traces to */
  citations: RegulatorySource[];
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
  /**
   * Compact Ed25519-signed JWT receipt — present only when `checkSigned()`
   * is called (or when a `ReceiptSigner` is used directly). Pass to
   * `verifyReceipt()` for offline verification.
   */
  receiptToken?: string;
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
  citations: RegulatorySource[];
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
