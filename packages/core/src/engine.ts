/**
 * comply54 evaluation engine (TypeScript).
 *
 * Evaluates a list of pack evaluator functions against an EvaluationInput
 * and returns a ComplianceResult. No OPA binary, no subprocess, no WASM.
 */

import type {
  Action,
  ComplianceCertificate,
  ComplianceResult,
  EvaluationInput,
  PackEvaluatorFn,
  PolicyDecision,
} from "./types.js";
import { buildResult, makeCertificateId, makeAuditId, nowIso } from "./utils.js";

function normaliseInput(input: EvaluationInput): Required<EvaluationInput> {
  return {
    action: input.action,
    params: input.params ?? {},
    output: input.output ?? "",
    context: input.context ?? {},
  };
}

function applyStrictMode(decisions: PolicyDecision[]): PolicyDecision[] {
  return decisions.map((d) => ({
    ...d,
    action: d.action === "escalate" ? ("deny" as Action) : d.action,
  }));
}

async function sha256hex(text: string): Promise<string> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  // Node.js fallback
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(text).digest("hex");
}

export class Comply54Engine {
  private readonly evaluators: PackEvaluatorFn[];
  private readonly strictMode: boolean;

  constructor(evaluators: PackEvaluatorFn[], options: { strictMode?: boolean } = {}) {
    this.evaluators = evaluators;
    this.strictMode = options.strictMode ?? false;
  }

  evaluate(input: EvaluationInput): ComplianceResult {
    const norm = normaliseInput(input);
    let decisions = this.evaluators.map((fn) => fn(norm));

    if (this.strictMode) {
      decisions = applyStrictMode(decisions);
    }

    // Share a single audit ID across all decisions in this evaluation
    const sharedAuditId = makeAuditId();
    decisions = decisions.map((d) => ({ ...d, auditId: sharedAuditId }));

    const result = buildResult(decisions);
    return { ...result, auditId: sharedAuditId };
  }

  check(
    action: string,
    params?: Record<string, unknown>,
    output?: string,
    context?: Record<string, unknown>
  ): ComplianceResult {
    return this.evaluate({ action, params, output, context });
  }

  async certificate(
    input: EvaluationInput,
    options: {
      sectorPack?: string;
      jurisdictions?: string[];
      regulations?: string[];
    } = {}
  ): Promise<ComplianceCertificate> {
    const result = this.evaluate(input);

    const violationsExport = result.violations.map((v) => ({
      pack: v.pack,
      regulation: v.regulation,
      jurisdiction: v.jurisdiction,
      action: v.action,
      messages: v.messages,
    }));

    const hashPayload = JSON.stringify(
      {
        auditId: result.auditId,
        overall: result.overall,
        violations: violationsExport,
        packs: result.decisions.map((d) => d.pack),
      },
      Object.keys({}).sort()
    );
    const integrityHash = await sha256hex(hashPayload);

    const cert: ComplianceCertificate = {
      certificateId: makeCertificateId(),
      issuedAt: result.evaluatedAt,
      sectorPack: options.sectorPack ?? "comply54",
      jurisdictions: options.jurisdictions ?? [],
      regulations: options.regulations ?? [],
      overall: result.overall,
      passed: result.passed,
      violations: violationsExport,
      packsEvaluated: result.decisions.map((d) => d.pack),
      auditId: result.auditId,
      integrityHash,
      toJSON() {
        return JSON.stringify(this.toObject(), null, 2);
      },
      toObject() {
        const { toJSON: _j, toObject: _o, ...rest } = this;
        return rest as Record<string, unknown>;
      },
    };

    return cert;
  }
}
