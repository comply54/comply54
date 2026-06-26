/**
 * KenyaFintechCompliance — TypeScript sector pack.
 *
 * Composes: KDPA 2019, OWASP Universal (PII, injection, tools, approval).
 */

import { Comply54Engine } from "../engine.js";
import { evaluateKDPA } from "../packs/africa.js";
import {
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
} from "../packs/universal.js";
import type { ComplianceCertificate, ComplianceResult, EvaluationInput } from "../types.js";

const PACKS = [
  evaluateKDPA,
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
];

const REGULATIONS = [
  "Kenya Data Protection Act 2019",
  "OWASP Agentic AI",
];

export class KenyaFintechCompliance {
  readonly name = "Kenya Fintech Compliance";
  readonly jurisdictions = ["KE"];
  readonly regulations = REGULATIONS;

  private readonly engine: Comply54Engine;

  constructor(options: { strictMode?: boolean } = {}) {
    this.engine = new Comply54Engine(PACKS, options);
  }

  check(
    action: string,
    params?: Record<string, unknown>,
    output?: string,
    context?: Record<string, unknown>
  ): ComplianceResult {
    return this.engine.check(action, params, output, context);
  }

  evaluate(input: EvaluationInput): ComplianceResult {
    return this.engine.evaluate(input);
  }

  async certificate(
    action: string,
    params?: Record<string, unknown>,
    output?: string,
    context?: Record<string, unknown>
  ): Promise<ComplianceCertificate> {
    return this.engine.certificate(
      { action, params, output, context },
      {
        sectorPack: this.name,
        jurisdictions: this.jurisdictions,
        regulations: this.regulations,
      }
    );
  }
}
