/**
 * NigeriaHealthcareCompliance — TypeScript sector pack.
 *
 * Composes: NHA 2014, NDPA 2023 (special-category health data),
 *           BVN/NIN Framework, OWASP Universal (PII, injection, tools, approval).
 *
 * Covers AI agents in: EHR systems, clinical decision support,
 *                       telemedicine platforms, health data analytics.
 */

import { Comply54Engine } from "../engine.js";
import { ReceiptSigner } from "../receipts.js";
import { evaluateNHA, evaluateNDPA, evaluateBvnNin } from "../packs/nigeria.js";
import {
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
} from "../packs/universal.js";
import type { ComplianceCertificate, ComplianceResult, EvaluationInput } from "../types.js";

const PACKS = [
  evaluateNHA,
  evaluateNDPA,
  evaluateBvnNin,
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
];

const REGULATIONS = [
  "Nigeria National Health Act 2014",
  "Nigeria Data Protection Act 2023 (Special-Category Health Data)",
  "Medical and Dental Practitioners Act Cap M8 LFN 2004",
  "FMOH AI in Healthcare Policy Draft 2024",
  "CBN BVN Framework & NIBSS Rules",
  "OWASP Agentic AI",
];

export class NigeriaHealthcareCompliance {
  readonly name = "Nigeria Healthcare Compliance";
  readonly jurisdictions = ["NG"];
  readonly regulations = REGULATIONS;

  private readonly engine: Comply54Engine;
  private readonly signer?: ReceiptSigner;

  constructor(options: { strictMode?: boolean; signingKey?: string } = {}) {
    this.engine = new Comply54Engine(PACKS, options);
    if (options.signingKey) {
      this.signer = new ReceiptSigner(options.signingKey);
    }
  }

  check(
    action: string,
    params?: Record<string, unknown>,
    output?: string,
    context?: Record<string, unknown>
  ): ComplianceResult {
    return this.engine.check(action, params, output, context);
  }

  /** Like `check()` but returns a `Promise<ComplianceResult>` with `receiptToken` populated. */
  async checkSigned(
    action: string,
    params?: Record<string, unknown>,
    output?: string,
    context?: Record<string, unknown>
  ): Promise<ComplianceResult> {
    if (!this.signer) {
      throw new Error("checkSigned() requires signingKey to be set in the constructor");
    }
    const result = this.check(action, params, output, context);
    const token = await this.signer.sign(result, action, params ?? {}, output ?? "", context ?? {});
    return { ...result, receiptToken: token };
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
