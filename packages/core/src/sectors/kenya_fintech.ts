/**
 * KenyaFintechCompliance — TypeScript sector pack.
 *
 * Composes: KDPA 2019, OWASP Universal (PII, injection, tools, approval).
 */

import { Comply54Engine } from "../engine.js";
import { ReceiptSigner } from "../receipts.js";
import { PACK_VERSIONS } from "../packs/versions.js";
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
    const packVersions = Object.fromEntries(
      result.decisions.map((d) => [d.pack, PACK_VERSIONS[d.pack] ?? "unknown"])
    );
    const token = await this.signer.sign(result, action, params ?? {}, output ?? "", context ?? {}, packVersions);
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
