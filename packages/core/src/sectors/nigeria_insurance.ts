/**
 * NigeriaInsuranceCompliance — TypeScript sector pack.
 *
 * Composes: NAICOM 2021/2023, NDPA 2023, NFIU/MLPPA 2022,
 *           OWASP Universal (PII, injection, tools, approval).
 *
 * Covers AI agents in: claims processing, automated underwriting,
 *                       fraud detection, policy management.
 */

import { Comply54Engine } from "../engine.js";
import { ReceiptSigner } from "../receipts.js";
import { PACK_VERSIONS } from "../packs/versions.js";
import { evaluateNAICOM, evaluateNDPA, evaluateNfiu } from "../packs/nigeria.js";
import {
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
} from "../packs/universal.js";
import type { ComplianceCertificate, ComplianceResult, EvaluationInput } from "../types.js";

const PACKS = [
  evaluateNAICOM,
  evaluateNDPA,
  evaluateNfiu,
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
];

const REGULATIONS = [
  "Insurance Act 2003 (Cap I17 LFN 2004)",
  "NAICOM Operational Guidelines 2021",
  "NAICOM Market Conduct Guidelines 2023",
  "Nigeria Data Protection Act 2023",
  "MLPPA 2022 / NFIU AML Guidelines",
  "OWASP Agentic AI",
];

export class NigeriaInsuranceCompliance {
  readonly name = "Nigeria Insurance Compliance";
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
