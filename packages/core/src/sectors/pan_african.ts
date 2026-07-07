/**
 * PanAfricanFintechCompliance — TypeScript sector pack.
 *
 * All 13 African jurisdiction packs + 5 universal packs. 18 total.
 * Supports strict_mode: treats escalate as deny (for maximum enforcement).
 */

import { Comply54Engine } from "../engine.js";
import { ReceiptSigner } from "../receipts.js";
import { PACK_VERSIONS } from "../packs/versions.js";
import { evaluateCBN, evaluateNDPA, evaluateBvnNin, evaluateNfiu } from "../packs/nigeria.js";
import {
  evaluateKDPA,
  evaluatePOPIA,
  evaluateGhanaDPA,
  evaluateRwandaDPA,
  evaluateEgyptPDPL,
  evaluateEthiopiaPDP,
  evaluateMauritiusDPA,
  evaluateTanzaniaPDPA,
  evaluateUgandaDPPA,
} from "../packs/africa.js";
import {
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
  evaluateModelRouting,
} from "../packs/universal.js";
import type { ComplianceCertificate, ComplianceResult, EvaluationInput } from "../types.js";

const PACKS = [
  // Nigeria
  evaluateNDPA,
  evaluateCBN,
  evaluateBvnNin,
  evaluateNfiu,
  // East Africa
  evaluateKDPA,
  evaluateMauritiusDPA,
  evaluateTanzaniaPDPA,
  evaluateUgandaDPPA,
  evaluateRwandaDPA,
  evaluateEthiopiaPDP,
  // Southern / West / North Africa
  evaluatePOPIA,
  evaluateGhanaDPA,
  evaluateEgyptPDPL,
  // Universal
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
  evaluateModelRouting,
];

const REGULATIONS = [
  "NDPA 2023 (Nigeria)",
  "CBN Transaction Controls (Nigeria)",
  "BVN/NIN Protection (Nigeria)",
  "NFIU AML (Nigeria)",
  "KDPA 2019 (Kenya)",
  "POPIA (South Africa)",
  "Ghana DPA 2012",
  "Rwanda DPA 2021",
  "Egypt PDPL 2020",
  "Ethiopia PDP 2024",
  "Mauritius DPA 2017",
  "Tanzania PDPA 2022",
  "Uganda DPPA 2019",
  "OWASP Agentic AI",
];

export class PanAfricanFintechCompliance {
  readonly name = "Pan-African Fintech Compliance";
  readonly jurisdictions = ["NG", "KE", "ZA", "GH", "RW", "EG", "ET", "MU", "TZ", "UG"];
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
