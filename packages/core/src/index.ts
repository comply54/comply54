/**
 * @comply54/core
 *
 * African AI governance compliance — enforcement engine and sector packs
 * for NDPA, CBN, KDPA, POPIA and 15+ African regulatory frameworks.
 *
 * Usage:
 *   import { NigeriaFintechCompliance } from "@comply54/core";
 *
 *   const compliance = new NigeriaFintechCompliance();
 *   const result = compliance.check("transfer_funds", { amount: 15_000_000, currency: "NGN" });
 *   if (result.blocked) throw new Error(result.primaryViolation?.messages[0]);
 */

// Types
export type {
  Action,
  RegulatorySource,
  PolicyDecision,
  ComplianceResult,
  ComplianceCertificate,
  CertificateViolation,
  EvaluationInput,
  PackEvaluatorFn,
} from "./types.js";

// Signed receipts
export {
  ReceiptSigner,
  verifyReceipt,
  digestInput,
  InvalidReceiptError,
  VERSION,
} from "./receipts.js";
export type { ReceiptPayload } from "./receipts.js";

// Engine
export { Comply54Engine } from "./engine.js";

// Sector packs (recommended entry point)
export { NigeriaFintechCompliance } from "./sectors/nigeria_fintech.js";
export { NigeriaHealthcareCompliance } from "./sectors/nigeria_health.js";
export { NigeriaInsuranceCompliance } from "./sectors/nigeria_insurance.js";
export { KenyaFintechCompliance } from "./sectors/kenya_fintech.js";
export { PanAfricanFintechCompliance } from "./sectors/pan_african.js";

// Nigerian pack evaluators
export {
  evaluateCBN,
  evaluateNDPA,
  evaluateBvnNin,
  evaluateNfiu,
  evaluateNHA,
  evaluateNAICOM,
} from "./packs/nigeria.js";

// African jurisdiction pack evaluators
export {
  evaluateKDPA,
  evaluatePOPIA,
  evaluateGhanaDPA,
  evaluateRwandaDPA,
  evaluateEgyptPDPL,
  evaluateEthiopiaPDP,
  evaluateMauritiusDPA,
  evaluateTanzaniaPDPA,
  evaluateUgandaDPPA,
} from "./packs/africa.js";

// Universal pack evaluators
export {
  evaluatePiiLeakage,
  evaluatePromptInjection,
  evaluateToolPermissions,
  evaluateHumanApproval,
  evaluateModelRouting,
} from "./packs/universal.js";
