import { compose } from "eve-policy";
import { owaspTop10Policy, financialBaselinePolicy } from "eve-policy/profiles";
import { ndpaPolicy, cbnFintechPolicy } from "../profiles/nigeria-ndpa.js";
import { kenyaDpaPolicy } from "../profiles/kenya-dpa.js";
import { popiaPolicy } from "../profiles/south-africa-popia.js";
import { mauritiusDpaPolicy } from "../profiles/mauritius-dpa.js";
import { ghanaDppaPolicy } from "../profiles/ghana-dppa.js";

/**
 * Comprehensive African Fintech Governance Policy
 *
 * A pre-composed policy combining OWASP Agentic Top 10, financial services
 * baseline, and all supported African regulatory jurisdictions.
 *
 * Use when your agent operates across multiple African markets and you need
 * a single policy that satisfies all jurisdictions simultaneously.
 *
 * Evaluation order (deny-wins across all):
 * 1. OWASP Agentic Top 10 — universal AI security baseline
 * 2. Financial Services Baseline — cross-jurisdiction AML/CTR/sanctions
 * 3. Nigeria NDPA — personal data protection
 * 4. Nigeria CBN — AML/CTR and digital finance
 * 5. Kenya DPA — personal data protection + CBK AML
 * 6. POPIA — South Africa personal data protection
 * 7. Mauritius DPA — data protection + automated decisions
 * 8. Ghana DPPA — personal data protection
 *
 * @example
 * import { withNamedPolicy } from "eve-policy";
 * import { africanFintechPolicy } from "comply54-adapter-eve/compose";
 *
 * const safeTool = withNamedPolicy("transfer_funds", transferTool, africanFintechPolicy, {
 *   auditLogger: new FileAuditLogger("/var/log/agent-audit.jsonl"),
 * });
 */
export const africanFintechPolicy = compose(
  owaspTop10Policy,
  financialBaselinePolicy,
  ndpaPolicy,
  cbnFintechPolicy,
  kenyaDpaPolicy,
  popiaPolicy,
  mauritiusDpaPolicy,
  ghanaDppaPolicy,
);

/**
 * Nigeria-focused fintech policy (OWASP + Financial Baseline + NDPA + CBN).
 * Use for agents that exclusively operate in the Nigerian market.
 */
export const nigeriaFintechPolicy = compose(
  owaspTop10Policy,
  financialBaselinePolicy,
  ndpaPolicy,
  cbnFintechPolicy,
);

/**
 * East Africa fintech policy (Kenya + Mauritius).
 * Suitable for Kenyan and Mauritian market operations.
 */
export const eastAfricaFintechPolicy = compose(
  owaspTop10Policy,
  financialBaselinePolicy,
  kenyaDpaPolicy,
  mauritiusDpaPolicy,
);

/**
 * Southern Africa policy (South Africa POPIA).
 * For agents operating primarily in the SA market.
 */
export const southernAfricaFintechPolicy = compose(
  owaspTop10Policy,
  financialBaselinePolicy,
  popiaPolicy,
);

/**
 * West Africa policy (Nigeria NDPA + Ghana DPPA + CBN).
 * For agents operating across West African markets.
 */
export const westAfricaFintechPolicy = compose(
  owaspTop10Policy,
  financialBaselinePolicy,
  ndpaPolicy,
  cbnFintechPolicy,
  ghanaDppaPolicy,
);
