/**
 * comply54-adapter-eve — African regulatory compliance for Vercel Eve agents
 *
 * Provides jurisdiction-specific governance profiles for African data protection
 * and fintech regulatory frameworks, implemented using eve-policy.
 *
 * Quick start:
 *
 *   import { withNamedPolicy } from "eve-policy";
 *   import { nigeriaFintechPolicy } from "comply54-adapter-eve/compose";
 *   import { FileAuditLogger } from "eve-policy/audit";
 *
 *   const safeTool = withNamedPolicy("transfer_funds", transferTool, nigeriaFintechPolicy, {
 *     auditLogger: new FileAuditLogger("/var/log/agent-audit.jsonl"),
 *   });
 *
 * Available profiles (via comply54-adapter-eve/profiles):
 *   ndpaPolicy         — Nigeria Data Protection Act 2023
 *   cbnFintechPolicy   — CBN Digital Finance Policy Framework
 *   kenyaDpaPolicy     — Kenya Data Protection Act 2019
 *   popiaPolicy        — South Africa POPIA 2021
 *   mauritiusDpaPolicy — Mauritius DPA 2017
 *   ghanaDppaPolicy    — Ghana Data Protection Act 2012
 *
 * Pre-composed policies (via comply54-adapter-eve/compose):
 *   africanFintechPolicy     — All jurisdictions + OWASP + Financial Baseline
 *   nigeriaFintechPolicy     — Nigeria (NDPA + CBN) + OWASP + Financial Baseline
 *   eastAfricaFintechPolicy  — Kenya + Mauritius
 *   southernAfricaFintechPolicy — South Africa (POPIA)
 *   westAfricaFintechPolicy  — Nigeria + Ghana
 */

export * from "./profiles/index.js";
export * from "./compose/index.js";
