/**
 * Semantic versions for every comply54 policy pack.
 *
 * These versions track the Rego policy rules, not the comply54 library version:
 *   patch (1.0.x) — bug fix with no behaviour change in normal flows
 *   minor (1.x.0) — new enforcement rule or new blocked case added
 *   major (x.0.0) — breaking regulatory change (new law replaces old)
 *
 * These are embedded in every signed receipt via `c54_pack_versions` so
 * auditors can confirm which version of each regulation was in force at
 * evaluation time.  Update the version here whenever a pack's Rego rules change.
 */
export const PACK_VERSIONS: Record<string, string> = {
  // Nigeria
  "nigeria/ndpa": "1.0.0",
  "nigeria/cbn": "1.0.0",
  "nigeria/bvn-nin": "1.0.0",
  "nigeria/nfiu-aml": "1.1.0", // sanctions_screening_required added (MLPPA 2022 s.6)
  "nigeria/nha": "1.0.0",
  "nigeria/naicom": "1.1.0", // state_of_origin added to prohibited_characteristics (NIIRA 2025 Part V)

  // East Africa
  "kenya/kdpa": "1.0.0",
  "mauritius/dpa": "1.0.0",
  "tanzania/pdpa": "1.0.0",
  "uganda/dppa": "1.0.0",
  "rwanda/dpa": "1.0.0",
  "ethiopia/pdp": "1.0.0",

  // Southern / West / North Africa
  "south-africa/popia": "1.0.0",
  "ghana/dpa": "1.0.0",
  "egypt/pdpl": "1.0.0",

  // Universal
  "universal/pii-leakage": "1.0.0",
  "universal/prompt-injection": "1.0.0",
  "universal/tool-permissions": "1.0.0",
  "universal/human-approval": "1.0.0",
  "universal/model-routing": "1.0.0",
}
