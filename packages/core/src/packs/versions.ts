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
  "nigeria/ndpa": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "nigeria/cbn": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "nigeria/bvn-nin": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "nigeria/nfiu-aml": "1.2.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "nigeria/nha": "1.1.0",
  "nigeria/naicom": "1.1.0", // state_of_origin added to prohibited_characteristics (NIIRA 2025 Part V)

  // East Africa
  "kenya/kdpa": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "mauritius/dpa": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "tanzania/pdpa": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "uganda/dppa": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "rwanda/dpa": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "ethiopia/pdp": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)

  // Southern / West / North Africa
  "south-africa/popia": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "ghana/dpa": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)
  "egypt/pdpl": "1.1.0", // regex rules fire under regopy (lowercase rewrite of (?i) patterns)

  // Universal
  "universal/pii-leakage": "1.0.0",
  "universal/prompt-injection": "2.1.0", // whitespace-normalised matching; separators work under regopy
  "universal/tool-permissions": "1.0.0",
  "universal/human-approval": "1.0.0",
  "universal/model-routing": "1.0.0",
  "universal/code-review-agent": "1.2.0",
  "universal/individual-risk-assessment": "1.0.0",
}
