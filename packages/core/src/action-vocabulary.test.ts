/**
 * Rules must key on what a request declares, not only on the action's name.
 *
 * Packs previously matched actions against closed sets of exact strings, and an
 * unrecognised name fell through to allow. A caller whose tool was named
 * `approve_insurance_claim` rather than `approve_claim`, or who sent `amount`
 * where the rule read `claim_amount`, got no enforcement and no signal that none
 * had run. Mirrors tests/test_action_vocabulary_fail_open.py so the two SDKs
 * cannot drift apart on this.
 */

import { describe, expect, it } from "vitest";
import { NigeriaInsuranceCompliance } from "./sectors/nigeria_insurance.js";
import { NigeriaFintechCompliance } from "./sectors/nigeria_fintech.js";
import type { ComplianceResult } from "./types.js";

const packsFiring = (r: ComplianceResult) =>
  new Set(r.decisions.filter((d) => d.action !== "allow").map((d) => d.pack));

describe("special-category data (NDPA s.30)", () => {
  it("denies health data logged without consent whatever the tool is called", () => {
    const r = new NigeriaInsuranceCompliance().check(
      "log_caller_health_data",
      { claim_id: "CLM-9920-WEM", conditions: ["HIV", "Type 2 Diabetes"] },
      "",
      { data_category: "health", special_category: true, consent_given: false, hiv_status: true },
    );
    expect(r.blocked).toBe(true);
    expect(packsFiring(r).has("nigeria/ndpa")).toBe(true);
  });

  it.each([
    { special_category: true },
    { contains_phi: true },
    { hiv_status: true },
    { data_category: "health" },
    { data_category: "biometric" },
    { data_category: "genetic" },
  ])("denies on signal %o without consent", (signal) => {
    const r = new NigeriaInsuranceCompliance().check("any_tool_name", {}, "", signal);
    expect(r.blocked).toBe(true);
  });

  it.each(["consent_documented", "consent_provided", "consent_given", "consent_obtained"])(
    "honours consent spelled %s",
    (key) => {
      const r = new NigeriaInsuranceCompliance().check(
        "log_caller_health_data", {}, "", { data_category: "health", [key]: true },
      );
      expect(packsFiring(r).has("nigeria/ndpa")).toBe(false);
    },
  );
});

describe("lawful basis (NDPA s.25)", () => {
  it("denies a declared-null basis with no consent", () => {
    const r = new NigeriaFintechCompliance().check(
      "bulk_export_customer_records", { record_count: 50340 }, "",
      { lawful_basis: null, consent_obtained: false, cross_border: true },
    );
    expect(r.blocked).toBe(true);
    expect(packsFiring(r).has("nigeria/ndpa")).toBe(true);
  });

  it("does not deny when the key is absent entirely", () => {
    const r = new NigeriaFintechCompliance().check("some_read_action", {}, "", {});
    expect(packsFiring(r).has("nigeria/ndpa")).toBe(false);
  });
});

describe("claim action vocabulary (NAICOM)", () => {
  it.each([
    "approve_claim",
    "approve_insurance_claim",
    "authorize_claim",
    "approve_payout",
    "disburse_claim",
  ])("escalates a high-value claim called %s", (action) => {
    const r = new NigeriaInsuranceCompliance().check(
      action, { claim_amount: 15_000_000 }, "", { senior_approval: false },
    );
    expect(r.blocked).toBe(true);
  });

  it.each(["claim_amount", "amount", "payout_amount", "settlement_amount"])(
    "reads the claim value from %s",
    (field) => {
      const r = new NigeriaInsuranceCompliance().check(
        "approve_claim", { [field]: 15_000_000 }, "", { senior_approval: false },
      );
      expect(r.blocked).toBe(true);
    },
  );
});

describe("sanctions screening (MLPPA 2022 s.3)", () => {
  it.each(["transfer_funds", "process_corporate_payment", "send_payment"])(
    "denies an unscreened payment called %s",
    (action) => {
      const r = new NigeriaFintechCompliance().check(
        action, { amount: 12_000_000, currency: "NGN" }, "",
        { sanctions_screened: false, aml_check_performed: false },
      );
      expect(r.blocked).toBe(true);
      expect(packsFiring(r).has("nigeria/nfiu-aml")).toBe(true);
    },
  );

  it("does not deny a screened payment via the screening rule", () => {
    const r = new NigeriaFintechCompliance().check(
      "transfer_funds", { amount: 50_000, currency: "NGN" }, "",
      { sanctions_screened: true, aml_check_performed: true, kyc_verified: true },
    );
    const amlDenials = r.decisions.filter(
      (d) => d.pack === "nigeria/nfiu-aml" && d.action === "deny",
    );
    expect(amlDenials).toEqual([]);
  });
});
