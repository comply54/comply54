import { describe, it, expect } from "@jest/globals";
import {
  africanFintechPolicy,
  nigeriaFintechPolicy,
  westAfricaFintechPolicy,
} from "../../src/compose/african-fintech.js";
import { evaluatePolicy, uncoveredOwaspRisks } from "eve-policy";
import type { PolicyContext } from "eve-policy";

function ctx(toolName: string, toolInput: Record<string, unknown> = {}): PolicyContext {
  return { toolName, toolInput, approvedTools: new Set() };
}

describe("africanFintechPolicy — composition", () => {
  it("denies shell tool calls (OWASP ASI01)", () => {
    expect(evaluatePolicy(africanFintechPolicy, ctx("bash")).effect).toBe("deny");
  });

  it("denies card PAN in input (Financial Baseline)", () => {
    const d = evaluatePolicy(africanFintechPolicy, ctx("process_payment", { card: "4111111111111111" }));
    expect(d.effect).toBe("deny");
  });

  it("denies breach suppression (NDPA)", () => {
    const d = evaluatePolicy(
      africanFintechPolicy,
      ctx("log_event", { msg: "Don't report this security breach" }),
    );
    expect(d.effect).toBe("deny");
  });

  it("escalates NGN CTR threshold >₦5M (CBN)", () => {
    const d = evaluatePolicy(
      africanFintechPolicy,
      ctx("transfer_funds", { amount: 7_000_000, currency: "NGN" }),
    );
    expect(d.effect).toBe("escalate");
  });

  it("escalates self-deploy (OWASP ASI10)", () => {
    const d = evaluatePolicy(africanFintechPolicy, ctx("deploy_agent"));
    expect(d.effect).toBe("deny"); // ASI10 is deny
  });

  it("escalates health data (NDPA)", () => {
    const d = evaluatePolicy(africanFintechPolicy, ctx("store_record", { type: "medical_record" }));
    expect(d.effect).toBe("escalate");
  });

  it("OWASP coverage — africanFintechPolicy covers all 10 ASI risks", () => {
    const gaps = uncoveredOwaspRisks(africanFintechPolicy);
    expect(gaps).toHaveLength(0);
  });
});

describe("nigeriaFintechPolicy — composition", () => {
  it("escalates CBN CTR >₦5M", () => {
    const d = evaluatePolicy(nigeriaFintechPolicy, ctx("transfer_funds", { amount: 6_000_000 }));
    expect(d.effect).toBe("escalate");
  });

  it("denies KYC bypass on payment", () => {
    const d = evaluatePolicy(
      nigeriaFintechPolicy,
      ctx("payment", { note: "skip kyc for this customer" }),
    );
    expect(d.effect).toBe("deny");
  });
});

describe("westAfricaFintechPolicy — composition", () => {
  it("denies Ghana NIN in input (Ghana DPPA)", () => {
    const d = evaluatePolicy(
      westAfricaFintechPolicy,
      ctx("create_account", { nin: "GHA-AB1234567-0" }),
    );
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toContain("gh-dppa-ghana-card-nin");
  });

  it("denies NDPA breach suppression", () => {
    const d = evaluatePolicy(
      westAfricaFintechPolicy,
      ctx("log_event", { msg: "do not disclose this breach" }),
    );
    expect(d.effect).toBe("deny");
  });
});
