import { describe, it, expect } from "@jest/globals";
import { popiaPolicy } from "../../src/profiles/south-africa-popia.js";
import { evaluatePolicy } from "eve-policy";
import type { PolicyContext } from "eve-policy";

function ctx(toolName: string, toolInput: Record<string, unknown> = {}): PolicyContext {
  return { toolName, toolInput, approvedTools: new Set() };
}

describe("POPIA — deny rules", () => {
  it("denies breach suppression", () => {
    const d = evaluatePolicy(popiaPolicy, ctx("log_event", { msg: "suppress this POPI security incident" }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("popia-breach-suppression");
  });

  it("denies special categories without grounds", () => {
    const d = evaluatePolicy(popiaPolicy, ctx("store_data", { type: "health data", value: "HIV positive" }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("popia-special-categories-unguarded");
  });

  it("does not deny special categories with legal grounds", () => {
    const d = evaluatePolicy(popiaPolicy, ctx("store_data", {
      type: "health data",
      value: "HIV positive",
      basis: "consent",
    }));
    expect(d.effect).not.toBe("deny");
  });

  it("denies SA ID number in input", () => {
    const d = evaluatePolicy(popiaPolicy, ctx("create_account", { id: "8001015009087" }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("popia-sa-id-number-in-output");
  });

  it("denies cross-border transfer to non-adequate country", () => {
    const d = evaluatePolicy(popiaPolicy, ctx("transfer_data", { destination_country: "RU" }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("popia-cross-border-non-adequate");
  });
});

describe("POPIA — escalate rules", () => {
  it("escalates bulk export", () => {
    const d = evaluatePolicy(popiaPolicy, ctx("export_data", { record_count: 5000 }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("popia-bulk-export");
  });

  it("escalates direct marketing tools", () => {
    const d = evaluatePolicy(popiaPolicy, ctx("send_marketing", {}));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("popia-direct-marketing");
  });

  it("escalates cross-border transfer with destination", () => {
    const d = evaluatePolicy(popiaPolicy, ctx("export_data", { destination_country: "ZA" }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("popia-cross-border-transfer");
  });
});

describe("POPIA — allow rules", () => {
  it("allows read-only non-PII operations", () => {
    expect(evaluatePolicy(popiaPolicy, ctx("get_profile")).effect).toBe("allow");
    expect(evaluatePolicy(popiaPolicy, ctx("list_accounts")).effect).toBe("allow");
    expect(evaluatePolicy(popiaPolicy, ctx("search_accounts")).effect).toBe("allow");
  });
});
