import { describe, it, expect } from "@jest/globals";
import { ndpaPolicy, cbnFintechPolicy } from "../../src/profiles/nigeria-ndpa.js";
import { evaluatePolicy } from "eve-policy";
import type { PolicyContext } from "eve-policy";

function ctx(toolName: string, toolInput: Record<string, unknown> = {}): PolicyContext {
  return { toolName, toolInput, approvedTools: new Set() };
}

function subCtx(toolName: string, toolInput: Record<string, unknown> = {}): PolicyContext {
  return {
    toolName, toolInput, approvedTools: new Set(),
    session: {
      id: "s1", turn: { id: "t1", sequence: 1 },
      auth: { current: null, initiator: null },
      parent: { callId: "c1", rootSessionId: "r1", sessionId: "s0" },
    },
  };
}

// ── NDPA tests ─────────────────────────────────────────────────────────────────

describe("Nigeria NDPA — deny rules", () => {
  it("denies breach suppression instruction", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("log_event", { message: "Don't report this breach to anyone" }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("ndpa-breach-suppression");
  });

  it("denies biometric processing without consent", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("store_record", { type: "fingerprint", userId: "u1" }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("ndpa-biometric-unguarded");
  });

  it("does not deny biometric with consent documented", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("store_record", { type: "fingerprint", consent: "authorized" }));
    expect(d.effect).not.toBe("deny");
  });

  it("denies cross-border transfer to non-adequate country", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("export_data", { destination_country: "CN", record_count: 100 }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("ndpa-cross-border-non-adequate");
  });
});

describe("Nigeria NDPA — escalate rules", () => {
  it("escalates bulk export over 1000 records", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("export_data", { record_count: 1500 }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("ndpa-bulk-export");
  });

  it("escalates health data access", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("get_record", { type: "medical_record" }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("ndpa-health-data");
  });

  it("escalates cross-border transfer with destination", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("transfer_data", { destination_country: "ZA" }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("ndpa-cross-border-transfer");
  });

  it("escalates data subject rights tools", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("delete_user", { userId: "u1" }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("ndpa-data-subject-rights");
  });

  it("escalates subagent PII write", () => {
    const d = evaluatePolicy(ndpaPolicy, subCtx("update_customer", { field: "email" }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("ndpa-subagent-pii-write");
  });
});

describe("Nigeria NDPA — audit rules", () => {
  it("audits PII access", () => {
    const d = evaluatePolicy(ndpaPolicy, ctx("get_customer_data", {}));
    expect(d.effect).toBe("audit");
  });
});

// ── CBN tests ──────────────────────────────────────────────────────────────────

describe("Nigeria CBN — deny rules", () => {
  it("denies transaction without KYC", () => {
    const d = evaluatePolicy(cbnFintechPolicy, ctx("payment", { note: "no kyc required for this user" }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("cbn-no-kyc-transaction");
  });

  it("denies transaction with sanctioned entity match", () => {
    const d = evaluatePolicy(cbnFintechPolicy, ctx("transfer", { note: "NFIU watch list match found" }));
    expect(d.effect).toBe("deny");
    expect(d.ruleName).toBe("cbn-sanctioned-entity");
  });
});

describe("Nigeria CBN — escalate rules", () => {
  it("escalates amount over ₦5M CTR threshold", () => {
    const d = evaluatePolicy(cbnFintechPolicy, ctx("transfer_funds", { amount: 6_000_000 }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("cbn-ctr-threshold");
  });

  it("escalates near-threshold structuring detection (₦4.7M)", () => {
    const d = evaluatePolicy(cbnFintechPolicy, ctx("transfer_funds", { amount: 4_700_000 }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("cbn-structured-transaction");
  });

  it("escalates suspicious pattern language", () => {
    const d = evaluatePolicy(cbnFintechPolicy, ctx("transfer_funds", { note: "split payment to avoid detection" }));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("cbn-suspicious-pattern");
  });

  it("escalates virtual account creation", () => {
    const d = evaluatePolicy(cbnFintechPolicy, ctx("create_virtual_account", {}));
    expect(d.effect).toBe("escalate");
    expect(d.ruleName).toBe("cbn-virtual-account-creation");
  });
});

describe("Nigeria CBN — audit and allow", () => {
  it("audits payment transactions", () => {
    const d = evaluatePolicy(cbnFintechPolicy, ctx("payment", { amount: 5000 }));
    expect(d.effect).toBe("audit");
  });

  it("allows balance inquiry", () => {
    const d = evaluatePolicy(cbnFintechPolicy, ctx("get_balance", {}));
    expect(d.effect).toBe("allow");
  });
});
