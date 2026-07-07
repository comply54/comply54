/**
 * comply54 signed compliance receipts — TypeScript/Node.js implementation.
 *
 * Produces the same JWT format as comply54[signing] (Python).
 * Algorithm: Ed25519 (EdDSA). No external dependencies — uses Web Crypto
 * API (Node 20+ / modern browsers) with a node:crypto fallback (Node 18+).
 *
 * CVE-2022-29217 mitigation: the verifier always checks the JWT header `alg`
 * claim and rejects any token that does not use EdDSA before attempting any
 * signature verification.
 */

import type { ComplianceResult } from "./types.js";

/** Current package version — embedded in every receipt. */
export const VERSION = "0.4.1";

// ─── Types ───────────────────────────────────────────────────────────────────

/** Decoded and cryptographically verified payload of a comply54 receipt. */
export interface ReceiptPayload {
  /** Unique receipt ID — matches `ComplianceResult.auditId`. */
  jti: string;
  /** UTC Unix timestamp when the receipt was signed. */
  issuedAt: number;
  /** Always `"comply54"`. */
  issuer: string;
  /** The compliance decision: `"allow"`, `"deny"`, `"escalate"`, or `"audit"`. */
  decision: string;
  /** Primary pack that triggered the decision (`null` for `"allow"`). */
  pack: string | null;
  /** Primary regulation cited (`null` for `"allow"`). */
  regulation: string | null;
  /** Specific rule key that triggered the decision. */
  ruleTriggered: string | null;
  /** Human-readable violation messages (up to 5). */
  messages: string[];
  /**
   * SHA-256 digest of the evaluation input in `sha256:<hex>` format.
   * Recompute with `digestInput()` to prove the receipt covers the exact
   * input under inspection.
   */
  inputDigest: string;
  /** Version of comply54 that produced this receipt. */
  comply54Version: string;
  /** All pack IDs evaluated in this check. */
  packsEvaluated: string[];
  /**
   * Mapping of pack ID → policy pack version at evaluation time.
   *
   * @example
   * { "nigeria/cbn": "1.0.0", "nigeria/nfiu-aml": "1.1.0" }
   *
   * Use this to confirm exactly which version of each regulation was enforced
   * when this receipt was issued. Empty object for pre-v0.4.1 receipts.
   */
  packVersions: Record<string, string>;
}

/** Raised by `verifyReceipt()` when the token fails verification. */
export class InvalidReceiptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidReceiptError";
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Recursively stable JSON — mirrors Python json.dumps(sort_keys=True, separators=(",", ":")) */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const sorted = Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`);
  return `{${sorted.join(",")}}`;
}

function b64urlEncode(data: Buffer | Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

function b64urlEncodeStr(str: string): string {
  return Buffer.from(str, "utf8").toString("base64url");
}

function b64urlDecode(str: string): Buffer {
  return Buffer.from(str, "base64url");
}

/** Strip PEM headers/footers and decode to DER bytes. */
function pemToDer(pem: string): Buffer {
  const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  return Buffer.from(base64, "base64");
}

async function sha256hex(text: string): Promise<string> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnySubtle = any;

function getSubtle(): AnySubtle | undefined {
  if (typeof crypto !== "undefined") {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (crypto as any).subtle;
  }
  return undefined;
}

async function signEd25519(privateKeyPem: string, data: string): Promise<Buffer> {
  const dataBytes = new TextEncoder().encode(data);
  const subtle = getSubtle();

  // Try Web Crypto (Ed25519 stable in Node 20+ / modern browsers)
  if (subtle) {
    try {
      const key = await subtle.importKey("pkcs8", pemToDer(privateKeyPem), { name: "Ed25519" }, false, ["sign"]);
      const sig: ArrayBuffer = await subtle.sign("Ed25519", key, dataBytes);
      return Buffer.from(sig);
    } catch {
      // Fall through to Node crypto (Ed25519 not yet stable in this runtime)
    }
  }

  // Node.js crypto fallback (works from Node 12+)
  const { createSign } = await import("node:crypto");
  const signer = createSign("Ed25519");
  signer.update(data, "utf8");
  return signer.sign(privateKeyPem);
}

async function verifyEd25519(
  publicKeyPem: string,
  data: string,
  signature: Buffer,
): Promise<boolean> {
  const dataBytes = new TextEncoder().encode(data);
  const subtle = getSubtle();

  if (subtle) {
    try {
      const key = await subtle.importKey("spki", pemToDer(publicKeyPem), { name: "Ed25519" }, false, ["verify"]);
      return subtle.verify("Ed25519", key, signature, dataBytes) as Promise<boolean>;
    } catch {
      // Fall through
    }
  }

  const { createVerify } = await import("node:crypto");
  const verifier = createVerify("Ed25519");
  verifier.update(data, "utf8");
  return verifier.verify(publicKeyPem, signature);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Return a deterministic SHA-256 digest of a comply54 evaluation input.
 *
 * The digest is formatted as `sha256:<hex>` and is identical to the Python
 * `digest_input()` function — the same input produces the same digest across
 * both SDKs, so receipts issued by the Python SDK can be confirmed by the TS
 * verifier and vice-versa.
 *
 * @example
 * const digest = await digestInput("transfer_funds", { amount: 5_000_000 });
 * assert(receipt.inputDigest === digest);
 */
export async function digestInput(
  action: string,
  params: Record<string, unknown> = {},
  output = "",
  context: Record<string, unknown> = {},
): Promise<string> {
  const raw = stableStringify({ action, params, output, context });
  const hex = await sha256hex(raw);
  return `sha256:${hex}`;
}

/**
 * Signs a `ComplianceResult` into a compact Ed25519 JWT receipt token.
 *
 * @example
 * const { privateKeyPem, publicKeyPem } = await ReceiptSigner.generateKeypair();
 * const signer = new ReceiptSigner(privateKeyPem);
 *
 * const result = compliance.check("transfer_funds", { amount: 5_000_000 });
 * const token = await signer.sign(result, "transfer_funds", { amount: 5_000_000 });
 *
 * const payload = await verifyReceipt(token, publicKeyPem);
 * console.log(payload.decision); // "escalate"
 */
export class ReceiptSigner {
  private readonly privateKeyPem: string;

  constructor(privateKeyPem: string) {
    if (
      !privateKeyPem.includes("-----BEGIN PRIVATE KEY-----") &&
      !privateKeyPem.includes("-----BEGIN EC PRIVATE KEY-----")
    ) {
      throw new Error(
        "comply54 ReceiptSigner requires a PEM-encoded PKCS#8 private key. " +
          'Use ReceiptSigner.generateKeypair() or openssl genpkey -algorithm Ed25519.',
      );
    }
    this.privateKeyPem = privateKeyPem;
  }

  /**
   * Sign a `ComplianceResult` and return a compact JWT receipt token.
   *
   * @param result  The ComplianceResult to sign.
   * @param action  The action string passed to `check()` / `evaluate()`.
   * @param params  The params dict from the same call.
   * @param output  The output string from the same call.
   * @param context The context dict from the same call.
   */
  async sign(
    result: ComplianceResult,
    action: string,
    params: Record<string, unknown> = {},
    output = "",
    context: Record<string, unknown> = {},
    packVersions: Record<string, string> = {},
  ): Promise<string> {
    const inputDigest = await digestInput(action, params, output, context);
    const pv = result.primaryViolation;
    const iat = Math.floor(new Date(result.evaluatedAt).getTime() / 1000);

    const claims = {
      iss: "comply54",
      iat,
      jti: result.auditId,
      c54_decision: result.overall,
      c54_pack: pv?.pack ?? null,
      c54_regulation: pv?.regulation ?? null,
      c54_rule: pv?.ruleTriggered ?? null,
      c54_messages: pv ? pv.messages.slice(0, 5) : [],
      c54_input_digest: inputDigest,
      c54_version: VERSION,
      c54_packs_evaluated: result.decisions.map((d) => d.pack),
      c54_pack_versions: packVersions,
    };

    const header = b64urlEncodeStr(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
    const payload = b64urlEncodeStr(JSON.stringify(claims));
    const signingInput = `${header}.${payload}`;

    const sigBytes = await signEd25519(this.privateKeyPem, signingInput);
    return `${signingInput}.${b64urlEncode(sigBytes)}`;
  }

  /**
   * Generate a new Ed25519 keypair for comply54 receipt signing.
   *
   * @warning For development and CI only. In production, generate keys inside
   * your secret manager (AWS KMS, HashiCorp Vault, GCP KMS).
   *
   * @returns `{ privateKeyPem, publicKeyPem }` — both PEM-encoded.
   */
  static async generateKeypair(): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
    const subtle = getSubtle();

    // Try Web Crypto (Node 22+ / modern browsers have stable Ed25519 key export)
    if (subtle) {
      try {
        const pair = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
        const privDer: ArrayBuffer = await subtle.exportKey("pkcs8", pair.privateKey);
        const pubDer: ArrayBuffer = await subtle.exportKey("spki", pair.publicKey);
        const wrap = (der: ArrayBuffer, label: string) => {
          const b64 = Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n");
          return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
        };
        return {
          privateKeyPem: wrap(privDer, "PRIVATE KEY"),
          publicKeyPem: wrap(pubDer, "PUBLIC KEY"),
        };
      } catch {
        // Fall through to Node crypto
      }
    }

    const { generateKeyPairSync } = await import("node:crypto");
    const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    return { privateKeyPem: privateKey as string, publicKeyPem: publicKey as string };
  }
}

/**
 * Verify a comply54 signed receipt token and return the decoded payload.
 *
 * Verification is fully offline — no network call. The caller supplies the
 * Ed25519 public key (PEM) that corresponds to the signing key.
 *
 * To confirm the receipt covers the exact input under inspection, recompute
 * the digest with `digestInput()` and compare it to `payload.inputDigest`.
 *
 * @throws `InvalidReceiptError` if the token is invalid, tampered, or does
 * not match the provided public key.
 *
 * @example
 * const payload = await verifyReceipt(result.receiptToken!, publicKeyPem);
 * assert(payload.decision === "deny");
 *
 * const expected = await digestInput("transfer_funds", { amount: 5_000_000 });
 * assert(payload.inputDigest === expected, "Input mismatch");
 */
export async function verifyReceipt(token: string, publicKeyPem: string): Promise<ReceiptPayload> {
  if (!token) throw new InvalidReceiptError("Receipt token is empty");

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new InvalidReceiptError("Receipt token is malformed — expected 3 JWT segments");
  }

  const [headerB64, payloadB64, sigB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;

  // ── Validate header ──────────────────────────────────────────────────────
  let headerObj: Record<string, unknown>;
  try {
    headerObj = JSON.parse(b64urlDecode(headerB64).toString("utf8"));
  } catch {
    throw new InvalidReceiptError("Receipt JWT header is malformed");
  }
  if (headerObj["alg"] !== "EdDSA") {
    // CVE-2022-29217: reject any algorithm other than EdDSA
    throw new InvalidReceiptError(
      `Receipt uses unexpected algorithm: ${String(headerObj["alg"])} — only EdDSA is accepted`,
    );
  }

  // ── Verify signature ─────────────────────────────────────────────────────
  const sigBytes = b64urlDecode(sigB64);
  let valid: boolean;
  try {
    valid = await verifyEd25519(publicKeyPem, signingInput, sigBytes);
  } catch (e) {
    throw new InvalidReceiptError(`Public key is invalid or unsupported: ${e}`);
  }
  if (!valid) {
    throw new InvalidReceiptError(
      "Receipt signature is invalid — token does not match the provided public key",
    );
  }

  // ── Decode claims ────────────────────────────────────────────────────────
  let claims: Record<string, unknown>;
  try {
    claims = JSON.parse(b64urlDecode(payloadB64).toString("utf8"));
  } catch {
    throw new InvalidReceiptError("Receipt JWT payload is malformed");
  }

  if (claims["iss"] !== "comply54") {
    throw new InvalidReceiptError(
      `Receipt issuer must be 'comply54', got: ${String(claims["iss"])}`,
    );
  }

  for (const req of ["jti", "iat", "iss", "c54_decision", "c54_input_digest", "c54_version"]) {
    if (!(req in claims)) {
      throw new InvalidReceiptError(`Receipt is missing required claim: '${req}'`);
    }
  }

  return {
    jti: claims["jti"] as string,
    issuedAt: claims["iat"] as number,
    issuer: claims["iss"] as string,
    decision: claims["c54_decision"] as string,
    pack: (claims["c54_pack"] as string | null) ?? null,
    regulation: (claims["c54_regulation"] as string | null) ?? null,
    ruleTriggered: (claims["c54_rule"] as string | null) ?? null,
    messages: ((claims["c54_messages"] as string[]) ?? []),
    inputDigest: claims["c54_input_digest"] as string,
    comply54Version: claims["c54_version"] as string,
    packsEvaluated: ((claims["c54_packs_evaluated"] as string[]) ?? []),
    packVersions: ((claims["c54_pack_versions"] as Record<string, string>) ?? {}),
  };
}
