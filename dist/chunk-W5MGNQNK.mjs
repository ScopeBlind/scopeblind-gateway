import {
  receiptHash
} from "./chunk-6JTYFG2X.mjs";

// src/egress-guard.ts
import { createHash, createHmac } from "crypto";
var EGRESS_SUMMARY_TYPE = "scopeblind.egress_summary.v1";
var EGRESS_SUMMARY_VERSION = 1;
var EGRESS_SUMMARY_FIELDS = /* @__PURE__ */ new Set([
  "type",
  "version",
  "source_receipt_commitment",
  "request_pseudonym",
  "decision",
  "reason_code",
  "tool_category",
  "policy_commitment",
  "mode",
  "action_commitment",
  "output_commitment",
  "disclosed_field_count",
  "deny_iteration"
]);
var EGRESS_SIGNED_PAYLOAD_FIELDS = /* @__PURE__ */ new Set([
  ...EGRESS_SUMMARY_FIELDS,
  "public_key",
  "issuer_id",
  "issued_at"
]);
var EGRESS_ALLOWED_PAYLOAD_FIELDS = EGRESS_SIGNED_PAYLOAD_FIELDS;
var KNOWN_RECEIPT_TYPES = /* @__PURE__ */ new Set(["protectmcp:decision", "protectmcp:artifact", "scopeblind.coverage_statement.v1"]);
var DECISIONS = /* @__PURE__ */ new Set(["allow", "deny", "approve"]);
var MODES = /* @__PURE__ */ new Set(["enforce", "shadow", "audit"]);
var REASON_CODES = /* @__PURE__ */ new Set([
  "cedar_allow",
  "cedar_deny",
  "policy_allow",
  "policy_deny",
  "policy_head_mismatch",
  "mandate_expired",
  "mandate_missing",
  "mandate_denied",
  "approval_required",
  "approval_denied",
  "signing_error",
  "rate_limited",
  "other"
]);
function str(v) {
  return typeof v === "string" && v.length ? v : void 0;
}
function integer(v) {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : void 0;
}
function hmacCommitment(domain, value, opts) {
  return `hmac-sha256:${createHmac("sha256", opts.pseudonymKey).update(`${domain}\0${opts.tenantScope || ""}\0${String(value ?? "")}`).digest("hex")}`;
}
function isReceiptCommitment(value) {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
}
function isPseudonym(value) {
  return typeof value === "string" && /^hmac-sha256:[0-9a-f]{64}$/.test(value);
}
function isPublicKey(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
function isIssuedAt(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function code(value) {
  const leading = (str(value) || "").split(/[\s:]/)[0].toLowerCase().slice(0, 64);
  return REASON_CODES.has(leading) ? leading : "other";
}
function category(tool) {
  const value = (str(tool) || "").toLowerCase();
  if (/(email|mail|slack|teams|message)/.test(value)) return "communication";
  if (/(github|git|commit|pull_request)/.test(value)) return "source_control";
  if (/(file|bash|shell|terminal|directory)/.test(value)) return "filesystem";
  if (/(sql|database|query)/.test(value)) return "database";
  if (/(aws|gcp|azure|cloud|deploy)/.test(value)) return "cloud";
  if (/(browser|web|fetch|http)/.test(value)) return "browser";
  if (/(trade|order|pms|broker|position)/.test(value)) return "finance";
  return "other";
}
function toEgressSummary(envelope, opts) {
  if (!opts?.pseudonymKey || typeof opts.pseudonymKey === "string" && !opts.pseudonymKey.length || opts.pseudonymKey instanceof Uint8Array && !opts.pseudonymKey.length) return null;
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) return null;
  const env = envelope;
  const p = env.payload;
  if (!p || typeof p !== "object" || typeof p.type !== "string" || !KNOWN_RECEIPT_TYPES.has(p.type)) return null;
  const ar = p.action_readback;
  const pd = p.payload_digest;
  const disclosed = ar && Array.isArray(ar.disclosed_fields) ? ar.disclosed_fields.length : void 0;
  const rawDecision = str(p.decision);
  const summary = {
    type: EGRESS_SUMMARY_TYPE,
    version: EGRESS_SUMMARY_VERSION,
    source_receipt_commitment: `sha256:${receiptHash(envelope)}`,
    request_pseudonym: hmacCommitment("scopeblind.egress.request.v1", p.request_id || p.scope || "", opts),
    decision: rawDecision && DECISIONS.has(rawDecision) ? rawDecision : "other",
    reason_code: code(p.reason),
    tool_category: category(p.tool_name),
    policy_commitment: hmacCommitment("scopeblind.egress.policy.v1", p.policy_digest || "", opts),
    mode: str(p.mode) && MODES.has(str(p.mode)) ? str(p.mode) : "other",
    ...ar && str(ar.payload_hash) ? { action_commitment: hmacCommitment("scopeblind.egress.action.v1", ar.payload_hash, opts) } : {},
    ...pd && str(pd.output_hash) ? { output_commitment: hmacCommitment("scopeblind.egress.output.v1", pd.output_hash, opts) } : {},
    ...disclosed !== void 0 ? { disclosed_field_count: disclosed } : {},
    ...integer(p.deny_iteration) !== void 0 ? { deny_iteration: integer(p.deny_iteration) } : {}
  };
  return summary;
}
function inspectEgress(obj, opts = {}) {
  const violations = [];
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return { safe: false, violations: [{ path: "$", reason: "not an egress summary object" }] };
  const o = obj;
  const allowed = opts.signed ? EGRESS_SIGNED_PAYLOAD_FIELDS : EGRESS_SUMMARY_FIELDS;
  for (const [key, value] of Object.entries(o)) {
    if (!allowed.has(key)) {
      violations.push({ path: `$.${key}`, reason: "field is not allowed in an egress summary" });
      continue;
    }
    if (value === null || value === void 0) {
      violations.push({ path: `$.${key}`, reason: "null and undefined are not permitted" });
      continue;
    }
    if (typeof value === "object") violations.push({ path: `$.${key}`, reason: "nested objects and arrays are not permitted" });
  }
  if (o.type !== EGRESS_SUMMARY_TYPE) violations.push({ path: "$.type", reason: "wrong egress summary type" });
  if (o.version !== EGRESS_SUMMARY_VERSION) violations.push({ path: "$.version", reason: "unsupported egress summary version" });
  if (!isReceiptCommitment(o.source_receipt_commitment)) violations.push({ path: "$.source_receipt_commitment", reason: "must be a sha256 receipt commitment" });
  for (const field of ["request_pseudonym", "policy_commitment"]) if (!isPseudonym(o[field])) violations.push({ path: `$.${field}`, reason: "must be a local hmac-sha256 pseudonym" });
  for (const field of ["action_commitment", "output_commitment"]) if (o[field] !== void 0 && !isPseudonym(o[field])) violations.push({ path: `$.${field}`, reason: "must be a local hmac-sha256 pseudonym" });
  if (!["allow", "deny", "approve", "other"].includes(String(o.decision))) violations.push({ path: "$.decision", reason: "invalid decision enum" });
  if (!REASON_CODES.has(String(o.reason_code))) violations.push({ path: "$.reason_code", reason: "invalid reason code enum" });
  if (!["communication", "source_control", "filesystem", "database", "cloud", "browser", "finance", "other"].includes(String(o.tool_category))) violations.push({ path: "$.tool_category", reason: "invalid tool category enum" });
  if (!["enforce", "shadow", "audit", "other"].includes(String(o.mode))) violations.push({ path: "$.mode", reason: "invalid mode enum" });
  for (const field of ["disclosed_field_count", "deny_iteration"]) if (o[field] !== void 0 && (!Number.isSafeInteger(o[field]) || Number(o[field]) < 0 || Number(o[field]) > 1e6)) violations.push({ path: `$.${field}`, reason: "must be a bounded non-negative integer" });
  if (opts.signed) {
    if (!isPublicKey(o.public_key)) violations.push({ path: "$.public_key", reason: "must be a 32-byte Ed25519 public key" });
    if (typeof o.issuer_id !== "string" || !/^[\x21-\x7e]{1,160}$/.test(o.issuer_id)) violations.push({ path: "$.issuer_id", reason: "must be a compact issuer id" });
    if (!isIssuedAt(o.issued_at)) violations.push({ path: "$.issued_at", reason: "must be an ISO timestamp" });
  }
  return { safe: violations.length === 0, violations };
}
function assertEgressSafe(summary, opts = {}) {
  const check = inspectEgress(summary, opts);
  if (!check.safe) throw new Error(`egress guard blocked a forward: ${check.violations.slice(0, 3).map((v) => `${v.path} (${v.reason})`).join("; ")}`);
}
function runEgressSelfCheck(sampleReceipts, now) {
  const opts = { pseudonymKey: "scopeblind-egress-self-check-v1" };
  const summaries = sampleReceipts.map((r) => toEgressSummary(r, opts)).filter((s) => s !== null);
  const allSafe = summaries.every((s) => inspectEgress(s).safe);
  const dirty = {
    payload: {
      type: "protectmcp:decision",
      tool_name: "send_email",
      decision: "allow",
      request_id: "ceo@victim.com",
      policy_digest: "strategy-mean-reversion",
      action_readback: { destination: "ceo@victim.com", payload_preview: { body: "we miss earnings by 40%, sell before the print" }, payload_hash: "deadbeef", disclosed_fields: ["to", "subject", "body"] },
      payload_digest: { preview: "positions AAPL 50000 shares", output_hash: "cafe" },
      privateKey: "deadbeef".repeat(8)
    },
    signature: { alg: "EdDSA", kid: "k", sig: "y" }
  };
  const dirtySummary = toEgressSummary(dirty, opts);
  const blob = JSON.stringify(dirtySummary);
  const deny = { payload: { type: "protectmcp:decision", tool_name: "Bash", decision: "deny", reason: 'cedar_deny: {"reason":["policy0"]}', request_id: "d1", policy_digest: "p" }, signature: { alg: "EdDSA", kid: "k", sig: "y" } };
  const denySummary = toEgressSummary(deny, opts);
  return {
    type: "scopeblind.egress_self_check.v1",
    generated_at: now,
    summary_fields: [...EGRESS_SUMMARY_FIELDS].sort(),
    samples_checked: summaries.length,
    all_summaries_safe: allSafe,
    raw_content_dropped: inspectEgress(dirtySummary).safe && !blob.includes("ceo@victim.com") && !blob.includes("earnings") && !blob.includes("positions") && !blob.includes("40%"),
    private_key_dropped: !blob.includes("deadbeef".repeat(8)),
    deny_receipt_forwardable: Boolean(denySummary && inspectEgress(denySummary).safe && denySummary.decision === "deny" && denySummary.reason_code === "cedar_deny"),
    statement: "The hosted layer receives a signed, fixed-schema summary of enums, a receipt hash, and local HMAC pseudonyms only. Request ids, policy references, action hashes, and output hashes cannot be dictionary-checked without the local key; raw prompts, payloads, outputs, recipients, positions, amounts, and private keys remain local."
  };
}

export {
  EGRESS_SUMMARY_TYPE,
  EGRESS_SUMMARY_VERSION,
  EGRESS_SUMMARY_FIELDS,
  EGRESS_SIGNED_PAYLOAD_FIELDS,
  EGRESS_ALLOWED_PAYLOAD_FIELDS,
  toEgressSummary,
  inspectEgress,
  assertEgressSafe,
  runEgressSelfCheck
};
