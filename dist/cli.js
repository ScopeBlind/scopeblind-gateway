#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/coordination-protocol.ts
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex5) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(hex5)) throw new Error("Invalid hexadecimal data");
  return Uint8Array.from(hex5.match(/../g).map((x) => parseInt(x, 16)));
}
function validUnicode(value) {
  for (let i = 0; i < value.length; i++) {
    const c2 = value.charCodeAt(i);
    if (c2 >= 55296 && c2 <= 56319) {
      const n = value.charCodeAt(++i);
      if (!(n >= 56320 && n <= 57343)) return false;
    } else if (c2 >= 56320 && c2 <= 57343) return false;
  }
  return true;
}
function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "string") {
    if (!validUnicode(value)) throw new Error("Invalid Unicode");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) if (!Object.hasOwn(value, i)) throw new Error("Sparse arrays are not JSON");
    return "[" + value.map(canonical).join(",") + "]";
  }
  if (typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new Error("Expected a plain JSON object");
    const object4 = value;
    return "{" + Object.keys(object4).sort().map((k) => canonical(k) + ":" + canonical(object4[k])).join(",") + "}";
  }
  throw new Error("Not a JSON value");
}
async function sha256(value) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}
async function payloadHash(input) {
  return sha256(canonical(input));
}
async function importIdentity(pkcs8Hex, publicKey) {
  if (!/^[0-9a-f]{64}$/.test(publicKey)) throw new Error("Invalid public key");
  const privateKey = await crypto.subtle.importKey("pkcs8", hexToBytes(pkcs8Hex), { name: "Ed25519" }, false, ["sign"]);
  const identity = { publicKey, privateKey };
  const check = await sign({ type: "scopeblind.coordination.key-check.v1" }, identity);
  if (!await verify(check, publicKey)) throw new Error("Signing key does not match authority key");
  return identity;
}
async function sign(payload, identity) {
  const preimage = COORDINATION_DOMAIN + canonical(payload);
  const signature = await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(preimage));
  const envelope3 = { payload, signer: identity.publicKey, digest: await sha256(preimage), signature: bytesToHex(new Uint8Array(signature)) };
  if (identity.deviceAuthorization) {
    envelope3.authorization = identity.deviceAuthorization;
    const binding = "scopeblind.coordination.device-authorization.v1\n" + envelope3.digest + "\n" + identity.deviceAuthorization.digest;
    envelope3.authorization_signature = bytesToHex(new Uint8Array(await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(binding))));
  }
  return envelope3;
}
async function verify(envelope3, expectedSigner) {
  try {
    if (!envelope3 || !/^[0-9a-f]{64}$/.test(envelope3.signer) || !/^[0-9a-f]{64}$/.test(envelope3.digest) || !/^[0-9a-f]{128}$/.test(envelope3.signature)) return false;
    if (expectedSigner && expectedSigner !== envelope3.signer) return false;
    const preimage = COORDINATION_DOMAIN + canonical(envelope3.payload);
    if (await sha256(preimage) !== envelope3.digest) return false;
    const key = await crypto.subtle.importKey("raw", hexToBytes(envelope3.signer), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, hexToBytes(envelope3.signature), new TextEncoder().encode(preimage));
  } catch {
    return false;
  }
}
function makeRequest(action, room_id, body) {
  return { type: "scopeblind.coordination.request.v1", action, room_id, body, issued_at: (/* @__PURE__ */ new Date()).toISOString(), nonce: crypto.randomUUID() };
}
var COORDINATION_DOMAIN;
var init_coordination_protocol = __esm({
  "src/coordination-protocol.ts"() {
    "use strict";
    COORDINATION_DOMAIN = "scopeblind.coordination.v1\n";
  }
});

// src/acta-envelope.ts
function canonicalize(obj) {
  if (Array.isArray(obj)) return "[" + Array.from(obj, canonicalize).join(",") + "]";
  if (obj !== null && typeof obj === "object") {
    if (Object.getPrototypeOf(obj) !== Object.prototype && Object.getPrototypeOf(obj) !== null) throw new Error("Expected a plain JSON object");
    const record = obj;
    return "{" + Object.keys(record).sort().map((key) => {
      if (!/^[\x20-\x7E]*$/.test(key)) throw new Error(`Non-ASCII key "${key}" in receipt payload. Only ASCII keys are permitted.`);
      return JSON.stringify(key) + ":" + canonicalize(record[key]);
    }).join(",") + "}";
  }
  return canonical(obj);
}
function legacyCanonicalize(obj) {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const sorted = {};
      for (const k of Object.keys(value).sort()) {
        if (!/^[\x20-\x7E]*$/.test(k)) {
          throw new Error(`Non-ASCII key "${k}" in receipt payload. Only ASCII keys are permitted.`);
        }
        sorted[k] = value[k];
      }
      return sorted;
    }
    return value;
  });
}
function hasLegacyUnsafeKey(value) {
  if (!value || typeof value !== "object") return false;
  if (Object.prototype.hasOwnProperty.call(value, "__proto__")) return true;
  return Object.values(value).some(hasLegacyUnsafeKey);
}
function verifyEncoding(payload, envelope3, signature, publicKeyHex, shape3, allowLegacy) {
  const jcs2 = canonicalize(payload);
  if (import_ed25519.ed25519.verify((0, import_utils.hexToBytes)(signature), (0, import_utils.utf8ToBytes)(jcs2), (0, import_utils.hexToBytes)(publicKeyHex))) {
    return { valid: true, shape: shape3, hash: receiptHash(envelope3), canonicalization: "jcs" };
  }
  if (!hasLegacyUnsafeKey(envelope3)) {
    const legacy = legacyCanonicalize(payload);
    if (legacy !== jcs2 && import_ed25519.ed25519.verify((0, import_utils.hexToBytes)(signature), (0, import_utils.utf8ToBytes)(legacy), (0, import_utils.hexToBytes)(publicKeyHex))) {
      const legacyHash = (0, import_utils.bytesToHex)((0, import_sha256.sha256)((0, import_utils.utf8ToBytes)(legacyCanonicalize(envelope3))));
      return {
        valid: allowLegacy,
        shape: shape3,
        canonicalization: "legacy-numeric-key-order",
        legacy_signature_valid: true,
        legacy_hash: legacyHash,
        ...allowLegacy ? { hash: legacyHash } : { error: "legacy_non_jcs_signature" },
        warning: "Historical signature verifies only with pre-fix integer-key ordering. This is not JCS-conformant; preserve its original bytes and chain hashes."
      };
    }
  }
  return { valid: false, shape: shape3, error: "invalid_signature" };
}
function receiptHash(obj) {
  return (0, import_utils.bytesToHex)((0, import_sha256.sha256)((0, import_utils.utf8ToBytes)(canonicalize(obj))));
}
function chainLink(receipt) {
  return "sha256:" + receiptHash(receipt);
}
function base58(bytes) {
  let n = BigInt("0x" + (0, import_utils.bytesToHex)(bytes));
  let out2 = "";
  while (n > 0n) {
    out2 = B58_ALPHABET[Number(n % 58n)] + out2;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out2 = "1" + out2;
    else break;
  }
  return out2;
}
function computeSbIssuerKid(publicKeyHex) {
  return `sb:issuer:${base58((0, import_utils.hexToBytes)(publicKeyHex)).slice(0, 12)}`;
}
function createReceiptEnvelope(fields, privateKeyHex, kid, issuedAt) {
  if (!fields.type) throw new Error("receipt payload requires a type");
  if (!kid) throw new Error("kid is required");
  const payload = {
    ...fields,
    issued_at: fields.issued_at || issuedAt || (/* @__PURE__ */ new Date()).toISOString(),
    issuer_id: kid
  };
  const sig = (0, import_utils.bytesToHex)(import_ed25519.ed25519.sign((0, import_utils.utf8ToBytes)(canonicalize(payload)), (0, import_utils.hexToBytes)(privateKeyHex)));
  const envelope3 = { payload, signature: { alg: "EdDSA", kid, sig } };
  return { envelope: envelope3, hash: receiptHash(envelope3) };
}
function verifyReceipt(envelope3, publicKeyHex, options2 = {}) {
  try {
    if (!envelope3 || typeof envelope3 !== "object") {
      return { valid: false, shape: null, error: "not_an_object" };
    }
    const env = envelope3;
    const signature = env.signature;
    if (signature && typeof signature === "object" && !Array.isArray(signature)) {
      const sigObj = signature;
      if (sigObj.alg !== "EdDSA") {
        return { valid: false, shape: "acta-02", error: `unsupported_alg:${String(sigObj.alg)}` };
      }
      if (typeof sigObj.sig !== "string" || !env.payload || typeof env.payload !== "object") {
        return { valid: false, shape: "acta-02", error: "malformed_envelope" };
      }
      return verifyEncoding(env.payload, env, sigObj.sig, publicKeyHex, "acta-02", options2.allowLegacyNumericKeys === true);
    }
    if (typeof signature === "string") {
      const rest = /* @__PURE__ */ Object.create(null);
      for (const k of Object.keys(env)) if (k !== "signature") rest[k] = env[k];
      const shape3 = env.v === 2 ? "legacy-v2" : "legacy-v1";
      return verifyEncoding(rest, env, signature, publicKeyHex, shape3, options2.allowLegacyNumericKeys === true);
    }
    return { valid: false, shape: null, error: "missing_signature" };
  } catch (err) {
    return {
      valid: false,
      shape: null,
      error: `verification_error:${err instanceof Error ? err.message : "unknown"}`
    };
  }
}
function receiptIdentity(envelope3) {
  if (!envelope3 || typeof envelope3 !== "object") return { kid: null, issuer: null, type: null };
  const env = envelope3;
  if (env.signature && typeof env.signature === "object") {
    const payload = env.payload || {};
    const sig = env.signature;
    return {
      kid: typeof sig.kid === "string" ? sig.kid : null,
      issuer: typeof payload.issuer_id === "string" ? payload.issuer_id : typeof payload.issuer_name === "string" ? payload.issuer_name : null,
      type: typeof payload.type === "string" ? payload.type : null
    };
  }
  return {
    kid: typeof env.kid === "string" ? env.kid : null,
    issuer: typeof env.issuer === "string" ? env.issuer : null,
    type: typeof env.type === "string" ? env.type : null
  };
}
var import_ed25519, import_sha256, import_utils, B58_ALPHABET;
var init_acta_envelope = __esm({
  "src/acta-envelope.ts"() {
    "use strict";
    import_ed25519 = require("@noble/curves/ed25519");
    import_sha256 = require("@noble/hashes/sha256");
    import_utils = require("@noble/hashes/utils");
    init_coordination_protocol();
    B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  }
});

// src/policy-digest.ts
function digestPolicyFiles(engine, files) {
  if (files.length === 0) throw new Error("policy digest requires at least one file");
  const names = /* @__PURE__ */ new Set();
  for (const f of files) {
    if (!f.name) throw new Error("policy file entries require a name");
    if (names.has(f.name)) throw new Error(`duplicate policy file name: ${f.name}`);
    names.add(f.name);
  }
  const entries = files.map((f) => ({ name: f.name, sha256: sha256hex(Buffer.from(f.content, "utf-8")) })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  const manifest = { construction: POLICY_DIGEST_CONSTRUCTION, engine, files: entries };
  return {
    policy_digest: `sha256:${sha256hex(Buffer.from(canonicalize(manifest), "utf-8"))}`,
    construction: POLICY_DIGEST_CONSTRUCTION,
    engine,
    files: entries
  };
}
function digestCedarDir(dirPath) {
  if (!(0, import_node_fs.existsSync)(dirPath)) throw new Error(`Cedar policy directory not found: ${dirPath}`);
  const names = (0, import_node_fs.readdirSync)(dirPath).filter((f) => (0, import_node_path.extname)(f) === ".cedar").sort();
  if (names.length === 0) throw new Error(`No .cedar files found in: ${dirPath}`);
  const files = names.map((name) => ({ name, content: (0, import_node_fs.readFileSync)((0, import_node_path.join)(dirPath, name), "utf-8") }));
  return { ...digestPolicyFiles("cedar", files), dir: dirPath };
}
function digestCedarSource(source) {
  return digestPolicyFiles("cedar", [{ name: "policy.cedar", content: source }]);
}
function digestBuiltinPolicy(policy) {
  return digestPolicyFiles("builtin", [{ name: "policy.json", content: canonicalize(policy) }]);
}
function shortPolicyLabel(result2) {
  return `${result2.engine}:${result2.policy_digest.replace(/^sha256:/, "").slice(0, 16)}`;
}
function buildPolicyBundle(engine, files, generatedAt) {
  const d = digestPolicyFiles(engine, files);
  const byName = new Map(files.map((f) => [f.name, f.content]));
  return {
    schema: POLICY_BUNDLE_SCHEMA,
    construction: POLICY_DIGEST_CONSTRUCTION,
    engine,
    policy_digest: d.policy_digest,
    files: d.files.map((e) => ({ ...e, content: byName.get(e.name) })),
    generated_at: generatedAt || (/* @__PURE__ */ new Date()).toISOString()
  };
}
function verifyPolicyBundle(bundle) {
  try {
    const b = bundle;
    if (!b || b.schema !== POLICY_BUNDLE_SCHEMA) return { valid: false, error: "unknown_schema" };
    if (b.construction !== POLICY_DIGEST_CONSTRUCTION) return { valid: false, error: "unknown_construction" };
    if (!Array.isArray(b.files) || b.files.length === 0) return { valid: false, error: "missing_files" };
    for (const f of b.files) {
      if (sha256hex(Buffer.from(f.content, "utf-8")) !== f.sha256) {
        return { valid: false, error: `file_hash_mismatch:${f.name}` };
      }
    }
    const recomputed = digestPolicyFiles(b.engine, b.files.map((f) => ({ name: f.name, content: f.content }))).policy_digest;
    return recomputed === b.policy_digest ? { valid: true, recomputed } : { valid: false, recomputed, error: "digest_mismatch" };
  } catch (err) {
    return { valid: false, error: `verify_error:${err instanceof Error ? err.message : "unknown"}` };
  }
}
var import_node_crypto, import_node_fs, import_node_path, POLICY_DIGEST_CONSTRUCTION, POLICY_BUNDLE_SCHEMA, sha256hex;
var init_policy_digest = __esm({
  "src/policy-digest.ts"() {
    "use strict";
    import_node_crypto = require("crypto");
    import_node_fs = require("fs");
    import_node_path = require("path");
    init_acta_envelope();
    POLICY_DIGEST_CONSTRUCTION = "acta-policy-digest-v1";
    POLICY_BUNDLE_SCHEMA = "acta.policy-bundle.v1";
    sha256hex = (data) => (0, import_node_crypto.createHash)("sha256").update(data).digest("hex");
  }
});

// src/policy.ts
function loadPolicy(path) {
  const raw = (0, import_node_fs2.readFileSync)(path, "utf-8");
  const parsed = JSON.parse(raw);
  if (!parsed.tools || typeof parsed.tools !== "object") {
    throw new Error(`Invalid policy file: missing "tools" object in ${path}`);
  }
  const policy = {
    tools: parsed.tools,
    default_tier: parsed.default_tier || "unknown",
    policy_engine: parsed.policy_engine || "built-in",
    ...parsed.external ? { external: parsed.external } : {}
  };
  const digest = computePolicyDigest(policy);
  return {
    policy,
    digest,
    credentials: parsed.credentials,
    signing: parsed.signing
  };
}
function computePolicyDigest(policy) {
  return digestBuiltinPolicy(policy).policy_digest;
}
function getToolPolicy(toolName, policy) {
  if (!policy) {
    return { require: "any" };
  }
  if (policy.tools[toolName]) {
    return policy.tools[toolName];
  }
  if (policy.tools["*"]) {
    return policy.tools["*"];
  }
  return { require: "any" };
}
function parseRateLimit(spec) {
  const match = spec.match(/^(\d+)\/(second|minute|hour|day)$/);
  if (!match) {
    throw new Error(`Invalid rate limit format: "${spec}". Expected "N/unit" (e.g. "5/hour")`);
  }
  const count = parseInt(match[1], 10);
  const unit = match[2];
  const windowMs = {
    second: 1e3,
    minute: 6e4,
    hour: 36e5,
    day: 864e5
  };
  return { count, windowMs: windowMs[unit] };
}
function checkRateLimit(key, limit, store) {
  const now = Date.now();
  const windowStart = now - limit.windowMs;
  const timestamps = (store.get(key) || []).filter((t) => t > windowStart);
  if (timestamps.length >= limit.count) {
    store.set(key, timestamps);
    return { allowed: false, remaining: 0 };
  }
  timestamps.push(now);
  store.set(key, timestamps);
  return { allowed: true, remaining: limit.count - timestamps.length };
}
var import_node_fs2;
var init_policy = __esm({
  "src/policy.ts"() {
    "use strict";
    import_node_fs2 = require("fs");
    init_policy_digest();
  }
});

// src/evidence-store.ts
var import_node_fs3, import_node_path2, DEFAULT_THRESHOLDS, EvidenceStore;
var init_evidence_store = __esm({
  "src/evidence-store.ts"() {
    "use strict";
    import_node_fs3 = require("fs");
    import_node_path2 = require("path");
    DEFAULT_THRESHOLDS = {
      min_receipts: 10,
      min_epoch_span: 3,
      min_issuers: 2
    };
    EvidenceStore = class {
      agents = /* @__PURE__ */ new Map();
      filePath;
      dirty = false;
      constructor(dir) {
        this.filePath = (0, import_node_path2.join)(dir || process.cwd(), ".protect-mcp-evidence.json");
        this.load();
      }
      /**
       * Record a receipt observation for an agent.
       */
      record(agentId, issuer, timestamp) {
        const ts = timestamp || (/* @__PURE__ */ new Date()).toISOString();
        const epochHour = Math.floor(new Date(ts).getTime() / (3600 * 1e3));
        const existing = this.agents.get(agentId);
        const observation = {
          issuer,
          timestamp: ts,
          epoch_hour: epochHour
        };
        if (existing) {
          existing.receipts.push(observation);
          existing.last_seen = ts;
          if (existing.receipts.length > 200) {
            existing.receipts = existing.receipts.slice(-200);
          }
        } else {
          this.agents.set(agentId, {
            agent_id: agentId,
            receipts: [observation],
            first_seen: ts,
            last_seen: ts
          });
        }
        this.dirty = true;
      }
      /**
       * Get the evidence summary for an agent.
       */
      getSummary(agentId) {
        const record = this.agents.get(agentId);
        if (!record || record.receipts.length === 0) {
          return { receipt_count: 0, epoch_span: 0, issuer_count: 0 };
        }
        const uniqueIssuers = new Set(record.receipts.map((r) => r.issuer));
        const uniqueEpochs = new Set(record.receipts.map((r) => r.epoch_hour));
        return {
          receipt_count: record.receipts.length,
          epoch_span: uniqueEpochs.size,
          issuer_count: uniqueIssuers.size
        };
      }
      /**
       * Check if an agent meets the evidenced tier thresholds.
       */
      meetsEvidencedThreshold(agentId, thresholds = DEFAULT_THRESHOLDS) {
        const summary = this.getSummary(agentId);
        return summary.receipt_count >= thresholds.min_receipts && summary.epoch_span >= thresholds.min_epoch_span && summary.issuer_count >= thresholds.min_issuers;
      }
      /**
       * Persist to disk (call periodically or on shutdown).
       */
      save() {
        if (!this.dirty) return;
        const data = {};
        for (const [id5, record] of this.agents) {
          data[id5] = record;
        }
        try {
          (0, import_node_fs3.writeFileSync)(this.filePath, JSON.stringify({ v: 1, agents: data }, null, 2) + "\n");
          this.dirty = false;
        } catch {
        }
      }
      /**
       * Load from disk.
       */
      load() {
        if (!(0, import_node_fs3.existsSync)(this.filePath)) return;
        try {
          const raw = (0, import_node_fs3.readFileSync)(this.filePath, "utf-8");
          const parsed = JSON.parse(raw);
          if (parsed.agents && typeof parsed.agents === "object") {
            for (const [id5, record] of Object.entries(parsed.agents)) {
              this.agents.set(id5, record);
            }
          }
        } catch {
        }
      }
      /**
       * Get total agent count (for status display).
       */
      agentCount() {
        return this.agents.size;
      }
      /**
       * Get all agent summaries (for status display).
       */
      allSummaries() {
        const result2 = [];
        for (const [id5] of this.agents) {
          result2.push({ agent_id: id5, summary: this.getSummary(id5) });
        }
        return result2;
      }
    };
  }
});

// src/admission.ts
function evaluateTier(manifest, opts) {
  const options2 = opts && ("evidenceStore" in opts || "overrides" in opts || "thresholds" in opts) ? opts : { overrides: opts };
  const { overrides, evidenceStore, thresholds } = options2;
  if (!manifest) {
    return {
      tier: "unknown",
      reason: "no_manifest_presented"
    };
  }
  if (overrides && manifest.agent_id && overrides[manifest.agent_id]) {
    return {
      tier: overrides[manifest.agent_id],
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: "operator_override"
    };
  }
  if (manifest.signature_valid === false) {
    return {
      tier: "unknown",
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: "invalid_manifest_signature"
    };
  }
  if (manifest.signature_valid === true) {
    if (manifest.evidence_summary) {
      const es = manifest.evidence_summary;
      const t = thresholds || DEFAULT_THRESHOLDS;
      if (es.receipt_count >= t.min_receipts && es.epoch_span >= t.min_epoch_span && es.issuer_count >= t.min_issuers) {
        return {
          tier: "evidenced",
          agent_id: manifest.agent_id,
          manifest_hash: manifest.manifest_hash,
          reason: "evidence_threshold_met"
        };
      }
    }
    if (evidenceStore && manifest.agent_id) {
      if (evidenceStore.meetsEvidencedThreshold(manifest.agent_id, thresholds)) {
        return {
          tier: "evidenced",
          agent_id: manifest.agent_id,
          manifest_hash: manifest.manifest_hash,
          reason: "evidence_store_threshold_met"
        };
      }
    }
    return {
      tier: "signed-known",
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: "valid_signed_manifest"
    };
  }
  return {
    tier: "unknown",
    agent_id: manifest.agent_id,
    manifest_hash: manifest.manifest_hash,
    reason: "manifest_unverified"
  };
}
function meetsMinTier(actual, required) {
  const order = ["unknown", "signed-known", "evidenced", "privileged"];
  return order.indexOf(actual) >= order.indexOf(required);
}
var init_admission = __esm({
  "src/admission.ts"() {
    "use strict";
    init_evidence_store();
  }
});

// src/credentials.ts
function resolveCredential(label, credentials) {
  if (!credentials || !credentials[label]) {
    return {
      resolved: false,
      label,
      error: `credential "${label}" not configured`
    };
  }
  const config = credentials[label];
  const value = process.env[config.value_env];
  if (!value) {
    return {
      resolved: false,
      label,
      error: `environment variable "${config.value_env}" for credential "${label}" is not set`
    };
  }
  return {
    resolved: true,
    label,
    value,
    inject: config.inject,
    name: config.name
  };
}
function validateCredentials(credentials) {
  const warnings = [];
  if (!credentials) return warnings;
  for (const [label, config] of Object.entries(credentials)) {
    if (!config.value_env) {
      warnings.push(`credential "${label}": missing value_env`);
      continue;
    }
    if (!config.inject) {
      warnings.push(`credential "${label}": missing inject type`);
      continue;
    }
    if (!process.env[config.value_env]) {
      warnings.push(`credential "${label}": env var "${config.value_env}" not set`);
    }
  }
  return warnings;
}
var init_credentials = __esm({
  "src/credentials.ts"() {
    "use strict";
  }
});

// src/signing.ts
async function initSigning(config) {
  const warnings = [];
  signerState = null;
  signingConfigured = Boolean(config && config.enabled !== false);
  signingInitError = null;
  if (!config || config.enabled === false) {
    return warnings;
  }
  if (!config.key_path) {
    signingInitError = "signing enabled but key_path is not configured";
    warnings.push(`signing: ${signingInitError}`);
    return warnings;
  }
  if (!(0, import_node_fs4.existsSync)(config.key_path)) {
    signingInitError = `key file not found at ${config.key_path}`;
    warnings.push(`signing: ${signingInitError} \u2014 run "protect-mcp init" to generate`);
    return warnings;
  }
  let keyData;
  try {
    keyData = JSON.parse((0, import_node_fs4.readFileSync)(config.key_path, "utf-8"));
    if (!keyData.privateKey || !keyData.publicKey) {
      signingInitError = "key file missing privateKey or publicKey fields";
      warnings.push(`signing: ${signingInitError}`);
      return warnings;
    }
  } catch (err) {
    signingInitError = `failed to load key file: ${err instanceof Error ? err.message : err}`;
    warnings.push(`signing: ${signingInitError}`);
    return warnings;
  }
  try {
    signerState = {
      privateKey: keyData.privateKey,
      publicKey: keyData.publicKey,
      // kid is opaque per draft-02; existing key files keep their explicit kid,
      // and keys without one get the s2.1.1 RECOMMENDED sb:issuer format.
      kid: keyData.kid || computeSbIssuerKid(keyData.publicKey),
      issuer: config.issuer || keyData.issuer || "protect-mcp"
    };
  } catch (err) {
    signingInitError = `failed to initialize signer: ${err instanceof Error ? err.message : err}`;
    warnings.push(`signing: ${signingInitError} \u2014 enforce mode will fail closed`);
  }
  return warnings;
}
function signDecision(entry, prevReceiptHash) {
  const artifactType = entry.decision === "deny" ? "gateway_restraint" : "decision_receipt";
  if (signingConfigured && signingInitError) {
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: `signing initialization failed: ${signingInitError}`,
      error: signingInitError
    };
  }
  if (signingConfigured && !signerState) {
    const error = "signing was configured but no signer is ready";
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: error,
      error
    };
  }
  if (!signerState) {
    return { ok: false, signed: null, artifact_type: "none" };
  }
  try {
    const payload = {
      // draft-02 s3.1 access-decision fields
      type: "protectmcp:decision",
      tool_name: entry.tool,
      decision: entry.decision,
      reason: entry.reason_code,
      policy_digest: entry.policy_digest,
      // Extension fields (signed alongside the s3.1 core)
      scope: entry.request_id,
      // request scope
      mode: entry.mode,
      request_id: entry.request_id,
      // Spec version: ties every receipt to the IETF standard
      spec: "draft-farley-acta-signed-receipts-03",
      // Issuer certification: distinguishes VOPRF-backed receipts from self-signed ones
      // - scopeblind:verified  = issued via ScopeBlind VOPRF backend (paid tier)
      // - self-signed          = signed with local Ed25519 key (free tier, protect-mcp default)
      // - uncertified          = unsigned receipt (shadow mode, no signing configured)
      issuer_certification: signerState ? "self-signed" : "uncertified",
      // The signer's PUBLIC key, inside the signed payload, so a receipt is
      // self-contained: any verifier (including the record viewer, in-browser)
      // can check the signature without a side channel. Binding the key inside
      // the signature means it cannot be swapped without breaking the signature;
      // authenticity (that the key is YOUR gate's) still comes from pinning it.
      public_key: signerState.publicKey
    };
    if (signerState.issuer && signerState.issuer !== signerState.kid) {
      payload.issuer_name = signerState.issuer;
    }
    if (prevReceiptHash) payload.previousReceiptHash = prevReceiptHash;
    if (entry.tier) payload.tier = entry.tier;
    if (entry.credential_ref) payload.credential_ref = entry.credential_ref;
    if (entry.rate_limit_remaining !== void 0) {
      payload.rate_limit_remaining = entry.rate_limit_remaining;
    }
    if (entry.policy_engine) payload.policy_engine = entry.policy_engine;
    if (entry.hook_event) payload.hook_event = entry.hook_event;
    if (entry.sandbox_state) payload.sandbox_state = entry.sandbox_state;
    if (entry.timing) payload.timing = entry.timing;
    if (entry.swarm) payload.swarm = entry.swarm;
    if (entry.payload_digest) payload.payload_digest = entry.payload_digest;
    if (entry.enrichment) payload.enrichment = entry.enrichment;
    if (entry.action_readback) payload.action_readback = entry.action_readback;
    if (entry.deny_iteration) payload.deny_iteration = entry.deny_iteration;
    if (entry.mandate_registry) payload.mandate_registry = entry.mandate_registry;
    if (entry.standard) payload.standard = entry.standard;
    if (entry.approval) payload.approval = entry.approval;
    const result2 = createReceiptEnvelope(
      payload,
      signerState.privateKey,
      signerState.kid,
      Number.isFinite(entry.timestamp) ? new Date(entry.timestamp).toISOString() : void 0
    );
    return {
      ok: true,
      signed: JSON.stringify(result2.envelope),
      artifact_type: artifactType,
      receipt_hash: result2.hash
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown error";
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: `signing failed: ${message}`,
      error: message
    };
  }
}
function signGenericArtifact(_artifactType, payload) {
  if (signingConfigured && signingInitError) {
    return { ok: false, signed: null, warning: `signing initialization failed: ${signingInitError}`, error: signingInitError };
  }
  if (signingConfigured && !signerState) {
    const error = "signing was configured but no signer is ready";
    return { ok: false, signed: null, warning: error, error };
  }
  if (!signerState) {
    return { ok: false, signed: null };
  }
  try {
    const full = {
      ...payload,
      type: String(payload.type || "protectmcp:artifact"),
      public_key: signerState.publicKey
    };
    if (signerState.issuer && signerState.issuer !== signerState.kid && full.type !== "scopeblind.egress_summary.v1") {
      full.issuer_name = signerState.issuer;
    }
    const result2 = createReceiptEnvelope(full, signerState.privateKey, signerState.kid);
    return { ok: true, signed: JSON.stringify(result2.envelope) };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown error";
    return { ok: false, signed: null, warning: `signing failed: ${message}`, error: message };
  }
}
function getSignerInfo() {
  if (!signerState) return null;
  return {
    publicKey: signerState.publicKey,
    kid: signerState.kid,
    issuer: signerState.issuer
  };
}
function isSigningEnabled() {
  return signingConfigured && signingInitError === null && signerState !== null;
}
var import_node_fs4, signerState, signingConfigured, signingInitError;
var init_signing = __esm({
  "src/signing.ts"() {
    "use strict";
    import_node_fs4 = require("fs");
    init_acta_envelope();
    signerState = null;
    signingConfigured = false;
    signingInitError = null;
  }
});

// src/external-pdp.ts
async function queryExternalPDP(context, config) {
  const timeout = config.timeout_ms || 500;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const body = formatRequest(context, config.format || "generic");
    const response = await fetch(config.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!response.ok) {
      return fallbackDecision(config, `PDP returned HTTP ${response.status}`);
    }
    const result2 = await response.json();
    return parseResponse(result2, config.format || "generic");
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      return fallbackDecision(config, `PDP timeout after ${timeout}ms`);
    }
    return fallbackDecision(config, `PDP error: ${err instanceof Error ? err.message : "unknown"}`);
  }
}
function formatRequest(context, format) {
  switch (format) {
    case "opa":
      return {
        input: {
          actor: context.actor,
          action: context.action,
          target: context.target,
          credential_ref: context.credential_ref,
          mode: context.mode,
          metadata: context.request_metadata
        }
      };
    case "cerbos":
      return {
        principal: {
          id: context.actor.id || "unknown",
          roles: [context.actor.tier],
          attr: {
            manifest_hash: context.actor.manifest_hash
          }
        },
        resource: {
          kind: "tool",
          id: context.action.tool,
          attr: context.target
        },
        actions: [context.action.operation || "call"]
      };
    case "cedar":
      return {
        principal: {
          type: "Agent",
          id: context.actor.id || "unknown"
        },
        action: {
          type: "Action",
          id: `MCP::Tool::${context.action.operation || "call"}`
        },
        resource: {
          type: "Tool",
          id: context.action.tool
        },
        context: {
          tier: context.actor.tier,
          manifest_hash: context.actor.manifest_hash || null,
          service: context.target.service || "default",
          mode: context.mode,
          credential_ref: context.credential_ref || null
        }
      };
    case "generic":
    default:
      return context;
  }
}
function parseResponse(result2, format) {
  switch (format) {
    case "opa":
      if (typeof result2.result === "boolean") {
        return { allowed: result2.result };
      }
      if (result2.result && typeof result2.result === "object") {
        const r = result2.result;
        return {
          allowed: Boolean(r.allow),
          reason: r.reason,
          metadata: r
        };
      }
      return { allowed: false, reason: "unrecognized OPA response" };
    case "cerbos":
      if (Array.isArray(result2.results) && result2.results.length > 0) {
        const actions = result2.results[0].actions;
        if (actions) {
          const effect = Object.values(actions)[0];
          return { allowed: effect === "EFFECT_ALLOW" };
        }
      }
      return { allowed: false, reason: "unrecognized Cerbos response" };
    case "cedar":
      if (typeof result2.decision === "string") {
        return {
          allowed: result2.decision === "Allow",
          reason: result2.decision === "Deny" ? `cedar_deny${result2.diagnostics ? ": " + JSON.stringify(result2.diagnostics) : ""}` : void 0,
          metadata: result2.diagnostics
        };
      }
      if (Array.isArray(result2.results) && result2.results.length > 0) {
        const first = result2.results[0];
        return {
          allowed: first.decision === "Allow",
          reason: first.decision === "Deny" ? "cedar_deny" : void 0
        };
      }
      return { allowed: false, reason: "unrecognized Cedar response" };
    case "generic":
    default:
      return {
        allowed: Boolean(result2.allowed),
        reason: result2.reason,
        metadata: result2.metadata
      };
  }
}
function fallbackDecision(config, reason) {
  const fallback = config.fallback || "deny";
  return {
    allowed: fallback === "allow",
    reason: `fallback_${fallback}: ${reason}`
  };
}
function buildDecisionContext(toolName, tier, opts) {
  return {
    v: 1,
    actor: {
      id: opts.agentId,
      tier,
      manifest_hash: opts.manifestHash
    },
    action: {
      tool: toolName,
      operation: "call"
    },
    target: {
      service: opts.slug || "default"
    },
    credential_ref: opts.credentialRef,
    mode: opts.mode,
    request_metadata: opts.requestMetadata || {}
  };
}
var init_external_pdp = __esm({
  "src/external-pdp.ts"() {
    "use strict";
  }
});

// src/cedar-evaluator.ts
async function ensureCedarWasm() {
  if (cedarWasm) return true;
  if (loadAttempted) return false;
  loadAttempted = true;
  const errors = [];
  for (const moduleName of CEDAR_WASM_SPECIFIERS) {
    try {
      const mod = await import(
        /* @vite-ignore */
        moduleName
      );
      const engine = mod && (mod.default || mod);
      if (!engine || typeof engine.isAuthorized !== "function") {
        errors.push(`${moduleName}: loaded but has no isAuthorized`);
        continue;
      }
      cedarWasm = mod;
      cedarWasmSpecifier = moduleName;
      return true;
    } catch (err) {
      const msg = err instanceof Error ? `${err.code ? err.code + " " : ""}${err.message.split("\n")[0]}` : String(err);
      errors.push(`${moduleName}: ${msg}`);
    }
  }
  cedarWasmLoadError = errors.join("; ");
  return false;
}
function loadCedarPolicies(dirPath) {
  if (!(0, import_node_fs5.existsSync)(dirPath)) {
    throw new Error(`Cedar policy directory not found: ${dirPath}`);
  }
  const entries = (0, import_node_fs5.readdirSync)(dirPath).filter((f) => (0, import_node_path3.extname)(f) === ".cedar").sort();
  if (entries.length === 0) {
    throw new Error(`No .cedar files found in: ${dirPath}`);
  }
  const files = [];
  for (const file of entries) {
    files.push({ name: file, content: (0, import_node_fs5.readFileSync)((0, import_node_path3.join)(dirPath, file), "utf-8") });
  }
  const concatenated = files.map((f) => f.content).join("\n\n");
  const digest = digestPolicyFiles("cedar", files).policy_digest;
  return {
    source: concatenated,
    digest,
    fileCount: entries.length,
    files: entries
  };
}
function buildEntities(req) {
  const agentId = req.agentId || req.tier;
  return [
    {
      uid: { type: "Agent", id: agentId },
      attrs: {
        tier: req.tier,
        ...req.agentId ? { agent_id: req.agentId } : {}
      },
      parents: []
    },
    {
      uid: { type: "Tool", id: req.tool },
      attrs: {},
      parents: []
    }
  ];
}
function onEvalError(reason, failClosed, extra) {
  return {
    allowed: !failClosed,
    reason: failClosed ? reason : `${reason} (observe mode; would DENY under enforcement)`,
    metadata: { error: true, fail_closed: failClosed, would_deny: true, ...extra || {} }
  };
}
async function evaluateCedar(policySet, req, schema, options2) {
  const failClosed = options2?.failClosed ?? true;
  const available = await ensureCedarWasm();
  if (!available) {
    return onEvalError(`cedar_wasm_not_available: ${cedarWasmLoadError || "unknown load failure"}`, failClosed, { fallback: true });
  }
  try {
    const agentId = req.agentId || req.tier;
    const context = {
      tier: req.tier,
      ...req.context || {}
    };
    if (req.toolInput && Object.keys(req.toolInput).length > 0) {
      context.input = req.toolInput;
    }
    const authRequest = {
      principal: { type: "Agent", id: agentId },
      action: { type: "Action", id: req.actionModel === "tool" ? req.tool : "MCP::Tool::call" },
      resource: { type: "Tool", id: req.tool },
      context
    };
    const entities = buildEntities(req);
    const cedarSchema = schema?.schemaJson ?? null;
    let result2;
    if (typeof cedarWasm.isAuthorized === "function") {
      result2 = cedarWasm.isAuthorized({
        policies: { staticPolicies: policySet.source },
        entities,
        principal: authRequest.principal,
        action: authRequest.action,
        resource: authRequest.resource,
        context: authRequest.context,
        schema: cedarSchema
      });
    } else if (typeof cedarWasm.checkAuthorization === "function") {
      result2 = cedarWasm.checkAuthorization(
        policySet.source,
        JSON.stringify(entities),
        JSON.stringify(authRequest)
      );
    } else {
      const cedarEngine = cedarWasm.default || cedarWasm;
      if (typeof cedarEngine.isAuthorized === "function") {
        result2 = cedarEngine.isAuthorized({
          policies: { staticPolicies: policySet.source },
          entities,
          principal: authRequest.principal,
          action: authRequest.action,
          resource: authRequest.resource,
          context: authRequest.context,
          schema: cedarSchema
        });
      } else {
        return onEvalError("cedar_wasm_api_unsupported", failClosed, { exports: Object.keys(cedarWasm) });
      }
    }
    const parsed = parseWasmResult(result2);
    const policyErrors = extractPolicyErrors(result2);
    if (parsed.kind === "error") {
      return onEvalError(`cedar_unparseable_result: ${parsed.diagnostics}`, failClosed);
    }
    if (policyErrors.length > 0) {
      return onEvalError(
        `cedar_policy_errored: ${policyErrors.length} policy error(s); decision is unsound`,
        failClosed,
        { policy_errors: policyErrors.slice(0, 5), policy_digest: policySet.digest }
      );
    }
    return {
      allowed: parsed.kind === "allow",
      reason: parsed.kind === "allow" ? void 0 : `cedar_deny${parsed.diagnostics ? ": " + parsed.diagnostics : ""}`,
      metadata: {
        policy_digest: policySet.digest,
        ...parsed.matchedPolicies ? { matched_policies: parsed.matchedPolicies } : {}
      }
    };
  } catch (err) {
    return onEvalError(`cedar_eval_error: ${err instanceof Error ? err.message : "unknown"}`, failClosed);
  }
}
function parseWasmResult(result2) {
  if (!result2) return { kind: "error", diagnostics: "null result from Cedar WASM" };
  if (result2.type === "failure") {
    return { kind: "error", diagnostics: `cedar failure: ${JSON.stringify(result2.errors ?? [])}` };
  }
  if (result2.type === "success" && result2.response) {
    const dec = result2.response.decision;
    const reasons = result2.response.diagnostics?.reason;
    if (dec === "allow" || dec === "Allow") return { kind: "allow", matchedPolicies: reasons };
    if (dec === "deny" || dec === "Deny") {
      return { kind: "deny", diagnostics: result2.response.diagnostics ? JSON.stringify(result2.response.diagnostics) : void 0, matchedPolicies: reasons };
    }
  }
  if (result2.type === "allow" || result2.decision === "Allow") return { kind: "allow" };
  if (result2.type === "deny" || result2.decision === "Deny") return { kind: "deny" };
  if (typeof result2 === "boolean") return result2 ? { kind: "allow" } : { kind: "deny" };
  return { kind: "error", diagnostics: `unknown result format: ${JSON.stringify(result2)}` };
}
function extractPolicyErrors(result2) {
  if (!result2 || typeof result2 !== "object") return [];
  const raw = result2.errors ?? result2.response?.diagnostics?.errors ?? result2.diagnostics?.errors ?? [];
  if (!Array.isArray(raw)) return [];
  return raw.map((e) => typeof e === "string" ? e : e?.message ?? e?.error ?? JSON.stringify(e)).filter(Boolean);
}
async function isCedarAvailable() {
  return ensureCedarWasm();
}
function policySetFromSource(source, name = "inline") {
  const digest = digestCedarSource(source).policy_digest;
  return { source, digest, fileCount: 1, files: [name] };
}
async function runEvaluatorSelfTest() {
  const wasmAvailable = await isCedarAvailable();
  const cases = [];
  const run = async (name, expected, policy, context) => {
    const d = await evaluateCedar(policy, { tool: "Bash", tier: "unknown", context }, void 0, { failClosed: true });
    const actual = d.allowed ? "ALLOW" : "DENY";
    cases.push({ name, expected, actual, pass: actual === expected, reason: d.reason });
  };
  if (!wasmAvailable) {
    await run("engine unavailable denies", "DENY", policySetFromSource("permit(principal, action, resource);"), {});
    return { wasmAvailable, passed: cases.every((c2) => c2.pass), cases };
  }
  const correct = policySetFromSource(
    'forbid(principal, action, resource) when { ["rm", "dd", "mkfs"].contains(context.command) };\npermit(principal, action, resource);'
  );
  await run("forbid denies rm", "DENY", correct, { command: "rm" });
  await run("permit allows ls", "ALLOW", correct, { command: "ls" });
  const broken = policySetFromSource(
    'forbid(principal, action, resource) when { context.command in ["rm", "dd"] };\npermit(principal, action, resource);'
  );
  await run("in-on-String forbid does not permit-all", "DENY", broken, { command: "rm" });
  return { wasmAvailable, passed: cases.every((c2) => c2.pass), cases };
}
var import_node_fs5, import_node_path3, cedarWasm, loadAttempted, cedarWasmSpecifier, cedarWasmLoadError, CEDAR_WASM_SPECIFIERS;
var init_cedar_evaluator = __esm({
  "src/cedar-evaluator.ts"() {
    "use strict";
    import_node_fs5 = require("fs");
    import_node_path3 = require("path");
    init_policy_digest();
    cedarWasm = null;
    loadAttempted = false;
    cedarWasmSpecifier = null;
    cedarWasmLoadError = null;
    CEDAR_WASM_SPECIFIERS = ["@cedar-policy/cedar-wasm/nodejs", "@cedar-policy/cedar-wasm"];
  }
});

// src/notifications.ts
async function sendApprovalNotification(config, notification) {
  const promises = [];
  if (config.sms) {
    promises.push(sendSms(config.sms, notification));
  }
  if (config.webhook) {
    promises.push(sendWebhook(config.webhook, notification));
  }
  if (config.email) {
    promises.push(sendEmail(config.email, notification));
  }
  const results = await Promise.allSettled(promises);
  for (const result2 of results) {
    if (result2.status === "rejected") {
      console.error(`[protect-mcp] Notification failed: ${result2.reason}`);
    }
  }
}
async function sendSms(config, notification) {
  const body = [
    `\u{1F512} Approval Required`,
    `Tool: ${notification.toolName}`,
    notification.agentId ? `Agent: ${notification.agentId}` : null,
    `Reason: ${notification.reason}`,
    notification.approveUrl ? `Approve: ${notification.approveUrl}` : null,
    notification.traceUrl ? `Trace: ${notification.traceUrl}` : null
  ].filter(Boolean).join("\n");
  const params = new URLSearchParams({
    To: config.to,
    From: config.from,
    Body: body
  });
  const response = await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${config.accountSid}/Messages.json`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${config.accountSid}:${config.authToken}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params.toString()
    }
  );
  if (!response.ok) {
    throw new Error(`Twilio SMS failed: ${response.status} ${await response.text()}`);
  }
}
async function sendWebhook(config, notification) {
  let payload;
  if (config.template === "slack") {
    payload = {
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: "\u{1F512} Agent Approval Required" }
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Tool:*
\`${notification.toolName}\`` },
            { type: "mrkdwn", text: `*Agent:*
${notification.agentId || "unknown"}` },
            { type: "mrkdwn", text: `*Policy:*
${notification.policyName || "default"}` },
            { type: "mrkdwn", text: `*Time:*
${notification.timestamp}` }
          ]
        },
        {
          type: "section",
          text: { type: "mrkdwn", text: `*Reason:* ${notification.reason}` }
        },
        ...notification.approveUrl || notification.traceUrl ? [
          {
            type: "actions",
            elements: [
              ...notification.approveUrl ? [{ type: "button", text: { type: "plain_text", text: "\u2705 Approve" }, url: notification.approveUrl, style: "primary" }] : [],
              ...notification.traceUrl ? [{ type: "button", text: { type: "plain_text", text: "\u{1F50D} View Trace" }, url: notification.traceUrl }] : []
            ]
          }
        ] : []
      ]
    };
  } else if (config.template === "pagerduty") {
    payload = {
      routing_key: config.headers?.["X-Routing-Key"] || "",
      event_action: "trigger",
      payload: {
        summary: `Agent approval required: ${notification.toolName}`,
        source: "protect-mcp",
        severity: "warning",
        custom_details: {
          tool: notification.toolName,
          agent: notification.agentId,
          policy: notification.policyName,
          reason: notification.reason,
          trace_url: notification.traceUrl,
          approve_url: notification.approveUrl
        }
      }
    };
  } else {
    payload = notification;
  }
  const response = await fetch(config.url, {
    method: config.method || "POST",
    headers: {
      "Content-Type": "application/json",
      ...config.headers
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error(`Webhook failed: ${response.status}`);
  }
}
async function sendEmail(config, notification) {
  if (!config.resendApiKey) {
    console.warn("[protect-mcp] Email notification skipped: no resendApiKey configured");
    return;
  }
  const html = `
    <div style="font-family: monospace; padding: 20px; background: #0d1117; color: #c9d1d9; border-radius: 8px;">
      <h2 style="color: #10b981;">\u{1F512} Agent Approval Required</h2>
      <table style="font-size: 14px; margin: 16px 0;">
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Tool:</td><td>${notification.toolName}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Agent:</td><td>${notification.agentId || "unknown"}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Reason:</td><td>${notification.reason}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Time:</td><td>${notification.timestamp}</td></tr>
      </table>
      ${notification.approveUrl ? `<a href="${notification.approveUrl}" style="background: #10b981; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; margin-right: 8px;">\u2705 Approve</a>` : ""}
      ${notification.traceUrl ? `<a href="${notification.traceUrl}" style="background: #1f2937; color: #c9d1d9; padding: 8px 16px; border-radius: 6px; text-decoration: none; border: 1px solid #374151;">\u{1F50D} View Trace</a>` : ""}
    </div>
  `;
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.resendApiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "ScopeBlind <noreply@scopeblind.com>",
      to: config.to,
      subject: `\u{1F512} Approval required: ${notification.toolName}`,
      html
    })
  });
  if (!response.ok) {
    throw new Error(`Resend email failed: ${response.status}`);
  }
}
function parseNotificationConfigFromEnv() {
  const config = {};
  let hasConfig = false;
  const smsTo = process.env.SCOPEBLIND_SMS_TO;
  const twilioSid = process.env.TWILIO_ACCOUNT_SID;
  const twilioToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioFrom = process.env.TWILIO_FROM_NUMBER;
  if (smsTo && twilioSid && twilioToken && twilioFrom) {
    config.sms = { accountSid: twilioSid, authToken: twilioToken, from: twilioFrom, to: smsTo };
    hasConfig = true;
  }
  const webhookUrl = process.env.SCOPEBLIND_WEBHOOK_URL;
  if (webhookUrl) {
    config.webhook = {
      url: webhookUrl,
      template: process.env.SCOPEBLIND_WEBHOOK_TEMPLATE || "custom"
    };
    hasConfig = true;
  }
  const emailTo = process.env.SCOPEBLIND_EMAIL_TO;
  if (emailTo) {
    config.email = { to: emailTo, resendApiKey: process.env.RESEND_API_KEY };
    hasConfig = true;
  }
  return hasConfig ? config : null;
}
var init_notifications = __esm({
  "src/notifications.ts"() {
    "use strict";
  }
});

// src/http-server.ts
function startStatusServer(config, receiptBuffer, approvalStore, approvalNonce) {
  const startTime = Date.now();
  const logDir = process.cwd();
  const server = (0, import_node_http.createServer)((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Content-Type", "application/json");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url || "/", `http://localhost:${config.port}`);
    const path = url.pathname;
    try {
      if (path === "/health") {
        handleHealth(res, startTime, config);
      } else if (path === "/status") {
        handleStatus(res, logDir);
      } else if (path === "/receipts") {
        handleReceipts(res, receiptBuffer, url);
      } else if (path === "/receipts/latest") {
        handleReceiptLatest(res, receiptBuffer);
      } else if (path.startsWith("/receipts/")) {
        const id5 = path.slice("/receipts/".length);
        handleReceiptById(res, receiptBuffer, id5);
      } else if (path === "/approve" && req.method === "POST") {
        handleApprove(req, res, approvalStore, approvalNonce);
      } else if (path === "/approvals" && req.method === "GET") {
        handleListApprovals(res, approvalStore);
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "not_found", endpoints: ["/health", "/status", "/receipts", "/receipts/latest", "/receipts/:id", "/approve", "/approvals"] }));
      }
    } catch (err) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  });
  server.on("error", (err) => {
    if (config.verbose) {
      process.stderr.write(`[PROTECT_MCP] HTTP status server error: ${err.message}
`);
    }
  });
  server.listen(config.port, "127.0.0.1", () => {
    if (config.verbose) {
      process.stderr.write(`[PROTECT_MCP] HTTP status server listening on http://127.0.0.1:${config.port}
`);
    }
  });
  server.unref();
  return server;
}
function handleHealth(res, startTime, config) {
  res.writeHead(200);
  res.end(JSON.stringify({
    status: "ok",
    uptime_ms: Date.now() - startTime,
    mode: config.mode,
    version: process.env.PROTECT_MCP_VERSION || "unknown"
  }));
}
function handleStatus(res, logDir) {
  const logPath = (0, import_node_path4.join)(logDir, LOG_FILE);
  if (!(0, import_node_fs6.existsSync)(logPath)) {
    res.writeHead(200);
    res.end(JSON.stringify({ entries: 0, message: "no log file yet" }));
    return;
  }
  const raw = (0, import_node_fs6.readFileSync)(logPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  const entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
    }
  }
  const toolCounts = {};
  let allowCount = 0, denyCount = 0;
  const tierCounts = {};
  for (const e of entries) {
    toolCounts[e.tool] = (toolCounts[e.tool] || 0) + 1;
    if (e.decision === "allow") allowCount++;
    else denyCount++;
    if (e.tier) tierCounts[e.tier] = (tierCounts[e.tier] || 0) + 1;
  }
  res.writeHead(200);
  res.end(JSON.stringify({
    entries: entries.length,
    allow: allowCount,
    deny: denyCount,
    tools: toolCounts,
    tiers: tierCounts,
    first_timestamp: entries.length > 0 ? entries[0].timestamp : null,
    last_timestamp: entries.length > 0 ? entries[entries.length - 1].timestamp : null
  }));
}
function handleReceipts(res, buffer, url) {
  const limit = parseInt(url.searchParams.get("limit") || "20", 10);
  const receipts = buffer.getAll().slice(0, Math.min(limit, MAX_RECEIPTS));
  res.writeHead(200);
  res.end(JSON.stringify({
    count: receipts.length,
    total: buffer.count(),
    receipts
  }));
}
function handleReceiptLatest(res, buffer) {
  const latest = buffer.getLatest();
  if (!latest) {
    res.writeHead(404);
    res.end(JSON.stringify({ error: "no_receipts", message: "No receipts yet. Make a tool call through protect-mcp first." }));
    return;
  }
  res.writeHead(200);
  res.end(JSON.stringify(latest));
}
function handleReceiptById(res, buffer, id5) {
  const receipt = buffer.getById(id5);
  if (!receipt) {
    res.writeHead(404);
    res.end(JSON.stringify({ error: "receipt_not_found", request_id: id5 }));
    return;
  }
  res.writeHead(200);
  res.end(JSON.stringify(receipt));
}
function handleApprove(req, res, approvalStore, expectedNonce) {
  if (!approvalStore) {
    res.writeHead(503);
    res.end(JSON.stringify({ error: "approval_store_not_available" }));
    return;
  }
  let body = "";
  req.on("data", (chunk) => {
    body += chunk.toString();
  });
  req.on("end", () => {
    try {
      const { request_id, tool, mode, nonce } = JSON.parse(body);
      if (expectedNonce && nonce !== expectedNonce) {
        res.writeHead(403);
        res.end(JSON.stringify({ error: "invalid_nonce", message: "Approval nonce does not match. Check stderr output for the correct nonce." }));
        return;
      }
      if (!tool || typeof tool !== "string") {
        res.writeHead(400);
        res.end(JSON.stringify({ error: "missing_tool", usage: '{"request_id":"abc123","tool":"send_email","mode":"once|always","nonce":"..."}' }));
        return;
      }
      const grantMode = mode === "always" ? "always" : "once";
      const ttlMs = grantMode === "once" ? 5 * 60 * 1e3 : 24 * 60 * 60 * 1e3;
      const grantEntry = { tool, mode: grantMode, expires_at: Date.now() + ttlMs };
      if (grantMode === "always") {
        approvalStore.set(`always:${tool}`, grantEntry);
      } else if (request_id) {
        approvalStore.set(request_id, grantEntry);
      } else {
        approvalStore.set(tool, grantEntry);
      }
      res.writeHead(200);
      res.end(JSON.stringify({
        approved: true,
        request_id: request_id || null,
        tool,
        mode: grantMode,
        expires_in_seconds: ttlMs / 1e3
      }));
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "invalid_json", usage: '{"request_id":"abc123","tool":"send_email","mode":"once","nonce":"..."}' }));
    }
  });
}
function handleListApprovals(res, approvalStore) {
  if (!approvalStore) {
    res.writeHead(200);
    res.end(JSON.stringify({ grants: [] }));
    return;
  }
  const now = Date.now();
  const grants = [];
  for (const [key, grant] of approvalStore) {
    if (now < grant.expires_at) {
      grants.push({ key, tool: grant.tool, mode: grant.mode, expires_in_seconds: Math.round((grant.expires_at - now) / 1e3) });
    }
  }
  res.writeHead(200);
  res.end(JSON.stringify({ grants }));
}
var import_node_http, import_node_fs6, import_node_path4, LOG_FILE, MAX_RECEIPTS, ReceiptBuffer;
var init_http_server = __esm({
  "src/http-server.ts"() {
    "use strict";
    import_node_http = require("http");
    import_node_fs6 = require("fs");
    import_node_path4 = require("path");
    LOG_FILE = ".protect-mcp-log.jsonl";
    MAX_RECEIPTS = 100;
    ReceiptBuffer = class {
      receipts = [];
      add(requestId, receipt) {
        this.receipts.push({
          request_id: requestId,
          receipt,
          timestamp: Date.now()
        });
        if (this.receipts.length > MAX_RECEIPTS) {
          this.receipts = this.receipts.slice(-MAX_RECEIPTS);
        }
      }
      getAll() {
        return [...this.receipts].reverse();
      }
      getById(requestId) {
        return this.receipts.find((r) => r.request_id === requestId);
      }
      count() {
        return this.receipts.length;
      }
      getLatest() {
        return this.receipts.length > 0 ? this.receipts[this.receipts.length - 1] : void 0;
      }
    };
  }
});

// src/action-readback.ts
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(",")}}`;
}
function redact(value, path = [], redacted = [], disclosed = [], depth = 0) {
  if (depth > 4) return "[truncated-depth]";
  if (value === null || value === void 0) return value;
  if (typeof value !== "object") {
    if (path.length > 0) disclosed.push(path.join("."));
    if (typeof value === "string" && value.length > 240) return `${value.slice(0, 240)}...`;
    return value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item, idx) => redact(item, [...path, String(idx)], redacted, disclosed, depth + 1));
  }
  const out2 = {};
  for (const [key, child] of Object.entries(value)) {
    const childPath = [...path, key];
    if (SECRET_KEY_RE.test(key)) {
      redacted.push(childPath.join("."));
      out2[key] = "[redacted]";
      continue;
    }
    out2[key] = redact(child, childPath, redacted, disclosed, depth + 1);
  }
  return out2;
}
function firstStringValue(input, keys2) {
  for (const key of keys2) {
    const value = input[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" || typeof value === "boolean") return String(value);
  }
  return void 0;
}
function actionFor(tool, input) {
  const explicit = firstStringValue(input, ["action", "operation", "method", "verb", "command"]);
  if (explicit) return explicit.length > 90 ? `${explicit.slice(0, 90)}...` : explicit;
  return tool;
}
function buildActionReadback(tool, input) {
  const normalized = input && typeof input === "object" && !Array.isArray(input) ? input : { value: input };
  const canonical2 = stableStringify(normalized);
  const redactedFields = [];
  const disclosedFields = [];
  const payloadPreview = redact(normalized, [], redactedFields, disclosedFields);
  const action = actionFor(tool, normalized);
  const destination = firstStringValue(normalized, DESTINATION_KEYS);
  const summary = destination ? `${tool} -> ${destination}` : `${tool} request`;
  return {
    tool,
    action,
    destination,
    payload_preview: payloadPreview,
    payload_hash: (0, import_node_crypto2.createHash)("sha256").update(canonical2).digest("hex"),
    payload_bytes: Buffer.byteLength(canonical2, "utf-8"),
    disclosed_fields: [...new Set(disclosedFields)].slice(0, 80),
    redacted_fields: [...new Set(redactedFields)].slice(0, 80),
    summary
  };
}
var import_node_crypto2, SECRET_KEY_RE, DESTINATION_KEYS;
var init_action_readback = __esm({
  "src/action-readback.ts"() {
    "use strict";
    import_node_crypto2 = require("crypto");
    SECRET_KEY_RE = /(api[_-]?key|authorization|bearer|credential|password|secret|session|token|private[_-]?key)/i;
    DESTINATION_KEYS = [
      "path",
      "file_path",
      "filePath",
      "url",
      "uri",
      "endpoint",
      "host",
      "hostname",
      "repo",
      "repository",
      "branch",
      "channel",
      "to",
      "recipient",
      "symbol",
      "account",
      "bucket",
      "database",
      "table",
      "service"
    ];
  }
});

// src/standard-gate.ts
function moneyFrom(v) {
  if (!isObj(v) || typeof v.amount !== "number" || !(v.amount >= 0) || typeof v.currency !== "string" || !/^[A-Z]{3}$/.test(v.currency)) return null;
  return { minor: Math.round(v.amount * 100), currency: v.currency };
}
function parseStandard(value) {
  if (!isObj(value) || value.type !== "scopeblind.proof_request.v1") throw new Error("not a signed standard (scopeblind.proof_request.v1)");
  if (typeof value.request_id !== "string" || typeof value.digest !== "string") throw new Error("the standard has no request_id or digest");
  const recipient = isObj(value.recipient) ? value.recipient : null;
  if (!recipient || typeof recipient.verification_key !== "string" || !/^[0-9a-f]{64}$/i.test(recipient.verification_key)) throw new Error("the standard names no signer key");
  if (!isObj(value.signature) || typeof value.signature.value !== "string") throw new Error("the standard is not signed");
  const q = isObj(value.requirements) ? value.requirements : {};
  const run = isObj(q.run) ? q.run : null;
  const tools = run && Array.isArray(run.allowed_tools) ? run.allowed_tools.filter((t) => typeof t === "string") : null;
  const limits = isObj(q.action_limits) ? q.action_limits : null;
  const amount_max = limits ? moneyFrom(limits.amount_max) : null;
  const approval = isObj(q.human_approval) ? q.human_approval : null;
  const required_above = approval ? moneyFrom(approval.required_above) : null;
  const enforcement = isObj(value.enforcement) ? value.enforcement : null;
  const policy_digest = enforcement && typeof enforcement.policy_digest === "string" ? enforcement.policy_digest : null;
  const parts = [tools ? `${tools.length} tool${tools.length === 1 ? "" : "s"}` : "no tool list", amount_max ? `at most ${fmt(amount_max)} per instruction` : "no amount limit", required_above ? `a person approves above ${fmt(required_above)}` : "no approval threshold"];
  return { request_id: value.request_id, digest: value.digest, signer_key: recipient.verification_key.toLowerCase(), tools, amount_max, required_above, policy_digest, summary: parts.join(", ") };
}
function loadStandardFile(path) {
  return parseStandard(JSON.parse((0, import_node_fs7.readFileSync)(path, "utf-8")));
}
function readAmount(input) {
  if (!isObj(input)) return null;
  const currency = typeof input.currency === "string" && /^[A-Za-z]{3}$/.test(input.currency) ? input.currency.toUpperCase() : null;
  if (typeof input.amount_minor === "number" && Number.isFinite(input.amount_minor)) return { minor: Math.round(input.amount_minor), currency: currency ?? "" };
  if (typeof input.amount === "number" && Number.isFinite(input.amount)) return { minor: Math.round(input.amount * 100), currency: currency ?? "" };
  return null;
}
function checkAmount(gate, input) {
  if (!gate.amount_max) return { ok: true };
  const amount3 = readAmount(input);
  if (!amount3) return { ok: true };
  if (amount3.currency !== gate.amount_max.currency) return { ok: false, reason: "standard_currency_not_permitted", detail: `the standard permits ${gate.amount_max.currency} only; this call is in ${amount3.currency || "no named currency"}` };
  if (amount3.minor > gate.amount_max.minor) return { ok: false, reason: "standard_amount_over_limit", detail: `${fmt(amount3)} is over the standard's limit of ${fmt(gate.amount_max)} per instruction` };
  return { ok: true };
}
function personRequired(gate, input) {
  if (!gate.required_above) return { required: false };
  const amount3 = readAmount(input);
  if (!amount3) return { required: false };
  if (amount3.currency !== gate.required_above.currency) return { required: true, detail: `${fmt(amount3)} cannot be compared with the standard's threshold of ${fmt(gate.required_above)}` };
  if (amount3.minor > gate.required_above.minor) return { required: true, detail: `${fmt(amount3)} is above ${fmt(gate.required_above)}, so a named person approves it` };
  return { required: false };
}
function heldIdFor(sid, tool, payloadHash2) {
  return (0, import_node_crypto3.createHash)("sha256").update(`scopeblind.held_action.v1\0${sid}\0${tool}\0${payloadHash2}`).digest("hex").slice(0, 24);
}
function sidFromReportUrl(url) {
  try {
    const s = new URL(url).searchParams.get("s");
    return s && /^[0-9a-f]{24}$/.test(s) ? s : null;
  } catch {
    return null;
  }
}
var import_node_crypto3, import_node_fs7, isObj, fmt, RecordReporter;
var init_standard_gate = __esm({
  "src/standard-gate.ts"() {
    "use strict";
    import_node_crypto3 = require("crypto");
    import_node_fs7 = require("fs");
    isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    fmt = (m) => `${m.currency} ${(m.minor / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    RecordReporter = class {
      url;
      sid;
      runId;
      token;
      fetchImpl;
      log;
      queue = [];
      timer = null;
      flushing = Promise.resolve();
      /** Counts for the startup and shutdown lines. */
      sent = 0;
      failed = 0;
      constructor(opts) {
        const sid = sidFromReportUrl(opts.url);
        if (!sid) throw new Error("--report must be the standard page's report URL (https://scopeblind.com/api/standard?s=<id>)");
        this.url = opts.url;
        this.sid = sid;
        this.token = opts.token;
        this.runId = opts.runId;
        this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
        this.log = opts.log ?? ((m) => process.stderr.write(`[PROTECT_MCP] ${m}
`));
      }
      async post(op, body) {
        const resp = await this.fetchImpl(`${this.url}&op=${op}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${this.token}` }, body: JSON.stringify({ sid: this.sid, ...body }), signal: AbortSignal.timeout(8e3) });
        const parsed = await resp.json().catch(() => ({}));
        return { ok: resp.ok, status: resp.status, body: parsed };
      }
      /** Queues one receipt line (and its call line) for the next flush. Never throws. */
      record(receipt, call) {
        this.queue.push({ receipt, call });
        if (!this.timer) this.timer = setTimeout(() => {
          this.timer = null;
          void this.flush();
        }, 800);
        this.timer.unref?.();
      }
      /** Sends everything queued, in order, as one append. */
      flush() {
        this.flushing = this.flushing.then(async () => {
          if (this.queue.length === 0) return;
          const batch = this.queue;
          this.queue = [];
          const receipts = batch.map((b) => b.receipt).filter((r) => !!r).join("\n");
          const calls = batch.map((b) => b.call).filter((c2) => !!c2).join("\n");
          try {
            const r = await this.post("record", { run_id: this.runId, receipts, calls, append: true });
            if (r.ok) this.sent += batch.length;
            else {
              this.failed += batch.length;
              this.log(`Record not accepted by the standard's page (${r.status} ${String(r.body.error ?? "")}); the local chain is intact`);
            }
          } catch (err) {
            this.failed += batch.length;
            this.log(`Record could not reach the standard's page (${err instanceof Error ? err.message : String(err)}); the local chain is intact`);
          }
        });
        return this.flushing;
      }
      /** Posts a held action. Returns the page URL to send the model to, or null when the page could not be reached. */
      async hold(held) {
        try {
          const r = await this.post("held", { ...held, run_id: this.runId });
          if (r.ok && typeof r.body.url === "string") return r.body.url;
          this.log(`Held action not accepted by the standard's page (${r.status} ${String(r.body.error ?? "")})`);
          return null;
        } catch (err) {
          this.log(`Held action could not reach the standard's page (${err instanceof Error ? err.message : String(err)})`);
          return null;
        }
      }
      /** The decision a person recorded for a held action: approve, deny, none yet (null), or unreachable. */
      async decision(hid) {
        try {
          const resp = await this.fetchImpl(`${this.url}&held=${hid}`, { method: "GET", headers: { accept: "application/json" }, signal: AbortSignal.timeout(8e3) });
          if (resp.status === 404) return null;
          const body = await resp.json().catch(() => ({}));
          if (!resp.ok || !body.ok || !body.held) return "unreachable";
          const d = body.held.decision;
          if (!d || d.decision !== "approve" && d.decision !== "deny") return null;
          return { decision: d.decision, approver_key_id: d.approver?.key_id ?? "unknown", digest: d.digest ?? "", note: d.note ?? "" };
        } catch {
          return "unreachable";
        }
      }
    };
  }
});

// src/gateway.ts
var import_node_child_process, import_node_crypto4, import_node_readline, import_node_fs8, import_node_path5, LOG_FILE2, RECEIPTS_FILE, ProtectGateway;
var init_gateway = __esm({
  "src/gateway.ts"() {
    "use strict";
    import_node_child_process = require("child_process");
    import_node_crypto4 = require("crypto");
    import_node_readline = require("readline");
    import_node_fs8 = require("fs");
    init_acta_envelope();
    import_node_path5 = require("path");
    init_policy();
    init_admission();
    init_credentials();
    init_signing();
    init_external_pdp();
    init_cedar_evaluator();
    init_evidence_store();
    init_notifications();
    init_http_server();
    init_action_readback();
    init_standard_gate();
    LOG_FILE2 = ".protect-mcp-log.jsonl";
    RECEIPTS_FILE = ".protect-mcp-receipts.jsonl";
    ProtectGateway = class {
      child = null;
      config;
      rateLimitStore = /* @__PURE__ */ new Map();
      clientReader = null;
      logFilePath;
      receiptFilePath;
      /** s5.7 hash of the last line appended to the receipt file (chain link) */
      lastReceiptHash = null;
      evidenceStore;
      receiptBuffer;
      /** Approval grants keyed by request_id (scoped to the specific action that was requested) */
      approvalStore = /* @__PURE__ */ new Map();
      /** Random nonce generated at startup — required for approval endpoint authentication */
      approvalNonce = (0, import_node_crypto4.randomBytes)(16).toString("hex");
      currentTier = "unknown";
      admissionResult = null;
      /** Notification config for approval gates (SMS, webhook, email) */
      notificationConfig = null;
      /** HTTP transport mode: pending response resolvers keyed by JSON-RPC id */
      pendingResponses = /* @__PURE__ */ new Map();
      httpMode = false;
      /** Loaded Cedar policy set (when policy_engine is "cedar") */
      cedarPolicySet = null;
      /** The signed standard in force (--standard) and the page its record lands on (--report) */
      standard = null;
      reporter = null;
      /** A person's decision on the page, attached to the receipt of the call it decided (keyed by request_id) */
      approvalsToRecord = /* @__PURE__ */ new Map();
      constructor(config) {
        this.config = config;
        this.logFilePath = (0, import_node_path5.join)(process.cwd(), LOG_FILE2);
        this.receiptFilePath = (0, import_node_path5.join)(process.cwd(), RECEIPTS_FILE);
        try {
          const existing = (0, import_node_fs8.readFileSync)(this.receiptFilePath, "utf-8").split("\n").filter((l) => l.trim());
          if (existing.length > 0) this.lastReceiptHash = chainLink(JSON.parse(existing[existing.length - 1]));
        } catch {
        }
        this.evidenceStore = new EvidenceStore();
        this.receiptBuffer = new ReceiptBuffer();
        this.notificationConfig = parseNotificationConfigFromEnv();
        this.standard = config.standard ?? null;
        this.reporter = config.reporter ?? null;
      }
      /**
       * Set the Cedar policy set for local evaluation.
       * Called during CLI startup when --cedar flag is used.
       */
      setCedarPolicies(policySet) {
        this.cedarPolicySet = policySet;
      }
      async start() {
        const { command, args, verbose } = this.config;
        const mode = this.config.enforce ? "enforce" : "shadow";
        if (verbose) {
          this.log(`Starting gateway in ${mode} mode`);
          this.log(`Wrapping: ${command} ${args.join(" ")}`);
          if (this.config.policy) {
            this.log(`Policy digest: ${this.config.policyDigest}`);
          }
          if (isSigningEnabled()) {
            this.log("Signing: enabled (receipts will be signed)");
          }
          if (this.config.credentials) {
            const labels = Object.keys(this.config.credentials);
            this.log(`Credential vault: ${labels.length} credential(s) configured [${labels.join(", ")}]`);
          }
          if (this.config.policy?.policy_engine === "external" || this.config.policy?.policy_engine === "hybrid") {
            this.log(`External PDP: ${this.config.policy.external?.endpoint || "not configured"}`);
          }
        }
        this.log(`Approval nonce: ${this.approvalNonce}`);
        if (this.standard) this.log(`Standard in force: ${this.standard.request_id} (${this.standard.summary})`);
        if (this.reporter) {
          this.log(`Record lands on ${new URL(this.reporter.url).origin}/standard?s=${this.reporter.sid} as run ${this.reporter.runId}`);
          if (!isSigningEnabled()) this.log("Warning: signing is not configured, so only unsigned call lines reach the page; add a signing key to protect-mcp.json for receipts");
          const reporter = this.reporter;
          process.once("beforeExit", () => {
            void reporter.flush();
          });
        }
        const httpPort = parseInt(process.env.PROTECT_MCP_HTTP_PORT || "9876", 10);
        if (httpPort > 0) {
          try {
            startStatusServer(
              { port: httpPort, mode, verbose },
              this.receiptBuffer,
              this.approvalStore,
              this.approvalNonce
            );
          } catch {
            if (verbose) this.log(`HTTP status server could not start on port ${httpPort}`);
          }
        }
        const childEnv = { ...process.env };
        if (this.config.credentials) {
          for (const [label, credConfig] of Object.entries(this.config.credentials)) {
            if (credConfig.inject === "env" && credConfig.name && credConfig.value_env) {
              const envValue = process.env[credConfig.value_env];
              if (envValue) {
                childEnv[credConfig.name] = envValue;
                if (verbose) this.log(`Credential "${label}": injected as env var "${credConfig.name}"`);
              }
            }
          }
        }
        this.child = (0, import_node_child_process.spawn)(command, args, { stdio: ["pipe", "pipe", "pipe"], env: childEnv });
        if (!this.child.stdin || !this.child.stdout || !this.child.stderr) {
          throw new Error("Failed to create pipes to child process");
        }
        this.child.stderr.on("data", (data) => {
          process.stderr.write(data);
        });
        const childReader = (0, import_node_readline.createInterface)({ input: this.child.stdout, crlfDelay: Infinity });
        childReader.on("line", (line) => {
          this.handleServerMessage(line);
        });
        this.clientReader = (0, import_node_readline.createInterface)({ input: process.stdin, crlfDelay: Infinity });
        this.clientReader.on("line", (line) => {
          this.handleClientMessage(line);
        });
        this.child.on("exit", (code2, signal) => {
          if (verbose) this.log(`Child process exited (code=${code2}, signal=${signal})`);
          this.evidenceStore.save();
          process.exit(code2 ?? 1);
        });
        this.child.on("error", (err) => {
          this.log(`Child process error: ${err.message}`);
          process.exit(1);
        });
        process.on("SIGINT", () => this.stop());
        process.on("SIGTERM", () => this.stop());
        process.stdin.on("end", () => {
          if (verbose) this.log("Client stdin closed, closing child stdin");
          if (this.child?.stdin?.writable) this.child.stdin.end();
        });
      }
      setManifest(manifest) {
        this.admissionResult = evaluateTier(manifest, { evidenceStore: this.evidenceStore });
        this.currentTier = this.admissionResult.tier;
        if (this.config.verbose) {
          this.log(`Admission: tier=${this.currentTier} agent=${this.admissionResult.agent_id || "none"}`);
        }
        return this.admissionResult;
      }
      handleClientMessage(raw) {
        const trimmed = raw.trim();
        if (!trimmed) return;
        let message;
        try {
          message = JSON.parse(trimmed);
        } catch {
          this.sendToChild(trimmed);
          return;
        }
        if (message.method === "tools/call" && message.id !== void 0) {
          this.interceptToolCallAsync(message, trimmed);
          return;
        }
        this.sendToChild(trimmed);
      }
      async interceptToolCallAsync(request, raw) {
        const result2 = await this.interceptToolCall(request);
        if (result2) {
          this.sendToClient(JSON.stringify(result2));
        } else {
          const modified = this.injectParamsCredentials(request);
          this.sendToChild(JSON.stringify(modified));
        }
      }
      handleServerMessage(raw) {
        this.sendToClient(raw);
      }
      injectParamsCredentials(request) {
        if (!this.config.credentials) return request;
        const injections = {};
        for (const [label, credConfig] of Object.entries(this.config.credentials)) {
          if (credConfig.inject === "header" || credConfig.inject === "query") {
            const cred = resolveCredential(label, this.config.credentials);
            if (cred.resolved && cred.value && cred.name) {
              injections[cred.name] = cred.value;
            }
          }
        }
        if (Object.keys(injections).length === 0) return request;
        return { ...request, params: { ...request.params, _credentials: injections } };
      }
      async interceptToolCall(request) {
        const toolName = request.params?.name || "unknown";
        const requestId = (0, import_node_crypto4.randomUUID)().slice(0, 12);
        const mode = this.config.enforce ? "enforce" : "shadow";
        const toolInput = request.params?.arguments && typeof request.params.arguments === "object" ? request.params.arguments : request.params || {};
        const actionReadback = buildActionReadback(toolName, toolInput);
        let resolvedAgentKid = this.admissionResult?.agent_id;
        let effectiveToolPolicy;
        if (this.config.multiAgent?.enabled) {
          const paramKid = request.params?._passport_kid;
          if (paramKid) resolvedAgentKid = paramKid;
          const agentOverrides = resolvedAgentKid ? this.config.multiAgent.agentPolicies?.[resolvedAgentKid] : void 0;
          if (agentOverrides && agentOverrides[toolName]) {
            effectiveToolPolicy = { ...getToolPolicy(toolName, this.config.policy), ...agentOverrides[toolName] };
          } else if (!resolvedAgentKid && this.config.multiAgent.unknownAgentPolicy === "deny") {
            this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "unknown_agent_denied", request_id: requestId, tier: this.currentTier, action_readback: actionReadback });
            if (this.config.enforce) {
              return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" denied: unidentified agent`);
            }
            return null;
          } else {
            effectiveToolPolicy = getToolPolicy(toolName, this.config.policy);
          }
          if (this.config.verbose && resolvedAgentKid) {
            this.log(`Multi-agent: resolved kid=${resolvedAgentKid} for tool=${toolName}`);
          }
        } else {
          effectiveToolPolicy = getToolPolicy(toolName, this.config.policy);
        }
        const toolPolicy = effectiveToolPolicy;
        let credentialRef;
        if (this.config.credentials) {
          const cred = resolveCredential(toolName, this.config.credentials);
          if (cred.resolved) {
            credentialRef = cred.label;
          } else if (cred.error && !cred.error.includes("not configured")) {
            this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "credential_error", request_id: requestId, tier: this.currentTier, credential_ref: toolName, action_readback: actionReadback });
            if (this.config.enforce) {
              return this.makeErrorResponse(request.id, -32600, `Credential error for tool "${toolName}"`);
            }
          }
        }
        if (this.standard) {
          const std = this.standard;
          if (std.tools && !std.tools.includes(toolName)) {
            this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "standard_tool_not_allowed", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
            if (this.config.enforce) return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" is not among the tools the standard permits`);
            return null;
          }
          const amount3 = checkAmount(std, toolInput);
          if (!amount3.ok) {
            this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: amount3.reason, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
            if (this.config.enforce) return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" refused by the standard: ${amount3.detail}`);
            return null;
          }
          const person = personRequired(std, toolInput);
          if (person.required) {
            const hid = heldIdFor(this.reporter?.sid ?? std.request_id, toolName, actionReadback.payload_hash);
            const page = this.reporter ? `${new URL(this.reporter.url).origin}/standard?s=${this.reporter.sid}#held-${hid}` : "";
            const localGrant = this.approvalStore.get(`always:${toolName}`);
            const verdict = localGrant && Date.now() < localGrant.expires_at ? { decision: "approve", approver_key_id: "gate", digest: "", note: "granted at the gate" } : this.reporter ? await this.reporter.decision(hid) : null;
            if (verdict === "unreachable") {
              this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "standard_page_unreachable", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
              if (this.config.enforce) return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" needs a named person's approval and the standard's page could not be reached; retry the same call later`);
            } else if (verdict) {
              this.approvalsToRecord.set(requestId, { hid, approver_key_id: verdict.approver_key_id, digest: verdict.digest, page });
              if (verdict.decision === "deny") {
                this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "person_denied", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
                if (this.config.enforce) return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" was denied by ${verdict.approver_key_id} on the standard's page${verdict.note ? `: ${verdict.note}` : ""}`);
              }
            } else {
              const amt = readAmount(toolInput);
              if (this.config.enforce && this.reporter) {
                await this.reporter.hold({ hid, request_id: requestId, tool: toolName, readback: { summary: actionReadback.summary, payload_hash: actionReadback.payload_hash, amount: amt ? amt.minor / 100 : null, currency: amt?.currency || null }, reason: person.detail });
              }
              this.emitDecisionLog({ tool: toolName, decision: "require_approval", reason_code: "standard_requires_person", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
              if (this.config.enforce) {
                const where = page ? `The action is waiting for the named person at ${page}. Tell the user, and retry this exact call once they have decided there; a changed call is a new action.` : `No standard page is configured (--report), so it must be granted at the gate (approval nonce ${this.approvalNonce}, request ID ${requestId}) before a retry.`;
                return {
                  jsonrpc: "2.0",
                  id: request.id,
                  result: {
                    content: [{ type: "text", text: `REQUIRES_APPROVAL: ${person.detail}. Exact action: ${actionReadback.summary}. Payload hash: ${actionReadback.payload_hash.slice(0, 16)}\u2026 ${where}` }],
                    isError: true
                  }
                };
              }
            }
          }
        }
        if (this.config.policy?.policy_engine === "cedar" && this.cedarPolicySet) {
          try {
            const cedarDecision = await evaluateCedar(this.cedarPolicySet, {
              tool: toolName,
              tier: this.currentTier,
              agentId: this.admissionResult?.agent_id,
              // The call's input, so a policy compiled from a standard can read amounts and fields (context.input).
              toolInput
            });
            if (!cedarDecision.allowed) {
              const reason = cedarDecision.reason || "cedar_deny";
              this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: reason, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
              if (this.config.enforce) {
                return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" denied by Cedar policy`);
              }
              return null;
            }
            this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: "cedar_allow", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
            return null;
          } catch (err) {
            if (this.config.verbose) this.log(`Cedar evaluation error: ${err instanceof Error ? err.message : err}`);
          }
        }
        if (this.config.policy?.external && (this.config.policy.policy_engine === "external" || this.config.policy.policy_engine === "hybrid")) {
          try {
            const ctx = buildDecisionContext(toolName, this.currentTier, {
              agentId: this.admissionResult?.agent_id,
              manifestHash: this.admissionResult?.manifest_hash,
              credentialRef,
              mode,
              slug: this.config.slug
            });
            const externalDecision = await queryExternalPDP(ctx, this.config.policy.external);
            if (!externalDecision.allowed) {
              const reason = `external_pdp_deny${externalDecision.reason ? ": " + externalDecision.reason : ""}`;
              this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: reason, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
              if (this.config.enforce) {
                return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" denied by external policy engine`);
              }
              if (this.config.policy.policy_engine === "external") return null;
            }
          } catch (err) {
            if (this.config.verbose) this.log(`External PDP error: ${err instanceof Error ? err.message : err}`);
          }
        }
        if (toolPolicy.min_tier) {
          if (!meetsMinTier(this.currentTier, toolPolicy.min_tier)) {
            this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "tier_insufficient", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
            if (this.config.enforce) {
              return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" requires tier "${toolPolicy.min_tier}"`);
            }
            return null;
          }
        }
        if (toolPolicy.block) {
          this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "policy_block", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
          if (this.config.enforce) {
            return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" is blocked by policy`);
          }
          return null;
        }
        if (toolPolicy.require_approval) {
          const grant = this.approvalStore.get(requestId);
          const alwaysGrant = this.approvalStore.get(`always:${toolName}`);
          if (grant && Date.now() < grant.expires_at || alwaysGrant && Date.now() < alwaysGrant.expires_at) {
            if (grant && grant.mode === "once") this.approvalStore.delete(requestId);
            this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: "approval_granted", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
            return null;
          }
          this.emitDecisionLog({ tool: toolName, decision: "require_approval", reason_code: "requires_human_approval", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
          if (this.notificationConfig) {
            sendApprovalNotification(this.notificationConfig, {
              requestId,
              toolName,
              agentId: this.admissionResult?.agent_id,
              policyName: "default",
              reason: `Policy requires human approval for "${toolName}"`,
              traceUrl: `https://scopeblind.com/trace`,
              approveUrl: void 0,
              // Approve URL provided when HTTP transport is active
              timestamp: (/* @__PURE__ */ new Date()).toISOString()
            }).catch(() => {
            });
          }
          if (this.config.enforce) {
            return {
              jsonrpc: "2.0",
              id: request.id,
              result: {
                content: [
                  {
                    type: "text",
                    text: `REQUIRES_APPROVAL: The tool "${toolName}" requires human approval before execution. Exact action: ${actionReadback.summary}. Payload hash: ${actionReadback.payload_hash.slice(0, 16)}\u2026 Request ID: ${requestId}. Approval nonce: ${this.approvalNonce}. Tell the user you need their approval to use "${toolName}" and will retry when granted. Do NOT retry this tool call until the user explicitly approves it.`
                  }
                ],
                isError: true
              }
            };
          }
          return null;
        }
        const rateSpec = this.getTierRateLimit(toolPolicy, this.currentTier);
        if (rateSpec) {
          try {
            const limit = parseRateLimit(rateSpec);
            const key = `tool:${toolName}:${this.currentTier}`;
            const { allowed, remaining } = checkRateLimit(key, limit, this.rateLimitStore);
            if (!allowed) {
              this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "rate_limit_exceeded", request_id: requestId, rate_limit_remaining: 0, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
              if (this.config.enforce) {
                return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" rate limit exceeded (${rateSpec})`);
              }
              return null;
            }
            this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: "policy_allow", request_id: requestId, rate_limit_remaining: remaining, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
          } catch {
            this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: "default_allow", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
          }
        } else {
          const reasonCode = this.config.enforce ? "policy_allow" : "observe_mode";
          this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: reasonCode, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
        }
        return null;
      }
      getTierRateLimit(policy, tier) {
        if (policy.rate_limits && policy.rate_limits[tier]) {
          const tierLimit = policy.rate_limits[tier];
          return `${tierLimit.max}/${tierLimit.window}`;
        }
        return policy.rate_limit;
      }
      /**
       * Emit a decision log entry with OTel-compatible trace IDs and optional
       * signed receipt generation.
       *
       * @patent Patent-protected construction — decision receipts with configurable
       * disclosure and issuer-blind properties. Covered by Apache 2.0 patent grant
       * for users of this code. Clean-room reimplementation requires a patent license.
       * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
       */
      emitDecisionLog(entry) {
        const mode = this.config.enforce ? "enforce" : "shadow";
        const otelTraceId = entry.otel_trace_id || (0, import_node_crypto4.randomBytes)(16).toString("hex");
        const otelSpanId = entry.otel_span_id || (0, import_node_crypto4.randomBytes)(8).toString("hex");
        const log = {
          v: 2,
          tool: entry.tool || "unknown",
          decision: entry.decision || "allow",
          reason_code: entry.reason_code || "default_allow",
          policy_digest: this.config.policyDigest,
          policy_engine: this.config.policy?.policy_engine || "built-in",
          request_id: entry.request_id || (0, import_node_crypto4.randomUUID)().slice(0, 12),
          timestamp: Date.now(),
          mode,
          ...entry.rate_limit_remaining !== void 0 && { rate_limit_remaining: entry.rate_limit_remaining },
          ...entry.tier && { tier: entry.tier },
          ...entry.credential_ref && { credential_ref: entry.credential_ref },
          ...entry.action_readback && { action_readback: entry.action_readback },
          otel_trace_id: otelTraceId,
          otel_span_id: otelSpanId
        };
        if (this.standard) log.standard = { request_id: this.standard.request_id, digest: this.standard.digest };
        const approval = this.approvalsToRecord.get(log.request_id);
        if (approval) {
          log.approval = approval;
          this.approvalsToRecord.delete(log.request_id);
        }
        const callLine = this.reporter ? JSON.stringify({ tool: log.tool, input: log.action_readback?.payload_preview ?? {}, decision: log.decision, request_id: log.request_id, at: new Date(log.timestamp).toISOString() }) : void 0;
        process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}
`);
        try {
          (0, import_node_fs8.appendFileSync)(this.logFilePath, JSON.stringify(log) + "\n");
        } catch {
        }
        if (isSigningEnabled()) {
          const signed2 = signDecision(log, this.lastReceiptHash || void 0);
          if (signed2.signed) {
            process.stderr.write(`[PROTECT_MCP_RECEIPT] ${signed2.signed}
`);
            try {
              (0, import_node_fs8.appendFileSync)(this.receiptFilePath, signed2.signed + "\n");
              if (signed2.receipt_hash) this.lastReceiptHash = signed2.receipt_hash;
            } catch {
            }
            this.reporter?.record(signed2.signed, callLine);
            this.receiptBuffer.add(log.request_id, signed2.signed);
            if (this.admissionResult?.agent_id) {
              this.evidenceStore.record(this.admissionResult.agent_id, this.config.signing?.issuer || "protect-mcp");
              if (this.evidenceStore.getSummary(this.admissionResult.agent_id).receipt_count % 10 === 0) {
                this.evidenceStore.save();
              }
            }
          } else if (signed2.error) {
            const tombstone = JSON.stringify({
              type: "scopeblind.signing_failure.v1",
              request_id: log.request_id,
              tool: log.tool,
              decision: log.decision,
              error: signed2.error,
              at: new Date(log.timestamp).toISOString()
            });
            try {
              (0, import_node_fs8.appendFileSync)(this.receiptFilePath, tombstone + "\n");
            } catch {
            }
            process.stderr.write(`[PROTECT_MCP_SIGNING_FAILURE] ${tombstone}
`);
          }
        } else if (this.reporter) {
          this.reporter.record(void 0, callLine);
        }
      }
      makeErrorResponse(id5, code2, message) {
        return { jsonrpc: "2.0", id: id5, error: { code: code2, message } };
      }
      sendToChild(message) {
        if (this.child?.stdin?.writable) this.child.stdin.write(message + "\n");
      }
      sendToClient(message) {
        if (this.httpMode) {
          try {
            const parsed = JSON.parse(message);
            if (parsed.id !== void 0 && parsed.id !== null) {
              const pending = this.pendingResponses.get(parsed.id);
              if (pending) {
                clearTimeout(pending.timeout);
                this.pendingResponses.delete(parsed.id);
                pending.resolve(message);
                return;
              }
            }
          } catch {
          }
        }
        process.stdout.write(message + "\n");
      }
      /**
       * Enable HTTP transport mode.
       * In this mode, sendToClient resolves pending promises instead of
       * writing to stdout, and start() skips stdin reading.
       */
      enableHttpMode() {
        this.httpMode = true;
      }
      /**
       * Start in HTTP mode — spawns child process but does NOT read from
       * process.stdin. Requests come in via processRequest() instead.
       */
      async startForHttp() {
        this.httpMode = true;
        const { command, args, verbose } = this.config;
        const mode = this.config.enforce ? "enforce" : "shadow";
        if (verbose) {
          this.log(`Starting gateway in ${mode} mode (HTTP transport)`);
          this.log(`Wrapping: ${command} ${args.join(" ")}`);
        }
        this.log(`Approval nonce: ${this.approvalNonce}`);
        if (this.standard) this.log(`Standard in force: ${this.standard.request_id} (${this.standard.summary})`);
        if (this.reporter) {
          this.log(`Record lands on ${new URL(this.reporter.url).origin}/standard?s=${this.reporter.sid} as run ${this.reporter.runId}`);
          if (!isSigningEnabled()) this.log("Warning: signing is not configured, so only unsigned call lines reach the page; add a signing key to protect-mcp.json for receipts");
          const reporter = this.reporter;
          process.once("beforeExit", () => {
            void reporter.flush();
          });
        }
        const childEnv = { ...process.env };
        if (this.config.credentials) {
          for (const [label, credConfig] of Object.entries(this.config.credentials)) {
            if (credConfig.inject === "env" && credConfig.name && credConfig.value_env) {
              const envValue = process.env[credConfig.value_env];
              if (envValue) {
                childEnv[credConfig.name] = envValue;
                if (verbose) this.log(`Credential "${label}": injected as env var "${credConfig.name}"`);
              }
            }
          }
        }
        this.child = (0, import_node_child_process.spawn)(command, args, { stdio: ["pipe", "pipe", "pipe"], env: childEnv });
        if (!this.child.stdin || !this.child.stdout || !this.child.stderr) {
          throw new Error("Failed to create pipes to child process");
        }
        this.child.stderr.on("data", (data) => {
          process.stderr.write(data);
        });
        const childReader = (0, import_node_readline.createInterface)({ input: this.child.stdout, crlfDelay: Infinity });
        childReader.on("line", (line) => {
          this.handleServerMessage(line);
        });
        this.child.on("exit", (code2, signal) => {
          if (verbose) this.log(`Child process exited (code=${code2}, signal=${signal})`);
          this.evidenceStore.save();
        });
        this.child.on("error", (err) => {
          this.log(`Child process error: ${err.message}`);
        });
      }
      /**
       * Process a JSON-RPC request programmatically (for HTTP transport).
       * Returns a promise that resolves with the JSON-RPC response string.
       */
      async processRequest(jsonRpc) {
        const REQUEST_TIMEOUT_MS = 3e4;
        if (jsonRpc.method === "tools/call" && jsonRpc.id !== void 0) {
          const blocked = await this.interceptToolCall(jsonRpc);
          if (blocked) {
            return JSON.stringify(blocked);
          }
        }
        return new Promise((resolve5, reject) => {
          const id5 = jsonRpc.id;
          if (id5 === void 0 || id5 === null) {
            const modified2 = this.injectParamsCredentials(jsonRpc);
            this.sendToChild(JSON.stringify(modified2));
            resolve5(JSON.stringify({ jsonrpc: "2.0", result: {}, id: null }));
            return;
          }
          const timeout = setTimeout(() => {
            this.pendingResponses.delete(id5);
            resolve5(JSON.stringify({
              jsonrpc: "2.0",
              error: { code: -32e3, message: "Request timeout (30s)" },
              id: id5
            }));
          }, REQUEST_TIMEOUT_MS);
          this.pendingResponses.set(id5, { resolve: resolve5, timeout });
          const modified = this.injectParamsCredentials(jsonRpc);
          this.sendToChild(JSON.stringify(modified));
        });
      }
      log(message) {
        process.stderr.write(`[PROTECT_MCP] ${message}
`);
      }
      stop() {
        this.evidenceStore.save();
        if (this.clientReader) this.clientReader.close();
        if (this.child) {
          this.child.kill("SIGTERM");
          this.child = null;
        }
        process.exit(0);
      }
    };
  }
});

// src/policy-packs.ts
function getPolicyPack(id5) {
  return POLICY_PACKS.find((pack) => pack.id === id5);
}
function policyPackIds() {
  return POLICY_PACKS.map((pack) => pack.id);
}
var header, defaultPermit, filesystemSafe, gitSafe, emailSafe, databaseSafe, cloudSpendSafe, secretsSafe, researchSafe, financeMandateSafe, POLICY_PACKS;
var init_policy_packs = __esm({
  "src/policy-packs.ts"() {
    "use strict";
    header = (id5, description) => `// ScopeBlind protect-mcp policy pack: ${id5}
// ${description}
// Start in shadow mode, review receipts, then run with --enforce.

`;
    defaultPermit = `
// Default posture: allow non-matching calls so teams can start in shadow mode.
// Tighten this after reviewing your local action dashboard.
permit(principal, action == Action::"MCP::Tool::call", resource);
`;
    filesystemSafe = `${header("filesystem-safe", "Block common destructive filesystem and secret-file access patterns.")}// Destructive file tools are never safe as an unattended default.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"delete_file");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"remove_file");

// Secret-like reads by path.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/id_rsa*" ||
    context.input.path like "*/.ssh/*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*credential*"
  )
};

// Dangerous shell operations that mutate or destroy local state.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*rm -rf*" ||
    context.command like "*mkfs*" ||
    context.command like "*dd if=*" ||
    context.command like "*chmod -R 777*" ||
    context.command like "*chown -R*"
  )
};
${defaultPermit}`;
    gitSafe = `${header("git-safe", "Prevent unattended history rewrites, force pushes, and destructive repo cleanup.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*git push --force*" ||
    context.command like "*git push -f*" ||
    context.command like "*git reset --hard*" ||
    context.command like "*git clean -fd*" ||
    context.command like "*git checkout --*" ||
    context.command like "*git branch -D*" ||
    context.command like "*gh repo delete*"
  )
};
${defaultPermit}`;
    emailSafe = `${header("email-safe", "Permit drafting but block unattended external sends.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"mail.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"email.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"send_email");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"gmail.send");

// Shell fallbacks that send mail are blocked too.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*sendmail*" ||
    context.command like "*mailx*" ||
    context.command like "*smtp*"
  )
};
${defaultPermit}`;
    databaseSafe = `${header("database-safe", "Allow reads, block write/admin SQL unless explicitly approved elsewhere.")}forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "query" && (
    context.input.query like "*DROP *" ||
    context.input.query like "*TRUNCATE *" ||
    context.input.query like "*DELETE *" ||
    context.input.query like "*UPDATE *" ||
    context.input.query like "*INSERT *" ||
    context.input.query like "*ALTER *" ||
    context.input.query like "*GRANT *" ||
    context.input.query like "*REVOKE *"
  )
};
${defaultPermit}`;
    cloudSpendSafe = `${header("cloud-spend-safe", "Block cloud actions that can create spend or destroy infrastructure.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*terraform destroy*" ||
    context.command like "*terraform apply*" ||
    context.command like "*pulumi up*" ||
    context.command like "*pulumi destroy*" ||
    context.command like "*aws ec2 run-instances*" ||
    context.command like "*aws rds create*" ||
    context.command like "*gcloud compute instances create*" ||
    context.command like "*az vm create*" ||
    context.command like "*kubectl delete*"
  )
};
${defaultPermit}`;
    secretsSafe = `${header("secrets-safe", "Block secret exfiltration from files, env, shell, and common credential tools.")}forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/.aws/credentials*" ||
    context.input.path like "*/.npmrc*" ||
    context.input.path like "*/.netrc*" ||
    context.input.path like "*/id_rsa*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*token*"
  )
};

forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*printenv*" ||
    context.command like "*env |*" ||
    context.command like "*security find-generic-password*" ||
    context.command like "*aws secretsmanager get-secret-value*" ||
    context.command like "*gcloud secrets versions access*" ||
    context.command like "*op read*"
  )
};
${defaultPermit}`;
    researchSafe = `${header("research-safe", "Let a research agent read and search, but never exfiltrate findings or touch secrets.")}// Reading credentials or secret-like files is never part of research.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/.ssh/*" ||
    context.input.path like "*/.aws/credentials*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*credential*" ||
    context.input.path like "*token*"
  )
};

// Research observes; it does not send or publish externally on its own.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"send_email");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"mail.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"slack.post");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"http.post");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"webhook.send");

// Shell fallbacks that exfiltrate (curl/wget POST, netcat) are blocked too.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*curl*-d*" ||
    context.command like "*curl*--data*" ||
    context.command like "*wget*--post*" ||
    context.command like "*nc *"
  )
};
${defaultPermit}`;
    financeMandateSafe = `${header("finance-mandate-safe", "Block restricted-list and concentration-limit breaches in booking tools.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"pms.book") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"booking.execute") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"booking.ticket") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};

// Default example caps: single-name > 10%, gross > 200%, net > 100%.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_weight_bps" && context.input.post_trade_weight_bps > 1000
};
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_gross_exposure_bps" && context.input.post_trade_gross_exposure_bps > 20000
};
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_net_exposure_bps" && context.input.post_trade_net_exposure_bps > 10000
};
${defaultPermit}`;
    POLICY_PACKS = [
      {
        id: "research-safe",
        name: "Research Safe",
        description: "Lets a research agent read and search, but blocks external sends and secret access.",
        recommendedMode: "shadow-first",
        files: [{ path: "research-safe.cedar", contents: researchSafe }]
      },
      {
        id: "filesystem-safe",
        name: "Filesystem Safe",
        description: "Blocks destructive filesystem calls and secret-like path reads.",
        recommendedMode: "shadow-first",
        files: [{ path: "filesystem-safe.cedar", contents: filesystemSafe }]
      },
      {
        id: "git-safe",
        name: "Git Safe",
        description: "Blocks force pushes, hard resets, destructive cleanup, and repo deletion.",
        recommendedMode: "shadow-first",
        files: [{ path: "git-safe.cedar", contents: gitSafe }]
      },
      {
        id: "email-safe",
        name: "Email Safe",
        description: "Allows drafting workflows while blocking unattended sends.",
        recommendedMode: "shadow-first",
        files: [{ path: "email-safe.cedar", contents: emailSafe }]
      },
      {
        id: "database-safe",
        name: "Database Safe",
        description: "Allows read-oriented DB tools while blocking mutating/admin SQL.",
        recommendedMode: "shadow-first",
        files: [{ path: "database-safe.cedar", contents: databaseSafe }]
      },
      {
        id: "cloud-spend-safe",
        name: "Cloud Spend Safe",
        description: "Blocks obvious cloud spend creation and infrastructure destruction.",
        recommendedMode: "shadow-first",
        files: [{ path: "cloud-spend-safe.cedar", contents: cloudSpendSafe }]
      },
      {
        id: "secrets-safe",
        name: "Secrets Safe",
        description: "Blocks common file, env, shell, and cloud secret exfiltration paths.",
        recommendedMode: "enforce-ready",
        files: [{ path: "secrets-safe.cedar", contents: secretsSafe }]
      },
      {
        id: "finance-mandate-safe",
        name: "Finance Mandate Safe",
        description: "Blocks restricted-list and concentration breaches in booking flows.",
        recommendedMode: "shadow-first",
        files: [{ path: "finance-mandate-safe.cedar", contents: financeMandateSafe }]
      }
    ];
  }
});

// src/webauthn-approval.ts
function createApprovalChallenge(requestId, toolName, agentId, rpId = "scopeblind.com", timeoutSeconds = 300, boundChallenge) {
  const challenge = boundChallenge ?? base64urlEncode((0, import_node_crypto5.randomBytes)(32));
  const contextHash = (0, import_node_crypto5.createHash)("sha256").update(JSON.stringify({ requestId, toolName, agentId, timestamp: Date.now() })).digest("hex");
  return {
    challenge,
    requestId,
    toolName,
    agentId,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    timeoutSeconds,
    rpId,
    contextHash
  };
}
function verifyApprovalAssertion(challenge, assertion, credentialPublicKey, opts = {}) {
  const now = opts.now ?? Date.now();
  const fail3 = (reason, partial = {}) => ({
    valid: false,
    reason,
    credentialId: assertion.credentialId,
    authenticatorType: "unknown",
    userVerified: false,
    signCount: 0,
    contextHash: challenge.contextHash,
    approvedAt: new Date(now).toISOString(),
    ...partial
  });
  const createdAt = new Date(challenge.createdAt).getTime();
  if (now - createdAt > challenge.timeoutSeconds * 1e3) return fail3("challenge_expired");
  if (!credentialPublicKey?.publicKeyHex) return fail3("missing_credential_public_key");
  const clientDataBytes = base64urlDecode(assertion.clientDataJSON);
  let clientData;
  try {
    clientData = JSON.parse(Buffer.from(clientDataBytes).toString("utf8"));
  } catch {
    return fail3("client_data_parse_error");
  }
  if (clientData.type !== "webauthn.get") return fail3("wrong_client_data_type");
  if (!constantTimeStrEqual(clientData.challenge ?? "", challenge.challenge)) return fail3("challenge_mismatch");
  const allowedOrigins = opts.expectedOrigin ? Array.isArray(opts.expectedOrigin) ? opts.expectedOrigin : [opts.expectedOrigin] : [`https://${challenge.rpId}`];
  if (!clientData.origin || !allowedOrigins.includes(clientData.origin)) return fail3("origin_mismatch");
  const authData = base64urlDecode(assertion.authenticatorData);
  if (authData.length < 37) return fail3("authenticator_data_too_short");
  const rpIdHash = authData.slice(0, 32);
  const expectedRpIdHash = (0, import_sha2562.sha256)(new TextEncoder().encode(challenge.rpId));
  if (!bytesEqual(rpIdHash, expectedRpIdHash)) return fail3("rp_id_hash_mismatch");
  const flags = authData[32];
  const userPresent = !!(flags & 1);
  const userVerified = !!(flags & 4);
  if (!userPresent) return fail3("user_not_present");
  if ((opts.requireUserVerification ?? true) && !userVerified) return fail3("user_verification_required", { userVerified });
  const signCount = authData[33] << 24 | authData[34] << 16 | authData[35] << 8 | authData[36];
  if (typeof opts.prevSignCount === "number" && signCount !== 0 && signCount <= opts.prevSignCount) {
    return fail3("sign_count_regression", { userVerified, signCount });
  }
  const signedData = concatBytes(authData, (0, import_sha2562.sha256)(clientDataBytes));
  const sigBytes = base64urlDecode(assertion.signature);
  let sigOk = false;
  try {
    if (credentialPublicKey.alg === -7) {
      sigOk = import_p256.p256.verify(sigBytes, (0, import_sha2562.sha256)(signedData), (0, import_utils2.hexToBytes)(credentialPublicKey.publicKeyHex), { format: "der" });
    } else if (credentialPublicKey.alg === -8) {
      sigOk = import_ed255192.ed25519.verify(sigBytes, signedData, (0, import_utils2.hexToBytes)(credentialPublicKey.publicKeyHex));
    } else {
      return fail3("unsupported_algorithm", { userVerified, signCount });
    }
  } catch {
    sigOk = false;
  }
  if (!sigOk) return fail3("invalid_signature", { userVerified, signCount });
  return {
    valid: true,
    credentialId: assertion.credentialId,
    // Heuristic: platform authenticators (TouchID/FaceID/Hello) report UV; roaming
    // keys without a PIN are UP-only. Attachment is authoritative only at registration.
    authenticatorType: userVerified ? "platform" : "cross-platform",
    userVerified,
    signCount,
    contextHash: challenge.contextHash,
    approvedAt: new Date(now).toISOString()
  };
}
function base64urlEncode(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(str2) {
  const base64 = str2.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}
function concatBytes(a, b) {
  const out2 = new Uint8Array(a.length + b.length);
  out2.set(a, 0);
  out2.set(b, a.length);
  return out2;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  return (0, import_node_crypto5.timingSafeEqual)(Buffer.from(a), Buffer.from(b));
}
function constantTimeStrEqual(a, b) {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return (0, import_node_crypto5.timingSafeEqual)(ab, bb);
}
var import_node_crypto5, import_p256, import_ed255192, import_sha2562, import_utils2;
var init_webauthn_approval = __esm({
  "src/webauthn-approval.ts"() {
    "use strict";
    import_node_crypto5 = require("crypto");
    import_p256 = require("@noble/curves/p256");
    import_ed255192 = require("@noble/curves/ed25519");
    import_sha2562 = require("@noble/hashes/sha256");
    import_utils2 = require("@noble/hashes/utils");
  }
});

// src/mandate-lifecycle.ts
function nowIso(now) {
  return (now || /* @__PURE__ */ new Date()).toISOString();
}
function mustIso(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be an ISO-8601 timestamp`);
  return parsed;
}
function safePolicyFileName(name) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*\.cedar$/.test(name) && !name.includes("..");
}
function stableDigest(value) {
  return `sha256:${SHA256(Buffer.from(canonicalize(value), "utf-8"))}`;
}
function controllerIdentity(c2) {
  return c2.type === "ed25519" ? { id: c2.id, label: c2.label, type: c2.type, public_key: c2.public_key.toLowerCase() } : { id: c2.id, label: c2.label, type: c2.type, credential_id: c2.credential_id, credential_public_key: c2.credential_public_key };
}
function controllersDigest(controllers) {
  const identities = controllers.map(controllerIdentity).sort((a, b) => String(a.id) < String(b.id) ? -1 : String(a.id) > String(b.id) ? 1 : 0);
  return stableDigest(identities);
}
function controllerKeyMaterial(c2) {
  return (c2.type === "ed25519" ? c2.public_key : c2.credential_public_key?.publicKeyHex || "").toLowerCase();
}
function policyApprovalChallenge(proposal, controllerId) {
  return (0, import_node_crypto6.createHash)("sha256").update(Buffer.from(canonicalize({
    purpose: "scopeblind:policy-change",
    proposed_by: proposal.proposed_by,
    proposal_id: proposal.proposal_id,
    proposal_digest: proposal.proposal_digest,
    base_policy_digest: proposal.base_policy_digest,
    proposed_policy_digest: proposal.proposed_policy_digest,
    expires_at: proposal.expires_at,
    controller_id: controllerId
  }), "utf-8")).digest("base64url");
}
function mandatePaths(cedarDir) {
  const absolute = (0, import_node_path7.resolve)(cedarDir);
  const parent = (0, import_node_path7.dirname)(absolute);
  const base = (0, import_node_path7.basename)(absolute);
  return {
    registry: (0, import_node_path7.join)(parent, `.${base}.scopeblind-mandate-registry.json`),
    snapshots: (0, import_node_path7.join)(parent, `.${base}.scopeblind-mandate-snapshots`),
    auditLog: (0, import_node_path7.join)(parent, `.${base}.scopeblind-mandate-history.jsonl`)
  };
}
function loadGateSigner(keyPath) {
  const raw = JSON.parse((0, import_node_fs11.readFileSync)(keyPath, "utf-8"));
  if (typeof raw.privateKey !== "string" || !/^[0-9a-f]{64}$/i.test(raw.privateKey)) {
    throw new Error("gate key must contain a 32-byte hexadecimal privateKey");
  }
  if (typeof raw.publicKey !== "string" || !/^[0-9a-f]{64}$/i.test(raw.publicKey)) {
    throw new Error("gate key must contain a 32-byte hexadecimal publicKey");
  }
  if (typeof raw.kid !== "string" || raw.kid.length === 0) {
    throw new Error("gate key must contain a non-empty kid");
  }
  return {
    privateKey: raw.privateKey.toLowerCase(),
    publicKey: raw.publicKey.toLowerCase(),
    kid: raw.kid,
    ...typeof raw.issuer === "string" ? { issuer: raw.issuer } : {}
  };
}
function snapshotFromDirectory(cedarDir, compiledAt) {
  const entries = (0, import_node_fs11.readdirSync)(cedarDir, { encoding: "utf-8" }).filter((name) => name.endsWith(".cedar")).sort();
  if (entries.length === 0) throw new Error(`no Cedar policy files found in ${cedarDir}`);
  const files = entries.map((name) => {
    if (!safePolicyFileName(name)) throw new Error(`unsafe Cedar policy filename: ${name}`);
    const content = (0, import_node_fs11.readFileSync)((0, import_node_path7.join)(cedarDir, name), "utf-8");
    return { name, content, sha256: SHA256(Buffer.from(content, "utf-8")) };
  });
  const digest = digestPolicyFiles("cedar", files).policy_digest;
  return { engine: "cedar", policy_digest: digest, files, compiled_at: compiledAt || nowIso() };
}
function assertSnapshot(snapshot) {
  if (!snapshot || snapshot.engine !== "cedar" || !Array.isArray(snapshot.files) || snapshot.files.length === 0) {
    throw new Error("invalid Cedar policy snapshot");
  }
  for (const file of snapshot.files) {
    if (!safePolicyFileName(file.name)) throw new Error(`unsafe policy filename: ${file.name}`);
    if (SHA256(Buffer.from(file.content, "utf-8")) !== file.sha256) {
      throw new Error(`policy snapshot content hash mismatch: ${file.name}`);
    }
  }
  const actual = digestPolicyFiles("cedar", snapshot.files).policy_digest;
  if (actual !== snapshot.policy_digest) throw new Error("policy snapshot digest mismatch");
}
function signLifecycleEvent(signer, fields, issuedAt) {
  return createReceiptEnvelope({
    type: "scopeblind.mandate-transition.v1",
    ...fields,
    gate_public_key: signer.publicKey,
    ...signer.issuer ? { gate_issuer: signer.issuer } : {}
  }, signer.privateKey, signer.kid, issuedAt).envelope;
}
function verifyGateEnvelope(envelope3, gate) {
  const check = verifyReceipt(envelope3, gate.public_key);
  if (!check.valid) return false;
  const payload = envelope3.payload;
  return payload.issuer_id === gate.kid && payload.gate_public_key === gate.public_key;
}
function writeAtomic(path, contents) {
  const parent = (0, import_node_path7.dirname)(path);
  (0, import_node_fs11.mkdirSync)(parent, { recursive: true });
  const temp = (0, import_node_path7.join)(parent, `.${(0, import_node_path7.basename)(path)}.${process.pid}.${(0, import_node_crypto6.randomUUID)()}.tmp`);
  try {
    (0, import_node_fs11.writeFileSync)(temp, contents, { encoding: "utf-8", mode: 384 });
    (0, import_node_fs11.renameSync)(temp, path);
  } finally {
    if ((0, import_node_fs11.existsSync)(temp)) (0, import_node_fs11.rmSync)(temp, { force: true });
  }
}
function persistRegistry(cedarDir, registry) {
  registry.updated_at = nowIso();
  const paths = mandatePaths(cedarDir);
  writeAtomic(paths.registry, JSON.stringify(registry, null, 2) + "\n");
  const last = registry.history[registry.history.length - 1];
  if (last) {
    (0, import_node_fs11.writeFileSync)(paths.auditLog, JSON.stringify(last) + "\n", { encoding: "utf-8", flag: "a", mode: 384 });
  }
}
function persistSnapshot(cedarDir, snapshot) {
  const paths = mandatePaths(cedarDir);
  (0, import_node_fs11.mkdirSync)(paths.snapshots, { recursive: true, mode: 448 });
  const name = `${snapshot.policy_digest.replace(/^sha256:/, "")}.json`;
  const output = (0, import_node_path7.join)(paths.snapshots, name);
  if (!(0, import_node_fs11.existsSync)(output)) writeAtomic(output, JSON.stringify(snapshot, null, 2) + "\n");
}
function sourceStatements(snapshot) {
  const byFile = /* @__PURE__ */ new Map();
  for (const file of snapshot.files) {
    const statements = file.content.split(/;\s*(?:\r?\n|$)/g).map((s) => s.replace(/\/\/[^\n]*/g, "").trim()).filter((s) => /^(permit|forbid)\s*\(/.test(s)).map((s) => `${s};`);
    byFile.set(file.name, new Set(statements));
  }
  return byFile;
}
function describePolicyDiff(before, after) {
  assertSnapshot(before);
  assertSnapshot(after);
  const beforeStatements = sourceStatements(before);
  const afterStatements = sourceStatements(after);
  const names = [.../* @__PURE__ */ new Set([...beforeStatements.keys(), ...afterStatements.keys()])].sort();
  const added = [];
  const removed = [];
  for (const name of names) {
    const oldSet = beforeStatements.get(name) || /* @__PURE__ */ new Set();
    const newSet = afterStatements.get(name) || /* @__PURE__ */ new Set();
    for (const statement of newSet) if (!oldSet.has(statement)) added.push(`${name}: ${statement}`);
    for (const statement of oldSet) if (!newSet.has(statement)) removed.push(`${name}: ${statement}`);
  }
  const beforeFiles = new Map(before.files.map((file) => [file.name, file.sha256]));
  const afterFiles = new Map(after.files.map((file) => [file.name, file.sha256]));
  const changedFiles = names.filter((name) => beforeFiles.get(name) !== afterFiles.get(name)).map((name) => ({ name, before_sha256: beforeFiles.get(name) || null, after_sha256: afterFiles.get(name) || null }));
  const plainEnglish = [];
  if (added.length) plainEnglish.push(`Adds ${added.length} executable policy statement${added.length === 1 ? "" : "s"}: the lines are shown below exactly as compiled.`);
  if (removed.length) plainEnglish.push(`Removes ${removed.length} executable policy statement${removed.length === 1 ? "" : "s"}: removed protections are shown below exactly as compiled.`);
  if (!added.length && !removed.length && changedFiles.length) plainEnglish.push("Changes policy file bytes without changing a recognisable permit or forbid statement; review the exact file digest change before approval.");
  if (!changedFiles.length) plainEnglish.push("No executable policy change was detected. The proposal cannot be used to widen a mandate.");
  return { added_statements: added, removed_statements: removed, changed_files: changedFiles, plain_english: plainEnglish };
}
function assertController(controller) {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(controller.id)) throw new Error("controller id is invalid");
  if (!controller.label.trim()) throw new Error("controller label is required");
  if (controller.type === "ed25519" && !/^[0-9a-f]{64}$/i.test(controller.public_key)) {
    throw new Error(`controller ${controller.id} requires a 32-byte Ed25519 public key`);
  }
  if (controller.type === "webauthn" && (!controller.credential_id || !controller.credential_public_key?.publicKeyHex)) {
    throw new Error(`controller ${controller.id} requires a registered WebAuthn credential`);
  }
}
function proposalUnsigned(input) {
  return {
    schema: input.schema,
    proposal_id: input.proposal_id,
    created_at: input.created_at,
    expires_at: input.expires_at,
    proposed_by: input.proposed_by,
    base_policy_digest: input.base_policy_digest,
    proposed_policy_digest: input.proposed_policy_digest,
    denial_origin: input.denial_origin,
    reason: input.reason,
    diff: input.diff,
    candidate: input.candidate
  };
}
function approvalDigest(approval) {
  return stableDigest(approval);
}
function transition(registry, signer, event, headBefore, headAfter, fields = {}, at2 = nowIso()) {
  const sequence = registry.history.length + 1;
  const body = {
    event,
    registry_id: registry.registry_id,
    sequence,
    head_before: headBefore,
    head_after: headAfter,
    ...fields
  };
  return {
    sequence,
    event,
    occurred_at: at2,
    head_before: headBefore,
    head_after: headAfter,
    ...fields,
    transition_receipt: signLifecycleEvent(signer, body, at2)
  };
}
function initializeMandateRegistry(input) {
  const { cedarDir, signer, controllers } = input;
  const paths = mandatePaths(cedarDir);
  if ((0, import_node_fs11.existsSync)(paths.registry)) throw new Error(`managed mandate registry already exists: ${paths.registry}`);
  if (!controllers.length) throw new Error("at least one distinct controller is required before managing a mandate");
  const ids = /* @__PURE__ */ new Set();
  for (const controller of controllers) {
    assertController(controller);
    if (ids.has(controller.id)) throw new Error(`duplicate controller id: ${controller.id}`);
    if (controller.id === signer.kid) throw new Error("the gate signer cannot be registered as a mandate controller");
    if (controllerKeyMaterial(controller) === signer.publicKey.toLowerCase()) {
      throw new Error("the gate signing key cannot also be a mandate controller key");
    }
    ids.add(controller.id);
  }
  const created = nowIso(input.now);
  const baseline = snapshotFromDirectory(cedarDir, created);
  const registryId = `sb:mandate:${SHA256(`${signer.kid}|${baseline.policy_digest}`).slice(0, 24)}`;
  const compilation = signLifecycleEvent(signer, {
    event: "compiled",
    registry_id: registryId,
    policy_digest: baseline.policy_digest,
    snapshot_digest: stableDigest(baseline)
  }, created);
  const registry = {
    schema: MANDATE_REGISTRY_SCHEMA,
    registry_id: registryId,
    created_at: created,
    updated_at: created,
    gate: { kid: signer.kid, public_key: signer.publicKey, ...signer.issuer ? { issuer: signer.issuer } : {} },
    controllers,
    active: {
      policy_digest: baseline.policy_digest,
      baseline_policy_digest: baseline.policy_digest,
      activated_at: created,
      compilation_receipt: compilation
    },
    policies: { [baseline.policy_digest]: baseline },
    proposals: {},
    approvals: {},
    pending_webauthn: {},
    history: []
  };
  registry.history.push(transition(registry, signer, "initialized", null, baseline.policy_digest, {
    policy_digest: baseline.policy_digest,
    controllers_digest: controllersDigest(controllers)
  }, created));
  persistSnapshot(cedarDir, baseline);
  persistRegistry(cedarDir, registry);
  return registry;
}
function loadMandateRegistry(cedarDir) {
  const path = mandatePaths(cedarDir).registry;
  if (!(0, import_node_fs11.existsSync)(path)) return null;
  try {
    return JSON.parse((0, import_node_fs11.readFileSync)(path, "utf-8"));
  } catch (error) {
    throw new Error(`could not parse mandate registry: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}
function verifyDirectApproval(registry, proposal, approval) {
  const controller = registry.controllers.find((candidate) => candidate.id === approval.controller_id);
  if (!controller || controller.type !== "ed25519") return "controller_not_registered";
  const check = verifyReceipt(approval.approval_receipt, controller.public_key);
  if (!check.valid) return `approval_${check.error || "signature_invalid"}`;
  const payload = approval.approval_receipt.payload;
  if (payload.type !== MANDATE_APPROVAL_SCHEMA) return "approval_schema_invalid";
  if (payload.proposal_id !== proposal.proposal_id || payload.proposal_digest !== proposal.proposal_digest) return "approval_not_bound_to_proposal";
  if (payload.controller_id !== controller.id || payload.decision !== "approve") return "approval_controller_or_decision_invalid";
  if (approval.approval_receipt.signature.kid !== controller.id) return "approval_signer_kid_invalid";
  return null;
}
function verifyWebAuthnApproval(registry, proposal, approval) {
  const controller = registry.controllers.find((candidate) => candidate.id === approval.controller_id);
  if (!controller || controller.type !== "webauthn") return "controller_not_registered";
  if (approval.challenge.requestId !== proposal.proposal_id || approval.challenge.toolName !== "scopeblind:policy-change" || approval.challenge.challenge !== policyApprovalChallenge(proposal, controller.id)) {
    return "approval_not_bound_to_proposal";
  }
  if (approval.assertion.credentialId !== controller.credential_id) return "approval_credential_not_registered";
  const verified = verifyApprovalAssertion(approval.challenge, approval.assertion, controller.credential_public_key, {
    expectedOrigin: approval.expected_origin,
    requireUserVerification: true,
    now: Date.parse(approval.approved_at)
  });
  if (!verified.valid || !verified.userVerified) return `approval_${verified.reason || "webauthn_invalid"}`;
  if (!approval.result.valid || approval.result.contextHash !== verified.contextHash) return "approval_result_invalid";
  return null;
}
function verifyProposal(registry, proposal) {
  if (proposal.schema !== MANDATE_PROPOSAL_SCHEMA) return "proposal_schema_invalid";
  const unsigned = proposalUnsigned(proposal);
  if (stableDigest(unsigned) !== proposal.proposal_digest) return "proposal_digest_invalid";
  if (!verifyGateEnvelope(proposal.proposal_receipt, registry.gate)) return "proposal_signature_invalid";
  const payload = proposal.proposal_receipt.payload;
  if (payload.type !== MANDATE_PROPOSAL_SCHEMA || payload.proposal_id !== proposal.proposal_id || payload.proposal_digest !== proposal.proposal_digest) {
    return "proposal_receipt_binding_invalid";
  }
  if (payload.registry_id !== registry.registry_id) return "proposal_registry_mismatch";
  if (proposal.proposed_by.gate_kid !== registry.gate.kid || proposal.proposed_by.gate_public_key !== registry.gate.public_key) {
    return "proposal_gate_identity_invalid";
  }
  const denialCheck = verifyReceipt(proposal.denial_origin.receipt, registry.gate.public_key);
  if (!denialCheck.valid || proposal.denial_origin.receipt_hash !== (denialCheck.hash || receiptHash(proposal.denial_origin.receipt))) {
    return "proposal_denial_receipt_invalid";
  }
  const denialPayload = proposal.denial_origin.receipt.payload;
  if (denialPayload.type !== "protectmcp:decision" || denialPayload.decision !== "deny" || denialPayload.policy_digest !== proposal.base_policy_digest || denialPayload.request_id !== proposal.denial_origin.request_id || denialPayload.tool_name !== proposal.denial_origin.tool) {
    return "proposal_denial_binding_invalid";
  }
  try {
    assertSnapshot(proposal.candidate);
  } catch {
    return "proposal_snapshot_invalid";
  }
  if (proposal.candidate.policy_digest !== proposal.proposed_policy_digest) return "proposal_snapshot_digest_invalid";
  return null;
}
function verifyMandateRegistry(registry, now = /* @__PURE__ */ new Date()) {
  try {
    if (!registry || registry.schema !== MANDATE_REGISTRY_SCHEMA) return { valid: false, code: "unknown_registry_schema", message: "Registry schema is not recognised." };
    if (!registry.gate?.kid || !/^[0-9a-f]{64}$/i.test(registry.gate.public_key)) return { valid: false, code: "gate_identity_invalid", message: "Registry gate identity is malformed." };
    const controllerIds = /* @__PURE__ */ new Set();
    for (const controller of registry.controllers || []) {
      assertController(controller);
      if (controllerIds.has(controller.id)) return { valid: false, code: "duplicate_controller", message: `Controller ${controller.id} appears more than once.` };
      if (controller.id === registry.gate.kid || controllerKeyMaterial(controller) === registry.gate.public_key.toLowerCase()) {
        return { valid: false, code: "gate_is_controller", message: "The gate signer cannot be a mandate controller." };
      }
      controllerIds.add(controller.id);
    }
    if (!registry.controllers.length) return { valid: false, code: "missing_controller", message: "Managed policy has no controller." };
    for (const [digest, snapshot] of Object.entries(registry.policies || {})) {
      assertSnapshot(snapshot);
      if (digest !== snapshot.policy_digest) return { valid: false, code: "snapshot_map_mismatch", message: "A stored policy snapshot is addressed by the wrong digest." };
    }
    const activeSnapshot = registry.policies?.[registry.active?.policy_digest];
    if (!activeSnapshot) return { valid: false, code: "active_snapshot_missing", message: "The active policy head has no compiled snapshot." };
    if (!verifyGateEnvelope(registry.active.compilation_receipt, registry.gate)) return { valid: false, code: "active_compilation_signature_invalid", message: "The active compiled policy is not signed by the configured gate." };
    const compilationPayload = registry.active.compilation_receipt.payload;
    if (compilationPayload.policy_digest !== registry.active.policy_digest) return { valid: false, code: "active_compilation_binding_invalid", message: "The signed compiled policy does not bind the active head." };
    let priorHash = null;
    let currentHead = null;
    let currentExpiry = null;
    let currentBaseline = null;
    let currentProposalId = null;
    for (let index = 0; index < registry.history.length; index += 1) {
      const item = registry.history[index];
      if (item.sequence !== index + 1 || !verifyGateEnvelope(item.transition_receipt, registry.gate)) {
        return { valid: false, code: "transition_signature_invalid", message: "A policy transition is missing or has an invalid gate signature." };
      }
      const payload = item.transition_receipt.payload;
      if (payload.registry_id !== registry.registry_id || payload.sequence !== item.sequence || payload.event !== item.event) {
        return { valid: false, code: "transition_binding_invalid", message: "A signed transition does not bind this registry state." };
      }
      if ((payload.head_before ?? null) !== (item.head_before ?? null) || (payload.head_after ?? null) !== (item.head_after ?? null) || (payload.proposal_id ?? null) !== (item.proposal_id ?? null) || (payload.approval_digest ?? null) !== (item.approval_digest ?? null) || (payload.policy_digest ?? null) !== (item.policy_digest ?? null) || (payload.controllers_digest ?? null) !== (item.controllers_digest ?? null) || (payload.expiry ?? null) !== (item.expiry ?? null)) {
        return { valid: false, code: "transition_state_mismatch", message: "Displayed policy transition state does not match the signed transition." };
      }
      if (item.event === "initialized") {
        const derived = controllersDigest(registry.controllers);
        if (!payload.controllers_digest || payload.controllers_digest !== derived) {
          return { valid: false, code: "controller_set_unanchored", message: "The controller set does not match the gate-signed controller-set digest. A controller may have been injected or a key swapped." };
        }
      }
      if (item.head_before !== currentHead) {
        return { valid: false, code: "transition_head_chain_invalid", message: "Policy transition heads are discontinuous." };
      }
      const hash = stableDigest(item.transition_receipt);
      if (priorHash && payload.previous_transition_hash !== priorHash) {
        return { valid: false, code: "transition_chain_invalid", message: "Policy transition chain is discontinuous." };
      }
      priorHash = hash;
      currentHead = item.head_after;
      const pExpiry = payload.expiry || null;
      const pProposalId = payload.proposal_id || null;
      const pHeadBefore = payload.head_before ?? null;
      const pHeadAfter = payload.head_after || "";
      if (item.event === "initialized") {
        currentBaseline = pHeadAfter;
        currentExpiry = null;
        currentProposalId = null;
      } else if (item.event === "policy_activated") {
        currentBaseline = pHeadBefore;
        currentExpiry = pExpiry;
        currentProposalId = pProposalId;
      } else if (item.event === "policy_expired_reverted") {
        currentBaseline = pHeadAfter;
        currentExpiry = null;
        currentProposalId = null;
      }
    }
    if (currentHead !== registry.active.policy_digest) return { valid: false, code: "active_head_transition_mismatch", message: "Active policy head does not match the signed transition chain." };
    if ((registry.active.expires_at || null) !== currentExpiry) {
      return { valid: false, code: "active_expiry_mismatch", message: "The active grant expiry does not match the gate-signed transition chain (stripped or extended)." };
    }
    if (registry.active.baseline_policy_digest !== currentBaseline) {
      return { valid: false, code: "active_baseline_mismatch", message: "The active baseline policy digest does not match the gate-signed transition chain." };
    }
    if ((registry.active.proposal_id || null) !== currentProposalId) {
      return { valid: false, code: "active_proposal_mismatch", message: "The active proposal id does not match the gate-signed transition chain." };
    }
    const usedDenials = /* @__PURE__ */ new Set();
    for (const proposal of Object.values(registry.proposals || {})) {
      const error = verifyProposal(registry, proposal);
      if (error) return { valid: false, code: error, message: "A policy proposal cannot be verified." };
      if (usedDenials.has(proposal.denial_origin.receipt_hash)) {
        return { valid: false, code: "denial_receipt_reused", message: "A denial receipt was used for more than one policy proposal." };
      }
      usedDenials.add(proposal.denial_origin.receipt_hash);
    }
    for (const [proposalId, approval] of Object.entries(registry.approvals || {})) {
      const proposal = registry.proposals[proposalId];
      if (!proposal) return { valid: false, code: "approval_without_proposal", message: "A controller approval refers to no proposal." };
      const error = approval.method === "ed25519" ? verifyDirectApproval(registry, proposal, approval) : verifyWebAuthnApproval(registry, proposal, approval);
      if (error) return { valid: false, code: error, message: "A controller approval cannot be verified." };
    }
    for (const item of registry.history) {
      if (item.event !== "proposal_approved" && item.event !== "policy_activated") continue;
      if (!item.proposal_id || !item.approval_digest) return { valid: false, code: "activation_approval_missing", message: "A policy activation lacks its proposal or controller approval reference." };
      const approval = registry.approvals[item.proposal_id];
      const proposal = registry.proposals[item.proposal_id];
      if (!approval || !proposal || approvalDigest(approval) !== item.approval_digest) {
        return { valid: false, code: "activation_approval_mismatch", message: "A policy activation does not bind the exact verified controller approval." };
      }
      if (item.event === "policy_activated" && (item.head_before !== proposal.base_policy_digest || item.head_after !== proposal.proposed_policy_digest)) {
        return { valid: false, code: "activation_policy_mismatch", message: "A policy activation does not bind the proposed policy transition." };
      }
    }
    if (registry.active.expires_at && Date.parse(registry.active.expires_at) <= now.getTime()) {
      return { valid: false, code: "active_grant_expired", message: "The active widened policy has expired and must be reverted before enforcement." };
    }
    return { valid: true, registry };
  } catch (error) {
    return { valid: false, code: "registry_verification_error", message: error instanceof Error ? error.message : "Registry verification failed." };
  }
}
function installSnapshotAtomically(cedarDir, snapshot) {
  assertSnapshot(snapshot);
  const target = (0, import_node_path7.resolve)(cedarDir);
  const parent = (0, import_node_path7.dirname)(target);
  const base = (0, import_node_path7.basename)(target);
  if (!(0, import_node_fs11.existsSync)(target) || !(0, import_node_fs11.statSync)(target).isDirectory()) throw new Error(`managed Cedar directory is missing: ${target}`);
  const stage = (0, import_node_path7.join)(parent, `.${base}.scopeblind-stage-${process.pid}-${(0, import_node_crypto6.randomUUID)()}`);
  const backup = (0, import_node_path7.join)(parent, `.${base}.scopeblind-backup-${process.pid}-${(0, import_node_crypto6.randomUUID)()}`);
  (0, import_node_fs11.mkdirSync)(stage, { recursive: true, mode: 448 });
  try {
    for (const file of snapshot.files) (0, import_node_fs11.writeFileSync)((0, import_node_path7.join)(stage, file.name), file.content, { encoding: "utf-8", mode: 384 });
    (0, import_node_fs11.renameSync)(target, backup);
    try {
      (0, import_node_fs11.renameSync)(stage, target);
    } catch (error) {
      (0, import_node_fs11.renameSync)(backup, target);
      throw error;
    }
    (0, import_node_fs11.rmSync)(backup, { recursive: true, force: true });
  } finally {
    if ((0, import_node_fs11.existsSync)(stage)) (0, import_node_fs11.rmSync)(stage, { recursive: true, force: true });
    if ((0, import_node_fs11.existsSync)(backup) && !(0, import_node_fs11.existsSync)(target)) (0, import_node_fs11.renameSync)(backup, target);
  }
}
function addTransition(registry, signer, item, at2) {
  const previous = registry.history[registry.history.length - 1];
  const previousTransitionHash = previous ? stableDigest(previous.transition_receipt) : void 0;
  const trans = transition(registry, signer, item.event, item.head_before, item.head_after, {
    ...item.proposal_id ? { proposal_id: item.proposal_id } : {},
    ...item.approval_digest ? { approval_digest: item.approval_digest } : {},
    ...item.policy_digest ? { policy_digest: item.policy_digest } : {},
    ...item.expiry ? { expiry: item.expiry } : {},
    ...previousTransitionHash ? { previous_transition_hash: previousTransitionHash } : {}
  }, at2 || item.occurred_at);
  registry.history.push(trans);
  return trans;
}
function createPolicyProposal(input) {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error("managed mandate registry not initialized");
  const integrity = verifyMandateRegistry(registry, input.now);
  if (!integrity.valid) throw new Error(`cannot propose against invalid registry: ${integrity.code}`);
  if (input.signer.kid !== registry.gate.kid || input.signer.publicKey !== registry.gate.public_key) throw new Error("proposal signer does not match the registered gate");
  const receiptCheck = verifyReceipt(input.denialReceipt, registry.gate.public_key);
  if (!receiptCheck.valid) throw new Error("proposal origin must be a valid gate-signed denial receipt");
  const receipt = input.denialReceipt.payload;
  if (receipt.type !== "protectmcp:decision" || receipt.decision !== "deny") throw new Error("proposal origin must be a denied protect-mcp decision");
  if (receipt.policy_digest !== registry.active.policy_digest) throw new Error("proposal origin was denied under a different policy head");
  const expiresAtMs = mustIso(input.expiresAt, "proposal expiry");
  const createdAt = nowIso(input.now);
  if (expiresAtMs <= Date.parse(createdAt)) throw new Error("proposal expiry must be in the future");
  const candidate = snapshotFromDirectory(input.candidateDir, createdAt);
  if (candidate.policy_digest === registry.active.policy_digest) throw new Error("candidate policy is identical to the active policy");
  if (registry.active.expires_at) throw new Error("a temporary widening is already active; let it expire or revert to baseline before proposing another");
  const origin = {
    receipt: input.denialReceipt,
    receipt_hash: receiptCheck.hash || stableDigest(input.denialReceipt),
    request_id: String(receipt.request_id || ""),
    tool: String(receipt.tool_name || ""),
    reason_code: String(receipt.reason || "")
  };
  if (!origin.request_id || !origin.tool) throw new Error("denial receipt lacks an actionable request id or tool name");
  if (Object.values(registry.proposals).some((p) => p.denial_origin.receipt_hash === origin.receipt_hash)) {
    throw new Error("this denial receipt has already been used for a policy proposal");
  }
  const draftBase = {
    schema: MANDATE_PROPOSAL_SCHEMA,
    proposal_id: `proposal-${(0, import_node_crypto6.randomUUID)()}`,
    created_at: createdAt,
    expires_at: input.expiresAt,
    proposed_by: { gate_kid: input.signer.kid, gate_public_key: input.signer.publicKey },
    base_policy_digest: registry.active.policy_digest,
    proposed_policy_digest: candidate.policy_digest,
    denial_origin: origin,
    reason: input.reason.trim(),
    diff: describePolicyDiff(registry.policies[registry.active.policy_digest], candidate),
    candidate
  };
  if (!draftBase.reason) throw new Error("a controller-facing reason is required");
  const proposalDigest = stableDigest(proposalUnsigned(draftBase));
  const proposalReceipt = signLifecycleEvent(input.signer, {
    type: MANDATE_PROPOSAL_SCHEMA,
    registry_id: registry.registry_id,
    proposal_id: draftBase.proposal_id,
    proposal_digest: proposalDigest,
    base_policy_digest: draftBase.base_policy_digest,
    proposed_policy_digest: draftBase.proposed_policy_digest,
    denial_receipt_hash: origin.receipt_hash
  }, createdAt);
  const proposal = { ...draftBase, proposal_digest: proposalDigest, proposal_receipt: proposalReceipt };
  registry.proposals[proposal.proposal_id] = proposal;
  persistSnapshot(input.cedarDir, candidate);
  addTransition(registry, input.signer, {
    event: "proposal_created",
    occurred_at: createdAt,
    head_before: registry.active.policy_digest,
    head_after: registry.active.policy_digest,
    proposal_id: proposal.proposal_id,
    policy_digest: proposal.proposed_policy_digest,
    expiry: proposal.expires_at
  }, createdAt);
  persistRegistry(input.cedarDir, registry);
  return proposal;
}
function createDirectControllerApproval(input) {
  const approvedAt = nowIso(input.now);
  const approval = createReceiptEnvelope({
    type: MANDATE_APPROVAL_SCHEMA,
    proposal_id: input.proposal.proposal_id,
    proposal_digest: input.proposal.proposal_digest,
    controller_id: input.controller.id,
    decision: "approve",
    approval_method: "ed25519",
    controller_public_key: input.controller.public_key
  }, input.privateKey, input.controller.id, approvedAt).envelope;
  return {
    method: "ed25519",
    controller_id: input.controller.id,
    controller_label: input.controller.label,
    approval_receipt: approval,
    approved_at: approvedAt
  };
}
function createWebAuthnPolicyChallenge(input) {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error("managed mandate registry not initialized");
  const proposal = registry.proposals[input.proposalId];
  if (!proposal) throw new Error("unknown policy proposal");
  const controller = registry.controllers.find((item) => item.id === input.controllerId);
  if (!controller || controller.type !== "webauthn") throw new Error("selected controller has no registered WebAuthn credential");
  const challenge = createApprovalChallenge(proposal.proposal_id, "scopeblind:policy-change", controller.id, input.rpId, input.timeoutSeconds || 300, policyApprovalChallenge(proposal, controller.id));
  registry.pending_webauthn[proposal.proposal_id] = { proposal_id: proposal.proposal_id, controller_id: controller.id, challenge };
  persistRegistry(input.cedarDir, registry);
  return challenge;
}
function activateApprovedProposal(cedarDir, registry, signer, proposal, approval, at2) {
  const integrity = verifyMandateRegistry(registry, new Date(Date.parse(at2)));
  if (!integrity.valid && integrity.code !== "active_grant_expired") throw new Error(`cannot activate against invalid registry: ${integrity.code}`);
  if (registry.active.policy_digest !== proposal.base_policy_digest) throw new Error("active policy changed after proposal; create a new proposal against the current head");
  if (Date.parse(proposal.expires_at) <= Date.parse(at2)) throw new Error("proposal expired before approval; it cannot be activated");
  const controller = registry.controllers.find((item) => item.id === approval.controller_id);
  if (!controller) throw new Error("approval controller is not registered");
  const error = approval.method === "ed25519" ? verifyDirectApproval(registry, proposal, approval) : verifyWebAuthnApproval(registry, proposal, approval);
  if (error) throw new Error(`controller approval rejected: ${error}`);
  if (controller.id === registry.gate.kid) throw new Error("the gate cannot approve its own policy proposal");
  const before = registry.active.policy_digest;
  const candidate = registry.policies[proposal.proposed_policy_digest] || proposal.candidate;
  assertSnapshot(candidate);
  installSnapshotAtomically(cedarDir, candidate);
  const compilationReceipt = signLifecycleEvent(signer, {
    event: "compiled",
    registry_id: registry.registry_id,
    policy_digest: candidate.policy_digest,
    snapshot_digest: stableDigest(candidate),
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval)
  }, at2);
  registry.policies[candidate.policy_digest] = candidate;
  registry.approvals[proposal.proposal_id] = approval;
  registry.active = {
    policy_digest: candidate.policy_digest,
    baseline_policy_digest: before,
    activated_at: at2,
    expires_at: proposal.expires_at,
    proposal_id: proposal.proposal_id,
    compilation_receipt: compilationReceipt
  };
  addTransition(registry, signer, {
    event: "proposal_approved",
    occurred_at: at2,
    head_before: before,
    head_after: before,
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval)
  }, at2);
  addTransition(registry, signer, {
    event: "policy_activated",
    occurred_at: at2,
    head_before: before,
    head_after: candidate.policy_digest,
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval),
    policy_digest: candidate.policy_digest,
    expiry: proposal.expires_at
  }, at2);
  delete registry.pending_webauthn[proposal.proposal_id];
  persistRegistry(cedarDir, registry);
  return registry;
}
function approvePolicyProposalWithDirectSignature(input) {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error("managed mandate registry not initialized");
  const proposal = registry.proposals[input.proposalId];
  if (!proposal) throw new Error("unknown policy proposal");
  return activateApprovedProposal(input.cedarDir, registry, input.signer, proposal, input.approval, nowIso(input.now));
}
function approvePolicyProposalWithWebAuthn(input) {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error("managed mandate registry not initialized");
  const proposal = registry.proposals[input.proposalId];
  const pending = registry.pending_webauthn[input.proposalId];
  if (!proposal || !pending) throw new Error("no pending WebAuthn approval exists for this proposal");
  const controller = registry.controllers.find((item) => item.id === pending.controller_id);
  if (!controller || controller.type !== "webauthn") throw new Error("pending approval controller is not registered for WebAuthn");
  if (pending.challenge.challenge !== policyApprovalChallenge(proposal, controller.id)) {
    throw new Error("pending WebAuthn challenge is not bound to this proposal");
  }
  const at2 = nowIso(input.now);
  const result2 = verifyApprovalAssertion(pending.challenge, input.assertion, controller.credential_public_key, {
    expectedOrigin: input.expectedOrigin,
    requireUserVerification: true,
    prevSignCount: controller.sign_count,
    now: Date.parse(at2)
  });
  if (!result2.valid || !result2.userVerified) throw new Error(`WebAuthn approval rejected: ${result2.reason || "user verification required"}`);
  controller.sign_count = result2.signCount;
  const approval = {
    method: "webauthn",
    controller_id: controller.id,
    controller_label: controller.label,
    challenge: pending.challenge,
    assertion: input.assertion,
    result: result2,
    expected_origin: input.expectedOrigin,
    approved_at: at2
  };
  return activateApprovedProposal(input.cedarDir, registry, input.signer, proposal, approval, at2);
}
function refreshManagedMandate(input) {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) return { valid: true };
  if (registry.gate.kid !== input.signer.kid || registry.gate.public_key !== input.signer.publicKey) {
    return { valid: false, code: "gate_signer_mismatch", message: "The local gate signer does not match the signer pinned in the mandate registry." };
  }
  const now = input.now || /* @__PURE__ */ new Date();
  const structural = verifyMandateRegistry(registry, now);
  if (!structural.valid && structural.code !== "active_grant_expired") return structural;
  const savedExpiry = registry.active.expires_at;
  if (savedExpiry && Date.parse(savedExpiry) <= now.getTime()) {
    const baseline = registry.policies[registry.active.baseline_policy_digest];
    if (!baseline) return { valid: false, code: "expiry_baseline_missing", message: "Expired policy has no baseline snapshot to restore." };
    try {
      installSnapshotAtomically(input.cedarDir, baseline);
      const at2 = nowIso(now);
      const before = registry.active.policy_digest;
      const compilationReceipt = signLifecycleEvent(input.signer, {
        event: "compiled",
        registry_id: registry.registry_id,
        policy_digest: baseline.policy_digest,
        snapshot_digest: stableDigest(baseline),
        reverted_from: before
      }, at2);
      registry.active = {
        policy_digest: baseline.policy_digest,
        baseline_policy_digest: baseline.policy_digest,
        activated_at: at2,
        compilation_receipt: compilationReceipt
      };
      addTransition(registry, input.signer, {
        event: "policy_expired_reverted",
        occurred_at: at2,
        head_before: before,
        head_after: baseline.policy_digest,
        policy_digest: baseline.policy_digest,
        expiry: savedExpiry
      }, at2);
      persistRegistry(input.cedarDir, registry);
      return { valid: true, registry, expired_reverted: true };
    } catch (error) {
      return { valid: false, code: "expiry_revert_failed", message: error instanceof Error ? error.message : "Failed to restore the expired policy baseline." };
    }
  }
  const check = verifyMandateRegistry(registry, now);
  if (!check.valid) return check;
  try {
    const current = snapshotFromDirectory(input.cedarDir);
    if (current.policy_digest !== registry.active.policy_digest) {
      return { valid: false, code: "policy_head_mismatch", message: "Policy files differ from the signed active registry head. The gate refuses to enforce an unauthorised edit." };
    }
  } catch (error) {
    return { valid: false, code: "policy_read_failed", message: error instanceof Error ? error.message : "Could not read active policy files." };
  }
  return check;
}
function publicMandateStatus(registry) {
  return {
    schema: registry.schema,
    registry_id: registry.registry_id,
    gate: { kid: registry.gate.kid, public_key: registry.gate.public_key, ...registry.gate.issuer ? { issuer: registry.gate.issuer } : {} },
    active: {
      policy_digest: registry.active.policy_digest,
      baseline_policy_digest: registry.active.baseline_policy_digest,
      activated_at: registry.active.activated_at,
      ...registry.active.expires_at ? { expires_at: registry.active.expires_at } : {},
      ...registry.active.proposal_id ? { proposal_id: registry.active.proposal_id } : {}
    },
    controllers: registry.controllers.map((controller) => ({ id: controller.id, label: controller.label, type: controller.type })),
    proposals: Object.values(registry.proposals).map((proposal) => ({
      proposal_id: proposal.proposal_id,
      proposal_digest: proposal.proposal_digest,
      base_policy_digest: proposal.base_policy_digest,
      proposed_policy_digest: proposal.proposed_policy_digest,
      expires_at: proposal.expires_at,
      reason: proposal.reason,
      diff: proposal.diff,
      approved: Boolean(registry.approvals[proposal.proposal_id])
    })),
    transitions: registry.history.map((entry) => ({
      sequence: entry.sequence,
      event: entry.event,
      occurred_at: entry.occurred_at,
      head_before: entry.head_before,
      head_after: entry.head_after,
      ...entry.proposal_id ? { proposal_id: entry.proposal_id } : {},
      ...entry.expiry ? { expiry: entry.expiry } : {},
      transition_receipt_hash: stableDigest(entry.transition_receipt)
    }))
  };
}
function exportMandateDisciplineRecord(registry, now) {
  const check = verifyMandateRegistry(registry, now);
  if (!check.valid) throw new Error(`cannot export invalid mandate lifecycle: ${check.code}`);
  return {
    type: "scopeblind.discipline-policy-changes.v1",
    generated_at: nowIso(),
    registry_id: registry.registry_id,
    registry_digest: stableDigest(registry),
    active_policy_digest: registry.active.policy_digest,
    active_baseline_policy_digest: registry.active.baseline_policy_digest,
    active_grant_expires_at: registry.active.expires_at || null,
    invariant: "A policy head becomes active only after a gate-signed proposal bound to a signed denial, a distinct registered controller approval, and an atomic install. Expired widened grants restore their signed baseline before another action is evaluated.",
    changes: registry.history.map((transition2) => ({
      sequence: transition2.sequence,
      event: transition2.event,
      occurred_at: transition2.occurred_at,
      head_before: transition2.head_before,
      head_after: transition2.head_after,
      proposal_id: transition2.proposal_id || null,
      expires_at: transition2.expiry || null,
      transition_receipt_hash: stableDigest(transition2.transition_receipt)
    })),
    proposals: Object.values(registry.proposals).map((proposal) => ({
      proposal_id: proposal.proposal_id,
      proposal_digest: proposal.proposal_digest,
      base_policy_digest: proposal.base_policy_digest,
      proposed_policy_digest: proposal.proposed_policy_digest,
      denial_receipt_hash: proposal.denial_origin.receipt_hash,
      expires_at: proposal.expires_at,
      approval_method: registry.approvals[proposal.proposal_id]?.method || null,
      active: registry.active.proposal_id === proposal.proposal_id
    })),
    disclosure: {
      included: ["policy digests", "transition hashes", "denial receipt hashes", "controller approval method", "expiry"],
      excluded: ["tool payloads", "prompts", "portfolio data", "strategy inputs"],
      full_registry_attachment_required_for_offline_transition_verification: true
    }
  };
}
var import_node_crypto6, import_node_fs11, import_node_path7, MANDATE_REGISTRY_SCHEMA, MANDATE_PROPOSAL_SCHEMA, MANDATE_APPROVAL_SCHEMA, SHA256;
var init_mandate_lifecycle = __esm({
  "src/mandate-lifecycle.ts"() {
    "use strict";
    import_node_crypto6 = require("crypto");
    import_node_fs11 = require("fs");
    import_node_path7 = require("path");
    init_acta_envelope();
    init_policy_digest();
    init_webauthn_approval();
    MANDATE_REGISTRY_SCHEMA = "scopeblind.mandate-registry.v1";
    MANDATE_PROPOSAL_SCHEMA = "scopeblind.mandate-proposal.v1";
    MANDATE_APPROVAL_SCHEMA = "scopeblind.mandate-approval.v1";
    SHA256 = (value) => (0, import_node_crypto6.createHash)("sha256").update(value).digest("hex");
  }
});

// src/receipt-registry.ts
var receipt_registry_exports = {};
__export(receipt_registry_exports, {
  ORG_IDENTITY_FILE: () => ORG_IDENTITY_FILE,
  REGISTRY_FILE: () => REGISTRY_FILE,
  VERIFIER_PAGE_FILE: () => VERIFIER_PAGE_FILE,
  createOrgIdentity: () => createOrgIdentity,
  createReceiptRegistry: () => createReceiptRegistry,
  readReceiptDigestRecords: () => readReceiptDigestRecords,
  renderVerifierPage: () => renderVerifierPage,
  writeOrgIdentity: () => writeOrgIdentity
});
function sha256Hex(input) {
  return (0, import_node_crypto7.createHash)("sha256").update(input).digest("hex");
}
function stableStringify2(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify2).join(",")}]`;
  const obj = value;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${stableStringify2(obj[key])}`).join(",")}}`;
}
function safeReadJson(path) {
  try {
    if (!(0, import_node_fs12.existsSync)(path)) return null;
    return JSON.parse((0, import_node_fs12.readFileSync)(path, "utf-8"));
  } catch {
    return null;
  }
}
function requestIdFromReceipt(receipt) {
  const direct = receipt.request_id || receipt.scope;
  if (typeof direct === "string") return direct;
  const payload = receipt.payload;
  if (payload && typeof payload === "object") {
    const candidate = payload.request_id || payload.scope;
    if (typeof candidate === "string") return candidate;
  }
  return void 0;
}
function keyIdFromReceipt(receipt) {
  const kid = receipt.kid;
  if (typeof kid === "string") return kid;
  const signature = receipt.signature;
  if (signature && typeof signature === "object") {
    const nested = signature.kid;
    if (typeof nested === "string") return nested;
  }
  return void 0;
}
function issuerFromReceipt(receipt) {
  const issuer = receipt.issuer;
  if (typeof issuer === "string") return issuer;
  const signature = receipt.signature;
  if (signature && typeof signature === "object") {
    const nested = signature.issuer;
    if (typeof nested === "string") return nested;
  }
  return void 0;
}
function receiptType(receipt) {
  return String(receipt.type || receipt.artifact_type || receipt.v || "receipt");
}
function readReceiptDigestRecords(dir) {
  const receiptPath = (0, import_node_path8.join)(dir, ".protect-mcp-receipts.jsonl");
  if (!(0, import_node_fs12.existsSync)(receiptPath)) return [];
  const raw = (0, import_node_fs12.readFileSync)(receiptPath, "utf-8");
  return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
    try {
      const receipt = JSON.parse(line);
      const publicKey = (() => {
        const sig = receipt.signature;
        if (sig && typeof sig === "object" && typeof sig.public_key === "string") {
          return String(sig.public_key);
        }
        return void 0;
      })();
      return [{
        type: "scopeblind.receipt_digest.v1",
        receipt_hash: sha256Hex(line),
        receipt_bytes: Buffer.byteLength(line, "utf-8"),
        receipt_type: receiptType(receipt),
        request_id: requestIdFromReceipt(receipt),
        local_issuer: issuerFromReceipt(receipt),
        local_kid: keyIdFromReceipt(receipt),
        local_public_key_hint: publicKey ? `${publicKey.slice(0, 12)}...${publicKey.slice(-8)}` : void 0,
        observed_at: (/* @__PURE__ */ new Date()).toISOString(),
        source_file: receiptPath
      }];
    } catch {
      return [];
    }
  });
}
function createOrgIdentity(opts) {
  const now = (opts.now || /* @__PURE__ */ new Date()).toISOString();
  const existing = safeReadJson((0, import_node_path8.join)(opts.dir, ORG_IDENTITY_FILE));
  const keyData = safeReadJson((0, import_node_path8.join)(opts.dir, "keys", "gateway.json")) || {};
  const orgId = opts.orgId || String(existing?.org_id || `org_${(0, import_node_crypto7.randomUUID)().slice(0, 12)}`);
  const orgName = opts.orgName || String(existing?.org_name || "Local ScopeBlind Org");
  const billingAccountId = opts.billingAccountId || String(existing?.billing_account_id || `billing_${orgId}`);
  const publicKey = typeof keyData.publicKey === "string" ? keyData.publicKey : "";
  const kid = typeof keyData.kid === "string" ? keyData.kid : publicKey ? `kid_${publicKey.slice(0, 12)}` : "local-key";
  const issuer = typeof keyData.issuer === "string" ? keyData.issuer : "protect-mcp";
  return {
    type: "scopeblind.org_identity.v1",
    org_id: orgId,
    org_name: orgName,
    billing_account_id: billingAccountId,
    created_at: typeof existing?.created_at === "string" ? existing.created_at : now,
    public_key_directory: publicKey ? [{
      type: "scopeblind.org_public_key.v1",
      org_id: orgId,
      key_id: kid,
      issuer,
      algorithm: "Ed25519",
      public_key_hex: publicKey,
      created_at: now,
      source: "local_gateway_key"
    }] : [],
    privacy: {
      raw_prompt_upload: false,
      raw_tool_payload_upload: false,
      raw_receipt_upload: false,
      digest_only: true
    }
  };
}
function writeOrgIdentity(dir, identity) {
  const path = (0, import_node_path8.join)(dir, ORG_IDENTITY_FILE);
  (0, import_node_fs12.writeFileSync)(path, JSON.stringify(identity, null, 2) + "\n");
  return path;
}
function localAnchors(records, org, now, verifierBaseUrl) {
  return records.map((record) => ({
    type: "scopeblind.timestamp_anchor.v1",
    anchor_id: `local_${record.receipt_hash.slice(0, 16)}`,
    receipt_hash: record.receipt_hash,
    org_id: org.org_id,
    timestamp_utc: now.toISOString(),
    timestamp_source: "local-preview-not-independent",
    verifier_url: verifierBaseUrl ? `${verifierBaseUrl.replace(/\/$/, "")}/verify?digest=${record.receipt_hash}` : void 0
  }));
}
async function hostedAnchors(opts) {
  const endpoint2 = opts.endpoint.replace(/\/$/, "") + "/v1/receipt-registry/anchor";
  const payload = {
    type: "scopeblind.receipt_registry_anchor_request.v1",
    org: {
      org_id: opts.org.org_id,
      org_name: opts.org.org_name,
      billing_account_id: opts.org.billing_account_id,
      public_key_directory: opts.org.public_key_directory
    },
    privacy: opts.org.privacy,
    billing: {
      metered_unit: null,
      status: "not_metered_by_receipt",
      raw_prompt_upload: false,
      raw_data_upload: false
    },
    receipt_digests: opts.records.map((record) => ({
      receipt_hash: record.receipt_hash,
      receipt_bytes: record.receipt_bytes,
      receipt_type: record.receipt_type,
      local_issuer: record.local_issuer,
      local_kid: record.local_kid
    }))
  };
  const bodyText = stableStringify2(payload);
  for (const forbidden of ["payload_preview", "raw_receipt", "prompt", "tool_output", "privateKey"]) {
    if (bodyText.includes(`${JSON.stringify(forbidden)}:`)) throw new Error(`hosted anchor payload contains forbidden field: ${forbidden}`);
  }
  const res = await fetch(endpoint2, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${opts.token}`,
      "user-agent": "protect-mcp/receipt-registry"
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const text5 = await res.text().catch(() => "");
    throw new Error(`hosted anchor failed: HTTP ${res.status} ${text5.slice(0, 200)}`);
  }
  const response = await res.json().catch(() => ({}));
  const anchors = Array.isArray(response.anchors) ? response.anchors : [];
  return opts.records.map((record, index) => {
    const anchor = anchors[index] || anchors.find((candidate) => candidate.receipt_hash === record.receipt_hash) || {};
    return {
      type: "scopeblind.timestamp_anchor.v1",
      anchor_id: String(anchor.anchor_id || `hosted_${record.receipt_hash.slice(0, 16)}`),
      receipt_hash: record.receipt_hash,
      org_id: opts.org.org_id,
      timestamp_utc: String(anchor.timestamp_utc || anchor.anchored_at || (/* @__PURE__ */ new Date()).toISOString()),
      timestamp_source: "scopeblind-hosted",
      registry_url: typeof response.registry_url === "string" ? response.registry_url : void 0,
      verifier_url: typeof anchor.verifier_url === "string" ? anchor.verifier_url : opts.verifierBaseUrl ? `${opts.verifierBaseUrl.replace(/\/$/, "")}/verify?digest=${record.receipt_hash}` : void 0,
      signature: anchor.signature
    };
  });
}
async function createReceiptRegistry(opts) {
  const now = opts.now || /* @__PURE__ */ new Date();
  const org = createOrgIdentity(opts);
  const records = readReceiptDigestRecords(opts.dir);
  if (records.length === 0) throw new Error("No signed receipts found. Run protect-mcp with signing enabled first.");
  let anchors;
  let uploaded = false;
  if (opts.hosted || opts.endpoint || opts.token) {
    if (!opts.endpoint) throw new Error("Hosted anchoring requires --endpoint or SCOPEBLIND_REGISTRY_ENDPOINT.");
    if (!opts.token) throw new Error("Hosted anchoring requires --token or SCOPEBLIND_TOKEN.");
    anchors = await hostedAnchors({ endpoint: opts.endpoint, token: opts.token, org, records, verifierBaseUrl: opts.verifierBaseUrl });
    uploaded = true;
  } else {
    anchors = localAnchors(records, org, now, opts.verifierBaseUrl);
  }
  const registry = {
    type: "scopeblind.receipt_registry.v1",
    version: 1,
    generated_at: now.toISOString(),
    org,
    billing: {
      billing_account_id: org.billing_account_id,
      metered_unit: null,
      charge_basis: "not_metered_by_receipt",
      status: "managed_witness_not_case_billing",
      raw_prompt_upload: false,
      raw_data_upload: false
    },
    privacy: {
      statement: uploaded ? "ScopeBlind managed witness received receipt digests and explicitly listed public metadata only. This is not an independent timestamp." : "Local preview registry only. It provides no independent timing or inclusion evidence.",
      uploaded_fields: ["receipt_hash", "receipt_bytes", "receipt_type", "local_issuer", "local_kid", "org_id", "billing_account_id", "org_public_keys"],
      excluded_fields: ["request_id", "raw_prompt", "raw_tool_payload", "payload_preview", "raw_receipt", "tool_output", "private_key"]
    },
    records,
    anchors,
    verifier: {
      local_page: (0, import_node_path8.join)(opts.dir, VERIFIER_PAGE_FILE),
      shareable_url_template: opts.verifierBaseUrl ? `${opts.verifierBaseUrl.replace(/\/$/, "")}/verify?digest={receipt_hash}` : "file://scopeblind-verifier.html#digest={receipt_hash}"
    }
  };
  writeOrgIdentity(opts.dir, org);
  const registryPath = opts.outPath || (0, import_node_path8.join)(opts.dir, REGISTRY_FILE);
  (0, import_node_fs12.mkdirSync)((0, import_node_path8.dirname)(registryPath), { recursive: true });
  (0, import_node_fs12.writeFileSync)(registryPath, JSON.stringify(registry, null, 2) + "\n");
  const verifierPath = (0, import_node_path8.join)(opts.dir, VERIFIER_PAGE_FILE);
  (0, import_node_fs12.writeFileSync)(verifierPath, renderVerifierPage(registry));
  return { registry, registryPath, verifierPath, uploaded };
}
function renderVerifierPage(registry) {
  const embedded = JSON.stringify(registry).replace(/</g, "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScopeBlind Receipt Verifier</title>
<style>
:root{--ink:#11110f;--muted:#6d675d;--line:#ded7c9;--paper:#f7f3ea;--card:#fffdf7;--ok:#2f6f4e;--warn:#8d620f;--bad:#8f241c}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top left,#fffdf7,#f7f3ea 48%,#e8dfce);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{width:min(1040px,calc(100vw - 32px));margin:32px auto}.card{background:rgba(255,253,247,.94);border:1px solid var(--line);border-radius:24px;padding:22px;box-shadow:0 24px 70px rgba(36,30,18,.10);margin-bottom:16px}.kicker{text-transform:uppercase;letter-spacing:.17em;color:var(--muted);font-size:11px;font-weight:900}h1{font:520 clamp(36px,6vw,72px)/.94 ui-serif,Georgia,serif;letter-spacing:-.05em;margin:12px 0}input{width:100%;border:1px solid var(--line);border-radius:14px;padding:13px;background:#fffaf0;font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.pill{display:inline-flex;border-radius:999px;padding:5px 9px;font-size:11px;font-weight:900}.ok{background:#dcebdd;color:var(--ok)}.warn{background:#f4e5bd;color:var(--warn)}.bad{background:#f7d9d3;color:var(--bad)}pre{white-space:pre-wrap;background:#181712;color:#f8f1df;border-radius:16px;padding:14px;overflow:auto}.muted{color:var(--muted)}code{background:#f2eadc;border:1px solid var(--line);border-radius:8px;padding:2px 6px}</style>
</head>
<body><main>
<section class="card"><div class="kicker">ScopeBlind verifier</div><h1>Verify that a managed witness saw this receipt digest.</h1><p class="muted">This page contains receipt digests, witness records, public key metadata, and commercial-boundary metadata. It does not contain raw prompts, payloads, tool outputs, request identifiers, or raw receipts. A ScopeBlind witness is not an independent timestamp.</p></section>
<section class="card"><label class="kicker" for="digest">Receipt digest</label><input id="digest" placeholder="Paste receipt SHA-256 digest" oninput="render()"><div id="result" style="margin-top:16px"></div></section>
<section class="card"><div class="kicker">Org public key directory</div><pre id="keys"></pre></section>
</main><script>
const registry=${embedded};
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function render(){const q=document.getElementById('digest').value.trim()||new URLSearchParams(location.search).get('digest')||location.hash.replace(/^#digest=/,'');const rec=registry.records.find(r=>r.receipt_hash===q);const anchor=registry.anchors.find(a=>a.receipt_hash===q);const el=document.getElementById('result');if(!q){el.innerHTML='<p class="muted">Paste a digest to verify registry inclusion.</p>';return;}if(!rec){el.innerHTML='<span class="pill bad">not found</span><p>No matching digest in this registry export.</p>';return;}const managed=anchor&&anchor.timestamp_source==='scopeblind-hosted';el.innerHTML='<span class="pill '+(managed?'ok':'warn')+'">'+(managed?'ScopeBlind managed witness':'local preview only')+'</span><pre>'+esc(JSON.stringify({receipt:rec,anchor:anchor||null,billing:registry.billing,privacy:registry.privacy},null,2))+'</pre>';}
document.getElementById('keys').textContent=JSON.stringify(registry.org.public_key_directory,null,2);render();
</script></body></html>`;
}
var import_node_crypto7, import_node_fs12, import_node_path8, ORG_IDENTITY_FILE, REGISTRY_FILE, VERIFIER_PAGE_FILE;
var init_receipt_registry = __esm({
  "src/receipt-registry.ts"() {
    "use strict";
    import_node_crypto7 = require("crypto");
    import_node_fs12 = require("fs");
    import_node_path8 = require("path");
    ORG_IDENTITY_FILE = ".protect-mcp-org.json";
    REGISTRY_FILE = ".protect-mcp-registry.json";
    VERIFIER_PAGE_FILE = "scopeblind-verifier.html";
  }
});

// src/bundle.ts
var bundle_exports = {};
__export(bundle_exports, {
  collectSignedReceipts: () => collectSignedReceipts,
  createAuditBundle: () => createAuditBundle
});
function createAuditBundle(opts) {
  const receipts = opts.receipts.filter(
    (r) => r && typeof r === "object" && (typeof r.signature === "string" || r.signature !== null && typeof r.signature === "object")
  );
  if (receipts.length === 0) {
    throw new Error("Audit bundle requires at least one signed receipt");
  }
  const keyMap = /* @__PURE__ */ new Map();
  for (const key of opts.signingKeys) {
    if (!keyMap.has(key.kid)) {
      keyMap.set(key.kid, key);
    }
  }
  let timeRange = opts.timeRange || null;
  if (!timeRange) {
    const timestamps = receipts.map((r) => r.issued_at || r.timestamp).filter(Boolean).sort();
    if (timestamps.length > 0) {
      timeRange = {
        from: timestamps[0],
        to: timestamps[timestamps.length - 1]
      };
    }
  }
  return {
    format: "scopeblind:audit-bundle",
    version: 1,
    exported_at: (/* @__PURE__ */ new Date()).toISOString(),
    tenant: opts.tenant,
    time_range: timeRange,
    receipts,
    anchors: opts.anchors || [],
    selective_disclosures: opts.selectiveDisclosures || [],
    privacy: {
      selective_disclosure: {
        supported: true,
        model: "salted_commitments_merkle_v0",
        statement: "Committed receipts may disclose selected fields with salted Merkle openings. Undisclosed committed fields remain hidden while staying bound to the signed commitment root."
      }
    },
    verification: {
      algorithm: "ed25519",
      signing_keys: Array.from(keyMap.values()),
      instructions: `Verify each receipt by: (1) remove the "signature" field, (2) canonicalize the remaining object with JCS (sorted keys at every level), (3) encode as UTF-8 bytes, (4) verify the Ed25519 signature using the signing key matching the receipt's "kid" field. For scopeblind.selective_disclosure.v0 packages, recompute each disclosed leaf and verify it against the receipt committed_fields_root; fields not disclosed remain hidden. CLI: npx @veritasacta/verify bundle.json --bundle`
    }
  };
}
function collectSignedReceipts(logs) {
  return logs.filter((log) => log.v === 2).map((log) => {
    const logRecord = log;
    if (logRecord.receipt) {
      return logRecord.receipt;
    }
    return logRecord;
  }).filter((r) => typeof r.signature === "string");
}
var init_bundle = __esm({
  "src/bundle.ts"() {
    "use strict";
  }
});

// src/receipt-enrichment.ts
function canonicalJson(value) {
  const seen = /* @__PURE__ */ new WeakSet();
  const enc = (v) => {
    if (v === null || v === void 0) return "null";
    const t = typeof v;
    if (t === "number") return Number.isFinite(v) ? JSON.stringify(v) : "null";
    if (t === "boolean" || t === "string") return JSON.stringify(v);
    if (t === "bigint") return JSON.stringify(v.toString());
    if (t === "function" || t === "symbol") return "null";
    if (Array.isArray(v)) return "[" + v.map(enc).join(",") + "]";
    if (t === "object") {
      const o = v;
      if (seen.has(o)) return '"[circular]"';
      seen.add(o);
      const body = Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + enc(o[k])).join(",");
      seen.delete(o);
      return "{" + body + "}";
    }
    return "null";
  };
  return enc(value);
}
function sha256Hex2(s) {
  return (0, import_utils3.bytesToHex)((0, import_sha2563.sha256)(new TextEncoder().encode(s)));
}
function deriveCapabilities(tool, input) {
  const t = String(tool || "").toLowerCase();
  let text5 = "";
  try {
    text5 = canonicalJson(input).toLowerCase();
  } catch {
  }
  const caps = /* @__PURE__ */ new Set();
  for (const r of RULES) {
    if (r.tool && r.tool.test(t)) caps.add(r.cap);
    if (r.text && r.text.test(text5)) caps.add(r.cap);
  }
  return Array.from(caps).sort();
}
function deriveResource(input) {
  const o = input && typeof input === "object" ? input : {};
  const path = o.file_path ?? o.path ?? o.filePath ?? o.notebook_path ?? o.filename;
  if (typeof path === "string" && path.trim()) return { kind: "path", digest: sha256Hex2(path.replace(/\\/g, "/")) };
  const url = o.url ?? o.uri ?? o.endpoint ?? o.href;
  if (typeof url === "string" && url.trim()) {
    try {
      return { kind: "host", digest: sha256Hex2(new URL(url).host.toLowerCase()) };
    } catch {
    }
  }
  const cmd = o.command ?? o.cmd ?? o.script;
  if (typeof cmd === "string" && cmd.trim()) {
    const first = cmd.trim().split(/\s+/)[0];
    if (first) return { kind: "command", digest: sha256Hex2(first) };
  }
  return void 0;
}
function findField(input, names, depth = 0) {
  if (depth > 4 || input === null || typeof input !== "object") return void 0;
  const o = input;
  const keys2 = Object.keys(o).sort();
  for (const k of keys2) {
    if (names.indexOf(k.toLowerCase()) >= 0 && o[k] !== void 0 && o[k] !== null) return o[k];
  }
  for (const k of keys2) {
    const v = findField(o[k], names, depth + 1);
    if (v !== void 0) return v;
  }
  return void 0;
}
function derivePayment(tool, input) {
  if (deriveCapabilities(tool, input).indexOf("payment") < 0) return void 0;
  const p = { amount: null, asset: null, recipient_digest: null };
  const amt = findField(input, ["amount"]);
  if (typeof amt === "number" && Number.isFinite(amt) && amt >= 0) p.amount = amt;
  else if (typeof amt === "string" && /^\d{1,15}(\.\d{1,18})?$/.test(amt.trim()) && amt.indexOf(".") >= 0) p.amount = parseFloat(amt);
  const asset = findField(input, ["asset", "currency", "token"]);
  if (typeof asset === "string" && asset.trim()) p.asset = asset.trim().slice(0, 64);
  const to = findField(input, ["payto", "pay_to", "recipient", "destination", "to"]);
  if (typeof to === "string" && to.trim()) p.recipient_digest = sha256Hex2(to.trim().toLowerCase());
  const scheme = findField(input, ["scheme"]);
  if (typeof scheme === "string" && scheme.trim()) p.scheme = scheme.trim().slice(0, 32);
  return p;
}
function buildEnrichment(tool, input) {
  const e = {
    v: ENRICHMENT_VERSION,
    input_digest: sha256Hex2(canonicalJson(input ?? {})),
    capabilities: deriveCapabilities(tool, input)
  };
  const resource = deriveResource(input);
  if (resource) e.resource = resource;
  const payment = derivePayment(tool, input);
  if (payment) e.payment = payment;
  return e;
}
var import_sha2563, import_utils3, ENRICHMENT_VERSION, RULES;
var init_receipt_enrichment = __esm({
  "src/receipt-enrichment.ts"() {
    "use strict";
    import_sha2563 = require("@noble/hashes/sha256");
    import_utils3 = require("@noble/hashes/utils");
    ENRICHMENT_VERSION = 2;
    RULES = [
      { cap: "exec.shell", tool: /bash|shell|exec|terminal|run_command|command/ },
      { cap: "fs.read", tool: /(^|[_.])(read|cat|glob|grep|search|ls|view|list_files|open)/ },
      { cap: "fs.write", tool: /write|create_file|save|append|edit|patch|replace|update_file|multiedit|notebook/ },
      { cap: "fs.delete", tool: /delete|remove|unlink|trash|(^|[_.])rm/ },
      { cap: "net.egress", tool: /fetch|http|curl|wget|request|download|browse|navigate|webfetch|web_search|scrape/ },
      { cap: "vcs", tool: /(^|[_.])git/, text: /\bgit\s+(commit|push|pull|clone|reset|checkout|branch|rebase|merge|tag)\b/ },
      { cap: "package.install", text: /\b(npm|pnpm|yarn)\s+(i|install|add)\b|\bpip3?\s+install\b|\bgo\s+get\b|\bcargo\s+add\b|\bbrew\s+install\b|\bapt(-get)?\s+install\b|\bgem\s+install\b/ },
      { cap: "secret.adjacent", text: /\.env\b|secret|credential|passwd|password|api[_-]?key|private[_-]?key|\.pem\b|\.key\b|id_rsa|bearer\s|aws_(access|secret)|authorization/ },
      { cap: "destructive", text: /rm\s+-[a-z]*[rf]|\brmdir\b|drop\s+table|truncate\s+table|delete\s+from|reset\s+--hard|--force\b|\bmkfs\b|\bdd\s+if=|shutdown|reboot|kill\s+-9|>\s*\/dev\/sd/ },
      { cap: "financial", text: /\b(order|trade|buy|sell|transfer|wire|payment|withdraw|deposit|swap|invoice|charge|refund|settle)\b/ },
      { cap: "data.query", text: /\bselect\s+[\s\S]+\bfrom\b|\binsert\s+into\b|\bupdate\s+[\s\S]+\bset\b|\bdelete\s+from\b/ },
      // Agent payments (x402 / value transfer). Deliberately BROAD: a false positive
      // only makes a `claim --no payment` harder to assert (conservative); a false
      // negative would let a real payment escape the record's payment claims.
      { cap: "payment", tool: /(^|[_.-])(pay|payment|x402|checkout)($|[_.-])|wallet.*send|send.*payment/, text: /x402|x-payment|paymentrequirements|maxamountrequired|payto|"pay_to"|eip-3009|transferwithauthorization|payment_intent|send_payment|create_payment/ }
    ];
  }
});

// src/claim.ts
var claim_exports = {};
__export(claim_exports, {
  ANCHOR_SCHEMA: () => ANCHOR_SCHEMA,
  CHECKPOINT_SCHEMA: () => CHECKPOINT_SCHEMA,
  CLAIM_TYPE: () => CLAIM_TYPE,
  DEFAULT_LOG: () => DEFAULT_LOG,
  MANDATE_CONTINUITY_SCHEMA: () => MANDATE_CONTINUITY_SCHEMA,
  anchorClaim: () => anchorClaim,
  anchorMandateContinuityCheckpoint: () => anchorMandateContinuityCheckpoint,
  anchorRecordCheckpoint: () => anchorRecordCheckpoint,
  buildAnchorEnvelope: () => buildAnchorEnvelope,
  buildClaim: () => buildClaim,
  buildMandateContinuityCheckpoint: () => buildMandateContinuityCheckpoint,
  buildRecordCheckpoint: () => buildRecordCheckpoint,
  checkClaimAnchor: () => checkClaimAnchor,
  claimDigest: () => claimDigest,
  evaluate: () => evaluate,
  leafHash: () => leafHash,
  lookupPinnedIdentity: () => lookupPinnedIdentity,
  merkleRoot: () => merkleRoot,
  receiptToLeaf: () => receiptToLeaf,
  verifyAnchorEnvelope: () => verifyAnchorEnvelope,
  verifyClaim: () => verifyClaim
});
function sha256Hex3(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return (0, import_utils4.bytesToHex)((0, import_sha2564.sha256)(bytes));
}
function receiptToLeaf(e) {
  const p = e && typeof e.payload === "object" && e.payload || e;
  const dec = String(p.decision || e.decision || "").toLowerCase();
  const v = /den|block|reject|refus/.test(dec) ? "blocked" : /ask|approv|hold|escal|review|pending/.test(dec) ? "held" : "allowed";
  const enr = p.enrichment;
  const c2 = enr && Array.isArray(enr.capabilities) ? enr.capabilities.map(String).sort() : [];
  const tsRaw = e.issued_at || p.timestamp || p.issued_at;
  const ms = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "string" ? Date.parse(tsRaw) : NaN;
  const t = isFinite(ms) ? new Date(ms).toISOString() : "";
  const d = sha256Hex3(canonicalJson(e));
  const leaf = { d, v, c: c2, t };
  const pay = enr && enr.payment;
  if (pay && typeof pay === "object") {
    const amt = pay.amount;
    leaf.p = typeof amt === "number" && Number.isFinite(amt) ? amt : null;
  }
  return leaf;
}
function leafHash(leaf) {
  return sha256Hex3(canonicalJson(leaf));
}
function merkleRoot(leafHashes) {
  if (leafHashes.length === 0) return sha256Hex3("scopeblind.claim.empty");
  let level = [...leafHashes].sort();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(sha256Hex3(a + b));
    }
    level = next;
  }
  return level[0];
}
function evaluate(pred, leaves) {
  if (pred.kind === "no_capability") {
    const matched2 = leaves.filter((l) => l.c.indexOf(pred.capability) >= 0).length;
    return { statement: `No action used capability "${pred.capability}"`, holds: matched2 === 0, matched: matched2 };
  }
  if (pred.kind === "only_capabilities") {
    const allow = new Set(pred.capabilities);
    const matched2 = leaves.filter((l) => !l.c.every((c2) => allow.has(c2))).length;
    return { statement: `All actions were confined to capabilities {${pred.capabilities.join(", ")}}`, holds: matched2 === 0, matched: matched2 };
  }
  if (pred.kind === "no_verdict") {
    const matched2 = leaves.filter((l) => l.v === pred.verdict).length;
    return { statement: `No action was ${pred.verdict}`, holds: matched2 === 0, matched: matched2 };
  }
  if (pred.kind === "payment_under") {
    const matched2 = leaves.filter((l) => "p" in l && (l.p === null || l.p >= pred.cap)).length;
    return { statement: `Every payment stayed under ${pred.cap} (unknown amounts count as over)`, holds: matched2 === 0, matched: matched2 };
  }
  const matched = leaves.filter((l) => l.v === pred.verdict).length;
  return { statement: `${matched} action${matched === 1 ? " was" : "s were"} ${pred.verdict}`, holds: true, matched };
}
function messageHash(unsigned) {
  return (0, import_sha2564.sha256)(new TextEncoder().encode(canonicalJson(unsigned)));
}
function buildClaim(receipts, predicate, key, issuedAt) {
  const leaves = receipts.map(receiptToLeaf);
  const root = merkleRoot(leaves.map(leafHash));
  const claim = evaluate(predicate, leaves);
  const times = leaves.map((l) => l.t).filter(Boolean).sort();
  const unsigned = {
    type: CLAIM_TYPE,
    predicate,
    claim,
    scope: { total: leaves.length, from: times[0] || "", to: times[times.length - 1] || "" },
    record: { root },
    leaves,
    issuer: { kid: key.kid, publicKey: key.publicKey, issuer: key.issuer || "protect-mcp" },
    issued_at: issuedAt
  };
  const signature = (0, import_utils4.bytesToHex)(import_ed255193.ed25519.sign(messageHash(unsigned), (0, import_utils4.hexToBytes)(key.privateKey)));
  return { ...unsigned, signature };
}
function verifyClaim(pack, overridePublicKey) {
  const reasons = [];
  const leaves = Array.isArray(pack.leaves) ? pack.leaves : [];
  const recomputedRoot = merkleRoot(leaves.map(leafHash));
  const root_ok = !!pack.record && recomputedRoot === pack.record.root;
  if (!root_ok) reasons.push("record commitment (Merkle root) does not match the disclosed decisions");
  const recomputed = evaluate(pack.predicate, leaves);
  const predicate_ok = !!pack.claim && recomputed.holds === pack.claim.holds && recomputed.matched === pack.claim.matched;
  if (!predicate_ok) reasons.push("claim result does not match the predicate recomputed over the disclosed decisions");
  let authentic = false;
  try {
    const { signature, ...unsigned } = pack;
    const pub = overridePublicKey || pack.issuer && pack.issuer.publicKey;
    if (pub && signature) {
      authentic = import_ed255193.ed25519.verify((0, import_utils4.hexToBytes)(signature), messageHash(unsigned), (0, import_utils4.hexToBytes)(pub));
    }
  } catch {
  }
  if (!authentic) reasons.push("signature does not verify against the issuer public key");
  return {
    valid: authentic && root_ok && predicate_ok,
    authentic,
    root_ok,
    predicate_ok,
    holds: !!(pack.claim && pack.claim.holds),
    matched: pack.claim ? pack.claim.matched : recomputed.matched,
    total: leaves.length,
    statement: pack.claim ? pack.claim.statement : recomputed.statement,
    reasons
  };
}
function anchorDeepSort(o) {
  if (o === null || typeof o !== "object") return o;
  if (Array.isArray(o)) return o.map(anchorDeepSort);
  const src = o;
  const out2 = {};
  for (const k of Object.keys(src).sort()) out2[k] = anchorDeepSort(src[k]);
  return out2;
}
function toBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function claimDigest(pack) {
  return sha256Hex3(canonicalJson(pack));
}
function buildAnchorEnvelope(pack, key, issuedAt) {
  const signed2 = {
    type: "evidence_pack",
    schema: ANCHOR_SCHEMA,
    anchors: "protect-mcp-claim",
    claim_digest: claimDigest(pack),
    record_root: pack.record.root,
    statement: pack.claim.statement,
    holds: pack.claim.holds,
    matched: pack.claim.matched,
    total: pack.scope.total,
    issued_at: issuedAt,
    verification_key: key.publicKey,
    disclosure: "internal"
  };
  const hash = (0, import_sha2564.sha256)(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed2))));
  const digest = (0, import_utils4.bytesToHex)(hash);
  const signature = (0, import_utils4.bytesToHex)(import_ed255193.ed25519.sign(hash, (0, import_utils4.hexToBytes)(key.privateKey)));
  return { ...signed2, signature, digest };
}
function verifyAnchorEnvelope(pack, envelope3) {
  const reasons = [];
  if (!envelope3 || envelope3.type !== "evidence_pack" || envelope3.anchors !== "protect-mcp-claim") {
    return { ok: false, reasons: ["sidecar does not contain a protect-mcp claim anchor envelope"] };
  }
  const expected = claimDigest(pack);
  if (envelope3.claim_digest !== expected) {
    reasons.push("anchored envelope binds a DIFFERENT claim (claim_digest mismatch)");
  }
  if (envelope3.record_root !== pack.record.root) {
    reasons.push("anchored envelope commits to a different record root");
  }
  if (pack.issuer && envelope3.verification_key !== pack.issuer.publicKey) {
    reasons.push("anchor was signed by a different key than the claim issuer");
  }
  try {
    const { signature, digest, ...signed2 } = envelope3;
    const hash = (0, import_sha2564.sha256)(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed2))));
    if ((0, import_utils4.bytesToHex)(hash) !== String(digest).toLowerCase()) {
      reasons.push("envelope digest does not match its contents");
    } else if (!import_ed255193.ed25519.verify((0, import_utils4.hexToBytes)(String(signature)), hash, (0, import_utils4.hexToBytes)(envelope3.verification_key))) {
      reasons.push("envelope signature does not verify");
    }
  } catch {
    reasons.push("envelope signature does not verify");
  }
  return { ok: reasons.length === 0, reasons };
}
async function checkClaimAnchor(pack, sidecar, opts) {
  const reasons = [];
  const envelope3 = sidecar && sidecar.envelope;
  if (!envelope3) {
    return { local_ok: false, log_ok: null, reasons: ["sidecar has no anchor envelope"] };
  }
  const local = verifyAnchorEnvelope(pack, envelope3);
  reasons.push(...local.reasons);
  const base = (sidecar.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out2 = {
    local_ok: local.ok,
    log_ok: null,
    seq: sidecar.seq,
    anchored_at: sidecar.anchored_at,
    entry_url: sidecar.entry_url || (typeof sidecar.seq === "number" ? `${base}/fn/log/${sidecar.seq}` : void 0),
    reasons
  };
  if (opts?.offline) return out2;
  const doFetch = opts?.fetchImpl || globalThis.fetch;
  if (!doFetch) return out2;
  try {
    const resp = await doFetch(`${base}/fn/log/digest/sha256:${envelope3.digest}`, { headers: { accept: "application/json" } });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data) {
      out2.log_ok = null;
      return out2;
    }
    if (data.anchored !== true) {
      out2.log_ok = false;
      out2.reasons.push("the public log does not contain this anchor digest");
      return out2;
    }
    if (typeof sidecar.seq === "number" && typeof data.seq === "number" && data.seq !== sidecar.seq) {
      out2.log_ok = false;
      out2.reasons.push(`log holds the digest at entry #${data.seq}, sidecar says #${sidecar.seq}`);
      return out2;
    }
    out2.log_ok = true;
    if (typeof data.seq === "number") out2.seq = data.seq;
    return out2;
  } catch {
    out2.log_ok = null;
    return out2;
  }
}
async function submitEnvelope(envelope3, base, fetchImpl) {
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) return { ok: false, error: "fetch_unavailable" };
  const encoded = toBase64(new TextEncoder().encode(JSON.stringify(envelope3)));
  try {
    const resp = await doFetch(`${base}/fn/log/anchor-pack`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ encoded })
    });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data || !data.ok || typeof data.seq !== "number") {
      return { ok: false, error: data && data.error || `http_${resp.status}` };
    }
    return { ok: true, seq: data.seq, anchored_at: data.anchored_at, already_anchored: !!data.already_anchored };
  } catch {
    return { ok: false, error: "network_error" };
  }
}
async function anchorClaim(pack, key, opts) {
  const envelope3 = buildAnchorEnvelope(pack, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out2 = await submitEnvelope(envelope3, base, opts.fetchImpl);
  if (!out2.ok) return { ok: false, claim_digest: envelope3.claim_digest, error: out2.error, envelope: envelope3 };
  return {
    ok: true,
    claim_digest: envelope3.claim_digest,
    seq: out2.seq,
    entry_url: `${base}/fn/log/${out2.seq}`,
    anchored_at: out2.anchored_at,
    already_anchored: out2.already_anchored,
    envelope: envelope3
  };
}
function buildRecordCheckpoint(receipts, key, issuedAt) {
  const leaves = receipts.map(receiptToLeaf);
  const times = leaves.map((l) => l.t).filter(Boolean).sort();
  const signed2 = {
    type: "evidence_pack",
    schema: CHECKPOINT_SCHEMA,
    anchors: "protect-mcp-record",
    record_root: merkleRoot(leaves.map(leafHash)),
    total: leaves.length,
    from: times[0] || "",
    to: times[times.length - 1] || "",
    issued_at: issuedAt,
    verification_key: key.publicKey,
    disclosure: "internal"
  };
  const hash = (0, import_sha2564.sha256)(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed2))));
  const digest = (0, import_utils4.bytesToHex)(hash);
  const signature = (0, import_utils4.bytesToHex)(import_ed255193.ed25519.sign(hash, (0, import_utils4.hexToBytes)(key.privateKey)));
  return { ...signed2, signature, digest };
}
async function anchorRecordCheckpoint(receipts, key, opts) {
  const checkpoint = buildRecordCheckpoint(receipts, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out2 = await submitEnvelope(checkpoint, base, opts.fetchImpl);
  if (!out2.ok) return { ok: false, record_root: checkpoint.record_root, total: checkpoint.total, checkpoint, error: out2.error };
  return {
    ok: true,
    record_root: checkpoint.record_root,
    total: checkpoint.total,
    seq: out2.seq,
    entry_url: `${base}/fn/log/${out2.seq}`,
    anchored_at: out2.anchored_at,
    already_anchored: out2.already_anchored,
    checkpoint
  };
}
function buildMandateContinuityCheckpoint(state, key, issuedAt) {
  if (!/^sha256:[0-9a-f]{64}$/i.test(state.registry_digest) || !/^sha256:[0-9a-f]{64}$/i.test(state.active_policy_digest) || !/^sha256:[0-9a-f]{64}$/i.test(state.latest_transition_hash)) {
    throw new Error("continuity state must contain sha256 commitments");
  }
  if (!Number.isSafeInteger(state.transition_count) || state.transition_count < 1) throw new Error("continuity state needs at least one transition");
  const signed2 = {
    type: "evidence_pack",
    schema: MANDATE_CONTINUITY_SCHEMA,
    anchors: "protect-mcp-mandate-continuity",
    continuity: state,
    issued_at: issuedAt,
    verification_key: key.publicKey,
    disclosure: "internal"
  };
  const hash = (0, import_sha2564.sha256)(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed2))));
  return { ...signed2, signature: (0, import_utils4.bytesToHex)(import_ed255193.ed25519.sign(hash, (0, import_utils4.hexToBytes)(key.privateKey))), digest: (0, import_utils4.bytesToHex)(hash) };
}
async function anchorMandateContinuityCheckpoint(checkpoint, opts) {
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out2 = await submitEnvelope(checkpoint, base, opts.fetchImpl);
  if (!out2.ok) return { ok: false, checkpoint, error: out2.error };
  return { ok: true, checkpoint, seq: out2.seq, entry_url: `${base}/fn/log/${out2.seq}`, anchored_at: out2.anchored_at, already_anchored: out2.already_anchored };
}
async function lookupPinnedIdentity(publicKey, opts) {
  const base = (opts && opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const doFetch = opts && opts.fetchImpl || globalThis.fetch;
  if (!doFetch || !/^[0-9a-f]{64}$/i.test(publicKey)) return null;
  try {
    const resp = await doFetch(`${base}/fn/log/keys/lookup/${publicKey.toLowerCase()}`, { headers: { accept: "application/json" } });
    const data = await resp.json().catch(() => null);
    if (!data || data.ok !== true) return null;
    if (!data.found) return { found: false };
    return {
      found: true,
      name: data.name,
      slug: data.slug,
      kid: data.kid,
      enrolled_at: data.enrolled_at,
      revoked: !!(data.revoked || data.revoked_at)
    };
  } catch {
    return null;
  }
}
var import_sha2564, import_utils4, import_ed255193, CLAIM_TYPE, ANCHOR_SCHEMA, DEFAULT_LOG, CHECKPOINT_SCHEMA, MANDATE_CONTINUITY_SCHEMA;
var init_claim = __esm({
  "src/claim.ts"() {
    "use strict";
    import_sha2564 = require("@noble/hashes/sha256");
    import_utils4 = require("@noble/hashes/utils");
    import_ed255193 = require("@noble/curves/ed25519");
    init_receipt_enrichment();
    CLAIM_TYPE = "scopeblind.claim.v1";
    ANCHOR_SCHEMA = "scopeblind.protect-mcp.anchor.v1";
    DEFAULT_LOG = "https://scopeblind.com";
    CHECKPOINT_SCHEMA = "scopeblind.protect-mcp.record-checkpoint.v1";
    MANDATE_CONTINUITY_SCHEMA = "scopeblind.mandate_continuity_checkpoint.v1";
  }
});

// src/commitments/merkle.ts
function hashLeaf(leafBytes) {
  const buf = new Uint8Array(leafBytes.length + 1);
  buf[0] = DOMAIN_LEAF;
  buf.set(leafBytes, 1);
  return (0, import_sha2565.sha256)(buf);
}
function hashInternal(left, right) {
  const buf = new Uint8Array(left.length + right.length + 1);
  buf[0] = DOMAIN_INTERNAL;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return (0, import_sha2565.sha256)(buf);
}
function merkleRoot2(leafHashes) {
  if (leafHashes.length === 0) {
    throw new Error("merkleRoot: cannot compute root of empty leaf set");
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }
  const n = leafHashes.length;
  const k = largestPowerOfTwoLessThan(n);
  const left = merkleRoot2(leafHashes.slice(0, k));
  const right = merkleRoot2(leafHashes.slice(k));
  return hashInternal(left, right);
}
function generateProof(leafHashes, index) {
  if (leafHashes.length === 0) {
    throw new Error("generateProof: empty tree");
  }
  if (index < 0 || index >= leafHashes.length) {
    throw new Error(
      `generateProof: index ${index} out of range [0, ${leafHashes.length})`
    );
  }
  const siblings = [];
  collectPath(leafHashes, index, siblings);
  return {
    index,
    treeSize: leafHashes.length,
    siblings: siblings.map((s) => (0, import_utils5.bytesToHex)(s))
  };
}
function collectPath(leaves, index, out2) {
  if (leaves.length === 1) return;
  const n = leaves.length;
  const k = largestPowerOfTwoLessThan(n);
  if (index < k) {
    collectPath(leaves.slice(0, k), index, out2);
    out2.push(merkleRoot2(leaves.slice(k)));
  } else {
    collectPath(leaves.slice(k), index - k, out2);
    out2.push(merkleRoot2(leaves.slice(0, k)));
  }
}
function verifyProof(expectedRootHex, leafHash2, proof) {
  if (proof.index < 0 || proof.index >= proof.treeSize) return false;
  if (proof.treeSize === 1) {
    return proof.siblings.length === 0 && (0, import_utils5.bytesToHex)(leafHash2).toLowerCase() === expectedRootHex.toLowerCase();
  }
  let result2;
  try {
    result2 = reconstructRoot(
      leafHash2,
      proof.index,
      proof.treeSize,
      proof.siblings
    );
  } catch {
    return false;
  }
  return (0, import_utils5.bytesToHex)(result2).toLowerCase() === expectedRootHex.toLowerCase();
}
function reconstructRoot(leafHash2, index, treeSize, siblings) {
  if (treeSize === 1) {
    if (siblings.length !== 0) {
      throw new Error("reconstructRoot: extra siblings at single-leaf level");
    }
    return leafHash2;
  }
  if (siblings.length === 0) {
    throw new Error("reconstructRoot: ran out of siblings before single-leaf");
  }
  const k = largestPowerOfTwoLessThan(treeSize);
  const outermostSibling = (0, import_utils5.hexToBytes)(siblings[siblings.length - 1]);
  const innerSiblings = siblings.slice(0, -1);
  if (index < k) {
    const leftHash = reconstructRoot(leafHash2, index, k, innerSiblings);
    return hashInternal(leftHash, outermostSibling);
  } else {
    const rightHash = reconstructRoot(
      leafHash2,
      index - k,
      treeSize - k,
      innerSiblings
    );
    return hashInternal(outermostSibling, rightHash);
  }
}
function largestPowerOfTwoLessThan(n) {
  if (n < 2) {
    throw new Error(`largestPowerOfTwoLessThan: n must be >= 2 (got ${n})`);
  }
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
var import_sha2565, import_utils5, DOMAIN_LEAF, DOMAIN_INTERNAL;
var init_merkle = __esm({
  "src/commitments/merkle.ts"() {
    "use strict";
    import_sha2565 = require("@noble/hashes/sha256");
    import_utils5 = require("@noble/hashes/utils");
    DOMAIN_LEAF = 0;
    DOMAIN_INTERNAL = 1;
  }
});

// src/commitments/primitives.ts
function jcs(value) {
  if (value === null || value === void 0) return "null";
  if (typeof value === "boolean" || typeof value === "number")
    return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(jcs).join(",") + "]";
  const obj = value;
  const keys2 = Object.keys(obj).sort();
  return "{" + keys2.map((k) => JSON.stringify(k) + ":" + jcs(obj[k])).join(",") + "}";
}
var import_sha2566, import_hmac, import_utils6;
var init_primitives = __esm({
  "src/commitments/primitives.ts"() {
    "use strict";
    import_sha2566 = require("@noble/hashes/sha256");
    import_hmac = require("@noble/hashes/hmac");
    import_utils6 = require("@noble/hashes/utils");
  }
});

// src/commitments/leaf.ts
function base64urlNoPad(bytes) {
  const std = typeof Buffer !== "undefined" ? Buffer.from(bytes).toString("base64") : btoa(String.fromCharCode(...bytes));
  return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode2(s) {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - std.length % 4) % 4);
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  const bin = atob(padded);
  const out2 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out2[i] = bin.charCodeAt(i);
  return out2;
}
function encodeLeaf(field) {
  const obj = {
    name: field.name,
    salt: base64urlNoPad(field.salt),
    value: field.value
  };
  const canonical2 = jcs(obj);
  return new TextEncoder().encode(canonical2);
}
function sortFields(fields) {
  const encoder = new TextEncoder();
  const decorated = fields.map((f) => ({
    field: f,
    nameBytes: encoder.encode(f.name)
  }));
  decorated.sort((a, b) => compareBytes(a.nameBytes, b.nameBytes));
  return decorated.map((d) => d.field);
}
function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
function leavesFromFields(fields) {
  const sorted = sortFields(fields);
  const leafBytes = sorted.map(encodeLeaf);
  return { sorted, leafBytes };
}
var init_leaf = __esm({
  "src/commitments/leaf.ts"() {
    "use strict";
    init_primitives();
  }
});

// src/signing-committed.ts
var signing_committed_exports = {};
__export(signing_committed_exports, {
  createSelectiveDisclosurePackage: () => createSelectiveDisclosurePackage,
  discloseField: () => discloseField,
  signCommittedDecision: () => signCommittedDecision,
  verifySelectiveDisclosurePackage: () => verifySelectiveDisclosurePackage
});
function freshSalt() {
  return (0, import_utils7.randomBytes)(32);
}
function signCommittedDecision(entry, committedFieldNames, signingKey, publicKey, kid, issuer) {
  const allFields = {
    tool: entry.tool,
    decision: entry.decision,
    reason_code: entry.reason_code,
    policy_digest: entry.policy_digest,
    scope: entry.request_id,
    mode: entry.mode,
    request_id: entry.request_id
  };
  if (entry.tier) allFields.tier = entry.tier;
  if (entry.credential_ref) allFields.credential_ref = entry.credential_ref;
  if (entry.rate_limit_remaining !== void 0) {
    allFields.rate_limit_remaining = entry.rate_limit_remaining;
  }
  if (entry.policy_engine) allFields.policy_engine = entry.policy_engine;
  if (entry.hook_event) allFields.hook_event = entry.hook_event;
  if (entry.sandbox_state) allFields.sandbox_state = entry.sandbox_state;
  if (entry.timing) allFields.timing = entry.timing;
  if (entry.swarm) allFields.swarm = entry.swarm;
  if (entry.payload_digest) allFields.payload_digest = entry.payload_digest;
  if (entry.deny_iteration) allFields.deny_iteration = entry.deny_iteration;
  const committedFields = [];
  const cleartextFields = {};
  const openings = {};
  for (const [name, value] of Object.entries(allFields)) {
    if (committedFieldNames.includes(name)) {
      const salt = freshSalt();
      committedFields.push({ name, salt, value });
    } else {
      cleartextFields[name] = value;
    }
  }
  let committedFieldsRoot = null;
  if (committedFields.length > 0) {
    const { sorted, leafBytes } = leavesFromFields(committedFields);
    const leafHashes = leafBytes.map(hashLeaf);
    const root = merkleRoot2(leafHashes);
    committedFieldsRoot = (0, import_utils7.bytesToHex)(root);
    sorted.forEach((f, i) => {
      openings[f.name] = { name: f.name, value: f.value, salt: f.salt, index: i };
    });
  }
  const payload = {
    type: "scopeblind.receipt.committed.v1",
    spec: "draft-farley-acta-signed-receipts",
    issuer_certification: "self-signed",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    ...cleartextFields
  };
  if (committedFieldsRoot !== null) {
    payload.committed_fields_root = committedFieldsRoot;
    payload.committed_field_names = committedFields.map((f) => f.name);
  }
  const canonical2 = jcs(payload);
  const signatureBytes = import_ed255194.ed25519.sign(new TextEncoder().encode(canonical2), (0, import_utils7.hexToBytes)(signingKey));
  const signedReceipt = {
    payload,
    signature: {
      alg: "EdDSA",
      kid,
      issuer,
      sig: (0, import_utils7.bytesToHex)(signatureBytes)
    }
  };
  const signedJson = JSON.stringify(signedReceipt);
  const receiptHash2 = (0, import_utils7.bytesToHex)((0, import_sha2567.sha256)(new TextEncoder().encode(jcs(signedReceipt))));
  return {
    signed: signedJson,
    artifact_type: "decision_receipt_committed_v1",
    openings,
    receipt_hash: receiptHash2
  };
}
function discloseField(receiptHash2, fieldName, openings) {
  const o = openings[fieldName];
  if (!o) {
    throw new Error(`disclose: no opening recorded for field "${fieldName}"`);
  }
  const fields = Object.values(openings).map((op) => ({
    name: op.name,
    salt: op.salt,
    value: op.value
  }));
  const { leafBytes } = leavesFromFields(fields);
  const leafHashes = leafBytes.map(hashLeaf);
  const proof = generateProof(leafHashes, o.index);
  return {
    parent_receipt_hash: receiptHash2,
    name: fieldName,
    value: o.value,
    salt: base64urlNoPad(o.salt),
    proof
  };
}
function createSelectiveDisclosurePackage(receipt, fieldNames, openings) {
  const receiptHash2 = receiptHashHex(receipt);
  const committedFieldsRoot = typeof committedPayload(receipt).committed_fields_root === "string" ? committedPayload(receipt).committed_fields_root : "";
  if (!committedFieldsRoot) {
    throw new Error("selective disclosure requires a committed receipt with committed_fields_root");
  }
  const committedFieldNames = committedFieldNamesFromReceipt(receipt, openings);
  const uniqueFields = Array.from(new Set(fieldNames));
  for (const fieldName of uniqueFields) {
    if (!committedFieldNames.includes(fieldName)) {
      throw new Error(`selective disclosure: field "${fieldName}" is not committed by this receipt`);
    }
  }
  const disclosures = uniqueFields.map((fieldName) => discloseField(receiptHash2, fieldName, openings));
  const hiddenFields = committedFieldNames.filter((fieldName) => !uniqueFields.includes(fieldName));
  return {
    type: "scopeblind.selective_disclosure.v0",
    version: 0,
    parent_receipt_hash: receiptHash2,
    committed_fields_root: committedFieldsRoot,
    disclosed_fields: uniqueFields,
    hidden_fields: hiddenFields,
    disclosures,
    verifier_explanation: {
      summary: "This package opens selected committed receipt fields and leaves the rest hidden.",
      disclosed: uniqueFields.length ? `Disclosed fields: ${uniqueFields.join(", ")}.` : "No fields were disclosed.",
      hidden: hiddenFields.length ? `Hidden committed fields: ${hiddenFields.join(", ")}. Their salted commitments remain bound to the signed receipt root.` : "No committed fields remain hidden.",
      limitation: "Selective Disclosure v0 uses salted SHA-256 commitments and Merkle proofs. It is not a full zero-knowledge proof."
    }
  };
}
function verifySelectiveDisclosurePackage(receipt, disclosure, publicKeyHex) {
  const errors = [];
  if (disclosure.type !== "scopeblind.selective_disclosure.v0") {
    errors.push("disclosure.type is not scopeblind.selective_disclosure.v0");
  }
  const actualReceiptHash = receiptHashHex(receipt);
  const receiptHashValid = disclosure.parent_receipt_hash === actualReceiptHash;
  if (!receiptHashValid) {
    errors.push("parent_receipt_hash does not match the supplied receipt");
  }
  const rootRaw = committedPayload(receipt).committed_fields_root;
  const root = typeof rootRaw === "string" ? rootRaw : "";
  const commitmentRootValid = Boolean(root) && disclosure.committed_fields_root === root;
  if (!commitmentRootValid) {
    errors.push("committed_fields_root does not match the supplied receipt");
  }
  const signatureValid = verifyCommittedReceiptSignature(receipt, publicKeyHex);
  if (signatureValid === false) {
    errors.push("receipt signature failed verification");
  } else if (signatureValid === null) {
    errors.push("receipt signature not checked: no public key was supplied and the receipt carries none");
  }
  const committedFieldNames = committedFieldNamesFromReceipt(receipt, {});
  const disclosed = /* @__PURE__ */ new Set();
  for (const item of disclosure.disclosures || []) {
    if (item.parent_receipt_hash !== disclosure.parent_receipt_hash) {
      errors.push(`disclosure for "${item.name}" targets a different receipt hash`);
      continue;
    }
    if (!committedFieldNames.includes(item.name)) {
      errors.push(`field "${item.name}" is not listed in committed_field_names`);
      continue;
    }
    const leafBytes = encodeLeaf({
      name: item.name,
      salt: base64urlDecode2(item.salt),
      value: item.value
    });
    const ok = root ? verifyProof(root, hashLeaf(leafBytes), item.proof) : false;
    if (!ok) {
      errors.push(`field "${item.name}" failed Merkle inclusion verification`);
    } else {
      disclosed.add(item.name);
    }
  }
  const disclosedFields = Array.from(disclosed);
  const hiddenFields = committedFieldNames.filter((fieldName) => !disclosed.has(fieldName));
  const valid = errors.length === 0 && receiptHashValid && commitmentRootValid && signatureValid === true;
  const explanation = [
    valid ? "Selective disclosure verified: the disclosed fields open to the signed receipt commitment root." : "Selective disclosure failed verification.",
    signatureValid === true ? "Receipt signature verified against the embedded Ed25519 public key." : signatureValid === null ? "Receipt signature was not checked: supply the issuer's public key (envelope receipts carry none). Unchecked is not verified." : "Receipt signature did not verify.",
    disclosedFields.length ? `Disclosed fields: ${disclosedFields.join(", ")}.` : "No fields were disclosed.",
    hiddenFields.length ? `Hidden fields: ${hiddenFields.join(", ")}. These remain private but bound to the same commitment root.` : "No committed fields remain hidden.",
    "Limitation: this is salted commitment disclosure, not full zero-knowledge."
  ];
  return {
    valid,
    receipt_hash_valid: receiptHashValid,
    signature_valid: signatureValid,
    commitment_root_valid: commitmentRootValid,
    disclosed_fields: disclosedFields,
    hidden_fields: hiddenFields,
    errors,
    explanation
  };
}
function committedFieldNamesFromReceipt(receipt, openings) {
  const names_ = committedPayload(receipt).committed_field_names;
  const fromReceipt = Array.isArray(names_) ? names_.filter((fieldName) => typeof fieldName === "string") : [];
  const names = fromReceipt.length ? fromReceipt : Object.keys(openings);
  return Array.from(new Set(names)).sort();
}
function receiptHashHex(receipt) {
  return (0, import_utils7.bytesToHex)((0, import_sha2567.sha256)(new TextEncoder().encode(jcs(receipt))));
}
function committedPayload(receipt) {
  const p = receipt.payload;
  if (p && typeof p === "object" && !Array.isArray(p)) return p;
  const { signature: _sig, ...rest } = receipt;
  return rest;
}
function verifyCommittedReceiptSignature(receipt, publicKeyHex) {
  const signature = receipt.signature;
  if (!signature || typeof signature !== "object") return null;
  const sig = signature;
  if (sig.alg !== "EdDSA" || typeof sig.sig !== "string") return null;
  const key = publicKeyHex ?? (typeof sig.public_key === "string" ? sig.public_key : void 0);
  if (!key) return null;
  const signed2 = committedPayload(receipt);
  const sigBytes = /^[0-9a-f]+$/i.test(sig.sig) && sig.sig.length % 2 === 0 ? (0, import_utils7.hexToBytes)(sig.sig) : base64urlDecode2(sig.sig);
  try {
    return import_ed255194.ed25519.verify(sigBytes, new TextEncoder().encode(jcs(signed2)), (0, import_utils7.hexToBytes)(key));
  } catch {
    return false;
  }
}
var import_ed255194, import_sha2567, import_utils7;
var init_signing_committed = __esm({
  "src/signing-committed.ts"() {
    "use strict";
    import_ed255194 = require("@noble/curves/ed25519");
    import_sha2567 = require("@noble/hashes/sha256");
    import_utils7 = require("@noble/hashes/utils");
    init_merkle();
    init_leaf();
    init_primitives();
  }
});

// src/hook-patterns.ts
var hook_patterns_exports = {};
__export(hook_patterns_exports, {
  BUILTIN_PATTERNS: () => BUILTIN_PATTERNS,
  generateHookSettings: () => generateHookSettings,
  generateSampleCedarPolicy: () => generateSampleCedarPolicy,
  generateVerifyReceiptSkill: () => generateVerifyReceiptSkill
});
function generateHookSettings(hookUrl, patterns = BUILTIN_PATTERNS) {
  const preToolUseEntries = [];
  preToolUseEntries.push({
    matcher: "",
    hooks: [{
      type: "http",
      url: hookUrl
    }]
  });
  const postToolUseEntries = [{
    matcher: "",
    hooks: [{
      type: "http",
      url: hookUrl
    }]
  }];
  const lifecycleEvents = {};
  for (const event of [
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "SessionStart",
    "SessionEnd",
    "TeammateIdle",
    "ConfigChange",
    "Stop"
  ]) {
    lifecycleEvents[event] = [{
      matcher: "",
      hooks: [{
        type: "http",
        url: hookUrl
      }]
    }];
  }
  return {
    hooks: {
      PreToolUse: preToolUseEntries,
      PostToolUse: postToolUseEntries,
      ...lifecycleEvents
    }
  };
}
function generateSampleCedarPolicy() {
  const lines = [
    "// Generated by protect-mcp init-hooks",
    "// Customize these policies to match your security requirements.",
    "// Cedar deny decisions are AUTHORITATIVE \u2014 they cannot be overridden.",
    "",
    "// Allow all read-only tools by default",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Read"',
    ");",
    "",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Glob"',
    ");",
    "",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Grep"',
    ");",
    "",
    "// Allow write/edit tools (remove these to require explicit approval)",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Write"',
    ");",
    "",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Edit"',
    ");",
    "",
    "// Allow Bash with caution (Cedar evaluates before hook patterns)",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Bash"',
    ");",
    "",
    "// Block dangerous tools entirely",
    "// Uncomment any of these to block specific tools:",
    "// forbid(",
    "//   principal,",
    '//   action == Action::"MCP::Tool::call",',
    '//   resource == Tool::"delete_file"',
    "// );",
    ""
  ];
  return lines.join("\n");
}
function generateVerifyReceiptSkill() {
  return `---
name: verify-receipt
description: Verify ScopeBlind receipt chain integrity and display audit trail
allowed-tools: [Read, Bash(npx:@veritasacta/verify*), Bash(cat:*protect-mcp*), Bash(jq:*)]
when_to_use: "Use when the user asks to verify receipts, check audit trails, validate decision logs, or see what tools were called"
context: inline
---

# ScopeBlind Receipt Verification

Every AI agent tool call gets a cryptographic receipt. Verify offline. No vendor trust required.

When the user asks to verify receipts or check the audit trail:

1. **Check for receipt files:**
   - Look for \`.protect-mcp-receipts.jsonl\` in the project root
   - Look for \`.protect-mcp-log.jsonl\` for decision history

2. **Display recent activity:**
   \`\`\`bash
   tail -n 20 .protect-mcp-log.jsonl | jq -r '[.tool, .decision, .reason_code, .hook_event // "stdio"] | @tsv'
   \`\`\`

3. **Verify receipt signatures:**
   \`\`\`bash
   npx @veritasacta/verify .protect-mcp-receipts.jsonl --format jsonl
   \`\`\`

4. **Show swarm topology (if multi-agent):**
   \`\`\`bash
   cat .protect-mcp-log.jsonl | jq -r 'select(.swarm != null) | [.swarm.agent_id, .swarm.agent_type, .tool, .decision] | @tsv'
   \`\`\`

5. **Show policy suggestions:**
   \`\`\`bash
   curl -s http://127.0.0.1:9377/suggestions | jq '.suggestions[]'
   \`\`\`

6. **Show config tamper alerts:**
   \`\`\`bash
   curl -s http://127.0.0.1:9377/alerts | jq '.alerts[]'
   \`\`\`

7. **Export audit bundle:**
   \`\`\`bash
   npx protect-mcp bundle --output audit-bundle.json
   \`\`\`

Present results in a clear, formatted table showing: timestamp, tool, decision, reason, and receipt ID.
If swarm data exists, show the agent topology (coordinator \u2192 workers).
`;
}
var BUILTIN_PATTERNS;
var init_hook_patterns = __esm({
  "src/hook-patterns.ts"() {
    "use strict";
    BUILTIN_PATTERNS = [
      // ── Destructive filesystem operations ──
      {
        matcher: "Bash",
        condition: "Bash(rm -rf *)",
        decision: "deny",
        description: "Recursive force-delete",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(rm -r *)",
        decision: "ask",
        description: "Recursive delete",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(chmod 777 *)",
        decision: "deny",
        description: "World-writable permissions",
        category: "privilege_escalation"
      },
      {
        matcher: "Bash",
        condition: "Bash(chmod -R *)",
        decision: "ask",
        description: "Recursive permission change",
        category: "privilege_escalation"
      },
      // ── SQL destruction ──
      {
        matcher: "Bash",
        condition: "Bash(DROP TABLE *)",
        decision: "deny",
        description: "SQL DROP TABLE",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(DROP DATABASE *)",
        decision: "deny",
        description: "SQL DROP DATABASE",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(TRUNCATE *)",
        decision: "deny",
        description: "SQL TRUNCATE",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(DELETE FROM *)",
        decision: "ask",
        description: "SQL DELETE (mass deletion)",
        category: "destructive"
      },
      // ── Network exfiltration ──
      {
        matcher: "Bash",
        condition: "Bash(curl * --upload-file *)",
        decision: "deny",
        description: "Upload file via curl",
        category: "exfiltration"
      },
      {
        matcher: "Bash",
        condition: "Bash(wget --post-file *)",
        decision: "deny",
        description: "Upload file via wget",
        category: "exfiltration"
      },
      {
        matcher: "Bash",
        condition: "Bash(scp * *:*)",
        decision: "ask",
        description: "Remote file copy",
        category: "exfiltration"
      },
      // ── Sensitive file access ──
      {
        matcher: "Write",
        condition: "Write(*.env)",
        decision: "ask",
        description: "Write to .env file",
        category: "sensitive_file"
      },
      {
        matcher: "Write",
        condition: "Write(*.key)",
        decision: "deny",
        description: "Write to key file",
        category: "sensitive_file"
      },
      {
        matcher: "Write",
        condition: "Write(*.pem)",
        decision: "deny",
        description: "Write to certificate file",
        category: "sensitive_file"
      },
      {
        matcher: "Edit",
        condition: "Edit(*.env)",
        decision: "ask",
        description: "Edit .env file",
        category: "sensitive_file"
      },
      {
        matcher: "Write",
        condition: "Write(*id_rsa*)",
        decision: "deny",
        description: "Write to SSH key",
        category: "sensitive_file"
      },
      {
        matcher: "Read",
        condition: "Read(*id_rsa*)",
        decision: "ask",
        description: "Read SSH private key",
        category: "sensitive_file"
      },
      // ── Privilege escalation ──
      {
        matcher: "Bash",
        condition: "Bash(sudo *)",
        decision: "ask",
        description: "Sudo execution",
        category: "privilege_escalation"
      },
      {
        matcher: "Bash",
        condition: "Bash(su *)",
        decision: "deny",
        description: "Switch user",
        category: "privilege_escalation"
      },
      // ── Package/system modification ──
      {
        matcher: "Bash",
        condition: "Bash(npm publish *)",
        decision: "ask",
        description: "Publish npm package",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(pip install *)",
        decision: "ask",
        description: "Install Python package",
        category: "network"
      },
      {
        matcher: "Bash",
        condition: "Bash(git push --force*)",
        decision: "ask",
        description: "Force push to git",
        category: "destructive"
      }
    ];
  }
});

// src/sample.ts
var sample_exports = {};
__export(sample_exports, {
  SAMPLE_KID: () => SAMPLE_KID,
  buildSampleKit: () => buildSampleKit
});
function signEnvelope(unsigned, privHex) {
  const msg = new TextEncoder().encode(canonicalJson(unsigned));
  const signature = (0, import_utils8.bytesToHex)(import_ed255195.ed25519.sign(msg, (0, import_utils8.hexToBytes)(privHex)));
  return { ...unsigned, signature };
}
function buildSampleKit(dir, opts) {
  const receiptsPath = (0, import_node_path9.join)(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = (0, import_node_path9.join)(dir, "keys", "gateway.json");
  if (!opts?.force && ((0, import_node_fs13.existsSync)(receiptsPath) || (0, import_node_fs13.existsSync)(keyPath))) {
    throw Object.assign(
      new Error(`refusing to overwrite an existing record or signing key in ${dir}`),
      { code: "SAMPLE_EXISTS" }
    );
  }
  (0, import_node_fs13.mkdirSync)((0, import_node_path9.join)(dir, "keys"), { recursive: true });
  const priv = import_ed255195.ed25519.utils.randomPrivateKey();
  const privHex = (0, import_utils8.bytesToHex)(priv);
  const pub = (0, import_utils8.bytesToHex)(import_ed255195.ed25519.getPublicKey(priv));
  (0, import_node_fs13.writeFileSync)(keyPath, JSON.stringify({ privateKey: privHex, publicKey: pub, kid: SAMPLE_KID }, null, 2));
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "keys", ".gitignore"), "# Never commit signing keys\n*.json\n");
  const now = opts?.now ?? /* @__PURE__ */ new Date();
  const stamp = (i) => new Date(now.getTime() - (7 - i) * 5 * 6e4).toISOString();
  const receipt = (i, tool, decision, caps, extra) => {
    const ts = stamp(i);
    const payload = {
      tool,
      decision,
      reason_code: decision === "deny" ? "policy_deny" : "policy_ok",
      policy_digest: SAMPLE_KID,
      scope: `${tool}-${ts}`,
      mode: "enforce",
      request_id: `${tool}-${ts}`,
      spec: "draft-farley-acta-signed-receipts-01",
      issuer_certification: "self-signed",
      public_key: pub,
      hook_event: "PreToolUse",
      enrichment: { v: 2, input_digest: sha256Hex4(tool + ts), capabilities: caps, ...extra || {} }
    };
    return signEnvelope({
      v: 2,
      type: decision === "deny" ? "gateway_restraint" : "decision_receipt",
      algorithm: "ed25519",
      kid: SAMPLE_KID,
      issuer: "protect-mcp",
      issued_at: ts,
      payload
    }, privHex);
  };
  const pay = (amount3) => ({
    payment: { amount: amount3, asset: "USDC", recipient_digest: sha256Hex4("sample-merchant"), scheme: "exact" }
  });
  const rows = [
    receipt(0, "Read", "allow", ["fs.read"]),
    receipt(1, "Bash", "allow", ["exec.shell"]),
    receipt(2, "Write", "allow", ["fs.write"]),
    receipt(3, "WebFetch", "deny", ["net.egress"]),
    receipt(4, "x402_pay", "allow", ["financial", "payment"], pay(0.02)),
    receipt(5, "Read", "allow", ["fs.read", "secret.adjacent"]),
    receipt(6, "wallet_send_payment", "allow", ["financial", "payment"], pay(12.5)),
    receipt(7, "Bash", "allow", ["exec.shell", "vcs"])
  ];
  (0, import_node_fs13.writeFileSync)(receiptsPath, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const tampered = rows.map((r) => JSON.parse(JSON.stringify(r)));
  tampered[3].payload.decision = "allow";
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "demo-tampered.jsonl"), tampered.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return {
    dir,
    publicKey: pub,
    kid: SAMPLE_KID,
    receipts: rows,
    paymentsUsd: [0.02, 12.5],
    files: [".protect-mcp-receipts.jsonl", "demo-tampered.jsonl", "keys/gateway.json"]
  };
}
var import_node_fs13, import_node_path9, import_sha2568, import_utils8, import_ed255195, SAMPLE_KID, sha256Hex4;
var init_sample = __esm({
  "src/sample.ts"() {
    "use strict";
    import_node_fs13 = require("fs");
    import_node_path9 = require("path");
    import_sha2568 = require("@noble/hashes/sha256");
    import_utils8 = require("@noble/hashes/utils");
    import_ed255195 = require("@noble/curves/ed25519");
    init_receipt_enrichment();
    SAMPLE_KID = "sample-demo";
    sha256Hex4 = (s) => (0, import_utils8.bytesToHex)((0, import_sha2568.sha256)(new TextEncoder().encode(s)));
  }
});

// src/egress-guard.ts
var egress_guard_exports = {};
__export(egress_guard_exports, {
  EGRESS_ALLOWED_PAYLOAD_FIELDS: () => EGRESS_ALLOWED_PAYLOAD_FIELDS,
  EGRESS_SIGNED_PAYLOAD_FIELDS: () => EGRESS_SIGNED_PAYLOAD_FIELDS,
  EGRESS_SUMMARY_FIELDS: () => EGRESS_SUMMARY_FIELDS,
  EGRESS_SUMMARY_TYPE: () => EGRESS_SUMMARY_TYPE,
  EGRESS_SUMMARY_VERSION: () => EGRESS_SUMMARY_VERSION,
  assertEgressSafe: () => assertEgressSafe,
  inspectEgress: () => inspectEgress,
  runEgressSelfCheck: () => runEgressSelfCheck,
  toEgressSummary: () => toEgressSummary
});
function str(v) {
  return typeof v === "string" && v.length ? v : void 0;
}
function integer(v) {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : void 0;
}
function hmacCommitment(domain, value, opts) {
  return `hmac-sha256:${(0, import_node_crypto8.createHmac)("sha256", opts.pseudonymKey).update(`${domain}\0${opts.tenantScope || ""}\0${String(value ?? "")}`).digest("hex")}`;
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
function toEgressSummary(envelope3, opts) {
  if (!opts?.pseudonymKey || typeof opts.pseudonymKey === "string" && !opts.pseudonymKey.length || opts.pseudonymKey instanceof Uint8Array && !opts.pseudonymKey.length) return null;
  if (!envelope3 || typeof envelope3 !== "object" || Array.isArray(envelope3)) return null;
  const env = envelope3;
  const p = env.payload;
  if (!p || typeof p !== "object" || typeof p.type !== "string" || !KNOWN_RECEIPT_TYPES.has(p.type)) return null;
  const ar = p.action_readback;
  const pd = p.payload_digest;
  const disclosed = ar && Array.isArray(ar.disclosed_fields) ? ar.disclosed_fields.length : void 0;
  const rawDecision = str(p.decision);
  const summary = {
    type: EGRESS_SUMMARY_TYPE,
    version: EGRESS_SUMMARY_VERSION,
    source_receipt_commitment: `sha256:${receiptHash(envelope3)}`,
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
var import_node_crypto8, EGRESS_SUMMARY_TYPE, EGRESS_SUMMARY_VERSION, EGRESS_SUMMARY_FIELDS, EGRESS_SIGNED_PAYLOAD_FIELDS, EGRESS_ALLOWED_PAYLOAD_FIELDS, KNOWN_RECEIPT_TYPES, DECISIONS, MODES, REASON_CODES;
var init_egress_guard = __esm({
  "src/egress-guard.ts"() {
    "use strict";
    import_node_crypto8 = require("crypto");
    init_acta_envelope();
    EGRESS_SUMMARY_TYPE = "scopeblind.egress_summary.v1";
    EGRESS_SUMMARY_VERSION = 1;
    EGRESS_SUMMARY_FIELDS = /* @__PURE__ */ new Set([
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
    EGRESS_SIGNED_PAYLOAD_FIELDS = /* @__PURE__ */ new Set([
      ...EGRESS_SUMMARY_FIELDS,
      "public_key",
      "issuer_id",
      "issued_at"
    ]);
    EGRESS_ALLOWED_PAYLOAD_FIELDS = EGRESS_SIGNED_PAYLOAD_FIELDS;
    KNOWN_RECEIPT_TYPES = /* @__PURE__ */ new Set(["protectmcp:decision", "protectmcp:artifact", "scopeblind.coverage_statement.v1"]);
    DECISIONS = /* @__PURE__ */ new Set(["allow", "deny", "approve"]);
    MODES = /* @__PURE__ */ new Set(["enforce", "shadow", "audit"]);
    REASON_CODES = /* @__PURE__ */ new Set([
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
  }
});

// src/mcp-server.ts
var mcp_server_exports = {};
__export(mcp_server_exports, {
  runMcpServer: () => runMcpServer
});
async function loadArtifacts() {
  if (artifacts) return artifacts;
  const moduleName = "@veritasacta/artifacts";
  const mod = await import(
    /* @vite-ignore */
    moduleName
  );
  artifacts = mod;
  return mod;
}
function buildReceiptPayload(args) {
  return {
    // draft-02 s3.1 access-decision fields
    type: "protectmcp:decision",
    tool_name: args.tool,
    decision: args.decision,
    reason: args.reason_code ?? (args.decision === "deny" ? "policy_denied" : "post_execution_receipt"),
    policy_digest: args.policy_digest ?? "none",
    // Extension fields (signed alongside the s3.1 core)
    scope: args.request_id,
    mode: "enforce",
    request_id: args.request_id,
    spec: "draft-farley-acta-signed-receipts-03",
    issuer_certification: "self-signed",
    public_key: args.public_key
  };
}
function newRequestId() {
  return `mcp-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
}
async function callEvaluate(args) {
  const tool = typeof args.tool === "string" ? args.tool : "";
  const policySource = typeof args.policy === "string" ? args.policy : "";
  const input = args.input && typeof args.input === "object" ? args.input : {};
  if (!tool) return { error: "missing_tool" };
  if (!policySource.trim()) return { allowed: false, decision: "deny", reason: "no policy provided (fail-closed)", policy_digest: "none" };
  const policySet = policySetFromSource(policySource);
  const decision = await evaluateCedar(
    policySet,
    { tool, tier: "unknown", context: { ...input, input }, toolInput: input },
    void 0,
    { failClosed: true }
  );
  return {
    allowed: decision.allowed,
    decision: decision.allowed ? "allow" : "deny",
    reason: decision.reason || (decision.allowed ? "allowed" : "denied by policy"),
    policy_digest: policySet.digest
  };
}
async function callSign(args) {
  const tool = typeof args.tool === "string" ? args.tool : "";
  const decision = args.decision === "deny" ? "deny" : args.decision === "allow" ? "allow" : null;
  if (!tool) return { error: "missing_tool" };
  if (!decision) return { error: 'decision must be "allow" or "deny"' };
  const a = await loadArtifacts();
  let privateKey = typeof args.private_key_hex === "string" ? args.private_key_hex : "";
  let publicKey;
  let ephemeral = false;
  if (privateKey) {
    publicKey = a.getPublicKey(privateKey);
  } else {
    const kp = a.generateKeypair();
    privateKey = kp.privateKey;
    publicKey = kp.publicKey;
    ephemeral = true;
  }
  const requestId = newRequestId();
  const payload = buildReceiptPayload({
    tool,
    decision,
    reason_code: typeof args.reason_code === "string" ? args.reason_code : void 0,
    policy_digest: typeof args.policy_digest === "string" ? args.policy_digest : void 0,
    request_id: requestId,
    public_key: publicKey
  });
  const artifactType = decision === "deny" ? "gateway_restraint" : "decision_receipt";
  const { envelope: envelope3 } = createReceiptEnvelope(payload, privateKey, computeSbIssuerKid(publicKey));
  return { receipt: envelope3, artifact_type: artifactType, public_key: publicKey, ephemeral };
}
async function callVerify(args) {
  const receipt = args.receipt;
  if (!receipt || typeof receipt !== "object") return { valid: false, error: "missing_receipt" };
  const identity = receiptIdentity(receipt);
  const embedded = receipt.payload?.public_key;
  const key = typeof args.public_key_hex === "string" && args.public_key_hex ? args.public_key_hex : typeof embedded === "string" ? embedded : null;
  if (!key) {
    return { valid: false, error: "no_public_key", type: identity.type ?? "unknown", kid: identity.kid, issuer: identity.issuer };
  }
  const result2 = verifyReceipt(receipt, key);
  return {
    valid: result2.valid,
    error: result2.valid ? null : result2.error || "invalid_signature",
    shape: result2.shape,
    type: identity.type ?? "unknown",
    kid: identity.kid,
    issuer: identity.issuer
  };
}
async function callSelfTest() {
  const details = {};
  const denied = await callEvaluate({ tool: "Bash", input: { command: "rm -rf /" }, policy: SELF_TEST_POLICY });
  const gateDeniesForbidden = denied.allowed === false;
  details.forbidden_action = { tool: "Bash", command: "rm -rf /", allowed: denied.allowed, reason: denied.reason };
  const allowed = await callEvaluate({ tool: "Read", input: { path: "./notes.txt" }, policy: SELF_TEST_POLICY });
  details.safe_action = { tool: "Read", allowed: allowed.allowed };
  let signVerifyRoundtrip = false;
  try {
    const signed2 = await callSign({ tool: "Bash", decision: "deny", reason_code: "self_test" });
    if (signed2.receipt && signed2.public_key) {
      const ok = await callVerify({ receipt: signed2.receipt, public_key_hex: signed2.public_key });
      const tampered = JSON.parse(JSON.stringify(signed2.receipt));
      if (tampered.payload) tampered.payload.tool_name = "tampered";
      const bad = await callVerify({ receipt: tampered, public_key_hex: signed2.public_key });
      signVerifyRoundtrip = ok.valid === true && bad.valid === false;
      details.sign_verify = { valid_verifies: ok.valid, tampered_rejected: bad.valid === false };
    }
  } catch (err) {
    details.sign_verify_error = err instanceof Error ? err.message : String(err);
  }
  return {
    ok: gateDeniesForbidden && allowed.allowed === true && signVerifyRoundtrip,
    gate_denies_forbidden: gateDeniesForbidden,
    sign_verify_roundtrip: signVerifyRoundtrip,
    details,
    note: "No network was contacted."
  };
}
function textResult(id5, value) {
  return JSON.stringify({ jsonrpc: "2.0", id: id5, result: { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] } });
}
async function handleRequest(request) {
  if (request.method === "initialize") {
    return JSON.stringify({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "protect-mcp", version: process.env.PROTECT_MCP_VERSION || "0.9.7" },
        capabilities: { tools: {} }
      }
    });
  }
  if (request.method === "notifications/initialized") return "";
  if (request.method === "tools/list") {
    return JSON.stringify({ jsonrpc: "2.0", id: request.id, result: { tools: TOOLS } });
  }
  if (request.method === "tools/call") {
    const name = request.params?.name || "";
    const args = request.params?.arguments || {};
    try {
      let value;
      switch (name) {
        case "evaluate_action":
          value = await callEvaluate(args);
          break;
        case "sign_decision":
          value = await callSign(args);
          break;
        case "verify_receipt":
          value = await callVerify(args);
          break;
        case "self_test":
          value = await callSelfTest();
          break;
        default:
          value = { error: `unknown tool: ${name}` };
      }
      return textResult(request.id, value);
    } catch (err) {
      return textResult(request.id, { error: err instanceof Error ? err.message : String(err) });
    }
  }
  if (request.id !== void 0) {
    return JSON.stringify({ jsonrpc: "2.0", id: request.id, error: { code: -32601, message: `Method not found: ${request.method}` } });
  }
  return "";
}
async function runMcpServer() {
  const rl = (0, import_node_readline2.createInterface)({ input: process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    chain = chain.then(async () => {
      try {
        const request = JSON.parse(trimmed);
        const response = await handleRequest(request);
        if (response) process.stdout.write(response + "\n");
      } catch {
      }
    });
  });
  process.stderr.write("[PROTECT_MCP] gate MCP server started \u2014 4 tools: evaluate_action, sign_decision, verify_receipt, self_test\n");
  await new Promise((resolve5) => rl.on("close", () => resolve5()));
  await chain;
}
var import_node_readline2, artifacts, RO, TOOLS, SELF_TEST_POLICY;
var init_mcp_server = __esm({
  "src/mcp-server.ts"() {
    "use strict";
    import_node_readline2 = require("readline");
    init_cedar_evaluator();
    init_acta_envelope();
    artifacts = null;
    RO = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
    TOOLS = [
      {
        name: "evaluate_action",
        description: `Decide whether a proposed agent tool call is allowed by a Cedar policy, fail-closed. Evaluates the call against the policy the same way the protect-mcp gate does at runtime, and on any policy error the decision is DENY (never a silent allow). Inputs: tool (the tool name, e.g. "Bash" or "send_email"), input (the tool's arguments object; the policy sees it at context.input.*), and policy (inline Cedar source text). Returns JSON { allowed: boolean, decision: "allow" | "deny", reason: string, policy_digest: string (sha256 prefix of the policy) }. A missing or unparseable policy denies. Use this before an agent acts; pair with sign_decision to make the decision auditable.`,
        inputSchema: {
          type: "object",
          properties: {
            tool: { type: "string", description: 'The tool name being evaluated, e.g. "Bash", "Write", "send_email".' },
            input: { type: "object", description: "The tool's arguments. Reachable in the policy at context.input.* (e.g. context.input.command)." },
            policy: { type: "string", description: 'Inline Cedar policy source. Use MCP::Tool::call as the action and Tool::"<name>" as the resource.' }
          },
          required: ["tool", "policy"]
        },
        annotations: { title: "Evaluate an action against a Cedar policy", idempotentHint: true, ...RO }
      },
      {
        name: "sign_decision",
        description: `Turn a gate decision into an Ed25519 signed receipt (Veritas Acta format, JCS-canonical). A denial signs a gateway_restraint artifact; an allow signs a decision_receipt. This is what makes 'what the agent was blocked from doing' provable after the fact. Inputs: tool (required), decision ("allow" | "deny", required), reason_code (optional), policy_digest (optional), and private_key_hex (optional 64-hex Ed25519 secret; if omitted, an ephemeral keypair is generated and its public key is returned so the receipt still verifies). Returns JSON { receipt: object (the signed artifact), artifact_type: "decision_receipt" | "gateway_restraint", public_key: string (hex, pass this to verify_receipt or pin it), ephemeral: boolean }. Writes nothing to disk and contacts no network.`,
        inputSchema: {
          type: "object",
          properties: {
            tool: { type: "string", description: "The tool the decision is about." },
            decision: { type: "string", enum: ["allow", "deny"], description: "The gate decision to receipt." },
            reason_code: { type: "string", description: 'Optional machine reason, e.g. "restricted_list" or "post_execution_receipt".' },
            policy_digest: { type: "string", description: "Optional digest of the policy that produced the decision (e.g. from evaluate_action)." },
            private_key_hex: { type: "string", description: "Optional 64-character hex Ed25519 secret key. If omitted, an ephemeral key is generated and its public key is returned." }
          },
          required: ["tool", "decision"]
        },
        // Not idempotent: an ephemeral key and a fresh request_id are minted per call.
        annotations: { title: "Sign a decision into a receipt", idempotentHint: false, ...RO }
      },
      {
        name: "verify_receipt",
        description: 'Verify a signed receipt offline against a public key. No network, no accounts: the Ed25519 signature is checked over the canonical bytes. Inputs: receipt (the signed artifact object, required) and public_key_hex (optional; falls back to a public_key embedded in the receipt payload). Returns JSON { valid: boolean, error: string | null (e.g. "invalid_signature", "no_public_key"), type: string, kid: string | null, issuer: string | null }. For authenticity you should verify against a key you pinned out of band, not only the one carried inside the receipt.',
        inputSchema: {
          type: "object",
          properties: {
            receipt: { type: "object", description: "The signed receipt/artifact to verify." },
            public_key_hex: { type: "string", description: "Optional Ed25519 public key hex to verify against. Defaults to a key embedded in the receipt payload." }
          },
          required: ["receipt"]
        },
        annotations: { title: "Verify a receipt offline", idempotentHint: true, ...RO }
      },
      {
        name: "self_test",
        description: "Prove the gate works, end to end, with no inputs. Runs a known-forbidden action (rm -rf) against a sample deny policy and asserts it is DENIED, then signs a decision and verifies the receipt round-trips. Returns JSON { ok: boolean, gate_denies_forbidden: boolean, sign_verify_roundtrip: boolean, details: object }. This is the 'a gate that cannot prove it denies does not start' check, exposed as a callable tool. Contacts no network.",
        inputSchema: { type: "object", properties: {} },
        annotations: { title: "Prove the gate denies and receipts verify", idempotentHint: true, ...RO }
      }
    ];
    SELF_TEST_POLICY = `
permit(principal, action == Action::"MCP::Tool::call", resource);
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")
  when {
    context has input && context.input has command &&
    (context.input.command like "*rm -rf*" || context.input.command like "*mkfs*")
  };
`;
    if (process.argv[1] && /mcp-server\.(js|mjs|cjs|ts)$/.test(process.argv[1])) {
      runMcpServer();
    }
  }
});

// src/coordination-repository.ts
function repositoryPath(path) {
  return text(path, 300) && !path.startsWith("/") && !path.endsWith("/") && !path.includes("\\") && !path.split("/").some((p) => !p || p === "." || p === ".." || p.toLowerCase() === ".git");
}
function repositoryBranch(branch) {
  return text(branch, 150) && !branch.includes("..") && !/[~^:?*\[\\\s]/.test(branch) && !branch.startsWith("/") && !branch.endsWith("/") && !branch.endsWith(".lock") && !branch.includes("@{") && !branch.split("/").some((p) => !p || p.startsWith(".") || p.endsWith("."));
}
function pathAllowed(path, allowed) {
  if (!repositoryPath(path) || /^\.github(?:\/|$)/i.test(path) || /(^|\/)(?:\.gitmodules|CODEOWNERS)$/i.test(path)) return false;
  return allowed.some((rule) => rule.endsWith("/**") ? path.startsWith(rule.slice(0, -2)) : path === rule);
}
function validRepositoryTask(v) {
  if (!object(v) || !exact(v, ["type", "id", "title", "repository", "pull_number", "base_branch", "owner_key", "receiver_key", "authority_key", "allowed_paths", "required_checks", "reviewer_secret_hash", "issued_at", "expires_at"])) return false;
  return v.type === "scopeblind.repository.task.v1" && REPOSITORY_ID.test(String(v.id)) && text(v.title, 140) && typeof v.repository === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v.repository) && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key, v.reviewer_secret_hash].every((x) => typeof x === "string" && REPOSITORY_HEX.test(x)) && v.owner_key !== v.receiver_key && v.owner_key !== v.authority_key && v.receiver_key !== v.authority_key && Array.isArray(v.allowed_paths) && v.allowed_paths.length > 0 && v.allowed_paths.length <= 12 && new Set(v.allowed_paths).size === v.allowed_paths.length && v.allowed_paths.every((p) => typeof p === "string" && repositoryPath(p.endsWith("/**") ? p.slice(0, -3) : p) && pathAllowed(p.endsWith("/**") ? p.slice(0, -2) + "placeholder" : p, [p])) && Array.isArray(v.required_checks) && v.required_checks.length > 0 && v.required_checks.length <= 12 && v.required_checks.every((c2) => object(c2) && exact(c2, ["name", "app_id"]) && text(c2.name, 100) && Number.isSafeInteger(c2.app_id) && Number(c2.app_id) > 0) && new Set(v.required_checks.map((c2) => canonical(c2))).size === v.required_checks.length && time(v.issued_at) && time(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 7 * 864e5;
}
function validRepositoryProposal(v, task, taskDigest) {
  if (!object(v) || !exact(v, ["type", "id", "task_id", "task_digest", "repository_id", "base_ref", "head_ref", "base_sha", "head_sha", "merge_sha", "tree_sha", "files", "checks", "observed_at"])) return false;
  if (v.type !== "scopeblind.repository.proposal.v1" || !REPOSITORY_ID.test(String(v.id)) || v.task_id !== task.id || v.task_digest !== taskDigest || !text(v.repository_id, 100) || v.base_ref !== `refs/heads/${task.base_branch}` || typeof v.head_ref !== "string" || !v.head_ref.startsWith("refs/heads/") || !repositoryBranch(v.head_ref.slice(11)) || v.head_ref === v.base_ref || ![v.base_sha, v.head_sha, v.merge_sha, v.tree_sha].every((s) => typeof s === "string" && REPOSITORY_SHA.test(s)) || v.base_sha === v.head_sha || v.merge_sha === v.base_sha || !time(v.observed_at)) return false;
  if (!Array.isArray(v.files) || !v.files.length || v.files.length > 50 || new Set(v.files.map((f) => object(f) ? f.path : null)).size !== v.files.length || !v.files.every((f) => object(f) && exact(f, ["path", "status", "mode", "additions", "deletions"], ["previous_path", "patch", "patch_truncated"]) && typeof f.path === "string" && pathAllowed(f.path, task.allowed_paths) && ["added", "modified", "removed", "renamed"].includes(String(f.status)) && ["100644", "100755"].includes(String(f.mode)) && Number.isSafeInteger(f.additions) && Number(f.additions) >= 0 && Number.isSafeInteger(f.deletions) && Number(f.deletions) >= 0 && (f.patch === void 0 || typeof f.patch === "string" && f.patch.length <= 400) && (f.patch_truncated === void 0 || f.patch_truncated === true) && (f.status === "renamed" ? typeof f.previous_path === "string" && pathAllowed(f.previous_path, task.allowed_paths) : f.previous_path === void 0))) return false;
  return Array.isArray(v.checks) && v.checks.length === task.required_checks.length && v.checks.every((c2) => object(c2) && exact(c2, ["id", "name", "app_id", "head_sha", "conclusion"]) && Number.isSafeInteger(c2.id) && Number(c2.id) > 0 && c2.head_sha === v.head_sha && c2.conclusion === "success" && task.required_checks.some((r) => r.name === c2.name && r.app_id === c2.app_id)) && new Set(v.checks.map((c2) => `${c2.name}:${c2.app_id}`)).size === v.checks.length;
}
async function repositorySnapshotDigest(p) {
  const { id: id5, observed_at, ...snapshot } = p;
  return sha256(canonical(snapshot));
}
function validRepositoryRecord(v, kind) {
  if (!object(v) || v.type !== `scopeblind.repository.${kind}.v1` || !REPOSITORY_ID.test(String(v.task_id)) || !REPOSITORY_HEX.test(String(v.task_digest))) return false;
  const common = ["type", "task_id", "task_digest"];
  if (kind === "claim") return exact(v, [...common, "reviewer_key", "name", "issued_at"]) && REPOSITORY_HEX.test(String(v.reviewer_key)) && text(v.name, 60) && time(v.issued_at);
  const note = (v2) => typeof v2 === "string" && v2.length <= 600;
  if (kind === "approval") return exact(v, [...common, "proposal_digest", "role", "principal_key", "decision", "issued_at", "expires_at", "note"]) && REPOSITORY_HEX.test(String(v.proposal_digest)) && REPOSITORY_HEX.test(String(v.principal_key)) && ["owner", "reviewer"].includes(String(v.role)) && ["approve", "reject"].includes(String(v.decision)) && time(v.issued_at) && time(v.expires_at) && note(v.note) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 9e5;
  if (kind === "execution") return exact(v, [...common, "operation_id", "receiver_attempt_id", "proposal_digest", "owner_approval_digest", "reviewer_approval_digest", "receiver_key", "action", "issued_at", "expires_at"]) && [v.operation_id, v.receiver_attempt_id].every((x) => REPOSITORY_ID.test(String(x))) && [v.proposal_digest, v.owner_approval_digest, v.reviewer_approval_digest, v.receiver_key].every((x) => REPOSITORY_HEX.test(String(x))) && v.action === "github.updateRefs" && time(v.issued_at) && time(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 12e4;
  if (kind === "outcome") return exact(v, [...common, "operation_id", "proposal_digest", "execution_digest", "status", "observed_base_sha", "readback", "observed_at", "note"], ["github_request_id"]) && REPOSITORY_ID.test(String(v.operation_id)) && [v.proposal_digest, v.execution_digest].every((x) => REPOSITORY_HEX.test(String(x))) && ["confirmed", "failed", "unknown"].includes(String(v.status)) && (v.observed_base_sha === null || REPOSITORY_SHA.test(String(v.observed_base_sha))) && ["exact_ref", "descendant_ref", "not_confirmed"].includes(String(v.readback)) && (v.status === "confirmed" ? v.readback !== "not_confirmed" && v.observed_base_sha !== null : v.readback === "not_confirmed") && time(v.observed_at) && note(v.note) && (v.github_request_id === void 0 || text(v.github_request_id, 200));
  return exact(v, [...common, "outcome_digest", "reviewer_key", "decision", "issued_at", "note"]) && [v.outcome_digest, v.reviewer_key].every((x) => REPOSITORY_HEX.test(String(x))) && ["accept", "request_changes"].includes(String(v.decision)) && time(v.issued_at) && note(v.note);
}
async function verifyRepositoryEvidence(value, pin) {
  const pins = typeof pin === "string" ? { authority_key: pin } : pin ?? { authority_key: value?.state?.payload?.task?.payload?.authority_key };
  const errors = [];
  let accepted = false;
  const check = (condition, message) => {
    if (!condition) errors.push(message);
  };
  try {
    const e = value, s = e.state?.payload, t = s?.task?.payload;
    check(object(e) && exact(e, ["type", "state"]) && e.type === "scopeblind.repository.evidence.v1" && validRepositoryEnvelope(e.state) && !!s && s.type === "scopeblind.repository.state.v1" && exact(s, ["type", "task", "reviewer", "proposal", "approvals", "execution", "outcome", "acceptance", "status", "revision", "observed_at"]) && Number.isSafeInteger(s.revision) && s.revision > 0 && time(s.observed_at) && await verify(e.state, pins.authority_key), "Service state signature or shape is invalid");
    check(validRepositoryEnvelope(s.task) && validRepositoryTask(t) && await verify(s.task, t.owner_key) && t.authority_key === pins.authority_key && (!pins.owner_key || pins.owner_key === t.owner_key) && (!pins.receiver_key || pins.receiver_key === t.receiver_key) && Date.parse(s.observed_at) >= Date.parse(t.issued_at), "Task or pinned owner/receiver is invalid");
    const reviewer = s.reviewer?.payload;
    if (s.reviewer) check(validRepositoryEnvelope(s.reviewer) && validRepositoryRecord(reviewer, "claim") && reviewer.task_id === t.id && reviewer.task_digest === s.task.digest && ![t.owner_key, t.receiver_key, t.authority_key].includes(reviewer.reviewer_key) && await verify(s.reviewer, reviewer.reviewer_key) && (!pins.reviewer_key || pins.reviewer_key === reviewer.reviewer_key) && Date.parse(reviewer.issued_at) >= Date.parse(t.issued_at) && Date.parse(reviewer.issued_at) < Date.parse(t.expires_at), "Reviewer role is invalid");
    if (s.proposal) check(!!reviewer && validRepositoryEnvelope(s.proposal) && validRepositoryProposal(s.proposal.payload, t, s.task.digest) && await verify(s.proposal, t.receiver_key) && Date.parse(s.proposal.payload.observed_at) >= Date.parse(reviewer.issued_at) && Date.parse(s.proposal.payload.observed_at) < Date.parse(t.expires_at), "Repository snapshot is invalid");
    check(Array.isArray(s.approvals) && s.approvals.length <= 2 && new Set(s.approvals.map((a) => a.payload.role)).size === s.approvals.length, "Approval roles are invalid");
    for (const approval of s.approvals) {
      const a = approval.payload, key = a.role === "owner" ? t.owner_key : reviewer?.reviewer_key;
      check(!!s.proposal && validRepositoryEnvelope(approval) && validRepositoryRecord(a, "approval") && a.principal_key === key && a.task_id === t.id && a.task_digest === s.task.digest && a.proposal_digest === s.proposal.digest && await verify(approval, key) && Date.parse(a.issued_at) >= Date.parse(s.proposal.payload.observed_at) && Date.parse(a.expires_at) <= Date.parse(t.expires_at), "Exact proposal approval is invalid");
    }
    if (s.execution) {
      const x = s.execution.payload, owner = s.approvals.find((a) => a.payload.role === "owner"), review = s.approvals.find((a) => a.payload.role === "reviewer");
      check(!!s.proposal && !!owner && !!review && validRepositoryEnvelope(s.execution) && validRepositoryRecord(x, "execution") && x.task_id === t.id && x.task_digest === s.task.digest && x.proposal_digest === s.proposal.digest && x.receiver_key === t.receiver_key && x.owner_approval_digest === owner?.digest && x.reviewer_approval_digest === review?.digest && owner?.payload.decision === "approve" && review?.payload.decision === "approve" && [owner, review].every((a) => a && Date.parse(a.payload.expires_at) >= Date.parse(x.expires_at) && Date.parse(a.payload.issued_at) <= Date.parse(x.issued_at)) && Date.parse(x.expires_at) <= Date.parse(t.expires_at) && await verify(s.execution, pins.authority_key), "Execution authority is invalid");
    }
    if (s.outcome) {
      const o = s.outcome.payload;
      check(!!s.execution && validRepositoryEnvelope(s.outcome) && validRepositoryRecord(o, "outcome") && o.task_id === t.id && o.task_digest === s.task.digest && o.proposal_digest === s.proposal?.digest && o.execution_digest === s.execution?.digest && o.operation_id === s.execution?.payload.operation_id && await verify(s.outcome, t.receiver_key) && Date.parse(o.observed_at) >= Date.parse(s.execution.payload.issued_at), "Receiver outcome is invalid");
      check(o.status !== "confirmed" || o.readback !== "exact_ref" || o.observed_base_sha === s.proposal?.payload.merge_sha, "Confirmed readback is invalid");
    }
    if (s.acceptance) {
      const a = s.acceptance.payload;
      check(s.outcome?.payload.status === "confirmed" && validRepositoryEnvelope(s.acceptance) && validRepositoryRecord(a, "acceptance") && a.task_id === t.id && a.task_digest === s.task.digest && a.outcome_digest === s.outcome.digest && a.reviewer_key === reviewer?.reviewer_key && await verify(s.acceptance, reviewer?.reviewer_key) && Date.parse(a.issued_at) >= Date.parse(s.outcome.payload.observed_at), "Recipient acceptance is invalid");
      accepted = a.decision === "accept";
    }
    const expected = s.acceptance ? s.acceptance.payload.decision === "accept" ? "accepted" : "changes_requested" : s.outcome ? s.outcome.payload.status : s.execution ? "executing" : !reviewer ? "awaiting_reviewer" : !s.proposal ? "awaiting_snapshot" : s.approvals.some((a) => a.payload.decision === "reject") ? "rejected" : s.approvals.length === 2 && s.approvals.every((a) => Date.parse(a.payload.expires_at) > Date.parse(s.observed_at)) ? "approved" : "review";
    check(s.status === expected || s.status === "cancelled" && !s.execution && !s.outcome && !s.acceptance, "State status is inconsistent with the signed records");
    for (const record of [s.reviewer, s.proposal, ...s.approvals, s.execution, s.outcome, s.acceptance]) if (record) check(Date.parse(record.payload.issued_at ?? record.payload.observed_at) <= Date.parse(s.observed_at), "A signed record is later than the state observation");
  } catch {
    errors.push("Malformed repository evidence");
  }
  return { valid: errors.length === 0, errors, accepted: accepted && errors.length === 0, authorityPinned: !!pin && errors.length === 0, limitations: ["The pinned receiver attests to GitHub API observations; this is not a GitHub-signed receipt.", "This controls the installed receiver\u2019s exact branch update. Other credentials and repository actions are outside its coverage.", "Destination readback establishes resulting repository state. After a lost reply it does not establish which actor caused that state.", "The checked files, commits and named checks do not prove the code is safe or universally correct.", "Signatures identify keys, not a person\u2019s legal identity.", ...!pin ? ["No independent authority key was supplied. Only consistency with the included authority was checked."] : []] };
}
var REPOSITORY_HEX, REPOSITORY_SHA, REPOSITORY_ID, object, text, time, exact, validRepositoryEnvelope;
var init_coordination_repository = __esm({
  "src/coordination-repository.ts"() {
    "use strict";
    init_coordination_protocol();
    REPOSITORY_HEX = /^[0-9a-f]{64}$/;
    REPOSITORY_SHA = /^[0-9a-f]{40}$/;
    REPOSITORY_ID = /^[A-Za-z0-9_-]{8,100}$/;
    object = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    text = (v, n) => typeof v === "string" && v.length > 0 && v.length <= n && !/[\u0000-\u001f\u007f]/.test(v);
    time = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
    exact = (v, required, optional = []) => required.every((k) => k in v) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
    validRepositoryEnvelope = (e) => object(e) && exact(e, ["payload", "signer", "digest", "signature"]);
  }
});

// src/coordination-repository-collaboration.ts
function validContactPage(value) {
  return shape(value, ["type", "button_label", "target", "accent"]) && value.type === "scopeblind.contact-page.v1" && text2(value.button_label, 40) && ["broken", "contact"].includes(String(value.target)) && ["indigo", "emerald", "rose"].includes(String(value.accent));
}
function contactPageBytes(value) {
  if (!validContactPage(value))
    throw new Error("invalid_contact_page");
  return canonical(value) + "\n";
}
function validRepositoryConnection(v) {
  if (!shape(v, ["type", "id", "endpoint", "repository", "base_branch", "owner_key", "receiver_key", "authority_key", "issued_at", "expires_at"]))
    return false;
  let endpoint2;
  try {
    endpoint2 = new URL(String(v.endpoint));
  } catch {
    return false;
  }
  return v.type === "scopeblind.repository.connection.v1" && id(v.id) && endpoint2.protocol === "https:" && endpoint2.pathname === "/api/coordination" && !endpoint2.search && !endpoint2.hash && !endpoint2.username && !endpoint2.password && endpoint2.href === v.endpoint && repository(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(hex) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.authority_key])).size === 3 && span(v.issued_at, v.expires_at, 30 * 864e5);
}
function validRepositoryReadiness(v) {
  if (!shape(v, ["type", "connection_digest", "repository", "base_branch", "owner_key", "receiver_key", "authority_key", "checks", "base_sha", "check_head_sha", "protection", "runtime", "workflow", "observed_at", "expires_at"], ["required_checks", "workflow_sha"]))
    return false;
  return v.type === "scopeblind.repository.readiness.v1" && hex(v.connection_digest) && repository(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(hex) && sha(v.base_sha) && sha(v.check_head_sha) && ["observed", "unavailable"].includes(String(v.protection)) && ["local", "github_actions"].includes(String(v.runtime)) && ["not_checked", "missing", "matching", "different", "unavailable"].includes(String(v.workflow)) && (v.workflow_sha === void 0 || sha(v.workflow_sha)) && span(v.observed_at, v.expires_at, 864e5) && Array.isArray(v.checks) && v.checks.length <= 100 && v.checks.every((c2) => shape(c2, ["name", "app_id"], ["app_name"]) && text2(c2.name, 100) && Number.isSafeInteger(c2.app_id) && Number(c2.app_id) > 0 && (c2.app_name === void 0 || text2(c2.app_name, 100))) && (v.required_checks === void 0 || Array.isArray(v.required_checks) && v.required_checks.length <= 100 && v.required_checks.every((c2) => shape(c2, ["name", "app_id"]) && text2(c2.name, 100) && (c2.app_id === null || Number.isSafeInteger(c2.app_id) && Number(c2.app_id) > 0)));
}
function validRepositoryParticipants(v) {
  return shape(v, ["type", "task_id", "task_digest", "owner_key", "receiver_key", "reviewer_key", "reviewer_claim_digest", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.participants.v1" && id(v.task_id) && [v.task_digest, v.owner_key, v.receiver_key, v.reviewer_key, v.reviewer_claim_digest].every(hex) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.reviewer_key])).size === 3 && span(v.issued_at, v.expires_at, 7 * 864e5);
}
function validRepositoryPreview(v) {
  return shape(v, ["type", "task_id", "task_digest", "proposal_digest", "base_sha", "head_sha", "merge_sha", "tree_sha", "path", "before", "after", "renderer", "observed_at"]) && v.type === "scopeblind.repository.preview.v1" && id(v.task_id) && hex(v.task_digest) && hex(v.proposal_digest) && [v.base_sha, v.head_sha, v.merge_sha, v.tree_sha].every(sha) && v.path === CONTACT_PATH && v.renderer === "scopeblind.contact-page.v1" && at(v.observed_at) && [v.before, v.after].every((side) => shape(side, ["model", "blob_sha", "content_sha256"]) && validContactPage(side.model) && sha(side.blob_sha) && hex(side.content_sha256));
}
function validRepositoryAgentGrant(v) {
  return shape(v, ["type", "id", "task_id", "task_digest", "issuer_key", "agent_key", "permissions", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.agent-grant.v1" && id(v.id) && id(v.task_id) && [v.task_digest, v.issuer_key, v.agent_key].every(hex) && v.issuer_key !== v.agent_key && Array.isArray(v.permissions) && v.permissions.length > 0 && v.permissions.length <= 2 && new Set(v.permissions).size === v.permissions.length && v.permissions.every((p) => p === "read_task" || p === "request_revision") && v.permissions.includes("read_task") && span(v.issued_at, v.expires_at, 36e5);
}
function validRepositoryRevisionRequest(v) {
  return shape(v, ["type", "id", "task_id", "task_digest", "basis_digest", "requester_key", "message", "proposed", "issued_at"], ["grant_digest"]) && v.type === "scopeblind.repository.revision-request.v1" && id(v.id) && id(v.task_id) && [v.task_digest, v.basis_digest, v.requester_key].every(hex) && (v.grant_digest === void 0 || hex(v.grant_digest)) && text2(v.message, 600) && validContactPage(v.proposed) && at(v.issued_at);
}
function validRepositoryRevisionLink(v) {
  return shape(v, ["type", "id", "parent_task_id", "parent_task_digest", "parent_basis_digest", "request_digest", "child_task_id", "child_task_digest", "owner_key", "issued_at"]) && v.type === "scopeblind.repository.revision-link.v1" && [v.id, v.parent_task_id, v.child_task_id].every(id) && v.parent_task_id !== v.child_task_id && [v.parent_task_digest, v.parent_basis_digest, v.request_digest, v.child_task_digest, v.owner_key].every(hex) && at(v.issued_at);
}
function validRepositoryDemoRequest(v) {
  if (!shape(v, ["type", "id", "owner_key", "receiver_key", "authority_key", "title", "goal", "proposed", "reviewer_secret_hash", "issued_at", "expires_at"], ["parent_task_id", "parent_task_digest", "parent_basis_digest", "revision_request_digest"]))
    return false;
  const parent = ["parent_task_id", "parent_task_digest", "parent_basis_digest", "revision_request_digest"];
  return v.type === "scopeblind.repository.demo-request.v1" && id(v.id) && [v.owner_key, v.receiver_key, v.authority_key, v.reviewer_secret_hash].every(hex) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.authority_key])).size === 3 && text2(v.title, 140) && text2(v.goal, 600) && validContactPage(v.proposed) && span(v.issued_at, v.expires_at, 864e5) && (parent.every((k) => v[k] === void 0) || id(v.parent_task_id) && [v.parent_task_digest, v.parent_basis_digest, v.revision_request_digest].every(hex));
}
function validRepositoryDemoProvision(v) {
  return shape(v, ["type", "request_id", "request_digest", "repository", "base_branch", "head_branch", "pull_number", "initial_base_sha", "initial_head_sha", "receiver_key", "required_checks", "observed_at"]) && v.type === "scopeblind.repository.demo-provision.v1" && id(v.request_id) && [v.request_digest, v.receiver_key].every(hex) && v.repository === DEMO_REPOSITORY && v.base_branch === `scopeblind/demo/${v.request_id}/base` && v.head_branch === `scopeblind/demo/${v.request_id}/change` && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && sha(v.initial_base_sha) && sha(v.initial_head_sha) && Array.isArray(v.required_checks) && canonical(v.required_checks) === canonical([DEMO_CHECK]) && at(v.observed_at);
}
function repositoryRevisionBasis(state) {
  return state.acceptance?.digest ?? state.outcome?.digest ?? state.proposal?.digest ?? null;
}
var DEMO_REPOSITORY, DEMO_CHECK, CONTACT_PATH, object2, shape, text2, hex, id, sha, at, span, repository;
var init_coordination_repository_collaboration = __esm({
  "src/coordination-repository-collaboration.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    DEMO_REPOSITORY = "ScopeBlind/scopeblind-repository-demo";
    DEMO_CHECK = { name: "ScopeBlind contact validation", app_id: 4962726 };
    CONTACT_PATH = "demo/contact.json";
    object2 = (value) => !!value && typeof value === "object" && !Array.isArray(value);
    shape = (value, required, optional = []) => object2(value) && required.every((key) => key in value) && Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
    text2 = (value, max, empty = false) => typeof value === "string" && (empty || value.trim().length > 0) && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
    hex = (value) => typeof value === "string" && REPOSITORY_HEX.test(value);
    id = (value) => typeof value === "string" && REPOSITORY_ID.test(value);
    sha = (value) => typeof value === "string" && REPOSITORY_SHA.test(value);
    at = (value) => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
    span = (issued, expires, max) => at(issued) && at(expires) && Date.parse(String(expires)) > Date.parse(String(issued)) && Date.parse(String(expires)) - Date.parse(String(issued)) <= max;
    repository = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value);
  }
});

// src/repository-receiver.ts
function requireValue(value, code2) {
  if (!value) throw new RepositoryReceiverError(code2);
}
function parseRepositoryReceiverConfig(value) {
  const c2 = value;
  requireValue(c2 && typeof c2 === "object" && Object.keys(c2).sort().join(",") === "authority_key,base_branch,endpoint,owner_key,receiver_key,repository,reviewer_key,type" && c2.type === "scopeblind.repository.receiver-config.v1", "invalid_receiver_config");
  let url;
  try {
    url = new URL(c2.endpoint);
  } catch {
    throw new RepositoryReceiverError("invalid_receiver_endpoint");
  }
  requireValue(url.protocol === "https:" && url.pathname === "/api/coordination" && !url.search && !url.hash && !url.username && !url.password && c2.endpoint === url.href, "invalid_receiver_endpoint");
  requireValue(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(c2.repository) && repositoryBranch(c2.base_branch) && [c2.authority_key, c2.owner_key, c2.reviewer_key, c2.receiver_key].every((k) => REPOSITORY_HEX.test(k)) && (/* @__PURE__ */ new Set([c2.authority_key, c2.owner_key, c2.reviewer_key, c2.receiver_key])).size === 4, "invalid_receiver_pins");
  return c2;
}
async function json(response, max = 2e6) {
  const reader = response.body?.getReader();
  requireValue(reader, "empty_http_response");
  let length = 0;
  const chunks = [];
  try {
    for (; ; ) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > max) {
        await reader.cancel();
        throw new RepositoryReceiverError("response_too_large");
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const combined = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder().decode(combined));
  } catch {
    throw new RepositoryReceiverError("invalid_json_response");
  }
}
async function runRepositoryReceiver(args) {
  const { readFile, writeFile } = await import("fs/promises");
  const action = args[0], option = (name) => {
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : void 0;
  };
  if (action === "keygen") {
    const output = option("--output");
    requireValue(output, "receiver_key_output_required");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]), publicKey = bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), privateKey2 = bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
    const identity = { publicKey };
    await writeFile(output, JSON.stringify({ type: "scopeblind.repository.receiver-key.v1", public_key: identity.publicKey, private_key: privateKey2 }, null, 2) + "\n", { mode: 384, flag: "wx" });
    process.stdout.write(`Receiver public key: ${identity.publicKey}
Private key saved to the requested owner-only file.
`);
    return;
  }
  requireValue(["inspect", "execute", "reconcile"].includes(action), "repository_command_required");
  const file = option("--config"), task = option("--task");
  requireValue(file && task && REPOSITORY_ID.test(task), "repository_config_and_task_required");
  const config = parseRepositoryReceiverConfig(JSON.parse(await readFile(file, "utf8")));
  let privateKey = process.env.SCOPEBLIND_RECEIVER_PRIVATE_KEY;
  if (option("--key-file")) {
    const key = JSON.parse(await readFile(option("--key-file"), "utf8"));
    requireValue(key.type === "scopeblind.repository.receiver-key.v1" && key.public_key === config.receiver_key, "receiver_key_mismatch");
    privateKey = key.private_key;
  }
  requireValue(privateKey && /^[0-9a-f]{96,300}$/.test(privateKey), "receiver_private_key_required");
  if (process.env.GITHUB_ACTIONS === "true") requireValue(process.env.GITHUB_REPOSITORY === config.repository && process.env.GITHUB_EVENT_NAME === "workflow_dispatch" && process.env.GITHUB_REF === `refs/heads/${config.base_branch}`, "receiver_trusted_workflow_required");
  const receiver = new RepositoryReceiver(config, await importIdentity(privateKey, config.receiver_key), process.env.GITHUB_TOKEN || ""), result2 = action === "inspect" ? await receiver.inspect(task) : action === "execute" ? await receiver.execute(task) : await receiver.reconcile(task);
  const out2 = option("--output");
  if (out2) await writeFile(out2, JSON.stringify({ type: "scopeblind.repository.evidence.v1", state: result2 }, null, 2) + "\n", { mode: 384 });
  process.stdout.write(`Repository task ${task}: ${result2.payload.status}. No PR code was executed by this receiver.
`);
}
var RepositoryReceiverError, RepositoryReceiver;
var init_repository_receiver = __esm({
  "src/repository-receiver.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    RepositoryReceiverError = class extends Error {
      constructor(code2, message = code2, uncertain = false) {
        super(message);
        this.code = code2;
        this.uncertain = uncertain;
      }
    };
    RepositoryReceiver = class {
      constructor(config, identity, githubToken2, fetchImpl = fetch) {
        this.identity = identity;
        this.githubToken = githubToken2;
        this.fetchImpl = fetchImpl;
        this.config = parseRepositoryReceiverConfig(config);
        requireValue(identity.publicKey === config.receiver_key && !identity.deviceAuthorization, "receiver_key_mismatch");
        requireValue(typeof githubToken2 === "string" && githubToken2.length > 0, "github_token_required");
      }
      config;
      async rpc(action, taskId, body = {}) {
        const request = await sign(makeRequest(action, taskId, body), this.identity);
        let response;
        try {
          response = await this.fetchImpl(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(2e4) });
        } catch {
          throw new RepositoryReceiverError("repository_service_unavailable", "The signed request may have been recorded. Inspect its current state before continuing.", true);
        }
        const data = await json(response, 15e4);
        requireValue(response.ok && data.ok === true, typeof data.error === "string" ? data.error : "repository_service_error");
        const state = data.repository_task;
        await this.validateState(state, taskId);
        return state;
      }
      async validateState(state, taskId) {
        const checked = await verifyRepositoryEvidence({ type: "scopeblind.repository.evidence.v1", state }, this.config);
        requireValue(checked.valid, "repository_evidence_invalid");
        const task = state.payload.task.payload;
        requireValue(task.id === taskId && task.repository === this.config.repository && task.base_branch === this.config.base_branch && task.owner_key === this.config.owner_key && task.receiver_key === this.config.receiver_key && state.payload.reviewer?.payload.reviewer_key === this.config.reviewer_key, "repository_scope_mismatch");
        requireValue(Math.abs(Date.now() - Date.parse(state.payload.observed_at)) <= 12e4, "repository_state_stale");
      }
      async github(path, init = {}) {
        let response;
        try {
          response = await this.fetchImpl(`https://api.github.com${path}`, { ...init, headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${this.githubToken}`, "X-GitHub-Api-Version": "2026-03-10", "content-type": "application/json" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
        } catch {
          throw new RepositoryReceiverError("github_connection_interrupted", "GitHub did not return a definite response.", init.method === "POST");
        }
        const body = await json(response);
        if (!response.ok) throw new RepositoryReceiverError(`github_http_${response.status}`, "GitHub refused the request; no repository rules are bypassed.", false);
        return { body, requestId: response.headers.get("x-github-request-id") || "" };
      }
      get repo() {
        return `/repos/${this.config.repository.split("/").map(encodeURIComponent).join("/")}`;
      }
      async ref(branch) {
        const r = (await this.github(`${this.repo}/git/ref/heads/${branch.split("/").map(encodeURIComponent).join("/")}`)).body;
        requireValue(r.ref === `refs/heads/${branch}` && r.object?.type === "commit" && REPOSITORY_SHA.test(r.object.sha), "invalid_github_ref");
        return r.object.sha;
      }
      async pull(number) {
        const pr = (await this.github(`${this.repo}/pulls/${number}`)).body;
        if (pr.merge_commit_sha === void 0 && pr.state === "open" && pr.mergeable === true) {
          const ref = (await this.github(`${this.repo}/git/ref/pull/${number}/merge`)).body;
          requireValue(ref.ref === `refs/pull/${number}/merge` && ref.object?.type === "commit" && REPOSITORY_SHA.test(ref.object.sha), "repository_merge_ref_invalid");
          return { ...pr, merge_commit_sha: ref.object.sha };
        }
        return pr;
      }
      async tree(sha2) {
        const body = (await this.github(`${this.repo}/git/trees/${sha2}?recursive=1`)).body;
        requireValue(body.sha === sha2 && !body.truncated && Array.isArray(body.tree) && body.tree.length <= 1e4, "repository_tree_incomplete");
        return new Map(body.tree.map((v) => [v.path, { type: v.type, mode: v.mode, sha: v.sha }]));
      }
      async snapshot(task, proposalId = crypto.randomUUID()) {
        const t = task.payload, pr = await this.pull(t.pull_number);
        requireValue(pr.number === t.pull_number && pr.state === "open" && !pr.draft && !pr.merged && pr.mergeable === true && pr.base?.repo?.full_name === t.repository && pr.head?.repo?.full_name === t.repository && pr.base.ref === t.base_branch && repositoryBranch(pr.head.ref) && pr.head.ref !== pr.base.ref && [pr.base.sha, pr.head.sha, pr.merge_commit_sha].every((s) => REPOSITORY_SHA.test(s)), "repository_pr_not_ready");
        const [repo, base, merge, comparison, runs, currentBase, currentHead] = await Promise.all([
          this.github(this.repo),
          this.github(`${this.repo}/git/commits/${pr.base.sha}`),
          this.github(`${this.repo}/git/commits/${pr.merge_commit_sha}`),
          this.github(`${this.repo}/compare/${pr.base.sha}...${pr.merge_commit_sha}`),
          this.github(`${this.repo}/commits/${pr.head.sha}/check-runs?per_page=100&filter=latest`),
          this.ref(t.base_branch),
          this.ref(pr.head.ref)
        ]);
        requireValue(currentBase === pr.base.sha && currentHead === pr.head.sha, "repository_changed_during_inspection");
        requireValue(repo.body.full_name === t.repository && typeof repo.body.node_id === "string" && base.body.sha === pr.base.sha && REPOSITORY_SHA.test(base.body.tree?.sha) && merge.body.sha === pr.merge_commit_sha && Array.isArray(merge.body.parents) && canonical(merge.body.parents.map((p) => p.sha)) === canonical([pr.base.sha, pr.head.sha]) && REPOSITORY_SHA.test(merge.body.tree?.sha), "repository_merge_mismatch");
        requireValue(comparison.body.base_commit?.sha === pr.base.sha && comparison.body.merge_base_commit?.sha === pr.base.sha && comparison.body.status === "ahead" && Array.isArray(comparison.body.files) && comparison.body.files.length > 0 && comparison.body.files.length <= 50, "repository_diff_incomplete");
        const [oldTree, newTree] = await Promise.all([this.tree(base.body.tree.sha), this.tree(merge.body.tree.sha)]);
        const files = comparison.body.files.map((file) => {
          requireValue(["added", "modified", "removed", "renamed"].includes(file.status) && typeof file.filename === "string" && pathAllowed(file.filename, t.allowed_paths) && (file.status !== "renamed" || typeof file.previous_filename === "string" && pathAllowed(file.previous_filename, t.allowed_paths)), "repository_path_not_allowed");
          const before = oldTree.get(file.previous_filename || file.filename), after = newTree.get(file.filename), entry = file.status === "removed" ? before : after;
          requireValue(entry?.type === "blob" && ["100644", "100755"].includes(entry.mode) && (!before || before.type === "blob" && ["100644", "100755"].includes(before.mode)) && (!after || after.type === "blob" && ["100644", "100755"].includes(after.mode)), "repository_unsafe_file_type");
          requireValue(Number.isSafeInteger(file.additions) && file.additions >= 0 && Number.isSafeInteger(file.deletions) && file.deletions >= 0, "invalid_repository_diff");
          return { path: file.filename, status: file.status, mode: entry.mode, additions: file.additions, deletions: file.deletions, ...file.status === "renamed" ? { previous_path: file.previous_filename } : {}, ...typeof file.patch === "string" ? { patch: file.patch.slice(0, 400), ...file.patch.length > 400 ? { patch_truncated: true } : {} } : {} };
        }).sort((a, b) => a.path.localeCompare(b.path));
        const actual = [.../* @__PURE__ */ new Set([...oldTree.keys(), ...newTree.keys()])].filter((path) => oldTree.get(path)?.type !== "tree" && newTree.get(path)?.type !== "tree" && canonical(oldTree.get(path) ?? null) !== canonical(newTree.get(path) ?? null)).sort();
        const listed = [...new Set(files.flatMap((f) => [f.path, ...f.previous_path ? [f.previous_path] : []]))].sort();
        requireValue(canonical(actual) === canonical(listed), "repository_diff_incomplete");
        requireValue(Number.isSafeInteger(runs.body.total_count) && runs.body.total_count <= 100 && Array.isArray(runs.body.check_runs) && runs.body.check_runs.length === runs.body.total_count, "repository_checks_incomplete");
        const checks = t.required_checks.map((required) => {
          const matching = runs.body.check_runs.filter((c2) => c2.name === required.name && c2.app?.id === required.app_id).sort((a, b) => b.id - a.id), run = matching[0];
          requireValue(run && run.head_sha === pr.head.sha && run.status === "completed" && run.conclusion === "success" && Number.isSafeInteger(run.id) && run.id > 0, "repository_check_not_passed");
          return { id: run.id, name: run.name, app_id: run.app.id, head_sha: run.head_sha, conclusion: "success" };
        }).sort((a, b) => a.name.localeCompare(b.name) || a.app_id - b.app_id);
        const current = await this.pull(t.pull_number);
        requireValue(current.state === "open" && !current.merged && !current.draft && current.head?.sha === pr.head.sha && current.base?.sha === pr.base.sha && current.merge_commit_sha === pr.merge_commit_sha && current.head?.repo?.full_name === t.repository && current.base?.repo?.full_name === t.repository, "repository_changed_during_inspection");
        const proposal = { type: "scopeblind.repository.proposal.v1", id: proposalId, task_id: t.id, task_digest: task.digest, repository_id: repo.body.node_id, base_ref: `refs/heads/${pr.base.ref}`, head_ref: `refs/heads/${pr.head.ref}`, base_sha: pr.base.sha, head_sha: pr.head.sha, merge_sha: pr.merge_commit_sha, tree_sha: merge.body.tree.sha, files, checks, observed_at: (/* @__PURE__ */ new Date()).toISOString() };
        requireValue(validRepositoryProposal(proposal, t, task.digest), "invalid_repository_proposal");
        return proposal;
      }
      async inspect(taskId) {
        requireValue(REPOSITORY_ID.test(taskId), "invalid_repository_task_id");
        const state = await this.rpc("repository_get", taskId);
        requireValue(!state.payload.execution && state.payload.status !== "cancelled" && Date.parse(state.payload.task.payload.expires_at) > Date.now(), "repository_task_inactive");
        const proposal = await sign(await this.snapshot(state.payload.task), this.identity);
        return this.rpc("repository_propose", taskId, { proposal });
      }
      async execute(taskId) {
        requireValue(REPOSITORY_ID.test(taskId), "invalid_repository_task_id");
        let state = await this.rpc("repository_get", taskId);
        if (state.payload.execution) return this.reconcileState(state);
        requireValue(state.payload.status === "approved" && state.payload.proposal && Date.parse(state.payload.task.payload.expires_at) > Date.now(), "repository_joint_approval_required");
        const approved = state.payload.proposal, observed = await this.snapshot(state.payload.task);
        requireValue(await repositorySnapshotDigest(approved.payload) === await repositorySnapshotDigest(observed), "repository_approval_stale");
        const operationId = `repo-${taskId}`, attemptId = crypto.randomUUID();
        state = await this.rpc("repository_begin", taskId, { proposal_digest: approved.digest, operation_id: operationId, attempt_id: attemptId });
        const execution = state.payload.execution;
        requireValue(execution && execution.payload.receiver_attempt_id === attemptId && execution.payload.operation_id === operationId && execution.payload.proposal_digest === approved.digest, "repository_execution_mismatch");
        requireValue(Date.parse(execution.payload.expires_at) > Date.now(), "repository_execution_expired");
        let sent = false, requestId = "", note = "";
        try {
          const final = await this.snapshot(state.payload.task);
          requireValue(await repositorySnapshotDigest(final) === await repositorySnapshotDigest(approved.payload), "repository_approval_stale");
          requireValue(Date.parse(execution.payload.expires_at) > Date.now() && state.payload.approvals.every((a) => Date.parse(a.payload.expires_at) > Date.now()), "repository_execution_expired");
          sent = true;
          const response = await this.github("/graphql", { method: "POST", body: JSON.stringify({ query: "mutation ScopeBlindApply($input: UpdateRefsInput!) { updateRefs(input: $input) { clientMutationId } }", variables: { input: { repositoryId: approved.payload.repository_id, clientMutationId: execution.payload.operation_id, refUpdates: [{ name: approved.payload.base_ref, beforeOid: approved.payload.base_sha, afterOid: approved.payload.merge_sha, force: false }, { name: approved.payload.head_ref, beforeOid: approved.payload.head_sha, afterOid: approved.payload.head_sha, force: false }] } } }) });
          requestId = response.requestId;
          if (response.body.errors?.length) throw new RepositoryReceiverError("github_atomic_update_rejected", "GitHub refused the atomic reference update.");
          requireValue(response.body.data?.updateRefs?.clientMutationId === execution.payload.operation_id, "github_update_response_unverified");
          note = "GitHub accepted the exact atomic reference update. The receiver then read back the destination.";
        } catch (error) {
          note = error instanceof RepositoryReceiverError ? error.message : "The receiver could not establish the operation outcome.";
          if (!sent) return this.report(state, { status: "failed", observed_base_sha: null, readback: "not_confirmed", note });
        }
        return this.reconcileState(state, note, requestId);
      }
      async reconcile(taskId) {
        return this.reconcileState(await this.rpc("repository_get", taskId));
      }
      async reconcileState(state, note = "Reconciled the existing operation by reading GitHub; no new reference update was sent.", requestId = "") {
        requireValue(state.payload.execution && state.payload.proposal, "repository_execution_missing");
        if (state.payload.outcome && state.payload.outcome.payload.status !== "unknown") return state;
        let sha2 = null, readback = "not_confirmed";
        try {
          sha2 = await this.ref(state.payload.task.payload.base_branch);
          if (sha2 === state.payload.proposal.payload.merge_sha) readback = "exact_ref";
          else if (sha2 !== state.payload.proposal.payload.base_sha) {
            const compare = (await this.github(`${this.repo}/compare/${state.payload.proposal.payload.merge_sha}...${sha2}`)).body;
            if (compare.base_commit?.sha === state.payload.proposal.payload.merge_sha && compare.merge_base_commit?.sha === state.payload.proposal.payload.merge_sha && ["ahead", "identical"].includes(compare.status)) readback = "descendant_ref";
          }
        } catch {
          note = "GitHub readback was unavailable. Keep this operation unresolved; do not dispatch a replacement.";
        }
        return this.report(state, { status: readback === "not_confirmed" ? "unknown" : "confirmed", observed_base_sha: sha2, readback, note, ...requestId ? { github_request_id: requestId } : {} });
      }
      async report(state, result2) {
        const s = state.payload, x = s.execution;
        const outcome = await sign({ type: "scopeblind.repository.outcome.v1", operation_id: x.payload.operation_id, task_id: s.task.payload.id, task_digest: s.task.digest, proposal_digest: s.proposal.digest, execution_digest: x.digest, ...result2, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
        return this.rpc("repository_outcome", s.task.payload.id, { outcome });
      }
    };
  }
});

// src/repository-setup.ts
var repository_setup_exports = {};
__export(repository_setup_exports, {
  REPOSITORY_SETUP_VERSION: () => REPOSITORY_SETUP_VERSION,
  createRepositoryReadiness: () => createRepositoryReadiness,
  discoverRepository: () => discoverRepository,
  parseRepositoryConnectionConfig: () => parseRepositoryConnectionConfig,
  renderRepositoryWorkflow: () => renderRepositoryWorkflow,
  runRepositoryCommand: () => runRepositoryCommand
});
function need(v, code2) {
  if (!v) throw new RepositoryReceiverError(code2);
}
async function readJson(response, max = 2e6) {
  const reader = response.body?.getReader();
  need(reader, "setup_empty_response");
  const parts = [];
  let size = 0;
  try {
    for (; ; ) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.length;
      if (size > max) {
        await reader.cancel();
        throw new RepositoryReceiverError("setup_response_too_large");
      }
      parts.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const out2 = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out2.set(part, offset);
    offset += part.length;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(out2));
  } catch {
    throw new RepositoryReceiverError("setup_invalid_json");
  }
}
async function github(path, token, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(`https://api.github.com${path}`, { method: "GET", headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2026-03-10" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
  } catch {
    throw new RepositoryReceiverError("setup_github_unavailable");
  }
  if ([403, 404].includes(response.status)) return { status: response.status, body: null };
  need(response.ok, `setup_github_http_${response.status}`);
  return { status: response.status, body: await readJson(response) };
}
async function discoverRepository(input, token, fetchImpl = fetch) {
  need(REPO.test(input.repository) && token.length > 0, "setup_repository_and_github_login_required");
  if (input.pull_number !== void 0) need(Number.isSafeInteger(input.pull_number) && input.pull_number > 0, "setup_invalid_pull_number");
  const path = `/repos/${input.repository.split("/").map(encodeURIComponent).join("/")}`;
  const repo = await github(path, token, fetchImpl);
  need(repo.status === 200 && REPO.test(repo.body.full_name) && repo.body.full_name.toLowerCase() === input.repository.toLowerCase() && repositoryBranch(repo.body.default_branch) && !repo.body.archived && !repo.body.disabled, "setup_repository_unavailable");
  const base = input.base_branch ?? repo.body.default_branch;
  need(repositoryBranch(base) && base === repo.body.default_branch, "setup_use_trusted_default_branch");
  const branch = await github(`${path}/branches/${encodeURIComponent(base)}`, token, fetchImpl);
  need(branch.status === 200 && branch.body.name === base && REPOSITORY_SHA.test(branch.body.commit?.sha), "setup_base_branch_unavailable");
  let head = branch.body.commit.sha;
  if (input.pull_number) {
    const pr = await github(`${path}/pulls/${input.pull_number}`, token, fetchImpl);
    need(pr.status === 200 && pr.body.number === input.pull_number && pr.body.state === "open" && !pr.body.merged && pr.body.base?.ref === base && pr.body.base?.repo?.full_name === repo.body.full_name && pr.body.head?.repo?.full_name === repo.body.full_name && REPOSITORY_SHA.test(pr.body.head?.sha), "setup_same_repository_pull_required");
    head = pr.body.head.sha;
  }
  const [runs, protection, rules, workflow] = await Promise.all([
    github(`${path}/commits/${head}/check-runs?per_page=100&filter=latest`, token, fetchImpl),
    github(`${path}/branches/${encodeURIComponent(base)}/protection`, token, fetchImpl),
    github(`${path}/rules/branches/${encodeURIComponent(base)}`, token, fetchImpl),
    github(`${path}/contents/${WORKFLOW_PATH}?ref=${encodeURIComponent(base)}`, token, fetchImpl)
  ]);
  need(runs.status === 200 && Number.isSafeInteger(runs.body.total_count) && runs.body.total_count >= 0 && runs.body.total_count <= 100 && Array.isArray(runs.body.check_runs) && runs.body.check_runs.length === runs.body.total_count, "setup_checks_incomplete");
  const checks = [];
  for (const run of runs.body.check_runs) {
    need(run.head_sha === head && safeText(run.name, 100) && Number.isSafeInteger(run.app?.id) && run.app.id > 0, "setup_invalid_check_provider");
    if (!checks.some((c2) => c2.name === run.name && c2.app_id === run.app.id)) checks.push({ name: run.name, app_id: run.app.id, ...safeText(run.app.name, 100) ? { app_name: run.app.name } : {} });
  }
  need(checks.length <= 100, "setup_checks_incomplete");
  checks.sort((a, b) => a.name.localeCompare(b.name) || a.app_id - b.app_id);
  const required = [];
  const add = (name, id5) => {
    need(safeText(name, 100) && (id5 === null || id5 === void 0 || id5 === -1 || Number.isSafeInteger(id5) && Number(id5) > 0), "setup_invalid_required_check");
    const check = { name, app_id: Number.isSafeInteger(id5) && Number(id5) > 0 ? Number(id5) : null };
    if (!required.some((c2) => c2.name === check.name && c2.app_id === check.app_id)) required.push(check);
    need(required.length <= 100, "setup_rules_incomplete");
  };
  if (protection.status === 200) {
    const status = protection.body.required_status_checks;
    if (status) {
      need(Array.isArray(status.contexts) && Array.isArray(status.checks), "setup_invalid_branch_protection");
      for (const c2 of status.checks) add(c2.context, c2.app_id);
      for (const context of status.contexts) if (!status.checks.some((c2) => c2.context === context)) add(context, null);
    }
  }
  if (rules.status === 200) {
    need(Array.isArray(rules.body) && rules.body.length <= 100, "setup_rules_incomplete");
    for (const rule of rules.body) if (rule.type === "required_status_checks") {
      need(Array.isArray(rule.parameters?.required_status_checks), "setup_invalid_repository_rules");
      for (const c2 of rule.parameters.required_status_checks) add(c2.context, c2.integration_id);
    }
  }
  let workflowSha, workflowHash;
  if (workflow.status === 200) {
    need(workflow.body.type === "file" && workflow.body.path === WORKFLOW_PATH && REPOSITORY_SHA.test(workflow.body.sha) && workflow.body.encoding === "base64" && typeof workflow.body.content === "string" && workflow.body.content.length <= 1e5, "setup_invalid_workflow_response");
    workflowSha = workflow.body.sha;
    workflowHash = await sha256(Buffer.from(workflow.body.content, "base64").toString("utf8"));
  }
  const warnings = [];
  if (!checks.length) warnings.push("No check runs were observed on this commit. Run the repository\u2019s existing CI or repeat setup with --pull NUMBER; do not invent a check name or provider.");
  if (protection.status !== 200 || rules.status !== 200) warnings.push("Some repository protection requirements could not be read. This does not mean the branch is unprotected; review its rules in GitHub.");
  if (required.some((c2) => c2.app_id === null)) warnings.push("Some required status checks do not pin an app. Select the actual observed provider explicitly; setup does not treat an unpinned name as a verified provider.");
  if (required.some((c2) => !checks.some((o) => o.name === c2.name && (c2.app_id === null || o.app_id === c2.app_id)))) warnings.push("Some required checks were not observed on this commit. Repeat discovery on a representative pull request before choosing task requirements.");
  if (checks.some((c2) => checks.some((other) => other.name === c2.name && other.app_id !== c2.app_id))) warnings.push("A check name is used by more than one app. Review the provider ID as well as the name.");
  return { repository: repo.body.full_name, base_branch: base, base_sha: branch.body.commit.sha, observed_head_sha: head, checks, required_checks: required, protection_read: protection.status === 200 ? "observed" : "unavailable", rules_read: rules.status === 200 ? "observed" : "unavailable", repository_permissions: repo.body.permissions ? { admin: repo.body.permissions.admin === true, push: repo.body.permissions.push === true } : null, workflow_state: workflow.status === 200 ? "present" : workflow.status === 404 ? "absent" : "not_checked", ...workflowSha ? { workflow_sha: workflowSha, workflow_sha256: workflowHash } : {}, warnings };
}
function endpoint(value) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new RepositoryReceiverError("setup_invalid_endpoint");
  }
  need(url.protocol === "https:" && url.pathname === "/api/coordination" && !url.username && !url.password && !url.search && !url.hash && url.href === value, "setup_invalid_endpoint");
  return url.href;
}
function parseRepositoryConnectionConfig(value) {
  const c2 = value, t = c2?.connection;
  need(c2 && Object.keys(c2).sort().join(",") === "connection,receiver_sha256,receiver_url,type,workflow_path,workflow_sha256" && c2.type === "scopeblind.repository.connection-config.v1" && t && Object.keys(t).sort().join(",") === "authority_key,base_branch,endpoint,expires_at,id,issued_at,owner_key,receiver_key,repository,type", "setup_invalid_connection_config");
  need(validRepositoryConnection(t), "setup_invalid_connection_config");
  endpoint(t.endpoint);
  need(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(c2.receiver_url) && REPOSITORY_HEX.test(c2.receiver_sha256) && c2.workflow_path === WORKFLOW_PATH && REPOSITORY_HEX.test(c2.workflow_sha256), "setup_invalid_artifact_pin");
  return c2;
}
function renderRepositoryWorkflow(artifact) {
  need(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(artifact.url) && REPOSITORY_HEX.test(artifact.sha256), "setup_invalid_artifact_pin");
  return WORKFLOW_TEMPLATE.replace("__RECEIVER_URL__", artifact.url).replace("__RECEIVER_SHA256__", artifact.sha256);
}
async function createRepositoryReadiness(connection, identity, discovery, options2 = {}) {
  const now = options2.now ?? Date.now();
  need(identity.publicKey === connection.receiver_key && !identity.deviceAuthorization && discovery.repository === connection.repository && discovery.base_branch === connection.base_branch && Date.parse(connection.expires_at) > now, "setup_connection_scope_mismatch");
  const workflow = discovery.workflow_state === "absent" ? "missing" : discovery.workflow_state === "not_checked" ? "unavailable" : !options2.workflow_sha256 ? "not_checked" : discovery.workflow_sha256 === options2.workflow_sha256 ? "matching" : "different";
  const readiness = { type: "scopeblind.repository.readiness.v1", connection_digest: await sha256(COORDINATION_DOMAIN + canonical(connection)), repository: connection.repository, base_branch: connection.base_branch, owner_key: connection.owner_key, receiver_key: identity.publicKey, authority_key: connection.authority_key, checks: discovery.checks, base_sha: discovery.base_sha, check_head_sha: discovery.observed_head_sha, required_checks: discovery.required_checks, protection: discovery.protection_read, runtime: options2.runtime ?? "local", workflow, ...discovery.workflow_sha ? { workflow_sha: discovery.workflow_sha } : {}, observed_at: new Date(now).toISOString(), expires_at: new Date(Math.min(now + 864e5, Date.parse(connection.expires_at))).toISOString() };
  need(validRepositoryConnection(connection) && validRepositoryReadiness(readiness), "setup_invalid_readiness");
  return { type: "scopeblind.repository.connection-import.v1", connection, readiness: await sign(readiness, identity) };
}
async function githubToken(env) {
  const value = env.GITHUB_TOKEN || env.GH_TOKEN;
  if (value) {
    need(!/[\r\n\u0000]/.test(value), "setup_invalid_github_token");
    return value;
  }
  const { execFile } = await import("child_process");
  const token = await new Promise((resolve5, reject) => execFile("gh", ["auth", "token", "--hostname", "github.com"], { encoding: "utf8", timeout: 1e4, maxBuffer: 8192, env }, (error, stdout) => error ? reject(new RepositoryReceiverError("setup_github_login_required", "Sign in locally with gh auth login, or set GITHUB_TOKEN on this trusted machine.")) : resolve5(stdout.trim())));
  need(token.length > 0 && !/[\r\n\u0000]/.test(token), "setup_github_login_required");
  return token;
}
async function localIdentity(file, expected, env) {
  const { readFile, stat } = await import("fs/promises");
  let privateKey = env.SCOPEBLIND_RECEIVER_PRIVATE_KEY, publicKey = expected;
  if (file) {
    const meta = await stat(file);
    need(meta.isFile() && (process.platform === "win32" || (meta.mode & 63) === 0), "setup_private_key_permissions");
    let key;
    try {
      key = JSON.parse(await readFile(file, "utf8"));
    } catch {
      throw new RepositoryReceiverError("setup_invalid_private_key_file");
    }
    need(key.type === "scopeblind.repository.receiver-key.v1" && (!expected || key.public_key === expected), "receiver_key_mismatch");
    privateKey = key.private_key;
    publicKey = key.public_key;
  }
  need(typeof privateKey === "string" && /^[0-9a-f]{96,300}$/.test(privateKey) && typeof publicKey === "string" && REPOSITORY_HEX.test(publicKey), "receiver_private_key_required");
  try {
    return await importIdentity(privateKey, publicKey);
  } catch {
    throw new RepositoryReceiverError("receiver_key_mismatch");
  }
}
async function checkServicePin(url, pin, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(`${endpoint(url)}?op=info`, { method: "GET", redirect: "error", signal: AbortSignal.timeout(2e4) });
  } catch {
    throw new RepositoryReceiverError("setup_service_unavailable");
  }
  const info = await readJson(response, 1e4);
  need(response.ok && info.ok === true && info.authority_key === pin && info.protocol === "scopeblind.coordination.v1", "setup_service_pin_mismatch");
}
async function artifactPin(url, pin, fetchImpl) {
  need(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(url), "setup_invalid_artifact_pin");
  if (pin) {
    need(REPOSITORY_HEX.test(pin), "setup_invalid_artifact_pin");
    return pin;
  }
  let response;
  try {
    response = await fetchImpl(`${url}.sha256`, { method: "GET", redirect: "error", signal: AbortSignal.timeout(2e4) });
  } catch {
    throw new RepositoryReceiverError("setup_release_checksum_unavailable");
  }
  need(response.ok, "setup_release_checksum_unavailable");
  const value = await response.text();
  need(value.length < 1e3 && /^[0-9a-f]{64}(?:\s+[^\r\n]+)?\s*$/.test(value), "setup_invalid_release_checksum");
  return value.slice(0, 64);
}
async function runRepositoryCommand(args, dependencies = {}) {
  if (!["setup", "ready"].includes(args[0])) return runRepositoryReceiver(args);
  const { readFile, writeFile, mkdir, stat } = await import("fs/promises"), { resolve: resolve5, join: join13 } = await import("path");
  const options2 = /* @__PURE__ */ new Map();
  const allowed = args[0] === "setup" ? ["--repository", "--owner-key", "--authority-key", "--endpoint", "--base", "--pull", "--key-file", "--output", "--receiver-url", "--receiver-sha256"] : ["--connection", "--key-file", "--pull", "--output"];
  for (let i = 1; i < args.length; i += 2) {
    need(allowed.includes(args[i]) && !options2.has(args[i]) && typeof args[i + 1] === "string" && !args[i + 1].startsWith("--"), "setup_invalid_arguments");
    options2.set(args[i], args[i + 1]);
  }
  const env = dependencies.env ?? process.env, fetchImpl = dependencies.fetchImpl ?? fetch, stdout = dependencies.stdout ?? ((s) => process.stdout.write(s));
  const pull = options2.get("--pull");
  if (pull !== void 0) need(/^[1-9][0-9]*$/.test(pull) && Number.isSafeInteger(Number(pull)), "setup_invalid_pull_number");
  const token = await githubToken(env);
  if (args[0] === "ready") {
    need(options2.get("--connection") && options2.get("--output"), "setup_connection_and_output_required");
    let value;
    try {
      value = JSON.parse(await readFile(options2.get("--connection"), "utf8"));
    } catch {
      throw new RepositoryReceiverError("setup_invalid_connection_config");
    }
    const config2 = parseRepositoryConnectionConfig(value), identity2 = await localIdentity(options2.get("--key-file"), config2.connection.receiver_key, env);
    await checkServicePin(config2.connection.endpoint, config2.connection.authority_key, fetchImpl);
    const discovery2 = await discoverRepository({ repository: config2.connection.repository, base_branch: config2.connection.base_branch, ...pull ? { pull_number: Number(pull) } : {} }, token, fetchImpl);
    const actions = env.GITHUB_ACTIONS === "true";
    if (actions) need(env.GITHUB_REPOSITORY === config2.connection.repository && env.GITHUB_EVENT_NAME === "workflow_dispatch" && env.GITHUB_REF === `refs/heads/${config2.connection.base_branch}` && discovery2.workflow_sha256 === config2.workflow_sha256 && env.GITHUB_WORKFLOW_REF === `${config2.connection.repository}/${WORKFLOW_PATH}@refs/heads/${config2.connection.base_branch}`, "receiver_trusted_workflow_required");
    const result3 = await createRepositoryReadiness(config2.connection, identity2, discovery2, { runtime: actions ? "github_actions" : "local", workflow_sha256: config2.workflow_sha256 });
    await writeFile(options2.get("--output"), JSON.stringify(result3, null, 2) + "\n", { mode: 384, flag: "wx" });
    stdout(`Read-only readiness recorded for ${config2.connection.repository}. No task was approved or executed. Import the public observation into the repository connection.
`);
    return;
  }
  const repository2 = options2.get("--repository"), owner = options2.get("--owner-key"), authority = options2.get("--authority-key"), output = options2.get("--output");
  need(repository2 && REPO.test(repository2) && owner && REPOSITORY_HEX.test(owner) && authority && REPOSITORY_HEX.test(authority) && owner !== authority && output, "setup_repository_owner_pin_and_output_required");
  const service = endpoint(options2.get("--endpoint") ?? "https://scopeblind.com/api/coordination");
  await checkServicePin(service, authority, fetchImpl);
  const discovery = await discoverRepository({ repository: repository2, base_branch: options2.get("--base"), ...pull ? { pull_number: Number(pull) } : {} }, token, fetchImpl);
  const url = options2.get("--receiver-url") ?? `https://scopeblind.com/releases/repository-receiver-${REPOSITORY_SETUP_VERSION}.cjs`, hash = await artifactPin(url, options2.get("--receiver-sha256"), fetchImpl), workflow = renderRepositoryWorkflow({ url, sha256: hash });
  const directory = resolve5(output);
  let exists = false;
  try {
    await stat(directory);
    exists = true;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  need(!exists, "setup_output_exists");
  await mkdir(directory, { mode: 448 });
  let keyFile = options2.get("--key-file");
  if (!keyFile) {
    keyFile = join13(directory, "receiver-key.json");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const key = { type: "scopeblind.repository.receiver-key.v1", public_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), private_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))) };
    await writeFile(keyFile, JSON.stringify(key, null, 2) + "\n", { mode: 384, flag: "wx" });
  }
  const identity = await localIdentity(keyFile, void 0, env);
  need(identity.publicKey !== owner && identity.publicKey !== authority, "setup_independent_receiver_key_required");
  const now = Date.now(), connection = { type: "scopeblind.repository.connection.v1", id: crypto.randomUUID(), endpoint: service, repository: discovery.repository, base_branch: discovery.base_branch, owner_key: owner, receiver_key: identity.publicKey, authority_key: authority, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 30 * 864e5).toISOString() };
  const config = { type: "scopeblind.repository.connection-config.v1", connection, receiver_url: url, receiver_sha256: hash, workflow_path: WORKFLOW_PATH, workflow_sha256: await sha256(workflow) };
  parseRepositoryConnectionConfig(config);
  const result2 = await createRepositoryReadiness(connection, identity, discovery, { now, workflow_sha256: config.workflow_sha256 });
  const review = installationReview(config, discovery, !!options2.get("--receiver-sha256"));
  for (const [file, data] of [["connection.json", JSON.stringify(result2, null, 2) + "\n"], ["connection-config.json", JSON.stringify(config, null, 2) + "\n"], ["discovery.json", JSON.stringify(discovery, null, 2) + "\n"], ["scopeblind-receiver.yml", workflow], ["INSTALL.md", review]]) await writeFile(join13(directory, file), data, { mode: 384, flag: "wx" });
  stdout(`Read-only repository setup prepared for ${discovery.repository}.
Receiver public key: ${identity.publicKey}
Review ${join13(directory, "INSTALL.md")} and import ${join13(directory, "connection.json")} in your original authorized browser.
No workflow, secret, repository setting, task approval or branch update was installed. Private keys and GitHub credentials stay local.
`);
}
function installationReview(config, d, independentPin) {
  return `# Review this repository connection

Repository: ${d.repository}
Trusted default branch: ${d.base_branch}
Receiver public key: ${config.connection.receiver_key}
Service: ${config.connection.endpoint}
Service authority key: ${config.connection.authority_key}
Connection expires: ${config.connection.expires_at}

This is a signed observation of read access from this machine. It does not prove that a workflow is installed, give a task approval, or establish that branch rules allow an update. Import connection.json and explicitly authorize its exact public fields in your original browser.

## Observed checks

${d.checks.length ? d.checks.map((c2) => `- ${JSON.stringify(c2.name)} \u2014 app ${c2.app_id}${c2.app_name ? " " + JSON.stringify(c2.app_name) : ""}`).join("\n") : "No check runs were observed."}

These are available observed checks, not a claim that all are required. GitHub requirements observed: ${JSON.stringify(d.required_checks)}. Protection read: ${d.protection_read}; rules read: ${d.rules_read}.

${d.warnings.map((w) => "- " + w).join("\n")}

## Review before installing

1. Keep receiver-key.json private; never upload the setup directory, private key, GitHub token, or an environment file to ScopeBlind or a repository. The public import is connection.json only.
2. Inspect scopeblind-receiver.yml, then copy just that file to ${WORKFLOW_PATH} on the trusted default branch through your normal repository review. It never checks out or runs PR code. It requests contents:write for a later separately approved update, pull-requests:read, and checks:read. It cannot bypass repository rules.
3. Set repository Actions variable SCOPEBLIND_CONNECTION_CONFIG to the exact contents of connection-config.json. Set Actions secret SCOPEBLIND_RECEIVER_PRIVATE_KEY to the private_key field using your local secret manager. The GitHub token is provided by Actions; never add a personal token to the workflow.
4. Run the workflow manually on ${d.base_branch}, operation ready. Download its public scopeblind-repository-evidence artifact and import repository-evidence.json. Local discovery and a signed response from the installed workflow are separate observations.
5. For each task, review the exact owner/reviewer binding and download its receiver config. Set SCOPEBLIND_RECEIVER_CONFIG to that config; it does not reuse a previous task's reviewer permission. Inspect, obtain both current exact approvals, then choose execute for that task ID. After an uncertain response use reconcile, never a replacement operation.

## Reproducible receiver artifact

URL: ${config.receiver_url}
SHA-256: ${config.receiver_sha256}
Workflow SHA-256: ${config.workflow_sha256}
Checksum source: ${independentPin ? "explicit --receiver-sha256 pin supplied by the owner" : "published HTTPS checksum; compare with your independently reviewed release before enabling"}

No GitHub changes were made by setup. Re-running setup writes to a new output directory; --key-file reuses the existing private receiver key. To refresh read access without a new connection, run repository ready --connection connection-config.json --key-file PRIVATE_KEY_FILE --output new-readiness.json.
`;
}
var REPOSITORY_SETUP_VERSION, REPO, WORKFLOW_PATH, safeText, WORKFLOW_TEMPLATE;
var init_repository_setup = __esm({
  "src/repository-setup.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_collaboration();
    init_repository_receiver();
    REPOSITORY_SETUP_VERSION = "0.22.0";
    REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/;
    WORKFLOW_PATH = ".github/workflows/scopeblind-receiver.yml";
    safeText = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
    WORKFLOW_TEMPLATE = `# Review on the trusted default branch before enabling. Setup grants no task approval.
name: ScopeBlind receiver
on:
  workflow_dispatch:
    inputs:
      operation:
        description: Read-only readiness, inspect, jointly approved execute, or reconcile
        required: true
        default: ready
        type: choice
        options: [ready, inspect, execute, reconcile]
      task_id:
        description: Exact task ID (required except for ready)
        required: false
        type: string
permissions:
  contents: write
  pull-requests: read
  checks: read
concurrency:
  group: scopeblind-receiver-\${{ inputs.task_id || 'readiness' }}
  cancel-in-progress: false
jobs:
  receiver:
    if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Use the reviewed Node runtime
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: '22.22.3'
      - name: Verify the reviewed receiver artifact
        env:
          RECEIVER_URL: __RECEIVER_URL__
          RECEIVER_SHA256: __RECEIVER_SHA256__
        shell: bash
        run: |
          set -euo pipefail
          curl --fail --silent --show-error --proto '=https' --max-time 30 "$RECEIVER_URL" --output receiver.cjs
          printf '%s  receiver.cjs\\n' "$RECEIVER_SHA256" | sha256sum --check --strict
      - name: Run the constrained receiver
        env:
          GITHUB_TOKEN: \${{ github.token }}
          SCOPEBLIND_RECEIVER_PRIVATE_KEY: \${{ secrets.SCOPEBLIND_RECEIVER_PRIVATE_KEY }}
          CONNECTION_CONFIG: \${{ vars.SCOPEBLIND_CONNECTION_CONFIG }}
          RECEIVER_CONFIG: \${{ vars.SCOPEBLIND_RECEIVER_CONFIG }}
          TASK_ID: \${{ inputs.task_id }}
          OPERATION: \${{ inputs.operation }}
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          if [ "$OPERATION" = ready ]; then
            node -e 'require("node:fs").writeFileSync("connection-config.json",process.env.CONNECTION_CONFIG,{mode:0o600,flag:"wx"})'
            node receiver.cjs ready --connection connection-config.json --output repository-evidence.json
          else
            node -e 'require("node:fs").writeFileSync("receiver-config.json",process.env.RECEIVER_CONFIG,{mode:0o600,flag:"wx"})'
            node receiver.cjs "$OPERATION" --config receiver-config.json --task "$TASK_ID" --output repository-evidence.json
          fi
      - name: Keep the public signed observation
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: scopeblind-repository-evidence
          path: repository-evidence.json
          retention-days: 7
          if-no-files-found: error
`;
  }
});

// src/coordination-devices.ts
function deviceAuthorizationPreimage(payloadDigest, authorizationDigest) {
  return DEVICE_AUTHORIZATION_DOMAIN + payloadDigest + "\n" + authorizationDigest;
}
async function verifyDeviceAuthorization(value) {
  try {
    const g = value.payload;
    return exact2(value, "payload signer digest signature") && await verify(value, g.principal_key) && exact2(g, "type id link_id room_id agreement_digest principal_key device_key device_name actions issued_at expires_at authority_key") && g.type === "scopeblind.coordination.device-authorization.v1" && id2(g.id) && id2(g.link_id) && id2(g.room_id) && hex2(g.agreement_digest) && hex2(g.principal_key) && hex2(g.device_key) && g.device_key !== g.principal_key && hex2(g.authority_key) && typeof g.device_name === "string" && g.device_name.trim() === g.device_name && g.device_name.length > 0 && g.device_name.length <= 60 && Array.isArray(g.actions) && g.actions.length > 0 && g.actions.length <= DEVICE_ACTIONS.length && new Set(g.actions).size === g.actions.length && g.actions.every((action) => DEVICE_ACTIONS.includes(action)) && Number.isFinite(time2(g.issued_at)) && time2(g.expires_at) > time2(g.issued_at) && time2(g.expires_at) - time2(g.issued_at) <= DEVICE_MAX_TTL_MS;
  } catch {
    return false;
  }
}
async function contextProposal(context, g) {
  const proposal = context.proposal, p = proposal?.payload;
  return proposal && p && await verify(proposal, g.authority_key) && p.type === "scopeblind.coordination.negotiation-proposal.v1" && p.room_id === g.room_id && p.agreement_digest === g.agreement_digest ? proposal : null;
}
async function humanPermission(value, context = {}) {
  const p = value.payload, g = value.authorization?.payload;
  if (!g || !object3(p)) return null;
  const direct = (action) => typeof p.issued_at === "string" && p.room_id === g.room_id && (p.agreement_digest === void 0 || p.agreement_digest === g.agreement_digest) ? { action, at: p.issued_at } : null;
  switch (p.type) {
    case "scopeblind.coordination.request.v1":
      return typeof p.action === "string" && DEVICE_ACTIONS.includes(p.action) ? direct(p.action) : null;
    case "scopeblind.coordination.approval.v1":
      return direct("decide");
    case "scopeblind.coordination.acceptance.v1":
      return direct("accept");
    case "scopeblind.coordination.negotiation-mandate.v1":
      return p.principal_key === g.principal_key ? direct("negotiation_mandate") : null;
    case "scopeblind.coordination.negotiation-approval.v1": {
      const proposal = await contextProposal(context, g), q = proposal?.payload;
      return q && p.principal_key === g.principal_key && p.session_id === q.session_id && p.proposal_digest === proposal.digest && p.next_agreement_digest === q.next_agreement_digest && canonical(p.mandate_digests) === canonical(q.mandate_digests) && typeof p.issued_at === "string" ? { action: "negotiation_approve", at: p.issued_at } : null;
    }
    case "scopeblind.coordination.agreement.v1":
    case "scopeblind.coordination.grant.v1":
    case "scopeblind.coordination.claim.v1": {
      const proposal = await contextProposal(context, g), q = proposal?.payload, approval = context.approval;
      if (!q || !approval || approval.payload.decision !== "approve" || approval.authorization?.digest !== value.authorization?.digest || !await verifyHuman(approval, g.principal_key, { proposal, requireRecordedUse: context.requireRecordedUse, authorityKey: context.authorityKey })) return null;
      const exactPayload = p.type === "scopeblind.coordination.agreement.v1" ? q.next_agreement.owner_key === g.principal_key && canonical(p) === canonical(q.next_agreement) : p.type === "scopeblind.coordination.grant.v1" ? q.reviewer_grant.issuer === g.principal_key && canonical(p) === canonical(q.reviewer_grant) : p.guest_key === g.principal_key && p.room_id === q.next_agreement.id && p.grant_id === q.reviewer_grant.grant_id && typeof p.issued_at === "string" && time2(p.issued_at) >= time2(approval.payload.issued_at) - 3e5 && time2(p.issued_at) <= time2(approval.payload.expires_at);
      return exactPayload ? { action: "negotiation_approve", at: approval.payload.issued_at } : null;
    }
    default:
      return null;
  }
}
async function verifyHuman(value, expectedPrincipal, context = {}) {
  try {
    if (!value || !object3(value) || Object.keys(value).some((key2) => !["payload", "signer", "digest", "signature", "authorization", "authorization_signature", "authorization_use"].includes(key2))) return false;
    if (!value.authorization) return !value.authorization_signature && !value.authorization_use && await verify(value, expectedPrincipal);
    const authorization = value.authorization, g = authorization.payload;
    if (context.authorityKey !== void 0 && g.authority_key !== context.authorityKey) return false;
    if (!await verify(value) || !await verifyDeviceAuthorization(authorization) || g.principal_key !== expectedPrincipal || g.device_key !== value.signer || typeof value.authorization_signature !== "string" || !/^[0-9a-f]{128}$/.test(value.authorization_signature)) return false;
    const key = await crypto.subtle.importKey("raw", hexToBytes(value.signer), { name: "Ed25519" }, false, ["verify"]);
    if (!await crypto.subtle.verify("Ed25519", key, hexToBytes(value.authorization_signature), new TextEncoder().encode(deviceAuthorizationPreimage(value.digest, authorization.digest)))) return false;
    const permission = await humanPermission(value, context);
    if (!permission || !g.actions.includes(permission.action) || time2(permission.at) < time2(g.issued_at) - 3e5 || time2(permission.at) >= time2(g.expires_at)) return false;
    const p = value.payload;
    if (p.expires_at !== void 0 && !["scopeblind.coordination.grant.v1", "scopeblind.coordination.agreement.v1"].includes(String(p.type)) && (!Number.isFinite(time2(p.expires_at)) || time2(p.expires_at) > time2(g.expires_at))) return false;
    const use = value.authorization_use;
    if (!use) return !context.requireRecordedUse;
    const u = use.payload;
    return exact2(use, "payload signer digest signature") && await verify(use, g.authority_key) && exact2(u, "type authorization_digest principal_key device_key room_id payload_digest action recorded_at") && u.type === "scopeblind.coordination.device-use.v1" && u.authorization_digest === authorization.digest && u.principal_key === g.principal_key && u.device_key === g.device_key && u.room_id === g.room_id && u.payload_digest === value.digest && u.action === permission.action && time2(u.recorded_at) >= time2(g.issued_at) && time2(u.recorded_at) < time2(g.expires_at) && time2(u.recorded_at) >= time2(permission.at) - 3e5;
  } catch {
    return false;
  }
}
var DEVICE_AUTHORIZATION_DOMAIN, DEVICE_ACTIONS, DEVICE_LINK_TTL_MS, DEVICE_MAX_TTL_MS, hex2, id2, object3, time2, exact2;
var init_coordination_devices = __esm({
  "src/coordination-devices.ts"() {
    "use strict";
    init_coordination_protocol();
    DEVICE_AUTHORIZATION_DOMAIN = "scopeblind.coordination.device-authorization.v1\n";
    DEVICE_ACTIONS = ["inspect", "decision_inbox", "negotiation_get", "decide", "accept", "negotiation_mandate", "negotiation_approve"];
    DEVICE_LINK_TTL_MS = 10 * 60 * 1e3;
    DEVICE_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1e3;
    hex2 = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
    id2 = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(value);
    object3 = (value) => !!value && typeof value === "object" && !Array.isArray(value);
    time2 = (value) => typeof value === "string" ? Date.parse(value) : NaN;
    exact2 = (value, fields) => Object.keys(value).sort().join(" ") === fields.split(" ").sort().join(" ");
  }
});

// src/coordination-evidence.ts
async function verifyOwnerAgreement(agreement, negotiation, depth = 0) {
  try {
    if (!agreement.authorization) return await verifyHuman(agreement, agreement.payload.owner_key);
    if (depth > 4 || !negotiation?.adoption || !negotiation.adopted_agreement || canonical(negotiation.adopted_agreement) !== canonical(agreement) || negotiation.adoption.payload.room_id !== agreement.payload.id) return false;
    return (await verifyNegotiationEvidence(negotiation, agreement.payload.registrar_key, depth)).valid;
  } catch {
    return false;
  }
}
var init_coordination_evidence = __esm({
  "src/coordination-evidence.ts"() {
    "use strict";
    init_coordination_devices();
    init_coordination_negotiation();
    init_coordination_protocol();
  }
});

// src/coordination-rehearsal.ts
function parseRehearsalCase(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_rehearsal_case");
  const v = value;
  if (Object.keys(v).some((k) => !["id", "title", "kind", "invoice_id", "amount_minor", "expected", "requirement", "required"].includes(k)) || typeof v.id !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(v.id) || typeof v.title !== "string" || !v.title.trim() || v.title.length > 120 || typeof v.kind !== "string" || !kinds.has(v.kind) || typeof v.invoice_id !== "string" || !/^[A-Za-z0-9_-]{1,60}$/.test(v.invoice_id) || typeof v.expected !== "string" || !outcomes.has(v.expected) || typeof v.requirement !== "string" || !v.requirement.trim() || v.requirement.length > 400 || v.amount_minor !== void 0 && (!Number.isSafeInteger(v.amount_minor) || Number(v.amount_minor) < 1 || Number(v.amount_minor) > 1e7) || v.required !== void 0 && typeof v.required !== "boolean") throw new Error("invalid_rehearsal_case");
  if (v.kind === "invoice" === (v.expected === "invariant")) throw new Error("invalid_rehearsal_expectation");
  if (v.amount_minor !== void 0 && ["changed_approval", "expired_approval", "budget_cap"].includes(v.kind)) throw new Error("rehearsal_amount_not_supported");
  return {
    id: v.id,
    title: v.title.trim(),
    kind: v.kind,
    invoice_id: v.invoice_id,
    ...v.amount_minor !== void 0 ? { amount_minor: Number(v.amount_minor) } : {},
    expected: v.expected,
    requirement: v.requirement.trim(),
    ...v.required !== void 0 ? { required: v.required } : {}
  };
}
function parseRepairProposal(value, budget) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_repair_proposal");
  const v = value;
  if (Object.keys(v).some((k) => !["id", "approval_above_minor", "rationale"].includes(k)) || typeof v.id !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(v.id) || !Number.isSafeInteger(v.approval_above_minor) || Number(v.approval_above_minor) < 0 || Number(v.approval_above_minor) > budget || typeof v.rationale !== "string" || !v.rationale.trim() || v.rationale.length > 600) throw new Error("invalid_repair_proposal");
  return { id: v.id, approval_above_minor: Number(v.approval_above_minor), rationale: v.rationale.trim() };
}
function defaultRehearsalCases(fixtures) {
  const invoice = fixtures.invoices.find((i) => !i.duplicate_of);
  const make = (id5, title, kind, requirement) => ({ id: `required-${id5}`, title, kind, invoice_id: invoice.invoice_id, expected: "invariant", requirement, required: true });
  return [
    make("valid", "A legitimate payment can complete", "approved_invoice", "An exact, authorized invoice can be paid once. Required review must not prevent approved work from completing."),
    make("duplicate", "Submit the same invoice twice", "duplicate_invoice", "A second operation for an already-paid invoice must not create another payment."),
    make("changed", "Change the amount after approval", "changed_approval", "Approval for one exact request must not authorize a changed amount."),
    make("destination", "Change the payment destination", "changed_destination", "A payment to a destination outside the approved vendor record must be refused."),
    make("expired", "Use an expired approval", "expired_approval", "An expired exact approval cannot authorize a payment that needs review."),
    make("budget", "Go over the total budget", "budget_cap", "The aggregate budget cannot be exceeded, even with separate operations and exact approvals.")
  ];
}
async function rehearsalDigest(value) {
  return sha256(canonical(value));
}
async function verifyRehearsalEvidence(bundle, pin) {
  const checks = [];
  const add = (label, ok) => checks.push({ label, ok: !!ok });
  try {
    add("Recognized rehearsal evidence", bundle.type === "scopeblind.coordination.rehearsal-evidence.v1");
    const a = bundle.agreement.payload, r = bundle.report.payload;
    add("Bounded invoice agreement and case set", a.type === "scopeblind.coordination.agreement.v1" && a.currency === "USD" && Number.isSafeInteger(a.budget_minor) && a.budget_minor > 0 && a.budget_minor <= 1e7 && Number.isSafeInteger(a.approval_above_minor) && a.approval_above_minor >= 0 && a.approval_above_minor <= a.budget_minor && Array.isArray(bundle.cases) && bundle.cases.length >= 6 && bundle.cases.length <= 30 && new Set(bundle.cases.map((c2) => c2.id)).size === bundle.cases.length && bundle.cases.every((c2) => canonical(parseRehearsalCase(c2)) === canonical(c2)));
    add("Owner signed the source agreement", await verifyOwnerAgreement(bundle.agreement, bundle.source_negotiation) && (bundle.agreement.authorization ? !!bundle.source_negotiation : bundle.source_negotiation === void 0));
    add("Named authority signed the report", await verify(bundle.report, pin || a.registrar_key));
    add("Report authority matches the agreement", bundle.report.signer === a.registrar_key);
    add("Report binds this agreement and room", r.type === "scopeblind.coordination.rehearsal-report.v1" && r.agreement_digest === bundle.agreement.digest && r.room_id === a.id);
    add("Exact source fixtures and included cases are present", r.fixture_digest === await rehearsalDigest(bundle.fixtures) && r.cases_digest === await rehearsalDigest(bundle.cases));
    add("Report includes each case exactly once", r.results.length === bundle.cases.length && canonical(r.results.map((x) => x.case)) === canonical(bundle.cases));
    add("Declared isolation and adapter are explicit", r.isolation === "separate-fixture-ledgers" && r.adapter === "coordination-d1-sandbox" && r.runtime_revision.length > 0);
    add("Source threshold matches the tested version", r.before_approval_above_minor === a.approval_above_minor);
    if (bundle.proposal) {
      const p = bundle.proposal.payload;
      add("Authority recorded the exact proposed change", await verify(bundle.proposal, a.registrar_key) && p.type === "scopeblind.coordination.repair-proposal.v1");
      add("Proposal and report share the same source and cases", r.proposal_digest === bundle.proposal.digest && p.room_id === a.id && p.agreement_digest === bundle.agreement.digest && p.fixture_digest === r.fixture_digest && p.cases_digest === r.cases_digest);
      add("Proposed threshold matches the comparison", p.previous_approval_above_minor === a.approval_above_minor && p.approval_above_minor === r.after_approval_above_minor && Number.isSafeInteger(p.approval_above_minor) && p.approval_above_minor >= 0 && p.approval_above_minor <= a.budget_minor);
    } else add("Baseline report claims no proposed version", r.proposal_digest === void 0 && r.after_approval_above_minor === void 0);
    const selected = r.results.map((x) => bundle.proposal ? x.after : x.before);
    add("Every compared case has an observation", selected.every(Boolean) && r.results.every((x) => !!x.before && (!bundle.proposal ? x.after === void 0 : true)));
    const sound = (c2, o) => o && typeof o.reason === "string" && o.reason.length <= 2e3 && Array.isArray(o.steps) && o.steps.length > 0 && o.steps.length <= 50 && o.steps.every((s) => typeof s.action === "string" && s.action.length <= 200 && typeof s.reason === "string" && s.reason.length <= 2e3 && ["allow", "ask", "refuse", "confirmed", "rejected"].includes(s.decision)) && Number.isSafeInteger(o.payments) && o.payments >= 0 && Number.isSafeInteger(o.spent_minor) && o.spent_minor >= 0 && ["allow", "ask", "refuse", "error"].includes(o.actual) && !(o.actual === "error" && o.matched) && o.matched === (c2.expected === "invariant" ? o.invariant_passed === true : o.actual === c2.expected);
    add("Observation summaries agree with stated expectations", r.results.every((x) => sound(x.case, x.before) && (!x.after || sound(x.case, x.after))));
    add("Required safety cases remain included", defaultRehearsalCases(bundle.fixtures).every((c2) => bundle.cases.some((x) => canonical(x) === canonical(c2))));
    add("Required-case and expectation totals match the observations", r.required_passed === r.results.every((x, i) => !x.case.required || selected[i]?.matched === true) && r.expectations_met === selected.every((x) => x?.matched === true));
    if (bundle.adoption) {
      const d = bundle.adoption.payload, authorization = bundle.adoption_authorization, next = bundle.adopted_agreement;
      add("Authority recorded adoption of this exact report", await verify(bundle.adoption, a.registrar_key) && d.type === "scopeblind.coordination.rehearsal-adoption.v1" && d.source_room_id === a.id && d.source_agreement_digest === bundle.agreement.digest && d.report_digest === bundle.report.digest && d.proposal_digest === bundle.proposal?.digest && d.fixture_digest === r.fixture_digest && d.cases_digest === r.cases_digest && d.owner_key === a.owner_key && d.scope === "new-separate-sample-task");
      add("Owner signed adoption of the exact report and new agreement", authorization && next && await verify(authorization, a.owner_key) && await verify(next, a.owner_key) && authorization.digest === d.authorization_digest && authorization.payload.type === "scopeblind.coordination.request.v1" && authorization.payload.action === "rehearsal_adopt" && authorization.payload.room_id === a.id && authorization.payload.body.report_digest === bundle.report.digest && authorization.payload.body.proposal_id === bundle.proposal?.payload.id && canonical(authorization.payload.body.agreement) === canonical(next) && next.digest === d.agreement_digest && next.payload.id === d.room_id && next.payload.id !== a.id);
      add("Only the tested threshold changed in the new task", next && bundle.proposal && canonical(next.payload) === canonical({ ...a, id: next.payload.id, issued_at: next.payload.issued_at, approval_above_minor: bundle.proposal.payload.approval_above_minor }) && r.required_passed && r.expectations_met);
    } else add("No unbound adoption claims are present", !bundle.adoption_authorization && !bundle.adopted_agreement);
  } catch {
    add("Complete, well-formed rehearsal evidence", false);
  }
  return { valid: checks.every((x) => x.ok), checks, errors: checks.filter((x) => !x.ok).map((x) => x.label), limitations: [
    "These are concrete checks against isolated sample ledgers, not proof for every possible input or another deployment.",
    "The named ScopeBlind authority attests to observed gate behavior. Signatures establish integrity and key control, not independent observation or legal identity.",
    "Proposed changes grant no authority by themselves. A new sample task has its own ledger; earlier work and payments remain unchanged."
  ] };
}
var REHEARSAL_ACTIONS, kinds, outcomes;
var init_coordination_rehearsal = __esm({
  "src/coordination-rehearsal.ts"() {
    "use strict";
    init_coordination_evidence();
    init_coordination_protocol();
    REHEARSAL_ACTIONS = ["rehearsal_get", "rehearsal_case", "rehearsal_run", "rehearsal_propose"];
    kinds = /* @__PURE__ */ new Set(["invoice", "approved_invoice", "duplicate_invoice", "changed_approval", "changed_destination", "expired_approval", "budget_cap"]);
    outcomes = /* @__PURE__ */ new Set(["allow", "ask", "refuse", "invariant"]);
  }
});

// src/coordination-negotiation.ts
async function privateBriefCommitment(brief) {
  return sha256("scopeblind.negotiation.private-brief.v1\n" + canonical(brief));
}
function parseNegotiationBrief(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_private_brief");
  const v = value;
  if (!["preference,salt,text", "budget_preference,preference,salt,text"].includes(Object.keys(v).sort().join(",")) || v.budget_preference !== void 0 && !["preserve_budget", "lower_budget", "more_capacity"].includes(String(v.budget_preference)) || typeof v.text !== "string" || v.text.length > 2e3 || !["fewer_reviews", "more_review", "balanced"].includes(String(v.preference)) || typeof v.salt !== "string" || !/^[0-9a-f]{64}$/.test(v.salt)) throw new Error("invalid_private_brief");
  canonical(v);
  return v;
}
function mandateCases(mandates, fixtures) {
  return [...defaultRehearsalCases(fixtures), ...mandates.some((m) => m.payload.min_budget_minor !== void 0) ? fixtures.invoices.filter((i) => !i.duplicate_of).map((i, index) => ({ id: `sample-invoice-${index}`, title: `${i.invoice_id} \xB7 sample outcome`, kind: "invoice", invoice_id: i.invoice_id, expected: "allow", required: false, requirement: "Observe this sample invoice in isolation; its outcome is not a hard requirement." })) : [], ...mandates.flatMap((m, side) => m.payload.required_invoices.map((r, index) => ({
    id: `principal-${side}-${index}`,
    title: `${r.invoice_id} \xB7 ${r.expected === "allow" ? "keep moving" : "needs review"}`,
    kind: "invoice",
    invoice_id: r.invoice_id,
    expected: r.expected,
    requirement: `Required by ${side === 0 ? "the organizer" : "the partner"}.`,
    required: true
  })))];
}
function mandateBudget(m, sourceBudget) {
  return { min: m.min_budget_minor ?? sourceBudget, max: m.max_budget_minor ?? sourceBudget };
}
function negotiationPlanWithinMandate(m, threshold, budget, sourceBudget) {
  const range = mandateBudget(m, sourceBudget);
  return Number.isSafeInteger(threshold) && Number.isSafeInteger(budget) && budget >= range.min && budget <= range.max && threshold >= m.min_threshold_minor && threshold <= m.max_threshold_minor && threshold <= budget;
}
async function signed(v, key) {
  return exact3(v, keys("payload signer digest signature")) && HEX.test(key) && await verify(v, key);
}
function boundedAgreement(a) {
  return exact3(a, keys("type id version title owner_key registrar_key currency budget_minor approval_above_minor approval_ttl_seconds allowed_destinations issued_at"), keys("mode brief preferences assumptions require_po_match")) && a.type === "scopeblind.coordination.agreement.v1" && id3(a.id) && a.version === 1 && text3(a.title, 200) && HEX.test(a.owner_key) && HEX.test(a.registrar_key) && a.currency === "USD" && integer2(a.budget_minor, 1, 1e7) && integer2(a.approval_above_minor, 0, a.budget_minor) && integer2(a.approval_ttl_seconds, 30, 900) && Number.isFinite(time3(a.issued_at)) && Array.isArray(a.allowed_destinations) && a.allowed_destinations.length > 0 && a.allowed_destinations.length <= 100 && new Set(a.allowed_destinations).size === a.allowed_destinations.length && a.allowed_destinations.every((d) => text3(d, 500)) && (a.mode === void 0 || ["guided", "live"].includes(a.mode)) && (a.require_po_match === void 0 || typeof a.require_po_match === "boolean") && (a.brief === void 0 || typeof a.brief === "string" && a.brief.length <= 1e4) && [a.preferences, a.assumptions].every((v) => v === void 0 || Array.isArray(v) && v.length <= 100 && v.every((t) => typeof t === "string" && t.length <= 2e3));
}
function boundedFixtures(f) {
  return exact3(f, keys("revision invoices purchase_orders")) && integer2(f.revision, 1, 1e7) && Array.isArray(f.invoices) && f.invoices.length > 0 && f.invoices.length <= 100 && f.invoices.some((i) => !i.duplicate_of) && new Set(f.invoices.filter((i) => !i.duplicate_of).map((i) => i.invoice_id)).size === f.invoices.filter((i) => !i.duplicate_of).length && f.invoices.every((i) => !i.duplicate_of || f.invoices.some((base) => !base.duplicate_of && base.id === i.duplicate_of && base.invoice_id === i.invoice_id && base.amount_minor === i.amount_minor && base.destination === i.destination && base.vendor === i.vendor)) && new Set(f.invoices.map((i) => i.id)).size === f.invoices.length && f.invoices.every((i) => exact3(i, keys("id invoice_id vendor description amount_minor destination"), keys("duplicate_of purchase_order_id")) && text3(i.id, 100) && text3(i.invoice_id, 60) && text3(i.vendor, 300) && typeof i.description === "string" && i.description.length <= 2e3 && integer2(i.amount_minor, 1, 1e7) && text3(i.destination, 500) && (i.duplicate_of === void 0 || text3(i.duplicate_of, 60)) && (i.purchase_order_id === void 0 || text3(i.purchase_order_id, 100))) && Array.isArray(f.purchase_orders) && f.purchase_orders.length <= 100 && new Set(f.purchase_orders.map((p) => p.id)).size === f.purchase_orders.length && f.purchase_orders.every((p) => exact3(p, keys("id vendor destination amount_minor currency")) && text3(p.id, 100) && text3(p.vendor, 300) && text3(p.destination, 500) && integer2(p.amount_minor, 1, 1e7) && p.currency === "USD");
}
function observationConsistent(c2, o, a, f) {
  if (!exact3(o, keys("actual matched reason steps payments spent_minor"), ["invariant_passed"]) || !["allow", "ask", "refuse", "error"].includes(o.actual) || typeof o.matched !== "boolean" || typeof o.reason !== "string" || o.reason.length > 2e3 || !integer2(o.payments, 0, 2) || !integer2(o.spent_minor, 0, 2e7) || !Array.isArray(o.steps) || o.steps.length < 1 || o.steps.length > 50 || !o.steps.every((s) => exact3(s, keys("action decision reason"), keys("operation_id payload_hash")) && ["setup", "admit", "submit_changed_request", "approve_exact", "submit_expired_approval", "execute"].includes(s.action) && ["allow", "ask", "refuse", "confirmed", "rejected"].includes(s.decision) && typeof s.reason === "string" && s.reason.length <= 2e3 && (s.operation_id === void 0 || id3(s.operation_id)) && (s.payload_hash === void 0 || HEX.test(s.payload_hash)))) return false;
  if (c2.expected === "invariant" ? typeof o.invariant_passed !== "boolean" : o.invariant_passed !== void 0) return false;
  if (o.matched !== (c2.expected === "invariant" ? o.invariant_passed === true : o.actual === c2.expected)) return false;
  if (o.actual === "error") return !o.matched && o.invariant_passed !== true;
  const original = f.invoices.find((i) => i.invoice_id === c2.invoice_id);
  if (!original) return false;
  let amount3 = c2.amount_minor ?? original.amount_minor;
  if (c2.kind !== "invoice" && c2.amount_minor === void 0) amount3 = Math.min(amount3, a.budget_minor);
  if (c2.kind === "budget_cap") amount3 = Math.floor(a.budget_minor / 2) + 1;
  if (["changed_approval", "expired_approval"].includes(c2.kind) && a.mode !== "live" && !a.require_po_match && a.approval_above_minor < a.budget_minor) amount3 = a.approval_above_minor + 1;
  const admissions = o.steps.filter((s) => s.action === "admit" || s.action === "submit_changed_request"), first = admissions[0], last = admissions.at(-1);
  const executed = o.steps.filter((s) => s.action === "execute" && s.decision === "confirmed");
  if (!first || !last || o.payments !== executed.length || o.spent_minor !== amount3 * o.payments) return false;
  if (executed.some((s) => !s.operation_id || !s.payload_hash || !o.steps.slice(0, o.steps.indexOf(s)).some((p) => (p.action === "admit" || p.action === "submit_changed_request") && p.decision === "allow" && p.operation_id === s.operation_id && p.payload_hash === s.payload_hash))) return false;
  let invariant = false;
  if (c2.kind === "invoice") {
    const order = f.purchase_orders.find((p) => p.id === original.purchase_order_id);
    const poMatches = c2.amount_minor !== void 0 || !!order && order.amount_minor === amount3 && order.vendor === original.vendor && order.destination === original.destination && order.currency === "USD";
    const expectedGate = !a.allowed_destinations.includes(original.destination) || amount3 > a.budget_minor ? "refuse" : amount3 > a.approval_above_minor || a.require_po_match === true && !poMatches ? "ask" : "allow";
    return o.actual === expectedGate && o.actual === first.decision && admissions.length === 1 && o.payments <= 1;
  }
  if (c2.kind === "approved_invoice") {
    invariant = o.payments === 1 && o.spent_minor === amount3;
    if (o.actual !== (executed.length ? "allow" : "refuse")) return false;
  } else if (c2.kind === "duplicate_invoice" || c2.kind === "budget_cap") {
    if (o.actual !== last.decision || admissions.length < 2) return false;
    invariant = executed.length > 0 && last.decision !== "allow" && o.payments === 1 && o.spent_minor <= a.budget_minor;
  } else if (c2.kind === "changed_destination") {
    if (o.actual !== last.decision) return false;
    invariant = last.decision === "refuse" && o.payments === 0;
  } else if (c2.kind === "changed_approval") {
    if (first.decision === "ask") {
      if (o.actual !== last.decision) return false;
      invariant = o.steps.some((s) => s.action === "approve_exact" && s.decision === "allow") && last.action === "submit_changed_request" && last.decision !== "allow" && o.payments === 0;
    } else if (first.decision === "allow") {
      invariant = last.decision === "rejected" && last.reason === "operation_id_payload_mismatch" && o.payments === 0;
      if (o.actual !== (invariant ? "refuse" : "allow")) return false;
    } else if (o.actual !== "refuse") return false;
  } else if (c2.kind === "expired_approval") {
    if (o.actual !== last.decision) return false;
    const expired = o.steps.find((s) => s.action === "submit_expired_approval");
    invariant = expired?.decision === "rejected" && expired.reason === "invalid_approval_expiry" && (!(a.require_po_match === true || amount3 > a.approval_above_minor) || last.decision !== "allow") && o.payments === 0;
  }
  return o.invariant_passed === invariant;
}
async function verifyNegotiationEvidence(value, authorityKey, depth = 0) {
  const checks = [];
  const add = (name, passed) => checks.push({ name, passed: !!passed });
  try {
    if (depth > 4) throw new Error("Device agreement lineage exceeds supported depth");
    const e = value;
    add("Recognized public negotiation export with no private context", exact3(e, keys("type session invitation binding agreement fixtures mandates proposals responses report approvals"), keys("adoption adopted_agreement reviewer_grant reviewer_binding agent_bindings source_negotiation")) && e.type === "scopeblind.coordination.negotiation-evidence.v1");
    add("Device-signed source has only its required bounded lineage", e.agreement.authorization ? !!e.source_negotiation : e.source_negotiation === void 0);
    const a = e.agreement.payload, s = e.session.payload, i = e.invitation.payload, b = e.binding.payload;
    const authority = authorityKey ?? a.registrar_key;
    add("Owner signed the bounded source agreement and exact fixture snapshot", boundedAgreement(a) && boundedFixtures(e.fixtures) && await verifyOwnerAgreement(e.agreement, e.source_negotiation, depth + 1) && a.registrar_key === authority);
    add("Named authority signed a bounded session tied to this source", await signed(e.session, authority) && exact3(s, keys("type id room_id agreement_digest fixture_digest owner_key registrar_key invitation_digest created_at expires_at max_proposals"), ["parent_session_id", "source_operation_id", "source_invoice_id", "source_operation_digest"]) && s.type === "scopeblind.coordination.negotiation-session.v1" && id3(s.id) && s.room_id === a.id && s.agreement_digest === e.agreement.digest && s.fixture_digest === await negotiationDigest(e.fixtures) && (s.parent_session_id === void 0 || id3(s.parent_session_id) && s.parent_session_id !== s.id) && s.parent_session_id === i.parent_session_id && s.source_operation_id === i.source_operation_id && (s.source_operation_id === void 0 ? s.source_invoice_id === void 0 && s.source_operation_digest === void 0 : id3(s.source_operation_id) && text3(s.source_invoice_id, 60) && HEX.test(s.source_operation_digest ?? "") && e.fixtures.invoices.some((v) => !v.duplicate_of && v.invoice_id === s.source_invoice_id)) && s.owner_key === a.owner_key && s.registrar_key === authority && s.invitation_digest === e.invitation.digest && s.max_proposals === 3 && time3(s.created_at) >= time3(a.issued_at) - 3e5 && time3(s.expires_at) > time3(s.created_at) && time3(s.expires_at) <= time3(s.created_at) + 864e5);
    const during = (at2) => time3(at2) >= time3(s.created_at) - 3e5 && time3(at2) < time3(s.expires_at);
    add("Owner invited one counterparty for this exact session", await signed(e.invitation, a.owner_key) && exact3(i, keys("type session_id room_id agreement_digest fixture_digest issuer registrar_key role token_hash max_claims expires_at"), ["parent_session_id", "source_operation_id"]) && i.type === "scopeblind.coordination.negotiation-invitation.v1" && i.session_id === s.id && i.room_id === a.id && i.agreement_digest === e.agreement.digest && i.fixture_digest === s.fixture_digest && i.issuer === a.owner_key && i.registrar_key === authority && i.role === "counterparty" && i.max_claims === 1 && HEX.test(i.token_hash) && i.expires_at === s.expires_at);
    const claim = b.claim.payload, partner = b.guest_key, principals = [a.owner_key, partner];
    add("Distinct counterparty signed its claim and the authority bound that claim", await signed(e.binding, authority) && await signed(b.claim, partner) && exact3(b, keys("type session_id room_id invitation_digest guest_key name issued_at expires_at claim")) && b.type === "scopeblind.coordination.negotiation-binding.v1" && b.session_id === s.id && b.room_id === a.id && b.invitation_digest === e.invitation.digest && HEX.test(partner) && partner !== a.owner_key && during(b.issued_at) && b.expires_at === s.expires_at && exact3(claim, keys("type session_id room_id guest_key name issued_at nonce")) && claim.type === "scopeblind.coordination.negotiation-claim.v1" && claim.session_id === s.id && claim.room_id === a.id && claim.guest_key === partner && text3(claim.name, 60) && claim.name === b.name && id3(claim.nonce) && Math.abs(time3(claim.issued_at) - time3(b.issued_at)) <= 3e5);
    add("Exactly two distinct principal mandates are included in organizer/partner order", Array.isArray(e.mandates) && e.mandates.length === 2 && e.mandates.every((m, n) => m.payload.principal_key === principals[n]) && new Set(e.mandates.map((m) => m.digest)).size === 2);
    const mandateDigests = e.mandates.map((m) => m.digest);
    for (let n = 0; n < e.mandates.length; n++) {
      const m = e.mandates[n].payload;
      add(`Principal ${n + 1} signed bounded negotiation-only authority`, await verifyHuman(e.mandates[n], principals[n], { requireRecordedUse: true, authorityKey: authority }) && exact3(m, keys("type session_id room_id principal_key version agreement_digest fixture_digest min_threshold_minor max_threshold_minor required_invoices private_brief_commitment agent_mode actions issued_at expires_at"), ["min_budget_minor", "max_budget_minor"]) && m.type === "scopeblind.coordination.negotiation-mandate.v1" && m.session_id === s.id && m.room_id === a.id && m.principal_key === principals[n] && m.agreement_digest === e.agreement.digest && m.fixture_digest === s.fixture_digest && integer2(m.version, 1, 1e6) && (m.min_budget_minor === void 0 && m.max_budget_minor === void 0 || integer2(m.min_budget_minor, 1, 1e7) && integer2(m.max_budget_minor, m.min_budget_minor, 1e7)) && integer2(m.min_threshold_minor, 0, mandateBudget(m, a.budget_minor).max) && integer2(m.max_threshold_minor, m.min_threshold_minor, mandateBudget(m, a.budget_minor).max) && Array.isArray(m.required_invoices) && m.required_invoices.length <= 2 && new Set(m.required_invoices.map((r2) => r2.invoice_id)).size === m.required_invoices.length && m.required_invoices.every((r2) => exact3(r2, keys("invoice_id expected")) && ["allow", "ask"].includes(r2.expected) && e.fixtures.invoices.some((v) => v.invoice_id === r2.invoice_id && !v.duplicate_of)) && (s.source_invoice_id === void 0 || m.required_invoices.some((r2) => r2.invoice_id === s.source_invoice_id)) && HEX.test(m.private_brief_commitment) && ["hosted", "own", "manual"].includes(m.agent_mode) && same(m.actions, NEGOTIATION_AGENT_ACTIONS) && during(m.issued_at) && time3(m.expires_at) > time3(m.issued_at) && time3(m.expires_at) <= time3(s.expires_at));
    }
    const validAt = (principal, at2) => {
      const m = e.mandates.find((m2) => m2.payload.principal_key === principal)?.payload;
      return !!m && during(at2) && time3(at2) >= time3(m.issued_at) - 3e5 && time3(at2) < time3(m.expires_at);
    };
    const agentBindings = e.agent_bindings ?? [];
    add("Installed agent bindings are bounded and independently scoped per principal", Array.isArray(agentBindings) && agentBindings.length <= 12 && new Set(agentBindings.map((v) => v.payload.pair_id)).size === agentBindings.length);
    for (const binding of agentBindings) {
      const g = binding.payload, auth = g.owner_authorization, q = auth.payload, body = q.body, principal = g.principal_key;
      add("Principal signed the installed agent pairing authorization", await signed(binding, authority) && await signed(auth, principal) && exact3(g, keys("type pair_id room_id session_id principal_key agreement_digest owner_key agent_key name scope audience issued_at expires_at owner_authorization")) && g.type === "scopeblind.coordination.agent-binding.v1" && g.audience === "scopeblind.coordination.negotiation" && id3(g.pair_id) && g.room_id === a.id && g.session_id === s.id && principals.includes(principal) && g.owner_key === principal && HEX.test(g.agent_key) && !principals.includes(g.agent_key) && g.agreement_digest === e.agreement.digest && same(g.scope, NEGOTIATION_AGENT_ACTIONS) && validAt(principal, g.issued_at) && time3(g.expires_at) > time3(g.issued_at) && time3(g.expires_at) <= time3(e.mandates.find((m) => m.payload.principal_key === principal).payload.expires_at) && exact3(q, keys("type action room_id body issued_at nonce")) && q.type === "scopeblind.coordination.request.v1" && q.action === "negotiation_pair_create" && q.room_id === a.id && id3(q.nonce) && exact3(body, keys("session_id pair_id secret_hash name expires_at token_expires_at scope"), ["expected_agent_key"]) && (body.expected_agent_key === void 0 || body.expected_agent_key === g.agent_key) && body.session_id === s.id && body.pair_id === g.pair_id && HEX.test(String(body.secret_hash)) && text3(body.name, 60) && text3(g.name, 60) && same(body.scope, NEGOTIATION_AGENT_ACTIONS) && body.token_expires_at === g.expires_at && validAt(principal, q.issued_at) && time3(body.expires_at) > time3(q.issued_at) && time3(body.expires_at) <= time3(q.issued_at) + 9e5 && time3(g.issued_at) < time3(body.expires_at) && time3(g.issued_at) >= time3(q.issued_at) - 3e5 && time3(body.expires_at) <= time3(g.expires_at) && !agentBindings.some((other) => other.payload.agent_key === g.agent_key && other.payload.principal_key !== principal));
    }
    const actorBound = (p2) => {
      const mandate = e.mandates.find((m) => m.payload.principal_key === p2.principal_key)?.payload;
      if (!mandate || !validAt(p2.principal_key, p2.issued_at)) return false;
      if (p2.agent_mode === "manual") return p2.agent_key === void 0;
      if (p2.agent_mode === "hosted") return mandate.agent_mode === "hosted" && p2.agent_key === void 0;
      return p2.agent_mode === "own" && mandate.agent_mode === "own" && agentBindings.some((v) => v.payload.agent_key === p2.agent_key && v.payload.principal_key === p2.principal_key && time3(p2.issued_at) >= time3(v.payload.issued_at) && time3(p2.issued_at) < time3(v.payload.expires_at));
    };
    add("At most three uniquely identified proposals are included", Array.isArray(e.proposals) && e.proposals.length >= 1 && e.proposals.length <= 3 && new Set(e.proposals.map((p2) => p2.payload.id)).size === e.proposals.length);
    for (let n = 0; n < e.proposals.length; n++) {
      const envelope3 = e.proposals[n], p2 = envelope3.payload, mine = e.mandates.find((m) => m.payload.principal_key === p2.principal_key)?.payload, g = p2.reviewer_grant;
      add(`Candidate ${n + 1} has a signed source, parent and principal authority`, await signed(envelope3, authority) && exact3(p2, keys("type id approval_above_minor session_id room_id round principal_key agent_mode agreement_digest fixture_digest mandate_digests next_agreement next_agreement_digest reviewer_grant reviewer_grant_digest issued_at"), keys("parent_digest agent_key budget_minor exploration")) && p2.type === "scopeblind.coordination.negotiation-proposal.v1" && typeof p2.id === "string" && /^[A-Za-z0-9_-]{1,80}$/.test(p2.id) && p2.session_id === s.id && p2.room_id === a.id && p2.round === n + 1 && p2.parent_digest === e.proposals[n - 1]?.digest && p2.agreement_digest === e.agreement.digest && p2.fixture_digest === s.fixture_digest && same(p2.mandate_digests, mandateDigests) && (p2.exploration === void 0 || p2.exploration === true && p2.agent_mode === "manual" && !p2.agent_key) && !!mine && negotiationPlanWithinMandate(mine, p2.approval_above_minor, p2.budget_minor ?? a.budget_minor, a.budget_minor) && actorBound(p2) && (n === 0 || time3(p2.issued_at) >= time3(e.proposals[n - 1].payload.issued_at)));
      add(`Candidate ${n + 1} changes only the tested threshold and authorized budget in a separate task`, boundedAgreement(p2.next_agreement) && p2.next_agreement.id !== a.id && same(p2.next_agreement, { ...a, id: p2.next_agreement.id, issued_at: p2.issued_at, approval_above_minor: p2.approval_above_minor, budget_minor: p2.budget_minor ?? a.budget_minor }) && p2.next_agreement_digest === await negotiationPayloadDigest(p2.next_agreement));
      add(`Candidate ${n + 1} fixes the partner's future reviewer role before approval`, exact3(g, keys("type grant_id room_id agreement_digest issuer registrar_key role actions expires_at token_hash max_claims")) && g.type === "scopeblind.coordination.grant.v1" && id3(g.grant_id) && g.room_id === p2.next_agreement.id && g.agreement_digest === p2.next_agreement_digest && g.issuer === a.owner_key && g.registrar_key === authority && g.role === "reviewer" && same(g.actions, ["decide", "accept"]) && HEX.test(g.token_hash) && g.max_claims === 1 && g.expires_at === s.expires_at && p2.reviewer_grant_digest === await negotiationPayloadDigest(g));
    }
    add("Recommendations are distinct from human approvals and uniquely bound", Array.isArray(e.responses) && e.responses.length <= 6 && new Set(e.responses.map((r2) => `${r2.payload.proposal_digest}:${r2.payload.principal_key}`)).size === e.responses.length);
    for (const response of e.responses) {
      const r2 = response.payload, p2 = e.proposals.find((p3) => p3.digest === r2.proposal_digest), mine = e.mandates.find((m) => m.payload.principal_key === r2.principal_key);
      add("Authority recorded an exactly scoped principal recommendation", await signed(response, authority) && exact3(r2, keys("type session_id principal_key proposal_digest mandate_digest decision agent_mode issued_at"), ["agent_key"]) && r2.type === "scopeblind.coordination.negotiation-response.v1" && r2.session_id === s.id && !!p2 && !!mine && r2.mandate_digest === mine.digest && ["support", "no_agreement"].includes(r2.decision) && actorBound(r2) && time3(r2.issued_at) >= time3(p2.payload.issued_at) && (r2.decision !== "support" || negotiationPlanWithinMandate(mine.payload, p2.payload.approval_above_minor, p2.payload.budget_minor ?? a.budget_minor, a.budget_minor)));
    }
    const r = e.report.payload, selected = e.proposals.find((p2) => p2.digest === r.proposal_digest), p = selected.payload;
    add("Named authority signed the exact comparison and full union of required cases", await signed(e.report, authority) && exact3(r, keys("type session_id room_id proposal_digest agreement_digest fixture_digest mandate_digests cases_digest runtime_revision adapter isolation issued_at before_approval_above_minor after_approval_above_minor results required_passed expectations_met mandates_met"), ["before_budget_minor", "after_budget_minor"]) && r.type === "scopeblind.coordination.negotiation-report.v1" && r.session_id === s.id && r.room_id === a.id && !!selected && r.agreement_digest === e.agreement.digest && r.fixture_digest === s.fixture_digest && same(r.mandate_digests, mandateDigests) && r.adapter === "coordination-d1-sandbox" && r.isolation === "separate-fixture-ledgers" && typeof r.runtime_revision === "string" && (r.runtime_revision === "development-unbound" || /^scopeblind\.invoice-rehearsal\.v1:[0-9a-f]{64}$/.test(r.runtime_revision)) && time3(r.issued_at) >= time3(p.issued_at) && principals.every((key) => validAt(key, r.issued_at)) && (p.budget_minor === void 0 ? r.before_budget_minor === void 0 && r.after_budget_minor === void 0 : r.before_budget_minor === a.budget_minor && r.after_budget_minor === p.budget_minor) && r.before_approval_above_minor === a.approval_above_minor && r.after_approval_above_minor === p.approval_above_minor && Array.isArray(r.results) && r.results.length <= 110 && r.results.every((x) => exact3(x, keys("case before after"))) && same(r.results.map((x) => x.case), mandateCases(e.mandates, e.fixtures)) && r.cases_digest === await negotiationDigest(mandateCases(e.mandates, e.fixtures)));
    add("Both gate traces and payment totals support every observation summary", r.results.every((x) => observationConsistent(x.case, x.before, a, e.fixtures) && observationConsistent(x.case, x.after, p.next_agreement, e.fixtures)));
    const rangeMet = e.mandates.every((m) => negotiationPlanWithinMandate(m.payload, p.approval_above_minor, p.budget_minor ?? a.budget_minor, a.budget_minor));
    add("Required cases, expectations and both mandates match the reported calculations", r.required_passed === r.results.every((x) => !x.case.required || x.after.matched) && r.expectations_met === r.results.every((x) => x.case.id.startsWith("sample-invoice-") || x.after.matched) && r.mandates_met === (rangeMet && r.results.filter((x) => x.case.id.startsWith("principal-")).every((x) => x.after.matched)));
    add("Human decisions are at most one per principal", Array.isArray(e.approvals) && e.approvals.length <= 2 && new Set(e.approvals.map((v) => v.payload.principal_key)).size === e.approvals.length);
    for (const approval of e.approvals) {
      const v = approval.payload;
      add("Human signed a decision over these exact rules, report and mandates", await verifyHuman(approval, v.principal_key, { proposal: selected, requireRecordedUse: true, authorityKey: authority }) && exact3(v, keys("type session_id principal_key proposal_digest report_digest next_agreement_digest mandate_digests decision issued_at expires_at"), ["selection_basis"]) && v.type === "scopeblind.coordination.negotiation-approval.v1" && principals.includes(v.principal_key) && v.session_id === s.id && v.proposal_digest === selected.digest && v.report_digest === e.report.digest && (v.selection_basis === void 0 || v.selection_basis === "human-selected-tested-plan") && v.next_agreement_digest === p.next_agreement_digest && same(v.mandate_digests, mandateDigests) && ["approve", "reject"].includes(v.decision) && validAt(v.principal_key, v.issued_at) && time3(v.issued_at) >= time3(r.issued_at) - 3e5 && time3(v.expires_at) > time3(v.issued_at) && time3(v.expires_at) <= time3(s.expires_at));
    }
    if (e.reviewer_grant) add("Organizer signed the exact proposed reviewer grant", await verifyHuman(e.reviewer_grant, a.owner_key, { proposal: selected, approval: e.approvals.find((v) => v.payload.principal_key === a.owner_key), requireRecordedUse: true, authorityKey: authority }) && same(e.reviewer_grant.payload, p.reviewer_grant) && e.reviewer_grant.digest === p.reviewer_grant_digest);
    if (e.adoption) {
      const d = e.adoption.payload, next = e.adopted_agreement, g = e.reviewer_grant, binding = e.reviewer_binding, rb = binding.payload, claim2 = rb.claim.payload;
      add("Both unexpired human approvals authorize adoption of this exact tested candidate", e.approvals.length === 2 && e.approvals.every((v) => v.payload.decision === "approve" && time3(d.issued_at) >= time3(v.payload.issued_at) - 3e5 && time3(d.issued_at) < time3(v.payload.expires_at)) && selected.digest === e.proposals.at(-1).digest && principals.every((key) => validAt(key, d.issued_at)) && r.required_passed && r.expectations_met && r.mandates_met && (e.approvals.every((v) => v.payload.selection_basis === "human-selected-tested-plan") || principals.every((key) => e.responses.some((v) => v.payload.principal_key === key && v.payload.proposal_digest === selected.digest && v.payload.decision === "support"))));
      add("Authority recorded exact lineage into a new separately authorized sample task", await signed(e.adoption, authority) && exact3(d, keys("type session_id source_room_id room_id source_agreement_digest agreement_digest proposal_digest report_digest approval_digests issued_at scope")) && d.type === "scopeblind.coordination.negotiation-adoption.v1" && d.session_id === s.id && d.source_room_id === a.id && d.room_id === p.next_agreement.id && d.room_id !== a.id && d.source_agreement_digest === e.agreement.digest && d.agreement_digest === p.next_agreement_digest && d.proposal_digest === selected.digest && d.report_digest === e.report.digest && same(d.approval_digests, principals.map((key) => e.approvals.find((v) => v.payload.principal_key === key).digest)) && d.scope === "new-separate-sample-task" && await verifyHuman(next, a.owner_key, { proposal: selected, approval: e.approvals.find((v) => v.payload.principal_key === a.owner_key), requireRecordedUse: true, authorityKey: authority }) && same(next.payload, p.next_agreement) && next.digest === d.agreement_digest);
      add("Partner independently claimed the fixed reviewer role in the new task", await signed(binding, authority) && await verifyHuman(rb.claim, partner, { proposal: selected, approval: e.approvals.find((v) => v.payload.principal_key === partner), requireRecordedUse: true, authorityKey: authority }) && exact3(rb, keys("type grant_id grant_digest room_id guest_key name issued_at expires_at claim")) && rb.type === "scopeblind.coordination.binding.v1" && rb.grant_id === g.payload.grant_id && rb.grant_digest === g.digest && rb.room_id === d.room_id && rb.guest_key === partner && rb.expires_at === g.payload.expires_at && time3(rb.issued_at) >= time3(d.issued_at) && time3(rb.issued_at) < time3(rb.expires_at) && exact3(claim2, keys("type grant_id room_id guest_key name issued_at nonce")) && claim2.type === "scopeblind.coordination.claim.v1" && claim2.grant_id === rb.grant_id && claim2.room_id === d.room_id && claim2.guest_key === partner && text3(claim2.name, 60) && claim2.name === rb.name && id3(claim2.nonce) && time3(claim2.issued_at) >= time3(r.issued_at) - 3e5 && time3(claim2.issued_at) <= time3(rb.issued_at) + 3e5);
    } else add("No unbound adopted agreement or reviewer binding is present", !e.adopted_agreement && !e.reviewer_binding);
  } catch {
    add("Complete, well-formed negotiation evidence", false);
  }
  return { valid: checks.length > 0 && checks.every((c2) => c2.passed), checks, limitations: [
    "Signatures establish record integrity and control of keys. Display names are not authenticated legal identities.",
    "The named service attests to gate traces and sample-ledger effects. These records do not independently prove execution or safety for every input or deployment.",
    "Private briefs are omitted; signed commitments do not reveal or validate their contents. Recommendations are separate from human approval and adoption.",
    "Comparisons test each case in a separate ledger; observing several payable invoices does not establish that all fit one shared run budget.",
    "Expiry is checked at recorded actions. An export does not establish present authorization, revocation status, or permission to make a payment."
  ] };
}
var NEGOTIATION_MAX_PROPOSALS, NEGOTIATION_MAX_MODEL_STEPS, NEGOTIATION_AGENT_ACTIONS, NEGOTIATION_ACTIONS, negotiationDigest, negotiationPayloadDigest, HEX, id3, integer2, time3, exact3, same, keys, text3;
var init_coordination_negotiation = __esm({
  "src/coordination-negotiation.ts"() {
    "use strict";
    init_coordination_devices();
    init_coordination_evidence();
    init_coordination_protocol();
    init_coordination_rehearsal();
    NEGOTIATION_MAX_PROPOSALS = 3;
    NEGOTIATION_MAX_MODEL_STEPS = 6;
    NEGOTIATION_AGENT_ACTIONS = ["negotiation_get", "negotiation_propose", "negotiation_respond", "negotiation_compare"];
    NEGOTIATION_ACTIONS = [
      ...NEGOTIATION_AGENT_ACTIONS,
      "negotiation_create",
      "negotiation_claim",
      "negotiation_mandate",
      "negotiation_approve",
      "negotiation_adopt",
      "negotiation_pair_create",
      "negotiation_pair_claim",
      "negotiation_pair_revoke",
      "negotiation_step",
      "negotiation_cancel"
    ];
    negotiationDigest = (value) => sha256(canonical(value));
    negotiationPayloadDigest = (value) => sha256(COORDINATION_DOMAIN + canonical(value));
    HEX = /^[0-9a-f]{64}$/;
    id3 = (v, max = 100) => typeof v === "string" && /^[A-Za-z0-9_-]+$/.test(v) && v.length >= 8 && v.length <= max;
    integer2 = (v, min, max) => Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max;
    time3 = (v) => typeof v === "string" ? Date.parse(v) : NaN;
    exact3 = (v, required, optional = []) => !!v && typeof v === "object" && !Array.isArray(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
    same = (a, b) => canonical(a) === canonical(b);
    keys = (s) => s.split(" ");
    text3 = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max;
  }
});

// src/coordination-pairing.ts
function isRehearsalPairingScope(scope) {
  return Array.isArray(scope) && JSON.stringify(scope) === JSON.stringify(REHEARSAL_PAIRING_SCOPE);
}
function isNegotiationPairingScope(scope) {
  return Array.isArray(scope) && JSON.stringify(scope) === JSON.stringify(NEGOTIATION_PAIRING_SCOPE);
}
function pairingScope(code2) {
  return code2.version === 3 ? NEGOTIATION_PAIRING_SCOPE : code2.version === 2 ? REHEARSAL_PAIRING_SCOPE : PAIRING_SCOPE;
}
function pairingAudience(code2) {
  return code2.version === 3 ? NEGOTIATION_PAIRING_AUDIENCE : code2.version === 2 ? REHEARSAL_PAIRING_AUDIENCE : "scopeblind.coordination.sample-ledger";
}
function decodePairingCode(value) {
  if (!/^sbp[123]\.[A-Za-z0-9_-]{100,4000}$/.test(value)) throw new Error("The pairing code is incomplete. Copy a fresh code from the room.");
  try {
    const raw = value.slice(5).replace(/-/g, "+").replace(/_/g, "/");
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(Uint8Array.from(atob(raw), (c2) => c2.charCodeAt(0))));
    const keys2 = parsed?.version === 3 ? "audience,authority_key,endpoint,pair_id,principal_key,room_id,scope,secret,session_id,version" : parsed?.version === 2 ? "audience,authority_key,endpoint,pair_id,room_id,scope,secret,version" : "authority_key,endpoint,pair_id,room_id,secret,version";
    if (!parsed || Object.keys(parsed).sort().join(",") !== keys2 || ![1, 2, 3].includes(parsed.version) || value.slice(0, 5) !== `sbp${parsed.version}.` || parsed.version === 3 && (!isNegotiationPairingScope(parsed.scope) || parsed.audience !== NEGOTIATION_PAIRING_AUDIENCE || !/^[0-9a-f]{64}$/.test(parsed.principal_key) || !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.session_id)) || parsed.version === 2 && (!isRehearsalPairingScope(parsed.scope) || parsed.audience !== REHEARSAL_PAIRING_AUDIENCE) || !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.room_id) || !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.pair_id) || !/^[0-9a-f]{64}$/.test(parsed.authority_key) || !/^[0-9a-f]{64}$/.test(parsed.secret) || typeof parsed.endpoint !== "string") throw new Error();
    return parsed;
  } catch {
    throw new Error("The pairing code is invalid. Copy a fresh code from the room.");
  }
}
var PAIRING_SCOPE, REHEARSAL_PAIRING_SCOPE, REHEARSAL_PAIRING_AUDIENCE, NEGOTIATION_PAIRING_SCOPE, NEGOTIATION_PAIRING_AUDIENCE;
var init_coordination_pairing = __esm({
  "src/coordination-pairing.ts"() {
    "use strict";
    init_coordination_negotiation();
    init_coordination_rehearsal();
    PAIRING_SCOPE = ["inspect", "admit", "execute", "outcome", "deliver"];
    REHEARSAL_PAIRING_SCOPE = REHEARSAL_ACTIONS;
    REHEARSAL_PAIRING_AUDIENCE = "scopeblind.coordination.rehearsal";
    NEGOTIATION_PAIRING_SCOPE = NEGOTIATION_AGENT_ACTIONS;
    NEGOTIATION_PAIRING_AUDIENCE = "scopeblind.coordination.negotiation";
  }
});

// src/coordination-config.ts
function validateCoordinationConfig(config) {
  if (config.purpose !== void 0 && !["execution", "rehearsal", "negotiation"].includes(config.purpose)) throw new Error("Unknown coordination connection purpose.");
  if (config.purpose === "negotiation") {
    if (!config.sessionId || !/^[A-Za-z0-9_-]{8,100}$/.test(config.sessionId)) throw new Error("A negotiation connection requires its exact paired session ID.");
    if (!config.principalKey || !/^[0-9a-f]{64}$/.test(config.principalKey)) throw new Error("A negotiation connection requires its paired principal public key.");
  } else if (config.sessionId !== void 0 || config.principalKey !== void 0) throw new Error("Negotiation session and principal fields require a negotiation connection.");
  let endpoint2;
  try {
    endpoint2 = new URL(config.endpoint);
  } catch {
    throw new Error("Coordination endpoint must be an absolute URL.");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(endpoint2.hostname);
  if (endpoint2.protocol !== "https:" && !(endpoint2.protocol === "http:" && local)) {
    throw new Error("Coordination endpoint requires HTTPS (HTTP is permitted only on loopback for local trials).");
  }
  if (endpoint2.username || endpoint2.password || endpoint2.search || endpoint2.hash) {
    throw new Error("Coordination endpoint must not contain credentials, query parameters, or a fragment.");
  }
  if (!/^[a-fA-F0-9]{64}$/.test(config.authorityKey)) {
    throw new Error("An explicitly pinned 32-byte Ed25519 authority public key is required (64 hexadecimal characters).");
  }
  if (!/^[A-Za-z0-9_-]{8,100}$/.test(config.roomId)) throw new Error("Room ID must use 8\u2013100 letters, numbers, underscores, or hyphens.");
  if (!config.token || /[\r\n]/.test(config.token)) throw new Error("An executor token is required in the configured environment variable.");
  if (config.runId !== void 0 && !/^run-[A-Za-z0-9_-]{8,100}$/.test(config.runId)) throw new Error("Run ID must be run- followed by the room ID.");
  if (config.timeoutMs !== void 0 && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 12e4)) {
    throw new Error("Coordination timeout must be an integer from 1 to 120000 milliseconds.");
  }
  return { ...config, endpoint: endpoint2.href, authorityKey: config.authorityKey.toLowerCase() };
}
function coordinationConfigFromArgs(args, env = process.env) {
  const values = /* @__PURE__ */ new Map();
  const flags = /* @__PURE__ */ new Set(["--endpoint", "--room", "--authority-key", "--token-env", "--run"]);
  for (let i = 0; i < args.length; i += 2) {
    const flag2 = args[i];
    if (!flags.has(flag2)) throw new Error("Unknown coordination option. Use --endpoint, --room, --authority-key, --token-env, and optionally --run.");
    if (values.has(flag2)) throw new Error("Coordination options may only be supplied once.");
    const value = args[i + 1];
    if (!value || value.startsWith("--")) throw new Error("Every coordination option requires a value.");
    values.set(flag2, value);
  }
  const variable = values.get("--token-env") || "PROTECT_MCP_COORDINATION_TOKEN";
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) throw new Error("--token-env must name an environment variable.");
  return validateCoordinationConfig({
    endpoint: values.get("--endpoint") || "",
    roomId: values.get("--room") || "",
    authorityKey: values.get("--authority-key") || "",
    token: env[variable] || "",
    runId: values.get("--run")
  });
}
var init_coordination_config = __esm({
  "src/coordination-config.ts"() {
    "use strict";
  }
});

// src/coordination-agent-setup.ts
function agentClient(value) {
  if (!AGENT_CLIENTS.some((client) => client.id === value)) throw new Error("Supported setup clients: claude-code, codex, or json.");
  return value;
}
function agentServerName(purpose, roomId, pairId, principalKey) {
  const suffix = (pairId || roomId).replace(/[^A-Za-z0-9_-]/g, "").slice(0, 12);
  return purpose === "negotiation" ? `scopeblind-negotiate-${principalKey?.slice(0, 8) || "agent"}-${suffix}` : `scopeblind-${purpose === "rehearsal" ? "test" : "work"}-${suffix}`;
}
function agentRegistration(client, serverName, configPath) {
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(serverName)) throw new Error("Invalid MCP server name.");
  const launch = `npx --yes ${AGENT_PACKAGE_URL} coordination --config ${shellQuote(configPath)}`;
  if (client === "claude-code") return `claude mcp add --transport stdio --scope local ${serverName} -- ${launch}`;
  if (client === "codex") return `codex mcp add ${serverName} -- ${launch}`;
  return JSON.stringify({ mcpServers: { [serverName]: { command: "npx", args: ["--yes", AGENT_PACKAGE_URL, "coordination", "--config", configPath] } } }, null, 2);
}
function agentProfileRegistration(client, serverName, profilePath) {
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(serverName)) throw new Error("Invalid MCP server name.");
  const args = ["--yes", AGENT_PACKAGE_URL, "coordination", "agent", "--profile", profilePath];
  const launch = `npx --yes ${AGENT_PACKAGE_URL} coordination agent --profile ${shellQuote(profilePath)}`;
  if (client === "claude-code") return `claude mcp add --transport stdio --scope local ${serverName} -- ${launch}`;
  if (client === "codex") return `codex mcp add ${serverName} -- ${launch}`;
  return JSON.stringify({ mcpServers: { [serverName]: { command: "npx", args } } }, null, 2);
}
function agentPrompt(purpose, roomId, sessionId) {
  const subject = purpose === "negotiation" ? `ScopeBlind negotiation ${sessionId || "(the paired session)"} in room ${roomId}` : `ScopeBlind ${purpose === "rehearsal" ? "rehearsal" : "room"} ${roomId}`;
  if (purpose === "negotiation") return `Resume ${subject}. First call coordination.inspect_negotiation to read my current signed mandate, my private instructions, and the shared state. Summarize my hard limits without disclosing my private brief. Take only my next permitted action: propose within my limits, respond to the exact candidate, or compare it in isolation. Keep stable IDs when retrying. Use coordination.wait_negotiation when waiting for the other participant. Stop at a human decision, an unmet hard limit, or the round limit. Recommendations are not human approval; do not pay, adopt terms, or claim to run after this agent session ends.`;
  if (purpose === "rehearsal") return `Resume ${subject}. First call coordination.inspect_rehearsal to read the current signed rules, sample records, and test history. Help test my expectations and compare a proposed repair using isolated ledgers. Explain observed tradeoffs. Keep stable case, proposal, and run IDs across retries. Leave adoption and approvals to me; this connection cannot pay or change the active rules.`;
  return `Resume ${subject}. First call coordination.inspect to read the current signed agreement, sample records, and recorded operations. Reconcile the invoices within those rules. Reuse existing operation IDs; check uncertain outcomes before retrying. Use coordination.wait for reviewer decisions while this agent session is active. Stop when human action is required, the room is paused, or the result is delivered. Do not approve your own exceptions or change the rules.`;
}
var AGENT_PACKAGE_URL, AGENT_CLIENTS, shellQuote;
var init_coordination_agent_setup = __esm({
  "src/coordination-agent-setup.ts"() {
    "use strict";
    AGENT_PACKAGE_URL = "protect-mcp@0.22.0";
    AGENT_CLIENTS = [
      { id: "claude-code", label: "Claude Code" },
      { id: "codex", label: "Codex CLI" },
      { id: "json", label: "Other MCP client" }
    ];
    shellQuote = (value) => "'" + value.replace(/'/g, "'\\''") + "'";
  }
});

// src/coordination-pair-cli.ts
var coordination_pair_cli_exports = {};
__export(coordination_pair_cli_exports, {
  DEFAULT_COORDINATION_CONFIG: () => DEFAULT_COORDINATION_CONFIG,
  claimPairing: () => claimPairing,
  coordinationConfigFromFile: () => coordinationConfigFromFile,
  readPrivateConfig: () => readPrivateConfig,
  runCoordinationPair: () => runCoordinationPair,
  runCoordinationSetup: () => runCoordinationSetup,
  shellQuote: () => shellQuote
});
function readPrivateConfig(path) {
  let fd;
  try {
    fd = (0, import_node_fs14.openSync)(path, import_node_fs14.constants.O_RDONLY | import_node_fs14.constants.O_NOFOLLOW);
  } catch {
    throw new Error("The agent connection file could not be opened. Pair from the room first.");
  }
  try {
    const stat = (0, import_node_fs14.fstatSync)(fd);
    if (!stat.isFile() || stat.size > 64e3 || process.platform !== "win32" && ((stat.mode & 63) !== 0 || process.getuid && stat.uid !== process.getuid())) throw new Error("The connection file must be owned by you, with permissions 600.");
    let data;
    try {
      data = JSON.parse((0, import_node_fs14.readFileSync)(fd, "utf8"));
    } catch {
      throw new Error("The agent connection file is not valid JSON.");
    }
    if (data.type !== "scopeblind.coordination.config.v1" || data.setupVersion !== void 0 && data.setupVersion !== 2 || !/^[0-9a-f]{64}$/.test(data.agentKey)) throw new Error("The agent connection file is invalid.");
    validateCoordinationConfig(data);
    return data;
  } finally {
    (0, import_node_fs14.closeSync)(fd);
  }
}
function coordinationConfigFromFile(path) {
  const data = readPrivateConfig((0, import_node_path10.resolve)(path));
  if (!data.binding || data.pending) throw new Error("Pairing has not completed. Run the pair command again with the same --config file.");
  const binding = data.binding.payload;
  const purpose = binding.audience === NEGOTIATION_PAIRING_AUDIENCE ? "negotiation" : binding.audience === REHEARSAL_PAIRING_AUDIENCE ? "rehearsal" : "execution";
  return validateCoordinationConfig({ ...data, purpose, ...purpose === "negotiation" ? { sessionId: binding.session_id, principalKey: binding.principal_key } : {} });
}
function savePrivateConfig(path, data, create) {
  (0, import_node_fs14.mkdirSync)((0, import_node_path10.dirname)(path), { recursive: true, mode: 448 });
  if (create) {
    const fd = (0, import_node_fs14.openSync)(path, import_node_fs14.constants.O_WRONLY | import_node_fs14.constants.O_CREAT | import_node_fs14.constants.O_EXCL | import_node_fs14.constants.O_NOFOLLOW, 384);
    try {
      (0, import_node_fs14.writeFileSync)(fd, JSON.stringify(data) + "\n");
    } finally {
      (0, import_node_fs14.closeSync)(fd);
    }
    return;
  }
  readPrivateConfig(path);
  const temporary = `${path}.${(0, import_node_crypto9.randomBytes)(8).toString("hex")}.tmp`;
  try {
    (0, import_node_fs14.writeFileSync)(temporary, JSON.stringify(data) + "\n", { flag: "wx", mode: 384 });
    (0, import_node_fs14.renameSync)(temporary, path);
    (0, import_node_fs14.chmodSync)(path, 384);
  } finally {
    try {
      (0, import_node_fs14.unlinkSync)(temporary);
    } catch {
    }
  }
}
async function codeFromInput(variable) {
  if (process.env[variable]) return process.env[variable].trim();
  process.stderr.write("Paste the private pairing code from your room, then press Enter:\n");
  const silent = new import_node_stream.Writable({ write(_chunk, _encoding, callback) {
    callback();
  } });
  const lines = (0, import_node_readline3.createInterface)({ input: process.stdin, output: silent, terminal: !!process.stdin.isTTY });
  try {
    for await (const line of lines) {
      if (line.trim()) {
        if (line.length > 4096) throw new Error("The pairing code is too long.");
        return line.trim();
      }
    }
  } finally {
    lines.close();
  }
  throw new Error("No pairing code was provided. Copy a new code from your room.");
}
async function claimPairing(config, fetchImpl = fetch) {
  if (!config.pending) return config;
  const { code: code2, privateKey } = config.pending;
  validateCoordinationConfig(config);
  if (code2.endpoint !== config.endpoint || code2.room_id !== config.roomId || code2.authority_key !== config.authorityKey) throw new Error("The saved pairing destination does not match its authority pin.");
  if (code2.version === 3 && (config.purpose !== "negotiation" || config.sessionId !== code2.session_id || config.principalKey !== code2.principal_key)) throw new Error("The saved pairing does not match its negotiation session and principal.");
  const identity = await importIdentity(privateKey, config.agentKey);
  const request = await sign(makeRequest(code2.version === 3 ? "negotiation_pair_claim" : "pair_claim", code2.room_id, { ...code2.version === 3 ? { session_id: code2.session_id } : {}, pair_id: code2.pair_id, secret: code2.secret, executor_token: config.token, name: config.name }), identity);
  const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 2e4);
  try {
    const response = await fetchImpl(config.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", signal: abort.signal });
    const raw = await response.text();
    if (raw.length > 64e3) throw new Error("Pairing returned an oversized response.");
    const result2 = JSON.parse(raw);
    if (!response.ok || !result2.ok) throw new Error(safeMessage[result2.error || ""] || "The room refused this pairing. Check its state before retrying.");
    const binding = result2.binding, b = binding?.payload;
    if (!binding || !b || !await verify(binding, config.authorityKey) || b.type !== "scopeblind.coordination.agent-binding.v1" || b.room_id !== code2.room_id || b.pair_id !== code2.pair_id || b.agent_key !== config.agentKey || b.name !== config.name || b.audience !== pairingAudience(code2) || canonical(b.scope) !== canonical(pairingScope(code2)) || result2.executor_token !== config.token || !Number.isFinite(Date.parse(b.expires_at)) || Date.parse(b.expires_at) <= Date.now() || !/^[0-9a-f]{64}$/.test(b.agreement_digest)) throw new Error("The pairing acknowledgment did not match the pinned authority and exact scope.");
    if (code2.version === 3 && (b.session_id !== code2.session_id || b.principal_key !== code2.principal_key || b.owner_key !== code2.principal_key)) throw new Error("The pairing acknowledgment names another negotiation session or principal.");
    const owner = b.owner_authorization, grant = owner?.payload;
    if (!await verify(owner, b.owner_key) || grant?.action !== (code2.version === 3 ? "negotiation_pair_create" : "pair_create") || grant.room_id !== code2.room_id || grant.body.pair_id !== code2.pair_id || grant.body.secret_hash !== await sha256(code2.secret) || grant.body.token_expires_at !== b.expires_at || (code2.version === 3 ? !isNegotiationPairingScope(grant.body.scope) || grant.body.session_id !== code2.session_id : code2.version === 2 ? !isRehearsalPairingScope(grant.body.scope) : grant.body.scope !== void 0)) throw new Error("The owner authorization for this connection could not be verified.");
    if (grant.body.expected_agent_key !== void 0 && (code2.version !== 3 || grant.body.expected_agent_key !== config.agentKey)) throw new Error("The owner authorization is bound to another agent key.");
    const { pending: _pending, ...ready } = config;
    return { ...ready, purpose: code2.version === 3 ? "negotiation" : code2.version === 2 ? "rehearsal" : "execution", binding };
  } catch (error) {
    if (error instanceof Error && error.name !== "AbortError" && !/fetch|connect|JSON|Unexpected|network/i.test(error.message)) throw error;
    throw new Error("The pairing response could not be verified. Rerun the same command and config to recover safely.");
  } finally {
    clearTimeout(timer);
  }
}
function configArgs(args, pairing) {
  const options2 = /* @__PURE__ */ new Map(), allowed = new Set(pairing ? ["--config", "--name", "--code-env", "--client"] : ["--config", "--client"]);
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.has(args[i]) || options2.has(args[i]) || !args[i + 1] || args[i + 1].startsWith("--")) throw new Error("Unsupported, repeated, or incomplete connection option.");
    options2.set(args[i], args[i + 1]);
  }
  return options2;
}
async function runCoordinationPair(args) {
  const options2 = configArgs(args, true), path = (0, import_node_path10.resolve)(options2.get("--config") || DEFAULT_COORDINATION_CONFIG);
  const client = agentClient(options2.get("--client") || "claude-code");
  let config;
  try {
    config = readPrivateConfig(path);
  } catch (error) {
    try {
      const fd = (0, import_node_fs14.openSync)(path, import_node_fs14.constants.O_RDONLY | import_node_fs14.constants.O_NOFOLLOW);
      (0, import_node_fs14.closeSync)(fd);
      throw error;
    } catch (check) {
      if (check.code !== "ENOENT") throw error;
    }
  }
  if (config?.binding && !config.pending) {
    if (Date.parse(config.binding.payload.expires_at) <= Date.now()) throw new Error("This saved connection has expired. Create a fresh pairing in the room and use its new config filename.");
    process.stdout.write("This config is already paired. Its existing identity and scope are unchanged. Reuse the setup below to reconnect; the room will confirm readiness only after a successful tool inspection. A revoked connection needs a fresh code and config filename.\n");
    runCoordinationSetup(["--config", path, "--client", client]);
    const existing = coordinationConfigFromFile(path);
    process.stdout.write("\nAsk your agent:\n" + agentPrompt(existing.purpose || "execution", existing.roomId, existing.sessionId) + "\n");
    return;
  }
  if (!config) {
    const variable = options2.get("--code-env") || "PROTECT_MCP_PAIRING_CODE";
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) throw new Error("--code-env must name an environment variable.");
    const code2 = decodePairingCode(await codeFromInput(variable));
    const name = options2.get("--name") || "My agent";
    if (!name.trim() || name !== name.trim() || name.length > 60 || /[\u0000-\u001f]/.test(name)) throw new Error("Agent name must contain 1\u201360 printable characters.");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const token = (0, import_node_crypto9.randomBytes)(32).toString("hex");
    config = {
      type: "scopeblind.coordination.config.v1",
      setupVersion: 2,
      ...validateCoordinationConfig({ endpoint: code2.endpoint, roomId: code2.room_id, authorityKey: code2.authority_key, token, ...code2.version === 3 ? { purpose: "negotiation", sessionId: code2.session_id, principalKey: code2.principal_key } : {} }),
      agentKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))),
      name,
      pending: { code: { ...code2, endpoint: new URL(code2.endpoint).href }, privateKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))) }
    };
    savePrivateConfig(path, config, true);
  }
  const ready = await claimPairing(config);
  savePrivateConfig(path, ready, false);
  if (ready.purpose === "negotiation") process.stdout.write(`Connected ${ready.name} for one principal\u2019s bounded negotiation until ${ready.binding.payload.expires_at}. This agent can read its principal\u2019s mandate and shared proposals, propose or support a candidate, compare it in isolation, and wait. It cannot inspect the other private brief, pay, approve, adopt, or run a hosted agent.
Connection saved privately. Each principal needs a separate pairing and config.
`);
  else if (ready.purpose === "rehearsal") process.stdout.write(`Connected ${ready.name} to test these rules until ${ready.binding.payload.expires_at}. This agent can inspect rules, add cases, propose repairs, and run isolated tests. It cannot pay, approve, or activate changes.
Connection saved privately. Return to the room to see or revoke this agent.
`);
  else process.stdout.write(`Connected ${ready.name}. This independently keyed agent can inspect records, request permitted sandbox payments, and deliver results until ${ready.binding.payload.expires_at}. It cannot approve exceptions or change the rules.
Connection saved privately. Return to the room to see or revoke this agent.
`);
  process.stdout.write(client === "json" ? "Merge this entry into your MCP client\u2019s local configuration; preserve existing servers:\n" : client === "codex" ? "Run this command to add the connection to your Codex configuration:\n" : "Run this command in the project where you use Claude Code:\n");
  runCoordinationSetup(["--config", path, "--client", client]);
  process.stdout.write("\nOpen or restart the selected client, then ask:\n" + agentPrompt(ready.purpose || "execution", ready.roomId, ready.sessionId) + "\n");
  process.stdout.write("The room will show \u201CRead current instructions\u201D only after your agent successfully inspects and verifies its signed context. Pairing alone does not start an agent. Resume requires an active agent session.\n");
}
function runCoordinationSetup(args) {
  const options2 = configArgs(args, false), path = (0, import_node_path10.resolve)(options2.get("--config") || DEFAULT_COORDINATION_CONFIG);
  const stored = readPrivateConfig(path), config = coordinationConfigFromFile(path);
  if (Date.parse(stored.binding.payload.expires_at) <= Date.now()) throw new Error("This saved connection has expired. Create a fresh pairing in the room and use its new config filename.");
  const serverName = stored.setupVersion === 2 ? agentServerName(config.purpose || "execution", config.roomId, stored.binding?.payload.pair_id, config.principalKey) : config.purpose === "negotiation" ? `scopeblind-negotiate-${config.principalKey.slice(0, 8)}` : config.purpose === "rehearsal" ? "scopeblind-test" : "scopeblind";
  process.stdout.write(agentRegistration(agentClient(options2.get("--client") || "claude-code"), serverName, path) + "\n");
}
var import_node_readline3, import_node_stream, import_node_fs14, import_node_path10, import_node_os, import_node_crypto9, DEFAULT_COORDINATION_CONFIG, safeMessage;
var init_coordination_pair_cli = __esm({
  "src/coordination-pair-cli.ts"() {
    "use strict";
    import_node_readline3 = require("readline");
    import_node_stream = require("stream");
    import_node_fs14 = require("fs");
    import_node_path10 = require("path");
    import_node_os = require("os");
    import_node_crypto9 = require("crypto");
    init_coordination_protocol();
    init_coordination_pairing();
    init_coordination_config();
    init_coordination_agent_setup();
    init_coordination_agent_setup();
    if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: import_node_crypto9.webcrypto, configurable: true });
    DEFAULT_COORDINATION_CONFIG = (0, import_node_path10.resolve)((0, import_node_os.homedir)(), ".scopeblind", "coordination.json");
    safeMessage = {
      pairing_not_found: "This pairing code could not be matched. Create a new code in the room.",
      pairing_expired_or_revoked: "This pairing has expired or was revoked. Create a new code in the room.",
      pairing_already_claimed: "This pairing code has already enrolled another agent. Create a new code in the room.",
      run_finalized: "This result is already delivered. Start an authorized revision before connecting another agent."
    };
  }
});

// src/coordination-client.ts
function waitDelay(ms, signal) {
  return new Promise((resolve5, reject) => {
    const cancelled = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", cancelled);
      reject(new CoordinationError("cancelled", "The wait was cancelled. No action or approval was performed."));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", cancelled);
      resolve5();
    }, Math.ceil(ms));
    if (signal.aborted) cancelled();
    else signal.addEventListener("abort", cancelled, { once: true });
  });
}
function validateCoordinationPayment(payment) {
  if (!payment || !operationIdentifier(payment.operation_id)) throw new CoordinationError("invalid_operation", "A stable operation_id of 8\u2013100 letters, numbers, underscores, or hyphens is required; retain it when retrying the same intended payment.");
  if (Object.keys(payment).sort().join(",") !== "input,operation_id") throw new CoordinationError("invalid_operation", "The executor accepts operation_id and input only; revisions must be made by the room owner.");
  const input = payment.input;
  if (!input || typeof input.invoice_id !== "string" || !input.invoice_id.length || input.invoice_id.length > 60 || !Number.isSafeInteger(input.amount_minor) || input.amount_minor <= 0 || input.amount_minor > 1e7 || input.currency !== "USD" || typeof input.destination !== "string" || !input.destination.length || input.destination.length > 100) {
    throw new CoordinationError("invalid_input", "Payment requires invoice_id, a positive integer amount_minor, currency USD, and a sample destination.");
  }
  if (input.fixture_revision !== void 0 && (!Number.isSafeInteger(input.fixture_revision) || input.fixture_revision < 1)) throw new CoordinationError("invalid_input", "fixture_revision must be a positive integer from coordination.inspect.");
  if (Object.keys(input).filter((key) => key !== "fixture_revision").sort().join(",") !== "amount_minor,currency,destination,invoice_id") {
    throw new CoordinationError("invalid_input", "Payment input contains unsupported fields.");
  }
}
var import_node_crypto10, CoordinationError, CoordinationTransport, operationIdentifier, CoordinationClient;
var init_coordination_client = __esm({
  "src/coordination-client.ts"() {
    "use strict";
    init_coordination_evidence();
    init_coordination_devices();
    init_coordination_config();
    init_coordination_rehearsal();
    init_coordination_negotiation();
    import_node_crypto10 = require("crypto");
    init_coordination_protocol();
    if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: import_node_crypto10.webcrypto, configurable: true });
    CoordinationError = class extends Error {
      constructor(code2, message) {
        super(message);
        this.code = code2;
        this.name = "CoordinationError";
      }
    };
    CoordinationTransport = class {
      constructor(config, fetchImpl = fetch) {
        this.fetchImpl = fetchImpl;
        this.#config = validateCoordinationConfig(config);
      }
      #config;
      async get(op, operationId) {
        const url = new URL(this.#config.endpoint);
        url.searchParams.set("op", op);
        url.searchParams.set("room_id", this.#config.roomId);
        if (operationId !== void 0) url.searchParams.set("operation_id", operationId);
        return this.request(url.href, { method: "GET" });
      }
      async post(action, body, signal) {
        if (this.#config.purpose === "negotiation" && !NEGOTIATION_AGENT_ACTIONS.includes(action)) throw new CoordinationError("tool_outside_grant", "This negotiation connection cannot access execution or rehearsal actions.");
        return this.request(this.#config.endpoint, {
          method: "POST",
          body: JSON.stringify({ action, room_id: this.#config.roomId, body }),
          signal
        }, action === "rehearsal_run" || action === "negotiation_compare" ? 6e4 : void 0);
      }
      async request(url, init, defaultTimeout) {
        const abort = new AbortController();
        const cancel = () => abort.abort();
        if (init.signal?.aborted) cancel();
        else init.signal?.addEventListener("abort", cancel, { once: true });
        const timeout = setTimeout(() => abort.abort(), this.#config.timeoutMs ?? defaultTimeout ?? 15e3);
        try {
          const response = await this.fetchImpl(url, {
            ...init,
            signal: abort.signal,
            redirect: "error",
            cache: "no-store",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.#config.token}` }
          });
          const raw = await response.text();
          if (raw.length > 2e6) throw new CoordinationError("invalid_response", "Coordination response exceeds the supported size.");
          let result2;
          try {
            result2 = JSON.parse(raw);
          } catch {
            throw new CoordinationError("invalid_response", "Coordination service returned invalid JSON.");
          }
          if (!response.ok) {
            const code2 = result2 && typeof result2 === "object" && "error" in result2 && typeof result2.error === "string" && /^[a-z_]{3,80}$/.test(result2.error) ? result2.error : "service_rejected";
            const guidance = { rehearsal_in_progress: "This exact test is still running. Wait before inspecting reports or retrying with the same test id.", rehearsal_run_failed: "This exact test ended without a completed report. Inspect the source and cases; a new deliberately requested test needs a new id.", proposal_stale: "Cases or source records changed. Inspect the rehearsal and propose a newly identified repair against the current snapshot.", executor_action_not_permitted: "This action is outside the owner\u2019s explicit grant. Ask for a separate connection with the required scope.", rehearsal_id_conflict: "This stable ID already names different content. Inspect the existing record; use a new ID only for a new intended case, proposal, or test.", executor_token_invalid: "This agent connection expired or was revoked. Ask the owner for a fresh pairing.", room_paused: "The owner paused this task. Wait for resume; retain all operation IDs.", run_has_unresolved_operations: "Resolve held or unknown operations before delivering the result.", run_finalized: "This attempt is already delivered. Wait for an owner-authorized revision.", rate_limited: "The room request limit was reached. Pause and retry later with unchanged operation IDs." };
            throw new CoordinationError(code2, guidance[code2] || `Coordination service rejected the request (${code2}; HTTP ${response.status}). Inspect current room state before retrying.`);
          }
          if (!result2 || typeof result2 !== "object" || Array.isArray(result2) || result2.ok !== true) {
            throw new CoordinationError("invalid_response", "Coordination service did not return a successful protocol response.");
          }
          return result2;
        } catch (error) {
          if (error instanceof CoordinationError) throw error;
          if (init.signal?.aborted) throw new CoordinationError("cancelled", "The wait was cancelled. No action or approval was performed.");
          throw new CoordinationError("service_unavailable", "Coordination service could not be reached or the request timed out.");
        } finally {
          clearTimeout(timeout);
          init.signal?.removeEventListener("abort", cancel);
        }
      }
    };
    operationIdentifier = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(value);
    CoordinationClient = class {
      #config;
      #transport;
      #acknowledgedContexts = /* @__PURE__ */ new Set();
      constructor(config, fetchImpl = fetch) {
        this.#config = validateCoordinationConfig(config);
        this.#transport = new CoordinationTransport(this.#config, fetchImpl);
      }
      /** Tool visibility is a local convenience; every RPC also checks the persisted grant. */
      get purpose() {
        return this.#config.purpose || "execution";
      }
      /** Acknowledge only a context that this adapter has already verified. Pairing and MCP initialization do not call this. */
      async acknowledgeInspection(response, action, contextDigest, signal) {
        const key = `${action}:${contextDigest}`;
        if (response.agent_inspection_supported !== true || this.#acknowledgedContexts.has(key)) return;
        const acknowledgment = await this.#transport.post(action, { ...action === "negotiation_get" ? { session_id: this.#config.sessionId } : {}, observed_context_digest: contextDigest }, signal);
        if (typeof acknowledgment.agent_inspection_acknowledged !== "boolean") throw new CoordinationError("agent_inspection_unconfirmed", "The room could not confirm this inspection. Inspect again before continuing.");
        this.#acknowledgedContexts.add(key);
      }
      negotiationConfig() {
        if (this.purpose !== "negotiation" || !this.#config.sessionId || !this.#config.principalKey) throw new CoordinationError("tool_outside_grant", "Use a separate principal-authorized negotiation pairing for these tools.");
        return { sessionId: this.#config.sessionId, principalKey: this.#config.principalKey };
      }
      /** Inspect only the scoped negotiation response. Never read the public room to obtain a mandate. */
      async checkedNegotiation(response) {
        const { sessionId, principalKey } = this.negotiationConfig();
        const state = response.negotiation;
        const invalid = () => {
          throw new CoordinationError("invalid_negotiation", "The negotiation identity, source records, mandate, or signed candidate could not be verified. No approval or authority was granted.");
        };
        const keys2 = (value, allowed) => {
          if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !allowed.includes(key))) invalid();
        };
        const envelope3 = (value) => keys2(value, ["payload", "signer", "digest", "signature"]);
        const humanEnvelope = (value) => keys2(value, ["payload", "signer", "digest", "signature", "authorization", "authorization_signature", "authorization_use"]);
        try {
          keys2(state, ["session", "invitation", "binding", "agreement", "fixtures", "principals", "status", "proposals", "responses", "reports", "approvals", "adoption", "adopted_agreement", "run", "feasibility", "next_principal_key", "model_steps", "max_model_steps", "error", "viewer", "started", "reviewer_grant", "reviewer_binding", "agent_bindings", "selected_proposal_digest", "runtime_changed", "source_negotiation"]);
          const session = state.session?.payload, agreement = state.agreement?.payload;
          if (!session || !agreement || session.type !== "scopeblind.coordination.negotiation-session.v1" || session.id !== sessionId || session.room_id !== this.#config.roomId || session.registrar_key !== this.#config.authorityKey || !await verify(state.session, this.#config.authorityKey) || agreement.type !== "scopeblind.coordination.agreement.v1" || agreement.id !== this.#config.roomId || agreement.owner_key !== session.owner_key || agreement.registrar_key !== this.#config.authorityKey || !await verifyOwnerAgreement(state.agreement, state.source_negotiation) || state.agreement.digest !== session.agreement_digest || session.max_proposals !== NEGOTIATION_MAX_PROPOSALS || state.max_model_steps !== NEGOTIATION_MAX_MODEL_STEPS || !Number.isSafeInteger(state.model_steps) || state.model_steps < 0 || state.model_steps > NEGOTIATION_MAX_MODEL_STEPS || !state.fixtures || await negotiationDigest(state.fixtures) !== session.fixture_digest) invalid();
          if (!Number.isFinite(Date.parse(session.created_at)) || !Number.isFinite(Date.parse(session.expires_at)) || Date.parse(session.expires_at) <= Date.parse(session.created_at) || Date.parse(session.expires_at) > Date.parse(session.created_at) + 864e5) invalid();
          envelope3(state.session);
          keys2(session, ["type", "id", "room_id", "agreement_digest", "fixture_digest", "owner_key", "registrar_key", "invitation_digest", "created_at", "expires_at", "max_proposals", "parent_session_id", "source_operation_id", "source_invoice_id", "source_operation_digest"]);
          const invitation = state.invitation?.payload;
          if (!invitation || !await verify(state.invitation, session.owner_key) || invitation.type !== "scopeblind.coordination.negotiation-invitation.v1" || state.invitation.digest !== session.invitation_digest || invitation.session_id !== sessionId || invitation.room_id !== session.room_id || invitation.agreement_digest !== session.agreement_digest || invitation.fixture_digest !== session.fixture_digest || invitation.issuer !== session.owner_key || invitation.registrar_key !== this.#config.authorityKey) invalid();
          if (invitation.role !== "counterparty" || invitation.max_claims !== 1 || invitation.expires_at !== session.expires_at || !/^[0-9a-f]{64}$/.test(invitation.token_hash)) invalid();
          envelope3(state.invitation);
          keys2(invitation, ["type", "session_id", "room_id", "agreement_digest", "fixture_digest", "issuer", "registrar_key", "role", "token_hash", "max_claims", "expires_at", "parent_session_id", "source_operation_id"]);
          if (!Array.isArray(state.principals) || state.principals.length < 1 || state.principals.length > 2 || new Set(state.principals.map((p) => p.key)).size !== state.principals.length || new Set(state.principals.map((p) => p.side)).size !== state.principals.length) invalid();
          if (state.binding) {
            const binding = state.binding.payload;
            envelope3(state.binding);
            keys2(binding, ["type", "session_id", "room_id", "invitation_digest", "guest_key", "name", "issued_at", "expires_at", "claim"]);
            if (!await verify(state.binding, this.#config.authorityKey) || binding.type !== "scopeblind.coordination.negotiation-binding.v1" || binding.session_id !== sessionId || binding.room_id !== session.room_id || binding.invitation_digest !== state.invitation.digest || !await verify(binding.claim, binding.guest_key) || binding.claim.payload.session_id !== sessionId || binding.claim.payload.room_id !== session.room_id || binding.claim.payload.guest_key !== binding.guest_key || binding.guest_key === session.owner_key) invalid();
            envelope3(binding.claim);
            keys2(binding.claim.payload, ["type", "session_id", "room_id", "guest_key", "name", "issued_at", "nonce"]);
          }
          for (const principal of state.principals) {
            keys2(principal, ["side", "key", "name", "mandate", "agent_status"]);
            if (principal.side === "organizer" ? principal.key !== session.owner_key : principal.side !== "partner" || principal.key !== state.binding?.payload.guest_key) invalid();
            if (principal.mandate) {
              humanEnvelope(principal.mandate);
              const mandate = principal.mandate.payload;
              keys2(mandate, ["type", "session_id", "room_id", "principal_key", "version", "agreement_digest", "fixture_digest", "min_threshold_minor", "max_threshold_minor", "min_budget_minor", "max_budget_minor", "required_invoices", "private_brief_commitment", "agent_mode", "actions", "issued_at", "expires_at"]);
              if (!await verifyHuman(principal.mandate, principal.key, { requireRecordedUse: true, authorityKey: this.#config.authorityKey }) || mandate.type !== "scopeblind.coordination.negotiation-mandate.v1" || mandate.session_id !== sessionId || mandate.room_id !== session.room_id || mandate.principal_key !== principal.key || mandate.agreement_digest !== session.agreement_digest || mandate.fixture_digest !== session.fixture_digest || canonical(mandate.actions) !== canonical(NEGOTIATION_AGENT_ACTIONS) || !Number.isSafeInteger(mandate.version) || mandate.version < 1 || !["hosted", "own", "manual"].includes(mandate.agent_mode) || !Number.isSafeInteger(mandate.min_threshold_minor) || !Number.isSafeInteger(mandate.max_threshold_minor) || mandate.min_threshold_minor < 0 || mandate.max_threshold_minor < mandate.min_threshold_minor || mandate.max_threshold_minor > mandateBudget(mandate, agreement.budget_minor).max || !Array.isArray(mandate.required_invoices) || !/^[0-9a-f]{64}$/.test(mandate.private_brief_commitment)) invalid();
              if (mandate.min_budget_minor === void 0 !== (mandate.max_budget_minor === void 0) || mandate.min_budget_minor !== void 0 && (!Number.isSafeInteger(mandate.min_budget_minor) || !Number.isSafeInteger(mandate.max_budget_minor) || mandate.min_budget_minor < 1 || mandate.max_budget_minor < mandate.min_budget_minor || mandate.max_budget_minor > 1e7)) invalid();
              if (!Number.isFinite(Date.parse(mandate.issued_at)) || !Number.isFinite(Date.parse(mandate.expires_at)) || Date.parse(mandate.expires_at) <= Date.parse(mandate.issued_at) || Date.parse(mandate.expires_at) > Date.parse(session.expires_at) || mandate.required_invoices.length > 2 || new Set(mandate.required_invoices.map((r) => r.invoice_id)).size !== mandate.required_invoices.length) invalid();
              for (const required of mandate.required_invoices) {
                keys2(required, ["invoice_id", "expected"]);
                if (!["allow", "ask"].includes(required.expected) || !state.fixtures.invoices.some((invoice) => invoice.invoice_id === required.invoice_id && !invoice.duplicate_of)) invalid();
              }
            }
          }
          const own = state.principals.find((p) => p.key === principalKey);
          keys2(state.viewer, ["principal_key", "side", "brief", "pairs", "is_agent"]);
          if (!own?.mandate || own.mandate.payload.agent_mode !== "own" || state.viewer.principal_key !== principalKey || state.viewer.side !== own.side || state.viewer.is_agent !== true || !state.viewer.brief || await privateBriefCommitment(parseNegotiationBrief(state.viewer.brief)) !== own.mandate.payload.private_brief_commitment || !Array.isArray(state.viewer.pairs)) invalid();
          for (const pair of state.viewer.pairs) {
            keys2(pair, ["pair_id", "name", "principal_key", "session_id", "status", "code_expires_at", "expires_at", "agent_key", "readiness", "profile_bound"]);
            if (pair.session_id !== sessionId || pair.principal_key !== principalKey || pair.profile_bound !== void 0 && pair.profile_bound !== true) invalid();
            if (pair.readiness) {
              keys2(pair.readiness, ["observed_at", "context_digest"]);
              if (!Number.isFinite(Date.parse(pair.readiness.observed_at)) || !/^[0-9a-f]{64}$/.test(pair.readiness.context_digest)) invalid();
            }
          }
          if (typeof state.started !== "boolean" || state.runtime_changed !== void 0 && typeof state.runtime_changed !== "boolean") invalid();
          if (!["waiting_partner", "setting_limits", "ready", "working", "waiting_agent", "needs_decision", "agreed", "no_overlap", "round_limit", "failed", "cancelled", "adopted"].includes(state.status) || state.next_principal_key !== void 0 && !state.principals.some((p) => p.key === state.next_principal_key)) invalid();
          if (!Array.isArray(state.proposals) || state.proposals.length > NEGOTIATION_MAX_PROPOSALS || !Array.isArray(state.responses) || !Array.isArray(state.reports) || !Array.isArray(state.approvals)) invalid();
          const mandates = ["organizer", "partner"].map((side) => state.principals.find((p) => p.side === side)?.mandate);
          const mandateDigests = mandates.filter(Boolean).map((m) => m.digest);
          const agentBindings = state.agent_bindings ?? [];
          if (!Array.isArray(agentBindings) || agentBindings.length > 12) invalid();
          for (const signed2 of agentBindings) {
            envelope3(signed2);
            const b = signed2.payload, auth = b.owner_authorization, q = auth?.payload;
            keys2(b, ["type", "pair_id", "room_id", "session_id", "principal_key", "agreement_digest", "owner_key", "agent_key", "name", "scope", "audience", "issued_at", "expires_at", "owner_authorization"]);
            if (!await verify(signed2, this.#config.authorityKey) || b.type !== "scopeblind.coordination.agent-binding.v1" || b.audience !== "scopeblind.coordination.negotiation" || b.session_id !== sessionId || b.room_id !== session.room_id || b.agreement_digest !== session.agreement_digest || b.owner_key !== b.principal_key || !state.principals.some((p) => p.key === b.principal_key) || state.principals.some((p) => p.key === b.agent_key) || canonical(b.scope) !== canonical(NEGOTIATION_AGENT_ACTIONS) || !await verify(auth, b.principal_key) || q.type !== "scopeblind.coordination.request.v1" || q.action !== "negotiation_pair_create" || q.room_id !== session.room_id || q.body.session_id !== sessionId || q.body.pair_id !== b.pair_id || q.body.token_expires_at !== b.expires_at || canonical(q.body.scope) !== canonical(NEGOTIATION_AGENT_ACTIONS)) invalid();
            envelope3(auth);
            keys2(q, ["type", "action", "room_id", "body", "issued_at", "nonce"]);
            keys2(q.body, ["session_id", "pair_id", "secret_hash", "name", "expires_at", "token_expires_at", "scope", "expected_agent_key"]);
            if (q.body.expected_agent_key !== void 0 && q.body.expected_agent_key !== b.agent_key) invalid();
            if (!/^[0-9a-f]{64}$/.test(b.agent_key) || !Number.isFinite(Date.parse(b.issued_at)) || Date.parse(b.expires_at) <= Date.parse(b.issued_at) || Date.parse(b.expires_at) > Date.parse(session.expires_at) || agentBindings.some((other) => other.payload.agent_key === b.agent_key && other.payload.principal_key !== b.principal_key)) invalid();
          }
          const actorBound = (record) => {
            const mandate = state.principals.find((p) => p.key === record.principal_key)?.mandate?.payload;
            if (!mandate || !Number.isFinite(Date.parse(record.issued_at)) || Date.parse(record.issued_at) >= Date.parse(mandate.expires_at)) return false;
            if (record.agent_mode === "manual") return record.agent_key === void 0;
            if (record.agent_mode === "hosted") return mandate.agent_mode === "hosted" && record.agent_key === void 0;
            return record.agent_mode === "own" && mandate.agent_mode === "own" && agentBindings.some((b) => b.payload.agent_key === record.agent_key && b.payload.principal_key === record.principal_key && Date.parse(record.issued_at) >= Date.parse(b.payload.issued_at) && Date.parse(record.issued_at) < Date.parse(b.payload.expires_at));
          };
          for (let index = 0; index < state.proposals.length; index++) {
            const signed2 = state.proposals[index], proposal = signed2.payload;
            envelope3(signed2);
            keys2(proposal, ["type", "id", "approval_above_minor", "budget_minor", "exploration", "parent_digest", "session_id", "room_id", "round", "principal_key", "agent_key", "agent_mode", "agreement_digest", "fixture_digest", "mandate_digests", "next_agreement", "next_agreement_digest", "reviewer_grant", "reviewer_grant_digest", "issued_at"]);
            if (!actorBound(proposal) || !await verify(signed2, this.#config.authorityKey) || proposal.type !== "scopeblind.coordination.negotiation-proposal.v1" || proposal.session_id !== sessionId || proposal.room_id !== session.room_id || proposal.round !== index + 1 || proposal.agreement_digest !== session.agreement_digest || proposal.fixture_digest !== session.fixture_digest || mandateDigests.length !== 2 || canonical(proposal.mandate_digests) !== canonical(mandateDigests) || !state.principals.some((p) => p.key === proposal.principal_key) || !Number.isSafeInteger(proposal.approval_above_minor) || proposal.approval_above_minor < 0 || proposal.approval_above_minor > (proposal.budget_minor ?? agreement.budget_minor) || proposal.next_agreement?.approval_above_minor !== proposal.approval_above_minor || await negotiationPayloadDigest(proposal.next_agreement) !== proposal.next_agreement_digest || (index === 0 ? proposal.parent_digest !== void 0 : proposal.parent_digest !== state.proposals[index - 1].digest)) invalid();
          }
          if (state.selected_proposal_digest !== void 0 && !state.proposals.some((p) => p.digest === state.selected_proposal_digest)) invalid();
          for (const { payload: p } of state.proposals) {
            const g = p.reviewer_grant;
            const authorMandate = state.principals.find((principal) => principal.key === p.principal_key).mandate.payload;
            if (!negotiationPlanWithinMandate(authorMandate, p.approval_above_minor, p.budget_minor ?? agreement.budget_minor, agreement.budget_minor) || p.exploration !== void 0 && (p.exploration !== true || p.agent_mode !== "manual")) invalid();
            keys2(g, ["type", "grant_id", "room_id", "agreement_digest", "issuer", "registrar_key", "role", "actions", "expires_at", "token_hash", "max_claims"]);
            if (canonical(p.next_agreement) !== canonical({ ...agreement, id: p.next_agreement.id, issued_at: p.issued_at, approval_above_minor: p.approval_above_minor, budget_minor: p.budget_minor ?? agreement.budget_minor }) || p.next_agreement.id === agreement.id || g.type !== "scopeblind.coordination.grant.v1" || g.room_id !== p.next_agreement.id || g.agreement_digest !== p.next_agreement_digest || g.issuer !== agreement.owner_key || g.registrar_key !== this.#config.authorityKey || g.role !== "reviewer" || canonical(g.actions) !== canonical(["decide", "accept"]) || g.max_claims !== 1 || g.expires_at !== session.expires_at || await negotiationPayloadDigest(g) !== p.reviewer_grant_digest) invalid();
          }
          for (const signed2 of state.responses) {
            const response2 = signed2.payload;
            envelope3(signed2);
            keys2(response2, ["type", "session_id", "principal_key", "proposal_digest", "mandate_digest", "decision", "agent_key", "agent_mode", "issued_at"]);
            if (!actorBound(response2) || !await verify(signed2, this.#config.authorityKey) || response2.type !== "scopeblind.coordination.negotiation-response.v1" || response2.session_id !== sessionId || !["support", "no_agreement"].includes(response2.decision) || !state.proposals.some((p) => p.digest === response2.proposal_digest) || state.principals.find((p) => p.key === response2.principal_key)?.mandate?.digest !== response2.mandate_digest) invalid();
          }
          for (const signed2 of state.reports) {
            const report = signed2.payload;
            envelope3(signed2);
            keys2(report, ["type", "session_id", "room_id", "proposal_digest", "agreement_digest", "fixture_digest", "mandate_digests", "cases_digest", "runtime_revision", "adapter", "isolation", "issued_at", "before_approval_above_minor", "after_approval_above_minor", "before_budget_minor", "after_budget_minor", "results", "required_passed", "expectations_met", "mandates_met"]);
            if (!await verify(signed2, this.#config.authorityKey) || report.type !== "scopeblind.coordination.negotiation-report.v1" || report.session_id !== sessionId || report.room_id !== session.room_id || report.agreement_digest !== session.agreement_digest || report.fixture_digest !== session.fixture_digest || canonical(report.mandate_digests) !== canonical(mandateDigests) || !state.proposals.some((p) => p.digest === report.proposal_digest) || report.adapter !== "coordination-d1-sandbox" || report.isolation !== "separate-fixture-ledgers") invalid();
          }
          for (const signed2 of state.approvals) {
            const approval = signed2.payload;
            humanEnvelope(signed2);
            keys2(approval, ["type", "session_id", "principal_key", "proposal_digest", "report_digest", "next_agreement_digest", "mandate_digests", "decision", "issued_at", "expires_at", "selection_basis"]);
            if (!state.principals.some((p) => p.key === approval.principal_key) || !await verifyHuman(signed2, approval.principal_key, { proposal: state.proposals.find((p) => p.digest === approval.proposal_digest), requireRecordedUse: true, authorityKey: this.#config.authorityKey }) || approval.type !== "scopeblind.coordination.negotiation-approval.v1" || approval.session_id !== sessionId || !["approve", "reject"].includes(approval.decision) || canonical(approval.mandate_digests) !== canonical(mandateDigests) || !state.reports.some((r) => r.digest === approval.report_digest && r.payload.proposal_digest === approval.proposal_digest) || !state.proposals.some((p) => p.digest === approval.proposal_digest && p.payload.next_agreement_digest === approval.next_agreement_digest)) invalid();
          }
          if (state.run) {
            keys2(state.run, ["proposal_digest", "status", "completed_cases", "total_cases", "error"]);
            const total = mandateDigests.length === 2 ? mandateCases(mandates, state.fixtures).length : 0;
            if (!state.proposals.some((p) => p.digest === state.run.proposal_digest) || !["running", "completed", "failed"].includes(state.run.status) || !Number.isSafeInteger(state.run.completed_cases) || state.run.completed_cases < 0 || state.run.total_cases !== total || state.run.completed_cases > total) invalid();
          }
          if (state.error !== void 0 && !/^[a-z_]{3,80}$/.test(state.error)) invalid();
          if (state.run?.error !== void 0 && !/^[a-z_]{3,80}$/.test(state.run.error)) invalid();
          return state;
        } catch (error) {
          if (error instanceof CoordinationError) throw error;
          return invalid();
        }
      }
      async negotiationResult(response) {
        const negotiation = await this.checkedNegotiation(response);
        let evidenceVerification;
        if (response.evidence !== void 0) {
          const evidence = response.evidence;
          evidenceVerification = await verifyNegotiationEvidence(evidence, this.#config.authorityKey);
          if (!evidenceVerification.valid || evidence.session?.digest !== negotiation.session.digest || !negotiation.reports.some((report) => report.digest === evidence.report?.digest)) throw new CoordinationError("invalid_negotiation_evidence", "The exact negotiation comparison evidence could not be verified. Do not treat it as a passing agreement or approval.");
        }
        return {
          negotiation,
          state_digest: await negotiationDigest(negotiation),
          ...response.evidence !== void 0 ? { evidence: response.evidence, evidence_verification: evidenceVerification } : {},
          signatures_verified: true,
          scope: "One principal\u2019s bounded negotiation. Its own private brief is for this agent only. Public proposals and signed mandate constraints are shared. The gate operator records isolated test observations; these are not independent execution observation or payment authority. Support is an agent recommendation, not a human approval.",
          next_steps: negotiation.runtime_changed ? ["These signed records remain historical evidence. Ask the people to start a fresh linked discussion for the current runtime; prior mandates and approvals do not carry over."] : ["Keep the private brief private. Work within your principal\u2019s signed limits; at most three candidates exist per session. Compare the exact supported candidate, stop on no agreement, and leave approval and adoption to both people."]
        };
      }
      async inspectNegotiation(reportDigest, signal) {
        const { sessionId } = this.negotiationConfig();
        if (reportDigest !== void 0 && (typeof reportDigest !== "string" || !/^[0-9a-f]{64}$/.test(reportDigest))) throw new CoordinationError("invalid_input", "report_digest must name an exact negotiation report.");
        const response = await this.#transport.post("negotiation_get", { session_id: sessionId, ...reportDigest ? { report_digest: reportDigest } : {} }, signal);
        if (reportDigest && response.evidence?.report?.digest !== reportDigest) throw new CoordinationError("invalid_negotiation_evidence", "The requested exact report was not returned.");
        const result2 = await this.negotiationResult(response);
        const state = result2.negotiation;
        const mandate = state.principals.find((principal) => principal.key === this.#config.principalKey).mandate;
        if (!state.runtime_changed) await this.acknowledgeInspection(response, "negotiation_get", mandate.digest, signal);
        return result2;
      }
      async proposeCandidate(value) {
        const { sessionId, principalKey } = this.negotiationConfig();
        if (!value || Object.keys(value).some((key) => !["id", "approval_above_minor", "budget_minor", "parent_digest"].includes(key)) || typeof value.id !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(value.id) || !Number.isSafeInteger(value.approval_above_minor) || value.approval_above_minor < 0 || value.approval_above_minor > 1e7 || value.budget_minor !== void 0 && (!Number.isSafeInteger(value.budget_minor) || value.budget_minor < 1 || value.budget_minor > 1e7) || value.parent_digest !== void 0 && !/^[0-9a-f]{64}$/.test(value.parent_digest)) throw new CoordinationError("invalid_input", "Provide a stable candidate id, a threshold and optional total budget in USD cents, and the current parent_digest for a counterproposal. Private notes and additional powers are not accepted.");
        const proposal = { ...value };
        const result2 = await this.inspectNegotiation(), before = result2.negotiation;
        if (before.runtime_changed) throw new CoordinationError("negotiation_runtime_changed", "This discussion belongs to an earlier runtime. Ask the people to start a fresh linked discussion; do not reuse its mandate.");
        const existing = before.proposals.find((p) => p.payload.id === proposal.id);
        if (existing) {
          if (existing.payload.principal_key !== principalKey || existing.payload.approval_above_minor !== proposal.approval_above_minor || (existing.payload.budget_minor ?? before.agreement.payload.budget_minor) !== (proposal.budget_minor ?? before.agreement.payload.budget_minor) || existing.payload.exploration !== void 0 || existing.payload.parent_digest !== proposal.parent_digest) throw new CoordinationError("negotiation_id_conflict", "This stable candidate id already names different terms. Inspect it before proposing anything else.");
          return result2;
        }
        const own = before.principals.find((p) => p.key === principalKey).mandate.payload;
        if (Date.parse(own.expires_at) <= Date.now() || Date.parse(before.session.payload.expires_at) <= Date.now()) throw new CoordinationError("negotiation_expired", "This session or your signed mandate has expired. Ask your principal to review it.");
        if (before.proposals.length >= NEGOTIATION_MAX_PROPOSALS) throw new CoordinationError("negotiation_round_limit", "The three-candidate limit has been reached. Stop and explain the remaining disagreement to your principal.");
        if (["needs_decision", "agreed", "no_overlap", "round_limit", "failed", "cancelled", "adopted"].includes(before.status) || before.next_principal_key !== principalKey) throw new CoordinationError("negotiation_not_your_turn", "This session does not currently invite your agent to propose. Inspect its status; leave human decisions to the people.");
        if (!negotiationPlanWithinMandate(own, proposal.approval_above_minor, proposal.budget_minor ?? before.agreement.payload.budget_minor, before.agreement.payload.budget_minor) || proposal.parent_digest !== before.proposals.at(-1)?.digest) throw new CoordinationError("invalid_candidate", "The candidate must fit your signed range and name the current parent candidate.");
        for (const requirement of own.required_invoices) {
          const invoice = before.fixtures.invoices.find((invoice2) => invoice2.invoice_id === requirement.invoice_id);
          const budget = proposal.budget_minor ?? before.agreement.payload.budget_minor;
          const matching = !before.agreement.payload.require_po_match || before.fixtures.purchase_orders.some((po) => po.id === invoice.purchase_order_id && po.vendor === invoice.vendor && po.destination === invoice.destination && po.amount_minor === invoice.amount_minor && po.currency === "USD");
          const expected = invoice.amount_minor > budget || !before.agreement.payload.allowed_destinations.includes(invoice.destination) ? "refuse" : !matching || invoice.amount_minor > proposal.approval_above_minor ? "ask" : "allow";
          if (expected !== requirement.expected) throw new CoordinationError("invalid_candidate", "The candidate does not meet your principal\u2019s required invoice decision.");
        }
        const response = await this.#transport.post("negotiation_propose", { session_id: sessionId, proposal });
        const checked = await this.negotiationResult(response), after = checked.negotiation;
        if (!after.proposals.some((p) => p.payload.id === proposal.id && p.payload.principal_key === principalKey && p.payload.approval_above_minor === proposal.approval_above_minor && (p.payload.budget_minor ?? before.agreement.payload.budget_minor) === (proposal.budget_minor ?? before.agreement.payload.budget_minor) && p.payload.exploration === void 0 && p.payload.parent_digest === proposal.parent_digest)) throw new CoordinationError("invalid_negotiation", "The service did not record the exact candidate submitted. Inspect before retrying with the same id.");
        return checked;
      }
      async respondCandidate(value) {
        const { sessionId, principalKey } = this.negotiationConfig();
        if (!value || Object.keys(value).sort().join(",") !== "decision,proposal_digest" || !/^[0-9a-f]{64}$/.test(value.proposal_digest) || !["support", "no_agreement"].includes(value.decision)) throw new CoordinationError("invalid_input", "Respond only support or no_agreement to an exact proposal_digest. A response does not approve or adopt it.");
        const submitted = { ...value };
        const response = await this.#transport.post("negotiation_respond", { session_id: sessionId, ...submitted });
        const result2 = await this.negotiationResult(response), state = result2.negotiation;
        if (!state.responses.some((r) => r.payload.principal_key === principalKey && r.payload.proposal_digest === submitted.proposal_digest && r.payload.decision === submitted.decision)) throw new CoordinationError("invalid_negotiation", "The returned record does not contain your exact response. Inspect before retrying.");
        return result2;
      }
      async compareCandidate(value, signal) {
        const { sessionId } = this.negotiationConfig();
        if (!value || Object.keys(value).join(",") !== "proposal_digest" || !/^[0-9a-f]{64}$/.test(value.proposal_digest)) throw new CoordinationError("invalid_input", "Compare takes only the exact supported proposal_digest. It cannot adopt or approve a proposal.");
        const proposalDigest = value.proposal_digest;
        const abort = new AbortController(), cancel = () => abort.abort();
        if (signal?.aborted) cancel();
        else signal?.addEventListener("abort", cancel, { once: true });
        const deadline = performance.now() + 18e4, timer = setTimeout(cancel, 18e4);
        let latest, completedCases = 0, advancingChunks = 0, busyWaits = 0;
        const pending = () => ({ ...latest, comparison_status: "pending", proposal_digest: proposalDigest, ...signal?.aborted ? { cancelled: true } : {}, next_steps: ["No verified final comparison is available yet. Inspect negotiation status, then resume compare_candidate with the SAME proposal_digest. The server retains its fixed test identity and completed chunks. No approval, payment, or adoption occurred."] });
        try {
          while (!abort.signal.aborted && performance.now() < deadline && advancingChunks < 8) {
            let response;
            try {
              response = await this.#transport.post("negotiation_compare", { session_id: sessionId, proposal_digest: proposalDigest }, abort.signal);
            } catch (error) {
              if (error instanceof CoordinationError && ["negotiation_in_progress", "rehearsal_in_progress"].includes(error.code) && busyWaits++ < 6) {
                await waitDelay(1e3, abort.signal);
                continue;
              }
              throw error;
            }
            latest = await this.negotiationResult(response);
            const state = latest.negotiation;
            const report = state.reports.find((report2) => report2.payload.proposal_digest === proposalDigest);
            if (report) {
              if (response.evidence?.report?.digest !== report.digest) latest = await this.inspectNegotiation(report.digest, abort.signal);
              return { ...latest, comparison_status: "completed", proposal_digest: proposalDigest };
            }
            const run = state.run;
            if (!run || run.proposal_digest !== proposalDigest || run.status !== "running") throw new CoordinationError("invalid_negotiation", "The comparison did not return a matching checkpoint or verified report. Inspect before resuming the same candidate.");
            if (run.completed_cases <= completedCases) {
              if (busyWaits++ >= 6) return pending();
              await waitDelay(1e3, abort.signal);
            } else {
              completedCases = run.completed_cases;
              advancingChunks++;
            }
          }
          return pending();
        } catch (error) {
          if (abort.signal.aborted || error instanceof CoordinationError && ["negotiation_in_progress", "rehearsal_in_progress"].includes(error.code)) return pending();
          if (error instanceof CoordinationError && error.code === "service_unavailable") throw new CoordinationError("negotiation_outcome_unknown", "The comparison response was lost or timed out. Inspect and resume the SAME proposal_digest; do not create another candidate or assume the test failed. No approval or adoption was requested.");
          throw error;
        } finally {
          clearTimeout(timer);
          signal?.removeEventListener("abort", cancel);
        }
      }
      async waitNegotiation(value, signal) {
        this.negotiationConfig();
        if (!value || Object.keys(value).some((key) => !["after_digest", "timeout_ms"].includes(key)) || value.after_digest !== void 0 && !/^[0-9a-f]{64}$/.test(value.after_digest)) throw new CoordinationError("invalid_wait", "Use the state_digest from inspect_negotiation as after_digest, with an optional timeout_ms.");
        const timeoutMs = value.timeout_ms ?? 3e4;
        if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1e3 || timeoutMs > 3e4) throw new CoordinationError("invalid_wait", "timeout_ms must be an integer from 1000 to 30000.");
        const abort = new AbortController(), cancel = () => abort.abort();
        if (signal?.aborted) cancel();
        else signal?.addEventListener("abort", cancel, { once: true });
        const deadline = performance.now() + timeoutMs;
        let timedOut = false;
        const timer = setTimeout(() => {
          timedOut = true;
          abort.abort();
        }, timeoutMs);
        let latest;
        const result2 = (waitStatus) => ({ ...latest, wait_status: waitStatus });
        try {
          for (; ; ) {
            if (abort.signal.aborted) throw new CoordinationError("cancelled", "The negotiation wait was cancelled.");
            latest = await this.inspectNegotiation(void 0, abort.signal);
            const state = latest.negotiation;
            if (state.runtime_changed) return result2("blocked");
            if (["agreed", "adopted"].includes(state.status)) return result2("completed");
            if (["no_overlap", "round_limit", "failed", "cancelled"].includes(state.status)) return result2("blocked");
            if (state.status === "needs_decision") return result2("awaiting_human_decision");
            if (state.next_principal_key === this.#config.principalKey) return result2("action_required");
            if (value.after_digest && latest.state_digest !== value.after_digest) return result2("changed");
            const remaining = deadline - performance.now();
            if (remaining <= 0) return result2("waiting");
            const finalInterval = remaining <= 2e3;
            await waitDelay(Math.min(2e3, remaining), abort.signal);
            if (finalInterval || timedOut || performance.now() >= deadline) return result2("waiting");
          }
        } catch (error) {
          if (!signal?.aborted && timedOut && error instanceof CoordinationError && error.code === "cancelled") {
            if (latest) return result2("waiting");
            throw new CoordinationError("wait_timeout", "No current negotiation state was retrieved before the timeout. Inspect before retrying.");
          }
          throw error;
        } finally {
          clearTimeout(timer);
          signal?.removeEventListener("abort", cancel);
        }
      }
      async checkedRehearsal(response) {
        const agreement = response.agreement, fixtures = response.fixtures, rehearsal = response.rehearsal;
        if (response.room_id !== this.#config.roomId || response.authority_key !== this.#config.authorityKey || !agreement || agreement.payload?.type !== "scopeblind.coordination.agreement.v1" || agreement.payload.id !== this.#config.roomId || agreement.payload.registrar_key !== this.#config.authorityKey || !await verifyOwnerAgreement(agreement, response.source_negotiation) || !fixtures || !rehearsal || rehearsal.agreement_digest !== agreement.digest || rehearsal.fixture_digest !== await rehearsalDigest(fixtures) || !Array.isArray(rehearsal.cases) || rehearsal.cases_digest !== await rehearsalDigest(rehearsal.cases)) {
          throw new CoordinationError("invalid_rehearsal", "The rehearsal source agreement, sample records, or case snapshot could not be verified against the pinned authority.");
        }
        if (!Array.isArray(rehearsal.proposals) || !Array.isArray(rehearsal.reports)) throw new CoordinationError("invalid_rehearsal", "The rehearsal record is incomplete.");
        for (const proposal of rehearsal.proposals) {
          if (!await verify(proposal, this.#config.authorityKey) || proposal.payload.type !== "scopeblind.coordination.repair-proposal.v1" || proposal.payload.room_id !== this.#config.roomId || proposal.payload.agreement_digest !== agreement.digest) {
            throw new CoordinationError("invalid_rehearsal", "A proposed repair does not verify against this source agreement and the pinned authority.");
          }
        }
        for (const report of rehearsal.reports) {
          if (!await verify(report, this.#config.authorityKey) || report.payload.type !== "scopeblind.coordination.rehearsal-report.v1" || report.payload.room_id !== this.#config.roomId || report.payload.agreement_digest !== agreement.digest) {
            throw new CoordinationError("invalid_rehearsal", "A rehearsal report does not verify against this source agreement and the pinned authority.");
          }
        }
        return { agreement, fixtures, rehearsal };
      }
      async rehearsalResult(response) {
        const source = await this.checkedRehearsal(response);
        if (response.proposal && !source.rehearsal.proposals.some((p) => canonical(p) === canonical(response.proposal))) throw new CoordinationError("invalid_rehearsal", "The returned proposal is absent from the verified rehearsal record.");
        if (response.report && !source.rehearsal.reports.some((r) => canonical(r) === canonical(response.report))) throw new CoordinationError("invalid_rehearsal", "The returned report is absent from the verified rehearsal record.");
        let evidenceVerification;
        if (response.evidence !== void 0) {
          const evidence = response.evidence;
          evidenceVerification = await verifyRehearsalEvidence(evidence, this.#config.authorityKey);
          if (!evidenceVerification.valid || evidence.agreement.digest !== source.agreement.digest || response.report && canonical(evidence.report) !== canonical(response.report)) throw new CoordinationError("invalid_rehearsal_evidence", "The isolated test evidence could not be verified. No authority has been activated.");
        }
        return {
          room_id: this.#config.roomId,
          ...source,
          ...response.run ? { run: response.run } : {},
          ...response.proposal ? { proposal: response.proposal } : {},
          ...response.report ? { report: response.report } : {},
          ...response.evidence ? { evidence: response.evidence, evidence_verification: evidenceVerification } : {},
          source_signature_verified: true,
          scope: "Test-only coordination. The named gate operator attests to observed outcomes in separate sample ledgers. Signed records establish integrity, not proof for every input or independent execution observation. Proposals do not change this agreement or authorize payments; adoption belongs to the owner.",
          next_steps: ["Inspect cases and their human expectations. Keep stable IDs for retries. Compare a proposed repair against required safety cases. Explain the observed tradeoffs; leave adoption to the owner."]
        };
      }
      async inspectRehearsal(reportDigest) {
        if (reportDigest !== void 0 && (typeof reportDigest !== "string" || !/^[0-9a-f]{64}$/.test(reportDigest))) throw new CoordinationError("invalid_input", "report_digest must identify an exact signed rehearsal report.");
        const response = await this.#transport.post("rehearsal_get", reportDigest ? { report_digest: reportDigest } : {});
        if (reportDigest && response.evidence?.report?.digest !== reportDigest) throw new CoordinationError("invalid_rehearsal_evidence", "The returned evidence does not identify the requested report.");
        const result2 = await this.rehearsalResult(response);
        await this.acknowledgeInspection(response, "rehearsal_get", result2.agreement.digest);
        return result2;
      }
      async proposeCase(value) {
        let testCase;
        try {
          if (value && ("required" in value || value.id?.startsWith("required-"))) throw new Error();
          testCase = parseRehearsalCase(value);
        } catch {
          throw new CoordinationError("invalid_input", "Provide a bounded case with a stable id and explicit expectation. The required safety cases are reserved and cannot be reassigned.");
        }
        const response = await this.#transport.post("rehearsal_case", { case: testCase });
        const result2 = await this.rehearsalResult(response);
        if (![...response.rehearsal.cases, ...response.rehearsal.excluded_cases || []].some((c2) => canonical(c2) === canonical(testCase))) throw new CoordinationError("invalid_rehearsal", "The returned cases do not contain the exact submitted expectation.");
        return result2;
      }
      async proposeRepair(value) {
        let snapshot;
        try {
          snapshot = parseRepairProposal(value, 1e7);
        } catch {
          throw new CoordinationError("invalid_input", "Provide only a stable id, review threshold in USD cents, and a rationale of at most 600 characters.");
        }
        const before = await this.checkedRehearsal(await this.#transport.post("rehearsal_get", {}));
        let proposal;
        try {
          proposal = parseRepairProposal(snapshot, before.agreement.payload.budget_minor);
        } catch {
          throw new CoordinationError("invalid_input", "Propose only a review threshold within the source budget, a stable id, and a rationale of at most 600 characters.");
        }
        const response = await this.#transport.post("rehearsal_propose", { proposal });
        const result2 = await this.rehearsalResult(response);
        const recorded = response.proposal;
        if (!recorded || recorded.payload.id !== proposal.id || recorded.payload.approval_above_minor !== proposal.approval_above_minor || recorded.payload.rationale !== proposal.rationale) throw new CoordinationError("invalid_rehearsal", "The signed repair does not match the exact proposed threshold and rationale.");
        return result2;
      }
      async runRehearsal(value, signal) {
        if (!value || Object.keys(value).some((k) => !["id", "proposal_id"].includes(k)) || typeof value.id !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(value.id) || value.proposal_id !== void 0 && (typeof value.proposal_id !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(value.proposal_id))) throw new CoordinationError("invalid_input", "Use a stable test id and optional exact proposal_id. Retain the same id if the response is lost.");
        const snapshot = { ...value }, abort = new AbortController(), cancel = () => abort.abort();
        if (signal?.aborted) cancel();
        else signal?.addEventListener("abort", cancel, { once: true });
        const deadline = performance.now() + 18e4, timer = setTimeout(cancel, 18e4);
        let latest, chunks = 0, busyWaits = 0, completedCases = 0;
        const pending = () => ({
          ...latest,
          status: "pending",
          run: latest?.run || { id: snapshot.id, status: "unknown" },
          ...signal?.aborted ? { cancelled: true } : {},
          next_steps: [`The comparison has no verified final report yet. Inspect rehearsal progress, then resume coordination.run_rehearsal with the SAME id '${snapshot.id}'${snapshot.proposal_id ? ` and proposal_id '${snapshot.proposal_id}'` : ""}. Completed case chunks are retained; do not create a replacement test id. No source payment or rule change was authorized.`]
        });
        try {
          while (chunks < 6 && performance.now() < deadline && !abort.signal.aborted) {
            let response;
            try {
              response = await this.#transport.post("rehearsal_run", snapshot, abort.signal);
            } catch (error) {
              if (error instanceof CoordinationError && error.code === "rehearsal_in_progress" && busyWaits++ < 6) {
                await waitDelay(1e3, abort.signal);
                continue;
              }
              throw error;
            }
            latest = await this.rehearsalResult(response);
            const report = response.report;
            if (report) {
              const proposal = response.rehearsal.proposals.find((p) => p.payload.id === snapshot.proposal_id);
              if (report.payload.id !== snapshot.id || (snapshot.proposal_id ? !proposal || report.payload.proposal_digest !== proposal.digest : report.payload.proposal_digest !== void 0)) throw new CoordinationError("invalid_rehearsal", "The report does not match the requested test ID and proposal.");
              if (!response.evidence) {
                const historical = await this.#transport.post("rehearsal_get", { report_digest: report.digest }, abort.signal);
                if (historical.evidence?.report?.digest !== report.digest) throw new CoordinationError("invalid_rehearsal_evidence", "The completed report\u2019s exact evidence snapshot could not be retrieved.");
                latest = { ...await this.rehearsalResult(historical), report };
              }
              return { ...latest, status: "completed" };
            }
            const run = response.run;
            if (!run || run.id !== snapshot.id || run.status !== "running" || !Number.isSafeInteger(run.completed_cases) || !Number.isSafeInteger(run.total_cases) || Number(run.completed_cases) < 0 || Number(run.completed_cases) > Number(run.total_cases) || Number(run.total_cases) < 1 || Number(run.total_cases) > 10) {
              throw new CoordinationError("invalid_rehearsal", "The service did not return a usable test checkpoint or final report. Inspect before resuming the same test id.");
            }
            if (Number(run.completed_cases) <= completedCases) {
              if (busyWaits++ >= 6) return pending();
              await waitDelay(1e3, abort.signal);
            } else {
              completedCases = Number(run.completed_cases);
              chunks++;
            }
          }
          return pending();
        } catch (error) {
          if (abort.signal.aborted || error instanceof CoordinationError && error.code === "rehearsal_in_progress") return pending();
          if (error instanceof CoordinationError && error.code === "service_unavailable") throw new CoordinationError("rehearsal_outcome_unknown", "The test response was lost or timed out. Inspect reports and retry with the SAME test id to recover its result. Do not assume failure or create another test id. No source payment or rule change was authorized.");
          throw error;
        } finally {
          clearTimeout(timer);
          signal?.removeEventListener("abort", cancel);
        }
      }
      async room(signal) {
        const response = await this.#transport.post("inspect", {}, signal);
        const room = response.room;
        const agreement = room?.agreement;
        if (!room || room.room_id !== this.#config.roomId || typeof room.run_id !== "string" || room.authority_key !== this.#config.authorityKey || !agreement || agreement.payload?.type !== "scopeblind.coordination.agreement.v1" || agreement.payload.id !== this.#config.roomId || agreement.payload.version !== 1 || agreement.payload.currency !== "USD" || !/^[0-9a-f]{64}$/.test(agreement.payload.owner_key) || agreement.payload.registrar_key !== this.#config.authorityKey || !await verifyOwnerAgreement(agreement, room.negotiation_evidence)) {
          throw new CoordinationError("invalid_agreement", "The room agreement or its pinned registrar binding could not be verified.");
        }
        if (room.run_id !== `run-${room.room_id}`) {
          const revisions = room.attempts || [];
          let prior = `run-${room.room_id}`;
          for (const attempt of revisions) {
            const r = attempt.revision;
            if (!r || !await verify(r, this.#config.authorityKey) || r.payload.type !== "scopeblind.coordination.revision.v1" || r.payload.room_id !== room.room_id || r.payload.previous_run_id !== prior || r.payload.previous_manifest_digest !== attempt.manifest.digest || attempt.manifest.payload.room_id !== room.room_id || attempt.manifest.payload.run_id !== prior || r.payload.requested_by !== agreement.payload.owner_key || r.payload.agreement_digest !== agreement.digest || !await verify(attempt.manifest, this.#config.authorityKey)) throw new CoordinationError("invalid_revision", "The signed chain of authorized result revisions could not be verified.");
            prior = r.payload.run_id;
          }
          if (prior !== room.run_id) throw new CoordinationError("invalid_revision", "The current run does not follow the signed revision history.");
        }
        if (this.#config.runId && room.run_id !== this.#config.runId) throw new CoordinationError("run_mismatch", "The configured run does not match this room.");
        await this.acknowledgeInspection(response, "inspect", agreement.digest, signal);
        return room;
      }
      /** Live room state is informational; only signed artifacts establish signed claims. */
      async inspect() {
        const room = await this.room();
        return {
          room_id: room.room_id,
          run_id: room.run_id,
          cursor: room.revision,
          agreement: room.agreement,
          authority_key: this.#config.authorityKey,
          paused: room.paused,
          budget: room.budget,
          invoices: room.invoices,
          operations: room.operations,
          fixtures: room.fixtures,
          historical_operations: room.historical_operations,
          revision_note: room.revision_note,
          result: room.manifest,
          acceptance: room.acceptances,
          next_steps: room.manifest ? ["Result is delivered. Wait for recipient acceptance or an owner-authorized revision."] : room.paused ? ["Wait for the owner to resume."] : ["Inspect invoices and purchase orders. Reuse operation IDs for retries. Await a reviewer for held requests; continue other permitted work. Deliver when all items have a recorded disposition."],
          agreement_signature_verified: true,
          scope: "Sample ledger only. No real money moves. Budget and operation lists are service-reported state; ledger.pay verifies each exact admission and outcome independently."
        };
      }
      /** Poll inside the tool, without model calls, for at most thirty seconds. */
      async wait(input, signal) {
        if (!input || Object.keys(input).some((key) => !["after_cursor", "run_id", "timeout_ms"].includes(key)) || !Number.isSafeInteger(input.after_cursor) || input.after_cursor < 0 || input.run_id !== void 0 && (typeof input.run_id !== "string" || !/^run-[A-Za-z0-9_-]{8,100}$/.test(input.run_id))) {
          throw new CoordinationError("invalid_wait", "Pass after_cursor and optionally run_id from coordination.inspect.");
        }
        const timeoutMs = input.timeout_ms === void 0 ? 3e4 : input.timeout_ms;
        if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1e3 || timeoutMs > 3e4) throw new CoordinationError("invalid_wait", "timeout_ms must be an integer from 1000 to 30000.");
        const abort = new AbortController(), cancel = () => abort.abort();
        if (signal?.aborted) cancel();
        else signal?.addEventListener("abort", cancel, { once: true });
        const deadline = performance.now() + timeoutMs;
        let timedOut = false;
        const timer = setTimeout(() => {
          timedOut = true;
          abort.abort();
        }, timeoutMs);
        let latest;
        const response = (room, status) => {
          const operations = room.operations || [];
          const ready = operations.filter((op) => op.status === "admitted" || op.status === "held" && op.decision?.payload.decision === "approve" && Date.parse(op.decision.payload.expires_at) > Date.now()).map((op) => op.operation_id);
          return {
            status,
            cursor: room.revision,
            run_id: room.run_id,
            paused: room.paused,
            result_ready: !!room.manifest,
            attention: {
              ready_to_retry: ready,
              awaiting_reviewer: operations.filter((op) => op.status === "held" && !ready.includes(op.operation_id)).map((op) => op.operation_id),
              changes_requested: operations.filter((op) => op.status === "request_changes").map((op) => op.operation_id),
              unknown_outcomes: operations.filter((op) => op.status === "unknown").map((op) => op.operation_id)
            },
            events: (room.events || []).filter((event) => event.id > input.after_cursor).slice(-30),
            next_steps: status === "waiting" ? ["No change was observed before the timeout. If the client session is still active, call coordination.wait again with this cursor; otherwise resume the session and inspect. This is bounded polling, not a push notification."] : ["Inspect the updated room. Retry approved operations with their existing IDs and exact input; unknown outcomes keep their reservations. A new run requires reviewing its revision instructions."],
            scope: "Authenticated service-reported state. A decision notification does not itself authorize execution; ledger.pay independently verifies each exact admission and outcome."
          };
        };
        try {
          for (; ; ) {
            if (abort.signal.aborted) throw new CoordinationError("cancelled", "The wait was cancelled. No action or approval was performed.");
            latest = await this.room(abort.signal);
            if (abort.signal.aborted) throw new CoordinationError("cancelled", "The wait was cancelled. No action or approval was performed.");
            if (!Number.isSafeInteger(latest.revision) || latest.revision < 0) throw new CoordinationError("invalid_cursor", "The room did not provide a usable event cursor.");
            if (latest.revision !== input.after_cursor || input.run_id !== void 0 && latest.run_id !== input.run_id) return response(latest, "changed");
            const remaining = deadline - performance.now();
            if (remaining <= 0) return response(latest, "waiting");
            const finalInterval = remaining <= 2e3;
            await waitDelay(Math.min(2e3, remaining), abort.signal);
            if (finalInterval || timedOut || performance.now() >= deadline) return response(latest, "waiting");
          }
        } catch (error) {
          if (!signal?.aborted && (timedOut || performance.now() >= deadline) && latest && error instanceof CoordinationError && error.code === "cancelled") return response(latest, latest.revision !== input.after_cursor || input.run_id !== void 0 && latest.run_id !== input.run_id ? "changed" : "waiting");
          if (!signal?.aborted && (timedOut || performance.now() >= deadline) && !latest && error instanceof CoordinationError && error.code === "cancelled") throw new CoordinationError("wait_timeout", "No current room state could be retrieved before the wait timed out. Inspect the room before retrying.");
          throw error;
        } finally {
          clearTimeout(timer);
          signal?.removeEventListener("abort", cancel);
        }
      }
      async deliver(runId) {
        if (typeof runId !== "string" || !/^run-[A-Za-z0-9_-]{8,100}$/.test(runId)) throw new CoordinationError("invalid_run", "Pass the exact run_id from coordination.inspect when delivering.");
        const before = await this.room();
        if (before.run_id !== runId) throw new CoordinationError("run_mismatch", "This attempt has changed. Inspect the revised instructions and work before delivering.");
        const response = await this.#transport.post("deliver", { run_id: before.run_id });
        const room = response.room;
        const manifest = room?.manifest;
        if (!manifest || !await verify(manifest, this.#config.authorityKey) || manifest.payload.type !== "scopeblind.coordination.manifest.v1" || manifest.payload.room_id !== this.#config.roomId || manifest.payload.run_id !== before.run_id || manifest.payload.agreement_digest !== before.agreement.digest) throw new CoordinationError("invalid_manifest", "The delivered result did not verify against this room and attempt. Inspect the room before retrying.");
        return { manifest, manifest_signature_verified: true, next_step: "The recipient can accept this exact result or request changes in the shared room. Delivery does not imply their acceptance." };
      }
      async checkAdmission(value, request, agreement, hash, fresh) {
        const envelope3 = value;
        if (!await verify(envelope3, this.#config.authorityKey)) throw new CoordinationError("invalid_admission", "Admission signature does not match the pinned authority. No execution was requested.");
        const a = envelope3.payload;
        if (a.type !== "scopeblind.coordination.admission.v1" || a.room_id !== this.#config.roomId || a.run_id !== request.run_id || a.operation_id !== request.operation_id || a.agreement_digest !== agreement.digest || a.payload_hash !== hash || canonical(a.input) !== canonical(request.input) || a.destination !== request.input.destination || !["admitted", "held", "refused"].includes(a.decision)) {
          throw new CoordinationError("invalid_admission", "Admission does not authorize these exact operation terms. No execution was requested.");
        }
        const issued = Date.parse(a.issued_at), expiry = Date.parse(a.expires_at);
        if (!Number.isFinite(issued) || !Number.isFinite(expiry) || expiry <= issued || issued > Date.now() + 3e4 || fresh && expiry <= Date.now()) {
          throw new CoordinationError("expired_admission", "Admission validity could not be established. No execution was requested.");
        }
        return envelope3;
      }
      async checkOutcome(value, request, hash) {
        const envelope3 = value;
        if (!await verify(envelope3, this.#config.authorityKey)) throw new CoordinationError("invalid_outcome", "Destination outcome signature does not match the pinned authority.");
        const o = envelope3.payload;
        if (o.type !== "scopeblind.coordination.outcome.v1" || o.room_id !== this.#config.roomId || o.run_id !== request.run_id || o.operation_id !== request.operation_id || o.payload_hash !== hash || o.amount_minor !== request.input.amount_minor || o.destination !== request.input.destination || !["confirmed", "failed", "unknown"].includes(o.status) || o.observed_by !== "sandbox-ledger" && !(o.status === "unknown" && o.observed_by === "gateway-report") || !Number.isFinite(Date.parse(o.issued_at)) || Date.parse(o.issued_at) > Date.now() + 3e4 || o.status === "confirmed" && !o.transaction_id) {
          throw new CoordinationError("invalid_outcome", "Destination outcome does not establish the result of these exact operation terms.");
        }
        return envelope3;
      }
      async pay(payment) {
        validateCoordinationPayment(payment);
        const input = JSON.parse(canonical(payment.input));
        const operationId = payment.operation_id;
        const room = await this.room();
        const request = { operation_id: operationId, run_id: room.run_id, tool: "ledger.pay", input };
        const hash = await payloadHash(input);
        const response = await this.#transport.post("admit", { operation: request });
        const receipt = response.operation?.receipt;
        const admission = await this.checkAdmission(response.admission, request, room.agreement, hash, !receipt);
        if (response.decision !== admission.payload.decision) throw new CoordinationError("invalid_admission", "Admission response contradicts its signed decision. No execution was requested.");
        if (receipt) {
          const outcome = await this.checkOutcome(receipt, request, hash);
          if (outcome.payload.status === "confirmed" && admission.payload.decision !== "admitted") {
            throw new CoordinationError("invalid_outcome", "A confirmed outcome contradicts the signed admission decision. No new execution was requested.");
          }
          if (outcome.payload.status === "unknown" && outcome.payload.observed_by === "gateway-report") {
            return { operation_id: operationId, status: "unknown", reason: outcome.payload.note || "A gateway reported an unknown outcome. Authority remains reserved; no new execution was requested.", admission, outcome, replay: true };
          }
          if (outcome.payload.status !== "unknown") return { operation_id: operationId, status: outcome.payload.status, reason: outcome.payload.note || "Previously observed destination outcome.", admission, outcome, replay: true };
          await this.checkAdmission(response.admission, request, room.agreement, hash, true);
        }
        if (admission.payload.decision !== "admitted") {
          return { operation_id: operationId, status: admission.payload.decision, reason: admission.payload.reason, admission };
        }
        try {
          const execution = await this.#transport.post("execute", { operation_id: operationId });
          const outcome = await this.checkOutcome(execution.outcome, request, hash);
          return { operation_id: operationId, status: outcome.payload.status, reason: outcome.payload.note || "Signed sample-ledger outcome.", admission, outcome, replay: execution.replay === true };
        } catch {
          return { operation_id: operationId, status: "unknown", reason: "Execution was requested, but its outcome could not be verified. Retain this operation_id and inspect or retry the same operation to reconcile; do not create a replacement payment.", admission };
        }
      }
    };
  }
});

// src/coordination-agent-requests.ts
function parseAgentTaskDraft(value) {
  const invalid = () => {
    throw new Error("Use a bounded invoice-task draft with explicit suggested limits and assumptions. No authority has been granted.");
  };
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalid();
  const v = value;
  if (Object.keys(v).sort().join(",") !== DRAFT_KEYS || v.type !== "scopeblind.coordination.agent-task-draft.v1" || !text4(v.title, 1, 100) || !v.title.trim() || !text4(v.goal, 1, 2e3) || !v.goal.trim() || !text4(v.counterparty_name, 0, 60) || !text4(v.private_brief, 0, 2e3) || !amount(v.budget_minor, 1) || !amount(v.approval_above_minor) || v.approval_above_minor > v.budget_minor || !Number.isSafeInteger(v.approval_ttl_seconds) || v.approval_ttl_seconds < 30 || v.approval_ttl_seconds > 900 || v.require_po_match !== true || !amount(v.min_budget_minor, 1) || !amount(v.max_budget_minor, 1) || v.min_budget_minor > v.max_budget_minor || !amount(v.min_threshold_minor) || !amount(v.max_threshold_minor) || v.min_threshold_minor > v.max_threshold_minor || v.max_threshold_minor > v.max_budget_minor || typeof v.preference !== "string" || !["fewer_reviews", "more_review", "balanced"].includes(v.preference) || typeof v.budget_preference !== "string" || !["preserve_budget", "lower_budget", "more_capacity"].includes(v.budget_preference) || !Array.isArray(v.assumptions) || v.assumptions.length > 12 || !v.assumptions.every((item) => text4(item, 1, 300))) return invalid();
  return structuredClone(v);
}
function prepareAgentTaskDraft(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Provide a task title and goal for human review.");
  const v = value;
  if (Object.keys(v).some((key) => !DRAFT_KEYS.split(",").includes(key))) throw new Error("The draft contains a rule this invoice trial cannot enforce. Explain it to the person instead of granting it.");
  if (v.type !== void 0 && v.type !== "scopeblind.coordination.agent-task-draft.v1" || v.assumptions !== void 0 && !Array.isArray(v.assumptions)) throw new Error("The draft type or assumptions are invalid.");
  const assumptions = [...v.assumptions || []];
  const fallback = (key, supplied, defaultValue, note) => {
    if (supplied !== void 0) return supplied;
    assumptions.push(note);
    return defaultValue;
  };
  const budget = fallback("budget_minor", v.budget_minor, 2e5, "Total budget was not supplied: $2,000 is suggested for review.");
  const threshold = fallback("approval_above_minor", v.approval_above_minor, Math.min(5e4, budget), "Review threshold was not supplied: up to $500 is suggested for review.");
  const draft = {
    type: "scopeblind.coordination.agent-task-draft.v1",
    title: v.title,
    goal: v.goal,
    counterparty_name: v.counterparty_name ?? "",
    budget_minor: budget,
    approval_above_minor: threshold,
    approval_ttl_seconds: fallback("approval_ttl_seconds", v.approval_ttl_seconds, 900, "Approval expiry was not supplied: 15 minutes is suggested."),
    require_po_match: v.require_po_match ?? true,
    min_budget_minor: fallback("min_budget_minor", v.min_budget_minor, budget, "Minimum negotiable budget defaults to the suggested total; review before signing."),
    max_budget_minor: fallback("max_budget_minor", v.max_budget_minor, budget, "Maximum negotiable budget defaults to the suggested total; review before signing."),
    min_threshold_minor: fallback("min_threshold_minor", v.min_threshold_minor, threshold, "Minimum review threshold defaults to the suggested threshold; review before signing."),
    max_threshold_minor: fallback("max_threshold_minor", v.max_threshold_minor, threshold, "Maximum review threshold defaults to the suggested threshold; review before signing."),
    private_brief: v.private_brief ?? "",
    preference: v.preference ?? "balanced",
    budget_preference: v.budget_preference ?? "preserve_budget",
    assumptions
  };
  if (!assumptions.includes("This draft uses fictional USD invoices and fixed sample destinations. No real payment service is connected.")) assumptions.push("This draft uses fictional USD invoices and fixed sample destinations. No real payment service is connected.");
  return parseAgentTaskDraft(draft);
}
var DRAFT_KEYS, text4, amount;
var init_coordination_agent_requests = __esm({
  "src/coordination-agent-requests.ts"() {
    "use strict";
    DRAFT_KEYS = ["type", "title", "goal", "counterparty_name", "budget_minor", "approval_above_minor", "approval_ttl_seconds", "require_po_match", "min_budget_minor", "max_budget_minor", "min_threshold_minor", "max_threshold_minor", "private_brief", "preference", "budget_preference", "assumptions"].sort().join(",");
    text4 = (value, min, max) => typeof value === "string" && value.length >= min && value.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value);
    amount = (value, min = 0) => Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= 1e7;
  }
});

// src/coordination-agent-profile.ts
function profileEntry(entries, id5) {
  return entries && Object.hasOwn(entries, id5) ? entries[id5] : void 0;
}
function validateProfileDestination(endpoint2, authorityKey) {
  const checked = validateCoordinationConfig({ endpoint: endpoint2, authorityKey, roomId: "profile-placeholder", token: "profile-placeholder" });
  return { endpoint: checked.endpoint, authorityKey: checked.authorityKey };
}
function readAgentProfile(path) {
  let fd;
  try {
    fd = (0, import_node_fs15.openSync)((0, import_node_path11.resolve)(path), import_node_fs15.constants.O_RDONLY | import_node_fs15.constants.O_NOFOLLOW);
  } catch {
    throw new Error("The private agent profile could not be opened. Run coordination agent setup first.");
  }
  try {
    const file = (0, import_node_fs15.fstatSync)(fd);
    if (!file.isFile() || file.size > 2e6 || process.platform !== "win32" && ((file.mode & 63) !== 0 || process.getuid && file.uid !== process.getuid())) throw new Error("The agent profile must be owned by you with permissions 600.");
    let value;
    try {
      value = JSON.parse((0, import_node_fs15.readFileSync)(fd, "utf8"));
    } catch {
      throw new Error("The private agent profile is not valid JSON.");
    }
    if (value?.type !== "scopeblind.coordination.agent-profile.v1" || !/^[a-f0-9]{64}$/.test(value.agentKey) || !/^[a-f0-9]{96,256}$/.test(value.privateKey) || [value.requests, value.connections, value.pendingHandoffs].some((v) => !v || typeof v !== "object" || Array.isArray(v))) throw new Error("The private agent profile has an unsupported format.");
    validateProfileDestination(value.endpoint, value.authorityKey);
    if (Object.keys(value.requests).length > 50 || Object.keys(value.connections).length > 50 || Object.keys(value.pendingHandoffs).length > 50) throw new Error("This private profile reached its connection limit. Use a separate profile for new work.");
    for (const entries of [value.repositoryConnections, value.repositoryRevisions]) if (entries !== void 0 && (!entries || typeof entries !== "object" || Array.isArray(entries) || Object.keys(entries).length > 50)) throw new Error("The private repository profile has an unsupported format or reached its connection limit.");
    for (const [id5, connection] of Object.entries(value.connections)) {
      validateCoordinationConfig(connection);
      if (!profileId(id5) || connection.endpoint !== value.endpoint || connection.authorityKey !== value.authorityKey || !connection.binding || connection.binding.payload.pair_id !== id5 || connection.binding.payload.agent_key !== connection.agentKey) throw new Error("A saved connection does not match this private profile.");
    }
    for (const [id5, connection] of Object.entries(value.repositoryConnections ?? {})) {
      const grant = connection?.grant?.payload;
      if (!profileId(id5) || !validRepositoryAgentGrant(grant) || grant.id !== id5 || grant.agent_key !== value.agentKey || grant.task_id !== connection.taskId || grant.task_digest !== connection.taskDigest) throw new Error("A saved repository grant does not match this private profile.");
    }
    for (const [id5, revision] of Object.entries(value.repositoryRevisions ?? {})) {
      const r = revision?.request?.payload, c2 = profileEntry(value.repositoryConnections, revision?.connectionId);
      if (!profileId(id5) || !c2 || !validRepositoryRevisionRequest(r) || r.id !== id5 || r.requester_key !== value.agentKey || r.task_id !== c2.taskId || r.task_digest !== c2.taskDigest || r.grant_digest !== c2.grant.digest) throw new Error("A saved repository revision does not match its exact grant.");
    }
    return value;
  } finally {
    (0, import_node_fs15.closeSync)(fd);
  }
}
async function updateAgentProfile(path, change) {
  path = (0, import_node_path11.resolve)(path);
  const lock = path + ".lock";
  let locked = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      (0, import_node_fs15.mkdirSync)(lock, { mode: 448 });
      locked = true;
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw new Error("The private profile could not be locked.");
    }
    await new Promise((resolve5) => setTimeout(resolve5, 50));
  }
  if (!locked) throw new Error("Another process is updating this profile. Retry after it finishes; no credentials were changed.");
  const temporary = path + "." + (0, import_node_crypto11.randomBytes)(8).toString("hex") + ".tmp";
  try {
    const profile = readAgentProfile(path), result2 = change(profile);
    if ([profile.requests, profile.connections, profile.pendingHandoffs, profile.repositoryConnections ?? {}, profile.repositoryRevisions ?? {}].some((entries) => Object.keys(entries).length > 50)) throw new Error("This private profile reached its connection limit. Use a separate profile for new work.");
    const serialized = JSON.stringify(profile) + "\n";
    if (Buffer.byteLength(serialized) > 2e6) throw new Error("This private profile reached its storage limit. Use a separate profile for new work.");
    (0, import_node_fs15.writeFileSync)(temporary, serialized, { flag: "wx", mode: 384 });
    (0, import_node_fs15.renameSync)(temporary, path);
    return result2;
  } finally {
    try {
      (0, import_node_fs15.unlinkSync)(temporary);
    } catch {
    }
    try {
      (0, import_node_fs15.rmdirSync)(lock);
    } catch {
    }
  }
}
async function ensureAgentProfile(path, endpoint2, authorityKey) {
  path = (0, import_node_path11.resolve)(path);
  try {
    const value = readAgentProfile(path);
    if (endpoint2 !== void 0 && validateProfileDestination(endpoint2, authorityKey || value.authorityKey).endpoint !== value.endpoint || authorityKey !== void 0 && authorityKey.toLowerCase() !== value.authorityKey) throw new Error("This profile is pinned to another authority or endpoint. Use its original settings or a separate profile.");
    await importIdentity(value.privateKey, value.agentKey);
    return value;
  } catch (error) {
    try {
      const fd2 = (0, import_node_fs15.openSync)(path, import_node_fs15.constants.O_RDONLY | import_node_fs15.constants.O_NOFOLLOW);
      (0, import_node_fs15.closeSync)(fd2);
      throw error;
    } catch (check) {
      if (check.code !== "ENOENT") throw error;
    }
  }
  if (!endpoint2 || !authorityKey) throw new Error("A new profile needs --endpoint and an independently pinned --authority-key.");
  const destination = validateProfileDestination(endpoint2, authorityKey), pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const profile = { type: "scopeblind.coordination.agent-profile.v1", ...destination, agentKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), privateKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))), requests: {}, connections: {}, pendingHandoffs: {} };
  (0, import_node_fs15.mkdirSync)((0, import_node_path11.dirname)(path), { recursive: true, mode: 448 });
  const fd = (0, import_node_fs15.openSync)(path, import_node_fs15.constants.O_WRONLY | import_node_fs15.constants.O_CREAT | import_node_fs15.constants.O_EXCL | import_node_fs15.constants.O_NOFOLLOW, 384);
  try {
    (0, import_node_fs15.writeFileSync)(fd, JSON.stringify(profile) + "\n");
  } finally {
    (0, import_node_fs15.closeSync)(fd);
  }
  return profile;
}
async function importProfileConnection(profilePath, configPath) {
  const stored = readPrivateConfig(configPath), config = coordinationConfigFromFile(configPath), binding = stored.binding;
  if (!await verify(binding, config.authorityKey) || !await verify(binding.payload.owner_authorization, binding.payload.owner_key)) throw new Error("The saved connection signatures could not be verified.");
  await updateAgentProfile(profilePath, (profile) => {
    if (config.endpoint !== profile.endpoint || config.authorityKey !== profile.authorityKey) throw new Error("Import requires the same pinned endpoint and authority.");
    const id5 = binding.payload.pair_id, existing = profile.connections[id5];
    if (existing && existing.binding.digest !== binding.digest) throw new Error("This connection ID already names another signed grant.");
    profile.connections[id5] = { ...config, type: stored.type, setupVersion: stored.setupVersion, agentKey: stored.agentKey, name: stored.name, binding };
  });
  return binding.payload.pair_id;
}
var import_node_fs15, import_node_path11, import_node_os2, import_node_crypto11, DEFAULT_AGENT_PROFILE, profileId;
var init_coordination_agent_profile = __esm({
  "src/coordination-agent-profile.ts"() {
    "use strict";
    import_node_fs15 = require("fs");
    import_node_path11 = require("path");
    import_node_os2 = require("os");
    import_node_crypto11 = require("crypto");
    init_coordination_protocol();
    init_coordination_config();
    init_coordination_pair_cli();
    init_coordination_repository_collaboration();
    DEFAULT_AGENT_PROFILE = (0, import_node_path11.resolve)((0, import_node_os2.homedir)(), ".scopeblind", "agent.json");
    profileId = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(value);
  }
});

// src/coordination-repository-collaboration-evidence.ts
function requireValid(condition, message) {
  if (!condition) throw new Error(message);
}
async function verifyRepositoryCollaborationEvidence(input, pins) {
  const result2 = { valid: false, accepted: false, authorityPinned: false, previewVerified: false, revisionLinked: false, errors: [], limitations: [...baseLimitations] };
  try {
    requireValid(shape2(input, ["type", "repository", "collaboration"], ["demo", "parent", "parent_request", "parent_agent_grant"]) && input.type === "scopeblind.repository.collaboration-evidence.v1", "Unsupported collaboration evidence shape.");
    const bundle = input;
    const core = await verifyRepositoryEvidence(bundle.repository, pins);
    result2.limitations.push(...core.limitations);
    requireValid(core.valid, core.errors.join("; "));
    result2.authorityPinned = core.authorityPinned;
    const state = bundle.repository.state.payload, task = state.task.payload, collaboration = bundle.collaboration, c2 = collaboration?.payload;
    requireValid(envelope(collaboration) && await verify(collaboration, task.authority_key) && shape2(c2, ["type", "task_id", "task_digest", "participants", "preview", "requests", "revisions", "agent_grants", "observed_at"]) && c2.type === "scopeblind.repository.collaboration.v1" && c2.task_id === task.id && c2.task_digest === state.task.digest && time4(c2.observed_at), "Collaboration must be signed by this task\u2019s authority and name the exact task.");
    const principals = [task.owner_key, ...state.reviewer ? [state.reviewer.payload.reviewer_key] : []];
    if (c2.participants !== null) {
      const signed2 = c2.participants, p = signed2?.payload;
      requireValid(envelope(signed2) && validRepositoryParticipants(p) && await verify(signed2, task.owner_key) && p.task_id === task.id && p.task_digest === state.task.digest && p.owner_key === task.owner_key && p.receiver_key === task.receiver_key && p.reviewer_key === state.reviewer?.payload.reviewer_key && p.reviewer_claim_digest === state.reviewer?.digest && within(p.issued_at, task.issued_at, task.expires_at) && Date.parse(p.expires_at) <= Date.parse(task.expires_at), "The owner\u2019s participant binding does not match this task and enrolled reviewer.");
    }
    if (c2.preview !== null) {
      const signed2 = c2.preview, p = signed2?.payload, proposal = state.proposal;
      requireValid(envelope(signed2) && validRepositoryPreview(p) && await verify(signed2, task.receiver_key) && proposal && p.task_id === task.id && p.task_digest === state.task.digest && p.proposal_digest === proposal.digest && ["base_sha", "head_sha", "merge_sha", "tree_sha"].every((k) => p[k] === proposal.payload[k]) && proposal.payload.files.some((f) => f.path === CONTACT_PATH), "The preview is not bound to this exact receiver-reviewed proposal.");
      for (const side of [p.before, p.after]) {
        const bytes = new TextEncoder().encode(contactPageBytes(side.model)), header2 = new TextEncoder().encode(`blob ${bytes.length}\0`), blob = new Uint8Array(header2.length + bytes.length);
        blob.set(header2);
        blob.set(bytes, header2.length);
        const gitSha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", blob)), (n) => n.toString(16).padStart(2, "0")).join("");
        requireValid(await sha256(contactPageBytes(side.model)) === side.content_sha256 && gitSha === side.blob_sha, "Preview content does not match its canonical bytes and Git blob digest.");
      }
      requireValid(Date.parse(p.observed_at) >= Date.parse(proposal.payload.observed_at) && Date.parse(p.observed_at) <= Date.parse(c2.observed_at), "Preview timing does not follow the reviewed proposal.");
      result2.previewVerified = true;
    }
    requireValid(Array.isArray(c2.agent_grants) && c2.agent_grants.length <= 100 && Array.isArray(c2.requests) && c2.requests.length <= 100 && Array.isArray(c2.revisions) && c2.revisions.length <= 100, "Collaboration collections exceed their supported bounds.");
    const incomingLinks = c2.revisions.filter((link) => link?.payload?.child_task_id === task.id);
    requireValid(incomingLinks.length <= 1 && (incomingLinks.length === 1 || !["parent", "parent_request", "parent_agent_grant"].some((key) => Object.hasOwn(bundle, key))), "Predecessor records must be consumed by exactly one incoming revision link.");
    const grants = /* @__PURE__ */ new Map(), requestIds = /* @__PURE__ */ new Set(), requests = /* @__PURE__ */ new Map();
    for (const entry of c2.agent_grants) {
      const signed2 = entry.grant, g = signed2?.payload;
      requireValid(shape2(entry, ["grant", "revoked"]) && typeof entry.revoked === "boolean" && envelope(signed2) && validRepositoryAgentGrant(g) && await verify(signed2, g.issuer_key) && principals.includes(g.issuer_key) && ![...principals, task.receiver_key, task.authority_key].includes(g.agent_key) && g.task_id === task.id && g.task_digest === state.task.digest && within(g.issued_at, task.issued_at, task.expires_at) && Date.parse(g.issued_at) <= Date.parse(c2.observed_at) && Date.parse(g.expires_at) <= Date.parse(task.expires_at) && !grants.has(signed2.digest), "An agent grant is invalid, duplicated, or crosses a human/receiver boundary.");
      grants.set(signed2.digest, entry);
    }
    for (const signed2 of c2.requests) {
      const r = signed2?.payload;
      requireValid(envelope(signed2) && validRepositoryRevisionRequest(r) && await verify(signed2, r.requester_key) && r.task_id === task.id && r.task_digest === state.task.digest && within(r.issued_at, task.issued_at, task.expires_at) && Date.parse(r.issued_at) <= Date.parse(c2.observed_at) && !requestIds.has(r.id) && !requests.has(signed2.digest), "A revision request is invalid or duplicated.");
      requestIds.add(r.id);
      requests.set(signed2.digest, signed2);
      if (principals.includes(r.requester_key)) requireValid(r.grant_digest === void 0, "A human revision must not borrow an agent grant.");
      else {
        const g = r.grant_digest ? grants.get(r.grant_digest)?.grant.payload : void 0;
        requireValid(g && g.agent_key === r.requester_key && g.permissions.includes("request_revision") && within(r.issued_at, g.issued_at, g.expires_at), "The suggesting agent did not hold the exact recorded revision scope.");
      }
    }
    let parent;
    if (bundle.parent) {
      const checked = await verifyRepositoryEvidence(bundle.parent, pins);
      requireValid(checked.valid, "The predecessor repository evidence does not verify.");
      parent = bundle.parent.state.payload;
      requireValid(parent.task.payload.owner_key === task.owner_key && parent.task.payload.receiver_key === task.receiver_key && parent.task.payload.authority_key === task.authority_key && parent.task.payload.repository === task.repository, "The predecessor crosses this repository or participant authority.");
    }
    const linkIds = /* @__PURE__ */ new Set();
    for (const signed2 of c2.revisions) {
      const l = signed2?.payload;
      requireValid(envelope(signed2) && validRepositoryRevisionLink(l) && await verify(signed2, task.owner_key) && l.owner_key === task.owner_key && time4(l.issued_at) && Date.parse(l.issued_at) <= Date.parse(c2.observed_at) && !linkIds.has(l.id), "A revision link is invalid or duplicated.");
      linkIds.add(l.id);
      if (l.child_task_id === task.id) {
        requireValid(l.child_task_digest === state.task.digest && parent && l.parent_task_id === parent.task.payload.id && l.parent_task_digest === parent.task.digest && l.parent_basis_digest === repositoryRevisionBasis(parent), "The child revision does not bind the included predecessor and exact feedback.");
        const signedRequest = bundle.parent_request, r = signedRequest?.payload, pt = parent.task.payload;
        requireValid(envelope(signedRequest) && validRepositoryRevisionRequest(r) && await verify(signedRequest, r.requester_key) && signedRequest.digest === l.request_digest && r.task_id === pt.id && r.task_digest === parent.task.digest && r.basis_digest === l.parent_basis_digest && within(r.issued_at, pt.issued_at, pt.expires_at) && Date.parse(r.issued_at) <= Date.parse(l.issued_at), "The original signed feedback is missing or does not match this revision.");
        const parentPrincipals = [pt.owner_key, ...parent.reviewer ? [parent.reviewer.payload.reviewer_key] : []];
        if (parentPrincipals.includes(r.requester_key)) requireValid(r.grant_digest === void 0 && bundle.parent_agent_grant === void 0, "Human feedback must not borrow an agent grant.");
        else {
          const signedGrant = bundle.parent_agent_grant, g = signedGrant?.payload;
          requireValid(envelope(signedGrant) && validRepositoryAgentGrant(g) && await verify(signedGrant, g.issuer_key) && signedGrant.digest === r.grant_digest && parentPrincipals.includes(g.issuer_key) && ![...parentPrincipals, pt.receiver_key, pt.authority_key].includes(g.agent_key) && g.agent_key === r.requester_key && g.task_id === pt.id && g.task_digest === parent.task.digest && g.permissions.includes("request_revision") && within(g.issued_at, pt.issued_at, pt.expires_at) && Date.parse(g.expires_at) <= Date.parse(pt.expires_at) && within(r.issued_at, g.issued_at, g.expires_at), "The original feedback agent\u2019s exact human-signed scope is missing or invalid.");
        }
        result2.revisionLinked = true;
      } else {
        requireValid(l.parent_task_id === task.id && l.parent_task_digest === state.task.digest && requests.has(l.request_digest) && requests.get(l.request_digest).payload.basis_digest === l.parent_basis_digest, "The outgoing revision link does not name this task and an included suggestion.");
      }
    }
    if (bundle.demo) {
      const signed2 = bundle.demo, d = signed2?.payload, r = d?.request?.payload, p = d?.provision?.payload;
      requireValid(envelope(signed2) && await verify(signed2, task.authority_key) && shape2(d, ["type", "request", "provision", "task", "status", "dispatch", "error", "observed_at"]) && d.type === "scopeblind.repository.demo-state.v1" && ["queued", "provisioning", "ready_to_review", "active", "failed", "expired"].includes(d.status) && ["requested", "unconfigured", "unavailable"].includes(d.dispatch) && (d.error === null || typeof d.error === "string" && d.error.length <= 100) && time4(d.observed_at), "The demo\u2019s service record is invalid.");
      requireValid(envelope(d.request) && validRepositoryDemoRequest(r) && await verify(d.request, task.owner_key) && r.id === task.id && r.owner_key === task.owner_key && r.authority_key === task.authority_key && r.receiver_key === task.receiver_key && r.reviewer_secret_hash === task.reviewer_secret_hash && r.title === task.title && Date.parse(task.expires_at) <= Date.parse(r.expires_at), "The demo request is not the task owner\u2019s exact provisioning authority.");
      requireValid(d.task && canonical(d.task) === canonical(state.task) && envelope(d.provision) && validRepositoryDemoProvision(p) && await verify(d.provision, task.receiver_key) && p.request_id === task.id && p.request_digest === d.request.digest && p.repository === task.repository && p.base_branch === task.base_branch && p.pull_number === task.pull_number && p.receiver_key === task.receiver_key && canonical(p.required_checks) === canonical(task.required_checks) && canonical(task.allowed_paths) === canonical([CONTACT_PATH]), "The provisioned workspace does not match the signed task.");
      if (c2.preview) requireValid(c2.preview.payload.base_sha === p.initial_base_sha && c2.preview.payload.head_sha === p.initial_head_sha && canonical(c2.preview.payload.after.model) === canonical(r.proposed), "The demo preview differs from the exact requested and provisioned change.");
      if (r.parent_task_id) requireValid(result2.revisionLinked && parent && r.parent_task_id === parent.task.payload.id && r.parent_task_digest === parent.task.digest && r.parent_basis_digest === repositoryRevisionBasis(parent) && canonical(bundle.parent_request?.payload.proposed) === canonical(r.proposed) && c2.revisions.some((l) => l.payload.child_task_id === task.id && l.payload.request_digest === r.revision_request_digest), "The demo revision lacks its exact predecessor link.");
    }
    result2.valid = true;
    result2.accepted = core.accepted;
  } catch (error) {
    result2.errors.push(error instanceof Error ? error.message : "The collaboration evidence could not be verified.");
    result2.previewVerified = false;
    result2.revisionLinked = false;
    result2.accepted = false;
  }
  return result2;
}
var shape2, envelope, time4, within, baseLimitations;
var init_coordination_repository_collaboration_evidence = __esm({
  "src/coordination-repository-collaboration-evidence.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_collaboration();
    shape2 = (v, required, optional = []) => !!v && typeof v === "object" && !Array.isArray(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
    envelope = (v) => shape2(v, ["payload", "signer", "digest", "signature"]);
    time4 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
    within = (at2, start, end) => Date.parse(at2) >= Date.parse(start) && Date.parse(at2) <= Date.parse(end);
    baseLimitations = [
      "A preview is the receiver\u2019s signed observation of canonical contact-page data, rendered by ScopeBlind\u2019s fixed template. It does not execute repository code or prove a deployed website.",
      "Agent grants allow only the recorded reading and revision suggestions. They do not convey human approval or receiver execution authority.",
      "Revocation flags and the completeness of the collaboration history are statements by the service. The included record does not prove a currently live grant."
    ];
  }
});

// src/coordination-repository-agent.ts
function fail(code2, message) {
  throw new CoordinationError(code2, message);
}
function repositoryConnectionSummary(id5, c2, agentKey) {
  return { connection_id: id5, purpose: "repository", room_id: c2.taskId, task_id: c2.taskId, task_digest: c2.taskDigest, principal_key: c2.grant.payload.issuer_key, agent_key: agentKey, expires_at: c2.grant.payload.expires_at, locally_expired: Date.parse(c2.grant.payload.expires_at) <= Date.now(), same_profile_key: true, scope: c2.grant.payload.permissions };
}
var exact4, hex3, RepositoryAgentClient;
var init_coordination_repository_agent = __esm({
  "src/coordination-repository-agent.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_client();
    init_coordination_agent_profile();
    init_coordination_repository_collaboration();
    init_coordination_repository_collaboration_evidence();
    exact4 = (v, keys2) => !!v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === keys2.length && keys2.every((k) => Object.hasOwn(v, k));
    hex3 = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
    RepositoryAgentClient = class {
      constructor(profilePath, transport) {
        this.profilePath = profilePath;
        this.transport = transport;
      }
      profile() {
        return readAgentProfile(this.profilePath);
      }
      async checked(response, taskId, grantId) {
        const profile = this.profile(), e = response.evidence;
        const checked = await verifyRepositoryCollaborationEvidence(e, profile.authorityKey);
        if (!checked.valid || !checked.authorityPinned || !response.repository_task || !response.collaboration || canonical(response.repository_task) !== canonical(e.repository.state) || canonical(response.collaboration) !== canonical(e.collaboration)) fail("repository_evidence_invalid", "The repository evidence did not verify against this profile\u2019s pinned authority. No grant was saved or revision reported as recorded.");
        const s = e.repository.state.payload, c2 = e.collaboration.payload, task = s.task.payload, now = Date.now();
        if (task.id !== taskId || Math.abs(now - Date.parse(s.observed_at)) > 12e4 || Math.abs(now - Date.parse(c2.observed_at)) > 12e4) fail("repository_state_stale", "Inspect this exact repository task again; the signed observation is stale or belongs to another task.");
        const entries = c2.agent_grants.filter((entry2) => entry2.grant.payload.id === grantId);
        if (entries.length !== 1) fail("repository_agent_grant_missing", "The signed task does not contain this exact agent grant. Ask your person to authorize this profile\u2019s public key.");
        const entry = entries[0], grant = entry.grant, g = grant.payload;
        if (entry.revoked || g.agent_key !== profile.agentKey || !g.permissions.includes("read_task") || Date.parse(g.issued_at) > now + 6e4 || Date.parse(g.expires_at) <= now || Date.parse(task.expires_at) <= now) fail("repository_agent_grant_inactive", "The exact repository grant is inactive, revoked, expired or belongs to another agent. No authority is inherited from another connection.");
        const saved = profileEntry(profile.repositoryConnections, grantId);
        if (saved && (saved.taskId !== taskId || saved.taskDigest !== s.task.digest || saved.grant.digest !== grant.digest)) fail("repository_agent_grant_conflict", "This connection ID already names a different signed repository grant.");
        return { evidence: e, grant, connection: { taskId, taskDigest: s.task.digest, grant } };
      }
      async read(taskId, grantId) {
        if (!profileId(taskId) || !profileId(grantId)) fail("invalid_repository_connection", "Use the task_id and grant_id supplied by the person after they authorize this profile key.");
        const response = await this.transport("repository_agent_get", taskId, { grant_id: grantId });
        return this.checked(response, taskId, grantId);
      }
      summary(e) {
        const s = e.repository.state.payload, c2 = e.collaboration.payload;
        return { task: s.task.payload, status: s.status, reviewer_key: s.reviewer?.payload.reviewer_key ?? null, proposal: s.proposal?.payload ?? null, preview: c2.preview?.payload ?? null, current_basis_digest: repositoryRevisionBasis(s), approvals: s.approvals.map((a) => ({ principal_key: a.payload.principal_key, decision: a.payload.decision, expires_at: a.payload.expires_at })), outcome: s.outcome?.payload ?? null, acceptance: s.acceptance?.payload ?? null, revision_requests: c2.requests.map((r) => ({ ...r.payload, digest: r.digest })), revisions: c2.revisions.map((r) => r.payload), observed_at: s.observed_at };
      }
      async inspect(taskId, grantId) {
        const checked = await this.read(taskId, grantId);
        await updateAgentProfile(this.profilePath, (p) => {
          const prior = profileEntry(p.repositoryConnections, grantId);
          if (prior && prior.grant.digest !== checked.grant.digest) fail("repository_agent_grant_conflict", "A different repository grant was saved concurrently.");
          p.repositoryConnections ??= /* @__PURE__ */ Object.create(null);
          Object.defineProperty(p.repositoryConnections, grantId, { value: checked.connection, enumerable: true, writable: true, configurable: true });
        });
        return { ...repositoryConnectionSummary(grantId, checked.connection, this.profile().agentKey), ...this.summary(checked.evidence), evidence: checked.evidence, next_step: "Read the verified task and exact current_basis_digest. If this grant permits request_revision, you may suggest only the supported contact-page model. Humans must review the suggestion, create any revision task, and approve its fresh exact snapshot. You cannot claim a human role, approve, accept, install a receiver, or execute a branch update." };
      }
      async requestRevision(input) {
        if (!exact4(input, ["connection_id", "request_id", "basis_digest", "message", "proposed"]) || !profileId(input.connection_id) || !profileId(input.request_id) || !hex3(input.basis_digest) || typeof input.message !== "string" || !input.message.trim() || input.message.length > 600 || /[\u0000-\u001f\u007f]/.test(input.message) || !validContactPage(input.proposed)) fail("invalid_repository_revision", "Use a stable request_id, the exact inspected basis_digest, a brief message, and only the supported contact-page model.");
        const p = this.profile(), saved = profileEntry(p.repositoryConnections, input.connection_id);
        if (!saved) fail("unknown_repository_connection", "Call coordination.inspect_repository with the person\u2019s exact task and grant IDs first.");
        const pending = profileEntry(p.repositoryRevisions, input.request_id);
        if (pending && (pending.connectionId !== input.connection_id || pending.request.payload.basis_digest !== input.basis_digest || pending.request.payload.message !== input.message || canonical(pending.request.payload.proposed) !== canonical(input.proposed))) fail("repository_revision_id_conflict", "This request ID already names another exact suggestion. Preserve it for retries; use a new ID for a different intended revision.");
        const checked = await this.read(saved.taskId, input.connection_id), c2 = checked.evidence.collaboration.payload;
        if (!checked.grant.payload.permissions.includes("request_revision")) fail("repository_revision_outside_grant", "This connection permits reading only. Ask the person to review any additional revision permission.");
        if (pending) {
          if (!await verify(pending.request, p.agentKey)) fail("repository_revision_invalid", "The locally saved revision signature is invalid; it cannot be replayed.");
          if (c2.requests.some((r) => r.digest === pending.request.digest)) return this.recorded(input.connection_id, pending.request);
        }
        if (repositoryRevisionBasis(checked.evidence.repository.state.payload) !== input.basis_digest) fail("repository_revision_basis_stale", "The task now has a different inspected change or result. Inspect it and ask whether a new suggestion is still appropriate; the saved suggestion was not rewritten.");
        if (!pending) {
          const payload = { type: "scopeblind.repository.revision-request.v1", id: input.request_id, task_id: saved.taskId, task_digest: saved.taskDigest, basis_digest: input.basis_digest, requester_key: p.agentKey, grant_digest: checked.grant.digest, message: input.message, proposed: input.proposed, issued_at: (/* @__PURE__ */ new Date()).toISOString() };
          if (!validRepositoryRevisionRequest(payload)) fail("invalid_repository_revision", "The proposed revision cannot be represented by this bounded protocol.");
          const request2 = await sign(payload, await importIdentity(p.privateKey, p.agentKey));
          await updateAgentProfile(this.profilePath, (current) => {
            const prior = profileEntry(current.repositoryRevisions, input.request_id);
            if (prior && (prior.connectionId !== input.connection_id || prior.request.payload.basis_digest !== input.basis_digest || prior.request.payload.message !== input.message || canonical(prior.request.payload.proposed) !== canonical(input.proposed))) fail("repository_revision_id_conflict", "Another writer used this request ID for a different exact suggestion.");
            current.repositoryRevisions ??= /* @__PURE__ */ Object.create(null);
            if (!prior) Object.defineProperty(current.repositoryRevisions, input.request_id, { value: { connectionId: input.connection_id, request: request2 }, enumerable: true, writable: true, configurable: true });
          });
        }
        const request = profileEntry(this.profile().repositoryRevisions, input.request_id).request;
        const response = await this.transport("repository_revision_request", saved.taskId, { request });
        const recorded = await this.checked(response, saved.taskId, input.connection_id);
        if (!recorded.evidence.collaboration.payload.requests.some((r) => r.digest === request.digest && canonical(r) === canonical(request))) fail("repository_revision_unverified", "The reply did not include this exact signed revision request. Retry the same request_id; its original signature is saved locally.");
        return this.recorded(input.connection_id, request);
      }
      recorded(connectionId, request) {
        return { connection_id: connectionId, request_id: request.payload.id, request_digest: request.digest, basis_digest: request.payload.basis_digest, status: "recorded", next_step: "The signed suggestion is recorded for human review. It did not create or approve a task, execute a change, or accept a result. Keep this request_id for retries." };
      }
    };
  }
});

// src/coordination-agent-client.ts
function fail2(code2, message) {
  throw new CoordinationError(code2, message);
}
var import_node_crypto12, hex4, exact5, envelope2, CoordinationAgentClient;
var init_coordination_agent_client = __esm({
  "src/coordination-agent-client.ts"() {
    "use strict";
    import_node_crypto12 = require("crypto");
    init_coordination_protocol();
    init_coordination_pairing();
    init_coordination_pair_cli();
    init_coordination_client();
    init_coordination_agent_requests();
    init_coordination_agent_profile();
    init_coordination_repository_agent();
    hex4 = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
    exact5 = (value, required, optional = []) => !!value && typeof value === "object" && !Array.isArray(value) && required.every((k) => Object.hasOwn(value, k)) && Object.keys(value).every((k) => required.includes(k) || optional.includes(k));
    envelope2 = (value) => exact5(value, ["payload", "signer", "digest", "signature"]);
    CoordinationAgentClient = class {
      constructor(profilePath, fetchImpl = fetch) {
        this.profilePath = profilePath;
        this.fetchImpl = fetchImpl;
      }
      profile() {
        return readAgentProfile(this.profilePath);
      }
      async request(action, roomId, body) {
        const profile = this.profile(), identity = await importIdentity(profile.privateKey, profile.agentKey);
        const request = await sign(makeRequest(action, roomId, body), identity);
        const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 25e3);
        try {
          const response = await this.fetchImpl(profile.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", cache: "no-store", signal: abort.signal });
          const raw = await response.text();
          if (raw.length > 2e6) fail2("invalid_agent_response", "The service response was too large.");
          let result2;
          try {
            result2 = JSON.parse(raw);
          } catch {
            fail2("invalid_agent_response", "The service did not return a readable response.");
          }
          if (!response.ok || result2.ok !== true) {
            const code2 = typeof result2.error === "string" && /^[a-z_]{3,80}$/.test(result2.error) ? result2.error : "agent_request_refused";
            fail2(code2, "The service refused this agent request. Inspect the current task or ask the person to review its permissions; no authority was added.");
          }
          return result2;
        } catch (error) {
          if (error instanceof CoordinationError) throw error;
          fail2("agent_connection_interrupted", "The reply was interrupted. Retry the same request or grant ID; its private recovery state is saved locally.");
        } finally {
          clearTimeout(timer);
        }
      }
      async checkedRequest(value, id5) {
        const profile = this.profile(), pending = profile.requests[id5];
        if (!pending || !exact5(value, ["request_id", "agent_key", "pairing_secret_hash", "status", "expires_at", "draft"], ["accepted", "connection"])) fail2("invalid_agent_request", "The returned draft does not match this profile.");
        const v = value;
        if (v.request_id !== id5 || v.agent_key !== profile.agentKey || v.pairing_secret_hash !== await sha256(pending.pairingSecret) || v.expires_at !== pending.expiresAt || !["pending", "accepted", "ready", "revoked", "expired"].includes(v.status) || canonical(parseAgentTaskDraft(v.draft)) !== canonical(pending.draft)) fail2("invalid_agent_request", "The returned draft does not match the exact request prepared here.");
        if (v.accepted) {
          const a = v.accepted;
          if (!exact5(a, ["owner_key", "room_id", "session_id", "pair_id", "reviewed_draft", "digest"]) || !hex4(a.owner_key) || a.owner_key === profile.agentKey || ![a.room_id, a.session_id, a.pair_id].every(profileId) || !hex4(a.digest)) fail2("invalid_agent_request", "The reviewed draft does not name a valid independent principal.");
          if (a.digest !== await sha256(canonical(parseAgentTaskDraft(a.reviewed_draft)))) fail2("invalid_agent_request", "The reviewed draft digest does not match its exact content.");
        }
        if (v.connection) {
          const c2 = v.connection, a = v.accepted;
          if (!a || !exact5(c2, ["purpose", "room_id", "session_id", "pair_id", "principal_key", "authority_key"], ["binding"]) || c2.purpose !== "negotiation" || c2.room_id !== a.room_id || c2.session_id !== a.session_id || c2.pair_id !== a.pair_id || c2.principal_key !== a.owner_key || c2.authority_key !== profile.authorityKey) fail2("invalid_agent_request", "The offered connection does not match the person\u2019s reviewed task.");
        }
        if (v.status === "ready" && !v.connection) fail2("invalid_agent_request", "A ready connection must name its exact signed task.");
        return v;
      }
      reviewLink(id5, secret) {
        const url = new URL("/standard", this.profile().endpoint);
        url.searchParams.set("trial", "new");
        url.hash = "agent_request=" + id5 + "." + secret;
        return url.href;
      }
      async prepareTask(input) {
        if (!exact5(input, ["request_id", "draft"]) || !profileId(input.request_id)) fail2("invalid_agent_draft", "Use one stable request_id and an explicit draft.");
        const draft = prepareAgentTaskDraft(input.draft), id5 = input.request_id;
        await updateAgentProfile(this.profilePath, (profile) => {
          if (profile.requests[id5]) {
            if (canonical(profile.requests[id5].draft) !== canonical(draft)) fail2("agent_request_id_conflict", "This request ID already names a different draft. Keep it for retries; use a new ID only for a different intended task.");
            return;
          }
          if (Object.keys(profile.requests).length >= 50) fail2("agent_profile_limit", "This profile has 50 saved requests. Use a separate profile for new work.");
          profile.requests[id5] = { draft, reviewSecret: (0, import_node_crypto12.randomBytes)(32).toString("hex"), pairingSecret: (0, import_node_crypto12.randomBytes)(32).toString("hex"), expiresAt: new Date(Date.now() + 30 * 60 * 1e3).toISOString() };
        });
        const saved = this.profile().requests[id5];
        const response = await this.request("agent_request_create", id5, { request_id: id5, secret_hash: await sha256(saved.reviewSecret), pairing_secret_hash: await sha256(saved.pairingSecret), draft: saved.draft, expires_at: saved.expiresAt });
        const request = await this.checkedRequest(response.agent_request, id5);
        return { request_id: id5, status: request.status, private_review_link: this.reviewLink(id5, saved.reviewSecret), draft: { ...draft, private_brief: void 0 }, assumptions: draft.assumptions, scope: "Unsigned suggestions only. Show this private review link to your own person; it includes access to their private draft instructions. They must review the draft, create the shared task, and sign a mandate. This does not create owner authority, invite the colleague, or start a model or payment." };
      }
      async inspectTaskRequest(id5) {
        if (!profileId(id5) || !this.profile().requests[id5]) fail2("unknown_agent_request", "This profile has no saved request with that ID.");
        const response = await this.request("agent_request_get", id5, { request_id: id5 }), request = await this.checkedRequest(response.agent_request, id5);
        return { request_id: id5, status: request.status, expires_at: request.expires_at, title: request.draft.title, ...request.accepted ? { reviewed_draft: request.accepted.reviewed_draft, owner_key: request.accepted.owner_key, room_id: request.accepted.room_id, session_id: request.accepted.session_id } : {}, ...request.connection ? { connection_id: request.connection.pair_id } : {}, next_step: request.status === "ready" ? "Call coordination.claim_task_connection with this request_id. Then inspect the exact mandate through the returned connection_id." : request.status === "pending" ? "Your person must open and review the private link. No authority is granted." : request.status === "accepted" ? "The person reviewed the draft. Wait for their signed mandate and explicit agent connection; acceptance of a draft is not an agent grant." : "This request is inactive. Keep its history; ask the person before preparing a new task." };
      }
      async claimTaskConnection(id5) {
        if (!profileId(id5) || !this.profile().requests[id5]) fail2("unknown_agent_request", "This profile has no saved request with that ID.");
        const response = await this.request("agent_request_get", id5, { request_id: id5 }), view = await this.checkedRequest(response.agent_request, id5);
        if (view.status !== "ready" || !view.connection) fail2("agent_grant_not_ready", "The person has not yet signed an active negotiation grant. A reviewed draft alone is not permission.");
        const c2 = view.connection;
        const existing = this.profile().connections[c2.pair_id];
        if (existing) return this.connectionSummary(c2.pair_id, existing);
        await updateAgentProfile(this.profilePath, (profile2) => {
          const saved2 = profile2.requests[id5];
          if (saved2.pendingPairId !== c2.pair_id || !saved2.pendingToken) {
            saved2.pendingPairId = c2.pair_id;
            saved2.pendingToken = (0, import_node_crypto12.randomBytes)(32).toString("hex");
          }
        });
        const profile = this.profile(), saved = profile.requests[id5];
        const ready = await claimPairing({ type: "scopeblind.coordination.config.v1", setupVersion: 2, endpoint: profile.endpoint, authorityKey: profile.authorityKey, agentKey: profile.agentKey, token: saved.pendingToken, roomId: c2.room_id, purpose: "negotiation", sessionId: c2.session_id, principalKey: c2.principal_key, name: "My agent", pending: { privateKey: profile.privateKey, code: { version: 3, endpoint: profile.endpoint, authority_key: profile.authorityKey, room_id: c2.room_id, session_id: c2.session_id, principal_key: c2.principal_key, pair_id: c2.pair_id, secret: saved.pairingSecret, scope: NEGOTIATION_PAIRING_SCOPE, audience: NEGOTIATION_PAIRING_AUDIENCE } } }, this.fetchImpl);
        if (ready.binding?.payload.owner_authorization.payload.body.expected_agent_key !== profile.agentKey) fail2("agent_grant_wrong_key", "This grant must explicitly name the profile\u2019s agent key.");
        await updateAgentProfile(this.profilePath, (current) => {
          const prior = current.connections[c2.pair_id];
          if (prior && prior.binding.digest !== ready.binding.digest) fail2("agent_grant_conflict", "The connection ID already belongs to another signed grant.");
          current.connections[c2.pair_id] = ready;
          delete current.requests[id5].pendingToken;
          delete current.requests[id5].pendingPairId;
        });
        return { ...this.connectionSummary(c2.pair_id, ready), next_step: "Call coordination.inspect_negotiation with this connection_id before taking any next action. Claiming does not establish readiness or start background work." };
      }
      connectionSummary(id5, connection) {
        return { connection_id: id5, purpose: connection.purpose || "execution", room_id: connection.roomId, ...connection.sessionId ? { session_id: connection.sessionId, principal_key: connection.principalKey } : {}, agent_key: connection.agentKey, expires_at: connection.binding.payload.expires_at, locally_expired: Date.parse(connection.binding.payload.expires_at) <= Date.now(), same_profile_key: connection.agentKey === this.profile().agentKey, scope: connection.binding.payload.scope };
      }
      connections() {
        const profile = this.profile();
        return { agent_key: profile.agentKey, connections: [...Object.entries(profile.connections).map(([id5, c2]) => this.connectionSummary(id5, c2)), ...Object.entries(profile.repositoryConnections ?? {}).map(([id5, c2]) => repositoryConnectionSummary(id5, c2, profile.agentKey))], scope: "Saved grants only; connection listings do not prove that authority remains active. Inspect the intended connection before acting. Every action is still checked by the service." };
      }
      repositoryClient() {
        return new RepositoryAgentClient(this.profilePath, (action, taskId, body) => this.request(action, taskId, body));
      }
      inspectRepository(taskId, grantId) {
        return this.repositoryClient().inspect(taskId, grantId);
      }
      requestRepositoryRevision(input) {
        return this.repositoryClient().requestRevision(input);
      }
      clientFor(id5) {
        if (!profileId(id5)) fail2("unknown_agent_connection", "Use an exact connection_id from coordination.connections.");
        const c2 = this.profile().connections[id5];
        if (!c2) fail2("unknown_agent_connection", "This profile does not hold that connection.");
        return new CoordinationClient(c2, this.fetchImpl);
      }
      sourceConnection(id5) {
        const profile = this.profile(), source = profile.connections[id5];
        if (!source || source.purpose !== "negotiation" || !source.sessionId || !source.principalKey || source.agentKey !== profile.agentKey) fail2("handoff_profile_key_required", "Seamless execution handoff needs a negotiation connection enrolled with this profile\u2019s own key. Imported legacy connections retain their original scope; their discarded private key cannot be recreated.");
        return source;
      }
      async checkedHandoff(value, source) {
        const p = this.profile();
        if (!exact5(value, ["pair_id", "room_id", "source_room_id", "session_id", "source_pair_id", "agent_key", "name", "status", "expires_at", "token_expires_at", "authorization"], ["binding"])) fail2("invalid_handoff", "The offered execution connection has an unsupported shape.");
        const h = value, q = h.authorization?.payload, b = q?.body;
        if (![h.pair_id, h.room_id].every(profileId) || h.source_room_id !== source.roomId || h.session_id !== source.sessionId || h.source_pair_id !== source.binding.payload.pair_id || h.agent_key !== p.agentKey || typeof h.name !== "string" || !h.name.length || h.name.length > 60 || !["waiting", "connected", "revoked", "expired"].includes(h.status) || ![h.expires_at, h.token_expires_at].every((t) => Number.isFinite(Date.parse(t))) || Date.parse(h.token_expires_at) < Date.parse(h.expires_at) || !envelope2(h.authorization) || !await verify(h.authorization, source.principalKey)) fail2("invalid_handoff", "The execution handoff is not signed by the expected human principal for this exact source connection.");
        if (!exact5(q, ["type", "action", "room_id", "body", "issued_at", "nonce"]) || q.type !== "scopeblind.coordination.request.v1" || q.action !== "agent_handoff_create" || q.room_id !== h.room_id || !profileId(q.nonce) || !exact5(b, ["session_id", "source_pair_id", "pair_id", "agent_key", "agreement_digest", "scope", "name", "expires_at", "token_expires_at"]) || b.session_id !== h.session_id || b.source_pair_id !== h.source_pair_id || b.pair_id !== h.pair_id || b.agent_key !== h.agent_key || !hex4(b.agreement_digest) || canonical(b.scope) !== canonical(PAIRING_SCOPE) || b.name !== h.name || b.expires_at !== h.expires_at || b.token_expires_at !== h.token_expires_at) fail2("invalid_handoff", "The human authorization does not match the exact execution scope and target agreement.");
        return h;
      }
      async checkHandoffs(id5) {
        const source = this.sourceConnection(id5), response = await this.request("agent_handoff_get", source.roomId, { session_id: source.sessionId, source_pair_id: source.binding.payload.pair_id });
        if (!Array.isArray(response.handoffs) || response.handoffs.length > 50) fail2("invalid_handoff", "The handoff response is invalid.");
        const handoffs = await Promise.all(response.handoffs.map((v) => this.checkedHandoff(v, source)));
        return { source_connection_id: id5, handoffs: handoffs.map((h) => ({ handoff_id: h.pair_id, room_id: h.room_id, name: h.name, status: h.status, expires_at: h.expires_at, token_expires_at: h.token_expires_at, agreement_digest: h.authorization.payload.body.agreement_digest })), next_step: "Only an active, separately human-authorized handoff can be claimed. Claiming never spends money or transfers human approval powers." };
      }
      async claimExecutionConnection(id5, handoffId) {
        if (!profileId(handoffId)) fail2("invalid_handoff", "Use the exact handoff_id returned by coordination.check_handoffs.");
        const source = this.sourceConnection(id5), response = await this.request("agent_handoff_get", source.roomId, { session_id: source.sessionId, source_pair_id: source.binding.payload.pair_id });
        if (!Array.isArray(response.handoffs)) fail2("invalid_handoff", "The handoff response is invalid.");
        const offered = response.handoffs.find((v) => v?.pair_id === handoffId);
        if (!offered) fail2("handoff_not_found", "No execution grant with that ID belongs to this source connection.");
        const handoff = await this.checkedHandoff(offered, source);
        if (["revoked", "expired"].includes(handoff.status) || Date.parse(handoff.token_expires_at) <= Date.now()) fail2("handoff_inactive", "This execution grant is expired or revoked. The person must decide whether to grant new access.");
        const prior = this.profile().connections[handoffId];
        if (prior) return this.connectionSummary(handoffId, prior);
        if (handoff.status === "waiting" && Date.parse(handoff.expires_at) <= Date.now()) fail2("handoff_inactive", "This unclaimed execution grant expired.");
        await updateAgentProfile(this.profilePath, (profile2) => {
          const pending = profile2.pendingHandoffs[handoffId];
          if (pending && pending.handoff.authorization.digest !== handoff.authorization.digest) fail2("handoff_conflict", "The saved handoff ID names a different authorization.");
          profile2.pendingHandoffs[handoffId] ??= { handoff, token: (0, import_node_crypto12.randomBytes)(32).toString("hex") };
        });
        const profile = this.profile(), token = profile.pendingHandoffs[handoffId].token, claimed = await this.request("agent_handoff_claim", handoff.room_id, { pair_id: handoffId, executor_token: token, name: handoff.name });
        const binding = claimed.binding, b = binding?.payload;
        if (claimed.executor_token !== token || !envelope2(binding) || !b || !await verify(binding, profile.authorityKey) || !exact5(b, ["type", "pair_id", "room_id", "agreement_digest", "owner_key", "agent_key", "name", "scope", "audience", "issued_at", "expires_at", "owner_authorization"]) || b.type !== "scopeblind.coordination.agent-binding.v1" || b.pair_id !== handoffId || b.room_id !== handoff.room_id || b.agreement_digest !== handoff.authorization.payload.body.agreement_digest || b.owner_key !== source.principalKey || b.agent_key !== profile.agentKey || b.name !== handoff.name || b.audience !== "scopeblind.coordination.sample-ledger" || canonical(b.scope) !== canonical(PAIRING_SCOPE) || b.expires_at !== handoff.token_expires_at || !Number.isFinite(Date.parse(b.issued_at)) || Date.parse(b.issued_at) >= Date.parse(b.expires_at) || Date.parse(b.issued_at) > Date.now() + 3e5 || canonical(b.owner_authorization) !== canonical(handoff.authorization)) fail2("invalid_handoff_binding", "The claimed execution grant did not verify against the pinned authority and exact human authorization. Retry the same ID; no connection is presented as verified.");
        const config = { type: "scopeblind.coordination.config.v1", setupVersion: 2, endpoint: profile.endpoint, authorityKey: profile.authorityKey, roomId: handoff.room_id, agentKey: profile.agentKey, token, name: handoff.name, purpose: "execution", binding };
        await updateAgentProfile(this.profilePath, (current) => {
          current.connections[handoffId] = config;
          delete current.pendingHandoffs[handoffId];
        });
        return { ...this.connectionSummary(handoffId, config), next_step: "Call coordination.inspect with this NEW connection_id to verify the adopted agreement and current work before acting. The negotiation connection remains separately scoped; no action was executed." };
      }
    };
  }
});

// src/coordination-server.ts
var coordination_server_exports = {};
__export(coordination_server_exports, {
  COORDINATION_TOOLS: () => COORDINATION_TOOLS,
  NEGOTIATION_TOOLS: () => NEGOTIATION_TOOLS,
  REHEARSAL_TOOLS: () => REHEARSAL_TOOLS,
  handleCoordinationRequest: () => handleCoordinationRequest,
  runCoordinationServer: () => runCoordinationServer
});
async function handleCoordinationRequest(client, request, signal) {
  if (!request || request.jsonrpc !== "2.0" || typeof request.method !== "string") return { jsonrpc: "2.0", id: request?.id ?? null, error: { code: -32600, message: "Invalid JSON-RPC request." } };
  if (request.id === void 0) return void 0;
  if (request.method === "initialize") return { jsonrpc: "2.0", id: request.id, result: { protocolVersion: "2024-11-05", serverInfo: { name: "protect-mcp-coordination", version: process.env.PROTECT_MCP_VERSION || "0.22.0" }, capabilities: { tools: {} } } };
  if (request.method === "ping") return { jsonrpc: "2.0", id: request.id, result: {} };
  if (request.method === "tools/list") return { jsonrpc: "2.0", id: request.id, result: { tools: toolsForPurpose(client.purpose) } };
  if (request.method !== "tools/call") return { jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found." } };
  try {
    const args = request.params?.arguments ?? {};
    if (!args || typeof args !== "object" || Array.isArray(args)) throw new CoordinationError("invalid_input", "Tool arguments must be an object.");
    const available = toolsForPurpose(client.purpose);
    if (!available.some((tool) => tool.name === request.params?.name)) throw new CoordinationError("tool_outside_grant", "This connection does not expose that capability. Use the separately authorized connection for its intended purpose.");
    const fields = args;
    if (request.params?.name === "coordination.inspect_negotiation") {
      if (Object.keys(fields).some((key) => key !== "report_digest")) throw new CoordinationError("invalid_input", "Inspect takes only an optional report_digest; session and principal come from the pairing.");
      return textResult2(request.id, await client.inspectNegotiation(fields.report_digest, signal));
    }
    if (request.params?.name === "coordination.propose_candidate") {
      if (Object.keys(fields).join(",") !== "proposal") throw new CoordinationError("invalid_input", "Propose requires only proposal.");
      return textResult2(request.id, await client.proposeCandidate(fields.proposal));
    }
    if (request.params?.name === "coordination.respond_candidate") return textResult2(request.id, await client.respondCandidate(fields));
    if (request.params?.name === "coordination.compare_candidate") return textResult2(request.id, await client.compareCandidate(fields, signal));
    if (request.params?.name === "coordination.wait_negotiation") return textResult2(request.id, await client.waitNegotiation(fields, signal));
    if (request.params?.name === "coordination.inspect_rehearsal") {
      if (Object.keys(fields).some((key) => key !== "report_digest")) throw new CoordinationError("invalid_input", "Inspect takes only an optional report_digest.");
      return textResult2(request.id, await client.inspectRehearsal(fields.report_digest));
    }
    if (request.params?.name === "coordination.propose_case") {
      if (Object.keys(fields).join(",") !== "case") throw new CoordinationError("invalid_input", "Propose case requires only case.");
      return textResult2(request.id, await client.proposeCase(fields.case));
    }
    if (request.params?.name === "coordination.propose_repair") {
      if (Object.keys(fields).join(",") !== "proposal") throw new CoordinationError("invalid_input", "Propose repair requires only proposal.");
      return textResult2(request.id, await client.proposeRepair(fields.proposal));
    }
    if (request.params?.name === "coordination.run_rehearsal") return textResult2(request.id, await client.runRehearsal(fields, signal));
    if (request.params?.name === "coordination.wait") return textResult2(request.id, await client.wait(args, signal));
    if (request.params?.name === "coordination.deliver") {
      if (Object.keys(args).join(",") !== "run_id") throw new CoordinationError("invalid_input", "coordination.deliver requires only the exact run_id from coordination.inspect.");
      return textResult2(request.id, await client.deliver(args.run_id));
    }
    if (request.params?.name === "coordination.inspect") {
      if (Object.keys(args).length) throw new CoordinationError("invalid_input", "coordination.inspect takes no arguments.");
      return textResult2(request.id, await client.inspect());
    }
    if (request.params?.name !== "ledger.pay") throw new CoordinationError("unknown_tool", "Unknown coordination tool.");
    const values = args;
    const allowed = /* @__PURE__ */ new Set(["operation_id", "invoice_id", "amount_minor", "currency", "destination", "fixture_revision"]);
    if (Object.keys(values).some((key) => !allowed.has(key))) throw new CoordinationError("invalid_input", "Payment contains unsupported fields.");
    const payment = {
      operation_id: values.operation_id,
      input: { invoice_id: values.invoice_id, amount_minor: values.amount_minor, currency: values.currency, destination: values.destination, ...values.fixture_revision !== void 0 ? { fixture_revision: values.fixture_revision } : {} }
    };
    return textResult2(request.id, await client.pay(payment));
  } catch (error) {
    return textResult2(request.id, {
      code: error instanceof CoordinationError ? error.code : "coordination_error",
      error: error instanceof CoordinationError ? error.message : "Coordination request could not be completed."
    }, true);
  }
}
async function runCoordinationServer(args) {
  const config = args.length === 2 && args[0] === "--config" ? coordinationConfigFromFile(args[1]) : coordinationConfigFromArgs(args);
  const client = new CoordinationClient(config);
  const lines = (0, import_node_readline4.createInterface)({ input: process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();
  const waits = /* @__PURE__ */ new Map();
  const cancelWaits = () => {
    for (const controller of waits.values()) controller.abort();
  };
  lines.on("close", cancelWaits);
  process.stdout.on("error", cancelWaits);
  lines.on("line", (line) => {
    if (!line.trim()) return;
    let request;
    try {
      if (line.length > 1e6) throw new Error("Frame too large");
      request = JSON.parse(line);
    } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Invalid or oversized JSON-RPC message." } }) + "\n");
      return;
    }
    if (request?.jsonrpc === "2.0" && request.method === "notifications/cancelled") {
      const id5 = request.params?.requestId;
      if (typeof id5 === "string" || typeof id5 === "number") waits.get(id5)?.abort();
      return;
    }
    const controller = request?.method === "tools/call" && ["coordination.wait", "coordination.run_rehearsal", "coordination.wait_negotiation", "coordination.compare_candidate"].includes(String(request.params?.name)) ? new AbortController() : void 0;
    if (controller) waits.set(request.id, controller);
    chain = chain.then(async () => {
      let response;
      try {
        response = await handleCoordinationRequest(client, request, controller?.signal);
      } catch {
        response = { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Invalid or oversized JSON-RPC message." } };
      } finally {
        if (controller && waits.get(request.id) === controller) waits.delete(request.id);
      }
      if (response !== void 0) process.stdout.write(JSON.stringify(response) + "\n");
    });
  });
  process.stderr.write(client.purpose === "negotiation" ? "[PROTECT_MCP] Negotiation MCP ready: inspect_negotiation, propose_candidate, respond_candidate, compare_candidate, and wait_negotiation. One principal only; no payment, human approval, adoption, or hosted-model authority.\n" : client.purpose === "rehearsal" ? "[PROTECT_MCP] Test MCP ready: inspect_rehearsal, propose_case, propose_repair, and run_rehearsal. Separate sample ledgers; no execution or adoption authority.\n" : "[PROTECT_MCP] Coordination MCP ready: ledger.pay, coordination.inspect, coordination.deliver, and coordination.wait. Sample ledger only; no real money moves.\n");
  await new Promise((resolve5) => lines.on("close", resolve5));
  await chain;
  process.stdout.removeListener("error", cancelWaits);
}
var import_node_readline4, COORDINATION_TOOLS, REHEARSAL_TOOLS, NEGOTIATION_TOOLS, toolsForPurpose, textResult2;
var init_coordination_server = __esm({
  "src/coordination-server.ts"() {
    "use strict";
    import_node_readline4 = require("readline");
    init_coordination_client();
    init_coordination_pair_cli();
    init_coordination_config();
    COORDINATION_TOOLS = [
      {
        name: "coordination.deliver",
        description: "Freeze the completed invoice result for the recipient to accept or request changes. The service refuses delivery while operations remain held, admitted, or unknown, or invoices have no recorded disposition. Does not accept the result on behalf of a person, change terms, or grant a revision. Returns the verified service-signed manifest.",
        inputSchema: { type: "object", properties: { run_id: { type: "string", pattern: "^run-[A-Za-z0-9_-]{8,100}$", description: "Exact run_id from the inspected task. Prevents delivery of a different revision." } }, required: ["run_id"], additionalProperties: false },
        annotations: { title: "Deliver the result for review", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "ledger.pay",
        description: "Pay a sample invoice through the shared room authority. The installed adapter obtains and verifies an exact signed admission BEFORE the sample ledger can execute. No real money moves. Reuse operation_id for retries of the same intended payment; a changed payload with the same ID is refused. Held requests need the room reviewer; call again with unchanged terms after approval. An unknown outcome must be reconciled with the same ID, never replaced by a new payment. Returns signed admission and destination evidence when available.",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            operation_id: { type: "string", minLength: 8, maxLength: 100, pattern: "^[A-Za-z0-9_-]{8,100}$", description: "Stable identity for this intended payment, retained across retries and restarts." },
            invoice_id: { type: "string", minLength: 1, maxLength: 60 },
            amount_minor: { type: "integer", minimum: 1, maximum: 1e7, description: "USD cents; 32000 means $320.00." },
            currency: { type: "string", enum: ["USD"] },
            fixture_revision: { type: "integer", minimum: 1, description: "Current records revision from coordination.inspect. Required for live rooms; binds this exact record version." },
            destination: { type: "string", minLength: 1, maxLength: 100, description: "Sample destination from coordination.inspect, for example sandbox:northstar." }
          },
          required: ["operation_id", "invoice_id", "amount_minor", "currency", "destination"]
        },
        annotations: { title: "Pay a sample invoice under the agreed rules", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.inspect",
        description: "Read this shared invoice room, its owner-signed agreement, sample invoices, budget, and pending outcomes. The configured registrar key is pinned; the adapter verifies the agreement signature. Live budget/operation listings are the service report, not proof of complete runtime coverage. Use ledger.pay to independently verify the exact admission and destination outcome. Does not approve, execute, change rules, or move money.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
        annotations: { title: "Inspect the shared invoice room", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.wait",
        description: "Await a colleague decision or other room event for up to 30 seconds. Pass the cursor from coordination.inspect or the last wait. The installed tool polls every two seconds without calling the model between checks. Returns changed or waiting, current cursor/run, recent events, and operations needing attention. On changed, inspect and retry approved requests with unchanged operation IDs. On timeout, the active agent session can call wait again; resumption depends on the MCP client. This does not push notifications, approve, execute, or grant authority.",
        inputSchema: { type: "object", properties: {
          after_cursor: { type: "integer", minimum: 0, description: "Event cursor returned by coordination.inspect or the preceding wait." },
          run_id: { type: "string", pattern: "^run-[A-Za-z0-9_-]{8,100}$", description: "Optional inspected run; a changed attempt returns immediately." },
          timeout_ms: { type: "integer", minimum: 1e3, maximum: 3e4, default: 3e4 }
        }, required: ["after_cursor"], additionalProperties: false },
        annotations: { title: "Wait for the next room decision", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      }
    ];
    REHEARSAL_TOOLS = [
      {
        name: "coordination.inspect_rehearsal",
        description: "Inspect the owner-signed agreement, sample records, proposed expectations, repairs, and signed test reports. Optional report_digest retrieves exact historical evidence. The adapter pins the authority and verifies source signatures; the gate operator attests to observations. This test grant cannot execute source payments, approve exceptions, or activate a repair.",
        inputSchema: { type: "object", properties: { report_digest: { type: "string", pattern: "^[0-9a-f]{64}$", description: "Optional exact report digest to retrieve its immutable evidence snapshot." } }, additionalProperties: false },
        annotations: { title: "Inspect rules and test evidence", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.propose_case",
        description: "Add an explicit human expectation or safety challenge against sample invoices. Stable case IDs make identical retries safe; changed content needs a new ID. Cases only influence isolated tests and do not pause work or change the active agreement. Required shipped safety cases cannot be replaced. Invoice expectations are allow, ask, or refuse; adversarial case kinds use invariant.",
        inputSchema: { type: "object", properties: { case: { type: "object", properties: {
          id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" },
          title: { type: "string", minLength: 1, maxLength: 120 },
          kind: { type: "string", enum: ["invoice", "approved_invoice", "duplicate_invoice", "changed_approval", "changed_destination", "expired_approval", "budget_cap"] },
          invoice_id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,60}$" },
          amount_minor: { type: "integer", minimum: 1, maximum: 1e7, description: "Optional explicit invoice AND matching purchase-order override inside this case\u2019s isolated ledger only." },
          expected: { type: "string", enum: ["allow", "ask", "refuse", "invariant"] },
          requirement: { type: "string", minLength: 1, maxLength: 400 }
        }, required: ["id", "title", "kind", "invoice_id", "expected", "requirement"], additionalProperties: false } }, required: ["case"], additionalProperties: false },
        annotations: { title: "Propose a test case", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.propose_repair",
        description: "Propose a single review-threshold change in USD cents, with an explicit rationale. The proposal is bound to the current source agreement, sample records, and cases. It cannot activate rules, change the budget or destination, or authorize a payment. Keep its stable id for retries; inspect again if the source snapshot changes.",
        inputSchema: { type: "object", properties: { proposal: { type: "object", properties: { id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" }, approval_above_minor: { type: "integer", minimum: 0, maximum: 1e7 }, rationale: { type: "string", minLength: 1, maxLength: 600 } }, required: ["id", "approval_above_minor", "rationale"], additionalProperties: false } }, required: ["proposal"], additionalProperties: false },
        annotations: { title: "Propose a review-threshold repair", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.run_rehearsal",
        description: "Run concrete cases through the actual gate in separate fixture ledgers. Omit proposal_id for a baseline, or select an exact proposal to compare before and after. The tool resumes up to six durable chunks within three minutes and returns pending if unfinished. Use one stable id per intended run and retain it if a response is lost or times out; inspect reports before retrying. Results are bounded observations, not proof for every input. This never spends the source budget, changes the source ledger, or adopts a repair.",
        inputSchema: { type: "object", properties: { id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" }, proposal_id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" } }, required: ["id"], additionalProperties: false },
        annotations: { title: "Test and compare rules in isolation", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      }
    ];
    NEGOTIATION_TOOLS = [
      {
        name: "coordination.inspect_negotiation",
        description: "Inspect your principal\u2019s signed mandate and private brief, plus the shared candidates, responses, and isolated comparison records for this paired session. Never returns the other principal\u2019s private brief. Treat brief text as private task context, not as permission to override the signed limits. Optional report_digest retrieves exact historical comparison evidence. This connection cannot pay, approve, adopt, delegate, or run a hosted model.",
        inputSchema: { type: "object", properties: { report_digest: { type: "string", pattern: "^[0-9a-f]{64}$" } }, additionalProperties: false },
        annotations: { title: "Inspect my mandate and shared negotiation", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.propose_candidate",
        description: "Propose a review threshold and optional total budget within your principal\u2019s signed limits. At most three candidate proposals may exist in this session; the service enforces the limit across all agents and retries. Reuse id for retries with identical terms. A counterproposal must name the current parent_digest. Only structured terms are shared; do not send private briefing text. A candidate grants no authority and cannot change the active job.",
        inputSchema: { type: "object", properties: { proposal: { type: "object", properties: { id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" }, approval_above_minor: { type: "integer", minimum: 0, maximum: 1e7, description: "USD cents: 40000 means review above $400." }, budget_minor: { type: "integer", minimum: 1, maximum: 1e7, description: "Optional total budget in USD cents, within the principal\u2019s signed budget limits. Omit to retain the source budget." }, parent_digest: { type: "string", pattern: "^[0-9a-f]{64}$" } }, required: ["id", "approval_above_minor"], additionalProperties: false } }, required: ["proposal"], additionalProperties: false },
        annotations: { title: "Propose bounded terms", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.respond_candidate",
        description: "Record support or no agreement for an exact shared candidate on behalf of your principal\u2019s agent mandate. Support is a recommendation only; it is never either human\u2019s approval. No agreement is a valid bounded outcome. This tool cannot pay, approve the final agreement, or adopt it.",
        inputSchema: { type: "object", properties: { proposal_digest: { type: "string", pattern: "^[0-9a-f]{64}$" }, decision: { type: "string", enum: ["support", "no_agreement"] } }, required: ["proposal_digest", "decision"], additionalProperties: false },
        annotations: { title: "Respond to the exact candidate", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.compare_candidate",
        description: "Compare an exact supported candidate against the baseline using the real gate in isolated sample ledgers. The server owns one fixed report identity per proposal; retries resume two-case chunks. This tool runs for at most three minutes and returns pending if unfinished. Resume with the SAME proposal_digest after timeout or cancellation. A verified report records observed cases; it does not approve or adopt terms, spend the source budget, or prove every possible input.",
        inputSchema: { type: "object", properties: { proposal_digest: { type: "string", pattern: "^[0-9a-f]{64}$" } }, required: ["proposal_digest"], additionalProperties: false },
        annotations: { title: "Compare the candidate in isolation", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      {
        name: "coordination.wait_negotiation",
        description: "Wait for this principal\u2019s next negotiation action or a completed, blocked, or human-decision state. Polls only the principal-scoped negotiation endpoint every two seconds for at most thirty seconds, without model calls. Pass state_digest from inspection as after_digest to also return on any state change. This is bounded polling, not a background notification or permission to keep proposing beyond three candidates.",
        inputSchema: { type: "object", properties: { after_digest: { type: "string", pattern: "^[0-9a-f]{64}$" }, timeout_ms: { type: "integer", minimum: 1e3, maximum: 3e4, default: 3e4 } }, additionalProperties: false },
        annotations: { title: "Wait for negotiation status", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      }
    ];
    toolsForPurpose = (purpose) => purpose === "negotiation" ? NEGOTIATION_TOOLS : purpose === "rehearsal" ? REHEARSAL_TOOLS : COORDINATION_TOOLS;
    textResult2 = (id5, value, isError = false) => ({ jsonrpc: "2.0", id: id5, result: { content: [{ type: "text", text: JSON.stringify(value) }], ...isError ? { isError: true } : {} } });
  }
});

// src/coordination-agent-server.ts
var coordination_agent_server_exports = {};
__export(coordination_agent_server_exports, {
  AGENT_PROFILE_TOOLS: () => AGENT_PROFILE_TOOLS,
  handleAgentProfileRequest: () => handleAgentProfileRequest,
  runCoordinationAgent: () => runCoordinationAgent
});
async function handleAgentProfileRequest(client, request, signal) {
  if (!request || request.jsonrpc !== "2.0" || typeof request.method !== "string") return { jsonrpc: "2.0", id: request?.id ?? null, error: { code: -32600, message: "Invalid JSON-RPC request." } };
  if (request.id === void 0) return void 0;
  if (request.method === "initialize") return { jsonrpc: "2.0", id: request.id, result: { protocolVersion: "2024-11-05", serverInfo: { name: "protect-mcp-agent", version: process.env.PROTECT_MCP_VERSION || "0.22.0" }, capabilities: { tools: {} } } };
  if (request.method === "ping") return { jsonrpc: "2.0", id: request.id, result: {} };
  if (request.method === "tools/list") return { jsonrpc: "2.0", id: request.id, result: { tools: [...AGENT_PROFILE_TOOLS, ...scopedTools] } };
  if (request.method !== "tools/call") return { jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found." } };
  try {
    const args = request.params?.arguments ?? {};
    if (!args || typeof args !== "object" || Array.isArray(args)) throw new CoordinationError("invalid_input", "Tool arguments must be an object.");
    const fields = args, name = request.params?.name;
    const only = (...keys2) => {
      if (Object.keys(fields).sort().join(",") !== keys2.sort().join(",")) throw new CoordinationError("invalid_input", "Use only the exact fields required by this tool.");
    };
    if (name === "coordination.prepare_task") {
      only("request_id", "draft");
      return result(request, await client.prepareTask(fields));
    }
    if (name === "coordination.inspect_task_request") {
      only("request_id");
      return result(request, await client.inspectTaskRequest(fields.request_id));
    }
    if (name === "coordination.claim_task_connection") {
      only("request_id");
      return result(request, await client.claimTaskConnection(fields.request_id));
    }
    if (name === "coordination.connections") {
      only();
      return result(request, client.connections());
    }
    if (name === "coordination.check_handoffs") {
      only("connection_id");
      return result(request, await client.checkHandoffs(fields.connection_id));
    }
    if (name === "coordination.claim_execution_connection") {
      only("connection_id", "handoff_id");
      return result(request, await client.claimExecutionConnection(fields.connection_id, fields.handoff_id));
    }
    if (name === "coordination.inspect_repository") {
      only("task_id", "grant_id");
      return result(request, await client.inspectRepository(fields.task_id, fields.grant_id));
    }
    if (name === "coordination.request_repository_revision") {
      only("connection_id", "request_id", "basis_digest", "message", "proposed");
      return result(request, await client.requestRepositoryRevision(fields));
    }
    if (!scopedTools.some((tool) => tool.name === name)) throw new CoordinationError("unknown_tool", "This profile does not expose that tool.");
    const { connection_id, ...scoped } = fields;
    return await handleCoordinationRequest(client.clientFor(connection_id), { ...request, params: { name, arguments: scoped } }, signal);
  } catch (error) {
    return result(request, { code: error instanceof CoordinationError ? error.code : "agent_request_error", error: error instanceof Error ? error.message : "The agent request could not be completed." }, true);
  }
}
function options(args, mode) {
  const allowed = /* @__PURE__ */ new Set(["--profile", "--endpoint", "--authority-key", ...mode === "setup" ? ["--client"] : [], ...mode === "import" ? ["--config"] : []]), values = /* @__PURE__ */ new Map();
  for (let index = 0; index < args.length; index += 2) {
    const flag2 = args[index], value = args[index + 1];
    if (!allowed.has(flag2) || values.has(flag2) || !value || value.startsWith("--")) throw new Error("Use --profile, optional --endpoint/--authority-key for first setup, and the documented setup/import options.");
    values.set(flag2, value);
  }
  return values;
}
async function runCoordinationAgent(args) {
  const mode = args[0] === "setup" ? "setup" : args[0] === "import" ? "import" : "server";
  const values = options(mode === "server" ? args : args.slice(1), mode), path = (0, import_node_path12.resolve)(values.get("--profile") || DEFAULT_AGENT_PROFILE);
  const selected = mode === "setup" ? agentClient(values.get("--client") || "claude-code") : void 0;
  const profile = await ensureAgentProfile(path, values.get("--endpoint"), values.get("--authority-key"));
  if (mode === "setup") {
    process.stdout.write(agentProfileRegistration(selected, `scopeblind-agent-${profile.agentKey.slice(0, 12)}`, path) + "\n");
    process.stdout.write("Register this server once, then ask your agent to prepare a shared task with coordination.prepare_task. The profile is an agent identity only; each person reviews and signs their own authority. Existing connections stay separately scoped.\n");
    return;
  }
  if (mode === "import") {
    if (!values.get("--config")) throw new Error("Import needs the existing --config file.");
    const id5 = await importProfileConnection(path, values.get("--config"));
    process.stdout.write(`Saved existing scoped connection ${id5}. Its authority is unchanged. Imported legacy keys cannot be recreated for automatic execution handoff.
`);
    return;
  }
  const client = new CoordinationAgentClient(path), lines = (0, import_node_readline5.createInterface)({ input: process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();
  const waits = /* @__PURE__ */ new Map(), cancel = () => {
    for (const controller of waits.values()) controller.abort();
  };
  lines.on("close", cancel);
  process.stdout.on("error", cancel);
  lines.on("line", (line) => {
    if (!line.trim()) return;
    let request;
    try {
      if (line.length > 1e6) throw new Error();
      request = JSON.parse(line);
    } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Invalid or oversized JSON-RPC message." } }) + "\n");
      return;
    }
    if (request?.jsonrpc === "2.0" && request.method === "notifications/cancelled") {
      const id5 = request.params?.requestId;
      if (typeof id5 === "string" || typeof id5 === "number") waits.get(id5)?.abort();
      return;
    }
    const controller = request?.method === "tools/call" && ["coordination.wait", "coordination.run_rehearsal", "coordination.wait_negotiation", "coordination.compare_candidate"].includes(String(request.params?.name)) ? new AbortController() : void 0;
    if (controller) waits.set(request.id, controller);
    chain = chain.then(async () => {
      try {
        const response = await handleAgentProfileRequest(client, request, controller?.signal);
        if (response !== void 0) process.stdout.write(JSON.stringify(response) + "\n");
      } finally {
        if (controller && waits.get(request.id) === controller) waits.delete(request.id);
      }
    });
  });
  process.stderr.write("[PROTECT_MCP] Agent profile ready. Drafts confer no authority. Every scoped tool needs a separately authorized connection_id. No background model work is started.\n");
  await new Promise((resolve5) => lines.on("close", resolve5));
  await chain;
  process.stdout.removeListener("error", cancel);
}
var import_node_readline5, import_node_path12, id4, amount2, contactPageSchema, draftSchema, AGENT_PROFILE_TOOLS, scopedTools, result;
var init_coordination_agent_server = __esm({
  "src/coordination-agent-server.ts"() {
    "use strict";
    import_node_readline5 = require("readline");
    import_node_path12 = require("path");
    init_coordination_agent_client();
    init_coordination_client();
    init_coordination_server();
    init_coordination_agent_profile();
    init_coordination_agent_setup();
    id4 = { type: "string", pattern: "^[A-Za-z0-9_-]{8,100}$" };
    amount2 = { type: "integer", minimum: 0, maximum: 1e7 };
    contactPageSchema = { type: "object", additionalProperties: false, properties: { type: { type: "string", const: "scopeblind.contact-page.v1" }, button_label: { type: "string", minLength: 1, maxLength: 40 }, target: { type: "string", enum: ["broken", "contact"] }, accent: { type: "string", enum: ["indigo", "emerald", "rose"] } }, required: ["type", "button_label", "target", "accent"] };
    draftSchema = { type: "object", additionalProperties: false, properties: {
      title: { type: "string", minLength: 1, maxLength: 100 },
      goal: { type: "string", minLength: 1, maxLength: 2e3 },
      counterparty_name: { type: "string", maxLength: 60 },
      budget_minor: { ...amount2, minimum: 1 },
      approval_above_minor: amount2,
      approval_ttl_seconds: { type: "integer", minimum: 30, maximum: 900 },
      require_po_match: { type: "boolean", const: true },
      min_budget_minor: { ...amount2, minimum: 1 },
      max_budget_minor: { ...amount2, minimum: 1 },
      min_threshold_minor: amount2,
      max_threshold_minor: amount2,
      private_brief: { type: "string", maxLength: 2e3 },
      preference: { type: "string", enum: ["fewer_reviews", "more_review", "balanced"] },
      budget_preference: { type: "string", enum: ["preserve_budget", "lower_budget", "more_capacity"] },
      assumptions: { type: "array", maxItems: 12, items: { type: "string", minLength: 1, maxLength: 300 } }
    }, required: ["title", "goal"] };
    AGENT_PROFILE_TOOLS = [
      { name: "coordination.prepare_task", description: "Prepare an unsigned shared invoice-task draft for your own person to review. Use a stable request_id for retries. Proposed limits, preferences, and assumptions grant no authority. Returns a private review link intended only for the requesting person; they review and sign in the browser, invite the other person, and explicitly authorize a scoped agent. Do not put unsupported hard rules into a preference. No room, human signature, payment, or hosted model is created by this tool.", inputSchema: { type: "object", additionalProperties: false, properties: { request_id: id4, draft: draftSchema }, required: ["request_id", "draft"] }, annotations: { title: "Prepare a shared task for human review", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
      { name: "coordination.inspect_task_request", description: "Check a draft prepared by this profile. An accepted draft is still not an agent grant. Ready means the person separately signed the named negotiation grant; use claim_task_connection and inspect the mandate before acting. Does not poll in the background or reveal the draft to another principal.", inputSchema: { type: "object", additionalProperties: false, properties: { request_id: id4 }, required: ["request_id"] }, annotations: { title: "Check the person\u2019s review and agent grant", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
      { name: "coordination.claim_task_connection", description: "Claim the exact negotiation connection explicitly authorized for this profile\u2019s key after human review. Saves its separate token locally and returns a connection_id. Does not sign a mandate, establish readiness, execute, approve, or grant ownership. Inspect the returned connection before taking its next permitted action.", inputSchema: { type: "object", additionalProperties: false, properties: { request_id: id4 }, required: ["request_id"] }, annotations: { title: "Connect to the human-authorized task", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
      { name: "coordination.connections", description: "List saved purpose-scoped connections without credentials. A saved grant may have expired or been revoked: inspect before acting. Every scoped tool requires its explicit connection_id so another task or purpose cannot be selected implicitly.", inputSchema: { type: "object", additionalProperties: false, properties: {} }, annotations: { title: "List this agent\u2019s separate connections", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
      { name: "coordination.check_handoffs", description: "Check whether the organizer separately authorized this same agent to execute the exact jointly adopted task. Requires the original negotiation connection_id. Uses the profile key, never broadens the old negotiation token, and performs no payment. Legacy imported connections without the original private agent key cannot claim this continuity.", inputSchema: { type: "object", additionalProperties: false, properties: { connection_id: id4 }, required: ["connection_id"] }, annotations: { title: "Check for a separately authorized execution handoff", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
      { name: "coordination.claim_execution_connection", description: "Claim one exact owner-signed execution handoff discovered by check_handoffs. Returns a NEW execution connection_id while preserving the negotiation grant separately. The local token is persisted before claiming so a lost reply can be retried with the same handoff_id. Does not execute or approve anything; inspect the new room before acting.", inputSchema: { type: "object", additionalProperties: false, properties: { connection_id: id4, handoff_id: id4 }, required: ["connection_id", "handoff_id"] }, annotations: { title: "Claim the approved execution handoff", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
      { name: "coordination.inspect_repository", description: "Inspect a repository task using the exact human-signed grant for this profile\u2019s public agent key. Get that public key from coordination.connections and give it to your person; they must explicitly authorize read_task and optionally request_revision in the repository task. Verifies pinned service, task, receiver, human grant and collaboration signatures, then saves a separate repository connection_id. Returns the exact current_basis_digest and bounded preview, never a human claim, approval, acceptance or receiver execution capability.", inputSchema: { type: "object", additionalProperties: false, properties: { task_id: id4, grant_id: id4 }, required: ["task_id", "grant_id"] }, annotations: { title: "Inspect the authorized repository task", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
      { name: "coordination.request_repository_revision", description: "Suggest a bounded contact-page revision under an existing repository connection with request_revision permission. Use a stable request_id and the exact current_basis_digest from inspect_repository. Persists the signed request before transport and reuses it after a lost reply; a changed basis requires fresh inspection and a new deliberate suggestion. Only the fixed contact-page data model is supported, not arbitrary code or permissions. Records a suggestion for humans; never creates or approves a task, updates a branch, or accepts a result.", inputSchema: { type: "object", additionalProperties: false, properties: { connection_id: id4, request_id: id4, basis_digest: { type: "string", pattern: "^[a-f0-9]{64}$" }, message: { type: "string", minLength: 1, maxLength: 600 }, proposed: contactPageSchema }, required: ["connection_id", "request_id", "basis_digest", "message", "proposed"] }, annotations: { title: "Request a repository revision for human review", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } }
    ];
    scopedTools = [...COORDINATION_TOOLS, ...REHEARSAL_TOOLS, ...NEGOTIATION_TOOLS].map((tool) => ({ ...tool, description: tool.description + " Select the exact saved connection_id for this purpose; permissions are never combined across connections.", inputSchema: { ...tool.inputSchema, properties: { ...tool.inputSchema.properties, connection_id: id4 }, required: [..."required" in tool.inputSchema ? tool.inputSchema.required ?? [] : [], "connection_id"] } }));
    result = (request, value, error = false) => ({ jsonrpc: "2.0", id: request.id, result: { content: [{ type: "text", text: JSON.stringify(value) }], ...error ? { isError: true } : {} } });
  }
});

// src/scopeblind-bridge.ts
function parseConfiguredPseudonymKey(value) {
  const key = Buffer.from(value, "base64url");
  if (key.length !== 32) throw new Error("SCOPEBLIND_EGRESS_HMAC_KEY must be a base64url-encoded 32-byte key");
  return key;
}
function loadOrCreatePseudonymKey(env, base, slug) {
  const dir = env.SCOPEBLIND_EGRESS_KEY_DIR || (0, import_node_path13.join)((0, import_node_os3.homedir)(), ".protect-mcp", "egress-keys");
  const scopeDigest = (0, import_node_crypto13.createHash)("sha256").update(`${base}\0${slug}`).digest("hex");
  const path = (0, import_node_path13.join)(dir, `${scopeDigest}.key`);
  (0, import_node_fs16.mkdirSync)(dir, { recursive: true, mode: 448 });
  (0, import_node_fs16.chmodSync)(dir, 448);
  try {
    const existing = (0, import_node_fs16.readFileSync)(path);
    if (existing.length !== 32) throw new Error(`local egress key has invalid length: ${path}`);
    (0, import_node_fs16.chmodSync)(path, 384);
    return existing;
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
  }
  const fresh = (0, import_node_crypto13.randomBytes)(32);
  try {
    (0, import_node_fs16.writeFileSync)(path, fresh, { mode: 384, flag: "wx" });
    return fresh;
  } catch (err) {
    if (err?.code !== "EEXIST") throw err;
    const existing = (0, import_node_fs16.readFileSync)(path);
    if (existing.length !== 32) throw new Error(`local egress key has invalid length: ${path}`);
    (0, import_node_fs16.chmodSync)(path, 384);
    return existing;
  }
}
function getScopeBlindBridge() {
  if (!singleton) singleton = new ScopeBlindBridge();
  return singleton;
}
var import_node_crypto13, import_node_fs16, import_node_os3, import_node_path13, DEFAULT_BASE, FLUSH_INTERVAL_MS, BATCH_MAX, BRASS_REFRESH_MARGIN_MS, ScopeBlindBridge, singleton;
var init_scopeblind_bridge = __esm({
  "src/scopeblind-bridge.ts"() {
    "use strict";
    import_node_crypto13 = require("crypto");
    import_node_fs16 = require("fs");
    import_node_os3 = require("os");
    import_node_path13 = require("path");
    init_egress_guard();
    init_signing();
    DEFAULT_BASE = "https://scopeblind.com";
    FLUSH_INTERVAL_MS = 5e3;
    BATCH_MAX = 128;
    BRASS_REFRESH_MARGIN_MS = 5 * 60 * 1e3;
    ScopeBlindBridge = class {
      env;
      token;
      base;
      tenantOverride;
      configuredPseudonymKey;
      cachedProof = null;
      /** Raw receipts stay only in this process until minimized at flush time. */
      queue = [];
      flushTimer = null;
      stats;
      shuttingDown = false;
      constructor(env = process.env) {
        this.env = env;
        this.token = env.SCOPEBLIND_TOKEN || null;
        this.base = (env.SCOPEBLIND_BASE || DEFAULT_BASE).replace(/\/$/, "");
        this.tenantOverride = env.SCOPEBLIND_TENANT || null;
        this.configuredPseudonymKey = env.SCOPEBLIND_EGRESS_HMAC_KEY ? parseConfiguredPseudonymKey(env.SCOPEBLIND_EGRESS_HMAC_KEY) : null;
        this.stats = {
          enabled: Boolean(this.token),
          tenant_slug: this.tenantOverride,
          forwarded_total: 0,
          rejected_total: 0,
          last_flush_at: null,
          last_error: null
        };
        if (this.enabled()) {
          this.flushTimer = setInterval(() => {
            void this.flush();
          }, FLUSH_INTERVAL_MS);
          if (typeof this.flushTimer === "object" && this.flushTimer && "unref" in this.flushTimer) {
            this.flushTimer.unref?.();
          }
          process.on("beforeExit", () => {
            void this.shutdown();
          });
        }
      }
      enabled() {
        return Boolean(this.token);
      }
      /** Push a receipt into the local-only queue. Non-blocking. */
      forward(signedReceipt) {
        if (!this.enabled() || this.shuttingDown) return;
        this.queue.push(signedReceipt);
        if (this.queue.length >= BATCH_MAX) void this.flush();
      }
      /** Flush the queue. Safe to call concurrently. */
      async flush() {
        if (!this.enabled() || this.queue.length === 0) return;
        const localReceipts = this.queue.splice(0, BATCH_MAX);
        try {
          const proof = await this.ensureBrassProof();
          if (!proof) {
            this.queue.unshift(...localReceipts);
            return;
          }
          const slug = this.tenantOverride || proof?.tenant_id;
          if (!slug) {
            this.queue.unshift(...localReceipts);
            return;
          }
          this.stats.tenant_slug = slug;
          let opts;
          try {
            opts = this.summaryOptions(slug);
          } catch (err) {
            this.stats.last_error = `local egress HMAC key: ${String(err?.message || err)}`;
            this.queue.unshift(...localReceipts);
            return;
          }
          const summaries = [];
          for (const receipt of localReceipts) {
            const summary = toEgressSummary(receipt, opts);
            const guard = summary ? inspectEgress(summary) : { safe: false, violations: [{ path: "$", reason: "not a recognized receipt or local HMAC key" }] };
            if (!summary || !guard.safe) {
              this.stats.blocked_by_egress_guard = (this.stats.blocked_by_egress_guard || 0) + 1;
              continue;
            }
            const signed2 = signGenericArtifact("scopeblind.egress_summary.v1", summary);
            if (!signed2.ok || !signed2.signed) {
              this.stats.blocked_by_egress_guard = (this.stats.blocked_by_egress_guard || 0) + 1;
              process.stderr.write(`[PROTECT_MCP] egress summary dropped: a locally signed summary is required (${signed2.error || signed2.warning || "signer unavailable"})
`);
              continue;
            }
            try {
              const envelope3 = JSON.parse(signed2.signed);
              const signedGuard = inspectEgress(envelope3?.payload, { signed: true });
              if (!signedGuard.safe || envelope3?.signature?.alg !== "EdDSA") {
                throw new Error(signedGuard.violations.slice(0, 2).map((v) => v.path).join(", "));
              }
              summaries.push(envelope3);
            } catch (err) {
              this.stats.blocked_by_egress_guard = (this.stats.blocked_by_egress_guard || 0) + 1;
              process.stderr.write(`[PROTECT_MCP] egress summary dropped after signing: ${String(err?.message || err)}
`);
            }
          }
          if (summaries.length === 0) return;
          const res = await fetch(`${this.base}/fn/console/${slug}/summaries`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${this.token}`,
              "user-agent": "protect-mcp/scopeblind-bridge"
            },
            body: JSON.stringify({ auth_proof: proof, summaries })
          });
          if (!res.ok) {
            const errBody = await res.text().catch(() => "");
            this.stats.last_error = `HTTP ${res.status} ${errBody.slice(0, 160)}`;
            this.stats.rejected_total += summaries.length;
            if (res.status >= 500 && res.status !== 503) {
              this.queue.unshift(...localReceipts);
            }
            return;
          }
          const body = await res.json().catch(() => ({}));
          this.stats.forwarded_total += body?.accepted ?? summaries.length;
          this.stats.rejected_total += body?.rejected ?? 0;
          this.stats.last_flush_at = (/* @__PURE__ */ new Date()).toISOString();
          this.stats.last_error = null;
        } catch (err) {
          this.stats.last_error = String(err?.message || err);
          this.queue.unshift(...localReceipts);
        }
      }
      summaryOptions(slug) {
        const pseudonymKey = this.configuredPseudonymKey || loadOrCreatePseudonymKey(this.env, this.base, slug);
        return { pseudonymKey, tenantScope: `${this.base}\0${slug}` };
      }
      /** Exchange SCOPEBLIND_TOKEN for a BRASS-v2 proof; refresh near expiry. */
      async ensureBrassProof() {
        if (!this.token) return null;
        const now = Date.now();
        if (this.cachedProof && Date.parse(this.cachedProof.expires_at) - now > BRASS_REFRESH_MARGIN_MS) {
          return this.cachedProof;
        }
        try {
          const res = await fetch(`${this.base}/fn/brass/issue`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "user-agent": "protect-mcp/scopeblind-bridge"
            },
            body: JSON.stringify({
              token: this.token,
              scope: "scopeblind-summary-emit",
              ttl_seconds: 3600
            })
          });
          if (!res.ok) {
            const text5 = await res.text().catch(() => "");
            this.stats.last_error = `brass-issue: HTTP ${res.status} ${text5.slice(0, 160)}`;
            return null;
          }
          const body = await res.json();
          if (!body?.auth_proof) {
            this.stats.last_error = "brass-issue: missing auth_proof in response";
            return null;
          }
          this.cachedProof = body.auth_proof;
          return this.cachedProof;
        } catch (err) {
          this.stats.last_error = `brass-issue: ${err?.message || err}`;
          return null;
        }
      }
      /**
       * Return a snapshot of bridge stats. Useful for `protect-mcp scopeblind status`.
       */
      getStats() {
        return {
          ...this.stats,
          queued: this.queue.length,
          brass_proof_expires_at: this.cachedProof?.expires_at || null
        };
      }
      /** Flush remaining receipts and stop the interval. Called on process exit. */
      async shutdown() {
        if (this.shuttingDown) return;
        this.shuttingDown = true;
        if (this.flushTimer) clearInterval(this.flushTimer);
        if (this.queue.length > 0) await this.flush();
      }
    };
    singleton = null;
  }
});

// src/hook-server.ts
var hook_server_exports = {};
__export(hook_server_exports, {
  startHookServer: () => startHookServer
});
function resumeReceiptChain(receiptFilePath) {
  try {
    if (!(0, import_node_fs17.existsSync)(receiptFilePath)) return null;
    const lines = (0, import_node_fs17.readFileSync)(receiptFilePath, "utf-8").split("\n").filter((l) => l.trim());
    if (lines.length === 0) return null;
    return receiptHash(JSON.parse(lines[lines.length - 1]));
  } catch {
    return null;
  }
}
function detectSwarmContext() {
  const teamName = process.env.CLAUDE_CODE_TEAM_NAME;
  const agentId = process.env.CLAUDE_CODE_AGENT_ID;
  const agentName = process.env.CLAUDE_CODE_AGENT_NAME;
  if (!teamName && !agentId) {
    return { agent_type: "standalone" };
  }
  const isLeader = !agentId || agentId === "team-lead";
  return {
    team_name: teamName,
    agent_id: agentId,
    agent_name: agentName,
    is_leader: isLeader,
    agent_type: isLeader ? "coordinator" : "worker"
  };
}
function computePayloadDigest(input) {
  const content = typeof input === "string" ? input : JSON.stringify(input || {});
  const size = Buffer.byteLength(content, "utf-8");
  if (size <= PAYLOAD_HASH_THRESHOLD) {
    return void 0;
  }
  return {
    input_hash: (0, import_node_crypto14.createHash)("sha256").update(content).digest("hex"),
    input_size: size,
    truncated: true,
    preview: content.slice(0, 256)
  };
}
function computeOutputDigest(output) {
  const content = typeof output === "string" ? output : JSON.stringify(output || {});
  const size = Buffer.byteLength(content, "utf-8");
  if (size <= PAYLOAD_HASH_THRESHOLD) {
    return void 0;
  }
  return {
    output_hash: (0, import_node_crypto14.createHash)("sha256").update(content).digest("hex"),
    output_size: size
  };
}
function detectSandboxState() {
  if (process.env.SANDBOX_ENABLED === "1" || process.env.CLAUDE_CODE_SANDBOX === "1") {
    return "enabled";
  }
  if (process.platform === "darwin" && process.env.APP_SANDBOX_CONTAINER_ID) {
    return "enabled";
  }
  if (process.platform === "linux") {
    try {
      const procStatus = (0, import_node_fs17.readFileSync)("/proc/self/status", "utf-8");
      if (procStatus.includes("Seccomp:	2")) return "enabled";
    } catch {
    }
  }
  return "unavailable";
}
async function handlePreToolUse(input, state) {
  const hookStart = Date.now();
  const toolName = input.toolName || "unknown";
  const requestId = input.toolUseId || (0, import_node_crypto14.randomUUID)().slice(0, 12);
  state.inflightTools.set(requestId, {
    tool: toolName,
    startedAt: hookStart,
    requestId
  });
  const payloadDigest = computePayloadDigest(input.toolInput);
  const actionReadback = buildActionReadback(toolName, input.toolInput || {});
  const mandate = ensureManagedMandate(state);
  if (!mandate.valid) {
    const hookLatency2 = Date.now() - hookStart;
    emitDecisionLog(state, {
      tool: toolName,
      decision: "deny",
      reason_code: mandate.code,
      request_id: requestId,
      hook_event: "PreToolUse",
      timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
      action_readback: actionReadback,
      sandbox_state: detectSandboxState()
    });
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `[ScopeBlind] Denied "${toolName}": the managed mandate cannot be verified (${mandate.code}). ${mandate.message} Failing closed until the signed policy state is restored.`
      }
    };
  }
  const enrichment = buildEnrichment(toolName, input.toolInput || {});
  const inflightRec = state.inflightTools.get(requestId);
  if (inflightRec) inflightRec.enrichment = enrichment;
  const swarm = {
    ...state.swarmContext,
    ...input.agentId && { agent_id: input.agentId },
    ...input.agentName && { agent_name: input.agentName },
    ...input.teamName && { team_name: input.teamName },
    ...input.agentType && { agent_type: input.agentType }
  };
  if (state.standard) {
    const std = state.standard;
    const common = () => ({ request_id: requestId, hook_event: "PreToolUse", swarm: swarm.team_name ? swarm : void 0, timing: { hook_latency_ms: Date.now() - hookStart, started_at: hookStart }, payload_digest: payloadDigest, action_readback: actionReadback, sandbox_state: detectSandboxState() });
    const refuse = (reason_code, why) => {
      emitDecisionLog(state, { tool: toolName, decision: "deny", reason_code, ...common() });
      if (!state.enforce) return null;
      return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `[ScopeBlind] ${why}` } };
    };
    if (std.tools && !std.tools.includes(toolName)) {
      const r = refuse("standard_tool_not_allowed", `"${toolName}" is not among the tools the standard permits.`);
      if (r) return r;
    } else {
      const amount3 = checkAmount(std, input.toolInput);
      if (!amount3.ok) {
        const r = refuse(amount3.reason, `"${toolName}" refused by the standard: ${amount3.detail}.`);
        if (r) return r;
      } else {
        const person = personRequired(std, input.toolInput);
        if (person.required) {
          const hid = heldIdFor(state.reporter?.sid ?? std.request_id, toolName, actionReadback.payload_hash);
          const page = state.reporter ? `${new URL(state.reporter.url).origin}/standard?s=${state.reporter.sid}#held-${hid}` : "";
          const verdict = state.reporter ? await state.reporter.decision(hid) : null;
          if (verdict === "unreachable") {
            const r = refuse("standard_page_unreachable", `"${toolName}" needs a named person's approval and the standard's page could not be reached; retry the same call later.`);
            if (r) return r;
          } else if (verdict) {
            state.approvalsToRecord.set(requestId, { hid, approver_key_id: verdict.approver_key_id, digest: verdict.digest, page });
            if (verdict.decision === "deny") {
              const r = refuse("person_denied", `"${toolName}" was denied by ${verdict.approver_key_id} on the standard's page${verdict.note ? `: ${verdict.note}` : ""}.`);
              if (r) return r;
            }
          } else {
            const amt = readAmount(input.toolInput);
            if (state.enforce && state.reporter) {
              await state.reporter.hold({ hid, request_id: requestId, tool: toolName, readback: { summary: actionReadback.summary, payload_hash: actionReadback.payload_hash, amount: amt ? amt.minor / 100 : null, currency: amt?.currency || null }, reason: person.detail });
            }
            emitDecisionLog(state, { tool: toolName, decision: "require_approval", reason_code: "standard_requires_person", ...common() });
            if (state.enforce) {
              return {
                hookSpecificOutput: {
                  hookEventName: "PreToolUse",
                  permissionDecision: "deny",
                  permissionDecisionReason: `[ScopeBlind] ${person.detail}. Exact action: ${actionReadback.summary}. ${page ? `Waiting for the named person at ${page}; retry this exact call once they have decided there. A changed call is a new action.` : "No standard page is configured (--report), so it cannot be decided here."}`
                }
              };
            }
          }
        }
      }
    }
  }
  maybeReloadCedar(state);
  if (state.cedarPolicies) {
    try {
      const cedarDecision = await evaluateCedar(state.cedarPolicies, {
        tool: toolName,
        tier: "unknown",
        // Hook mode doesn't have admission tier yet
        agentId: swarm.agent_id,
        context: {
          hook_event: "PreToolUse",
          ...input.toolInput || {}
        },
        // Also expose the raw tool input under context.input so policies written
        // against the documented nested shape match on the hook path too.
        toolInput: input.toolInput || {}
      });
      if (!cedarDecision.allowed) {
        const reason = cedarDecision.reason || "cedar_deny";
        const hookLatency2 = Date.now() - hookStart;
        const denyKey2 = `${toolName}:${input.sessionId || "default"}`;
        const denyCount = (state.denyCounter.get(denyKey2) || 0) + 1;
        state.denyCounter.set(denyKey2, denyCount);
        const suggestion = `permit(principal, action == Action::"MCP::Tool::call", resource == Tool::"${toolName}");`;
        state.permissionSuggestions.set(toolName, suggestion);
        emitDecisionLog(state, {
          tool: toolName,
          decision: "deny",
          reason_code: reason,
          request_id: requestId,
          hook_event: "PreToolUse",
          swarm: swarm.team_name ? swarm : void 0,
          timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
          payload_digest: payloadDigest,
          action_readback: actionReadback,
          deny_iteration: denyCount,
          sandbox_state: detectSandboxState(),
          plan_receipt_id: state.activePlanReceiptId || void 0
        });
        const isDefaultDeny = !reason || reason === "cedar_deny" || /reason":\[\]/.test(reason);
        const policyRef = state.cedarDir ? ` Policy: ${state.cedarDir}.` : "";
        const howTo = isDefaultDeny ? ` No permit matched (default-deny, fail-closed).${policyRef} Allow it: npx protect-mcp policy allow ${toolName}` : ` Blocked by an explicit forbid rule.${policyRef} Review: npx protect-mcp policy show`;
        if (denyCount === 1) {
          process.stderr.write(
            `[PROTECT_MCP] Denied "${toolName}" (${isDefaultDeny ? "default-deny" : "forbid"}).
  Allow with: npx protect-mcp policy allow ${toolName}
`
          );
        }
        return {
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: `[ScopeBlind] Denied "${toolName}".${howTo}` + (denyCount > 1 ? ` (attempt ${denyCount})` : "")
          }
        };
      }
    } catch (err) {
      const hookLatency2 = Date.now() - hookStart;
      process.stderr.write(
        `[PROTECT_MCP] Cedar eval threw for "${toolName}", failing closed: ${err instanceof Error ? err.message : err}
`
      );
      emitDecisionLog(state, {
        tool: toolName,
        decision: "deny",
        reason_code: "cedar_eval_error",
        request_id: requestId,
        hook_event: "PreToolUse",
        swarm: swarm.team_name ? swarm : void 0,
        timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
        payload_digest: payloadDigest,
        action_readback: actionReadback,
        sandbox_state: detectSandboxState()
      });
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `[ScopeBlind] Denied: the policy engine errored while evaluating "${toolName}", so the gate fails closed rather than allow an unverified call. Check the policy set and server logs.`
        }
      };
    }
  }
  if (state.jsonPolicy?.policy) {
    const toolPolicy = getToolPolicy(toolName, state.jsonPolicy.policy);
    if (toolPolicy.block) {
      const hookLatency2 = Date.now() - hookStart;
      emitDecisionLog(state, {
        tool: toolName,
        decision: "deny",
        reason_code: "policy_block",
        request_id: requestId,
        hook_event: "PreToolUse",
        swarm: swarm.team_name ? swarm : void 0,
        timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
        payload_digest: payloadDigest,
        action_readback: actionReadback,
        sandbox_state: detectSandboxState()
      });
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `[ScopeBlind] "${toolName}" is blocked by policy.`
        }
      };
    }
    if (toolPolicy.require_approval) {
      const hookLatency2 = Date.now() - hookStart;
      emitDecisionLog(state, {
        tool: toolName,
        decision: "require_approval",
        reason_code: "requires_human_approval",
        request_id: requestId,
        hook_event: "PreToolUse",
        swarm: swarm.team_name ? swarm : void 0,
        timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
        payload_digest: payloadDigest,
        action_readback: actionReadback,
        sandbox_state: detectSandboxState()
      });
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "ask",
          permissionDecisionReason: `[ScopeBlind] Approval required for exactly this action: ${actionReadback.summary}. Payload hash: ${actionReadback.payload_hash.slice(0, 16)}\u2026 Policy: ${state.policyDigest}`
        }
      };
    }
    if (toolPolicy.rate_limit) {
      try {
        const limit = parseRateLimit(toolPolicy.rate_limit);
        const key = `tool:${toolName}:hook`;
        const { allowed, remaining } = checkRateLimit(key, limit, state.rateLimitStore);
        if (!allowed) {
          const hookLatency2 = Date.now() - hookStart;
          emitDecisionLog(state, {
            tool: toolName,
            decision: "deny",
            reason_code: "rate_limit_exceeded",
            request_id: requestId,
            hook_event: "PreToolUse",
            swarm: swarm.team_name ? swarm : void 0,
            timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
            sandbox_state: detectSandboxState()
          });
          return {
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "deny",
              permissionDecisionReason: `[ScopeBlind] "${toolName}" rate limit exceeded (${toolPolicy.rate_limit}).`
            }
          };
        }
      } catch {
      }
    }
  }
  const hookLatency = Date.now() - hookStart;
  const denyKey = `${toolName}:${input.sessionId || "default"}`;
  state.denyCounter.delete(denyKey);
  const emit = emitDecisionLog(state, {
    tool: toolName,
    decision: "allow",
    reason_code: state.cedarPolicies ? "cedar_allow" : state.jsonPolicy ? "policy_allow" : "observe_mode",
    request_id: requestId,
    hook_event: "PreToolUse",
    swarm: swarm.team_name ? swarm : void 0,
    timing: { hook_latency_ms: hookLatency, started_at: hookStart },
    payload_digest: payloadDigest,
    action_readback: actionReadback,
    sandbox_state: detectSandboxState(),
    plan_receipt_id: state.activePlanReceiptId || void 0
  });
  if (state.enforce && emit.signingFailed) {
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `[ScopeBlind] "${toolName}" was blocked because its receipt could not be signed. Failing closed: a governed action that cannot be proven is not allowed.`
      }
    };
  }
  return {};
}
async function handlePostToolUse(input, state) {
  const toolName = input.toolName || "unknown";
  const requestId = input.toolUseId || (0, import_node_crypto14.randomUUID)().slice(0, 12);
  const now = Date.now();
  const inflight = state.inflightTools.get(requestId);
  const timing = {
    completed_at: now
  };
  if (inflight) {
    timing.tool_duration_ms = now - inflight.startedAt;
    timing.started_at = inflight.startedAt;
    state.inflightTools.delete(requestId);
  }
  const outputDigest = computeOutputDigest(input.toolResult);
  const receiptId = (0, import_node_crypto14.randomUUID)().slice(0, 8);
  const policyName = state.cedarPolicies ? `cedar:${state.policyDigest}` : state.policyDigest;
  const additionalContext = `[ScopeBlind] Tool call receipted. Policy: ${policyName}. Decision: allow. Receipt: #${receiptId}.` + (timing.tool_duration_ms !== void 0 ? ` Duration: ${timing.tool_duration_ms}ms.` : "") + (timing.hook_latency_ms !== void 0 ? ` Overhead: ${timing.hook_latency_ms}ms.` : "");
  emitDecisionLog(state, {
    tool: toolName,
    decision: "allow",
    reason_code: "post_execution_receipt",
    request_id: requestId,
    hook_event: "PostToolUse",
    swarm: state.swarmContext.team_name ? state.swarmContext : void 0,
    timing,
    payload_digest: outputDigest ? {
      truncated: true,
      output_hash: outputDigest.output_hash,
      output_size: outputDigest.output_size
    } : void 0,
    sandbox_state: detectSandboxState()
  });
  return {
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext
    }
  };
}
function handleSubagentStart(input, state) {
  const agentId = input.agentId || "unknown";
  const agentType = input.agentType || "worker";
  emitDecisionLog(state, {
    tool: `subagent:${agentId}`,
    decision: "allow",
    reason_code: "subagent_started",
    request_id: (0, import_node_crypto14.randomUUID)().slice(0, 12),
    hook_event: "SubagentStart",
    swarm: {
      ...state.swarmContext,
      agent_id: agentId,
      agent_name: input.agentName,
      agent_type: agentType
    }
  });
  if (state.verbose) {
    process.stderr.write(`[PROTECT_MCP] Subagent started: ${agentId} (${agentType})
`);
  }
  return {};
}
function handleSubagentStop(input, state) {
  const agentId = input.agentId || "unknown";
  emitDecisionLog(state, {
    tool: `subagent:${agentId}`,
    decision: "allow",
    reason_code: "subagent_stopped",
    request_id: (0, import_node_crypto14.randomUUID)().slice(0, 12),
    hook_event: "SubagentStop",
    swarm: {
      ...state.swarmContext,
      agent_id: agentId,
      agent_name: input.agentName
    }
  });
  return {};
}
function handleTaskCreated(input, state) {
  emitDecisionLog(state, {
    tool: `task:${input.taskId || "unknown"}`,
    decision: "allow",
    reason_code: "task_created",
    request_id: (0, import_node_crypto14.randomUUID)().slice(0, 12),
    hook_event: "TaskCreated",
    swarm: {
      ...state.swarmContext,
      agent_name: input.teammateName
    }
  });
  return {};
}
function handleTaskCompleted(input, state) {
  emitDecisionLog(state, {
    tool: `task:${input.taskId || "unknown"}`,
    decision: "allow",
    reason_code: "task_completed",
    request_id: (0, import_node_crypto14.randomUUID)().slice(0, 12),
    hook_event: "TaskCompleted",
    swarm: state.swarmContext
  });
  return {};
}
function handleSessionStart(input, state) {
  emitDecisionLog(state, {
    tool: "session",
    decision: "allow",
    reason_code: "session_started",
    request_id: input.sessionId || (0, import_node_crypto14.randomUUID)().slice(0, 12),
    hook_event: "SessionStart",
    swarm: state.swarmContext,
    sandbox_state: detectSandboxState()
  });
  return {};
}
function handleSessionEnd(input, state) {
  const suggestions = [...state.permissionSuggestions.entries()];
  if (suggestions.length > 0) {
    process.stderr.write(`
[PROTECT_MCP] Session summary \u2014 ${suggestions.length} policy suggestion(s):
`);
    for (const [tool, suggestion] of suggestions) {
      process.stderr.write(`  ${tool}: ${suggestion}
`);
    }
    process.stderr.write("\n");
  }
  emitDecisionLog(state, {
    tool: "session",
    decision: "allow",
    reason_code: "session_ended",
    request_id: input.sessionId || (0, import_node_crypto14.randomUUID)().slice(0, 12),
    hook_event: "SessionEnd",
    swarm: state.swarmContext
  });
  return {};
}
function handleTeammateIdle(input, state) {
  emitDecisionLog(state, {
    tool: `teammate:${input.agentId || "unknown"}`,
    decision: "allow",
    reason_code: "teammate_idle",
    request_id: (0, import_node_crypto14.randomUUID)().slice(0, 12),
    hook_event: "TeammateIdle",
    swarm: {
      ...state.swarmContext,
      agent_id: input.agentId,
      agent_name: input.agentName
    }
  });
  return {};
}
function handleConfigChange(input, state) {
  const configPath = input.filePath || input.configPath || "unknown";
  const source = input.configSource || "unknown";
  const isSelfModification = configPath.includes("settings.json") || configPath.includes(".claude/");
  if (isSelfModification) {
    state.configAlerts.push({
      timestamp: Date.now(),
      path: configPath,
      source
    });
    process.stderr.write(
      `[PROTECT_MCP] \u26A0\uFE0F  TAMPER ALERT: Config file modified: ${configPath} (source: ${source})
`
    );
    emitDecisionLog(state, {
      tool: "config",
      decision: "deny",
      reason_code: "config_tamper_detected",
      request_id: (0, import_node_crypto14.randomUUID)().slice(0, 12),
      hook_event: "ConfigChange",
      swarm: state.swarmContext
    });
  } else {
    emitDecisionLog(state, {
      tool: "config",
      decision: "allow",
      reason_code: "config_changed",
      request_id: (0, import_node_crypto14.randomUUID)().slice(0, 12),
      hook_event: "ConfigChange"
    });
  }
  return {};
}
function handleStop(input, state) {
  const suggestions = [...state.permissionSuggestions.entries()];
  if (suggestions.length > 0) {
    process.stderr.write(`
[PROTECT_MCP] Final policy suggestions:
`);
    for (const [tool, suggestion] of suggestions) {
      process.stderr.write(`  ${suggestion}
`);
    }
    process.stderr.write("\n");
  }
  emitDecisionLog(state, {
    tool: "session",
    decision: "allow",
    reason_code: "agent_stopped",
    request_id: (0, import_node_crypto14.randomUUID)().slice(0, 12),
    hook_event: "Stop",
    swarm: state.swarmContext
  });
  return {};
}
function emitDecisionLog(state, entry) {
  const mode = state.enforce ? "enforce" : "shadow";
  const otelTraceId = (0, import_node_crypto14.randomBytes)(16).toString("hex");
  const otelSpanId = (0, import_node_crypto14.randomBytes)(8).toString("hex");
  const log = {
    v: 2,
    tool: entry.tool || "unknown",
    decision: entry.decision || "allow",
    reason_code: entry.reason_code || "default_allow",
    policy_digest: state.policyDigest,
    policy_engine: state.cedarPolicies ? "cedar" : "built-in",
    request_id: entry.request_id || (0, import_node_crypto14.randomUUID)().slice(0, 12),
    timestamp: Date.now(),
    mode,
    otel_trace_id: otelTraceId,
    otel_span_id: otelSpanId,
    ...entry.tier && { tier: entry.tier },
    ...entry.hook_event && { hook_event: entry.hook_event },
    ...entry.swarm && { swarm: entry.swarm },
    ...entry.timing && { timing: entry.timing },
    ...entry.payload_digest && { payload_digest: entry.payload_digest },
    ...entry.deny_iteration && { deny_iteration: entry.deny_iteration },
    ...entry.sandbox_state && { sandbox_state: entry.sandbox_state },
    ...entry.plan_receipt_id && { plan_receipt_id: entry.plan_receipt_id },
    ...state.managedMandate ? {
      mandate_registry: {
        registry_id: state.managedMandate.registry.registry_id,
        active_policy_digest: state.managedMandate.registry.active.policy_digest,
        active_transition_hash: receiptHash(state.managedMandate.registry.history.at(-1)?.transition_receipt || {}),
        ...state.managedMandate.registry.active.expires_at ? { expires_at: state.managedMandate.registry.active.expires_at } : {}
      }
    } : {}
  };
  const enr = state.inflightTools.get(log.request_id)?.enrichment;
  if (enr) log.enrichment = enr;
  if (state.standard) log.standard = { request_id: state.standard.request_id, digest: state.standard.digest };
  const approval = state.approvalsToRecord.get(log.request_id);
  if (approval) {
    log.approval = approval;
    state.approvalsToRecord.delete(log.request_id);
  }
  const callLine = state.reporter ? JSON.stringify({ tool: log.tool, input: log.action_readback?.payload_preview ?? {}, decision: log.decision, request_id: log.request_id, at: new Date(log.timestamp).toISOString() }) : void 0;
  if (state.reporter && !isSigningEnabled()) state.reporter.record(void 0, callLine);
  process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}
`);
  try {
    (0, import_node_fs17.appendFileSync)(state.logFilePath, JSON.stringify(log) + "\n");
  } catch {
  }
  if (isSigningEnabled()) {
    const signed2 = signDecision(log, state.lastReceiptHash || void 0);
    if (signed2.signed) {
      try {
        (0, import_node_fs17.appendFileSync)(state.receiptFilePath, signed2.signed + "\n");
        if (signed2.receipt_hash) state.lastReceiptHash = signed2.receipt_hash;
      } catch {
      }
      state.receiptBuffer.add(log.request_id, signed2.signed);
      state.reporter?.record(signed2.signed, callLine);
      try {
        const bridge = getScopeBlindBridge();
        if (bridge.enabled()) {
          const parsed = typeof signed2.signed === "string" ? JSON.parse(signed2.signed) : signed2.signed;
          bridge.forward(parsed);
        }
      } catch (err) {
        process.stderr.write(`[PROTECT_MCP] ScopeBlind forward error: ${err instanceof Error ? err.message : err}
`);
      }
    } else if (signed2.error) {
      const tombstoneObj = {
        type: "scopeblind.signing_failure.v1",
        request_id: log.request_id,
        tool: log.tool,
        decision: log.decision,
        error: signed2.error,
        at: new Date(log.timestamp).toISOString(),
        ...state.lastReceiptHash ? { previousReceiptHash: state.lastReceiptHash } : {}
      };
      const tombstone = JSON.stringify(tombstoneObj);
      try {
        (0, import_node_fs17.appendFileSync)(state.receiptFilePath, tombstone + "\n");
        state.lastReceiptHash = receiptHash(tombstoneObj);
      } catch {
      }
      process.stderr.write(`[PROTECT_MCP_SIGNING_FAILURE] ${tombstone}
`);
      return { signingFailed: true };
    }
  }
  return { signingFailed: false };
}
async function routeHookEvent(input, state) {
  switch (input.hookEventName) {
    case "PreToolUse":
      return handlePreToolUse(input, state);
    case "PostToolUse":
      return handlePostToolUse(input, state);
    case "SubagentStart":
      return handleSubagentStart(input, state);
    case "SubagentStop":
      return handleSubagentStop(input, state);
    case "TaskCreated":
      return handleTaskCreated(input, state);
    case "TaskCompleted":
      return handleTaskCompleted(input, state);
    case "SessionStart":
      return handleSessionStart(input, state);
    case "SessionEnd":
      return handleSessionEnd(input, state);
    case "TeammateIdle":
      return handleTeammateIdle(input, state);
    case "ConfigChange":
      return handleConfigChange(input, state);
    case "Stop":
      return handleStop(input, state);
    default:
      if (state.verbose) {
        process.stderr.write(`[PROTECT_MCP] Unknown hook event: ${input.hookEventName}
`);
      }
      return {};
  }
}
async function startHookServer(options2 = {}) {
  const port = options2.port || DEFAULT_PORT;
  const verbose = options2.verbose || false;
  const enforce = options2.enforce || false;
  const dataDir = options2.dataDir || process.cwd();
  let cedarPolicies = null;
  let jsonPolicy = null;
  let policyDigest = "none";
  let gateKeyPath;
  let managedMandate = null;
  const cedarDir = options2.cedarDir || findCedarDir();
  if (cedarDir) {
    try {
      cedarPolicies = loadCedarPolicies(cedarDir);
      policyDigest = cedarPolicies.digest;
      process.stderr.write(
        `[PROTECT_MCP] Cedar policies loaded: ${cedarPolicies.fileCount} files from ${cedarDir} (digest: ${policyDigest})
`
      );
      const cedarAvailable = await isCedarAvailable();
      if (!cedarAvailable) {
        process.stderr.write(
          "[PROTECT_MCP] Warning: @cedar-policy/cedar-wasm not installed. Cedar policies loaded but evaluation fallback is allow-all.\n"
        );
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Cedar load error: ${err instanceof Error ? err.message : err}
`);
    }
  }
  if (options2.policyPath) {
    try {
      jsonPolicy = loadPolicy(options2.policyPath);
      if (!cedarPolicies) policyDigest = jsonPolicy.digest;
      process.stderr.write(`[PROTECT_MCP] JSON policy loaded from ${options2.policyPath}
`);
      if (jsonPolicy.signing) {
        gateKeyPath = jsonPolicy.signing.key_path;
        const warnings = await initSigning(jsonPolicy.signing);
        for (const w of warnings) {
          process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
        }
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Policy load error: ${err instanceof Error ? err.message : err}
`);
    }
  }
  if (!jsonPolicy?.signing) {
    const keyPath = (0, import_node_path14.join)(dataDir, "keys", "gateway.json");
    if ((0, import_node_fs17.existsSync)(keyPath)) {
      gateKeyPath = keyPath;
      const warnings = await initSigning({ key_path: keyPath, issuer: "protect-mcp", enabled: true });
      for (const w of warnings) {
        process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
      }
    }
  }
  if (cedarDir) {
    const existingRegistry = loadMandateRegistry(cedarDir);
    if (existingRegistry) {
      if (!gateKeyPath) {
        const message = "managed mandate found but no local gate signing key is configured";
        if (enforce) throw new Error(`enforce mode refused to start: ${message}`);
        process.stderr.write(`[PROTECT_MCP] Warning: ${message}; governed enforcement remains unavailable.
`);
      } else {
        try {
          const gateSigner = loadGateSigner(gateKeyPath);
          const receiptSigner = getSignerInfo();
          if (!isSigningEnabled() || !receiptSigner || receiptSigner.kid !== gateSigner.kid || receiptSigner.publicKey !== gateSigner.publicKey) {
            throw new Error("managed mandate requires decision receipt signing with the exact gate key pinned in the registry");
          }
          const check = refreshManagedMandate({ cedarDir, signer: gateSigner });
          if (!check.valid || !check.registry) {
            const message = `${check.code || "mandate_registry_invalid"}: ${check.message || "registry verification failed"}`;
            if (enforce) throw new Error(`enforce mode refused to start: ${message}`);
            process.stderr.write(`[PROTECT_MCP] Warning: managed mandate invalid (${message}).
`);
          } else {
            const reloaded = loadCedarPolicies(cedarDir);
            if (reloaded.digest !== check.registry.active.policy_digest) {
              throw new Error("loaded Cedar bytes do not match the signed active mandate head");
            }
            cedarPolicies = reloaded;
            policyDigest = reloaded.digest;
            managedMandate = {
              signer: gateSigner,
              registry: check.registry,
              rpId: options2.mandateRelyingPartyId || "localhost",
              expectedOrigin: options2.mandateApprovalOrigin || `http://localhost:${port}`,
              highWaterSequence: check.registry.history.length,
              highWaterHash: check.registry.history.length ? receiptHash(check.registry.history[check.registry.history.length - 1].transition_receipt) : "",
              maxSeenTimeMs: Math.max(Date.now(), check.registry.history.reduce((m, t) => Math.max(m, Date.parse(t.occurred_at) || 0), 0))
            };
            process.stderr.write(
              `[PROTECT_MCP] Managed mandate loaded: ${check.registry.registry_id} (head: ${check.registry.active.policy_digest}${check.registry.active.expires_at ? `; expires ${check.registry.active.expires_at}` : ""}).
`
            );
          }
        } catch (error) {
          if (enforce) throw error;
          process.stderr.write(`[PROTECT_MCP] Warning: managed mandate unavailable: ${error instanceof Error ? error.message : error}
`);
        }
      }
    }
  }
  if (enforce) {
    const selfTest = await runEvaluatorSelfTest();
    for (const c2 of selfTest.cases) {
      if (!c2.pass) {
        process.stderr.write(
          `[PROTECT_MCP] SELF-TEST FAIL: ${c2.name} (expected ${c2.expected}, got ${c2.actual})
`
        );
      }
    }
    if (!selfTest.passed) {
      throw new Error(
        "enforce mode refused to start: the restraint self-test failed. A gate that cannot prove it denies must not arm."
      );
    }
    const receiptProbe = signDecision({
      v: 2,
      tool: "__protect_mcp_startup_selftest__",
      decision: "deny",
      reason_code: "startup_selftest",
      policy_digest: policyDigest,
      request_id: `selftest-${Date.now()}`,
      mode: "enforce",
      timestamp: Date.now()
    });
    if (receiptProbe.error) {
      throw new Error(
        `enforce mode refused to start: signing is configured but a denial receipt could not be produced (${receiptProbe.error}). An enforcing gate that cannot evidence a denial must not arm.`
      );
    }
    process.stderr.write(
      `[PROTECT_MCP] Restraint self-test passed (${selfTest.cases.length} vectors${selfTest.wasmAvailable ? "" : "; Cedar WASM absent, fail-closed invariant verified"})${receiptProbe.ok ? "; denial receipt signing verified" : ""}. Arming enforce mode.
`
    );
  }
  let standard = null;
  let reporter = null;
  if (options2.standardPath) {
    standard = loadStandardFile(options2.standardPath);
    process.stderr.write(`[PROTECT_MCP] Standard in force: ${standard.request_id} (${standard.summary})
`);
  }
  if (options2.reportUrl) {
    if (!standard) throw new Error("--report needs --standard <standard.json>; the page belongs to a signed standard");
    const token = options2.reportToken || process.env.PROTECT_MCP_REPORT_TOKEN || "";
    if (!token) throw new Error("--report needs the page's write token: --report-token <token> or PROTECT_MCP_REPORT_TOKEN");
    reporter = new RecordReporter({ url: options2.reportUrl, token, runId: options2.runId || `run-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace(/[-:T]/g, "")}` });
    process.stderr.write(`[PROTECT_MCP] Record lands on ${new URL(reporter.url).origin}/standard?s=${reporter.sid} as run ${reporter.runId}
`);
    if (!isSigningEnabled()) process.stderr.write("[PROTECT_MCP] Warning: signing is not configured, so only unsigned call lines reach the page; add a signing key for receipts\n");
  }
  const state = {
    cedarPolicies,
    cedarDir: cedarDir || null,
    cedarMtimeMs: cedarDir ? newestCedarMtime(cedarDir) : 0,
    cedarCheckedMs: 0,
    jsonPolicy,
    rateLimitStore: /* @__PURE__ */ new Map(),
    receiptBuffer: new ReceiptBuffer(),
    inflightTools: /* @__PURE__ */ new Map(),
    denyCounter: /* @__PURE__ */ new Map(),
    swarmContext: detectSwarmContext(),
    activePlanReceiptId: null,
    startTime: Date.now(),
    port,
    verbose,
    enforce,
    policyDigest,
    logFilePath: (0, import_node_path14.join)(dataDir, LOG_FILE3),
    receiptFilePath: (0, import_node_path14.join)(dataDir, RECEIPTS_FILE2),
    lastReceiptHash: resumeReceiptChain((0, import_node_path14.join)(dataDir, RECEIPTS_FILE2)),
    permissionSuggestions: /* @__PURE__ */ new Map(),
    configAlerts: [],
    managedMandate,
    standard,
    reporter,
    approvalsToRecord: /* @__PURE__ */ new Map()
  };
  const server = (0, import_node_http2.createServer)(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Content-Type", "application/json");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url || "/", `http://localhost:${port}`);
    if (url.pathname === "/health" && req.method === "GET") {
      const signerInfo = getSignerInfo();
      res.writeHead(200);
      res.end(JSON.stringify({
        status: "ok",
        server: "protect-mcp-hooks",
        version: process.env.PROTECT_MCP_VERSION || "unknown",
        uptime_ms: Date.now() - state.startTime,
        mode: enforce ? "enforce" : "shadow",
        policy_digest: policyDigest,
        policy_engine: cedarPolicies ? "cedar" : jsonPolicy ? "built-in" : "none",
        signing: isSigningEnabled(),
        swarm: state.swarmContext,
        signer: signerInfo ? { kid: signerInfo.kid, issuer: signerInfo.issuer } : null,
        cedar_files: cedarPolicies?.fileCount || 0,
        mandate: state.managedMandate ? {
          registry_id: state.managedMandate.registry.registry_id,
          active_policy_digest: state.managedMandate.registry.active.policy_digest,
          ...state.managedMandate.registry.active.expires_at ? { expires_at: state.managedMandate.registry.active.expires_at } : {},
          controller_count: state.managedMandate.registry.controllers.length
        } : null
      }));
      return;
    }
    if (url.pathname === "/mandate" && req.method === "GET") {
      const check = ensureManagedMandate(state);
      if (!state.managedMandate) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "no_managed_mandate", hint: "Run protect-mcp mandate init before requesting lifecycle status." }));
        return;
      }
      res.writeHead(check.valid ? 200 : 409);
      res.end(JSON.stringify({
        valid: check.valid,
        ...check.valid ? {} : { error: check.code, message: check.message },
        mandate: publicMandateStatus(state.managedMandate.registry)
      }));
      return;
    }
    const approvalMatch = url.pathname.match(/^\/mandate\/proposals\/([^/]+)\/(approve|webauthn\/challenge)$/);
    if (approvalMatch && req.method === "GET") {
      const proposalId = decodeURIComponent(approvalMatch[1]);
      const check = ensureManagedMandate(state);
      if (!check.valid || !state.managedMandate) {
        res.writeHead(409);
        res.end(JSON.stringify({ error: check.valid ? "no_managed_mandate" : check.code, message: check.valid ? "No managed mandate is active." : check.message }));
        return;
      }
      const proposal = state.managedMandate.registry.proposals[proposalId];
      if (!proposal) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "unknown_proposal" }));
        return;
      }
      const controllerId = url.searchParams.get("controller_id") || state.managedMandate.registry.controllers.find((item) => item.type === "webauthn")?.id;
      const controller = state.managedMandate.registry.controllers.find((item) => item.id === controllerId);
      if (!controller || controller.type !== "webauthn") {
        res.writeHead(400);
        res.end(JSON.stringify({ error: "webauthn_controller_required", hint: "Register a WebAuthn controller before using browser approval." }));
        return;
      }
      if (approvalMatch[2] === "webauthn/challenge") {
        try {
          const challenge = createWebAuthnPolicyChallenge({
            cedarDir: state.cedarDir,
            proposalId,
            controllerId: controller.id,
            rpId: state.managedMandate.rpId
          });
          state.managedMandate.registry = loadMandateRegistry(state.cedarDir);
          res.writeHead(200);
          res.end(JSON.stringify({
            proposal_id: proposal.proposal_id,
            proposal_digest: proposal.proposal_digest,
            controller: { id: controller.id, label: controller.label },
            publicKey: {
              challenge: challenge.challenge,
              rpId: challenge.rpId,
              timeout: challenge.timeoutSeconds * 1e3,
              userVerification: "required",
              allowCredentials: [{ id: controller.credential_id, type: "public-key" }]
            }
          }));
        } catch (error) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: "challenge_failed", message: error instanceof Error ? error.message : "Could not create approval challenge." }));
        }
        return;
      }
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.writeHead(200);
      res.end(renderMandateApprovalPage({ proposal, controller: { id: controller.id, label: controller.label }, port }));
      return;
    }
    const approveMatch = url.pathname.match(/^\/mandate\/proposals\/([^/]+)\/webauthn\/approve$/);
    if (approveMatch && req.method === "POST") {
      const proposalId = decodeURIComponent(approveMatch[1]);
      if (!state.managedMandate || !state.cedarDir) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "no_managed_mandate" }));
        return;
      }
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          if (!parsed.assertion) throw new Error("missing WebAuthn assertion");
          const registry = approvePolicyProposalWithWebAuthn({
            cedarDir: state.cedarDir,
            signer: state.managedMandate.signer,
            proposalId,
            assertion: parsed.assertion,
            expectedOrigin: state.managedMandate.expectedOrigin
          });
          state.managedMandate.registry = registry;
          const refreshed = ensureManagedMandate(state);
          if (!refreshed.valid) throw new Error(`${refreshed.code}: ${refreshed.message}`);
          res.writeHead(200);
          res.end(JSON.stringify({
            approved: true,
            active_policy_digest: state.managedMandate.registry.active.policy_digest,
            expires_at: state.managedMandate.registry.active.expires_at || null,
            mandate: publicMandateStatus(state.managedMandate.registry)
          }));
        } catch (error) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: "approval_rejected", message: error instanceof Error ? error.message : "Policy approval was rejected." }));
        }
      });
      return;
    }
    if (url.pathname === "/receipts" && req.method === "GET") {
      const limit = parseInt(url.searchParams.get("limit") || "20", 10);
      const receipts = state.receiptBuffer.getAll().slice(0, Math.min(limit, 100));
      res.writeHead(200);
      res.end(JSON.stringify({ count: receipts.length, total: state.receiptBuffer.count(), receipts }));
      return;
    }
    if (url.pathname === "/receipts/latest" && req.method === "GET") {
      const latest = state.receiptBuffer.getLatest();
      if (!latest) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "no_receipts" }));
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify(latest));
      return;
    }
    if (url.pathname === "/suggestions" && req.method === "GET") {
      const suggestions = [...state.permissionSuggestions.entries()].map(([tool, rule]) => ({ tool, cedar_rule: rule }));
      res.writeHead(200);
      res.end(JSON.stringify({ count: suggestions.length, suggestions }));
      return;
    }
    if (url.pathname === "/alerts" && req.method === "GET") {
      res.writeHead(200);
      res.end(JSON.stringify({ count: state.configAlerts.length, alerts: state.configAlerts }));
      return;
    }
    if (url.pathname === "/hook" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", async () => {
        let input;
        try {
          const raw = JSON.parse(body);
          input = normalizeHookInput(raw);
          if (!input.hookEventName) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: "missing_hook_event_name", hint: "Expected hook_event_name or hookEventName in POST body" }));
            return;
          }
          const response = await routeHookEvent(input, state);
          res.writeHead(200);
          res.end(JSON.stringify(response));
        } catch (err) {
          if (verbose) {
            process.stderr.write(`[PROTECT_MCP] Hook error: ${err instanceof Error ? err.message : err}
`);
          }
          if (input?.hookEventName === "PreToolUse") {
            res.writeHead(200);
            res.end(JSON.stringify({
              hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "deny",
                permissionDecisionReason: `[ScopeBlind] Denied "${input.toolName || "unknown"}": the gate hit an unexpected error while deciding, so it fails closed rather than allow an unverified call. Check the server logs.`
              }
            }));
            return;
          }
          res.writeHead(400);
          res.end(JSON.stringify({ error: "invalid_request" }));
        }
      });
      return;
    }
    res.writeHead(404);
    res.end(JSON.stringify({
      error: "not_found",
      endpoints: [
        "POST /hook           \u2014 Claude Code hook endpoint",
        "GET  /health         \u2014 Health check",
        "GET  /receipts       \u2014 Recent receipts",
        "GET  /receipts/latest \u2014 Most recent receipt",
        "GET  /suggestions    \u2014 Policy suggestions",
        "GET  /alerts         \u2014 Config tamper alerts"
      ]
    }));
  });
  server.listen(port, "127.0.0.1", () => {
    const w = (s) => process.stderr.write(s);
    const pad = (s, n = 46) => s.padEnd(n);
    w(`
`);
    w(process.env.PROTECT_MCP_VERSION ? `  protect-mcp v${process.env.PROTECT_MCP_VERSION}
` : `  protect-mcp
`);
    w(`  ScopeBlind \xB7 https://scopeblind.com
`);
    w(`
`);
    w(`  Listening     http://127.0.0.1:${port}
`);
    w(`  Mode          ${enforce ? "enforce" : "shadow"}
`);
    w(`  Policy        ${cedarPolicies ? `Cedar (${cedarPolicies.fileCount} files)` : jsonPolicy ? "JSON" : "none"}
`);
    w(`  Signing       ${isSigningEnabled() ? "Ed25519" : "disabled"}
`);
    if (state.swarmContext.team_name) {
      w(`  Swarm         ${state.swarmContext.team_name} (${state.swarmContext.agent_type})
`);
    }
    w(`
`);
    w(`  POST /hook         Hook receiver
`);
    w(`  GET  /health       Health + signer info
`);
    w(`  GET  /receipts     Signed receipts
`);
    w(`  GET  /suggestions  Cedar policy suggestions
`);
    w(`
`);
    w(`  deny is authoritative: it cannot be overridden.
`);
    w(`
`);
    w(`  See your record   npx protect-mcp record
`);
    w(`                    a searchable view of every decision, all on this machine
`);
    w(`
`);
    const hasSlug = process.env.SCOPEBLIND_SLUG || (0, import_node_fs17.existsSync)((0, import_node_path14.join)(dataDir, ".scopeblind"));
    if (!hasSlug) {
      w(`  Dashboard  npx protect-mcp connect
`);
      w(`             Sends privacy-safe summaries; raw receipts stay local
`);
      w(`
`);
    }
  });
  const shutdown = () => {
    process.stderr.write("\n[PROTECT_MCP] Shutting down hook server...\n");
    const suggestions = [...state.permissionSuggestions.entries()];
    if (suggestions.length > 0) {
      process.stderr.write(`[PROTECT_MCP] ${suggestions.length} policy suggestion(s) accumulated:
`);
      for (const [tool, suggestion] of suggestions) {
        process.stderr.write(`  ${suggestion}
`);
      }
    }
    server.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  return server;
}
function newestCedarMtime(dir) {
  try {
    let newest = 0;
    for (const f of (0, import_node_fs17.readdirSync)(dir)) {
      if (!f.endsWith(".cedar")) continue;
      const m = (0, import_node_fs17.statSync)((0, import_node_path14.join)(dir, f)).mtimeMs;
      if (m > newest) newest = m;
    }
    return newest;
  } catch {
    return 0;
  }
}
function ensureManagedMandate(state) {
  try {
    if (!state.managedMandate || !state.cedarDir) return { valid: true };
    const mm = state.managedMandate;
    const floorMs = Math.max(Date.now(), mm.maxSeenTimeMs);
    const result2 = refreshManagedMandate({ cedarDir: state.cedarDir, signer: mm.signer, now: new Date(floorMs) });
    if (!result2.valid || !result2.registry) {
      return {
        valid: false,
        code: result2.code || "mandate_registry_invalid",
        message: result2.message || "The mandate registry could not be verified."
      };
    }
    const history = result2.registry.history;
    if (mm.highWaterSequence > 0) {
      if (history.length < mm.highWaterSequence) {
        return { valid: false, code: "mandate_rollback_detected", message: "The mandate history is shorter than a state this gate already enforced. The registry was rolled back or truncated." };
      }
      const atMark = history[mm.highWaterSequence - 1];
      if (!atMark || receiptHash(atMark.transition_receipt) !== mm.highWaterHash) {
        return { valid: false, code: "mandate_history_forked", message: "The mandate history diverges from a state this gate already enforced. The registry was forked or rewritten." };
      }
    }
    mm.highWaterSequence = history.length;
    mm.highWaterHash = history.length ? receiptHash(history[history.length - 1].transition_receipt) : "";
    const latestTransitionMs = history.reduce((m, t) => Math.max(m, Date.parse(t.occurred_at) || 0), 0);
    mm.maxSeenTimeMs = Math.max(mm.maxSeenTimeMs, floorMs, latestTransitionMs);
    state.managedMandate.registry = result2.registry;
    if (state.policyDigest !== result2.registry.active.policy_digest || result2.expired_reverted) {
      const reloaded = loadCedarPolicies(state.cedarDir);
      if (reloaded.digest !== result2.registry.active.policy_digest) {
        return { valid: false, code: "policy_head_mismatch", message: "Reloaded policy bytes do not match the signed active mandate head." };
      }
      state.cedarPolicies = reloaded;
      state.policyDigest = reloaded.digest;
      state.cedarMtimeMs = newestCedarMtime(state.cedarDir);
      state.cedarCheckedMs = Date.now();
      if (result2.expired_reverted) {
        process.stderr.write(`[PROTECT_MCP] Mandate grant expired; restored signed baseline ${reloaded.digest}.
`);
      }
    }
    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      code: "mandate_registry_unreadable",
      message: `The managed mandate registry could not be read or verified (${error instanceof Error ? error.message : "unknown error"}). Failing closed until the signed policy state is restored.`
    };
  }
}
function maybeReloadCedar(state) {
  if (!state.cedarDir) return;
  if (state.managedMandate) return;
  const nowMs = Date.now();
  if (nowMs - state.cedarCheckedMs < CEDAR_CHECK_THROTTLE_MS) return;
  state.cedarCheckedMs = nowMs;
  const m = newestCedarMtime(state.cedarDir);
  if (m <= state.cedarMtimeMs) return;
  try {
    const reloaded = loadCedarPolicies(state.cedarDir);
    state.cedarPolicies = reloaded;
    state.policyDigest = reloaded.digest;
    state.cedarMtimeMs = m;
    process.stderr.write(`[PROTECT_MCP] Cedar policy reloaded (digest: ${reloaded.digest}) after on-disk change.
`);
  } catch (err) {
    process.stderr.write(`[PROTECT_MCP] Cedar reload failed, keeping the previous policy: ${err instanceof Error ? err.message : err}
`);
    state.cedarMtimeMs = m;
  }
}
function findCedarDir() {
  for (const candidate of ["cedar", "policies", "."]) {
    try {
      if ((0, import_node_fs17.existsSync)(candidate)) {
        const files = (0, import_node_fs17.readdirSync)(candidate, { encoding: "utf-8" });
        if (files.some((f) => f.endsWith(".cedar"))) {
          return candidate;
        }
      }
    } catch {
    }
  }
  return void 0;
}
function escapeHtml(value) {
  return value.replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char] || char);
}
function renderMandateApprovalPage(input) {
  const { proposal, controller } = input;
  const rows = (values, empty) => values.length ? values.map((value) => `<li><code>${escapeHtml(value)}</code></li>`).join("") : `<li class="muted">${escapeHtml(empty)}</li>`;
  const controllerId = JSON.stringify(controller.id);
  const proposalId = JSON.stringify(proposal.proposal_id);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve Policy Change | ScopeBlind</title>
<style>
  :root { color-scheme: light; --ink:#151515; --paper:#f7f5f0; --muted:#6d6b66; --line:#d8d3c9; --warn:#8b2b18; --ok:#22543d; }
  * { box-sizing:border-box; } body { margin:0; background:var(--paper); color:var(--ink); font:15px/1.5 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  main { max-width:860px; margin:0 auto; padding:48px 24px 72px; } .eyebrow { color:var(--muted); font:600 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing:.09em; text-transform:uppercase; }
  h1 { max-width:680px; font:600 clamp(30px,5vw,50px)/1.05 ui-serif, Georgia, serif; letter-spacing:-.035em; margin:12px 0 20px; } h2 { font-size:14px; letter-spacing:.04em; text-transform:uppercase; margin:0 0 12px; }
  .card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:22px; margin:16px 0; } .danger { border-left:4px solid var(--warn); } .meta { display:grid; grid-template-columns:1fr 1fr; gap:12px; font-size:13px; }
  .meta strong { display:block; font-size:11px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); } ul { margin:0; padding-left:20px; } li { margin:7px 0; } code { font:12px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap:anywhere; } .muted { color:var(--muted); }
  button { border:0; border-radius:8px; padding:13px 18px; color:white; background:#151515; cursor:pointer; font:600 15px/1 ui-sans-serif, sans-serif; } button:disabled { cursor:wait; opacity:.6; } #result { min-height:24px; margin:14px 0 0; font-weight:600; } .success { color:var(--ok); } .error { color:var(--warn); }
</style></head><body><main>
  <div class="eyebrow">ScopeBlind Legate \xB7 controller approval</div>
  <h1>You are approving exactly this policy change.</h1>
  <p class="muted">This is a time-limited change to a local enforcement gate. Your passkey approves this exact proposal digest, not a general permission for the agent to edit its mandate.</p>
  <section class="card danger"><h2>Why it was proposed</h2><p>${escapeHtml(proposal.reason)}</p><div class="meta"><div><strong>Blocked action</strong>${escapeHtml(proposal.denial_origin.tool)}</div><div><strong>Denied request</strong><code>${escapeHtml(proposal.denial_origin.request_id)}</code></div><div><strong>Current policy</strong><code>${escapeHtml(proposal.base_policy_digest)}</code></div><div><strong>Expires automatically</strong>${escapeHtml(proposal.expires_at)}</div></div></section>
  <section class="card"><h2>Plain-English diff</h2><ul>${rows(proposal.diff.plain_english, "No interpretable policy change.")}</ul></section>
  <section class="card"><h2>Executable statements added</h2><ul>${rows(proposal.diff.added_statements, "None.")}</ul></section>
  <section class="card"><h2>Executable statements removed</h2><ul>${rows(proposal.diff.removed_statements, "None.")}</ul></section>
  <section class="card"><h2>Controller</h2><p><strong>${escapeHtml(controller.label)}</strong><br><span class="muted">A user-verified passkey is required. This local page sends neither a portfolio nor agent prompt to ScopeBlind.</span></p><button id="approve">Approve this exact change</button><div id="result" role="status"></div></section>
<script>
const proposalId = ${proposalId}; const controllerId = ${controllerId};
const result = document.getElementById('result'); const button = document.getElementById('approve');
const toBytes = (s) => { const b = atob(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4 - s.length % 4) % 4)); return Uint8Array.from(b, c => c.charCodeAt(0)); };
const fromBytes = (buffer) => { const b = new Uint8Array(buffer); let out=''; for (const x of b) out += String.fromCharCode(x); return btoa(out).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); };
button.addEventListener('click', async () => { try {
  button.disabled = true; result.className = ''; result.textContent = 'Requesting a passkey for this exact policy diff...';
  const challengeResponse = await fetch('/mandate/proposals/' + encodeURIComponent(proposalId) + '/webauthn/challenge?controller_id=' + encodeURIComponent(controllerId));
  const challenge = await challengeResponse.json(); if (!challengeResponse.ok) throw new Error(challenge.message || challenge.error);
  const p = challenge.publicKey; p.challenge = toBytes(p.challenge); p.allowCredentials = p.allowCredentials.map(c => ({...c, id: toBytes(c.id)}));
  const credential = await navigator.credentials.get({ publicKey:p }); if (!credential) throw new Error('No passkey assertion was returned.');
  const response = credential.response;
  const assertion = { credentialId: fromBytes(credential.rawId), authenticatorData: fromBytes(response.authenticatorData), clientDataJSON: fromBytes(response.clientDataJSON), signature: fromBytes(response.signature), ...(response.userHandle ? { userHandle: fromBytes(response.userHandle) } : {}) };
  const approved = await fetch('/mandate/proposals/' + encodeURIComponent(proposalId) + '/webauthn/approve', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({assertion}) });
  const body = await approved.json(); if (!approved.ok) throw new Error(body.message || body.error);
  result.className = 'success'; result.textContent = 'Approved. The signed policy head is now active' + (body.expires_at ? ' until ' + body.expires_at : '') + '.'; button.remove();
} catch (error) { result.className = 'error'; result.textContent = 'Not approved: ' + (error && error.message ? error.message : String(error)); button.disabled = false; } });
</script></main></body></html>`;
}
function normalizeHookInput(raw) {
  const result2 = {};
  for (const [key, value] of Object.entries(raw)) {
    const camelKey = SNAKE_TO_CAMEL_MAP[key] || key;
    result2[camelKey] = value;
  }
  if (raw.source !== void 0 && raw.hook_event_name === "ConfigChange" && !raw.config_source) {
    result2["configSource"] = raw.source;
  }
  return result2;
}
var import_node_http2, import_node_crypto14, import_node_fs17, import_node_path14, DEFAULT_PORT, LOG_FILE3, RECEIPTS_FILE2, PAYLOAD_HASH_THRESHOLD, CEDAR_CHECK_THROTTLE_MS, SNAKE_TO_CAMEL_MAP;
var init_hook_server = __esm({
  "src/hook-server.ts"() {
    "use strict";
    import_node_http2 = require("http");
    import_node_crypto14 = require("crypto");
    import_node_fs17 = require("fs");
    import_node_path14 = require("path");
    init_cedar_evaluator();
    init_standard_gate();
    init_signing();
    init_acta_envelope();
    init_policy();
    init_http_server();
    init_scopeblind_bridge();
    init_action_readback();
    init_receipt_enrichment();
    init_mandate_lifecycle();
    DEFAULT_PORT = 9377;
    LOG_FILE3 = ".protect-mcp-log.jsonl";
    RECEIPTS_FILE2 = ".protect-mcp-receipts.jsonl";
    PAYLOAD_HASH_THRESHOLD = 1024;
    CEDAR_CHECK_THROTTLE_MS = 2e3;
    SNAKE_TO_CAMEL_MAP = {
      hook_event_name: "hookEventName",
      session_id: "sessionId",
      transcript_path: "transcriptPath",
      permission_mode: "permissionMode",
      agent_id: "agentId",
      agent_type: "agentType",
      tool_name: "toolName",
      tool_input: "toolInput",
      tool_use_id: "toolUseId",
      tool_response: "toolResult",
      // Claude Code sends tool_response, we read toolResult
      stop_hook_active: "stopHookActive",
      agent_transcript_path: "agentTranscriptPath",
      last_assistant_message: "lastAssistantMessage",
      teammate_name: "teammateName",
      team_name: "teamName",
      task_id: "taskId",
      task_subject: "taskSubject",
      task_description: "taskDescription",
      file_path: "filePath",
      config_path: "configPath",
      old_cwd: "oldCwd",
      new_cwd: "newCwd",
      notification_type: "notificationType",
      is_interrupt: "isInterrupt",
      error_details: "errorDetails",
      compact_summary: "compactSummary",
      custom_instructions: "customInstructions",
      worktree_path: "worktreePath",
      trigger_file_path: "triggerFilePath",
      parent_file_path: "parentFilePath",
      memory_type: "memoryType",
      load_reason: "loadReason",
      mcp_server_name: "mcpServerName",
      elicitation_id: "elicitationId",
      requested_schema: "requestedSchema",
      permission_suggestions: "permissionSuggestions"
    };
  }
});

// src/onboard.ts
var onboard_exports = {};
__export(onboard_exports, {
  ONBOARD_PACKS: () => ONBOARD_PACKS,
  handleOffboard: () => handleOffboard,
  handleOnboard: () => handleOnboard
});
function scenarioFor(id5) {
  return ONBOARD_PACKS.find((p) => p.id === id5)?.scenario;
}
function flag(argv, name) {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : void 0;
}
function has(argv, name) {
  return argv.includes(name);
}
function keypair() {
  const priv = (0, import_node_crypto15.randomBytes)(32);
  return { privateKey: (0, import_utils9.bytesToHex)(priv), publicKey: (0, import_utils9.bytesToHex)(import_ed255196.ed25519.getPublicKey(priv)), kid: "onboard", issuer: "protect-mcp" };
}
async function handleOnboard(argv) {
  const dir = flag(argv, "--dir") || (0, import_node_path15.join)(process.cwd(), "scopeblind-demo");
  const enforce = has(argv, "--enforce");
  const yes = has(argv, "--yes") || has(argv, "-y");
  const interactive = Boolean(process.stdin.isTTY) && !yes;
  let packId = flag(argv, "--pack") || (interactive ? "" : "research-safe");
  out();
  out(bold("  ScopeBlind protect-mcp \u2014 guided first run"));
  out(dim("  A governed demo and a verified receipt in a few minutes."));
  out(dim("  No account. No credentials. Everything stays on this machine."));
  out();
  out(bold("  Step 1/6  What this does, and what stays local"));
  out("  protect-mcp is a policy gate that sits in front of an AI agent's tools.");
  out("  It decides allow / block / needs-approval, and signs a receipt for each.");
  out(green("  Local by default: ") + "nothing is uploaded. No prompts, files, or keys leave this box.");
  out();
  const rl = interactive ? (0, import_promises.createInterface)({ input: process.stdin, output: process.stdout }) : null;
  try {
    out(bold("  Step 2/6  Choose what the agent is allowed to do"));
    if (interactive && !packId) {
      ONBOARD_PACKS.forEach((p, i) => {
        const pack2 = getPolicyPack(p.id);
        out(`    ${cyan(String(i + 1))}) ${bold(pack2.name)}  ${dim("(" + p.id + ")")}`);
        out(`       ${p.scenario.plainEnglish}`);
        out(dim(`       Tradeoff: ${p.scenario.tradeoff}`));
      });
      const ans = (await rl.question(cyan("  Pick a pack [1-" + ONBOARD_PACKS.length + ", default 1]: "))).trim();
      const idx = ans === "" ? 0 : Number(ans) - 1;
      packId = ONBOARD_PACKS[Number.isInteger(idx) && idx >= 0 && idx < ONBOARD_PACKS.length ? idx : 0].id;
    }
    const pack = getPolicyPack(packId);
    const scenario = scenarioFor(packId);
    if (!pack || !scenario) {
      out(red(`  Unknown onboarding pack: ${packId}. Options: ${ONBOARD_PACKS.map((p) => p.id).join(", ")}`));
      throw new Error(`unknown onboarding pack: ${packId}`);
    }
    out("  Selected: " + bold(pack.name) + dim(" (" + packId + ")"));
    out("  " + scenario.plainEnglish);
    out();
    out(bold("  Step 3/6  Set up a local workspace in " + dir));
    const force = has(argv, "--force");
    const existingCfg = (() => {
      try {
        return (0, import_node_fs18.existsSync)((0, import_node_path15.join)(dir, "protect-mcp.json")) ? JSON.parse((0, import_node_fs18.readFileSync)((0, import_node_path15.join)(dir, "protect-mcp.json"), "utf-8")) : null;
      } catch {
        return {};
      }
    })();
    if (existingCfg && existingCfg._scopeblind_onboarding !== true && !force) {
      out(red("  " + (0, import_node_path15.join)(dir, "protect-mcp.json") + " already exists and was not created by onboard."));
      out(red("  Refusing to overwrite a real workspace. Use --dir <a fresh folder>, or --force if you are sure."));
      throw new Error("onboard: refusing to overwrite a non-onboarding workspace at " + dir);
    }
    if (existingCfg && interactive && !yes) {
      const go = (await rl.question(yellow("  A demo workspace already exists there. Overwrite it? [y/N]: "))).trim().toLowerCase();
      if (go !== "y" && go !== "yes") {
        out(dim("  Cancelled. Pass --dir <path> to use a fresh folder."));
        return;
      }
    }
    (0, import_node_fs18.mkdirSync)((0, import_node_path15.join)(dir, "cedar"), { recursive: true });
    (0, import_node_fs18.mkdirSync)((0, import_node_path15.join)(dir, "keys"), { recursive: true });
    const kp = keypair();
    const keyPath = (0, import_node_path15.join)(dir, "keys", "gateway.json");
    (0, import_node_fs18.writeFileSync)(keyPath, JSON.stringify({ ...kp, generated_at: (/* @__PURE__ */ new Date()).toISOString(), warning: "KEEP THIS FILE SECRET." }, null, 2) + "\n");
    (0, import_node_fs18.writeFileSync)((0, import_node_path15.join)(dir, "keys", ".gitignore"), "*.json\n");
    (0, import_node_fs18.writeFileSync)((0, import_node_path15.join)(dir, "cedar", pack.files[0].path), pack.files[0].contents);
    (0, import_node_fs18.writeFileSync)((0, import_node_path15.join)(dir, "protect-mcp.json"), JSON.stringify({
      cedar_dir: "./cedar",
      default_tier: "unknown",
      signing: { key_path: "./keys/gateway.json", issuer: kp.issuer, enabled: true },
      _mode: enforce ? "enforce" : "shadow (default): observe and record, do not block",
      // Marker so `offboard --uninstall` knows this is a disposable onboarding
      // workspace and can safely remove the policy/config, not a real project.
      _scopeblind_onboarding: true
    }, null, 2) + "\n");
    await initSigning({ enabled: true, key_path: keyPath, issuer: kp.issuer });
    out(green("  \u2713 ") + "workspace, signing key, and the " + packId + " policy are ready.");
    out(enforce ? yellow("  Mode: ENFORCE (blocks in real time).") : "  Mode: " + bold("shadow") + dim(" (default) \u2014 observe and record, block nothing yet. Flip to --enforce when ready."));
    out();
    out(bold("  Step 4/6  Run a safe governed demo (synthetic actions, no real credentials)"));
    const policySet = policySetFromSource(pack.files[0].contents, pack.files[0].path);
    const receiptsPath = (0, import_node_path15.join)(dir, ".protect-mcp-receipts.jsonl");
    const logPath = (0, import_node_path15.join)(dir, ".protect-mcp-log.jsonl");
    for (const p of [receiptsPath, logPath]) if ((0, import_node_fs18.existsSync)(p)) (0, import_node_fs18.rmSync)(p, { force: true });
    const base = Date.parse("2026-07-10T12:00:00.000Z");
    let cedarEngine = true;
    const rows = [];
    for (const [i, a] of scenario.demoActions.entries()) {
      const context = a.context;
      const decision = await evaluateCedar(policySet, { tool: a.tool, tier: "unknown", toolInput: a.input, context });
      let allowed = decision.allowed;
      let simulated = false;
      if (decision.metadata && decision.metadata.fallback) {
        cedarEngine = false;
        simulated = true;
        allowed = a.expect === "allow";
      }
      const reason_code = simulated ? allowed ? "policy_simulated_allow" : "policy_simulated_deny" : allowed ? "policy_allow" : "cedar_deny";
      const entry = {
        v: 2,
        tool: a.tool,
        decision: allowed ? "allow" : "deny",
        reason_code,
        policy_digest: policySet.digest,
        request_id: `onboard-${i + 1}`,
        timestamp: base + i,
        mode: enforce ? "enforce" : "shadow",
        ...simulated ? {} : { policy_engine: "cedar" }
      };
      (0, import_node_fs18.appendFileSync)(logPath, JSON.stringify(entry) + "\n");
      const signed2 = signDecision(entry);
      if (signed2.signed) (0, import_node_fs18.appendFileSync)(receiptsPath, signed2.signed + "\n");
      rows.push({ label: a.label, tool: a.tool, allowed, simulated });
    }
    if (!cedarEngine) out(yellow("  Note: the Cedar engine (optional dep) is not installed here, so decisions are POLICY-SIMULATED from the pack. Install @cedar-policy/cedar-wasm for live evaluation."));
    out();
    out(bold("  Step 5/6  What the gate did"));
    for (const r of rows) {
      const verdict = r.allowed ? green("ALLOW") : red("BLOCK");
      out(`    ${verdict}  ${r.label}  ${dim(r.tool + (r.simulated ? " (simulated)" : ""))}`);
    }
    const blocked = rows.filter((r) => !r.allowed);
    out();
    if (blocked.length) {
      const n = bold(String(blocked.length) + " action" + (blocked.length === 1 ? "" : "s"));
      out("  " + n + (enforce ? " blocked in real time." : " would have been blocked once you turn on --enforce."));
      out(dim("  Every decision above is Ed25519-signed into a receipt you can verify offline."));
    }
    out();
    out(bold("  Step 6/6  Export an evidence pack and verify a receipt"));
    const receipts = (0, import_node_fs18.readFileSync)(receiptsPath, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const bundle = createAuditBundle({
      tenant: kp.issuer,
      receipts,
      signingKeys: [{ kty: "OKP", crv: "Ed25519", kid: kp.kid, x: Buffer.from(kp.publicKey, "hex").toString("base64url"), use: "sig" }]
    });
    const bundlePath = (0, import_node_path15.join)(dir, "audit-bundle.json");
    (0, import_node_fs18.writeFileSync)(bundlePath, JSON.stringify(bundle, null, 2) + "\n");
    const firstReceipt = receipts[0];
    const check = verifyReceipt(firstReceipt, kp.publicKey);
    out("  " + green("\u2713 ") + receipts.length + " signed receipts exported to " + dim("audit-bundle.json"));
    out("  " + (check.valid ? green("\u2713 receipt signature VERIFIED") : red("\u2717 receipt did not verify")) + " with your gate's public key, offline (no ScopeBlind account or service).");
    out(dim("  Re-verify the whole pack yourself with the open verifier:  npx @veritasacta/verify " + bundlePath + " --bundle"));
    out();
    out(bold("  What ScopeBlind sees"));
    out("  " + green("Local only.") + " These files live in " + dir + " and were never uploaded:");
    out(dim("    .protect-mcp-receipts.jsonl   the signed decision receipts"));
    out(dim("    audit-bundle.json             the offline-verifiable evidence pack"));
    out("  If you later opt into the hosted layer, it forwards the " + bold("signed decision receipts") + " themselves \u2014");
    out("  tool name, decision, reason, policy digest, request id, your gate's " + bold("public") + " key, and");
    out("  minimized action metadata (e.g. a redacted destination). It does " + bold("not") + " send raw prompts,");
    out("  raw tool inputs/outputs, or your " + bold("private") + " key. Nothing is sent unless you turn it on.");
    out();
    out(bold("  Optional: human approval + phone"));
    out("  To require a person to approve a specific action (with a passkey, and optionally a paired");
    out("  iPhone), set up a governed mandate:  " + cyan("protect-mcp mandate init --cedar " + (0, import_node_path15.join)(dir, "cedar") + " --controller-id ..."));
    out(dim("  (Desktop localhost WebAuthn is the tested route; paired-iPhone approval is a further step.)"));
    out();
    out(bold("  You are set up."));
    out("  Govern a real agent:  " + cyan("protect-mcp serve --enforce --cedar " + (0, import_node_path15.join)(dir, "cedar")));
    out("  See the local record:  " + cyan("protect-mcp record --dir " + dir));
    out("  Remove everything:     " + cyan("protect-mcp offboard --dir " + dir + " --uninstall"));
    out();
  } finally {
    rl?.close();
  }
}
async function handleOffboard(argv) {
  const dir = flag(argv, "--dir") || (0, import_node_path15.join)(process.cwd(), "scopeblind-demo");
  const yes = has(argv, "--yes") || has(argv, "-y");
  const interactive = Boolean(process.stdin.isTTY) && !yes;
  const all = has(argv, "--uninstall") || has(argv, "--all");
  const isOnboardingWorkspace = (() => {
    try {
      return JSON.parse((0, import_node_fs18.readFileSync)((0, import_node_path15.join)(dir, "protect-mcp.json"), "utf-8"))._scopeblind_onboarding === true;
    } catch {
      return false;
    }
  })();
  const fullTeardown = all && isOnboardingWorkspace;
  const deleteData = has(argv, "--delete-data") || fullTeardown;
  const deleteKeys = has(argv, "--delete-keys") || fullTeardown;
  const disable = has(argv, "--disable-enforcement") || all;
  if (!deleteData && !disable && !deleteKeys && !all) {
    out();
    out(bold("  protect-mcp offboard") + " \u2014 remove ScopeBlind cleanly from " + dir);
    out();
    out("  " + cyan("--delete-data") + "           delete local receipts, logs, record, and evidence packs");
    out("  " + cyan("--disable-enforcement") + "   remove protect-mcp hooks (the gate stops intercepting tools)");
    out("  " + cyan("--delete-keys") + "           delete the signing keypair (receipts become unverifiable)");
    out("  " + cyan("--uninstall") + "             all of the above, plus config and policies (workspaces created by onboard)");
    out("  " + dim("add --yes to skip the confirmation prompt"));
    out();
    return;
  }
  const dataFiles = [
    ".protect-mcp-receipts.jsonl",
    ".protect-mcp-log.jsonl",
    ".protect-mcp-approval-resolutions.jsonl",
    "audit-bundle.json",
    "record.html",
    "verification-results.json",
    "receipts"
  ];
  const teardownFiles = ["protect-mcp.json", "cedar", "coverage.json"];
  const targets = [];
  if (deleteData) {
    for (const f of dataFiles) if ((0, import_node_fs18.existsSync)((0, import_node_path15.join)(dir, f))) targets.push(f);
  }
  if (deleteKeys && (0, import_node_fs18.existsSync)((0, import_node_path15.join)(dir, "keys"))) targets.push("keys");
  if (fullTeardown) {
    for (const f of teardownFiles) if ((0, import_node_fs18.existsSync)((0, import_node_path15.join)(dir, f))) targets.push(f);
  }
  if (all && !isOnboardingWorkspace) {
    out();
    out(yellow("  Note: " + dir + " was not created by onboard, so --uninstall will NOT delete your"));
    out(yellow("  config, policies, keys, or receipts. It only removes protect-mcp hooks (below)."));
    out(yellow("  If you really want the local data or keys gone, pass --delete-data / --delete-keys."));
  }
  const settingsPath = (0, import_node_path15.join)(process.cwd(), ".claude", "settings.json");
  const hookHits = disable ? countProtectHooks(settingsPath) : 0;
  out();
  out(bold("  protect-mcp offboard") + " will remove, in " + dir + ":");
  if (targets.length) targets.forEach((t) => out(red("    - ") + t));
  if (hookHits > 0) out(red("    - ") + hookHits + " protect-mcp hook(s) from " + settingsPath);
  if (!targets.length && hookHits === 0) {
    out(dim("    (nothing to remove)"));
    out();
    return;
  }
  out();
  if (interactive) {
    const rl = (0, import_promises.createInterface)({ input: process.stdin, output: process.stdout });
    try {
      const go = (await rl.question(yellow("  Proceed? This cannot be undone. [y/N]: "))).trim().toLowerCase();
      if (go !== "y" && go !== "yes") {
        out(dim("  Cancelled."));
        return;
      }
    } finally {
      rl.close();
    }
  }
  for (const t of targets) {
    const p = (0, import_node_path15.join)(dir, t);
    try {
      (0, import_node_fs18.rmSync)(p, { recursive: (0, import_node_fs18.statSync)(p).isDirectory(), force: true });
      out(green("  \u2713 removed ") + t);
    } catch (e) {
      out(red("  \u2717 could not remove " + t + ": " + (e instanceof Error ? e.message : e)));
    }
  }
  if (hookHits > 0) {
    const removed = removeProtectHooks(settingsPath);
    out(green("  \u2713 removed ") + removed + " protect-mcp hook(s); the gate no longer intercepts tool calls");
  }
  if (fullTeardown && (0, import_node_fs18.existsSync)(dir)) {
    try {
      if ((0, import_node_fs18.readdirSync)(dir).length === 0) {
        (0, import_node_fs18.rmSync)(dir, { recursive: true, force: true });
        out(green("  \u2713 removed ") + "the empty workspace folder");
      }
    } catch {
    }
  }
  out();
  out(bold("  Done.") + " ScopeBlind has been " + (fullTeardown ? "fully uninstalled from this folder." : "cleaned up."));
  out();
}
function countProtectHooks(settingsPath) {
  if (!(0, import_node_fs18.existsSync)(settingsPath)) return 0;
  try {
    const s = JSON.parse((0, import_node_fs18.readFileSync)(settingsPath, "utf-8"));
    return protectHookCount(s?.hooks);
  } catch {
    return 0;
  }
}
function protectHookCount(hooks) {
  if (!hooks || typeof hooks !== "object") return 0;
  let n = 0;
  for (const groups of Object.values(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      const inner = g?.hooks;
      if (Array.isArray(inner)) {
        for (const h of inner) if (referencesProtect(h)) n++;
      }
    }
  }
  return n;
}
function referencesProtect(h) {
  if (!h || typeof h !== "object") return false;
  const o = h;
  const cmd = typeof o.command === "string" ? o.command : "";
  const url = typeof o.url === "string" ? o.url : "";
  const invokesProtect = /(^|[\s"'/@])protect-mcp(-mcp)?([\s"'/]|$)/.test(cmd);
  return invokesProtect || url.includes("protect-mcp");
}
function removeProtectHooks(settingsPath) {
  if (!(0, import_node_fs18.existsSync)(settingsPath)) return 0;
  let s;
  try {
    s = JSON.parse((0, import_node_fs18.readFileSync)(settingsPath, "utf-8"));
  } catch {
    return 0;
  }
  if (!s.hooks) return 0;
  let removed = 0;
  for (const [event, groups] of Object.entries(s.hooks)) {
    if (!Array.isArray(groups)) continue;
    const kept = [];
    for (const g of groups) {
      const inner = g?.hooks;
      if (Array.isArray(inner)) {
        const innerKept = inner.filter((h) => {
          if (referencesProtect(h)) {
            removed++;
            return false;
          }
          return true;
        });
        if (innerKept.length) kept.push({ ...g, hooks: innerKept });
      } else {
        kept.push(g);
      }
    }
    s.hooks[event] = kept;
  }
  (0, import_node_fs18.writeFileSync)(settingsPath, JSON.stringify(s, null, 2) + "\n");
  return removed;
}
var import_promises, import_node_fs18, import_node_path15, import_node_crypto15, import_ed255196, import_utils9, c, bold, dim, green, red, yellow, cyan, out, ONBOARD_PACKS;
var init_onboard = __esm({
  "src/onboard.ts"() {
    "use strict";
    import_promises = require("readline/promises");
    import_node_fs18 = require("fs");
    import_node_path15 = require("path");
    import_node_crypto15 = require("crypto");
    import_ed255196 = require("@noble/curves/ed25519");
    import_utils9 = require("@noble/hashes/utils");
    init_cedar_evaluator();
    init_signing();
    init_acta_envelope();
    init_bundle();
    init_policy_packs();
    c = (code2) => (s) => process.env.NO_COLOR ? s : `\x1B[${code2}m${s}\x1B[0m`;
    bold = c("1");
    dim = c("2");
    green = c("32");
    red = c("31");
    yellow = c("33");
    cyan = c("36");
    out = (s = "") => process.stdout.write(s + "\n");
    ONBOARD_PACKS = [
      {
        id: "research-safe",
        scenario: {
          plainEnglish: "A research agent can read files and search, but cannot email findings out or read your secrets.",
          tradeoff: "Blocks external sends and secret-file reads. If you WANT the agent to send, use email-safe with approval instead.",
          demoActions: [
            { tool: "read_file", input: { path: "/research/macro-notes.md" }, label: "Read a research note", expect: "allow" },
            { tool: "web_search", input: { query: "2026 rate outlook" }, label: "Search the web", expect: "allow" },
            { tool: "read_file", input: { path: "/home/analyst/.env" }, label: "Read a secrets file (.env)", expect: "deny" },
            { tool: "send_email", input: { to: "outside@example.com", subject: "my findings" }, label: "Email findings to an outside address", expect: "deny" }
          ]
        }
      },
      {
        id: "filesystem-safe",
        scenario: {
          plainEnglish: "The agent can read and write project files, but cannot delete files or run destructive shell commands.",
          tradeoff: "Blocks delete_file and rm -rf / mkfs / dd. Writes are still allowed; tighten write_file later if you want.",
          demoActions: [
            { tool: "read_file", input: { path: "/project/README.md" }, label: "Read a project file", expect: "allow" },
            { tool: "write_file", input: { path: "/project/draft.txt" }, label: "Write a draft file", expect: "allow" },
            { tool: "delete_file", input: { path: "/project/database.db" }, label: "Delete a file", expect: "deny" },
            { tool: "Bash", input: {}, context: { command: "rm -rf /project/build" }, label: "Run rm -rf", expect: "deny" }
          ]
        }
      },
      {
        id: "email-safe",
        scenario: {
          plainEnglish: "The agent can draft and read email, but cannot send anything on its own.",
          tradeoff: "Blocks every send tool. Drafting still works; add human approval to allow supervised sends.",
          demoActions: [
            { tool: "read_file", input: { path: "/drafts/reply.md" }, label: "Read a draft reply", expect: "allow" },
            { tool: "send_email", input: { to: "client@example.com", subject: "Update" }, label: "Send an email", expect: "deny" }
          ]
        }
      },
      {
        id: "git-safe",
        scenario: {
          plainEnglish: "The agent can use git normally, but cannot force-push, hard-reset, or delete branches/repos.",
          tradeoff: "Blocks history-rewriting and destructive git. Normal add/commit/status/pull still work.",
          demoActions: [
            { tool: "Bash", input: {}, context: { command: "git status" }, label: "Run git status", expect: "allow" },
            { tool: "Bash", input: {}, context: { command: "git push --force origin main" }, label: "Force-push to main", expect: "deny" }
          ]
        }
      },
      {
        id: "finance-mandate-safe",
        scenario: {
          plainEnglish: "A trading agent can book orders within the mandate, but cannot touch the restricted list or breach concentration caps.",
          tradeoff: "Blocks restricted-list bookings and single-name >10% / gross >200% / net >100%. The example caps are yours to set.",
          demoActions: [
            { tool: "pms.book", input: { symbol: "AAPL", side: "BUY", quantity: 50, on_restricted_list: false }, label: "Book an in-mandate order", expect: "allow" },
            { tool: "pms.book", input: { symbol: "RESTR", side: "BUY", quantity: 100, on_restricted_list: true }, label: "Book a RESTRICTED-list name", expect: "deny" },
            { tool: "order.execute", input: { symbol: "XYZ", post_trade_weight_bps: 1500 }, label: "Push a single name to 15% (cap is 10%)", expect: "deny" }
          ]
        }
      }
    ];
  }
});

// src/coverage.ts
var coverage_exports = {};
__export(coverage_exports, {
  DEFAULT_NOT_GOVERNED: () => DEFAULT_NOT_GOVERNED,
  RESIDUAL_BYPASS_ROUTES: () => RESIDUAL_BYPASS_ROUTES,
  analyzeBuiltInPolicy: () => analyzeBuiltInPolicy,
  buildCoverageStatement: () => buildCoverageStatement,
  handleCoverage: () => handleCoverage
});
function buildCoverageStatement(input) {
  const extras = (input.extraNotGoverned || []).map((s) => s.trim()).filter(Boolean);
  return {
    type: "scopeblind.coverage_statement.v1",
    generated_at: input.generatedAt || (/* @__PURE__ */ new Date()).toISOString(),
    package: { name: "protect-mcp", version: input.packageVersion },
    deployment: {
      mode: input.mode,
      enforcement: input.enforce ? "enforce" : "shadow",
      governed_channel: CHANNEL_DESCRIPTION[input.mode]
    },
    policy: {
      engine: input.engine,
      digest: input.policyDigest,
      source: input.policySource,
      ...input.policyFiles && input.policyFiles.length > 0 ? { files: input.policyFiles } : {}
    },
    governed: {
      tools_with_explicit_rules: [...input.governedTools].sort(),
      explicitly_blocked_tools: [...input.blockedTools].sort(),
      wildcard_rule: input.wildcardRule ?? null
    },
    not_governed: [...DEFAULT_NOT_GOVERNED, ...extras],
    residual_bypass_routes: RESIDUAL_BYPASS_ROUTES,
    self_test: input.probe,
    ...input.evaluatorSelfTest !== void 0 ? { evaluator_self_test: input.evaluatorSelfTest } : {},
    basis: "configuration-at-generation-time",
    attestation_note: ATTESTATION_NOTE
  };
}
function analyzeBuiltInPolicy(policy) {
  const names = Object.keys(policy.tools).filter((t) => t !== "*");
  const blocked = names.filter((t) => policy.tools[t]?.block === true);
  const wildcard = policy.tools["*"];
  const wildcardRule = wildcard ? Object.entries(wildcard).map(([k, v]) => `${k}: ${v}`).join(", ") : void 0;
  let probe;
  if (blocked.length > 0) {
    const probeTool = blocked[0];
    const effective = getToolPolicy(probeTool, policy);
    probe = {
      method: "static-policy-probe",
      probe_tool: probeTool,
      would_deny: effective.block === true
    };
  } else {
    probe = {
      method: "none",
      reason: "policy declares no explicitly blocked tool to probe"
    };
  }
  return { governedTools: names, blockedTools: blocked, wildcardRule, probe };
}
function parseCoverageArgs(args) {
  let mode;
  let enforce = false;
  let policyPath;
  let cedarDir;
  let out2 = "scopeblind-coverage.json";
  let json2 = false;
  const extraNotGoverned = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--mode" && args[i + 1]) mode = args[++i];
    else if (args[i] === "--enforce") enforce = true;
    else if (args[i] === "--policy" && args[i + 1]) policyPath = args[++i];
    else if (args[i] === "--cedar" && args[i + 1]) cedarDir = args[++i];
    else if (args[i] === "--out" && args[i + 1]) out2 = args[++i];
    else if (args[i] === "--json") json2 = true;
    else if (args[i] === "--not-governed" && args[i + 1]) {
      extraNotGoverned.push(...args[++i].split(",").map((s) => s.trim()).filter(Boolean));
    }
  }
  return { mode, enforce, policyPath, cedarDir, out: out2, json: json2, extraNotGoverned };
}
async function handleCoverage(args) {
  const opts = parseCoverageArgs(args);
  if (opts.mode !== "hook" && opts.mode !== "proxy") {
    process.stderr.write(
      'Usage: protect-mcp coverage --mode <hook|proxy> [--enforce] [--policy <path> | --cedar <dir>]\n                            [--not-governed "<item>,<item>"] [--out <file>] [--json]\n\n--mode is required: the deployment mode is a fact the operator declares, not one the CLI can guess.\n'
    );
    process.exitCode = 1;
    return;
  }
  const version = process.env.PROTECT_MCP_VERSION || "unknown";
  const evaluatorSelfTest = await runEvaluatorSelfTest();
  let statement;
  let signingConfig;
  if (opts.cedarDir) {
    const set = loadCedarPolicies(opts.cedarDir);
    statement = buildCoverageStatement({
      mode: opts.mode,
      enforce: opts.enforce,
      engine: "cedar",
      policyDigest: set.digest,
      policySource: opts.cedarDir,
      policyFiles: set.files,
      // Cedar governs by predicate over (principal, action, resource), not a
      // static tool list; the enumerable surface is the policy files themselves.
      governedTools: [],
      blockedTools: [],
      probe: {
        method: "none",
        reason: "cedar policies are evaluated per-request; a static probe would not exercise the WASM evaluation path. Run the gate with --enforce to exercise live evaluation."
      },
      extraNotGoverned: opts.extraNotGoverned,
      evaluatorSelfTest,
      packageVersion: version
    });
  } else if (opts.policyPath) {
    const loaded = loadPolicy(opts.policyPath);
    signingConfig = loaded.signing;
    const analyzed = analyzeBuiltInPolicy(loaded.policy);
    statement = buildCoverageStatement({
      mode: opts.mode,
      enforce: opts.enforce,
      engine: "built-in",
      policyDigest: loaded.digest,
      policySource: opts.policyPath,
      governedTools: analyzed.governedTools,
      blockedTools: analyzed.blockedTools,
      wildcardRule: analyzed.wildcardRule,
      probe: analyzed.probe,
      extraNotGoverned: opts.extraNotGoverned,
      evaluatorSelfTest,
      packageVersion: version
    });
  } else {
    statement = buildCoverageStatement({
      mode: opts.mode,
      enforce: opts.enforce,
      engine: "none",
      policyDigest: "none",
      policySource: "no policy loaded (allow-all default)",
      governedTools: [],
      blockedTools: [],
      probe: { method: "none", reason: "no policy loaded; the gate would allow all tool calls" },
      extraNotGoverned: opts.extraNotGoverned,
      evaluatorSelfTest,
      packageVersion: version
    });
  }
  let output;
  if (signingConfig) {
    const warnings = await initSigning(signingConfig);
    for (const w of warnings) process.stderr.write(`[protect-mcp] Warning: ${w}
`);
    if (!isSigningEnabled()) {
      process.stderr.write(
        "[protect-mcp] coverage: signing is configured in the policy but no signer is ready. Refusing to emit an unsigned statement where a signed one was promised.\n"
      );
      process.exitCode = 1;
      return;
    }
    const signed2 = signGenericArtifact("coverage_statement", statement);
    if (!signed2.ok || !signed2.signed) {
      process.stderr.write(`[protect-mcp] coverage: signing failed: ${signed2.error || "unknown error"}
`);
      process.exitCode = 1;
      return;
    }
    output = JSON.parse(signed2.signed);
  } else {
    output = {
      artifact: statement,
      signature: null,
      unsigned_reason: "no signing configured in the policy file; this statement is a declaration, not evidence. Add a signing block (protect-mcp init) to emit a verifiable statement."
    };
  }
  const serialized = JSON.stringify(output, null, 2) + "\n";
  (0, import_node_fs19.writeFileSync)(opts.out, serialized);
  if (opts.json) process.stdout.write(serialized);
  const signer = getSignerInfo();
  process.stderr.write(
    `[protect-mcp] coverage statement written to ${opts.out}
  mode        : ${statement.deployment.mode} (${statement.deployment.enforcement})
  policy      : ${statement.policy.engine} digest ${statement.policy.digest}
  governed    : ${statement.governed.tools_with_explicit_rules.length} tools with explicit rules${statement.governed.explicitly_blocked_tools.length ? `, ${statement.governed.explicitly_blocked_tools.length} explicitly blocked` : ""}
  not governed: ${statement.not_governed.length} declared items (defaults cannot be removed)
  self test   : ${statement.self_test.method}${statement.self_test.would_deny !== void 0 ? ` (would_deny=${statement.self_test.would_deny})` : ""}
  evaluator   : live self-test ${evaluatorSelfTest.passed ? "passed" : "FAILED"} (${evaluatorSelfTest.cases.length} vectors)
  signed      : ${signer ? `yes (kid ${signer.kid})` : "no (unsigned declaration)"}
`
  );
}
var import_node_fs19, DEFAULT_NOT_GOVERNED, RESIDUAL_BYPASS_ROUTES, ATTESTATION_NOTE, CHANNEL_DESCRIPTION;
var init_coverage = __esm({
  "src/coverage.ts"() {
    "use strict";
    import_node_fs19 = require("fs");
    init_policy();
    init_cedar_evaluator();
    init_signing();
    DEFAULT_NOT_GOVERNED = [
      "tool calls made to any second, ungated MCP server the agent is also configured to reach",
      "direct network egress from the agent runtime that is not expressed as a gated tool call",
      "in-process capabilities never registered as gated tools (e.g. a code interpreter writing files)",
      "anything a downstream system does after a gated tool call returns"
    ];
    RESIDUAL_BYPASS_ROUTES = [
      {
        vector: "second ungated tool server",
        closed_by: "single-endpoint configuration; this statement makes the extra server visible",
        residual_risk: "operator misconfiguration (visible, auditable)"
      },
      {
        vector: "direct network egress",
        closed_by: "egress lockdown: the runtime can only reach the gate",
        residual_risk: "container or host escape (shared-tenancy risk)"
      },
      {
        vector: "unregistered in-process capability",
        closed_by: "register every consequential capability as a gated tool; this statement enumerates what is gated",
        residual_risk: "a capability the operator forgot to route (visible in this statement)"
      },
      {
        vector: "harness misconfiguration",
        closed_by: "hook wiring audit; enforce-mode startup checks",
        residual_risk: "harness bug (rare, detectable)"
      },
      {
        vector: "post-return effects",
        closed_by: "out of scope by design: the gate governs the decision to call, not the callee internals",
        residual_risk: "downstream system behavior (not this layer)"
      }
    ];
    ATTESTATION_NOTE = "This statement enumerates what the gate is configured to govern and declares what it does not see. It is a scope declaration, not a proof of the absence of other action paths: making the gate the only path is a deployment property (single-endpoint configuration, or egress lockdown for a hard guarantee). Shadow enforcement observes and receipts but does not block. The statement reflects configuration at generation time; a statement emitted by the running gateway (observed coverage, with intended-versus-observed mismatch flagging) is on the roadmap. In enforce mode the gate refuses to arm unless the live restraint self-test passes.";
    CHANNEL_DESCRIPTION = {
      hook: "every tool call the agent harness routes through the pre-tool-call hook",
      proxy: "every call made to the gate HTTP endpoint wrapping the tool server"
    };
  }
});

// src/http-transport.ts
var http_transport_exports = {};
__export(http_transport_exports, {
  startHttpTransport: () => startHttpTransport
});
async function startHttpTransport(options2) {
  const { port, config, serverCommand } = options2;
  const sseClients = /* @__PURE__ */ new Set();
  const httpConfig = {
    ...config,
    command: serverCommand[0],
    args: serverCommand.slice(1)
  };
  const gateway = new ProtectGateway(httpConfig);
  if (options2.cedarPolicySet) {
    gateway.setCedarPolicies(options2.cedarPolicySet);
  }
  await gateway.startForHttp();
  const server = (0, import_node_http3.createServer)(async (req, res) => {
    const origin = req.headers.origin || "*";
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url || "/", `http://localhost:${port}`);
    if (url.pathname === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        server: "protect-mcp",
        version: process.env.PROTECT_MCP_VERSION || "unknown",
        transport: "streamable-http",
        mode: config.policy ? config.enforce ? "enforce" : "shadow" : "shadow",
        wrapping: serverCommand.join(" ")
      }));
      return;
    }
    if (url.pathname === "/mcp/sse" && req.method === "GET") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      });
      res.write(`data: ${JSON.stringify({ type: "connected", server: "protect-mcp" })}

`);
      sseClients.add(res);
      req.on("close", () => sseClients.delete(res));
      return;
    }
    if (url.pathname === "/mcp" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", async () => {
        try {
          const jsonRpc = JSON.parse(body);
          const acceptSSE = (req.headers.accept || "").includes("text/event-stream");
          const responseStr = await gateway.processRequest(jsonRpc);
          const response = JSON.parse(responseStr);
          if (acceptSSE) {
            res.writeHead(200, {
              "Content-Type": "text/event-stream",
              "Cache-Control": "no-cache"
            });
            res.write(`data: ${JSON.stringify(response)}

`);
            res.end();
          } else {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(response));
          }
          if (jsonRpc.method === "tools/call") {
            const event = {
              type: "decision",
              tool: jsonRpc.params?.name,
              timestamp: (/* @__PURE__ */ new Date()).toISOString()
            };
            for (const client of sseClients) {
              try {
                client.write(`data: ${JSON.stringify(event)}

`);
              } catch {
                sseClients.delete(client);
              }
            }
          }
        } catch (err) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32700, message: "Parse error" },
            id: null
          }));
        }
      });
      return;
    }
    if (url.pathname === "/mcp" && req.method === "DELETE") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "session_closed" }));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: "not_found",
      endpoints: [
        "POST /mcp          \u2014 JSON-RPC endpoint (Streamable HTTP)",
        "GET  /mcp/sse      \u2014 Server-Sent Events stream",
        "GET  /health       \u2014 Health check",
        "DELETE /mcp        \u2014 Close session"
      ]
    }));
  });
  server.listen(port, () => {
    process.stderr.write(`
[PROTECT_MCP] HTTP transport listening on http://0.0.0.0:${port}
`);
    process.stderr.write(`  POST   /mcp        \u2014 JSON-RPC (Streamable HTTP)
`);
    process.stderr.write(`  GET    /mcp/sse    \u2014 Server-Sent Events
`);
    process.stderr.write(`  GET    /health     \u2014 Health check
`);
    process.stderr.write(`  DELETE /mcp        \u2014 Close session
`);
    process.stderr.write(`
  Wrapping: ${serverCommand.join(" ")}
`);
    process.stderr.write(`  Mode: ${config.enforce ? "enforce" : "shadow"}

`);
  });
  const shutdown = () => {
    process.stderr.write("\n[PROTECT_MCP] Shutting down HTTP transport...\n");
    for (const client of sseClients) {
      try {
        client.end();
      } catch {
      }
    }
    server.close();
    gateway.stop();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
var import_node_http3;
var init_http_transport = __esm({
  "src/http-transport.ts"() {
    "use strict";
    import_node_http3 = require("http");
    init_gateway();
  }
});

// src/report.ts
var report_exports = {};
__export(report_exports, {
  formatReportMarkdown: () => formatReportMarkdown,
  generateReport: () => generateReport
});
function generateReport(logPath, receiptPath, periodDays) {
  const now = /* @__PURE__ */ new Date();
  const from = new Date(now.getTime() - periodDays * 864e5);
  const entries = [];
  if ((0, import_node_fs20.existsSync)(logPath)) {
    const raw = (0, import_node_fs20.readFileSync)(logPath, "utf-8");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const jsonStr = trimmed.replace(/^\[PROTECT_MCP\]\s*/, "");
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed.tool && parsed.decision && parsed.timestamp) {
          const entryTime = typeof parsed.timestamp === "number" && parsed.timestamp > 1e12 ? parsed.timestamp : parsed.timestamp * 1e3;
          if (entryTime >= from.getTime()) {
            entries.push(parsed);
          }
        }
      } catch {
      }
    }
  }
  let receiptsSigned = 0;
  let signerKid = "";
  let signerIssuer = "";
  if ((0, import_node_fs20.existsSync)(receiptPath)) {
    const raw = (0, import_node_fs20.readFileSync)(receiptPath, "utf-8");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.signature) {
          receiptsSigned++;
          const identity = receiptIdentity(parsed);
          if (identity.kid && !signerKid) signerKid = identity.kid;
          if (identity.issuer && !signerIssuer) signerIssuer = identity.issuer;
        }
      } catch {
      }
    }
  }
  const toolMap = /* @__PURE__ */ new Map();
  const tiers = /* @__PURE__ */ new Set();
  const policyDigests = /* @__PURE__ */ new Map();
  let allowed = 0;
  let blocked = 0;
  let rateLimited = 0;
  let approvalRequired = 0;
  for (const entry of entries) {
    const tool = entry.tool;
    if (!toolMap.has(tool)) {
      toolMap.set(tool, { total: 0, allowed: 0, blocked: 0, rate_limited: 0, approval_required: 0 });
    }
    const tm = toolMap.get(tool);
    tm.total++;
    if (entry.decision === "allow") {
      allowed++;
      tm.allowed++;
    } else if (entry.decision === "deny" && entry.reason_code === "rate_limit_exceeded") {
      rateLimited++;
      tm.rate_limited++;
    } else if (entry.decision === "deny" && entry.reason_code === "require_approval") {
      approvalRequired++;
      tm.approval_required++;
    } else {
      blocked++;
      tm.blocked++;
    }
    if (entry.tier) tiers.add(entry.tier);
    if (entry.policy_digest && !policyDigests.has(entry.policy_digest)) {
      policyDigests.set(entry.policy_digest, new Date(entry.timestamp).toISOString());
    }
  }
  const policyChanges = Array.from(policyDigests.entries()).map(([digest, at2]) => ({
    at: at2,
    policy_digest: digest
  })).sort((a, b) => a.at.localeCompare(b.at));
  return {
    generated_at: now.toISOString(),
    period: { from: from.toISOString(), to: now.toISOString() },
    signing_identity: signerKid ? { kid: signerKid, issuer: signerIssuer } : null,
    summary: {
      total_decisions: entries.length,
      allowed,
      blocked,
      rate_limited: rateLimited,
      approval_required: approvalRequired,
      unique_tools: toolMap.size,
      unique_tiers: tiers.size
    },
    tool_breakdown: Array.from(toolMap.entries()).map(([tool, stats]) => ({ tool, ...stats })).sort((a, b) => b.total - a.total),
    policy_changes: policyChanges,
    verification: {
      receipts_signed: receiptsSigned,
      receipts_unsigned: entries.length - receiptsSigned,
      verify_command: "npx @veritasacta/verify audit-bundle.json --bundle"
    }
  };
}
function formatReportMarkdown(report) {
  const lines = [];
  lines.push("# ScopeBlind Compliance Report");
  lines.push("");
  lines.push(`**Generated:** ${report.generated_at}`);
  lines.push(`**Period:** ${report.period.from.split("T")[0]} to ${report.period.to.split("T")[0]}`);
  if (report.signing_identity) {
    lines.push(`**Signing identity:** kid \`${report.signing_identity.kid}\`, issuer \`${report.signing_identity.issuer}\``);
  }
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total decisions | ${report.summary.total_decisions} |`);
  lines.push(`| Allowed | ${report.summary.allowed} |`);
  lines.push(`| Blocked | ${report.summary.blocked} |`);
  lines.push(`| Rate-limited | ${report.summary.rate_limited} |`);
  lines.push(`| Approval required | ${report.summary.approval_required} |`);
  lines.push(`| Unique tools | ${report.summary.unique_tools} |`);
  lines.push(`| Unique tiers | ${report.summary.unique_tiers} |`);
  lines.push("");
  if (report.tool_breakdown.length > 0) {
    lines.push("## Tool Breakdown");
    lines.push("");
    lines.push("| Tool | Total | Allowed | Blocked | Rate-limited | Approval |");
    lines.push("|------|-------|---------|---------|--------------|----------|");
    for (const t of report.tool_breakdown) {
      lines.push(`| \`${t.tool}\` | ${t.total} | ${t.allowed} | ${t.blocked} | ${t.rate_limited} | ${t.approval_required} |`);
    }
    lines.push("");
  }
  if (report.policy_changes.length > 0) {
    lines.push("## Policy History");
    lines.push("");
    lines.push("| Timestamp | Policy Digest |");
    lines.push("|-----------|--------------|");
    for (const pc of report.policy_changes) {
      lines.push(`| ${pc.at} | \`${pc.policy_digest}\` |`);
    }
    lines.push("");
  }
  lines.push("## Verification");
  lines.push("");
  lines.push(`- Receipts signed: **${report.verification.receipts_signed}**`);
  lines.push(`- Receipts unsigned: **${report.verification.receipts_unsigned}**`);
  lines.push("");
  lines.push("Verify the audit bundle:");
  lines.push("");
  lines.push("```bash");
  lines.push(report.verification.verify_command);
  lines.push("```");
  lines.push("");
  lines.push("The verifier is MIT-licensed and works offline. No ScopeBlind account required.");
  lines.push("");
  lines.push("---");
  lines.push("*Generated by protect-mcp \xB7 scopeblind.com*");
  return lines.join("\n");
}
var import_node_fs20;
var init_report = __esm({
  "src/report.ts"() {
    "use strict";
    import_node_fs20 = require("fs");
    init_acta_envelope();
  }
});

// src/cli.ts
init_gateway();
init_policy();
init_signing();
init_acta_envelope();
init_policy_digest();
init_acta_envelope();
init_credentials();

// src/simulate.ts
var import_node_fs9 = require("fs");
init_policy();
init_admission();
function parseLogFile(path) {
  const raw = (0, import_node_fs9.readFileSync)(path, "utf-8");
  const entries = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const jsonStr = trimmed.replace(/^\[PROTECT_MCP\]\s*/, "");
    try {
      const parsed = JSON.parse(jsonStr);
      if (parsed.tool && parsed.decision) {
        entries.push(parsed);
      }
    } catch {
    }
  }
  return entries;
}
function simulate(entries, policy, tier = "unknown") {
  const rateLimitStore = /* @__PURE__ */ new Map();
  const toolResults = /* @__PURE__ */ new Map();
  const totals = {
    allow: 0,
    block: 0,
    rate_limited: 0,
    require_approval: 0,
    tier_insufficient: 0
  };
  const originalTotals = { allow: 0, deny: 0 };
  const changes = [];
  for (const entry of entries) {
    const toolName = entry.tool;
    const toolPolicy = getToolPolicy(toolName, policy);
    if (entry.decision === "allow") {
      originalTotals.allow++;
    } else {
      originalTotals.deny++;
    }
    let newDecision;
    if (toolPolicy.block) {
      newDecision = "block";
    } else if (toolPolicy.min_tier && !meetsMinTier(tier, toolPolicy.min_tier)) {
      newDecision = "tier_insufficient";
    } else if (toolPolicy.require_approval) {
      newDecision = "require_approval";
    } else if (toolPolicy.rate_limit) {
      const limit = parseRateLimit(toolPolicy.rate_limit);
      const result2 = checkRateLimit(toolName, limit, rateLimitStore);
      newDecision = result2.allowed ? "allow" : "rate_limited";
    } else {
      newDecision = "allow";
    }
    totals[newDecision]++;
    if (!toolResults.has(toolName)) {
      toolResults.set(toolName, {
        tool: toolName,
        calls: 0,
        results: { allow: 0, block: 0, rate_limited: 0, require_approval: 0, tier_insufficient: 0 },
        original: { allow: 0, deny: 0 }
      });
    }
    const tr = toolResults.get(toolName);
    tr.calls++;
    tr.results[newDecision]++;
    if (entry.decision === "allow") {
      tr.original.allow++;
    } else {
      tr.original.deny++;
    }
  }
  for (const [tool, result2] of toolResults) {
    const wasAllBlocked = result2.original.allow === 0;
    const nowAllBlocked = result2.results.allow === 0;
    const wasAllAllowed = result2.original.deny === 0;
    if (wasAllAllowed && result2.results.block > 0) {
      changes.push(`${tool}: ${result2.results.block} calls would be blocked (was: all allowed)`);
    }
    if (wasAllAllowed && result2.results.rate_limited > 0) {
      changes.push(`${tool}: ${result2.results.rate_limited} calls would be rate-limited (was: all allowed)`);
    }
    if (wasAllAllowed && result2.results.require_approval > 0) {
      changes.push(`${tool}: ${result2.results.require_approval} calls would require approval (was: all allowed)`);
    }
    if (wasAllAllowed && result2.results.tier_insufficient > 0) {
      changes.push(`${tool}: ${result2.results.tier_insufficient} calls would fail tier check (was: all allowed)`);
    }
    if (wasAllBlocked && result2.results.allow > 0 && !nowAllBlocked) {
      changes.push(`${tool}: ${result2.results.allow} calls would now be allowed (was: all blocked)`);
    }
  }
  return {
    policy_file: "",
    log_file: "",
    total_calls: entries.length,
    results: totals,
    original: originalTotals,
    tool_breakdown: Array.from(toolResults.values()).sort((a, b) => b.calls - a.calls),
    changes
  };
}
function formatSimulation(summary) {
  const lines = [];
  lines.push(`Simulating ${summary.policy_file} against ${summary.total_calls} recorded tool calls:
`);
  const maxToolLen = Math.max(...summary.tool_breakdown.map((t) => t.tool.length), 4);
  for (const tr of summary.tool_breakdown) {
    const parts = [];
    if (tr.results.allow > 0) parts.push(`${tr.results.allow} allow`);
    if (tr.results.block > 0) parts.push(`\x1B[31m${tr.results.block} blocked\x1B[0m`);
    if (tr.results.rate_limited > 0) parts.push(`\x1B[33m${tr.results.rate_limited} rate_limited\x1B[0m`);
    if (tr.results.require_approval > 0) parts.push(`\x1B[36m${tr.results.require_approval} require_approval\x1B[0m`);
    if (tr.results.tier_insufficient > 0) parts.push(`\x1B[35m${tr.results.tier_insufficient} tier_insufficient\x1B[0m`);
    const originalParts = [];
    if (tr.original.allow > 0) originalParts.push(`${tr.original.allow} allow`);
    if (tr.original.deny > 0) originalParts.push(`${tr.original.deny} deny`);
    lines.push(`  ${tr.tool.padEnd(maxToolLen)}  \xD7 ${String(tr.calls).padStart(3)} \u2192 ${parts.join(", ")}  (was: ${originalParts.join(", ")})`);
  }
  lines.push("");
  lines.push(`Summary: ${summary.results.allow} allow, ${summary.results.block} blocked, ${summary.results.rate_limited} rate_limited, ${summary.results.require_approval} require_approval, ${summary.results.tier_insufficient} tier_insufficient`);
  lines.push(`  vs original: ${summary.original.allow} allow, ${summary.original.deny} deny`);
  if (summary.changes.length > 0) {
    lines.push("");
    lines.push("Changes:");
    for (const change of summary.changes) {
      lines.push(`  \u2022 ${change}`);
    }
  }
  return lines.join("\n");
}

// src/cli.ts
init_action_readback();
init_cedar_evaluator();
init_standard_gate();
init_policy_packs();

// src/connector-pilots.ts
var import_node_fs10 = require("fs");
var import_node_path6 = require("path");
var defaultPermit2 = `
// Default posture: observe all non-matching tools so the connector can be piloted in shadow mode.
permit(principal, action == Action::"MCP::Tool::call", resource);
`;
var nautilusBridgePy = String.raw`#!/usr/bin/env python3
"""
ScopeBlind external bridge for NautilusTrader-compatible pilots.

This file is intentionally outside NautilusTrader. It gives protect-mcp a stable
JSONL command boundary for staging, approval-gated submission, cancellation, and
event export while keeping the trading engine customer-owned.

Mock mode runs without NautilusTrader installed. Real mode is enabled by setting
NAUTILUS_BRIDGE_MODULE to "module.path:ClassName"; the class may implement:
  submit_order(order), modify_order(order), cancel_order(order), reconcile(order),
  export_events(since=None)
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class BridgeState:
    root: Path = field(default_factory=lambda: Path(os.environ.get("SCOPEBLIND_NAUTILUS_STATE_DIR", ".protect-mcp/nautilus")))

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.orders_path.touch(exist_ok=True)
        self.events_path.touch(exist_ok=True)

    @property
    def orders_path(self) -> Path:
        return self.root / "orders.jsonl"

    @property
    def events_path(self) -> Path:
        return self.root / "events.jsonl"

    def append_order(self, order: dict[str, Any]) -> None:
        with self.orders_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(order) + "\n")

    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        enriched = {
            "event_id": event.get("event_id") or f"nt-{now_ms()}-{len(event)}",
            "observed_at_ms": now_ms(),
            **event,
        }
        enriched["event_digest"] = sha256_json(enriched)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(enriched) + "\n")
        return enriched

    def events(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        with self.events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    rows.append(json.loads(line))
        return rows


class ScopeBlindNautilusBridge:
    def __init__(self) -> None:
        self.state = BridgeState()
        self.real = self._load_real_bridge()

    def _load_real_bridge(self) -> Any | None:
        target = os.environ.get("NAUTILUS_BRIDGE_MODULE")
        if not target:
            return None
        module_name, _, class_name = target.partition(":")
        if not module_name or not class_name:
            raise ValueError("NAUTILUS_BRIDGE_MODULE must be module.path:ClassName")
        module = importlib.import_module(module_name)
        return getattr(module, class_name)()

    def handle(self, command: dict[str, Any]) -> dict[str, Any]:
        action = command.get("action")
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "stage_order": self.stage_order,
            "submit_order": self.submit_order,
            "modify_order": self.modify_order,
            "cancel_order": self.cancel_order,
            "reconcile": self.reconcile,
            "export_events": self.export_events,
        }
        if action not in handlers:
            return self.error(command, "unknown_action", f"Unsupported action: {action}")
        try:
            return handlers[action](command)
        except Exception as exc:
            return self.error(command, "bridge_error", str(exc))

    def require(self, command: dict[str, Any], *fields: str) -> None:
        missing = [field for field in fields if command.get(field) in (None, "")]
        if missing:
            raise ValueError(f"missing required field(s): {', '.join(missing)}")

    def require_approved(self, command: dict[str, Any]) -> None:
        self.require(command, "approval_receipt")
        if command.get("mandate_passed") is not True:
            raise ValueError("mandate_passed must be true before live order mutation")

    def stage_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require(command, "client_order_id", "instrument_id", "side", "quantity")
        order = self.order_projection(command, status="staged")
        self.state.append_order(order)
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_staged.v1",
            "client_order_id": order["client_order_id"],
            "order_digest": sha256_json(order),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "staged", "order": order, "event": event})

    def submit_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        order = self.order_projection(command, status="submitted")
        if self.real and hasattr(self.real, "submit_order"):
            external = self.real.submit_order(order)
        else:
            external = {"mode": "mock", "external_order_id": f"MOCK-{order['client_order_id']}"}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_submitted.v1",
            "client_order_id": order["client_order_id"],
            "order_digest": sha256_json(order),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "submitted", "order": order, "external": external, "event": event})

    def modify_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "modify_order"):
            external = self.real.modify_order(command)
        else:
            external = {"mode": "mock", "modified": command["client_order_id"]}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_modified.v1",
            "client_order_id": command["client_order_id"],
            "command_digest": sha256_json(command),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "modified", "external": external, "event": event})

    def cancel_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "cancel_order"):
            external = self.real.cancel_order(command)
        else:
            external = {"mode": "mock", "cancelled": command["client_order_id"]}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_cancelled.v1",
            "client_order_id": command["client_order_id"],
            "command_digest": sha256_json(command),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "cancelled", "external": external, "event": event})

    def reconcile(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "reconcile"):
            external = self.real.reconcile(command)
        else:
            external = {"mode": "mock", "client_order_id": command["client_order_id"], "state": "accepted"}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.reconciled.v1",
            "client_order_id": command["client_order_id"],
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "reconciled", "external": external, "event": event})

    def export_events(self, command: dict[str, Any]) -> dict[str, Any]:
        if self.real and hasattr(self.real, "export_events"):
            external_events = self.real.export_events(command.get("since"))
        else:
            external_events = self.state.events()
        return self.ok(command, {
            "status": "exported",
            "event_count": len(external_events),
            "commitment_root": sha256_json(external_events),
            "events": external_events,
        })

    def order_projection(self, command: dict[str, Any], status: str) -> dict[str, Any]:
        return {
            "client_order_id": command["client_order_id"],
            "instrument_id": command["instrument_id"],
            "side": command["side"],
            "quantity": command["quantity"],
            "price": command.get("price"),
            "time_in_force": command.get("time_in_force", "GTC"),
            "strategy_id": command.get("strategy_id"),
            "mandate_digest": command.get("mandate_digest"),
            "approval_receipt": command.get("approval_receipt"),
            "status": status,
            "created_at_ms": now_ms(),
        }

    def ok(self, command: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "bridge": "scopeblind.nautilus.external.v1",
            "mode": "real" if self.real else "mock",
            "request_digest": sha256_json(command),
            **result,
        }

    def error(self, command: dict[str, Any], code: str, message: str) -> dict[str, Any]:
        return {
            "ok": False,
            "bridge": "scopeblind.nautilus.external.v1",
            "mode": "real" if self.real else "mock",
            "error": {"code": code, "message": message},
            "request_digest": sha256_json(command),
        }


def main() -> int:
    bridge = ScopeBlindNautilusBridge()
    for line in sys.stdin:
        if not line.strip():
            continue
        command = json.loads(line)
        print(canonical_json(bridge.handle(command)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
`;
var nautilusAdapterReadme = `# NautilusTrader-compatible external bridge

This connector is intentionally external to NautilusTrader. It lets protect-mcp
control and receipt high-risk order actions while a customer-owned Nautilus
process remains the trading engine.

## Local mock run

\`\`\`bash
python3 .protect-mcp/connectors/nautilus-trader/bridge.py <<'JSONL'
{"action":"stage_order","client_order_id":"SB-1","instrument_id":"AAPL.NASDAQ","side":"BUY","quantity":"50","price":"182.40","mandate_digest":"demo"}
{"action":"submit_order","client_order_id":"SB-1","instrument_id":"AAPL.NASDAQ","side":"BUY","quantity":"50","price":"182.40","mandate_digest":"demo","mandate_passed":true,"approval_receipt":"receipt-demo"}
{"action":"export_events"}
JSONL
\`\`\`

## Real mode

Set \`NAUTILUS_BRIDGE_MODULE=customer_module:BridgeClass\`. The class can
implement \`submit_order\`, \`modify_order\`, \`cancel_order\`, \`reconcile\`,
and \`export_events\`. Keep that glue in the customer's repository so Nautilus
licensing, credentials, and trading logic stay outside ScopeBlind.

## Upstream contribution posture

The best NautilusTrader contribution is not this bridge or a UI. It is a small,
vendor-neutral audit/event sink RFC: a documented way to export normalized order
commands, execution reports, fills, cancels, and reconciliation events so
external compliance wrappers can prove what happened without mutating the
engine.
`;
var CONNECTOR_PILOTS = [
  {
    id: "github",
    category: "code",
    name: "GitHub pull-request control",
    status: "usable-pilot",
    description: "Controls GitHub REST/MCP calls for issue, PR, branch, and workflow actions.",
    value: "Useful when agents already have repo access through GitHub MCP, gh, or a GitHub-backed tool server.",
    env: [
      { name: "GITHUB_TOKEN", required: true, description: "Fine-grained token scoped to the pilot repo." },
      { name: "GITHUB_REPOSITORY", required: true, description: "owner/repo target for the pilot." }
    ],
    tools: ["github.rest.request", "github.issue.create", "github.pull_request.merge", "github.workflow.dispatch"],
    actions: [
      { name: "Read repo metadata", tool: "github.rest.request", risk: "low", mode: "observe", description: "GET-only repository and PR inspection." },
      { name: "Create issue or comment", tool: "github.issue.create", risk: "medium", mode: "require_approval", description: "External write to the system of record." },
      { name: "Merge PR / dispatch workflow", tool: "github.pull_request.merge", risk: "high", mode: "require_approval", description: "Code-changing or CI-triggering action." }
    ],
    setup: [
      "Create a fine-grained GitHub token for one repository.",
      "Set GITHUB_TOKEN and GITHUB_REPOSITORY.",
      "Run the agent through protect-mcp and review GitHub tool calls in the dashboard."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "github",
      target_env: ["GITHUB_TOKEN", "GITHUB_REPOSITORY"],
      safe_read_probe: "GET /repos/{GITHUB_REPOSITORY}",
      controlled_tools: ["github.rest.request", "github.issue.create", "github.pull_request.merge", "github.workflow.dispatch"],
      approval_required_for: ["POST", "PATCH", "PUT", "DELETE", "merge", "workflow_dispatch"],
      receipt_fields: ["method", "path", "repo", "actor", "payload_hash", "approval_reason"]
    },
    cedar: `${defaultPermit2}
// GitHub pilot: reads are observed; writes and merges need exact-action approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.pull_request.merge" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.workflow.dispatch" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.issue.create" && !context.approved };
`
  },
  {
    id: "email-gmail",
    category: "communications",
    name: "Gmail self-send / draft approval",
    status: "usable-pilot",
    description: "Uses the existing Gmail OAuth connector path and restricts send mode to email.self for the first production pilot.",
    value: "Makes external communications reviewable before an agent can send mail.",
    env: [
      { name: "GOOGLE_CLIENT_ID", required: true, description: "OAuth client for Gmail." },
      { name: "GOOGLE_CLIENT_SECRET", required: true, description: "OAuth client secret." },
      { name: "CONNECTOR_TOKEN_KEY", required: true, description: "AES-GCM key material for sealed connector tokens." }
    ],
    tools: ["gmail.draft.create", "gmail.send.email_self", "email.send"],
    actions: [
      { name: "Create draft", tool: "gmail.draft.create", risk: "medium", mode: "require_approval", description: "Draft content can leak sensitive information." },
      { name: "Self-send test", tool: "gmail.send.email_self", risk: "medium", mode: "require_approval", description: "First release allows only sending to the account owner." },
      { name: "External send", tool: "email.send", risk: "high", mode: "deny", description: "Direct external send stays blocked until a customer-specific allowlist exists." }
    ],
    setup: [
      "Configure Google OAuth redirect /fn/connectors/gmail/callback.",
      "Connect Gmail through the hosted console or local connector flow.",
      "Keep send mode to email.self until the customer approves recipient allowlists."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "gmail",
      hosted_functions: ["/fn/connectors/gmail/start", "/fn/connectors/gmail/callback", "/fn/connectors/gmail/send", "/fn/connectors/gmail/status"],
      first_release_scope: "email.self",
      denied_until_configured: ["email.send.external", "email.bulk_send"],
      receipt_fields: ["to_hash", "subject_hash", "body_hash", "approval_reason", "gmail_message_id"]
    },
    cedar: `${defaultPermit2}
// Email pilot: no direct external send. Draft/self-send require exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "email.send" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.draft.create" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.send.email_self" && !context.approved };
`
  },
  {
    id: "filesystem-git",
    category: "local-computer",
    name: "Filesystem and Git control",
    status: "usable-pilot",
    description: "Controls reads, writes, shell commands, and Git mutation in the local project.",
    value: "Immediately useful with Claude Code, Codex, Cursor, and any agent that edits files or runs shell commands.",
    env: [],
    tools: ["Read", "Write", "Edit", "MultiEdit", "Bash", "git.commit", "git.push"],
    actions: [
      { name: "Read files", tool: "Read", risk: "low", mode: "observe", description: "Observe file reads for audit context." },
      { name: "Write/edit files", tool: "Write", risk: "medium", mode: "require_approval", description: "Require approval for sensitive paths or broad rewrites." },
      { name: "Git push/reset", tool: "Bash", risk: "high", mode: "require_approval", description: "Commands that publish, reset, or delete require exact-action approval." }
    ],
    setup: [
      "Run protect-mcp init-hooks in the project.",
      "Install filesystem-safe and Git-safe policy packs.",
      "Review the dashboard before turning on enforce mode."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "filesystem-git",
      local_only: true,
      protected_paths: [".env", ".ssh", "keys/", "secrets/", "node_modules/"],
      dangerous_command_patterns: ["rm -rf", "git push", "git reset --hard", "curl | sh", "chmod 777"],
      receipt_fields: ["tool", "path_hash", "command_hash", "diff_hash", "approval_reason"]
    },
    cedar: `${defaultPermit2}
// Filesystem/Git pilot: dangerous shell and protected-path writes need approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git reset --hard") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git push") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["Write", "Edit", "MultiEdit"].contains(context.tool) && context.path.contains(".env") && !context.approved };
`
  },
  {
    id: "slack-teams",
    category: "communications",
    name: "Slack or Teams outbound approval",
    status: "usable-pilot",
    description: "Controls messages to Slack channels or Microsoft Teams webhooks.",
    value: "Makes high-impact internal broadcasts and client channels approval-gated.",
    env: [
      { name: "SLACK_BOT_TOKEN", required: false, description: "Slack bot token for chat.postMessage pilots." },
      { name: "SLACK_CHANNEL_ID", required: false, description: "Default Slack channel for the pilot." },
      { name: "TEAMS_WEBHOOK_URL", required: false, description: "Teams incoming webhook URL if Teams is preferred." }
    ],
    tools: ["slack.chat.postMessage", "slack.files.upload", "teams.webhook.post"],
    actions: [
      { name: "Post internal message", tool: "slack.chat.postMessage", risk: "medium", mode: "require_approval", description: "Message text and channel are read back before send." },
      { name: "Upload file", tool: "slack.files.upload", risk: "high", mode: "require_approval", description: "Files can leak customer data and need explicit approval." },
      { name: "Teams webhook post", tool: "teams.webhook.post", risk: "medium", mode: "require_approval", description: "Webhook destination and payload hash are receipted." }
    ],
    setup: [
      "Choose Slack or Teams for the first pilot, not both.",
      "Set the relevant token/webhook environment variables.",
      "Start with a private test channel and exact-action approval for every send."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "slack-or-teams",
      supported_modes: ["slack.chat.postMessage", "teams.webhook.post"],
      require_channel_allowlist: true,
      receipt_fields: ["channel_hash", "message_hash", "file_hash", "approval_reason", "provider_message_id"]
    },
    cedar: `${defaultPermit2}
// Slack/Teams pilot: all outbound posts and uploads require approval by default.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["slack.chat.postMessage", "slack.files.upload", "teams.webhook.post"].contains(context.tool) && !context.approved };
`
  },
  {
    id: "finance-pms",
    category: "finance",
    name: "Finance PMS mock-to-real adapter",
    status: "usable-pilot",
    description: "Stages orders into a PMS adapter contract, with mock mode locally and real mode through PMS_ADAPTER_URL.",
    value: "Gives hedge funds the controlled booking path: parse, mandate-check, approve, book, corroborate, receipt.",
    env: [
      { name: "PMS_ADAPTER_URL", required: false, description: "Customer-owned adapter endpoint. Omit for local mock mode." },
      { name: "PMS_ADAPTER_TOKEN", required: false, description: "Bearer token for the customer-owned PMS adapter." }
    ],
    tools: ["pms.order.stage", "pms.order.book", "pms.order.cancel", "pms.reconcile"],
    actions: [
      { name: "Stage order", tool: "pms.order.stage", risk: "medium", mode: "require_approval", description: "Creates a booking ticket but does not execute." },
      { name: "Book order", tool: "pms.order.book", risk: "high", mode: "require_approval", description: "Must pass mandate checks and human readback." },
      { name: "Cancel/order correction", tool: "pms.order.cancel", risk: "high", mode: "require_approval", description: "Mutates book state and requires approval." }
    ],
    setup: [
      "Run local mock mode first with the Legate finance pilot pack.",
      "Point PMS_ADAPTER_URL at a customer-owned bridge when ready.",
      "Require mandate checks and exact-action approval before pms.order.book."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "finance-pms",
      mode: "mock-first",
      adapter_contract: {
        stage: "POST /orders/stage",
        book: "POST /orders/book",
        cancel: "POST /orders/{client_order_id}/cancel",
        reconcile: "GET /orders/{client_order_id}"
      },
      receipt_fields: ["client_order_id", "side", "symbol_hash", "qty", "price", "mandate_digest", "approval_reason", "external_confirmation_hash"]
    },
    cedar: `${defaultPermit2}
// Finance/PMS pilot: booking actions require mandate pass and exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["pms.order.stage", "pms.order.book", "pms.order.cancel"].contains(context.tool) && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "pms.order.book" && context.mandate_passed != true };
`
  },
  {
    id: "nautilus-trader",
    category: "finance",
    name: "NautilusTrader-compatible external bridge",
    status: "usable-pilot",
    description: "Controls NautilusTrader-compatible staged orders through an external JSONL bridge, with local mock mode and customer-owned real mode.",
    value: "Turns Nautilus into a strong Legate demo target: mandate-check, exact approval, external order event, position-blind audit bundle, and later reconciliation.",
    env: [
      { name: "NAUTILUS_BRIDGE_MODULE", required: false, description: "Optional customer glue in module.path:ClassName form for real Nautilus submission." },
      { name: "SCOPEBLIND_NAUTILUS_STATE_DIR", required: false, description: "Optional state directory for local mock events. Defaults to .protect-mcp/nautilus." },
      { name: "NAUTILUS_TRADER_PROJECT", required: false, description: "Optional path to the customer Nautilus project when running real mode." }
    ],
    tools: [
      "nautilus.order.stage",
      "nautilus.order.submit",
      "nautilus.order.modify",
      "nautilus.order.cancel",
      "nautilus.strategy.deploy",
      "nautilus.event.export",
      "nautilus.reconcile"
    ],
    actions: [
      { name: "Stage order", tool: "nautilus.order.stage", risk: "medium", mode: "require_approval", description: "Creates a position-blind booking intent and event commitment." },
      { name: "Submit order", tool: "nautilus.order.submit", risk: "high", mode: "require_approval", description: "Requires mandate pass plus exact approval before live order mutation." },
      { name: "Modify or cancel order", tool: "nautilus.order.modify", risk: "high", mode: "require_approval", description: "Mutates live order state and must carry a fresh approval receipt." },
      { name: "Deploy strategy", tool: "nautilus.strategy.deploy", risk: "high", mode: "require_approval", description: "Requires signed strategy pack, mandate scope, and operator approval." },
      { name: "Export event log", tool: "nautilus.event.export", risk: "low", mode: "observe", description: "Exports normalized event commitments for receipt corroboration." }
    ],
    setup: [
      "Run mock mode first: protect-mcp connectors init nautilus-trader --force.",
      "Pipe stage/submit/reconcile JSONL through .protect-mcp/connectors/nautilus-trader/bridge.py.",
      "For real mode, set NAUTILUS_BRIDGE_MODULE to customer-owned glue that calls NautilusTrader APIs.",
      "Open an upstream NautilusTrader RFC for a neutral audit/event sink before proposing any PR."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "nautilus-trader-compatible",
      mode: "external-bridge-mock-first",
      license_boundary: "No NautilusTrader code is bundled. Real mode calls a customer-owned process/module.",
      adapter_contract: {
        protocol: "stdin/stdout JSONL",
        bridge: ".protect-mcp/connectors/nautilus-trader/bridge.py",
        real_mode_env: "NAUTILUS_BRIDGE_MODULE=module.path:ClassName",
        actions: ["stage_order", "submit_order", "modify_order", "cancel_order", "reconcile", "export_events"]
      },
      controlled_tools: [
        "nautilus.order.stage",
        "nautilus.order.submit",
        "nautilus.order.modify",
        "nautilus.order.cancel",
        "nautilus.strategy.deploy",
        "nautilus.event.export",
        "nautilus.reconcile"
      ],
      approval_required_for: ["submit_order", "modify_order", "cancel_order", "strategy_deploy"],
      receipt_fields: [
        "client_order_id",
        "instrument_id_hash",
        "side",
        "quantity",
        "price",
        "mandate_digest",
        "approval_receipt",
        "external_event_digest",
        "commitment_root"
      ],
      upstream_rfc: {
        title: "[RFC] Add a vendor-neutral order/execution audit event sink",
        non_goals: ["ScopeBlind dependency", "UI dashboard", "AI tooling", "new venue adapter"]
      }
    },
    artifacts: [
      { path: "nautilus-trader/bridge.py", contents: nautilusBridgePy, executable: true },
      { path: "nautilus-trader/README.md", contents: nautilusAdapterReadme }
    ],
    cedar: `${defaultPermit2}
// NautilusTrader-compatible pilot: stage can be observed, but any live mutation requires exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["nautilus.order.submit", "nautilus.order.modify", "nautilus.order.cancel", "nautilus.strategy.deploy"].contains(context.tool) && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["nautilus.order.submit", "nautilus.order.modify", "nautilus.order.cancel"].contains(context.tool) && context.mandate_passed != true };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "nautilus.strategy.deploy" && context.strategy_pack_signed != true };
`
  }
];
function getConnectorPilot(id5) {
  return CONNECTOR_PILOTS.find((pilot) => pilot.id === id5);
}
function connectorDirectory(dir) {
  return (0, import_node_path6.join)(dir, ".protect-mcp", "connectors");
}
function writeConnectorPilots(opts) {
  const directory = connectorDirectory(opts.dir);
  (0, import_node_fs10.mkdirSync)(directory, { recursive: true });
  const selected = opts.ids && opts.ids.length > 0 && !opts.ids.includes("all") ? opts.ids.map((id5) => {
    const pilot = getConnectorPilot(id5);
    if (!pilot) throw new Error(`Unknown connector pilot: ${id5}`);
    return pilot;
  }) : CONNECTOR_PILOTS;
  const written = [];
  for (const pilot of selected) {
    const configPath = (0, import_node_path6.join)(directory, `${pilot.id}.json`);
    const policyPath = (0, import_node_path6.join)(directory, `${pilot.id}.cedar`);
    if (!opts.force && ((0, import_node_fs10.existsSync)(configPath) || (0, import_node_fs10.existsSync)(policyPath))) {
      throw new Error(`Refusing to overwrite ${pilot.id}. Re-run with --force if intentional.`);
    }
    (0, import_node_fs10.writeFileSync)(configPath, JSON.stringify({ ...pilot.config, id: pilot.id, name: pilot.name, category: pilot.category, tools: pilot.tools, actions: pilot.actions, setup: pilot.setup }, null, 2) + "\n");
    (0, import_node_fs10.writeFileSync)(policyPath, pilot.cedar.endsWith("\n") ? pilot.cedar : `${pilot.cedar}
`);
    written.push(configPath, policyPath);
    for (const artifact of pilot.artifacts || []) {
      const artifactPath = connectorArtifactPath(directory, artifact.path);
      (0, import_node_fs10.mkdirSync)((0, import_node_path6.dirname)(artifactPath), { recursive: true });
      (0, import_node_fs10.writeFileSync)(artifactPath, artifact.contents.endsWith("\n") ? artifact.contents : `${artifact.contents}
`);
      if (artifact.executable) (0, import_node_fs10.chmodSync)(artifactPath, 493);
      written.push(artifactPath);
    }
  }
  (0, import_node_fs10.writeFileSync)((0, import_node_path6.join)(directory, "README.md"), renderConnectorReadme(selected));
  written.push((0, import_node_path6.join)(directory, "README.md"));
  return { written, pilots: selected, directory };
}
function connectorArtifactPath(directory, relativePath) {
  const clean = (0, import_node_path6.normalize)(relativePath).replace(/^(\.\.(\/|\\|$))+/, "");
  if (clean.startsWith("/") || clean.includes("..")) {
    throw new Error(`Unsafe connector artifact path: ${relativePath}`);
  }
  return (0, import_node_path6.join)(directory, clean);
}
function readInstalledConnectorPilots(dir) {
  const directory = connectorDirectory(dir);
  if (!(0, import_node_fs10.existsSync)(directory)) return [];
  return (0, import_node_fs10.readdirSync)(directory).filter((name) => name.endsWith(".json")).map((name) => {
    const configPath = (0, import_node_path6.join)(directory, name);
    try {
      const parsed = JSON.parse((0, import_node_fs10.readFileSync)(configPath, "utf-8"));
      const id5 = String(parsed.id || name.replace(/\.json$/, ""));
      const pilot = getConnectorPilot(id5);
      return {
        id: id5,
        name: String(parsed.name || pilot?.name || id5),
        category: String(parsed.category || pilot?.category || "unknown"),
        status: String(parsed.status || parsed.type || "installed"),
        config_path: configPath,
        policy_path: (0, import_node_path6.join)(directory, `${id5}.cedar`)
      };
    } catch {
      return null;
    }
  }).filter(Boolean);
}
function connectorDoctor(dir, env = process.env) {
  const installed = new Set(readInstalledConnectorPilots(dir).map((pilot) => pilot.id));
  return CONNECTOR_PILOTS.map((pilot) => {
    const envRows = pilot.env.map((item) => ({
      name: item.name,
      required: item.required,
      present: Boolean(env[item.name]),
      description: item.description
    }));
    const missingRequired = envRows.filter((item) => item.required && !item.present).map((item) => item.name);
    const optionalPresent = envRows.filter((item) => !item.required && item.present).map((item) => item.name);
    const optionalProviderReady = pilot.id === "slack-teams" ? Boolean(env.SLACK_BOT_TOKEN || env.TEAMS_WEBHOOK_URL) : pilot.id === "finance-pms" ? Boolean(env.PMS_ADAPTER_URL) : pilot.id === "nautilus-trader" ? Boolean(env.NAUTILUS_BRIDGE_MODULE || env.NAUTILUS_TRADER_PROJECT) : false;
    const mockModeReady = pilot.id === "finance-pms" || pilot.id === "nautilus-trader";
    return {
      id: pilot.id,
      name: pilot.name,
      category: pilot.category,
      installed: installed.has(pilot.id),
      usable: missingRequired.length === 0 && (pilot.env.some((item) => item.required) || pilot.env.length === 0 || optionalProviderReady || mockModeReady),
      mode: pilot.id === "finance-pms" && !env.PMS_ADAPTER_URL ? "mock" : pilot.id === "nautilus-trader" && !env.NAUTILUS_BRIDGE_MODULE ? "mock_bridge" : pilot.id === "slack-teams" && !env.SLACK_BOT_TOKEN && !env.TEAMS_WEBHOOK_URL ? "needs_provider_choice" : "configured_or_local",
      missing_required: missingRequired,
      optional_present: optionalPresent,
      tools: pilot.tools,
      next: missingRequired.length > 0 ? `Set ${missingRequired.join(", ")}` : installed.has(pilot.id) ? "Run through protect-mcp and inspect the dashboard." : `Install with protect-mcp connectors init ${pilot.id}`
    };
  });
}
function renderConnectorReadme(pilots) {
  return `# protect-mcp connector pilots

These files make real tool classes visible and controllable without uploading raw prompts or payloads.

${pilots.map((pilot) => `## ${pilot.name}

${pilot.description}

Value: ${pilot.value}

Tools: ${pilot.tools.map((tool) => `\`${tool}\``).join(", ")}

Setup:
${pilot.setup.map((step) => `- ${step}`).join("\n")}
${pilot.artifacts?.length ? `
Generated files:
${pilot.artifacts.map((artifact) => `- \`${artifact.path}\``).join("\n")}
` : ""}`).join("\n")}
Next: run \`npx protect-mcp dashboard --open\` and review tool inventory, policy coverage, approvals, and receipts.
`;
}

// src/cli.ts
init_mandate_lifecycle();
var import_node_crypto16 = require("crypto");
var import_node_fs21 = require("fs");
var import_node_path16 = require("path");
var import_node_os4 = require("os");
function printHelp() {
  process.stderr.write(`
protect-mcp: Enterprise security gateway for MCP servers & Claude Code hooks

Usage:
  protect-mcp [options] -- <command> [args...]
  protect-mcp serve [--port <port>] [--enforce] [--policy <path>] [--cedar <dir>]
  protect-mcp mcp                                 # the gate as an MCP server (evaluate/sign/verify/self_test tools)
  protect-mcp coordination pair [--config <private-file>] [--name <name>] [--code-env <variable>]
  protect-mcp coordination setup [--config <private-file>] [--client claude-code|codex|json]
  protect-mcp coordination agent setup --endpoint <url> --authority-key <hex> [--profile <private-file>] [--client claude-code|codex|json]
  protect-mcp coordination agent [--profile <private-file>]
  protect-mcp coordination agent import --config <existing-private-file> [--profile <private-file>]
  protect-mcp coordination --config <private-file>
  protect-mcp coordination --endpoint <url> --room <id> --authority-key <hex> [--token-env <name>] [--run <id>]
  protect-mcp init-hooks [--dir <path>] [--port <port>]
  protect-mcp quickstart [--connect]
  protect-mcp wrap [--write] [--claude-desktop] [-- <command>]
  protect-mcp dashboard [--port <port>] [--dir <path>] [--open]
  protect-mcp recommend [--dir <path>] [--output <path>] [--write]
  protect-mcp registry init|anchor|status [--dir <path>] [--org <name>] [--hosted]
  protect-mcp trial [--dir <path>] [--hosted]
  protect-mcp killer-demo [--dir <path>] [--hosted]
  protect-mcp connectors list|show|init|doctor [connector|all] [--dir <path>] [--force]
  protect-mcp verify-disclosure --receipt <path> --disclosure <path>
  protect-mcp policy-packs list|show|install [pack] [--dir ./cedar] [--force]
  protect-mcp connect
  protect-mcp init [--dir <path>]
  protect-mcp sample [--dir <path>] [--force]
  protect-mcp policy list|show|allow <tool>|deny <tool>|path
  protect-mcp mandate init|status|history|propose|approve|export|continuity|verify [--cedar <dir>]
  protect-mcp demo
  protect-mcp trace <receipt_id> [--endpoint <url>] [--depth <n>]
  protect-mcp status [--dir <path>]
  protect-mcp digest [--today] [--dir <path>]
  protect-mcp receipts [--last <n>] [--dir <path>]
  protect-mcp record [--dir <path>] [--live] [--no-open]
  protect-mcp claim [--no <cap>] [--only <c,c>] [--count <verdict>] [--payment-under <amount>] [--anchor] [--dir <path>] [--output <path>]
  protect-mcp verify-claim <claim.json> [--key <public-hex>] [--check-anchor] [--offline]
  protect-mcp anchor-record [--dir <path>] [--force]
  protect-mcp bundle [--output <path>] [--dir <path>]
  protect-mcp simulate --policy <path> [--log <path>] [--tier <tier>] [--json]
  protect-mcp report [--period <days>d] [--format md|json] [--output <path>] [--dir <path>]
  protect-mcp coverage --mode <hook|proxy> [--enforce] [--policy <path> | --cedar <dir>] [--out <file>]

Options:
  --policy <path>   Policy/config JSON file (default: allow-all)
  --cedar <dir>     Cedar policy directory (alternative to --policy, evaluates locally via WASM)
  --slug <slug>     ScopeBlind tenant slug (optional)
  --enforce         Enable enforcement mode (default: shadow mode)
  --standard <file> The signed standard in force (standard.json from scopeblind.com/write): its tool list and per-instruction limit are refused at the gate; an amount above its approval threshold is held for the named person
  --report <url>    The standard page's report URL; every receipt lands there after it is chained locally, and held actions wait there for a signed decision
  --report-token <t> The page's write token (or PROTECT_MCP_REPORT_TOKEN)
  --run <id>        A name for this run on the page (default: a timestamp)
  --http            Start HTTP/SSE server instead of stdio proxy
  --port <port>     HTTP server port (default: 3000 for --http, 9377 for serve)
  --verbose         Enable debug logging to stderr
  --help            Show this help
  --version         Print the installed version

Commands:
  coordination      Shared invoice MCP tools; verifies pinned admission before an idempotent sample-ledger action (token from environment)
  serve             Start HTTP hook server for Claude Code integration (port 9377)
  evaluate          Evaluate one tool call against a Cedar policy (PreToolUse gate; exit 2 = deny, fail-closed)
  sign              Sign one tool call into a receipt (PostToolUse)
  init-hooks        Generate Claude Code hook config + skill + sample Cedar policy
  quickstart        Zero-config onboarding: init + demo + show receipts in one command
  onboard           Guided first run: pick a policy pack, run a governed demo, verify a receipt
  offboard          Remove ScopeBlind cleanly: delete local data / disable enforcement / uninstall
  wrap              Print or install a protect-mcp wrapper for MCP servers
  dashboard         Start a local-only action dashboard from logs/receipts
  recommend         Draft a policy from shadow-mode call inventory
  registry          Paid-boundary receipt digest registry and verifier page
  trial             Build the 10-minute self-serve proof path locally
  killer-demo       Build a 3-minute shadow\u2192policy\u2192approval\u2192receipt demo pack
  connectors        Install and inspect real connector pilots
  verify-disclosure Verify a v0 selective-disclosure package and explain hidden fields
  policy-packs      List, inspect, or install starter Cedar policy packs
  mandate           Require dual control, signed policy heads, automatic expiry, and optional external continuity anchors
  connect           Create a ScopeBlind sandbox dashboard and configure receipt upload
  init              Generate config template, Ed25519 keypair, and sample policy
  demo              Start a demo server wrapped with protect-mcp (see receipts instantly)
  doctor            Check your setup: keys, policies, verifier, API connectivity
  trace <id>        Visualize the receipt DAG from a given receipt_id (ASCII tree)
  status            Show tool call statistics from the local decision log
  digest            Generate a human-readable summary of agent activity
  receipts          Show recent persisted signed receipts
  record            Open a local, searchable view of your record in the browser
  claim             Attest a signed, position-blind claim over your record (e.g. no egress,
                    no payment, every payment under a cap)
  verify-claim      Verify a claim attestation offline (signature + predicate + commitment
                    + the anchor sidecar and issuer identity when present)
  anchor-record     Checkpoint the record's Merkle root + count into the public log
                    (heartbeat-friendly: skips when unchanged; only hashes leave)
  bundle            Export an offline-verifiable audit bundle
  coverage          Emit a signed coverage/scope statement: what is and is not governed
  egress-check      Prove no raw data leaves the box: the pilot "no upload" health check

Examples:
  protect-mcp serve                           # Start hook server (Claude Code)
  protect-mcp serve --enforce --cedar ./cedar  # Enforce Cedar policies
  protect-mcp init-hooks                       # One-command Claude Code setup
  protect-mcp quickstart
  protect-mcp quickstart --connect               # Quickstart + create dashboard
  protect-mcp wrap -- node my-server.js          # Print wrapped MCP command
  protect-mcp wrap --claude-desktop --write      # Patch Claude Desktop MCP config
  protect-mcp dashboard --open                   # Local risk/inventory dashboard
  protect-mcp recommend --write                  # Draft a policy from observed calls
  protect-mcp registry anchor --hosted           # Upload only receipt digests for anchoring
  protect-mcp trial --dir ./scopeblind-trial     # Generate self-serve trial artifacts
  protect-mcp killer-demo --dir ./scopeblind-demo # Generate sales-demo artifacts
  protect-mcp connectors init all --force        # Install connector pilot configs
  protect-mcp connectors doctor                  # Check connector credentials safely
  protect-mcp verify-disclosure --receipt committed.json --disclosure tool-only.json
  protect-mcp policy-packs install filesystem-safe --dir ./cedar
  protect-mcp connect                             # Connect existing setup to dashboard
  protect-mcp -- node my-server.js
  protect-mcp init
  protect-mcp demo
  protect-mcp trace sha256:abc123 --depth 5
  protect-mcp status
  protect-mcp bundle --output audit.json

Dashboard:
  npx protect-mcp dashboard      Local-only dashboard (127.0.0.1; no account)
  npx protect-mcp connect        Connect privacy-safe summaries to ScopeBlind
                                  Raw receipts, prompts, and outputs stay local

  https://scopeblind.com          Docs, pricing, enterprise

`);
}
function parseArgs(argv) {
  let policyPath;
  let cedarDir;
  let slug;
  let enforce = false;
  let verbose = false;
  let childCommand = [];
  let standardPath;
  let reportUrl;
  let reportToken;
  let runId;
  const separatorIndex = argv.indexOf("--");
  if (separatorIndex === -1) {
    process.stderr.write(
      '[PROTECT_MCP] Error: Missing "--" separator before the command to wrap.\nUsage: protect-mcp [options] -- <command> [args...]\nExample: protect-mcp --policy policy.json -- node my-server.js\n'
    );
    process.exit(1);
  }
  childCommand = argv.slice(separatorIndex + 1);
  if (childCommand.length === 0) {
    process.stderr.write('[PROTECT_MCP] Error: No command specified after "--"\n');
    process.exit(1);
  }
  const options2 = argv.slice(0, separatorIndex);
  for (let i = 0; i < options2.length; i++) {
    const arg = options2[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else if (arg === "--policy" && i + 1 < options2.length) {
      policyPath = options2[++i];
    } else if (arg === "--cedar" && i + 1 < options2.length) {
      cedarDir = options2[++i];
    } else if (arg === "--slug" && i + 1 < options2.length) {
      slug = options2[++i];
    } else if (arg === "--enforce") {
      enforce = true;
    } else if (arg === "--verbose" || arg === "-v") {
      verbose = true;
    } else if (arg === "--standard" && i + 1 < options2.length) {
      standardPath = options2[++i];
    } else if (arg === "--report" && i + 1 < options2.length) {
      reportUrl = options2[++i];
    } else if (arg === "--report-token" && i + 1 < options2.length) {
      reportToken = options2[++i];
    } else if (arg === "--run" && i + 1 < options2.length) {
      runId = options2[++i];
    } else {
      process.stderr.write(`[PROTECT_MCP] Warning: Unknown option "${arg}"
`);
    }
  }
  return { policyPath, cedarDir, slug, enforce, verbose, childCommand, standardPath, reportUrl, reportToken, runId };
}
async function handleInit(argv) {
  const { writeFileSync: writeFileSync11, existsSync: existsSync13, mkdirSync: mkdirSync9 } = await import("fs");
  const { join: join13 } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) {
    dir = argv[dirIdx + 1];
  }
  const configPath = join13(dir, "protect-mcp.json");
  const keysDir = join13(dir, "keys");
  const keyPath = join13(keysDir, "gateway.json");
  if (existsSync13(configPath)) {
    process.stderr.write(`[PROTECT_MCP] Config already exists at ${configPath}
`);
    process.stderr.write("[PROTECT_MCP] Delete it first if you want to regenerate.\n");
    process.exit(1);
  }
  let keypair2;
  {
    const { randomBytes: randomBytes11 } = await import("crypto");
    const { ed25519: ed255197 } = await import("@noble/curves/ed25519");
    const { bytesToHex: bytesToHex10 } = await import("@noble/hashes/utils");
    const privateKey = randomBytes11(32);
    const publicKey = ed255197.getPublicKey(privateKey);
    keypair2 = {
      privateKey: bytesToHex10(privateKey),
      publicKey: bytesToHex10(publicKey),
      kid: "generated"
    };
  }
  if (!existsSync13(keysDir)) {
    mkdirSync9(keysDir, { recursive: true });
  }
  writeFileSync11(keyPath, JSON.stringify({
    privateKey: keypair2.privateKey,
    publicKey: keypair2.publicKey,
    kid: keypair2.kid,
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    warning: "KEEP THIS FILE SECRET. Never commit to version control."
  }, null, 2) + "\n");
  const gitignorePath = join13(keysDir, ".gitignore");
  if (!existsSync13(gitignorePath)) {
    writeFileSync11(gitignorePath, "# Never commit signing keys\n*.json\n");
  }
  const config = {
    tools: {
      "*": {
        rate_limit: "100/hour"
      },
      "delete_file": {
        block: true,
        min_tier: "privileged"
      },
      "write_file": {
        min_tier: "signed-known",
        rate_limit: "10/minute"
      },
      "read_file": {
        rate_limit: "50/minute"
      }
    },
    default_tier: "unknown",
    signing: {
      key_path: "./keys/gateway.json",
      issuer: "protect-mcp",
      enabled: true
    },
    credentials: {
      _example_api: {
        inject: "env",
        name: "EXAMPLE_API_KEY",
        value_env: "EXAMPLE_API_KEY",
        _comment: "Remove the underscore prefix and set EXAMPLE_API_KEY in your environment"
      }
    }
  };
  writeFileSync11(configPath, JSON.stringify(config, null, 2) + "\n");
  const claudeConfig = {
    "mcpServers": {
      "my-server": {
        "command": "npx",
        "args": ["protect-mcp", "--policy", configPath, "--", "node", "my-server.js"]
      }
    }
  };
  process.stderr.write(`
${bold2("protect-mcp initialized!")}

Created:
  ${configPath}     Config with shadow mode + local signing
  ${keyPath}       Ed25519 signing keypair

${bold2("Next steps:")}
  1. Edit protect-mcp.json to match your MCP server's tools
  2. Set any credential environment variables
  3. Run: protect-mcp --policy protect-mcp.json -- <your-mcp-server>

${bold2("Your gateway public key:")}
  ${keypair2.publicKey}

${bold2("Key ID (kid):")}
  ${keypair2.kid}

${bold2("Claude Desktop config snippet")} (add to claude_desktop_config.json):
${dim2(JSON.stringify(claudeConfig, null, 2))}

${bold2("Quick demo:")}
  protect-mcp demo

Shadow mode is the default \u2014 all tool calls are logged and nothing is blocked.
Add --enforce when ready to block policy violations.
`);
}
async function handleDemo() {
  const { existsSync: existsSync13 } = await import("fs");
  const { join: join13, dirname: dirname6, resolve: resolve5 } = await import("path");
  const { realpathSync } = await import("fs");
  const cliPath = resolve5(process.argv[1] || "dist/cli.js");
  let cliDir;
  try {
    cliDir = dirname6(realpathSync(cliPath));
  } catch {
    cliDir = dirname6(cliPath);
  }
  const demoServerPath = join13(cliDir, "demo-server.js");
  const configPath = join13(process.cwd(), "protect-mcp.json");
  const hasConfig = existsSync13(configPath);
  if (!hasConfig) {
    process.stderr.write(`
${bold2("protect-mcp demo")}

Starting demo with default shadow mode (no signing).
For signed receipts, run ${dim2("npx protect-mcp init")} first.

`);
  } else {
    process.stderr.write(`
${bold2("protect-mcp demo")}

Using config from ${configPath}
Starting demo server with 5 tools...

`);
  }
  let policy = null;
  let policyDigest = "none";
  let credentials;
  let signing;
  if (hasConfig) {
    try {
      const loaded = loadPolicy(configPath);
      policy = loaded.policy;
      policyDigest = loaded.digest;
      credentials = loaded.credentials;
      signing = loaded.signing;
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Warning: Could not load config: ${err instanceof Error ? err.message : err}
`);
    }
  }
  if (signing) {
    const warnings = await initSigning(signing);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  if (credentials) {
    const warnings = validateCredentials(credentials);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  const config = {
    command: process.execPath,
    // node
    args: [demoServerPath],
    policy,
    policyDigest,
    enforce: false,
    // Demo always runs in shadow mode
    verbose: true,
    signing,
    credentials
  };
  const gateway = new ProtectGateway(config);
  process.stderr.write(`${bold2("Demo ready!")} The demo server is running.
`);
  process.stderr.write(`Send JSON-RPC tool calls on stdin, or use an MCP client.

`);
  process.stderr.write(`${dim2("Example (paste into stdin):")}
`);
  process.stderr.write(`${dim2('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}')}

`);
  await gateway.start();
}
async function handleStatus2(argv) {
  const { readFileSync: readFileSync19, existsSync: existsSync13 } = await import("fs");
  const { join: join13 } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) {
    dir = argv[dirIdx + 1];
  }
  const logPath = join13(dir, ".protect-mcp-log.jsonl");
  if (!existsSync13(logPath)) {
    process.stderr.write(`${bold2("protect-mcp status")}

`);
    process.stderr.write(`No log file found at ${logPath}
`);
    process.stderr.write(`Run protect-mcp with a wrapped server first to generate logs.
`);
    process.exit(0);
  }
  const raw = readFileSync19(logPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  if (lines.length === 0) {
    process.stderr.write(`${bold2("protect-mcp status")}

No entries in log file.
`);
    process.exit(0);
  }
  const entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
    }
  }
  if (entries.length === 0) {
    process.stderr.write(`${bold2("protect-mcp status")}

No valid entries in log file.
`);
    process.exit(0);
  }
  const toolCounts = /* @__PURE__ */ new Map();
  let allowCount = 0;
  let denyCount = 0;
  let rateLimitCount = 0;
  const tierCounts = /* @__PURE__ */ new Map();
  const reasonCounts = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    toolCounts.set(entry.tool, (toolCounts.get(entry.tool) || 0) + 1);
    if (entry.decision === "allow") allowCount++;
    else if (entry.decision === "deny") denyCount++;
    if (entry.reason_code === "rate_limit_exceeded") rateLimitCount++;
    if (entry.tier) tierCounts.set(entry.tier, (tierCounts.get(entry.tier) || 0) + 1);
    reasonCounts.set(entry.reason_code, (reasonCounts.get(entry.reason_code) || 0) + 1);
  }
  const firstTs = new Date(Math.min(...entries.map((e) => e.timestamp)));
  const lastTs = new Date(Math.max(...entries.map((e) => e.timestamp)));
  const sortedTools = [...toolCounts.entries()].sort((a, b) => b[1] - a[1]);
  process.stdout.write(`
${bold2("protect-mcp status")}

`);
  process.stdout.write(`  Total decisions: ${bold2(String(entries.length))}
`);
  process.stdout.write(`  ${green2("\u2713 Allow")}: ${allowCount}    ${red2("\u2717 Deny")}: ${denyCount}    ${yellow2("\u2298 Rate-limited")}: ${rateLimitCount}

`);
  process.stdout.write(`  ${bold2("Time range:")}
`);
  process.stdout.write(`    First: ${firstTs.toISOString()}
`);
  process.stdout.write(`    Last:  ${lastTs.toISOString()}

`);
  process.stdout.write(`  ${bold2("Top tools:")}
`);
  for (const [tool, count] of sortedTools.slice(0, 10)) {
    const bar = "\u2588".repeat(Math.min(Math.ceil(count / entries.length * 30), 30));
    process.stdout.write(`    ${tool.padEnd(20)} ${String(count).padStart(4)}  ${dim2(bar)}
`);
  }
  if (tierCounts.size > 0) {
    process.stdout.write(`
  ${bold2("Trust tiers seen:")}
`);
    for (const [tier, count] of tierCounts) {
      process.stdout.write(`    ${tier.padEnd(15)} ${count}
`);
    }
  }
  process.stdout.write(`
  ${bold2("Decision reasons:")}
`);
  for (const [reason, count] of [...reasonCounts.entries()].sort((a, b) => b[1] - a[1])) {
    process.stdout.write(`    ${reason.padEnd(25)} ${count}
`);
  }
  const evidencePath = join13(dir, ".protect-mcp-evidence.json");
  if (existsSync13(evidencePath)) {
    try {
      const evidenceRaw = readFileSync19(evidencePath, "utf-8");
      const evidence = JSON.parse(evidenceRaw);
      const agentCount = Object.keys(evidence.agents || {}).length;
      process.stdout.write(`
  ${bold2("Evidence store:")} ${agentCount} agent(s) tracked
`);
    } catch {
    }
  }
  const keyPath = join13(dir, "keys", "gateway.json");
  if (existsSync13(keyPath)) {
    try {
      const keyData = JSON.parse(readFileSync19(keyPath, "utf-8"));
      if (keyData.publicKey) {
        const fingerprint = keyData.publicKey.slice(0, 16) + "...";
        process.stdout.write(`
  ${bold2("\u{1F6E1}\uFE0F Passport identity:")}
`);
        process.stdout.write(`    Public key:  ${fingerprint}
`);
        if (keyData.kid) process.stdout.write(`    Key ID:      ${keyData.kid}
`);
        process.stdout.write(`    Issuer:      ${keyData.issuer || "protect-mcp"}
`);
        process.stdout.write(`    Verify:      ${dim2("npx @veritasacta/verify <receipt.json>")}
`);
      }
    } catch {
    }
  }
  process.stdout.write(`
  Log file: ${dim2(logPath)}

`);
}
function commandNeedsValue(argv, flag2) {
  const value = flagValue(argv, flag2);
  return Boolean(value && !value.startsWith("--"));
}
function absoluteOrCwd(pathValue) {
  return (0, import_node_path16.resolve)(process.cwd(), pathValue);
}
function shellQuoteArg(arg) {
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}
function shellCommand(command, args) {
  return [command, ...args].map(shellQuoteArg).join(" ");
}
function wrapperArgsFor(command, opts) {
  const args = ["-y", "protect-mcp@latest"];
  if (opts.cedarDir) args.push("--cedar", opts.cedarDir);
  else args.push("--policy", opts.configPath || absoluteOrCwd("protect-mcp.json"));
  if (opts.enforce) args.push("--enforce");
  if (opts.standardPath) args.push("--standard", opts.standardPath);
  if (opts.reportUrl) args.push("--report", opts.reportUrl);
  if (opts.reportToken) args.push("--report-token", opts.reportToken);
  if (opts.runId) args.push("--run", opts.runId);
  args.push("--", ...command);
  return args;
}
function claudeDesktopConfigPath() {
  if (process.platform === "darwin") {
    return (0, import_node_path16.join)((0, import_node_os4.homedir)(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
  }
  if (process.platform === "win32") {
    return (0, import_node_path16.join)(process.env.APPDATA || (0, import_node_path16.join)((0, import_node_os4.homedir)(), "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
  }
  return (0, import_node_path16.join)((0, import_node_os4.homedir)(), ".config", "Claude", "claude_desktop_config.json");
}
async function ensureLocalConfig(dir = process.cwd()) {
  const { existsSync: existsSync13 } = await import("fs");
  const { join: join13, resolve: resolve5 } = await import("path");
  const configPath = join13(dir, "protect-mcp.json");
  if (!existsSync13(configPath)) {
    process.stderr.write(`${bold2("protect-mcp wrap")}

No protect-mcp.json found; creating local shadow-mode config first.

`);
    await handleInit(["--dir", dir]);
  }
  return resolve5(configPath);
}
function parseJsonlFile(pathValue) {
  try {
    const raw = (0, import_node_fs21.readFileSync)(pathValue, "utf-8");
    return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
  } catch {
    return [];
  }
}
function parseJsonlRecords(pathValue) {
  try {
    const raw = (0, import_node_fs21.readFileSync)(pathValue, "utf-8");
    return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
      try {
        return [{
          value: JSON.parse(line),
          raw: line,
          hash: (0, import_node_crypto16.createHash)("sha256").update(line).digest("hex")
        }];
      } catch {
        return [];
      }
    });
  } catch {
    return [];
  }
}
function loadPolicyJson(policyPath) {
  try {
    if (!(0, import_node_fs21.existsSync)(policyPath)) return null;
    return JSON.parse((0, import_node_fs21.readFileSync)(policyPath, "utf-8"));
  } catch {
    return null;
  }
}
function policyCoverageForTool(tool, policy) {
  const tools = policy?.tools && typeof policy.tools === "object" ? policy.tools : {};
  if (tools[tool]) {
    return { status: "exact", label: "Exact rule", policy: tools[tool] };
  }
  if (tools["*"]) {
    return { status: "wildcard", label: "Wildcard fallback", policy: tools["*"] };
  }
  return { status: "none", label: "No rule" };
}
function receiptRequestId(receipt) {
  const direct = receipt.request_id || receipt.scope;
  if (typeof direct === "string") return direct;
  const payload = receipt.payload;
  if (payload && typeof payload === "object") {
    const candidate = payload.request_id || payload.scope;
    if (typeof candidate === "string") return candidate;
  }
  const claims = receipt.signed_claims;
  if (claims && typeof claims === "object") {
    const nestedClaims = claims.claims;
    if (nestedClaims && typeof nestedClaims === "object") {
      const candidate = nestedClaims.request_id || nestedClaims.scope;
      if (typeof candidate === "string") return candidate;
    }
  }
  return void 0;
}
function buildReceiptChains(entries, receipts) {
  const receiptMap = /* @__PURE__ */ new Map();
  for (const receipt of receipts) {
    const requestId = receiptRequestId(receipt.value);
    if (!requestId) continue;
    const rows = receiptMap.get(requestId) || [];
    rows.push(receipt);
    receiptMap.set(requestId, rows);
  }
  const logMap = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    if (!entry.request_id) continue;
    const rows = logMap.get(entry.request_id) || [];
    rows.push(entry);
    logMap.set(entry.request_id, rows);
  }
  return [...logMap.entries()].map(([requestId, logs]) => {
    const relatedReceipts = receiptMap.get(requestId) || [];
    const latest = logs[logs.length - 1];
    return {
      request_id: requestId,
      tool: latest?.tool || "unknown",
      decision: latest?.decision || "unknown",
      reason_code: latest?.reason_code || "",
      action_readback: latest?.action_readback,
      log_events: logs.map((log) => ({
        decision: log.decision,
        reason_code: log.reason_code,
        timestamp: log.timestamp,
        hook_event: log.hook_event
      })),
      receipts: relatedReceipts.map((receipt) => ({
        hash: receipt.hash,
        type: String(receipt.value.type || receipt.value.artifact_type || "receipt")
      })),
      complete: relatedReceipts.length > 0
    };
  }).sort((a, b) => {
    const at2 = a.log_events[0]?.timestamp || 0;
    const bt = b.log_events[0]?.timestamp || 0;
    return bt - at2;
  }).slice(0, 80);
}
function riskForTool(toolRaw) {
  const tool = toolRaw.toLowerCase();
  const reasons = [];
  const highPatterns = [
    ["delete", "delete/destructive"],
    ["remove", "delete/destructive"],
    ["rm", "delete/destructive"],
    ["write", "writes data"],
    ["send", "external send"],
    ["email", "external comms"],
    ["slack", "external comms"],
    ["teams", "external comms"],
    ["github", "source-control mutation"],
    ["commit", "source-control mutation"],
    ["push", "source-control mutation"],
    ["deploy", "deployment"],
    ["terraform", "cloud infrastructure"],
    ["aws", "cloud infrastructure"],
    ["gcp", "cloud infrastructure"],
    ["azure", "cloud infrastructure"],
    ["sql", "database access"],
    ["database", "database access"],
    ["payment", "spend/payment"],
    ["order", "order/transaction"],
    ["trade", "trade/transaction"],
    ["pms", "portfolio-system mutation"],
    ["book", "portfolio-system mutation"],
    ["fill", "portfolio-system mutation"],
    ["secret", "secrets"],
    ["token", "secrets"]
  ];
  for (const [needle, label] of highPatterns) {
    if (tool.includes(needle) && !reasons.includes(label)) reasons.push(label);
  }
  if (reasons.length > 0) return { tier: "high", reasons };
  if (tool.includes("read") || tool.includes("search") || tool.includes("list") || tool.includes("fetch")) {
    return { tier: "medium", reasons: ["data access"] };
  }
  return { tier: "low", reasons: ["observed"] };
}
function suggestedGuardrailFor(_tool, risk, reasons) {
  const reasonSet = new Set(reasons);
  if (reasonSet.has("delete/destructive") || reasonSet.has("secrets")) {
    return {
      action: "Block by default",
      reason: "Destructive and secret-handling tools should start deny-first.",
      policy: { block: true, min_tier: "privileged" }
    };
  }
  if (reasonSet.has("order/transaction") || reasonSet.has("trade/transaction") || reasonSet.has("spend/payment") || reasonSet.has("portfolio-system mutation") || reasonSet.has("deployment") || reasonSet.has("cloud infrastructure") || reasonSet.has("database access") || reasonSet.has("external send") || reasonSet.has("source-control mutation")) {
    return {
      action: "Require approval",
      reason: "Consequential tools should require a human approval receipt before enforce mode.",
      policy: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" }
    };
  }
  if (risk === "medium") {
    return {
      action: "Rate-limit and identify",
      reason: "Read/search/fetch tools can leak data at scale; keep them visible and bounded.",
      policy: { min_tier: "signed-known", rate_limit: "60/hour" }
    };
  }
  return {
    action: "Observe",
    reason: "Low-risk observed tool. Keep receipts and a broad rate limit.",
    policy: { rate_limit: "100/hour" }
  };
}
function buildDashboardSummary(dir, policyPath = (0, import_node_path16.join)(dir, "protect-mcp.json")) {
  const logPath = (0, import_node_path16.join)(dir, ".protect-mcp-log.jsonl");
  const receiptPath = (0, import_node_path16.join)(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = (0, import_node_path16.join)(dir, "keys", "gateway.json");
  const entries = parseJsonlFile(logPath);
  const receiptRecords = parseJsonlRecords(receiptPath);
  const receipts = receiptRecords.map((record) => record.value);
  const activePolicy = loadPolicyJson(policyPath);
  const tools = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    const tool = String(entry.tool || "unknown");
    const risk = riskForTool(tool);
    const current = tools.get(tool) || {
      tool,
      calls: 0,
      allows: 0,
      denies: 0,
      reviews: 0,
      risk: risk.tier,
      reasons: risk.reasons
    };
    current.calls += 1;
    if (entry.decision === "allow") current.allows += 1;
    else if (entry.decision === "deny") current.denies += 1;
    else if (entry.decision === "require_approval") current.reviews += 1;
    if (risk.tier === "high" || risk.tier === "medium" && current.risk === "low") current.risk = risk.tier;
    current.reasons = [.../* @__PURE__ */ new Set([...current.reasons, ...risk.reasons])];
    if (typeof entry.timestamp === "number") current.last_seen = new Date(entry.timestamp).toISOString();
    tools.set(tool, current);
  }
  const toolRows = [...tools.values()].sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 };
    return order[a.risk] - order[b.risk] || b.calls - a.calls || a.tool.localeCompare(b.tool);
  }).map((tool) => ({
    ...tool,
    suggestion: suggestedGuardrailFor(tool.tool, tool.risk, tool.reasons),
    policy_coverage: policyCoverageForTool(tool.tool, activePolicy)
  }));
  const highRisk = toolRows.filter((t) => t.risk === "high");
  const uncovered = toolRows.filter((t) => t.policy_coverage.status === "none").length;
  const exactCovered = toolRows.filter((t) => t.policy_coverage.status === "exact").length;
  const wildcardCovered = toolRows.filter((t) => t.policy_coverage.status === "wildcard").length;
  const allowed = entries.filter((e) => e.decision === "allow").length;
  const denied = entries.filter((e) => e.decision === "deny").length;
  const review = entries.filter((e) => e.decision === "require_approval").length;
  const pendingApprovals = entries.filter((e) => e.decision === "require_approval").slice(-25).reverse();
  const chains = buildReceiptChains(entries, receiptRecords);
  let key = null;
  if ((0, import_node_fs21.existsSync)(keyPath)) {
    try {
      const parsed = JSON.parse((0, import_node_fs21.readFileSync)(keyPath, "utf-8"));
      key = {
        kid: parsed.kid || null,
        issuer: parsed.issuer || "protect-mcp",
        publicKeyPrefix: typeof parsed.publicKey === "string" ? `${parsed.publicKey.slice(0, 16)}...` : null
      };
    } catch {
    }
  }
  return {
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    dir,
    files: {
      log: logPath,
      receipts: receiptPath,
      key: keyPath,
      policy: policyPath,
      log_exists: (0, import_node_fs21.existsSync)(logPath),
      receipts_exist: (0, import_node_fs21.existsSync)(receiptPath),
      key_exists: (0, import_node_fs21.existsSync)(keyPath),
      policy_exists: (0, import_node_fs21.existsSync)(policyPath)
    },
    totals: {
      decisions: entries.length,
      receipts: receipts.length,
      tools: toolRows.length,
      high_risk_tools: highRisk.length,
      exact_covered: exactCovered,
      wildcard_covered: wildcardCovered,
      uncovered,
      allowed,
      denied,
      review
    },
    key,
    policy: activePolicy ? {
      path: policyPath,
      digest: (0, import_node_crypto16.createHash)("sha256").update(JSON.stringify(activePolicy)).digest("hex").slice(0, 16),
      default_tier: activePolicy.default_tier || "unknown",
      tools: activePolicy.tools || {}
    } : null,
    tools: toolRows,
    pending_approvals: pendingApprovals,
    receipt_chains: chains,
    recent: entries.slice(-50).reverse(),
    policy_packs: {
      directory: policyPackDirectory(dir),
      installed: installedPolicyPackIds(dir),
      available: POLICY_PACKS.map((pack) => ({
        id: pack.id,
        name: pack.name,
        description: pack.description,
        recommendedMode: pack.recommendedMode,
        files: pack.files.map((file) => ({ path: file.path, contents: file.contents }))
      }))
    },
    connector_pilots: {
      directory: (0, import_node_path16.join)(dir, ".protect-mcp", "connectors"),
      installed: readInstalledConnectorPilots(dir),
      doctor: connectorDoctor(dir),
      available: CONNECTOR_PILOTS.map((pilot) => ({
        id: pilot.id,
        name: pilot.name,
        category: pilot.category,
        description: pilot.description,
        value: pilot.value,
        tools: pilot.tools,
        actions: pilot.actions,
        setup: pilot.setup
      }))
    },
    registry: dashboardRegistryStatus(dir),
    recommendations: [
      entries.length === 0 ? "Run in shadow mode first: npx protect-mcp -- node your-mcp-server.js" : "",
      highRisk.length > 0 ? "Run npx protect-mcp recommend --write, review the generated policy, then restart your wrapper with --enforce." : "",
      receipts.length === 0 ? "Run npx protect-mcp init so decisions are signed into local receipts." : "",
      "Install a starter policy pack from this dashboard when you know the tool class: filesystem, Git, email, database, cloud spend, secrets, or finance.",
      "Create a registry preview locally, then use hosted digest anchoring when you need independent timestamp evidence.",
      "Export an audit bundle with: npx protect-mcp bundle --output audit.json"
    ].filter(Boolean)
  };
}
function dashboardHtml() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>protect-mcp local action dashboard</title>
<style>
:root {
  color-scheme: light;
  --ink:#12110e; --muted:#6f6b61; --soft:#9a9488; --line:#ded7c9;
  --paper:#f7f3ea; --card:#fffdf7; --black:#11110f;
  --bad:#8f241c; --warn:#8d620f; --ok:#2f6f4e;
  --shadow: 0 22px 70px rgba(36,30,18,.10);
}
* { box-sizing: border-box; }
body { margin:0; background:radial-gradient(circle at top left,#fffdf7 0,#f7f3ea 34%,#e8dfce 100%); color:var(--ink); font:14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
main { width:min(1380px, calc(100vw - 32px)); margin:24px auto 60px; }
.hero { display:grid; grid-template-columns:1.35fr .65fr; gap:16px; align-items:stretch; }
.card { background:rgba(255,253,247,.92); border:1px solid var(--line); border-radius:24px; padding:22px; box-shadow:var(--shadow); }
.kicker { text-transform:uppercase; letter-spacing:.18em; font-size:11px; color:var(--muted); font-weight:800; }
h1 { font-family: ui-serif, Georgia, serif; font-weight:520; font-size:clamp(38px,5vw,76px); line-height:.92; letter-spacing:-.045em; margin:12px 0 14px; max-width:980px; }
h2 { margin:0 0 12px; font-size:17px; letter-spacing:-.01em; }
h3 { margin:0 0 8px; font-size:14px; }
p { color:var(--muted); margin:0; }
small { color:var(--muted); }
.layout { display:grid; grid-template-columns:1.28fr .72fr; gap:16px; margin-top:16px; }
.stack { display:grid; gap:16px; }
.stats { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:16px 0; }
.stat { background:#fffaf0; border:1px solid var(--line); border-radius:18px; padding:13px; min-height:86px; }
.stat strong { display:block; font-size:26px; letter-spacing:-.04em; }
.actions { display:flex; flex-wrap:wrap; gap:9px; margin-top:16px; }
button, a.btn { appearance:none; border:1px solid var(--black); background:var(--black); color:#fff; text-decoration:none; border-radius:999px; padding:9px 12px; cursor:pointer; font-weight:800; font-size:13px; }
button.secondary, a.btn.secondary { background:transparent; color:var(--black); }
button.ghost { border-color:var(--line); background:#fffaf0; color:var(--ink); }
button.danger { background:#7f1d18; border-color:#7f1d18; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:12px 9px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-size:11px; letter-spacing:.09em; text-transform:uppercase; }
.pill { display:inline-flex; align-items:center; border-radius:999px; padding:4px 9px; font-size:11px; font-weight:900; white-space:nowrap; }
.high { background:#f7d9d3; color:var(--bad); }
.medium { background:#f4e5bd; color:var(--warn); }
.low { background:#dcebdd; color:var(--ok); }
.exact { background:#dcebdd; color:var(--ok); }
.wildcard { background:#e5decc; color:#5e5545; }
.none { background:#f7d9d3; color:var(--bad); }
.allow { color:var(--ok); } .deny { color:var(--bad); } .require_approval { color:var(--warn); }
code { background:#f2eadc; border:1px solid var(--line); border-radius:8px; padding:2px 6px; }
pre { white-space:pre-wrap; background:#181712; color:#f8f1df; border-radius:16px; padding:14px; overflow:auto; font-size:12px; }
.muted { color:var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.approval { border:1px solid var(--line); background:#fffaf0; border-radius:18px; padding:14px; margin-bottom:10px; }
.readback { background:#181712; color:#f8f1df; border-radius:16px; padding:12px; margin:10px 0; }
.readback .label { color:#bdb49f; font-size:11px; text-transform:uppercase; letter-spacing:.12em; }
.preview { max-height:180px; overflow:auto; }
.row-actions { display:flex; flex-wrap:wrap; gap:6px; }
.chain { display:grid; gap:8px; }
.chain-item { border:1px solid var(--line); border-radius:16px; padding:12px; background:#fffaf0; }
.pack-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; margin-top:12px; }
.pack { border:1px solid var(--line); border-radius:16px; padding:12px; background:#fffaf0; display:grid; gap:8px; }
.pack.installed { border-color:rgba(47,111,78,.35); background:#f3f8ef; }
.divider { border:0; border-top:1px solid var(--line); margin:14px 0; }
.field { display:grid; gap:5px; margin-top:9px; }
.field label { font-size:11px; text-transform:uppercase; letter-spacing:.09em; color:var(--muted); font-weight:900; }
input { border:1px solid var(--line); border-radius:12px; background:#fffaf0; color:var(--ink); padding:10px; font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
.toast { position:fixed; right:18px; bottom:18px; background:#111; color:#fff; padding:12px 14px; border-radius:14px; box-shadow:var(--shadow); display:none; max-width:360px; }
@media (max-width: 980px) { .hero,.layout { grid-template-columns:1fr; } .stats { grid-template-columns:repeat(2,1fr); } main { width:min(100vw - 20px, 1380px); margin-top:14px; } }
</style>
</head>
<body>
<main>
  <section class="hero">
    <div class="card">
      <div class="kicker">Local Action Dashboard</div>
      <h1>See what agents can do. Control dangerous actions. Prove what happened.</h1>
      <p>Runs on <code>127.0.0.1</code>. Start in shadow mode, switch risky tools to exact-action approval, then export signed evidence without uploading sensitive data.</p>
      <div class="actions">
        <button onclick="refresh()">Refresh</button>
        <button class="secondary" onclick="exportBundle()">Export audit bundle</button>
        <a class="btn secondary" href="/api/summary">Raw JSON</a>
      </div>
    </div>
    <div class="card">
      <div class="kicker">Next move</div>
      <h2>Shadow, review, then enforce</h2>
      <pre>npx protect-mcp wrap -- node your-server.js
npx protect-mcp dashboard --open
npx protect-mcp recommend --write
npx protect-mcp --policy protect-mcp.json --enforce -- node your-server.js</pre>
      <p class="muted" id="dir"></p>
      <p class="muted" id="policy"></p>
    </div>
  </section>

  <section class="stats" id="stats"></section>

  <section class="layout">
    <div class="stack">
      <section class="card">
        <h2>Tool Inventory</h2>
        <p>Risk, policy coverage, and one-click guardrail drafting for each observed tool.</p>
        <div style="overflow:auto; margin-top:12px"><table id="tools"></table></div>
      </section>
      <section class="card">
        <h2>Policy Packs</h2>
        <p>Install a starter Cedar pack from the dashboard. This removes the blank-policy problem while keeping final enforcement local and reviewable.</p>
        <div id="policy-packs" class="pack-grid"></div>
      </section>
      <section class="card">
        <h2>Connector Pilots</h2>
        <p>Real tool categories teams already use: GitHub, Gmail/email, filesystem/Git, Slack or Teams, and finance/PMS. Install a pilot, check credentials, then watch those tools in the dashboard.</p>
        <div id="connector-pilots" class="pack-grid"></div>
      </section>
      <section class="card">
        <h2>Call History</h2>
        <p>What agents actually tried to do, including exact-action readbacks when available.</p>
        <div id="recent" style="margin-top:12px"></div>
      </section>
    </div>
    <div class="stack">
      <section class="card">
        <h2>Approval Queue</h2>
        <p>Desktop fallback approval surface. If you start this dashboard with <code>--approval-endpoint</code> and <code>--approval-nonce</code>, Approve forwards to the live local gateway.</p>
        <div id="approvals" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Receipt Chain</h2>
        <p>Decision logs correlated with signed receipts by request id.</p>
        <div id="chains" class="chain" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Paid Boundary</h2>
        <p>Free local receipts stay local. The paid line starts when a ScopeBlind org identity independently timestamps receipt digests without raw prompt, payload, or receipt upload.</p>
        <div id="registry" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Recommendations</h2>
        <div id="recommendations"></div>
      </section>
    </div>
  </section>
</main>
<div class="toast" id="toast"></div>
<script>
var state = null;
async function refresh(){
  state = await fetch('/api/summary').then(function(r){ return r.json(); });
  render(state);
}
function render(data){
  document.getElementById('dir').textContent = 'Reading: ' + data.dir;
  document.getElementById('policy').textContent = 'Policy: ' + ((data.files || {}).policy || 'protect-mcp.json');
  var t = data.totals || {};
  document.getElementById('stats').innerHTML = [
    ['Decisions', t.decisions || 0, 'All observed tool decisions'],
    ['High risk', t.high_risk_tools || 0, 'Tools that can mutate, send, trade, deploy, or expose secrets'],
    ['Exact rules', t.exact_covered || 0, 'Tools with explicit policy entries'],
    ['Uncovered', t.uncovered || 0, 'Tools falling through without exact policy'],
    ['Receipts', t.receipts || 0, 'Signed proof records available for audit']
  ].map(function(x){ return '<div class="stat"><span class="muted">'+escapeHtml(x[0])+'</span><strong>'+x[1]+'</strong><small>'+escapeHtml(x[2])+'</small></div>'; }).join('');
  renderTools(data.tools || []);
  renderApprovals(data.pending_approvals || []);
  renderRecent(data.recent || []);
  renderChains(data.receipt_chains || []);
  renderPolicyPacks(data.policy_packs || {});
  renderConnectorPilots(data.connector_pilots || {});
  renderRegistry(data.registry || {});
  document.getElementById('recommendations').innerHTML = (data.recommendations || []).map(function(r){ return '<p style="margin:0 0 10px">* '+escapeHtml(r)+'</p>'; }).join('') || '<p class="muted">No recommendations yet.</p>';
}
function renderTools(tools){
  document.getElementById('tools').innerHTML = '<thead><tr><th>Risk</th><th>Tool</th><th>Coverage</th><th>Observed</th><th>Suggested guardrail</th><th>Actions</th></tr></thead><tbody>' +
    tools.map(function(t){
      var cov = t.policy_coverage || { status:'none', label:'No rule' };
      var s = t.suggestion || { action:'Observe', reason:'' };
      return '<tr><td><span class="pill '+t.risk+'">'+escapeHtml(t.risk)+'</span></td>'+
        '<td><strong>'+escapeHtml(t.tool)+'</strong><br><span class="muted">'+escapeHtml((t.reasons || []).join(', '))+'</span></td>'+
        '<td><span class="pill '+escapeHtml(cov.status)+'">'+escapeHtml(cov.label)+'</span><br><span class="muted mono">'+escapeHtml(JSON.stringify(cov.policy || {}))+'</span></td>'+
        '<td>'+t.calls+' calls<br><span class="allow">'+t.allows+' allow</span> \xB7 <span class="deny">'+t.denies+' deny</span> \xB7 <span class="require_approval">'+t.reviews+' review</span></td>'+
        '<td><strong>'+escapeHtml(s.action)+'</strong><br><span class="muted">'+escapeHtml(s.reason)+'</span></td>'+
        '<td><div class="row-actions"><button data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="require_approval">Require approval</button><button class="danger" data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="block">Block</button><button class="ghost" data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="observe">Observe</button></div></td></tr>';
    }).join('') + (tools.length ? '' : '<tr><td colspan="6" class="muted">No tool calls yet. Wrap an MCP server or run the demo.</td></tr>') + '</tbody>';
}
function renderApprovals(rows){
  document.getElementById('approvals').innerHTML = rows.map(function(r){
    var rb = r.action_readback || {};
    var id = r.request_id || '';
    return '<div class="approval"><div class="kicker">Pending exact-action review</div><h3>'+escapeHtml(rb.summary || r.tool || 'Unknown action')+'</h3>'+
      '<div class="readback"><div class="label">You are approving exactly this</div><div><strong>Tool</strong>: '+escapeHtml(r.tool || 'unknown')+'</div><div><strong>Action</strong>: '+escapeHtml(rb.action || r.tool || 'unknown')+'</div><div><strong>Destination</strong>: '+escapeHtml(rb.destination || 'not declared')+'</div><div><strong>Payload hash</strong>: <span class="mono">'+escapeHtml(rb.payload_hash || 'not available')+'</span></div><div><strong>Policy basis</strong>: '+escapeHtml(r.reason_code || 'requires approval')+'</div><div class="preview"><pre>'+escapeHtml(JSON.stringify(rb.payload_preview || {}, null, 2))+'</pre></div></div>'+
      '<textarea id="reason-'+escapeAttr(id)+'" placeholder="Reason or instruction" style="width:100%; min-height:64px; border:1px solid var(--line); border-radius:12px; padding:10px"></textarea>'+
      '<div class="row-actions" style="margin-top:10px"><button data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="approve">Approve</button><button class="danger" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="deny">Deny</button><button class="ghost" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="edit">Edit</button><button class="ghost" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="take_over">Take over</button></div></div>';
  }).join('') || '<p class="muted">No approval-required calls in the local log yet.</p>';
}
function renderRecent(rows){
  document.getElementById('recent').innerHTML = rows.slice(0,20).map(function(r){
    var rb = r.action_readback || {};
    return '<div class="chain-item"><strong class="'+escapeHtml(r.decision || '')+'">'+escapeHtml(r.decision || 'unknown')+'</strong> \xB7 '+escapeHtml(r.tool || 'unknown')+'<br><span class="muted">'+escapeHtml(rb.summary || r.reason_code || '')+'</span><br><span class="muted mono">'+escapeHtml(r.request_id || '')+'</span></div>';
  }).join('') || '<p class="muted">No decisions yet.</p>';
}
function renderChains(rows){
  document.getElementById('chains').innerHTML = rows.slice(0,12).map(function(c){
    var hashes = (c.receipts || []).map(function(r){ return '<span class="mono">'+escapeHtml((r.hash || '').slice(0,16))+'...</span>'; }).join('<br>');
    return '<div class="chain-item"><strong>'+escapeHtml(c.tool || 'unknown')+'</strong> <span class="pill '+(c.complete ? 'exact' : 'none')+'">'+(c.complete ? 'receipt linked' : 'no receipt')+'</span><br><span class="muted">'+escapeHtml(((c.action_readback || {}).summary) || c.reason_code || '')+'</span><br><span class="muted mono">request '+escapeHtml(c.request_id || '')+'</span><div style="margin-top:8px">'+(hashes || '<span class="muted">No signed receipt hash found</span>')+'</div></div>';
  }).join('') || '<p class="muted">No receipt chains yet.</p>';
}
function renderPolicyPacks(info){
  var available = info.available || [];
  var installed = new Set(info.installed || []);
  document.getElementById('policy-packs').innerHTML = available.map(function(pack){
    var isInstalled = installed.has(pack.id);
    var files = (pack.files || []).map(function(f){ return f.path; }).join(', ');
    return '<div class="pack '+(isInstalled ? 'installed' : '')+'">'+
      '<div style="display:flex;gap:8px;align-items:center"><strong>'+escapeHtml(pack.name)+'</strong><span class="pill '+(isInstalled ? 'exact' : 'wildcard')+'">'+(isInstalled ? 'installed' : escapeHtml(pack.recommendedMode || 'shadow-first'))+'</span></div>'+
      '<p>'+escapeHtml(pack.description || '')+'</p>'+
      '<small>Writes to <code>'+escapeHtml((info.directory || './cedar') + '/' + files)+'</code></small>'+
      '<div class="row-actions"><button data-pack-install="'+escapeHtml(pack.id)+'">'+(isInstalled ? 'Reinstall' : 'Install')+'</button><button class="ghost" data-pack-preview="'+escapeHtml(pack.id)+'">Preview</button></div>'+
      '<pre id="pack-preview-'+escapeAttr(pack.id)+'" style="display:none;max-height:240px">'+escapeHtml((pack.files || []).map(function(f){ return '--- '+f.path+' ---\\n'+f.contents; }).join('\\n\\n'))+'</pre>'+
    '</div>';
  }).join('') || '<p class="muted">No policy packs bundled.</p>';
}
function renderConnectorPilots(info){
  var available = info.available || [];
  var installed = new Set((info.installed || []).map(function(row){ return row.id; }));
  var doctor = {};
  (info.doctor || []).forEach(function(row){ doctor[row.id] = row; });
  document.getElementById('connector-pilots').innerHTML = available.map(function(pilot){
    var row = doctor[pilot.id] || {};
    var isInstalled = installed.has(pilot.id);
    var status = row.installed ? (row.usable ? 'installed' : 'needs env') : 'not installed';
    var statusClass = row.installed ? (row.usable ? 'exact' : 'wildcard') : 'none';
    var missing = (row.missing_required || []).join(', ');
    var tools = (pilot.tools || []).slice(0,4).map(function(tool){ return '<code>'+escapeHtml(tool)+'</code>'; }).join(' ');
    return '<div class="pack '+(isInstalled ? 'installed' : '')+'">'+
      '<div style="display:flex;gap:8px;align-items:center"><strong>'+escapeHtml(pilot.name)+'</strong><span class="pill '+statusClass+'">'+escapeHtml(status)+'</span></div>'+
      '<p>'+escapeHtml(pilot.description || '')+'</p>'+
      '<small>'+escapeHtml(pilot.value || '')+'</small>'+
      '<div>'+tools+'</div>'+
      (missing ? '<small>Missing: <code>'+escapeHtml(missing)+'</code></small>' : '<small>'+escapeHtml(row.next || 'Ready for shadow-mode review.')+'</small>')+
      '<details><summary>Details</summary><pre>'+escapeHtml(JSON.stringify({ setup: pilot.setup, actions: pilot.actions, doctor: row }, null, 2))+'</pre></details>'+
      '<div class="row-actions"><button data-connector-install="'+escapeHtml(pilot.id)+'">'+(isInstalled ? 'Reinstall' : 'Install')+'</button><button class="ghost" data-connector-doctor="1">Run doctor</button></div>'+
    '</div>';
  }).join('') || '<p class="muted">No connector pilots bundled.</p>';
}
function renderRegistry(reg){
  var boundaryClass = reg.hosted ? 'exact' : reg.registry_exists ? 'wildcard' : 'none';
  document.getElementById('registry').innerHTML =
    '<div class="chain-item"><span class="pill '+boundaryClass+'">'+escapeHtml(reg.boundary || 'not configured')+'</span>'+
    '<p style="margin-top:8px"><strong>'+escapeHtml(reg.org_name || 'No org identity yet')+'</strong></p>'+
    '<p class="muted">Digests: '+(reg.records || 0)+' \xB7 Anchors: '+(reg.anchors || 0)+'</p>'+
    '<p class="muted mono" style="margin-top:6px">'+escapeHtml(reg.registry_path || '')+'</p></div>'+
    '<div class="field"><label>Org name</label><input id="registry-org" placeholder="Meridian Global Macro" value="'+escapeHtml(reg.org_name || '')+'"></div>'+
    '<div class="field"><label>Hosted token (optional, not stored)</label><input id="registry-token" type="password" placeholder="SCOPEBLIND_TOKEN for hosted digest anchoring"></div>'+
    '<div class="row-actions" style="margin-top:10px"><button data-registry-anchor="local">Create local registry preview</button><button class="secondary" data-registry-anchor="hosted">Hosted digest anchor</button></div>'+
    '<small style="display:block;margin-top:8px">Hosted mode uploads digest metadata only: receipt hash, byte count, receipt type, request id, local issuer/kid, org id, billing account, and public keys. It does not upload prompts, tool payloads, outputs, raw receipts, or private keys.</small>';
}
async function setPolicy(tool, action){
  var res = await fetch('/api/tool-policy', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ tool: tool, action: action }) });
  if(!res.ok){ toast('Policy update failed'); return; }
  toast('Policy updated: '+tool+' -> '+action+'. Restart the wrapper to apply.');
  await refresh();
}
async function resolveApproval(requestId, tool, resolution){
  var reasonEl = document.getElementById('reason-'+escapeAttr(requestId));
  var reason = reasonEl ? reasonEl.value : '';
  var edited = undefined;
  if(resolution === 'edit'){
    var raw = prompt('Paste edited JSON payload. This records the edit instruction; rerun the tool with the edited payload.');
    if(raw){ try { edited = JSON.parse(raw); } catch(e){ toast('Edit payload is not valid JSON'); return; } }
  }
  var res = await fetch('/api/approval/resolve', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ request_id: requestId, tool: tool, resolution: resolution, reason: reason, edited_payload: edited }) });
  var body = await res.json().catch(function(){ return {}; });
  toast(resolution+' recorded'+(body.forwarded && body.forwarded.ok ? ' and forwarded to live gateway' : ' locally'));
}
async function installPack(pack){
  var res = await fetch('/api/policy-packs/install', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ pack: pack, force: true }) });
  var body = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(body.error || 'Policy pack install failed'); return; }
  toast('Installed '+pack+' into '+body.dir);
  await refresh();
}
async function installConnector(pilot){
  var res = await fetch('/api/connectors/install', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ pilot: pilot, force: true }) });
  var body = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(body.error || 'Connector install failed'); return; }
  toast('Installed '+pilot+' into '+body.dir);
  await refresh();
}
function togglePackPreview(pack){
  var el = document.getElementById('pack-preview-'+escapeAttr(pack));
  if(el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
async function anchorRegistry(mode){
  var org = document.getElementById('registry-org') ? document.getElementById('registry-org').value : '';
  var token = document.getElementById('registry-token') ? document.getElementById('registry-token').value : '';
  var body = { org_name: org, hosted: mode === 'hosted', token: token };
  var res = await fetch('/api/registry/anchor', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body) });
  var out = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(out.error || 'Registry anchor failed'); return; }
  toast((out.uploaded ? 'Hosted anchor complete' : 'Local registry preview written') + ': ' + out.records + ' digest(s)');
  await refresh();
}
async function exportBundle(){
  var res = await fetch('/api/audit-bundle');
  if(!res.ok){
    var err = await res.json().catch(function(){ return {}; });
    toast(err.message || 'Audit bundle export requires signed receipts');
    return;
  }
  var blob = await res.blob();
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'protect-mcp-audit-bundle.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
}
document.addEventListener('click', function(ev){
  var target = ev.target && ev.target.closest ? ev.target.closest('[data-policy-tool],[data-approval-id],[data-pack-install],[data-pack-preview],[data-registry-anchor],[data-connector-install],[data-connector-doctor]') : null;
  if(!target) return;
  var connectorInstall = target.getAttribute('data-connector-install');
  if(connectorInstall){ installConnector(connectorInstall); return; }
  if(target.getAttribute('data-connector-doctor')){ toast('Connector doctor refreshed. Missing secrets are shown as names only, never values.'); refresh(); return; }
  var packInstall = target.getAttribute('data-pack-install');
  if(packInstall){ installPack(packInstall); return; }
  var packPreview = target.getAttribute('data-pack-preview');
  if(packPreview){ togglePackPreview(packPreview); return; }
  var anchorMode = target.getAttribute('data-registry-anchor');
  if(anchorMode){ anchorRegistry(anchorMode); return; }
  var policyTool = target.getAttribute('data-policy-tool');
  if(policyTool){
    setPolicy(policyTool, target.getAttribute('data-policy-action') || 'require_approval');
    return;
  }
  var approvalId = target.getAttribute('data-approval-id');
  if(approvalId){
    resolveApproval(approvalId, target.getAttribute('data-approval-tool') || '', target.getAttribute('data-approval-resolution') || 'deny');
  }
});
function toast(msg){ var el=document.getElementById('toast'); el.textContent=msg; el.style.display='block'; setTimeout(function(){el.style.display='none';}, 4200); }
function escapeHtml(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function escapeAttr(v){ return String(v || '').replace(/[^A-Za-z0-9_-]/g,'_'); }
refresh();
</script>
</body>
</html>`;
}
async function handleDashboard(argv) {
  const { createServer: createServer4 } = await import("http");
  const { execFile } = await import("child_process");
  const { resolve: resolve5 } = await import("path");
  const port = commandNeedsValue(argv, "--port") ? parseInt(flagValue(argv, "--port") || "9877", 10) : 9877;
  const dir = resolve5(commandNeedsValue(argv, "--dir") ? flagValue(argv, "--dir") || process.cwd() : process.cwd());
  const policyPath = resolve5(flagValue(argv, "--policy") || (0, import_node_path16.join)(dir, "protect-mcp.json"));
  const approvalEndpoint = flagValue(argv, "--approval-endpoint");
  const approvalNonce = flagValue(argv, "--approval-nonce");
  const open = argv.includes("--open");
  const server = createServer4((req, res) => {
    void (async () => {
      try {
        const url2 = new URL(req.url || "/", "http://127.0.0.1");
        if (url2.pathname === "/api/summary") {
          const body = JSON.stringify(buildDashboardSummary(dir, policyPath), null, 2);
          res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
          res.end(body);
          return;
        }
        if (url2.pathname === "/api/tool-policy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const tool = typeof body.tool === "string" ? body.tool : "";
          const action = body.action === "block" || body.action === "observe" ? body.action : "require_approval";
          if (!tool) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_tool" }));
            return;
          }
          const policy = writeToolPolicy(policyPath, tool, action);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, policy_path: policyPath, policy }));
          return;
        }
        if (url2.pathname === "/api/policy-packs/install" && req.method === "POST") {
          const body = await readJsonBody(req);
          const pack = typeof body.pack === "string" ? body.pack : "";
          if (!pack) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_policy_pack" }));
            return;
          }
          const installed = installPolicyPackToDir(dir, pack, Boolean(body.force));
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            ok: true,
            ...installed,
            installed: installedPolicyPackIds(dir)
          }));
          return;
        }
        if (url2.pathname === "/api/connectors/install" && req.method === "POST") {
          const body = await readJsonBody(req);
          const pilot = typeof body.pilot === "string" ? body.pilot : "";
          if (!pilot) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_connector_pilot" }));
            return;
          }
          const installed = writeConnectorPilots({ dir, ids: [pilot], force: Boolean(body.force) });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            ok: true,
            dir: installed.directory,
            written: installed.written,
            installed: readInstalledConnectorPilots(dir),
            doctor: connectorDoctor(dir)
          }));
          return;
        }
        if (url2.pathname === "/api/registry/anchor" && req.method === "POST") {
          const body = await readJsonBody(req);
          const { createReceiptRegistry: createReceiptRegistry2 } = await Promise.resolve().then(() => (init_receipt_registry(), receipt_registry_exports));
          try {
            const hosted = Boolean(body.hosted);
            const result2 = await createReceiptRegistry2({
              dir,
              orgName: typeof body.org_name === "string" && body.org_name.trim() ? body.org_name.trim() : void 0,
              orgId: typeof body.org_id === "string" && body.org_id.trim() ? body.org_id.trim() : void 0,
              billingAccountId: typeof body.billing_account_id === "string" && body.billing_account_id.trim() ? body.billing_account_id.trim() : void 0,
              hosted,
              token: typeof body.token === "string" && body.token.trim() ? body.token.trim() : process.env.SCOPEBLIND_TOKEN,
              endpoint: typeof body.endpoint === "string" && body.endpoint.trim() ? body.endpoint.trim() : hosted ? process.env.SCOPEBLIND_REGISTRY_ENDPOINT || "https://api.scopeblind.com" : void 0,
              verifierBaseUrl: typeof body.verifier_base === "string" && body.verifier_base.trim() ? body.verifier_base.trim() : process.env.SCOPEBLIND_VERIFIER_BASE || "https://legate.scopeblind.com"
            });
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({
              ok: true,
              uploaded: result2.uploaded,
              records: result2.registry.records.length,
              anchors: result2.registry.anchors.length,
              registry_path: result2.registryPath,
              verifier_path: result2.verifierPath,
              registry: dashboardRegistryStatus(dir)
            }));
          } catch (err) {
            res.writeHead(409, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
            res.end(JSON.stringify({
              error: "registry_anchor_unavailable",
              message: err instanceof Error ? err.message : String(err),
              next_step: "Run protect-mcp with signing enabled so decisions are written as signed receipts, then try again."
            }));
          }
          return;
        }
        if (url2.pathname === "/api/approval/resolve" && req.method === "POST") {
          const body = await readJsonBody(req);
          const result2 = await recordApprovalResolution({ dir, approvalEndpoint, approvalNonce, body });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(result2));
          return;
        }
        if (url2.pathname === "/api/audit-bundle") {
          let bundle;
          try {
            bundle = await buildAuditBundleForDir(dir);
          } catch (err) {
            res.writeHead(409, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
            res.end(JSON.stringify({
              error: "audit_bundle_unavailable",
              message: err instanceof Error ? err.message : String(err),
              next_step: "Run protect-mcp with signing enabled so decisions are written as signed receipts, then export again."
            }));
            return;
          }
          res.writeHead(200, {
            "content-type": "application/json; charset=utf-8",
            "content-disposition": 'attachment; filename="protect-mcp-audit-bundle.json"',
            "cache-control": "no-store"
          });
          res.end(JSON.stringify(bundle, null, 2) + "\n");
          return;
        }
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        });
        res.end(dashboardHtml());
      } catch (err) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
    })();
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(port, "127.0.0.1", () => resolveListen());
  });
  const url = `http://127.0.0.1:${port}`;
  process.stderr.write(`
${bold2("protect-mcp dashboard")}

`);
  process.stderr.write(`  Local URL: ${url}
`);
  process.stderr.write(`  Reading:   ${dir}
`);
  process.stderr.write(`  Policy:    ${policyPath}
`);
  process.stderr.write(`  Network:   127.0.0.1 only; no uploads

`);
  if (open) {
    const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
    const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
    execFile(opener, args, () => {
    });
  }
}
function draftPolicyFromSummary(summary) {
  const files = summary.files || {};
  const rows = Array.isArray(summary.tools) ? summary.tools : [];
  const tools = {
    "*": { rate_limit: "100/hour" }
  };
  for (const row of rows) {
    if (!row.tool || row.tool === "unknown") continue;
    const suggestion = row.suggestion || suggestedGuardrailFor(row.tool, row.risk || "low", row.reasons || []);
    tools[row.tool] = suggestion.policy;
  }
  return {
    tools,
    default_tier: "unknown",
    signing: files.key_exists ? {
      key_path: "./keys/gateway.json",
      issuer: "protect-mcp"
    } : void 0,
    notes: [
      "Generated from local shadow-mode inventory.",
      "Review before running with --enforce.",
      "High-risk transaction, deployment, external-send, and database tools require approval.",
      "Destructive and secret-handling tools are blocked by default."
    ]
  };
}
function writeToolPolicy(policyPath, tool, action) {
  const existing = loadPolicyJson(policyPath) || { tools: {}, default_tier: "unknown" };
  const tools = existing.tools && typeof existing.tools === "object" ? { ...existing.tools } : {};
  if (action === "require_approval") {
    tools[tool] = { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" };
  } else if (action === "block") {
    tools[tool] = { block: true, min_tier: "privileged" };
  } else {
    tools[tool] = { rate_limit: "100/hour" };
  }
  const next = {
    ...existing,
    tools,
    default_tier: existing.default_tier || "unknown"
  };
  (0, import_node_fs21.writeFileSync)(policyPath, JSON.stringify(next, null, 2) + "\n");
  return next;
}
function policyPackDirectory(dir) {
  return (0, import_node_path16.join)(dir, "cedar");
}
function installedPolicyPackIds(dir) {
  const cedarDir = policyPackDirectory(dir);
  return POLICY_PACKS.filter(
    (pack) => pack.files.every((file) => (0, import_node_fs21.existsSync)((0, import_node_path16.join)(cedarDir, file.path)))
  ).map((pack) => pack.id);
}
function installPolicyPackToDir(dir, packId, force = false) {
  const packs = packId === "all" ? POLICY_PACKS : [getPolicyPack(packId)].filter(Boolean);
  if (packs.length === 0) throw new Error(`Unknown policy pack: ${packId}`);
  const outDir = policyPackDirectory(dir);
  (0, import_node_fs21.mkdirSync)(outDir, { recursive: true });
  const written = [];
  for (const pack of packs) {
    for (const file of pack.files) {
      const outPath = (0, import_node_path16.join)(outDir, file.path);
      if ((0, import_node_fs21.existsSync)(outPath) && !force) {
        throw new Error(`Refusing to overwrite ${outPath}. Pass force=true if intentional.`);
      }
      (0, import_node_fs21.mkdirSync)((0, import_node_path16.dirname)(outPath), { recursive: true });
      (0, import_node_fs21.writeFileSync)(outPath, file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
      written.push(outPath);
    }
  }
  return { dir: outDir, written, packs: packs.map((pack) => pack.id) };
}
function dashboardRegistryStatus(dir) {
  const identityPath = (0, import_node_path16.join)(dir, ".protect-mcp-org.json");
  const registryPath = (0, import_node_path16.join)(dir, ".protect-mcp-registry.json");
  const verifierPath = (0, import_node_path16.join)(dir, "scopeblind-verifier.html");
  const identity = (0, import_node_fs21.existsSync)(identityPath) ? (() => {
    try {
      return JSON.parse((0, import_node_fs21.readFileSync)(identityPath, "utf-8"));
    } catch {
      return null;
    }
  })() : null;
  const registry = (0, import_node_fs21.existsSync)(registryPath) ? (() => {
    try {
      return JSON.parse((0, import_node_fs21.readFileSync)(registryPath, "utf-8"));
    } catch {
      return null;
    }
  })() : null;
  const anchors = Array.isArray(registry?.anchors) ? registry.anchors : [];
  const hosted = anchors.some((anchor) => anchor.timestamp_source === "scopeblind-hosted");
  return {
    identity_exists: (0, import_node_fs21.existsSync)(identityPath),
    registry_exists: (0, import_node_fs21.existsSync)(registryPath),
    verifier_exists: (0, import_node_fs21.existsSync)(verifierPath),
    identity_path: identityPath,
    registry_path: registryPath,
    verifier_path: verifierPath,
    org_name: identity?.org_name || (registry?.org && typeof registry.org === "object" ? registry.org.org_name : null),
    org_id: identity?.org_id || (registry?.org && typeof registry.org === "object" ? registry.org.org_id : null),
    billing_account_id: identity?.billing_account_id || (registry?.billing && typeof registry.billing === "object" ? registry.billing.billing_account_id : null),
    records: Array.isArray(registry?.records) ? registry.records.length : 0,
    anchors: anchors.length,
    hosted,
    boundary: hosted ? "hosted digest anchor" : registry ? "local preview only" : "not configured"
  };
}
async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  const raw = Buffer.concat(chunks).toString("utf-8").trim();
  return raw ? JSON.parse(raw) : {};
}
async function buildAuditBundleForDir(dir) {
  const { createAuditBundle: createAuditBundle2 } = await Promise.resolve().then(() => (init_bundle(), bundle_exports));
  const receiptPath = (0, import_node_path16.join)(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = (0, import_node_path16.join)(dir, "keys", "gateway.json");
  if (!(0, import_node_fs21.existsSync)(receiptPath)) throw new Error("No receipt file found.");
  if (!(0, import_node_fs21.existsSync)(keyPath)) throw new Error("No signing key found.");
  const receipts = parseJsonlFile(receiptPath);
  if (receipts.length === 0) throw new Error("No signed receipts found.");
  const keyData = JSON.parse((0, import_node_fs21.readFileSync)(keyPath, "utf-8"));
  return createAuditBundle2({
    tenant: keyData.issuer || "protect-mcp",
    receipts,
    selectiveDisclosures: collectSelectiveDisclosurePackages(dir),
    signingKeys: [{
      kty: "OKP",
      crv: "Ed25519",
      kid: keyData.kid || "unknown",
      x: Buffer.from(keyData.publicKey || "", "hex").toString("base64url"),
      use: "sig"
    }]
  });
}
function collectSelectiveDisclosurePackages(dir) {
  const out2 = [];
  const seen = /* @__PURE__ */ new Set();
  const candidates = [];
  const receiptsDir = (0, import_node_path16.join)(dir, "receipts");
  if ((0, import_node_fs21.existsSync)(receiptsDir)) {
    for (const name of (0, import_node_fs21.readdirSync)(receiptsDir)) {
      if (name.includes("selective-disclosure") && name.endsWith(".json")) {
        candidates.push((0, import_node_path16.join)(receiptsDir, name));
      }
    }
  }
  const jsonlPath = (0, import_node_path16.join)(dir, ".protect-mcp-selective-disclosures.jsonl");
  if ((0, import_node_fs21.existsSync)(jsonlPath)) {
    for (const line of (0, import_node_fs21.readFileSync)(jsonlPath, "utf-8").split("\n").map((s) => s.trim()).filter(Boolean)) {
      try {
        const parsed = JSON.parse(line);
        addSelectiveDisclosure(out2, seen, parsed);
      } catch {
      }
    }
  }
  for (const path of candidates) {
    try {
      const parsed = JSON.parse((0, import_node_fs21.readFileSync)(path, "utf-8"));
      addSelectiveDisclosure(out2, seen, parsed);
    } catch {
    }
  }
  return out2;
}
function addSelectiveDisclosure(out2, seen, parsed) {
  if (parsed?.type !== "scopeblind.selective_disclosure.v0") return;
  const key = [
    parsed.parent_receipt_hash || "",
    Array.isArray(parsed.disclosed_fields) ? parsed.disclosed_fields.slice().sort().join(",") : "",
    Array.isArray(parsed.hidden_fields) ? parsed.hidden_fields.slice().sort().join(",") : ""
  ].join("|");
  if (seen.has(key)) return;
  seen.add(key);
  out2.push(parsed);
}
async function recordApprovalResolution(opts) {
  const resolution = String(opts.body.resolution || "deny");
  const requestId = String(opts.body.request_id || "");
  const tool = String(opts.body.tool || "unknown");
  const record = {
    type: "scopeblind.approval_resolution.v1",
    at: (/* @__PURE__ */ new Date()).toISOString(),
    request_id: requestId,
    tool,
    resolution,
    reason: typeof opts.body.reason === "string" ? opts.body.reason.slice(0, 1e3) : "",
    edited_payload: opts.body.edited_payload || void 0,
    takeover_note: opts.body.takeover_note || void 0,
    payload_hash: opts.body.payload_hash || void 0
  };
  (0, import_node_fs21.appendFileSync)((0, import_node_path16.join)(opts.dir, ".protect-mcp-approval-resolutions.jsonl"), JSON.stringify(record) + "\n");
  let forwarded = null;
  if (resolution === "approve" && opts.approvalEndpoint && opts.approvalNonce) {
    const endpoint2 = opts.approvalEndpoint.replace(/\/$/, "") + "/approve";
    const response = await fetch(endpoint2, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        request_id: requestId,
        tool,
        mode: "once",
        nonce: opts.approvalNonce
      })
    });
    forwarded = {
      ok: response.ok,
      status: response.status,
      body: await response.text().catch(() => "")
    };
  }
  return { recorded: true, resolution: record, forwarded };
}
async function handleRecommend(argv) {
  const { writeFileSync: writeFileSync11 } = await import("fs");
  const { resolve: resolve5 } = await import("path");
  const dir = resolve5(commandNeedsValue(argv, "--dir") ? flagValue(argv, "--dir") || process.cwd() : process.cwd());
  const outputPath = resolve5(flagValue(argv, "--output") || "protect-mcp.recommended.json");
  const write = argv.includes("--write");
  const summary = buildDashboardSummary(dir);
  const totals = summary.totals;
  const policy = draftPolicyFromSummary(summary);
  const rows = Array.isArray(summary.tools) ? summary.tools : [];
  process.stdout.write(`
${bold2("protect-mcp recommend")}

`);
  process.stdout.write(`  Source:    ${dir}
`);
  process.stdout.write(`  Decisions: ${totals.decisions || 0}
`);
  process.stdout.write(`  Tools:     ${totals.tools || 0}

`);
  if (rows.length === 0) {
    process.stdout.write(`No tool calls found yet. First run:

`);
    process.stdout.write(`  ${dim2("npx protect-mcp wrap -- node your-mcp-server.js")}
`);
    process.stdout.write(`  ${dim2("npx protect-mcp dashboard --open")}

`);
    return;
  }
  for (const row of rows) {
    const suggestion = row.suggestion || suggestedGuardrailFor(row.tool, row.risk, row.reasons);
    process.stdout.write(`  - ${row.tool}: ${bold2(suggestion.action)} (${row.risk})
`);
    process.stdout.write(`    ${dim2(suggestion.reason)}
`);
  }
  const body = JSON.stringify(policy, null, 2) + "\n";
  if (!write) {
    process.stdout.write(`
Dry run only. Write the policy with:
`);
    process.stdout.write(`  ${dim2("npx protect-mcp recommend --write")}

`);
    process.stdout.write(dim2(body));
    return;
  }
  writeFileSync11(outputPath, body);
  process.stdout.write(`
${green2("\u2713 Wrote recommended policy")}
`);
  process.stdout.write(`  Output: ${outputPath}
`);
  process.stdout.write(`  Review it, then restart your wrapper with:
`);
  process.stdout.write(`  ${dim2(shellCommand("npx", ["protect-mcp", "--policy", outputPath, "--enforce", "--", "node", "your-mcp-server.js"]))}

`);
}
async function handleWrap(argv) {
  const { existsSync: existsSync13, readFileSync: readFileSync19, writeFileSync: writeFileSync11 } = await import("fs");
  const { resolve: resolve5 } = await import("path");
  const configFlag = flagValue(argv, "--config");
  const cedarFlag = flagValue(argv, "--cedar");
  const enforce = argv.includes("--enforce");
  const write = argv.includes("--write");
  const claudeDesktop = argv.includes("--claude-desktop") || argv.includes("--claude");
  const serverName = flagValue(argv, "--server");
  const separator = argv.indexOf("--");
  const childCommand = separator >= 0 ? argv.slice(separator + 1).filter(Boolean) : [];
  const configPath = cedarFlag ? void 0 : resolve5(configFlag || await ensureLocalConfig(process.cwd()));
  const cedarDir = cedarFlag ? resolve5(cedarFlag) : void 0;
  const standardFlag = flagValue(argv, "--standard");
  const standardPath = standardFlag ? resolve5(standardFlag) : void 0;
  const reportUrl = flagValue(argv, "--report") || void 0;
  const reportToken = flagValue(argv, "--report-token") || void 0;
  const runId = flagValue(argv, "--run") || void 0;
  if (childCommand.length > 0) {
    const args = wrapperArgsFor(childCommand, { configPath, cedarDir, enforce, standardPath, reportUrl, reportToken, runId });
    process.stdout.write(`
${bold2("protect-mcp wrap")}

`);
    process.stdout.write(`Use this command in your MCP client config:

`);
    process.stdout.write(`  ${shellCommand("npx", args)}

`);
    process.stdout.write(`Claude Desktop JSON snippet:

`);
    process.stdout.write(dim2(JSON.stringify({
      command: "npx",
      args
    }, null, 2)) + "\n\n");
    process.stdout.write(`Then inspect calls with: ${dim2("npx protect-mcp dashboard --open")}

`);
    return;
  }
  const claudePath = resolve5(flagValue(argv, "--path") || claudeDesktopConfigPath());
  if (!claudeDesktop && !existsSync13(claudePath)) {
    process.stdout.write(`
${bold2("protect-mcp wrap")}

`);
    process.stdout.write(`No command was passed after "--" and no Claude Desktop config was found.

`);
    process.stdout.write(`Examples:
`);
    process.stdout.write(`  ${dim2("npx protect-mcp wrap -- node server.js")}
`);
    process.stdout.write(`  ${dim2("npx protect-mcp wrap --claude-desktop --write")}

`);
    return;
  }
  if (!existsSync13(claudePath)) {
    process.stderr.write(`protect-mcp wrap: Claude Desktop config not found at ${claudePath}
`);
    process.exit(1);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync19(claudePath, "utf-8"));
  } catch (err) {
    process.stderr.write(`protect-mcp wrap: could not parse ${claudePath}: ${err instanceof Error ? err.message : err}
`);
    process.exit(1);
  }
  const servers = parsed.mcpServers || {};
  const names = Object.keys(servers).filter((name) => !serverName || name === serverName);
  if (names.length === 0) {
    process.stderr.write(`protect-mcp wrap: no MCP servers found${serverName ? ` matching "${serverName}"` : ""}.
`);
    process.exit(1);
  }
  const next = { ...parsed, mcpServers: { ...servers } };
  const changes = [];
  for (const name of names) {
    const before = servers[name] || {};
    const originalCommand = before.command;
    const originalArgs = Array.isArray(before.args) ? before.args : [];
    if (!originalCommand) {
      changes.push({ name, before, after: before, skipped: "missing command" });
      continue;
    }
    if (originalCommand === "npx" && originalArgs.some((arg) => String(arg).includes("protect-mcp"))) {
      changes.push({ name, before, after: before, skipped: "already wrapped" });
      continue;
    }
    const wrappedArgs = wrapperArgsFor([originalCommand, ...originalArgs], { configPath, cedarDir, enforce, standardPath, reportUrl, reportToken, runId });
    const after = { ...before, command: "npx", args: wrappedArgs };
    next.mcpServers[name] = after;
    changes.push({ name, before, after });
  }
  process.stdout.write(`
${bold2("protect-mcp wrap: Claude Desktop")}

`);
  process.stdout.write(`Config: ${claudePath}
`);
  process.stdout.write(`Mode:   ${enforce ? "enforce" : "shadow"}

`);
  for (const change of changes) {
    if (change.skipped) {
      process.stdout.write(`  - ${change.name}: ${yellow2(change.skipped)}
`);
    } else {
      process.stdout.write(`  - ${change.name}: ${green2("will wrap")}
`);
      process.stdout.write(`    ${dim2(`${change.before.command || ""} ${(change.before.args || []).join(" ")}`)}
`);
      process.stdout.write(`    ${dim2(shellCommand("npx", change.after.args || []))}
`);
    }
  }
  if (!write) {
    process.stdout.write(`
Dry run only. Apply with:
`);
    process.stdout.write(`  ${dim2("npx protect-mcp wrap --claude-desktop --write")}

`);
    return;
  }
  const backupPath = `${claudePath}.bak.${Date.now()}`;
  writeFileSync11(backupPath, readFileSync19(claudePath, "utf-8"));
  writeFileSync11(claudePath, JSON.stringify(next, null, 2) + "\n");
  process.stdout.write(`
${green2("\u2713 Claude Desktop config updated")}
`);
  process.stdout.write(`  Backup: ${backupPath}
`);
  process.stdout.write(`  Restart Claude Desktop, then run: ${dim2("npx protect-mcp dashboard --open")}

`);
}
function bold2(s) {
  return process.env.NO_COLOR ? s : `\x1B[1m${s}\x1B[0m`;
}
function dim2(s) {
  return process.env.NO_COLOR ? s : `\x1B[2m${s}\x1B[0m`;
}
function green2(s) {
  return process.env.NO_COLOR ? s : `\x1B[32m${s}\x1B[0m`;
}
function red2(s) {
  return process.env.NO_COLOR ? s : `\x1B[31m${s}\x1B[0m`;
}
function yellow2(s) {
  return process.env.NO_COLOR ? s : `\x1B[33m${s}\x1B[0m`;
}
async function handleDigest(argv) {
  const { readFileSync: readFileSync19, existsSync: existsSync13 } = await import("fs");
  const { join: join13 } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const today = argv.includes("--today");
  const logPath = join13(dir, ".protect-mcp-log.jsonl");
  if (!existsSync13(logPath)) {
    process.stderr.write(`${bold2("protect-mcp digest")}

No log file found. Run protect-mcp first.
`);
    process.exit(0);
  }
  const raw = readFileSync19(logPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  let entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
    }
  }
  if (today) {
    const todayStart = /* @__PURE__ */ new Date();
    todayStart.setHours(0, 0, 0, 0);
    entries = entries.filter((e) => e.timestamp >= todayStart.getTime());
  }
  if (entries.length === 0) {
    process.stdout.write(`
${bold2("\u{1F6E1}\uFE0F Agent Digest")}

  No activity${today ? " today" : ""}.

`);
    process.exit(0);
  }
  const allowed = entries.filter((e) => e.decision === "allow").length;
  const denied = entries.filter((e) => e.decision === "deny").length;
  const approvalRequired = entries.filter((e) => e.decision === "require_approval").length;
  const toolUsage = /* @__PURE__ */ new Map();
  for (const e of entries) {
    toolUsage.set(e.tool, (toolUsage.get(e.tool) || 0) + 1);
  }
  const sortedTools = [...toolUsage.entries()].sort((a, b) => b[1] - a[1]);
  const currentTier = entries[entries.length - 1]?.tier || "unknown";
  const firstTime = new Date(Math.min(...entries.map((e) => e.timestamp)));
  const lastTime = new Date(Math.max(...entries.map((e) => e.timestamp)));
  const durationMs = lastTime.getTime() - firstTime.getTime();
  const durationStr = durationMs < 6e4 ? `${Math.round(durationMs / 1e3)}s` : durationMs < 36e5 ? `${Math.round(durationMs / 6e4)}m` : `${(durationMs / 36e5).toFixed(1)}h`;
  process.stdout.write(`
${bold2("\u{1F6E1}\uFE0F Agent Daily Digest")}

`);
  process.stdout.write(`  \u{1F4CA} ${bold2(String(entries.length))} actions | `);
  process.stdout.write(`${green2("\u2713 " + allowed)} allowed | `);
  process.stdout.write(`${red2("\u2717 " + denied)} blocked`);
  if (approvalRequired > 0) process.stdout.write(` | ${yellow2("\u23F3 " + approvalRequired)} awaiting approval`);
  process.stdout.write(`
`);
  process.stdout.write(`  \u{1F3C5} Trust tier: ${bold2(currentTier)} | \u23F1 Active: ${durationStr}

`);
  process.stdout.write(`  ${bold2("Tools used:")}
`);
  for (const [tool, count] of sortedTools.slice(0, 8)) {
    process.stdout.write(`    ${tool.padEnd(22)} ${count}x
`);
  }
  if (denied > 0) {
    const deniedTools = entries.filter((e) => e.decision === "deny");
    const deniedToolNames = [...new Set(deniedTools.map((e) => e.tool))];
    process.stdout.write(`
  ${bold2(red2("Blocked tools:"))}
`);
    for (const tool of deniedToolNames) {
      const reason = deniedTools.find((e) => e.tool === tool)?.reason_code || "policy";
      process.stdout.write(`    ${red2("\u2717")} ${tool} (${reason})
`);
    }
  }
  process.stdout.write(`
  ${dim2("Latest receipt: curl -s http://127.0.0.1:9876/receipts/latest | jq -r .receipt > receipt.json")}
`);
  process.stdout.write(`  ${dim2("Verify: npx @veritasacta/verify receipt.json --key <public-key-hex>")}
`);
  process.stdout.write(`  ${dim2("Export: npx protect-mcp bundle --output audit.json")}

`);
}
async function handleReceipts2(argv) {
  const { readFileSync: readFileSync19, existsSync: existsSync13 } = await import("fs");
  const { join: join13 } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const lastIdx = argv.indexOf("--last");
  const count = lastIdx !== -1 && argv[lastIdx + 1] ? parseInt(argv[lastIdx + 1], 10) : 20;
  const receiptsPath = join13(dir, ".protect-mcp-receipts.jsonl");
  if (!existsSync13(receiptsPath)) {
    process.stderr.write(`${bold2("protect-mcp receipts")}

No signed receipt file found. Run protect-mcp with signing enabled first.
`);
    process.exit(0);
  }
  const raw = readFileSync19(receiptsPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  const recent = lines.slice(-count);
  process.stdout.write(`
${bold2("\u{1F6E1}\uFE0F Recent Receipts")} (last ${recent.length})

`);
  for (const line of recent) {
    try {
      const entry = JSON.parse(line);
      const payload = entry.payload || {};
      const time5 = typeof entry.issued_at === "string" ? new Date(entry.issued_at).toLocaleTimeString() : "unknown";
      const decision = payload.decision || "unknown";
      const icon = decision === "allow" ? green2("\u2713") : decision === "require_approval" ? yellow2("\u23F3") : red2("\u2717");
      process.stdout.write(`  ${dim2(time5)} ${icon} ${String(payload.tool || "unknown").padEnd(22)} ${String(entry.type || "receipt").padEnd(18)} ${dim2(String(payload.reason_code || "signed"))}
`);
    } catch {
    }
  }
  process.stdout.write(`
`);
}
var _pkgV = null;
async function pkgVersion() {
  if (_pkgV) return _pkgV;
  let v = "0.0.0";
  try {
    const { readFileSync: readFileSync19, existsSync: existsSync13, realpathSync } = await import("fs");
    const { dirname: dirname6, join: join13, resolve: resolve5 } = await import("path");
    let base = "";
    try {
      base = dirname6(realpathSync(resolve5(process.argv[1] || "")));
    } catch {
    }
    const candidates = [
      base ? join13(base, "..", "package.json") : "",
      base ? join13(base, "package.json") : ""
    ].filter(Boolean);
    for (const p of candidates) {
      if (existsSync13(p)) {
        const parsed = JSON.parse(readFileSync19(p, "utf-8"));
        if (parsed && parsed.name === "protect-mcp" && parsed.version) {
          v = parsed.version;
          break;
        }
      }
    }
  } catch {
  }
  _pkgV = v;
  return v;
}
function mapRecordEntry(e) {
  const p = e && e.payload && typeof e.payload === "object" ? e.payload : e;
  const dec = String(p.decision || e.decision || "").toLowerCase();
  const verdict = /den|block|reject|refus/.test(dec) ? "blocked" : /ask|approv|hold|escal|review|pending/.test(dec) ? "held" : "allowed";
  const tsRaw = e.issued_at || e.timestamp || p.timestamp || p.issued_at;
  const ms = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "string" ? Date.parse(tsRaw) : NaN;
  const ts = isFinite(ms) ? new Date(ms).toISOString() : "";
  const tool = String(p.tool || e.tool || "action");
  const reason = String(p.reason_code || e.reason_code || p.policy_engine || "signed");
  const hook = String(p.hook_event || e.hook_event || "");
  const signed2 = !!(e.signature || e.sig || e.receipt_hash || typeof e.type === "string" && e.type.indexOf("receipt") >= 0);
  let digest = "";
  if (e.receipt_hash) digest = String(e.receipt_hash);
  else if (e.digest) digest = String(e.digest);
  else if (p.payload_digest && p.payload_digest.output_hash) digest = String(p.payload_digest.output_hash);
  const enr = p && typeof p.enrichment === "object" && p.enrichment || typeof e.enrichment === "object" && e.enrichment || null;
  const caps = enr && Array.isArray(enr.capabilities) ? enr.capabilities.map(String) : [];
  const sw = p && typeof p.swarm === "object" && p.swarm || null;
  const agent = sw && (sw.agent_name || sw.agent_id || sw.agent_type) ? String(sw.agent_name || sw.agent_id || sw.agent_type) : "main agent";
  const tm = p && typeof p.timing === "object" && p.timing || null;
  const dur = tm && typeof tm.tool_duration_ms === "number" ? tm.tool_duration_ms : 0;
  return { ts, tool, verdict, reason, hook, signed: signed2, caps, agent, dur, id: String(e.request_id || p.request_id || ""), digest, raw: e };
}
async function handleRecord(argv) {
  const { readFileSync: readFileSync19, existsSync: existsSync13, writeFileSync: writeFileSync11 } = await import("fs");
  const { join: join13 } = await import("path");
  const osMod = await import("os");
  const cp = await import("child_process");
  let dir = process.cwd();
  const di = argv.indexOf("--dir");
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  const recPath = join13(dir, ".protect-mcp-receipts.jsonl");
  const logPath = join13(dir, ".protect-mcp-log.jsonl");
  const pick = () => existsSync13(recPath) ? recPath : existsSync13(logPath) ? logPath : null;
  const chosen = pick();
  if (!chosen) {
    process.stderr.write(`
${bold2("protect-mcp record")}

No record found in ${dir}.
Start the gate with ${bold2("npx protect-mcp serve")}, use your agent, then run this again.
`);
    process.stderr.write(`Tip: run this in the directory where your gate is signing (where .protect-mcp-receipts.jsonl lives), or pass ${bold2("--dir <path>")}.

`);
    process.exit(0);
    return;
  }
  const readRecs = (file) => readFileSync19(file, "utf-8").split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter((x) => x !== null).map(mapRecordEntry);
  let pinnedKey = "";
  let pinnedKid = "";
  try {
    const kd = JSON.parse(readFileSync19(join13(dir, "keys", "gateway.json"), "utf-8"));
    if (kd && typeof kd.publicKey === "string" && /^[0-9a-f]{64}$/i.test(kd.publicKey)) {
      pinnedKey = kd.publicKey;
      pinnedKid = typeof kd.kid === "string" ? kd.kid : "";
    }
  } catch {
  }
  const openTarget = (target) => {
    if (argv.includes("--no-open")) return;
    const platform = process.platform;
    const opener = platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
    const openArgs = platform === "win32" ? ["/c", "start", "", target] : [target];
    try {
      const child = cp.spawn(opener, openArgs, { stdio: "ignore", detached: true });
      child.unref();
    } catch {
    }
  };
  if (argv.includes("--live") || argv.includes("--watch")) {
    const http = await import("http");
    const pi = argv.indexOf("--port");
    const port = pi !== -1 && argv[pi + 1] ? parseInt(argv[pi + 1], 10) : 9378;
    const server = http.createServer((req, res) => {
      if (req.url && req.url.indexOf("/data") === 0) {
        let recs2 = [];
        const f = pick();
        try {
          if (f) recs2 = readRecs(f);
        } catch {
        }
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ recs: recs2, signed: f === recPath }));
        return;
      }
      const meta2 = { file: chosen, signed: pick() === recPath, count: 0, live: true, pinned_key: pinnedKey, pinned_kid: pinnedKid };
      const page = RECORD_HTML.replace("__DATA__", () => "[]").replace("__META__", () => JSON.stringify(meta2));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(page);
    });
    server.on("error", (e) => {
      process.stderr.write(`
protect-mcp record --live: could not start on port ${port}${e && e.code ? ` (${e.code})` : ""}. Try ${bold2("--port <n>")}.

`);
      process.exit(1);
    });
    server.listen(port, "127.0.0.1", () => {
      const url = `http://127.0.0.1:${port}`;
      openTarget(url);
      process.stdout.write(`
${bold2("\u{1F6E1}\uFE0F  Your record")} ${dim2("\xB7")} live at ${url}
`);
      process.stdout.write(`  Updates as your agent runs. All local, nothing uploaded. ${dim2("Ctrl-C to stop.")}

`);
    });
    return;
  }
  const recs = readRecs(chosen);
  const meta = { file: chosen, signed: chosen === recPath, count: recs.length, live: false, pinned_key: pinnedKey, pinned_kid: pinnedKid };
  const html = RECORD_HTML.replace("__DATA__", () => JSON.stringify(recs)).replace("__META__", () => JSON.stringify(meta));
  const out2 = join13(osMod.tmpdir(), "protect-mcp-record-" + Date.now() + ".html");
  writeFileSync11(out2, html);
  openTarget(out2);
  process.stdout.write(`
${bold2("\u{1F6E1}\uFE0F  Your record")} ${dim2("\xB7")} ${recs.length} decision${recs.length === 1 ? "" : "s"}, all on this machine
`);
  if (!meta.signed) process.stdout.write(`  ${dim2("(decision log; signed receipts appear in .protect-mcp-receipts.jsonl once signing is on)")}
`);
  const fileUrl = "file://" + encodeURI(out2);
  if (process.stdout.isTTY) {
    process.stdout.write(`  Opened in your browser. If it did not open, click: \x1B]8;;${fileUrl}\x1B\\${bold2("your record")}\x1B]8;;\x1B\\
`);
  } else {
    process.stdout.write(`  Opened in your browser. If it did not open, open: ${out2}
`);
  }
  process.stdout.write(`  ${dim2("Want it to update live as your agent runs? npx protect-mcp record --live")}

`);
  process.exit(0);
}
var RECORD_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>protect-mcp record</title>
<style>
:root{--paper:#f6f4ef;--ink:#1b1815;--soft:#524d46;--faint:#8a837a;--line:#ddd7c9;--g:#3f6146;--gb:#e7eee3;--a:#8f6216;--ab:#f2e8d3;--r:#7d3535;--rb:#f2e0dc}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto;padding:26px 22px 60px}
h1{font-size:24px;margin:0 0 4px;letter-spacing:-.012em}
.meta{color:var(--faint);font-size:12.5px;font-family:ui-monospace,Menlo,Consolas,monospace;display:flex;align-items:center}
.pulse{width:7px;height:7px;border-radius:100px;background:var(--g);display:inline-block;margin-left:8px;animation:pl 1.6s ease-in-out infinite}
@keyframes pl{0%,100%{opacity:.3}50%{opacity:1}}
@media (prefers-reduced-motion:reduce){.pulse{animation:none}}
.stats{display:flex;gap:15px;flex-wrap:wrap;align-items:center;margin:14px 0 10px;font-size:13px}
.stat{display:flex;align-items:center;gap:6px;color:var(--soft)}
.stat b{color:var(--ink);font-weight:680}
.dot{width:8px;height:8px;border-radius:100px;display:inline-block}
.dot.g{background:var(--g)}.dot.a{background:var(--a)}.dot.r{background:var(--r)}
.stat.sig{margin-left:auto;color:var(--g);font-weight:600}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 16px}
.btn{cursor:pointer;font:inherit;font-size:12.5px;padding:7px 13px;border-radius:8px;border:1px solid var(--line);background:#fff;color:var(--ink);transition:border-color .12s}
.btn:hover{border-color:var(--ink)}
.btn.p{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.btn:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.vhint{font-size:12px;color:var(--faint);margin-left:auto;font-family:ui-monospace,Menlo,monospace}
.attest{margin:0 0 12px;font-size:12.5px;color:var(--soft);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cmd{font-family:ui-monospace,Menlo,monospace;font-size:12px;background:#efece4;border:1px solid var(--line);border-radius:6px;padding:3px 8px;color:var(--ink)}
.btn2{cursor:pointer;font:inherit;font-size:12px;padding:4px 9px;border-radius:7px;border:1px solid var(--line);background:#fff;color:var(--ink)}
.btn2:hover{border-color:var(--ink)}
.bar{margin:6px 0 12px}
input{width:100%;padding:10px 13px;border:1px solid var(--line);border-radius:9px;background:#fff;font:inherit}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.chip{cursor:pointer;font-size:12px;padding:3px 10px;border-radius:100px;border:1px solid var(--line);background:#fff;color:var(--soft)}
.chip.on{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.count{color:var(--faint);font-size:12px;font-family:ui-monospace,Menlo,monospace;margin-bottom:8px}
.row{border:1px solid var(--line);border-radius:9px;background:#fcfbf7;padding:11px 13px;margin-bottom:8px;cursor:pointer}
.row.blocked{background:#fbf3f0}.row.held{background:#fbf7ee}
.top{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.pill{font-size:11px;font-weight:600;padding:2px 9px;border-radius:100px}
.pill.allowed{background:var(--gb);color:var(--g)}.pill.held{background:var(--ab);color:var(--a)}.pill.blocked{background:var(--rb);color:var(--r)}
.tag{font-size:11px;padding:1px 7px;border-radius:100px;background:var(--paper);border:1px solid var(--line);color:var(--faint)}
.cap{font-size:10px;padding:1px 6px;border-radius:100px;background:#eef0ea;border:1px solid var(--line);color:var(--soft)}
.badge{font-size:10.5px;font-weight:600;padding:1px 7px;border-radius:100px}
.badge.sgn{background:var(--gb);color:var(--g)}
.badge.log{background:var(--paper);color:var(--faint);border:1px solid var(--line)}
.badge.vbad{background:#fbecec;color:#b3382f;border:1px solid #edc6c2}
.badge.vfor{background:#fbf3df;color:#8a6d1a;border:1px solid #e8d8ae}
.stat .badk{color:#b3382f;font-weight:680}.stat .warnk{color:#8a6d1a}.stat .dim2{color:var(--faint);font-weight:400}
.dg{font-size:10.5px;color:var(--faint);font-family:ui-monospace,Menlo,monospace}
.when{margin-left:auto;font-size:12px;color:var(--faint);font-family:ui-monospace,Menlo,monospace}
.det{margin-top:8px;padding-top:8px;border-top:1px solid var(--line);font-size:12px;color:var(--soft);font-family:ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-all;display:none}
.row.open .det{display:block}
.foot{margin-top:22px;color:var(--faint);font-size:12px;line-height:1.6;border-top:1px solid var(--line);padding-top:14px}
.foot b{color:var(--soft)}
.viewtoggle{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.viewtoggle button{border:0;background:#fff;color:var(--soft);font:inherit;font-size:12.5px;padding:7px 12px;cursor:pointer}
.viewtoggle button.on{background:var(--ink);color:var(--paper)}
.agent{border:1px solid var(--line);border-radius:10px;background:#fcfbf7;margin-bottom:10px;overflow:hidden}
.ahead{display:flex;gap:9px;align-items:center;flex-wrap:wrap;padding:11px 13px;cursor:pointer}
.atwist{color:var(--faint);font-size:11px;transition:transform .12s;display:inline-block}
.agent.open .atwist{transform:rotate(90deg)}
.acount{font-size:12px;color:var(--faint)}
.akids{display:none;padding:2px 12px 12px 24px;border-top:1px solid var(--line)}
.agent.open .akids{display:block}
.act{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:9px 4px;cursor:pointer;border-bottom:1px solid var(--line)}
.akids .act:last-child{border-bottom:0}
.act:hover{background:rgba(0,0,0,.02)}
.act.blocked{background:#fbf3f0}.act.held{background:#fbf7ee}
.act .det{flex-basis:100%}
.act.open .det{display:block}
.ev{display:flex;gap:8px;align-items:center;font-size:12px;color:var(--faint);padding:5px 10px;margin-top:6px}
.evdot{width:6px;height:6px;border-radius:100px;background:var(--faint);display:inline-block}
.evre{color:var(--soft)}
.badge.blk{background:var(--rb);color:var(--r)}
</style></head><body><div class="wrap">
<h1>Your record</h1>
<div class="meta"><span id="meta"></span><span id="live"></span></div>
<div class="stats" id="stats"></div>
<div class="actions">
<div class="viewtoggle"><button id="vlist" class="on" onclick="setView('list')">List</button><button id="vtree" onclick="setView('tree')">Tree</button></div>
<button class="btn p" onclick="exportJsonl()">Export receipts (.jsonl)</button>
<button class="btn" onclick="exportMd()">Export report (.md)</button>
<button class="btn" id="cpv" onclick="copyVerify()">Copy verify command</button>
<span class="vhint">verify offline: npx @veritasacta/verify</span>
</div>
<div class="bar"><input id="q" placeholder="Search your record: tool, reason, verdict"></div>
<div class="chips" id="chips"></div>
<div class="count" id="count"></div>
<div class="attest" id="attest"></div>
<div id="list"></div>
<div class="foot">Signed decisions from your own gate, on this machine. Nothing was uploaded. Each row is Ed25519-signed, and the exports carry the signatures, so anyone you hand them to (an allocator, an auditor, a counterparty) verifies offline with <b>npx @veritasacta/verify</b>, our code removed. For a Merkle-rooted evidence pack: <b>npx protect-mcp bundle</b>. To prove a claim over this record without revealing it (e.g. no egress): <b>npx protect-mcp claim --no net.egress</b>, checked offline with <b>npx protect-mcp verify-claim</b>. protect-mcp governs proposed actions before they run.</div>
</div>
<script>
var RECORDS=__DATA__;var META=__META__;var Q="",ACT={},VIEW="list",OPEN={};var NL=String.fromCharCode(10);
// In-browser signature verification. Mirrors @veritasacta/artifacts exactly:
// preimage = JCS-style canonical JSON (sorted keys) of the receipt minus its
// signature, verified with WebCrypto Ed25519. Pinned key (your keys/gateway.json
// public half, injected by the CLI) = authenticity; key embedded in the receipt
// payload (0.9.3+) = self-consistency. Everything runs locally.
var VSTATE={},VDONE=false,VBUSY=false,VUNSUP=false;
function vkey(r){return "row:"+(r.id||"")+"|"+(r.ts||"")}
function hexb(h){h=String(h||"");var a=new Uint8Array(h.length>>1);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a}
function canon(v){return JSON.stringify(v,function(k,x){if(x&&typeof x==="object"&&!Array.isArray(x)){var s={},ks=Object.keys(x).sort();for(var i=0;i<ks.length;i++)s[ks[i]]=x[ks[i]];return s}return x})}
async function edv(sig,msg,pub){var key=await crypto.subtle.importKey("raw",hexb(pub),{name:"Ed25519"},false,["verify"]);return crypto.subtle.verify({name:"Ed25519"},key,hexb(sig),msg)}
async function verifyRow(r){var raw=r.raw;if(!raw)return"unsigned";
var sigHex=null,msgObj=null;
if(raw.signature&&typeof raw.signature==="object"&&typeof raw.signature.sig==="string"&&raw.payload){if(raw.signature.alg!=="EdDSA")return"bad";sigHex=raw.signature.sig;msgObj=raw.payload}
else if(typeof raw.signature==="string"){var rest={},k;for(k in raw)if(k!=="signature")rest[k]=raw[k];sigHex=raw.signature;msgObj=rest}
else return"unsigned";
var msg=new TextEncoder().encode(canon(msgObj));
var pin=String(META.pinned_key||"").toLowerCase();
var emb=String((raw.payload&&raw.payload.public_key)||raw.public_key||"").toLowerCase();
if(!/^[0-9a-f]{64}$/.test(emb))emb="";
if(pin){if(await edv(sigHex,msg,pin))return"ok";if(emb&&emb!==pin&&await edv(sigHex,msg,emb))return"foreign";return"bad"}
if(emb)return(await edv(sigHex,msg,emb))?"ok":"bad";
return"nokey"}
function vsum(){var s={ok:0,bad:0,foreign:0,nokey:0};RECORDS.forEach(function(r){if(!r.signed)return;var v=VSTATE[vkey(r)];if(v&&s[v]!==undefined)s[v]++});return s}
async function kickVerify(){if(VBUSY||VUNSUP||!(window.crypto&&crypto.subtle))return;VBUSY=true;
try{var rows=RECORDS.slice(0,1500);for(var i=0;i<rows.length;i++){var r=rows[i],kk=vkey(r);if(VSTATE[kk])continue;
try{VSTATE[kk]=await verifyRow(r)}catch(e){if(e&&e.name==="NotSupportedError"){VUNSUP=true;break}VSTATE[kk]="bad"}}}
finally{VDONE=true;VBUSY=false;render()}}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
function vlabel(v){return v==="allowed"?"Allowed":v==="held"?"Held":"Blocked"}
function when(ts){if(!ts)return"";var d=new Date(ts);return d.toLocaleDateString(undefined,{month:"short",day:"numeric"})+" "+d.toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit"})}
function counts(rows){var c={allowed:0,held:0,blocked:0,signed:0};rows.forEach(function(r){c[r.verdict]=(c[r.verdict]||0)+1;if(r.signed)c.signed++});return c}
function fvals(key){var m={};RECORDS.forEach(function(r){var vs=key==="Decision"?[vlabel(r.verdict)]:(key==="Capability"?(r.caps||[]):[r[key.toLowerCase()]]);vs.forEach(function(v){if(v){m[v]=(m[v]||0)+1}})});return Object.keys(m).sort(function(a,b){return m[b]-m[a]}).slice(0,10).map(function(v){return[v,m[v]]})}
function match(r){if(ACT.Decision&&vlabel(r.verdict)!==ACT.Decision)return false;if(ACT.Tool&&r.tool!==ACT.Tool)return false;if(ACT.Reason&&r.reason!==ACT.Reason)return false;if(ACT.Capability&&(r.caps||[]).indexOf(ACT.Capability)<0)return false;if(Q){var h=(r.tool+" "+r.reason+" "+vlabel(r.verdict)+" "+r.hook+" "+(r.caps||[]).join(" ")).toLowerCase();if(h.indexOf(Q)<0)return false}return true}
function filtered(){return RECORDS.filter(match)}
function dl(name,text,type){var b=new Blob([text],{type:type||"text/plain"});var u=URL.createObjectURL(b);var a=document.createElement("a");a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(u)},1500)}
function stamp(){return new Date().toISOString().replace(/[:.]/g,"-").slice(0,19)}
function exportJsonl(){var rows=filtered();if(!rows.length)return;var lines=rows.map(function(r){return JSON.stringify(r.raw||r)}).join(NL);dl("protect-mcp-record-"+stamp()+".jsonl",lines,"application/x-ndjson")}
function exportMd(){var rows=filtered();if(!rows.length)return;var c=counts(rows);var head=["# Agent decision record","",rows.length+" decisions from "+META.file,c.allowed+" allowed, "+c.held+" held, "+c.blocked+" blocked, "+c.signed+" signed.","","Generated locally by protect-mcp. These are signed receipts; verify offline with npx @veritasacta/verify (our code removed).","","| When | Decision | Tool | Reason | Hook | Signed |","|---|---|---|---|---|---|"];var body=rows.slice(0,3000).map(function(r){return "| "+(r.ts||"")+" | "+vlabel(r.verdict)+" | "+String(r.tool||"").replace(/\\|/g,"/")+" | "+String(r.reason||"").replace(/\\|/g,"/")+" | "+(r.hook||"")+" | "+(r.signed?"yes":"no")+" |"});dl("protect-mcp-record-"+stamp()+".md",head.concat(body).join(NL)+NL,"text/markdown")}
function copyAttest(){var a=document.getElementById("attest");var cmd=a?a.getAttribute("data-cmd"):"";try{navigator.clipboard&&cmd&&navigator.clipboard.writeText(cmd)}catch(e){}var b=document.getElementById("cpa");if(b){var t=b.textContent;b.textContent="Copied";setTimeout(function(){b.textContent=t},1200)}}
function copyVerify(){var cmd="npx @veritasacta/verify";try{navigator.clipboard&&navigator.clipboard.writeText(cmd)}catch(e){}var b=document.getElementById("cpv");if(b){var t=b.textContent;b.textContent="Copied";setTimeout(function(){b.textContent=t},1200)}}
function renderStats(){var c=counts(RECORDS);var p=[];p.push('<span class="stat"><b>'+RECORDS.length+'</b> decisions</span>');p.push('<span class="stat"><span class="dot g"></span>'+c.allowed+' allowed</span>');if(c.held)p.push('<span class="stat"><span class="dot a"></span>'+c.held+' held</span>');p.push('<span class="stat"><span class="dot r"></span>'+c.blocked+' blocked</span>');var st;if(!c.signed){st='0 signed, verifiable offline'}else if(VUNSUP||!(window.crypto&&crypto.subtle)){st=c.signed+' signed, verifiable offline <span class="dim2">(in-browser check unavailable here; run npx protect-mcp receipts)</span>'}else if(!VDONE){st=c.signed+' signed \xB7 verifying in your browser\u2026'}else{var s=vsum();st=s.ok+' of '+c.signed+' signatures verified in your browser';if(s.foreign)st+=' <span class="warnk">\xB7 '+s.foreign+' signed by an unpinned key</span>';if(s.bad)st+=' <span class="badk">\xB7 '+s.bad+' INVALID</span>';if(s.nokey)st+=' <span class="dim2">\xB7 '+s.nokey+' need a key to check</span>'}
p.push('<span class="stat sig">'+st+'</span>');document.getElementById("stats").innerHTML=p.join("")}
function renderList(rows){var html="";rows.slice(0,800).forEach(function(r){var vs=VSTATE[vkey(r)];var sig=!r.signed?'<span class="badge log">log</span>':vs==="ok"?'<span class="badge sgn">\u2713 verified</span>':vs==="bad"?'<span class="badge vbad">\u2717 invalid signature</span>':vs==="foreign"?'<span class="badge vfor">signed \xB7 unpinned key</span>':'<span class="badge sgn">signed</span>';var dg=r.digest?'<span class="dg">'+esc(String(r.digest).slice(0,10))+'</span>':'';var ct=(r.caps||[]).map(function(c){return '<span class="cap">'+esc(c)+'</span>'}).join('');var rk="row:"+(r.id||"")+"|"+(r.ts||"");html+='<div class="row '+r.verdict+(OPEN[rk]?" open":"")+'" data-k="'+esc(rk)+'"><div class="top"><span class="pill '+r.verdict+'">'+vlabel(r.verdict)+"</span><b>"+esc(r.tool)+'</b><span class="tag">'+esc(r.reason)+"</span>"+ct+(r.hook?'<span class="tag">'+esc(r.hook)+"</span>":"")+sig+dg+'<span class="when">'+esc(when(r.ts))+'</span></div><div class="det">'+esc(JSON.stringify(r.raw||r,null,2))+"</div></div>"});document.getElementById("list").innerHTML=html||'<p style="color:#8a837a">No records match.</p>';}
function isLifecycle(r){var h=r.hook||"";return h==="SessionStart"||h==="SessionEnd"||h==="Stop"||h==="SubagentStart"||h==="SubagentStop"||h==="TaskCreated"||h==="TaskCompleted"||h==="ConfigChange"||h==="Notification"||h==="PreCompact";}
function buildTree(rows){var ags={},order=[];rows.forEach(function(r){var a=r.agent||"main agent";if(!ags[a]){ags[a]={name:a,byId:{},items:[],caps:{},blocked:0,actions:0};order.push(a);}var g=ags[a];(r.caps||[]).forEach(function(c){g.caps[c]=(g.caps[c]||0)+1;});if(isLifecycle(r)){g.items.push({t:"e",ts:r.ts,r:r});return;}var id=r.id||("_"+r.ts);var n=g.byId[id];if(!n){n={t:"a",id:id,tool:r.tool,verdict:r.verdict,caps:(r.caps||[]).slice(),ts:r.ts,dur:0,signed:!!r.signed,raw:r.raw};g.byId[id]=n;g.items.push(n);g.actions++;}if(r.hook==="PostToolUse"){if(r.dur)n.dur=r.dur;if(!n.raw)n.raw=r.raw;}else{n.verdict=r.verdict;if((r.caps||[]).length)n.caps=r.caps.slice();n.raw=r.raw;n.ts=r.ts;}if(r.signed)n.signed=true;});order.forEach(function(a){var g=ags[a];g.blocked=g.items.filter(function(it){return it.t==="a"&&it.verdict==="blocked";}).length;g.items.sort(function(x,y){return (x.ts<y.ts)?-1:1;});});return order.map(function(a){return ags[a];});}
function renderTree(ags){if(!ags.length){document.getElementById("list").innerHTML='<p style="color:#8a837a">No records match.</p>';return;}var html="",N=0;ags.forEach(function(g,gi){var capstr=Object.keys(g.caps).sort(function(a,b){return g.caps[b]-g.caps[a];}).slice(0,5).map(function(c){return '<span class="cap">'+esc(c)+'</span>';}).join('');var ak="ag:"+g.name;var op=(OPEN.hasOwnProperty(ak)?OPEN[ak]:(ags.length===1||gi===0))?" open":"";html+='<div class="agent'+op+'" data-k="'+esc(ak)+'"><div class="ahead"><span class="atwist">\u25B8</span><b>'+esc(g.name)+'</b><span class="acount">'+g.actions+' action'+(g.actions===1?'':'s')+'</span>'+(g.blocked?'<span class="badge blk">'+g.blocked+' blocked</span>':'')+capstr+'</div><div class="akids">';g.items.forEach(function(it){if(N++>1500)return;if(it.t==="e"){var r=it.r;html+='<div class="ev"><span class="evdot"></span>'+esc(r.hook||r.tool)+' <span class="evre">'+esc(r.reason)+'</span><span class="when">'+esc(when(r.ts))+'</span></div>';}else{var ct=(it.caps||[]).map(function(c){return '<span class="cap">'+esc(c)+'</span>';}).join('');var dur=it.dur?'<span class="dg">'+it.dur+'ms</span>':'';var ik="act:"+it.id;html+='<div class="act '+it.verdict+(OPEN[ik]?" open":"")+'" data-k="'+esc(ik)+'"><span class="pill '+it.verdict+'">'+vlabel(it.verdict)+'</span><b>'+esc(it.tool)+'</b>'+ct+(it.signed?'<span class="badge sgn">signed</span>':'')+dur+'<span class="when">'+esc(when(it.ts))+'</span><div class="det">'+esc(JSON.stringify(it.raw||{},null,2))+'</div></div>';}});html+='</div></div>';});if(N>1500)html+='<p style="color:#8a837a;font-size:12px;margin-top:10px">Showing the first 1500 items. Search or pick a facet to narrow.</p>';document.getElementById("list").innerHTML=html;}
function setView(v){VIEW=v;document.getElementById("vlist").className=v==="list"?"on":"";document.getElementById("vtree").className=v==="tree"?"on":"";render();}
function render(){
document.getElementById("meta").textContent=META.count+" decisions from "+META.file+(META.signed?" (signed)":" (decision log)")+" - all local"+(META.live?" \xB7 live, updating":"");
document.getElementById("live").innerHTML=META.live?'<span class="pulse"></span>':"";
renderStats();
var chips="";["Decision","Tool","Reason","Capability"].forEach(function(key){fvals(key).forEach(function(p){var on=ACT[key]===p[0];chips+='<span class="chip'+(on?" on":"")+'" data-k="'+key+'" data-v="'+esc(p[0])+'">'+esc(p[0])+" "+p[1]+"</span>"})});
document.getElementById("chips").innerHTML=chips;
var rows=RECORDS.filter(match);
document.getElementById("count").textContent=rows.length+" of "+RECORDS.length+" records"+(VIEW==="tree"?" \xB7 grouped by agent":"");
var _at=document.getElementById("attest");if(ACT.Capability){var _cmd="npx protect-mcp claim --no "+ACT.Capability;_at.setAttribute("data-cmd",_cmd);_at.innerHTML='Prove it over this record, revealing nothing: <span class="cmd">'+esc(_cmd)+'</span><button class="btn2" id="cpa" onclick="copyAttest()">Copy</button>';}else{_at.innerHTML="";_at.removeAttribute("data-cmd");}
if(VIEW==="tree"){renderTree(buildTree(rows));}else{renderList(rows);}}
document.getElementById("q").addEventListener("input",function(e){Q=e.target.value.toLowerCase().trim();render()});
document.getElementById("chips").addEventListener("click",function(e){var c=e.target.closest(".chip");if(!c)return;var k=c.getAttribute("data-k"),v=c.getAttribute("data-v");ACT[k]=ACT[k]===v?undefined:v;render()});
document.getElementById("list").addEventListener("click",function(e){var ah=e.target.closest(".ahead");if(ah){var ag=ah.parentNode;ag.classList.toggle("open");var ak=ag.getAttribute("data-k");if(ak)OPEN[ak]=ag.classList.contains("open");return;}var el=e.target.closest(".act")||e.target.closest(".row");if(el){el.classList.toggle("open");var k=el.getAttribute("data-k");if(k)OPEN[k]=el.classList.contains("open");}});
render();kickVerify();
if(META.live){var poll=function(){fetch('/data',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){var nr=d.recs||[];var changed=nr.length!==RECORDS.length;RECORDS=nr;META.count=RECORDS.length;if(typeof d.signed==='boolean')META.signed=d.signed;if(changed){render();kickVerify()}}).catch(function(){})};poll();setInterval(poll,2000);}
</script></body></html>`;
async function handleClaim(argv) {
  const { readFileSync: readFileSync19, existsSync: existsSync13, writeFileSync: writeFileSync11 } = await import("fs");
  const { join: join13 } = await import("path");
  const { buildClaim: buildClaim2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
  let dir = process.cwd();
  const di = argv.indexOf("--dir");
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  let predicate = null;
  const noIdx = argv.indexOf("--no"), onlyIdx = argv.indexOf("--only"), nvIdx = argv.indexOf("--no-verdict"), cvIdx = argv.indexOf("--count"), puIdx = argv.indexOf("--payment-under");
  if (noIdx !== -1 && argv[noIdx + 1]) predicate = { kind: "no_capability", capability: argv[noIdx + 1] };
  else if (onlyIdx !== -1 && argv[onlyIdx + 1]) predicate = { kind: "only_capabilities", capabilities: argv[onlyIdx + 1].split(",").map((s) => s.trim()).filter(Boolean) };
  else if (nvIdx !== -1 && argv[nvIdx + 1]) predicate = { kind: "no_verdict", verdict: argv[nvIdx + 1] };
  else if (cvIdx !== -1 && argv[cvIdx + 1]) predicate = { kind: "count_verdict", verdict: argv[cvIdx + 1] };
  else if (puIdx !== -1 && argv[puIdx + 1] && isFinite(parseFloat(argv[puIdx + 1]))) predicate = { kind: "payment_under", cap: parseFloat(argv[puIdx + 1]) };
  if (!predicate) {
    process.stderr.write(`
${bold2("protect-mcp claim")}

Attest a signed, position-blind claim over your record:
  --no <capability>        no action used it, e.g. ${dim2("--no net.egress")} or ${dim2("--no payment")}
  --only <c1,c2,...>       all actions confined to these capabilities
  --no-verdict <verdict>   e.g. ${dim2("--no-verdict blocked")}
  --count <verdict>        how many, e.g. ${dim2("--count blocked")}
  --payment-under <cap>    every agent payment stayed under the cap (amounts the
                           gate could not read count as OVER, so this cannot lie)
  --anchor                 also record the claim digest in the public append-only
                           log so a counterparty can trust it is complete (only the
                           hash is sent; your record stays local)

Example: ${bold2("npx protect-mcp claim --no net.egress --anchor")}

`);
    process.exit(0);
    return;
  }
  const keyPath = join13(dir, "keys", "gateway.json");
  if (!existsSync13(keyPath)) {
    process.stderr.write(`
${bold2("protect-mcp claim")}

No signing key at ${keyPath}. A claim must be signed. Run ${bold2("npx protect-mcp init")} first.

`);
    process.exit(1);
    return;
  }
  let key;
  try {
    key = JSON.parse(readFileSync19(keyPath, "utf-8"));
  } catch {
    process.stderr.write(`
protect-mcp claim: ${keyPath} is not valid JSON.

`);
    process.exit(1);
    return;
  }
  if (!key.privateKey || !key.publicKey) {
    process.stderr.write(`
protect-mcp claim: ${keyPath} is missing privateKey/publicKey.

`);
    process.exit(1);
    return;
  }
  const recPath = join13(dir, ".protect-mcp-receipts.jsonl");
  if (!existsSync13(recPath)) {
    process.stderr.write(`
${bold2("protect-mcp claim")}

No signed receipts in ${dir}. Run the gate with signing on, then try again.

`);
    process.exit(0);
    return;
  }
  const receipts = readFileSync19(recPath, "utf-8").split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter((x) => x !== null);
  if (!receipts.length) {
    process.stderr.write(`
protect-mcp claim: no readable receipts in ${recPath}.

`);
    process.exit(0);
    return;
  }
  const pack = buildClaim2(receipts, predicate, { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || "gateway", issuer: "protect-mcp" }, (/* @__PURE__ */ new Date()).toISOString());
  const oi = argv.indexOf("--output");
  const out2 = oi !== -1 && argv[oi + 1] ? argv[oi + 1] : join13(dir, "claim-" + Date.now() + ".json");
  writeFileSync11(out2, JSON.stringify(pack, null, 2) + "\n");
  process.stdout.write(`
${bold2("\u{1F6E1}\uFE0F  Signed claim")}
`);
  process.stdout.write(`  ${pack.claim.statement}: ${pack.claim.holds ? green2("holds") : yellow2("does not hold")}  ${dim2("(" + pack.claim.matched + " matched of " + pack.scope.total + " decisions)")}
`);
  process.stdout.write(`  ${dim2("Position-blind: reveals decision categories, never tool inputs, outputs, or data. Ed25519-signed.")}
`);
  process.stdout.write(`  Written to ${out2}
`);
  process.stdout.write(`  Hand it to anyone. They verify offline: ${bold2("npx protect-mcp verify-claim " + out2)}
`);
  if (argv.indexOf("--anchor") !== -1) {
    const { anchorClaim: anchorClaim2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
    const li = argv.indexOf("--log");
    const logBase = li !== -1 && argv[li + 1] ? argv[li + 1] : void 0;
    process.stdout.write(`
  ${dim2("Anchoring the claim digest to the public append-only log (only the hash leaves your machine)...")}
`);
    const res = await anchorClaim2(
      pack,
      { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || "gateway", issuer: "protect-mcp" },
      { log: logBase, issuedAt: (/* @__PURE__ */ new Date()).toISOString() }
    );
    if (res.ok) {
      const sidecar = out2.replace(/\.json$/, "") + ".anchor.json";
      writeFileSync11(sidecar, JSON.stringify({ log: logBase || "https://scopeblind.com", seq: res.seq, entry_url: res.entry_url, anchored_at: res.anchored_at, claim_digest: res.claim_digest, envelope: res.envelope }, null, 2) + "\n");
      process.stdout.write(`  ${green2("Anchored")} as log entry ${bold2("#" + res.seq)}${res.already_anchored ? dim2(" (already present)") : ""}  ${dim2(res.entry_url || "")}
`);
      process.stdout.write(`  ${dim2("A counterparty can now confirm this exact claim existed at " + (res.anchored_at || "this time") + " and cannot be quietly re-cut.")}
`);
      process.stdout.write(`  ${dim2("Anchor record written to " + sidecar + ". Only the digest was sent; your record stayed local.")}
`);
      const { lookupPinnedIdentity: lookupPinnedIdentity2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
      const who = await lookupPinnedIdentity2(key.publicKey, { log: logBase });
      if (who && who.found && !who.revoked) {
        process.stdout.write(`  ${green2("Identity:")} anchored as ${bold2(who.name || who.slug || "enrolled org")} ${dim2("(key pinned in the ScopeBlind directory" + (who.enrolled_at ? ", enrolled " + who.enrolled_at.slice(0, 10) : "") + ")")}
`);
      } else if (who && who.found && who.revoked) {
        process.stdout.write(`  ${red2("Identity: this key is REVOKED in the ScopeBlind directory.")}
`);
      } else {
        process.stdout.write(`  ${dim2("Identity: anonymous (key not enrolled). To anchor as a named org a counterparty can pin, see")} ${bold2("scopeblind.com/enroll")}
`);
      }
    } else {
      process.stdout.write(`  ${yellow2("Anchor skipped")} ${dim2("(" + (res.error || "unavailable") + "). The claim above is complete and verifiable offline without it.")}
`);
    }
  }
  process.stdout.write(`
`);
  process.exit(0);
}
async function handleAnchorRecord(argv) {
  const { readFileSync: readFileSync19, existsSync: existsSync13, appendFileSync: appendFileSync4 } = await import("fs");
  const { join: join13 } = await import("path");
  const { anchorRecordCheckpoint: anchorRecordCheckpoint2, buildRecordCheckpoint: buildRecordCheckpoint2, lookupPinnedIdentity: lookupPinnedIdentity2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
  let dir = process.cwd();
  const di = argv.indexOf("--dir");
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  const li = argv.indexOf("--log");
  const logBase = li !== -1 && argv[li + 1] ? argv[li + 1] : void 0;
  const keyPath = join13(dir, "keys", "gateway.json");
  if (!existsSync13(keyPath)) {
    process.stderr.write(`
${bold2("protect-mcp anchor-record")}

No signing key at ${keyPath}. A checkpoint must be signed. Run ${bold2("npx protect-mcp init")} first.

`);
    process.exit(1);
    return;
  }
  let key;
  try {
    key = JSON.parse(readFileSync19(keyPath, "utf-8"));
  } catch {
    process.stderr.write(`
protect-mcp anchor-record: ${keyPath} is not valid JSON.

`);
    process.exit(1);
    return;
  }
  if (!key.privateKey || !key.publicKey) {
    process.stderr.write(`
protect-mcp anchor-record: ${keyPath} is missing privateKey/publicKey.

`);
    process.exit(1);
    return;
  }
  const recPath = join13(dir, ".protect-mcp-receipts.jsonl");
  if (!existsSync13(recPath)) {
    process.stderr.write(`
${bold2("protect-mcp anchor-record")}

No signed receipts in ${dir}. Run the gate with signing on, then try again.

`);
    process.exit(0);
    return;
  }
  const receipts = readFileSync19(recPath, "utf-8").split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter((x) => x !== null);
  if (!receipts.length) {
    process.stderr.write(`
protect-mcp anchor-record: no readable receipts in ${recPath}.

`);
    process.exit(0);
    return;
  }
  const claimKey = { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || "gateway", issuer: "protect-mcp" };
  const historyPath = join13(dir, ".protect-mcp-anchors.jsonl");
  const preview = buildRecordCheckpoint2(receipts, claimKey, "preview");
  if (!argv.includes("--force") && existsSync13(historyPath)) {
    const lines = readFileSync19(historyPath, "utf-8").split(/\r?\n/).filter(Boolean);
    const last = lines.length ? (() => {
      try {
        return JSON.parse(lines[lines.length - 1]);
      } catch {
        return null;
      }
    })() : null;
    if (last && last.record_root === preview.record_root && last.total === preview.total) {
      process.stdout.write(`
${bold2("\u{1F6E1}\uFE0F  Record checkpoint")}
`);
      process.stdout.write(`  Unchanged since entry ${bold2("#" + last.seq)} ${dim2("(" + last.total + " receipts, anchored " + (last.anchored_at || "") + ")")}. Nothing new to anchor.
`);
      process.stdout.write(`  ${dim2("Use --force to re-anchor anyway.")}

`);
      process.exit(0);
      return;
    }
  }
  const res = await anchorRecordCheckpoint2(receipts, claimKey, { log: logBase, issuedAt: (/* @__PURE__ */ new Date()).toISOString() });
  process.stdout.write(`
${bold2("\u{1F6E1}\uFE0F  Record checkpoint")}
`);
  process.stdout.write(`  ${res.total} receipts ${dim2("\xB7")} root ${dim2(res.record_root.slice(0, 16) + "\u2026")} ${dim2("(" + res.checkpoint.from.slice(0, 10) + " \u2192 " + res.checkpoint.to.slice(0, 10) + ")")}
`);
  if (!res.ok) {
    process.stdout.write(`  ${yellow2("Anchor failed")} ${dim2("(" + (res.error || "unavailable") + "). Nothing was recorded; try again.")}

`);
    process.exit(1);
    return;
  }
  appendFileSync4(historyPath, JSON.stringify({ schema: res.checkpoint.schema, seq: res.seq, anchored_at: res.anchored_at, total: res.total, record_root: res.record_root, entry_url: res.entry_url, digest: res.checkpoint.digest }) + "\n");
  process.stdout.write(`  ${green2("Anchored")} as log entry ${bold2("#" + res.seq)}  ${dim2(res.entry_url || "")}
`);
  process.stdout.write(`  ${dim2("Only the root, count, and time range were sent. History: " + historyPath)}
`);
  const who = await lookupPinnedIdentity2(claimKey.publicKey, { log: logBase });
  if (who && who.found && !who.revoked) {
    process.stdout.write(`  ${green2("Identity:")} anchored as ${bold2(who.name || who.slug || "enrolled org")} ${dim2("(key pinned in the ScopeBlind directory)")}
`);
  } else if (who && who.found && who.revoked) {
    process.stdout.write(`  ${red2("Identity: this key is REVOKED in the ScopeBlind directory.")}
`);
  } else {
    process.stdout.write(`  ${dim2("Identity: anonymous (key not enrolled). Named identity: scopeblind.com/enroll")}
`);
  }
  process.stdout.write(`  ${dim2("A claim whose commitment matches this root is provably over the complete record as of")}
`);
  process.stdout.write(`  ${dim2("this checkpoint. Run this on a heartbeat (e.g. cron) to keep the anchored history growing.")}

`);
  process.exit(0);
}
async function handleVerifyClaim(argv) {
  const { readFileSync: readFileSync19, existsSync: existsSync13 } = await import("fs");
  const { verifyClaim: verifyClaim2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
  const file = argv.find((a) => !a.startsWith("--"));
  if (!file || !existsSync13(file)) {
    process.stderr.write(`
${bold2("protect-mcp verify-claim")} <claim.json> [--key <public-hex>]

Provide a claim pack file.

`);
    process.exit(2);
    return;
  }
  let pack;
  try {
    pack = JSON.parse(readFileSync19(file, "utf-8"));
  } catch {
    process.stderr.write(`
protect-mcp verify-claim: ${file} is not valid JSON.

`);
    process.exit(2);
    return;
  }
  if (!pack || pack.type !== "scopeblind.claim.v1") {
    process.stderr.write(`
protect-mcp verify-claim: not a scopeblind.claim.v1 pack.

`);
    process.exit(2);
    return;
  }
  const ki = argv.indexOf("--key");
  const v = verifyClaim2(pack, ki !== -1 ? argv[ki + 1] : void 0);
  const ok = (b) => b ? green2("\u2713") : red2("\u2717");
  process.stdout.write(`
${bold2("protect-mcp verify-claim")}
`);
  process.stdout.write(`  Claim:      ${pack.claim ? pack.claim.statement : "(none)"}
`);
  process.stdout.write(`  Holds:      ${v.holds ? green2("yes") : yellow2("no")}  ${dim2("(" + v.matched + " matched of " + v.total + " decisions)")}
`);
  process.stdout.write(`  Signature:  ${ok(v.authentic)} ${v.authentic ? "valid" : "INVALID"}  ${dim2("issuer kid " + (pack.issuer && pack.issuer.kid || "?"))}
`);
  process.stdout.write(`  Commitment: ${ok(v.root_ok)} ${v.root_ok ? "Merkle root matches the " + v.total + " disclosed decisions" : "MISMATCH"}
`);
  process.stdout.write(`  Predicate:  ${ok(v.predicate_ok)} ${v.predicate_ok ? "recomputed independently and matches" : "MISMATCH"}
`);
  const ai = argv.indexOf("--anchor-file");
  const sidecarPath = ai !== -1 && argv[ai + 1] ? argv[ai + 1] : file.replace(/\.json$/, "") + ".anchor.json";
  const requireAnchor = argv.includes("--check-anchor");
  let anchorOk = true;
  if (existsSync13(sidecarPath)) {
    const { checkClaimAnchor: checkClaimAnchor2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
    let sidecar = null;
    try {
      sidecar = JSON.parse(readFileSync19(sidecarPath, "utf-8"));
    } catch {
    }
    if (!sidecar) {
      anchorOk = false;
      process.stdout.write(`  Anchor:     ${red2("\u2717")} ${sidecarPath} is not valid JSON
`);
    } else {
      const a = await checkClaimAnchor2(pack, sidecar, { offline: argv.includes("--offline") });
      anchorOk = a.local_ok && a.log_ok !== false;
      if (a.local_ok) {
        process.stdout.write(`  Anchor:     ${green2("\u2713")} anchored envelope binds this exact claim and its record root
`);
        process.stdout.write(`              ${green2("\u2713")} envelope signed by the claim issuer's key
`);
      } else {
        for (const r of a.reasons.slice(0, 3)) process.stdout.write(`  Anchor:     ${red2("\u2717")} ${r}
`);
      }
      if (a.log_ok === true) {
        process.stdout.write(`              ${green2("\u2713")} public log confirms it${typeof a.seq === "number" ? ": entry " + bold2("#" + a.seq) : ""}${a.anchored_at ? dim2(" \xB7 anchored " + a.anchored_at) : ""}
`);
      } else if (a.log_ok === false) {
        process.stdout.write(`              ${red2("\u2717")} ${a.reasons[a.reasons.length - 1]}
`);
      } else if (a.local_ok) {
        process.stdout.write(`              ${yellow2("~")} log not checked ${dim2(argv.includes("--offline") ? "(--offline)" : "(unreachable; local binding checks stand)")}
`);
      }
      if (!argv.includes("--offline") && sidecar.envelope) {
        const { lookupPinnedIdentity: lookupPinnedIdentity2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
        const who = await lookupPinnedIdentity2(sidecar.envelope.verification_key, {});
        if (who && who.found && !who.revoked) {
          process.stdout.write(`              ${green2("\u2713")} issuer key pinned to ${bold2(who.name || who.slug || "an enrolled org")} ${dim2("(ScopeBlind key directory)")}
`);
        } else if (who && who.found && who.revoked) {
          anchorOk = false;
          process.stdout.write(`              ${red2("\u2717")} issuer key is REVOKED in the ScopeBlind key directory
`);
        } else if (who && !who.found) {
          process.stdout.write(`              ${dim2("issuer key not enrolled (anonymous issuer); named identities pin via scopeblind.com/enroll")}
`);
        }
      }
    }
  } else if (requireAnchor) {
    anchorOk = false;
    process.stdout.write(`  Anchor:     ${red2("\u2717")} no anchor sidecar at ${sidecarPath} ${dim2("(mint with: protect-mcp claim ... --anchor)")}
`);
  } else {
    process.stdout.write(`  Anchor:     ${dim2("none found (" + sidecarPath + "). Anchoring proves the claim was fixed at a time: claim ... --anchor")}
`);
  }
  const finalValid = v.valid && anchorOk;
  process.stdout.write(`
  ${finalValid ? green2("VALID") : red2("INVALID")} attestation${v.valid && !anchorOk ? red2(" (anchor check failed)") : ""}.
`);
  process.stdout.write(`  ${dim2("Proves the pack came from the issuer key and the claim is true over the disclosed decision")}
`);
  process.stdout.write(`  ${dim2("categories (verdict + capabilities), which reveal no tool inputs, outputs, or data. Completeness")}
`);
  process.stdout.write(`  ${dim2("of the disclosed set is attested by the issuer; the anchor fixes it in a public append-only log.")}

`);
  process.exit(finalValid ? 0 : 1);
}
async function handleBundle(argv) {
  const { readFileSync: readFileSync19, writeFileSync: writeFileSync11, existsSync: existsSync13 } = await import("fs");
  const { join: join13 } = await import("path");
  const { createAuditBundle: createAuditBundle2 } = await Promise.resolve().then(() => (init_bundle(), bundle_exports));
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const outputIdx = argv.indexOf("--output");
  const outputPath = outputIdx !== -1 && argv[outputIdx + 1] ? argv[outputIdx + 1] : join13(dir, "audit-bundle.json");
  const receiptsPath = join13(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = join13(dir, "keys", "gateway.json");
  if (!existsSync13(receiptsPath)) {
    process.stderr.write(`${bold2("protect-mcp bundle")}

No signed receipt file found. Run protect-mcp with signing enabled first.
`);
    process.exit(0);
  }
  if (!existsSync13(keyPath)) {
    process.stderr.write(`${bold2("protect-mcp bundle")}

No key file found at ${keyPath}
`);
    process.exit(1);
  }
  const receipts = readFileSync19(receiptsPath, "utf-8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const keyData = JSON.parse(readFileSync19(keyPath, "utf-8"));
  const bundle = createAuditBundle2({
    tenant: keyData.issuer || "protect-mcp",
    receipts,
    selectiveDisclosures: collectSelectiveDisclosurePackages(dir),
    signingKeys: [{
      kty: "OKP",
      crv: "Ed25519",
      kid: keyData.kid || "unknown",
      x: Buffer.from(keyData.publicKey, "hex").toString("base64url"),
      use: "sig"
    }]
  });
  writeFileSync11(outputPath, JSON.stringify(bundle, null, 2) + "\n");
  process.stdout.write(`
${bold2("protect-mcp bundle")}

`);
  process.stdout.write(`  Receipts: ${receipts.length}
`);
  process.stdout.write(`  Disclosures: ${collectSelectiveDisclosurePackages(dir).length}
`);
  process.stdout.write(`  Output:   ${outputPath}
`);
  process.stdout.write(`  Verify:   npx @veritasacta/verify ${outputPath} --bundle

`);
}
async function createSandbox() {
  const { mkdirSync: mkdirSync9, writeFileSync: writeFileSync11, existsSync: existsSync13, readFileSync: readFileSync19 } = await import("fs");
  const { join: join13 } = await import("path");
  const { homedir: homedir4 } = await import("os");
  let response;
  try {
    response = await fetch("https://api.scopeblind.com/sandbox/create", { method: "POST" });
  } catch {
    process.stderr.write(yellow2("  \u26A0 Could not create dashboard (offline or server unavailable).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  if (!response.ok) {
    process.stderr.write(yellow2("  \u26A0 Could not create dashboard (offline or server unavailable).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  let data;
  try {
    data = await response.json();
  } catch {
    process.stderr.write(yellow2("  \u26A0 Could not create dashboard (unexpected response).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  const dashboardUrl = `https://scopeblind.com/t/${data.slug}`;
  const configDir = join13(homedir4(), ".protect-mcp");
  if (!existsSync13(configDir)) {
    mkdirSync9(configDir, { recursive: true });
  }
  const configPath = join13(configDir, "config.json");
  let existing = {};
  if (existsSync13(configPath)) {
    try {
      existing = JSON.parse(readFileSync19(configPath, "utf-8"));
    } catch {
    }
  }
  writeFileSync11(configPath, JSON.stringify({
    ...existing,
    sandbox_slug: data.slug,
    dashboard_url: dashboardUrl
  }, null, 2) + "\n");
  return dashboardUrl;
}
async function handleConnect() {
  process.stderr.write(`
${bold2("protect-mcp connect")}
`);
  process.stderr.write(`${"\u2500".repeat(50)}

`);
  process.stderr.write(`  Creating ScopeBlind sandbox dashboard...

`);
  const dashboardUrl = await createSandbox();
  if (dashboardUrl) {
    process.stderr.write(green2(`  \u2713 Dashboard created: ${dashboardUrl}
`));
    process.stderr.write(`    Privacy-safe summaries will be sent automatically.
`);
    process.stderr.write(dim2(`    Raw receipts, prompts, payloads, and outputs stay local.
`));
    process.stderr.write(`
${"\u2500".repeat(50)}

`);
  }
}
async function handleQuickstart(argv) {
  const connectFlag = argv.includes("--connect");
  const { mkdtempSync, writeFileSync: writeFileSync11, existsSync: existsSync13, mkdirSync: mkdirSync9, readFileSync: readFileSync19 } = await import("fs");
  const { join: join13 } = await import("path");
  const { tmpdir } = await import("os");
  const dir = mkdtempSync(join13(tmpdir(), "protect-mcp-quickstart-"));
  process.stdout.write(`
${bold2("protect-mcp quickstart")}
`);
  process.stdout.write(`${"\u2500".repeat(50)}

`);
  process.stdout.write(`  This will:
`);
  process.stdout.write(`  1. Generate an Ed25519 signing keypair
`);
  process.stdout.write(`  2. Create a shadow-mode policy
`);
  process.stdout.write(`  3. Start a demo MCP server with protect-mcp wrapping it
`);
  process.stdout.write(`  4. Log signed receipts for every tool call
`);
  if (connectFlag) {
    process.stdout.write(`  5. Create a ScopeBlind dashboard for receipt viewing
`);
  }
  process.stdout.write(`
  Working dir: ${dir}

`);
  const keysDir = join13(dir, "keys");
  mkdirSync9(keysDir, { recursive: true });
  const { randomBytes: randomBytes11 } = await import("crypto");
  let keypair2;
  try {
    const { ed25519: ed255197 } = await import("@noble/curves/ed25519");
    const { bytesToHex: bytesToHex10 } = await import("@noble/hashes/utils");
    const privateKey = randomBytes11(32);
    const publicKey = ed255197.getPublicKey(privateKey);
    keypair2 = {
      privateKey: bytesToHex10(privateKey),
      publicKey: bytesToHex10(publicKey),
      kid: `quickstart-${Date.now()}`
    };
  } catch {
    keypair2 = {
      privateKey: randomBytes11(32).toString("hex"),
      publicKey: randomBytes11(32).toString("hex"),
      kid: `quickstart-${Date.now()}`
    };
  }
  writeFileSync11(join13(keysDir, "gateway.json"), JSON.stringify({
    privateKey: keypair2.privateKey,
    publicKey: keypair2.publicKey,
    kid: keypair2.kid,
    generated_at: (/* @__PURE__ */ new Date()).toISOString()
  }, null, 2) + "\n");
  const configPath = join13(dir, "protect-mcp.json");
  const config = {
    tools: {
      "*": { rate_limit: "100/hour" },
      "delete_file": { block: true }
    },
    default_tier: "unknown",
    signing: {
      key_path: join13(keysDir, "gateway.json"),
      issuer: "protect-mcp-quickstart",
      enabled: true
    }
  };
  writeFileSync11(configPath, JSON.stringify(config, null, 2) + "\n");
  process.stdout.write(`  \u2713 Keypair generated (kid: ${keypair2.kid})
`);
  process.stdout.write(`  \u2713 Policy created (shadow mode, all tools logged)
`);
  process.stdout.write(`  \u2713 Signing enabled (Ed25519)

`);
  if (connectFlag) {
    process.stdout.write(`${bold2("Connecting to ScopeBlind dashboard...")}

`);
    const dashboardUrl = await createSandbox();
    if (dashboardUrl) {
      const updatedConfig = { ...config, dashboard_url: dashboardUrl };
      writeFileSync11(configPath, JSON.stringify(updatedConfig, null, 2) + "\n");
      process.stdout.write(green2(`  \u2713 Dashboard created: ${dashboardUrl}
`));
      process.stdout.write(`    Privacy-safe summaries will be sent automatically.
`);
      process.stdout.write(dim2(`    Raw receipts, prompts, payloads, and outputs stay local.
`));
      process.stdout.write(`
`);
    }
  }
  process.stdout.write(`${bold2("Starting demo server...")}

`);
  process.stdout.write(`  Every tool call will produce a signed receipt.
`);
  process.stdout.write(`  Try it with Claude Desktop or any MCP client.

`);
  process.stdout.write(`  ${bold2("To use in production:")}
`);
  process.stdout.write(`    1. Copy ${configPath} to your project
`);
  process.stdout.write(`    2. Edit tool policies to match your server
`);
  process.stdout.write(`    3. Run: protect-mcp --policy protect-mcp.json -- node your-server.js

`);
  process.stdout.write(`${"\u2500".repeat(50)}

`);
  process.env.PROTECT_MCP_CONFIG = configPath;
  await handleDemo();
}
async function handleRegistry(argv) {
  const subcommand = argv[0] || "status";
  const dir = (0, import_node_path16.resolve)(flagValue(argv, "--dir") || process.cwd());
  const orgName = flagValue(argv, "--org") || process.env.SCOPEBLIND_ORG;
  const orgId = flagValue(argv, "--org-id") || process.env.SCOPEBLIND_ORG_ID;
  const billingAccountId = flagValue(argv, "--billing-account") || process.env.SCOPEBLIND_BILLING_ACCOUNT;
  const endpoint2 = flagValue(argv, "--endpoint") || process.env.SCOPEBLIND_REGISTRY_ENDPOINT || (argv.includes("--hosted") ? "https://api.scopeblind.com" : void 0);
  const token = flagValue(argv, "--token") || process.env.SCOPEBLIND_TOKEN;
  const verifierBaseUrl = flagValue(argv, "--verifier-base") || process.env.SCOPEBLIND_VERIFIER_BASE || "https://legate.scopeblind.com";
  const registryMod = await Promise.resolve().then(() => (init_receipt_registry(), receipt_registry_exports));
  if (subcommand === "init") {
    const identity = registryMod.createOrgIdentity({
      dir,
      orgName,
      orgId,
      billingAccountId
    });
    const path = registryMod.writeOrgIdentity(dir, identity);
    process.stdout.write(`
${bold2("protect-mcp registry init")}

`);
    process.stdout.write(`  Org:              ${identity.org_name}
`);
    process.stdout.write(`  Org ID:           ${identity.org_id}
`);
    process.stdout.write(`  Billing account:  ${identity.billing_account_id}
`);
    process.stdout.write(`  Public keys:      ${identity.public_key_directory.length}
`);
    process.stdout.write(`  Wrote:            ${path}

`);
    process.stdout.write(`${dim2("No prompts, tool payloads, raw receipts, or private keys are included.")}

`);
    return;
  }
  if (subcommand === "anchor") {
    process.stdout.write(`
${bold2("protect-mcp registry anchor")}

`);
    const result2 = await registryMod.createReceiptRegistry({
      dir,
      orgName,
      orgId,
      billingAccountId,
      endpoint: endpoint2,
      token,
      hosted: argv.includes("--hosted") || Boolean(endpoint2 || token),
      verifierBaseUrl,
      outPath: flagValue(argv, "--output")
    });
    process.stdout.write(`  Org:              ${result2.registry.org.org_name}
`);
    process.stdout.write(`  Billing account:  ${result2.registry.billing.billing_account_id}
`);
    process.stdout.write(`  Digests:          ${result2.registry.records.length}
`);
    process.stdout.write(`  Anchors:          ${result2.registry.anchors.length}
`);
    process.stdout.write(`  Boundary:         ${result2.uploaded ? green2("hosted digest anchor") : yellow2("local preview only")}
`);
    process.stdout.write(`  Registry:         ${result2.registryPath}
`);
    process.stdout.write(`  Verifier page:    ${result2.verifierPath}

`);
    process.stdout.write(`  Uploaded fields:  ${result2.registry.privacy.uploaded_fields.join(", ")}
`);
    process.stdout.write(`  Excluded fields:  ${result2.registry.privacy.excluded_fields.join(", ")}

`);
    if (!result2.uploaded) {
      process.stdout.write(`${yellow2("  This is not an independent timestamp yet.")}
`);
      process.stdout.write(`  Run with ${dim2("--hosted --token $SCOPEBLIND_TOKEN")} to make the paid boundary real.

`);
    }
    return;
  }
  if (subcommand === "status") {
    const registryPath = (0, import_node_path16.join)(dir, registryMod.REGISTRY_FILE);
    const identityPath = (0, import_node_path16.join)(dir, registryMod.ORG_IDENTITY_FILE);
    process.stdout.write(`
${bold2("protect-mcp registry status")}

`);
    if ((0, import_node_fs21.existsSync)(identityPath)) {
      const identity = JSON.parse((0, import_node_fs21.readFileSync)(identityPath, "utf-8"));
      process.stdout.write(`  Org:              ${identity.org_name || "unknown"}
`);
      process.stdout.write(`  Org ID:           ${identity.org_id || "unknown"}
`);
      process.stdout.write(`  Billing account:  ${identity.billing_account_id || "unknown"}
`);
    } else {
      process.stdout.write(`  Org identity:     ${yellow2("missing")} (${identityPath})
`);
    }
    if ((0, import_node_fs21.existsSync)(registryPath)) {
      const registry = JSON.parse((0, import_node_fs21.readFileSync)(registryPath, "utf-8"));
      const hosted = Array.isArray(registry.anchors) && registry.anchors.some((a) => a.timestamp_source === "scopeblind-hosted");
      process.stdout.write(`  Registry:         ${registryPath}
`);
      process.stdout.write(`  Digests:          ${registry.records?.length || 0}
`);
      process.stdout.write(`  Anchors:          ${registry.anchors?.length || 0}
`);
      process.stdout.write(`  Boundary:         ${hosted ? green2("hosted digest anchor") : yellow2("local preview only")}
`);
      process.stdout.write(`  Verifier page:    ${(0, import_node_path16.join)(dir, registryMod.VERIFIER_PAGE_FILE)}
`);
    } else {
      process.stdout.write(`  Registry:         ${yellow2("missing")} (${registryPath})
`);
      process.stdout.write(`  Next:             ${dim2("npx protect-mcp registry anchor --hosted")}
`);
    }
    process.stdout.write(`
`);
    return;
  }
  process.stderr.write("Usage: protect-mcp registry init|anchor|status [--dir <path>] [--org <name>] [--hosted]\\n");
  process.exit(1);
}
async function handleKillerDemo(argv) {
  const { mkdtempSync } = await import("fs");
  const { tmpdir } = await import("os");
  const { ed25519: ed255197 } = await import("@noble/curves/ed25519");
  const { bytesToHex: bytesToHex10 } = await import("@noble/hashes/utils");
  const { randomBytes: randomBytes11 } = await import("crypto");
  const artifacts2 = await import("@veritasacta/artifacts");
  const {
    createSelectiveDisclosurePackage: createSelectiveDisclosurePackage2,
    signCommittedDecision: signCommittedDecision2,
    verifySelectiveDisclosurePackage: verifySelectiveDisclosurePackage2
  } = await Promise.resolve().then(() => (init_signing_committed(), signing_committed_exports));
  const registryMod = await Promise.resolve().then(() => (init_receipt_registry(), receipt_registry_exports));
  const dir = (0, import_node_path16.resolve)(flagValue(argv, "--dir") || mkdtempSync((0, import_node_path16.join)(tmpdir(), "scopeblind-killer-demo-")));
  (0, import_node_fs21.mkdirSync)(dir, { recursive: true });
  (0, import_node_fs21.mkdirSync)((0, import_node_path16.join)(dir, "keys"), { recursive: true });
  (0, import_node_fs21.mkdirSync)((0, import_node_path16.join)(dir, "receipts"), { recursive: true });
  const privateKeyBytes = randomBytes11(32);
  const publicKeyBytes = ed255197.getPublicKey(privateKeyBytes);
  const keypair2 = {
    privateKey: bytesToHex10(privateKeyBytes),
    publicKey: bytesToHex10(publicKeyBytes),
    kid: `killer-demo-${Date.now()}`,
    issuer: "scopeblind-killer-demo"
  };
  const keyPath = (0, import_node_path16.join)(dir, "keys", "gateway.json");
  (0, import_node_fs21.writeFileSync)(keyPath, JSON.stringify({
    ...keypair2,
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    warning: "Demo key only. Do not use for production."
  }, null, 2) + "\n");
  const shadowConfigPath = (0, import_node_path16.join)(dir, "protect-mcp.shadow.json");
  const policyPackPath = (0, import_node_path16.join)(dir, "protect-mcp.policy-pack.json");
  const config = {
    tools: { "*": { rate_limit: "100/hour" } },
    default_tier: "signed-known",
    signing: { key_path: keyPath, issuer: keypair2.issuer, enabled: true }
  };
  const policyPack = {
    tools: {
      "*": { rate_limit: "100/hour" },
      read_file: { rate_limit: "60/hour" },
      github_create_pr: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      send_email: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      pms_book_fill: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      delete_file: { block: true, min_tier: "privileged" }
    },
    default_tier: "signed-known",
    signing: { key_path: keyPath, issuer: keypair2.issuer, enabled: true },
    notes: ["Demo policy pack: approvals for GitHub, email, and PMS booking; destructive tools blocked."]
  };
  (0, import_node_fs21.writeFileSync)(shadowConfigPath, JSON.stringify(config, null, 2) + "\n");
  (0, import_node_fs21.writeFileSync)(policyPackPath, JSON.stringify(policyPack, null, 2) + "\n");
  await initSigning({ enabled: true, key_path: keyPath, issuer: keypair2.issuer });
  const logPath = (0, import_node_path16.join)(dir, ".protect-mcp-log.jsonl");
  const receiptPath = (0, import_node_path16.join)(dir, ".protect-mcp-receipts.jsonl");
  const shadowCalls = [
    { tool: "read_file", input: { path: "/research/macro-notes.md" }, reason: "observe_mode" },
    { tool: "github_create_pr", input: { repo: "scopeblind/legate", branch: "agent/pms-adapter", title: "Wire mock PMS adapter" }, reason: "observe_mode" },
    { tool: "send_email", input: { to: "ops@examplefund.com", subject: "Booking update", body: "Draft only", api_key: "demo-secret" }, reason: "observe_mode" },
    { tool: "pms_book_fill", input: { account: "Meridian Global Macro", symbol: "AAPL", side: "BUY", quantity: 50, price: 182.4, strategy: "US Large Cap Tactical", bearerToken: "demo-secret" }, reason: "observe_mode" }
  ];
  for (const [idx, call] of shadowCalls.entries()) {
    const requestId2 = `demo-shadow-${idx + 1}`;
    (0, import_node_fs21.appendFileSync)(logPath, JSON.stringify({
      v: 2,
      tool: call.tool,
      decision: "allow",
      reason_code: call.reason,
      request_id: requestId2,
      timestamp: Date.now() + idx,
      mode: "shadow",
      policy_digest: "shadow-policy",
      action_readback: buildActionReadback(call.tool, call.input)
    }) + "\n");
  }
  const sensitiveInput = {
    account: "Meridian Global Macro",
    symbol: "AAPL",
    side: "BUY",
    quantity: 50,
    price: 182.4,
    strategy: "US Large Cap Tactical",
    trader_note: "Do not reveal portfolio context outside the desk.",
    api_key: "demo-pms-secret"
  };
  const readback = buildActionReadback("pms_book_fill", sensitiveInput);
  const requestId = "demo-sensitive-pms-booking";
  const requireApprovalEntry = {
    v: 2,
    tool: "pms_book_fill",
    decision: "require_approval",
    reason_code: "requires_human_approval",
    request_id: requestId,
    timestamp: Date.now() + 10,
    mode: "enforce",
    policy_digest: (0, import_node_crypto16.createHash)("sha256").update(JSON.stringify(policyPack)).digest("hex").slice(0, 16),
    action_readback: readback
  };
  (0, import_node_fs21.appendFileSync)(logPath, JSON.stringify(requireApprovalEntry) + "\n");
  (0, import_node_fs21.appendFileSync)((0, import_node_path16.join)(dir, ".protect-mcp-approval-resolutions.jsonl"), JSON.stringify({
    type: "scopeblind.approval_resolution.v1",
    at: (/* @__PURE__ */ new Date()).toISOString(),
    request_id: requestId,
    tool: "pms_book_fill",
    resolution: "approve",
    reason: "Matches the ticket and stays inside mandate.",
    payload_hash: readback.payload_hash
  }) + "\n");
  const executedEntry = {
    ...requireApprovalEntry,
    decision: "allow",
    reason_code: "approval_granted",
    timestamp: Date.now() + 20,
    payload_digest: {
      output_hash: (0, import_node_crypto16.createHash)("sha256").update("mock-pms-booking-confirmed").digest("hex"),
      output_size: 26,
      truncated: false
    }
  };
  (0, import_node_fs21.appendFileSync)(logPath, JSON.stringify(executedEntry) + "\n");
  const signed2 = signDecision(executedEntry);
  if (!signed2.signed) throw new Error(`demo signing failed: ${signed2.warning || signed2.error || "unknown"}`);
  (0, import_node_fs21.appendFileSync)(receiptPath, signed2.signed + "\n");
  (0, import_node_fs21.writeFileSync)((0, import_node_path16.join)(dir, "receipts", "approved-pms-booking.receipt.json"), JSON.stringify(JSON.parse(signed2.signed), null, 2) + "\n");
  const receiptArtifact = JSON.parse(signed2.signed);
  const tamperedArtifact = JSON.parse(signed2.signed);
  if (tamperedArtifact.payload && typeof tamperedArtifact.payload === "object") {
    tamperedArtifact.payload.decision = "deny";
    tamperedArtifact.payload.tool_name = "send_email";
  } else {
    tamperedArtifact.tool = "send_email";
  }
  const validOriginal = verifyReceipt(receiptArtifact, keypair2.publicKey);
  const validTampered = verifyReceipt(tamperedArtifact, keypair2.publicKey);
  (0, import_node_fs21.writeFileSync)((0, import_node_path16.join)(dir, "receipts", "tampered.receipt.json"), JSON.stringify(tamperedArtifact, null, 2) + "\n");
  const committed = signCommittedDecision2(
    executedEntry,
    ["tool", "payload_digest", "swarm"],
    keypair2.privateKey,
    keypair2.publicKey,
    keypair2.kid,
    keypair2.issuer
  );
  const committedReceipt = JSON.parse(committed.signed);
  const disclosurePackage = createSelectiveDisclosurePackage2(committedReceipt, ["tool"], committed.openings);
  const disclosureVerification = verifySelectiveDisclosurePackage2(committedReceipt, disclosurePackage);
  (0, import_node_fs21.appendFileSync)(receiptPath, committed.signed + "\n");
  (0, import_node_fs21.writeFileSync)((0, import_node_path16.join)(dir, "receipts", "selective-disclosure.receipt.json"), JSON.stringify(committedReceipt, null, 2) + "\n");
  (0, import_node_fs21.writeFileSync)((0, import_node_path16.join)(dir, "receipts", "selective-disclosure.package.json"), JSON.stringify(disclosurePackage, null, 2) + "\n");
  (0, import_node_fs21.writeFileSync)((0, import_node_path16.join)(dir, "receipts", "selective-disclosure.tool-only.json"), JSON.stringify(disclosurePackage, null, 2) + "\n");
  (0, import_node_fs21.writeFileSync)((0, import_node_path16.join)(dir, "verification-results.json"), JSON.stringify({
    original_receipt_valid: validOriginal,
    tampered_receipt_valid: validTampered,
    selective_disclosure_valid: disclosureVerification.valid,
    selective_disclosure_explanation: disclosureVerification.explanation
  }, null, 2) + "\n");
  const registry = await registryMod.createReceiptRegistry({
    dir,
    orgName: flagValue(argv, "--org") || "Meridian Global Macro Demo",
    billingAccountId: flagValue(argv, "--billing-account") || "demo_billing_digest_only",
    hosted: argv.includes("--hosted"),
    endpoint: flagValue(argv, "--endpoint") || process.env.SCOPEBLIND_REGISTRY_ENDPOINT || (argv.includes("--hosted") ? "https://api.scopeblind.com" : void 0),
    token: flagValue(argv, "--token") || process.env.SCOPEBLIND_TOKEN,
    verifierBaseUrl: flagValue(argv, "--verifier-base") || "https://legate.scopeblind.com"
  });
  const runbook = [
    "# ScopeBlind Killer Demo",
    "",
    "Three-minute flow, generated locally.",
    "",
    "## 1. Agent has tools",
    "",
    "Mock tools represented: filesystem `read_file`, GitHub `github_create_pr`, email `send_email`, and PMS `pms_book_fill`.",
    "",
    "## 2. Shadow mode shows risk",
    "",
    "Open the dashboard against this directory:",
    "",
    "```bash",
    `npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`,
    "```",
    "",
    "You will see GitHub, email, and PMS calls ranked as high risk.",
    "",
    "## 3. Apply policy pack",
    "",
    `Policy pack: \`${policyPackPath}\`.`,
    "",
    "It requires approval for GitHub PRs, outbound email, and PMS booking; destructive file deletion is blocked.",
    "",
    "## 4. Sensitive action requires exact approval",
    "",
    `Request id: \`${requestId}\``,
    "",
    `Exact readback summary: \`${readback.summary}\``,
    "",
    `Payload hash: \`${readback.payload_hash}\``,
    "",
    "Secret-like fields are redacted from the approval preview but still affect the hash.",
    "",
    "## 5. User approves; tool executes through gateway",
    "",
    "Approval resolution: `.protect-mcp-approval-resolutions.jsonl`",
    "",
    "Signed receipt: `receipts/approved-pms-booking.receipt.json`",
    "",
    "## 6. Offline verification and tamper failure",
    "",
    "Verification result: `verification-results.json`.",
    "",
    "Expected: original valid, tampered invalid.",
    "",
    "## 7. Selective disclosure",
    "",
    "Committed receipt: `receipts/selective-disclosure.receipt.json`",
    "",
    "Tool-only v0 disclosure package: `receipts/selective-disclosure.tool-only.json`",
    "",
    "The disclosure opens only the committed `tool` field. Other committed fields, such as `payload_digest`, remain hidden but bound to the signed `committed_fields_root`.",
    "",
    "This demonstrates hiding sensitive context while revealing the minimum needed proof. It is salted commitment disclosure, not full zero-knowledge.",
    "",
    "## 8. Paid boundary MVP",
    "",
    `Registry: \`${registry.registryPath}\``,
    "",
    `Verifier page: \`${registry.verifierPath}\``,
    "",
    `Boundary: ${registry.uploaded ? "hosted digest anchor with independent timestamp" : "local preview only; hosted anchoring not used"}.`,
    "",
    "No raw prompt, payload, output, private key, or raw receipt is uploaded by the registry flow. Hosted mode submits receipt digests, request ids, org public keys, and billing account metadata only.",
    ""
  ].join("\n");
  (0, import_node_fs21.writeFileSync)((0, import_node_path16.join)(dir, "DEMO-RUNBOOK.md"), runbook);
  (0, import_node_fs21.writeFileSync)((0, import_node_path16.join)(dir, "demo-summary.json"), JSON.stringify({
    dir,
    dashboard_command: `npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`,
    policy_pack: policyPackPath,
    receipt: (0, import_node_path16.join)(dir, "receipts", "approved-pms-booking.receipt.json"),
    tampered_receipt: (0, import_node_path16.join)(dir, "receipts", "tampered.receipt.json"),
    selective_disclosure_receipt: (0, import_node_path16.join)(dir, "receipts", "selective-disclosure.receipt.json"),
    selective_disclosure_package: (0, import_node_path16.join)(dir, "receipts", "selective-disclosure.tool-only.json"),
    verification_results: (0, import_node_path16.join)(dir, "verification-results.json"),
    registry: registry.registryPath,
    verifier_page: registry.verifierPath,
    runbook: (0, import_node_path16.join)(dir, "DEMO-RUNBOOK.md"),
    original_valid: validOriginal.valid,
    tampered_valid: validTampered.valid,
    selective_disclosure_valid: disclosureVerification.valid
  }, null, 2) + "\n");
  process.stdout.write(`
${bold2("protect-mcp killer-demo")}

`);
  process.stdout.write(`  Demo dir:          ${dir}
`);
  process.stdout.write(`  Dashboard:         ${dim2(`npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`)}
`);
  process.stdout.write(`  Runbook:           ${(0, import_node_path16.join)(dir, "DEMO-RUNBOOK.md")}
`);
  process.stdout.write(`  Signed receipt:    ${(0, import_node_path16.join)(dir, "receipts", "approved-pms-booking.receipt.json")}
`);
  process.stdout.write(`  Tamper check:      original=${validOriginal.valid ? green2("valid") : red2("invalid")} tampered=${validTampered.valid ? red2("valid") : green2("invalid")}
`);
  process.stdout.write(`  Registry:          ${registry.registryPath}
`);
  process.stdout.write(`  Verifier page:     ${registry.verifierPath}
`);
  process.stdout.write(`  Boundary:          ${registry.uploaded ? green2("hosted digest anchor") : yellow2("local preview only")}

`);
}
async function handleVerifyDisclosure(argv) {
  const receiptPath = flagValue(argv, "--receipt");
  const disclosurePath = flagValue(argv, "--disclosure");
  if (!receiptPath || !disclosurePath) {
    process.stderr.write("Usage: protect-mcp verify-disclosure --receipt <committed-receipt.json> --disclosure <selective-disclosure.json>\\n");
    process.exit(1);
  }
  const { verifySelectiveDisclosurePackage: verifySelectiveDisclosurePackage2 } = await Promise.resolve().then(() => (init_signing_committed(), signing_committed_exports));
  const receipt = JSON.parse((0, import_node_fs21.readFileSync)((0, import_node_path16.resolve)(receiptPath), "utf-8"));
  const disclosure = JSON.parse((0, import_node_fs21.readFileSync)((0, import_node_path16.resolve)(disclosurePath), "utf-8"));
  const result2 = verifySelectiveDisclosurePackage2(receipt, disclosure);
  process.stdout.write(`
${bold2("protect-mcp verify-disclosure")}

`);
  process.stdout.write(`  Result:           ${result2.valid ? green2("valid") : red2("invalid")}
`);
  process.stdout.write(`  Receipt hash:     ${result2.receipt_hash_valid ? green2("matches") : red2("mismatch")}
`);
  process.stdout.write(`  Signature:        ${result2.signature_valid === true ? green2("valid") : result2.signature_valid === null ? yellow2("not checked") : red2("invalid")}
`);
  process.stdout.write(`  Commitment root:  ${result2.commitment_root_valid ? green2("matches") : red2("mismatch")}
`);
  process.stdout.write(`  Disclosed fields: ${result2.disclosed_fields.length ? result2.disclosed_fields.join(", ") : "none"}
`);
  process.stdout.write(`  Hidden fields:    ${result2.hidden_fields.length ? result2.hidden_fields.join(", ") : "none"}

`);
  for (const line of result2.explanation) {
    process.stdout.write(`  - ${line}
`);
  }
  if (result2.errors.length > 0) {
    process.stdout.write(`
${red2("Errors:")}
`);
    for (const err of result2.errors) process.stdout.write(`  - ${err}
`);
  }
  process.stdout.write("\n");
  if (!result2.valid) process.exit(2);
}
async function handlePolicyPacks(argv) {
  const subcommand = argv[0] || "list";
  const packArg = argv[1];
  const dir = (0, import_node_path16.resolve)(flagValue(argv, "--dir") || "./cedar");
  const force = argv.includes("--force");
  if (subcommand === "list") {
    process.stdout.write(`
${bold2("protect-mcp policy-packs")}

`);
    for (const pack of POLICY_PACKS) {
      process.stdout.write(`  ${bold2(pack.id.padEnd(22))} ${pack.name}
`);
      process.stdout.write(`  ${dim2(" ".repeat(24) + pack.description)}
`);
      process.stdout.write(`  ${dim2(" ".repeat(24) + `recommended: ${pack.recommendedMode}`)}

`);
    }
    process.stdout.write(`Install one: ${dim2("protect-mcp policy-packs install filesystem-safe --dir ./cedar")}
`);
    process.stdout.write(`Install all: ${dim2("protect-mcp policy-packs install all --dir ./cedar")}

`);
    return;
  }
  if (subcommand === "show") {
    const pack = getPolicyPack(packArg || "");
    if (!pack) {
      process.stderr.write(`Unknown policy pack "${packArg || ""}". Available: ${policyPackIds().join(", ")}
`);
      process.exit(1);
    }
    process.stdout.write(`
${bold2(pack.name)} (${pack.id})

`);
    process.stdout.write(`${pack.description}
`);
    process.stdout.write(`Recommended rollout: ${pack.recommendedMode}

`);
    for (const file of pack.files) {
      process.stdout.write(`${dim2(`--- ${file.path} ---`)}
`);
      process.stdout.write(file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
      process.stdout.write("\n");
    }
    return;
  }
  if (subcommand === "install") {
    const packs = packArg === "all" ? POLICY_PACKS : [getPolicyPack(packArg || "")].filter(Boolean);
    if (packs.length === 0) {
      process.stderr.write(`Usage: protect-mcp policy-packs install <${policyPackIds().join("|")}|all> [--dir ./cedar] [--force]
`);
      process.exit(1);
    }
    (0, import_node_fs21.mkdirSync)(dir, { recursive: true });
    const written = [];
    for (const pack of packs) {
      for (const file of pack.files) {
        const outPath = (0, import_node_path16.join)(dir, file.path);
        if ((0, import_node_fs21.existsSync)(outPath) && !force) {
          process.stderr.write(`Refusing to overwrite ${outPath}. Re-run with --force if intentional.
`);
          process.exit(1);
        }
        (0, import_node_fs21.writeFileSync)(outPath, file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
        written.push(outPath);
      }
    }
    process.stdout.write(`
${bold2("protect-mcp policy-packs install")}

`);
    process.stdout.write(`  Directory: ${dir}
`);
    for (const outPath of written) process.stdout.write(`  Wrote:     ${outPath}
`);
    process.stdout.write(`
Next: ${dim2(`protect-mcp serve --cedar ${dir}`)} for shadow mode, then add ${dim2("--enforce")} after reviewing receipts.

`);
    return;
  }
  process.stderr.write("Usage: protect-mcp policy-packs list|show|install [pack] [--dir ./cedar] [--force]\n");
  process.exit(1);
}
async function handleConnectors(argv) {
  const subcommand = argv[0] || "list";
  const pilotArg = argv[1];
  const dir = (0, import_node_path16.resolve)(flagValue(argv, "--dir") || process.cwd());
  const force = argv.includes("--force");
  if (subcommand === "list") {
    process.stdout.write(`
${bold2("protect-mcp connector pilots")}

`);
    for (const pilot of CONNECTOR_PILOTS) {
      process.stdout.write(`  ${bold2(pilot.id.padEnd(18))} ${pilot.name}
`);
      process.stdout.write(`  ${dim2(" ".repeat(20) + pilot.description)}
`);
      process.stdout.write(`  ${dim2(" ".repeat(20) + `tools: ${pilot.tools.join(", ")}`)}

`);
    }
    process.stdout.write(`Install all: ${dim2("protect-mcp connectors init all --force")}
`);
    process.stdout.write(`Check credentials: ${dim2("protect-mcp connectors doctor")}

`);
    return;
  }
  if (subcommand === "show") {
    const pilot = getConnectorPilot(pilotArg || "");
    if (!pilot) {
      process.stderr.write(`Unknown connector pilot "${pilotArg || ""}". Available: ${CONNECTOR_PILOTS.map((p) => p.id).join(", ")}
`);
      process.exit(1);
    }
    process.stdout.write(`
${bold2(pilot.name)} (${pilot.id})

`);
    process.stdout.write(`${pilot.description}

`);
    process.stdout.write(`${bold2("Why it matters:")} ${pilot.value}

`);
    process.stdout.write(`${bold2("Tools:")} ${pilot.tools.join(", ")}

`);
    process.stdout.write(`${bold2("Setup:")}
`);
    for (const step of pilot.setup) process.stdout.write(`  - ${step}
`);
    process.stdout.write(`
${bold2("Starter policy:")}
${pilot.cedar}
`);
    return;
  }
  if (subcommand === "init") {
    const ids = pilotArg ? [pilotArg] : ["all"];
    const installed = writeConnectorPilots({ dir, ids, force });
    process.stdout.write(`
${bold2("protect-mcp connectors init")}

`);
    process.stdout.write(`  Directory: ${installed.directory}
`);
    for (const outPath of installed.written) process.stdout.write(`  Wrote:     ${outPath}
`);
    process.stdout.write(`
Next: ${dim2("protect-mcp connectors doctor")} then ${dim2("protect-mcp dashboard --open")}.

`);
    return;
  }
  if (subcommand === "doctor") {
    let rows = connectorDoctor(dir);
    if (pilotArg && pilotArg !== "all") {
      const pilot = getConnectorPilot(pilotArg);
      if (!pilot) {
        process.stderr.write(`Unknown connector pilot "${pilotArg}". Available: ${CONNECTOR_PILOTS.map((p) => p.id).join(", ")}
`);
        process.exit(1);
      }
      rows = rows.filter((row) => row.id === pilot.id);
    }
    process.stdout.write(`
${bold2("protect-mcp connectors doctor")}

`);
    for (const row of rows) {
      const missing = Array.isArray(row.missing_required) && row.missing_required.length > 0 ? row.missing_required.join(", ") : "";
      const status = row.installed ? row.usable ? green2("ready") : yellow2("needs setup") : dim2("not installed");
      process.stdout.write(`  ${bold2(String(row.id).padEnd(18))} ${status}
`);
      process.stdout.write(`  ${dim2(" ".repeat(20) + `mode: ${String(row.mode || "unknown")}`)}
`);
      if (missing) process.stdout.write(`  ${yellow2(" ".repeat(20) + `missing: ${missing}`)}
`);
      process.stdout.write(`  ${dim2(" ".repeat(20) + String(row.next || ""))}

`);
    }
    process.stdout.write(`${dim2("Secret values are never printed; only missing variable names are shown.")}

`);
    return;
  }
  process.stderr.write("Usage: protect-mcp connectors list|show|init|doctor [connector|all] [--dir <path>] [--force]\n");
  process.exit(1);
}
async function handleTrace(argv) {
  const receiptId = argv[0];
  if (!receiptId) {
    process.stderr.write("[PROTECT_MCP] Usage: protect-mcp trace <receipt_id> [--endpoint <url>] [--depth <n>]\n");
    process.exit(1);
  }
  let endpoint2 = "https://api.scopeblind.com/evidence";
  let depth = 3;
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === "--endpoint" && argv[i + 1]) {
      endpoint2 = argv[++i];
    } else if (argv[i] === "--depth" && argv[i + 1]) {
      depth = Math.min(10, Math.max(1, parseInt(argv[++i], 10) || 3));
    }
  }
  process.stdout.write(`
${bold2("protect-mcp trace")}
`);
  process.stdout.write(`${"\u2500".repeat(60)}

`);
  process.stdout.write(`  Root:     ${receiptId}
`);
  process.stdout.write(`  Endpoint: ${endpoint2}
`);
  process.stdout.write(`  Depth:    ${depth}

`);
  const url = `${endpoint2}/evidence/graph/${encodeURIComponent(receiptId)}?depth=${depth}&direction=both&max=50`;
  let graphData;
  try {
    const resp = await fetch(url);
    if (!resp.ok) {
      const body = await resp.text();
      process.stderr.write(`[PROTECT_MCP] Error fetching graph: ${resp.status} ${body}
`);
      process.exit(1);
    }
    graphData = await resp.json();
  } catch (err) {
    process.stderr.write(`[PROTECT_MCP] Could not reach evidence indexer at ${endpoint2}
`);
    process.stderr.write(`[PROTECT_MCP] Trying local receipts...

`);
    await traceLocal(receiptId);
    return;
  }
  if (!graphData.nodes || graphData.nodes.length === 0) {
    process.stdout.write(`  No receipts found for ${receiptId}

`);
    return;
  }
  process.stdout.write(`  ${bold2("Evidence DAG")} (${graphData.node_count} nodes, ${graphData.edge_count} edges)

`);
  const nodeMap = /* @__PURE__ */ new Map();
  for (const node of graphData.nodes) {
    nodeMap.set(node.receipt_id, node);
  }
  const childMap = /* @__PURE__ */ new Map();
  for (const edge of graphData.edges) {
    if (!childMap.has(edge.from)) childMap.set(edge.from, []);
    childMap.get(edge.from).push({ to: edge.to, relation: edge.relation });
  }
  const rendered = /* @__PURE__ */ new Set();
  function renderNode(id5, prefix, isLast) {
    const node = nodeMap.get(id5);
    const connector = isLast ? "\u2514\u2500\u2500 " : "\u251C\u2500\u2500 ";
    const childPrefix = isLast ? "    " : "\u2502   ";
    const typeEmoji = getTypeEmoji(node?.receipt_type || "unknown");
    const shortId = id5.length > 16 ? id5.slice(0, 12) + "\u2026" : id5;
    const time5 = node?.event_time ? new Date(node.event_time).toLocaleTimeString() : "?";
    const type = node?.receipt_type?.replace("acta:", "") || "unknown";
    process.stdout.write(`${prefix}${connector}${typeEmoji} ${bold2(type)} ${dim2(shortId)} ${dim2(time5)}
`);
    if (rendered.has(id5)) {
      process.stdout.write(`${prefix}${childPrefix}${dim2("(cycle: already rendered)")}
`);
      return;
    }
    rendered.add(id5);
    const children = childMap.get(id5) || [];
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const edgeLabel = dim2(`\u2500\u2500[${child.relation}]\u2500\u2500\u25B6`);
      process.stdout.write(`${prefix}${childPrefix}${edgeLabel}
`);
      renderNode(child.to, prefix + childPrefix, i === children.length - 1);
    }
  }
  const rootNode = nodeMap.get(receiptId);
  if (rootNode) {
    const typeEmoji = getTypeEmoji(rootNode.receipt_type);
    const type = rootNode.receipt_type?.replace("acta:", "") || "unknown";
    const time5 = rootNode.event_time ? new Date(rootNode.event_time).toLocaleTimeString() : "?";
    process.stdout.write(`  ${typeEmoji} ${bold2(type)} ${dim2(receiptId.slice(0, 16) + "\u2026")} ${dim2(time5)} ${bold2("(root)")}
`);
    rendered.add(receiptId);
    const children = childMap.get(receiptId) || [];
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const edgeLabel = dim2(`\u2500\u2500[${child.relation}]\u2500\u2500\u25B6`);
      process.stdout.write(`  ${edgeLabel}
`);
      renderNode(child.to, "  ", i === children.length - 1);
    }
    const incomingEdges = (graphData.edges || []).filter((e) => e.to === receiptId);
    if (incomingEdges.length > 0) {
      process.stdout.write(`
  ${bold2("Incoming edges:")}
`);
      for (const edge of incomingEdges) {
        const fromNode = nodeMap.get(edge.from);
        const fromType = fromNode?.receipt_type?.replace("acta:", "") || "unknown";
        process.stdout.write(`  \u25C0\u2500\u2500[${edge.relation}]\u2500\u2500 ${getTypeEmoji(fromNode?.receipt_type)} ${fromType} ${dim2(edge.from.slice(0, 16) + "\u2026")}
`);
      }
    }
  } else {
    for (const node of graphData.nodes) {
      const typeEmoji = getTypeEmoji(node.receipt_type);
      const type = node.receipt_type?.replace("acta:", "") || "unknown";
      process.stdout.write(`  ${typeEmoji} ${bold2(type)} ${dim2(node.receipt_id.slice(0, 16) + "\u2026")}
`);
    }
  }
  process.stdout.write(`
${"\u2500".repeat(60)}
`);
  process.stdout.write(`  ${dim2(`Fetched from ${endpoint2}`)}

`);
}
async function traceLocal(receiptId) {
  const { readFileSync: readFileSync19, existsSync: existsSync13 } = await import("fs");
  const { join: join13 } = await import("path");
  const dir = process.cwd();
  const receiptsDir = join13(dir, ".protect-mcp", "receipts");
  if (!existsSync13(receiptsDir)) {
    process.stdout.write(`  No local receipts found in ${receiptsDir}

`);
    return;
  }
  const { readdirSync: readdirSync7 } = await import("fs");
  const files = readdirSync7(receiptsDir).filter((f) => f.endsWith(".json"));
  process.stdout.write(`  Scanning ${files.length} local receipts...

`);
  const receipts = [];
  for (const file of files) {
    try {
      const content = readFileSync19(join13(receiptsDir, file), "utf-8");
      const receipt = JSON.parse(content);
      receipts.push(receipt);
    } catch {
    }
  }
  const match = receipts.find(
    (r) => r.signed_claims?.claims?.receipt_id === receiptId || r.receipt_id === receiptId
  );
  if (match) {
    const claims = match.signed_claims?.claims || match;
    process.stdout.write(`  Found: ${getTypeEmoji(claims.receipt_type)} ${bold2(claims.receipt_type?.replace("acta:", "") || "unknown")}
`);
    process.stdout.write(`  Event:  ${claims.event_id || "?"}
`);
    process.stdout.write(`  Issuer: ${claims.issuer_id || "?"}
`);
    process.stdout.write(`  Time:   ${claims.event_time || "?"}
`);
    if (claims.edges && claims.edges.length > 0) {
      process.stdout.write(`
  ${bold2("Edges:")}
`);
      for (const edge of claims.edges) {
        process.stdout.write(`    \u2500\u2500[${edge.relation}]\u2500\u2500\u25B6 ${dim2(edge.receipt_id?.slice(0, 16) + "\u2026")}
`);
      }
    }
  } else {
    process.stdout.write(`  Receipt ${receiptId} not found locally.
`);
  }
  process.stdout.write("\n");
}
function getTypeEmoji(type) {
  switch (type) {
    case "acta:observation":
      return "\u{1F441} ";
    case "acta:policy-load":
      return "\u{1F4CB}";
    case "acta:approval":
      return "\u2705";
    case "acta:decision":
      return "\u2696\uFE0F ";
    case "acta:execution":
      return "\u26A1";
    case "acta:outcome":
      return "\u{1F4E6}";
    case "acta:delegation":
      return "\u{1F91D}";
    case "acta:capability-attestation":
      return "\u{1F3C5}";
    default:
      return "\u{1F4C4}";
  }
}
async function handleInitHooks(argv) {
  const { writeFileSync: writeFileSync11, existsSync: existsSync13, mkdirSync: mkdirSync9, readFileSync: readFileSync19 } = await import("fs");
  const { join: join13 } = await import("path");
  const { generateHookSettings: generateHookSettings2, generateSampleCedarPolicy: generateSampleCedarPolicy2, generateVerifyReceiptSkill: generateVerifyReceiptSkill2 } = await Promise.resolve().then(() => (init_hook_patterns(), hook_patterns_exports));
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const portIdx = argv.indexOf("--port");
  const port = portIdx >= 0 && argv[portIdx + 1] ? parseInt(argv[portIdx + 1]) : 9377;
  const hookUrl = `http://127.0.0.1:${port}/hook`;
  process.stdout.write(`
${bold2("protect-mcp init-hooks")}
`);
  process.stdout.write(`${"\u2500".repeat(55)}

`);
  const claudeDir = join13(dir, ".claude");
  const settingsPath = join13(claudeDir, "settings.json");
  let existingSettings = {};
  if (!existsSync13(claudeDir)) {
    mkdirSync9(claudeDir, { recursive: true });
  }
  if (existsSync13(settingsPath)) {
    try {
      existingSettings = JSON.parse(readFileSync19(settingsPath, "utf-8"));
    } catch {
      process.stderr.write(`[PROTECT_MCP] Warning: Could not parse existing ${settingsPath}
`);
    }
  }
  const hookSettings = generateHookSettings2(hookUrl);
  const mergedSettings = {
    ...existingSettings,
    hooks: {
      ...existingSettings.hooks || {},
      ...hookSettings.hooks
    }
  };
  writeFileSync11(settingsPath, JSON.stringify(mergedSettings, null, 2) + "\n");
  process.stdout.write(`  ${green2("\u2713")} ${settingsPath}
`);
  process.stdout.write(`    Hook URL: ${dim2(hookUrl)}
`);
  process.stdout.write(`    Events: PreToolUse, PostToolUse, SubagentStart/Stop, Task, Session, Config, Stop

`);
  const keysDir = join13(dir, "keys");
  const keyPath = join13(keysDir, "gateway.json");
  if (!existsSync13(keyPath)) {
    if (!existsSync13(keysDir)) mkdirSync9(keysDir, { recursive: true });
    const { randomBytes: rb } = await import("crypto");
    try {
      const { ed25519: ed255197 } = await import("@noble/curves/ed25519");
      const { bytesToHex: bytesToHex10 } = await import("@noble/hashes/utils");
      const privateKey = rb(32);
      const publicKey = ed255197.getPublicKey(privateKey);
      writeFileSync11(keyPath, JSON.stringify({
        privateKey: bytesToHex10(privateKey),
        publicKey: bytesToHex10(publicKey),
        kid: `hook-${Date.now()}`,
        generated_at: (/* @__PURE__ */ new Date()).toISOString(),
        warning: "KEEP THIS FILE SECRET. Never commit to version control."
      }, null, 2) + "\n");
      const gitignorePath = join13(keysDir, ".gitignore");
      if (!existsSync13(gitignorePath)) {
        writeFileSync11(gitignorePath, "# Never commit signing keys\n*.json\n");
      }
      process.stdout.write(`  ${green2("\u2713")} ${keyPath} (Ed25519 keypair)

`);
    } catch {
      process.stdout.write(`  ${yellow2("\u26A0")} Could not generate Ed25519 keys, signing disabled

`);
    }
  } else {
    process.stdout.write(`  ${green2("\u2713")} ${keyPath} (existing keys found)

`);
  }
  const policiesDir = join13(dir, "policies");
  const cedarPath = join13(policiesDir, "agent.cedar");
  if (!existsSync13(cedarPath)) {
    if (!existsSync13(policiesDir)) mkdirSync9(policiesDir, { recursive: true });
    writeFileSync11(cedarPath, generateSampleCedarPolicy2());
    process.stdout.write(`  ${green2("\u2713")} ${cedarPath}
`);
    process.stdout.write(`    Edit to customize tool permissions. Cedar deny is AUTHORITATIVE.

`);
  } else {
    process.stdout.write(`  ${green2("\u2713")} ${cedarPath} (existing policy found)

`);
  }
  const configPath = join13(dir, "protect-mcp.json");
  if (!existsSync13(configPath)) {
    const config = {
      tools: { "*": { rate_limit: "100/hour" } },
      default_tier: "unknown",
      signing: {
        key_path: "./keys/gateway.json",
        issuer: "protect-mcp",
        enabled: true
      }
    };
    writeFileSync11(configPath, JSON.stringify(config, null, 2) + "\n");
    process.stdout.write(`  ${green2("\u2713")} ${configPath}

`);
  }
  const skillsDir = join13(dir, ".claude", "skills", "verify-receipt");
  const skillPath = join13(skillsDir, "SKILL.md");
  if (!existsSync13(skillPath)) {
    mkdirSync9(skillsDir, { recursive: true });
    writeFileSync11(skillPath, generateVerifyReceiptSkill2());
    process.stdout.write(`  ${green2("\u2713")} ${skillPath}
`);
    process.stdout.write(`    Use ${dim2("/verify-receipt")} in Claude Code to check audit trails.

`);
  } else {
    process.stdout.write(`  ${green2("\u2713")} ${skillPath} (existing skill found)

`);
  }
  process.stdout.write(`${"\u2500".repeat(55)}

`);
  process.stdout.write(`${bold2("Next steps:")}

`);
  process.stdout.write(`  1. Start the hook server:
`);
  process.stdout.write(`     ${dim2(`npx protect-mcp serve`)}

`);
  process.stdout.write(`  2. Open a Claude Code session in this project.
`);
  process.stdout.write(`     Every tool call will be receipted automatically.

`);
  process.stdout.write(`  3. See your record: a searchable view of every decision.
`);
  process.stdout.write(`     ${dim2(`npx protect-mcp record`)}
`);
  process.stdout.write(`     ${dim2(`Everything stays on this machine. Nothing is uploaded.`)}

`);
  process.stdout.write(`     Prefer the terminal? ${dim2(`npx protect-mcp receipts`)}, or ${dim2("/verify-receipt")} in Claude Code.

`);
  process.stdout.write(`  4. View policy suggestions:
`);
  process.stdout.write(`     ${dim2(`curl http://127.0.0.1:${port}/suggestions`)}

`);
  process.stdout.write(`${bold2("Key facts:")}
`);
  process.stdout.write(`  \u2022 deny decisions are ${bold2("AUTHORITATIVE")}: they cannot be overridden
`);
  process.stdout.write(`  \u2022 PostToolUse runs ${bold2("async")}, so there is zero latency impact on tool execution
`);
  process.stdout.write(`  \u2022 Receipts are Ed25519-signed and append-only
`);
  process.stdout.write(`  \u2022 Swarm topology (coordinator/workers) is tracked automatically

`);
}
async function sendInstallTelemetry() {
  try {
    const { existsSync: existsSync13, mkdirSync: mkdirSync9, writeFileSync: writeFileSync11 } = await import("fs");
    const { join: join13 } = await import("path");
    const { homedir: homedir4 } = await import("os");
    const markerDir = join13(homedir4(), ".protect-mcp");
    const markerFile = join13(markerDir, ".telemetry-sent");
    if (existsSync13(markerFile) || process.env.PROTECT_MCP_TELEMETRY !== "on") {
      return;
    }
    const version = await pkgVersion();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3e3);
    const response = await fetch("https://api.scopeblind.com/telemetry/install", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: "protect-mcp",
        version,
        os: process.platform,
        arch: process.arch,
        node: process.version,
        ts: Date.now()
      }),
      signal: controller.signal
    }).finally(() => clearTimeout(timeout));
    if (!response.ok) return;
    if (!existsSync13(markerDir)) {
      mkdirSync9(markerDir, { recursive: true });
    }
    writeFileSync11(markerFile, String(Date.now()), "utf-8");
    process.stderr.write(
      "[protect-mcp] Explicitly enabled anonymous install telemetry was accepted. Set PROTECT_MCP_TELEMETRY=off to disable future sends.\n[protect-mcp] Free dashboard: npx protect-mcp connect | https://scopeblind.com\n"
    );
  } catch {
  }
}
function flagValue(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : void 0;
}
function loadPolicyArg(argv) {
  const cedarDir = flagValue(argv, "--cedar");
  const policyFile = flagValue(argv, "--policy");
  try {
    if (cedarDir) return loadCedarPolicies(cedarDir);
    if (policyFile && (0, import_node_fs21.existsSync)(policyFile)) {
      return policySetFromSource((0, import_node_fs21.readFileSync)(policyFile, "utf-8"), (0, import_node_path16.basename)(policyFile));
    }
  } catch {
  }
  return null;
}
async function readHookStdin() {
  if (process.stdin.isTTY) return null;
  try {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf-8").trim();
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function mapHookPayload(j) {
  const tool = j.tool_name ?? j.toolName;
  const input = j.tool_input ?? j.toolInput;
  if (input === void 0 && j.command !== void 0) {
    return { tool: tool ?? "Bash", input: { command: j.command } };
  }
  return { tool, input };
}
function emitDecision(format, allowed, reason) {
  if (format === "hermes") {
    process.stdout.write(JSON.stringify(allowed ? {} : { decision: "block", reason }) + "\n");
    process.exit(0);
  }
  if (allowed) {
    process.stdout.write(JSON.stringify({ allowed: true, reason }) + "\n");
    process.exit(0);
  }
  if (format === "cursor") {
    process.stdout.write(JSON.stringify({ permission: "deny", userMessage: reason }) + "\n");
  } else if (format === "gemini") {
    process.stdout.write(JSON.stringify({ decision: "deny", reason }) + "\n");
  } else if (format === "claude") {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `protect-mcp denied: ${reason}` } }) + "\n");
  }
  process.stderr.write(`protect-mcp denied: ${reason}
`);
  process.exit(2);
}
async function handleEvaluate(argv) {
  const format = flagValue(argv, "--format");
  let tool = flagValue(argv, "--tool") || "";
  let inputRaw = flagValue(argv, "--input") || "{}";
  const contextRaw = flagValue(argv, "--context");
  const actionModel = flagValue(argv, "--action-model") === "tool" ? "tool" : "mcp";
  const failOnMissing = flagValue(argv, "--fail-on-missing-policy") !== "false";
  if (format) {
    const j = await readHookStdin();
    if (j) {
      const m = mapHookPayload(j);
      if (m.tool) tool = m.tool;
      if (m.input !== void 0) inputRaw = JSON.stringify(m.input);
    }
  }
  const policySet = loadPolicyArg(argv);
  if (!policySet) {
    if (failOnMissing) {
      if (format) emitDecision(format, false, "policy not found (fail-closed)");
      process.stderr.write("protect-mcp evaluate: policy not found; denying (fail-closed). Pass --fail-on-missing-policy false to allow.\n");
      process.exit(2);
    }
    process.stderr.write(`protect-mcp evaluate: no policy found${flagValue(argv, "--cedar") ? ` at ${flagValue(argv, "--cedar")}` : flagValue(argv, "--policy") ? ` at ${flagValue(argv, "--policy")}` : ""}; allowing because --fail-on-missing-policy false is set. Nothing is being enforced.
`);
    if (format) emitDecision(format, true, "no_policy_configured");
    process.stdout.write(JSON.stringify({ allowed: true, reason: "no_policy_configured" }) + "\n");
    process.exit(0);
  }
  let input = {};
  try {
    input = JSON.parse(inputRaw);
  } catch {
  }
  let extra = {};
  if (contextRaw) {
    try {
      extra = JSON.parse(contextRaw);
    } catch {
    }
  }
  const context = { ...input, ...extra };
  if (typeof input.command === "string" && context.command_pattern === void 0) {
    context.command_pattern = input.command;
  }
  const decision = await evaluateCedar(policySet, { tool, tier: "unknown", context, toolInput: input, actionModel }, void 0, { failClosed: true });
  if (format) emitDecision(format, decision.allowed, decision.reason || (decision.allowed ? "allowed" : "denied by policy"));
  process.stdout.write(JSON.stringify({ allowed: decision.allowed, reason: decision.reason, policy_digest: policySet.digest }) + "\n");
  process.exit(decision.allowed ? 0 : 2);
}
async function handleSign(argv) {
  const format = flagValue(argv, "--format");
  const dir = (0, import_node_path16.resolve)(flagValue(argv, "--dir") || process.cwd());
  let tool = flagValue(argv, "--tool") || "";
  const receiptsFlag = flagValue(argv, "--receipts");
  const receiptsDir = receiptsFlag || dir;
  const receiptLogPath = receiptsFlag ? (0, import_node_path16.join)(receiptsFlag, "receipts.jsonl") : (0, import_node_path16.join)(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = flagValue(argv, "--key");
  const cedarDir = flagValue(argv, "--cedar");
  const actionModel = flagValue(argv, "--action-model") === "tool" ? "tool" : "mcp";
  const contextRaw = flagValue(argv, "--context");
  let toolInput;
  const inputFlag = flagValue(argv, "--input");
  if (inputFlag) {
    try {
      toolInput = JSON.parse(inputFlag);
    } catch {
      process.stderr.write("protect-mcp sign: --input is not valid JSON\n");
      process.exit(2);
    }
  }
  const j = await readHookStdin();
  if (j) {
    const m = mapHookPayload(j);
    if (m.tool) tool = m.tool;
    if (toolInput === void 0 && m.input && typeof m.input === "object") toolInput = m.input;
  }
  let policyDigest = "none";
  let signing;
  const signConfigPath = (0, import_node_path16.join)(dir, "protect-mcp.json");
  if ((0, import_node_fs21.existsSync)(signConfigPath)) {
    try {
      const loaded = loadPolicy(signConfigPath);
      policyDigest = loaded.digest || "none";
      signing = loaded.signing;
      if (signing?.key_path) {
        signing = { ...signing, key_path: (0, import_node_path16.resolve)(dir, signing.key_path) };
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Warning: could not load ${signConfigPath}: ${err instanceof Error ? err.message : err}
`);
    }
  }
  if (keyPath) signing = { enabled: true, key_path: (0, import_node_path16.resolve)(keyPath) };
  if (signing) {
    for (const w of await initSigning(signing)) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  try {
    (0, import_node_fs21.mkdirSync)(receiptsDir, { recursive: true });
  } catch {
  }
  const releaseLogLock = acquireReceiptLogLock(receiptsDir);
  try {
    let prevReceiptHash;
    try {
      const logPath = receiptLogPath;
      if ((0, import_node_fs21.existsSync)(logPath)) {
        const lines = (0, import_node_fs21.readFileSync)(logPath, "utf-8").trim().split("\n").filter(Boolean);
        const last = lines.length ? lines[lines.length - 1] : null;
        if (last) {
          const parsed = JSON.parse(last);
          if (parsed && parsed.signature) prevReceiptHash = chainLink(parsed);
        }
      }
    } catch {
    }
    let payloadDigest;
    if (toolInput) {
      const canonicalInput = canonicalize(toolInput);
      payloadDigest = { input_hash: (0, import_node_crypto16.createHash)("sha256").update(canonicalInput, "utf-8").digest("hex"), input_size: Buffer.byteLength(canonicalInput, "utf-8"), canonical: "jcs" };
    }
    let decisionValue = "allow";
    let reasonCode = "post_execution_receipt";
    if (cedarDir) {
      const policySet = loadCedarPolicies((0, import_node_path16.resolve)(cedarDir));
      let ctx = {};
      if (contextRaw) {
        try {
          ctx = JSON.parse(contextRaw);
        } catch {
          process.stderr.write("protect-mcp sign: --context is not valid JSON\n");
          process.exit(2);
        }
      }
      const verdict = await evaluateCedar(policySet, { tool, tier: "unknown", context: ctx, toolInput, actionModel }, void 0, { failClosed: true });
      decisionValue = verdict.allowed ? "allow" : "deny";
      reasonCode = verdict.allowed ? "cedar_allow" : verdict.reason || "cedar_deny";
      policyDigest = policySet.digest;
    }
    const requestId = `tu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const signed2 = signDecision({
      tool,
      decision: decisionValue,
      reason_code: reasonCode,
      policy_digest: policyDigest,
      request_id: requestId,
      mode: "enforce",
      timestamp: Date.now(),
      ...payloadDigest ? { payload_digest: payloadDigest } : {}
    }, prevReceiptHash);
    const line = signed2.signed ?? JSON.stringify({ tool, request_id: requestId, signed: false, note: signed2.warning || "no signer configured" });
    try {
      (0, import_node_fs21.appendFileSync)(receiptLogPath, line + "\n");
    } catch {
    }
    releaseLogLock();
    if (format === "hermes") {
      process.stdout.write("{}\n");
      process.exit(0);
    }
    process.stdout.write(JSON.stringify({ signed: Boolean(signed2.signed), decision: decisionValue, policy_digest: policyDigest, artifact_type: signed2.artifact_type, request_id: requestId, log: receiptLogPath }) + "\n");
    process.exit(0);
  } finally {
    releaseLogLock();
  }
}
function acquireReceiptLogLock(dir) {
  const lock = (0, import_node_path16.join)(dir, ".chain-lock");
  const started = Date.now();
  const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  for (; ; ) {
    try {
      (0, import_node_fs21.mkdirSync)(lock);
      break;
    } catch (err) {
      if (err.code !== "EEXIST") return () => {
      };
      try {
        if (Date.now() - (0, import_node_fs21.statSync)(lock).mtimeMs > 45e3) (0, import_node_fs21.rmSync)(lock, { recursive: true, force: true });
      } catch {
      }
      if (Date.now() - started > 55e3) {
        process.stderr.write("[PROTECT_MCP] Warning: could not take the receipt-log lock; this receipt is written without a chain link.\n");
        return () => {
        };
      }
      pause(15);
    }
  }
  return () => {
    try {
      (0, import_node_fs21.rmSync)(lock, { recursive: true, force: true });
    } catch {
    }
  };
}
async function handleSample(argv) {
  const dir = flagValue(argv, "--dir") || process.cwd();
  const { buildSampleKit: buildSampleKit2 } = await Promise.resolve().then(() => (init_sample(), sample_exports));
  let kit;
  try {
    kit = buildSampleKit2(dir, { force: argv.includes("--force") });
  } catch (err) {
    if (err?.code === "SAMPLE_EXISTS") {
      process.stderr.write(
        "\nprotect-mcp sample: this folder already has a record or signing key.\nThis command seeds a LABELED SAMPLE record and will not touch a real one.\nRun it in an empty folder, or pass --force to overwrite.\n\n"
      );
      process.exit(1);
    }
    throw err;
  }
  process.stdout.write(`
${bold2("\u{1F6E1} Sample record seeded")} \xB7 8 decisions (1 blocked, 2 payments), signed with a fresh key ${dim2(`(kid ${kit.kid})`)}

`);
  process.stdout.write("  .protect-mcp-receipts.jsonl   the signed sample record\n");
  process.stdout.write("  demo-tampered.jsonl           the same record with ONE decision edited after signing\n");
  process.stdout.write(`  keys/gateway.json             sample keypair ${dim2("(never commit)")}

`);
  process.stdout.write(`${bold2("Replay the demo")} ${dim2("(the film: legate.scopeblind.com/record)")}
`);
  process.stdout.write("  npx protect-mcp record\n");
  process.stdout.write("  npx protect-mcp claim --payment-under 100 --anchor --output payments-under-100.json\n");
  process.stdout.write("  npx protect-mcp verify-claim payments-under-100.json\n");
  process.stdout.write("  npx protect-mcp anchor-record\n\n");
  process.stdout.write(`${dim2("Drop demo-tampered.jsonl into the record page to watch tampering get caught.")}
`);
  process.stdout.write(`${dim2("Everything runs locally; --anchor publishes only a digest to the public log.")}

`);
  process.exit(0);
}
function mandateFlag(argv, name) {
  const index = argv.indexOf(name);
  return index >= 0 && argv[index + 1] && !argv[index + 1].startsWith("--") ? argv[index + 1] : void 0;
}
function mandateCedarDir(argv) {
  const explicit = mandateFlag(argv, "--cedar");
  if (explicit) return explicit;
  for (const candidate of ["cedar", "policies", "."]) {
    try {
      if ((0, import_node_fs21.existsSync)(candidate) && (0, import_node_fs21.readdirSync)(candidate).some((file) => file.endsWith(".cedar"))) return candidate;
    } catch {
    }
  }
  throw new Error("no Cedar policy directory found; pass --cedar <directory>");
}
function printMandateDiff(proposal) {
  process.stdout.write(`
${bold2("Policy proposal")} ${proposal.proposal_id}
`);
  process.stdout.write(`  ${dim2(`current ${proposal.base_policy_digest}`)}
`);
  process.stdout.write(`  ${dim2(`proposed ${proposal.proposed_policy_digest}`)}
`);
  process.stdout.write(`  ${dim2(`expires  ${proposal.expires_at}`)}

`);
  process.stdout.write(`${bold2("You are changing")}
`);
  for (const item of proposal.diff.plain_english) process.stdout.write(`  - ${item}
`);
  if (proposal.diff.added_statements.length) {
    process.stdout.write(`
${bold2("Added executable statements")}
`);
    for (const item of proposal.diff.added_statements) process.stdout.write(`  + ${item}
`);
  }
  if (proposal.diff.removed_statements.length) {
    process.stdout.write(`
${bold2("Removed executable statements")}
`);
    for (const item of proposal.diff.removed_statements) process.stdout.write(`  - ${item}
`);
  }
  process.stdout.write(`
${dim2("This proposal is not active until a distinct registered controller approves this exact proposal digest.")}
`);
}
async function handleMandate(argv) {
  const sub = argv[0] || "status";
  const cedarDir = mandateCedarDir(argv);
  const gateKeyPath = mandateFlag(argv, "--gate-key") || (0, import_node_path16.join)(process.cwd(), "keys", "gateway.json");
  if (sub === "init") {
    const controllerId = mandateFlag(argv, "--controller-id");
    const controllerLabel = mandateFlag(argv, "--controller-label") || "Mandate controller";
    const controllerPublicKey = mandateFlag(argv, "--controller-public-key");
    if (!controllerId || !controllerPublicKey) {
      throw new Error("usage: protect-mcp mandate init --cedar <dir> --controller-id <id> --controller-public-key <hex> [--controller-label <label>]");
    }
    const signer = loadGateSigner(gateKeyPath);
    const credentialId = mandateFlag(argv, "--credential-id");
    const controller = credentialId ? {
      id: controllerId,
      label: controllerLabel,
      type: "webauthn",
      credential_id: credentialId,
      credential_public_key: { alg: mandateFlag(argv, "--credential-alg") === "-7" ? -7 : -8, publicKeyHex: controllerPublicKey },
      sign_count: 0
    } : { id: controllerId, label: controllerLabel, type: "ed25519", public_key: controllerPublicKey };
    const registry2 = initializeMandateRegistry({ cedarDir, signer, controllers: [controller] });
    process.stdout.write(`${bold2("Managed mandate initialized")}
`);
    process.stdout.write(`  ${dim2(`registry ${registry2.registry_id}`)}
`);
    process.stdout.write(`  ${dim2(`active head ${registry2.active.policy_digest}`)}
`);
    process.stdout.write(`  ${dim2(`controller ${controller.label} (${controller.type})`)}
`);
    process.stdout.write(`
${bold2("Start the governed gate")}
  protect-mcp serve --enforce --cedar ${cedarDir}
`);
    process.stdout.write(`${dim2("Direct `policy allow|deny` writes are now refused for this directory. Use `mandate propose` and controller approval instead.")}
`);
    return;
  }
  const registry = loadMandateRegistry(cedarDir);
  if (!registry) throw new Error(`no managed mandate registry found for ${cedarDir}; run protect-mcp mandate init first`);
  if (sub === "status" || sub === "history") {
    const check = verifyMandateRegistry(registry);
    const output = publicMandateStatus(registry);
    if (argv.includes("--json")) {
      process.stdout.write(JSON.stringify({ valid: check.valid, ...check.valid ? {} : { code: check.code, message: check.message }, mandate: output }, null, 2) + "\n");
    } else {
      process.stdout.write(`
${bold2("Managed mandate")} ${registry.registry_id}
`);
      process.stdout.write(`  ${check.valid ? green2("verified") : red2(`invalid: ${check.code}`)}
`);
      process.stdout.write(`  ${dim2(`active head ${registry.active.policy_digest}`)}
`);
      process.stdout.write(`  ${dim2(`baseline    ${registry.active.baseline_policy_digest}`)}
`);
      process.stdout.write(`  ${dim2(`expires     ${registry.active.expires_at || "no temporary grant active"}`)}
`);
      process.stdout.write(`  ${dim2(`transitions ${registry.history.length}; proposals ${Object.keys(registry.proposals).length}`)}
`);
      if (sub === "history") {
        process.stdout.write("\n");
        for (const transition2 of registry.history) process.stdout.write(`  #${transition2.sequence} ${transition2.occurred_at}  ${transition2.event}  ${transition2.head_before || "none"} -> ${transition2.head_after}
`);
        process.stdout.write(`
${dim2(`append-only transition export: ${mandatePaths(cedarDir).auditLog}`)}
`);
      }
    }
    process.exit(check.valid ? 0 : 1);
  }
  if (sub === "propose") {
    const candidateDir = mandateFlag(argv, "--candidate");
    const denialPath = mandateFlag(argv, "--denial-receipt");
    const reason = mandateFlag(argv, "--reason");
    const expiresAt = mandateFlag(argv, "--expires-at");
    if (!candidateDir || !denialPath || !reason || !expiresAt) {
      throw new Error("usage: protect-mcp mandate propose --cedar <dir> --candidate <cedar-dir> --denial-receipt <receipt.json> --reason <plain-English reason> --expires-at <ISO-8601>");
    }
    const signer = loadGateSigner(gateKeyPath);
    const proposal = createPolicyProposal({
      cedarDir,
      signer,
      candidateDir,
      denialReceipt: JSON.parse((0, import_node_fs21.readFileSync)(denialPath, "utf-8")),
      reason,
      expiresAt
    });
    printMandateDiff(proposal);
    const passkeyController = registry.controllers.find((controller) => controller.type === "webauthn");
    if (passkeyController) {
      const approvalPort = mandateFlag(argv, "--approval-port") || "9377";
      if (!/^\d{2,5}$/.test(approvalPort) || Number(approvalPort) > 65535) throw new Error("--approval-port must be a valid local TCP port");
      process.stdout.write(`
${bold2("Desktop passkey approval")}
  http://localhost:${approvalPort}/mandate/proposals/${proposal.proposal_id}/approve?controller_id=${encodeURIComponent(passkeyController.id)}
`);
    }
    return;
  }
  if (sub === "approve") {
    const proposalId = argv[1];
    const controllerId = mandateFlag(argv, "--controller-id");
    const controllerKeyPath = mandateFlag(argv, "--controller-key");
    if (!proposalId || !controllerId || !controllerKeyPath) {
      throw new Error("usage: protect-mcp mandate approve <proposal-id> --controller-id <id> --controller-key <controller-key.json>");
    }
    const proposal = registry.proposals[proposalId];
    const controller = registry.controllers.find((item) => item.id === controllerId);
    if (!proposal || !controller || controller.type !== "ed25519") throw new Error("proposal or direct Ed25519 controller not found");
    const raw = JSON.parse((0, import_node_fs21.readFileSync)(controllerKeyPath, "utf-8"));
    if (!raw.privateKey) throw new Error("controller key file must contain privateKey");
    const signer = loadGateSigner(gateKeyPath);
    const approval = createDirectControllerApproval({ proposal, controller, privateKey: raw.privateKey });
    const updated = approvePolicyProposalWithDirectSignature({ cedarDir, signer, proposalId, approval });
    process.stdout.write(`${bold2("Approved and activated")} ${proposalId}
`);
    process.stdout.write(`  ${dim2(`active head ${updated.active.policy_digest}`)}
`);
    process.stdout.write(`  ${dim2(`automatic rollback ${updated.active.expires_at || "not scheduled"}`)}
`);
    process.stdout.write(`${dim2("This direct-key path is an offline recovery/test ceremony. Production controller approval should use the local WebAuthn URL printed by `mandate propose`.")}
`);
    return;
  }
  if (sub === "export") {
    const output = mandateFlag(argv, "--output");
    if (!output) throw new Error("usage: protect-mcp mandate export --output <discipline-policy-changes.json> [--cedar <dir>]");
    const summary = exportMandateDisciplineRecord(registry);
    const attachment = { type: "scopeblind.mandate-registry-attachment.v1", registry };
    const attachmentPath = output.replace(/\.json$/i, "") + ".registry.json";
    (0, import_node_fs21.writeFileSync)(output, JSON.stringify(summary, null, 2) + "\n");
    (0, import_node_fs21.writeFileSync)(attachmentPath, JSON.stringify(attachment, null, 2) + "\n");
    process.stdout.write(`${bold2("Discipline Record policy-change attachment exported")}
`);
    process.stdout.write(`  ${dim2(output)}                 position-blind summary
`);
    process.stdout.write(`  ${dim2(attachmentPath)}       full offline-verifiable registry; handle as audit evidence
`);
    return;
  }
  if (sub === "continuity") {
    const output = mandateFlag(argv, "--output") || (0, import_node_path16.join)(cedarDir, "mandate-continuity-checkpoint.json");
    const log = mandateFlag(argv, "--log");
    const shouldAnchor = argv.includes("--anchor") || argv.includes("--require-anchor");
    const summary = exportMandateDisciplineRecord(registry);
    const latest = summary.changes[summary.changes.length - 1];
    if (!latest) throw new Error("managed mandate has no transition to checkpoint");
    const { buildMandateContinuityCheckpoint: buildMandateContinuityCheckpoint2, anchorMandateContinuityCheckpoint: anchorMandateContinuityCheckpoint2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
    const signer = loadGateSigner(gateKeyPath);
    const checkpoint = buildMandateContinuityCheckpoint2({
      registry_id: summary.registry_id,
      registry_digest: summary.registry_digest,
      active_policy_digest: summary.active_policy_digest,
      transition_count: summary.changes.length,
      latest_transition_hash: latest.transition_receipt_hash
    }, signer, (/* @__PURE__ */ new Date()).toISOString());
    (0, import_node_fs21.writeFileSync)(output, JSON.stringify(checkpoint, null, 2) + "\n");
    process.stdout.write(`${bold2("Mandate continuity checkpoint written")}
`);
    process.stdout.write(`  ${dim2(output)}
`);
    process.stdout.write(`  ${dim2(`head ${summary.active_policy_digest}; transitions ${summary.changes.length}`)}
`);
    if (!shouldAnchor) {
      process.stdout.write(`${yellow2("Local checkpoint only")} ${dim2("Use --anchor to witness this commitment outside the local host.")}
`);
      return;
    }
    const anchored = await anchorMandateContinuityCheckpoint2(checkpoint, { ...log ? { log } : {} });
    if (!anchored.ok) {
      process.stdout.write(`${red2("External anchor failed")} ${dim2(anchored.error || "unknown error")}
`);
      if (argv.includes("--require-anchor")) process.exit(1);
      return;
    }
    const sidecar = output.replace(/\.json$/i, "") + ".anchor.json";
    (0, import_node_fs21.writeFileSync)(sidecar, JSON.stringify({ log: log || "https://scopeblind.com", seq: anchored.seq, entry_url: anchored.entry_url, anchored_at: anchored.anchored_at, checkpoint_digest: checkpoint.digest }, null, 2) + "\n");
    process.stdout.write(`${green2("Externally anchored")} ${dim2(`entry #${anchored.seq}; only commitments left this host`)}
`);
    process.stdout.write(`${dim2(`sidecar ${sidecar}`)}
`);
    return;
  }
  if (sub === "verify") {
    const check = verifyMandateRegistry(registry);
    let onDiskMatches = false;
    try {
      onDiskMatches = snapshotFromDirectory(cedarDir).policy_digest === registry.active.policy_digest;
    } catch {
    }
    const valid = check.valid && onDiskMatches;
    process.stdout.write(JSON.stringify({
      valid,
      ...check.valid ? {} : { code: check.code, message: check.message },
      active_policy_digest: registry.active.policy_digest,
      cedar_directory_matches_signed_head: onDiskMatches,
      transitions: registry.history.length
    }, null, 2) + "\n");
    process.exit(valid ? 0 : 1);
  }
  throw new Error("usage: protect-mcp mandate init|status|history|propose|approve|export|continuity|verify [--cedar <dir>]");
}
async function handlePolicy(argv) {
  const { readFileSync: rf, writeFileSync: wf, existsSync: ex, readdirSync: rd, appendFileSync: af } = await import("fs");
  const { join: pj } = await import("path");
  const { createHash: createHash10 } = await import("crypto");
  const sub = argv[0] || "list";
  const findDir = () => {
    for (const c2 of ["cedar", "policies", "."]) {
      try {
        if (ex(c2) && rd(c2).some((f) => f.endsWith(".cedar"))) return c2;
      } catch {
      }
    }
    return null;
  };
  const dir = findDir();
  const cedarFiles = dir ? rd(dir).filter((f) => f.endsWith(".cedar")).sort() : [];
  const readAll = () => cedarFiles.map((f) => rf(pj(dir, f), "utf-8")).join("\n\n");
  const digestOf = (_src) => {
    try {
      return shortPolicyLabel(digestCedarDir(dir));
    } catch {
      return "unavailable";
    }
  };
  const stripComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  const targetFile = cedarFiles.includes("agent.cedar") ? "agent.cedar" : cedarFiles[0];
  if (sub === "path") {
    if (!dir) {
      process.stdout.write("No Cedar policy directory found (looked in ./cedar, ./policies, .).\n");
      process.exit(0);
    }
    process.stdout.write(`${pj(dir, targetFile)}
`);
    process.exit(0);
  }
  if (sub === "show") {
    if (!dir) {
      process.stderr.write("No Cedar policy found. Run: npx protect-mcp init-hooks\n");
      process.exit(1);
    }
    const src = readAll();
    process.stdout.write(`${bold2("Cedar policy")} ${dim2(`(${cedarFiles.length} file${cedarFiles.length === 1 ? "" : "s"} in ${dir}, digest ${digestOf(src)})`)}

`);
    process.stdout.write(src.endsWith("\n") ? src : src + "\n");
    process.exit(0);
  }
  if (sub === "allow" || sub === "deny") {
    const tool = argv[1];
    if (!tool) {
      process.stderr.write(`Usage: npx protect-mcp policy ${sub} <ToolName>
`);
      process.exit(1);
    }
    if (!/^[A-Za-z0-9_.:-]+$/.test(tool)) {
      process.stderr.write(`Refusing: "${tool}" is not a valid tool name.
`);
      process.exit(1);
    }
    if (!dir) {
      process.stderr.write("No Cedar policy found. Run: npx protect-mcp init-hooks\n");
      process.exit(1);
    }
    if (ex(mandatePaths(dir).registry)) {
      process.stderr.write(
        "This Cedar directory is managed by a signed mandate lifecycle. Direct policy writes are refused.\nCreate a candidate policy, then run: protect-mcp mandate propose --candidate <dir> --denial-receipt <receipt.json> --reason <reason> --expires-at <ISO-8601>\n"
      );
      process.exit(1);
    }
    const effect = sub === "allow" ? "permit" : "forbid";
    const before = readAll();
    const beforeLabel = digestOf(before);
    const ruleRe = new RegExp(`${effect}\\s*\\([^)]*resource\\s*==\\s*Tool::"${tool.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}"`, "s");
    if (ruleRe.test(stripComments(before))) {
      process.stdout.write(`${dim2("No change:")} a ${effect} rule for ${bold2(tool)} already exists in ${targetFile}.
`);
      process.exit(0);
    }
    const block = `
// ${effect === "permit" ? "Allow" : "Block"} ${tool} (added by \`protect-mcp policy ${sub}\`)
${effect}(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"${tool}"
);
`;
    af(pj(dir, targetFile), block);
    const after = readAll();
    process.stdout.write(`${bold2(sub === "allow" ? "\u2713 Allowed" : "\u2713 Denied")} ${tool}
`);
    process.stdout.write(`  ${dim2(`appended to ${pj(dir, targetFile)}`)}
`);
    process.stdout.write(`  ${dim2(`policy digest ${beforeLabel} \u2192 ${digestOf(after)}`)}
`);
    process.stdout.write(`
${dim2("A running gate (protect-mcp serve) hot-reloads on this change; no restart needed. The one-shot hook path re-reads per call.")}
`);
    process.exit(0);
  }
  if (sub === "digest") {
    if (!dir) {
      process.stderr.write("No Cedar policy found. Run: npx protect-mcp init-hooks\n");
      process.exit(1);
    }
    const result2 = digestCedarDir(dir);
    const expectIdx = argv.indexOf("--expect");
    const expected = expectIdx >= 0 ? argv[expectIdx + 1] : null;
    if (argv.includes("--json")) {
      process.stdout.write(JSON.stringify({ ...result2, ...expected ? { expected, matches: expected === result2.policy_digest } : {} }, null, 2) + "\n");
    } else {
      process.stdout.write(`${bold2("policy_digest")}  ${result2.policy_digest}
`);
      process.stdout.write(`${dim2(`construction   ${result2.construction}`)}
`);
      process.stdout.write(`${dim2(`engine         ${result2.engine}   (${result2.files.length} file${result2.files.length === 1 ? "" : "s"} in ${dir})`)}
`);
      for (const f of result2.files) process.stdout.write(`${dim2(`  ${f.sha256.slice(0, 16)}\u2026  ${f.name}`)}
`);
      process.stdout.write(`${dim2('recompute: sha256 each file; M = {construction, engine, files:[{name, sha256}] sorted by name}; digest = "sha256:" + hex(SHA-256(JCS(M)))')}
`);
      if (expected) process.stdout.write(expected === result2.policy_digest ? `${bold2("\u2713 matches --expect")}
` : `${bold2("\u2717 does NOT match --expect")} ${dim2(expected)}
`);
    }
    process.exit(expected && expected !== result2.policy_digest ? 1 : 0);
  }
  if (sub === "publish") {
    if (!dir) {
      process.stderr.write("No Cedar policy found. Run: npx protect-mcp init-hooks\n");
      process.exit(1);
    }
    const outIdx = argv.indexOf("--out");
    const outDir = outIdx >= 0 && argv[outIdx + 1] ? argv[outIdx + 1] : pj(".well-known", "acta-policies");
    const files = cedarFiles.map((f) => ({ name: f, content: rf(pj(dir, f), "utf-8") }));
    const bundle = buildPolicyBundle("cedar", files);
    const check = verifyPolicyBundle(bundle);
    if (!check.valid) {
      process.stderr.write(`internal error: bundle failed self-verification (${check.error})
`);
      process.exit(1);
    }
    const { mkdirSync: mk } = await import("fs");
    mk(outDir, { recursive: true });
    const outPath = pj(outDir, `${bundle.policy_digest.replace(/^sha256:/, "")}.json`);
    wf(outPath, JSON.stringify(bundle, null, 2) + "\n");
    process.stdout.write(`${bold2("\u2713 published")} ${outPath}
`);
    process.stdout.write(`  ${dim2(`policy_digest ${bundle.policy_digest}`)}
`);
    process.stdout.write(`  ${dim2("self-verified: per-file hashes and manifest digest recompute from the bundle bytes alone")}
`);
    process.stdout.write(`  ${dim2("serve this directory at https://<your-domain>/.well-known/acta-policies/")}
`);
    process.exit(0);
  }
  if (sub === "list") {
    if (!dir) {
      process.stderr.write("No Cedar policy found. Run: npx protect-mcp init-hooks\n");
      process.exit(1);
    }
    const src = readAll();
    const active = stripComments(src);
    const named = (effect) => {
      const set = /* @__PURE__ */ new Set();
      const re = new RegExp(`${effect}\\s*\\([\\s\\S]*?resource\\s*==\\s*Tool::"([^"]+)"[\\s\\S]*?\\);`, "g");
      let m;
      while (m = re.exec(active)) set.add(m[1]);
      return set;
    };
    const permitted = named("permit"), forbidden = named("forbid");
    const seen = /* @__PURE__ */ new Map();
    try {
      const logPath = pj(process.cwd(), ".protect-mcp-log.jsonl");
      if (ex(logPath)) {
        for (const line of rf(logPath, "utf-8").split("\n")) {
          if (!line.trim()) continue;
          try {
            const e = JSON.parse(line);
            if (!e.tool) continue;
            const rec = seen.get(e.tool) || { allow: 0, deny: 0 };
            if (e.decision === "deny") rec.deny++;
            else rec.allow++;
            seen.set(e.tool, rec);
          } catch {
          }
        }
      }
    } catch {
    }
    process.stdout.write(`${bold2("Cedar policy")} ${dim2(`(${dir}, digest ${digestOf(src)}) \xB7 default-deny, fail-closed`)}

`);
    const allTools = /* @__PURE__ */ new Set([...permitted, ...forbidden, ...seen.keys()]);
    if (allTools.size === 0) {
      process.stdout.write(dim2("  No rules and no decisions logged yet.\n"));
      process.exit(0);
    }
    const rows = [...allTools].sort().map((t) => {
      const label = forbidden.has(t) ? "forbid" : permitted.has(t) ? "permit" : "default-deny";
      const colored = forbidden.has(t) ? red2(label) : permitted.has(t) ? green2(label) : yellow2(label);
      const pad = " ".repeat(Math.max(1, 13 - label.length));
      const s = seen.get(t);
      const hits = s ? dim2(`  ${s.allow} allowed, ${s.deny} denied`) : "";
      return `  ${colored}${pad}${bold2(t)}${hits}`;
    });
    process.stdout.write(rows.join("\n") + "\n");
    process.stdout.write(`
${dim2("Allow a tool: npx protect-mcp policy allow <ToolName>  \xB7  Block one: policy deny <ToolName>")}
`);
    process.exit(0);
  }
  process.stderr.write("Usage: npx protect-mcp policy <list|show|allow <tool>|deny <tool>|path>\n");
  process.exit(1);
}
async function handleEgressCheck(argv) {
  const { readFileSync: readFileSync19, existsSync: existsSync13, writeFileSync: writeFileSync11 } = await import("fs");
  const { join: join13 } = await import("path");
  const { inspectEgress: inspectEgress2, toEgressSummary: toEgressSummary2, runEgressSelfCheck: runEgressSelfCheck2 } = await Promise.resolve().then(() => (init_egress_guard(), egress_guard_exports));
  let dir = process.cwd();
  const di = argv.indexOf("--dir");
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  const oi = argv.indexOf("--out");
  const outPath = oi !== -1 && argv[oi + 1] ? argv[oi + 1] : void 0;
  const receiptsPath = join13(dir, ".protect-mcp-receipts.jsonl");
  const receipts = existsSync13(receiptsPath) ? readFileSync19(receiptsPath, "utf-8").trim().split("\n").filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return {};
    }
  }) : [];
  const pseudonymKey = Buffer.from("scopeblind-egress-health-check-v1", "utf8");
  const summaries = receipts.map((r, i) => ({ i, s: toEgressSummary2(r, { pseudonymKey }) }));
  const unsafe = summaries.filter((x) => !x.s || !inspectEgress2(x.s).safe);
  const report = runEgressSelfCheck2(receipts, (/* @__PURE__ */ new Date()).toISOString());
  if (outPath) writeFileSync11(outPath, JSON.stringify(report, null, 2) + "\n");
  process.stdout.write(`
${bold2("protect-mcp egress-check")}  ${dim2('(the "no raw data leaves the box" health check)')}

`);
  process.stdout.write(`  Local receipts checked : ${receipts.length}
`);
  process.stdout.write(`  Summaries egress-safe   : ${report.all_summaries_safe ? green2("yes") : red2("NO")} ${dim2("(only decision, tool name, digests, ids, public key leave)")}
`);
  process.stdout.write(`  Raw content dropped     : ${report.raw_content_dropped ? green2("yes") : red2("NO")} ${dim2("(a receipt carrying an email body / recipient / position summarises WITHOUT them)")}
`);
  process.stdout.write(`  Private keys dropped    : ${report.private_key_dropped ? green2("yes") : red2("NO")}
`);
  process.stdout.write(`  Deny receipts forwarded : ${report.deny_receipt_forwardable ? green2("yes") : red2("NO")} ${dim2("(a Cedar deny is not dropped by the guard)")}
`);
  if (unsafe.length) {
    process.stdout.write(`
  ${red2(unsafe.length + " local receipt(s) do not summarise to a safe shape")} (these would be DROPPED from the dashboard, not sent). The local copy stays authoritative.
`);
  }
  process.stdout.write(`
  ${dim2("Only a minimized summary leaves, and only when you opt into the hosted dashboard. The full signed receipt stays local. No prompts, tool bodies, recipients, positions, outputs, or private keys.")}
`);
  if (outPath) process.stdout.write(`  ${dim2("self-check written to " + outPath)}
`);
  process.stdout.write("\n");
  if (!report.raw_content_dropped || !report.private_key_dropped || !report.deny_receipt_forwardable || unsafe.length > 0) process.exitCode = 1;
}
async function main() {
  await sendInstallTelemetry();
  const args = process.argv.slice(2);
  process.env.PROTECT_MCP_VERSION = process.env.PROTECT_MCP_VERSION || await pkgVersion();
  const preSep = args.includes("--") ? args.slice(0, args.indexOf("--")) : args;
  if (args[0] === "version" || preSep.includes("--version") || preSep.includes("-V")) {
    process.stdout.write(`${process.env.PROTECT_MCP_VERSION || "unknown"}
`);
    process.exit(0);
  }
  if (args.length === 0 || args[0] === "help" || preSep.includes("--help") || preSep.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  if (args[0] === "evaluate") {
    await handleEvaluate(args.slice(1));
    return;
  }
  if (args[0] === "sign") {
    await handleSign(args.slice(1));
    return;
  }
  if (args[0] === "mcp") {
    await (await Promise.resolve().then(() => (init_mcp_server(), mcp_server_exports))).runMcpServer();
    return;
  }
  if (args[0] === "repository") {
    await (await Promise.resolve().then(() => (init_repository_setup(), repository_setup_exports))).runRepositoryCommand(args.slice(1));
    return;
  }
  if (args[0] === "coordination" && args[1] === "agent") {
    await (await Promise.resolve().then(() => (init_coordination_agent_server(), coordination_agent_server_exports))).runCoordinationAgent(args.slice(2));
    return;
  }
  if (args[0] === "coordination" && args[1] === "pair") {
    await (await Promise.resolve().then(() => (init_coordination_pair_cli(), coordination_pair_cli_exports))).runCoordinationPair(args.slice(2));
    return;
  }
  if (args[0] === "coordination" && args[1] === "setup") {
    (await Promise.resolve().then(() => (init_coordination_pair_cli(), coordination_pair_cli_exports))).runCoordinationSetup(args.slice(2));
    return;
  }
  if (args[0] === "coordination") {
    await (await Promise.resolve().then(() => (init_coordination_server(), coordination_server_exports))).runCoordinationServer(args.slice(1));
    return;
  }
  if (args[0] === "serve") {
    const { startHookServer: startHookServer2 } = await Promise.resolve().then(() => (init_hook_server(), hook_server_exports));
    const portIdx = args.indexOf("--port");
    const port = portIdx >= 0 && args[portIdx + 1] ? parseInt(args[portIdx + 1]) : 9377;
    const policyIdx = args.indexOf("--policy");
    const policyPath2 = policyIdx >= 0 && args[policyIdx + 1] ? args[policyIdx + 1] : void 0;
    const cedarIdx = args.indexOf("--cedar");
    const cedarDir2 = cedarIdx >= 0 && args[cedarIdx + 1] ? args[cedarIdx + 1] : void 0;
    const enforce2 = args.includes("--enforce");
    const verbose2 = args.includes("--verbose") || args.includes("-v");
    const standardPath2 = flagValue(args, "--standard") || void 0;
    const reportUrl2 = flagValue(args, "--report") || void 0;
    const reportToken2 = flagValue(args, "--report-token") || void 0;
    const runId2 = flagValue(args, "--run") || void 0;
    if (enforce2) {
      const selfTest = await runEvaluatorSelfTest();
      if (!selfTest.passed) {
        process.stderr.write("protect-mcp serve --enforce: the policy-engine restraint self-test FAILED. Refusing to arm the gate.\n");
        for (const c2 of selfTest.cases.filter((c3) => !c3.pass)) {
          process.stderr.write(`  [FAIL] ${c2.name}: expected ${c2.expected}, got ${c2.actual}
`);
        }
        process.exit(1);
      }
      if (verbose2) process.stderr.write(`protect-mcp: restraint self-test passed (${selfTest.cases.length} vectors). Arming gate.
`);
    }
    try {
      await startHookServer2({ port, policyPath: policyPath2, cedarDir: cedarDir2, enforce: enforce2, verbose: verbose2, standardPath: standardPath2, reportUrl: reportUrl2, reportToken: reportToken2, runId: runId2 });
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
    return;
  }
  if (args[0] === "record") {
    await handleRecord(args.slice(1));
    return;
  }
  if (args[0] === "claim") {
    await handleClaim(args.slice(1));
    return;
  }
  if (args[0] === "verify-claim") {
    await handleVerifyClaim(args.slice(1));
    return;
  }
  if (args[0] === "anchor-record") {
    await handleAnchorRecord(args.slice(1));
    return;
  }
  if (args[0] === "sample") {
    await handleSample(args.slice(1));
    return;
  }
  if (args[0] === "mandate") {
    await handleMandate(args.slice(1));
    return;
  }
  if (args[0] === "policy") {
    await handlePolicy(args.slice(1));
    return;
  }
  if (args[0] === "init-hooks") {
    await handleInitHooks(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "quickstart") {
    await handleQuickstart(args.slice(1));
    return;
  }
  if (args[0] === "onboard") {
    const { handleOnboard: handleOnboard2 } = await Promise.resolve().then(() => (init_onboard(), onboard_exports));
    await handleOnboard2(args.slice(1));
    return;
  }
  if (args[0] === "offboard") {
    const { handleOffboard: handleOffboard2 } = await Promise.resolve().then(() => (init_onboard(), onboard_exports));
    await handleOffboard2(args.slice(1));
    return;
  }
  if (args[0] === "wrap") {
    await handleWrap(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "dashboard") {
    await handleDashboard(args.slice(1));
    return;
  }
  if (args[0] === "recommend") {
    await handleRecommend(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "registry") {
    await handleRegistry(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "trial") {
    await handleKillerDemo(args.slice(1));
    process.stdout.write(`${bold2("Next: open the local dashboard")}
`);
    process.stdout.write(`  npx protect-mcp dashboard --dir ${dim2(flagValue(args.slice(1), "--dir") || "<demo dir printed above>")} --open

`);
    process.stdout.write(`${dim2("No ScopeBlind account is required for local receipts. Add --hosted with SCOPEBLIND_TOKEN when you want independent digest anchoring.")}

`);
    process.exit(0);
  }
  if (args[0] === "killer-demo") {
    await handleKillerDemo(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "verify-disclosure") {
    await handleVerifyDisclosure(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "policy-packs") {
    await handlePolicyPacks(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "connectors") {
    await handleConnectors(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "connect") {
    await handleConnect();
    process.exit(0);
  }
  if (args[0] === "init") {
    await handleInit(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "demo") {
    await handleDemo();
    return;
  }
  if (args[0] === "coverage") {
    const { handleCoverage: handleCoverage2 } = await Promise.resolve().then(() => (init_coverage(), coverage_exports));
    await handleCoverage2(args.slice(1));
    process.exit(process.exitCode || 0);
  }
  if (args[0] === "egress-check") {
    await handleEgressCheck(args.slice(1));
    process.exit(process.exitCode || 0);
  }
  if (args[0] === "status") {
    await handleStatus2(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "digest") {
    await handleDigest(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "receipts") {
    await handleReceipts2(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "bundle") {
    await handleBundle(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "trace") {
    await handleTrace(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "simulate") {
    await handleSimulate(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "report") {
    await handleReport(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "doctor") {
    await handleDoctor();
    process.exit(0);
  }
  const { policyPath, cedarDir, slug, enforce, verbose, childCommand, standardPath, reportUrl, reportToken, runId } = parseArgs(args);
  let policy = null;
  let policyDigest = "none";
  let credentials;
  let signing;
  let cedarPolicySet = null;
  let effectiveCedarDir = cedarDir;
  if (!effectiveCedarDir && !policyPath) {
    const { existsSync: existsSync13, readdirSync: readdirSync7 } = await import("fs");
    for (const candidate of ["cedar", "policies", "."]) {
      try {
        if (existsSync13(candidate) && readdirSync7(candidate).some((f) => f.endsWith(".cedar"))) {
          effectiveCedarDir = candidate;
          process.stderr.write(`[PROTECT_MCP] Auto-detected Cedar policies in ./${candidate}/
`);
          break;
        }
      } catch {
      }
    }
  }
  if (effectiveCedarDir) {
    try {
      const cedarAvailable = await isCedarAvailable();
      if (!cedarAvailable) {
        process.stderr.write("[PROTECT_MCP] Warning: @cedar-policy/cedar-wasm not installed. Install with: npm install @cedar-policy/cedar-wasm\n");
        process.stderr.write("[PROTECT_MCP] Cedar policies will be loaded but evaluated with fallback (allow-all).\n");
      }
      cedarPolicySet = loadCedarPolicies(effectiveCedarDir);
      policyDigest = cedarPolicySet.digest;
      policy = {
        tools: { "*": { require: "any" } },
        policy_engine: "cedar",
        cedar_dir: effectiveCedarDir
      };
      process.stderr.write(`[PROTECT_MCP] Cedar policy engine: loaded ${cedarPolicySet.fileCount} policies from ${effectiveCedarDir} (digest: ${policyDigest})
`);
      if (verbose) {
        process.stderr.write(`[PROTECT_MCP] Cedar files: ${cedarPolicySet.files.join(", ")}
`);
      }
      const { existsSync: cfgExists } = await import("fs");
      if (cfgExists("protect-mcp.json")) {
        try {
          const cfg = loadPolicy("protect-mcp.json");
          signing = cfg.signing;
          credentials = cfg.credentials;
          if (signing) process.stderr.write("[PROTECT_MCP] Signing config loaded from protect-mcp.json (receipts enabled)\n");
        } catch (err) {
          process.stderr.write(`[PROTECT_MCP] Warning: could not read signing config from protect-mcp.json: ${err instanceof Error ? err.message : err}
`);
        }
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading Cedar policies: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
  } else if (policyPath) {
    try {
      const loaded = loadPolicy(policyPath);
      policy = loaded.policy;
      policyDigest = loaded.digest;
      credentials = loaded.credentials;
      signing = loaded.signing;
      if (verbose) {
        process.stderr.write(`[PROTECT_MCP] Loaded policy from ${policyPath} (digest: ${policyDigest})
`);
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading policy: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
  }
  if (signing) {
    const warnings = await initSigning(signing);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  if (credentials) {
    const warnings = validateCredentials(credentials);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  let standard;
  let reporter;
  if (standardPath) {
    try {
      standard = loadStandardFile(standardPath);
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading the standard ${standardPath}: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
  }
  if (reportUrl) {
    if (!standard) {
      process.stderr.write("[PROTECT_MCP] Error: --report needs --standard <standard.json>; the page belongs to a signed standard\n");
      process.exit(1);
    }
    const token = reportToken || process.env.PROTECT_MCP_REPORT_TOKEN || "";
    if (!token) {
      process.stderr.write("[PROTECT_MCP] Error: --report needs the page's write token: --report-token <token> or PROTECT_MCP_REPORT_TOKEN\n");
      process.exit(1);
    }
    try {
      reporter = new RecordReporter({ url: reportUrl, token, runId: runId || `run-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace(/[-:T]/g, "")}` });
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
  }
  const config = {
    command: childCommand[0],
    args: childCommand.slice(1),
    policy,
    policyDigest,
    slug,
    enforce,
    verbose,
    signing,
    credentials,
    standard,
    reporter
  };
  const useHttp = args.includes("--http");
  if (useHttp) {
    const portIdx = args.indexOf("--port");
    const httpPort = portIdx >= 0 && args[portIdx + 1] ? parseInt(args[portIdx + 1]) : 3e3;
    const { startHttpTransport: startHttpTransport2 } = await Promise.resolve().then(() => (init_http_transport(), http_transport_exports));
    startHttpTransport2({ port: httpPort, config, serverCommand: childCommand, cedarPolicySet: cedarPolicySet ?? void 0 });
    return;
  }
  const gateway = new ProtectGateway(config);
  if (cedarPolicySet) {
    gateway.setCedarPolicies(cedarPolicySet);
  }
  await gateway.start();
}
async function handleSimulate(args) {
  let policyPath = "";
  let logPath = ".protect-mcp-log.jsonl";
  let tier = "unknown";
  let jsonOutput = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--policy" && args[i + 1]) {
      policyPath = args[++i];
    } else if (args[i] === "--log" && args[i + 1]) {
      logPath = args[++i];
    } else if (args[i] === "--tier" && args[i + 1]) {
      tier = args[++i];
    } else if (args[i] === "--json") {
      jsonOutput = true;
    }
  }
  if (!policyPath) {
    process.stderr.write("Usage: protect-mcp simulate --policy <path> [--log <path>] [--tier <tier>] [--json]\n");
    process.exit(1);
  }
  const { existsSync: existsSync13 } = await import("fs");
  if (!existsSync13(logPath)) {
    process.stderr.write(`Log file not found: ${logPath}
`);
    process.stderr.write("Run protect-mcp in shadow mode first to generate a log file.\n");
    process.exit(1);
  }
  const { policy } = loadPolicy(policyPath);
  const entries = parseLogFile(logPath);
  if (entries.length === 0) {
    process.stderr.write("No tool call entries found in log file.\n");
    process.exit(1);
  }
  const summary = simulate(entries, policy, tier);
  summary.policy_file = policyPath;
  summary.log_file = logPath;
  if (jsonOutput) {
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  } else {
    process.stdout.write(formatSimulation(summary) + "\n");
  }
}
async function handleDoctor() {
  const { existsSync: existsSync13, readFileSync: readFileSync19, readdirSync: readdirSync7 } = await import("fs");
  const { join: join13 } = await import("path");
  const { execSync } = await import("child_process");
  const green3 = (s) => `\x1B[32m\u2713\x1B[0m ${s}`;
  const red3 = (s) => `\x1B[31m\u2717\x1B[0m ${s}`;
  const yellow3 = (s) => `\x1B[33m\u26A0\x1B[0m ${s}`;
  const dim3 = (s) => `\x1B[2m${s}\x1B[0m`;
  process.stdout.write("\n\x1B[1mprotect-mcp doctor\x1B[0m\n");
  process.stdout.write(dim3("Checking your ScopeBlind setup...\n\n"));
  let issues = 0;
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1));
  if (major >= 18) {
    process.stdout.write(green3(`Node.js ${nodeVersion}
`));
  } else {
    process.stdout.write(red3(`Node.js ${nodeVersion}, requires >= 18
`));
    issues++;
  }
  const configPath = join13(process.cwd(), "scopeblind.config.json");
  if (existsSync13(configPath)) {
    try {
      const config = JSON.parse(readFileSync19(configPath, "utf-8"));
      if (config.signing?.private_key || config.signing?.key_file) {
        process.stdout.write(green3("Signing keys configured\n"));
      } else {
        process.stdout.write(yellow3("Config found but no signing keys. Run: protect-mcp init\n"));
        issues++;
      }
    } catch {
      process.stdout.write(red3("Invalid scopeblind.config.json\n"));
      issues++;
    }
  } else {
    process.stdout.write(yellow3("No scopeblind.config.json. Run: protect-mcp init\n"));
  }
  let policyFound = false;
  for (const dir of ["cedar", "policies", "."]) {
    try {
      if (existsSync13(dir) && readdirSync7(dir).some((f) => f.endsWith(".cedar"))) {
        process.stdout.write(green3(`Cedar policies found in ./${dir}/
`));
        policyFound = true;
        break;
      }
    } catch {
    }
  }
  if (!policyFound) {
    for (const name of ["policy.json", "protect-mcp.policy.json", "scopeblind-policy.json"]) {
      if (existsSync13(name)) {
        process.stdout.write(green3(`JSON policy found: ${name}
`));
        policyFound = true;
        break;
      }
    }
  }
  if (!policyFound) {
    process.stdout.write(yellow3("No policy files found, running in shadow mode (allow all)\n"));
  }
  try {
    const cedarAvailable = await isCedarAvailable();
    if (cedarAvailable) {
      process.stdout.write(green3("Cedar WASM engine available\n"));
    } else {
      process.stdout.write(dim3("  Cedar WASM not installed. Install: npm install @cedar-policy/cedar-wasm\n"));
    }
  } catch {
    process.stdout.write(dim3("  Cedar WASM not installed\n"));
  }
  const logFile = join13(process.cwd(), "protect-mcp-decisions.jsonl");
  const receiptFile = join13(process.cwd(), "protect-mcp-receipts.jsonl");
  if (existsSync13(logFile)) {
    try {
      const lines = readFileSync19(logFile, "utf-8").trim().split("\n").length;
      process.stdout.write(green3(`Decision log: ${lines} entries
`));
    } catch {
      process.stdout.write(green3("Decision log exists\n"));
    }
  } else {
    process.stdout.write(dim3("  No decision log yet, will be created on first tool call\n"));
  }
  if (existsSync13(receiptFile)) {
    try {
      const lines = readFileSync19(receiptFile, "utf-8").trim().split("\n").length;
      process.stdout.write(green3(`Receipt file: ${lines} signed receipts
`));
    } catch {
      process.stdout.write(green3("Receipt file exists\n"));
    }
  }
  try {
    execSync("npx @veritasacta/verify --version 2>/dev/null", { stdio: "pipe", timeout: 1e4 });
    process.stdout.write(green3("Verifier available: @veritasacta/verify\n"));
  } catch {
    process.stdout.write(dim3("  Verifier not cached. Install: npm install -g @veritasacta/verify\n"));
  }
  try {
    const res = await fetch("https://api.scopeblind.com/health", { signal: AbortSignal.timeout(5e3) });
    if (res.ok) {
      process.stdout.write(green3("ScopeBlind API reachable\n"));
    } else {
      process.stdout.write(yellow3("ScopeBlind API returned non-200, receipts will be stored locally\n"));
    }
  } catch {
    process.stdout.write(dim3("  ScopeBlind API not reachable, offline mode (receipts stored locally)\n"));
  }
  process.stdout.write("\nRestraint self-test:\n");
  try {
    const st = await runEvaluatorSelfTest();
    if (!st.wasmAvailable) {
      process.stdout.write(dim3("  Cedar WASM not installed; the gate fails closed (denies) until it is.\n"));
    }
    for (const c2 of st.cases) {
      process.stdout.write(c2.pass ? green3(`  ${c2.name}
`) : `\x1B[31m  FAIL: ${c2.name} (expected ${c2.expected}, got ${c2.actual})
\x1B[0m`);
    }
    if (!st.passed) issues++;
    else process.stdout.write(green3("  the gate denies what it should and allows what it should\n"));
  } catch (err) {
    process.stdout.write(yellow3(`  self-test could not run: ${err instanceof Error ? err.message : "unknown"}
`));
    issues++;
  }
  process.stdout.write("\n");
  if (issues === 0) {
    process.stdout.write("\x1B[32m\x1B[1mAll checks passed.\x1B[0m Ready to wrap MCP servers.\n");
    process.stdout.write(dim3("\n  npx protect-mcp -- node your-server.js\n\n"));
  } else {
    process.stdout.write(`\x1B[33m\x1B[1m${issues} issue(s) found.\x1B[0m Fix them and run doctor again.

`);
  }
}
async function handleReport(args) {
  let period = 30;
  let format = "json";
  let outputPath = "";
  let dir = process.cwd();
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--period" && args[i + 1]) {
      const match = args[++i].match(/^(\d+)d$/);
      if (match) period = parseInt(match[1], 10);
    } else if (args[i] === "--format" && args[i + 1]) {
      format = args[++i];
    } else if (args[i] === "--output" && args[i + 1]) {
      outputPath = args[++i];
    } else if (args[i] === "--dir" && args[i + 1]) {
      dir = args[++i];
    }
  }
  const { generateReport: generateReport2, formatReportMarkdown: formatReportMarkdown2 } = await Promise.resolve().then(() => (init_report(), report_exports));
  const { join: join13 } = await import("path");
  const logPath = join13(dir, ".protect-mcp-log.jsonl");
  const receiptPath = join13(dir, ".protect-mcp-receipts.jsonl");
  const report = generateReport2(logPath, receiptPath, period);
  let output;
  if (format === "md") {
    output = formatReportMarkdown2(report);
  } else {
    output = JSON.stringify(report, null, 2);
  }
  if (outputPath) {
    const { writeFileSync: writeFileSync11 } = await import("fs");
    writeFileSync11(outputPath, output, "utf-8");
    process.stderr.write(`Report written to ${outputPath}
`);
  } else {
    process.stdout.write(output + "\n");
  }
}
main().catch((err) => {
  process.stderr.write(`[PROTECT_MCP] Fatal error: ${err instanceof Error ? err.message : err}
`);
  process.exit(1);
});
/**
 * scopeblind-bridge.ts
 *
 * Optional bridge between protect-mcp (local, MIT) and a paid ScopeBlind
 * tenant. When SCOPEBLIND_TOKEN is set in the environment, every signed
 * receipt that protect-mcp emits also gets forwarded to the tenant's
 * dashboard at https://scopeblind.com/console/<slug>.
 *
 * Lifecycle:
 *   1. On first use, exchange SCOPEBLIND_TOKEN for a short-lived BRASS-v2
 *      auth proof from /fn/brass/issue. Cache the proof in memory until
 *      ~5 minutes before expiry, then refresh.
 *   2. As receipts are emitted by hook-server.ts, push them into an
 *      in-memory batch queue.
 *   3. After the tenant is known, reduce each local receipt to a pseudonymous
 *      egress summary using a tenant-scoped, local-only HMAC key; sign that
 *      separate summary envelope locally, and POST it to /summaries. The raw
 *      signed receipt endpoint is intentionally not used by this bridge.
 *
 * Failure mode: forward errors NEVER throw upstream. protect-mcp continues
 * to mint and persist receipts locally regardless of dashboard availability.
 * The bridge logs failures to stderr (best-effort) and retries on the next
 * flush.
 *
 * Configuration:
 *   SCOPEBLIND_TOKEN        Tenant bearer token (from welcome email).
 *   SCOPEBLIND_TENANT       Optional slug override. By default we discover
 *                           the slug from the BRASS proof's tenant_id.
 *   SCOPEBLIND_BASE         Defaults to https://scopeblind.com.
 *   SCOPEBLIND_EGRESS_HMAC_KEY
 *                           Optional base64url 32-byte local-only HMAC key.
 *                           If omitted, protect-mcp creates a per-tenant key
 *                           in ~/.protect-mcp/egress-keys (mode 0600).
 *   SCOPEBLIND_EGRESS_KEY_DIR
 *                           Optional local directory for generated HMAC keys.
 *
 * @license MIT
 */
