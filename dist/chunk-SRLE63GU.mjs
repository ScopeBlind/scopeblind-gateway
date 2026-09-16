import {
  canonical
} from "./chunk-O3K3FPBT.mjs";

// src/acta-envelope.ts
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
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
function verifyEncoding(payload, envelope, signature, publicKeyHex, shape, allowLegacy) {
  const jcs = canonicalize(payload);
  if (ed25519.verify(hexToBytes(signature), utf8ToBytes(jcs), hexToBytes(publicKeyHex))) {
    return { valid: true, shape, hash: receiptHash(envelope), canonicalization: "jcs" };
  }
  if (!hasLegacyUnsafeKey(envelope)) {
    const legacy = legacyCanonicalize(payload);
    if (legacy !== jcs && ed25519.verify(hexToBytes(signature), utf8ToBytes(legacy), hexToBytes(publicKeyHex))) {
      const legacyHash = bytesToHex(sha256(utf8ToBytes(legacyCanonicalize(envelope))));
      return {
        valid: allowLegacy,
        shape,
        canonicalization: "legacy-numeric-key-order",
        legacy_signature_valid: true,
        legacy_hash: legacyHash,
        ...allowLegacy ? { hash: legacyHash } : { error: "legacy_non_jcs_signature" },
        warning: "Historical signature verifies only with pre-fix integer-key ordering. This is not JCS-conformant; preserve its original bytes and chain hashes."
      };
    }
  }
  return { valid: false, shape, error: "invalid_signature" };
}
function receiptHash(obj) {
  return bytesToHex(sha256(utf8ToBytes(canonicalize(obj))));
}
function chainLink(receipt) {
  return "sha256:" + receiptHash(receipt);
}
var B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let n = BigInt("0x" + bytesToHex(bytes));
  let out = "";
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}
function computeSbIssuerKid(publicKeyHex) {
  return `sb:issuer:${base58(hexToBytes(publicKeyHex)).slice(0, 12)}`;
}
function createReceiptEnvelope(fields, privateKeyHex, kid, issuedAt) {
  if (!fields.type) throw new Error("receipt payload requires a type");
  if (!kid) throw new Error("kid is required");
  const payload = {
    ...fields,
    issued_at: fields.issued_at || issuedAt || (/* @__PURE__ */ new Date()).toISOString(),
    issuer_id: kid
  };
  const sig = bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), hexToBytes(privateKeyHex)));
  const envelope = { payload, signature: { alg: "EdDSA", kid, sig } };
  return { envelope, hash: receiptHash(envelope) };
}
function verifyReceipt(envelope, publicKeyHex, options = {}) {
  try {
    if (!envelope || typeof envelope !== "object") {
      return { valid: false, shape: null, error: "not_an_object" };
    }
    const env = envelope;
    const signature = env.signature;
    if (signature && typeof signature === "object" && !Array.isArray(signature)) {
      const sigObj = signature;
      if (sigObj.alg !== "EdDSA") {
        return { valid: false, shape: "acta-02", error: `unsupported_alg:${String(sigObj.alg)}` };
      }
      if (typeof sigObj.sig !== "string" || !env.payload || typeof env.payload !== "object") {
        return { valid: false, shape: "acta-02", error: "malformed_envelope" };
      }
      return verifyEncoding(env.payload, env, sigObj.sig, publicKeyHex, "acta-02", options.allowLegacyNumericKeys === true);
    }
    if (typeof signature === "string") {
      const rest = /* @__PURE__ */ Object.create(null);
      for (const k of Object.keys(env)) if (k !== "signature") rest[k] = env[k];
      const shape = env.v === 2 ? "legacy-v2" : "legacy-v1";
      return verifyEncoding(rest, env, signature, publicKeyHex, shape, options.allowLegacyNumericKeys === true);
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
function receiptIdentity(envelope) {
  if (!envelope || typeof envelope !== "object") return { kid: null, issuer: null, type: null };
  const env = envelope;
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

export {
  canonicalize,
  receiptHash,
  chainLink,
  computeSbIssuerKid,
  createReceiptEnvelope,
  verifyReceipt,
  receiptIdentity
};
