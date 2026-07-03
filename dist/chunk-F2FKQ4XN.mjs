import {
  ed25519,
  sha256
} from "./chunk-LYKNULYU.mjs";
import {
  bytesToHex,
  hexToBytes,
  randomBytes
} from "./chunk-D733KAPG.mjs";

// node_modules/@noble/hashes/esm/sha256.js
var sha2562 = sha256;

// src/commitments/merkle.ts
var DOMAIN_LEAF = 0;
var DOMAIN_INTERNAL = 1;
function hashLeaf(leafBytes) {
  const buf = new Uint8Array(leafBytes.length + 1);
  buf[0] = DOMAIN_LEAF;
  buf.set(leafBytes, 1);
  return sha2562(buf);
}
function hashInternal(left, right) {
  const buf = new Uint8Array(left.length + right.length + 1);
  buf[0] = DOMAIN_INTERNAL;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha2562(buf);
}
function merkleRoot(leafHashes) {
  if (leafHashes.length === 0) {
    throw new Error("merkleRoot: cannot compute root of empty leaf set");
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }
  const n = leafHashes.length;
  const k = largestPowerOfTwoLessThan(n);
  const left = merkleRoot(leafHashes.slice(0, k));
  const right = merkleRoot(leafHashes.slice(k));
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
    siblings: siblings.map((s) => bytesToHex(s))
  };
}
function collectPath(leaves, index, out) {
  if (leaves.length === 1) return;
  const n = leaves.length;
  const k = largestPowerOfTwoLessThan(n);
  if (index < k) {
    collectPath(leaves.slice(0, k), index, out);
    out.push(merkleRoot(leaves.slice(k)));
  } else {
    collectPath(leaves.slice(k), index - k, out);
    out.push(merkleRoot(leaves.slice(0, k)));
  }
}
function verifyProof(expectedRootHex, leafHash, proof) {
  if (proof.index < 0 || proof.index >= proof.treeSize) return false;
  if (proof.treeSize === 1) {
    return proof.siblings.length === 0 && bytesToHex(leafHash).toLowerCase() === expectedRootHex.toLowerCase();
  }
  let result;
  try {
    result = reconstructRoot(
      leafHash,
      proof.index,
      proof.treeSize,
      proof.siblings
    );
  } catch {
    return false;
  }
  return bytesToHex(result).toLowerCase() === expectedRootHex.toLowerCase();
}
function reconstructRoot(leafHash, index, treeSize, siblings) {
  if (treeSize === 1) {
    if (siblings.length !== 0) {
      throw new Error("reconstructRoot: extra siblings at single-leaf level");
    }
    return leafHash;
  }
  if (siblings.length === 0) {
    throw new Error("reconstructRoot: ran out of siblings before single-leaf");
  }
  const k = largestPowerOfTwoLessThan(treeSize);
  const outermostSibling = hexToBytes(siblings[siblings.length - 1]);
  const innerSiblings = siblings.slice(0, -1);
  if (index < k) {
    const leftHash = reconstructRoot(leafHash, index, k, innerSiblings);
    return hashInternal(leftHash, outermostSibling);
  } else {
    const rightHash = reconstructRoot(
      leafHash,
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

// src/commitments/primitives.ts
function jcs(value) {
  if (value === null || value === void 0) return "null";
  if (typeof value === "boolean" || typeof value === "number")
    return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(jcs).join(",") + "]";
  const obj = value;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(obj[k])).join(",") + "}";
}

// src/commitments/leaf.ts
function base64urlNoPad(bytes) {
  const std = typeof Buffer !== "undefined" ? Buffer.from(bytes).toString("base64") : btoa(String.fromCharCode(...bytes));
  return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(s) {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - std.length % 4) % 4);
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function encodeLeaf(field) {
  const obj = {
    name: field.name,
    salt: base64urlNoPad(field.salt),
    value: field.value
  };
  const canonical = jcs(obj);
  return new TextEncoder().encode(canonical);
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

// src/signing-committed.ts
function freshSalt() {
  return randomBytes(32);
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
    const root = merkleRoot(leafHashes);
    committedFieldsRoot = bytesToHex(root);
    sorted.forEach((f, i) => {
      openings[f.name] = { name: f.name, value: f.value, salt: f.salt, index: i };
    });
  }
  const payload = {
    type: "scopeblind.receipt.committed.v1",
    spec: "draft-farley-acta-signed-receipts-01",
    issuer_certification: "self-signed",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    ...cleartextFields
  };
  if (committedFieldsRoot !== null) {
    payload.committed_fields_root = committedFieldsRoot;
    payload.committed_field_names = committedFields.map((f) => f.name);
  }
  const canonical = jcs(payload);
  const messageHash = sha2562(new TextEncoder().encode(canonical));
  const signatureBytes = ed25519.sign(messageHash, hexToBytes(signingKey));
  const signedReceipt = {
    ...payload,
    signature: {
      alg: "EdDSA",
      kid,
      issuer,
      sig: base64urlNoPad(signatureBytes),
      public_key: publicKey
      // hex
    }
  };
  const signedJson = JSON.stringify(signedReceipt);
  const receiptHash = bytesToHex(sha2562(new TextEncoder().encode(jcs(signedReceipt))));
  return {
    signed: signedJson,
    artifact_type: "decision_receipt_committed_v1",
    openings,
    receipt_hash: receiptHash
  };
}
function discloseField(receiptHash, fieldName, openings) {
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
    parent_receipt_hash: receiptHash,
    name: fieldName,
    value: o.value,
    salt: base64urlNoPad(o.salt),
    proof
  };
}
function createSelectiveDisclosurePackage(receipt, fieldNames, openings) {
  const receiptHash = receiptHashHex(receipt);
  const committedFieldsRoot = typeof receipt.committed_fields_root === "string" ? receipt.committed_fields_root : "";
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
  const disclosures = uniqueFields.map((fieldName) => discloseField(receiptHash, fieldName, openings));
  const hiddenFields = committedFieldNames.filter((fieldName) => !uniqueFields.includes(fieldName));
  return {
    type: "scopeblind.selective_disclosure.v0",
    version: 0,
    parent_receipt_hash: receiptHash,
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
function verifySelectiveDisclosurePackage(receipt, disclosure) {
  const errors = [];
  if (disclosure.type !== "scopeblind.selective_disclosure.v0") {
    errors.push("disclosure.type is not scopeblind.selective_disclosure.v0");
  }
  const actualReceiptHash = receiptHashHex(receipt);
  const receiptHashValid = disclosure.parent_receipt_hash === actualReceiptHash;
  if (!receiptHashValid) {
    errors.push("parent_receipt_hash does not match the supplied receipt");
  }
  const root = typeof receipt.committed_fields_root === "string" ? receipt.committed_fields_root : "";
  const commitmentRootValid = Boolean(root) && disclosure.committed_fields_root === root;
  if (!commitmentRootValid) {
    errors.push("committed_fields_root does not match the supplied receipt");
  }
  const signatureValid = verifyCommittedReceiptSignature(receipt);
  if (signatureValid === false) {
    errors.push("receipt signature failed verification");
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
      salt: base64urlDecode(item.salt),
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
  const valid = errors.length === 0 && receiptHashValid && commitmentRootValid && signatureValid !== false;
  const explanation = [
    valid ? "Selective disclosure verified: the disclosed fields open to the signed receipt commitment root." : "Selective disclosure failed verification.",
    signatureValid === true ? "Receipt signature verified against the embedded Ed25519 public key." : signatureValid === null ? "Receipt signature was not checked because the committed receipt did not carry an embedded Ed25519 signature object." : "Receipt signature did not verify.",
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
  const fromReceipt = Array.isArray(receipt.committed_field_names) ? receipt.committed_field_names.filter((fieldName) => typeof fieldName === "string") : [];
  const names = fromReceipt.length ? fromReceipt : Object.keys(openings);
  return Array.from(new Set(names)).sort();
}
function receiptHashHex(receipt) {
  return bytesToHex(sha2562(new TextEncoder().encode(jcs(receipt))));
}
function verifyCommittedReceiptSignature(receipt) {
  const signature = receipt.signature;
  if (!signature || typeof signature !== "object") return null;
  const sig = signature;
  if (sig.alg !== "EdDSA" || typeof sig.sig !== "string" || typeof sig.public_key !== "string") {
    return null;
  }
  const { signature: _signature, ...payloadWithoutSig } = receipt;
  const messageHash = sha2562(new TextEncoder().encode(jcs(payloadWithoutSig)));
  try {
    return ed25519.verify(base64urlDecode(sig.sig), messageHash, hexToBytes(sig.public_key));
  } catch {
    return false;
  }
}

export {
  signCommittedDecision,
  discloseField,
  createSelectiveDisclosurePackage,
  verifySelectiveDisclosurePackage
};
