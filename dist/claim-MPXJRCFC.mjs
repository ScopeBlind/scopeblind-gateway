import {
  canonicalJson
} from "./chunk-KRKZ2YX7.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/claim.ts
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { ed25519 } from "@noble/curves/ed25519";
var CLAIM_TYPE = "scopeblind.claim.v1";
function sha256Hex(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return bytesToHex(sha256(bytes));
}
function receiptToLeaf(e) {
  const p = e && typeof e.payload === "object" && e.payload || e;
  const dec = String(p.decision || e.decision || "").toLowerCase();
  const v = /den|block|reject|refus/.test(dec) ? "blocked" : /ask|approv|hold|escal|review|pending/.test(dec) ? "held" : "allowed";
  const enr = p.enrichment;
  const c = enr && Array.isArray(enr.capabilities) ? enr.capabilities.map(String).sort() : [];
  const tsRaw = e.issued_at || p.timestamp || p.issued_at;
  const ms = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "string" ? Date.parse(tsRaw) : NaN;
  const t = isFinite(ms) ? new Date(ms).toISOString() : "";
  const d = sha256Hex(canonicalJson(e));
  const leaf = { d, v, c, t };
  const pay = enr && enr.payment;
  if (pay && typeof pay === "object") {
    const amt = pay.amount;
    leaf.p = typeof amt === "number" && Number.isFinite(amt) ? amt : null;
  }
  return leaf;
}
function leafHash(leaf) {
  return sha256Hex(canonicalJson(leaf));
}
function merkleRoot(leafHashes) {
  if (leafHashes.length === 0) return sha256Hex("scopeblind.claim.empty");
  let level = [...leafHashes].sort();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(sha256Hex(a + b));
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
    const matched2 = leaves.filter((l) => !l.c.every((c) => allow.has(c))).length;
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
  return sha256(new TextEncoder().encode(canonicalJson(unsigned)));
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
  const signature = bytesToHex(ed25519.sign(messageHash(unsigned), hexToBytes(key.privateKey)));
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
      authentic = ed25519.verify(hexToBytes(signature), messageHash(unsigned), hexToBytes(pub));
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
var ANCHOR_SCHEMA = "scopeblind.protect-mcp.anchor.v1";
var DEFAULT_LOG = "https://scopeblind.com";
function anchorDeepSort(o) {
  if (o === null || typeof o !== "object") return o;
  if (Array.isArray(o)) return o.map(anchorDeepSort);
  const src = o;
  const out = {};
  for (const k of Object.keys(src).sort()) out[k] = anchorDeepSort(src[k]);
  return out;
}
function toBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function claimDigest(pack) {
  return sha256Hex(canonicalJson(pack));
}
function buildAnchorEnvelope(pack, key, issuedAt) {
  const signed = {
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
  const hash = sha256(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
  const digest = bytesToHex(hash);
  const signature = bytesToHex(ed25519.sign(hash, hexToBytes(key.privateKey)));
  return { ...signed, signature, digest };
}
function verifyAnchorEnvelope(pack, envelope) {
  const reasons = [];
  if (!envelope || envelope.type !== "evidence_pack" || envelope.anchors !== "protect-mcp-claim") {
    return { ok: false, reasons: ["sidecar does not contain a protect-mcp claim anchor envelope"] };
  }
  const expected = claimDigest(pack);
  if (envelope.claim_digest !== expected) {
    reasons.push("anchored envelope binds a DIFFERENT claim (claim_digest mismatch)");
  }
  if (envelope.record_root !== pack.record.root) {
    reasons.push("anchored envelope commits to a different record root");
  }
  if (pack.issuer && envelope.verification_key !== pack.issuer.publicKey) {
    reasons.push("anchor was signed by a different key than the claim issuer");
  }
  try {
    const { signature, digest, ...signed } = envelope;
    const hash = sha256(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
    if (bytesToHex(hash) !== String(digest).toLowerCase()) {
      reasons.push("envelope digest does not match its contents");
    } else if (!ed25519.verify(hexToBytes(String(signature)), hash, hexToBytes(envelope.verification_key))) {
      reasons.push("envelope signature does not verify");
    }
  } catch {
    reasons.push("envelope signature does not verify");
  }
  return { ok: reasons.length === 0, reasons };
}
async function checkClaimAnchor(pack, sidecar, opts) {
  const reasons = [];
  const envelope = sidecar && sidecar.envelope;
  if (!envelope) {
    return { local_ok: false, log_ok: null, reasons: ["sidecar has no anchor envelope"] };
  }
  const local = verifyAnchorEnvelope(pack, envelope);
  reasons.push(...local.reasons);
  const base = (sidecar.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out = {
    local_ok: local.ok,
    log_ok: null,
    seq: sidecar.seq,
    anchored_at: sidecar.anchored_at,
    entry_url: sidecar.entry_url || (typeof sidecar.seq === "number" ? `${base}/fn/log/${sidecar.seq}` : void 0),
    reasons
  };
  if (opts?.offline) return out;
  const doFetch = opts?.fetchImpl || globalThis.fetch;
  if (!doFetch) return out;
  try {
    const resp = await doFetch(`${base}/fn/log/digest/sha256:${envelope.digest}`, { headers: { accept: "application/json" } });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data) {
      out.log_ok = null;
      return out;
    }
    if (data.anchored !== true) {
      out.log_ok = false;
      out.reasons.push("the public log does not contain this anchor digest");
      return out;
    }
    if (typeof sidecar.seq === "number" && typeof data.seq === "number" && data.seq !== sidecar.seq) {
      out.log_ok = false;
      out.reasons.push(`log holds the digest at entry #${data.seq}, sidecar says #${sidecar.seq}`);
      return out;
    }
    out.log_ok = true;
    if (typeof data.seq === "number") out.seq = data.seq;
    return out;
  } catch {
    out.log_ok = null;
    return out;
  }
}
async function submitEnvelope(envelope, base, fetchImpl) {
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) return { ok: false, error: "fetch_unavailable" };
  const encoded = toBase64(new TextEncoder().encode(JSON.stringify(envelope)));
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
  const envelope = buildAnchorEnvelope(pack, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out = await submitEnvelope(envelope, base, opts.fetchImpl);
  if (!out.ok) return { ok: false, claim_digest: envelope.claim_digest, error: out.error, envelope };
  return {
    ok: true,
    claim_digest: envelope.claim_digest,
    seq: out.seq,
    entry_url: `${base}/fn/log/${out.seq}`,
    anchored_at: out.anchored_at,
    already_anchored: out.already_anchored,
    envelope
  };
}
var CHECKPOINT_SCHEMA = "scopeblind.protect-mcp.record-checkpoint.v1";
function buildRecordCheckpoint(receipts, key, issuedAt) {
  const leaves = receipts.map(receiptToLeaf);
  const times = leaves.map((l) => l.t).filter(Boolean).sort();
  const signed = {
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
  const hash = sha256(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
  const digest = bytesToHex(hash);
  const signature = bytesToHex(ed25519.sign(hash, hexToBytes(key.privateKey)));
  return { ...signed, signature, digest };
}
async function anchorRecordCheckpoint(receipts, key, opts) {
  const checkpoint = buildRecordCheckpoint(receipts, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out = await submitEnvelope(checkpoint, base, opts.fetchImpl);
  if (!out.ok) return { ok: false, record_root: checkpoint.record_root, total: checkpoint.total, checkpoint, error: out.error };
  return {
    ok: true,
    record_root: checkpoint.record_root,
    total: checkpoint.total,
    seq: out.seq,
    entry_url: `${base}/fn/log/${out.seq}`,
    anchored_at: out.anchored_at,
    already_anchored: out.already_anchored,
    checkpoint
  };
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
export {
  ANCHOR_SCHEMA,
  CHECKPOINT_SCHEMA,
  CLAIM_TYPE,
  DEFAULT_LOG,
  anchorClaim,
  anchorRecordCheckpoint,
  buildAnchorEnvelope,
  buildClaim,
  buildRecordCheckpoint,
  checkClaimAnchor,
  claimDigest,
  evaluate,
  leafHash,
  lookupPinnedIdentity,
  merkleRoot,
  receiptToLeaf,
  verifyAnchorEnvelope,
  verifyClaim
};
