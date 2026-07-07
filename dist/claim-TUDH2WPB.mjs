import {
  canonicalJson
} from "./chunk-KMNXHGGT.mjs";
import {
  sha256
} from "./chunk-AYNQIEN7.mjs";
import {
  ed25519
} from "./chunk-FFVJL3KQ.mjs";
import "./chunk-JIDDQUSQ.mjs";
import {
  bytesToHex,
  hexToBytes
} from "./chunk-D733KAPG.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/claim.ts
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
  return { d, v, c, t };
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
async function anchorClaim(pack, key, opts) {
  const envelope = buildAnchorEnvelope(pack, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const doFetch = opts.fetchImpl || globalThis.fetch;
  if (!doFetch) return { ok: false, claim_digest: envelope.claim_digest, error: "fetch_unavailable", envelope };
  const encoded = toBase64(new TextEncoder().encode(JSON.stringify(envelope)));
  try {
    const resp = await doFetch(`${base}/fn/log/anchor-pack`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ encoded })
    });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data || !data.ok || typeof data.seq !== "number") {
      return { ok: false, claim_digest: envelope.claim_digest, error: data && data.error || `http_${resp.status}`, envelope };
    }
    return {
      ok: true,
      claim_digest: envelope.claim_digest,
      seq: data.seq,
      entry_url: `${base}/fn/log/${data.seq}`,
      anchored_at: data.anchored_at,
      already_anchored: !!data.already_anchored,
      envelope
    };
  } catch {
    return { ok: false, claim_digest: envelope.claim_digest, error: "network_error", envelope };
  }
}
export {
  ANCHOR_SCHEMA,
  CLAIM_TYPE,
  DEFAULT_LOG,
  anchorClaim,
  buildAnchorEnvelope,
  buildClaim,
  claimDigest,
  evaluate,
  leafHash,
  merkleRoot,
  receiptToLeaf,
  verifyClaim
};
