/**
 * Claim attestations (scopeblind.claim.v1): a signed, position-blind proof of a
 * PREDICATE over a record, that a third party (an allocator, an auditor) verifies
 * offline without seeing the receipts.
 *
 * The pack discloses, per decision, only the position-blind CATEGORIES needed to
 * check the claim: a receipt digest (a hash, reveals nothing), the verdict, the
 * capability tags, and a timestamp. It never discloses tool inputs, outputs,
 * arguments, paths, hosts, or counterparties.
 *
 * TRUST MODEL (kept honest, not overstated):
 *  - Authenticity + integrity: the pack is Ed25519-signed by the gate's key; a
 *    changed field breaks the signature. Pin/enrol the key and the verifier knows
 *    it is THIS gate. Verifiable with @noble primitives, our code removed.
 *  - The predicate is INDEPENDENTLY re-computable by the verifier over the
 *    disclosed categories, so the issuer cannot lie about the claim given the
 *    disclosure.
 *  - A Merkle root binds the disclosed set together; the verifier recomputes it,
 *    so leaves cannot be altered without detection.
 *  - Residual trust: that the disclosed set is COMPLETE (no receipts omitted) is
 *    attested by the issuer. Close it by anchoring receipts to the transparency
 *    log and checking the count/root against it. This is NOT a zero-knowledge
 *    proof and NOT trustless; it is an accountable, position-blind attestation.
 */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { canonicalJson } from './receipt-enrichment.js';

export const CLAIM_TYPE = 'scopeblind.claim.v1';

export type Verdict = 'allowed' | 'held' | 'blocked';

export interface ClaimLeaf {
  /** SHA-256 (hex) of the canonical signed receipt: a unique, content-free id. */
  d: string;
  /** Verdict category. */
  v: Verdict;
  /** Deterministic capability tags (categories, not content). */
  c: string[];
  /** ISO timestamp. */
  t: string;
}

export type ClaimPredicate =
  | { kind: 'no_capability'; capability: string }
  | { kind: 'only_capabilities'; capabilities: string[] }
  | { kind: 'no_verdict'; verdict: Verdict }
  | { kind: 'count_verdict'; verdict: Verdict };

export interface ClaimResult { statement: string; holds: boolean; matched: number; }

export interface ClaimPackUnsigned {
  type: typeof CLAIM_TYPE;
  predicate: ClaimPredicate;
  claim: ClaimResult;
  scope: { total: number; from: string; to: string };
  record: { root: string };
  leaves: ClaimLeaf[];
  issuer: { kid: string; publicKey: string; issuer: string };
  issued_at: string;
}
export interface ClaimPack extends ClaimPackUnsigned { signature: string; }

function sha256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return bytesToHex(sha256(bytes));
}

/** Position-blind leaf from a raw (signed) receipt. */
export function receiptToLeaf(e: Record<string, unknown>): ClaimLeaf {
  const p = (e && typeof (e as { payload?: unknown }).payload === 'object' && (e as { payload?: Record<string, unknown> }).payload) || e;
  const dec = String((p as { decision?: unknown }).decision || (e as { decision?: unknown }).decision || '').toLowerCase();
  const v: Verdict = /den|block|reject|refus/.test(dec) ? 'blocked' : (/ask|approv|hold|escal|review|pending/.test(dec) ? 'held' : 'allowed');
  const enr = (p as { enrichment?: { capabilities?: unknown } }).enrichment;
  const c = enr && Array.isArray(enr.capabilities) ? enr.capabilities.map(String).sort() : [];
  const tsRaw = (e as { issued_at?: unknown }).issued_at || (p as { timestamp?: unknown; issued_at?: unknown }).timestamp || (p as { issued_at?: unknown }).issued_at;
  const ms = typeof tsRaw === 'number' ? tsRaw : (typeof tsRaw === 'string' ? Date.parse(tsRaw) : NaN);
  const t = isFinite(ms) ? new Date(ms).toISOString() : '';
  const d = sha256Hex(canonicalJson(e));
  return { d, v, c, t };
}

export function leafHash(leaf: ClaimLeaf): string {
  return sha256Hex(canonicalJson(leaf));
}

/** Order-independent binary Merkle root over leaf hashes (sorted set commitment). */
export function merkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) return sha256Hex('scopeblind.claim.empty');
  let level = [...leafHashes].sort();
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(sha256Hex(a + b));
    }
    level = next;
  }
  return level[0];
}

export function evaluate(pred: ClaimPredicate, leaves: ClaimLeaf[]): ClaimResult {
  if (pred.kind === 'no_capability') {
    const matched = leaves.filter((l) => l.c.indexOf(pred.capability) >= 0).length;
    return { statement: `No action used capability "${pred.capability}"`, holds: matched === 0, matched };
  }
  if (pred.kind === 'only_capabilities') {
    const allow = new Set(pred.capabilities);
    const matched = leaves.filter((l) => !l.c.every((c) => allow.has(c))).length;
    return { statement: `All actions were confined to capabilities {${pred.capabilities.join(', ')}}`, holds: matched === 0, matched };
  }
  if (pred.kind === 'no_verdict') {
    const matched = leaves.filter((l) => l.v === pred.verdict).length;
    return { statement: `No action was ${pred.verdict}`, holds: matched === 0, matched };
  }
  // count_verdict
  const matched = leaves.filter((l) => l.v === pred.verdict).length;
  return { statement: `${matched} action${matched === 1 ? ' was' : 's were'} ${pred.verdict}`, holds: true, matched };
}

function messageHash(unsigned: ClaimPackUnsigned): Uint8Array {
  return sha256(new TextEncoder().encode(canonicalJson(unsigned)));
}

export interface ClaimKey { privateKey: string; publicKey: string; kid: string; issuer?: string; }

export function buildClaim(receipts: Array<Record<string, unknown>>, predicate: ClaimPredicate, key: ClaimKey, issuedAt: string): ClaimPack {
  const leaves = receipts.map(receiptToLeaf);
  const root = merkleRoot(leaves.map(leafHash));
  const claim = evaluate(predicate, leaves);
  const times = leaves.map((l) => l.t).filter(Boolean).sort();
  const unsigned: ClaimPackUnsigned = {
    type: CLAIM_TYPE,
    predicate,
    claim,
    scope: { total: leaves.length, from: times[0] || '', to: times[times.length - 1] || '' },
    record: { root },
    leaves,
    issuer: { kid: key.kid, publicKey: key.publicKey, issuer: key.issuer || 'protect-mcp' },
    issued_at: issuedAt,
  };
  const signature = bytesToHex(ed25519.sign(messageHash(unsigned), hexToBytes(key.privateKey)));
  return { ...unsigned, signature };
}

export interface ClaimVerification {
  valid: boolean;
  authentic: boolean;
  root_ok: boolean;
  predicate_ok: boolean;
  holds: boolean;
  matched: number;
  total: number;
  statement: string;
  reasons: string[];
}

export function verifyClaim(pack: ClaimPack, overridePublicKey?: string): ClaimVerification {
  const reasons: string[] = [];
  const leaves = Array.isArray(pack.leaves) ? pack.leaves : [];

  const recomputedRoot = merkleRoot(leaves.map(leafHash));
  const root_ok = !!pack.record && recomputedRoot === pack.record.root;
  if (!root_ok) reasons.push('record commitment (Merkle root) does not match the disclosed decisions');

  const recomputed = evaluate(pack.predicate, leaves);
  const predicate_ok = !!pack.claim && recomputed.holds === pack.claim.holds && recomputed.matched === pack.claim.matched;
  if (!predicate_ok) reasons.push('claim result does not match the predicate recomputed over the disclosed decisions');

  let authentic = false;
  try {
    const { signature, ...unsigned } = pack;
    const pub = overridePublicKey || (pack.issuer && pack.issuer.publicKey);
    if (pub && signature) {
      authentic = ed25519.verify(hexToBytes(signature), messageHash(unsigned as ClaimPackUnsigned), hexToBytes(pub));
    }
  } catch { /* authentic stays false */ }
  if (!authentic) reasons.push('signature does not verify against the issuer public key');

  return {
    valid: authentic && root_ok && predicate_ok,
    authentic, root_ok, predicate_ok,
    holds: !!(pack.claim && pack.claim.holds),
    matched: pack.claim ? pack.claim.matched : recomputed.matched,
    total: leaves.length,
    statement: pack.claim ? pack.claim.statement : recomputed.statement,
    reasons,
  };
}
