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
  /**
   * Payment amount, present ONLY on rows the gate tagged as a payment:
   * a number when the amount was clearly readable at gate time, null when a
   * payment happened but its amount was not derivable (atomic units, unknown
   * decimals). Still position-blind: an amount is a category-level fact; the
   * recipient stays a hash and never appears in a leaf.
   */
  p?: number | null;
}

export type ClaimPredicate =
  | { kind: 'no_capability'; capability: string }
  | { kind: 'only_capabilities'; capabilities: string[] }
  | { kind: 'no_verdict'; verdict: Verdict }
  | { kind: 'count_verdict'; verdict: Verdict }
  | { kind: 'payment_under'; cap: number };

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
  const leaf: ClaimLeaf = { d, v, c, t };
  const pay = enr && (enr as { payment?: { amount?: unknown } }).payment;
  if (pay && typeof pay === 'object') {
    const amt = (pay as { amount?: unknown }).amount;
    leaf.p = typeof amt === 'number' && Number.isFinite(amt) ? amt : null;
  }
  return leaf;
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
  if (pred.kind === 'payment_under') {
    // A payment row violates when its amount reached the cap OR was not
    // readable at gate time: you cannot prove an unknown amount stayed under.
    const matched = leaves.filter((l) => 'p' in l && (l.p === null || (l.p as number) >= pred.cap)).length;
    return { statement: `Every payment stayed under ${pred.cap} (unknown amounts count as over)`, holds: matched === 0, matched };
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

// ── Anchoring: record a claim's digest in the public transparency log ──────────
// The log (scopeblind.com/fn/log) is credential-free and CT-style: it proves a
// digest existed at a time in an append-only chain; it does NOT endorse. Anchoring
// closes the one honest gap in a bare claim (that the disclosed set is COMPLETE):
// a counterparty who distrusts you can confirm the claim's commitment was fixed at
// a time and cannot be quietly re-cut later. ONLY hashes leave your machine; the
// claim, its leaves, and every receipt stay local.
export const ANCHOR_SCHEMA = 'scopeblind.protect-mcp.anchor.v1';
export const DEFAULT_LOG = 'https://scopeblind.com';

// Matches the log endpoint's preimage (anchor-pack.js): sha256 over the deep-sorted
// JSON of the envelope minus {signature, digest}; the signature is over those bytes.
function anchorDeepSort(o: unknown): unknown {
  if (o === null || typeof o !== 'object') return o;
  if (Array.isArray(o)) return o.map(anchorDeepSort);
  const src = o as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(src).sort()) out[k] = anchorDeepSort(src[k]);
  return out;
}
function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

/** SHA-256 (hex) of the full signed claim pack: the exact artifact a counterparty holds. */
export function claimDigest(pack: ClaimPack): string {
  return sha256Hex(canonicalJson(pack));
}

export interface AnchorEnvelope {
  type: 'evidence_pack'; // the log's generic signed-submission wire type
  schema: string;
  anchors: 'protect-mcp-claim';
  claim_digest: string;
  record_root: string;
  statement: string;
  holds: boolean;
  matched: number;
  total: number;
  issued_at: string;
  verification_key: string;
  disclosure: 'internal';
  signature: string;
  digest: string;
}

/**
 * Build the signed envelope submitted to the log. It is a self-verifying signed
 * object (the log re-checks the Ed25519 signature against verification_key and the
 * digest against the body), carrying only hashes plus the claim's PUBLIC result.
 * Pure and unit-testable; no network.
 */
export function buildAnchorEnvelope(pack: ClaimPack, key: ClaimKey, issuedAt: string): AnchorEnvelope {
  const signed = {
    type: 'evidence_pack' as const,
    schema: ANCHOR_SCHEMA,
    anchors: 'protect-mcp-claim' as const,
    claim_digest: claimDigest(pack),
    record_root: pack.record.root,
    statement: pack.claim.statement,
    holds: pack.claim.holds,
    matched: pack.claim.matched,
    total: pack.scope.total,
    issued_at: issuedAt,
    verification_key: key.publicKey,
    disclosure: 'internal' as const,
  };
  const hash = sha256(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
  const digest = bytesToHex(hash);
  const signature = bytesToHex(ed25519.sign(hash, hexToBytes(key.privateKey)));
  return { ...signed, signature, digest };
}

export interface AnchorResult {
  ok: boolean;
  claim_digest: string;
  seq?: number;
  entry_url?: string;
  anchored_at?: string;
  already_anchored?: boolean;
  envelope?: AnchorEnvelope;
  error?: string;
}

// ── Anchor verification: the counterparty side of --anchor ─────────────────────
// A verifier holding the claim pack + its .anchor.json sidecar can check, without
// trusting the issuer: (a) the anchored envelope binds THIS exact claim (its
// digest and record root), (b) the envelope's own signature verifies and was made
// by the same key that signed the claim, and (c) the public log really holds the
// envelope digest at the recorded position. (a)+(b) are pure/offline; (c) needs
// one GET to the log.

/** The .anchor.json sidecar written by `claim --anchor`. */
export interface AnchorSidecar {
  log?: string;
  seq?: number;
  entry_url?: string;
  anchored_at?: string;
  claim_digest?: string;
  envelope?: AnchorEnvelope;
}

/** Pure, offline: does this anchored envelope bind this exact claim pack? */
export function verifyAnchorEnvelope(pack: ClaimPack, envelope: AnchorEnvelope): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (!envelope || envelope.type !== 'evidence_pack' || envelope.anchors !== 'protect-mcp-claim') {
    return { ok: false, reasons: ['sidecar does not contain a protect-mcp claim anchor envelope'] };
  }
  const expected = claimDigest(pack);
  if (envelope.claim_digest !== expected) {
    reasons.push('anchored envelope binds a DIFFERENT claim (claim_digest mismatch)');
  }
  if (envelope.record_root !== pack.record.root) {
    reasons.push('anchored envelope commits to a different record root');
  }
  if (pack.issuer && envelope.verification_key !== pack.issuer.publicKey) {
    reasons.push('anchor was signed by a different key than the claim issuer');
  }
  // Recompute the envelope digest + signature exactly as the log endpoint does.
  try {
    const { signature, digest, ...signed } = envelope as unknown as Record<string, unknown>;
    const hash = sha256(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
    if (bytesToHex(hash) !== String(digest).toLowerCase()) {
      reasons.push('envelope digest does not match its contents');
    } else if (!ed25519.verify(hexToBytes(String(signature)), hash, hexToBytes(envelope.verification_key))) {
      reasons.push('envelope signature does not verify');
    }
  } catch {
    reasons.push('envelope signature does not verify');
  }
  return { ok: reasons.length === 0, reasons };
}

export interface AnchorCheck {
  /** Local (offline) binding checks: envelope binds this claim and is authentic. */
  local_ok: boolean;
  /** Log confirmation: true/false when the log answered, null when unreachable. */
  log_ok: boolean | null;
  seq?: number;
  anchored_at?: string;
  entry_url?: string;
  reasons: string[];
}

/** Verify a claim's anchor sidecar offline, then confirm against the public log. */
export async function checkClaimAnchor(
  pack: ClaimPack,
  sidecar: AnchorSidecar,
  opts?: { fetchImpl?: typeof fetch; offline?: boolean },
): Promise<AnchorCheck> {
  const reasons: string[] = [];
  const envelope = sidecar && sidecar.envelope;
  if (!envelope) {
    return { local_ok: false, log_ok: null, reasons: ['sidecar has no anchor envelope'] };
  }
  const local = verifyAnchorEnvelope(pack, envelope);
  reasons.push(...local.reasons);

  const base = (sidecar.log || DEFAULT_LOG).replace(/\/+$/, '');
  const out: AnchorCheck = {
    local_ok: local.ok,
    log_ok: null,
    seq: sidecar.seq,
    anchored_at: sidecar.anchored_at,
    entry_url: sidecar.entry_url || (typeof sidecar.seq === 'number' ? `${base}/fn/log/${sidecar.seq}` : undefined),
    reasons,
  };
  if (opts?.offline) return out;

  const doFetch = opts?.fetchImpl || (globalThis.fetch as typeof fetch | undefined);
  if (!doFetch) return out;
  try {
    const resp = await doFetch(`${base}/fn/log/digest/sha256:${envelope.digest}`, { headers: { accept: 'application/json' } });
    const data = (await resp.json().catch(() => null)) as { anchored?: boolean; seq?: number; timestamp?: string } | null;
    if (!resp.ok || !data) {
      out.log_ok = null; // treat a malformed answer as unreachable, not as refutation
      return out;
    }
    if (data.anchored !== true) {
      out.log_ok = false;
      out.reasons.push('the public log does not contain this anchor digest');
      return out;
    }
    if (typeof sidecar.seq === 'number' && typeof data.seq === 'number' && data.seq !== sidecar.seq) {
      out.log_ok = false;
      out.reasons.push(`log holds the digest at entry #${data.seq}, sidecar says #${sidecar.seq}`);
      return out;
    }
    out.log_ok = true;
    if (typeof data.seq === 'number') out.seq = data.seq;
    return out;
  } catch {
    out.log_ok = null; // offline is not a failure; local binding checks stand alone
    return out;
  }
}

interface SubmitOutcome { ok: boolean; seq?: number; anchored_at?: string; already_anchored?: boolean; error?: string; }

/** POST a signed envelope to the log's anchor endpoint. Sends only the envelope (hashes + public facts). */
async function submitEnvelope(envelope: object, base: string, fetchImpl?: typeof fetch): Promise<SubmitOutcome> {
  const doFetch = fetchImpl || (globalThis.fetch as typeof fetch | undefined);
  if (!doFetch) return { ok: false, error: 'fetch_unavailable' };
  const encoded = toBase64(new TextEncoder().encode(JSON.stringify(envelope)));
  try {
    const resp = await doFetch(`${base}/fn/log/anchor-pack`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ encoded }),
    });
    const data = (await resp.json().catch(() => null)) as
      | { ok?: boolean; seq?: number; anchored_at?: string; already_anchored?: boolean; error?: string }
      | null;
    if (!resp.ok || !data || !data.ok || typeof data.seq !== 'number') {
      return { ok: false, error: (data && data.error) || `http_${resp.status}` };
    }
    return { ok: true, seq: data.seq, anchored_at: data.anchored_at, already_anchored: !!data.already_anchored };
  } catch {
    return { ok: false, error: 'network_error' };
  }
}

/** Anchor a claim by POSTing its signed envelope to the transparency log. Sends only hashes. */
export async function anchorClaim(
  pack: ClaimPack,
  key: ClaimKey,
  opts: { log?: string; issuedAt: string; fetchImpl?: typeof fetch },
): Promise<AnchorResult> {
  const envelope = buildAnchorEnvelope(pack, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, '');
  const out = await submitEnvelope(envelope, base, opts.fetchImpl);
  if (!out.ok) return { ok: false, claim_digest: envelope.claim_digest, error: out.error, envelope };
  return {
    ok: true,
    claim_digest: envelope.claim_digest,
    seq: out.seq,
    entry_url: `${base}/fn/log/${out.seq}`,
    anchored_at: out.anchored_at,
    already_anchored: out.already_anchored,
    envelope,
  };
}

// ── Record checkpoints: continuous completeness (heartbeat anchoring) ──────────
// Anchoring a CLAIM proves that claim existed; it does not prove receipts were
// not quietly dropped before the claim was minted. A checkpoint anchors the
// record's CURRENT commitment (the same Merkle root a claim over the same set
// commits to, plus the count and time range) into the public log. Run it on a
// heartbeat and the record grows an anchored history: a later claim whose root
// matches an anchored checkpoint is provably over the complete set as of that
// checkpoint. Only the root, count, and time range leave the machine.
export const CHECKPOINT_SCHEMA = 'scopeblind.protect-mcp.record-checkpoint.v1';

export interface RecordCheckpoint {
  type: 'evidence_pack'; // the log's generic signed-submission wire type
  schema: string;
  anchors: 'protect-mcp-record';
  /** Same computation as ClaimPack.record.root over the same receipts. */
  record_root: string;
  total: number;
  from: string;
  to: string;
  issued_at: string;
  verification_key: string;
  disclosure: 'internal';
  signature: string;
  digest: string;
}

export function buildRecordCheckpoint(receipts: Array<Record<string, unknown>>, key: ClaimKey, issuedAt: string): RecordCheckpoint {
  const leaves = receipts.map(receiptToLeaf);
  const times = leaves.map((l) => l.t).filter(Boolean).sort();
  const signed = {
    type: 'evidence_pack' as const,
    schema: CHECKPOINT_SCHEMA,
    anchors: 'protect-mcp-record' as const,
    record_root: merkleRoot(leaves.map(leafHash)),
    total: leaves.length,
    from: times[0] || '',
    to: times[times.length - 1] || '',
    issued_at: issuedAt,
    verification_key: key.publicKey,
    disclosure: 'internal' as const,
  };
  const hash = sha256(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
  const digest = bytesToHex(hash);
  const signature = bytesToHex(ed25519.sign(hash, hexToBytes(key.privateKey)));
  return { ...signed, signature, digest };
}

export interface CheckpointResult {
  ok: boolean;
  record_root: string;
  total: number;
  seq?: number;
  entry_url?: string;
  anchored_at?: string;
  already_anchored?: boolean;
  checkpoint: RecordCheckpoint;
  error?: string;
}

/** Build + anchor a record checkpoint. Sends only the root, count, and time range. */
export async function anchorRecordCheckpoint(
  receipts: Array<Record<string, unknown>>,
  key: ClaimKey,
  opts: { log?: string; issuedAt: string; fetchImpl?: typeof fetch },
): Promise<CheckpointResult> {
  const checkpoint = buildRecordCheckpoint(receipts, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, '');
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
    checkpoint,
  };
}

// ── Pinned identity: is this key enrolled in the public key directory? ─────────
// The free anchor is anonymous (a timestamp, not an identity). Enrolling a key
// (scopeblind.com/enroll) upgrades it: a counterparty resolves the key to a
// named org they can pin. This lookup is read-only and public.
export interface PinnedIdentity {
  found: boolean;
  name?: string;
  slug?: string;
  kid?: string;
  enrolled_at?: string;
  revoked?: boolean;
}

export async function lookupPinnedIdentity(
  publicKey: string,
  opts?: { log?: string; fetchImpl?: typeof fetch },
): Promise<PinnedIdentity | null> {
  const base = ((opts && opts.log) || DEFAULT_LOG).replace(/\/+$/, '');
  const doFetch = (opts && opts.fetchImpl) || (globalThis.fetch as typeof fetch | undefined);
  if (!doFetch || !/^[0-9a-f]{64}$/i.test(publicKey)) return null;
  try {
    const resp = await doFetch(`${base}/fn/log/keys/lookup/${publicKey.toLowerCase()}`, { headers: { accept: 'application/json' } });
    const data = (await resp.json().catch(() => null)) as
      | { ok?: boolean; found?: boolean; name?: string; slug?: string; kid?: string; enrolled_at?: string; revoked?: boolean; revoked_at?: string | null }
      | null;
    if (!data || data.ok !== true) return null;
    if (!data.found) return { found: false };
    return {
      found: true,
      name: data.name,
      slug: data.slug,
      kid: data.kid,
      enrolled_at: data.enrolled_at,
      revoked: !!(data.revoked || data.revoked_at),
    };
  } catch {
    return null; // unreachable directory is "unknown", never a refutation
  }
}
