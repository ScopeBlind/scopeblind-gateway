import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { buildClaim, verifyClaim, buildAnchorEnvelope, claimDigest, verifyAnchorEnvelope, checkClaimAnchor, buildRecordCheckpoint, lookupPinnedIdentity, type ClaimKey } from './claim.js';

// Replicates the transparency-log endpoint's acceptance check (functions/fn/log/
// anchor-pack.js): type gate, digest == sha256(deepSort(pack minus sig/digest/cosigs)),
// and Ed25519 sig verifies against the embedded key. If this passes, the live log
// will anchor the envelope.
function endpointAccepts(env: Record<string, unknown>): boolean {
  if (env.type !== 'evidence_pack' || typeof env.signature !== 'string' || typeof env.digest !== 'string' || typeof env.verification_key !== 'string') return false;
  const deepSort = (o: unknown): unknown => {
    if (o === null || typeof o !== 'object') return o;
    if (Array.isArray(o)) return o.map(deepSort);
    const s: Record<string, unknown> = {};
    for (const k of Object.keys(o as Record<string, unknown>).sort()) s[k] = deepSort((o as Record<string, unknown>)[k]);
    return s;
  };
  const { signature, digest, co_signatures, ...signed } = env as Record<string, unknown>;
  void co_signatures;
  const hash = sha256(new TextEncoder().encode(JSON.stringify(deepSort(signed))));
  if (bytesToHex(hash) !== String(digest).toLowerCase()) return false;
  try { return ed25519.verify(hexToBytes(signature as string), hash, hexToBytes(env.verification_key as string)); } catch { return false; }
}

function genKey(): ClaimKey {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  return { privateKey: bytesToHex(priv), publicKey: bytesToHex(pub), kid: 'test', issuer: 'protect-mcp' };
}
function receipt(tool: string, decision: string, caps: string[], ts: string): Record<string, unknown> {
  return {
    v: 2, type: 'decision_receipt', issued_at: ts,
    payload: { tool, decision, request_id: tool + ts, enrichment: { v: 1, input_digest: 'x', capabilities: caps } },
    signature: 'sig' + tool + ts,
  };
}

describe('claim attestations', () => {
  const key = genKey();
  const recs = [
    receipt('Bash', 'allow', ['exec.shell'], '2026-07-05T10:00:00Z'),
    receipt('Read', 'allow', ['fs.read'], '2026-07-05T10:01:00Z'),
    receipt('Write', 'allow', ['fs.write', 'secret.adjacent'], '2026-07-05T10:02:00Z'),
    receipt('WebFetch', 'deny', ['net.egress'], '2026-07-05T10:03:00Z'),
  ];

  it('no_capability: does not hold when present, with the right count, and the pack still verifies', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'net.egress' }, key, '2026-07-05T11:00:00Z');
    expect(pack.claim.holds).toBe(false);
    expect(pack.claim.matched).toBe(1);
    const v = verifyClaim(pack);
    expect(v.valid).toBe(true); // the pack correctly attests that the claim is false
    expect([v.authentic, v.root_ok, v.predicate_ok]).toEqual([true, true, true]);
  });

  it('no_capability: holds when absent', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'financial' }, key, 't');
    expect(pack.claim.holds).toBe(true);
    expect(pack.claim.matched).toBe(0);
    expect(verifyClaim(pack).valid).toBe(true);
  });

  it('only_capabilities, count_verdict and no_verdict evaluate correctly', () => {
    expect(buildClaim(recs, { kind: 'only_capabilities', capabilities: ['fs.read', 'fs.write', 'exec.shell', 'secret.adjacent', 'net.egress'] }, key, 't').claim.holds).toBe(true);
    expect(buildClaim(recs, { kind: 'only_capabilities', capabilities: ['fs.read'] }, key, 't').claim.holds).toBe(false);
    expect(buildClaim(recs, { kind: 'count_verdict', verdict: 'blocked' }, key, 't').claim.matched).toBe(1);
    expect(buildClaim(recs, { kind: 'no_verdict', verdict: 'blocked' }, key, 't').claim.holds).toBe(false);
  });

  it('is position-blind: leaves carry only digest/verdict/caps/ts, no content', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'financial' }, key, 't');
    expect(Object.keys(pack.leaves[0]).sort()).toEqual(['c', 'd', 't', 'v']);
    expect(JSON.stringify(pack)).not.toContain('request_id');
    expect(JSON.stringify(pack)).not.toContain('input_digest');
  });

  it('detects a tampered leaf (capability stripped to hide egress)', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'net.egress' }, key, 't');
    const egress = pack.leaves.find((l) => l.c.indexOf('net.egress') >= 0)!;
    egress.c = [];
    pack.claim.holds = true; pack.claim.matched = 0;
    const v = verifyClaim(pack);
    expect(v.valid).toBe(false);
    expect(v.root_ok).toBe(false);   // Merkle root no longer matches the disclosed leaves
    expect(v.authentic).toBe(false); // and the signature breaks
  });

  it('detects a tampered claim result (independent predicate recompute)', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'net.egress' }, key, 't');
    pack.claim.holds = true; // lie
    const v = verifyClaim(pack);
    expect(v.valid).toBe(false);
    expect(v.predicate_ok).toBe(false);
  });

  it('binds the issuer key in the signature and honours a pinned-key override', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'financial' }, key, 't');
    // the embedded issuer key is part of the signed content: swapping it breaks the signature
    const swapped = JSON.parse(JSON.stringify(pack));
    swapped.issuer.publicKey = genKey().publicKey;
    expect(verifyClaim(swapped).authentic).toBe(false);
    // pinned-key override: verifying against the real key works; a wrong pinned key fails
    expect(verifyClaim(pack, key.publicKey).authentic).toBe(true);
    expect(verifyClaim(pack, genKey().publicKey).authentic).toBe(false);
  });

  it('anchor envelope binds the claim digest and is accepted by the log endpoint', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'net.egress' }, key, '2026-07-05T11:00:00Z');
    const env = buildAnchorEnvelope(pack, key, '2026-07-06T00:00:00Z');
    expect(env.type).toBe('evidence_pack');
    expect(env.anchors).toBe('protect-mcp-claim');
    expect(env.claim_digest).toBe(claimDigest(pack)); // binds the exact signed pack
    expect(env.record_root).toBe(pack.record.root);
    expect(env.total).toBe(pack.scope.total);
    expect(endpointAccepts(env as unknown as Record<string, unknown>)).toBe(true);
  });

  it('anchor envelope discloses only hashes + the public claim result, never leaves/receipts', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'net.egress' }, key, 't');
    const env = buildAnchorEnvelope(pack, key, 't2');
    const s = JSON.stringify(env);
    expect(s).not.toContain('exec.shell'); // a capability that appears in the record's leaves
    expect(s).not.toContain('input_digest');
    expect(s).not.toContain('"leaves"');
  });

  it('tampering the anchored digest breaks the log endpoint check', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'net.egress' }, key, 't');
    const env = buildAnchorEnvelope(pack, key, 't2') as unknown as Record<string, unknown>;
    expect(endpointAccepts(env)).toBe(true);
    expect(endpointAccepts({ ...env, claim_digest: '00'.repeat(32) })).toBe(false); // digest no longer matches signature
    expect(endpointAccepts({ ...env, verification_key: genKey().publicKey })).toBe(false); // wrong key
  });

  it('verifyAnchorEnvelope: binds the exact claim, refuses a different claim or key', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'net.egress' }, key, 't');
    const env = buildAnchorEnvelope(pack, key, 't2');
    expect(verifyAnchorEnvelope(pack, env).ok).toBe(true);
    // a DIFFERENT claim (same record) must not be bound by this envelope
    const other = buildClaim(recs, { kind: 'no_capability', capability: 'financial' }, key, 't');
    const vOther = verifyAnchorEnvelope(other, env);
    expect(vOther.ok).toBe(false);
    expect(vOther.reasons.join(' ')).toContain('claim_digest');
    // tampered claim_digest in the envelope breaks its own signature check
    const tampered = { ...env, claim_digest: '00'.repeat(32) };
    expect(verifyAnchorEnvelope(pack, tampered).ok).toBe(false);
    // an envelope signed by a stranger's key is rejected as not-the-issuer
    const strangerEnv = buildAnchorEnvelope(pack, genKey(), 't2');
    const vStranger = verifyAnchorEnvelope(pack, strangerEnv);
    expect(vStranger.ok).toBe(false);
    expect(vStranger.reasons.join(' ')).toContain('different key');
  });

  it('checkClaimAnchor: confirms via the log, refutes a missing digest, tolerates offline', async () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'net.egress' }, key, 't');
    const env = buildAnchorEnvelope(pack, key, 't2');
    const sidecar = { log: 'https://log.test', seq: 7, anchored_at: 't3', envelope: env };
    const fetchOk = (async (url: string) => {
      expect(String(url)).toBe(`https://log.test/fn/log/digest/sha256:${env.digest}`);
      return { ok: true, json: async () => ({ ok: true, anchored: true, seq: 7 }) };
    }) as unknown as typeof fetch;
    const a = await checkClaimAnchor(pack, sidecar, { fetchImpl: fetchOk });
    expect(a.local_ok).toBe(true);
    expect(a.log_ok).toBe(true);
    expect(a.seq).toBe(7);
    // the log does not hold the digest -> refuted
    const fetchMiss = (async () => ({ ok: true, json: async () => ({ ok: false, anchored: false }) })) as unknown as typeof fetch;
    const miss = await checkClaimAnchor(pack, sidecar, { fetchImpl: fetchMiss });
    expect(miss.log_ok).toBe(false);
    // seq disagreement between sidecar and log -> refuted
    const fetchSeq = (async () => ({ ok: true, json: async () => ({ ok: true, anchored: true, seq: 9 }) })) as unknown as typeof fetch;
    const seq = await checkClaimAnchor(pack, sidecar, { fetchImpl: fetchSeq });
    expect(seq.log_ok).toBe(false);
    // network failure -> log_ok null, local checks stand
    const fetchBoom = (async () => { throw new Error('offline'); }) as unknown as typeof fetch;
    const off = await checkClaimAnchor(pack, sidecar, { fetchImpl: fetchBoom });
    expect(off.local_ok).toBe(true);
    expect(off.log_ok).toBe(null);
  });

  function paymentReceipt(tool: string, amount: number | null, ts: string): Record<string, unknown> {
    return {
      v: 2, type: 'decision_receipt', issued_at: ts,
      payload: { tool, decision: 'allow', request_id: tool + ts, enrichment: { v: 2, input_digest: 'x', capabilities: ['payment'], payment: { amount, asset: 'USDC', recipient_digest: 'r'.repeat(64) } } },
      signature: 'sig' + tool + ts,
    };
  }

  it('payment_under: holds when every readable payment is under the cap', () => {
    const rows = [
      paymentReceipt('pay_a', 0.5, '2026-07-07T10:00:00Z'),
      paymentReceipt('pay_b', 2, '2026-07-07T10:01:00Z'),
      receipt('Read', 'allow', ['fs.read'], '2026-07-07T10:02:00Z'), // non-payment row
    ];
    const pack = buildClaim(rows, { kind: 'payment_under', cap: 5 }, key, 't');
    expect(pack.claim.holds).toBe(true);
    expect(pack.claim.matched).toBe(0);
    expect(verifyClaim(pack).valid).toBe(true);
    // leaves carry `p` ONLY on payment rows; non-payment leaves stay {c,d,t,v}
    const withP = pack.leaves.filter((l) => 'p' in l);
    expect(withP.length).toBe(2);
    const bare = pack.leaves.find((l) => !('p' in l))!;
    expect(Object.keys(bare).sort()).toEqual(['c', 'd', 't', 'v']);
    expect(JSON.stringify(pack)).not.toContain('r'.repeat(64)); // recipient hash never enters leaves
  });

  it('payment_under: an over-cap payment or an UNREADABLE amount refutes the claim', () => {
    const over = buildClaim([paymentReceipt('pay_a', 9, 't1')], { kind: 'payment_under', cap: 5 }, key, 't');
    expect(over.claim.holds).toBe(false);
    expect(over.claim.matched).toBe(1);
    // unknown amount (atomic units the gate could not normalize) counts as over:
    // you cannot prove an amount you could not read.
    const unknown = buildClaim([paymentReceipt('pay_b', null, 't2')], { kind: 'payment_under', cap: 5 }, key, 't');
    expect(unknown.claim.holds).toBe(false);
    // and a verifier recomputes that refusal independently: lying about it breaks the pack
    const lied = JSON.parse(JSON.stringify(unknown));
    lied.claim.holds = true; lied.claim.matched = 0;
    expect(verifyClaim(lied).valid).toBe(false);
  });

  it('record checkpoint commits to the SAME root a claim commits to, and the log endpoint accepts it', () => {
    const pack = buildClaim(recs, { kind: 'no_capability', capability: 'financial' }, key, 't');
    const cp = buildRecordCheckpoint(recs, key, '2026-07-07T12:00:00Z');
    expect(cp.record_root).toBe(pack.record.root); // cross-checkable by construction
    expect(cp.total).toBe(pack.scope.total);
    expect(cp.anchors).toBe('protect-mcp-record');
    expect(endpointAccepts(cp as unknown as Record<string, unknown>)).toBe(true);
    // tampering the count breaks the checkpoint's own signature binding
    expect(endpointAccepts({ ...(cp as unknown as Record<string, unknown>), total: 999 })).toBe(false);
  });

  it('lookupPinnedIdentity: found / not-found / revoked / unreachable / bad key', async () => {
    const mk = (body: unknown) => (async () => ({ ok: true, json: async () => body })) as unknown as typeof fetch;
    const found = await lookupPinnedIdentity('a'.repeat(64), { fetchImpl: mk({ ok: true, found: true, name: 'Meridian', slug: 'meridian', enrolled_at: '2026-07-01T00:00:00Z' }) });
    expect(found).toEqual(expect.objectContaining({ found: true, name: 'Meridian', revoked: false }));
    const missing = await lookupPinnedIdentity('b'.repeat(64), { fetchImpl: mk({ ok: true, found: false }) });
    expect(missing).toEqual({ found: false });
    const revoked = await lookupPinnedIdentity('c'.repeat(64), { fetchImpl: mk({ ok: true, found: true, name: 'Old', revoked_at: '2026-07-02T00:00:00Z' }) });
    expect(revoked!.revoked).toBe(true);
    const down = await lookupPinnedIdentity('d'.repeat(64), { fetchImpl: (async () => { throw new Error('net'); }) as unknown as typeof fetch });
    expect(down).toBe(null); // unknown, never a refutation
    expect(await lookupPinnedIdentity('not-a-key', { fetchImpl: mk({}) })).toBe(null);
  });
});
