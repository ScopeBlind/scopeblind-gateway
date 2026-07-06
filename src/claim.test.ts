import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { buildClaim, verifyClaim, type ClaimKey } from './claim.js';

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
});
