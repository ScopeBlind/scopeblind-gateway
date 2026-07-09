/**
 * Migration contract for the draft-02 Acta envelope.
 *
 * Locks three properties:
 *  1. Emission is draft-02 conformant: { payload, signature: { alg: "EdDSA",
 *     kid, sig } }, issuer_id == kid, PureEdDSA over JCS(payload) (s5.6).
 *  2. Verification is dual-shape: legacy v1/v2 envelopes from
 *     @veritasacta/artifacts (protect-mcp <= 0.9.x) still verify.
 *  3. The s5.7 chain hash covers the entire envelope including the signature.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import {
  createReceiptEnvelope,
  verifyReceipt,
  receiptHash,
  computeSbIssuerKid,
  canonicalize,
} from './acta-envelope.js';
import { initSigning, signDecision } from './signing.js';
import type { DecisionLog } from './types.js';

const priv = ed25519.utils.randomPrivateKey();
const privHex = bytesToHex(priv);
const pubHex = bytesToHex(ed25519.getPublicKey(priv));
const otherPriv = ed25519.utils.randomPrivateKey();
const otherPubHex = bytesToHex(ed25519.getPublicKey(otherPriv));

const FIELDS = {
  type: 'protectmcp:decision',
  tool_name: 'Bash',
  decision: 'deny',
  reason: 'policy_block',
  policy_digest: 'sha256:' + 'a'.repeat(64),
};

describe('draft-02 envelope emission', () => {
  const kid = computeSbIssuerKid(pubHex);
  const { envelope, hash } = createReceiptEnvelope({ ...FIELDS }, privHex, kid);

  it('has the two-field draft-02 shape with an EdDSA signature object', () => {
    expect(Object.keys(envelope).sort()).toEqual(['payload', 'signature']);
    expect(envelope.signature.alg).toBe('EdDSA');
    expect(envelope.signature.kid).toBe(kid);
    expect(envelope.signature.sig).toMatch(/^[0-9a-f]{128}$/);
  });

  it('fills issued_at and forces issuer_id == kid (s2.2)', () => {
    expect(envelope.payload.issuer_id).toBe(kid);
    expect(typeof envelope.payload.issued_at).toBe('string');
  });

  it('kid follows the s2.1.1 recommended sb:issuer:<base58-12> format', () => {
    expect(kid).toMatch(/^sb:issuer:[1-9A-HJ-NP-Za-km-z]{1,12}$/);
  });

  it('signs JCS(payload) directly (s5.6): the signature verifies over payload bytes alone', () => {
    const msg = new TextEncoder().encode(canonicalize(envelope.payload));
    const bytes = new Uint8Array(Buffer.from(envelope.signature.sig, 'hex'));
    expect(ed25519.verify(bytes, msg, ed25519.getPublicKey(priv))).toBe(true);
  });

  it('verifies via verifyReceipt with shape acta-02, and fails with the wrong key', () => {
    expect(verifyReceipt(envelope, pubHex)).toMatchObject({ valid: true, shape: 'acta-02' });
    expect(verifyReceipt(envelope, otherPubHex)).toMatchObject({ valid: false, shape: 'acta-02' });
  });

  it('rejects an unsupported alg instead of misverifying it', () => {
    const wrongAlg = JSON.parse(JSON.stringify(envelope));
    wrongAlg.signature.alg = 'ES256';
    const res = verifyReceipt(wrongAlg, pubHex);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('unsupported_alg');
  });

  it('tampering the payload breaks verification', () => {
    const tampered = JSON.parse(JSON.stringify(envelope));
    tampered.payload.decision = 'allow';
    expect(verifyReceipt(tampered, pubHex).valid).toBe(false);
  });

  it('the s5.7 chain hash covers the signature, not just the payload', () => {
    expect(hash).toBe(receiptHash(envelope));
    const resigned = JSON.parse(JSON.stringify(envelope));
    resigned.signature.sig = 'f'.repeat(128);
    expect(receiptHash(resigned)).not.toBe(hash);
  });
});

describe('legacy dual-accept', () => {
  it('verifies a legacy v2 structured artifact (protect-mcp <= 0.9.x wire shape)', async () => {
    const artifacts = await import('@veritasacta/artifacts');
    const { artifact } = artifacts.createSignedArtifact(
      'decision_receipt',
      { tool: 'Bash', decision: 'deny', reason_code: 'policy_block', policy_digest: 'x', scope: 'r1' },
      privHex,
      { kid: 'legacy-kid', issuer: 'protect-mcp' },
    );
    const res = verifyReceipt(artifact, pubHex);
    expect(res).toMatchObject({ valid: true, shape: 'legacy-v2' });
    const tampered = JSON.parse(JSON.stringify(artifact));
    tampered.payload.decision = 'allow';
    expect(verifyReceipt(tampered, pubHex).valid).toBe(false);
  });

  it('verifies a legacy v1 flat artifact', async () => {
    const artifacts = await import('@veritasacta/artifacts');
    const { artifact } = artifacts.signArtifact(
      { v: 1, type: 'decision_receipt', timestamp: '2026-07-08T00:00:00Z', tool: 'Bash', decision: 'deny' },
      privHex,
    );
    expect(verifyReceipt(artifact, pubHex)).toMatchObject({ valid: true, shape: 'legacy-v1' });
  });

  it('reports unsigned objects honestly', () => {
    expect(verifyReceipt({ v: 2, type: 'decision_log' }, pubHex).error).toBe('missing_signature');
  });
});

describe('signDecision emits chained draft-02 receipts', () => {
  beforeAll(async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-acta-'));
    mkdirSync(join(dir, 'keys'), { recursive: true });
    const keyPath = join(dir, 'keys', 'gateway.json');
    writeFileSync(keyPath, JSON.stringify({ privateKey: privHex, publicKey: pubHex }));
    const warnings = await initSigning({ enabled: true, key_path: keyPath } as never);
    expect(warnings).toEqual([]);
  });

  const entry = {
    tool: 'Write',
    decision: 'allow',
    reason_code: 'policy_ok',
    policy_digest: 'abc123',
    request_id: 'chain-1',
    mode: 'enforce',
    timestamp: 1751971200000,
  } as unknown as DecisionLog;

  it('uses draft-02 s3.1 field names and pins spec revision 02', () => {
    const res = signDecision(entry);
    expect(res.ok).toBe(true);
    const env = JSON.parse(res.signed as string);
    expect(env.payload.type).toBe('protectmcp:decision');
    expect(env.payload.tool_name).toBe('Write');
    expect(env.payload.reason).toBe('policy_ok');
    expect(env.payload.spec).toBe('draft-farley-acta-signed-receipts-02');
    expect(env.payload.issuer_id).toBe(env.signature.kid);
    expect(verifyReceipt(env, pubHex).valid).toBe(true);
  });

  it('threads previousReceiptHash and returns the next chain link', () => {
    const first = signDecision(entry);
    expect(first.receipt_hash).toMatch(/^[0-9a-f]{64}$/);
    const second = signDecision({ ...entry, request_id: 'chain-2' } as DecisionLog, first.receipt_hash);
    const env2 = JSON.parse(second.signed as string);
    expect(env2.payload.previousReceiptHash).toBe(first.receipt_hash);
    // The link is the s5.7 hash of the first envelope exactly as written.
    expect(first.receipt_hash).toBe(receiptHash(JSON.parse(first.signed as string)));
    expect(verifyReceipt(env2, pubHex).valid).toBe(true);
  });
});
