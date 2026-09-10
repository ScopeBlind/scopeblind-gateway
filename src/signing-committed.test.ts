/**
 * Smoke tests for commitment-mode signing (v0.6.0).
 *
 * Verifies:
 *   - signCommittedDecision produces a valid Ed25519 signature
 *   - committed_fields_root reproduces from openings via Merkle proof
 *   - discloseField generates a verifiable inclusion proof
 *   - Tampering with disclosed value fails verification
 */

import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {
  createSelectiveDisclosurePackage,
  signCommittedDecision,
  discloseField,
  verifySelectiveDisclosurePackage,
} from './signing-committed.js';
import { hashLeaf, verifyProof } from './commitments/merkle.js';
import { encodeLeaf, base64urlNoPad } from './commitments/leaf.js';
import { jcs } from './commitments/primitives.js';
import type { DecisionLog } from './types.js';

function b64urlDecode(s: string): Uint8Array {
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

function makeKeyPair() {
  const sk = ed25519.utils.randomPrivateKey();
  const pk = ed25519.getPublicKey(sk);
  return { skHex: bytesToHex(sk), pkHex: bytesToHex(pk) };
}

function sampleEntry(): DecisionLog {
  return {
    timestamp: '2026-04-25T15:00:00Z',
    request_id: 'req-test-001',
    tool: 'lookup_flights',
    decision: 'allow',
    reason_code: 'allowed_by_policy',
    policy_digest: 'sha256:dummy',
    mode: 'enforce',
    tier: 'signed-known',
    payload_digest: 'sha256:abc123',
  };
}

describe('signCommittedDecision', () => {
  it('produces a parseable signed receipt with committed_fields_root', () => {
    const { skHex, pkHex } = makeKeyPair();
    const result = signCommittedDecision(
      sampleEntry(),
      ['tool', 'payload_digest', 'scope'],
      skHex,
      pkHex,
      'test-kid',
      'test-issuer',
    );

    expect(result.signed).toBeTruthy();
    const receipt = JSON.parse(result.signed);

    // Envelope shape: exactly a payload member and a signature member.
    expect(Object.keys(receipt).sort()).toEqual(['payload', 'signature']);

    expect(receipt.payload.type).toBe('scopeblind.receipt.committed.v1');
    expect(receipt.payload.spec).toBe('draft-farley-acta-signed-receipts');
    expect(receipt.payload.committed_fields_root).toMatch(/^[0-9a-f]{64}$/);
    expect(receipt.payload.committed_field_names).toEqual(
      expect.arrayContaining(['tool', 'payload_digest', 'scope']),
    );
    expect(receipt.signature.alg).toBe('EdDSA');
    expect(receipt.signature.kid).toBe('test-kid');
    // Lowercase hex, and no key travelling inside the artifact it authenticates.
    expect(receipt.signature.sig).toMatch(/^[0-9a-f]{128}$/);
    expect(receipt.signature.public_key).toBeUndefined();

    // Cleartext fields stay outside the committed root.
    expect(receipt.payload.decision).toBe('allow');
    expect(receipt.payload.reason_code).toBe('allowed_by_policy');
    expect(receipt.payload.tier).toBe('signed-known');
    expect(receipt.payload.tool).toBeUndefined();
    expect(receipt.payload.payload_digest).toBeUndefined();
  });

  it('produces an Ed25519 signature that verifies over JCS(payload)', () => {
    const { skHex, pkHex } = makeKeyPair();
    const result = signCommittedDecision(
      sampleEntry(),
      ['tool'],
      skHex,
      pkHex,
      'test-kid',
      'test-issuer',
    );

    const receipt = JSON.parse(result.signed);
    const sigBytes = hexToBytes(receipt.signature.sig);
    const pkBytes = hexToBytes(pkHex);

    // The signing input is JCS(payload), and the signature covers those bytes
    // directly. PureEdDSA hashes the message internally, so a SHA-256 pre-hash
    // is both redundant and forbidden by the spec; assert the direct form and
    // that the pre-hashed form no longer verifies, so neither can silently
    // regress.
    const canonical = new TextEncoder().encode(jcs(receipt.payload));
    expect(ed25519.verify(sigBytes, canonical, pkBytes)).toBe(true);
    expect(ed25519.verify(sigBytes, sha256(canonical), pkBytes)).toBe(false);

    // Canonicalizing the enclosing receipt is the other shape's rule and must
    // not verify under this one.
    const { signature: _s, ...receiptMinusSig } = receipt;
    expect(ed25519.verify(sigBytes, new TextEncoder().encode(jcs(receiptMinusSig)), pkBytes)).toBe(false);
  });

  it('records openings keyed by field name', () => {
    const { skHex, pkHex } = makeKeyPair();
    const result = signCommittedDecision(
      sampleEntry(),
      ['tool', 'payload_digest'],
      skHex,
      pkHex,
      'kid',
      'issuer',
    );

    expect(Object.keys(result.openings).sort()).toEqual([
      'payload_digest',
      'tool',
    ]);
    expect(result.openings.tool.value).toBe('lookup_flights');
    expect(result.openings.payload_digest.value).toBe('sha256:abc123');
    expect(result.openings.tool.salt).toBeInstanceOf(Uint8Array);
    expect(result.openings.tool.salt.length).toBe(32);
  });

  it('produces a verifiable Merkle inclusion proof per disclosed field', () => {
    const { skHex, pkHex } = makeKeyPair();
    const result = signCommittedDecision(
      sampleEntry(),
      ['tool', 'payload_digest', 'scope'],
      skHex,
      pkHex,
      'kid',
      'issuer',
    );
    const receipt = JSON.parse(result.signed);

    for (const fieldName of ['tool', 'payload_digest', 'scope']) {
      const disclosure = discloseField(
        result.receipt_hash,
        fieldName,
        result.openings,
      );

      // Reconstruct the leaf from the disclosure and check the proof.
      const leafBytes = encodeLeaf({
        name: disclosure.name,
        salt: b64urlDecode(disclosure.salt),
        value: disclosure.value,
      });
      const leafHash = hashLeaf(leafBytes);

      expect(
        verifyProof(receipt.payload.committed_fields_root, leafHash, disclosure.proof),
      ).toBe(true);
    }
  });

  it('rejects tampered disclosure (wrong value with original salt+proof)', () => {
    const { skHex, pkHex } = makeKeyPair();
    const result = signCommittedDecision(
      sampleEntry(),
      ['tool'],
      skHex,
      pkHex,
      'kid',
      'issuer',
    );
    const receipt = JSON.parse(result.signed);
    const disclosure = discloseField(result.receipt_hash, 'tool', result.openings);

    // Tamper: claim the field was a different value.
    const tamperedLeafBytes = encodeLeaf({
      name: disclosure.name,
      salt: b64urlDecode(disclosure.salt),
      value: 'not_lookup_flights',
    });
    const tamperedLeafHash = hashLeaf(tamperedLeafBytes);

    expect(
      verifyProof(
        receipt.payload.committed_fields_root,
        tamperedLeafHash,
        disclosure.proof,
      ),
    ).toBe(false);
  });

  it('creates a v0 selective disclosure package with disclosed vs hidden fields', () => {
    const { skHex, pkHex } = makeKeyPair();
    const result = signCommittedDecision(
      sampleEntry(),
      ['tool', 'payload_digest', 'scope'],
      skHex,
      pkHex,
      'kid',
      'issuer',
    );
    const receipt = JSON.parse(result.signed);
    const disclosure = createSelectiveDisclosurePackage(
      receipt,
      ['tool', 'scope'],
      result.openings,
    );
    // The receipt carries no public key, so the verifier needs one supplied
    // out of band. Without it the signature is undecidable, not valid.
    const undecidable = verifySelectiveDisclosurePackage(receipt, disclosure);
    expect(undecidable.signature_valid).toBeNull();

    const verification = verifySelectiveDisclosurePackage(receipt, disclosure, pkHex);

    expect(disclosure.type).toBe('scopeblind.selective_disclosure.v0');
    expect(disclosure.committed_fields_root).toBe(receipt.payload.committed_fields_root);
    expect(disclosure.disclosed_fields.sort()).toEqual(['scope', 'tool']);
    expect(disclosure.hidden_fields).toEqual(['payload_digest']);
    expect(verification.valid).toBe(true);
    expect(verification.signature_valid).toBe(true);
    expect(verification.disclosed_fields.sort()).toEqual(['scope', 'tool']);
    expect(verification.hidden_fields).toEqual(['payload_digest']);
    expect(verification.explanation.join(' ')).toContain('Hidden fields: payload_digest');
  });

  it('rejects tampered v0 selective disclosure packages', () => {
    const { skHex, pkHex } = makeKeyPair();
    const result = signCommittedDecision(
      sampleEntry(),
      ['tool', 'payload_digest'],
      skHex,
      pkHex,
      'kid',
      'issuer',
    );
    const receipt = JSON.parse(result.signed);
    const disclosure = createSelectiveDisclosurePackage(receipt, ['tool'], result.openings);
    disclosure.disclosures[0].value = 'not_lookup_flights';
    const verification = verifySelectiveDisclosurePackage(receipt, disclosure);

    expect(verification.valid).toBe(false);
    expect(verification.errors.join(' ')).toContain('failed Merkle inclusion');
  });

  it('handles empty committedFieldNames list (no commitment mode)', () => {
    const { skHex, pkHex } = makeKeyPair();
    const result = signCommittedDecision(
      sampleEntry(),
      [], // no fields committed
      skHex,
      pkHex,
      'kid',
      'issuer',
    );
    const receipt = JSON.parse(result.signed);

    expect(receipt.payload.committed_fields_root).toBeUndefined();
    expect(receipt.payload.committed_field_names).toBeUndefined();
    expect(receipt.payload.tool).toBe('lookup_flights');
    expect(Object.keys(result.openings).length).toBe(0);
  });
});
