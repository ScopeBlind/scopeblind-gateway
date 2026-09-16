import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize, createReceiptEnvelope, receiptHash, verifyReceipt } from './acta-envelope.js';

const secret = '01'.repeat(32);
const publicKey = bytesToHex(ed25519.getPublicKey(hexToBytes(secret)));
const time = '2026-09-14T00:00:00.000Z';
const jcsPayload = '{"10":"first","2":"second","issued_at":"2026-09-14T00:00:00.000Z","issuer_id":"fixture-key","type":"test.numeric"}';
const legacyPayload = '{"2":"second","10":"first","issued_at":"2026-09-14T00:00:00.000Z","issuer_id":"fixture-key","type":"test.numeric"}';

describe('Acta receipt JCS conformance and explicit historical compatibility', () => {
  it('emits integer-like properties in lexical order at every depth', () => {
    expect(canonicalize({ '2': { '3': 'nested', '11': 'first' }, '10': 'first' }))
      .toBe('{"10":"first","2":{"11":"first","3":"nested"}}');
    expect(canonicalize({ '4294967295': 5, '4294967294': 4, '1': 1, '01': 0, '-1': -1, a: [{ '2': 2, '10': 10 }] }))
      .toBe('{"-1":-1,"01":0,"1":1,"4294967294":4,"4294967295":5,"a":[{"10":10,"2":2}]}');
  });

  it('does not lose a JSON __proto__ member and keeps the supported ASCII-key profile', () => {
    expect(canonicalize(JSON.parse('{"__proto__":{"kept":true},"2":2,"10":10}')))
      .toBe('{"10":10,"2":2,"__proto__":{"kept":true}}');
    expect(() => canonicalize({ 'é': 1 })).toThrow('Non-ASCII key');
  });

  it('rejects non-JSON and invalid-Unicode values rather than silently changing their meaning', () => {
    for (const input of [NaN, Infinity, undefined, { a: undefined }, [undefined], new Array(1), '\ud800', new Date()]) {
      expect(() => canonicalize(input)).toThrow();
    }
  });

  it('new numeric-key receipts verify against independently specified JCS bytes', () => {
    const result = createReceiptEnvelope({ type: 'test.numeric', '2': 'second', '10': 'first' }, secret, 'fixture-key', time);
    expect(canonicalize(result.envelope.payload)).toBe(jcsPayload);
    expect(ed25519.verify(hexToBytes(result.envelope.signature.sig), utf8ToBytes(jcsPayload), hexToBytes(publicKey))).toBe(true);
    expect(ed25519.verify(hexToBytes(result.envelope.signature.sig), utf8ToBytes(legacyPayload), hexToBytes(publicKey))).toBe(false);
    expect(verifyReceipt(result.envelope, publicKey)).toMatchObject({ valid: true, canonicalization: 'jcs', hash: result.hash });
  });

  it('rejects unsigned __proto__ fields injected into a flat historical envelope', () => {
    const payload = { v: 1, type: 'test.flat', decision: 'allow' };
    const original = { ...payload, signature: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), hexToBytes(secret))) };
    expect(verifyReceipt(original, publicKey).valid).toBe(true);
    const forged = JSON.parse(JSON.stringify(original));
    Object.defineProperty(forged, '__proto__', { value: { unsigned: true }, enumerable: true });
    expect(verifyReceipt(forged, publicKey).valid).toBe(false);
    expect(verifyReceipt(forged, publicKey, { allowLegacyNumericKeys: true }).valid).toBe(false);
  });

  it('identifies old non-JCS signatures and only accepts their original hash with explicit compatibility opt-in', () => {
    const historical = { payload: JSON.parse(legacyPayload), signature: { alg: 'EdDSA', kid: 'fixture-key', sig: bytesToHex(ed25519.sign(utf8ToBytes(legacyPayload), hexToBytes(secret))) } };
    const strict = verifyReceipt(historical, publicKey);
    expect(strict).toMatchObject({ valid: false, error: 'legacy_non_jcs_signature', legacy_signature_valid: true, canonicalization: 'legacy-numeric-key-order' });
    expect(strict.legacy_hash).not.toBe(receiptHash(historical));
    const compatible = verifyReceipt(historical, publicKey, { allowLegacyNumericKeys: true });
    expect(compatible).toMatchObject({ valid: true, hash: strict.legacy_hash, canonicalization: 'legacy-numeric-key-order' });
    expect(compatible.warning).toContain('not JCS-conformant');
    const tampered = structuredClone(historical); tampered.payload['2'] = 'different';
    expect(verifyReceipt(tampered, publicKey, { allowLegacyNumericKeys: true }).valid).toBe(false);
    // Old object rebuilding ignored __proto__; that historical weakness must
    // not become a compatibility bypass for newly added unsigned fields.
    const ignoredMember = JSON.parse(JSON.stringify(historical));
    Object.defineProperty(ignoredMember.payload, '__proto__', { value: { unsigned: true }, enumerable: true });
    expect(verifyReceipt(ignoredMember, publicKey, { allowLegacyNumericKeys: true }).valid).toBe(false);
  });
});
