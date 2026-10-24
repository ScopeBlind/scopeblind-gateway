import { describe, expect, it } from 'vitest';
import { ConfidentialGate, type AttestationDocument } from './confidential.js';

const doc: AttestationDocument = {
  provider: 'nitro',
  attestation: 'bm90LWEtcmVhbC1hdHRlc3RhdGlvbg==',
  enclave_public_key: 'ab'.repeat(32),
  measurements: { PCR0: 'expected-pcr0' },
  timestamp: new Date().toISOString(),
};
const base = { require_attestation: true, accepted_providers: ['nitro' as const], min_trust_tier: 'evidenced' as const };

describe('ConfidentialGate accepts an attestation only through the operator verifier', () => {
  it('refuses every document when no verify function is configured, whatever its measurements say', () => {
    const gate = new ConfidentialGate({ ...base, expected_measurements: { PCR0: 'expected-pcr0' } });
    const r = gate.evaluateAttestation(doc);
    expect(r.accepted).toBe(false);
    expect(r.tier).toBe('unknown');
    expect(r.reason).toMatch(/not verified/);
  });

  it('refuses when the verifier returns false, returns a non-boolean, or throws', () => {
    for (const verify of [() => false, () => 'yes' as unknown as boolean, () => { throw new Error('bad quote'); }]) {
      const r = new ConfidentialGate({ ...base, verify }).evaluateAttestation(doc);
      expect(r.accepted).toBe(false);
      expect(r.tier).toBe('unknown');
    }
  });

  it('still checks the expected measurements after the verifier accepts', () => {
    const gate = new ConfidentialGate({ ...base, verify: () => true, expected_measurements: { PCR0: 'other' } });
    const r = gate.evaluateAttestation(doc);
    expect(r.accepted).toBe(false);
    expect(r.reason).toMatch(/Measurement mismatch/);
  });

  it('accepts only when the verifier accepts and the measurements match', () => {
    const seen: AttestationDocument[] = [];
    const gate = new ConfidentialGate({ ...base, verify: (d) => { seen.push(d); return true; }, expected_measurements: { PCR0: 'expected-pcr0' } });
    const r = gate.evaluateAttestation(doc);
    expect(seen).toHaveLength(1);
    expect(r.accepted).toBe(true);
    expect(r.tier).toBe('privileged');
    expect(r.reason).toMatch(/configured verifier/);
  });

  it('refuses an unaccepted provider before calling the verifier', () => {
    let called = false;
    const r = new ConfidentialGate({ ...base, verify: () => { called = true; return true; } }).evaluateAttestation({ ...doc, provider: 'tdx' });
    expect(r.accepted).toBe(false);
    expect(called).toBe(false);
  });
});
