import { describe, expect, it } from 'vitest';
import { verifyEvidenceAttestation, type EvidenceAttestation } from './evidence-authenticity.js';

const base = {
  version: '0.1-beta',
  url: 'https://example.com/data',
  httpMethod: 'GET',
  responseHash: 'sha256:' + '0'.repeat(64),
  statusCode: 200,
  fetchedAt: '2026-10-24T00:00:00.000Z',
};

describe('verifyEvidenceAttestation never reports a producer claim as a check', () => {
  it('oracle and witness attestations that say verified: true are not valid here', async () => {
    for (const method of ['oracle', 'witness'] as const) {
      const r = await verifyEvidenceAttestation({ ...base, method, verified: true } as unknown as EvidenceAttestation);
      expect(r.valid).toBe(false);
      expect(r.method).toBe(method);
      expect(r.note).toMatch(/not verified here/);
      expect(r.note).toMatch(/producer's claim/);
    }
  });

  it('self-reported and tlsnotary attestations stay not valid', async () => {
    const self = await verifyEvidenceAttestation({ ...base, method: 'self-reported', verified: false } as unknown as EvidenceAttestation);
    expect(self.valid).toBe(false);
    const tls = await verifyEvidenceAttestation({ ...base, method: 'tlsnotary', verified: true, notaryPublicKey: 'k', notarySignature: 's' } as unknown as EvidenceAttestation);
    expect(tls.valid).toBe(false);
  });
});
