import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { buildMandateContinuityCheckpoint, MANDATE_CONTINUITY_SCHEMA } from './claim.js';

const privateKey = sha256(new TextEncoder().encode('continuity-checkpoint-test'));
const publicKey = bytesToHex(ed25519.getPublicKey(privateKey));
const key = { privateKey: bytesToHex(privateKey), publicKey, kid: 'gate-test' };
const state = {
  registry_id: 'mr_test',
  registry_digest: `sha256:${'a'.repeat(64)}`,
  active_policy_digest: `sha256:${'b'.repeat(64)}`,
  transition_count: 3,
  latest_transition_hash: `sha256:${'c'.repeat(64)}`,
};

describe('managed mandate continuity checkpoint', () => {
  it('signs only lifecycle commitments for an external witness', () => {
    const checkpoint = buildMandateContinuityCheckpoint(state, key, '2026-07-10T12:00:00.000Z');
    expect(checkpoint.schema).toBe(MANDATE_CONTINUITY_SCHEMA);
    expect(checkpoint.continuity).toEqual(state);
    expect(JSON.stringify(checkpoint)).not.toContain('policy source');
    expect(ed25519.verify(hexToBytes(checkpoint.signature), hexToBytes(checkpoint.digest), hexToBytes(publicKey))).toBe(true);
  });

  it('refuses a checkpoint with a non-commitment lifecycle value', () => {
    expect(() => buildMandateContinuityCheckpoint({ ...state, latest_transition_hash: 'not-a-digest' }, key, '2026-07-10T12:00:00.000Z')).toThrow(/sha256 commitments/);
  });
});
