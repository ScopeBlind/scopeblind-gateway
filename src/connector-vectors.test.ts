/**
 * Test vectors for the connector-action profile
 * (draft-farley-acta-connector-action-00), shared with the verifier.
 *
 * The vectors are deterministic: fixed keys, fixed timestamps, Ed25519. Each
 * one is a complete decision receipt signed by a gate key, carrying a
 * `connector` member, with the outcome a conformant verifier must reach with
 * and without the platform's key. The negative vectors describe receipts a
 * conformant gate never emits; a verifier must still refuse them.
 *
 * Regenerate after a deliberate change with:
 *   UPDATE_VECTORS=1 npx vitest run src/connector-vectors.test.ts
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalize, computeSbIssuerKid, createReceiptEnvelope, verifyReceipt } from './acta-envelope.js';
import {
  checkContextSignature,
  connectorRecordErrors,
  readbackDigest,
  recordConnectorAction,
  signConnectorContext,
  withEffect,
  type ConnectorRecord,
} from './connector-action.js';

const FILE = join(dirname(fileURLToPath(import.meta.url)), '..', 'vectors', 'connector-action.v1.json');
const GATE_PRIV = new Uint8Array(32).fill(0x11);
const GATE_PRIV_HEX = bytesToHex(GATE_PRIV);
const GATE_PUB = bytesToHex(ed25519.getPublicKey(GATE_PRIV));
const GATE_KID = computeSbIssuerKid(GATE_PUB);
const PLATFORM_PRIV = new Uint8Array(32).fill(0x22);
const PLATFORM_PRIV_HEX = bytesToHex(PLATFORM_PRIV);
const PLATFORM_PUB = bytesToHex(ed25519.getPublicKey(PLATFORM_PRIV));
const PLATFORM_KID = 'sb:platform:vector-muse';
const KEYS = { [PLATFORM_KID]: PLATFORM_PUB };
const AT = '2026-09-20T06:00:00.000Z';
const TOOL = 'prepare_repository_review';
const INPUT = { pull_number: 25, request_id: 'rehearsal-20260920-review-1' };
const base = {
  platform: 'meta.muse',
  agent: 'agent-e8d36428',
  grant: { type: 'task' as const, id: 'grant-42', purpose: 'Prepare the client review of pull request 25', issued_at: '2026-09-20T05:44:36.339Z', expires_at: '2026-09-21T05:44:36.339Z' },
  mandate_digest: 'sha256:' + 'a'.repeat(64),
  issued_at: '2026-09-20T05:45:00.000Z',
};

interface Expect {
  /** The receipt's own signature under the gate key: always valid here; the profile is what varies. */
  gate_signature: 'valid';
  /** Whether the connector member is well formed under the profile's schema. */
  schema: 'ok' | 'invalid';
  /** What a verifier that holds the platform key must conclude about the presented signature. */
  with_platform_key: 'absent' | 'valid' | 'invalid';
  /** The overall outcome for a verifier that holds the platform key. */
  verdict_with_platform_key: 'valid' | 'invalid';
  /** The overall outcome for a verifier without it (the presented signature is then unverifiable, never a failure by itself). */
  verdict_without_platform_key: 'valid' | 'invalid';
  context_check: string;
  effect?: string;
}
interface Vector { id: string; description: string; expect: Expect; receipt: unknown }

function receipt(n: number, connector: unknown): unknown {
  return createReceiptEnvelope({
    type: 'protectmcp:decision', tool_name: TOOL, decision: 'allow', reason: 'default_allow',
    policy_digest: 'sha256:' + 'b'.repeat(64), request_id: `vector-${n}`, mode: 'enforce',
    spec: 'draft-farley-acta-signed-receipts-04', connector,
  }, GATE_PRIV_HEX, GATE_KID, AT).envelope;
}

function build(): { type: string; profile: string; gate_public_key: string; platform_keys: Record<string, string>; vectors: Vector[] } {
  const unsigned = { payload: { type: 'acta:connector-context' as const, ...base } };
  const signed = signConnectorContext(base, PLATFORM_PRIV_HEX, PLATFORM_KID);
  const good = recordConnectorAction(signed, TOOL, INPUT, KEYS);
  const vectors: Vector[] = [
    { id: 'unsigned-context', description: 'The platform presented its grant without a signature. The gate recorded it as unsigned; nothing about the grant is established beyond the platform\'s word.',
      expect: { gate_signature: 'valid', schema: 'ok', with_platform_key: 'absent', verdict_with_platform_key: 'valid', verdict_without_platform_key: 'valid', context_check: 'unsigned' },
      receipt: receipt(1, recordConnectorAction(unsigned, TOOL, INPUT, KEYS)) },
    { id: 'signed-context-valid-confirmed', description: 'The platform signed the context, the gate held its key and verified it, and the service confirmed the effect with a readback digest.',
      expect: { gate_signature: 'valid', schema: 'ok', with_platform_key: 'valid', verdict_with_platform_key: 'valid', verdict_without_platform_key: 'valid', context_check: 'valid', effect: 'confirmed' },
      receipt: receipt(2, withEffect(good, { status: 'confirmed', readback_digest: readbackDigest({ ref: 'refs/heads/main', sha: 'a6fda804e354334ad7268ac065509745daf131a2' }), observed_at: '2026-09-20T06:09:00.000Z' })) },
    { id: 'signed-context-unverifiable-at-the-gate', description: 'The platform signed the context but the gate held no key for it, so it recorded unverifiable. A verifier that holds the key can still check the signature itself.',
      expect: { gate_signature: 'valid', schema: 'ok', with_platform_key: 'valid', verdict_with_platform_key: 'valid', verdict_without_platform_key: 'valid', context_check: 'unverifiable' },
      receipt: receipt(3, recordConnectorAction(signed, TOOL, INPUT, undefined)) },
    { id: 'tampered-context-recorded-as-valid', description: 'The recorded context differs from what the platform signed (the purpose was changed), yet the record claims the check was valid. A verifier with the platform key must refuse the receipt; without it the claim cannot be tested and is reported as unverifiable.',
      expect: { gate_signature: 'valid', schema: 'ok', with_platform_key: 'invalid', verdict_with_platform_key: 'invalid', verdict_without_platform_key: 'valid', context_check: 'valid' },
      receipt: receipt(4, { ...good, context: { ...good.context, grant: { ...good.context.grant, purpose: 'Merge whatever is open' } } }) },
    { id: 'grant-type-outside-the-profile', description: 'The grant type is not one of the five the profile admits. The member fails the schema, so the receipt is invalid whatever keys the verifier holds.',
      expect: { gate_signature: 'valid', schema: 'invalid', with_platform_key: 'absent', verdict_with_platform_key: 'invalid', verdict_without_platform_key: 'invalid', context_check: 'unsigned' },
      receipt: receipt(5, { ...recordConnectorAction(unsigned, TOOL, INPUT, KEYS), context: { ...unsigned.payload, grant: { ...base.grant, type: 'forever' } } }) },
    { id: 'confirmed-effect-without-readback', description: 'The effect says confirmed but carries no readback digest. Confirmation without a readback is a claim, not a record; the schema refuses it.',
      expect: { gate_signature: 'valid', schema: 'invalid', with_platform_key: 'valid', verdict_with_platform_key: 'invalid', verdict_without_platform_key: 'invalid', context_check: 'valid', effect: 'confirmed' },
      receipt: receipt(6, { ...good, effect: { status: 'confirmed', observed_at: '2026-09-20T06:09:00.000Z' } }) },
    { id: 'unsigned-context-recorded-as-valid', description: 'No signature was presented, yet the record claims a valid check and names a platform key. The schema refuses it.',
      expect: { gate_signature: 'valid', schema: 'invalid', with_platform_key: 'absent', verdict_with_platform_key: 'invalid', verdict_without_platform_key: 'invalid', context_check: 'valid' },
      receipt: receipt(7, { ...recordConnectorAction(unsigned, TOOL, INPUT, KEYS), context_check: 'valid', platform_kid: PLATFORM_KID }) },
  ];
  return { type: 'acta.connector-action.vectors.v1', profile: 'draft-farley-acta-connector-action-00', gate_public_key: GATE_PUB, platform_keys: KEYS, vectors };
}

describe('connector-action vectors', () => {
  const built = build();
  const text = JSON.stringify(built, null, 1) + '\n';
  if (process.env.UPDATE_VECTORS === '1') writeFileSync(FILE, text);

  it('are what this source builds', () => {
    expect(readFileSync(FILE, 'utf8')).toBe(text);
  });

  it('carry the outcomes the profile requires, checked by this implementation', () => {
    for (const v of built.vectors) {
      const env = v.receipt as { payload: { connector: ConnectorRecord } };
      expect(verifyReceipt(env, GATE_PUB), v.id).toMatchObject({ valid: true });
      const errors = connectorRecordErrors(env.payload.connector);
      expect(errors.length === 0 ? 'ok' : 'invalid', `${v.id}: ${errors.join('; ')}`).toBe(v.expect.schema);
      expect(env.payload.connector.context_check, v.id).toBe(v.expect.context_check);
      if (v.expect.effect) expect(env.payload.connector.effect?.status, v.id).toBe(v.expect.effect);
      const sig = env.payload.connector.context_signature;
      const withKey = sig ? checkContextSignature(env.payload.connector.context, sig, KEYS).check : 'absent';
      expect(withKey === 'unsigned' ? 'absent' : withKey, v.id).toBe(v.expect.with_platform_key);
    }
  });

  it('are deterministic bytes', () => {
    expect(canonicalize(build())).toBe(canonicalize(built));
  });
});
