/**
 * B1: hardened WebAuthn assertion verification. Builds real ES256 and EdDSA
 * assertions and exercises the full fail-closed check matrix.
 */
import { describe, it, expect } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import {
  createApprovalChallenge,
  verifyApprovalAssertion,
  type ApprovalChallenge,
  type ApprovalAssertion,
  type CredentialPublicKey,
} from './webauthn-approval.js';

const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const b64url = (u: Uint8Array) =>
  Buffer.from(u).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function authenticatorData(rpId: string, opts: { up?: boolean; uv?: boolean; signCount?: number } = {}): Uint8Array {
  const { up = true, uv = true, signCount = 1 } = opts;
  const out = new Uint8Array(37);
  out.set(sha256(new TextEncoder().encode(rpId)), 0);
  out[32] = (up ? 0x01 : 0) | (uv ? 0x04 : 0);
  out[33] = (signCount >>> 24) & 0xff;
  out[34] = (signCount >>> 16) & 0xff;
  out[35] = (signCount >>> 8) & 0xff;
  out[36] = signCount & 0xff;
  return out;
}

interface BuildOpts {
  origin?: string;
  rpIdForAuthData?: string;
  up?: boolean;
  uv?: boolean;
  signCount?: number;
  tamperSig?: boolean;
  wrongChallenge?: boolean;
}

function buildAssertion(
  alg: -7 | -8,
  priv: Uint8Array,
  challenge: ApprovalChallenge,
  o: BuildOpts = {},
): ApprovalAssertion {
  const origin = o.origin ?? `https://${challenge.rpId}`;
  const clientDataBytes = new TextEncoder().encode(
    JSON.stringify({ type: 'webauthn.get', challenge: o.wrongChallenge ? 'AAAA' : challenge.challenge, origin }),
  );
  const authData = authenticatorData(o.rpIdForAuthData ?? challenge.rpId, o);
  const signedData = new Uint8Array([...authData, ...sha256(clientDataBytes)]);
  let sig: Uint8Array;
  if (alg === -7) sig = p256.sign(sha256(signedData), priv).toDERRawBytes();
  else sig = ed25519.sign(signedData, priv);
  if (o.tamperSig) { sig = Uint8Array.from(sig); sig[5] ^= 0xff; }
  return {
    credentialId: 'cred-1',
    authenticatorData: b64url(authData),
    clientDataJSON: b64url(clientDataBytes),
    signature: b64url(sig),
  };
}

function es256() {
  const priv = p256.utils.randomPrivateKey();
  const key: CredentialPublicKey = { alg: -7, publicKeyHex: hex(p256.getPublicKey(priv, false)) };
  return { priv, key };
}
function eddsa() {
  const priv = ed25519.utils.randomSecretKey();
  const key: CredentialPublicKey = { alg: -8, publicKeyHex: hex(ed25519.getPublicKey(priv)) };
  return { priv, key };
}

describe('verifyApprovalAssertion (hardened)', () => {
  const now = Date.now();
  const challenge = createApprovalChallenge('req-1', 'db_write', 'agent:pm');

  it('accepts a valid ES256 assertion', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge);
    const r = verifyApprovalAssertion(challenge, a, key, { now });
    expect(r.valid).toBe(true);
    expect(r.userVerified).toBe(true);
    expect(r.signCount).toBe(1);
  });

  it('accepts a valid EdDSA assertion', () => {
    const { priv, key } = eddsa();
    const a = buildAssertion(-8, priv, challenge);
    expect(verifyApprovalAssertion(challenge, a, key, { now }).valid).toBe(true);
  });

  it('fails closed without a registered public key', () => {
    const { priv } = es256();
    const a = buildAssertion(-7, priv, challenge);
    const r = verifyApprovalAssertion(challenge, a, undefined, { now });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('missing_credential_public_key');
  });

  it('rejects a tampered signature', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge, { tamperSig: true });
    expect(verifyApprovalAssertion(challenge, a, key, { now }).reason).toBe('invalid_signature');
  });

  it('rejects a signature made for a different challenge', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge, { wrongChallenge: true });
    expect(verifyApprovalAssertion(challenge, a, key, { now }).reason).toBe('challenge_mismatch');
  });

  it('rejects a wrong origin', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge, { origin: 'https://evil.example' });
    expect(verifyApprovalAssertion(challenge, a, key, { now }).reason).toBe('origin_mismatch');
  });

  it('rejects a mismatched rpIdHash (phishing / wrong RP)', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge, { rpIdForAuthData: 'evil.example' });
    expect(verifyApprovalAssertion(challenge, a, key, { now }).reason).toBe('rp_id_hash_mismatch');
  });

  it('requires user verification by default', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge, { uv: false });
    expect(verifyApprovalAssertion(challenge, a, key, { now }).reason).toBe('user_verification_required');
    // but passes when UV is not required (a UP-only security key)
    expect(verifyApprovalAssertion(challenge, a, key, { now, requireUserVerification: false }).valid).toBe(true);
  });

  it('rejects user-not-present', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge, { up: false, uv: false });
    expect(verifyApprovalAssertion(challenge, a, key, { now }).reason).toBe('user_not_present');
  });

  it('detects a cloned authenticator via signCount regression', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge, { signCount: 5 });
    // a later assertion with a non-increasing counter is a clone signal
    expect(verifyApprovalAssertion(challenge, a, key, { now, prevSignCount: 5 }).reason).toBe('sign_count_regression');
    expect(verifyApprovalAssertion(challenge, a, key, { now, prevSignCount: 4 }).valid).toBe(true);
  });

  it('rejects an expired challenge', () => {
    const { priv, key } = es256();
    const a = buildAssertion(-7, priv, challenge);
    const late = new Date(challenge.createdAt).getTime() + challenge.timeoutSeconds * 1000 + 1;
    expect(verifyApprovalAssertion(challenge, a, key, { now: late }).reason).toBe('challenge_expired');
  });
});
