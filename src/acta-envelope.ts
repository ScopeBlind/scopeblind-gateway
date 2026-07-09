/**
 * @scopeblind/protect-mcp — Acta draft-02 receipt envelope
 *
 * Implements the signed-receipt envelope from draft-farley-acta-signed-receipts-02:
 *
 *   { "payload": { "type", "issued_at", "issuer_id", ... },
 *     "signature": { "alg": "EdDSA", "kid", "sig" } }
 *
 * Conformance points (section references are to the published draft-02 text):
 *  - s2.1/s2.1.1: two-field envelope; alg "EdDSA" is mandatory-to-implement;
 *    sig is 128 lowercase hex chars; kid RECOMMENDED format
 *    sb:issuer:<first 12 Base58 chars of the Ed25519 public key>.
 *  - s2.2: payload common fields type / issued_at / issuer_id, and issuer_id
 *    MUST match signature.kid.
 *  - s4.1/s5.6: the signature covers the JCS-canonical bytes of payload
 *    directly (PureEdDSA, no intermediate hash).
 *  - s5.7: previousReceiptHash is the bare lowercase hex SHA-256 of the JCS
 *    bytes of the predecessor's ENTIRE envelope, signature included.
 *
 * Verification is dual-shape: envelopes produced by protect-mcp <= 0.9.x
 * (flat v1 artifacts and structured v2 artifacts with a top-level signature
 * string) continue to verify, so receipt logs written before the migration
 * remain checkable with the same tooling.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

/** The receipt envelope shape a verification resolved to. */
export type ReceiptShape = 'acta-02' | 'legacy-v2' | 'legacy-v1';

export interface ActaSignature {
  alg: 'EdDSA';
  kid: string;
  sig: string;
}

export interface ActaEnvelope {
  payload: Record<string, unknown>;
  signature: ActaSignature;
}

/**
 * Deterministic JSON serialization (JCS-style: keys sorted at every level).
 * ASCII-only keys enforced, matching the ingest rule used across the stack.
 */
export function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        if (!/^[\x20-\x7E]*$/.test(k)) {
          throw new Error(`Non-ASCII key "${k}" in receipt payload. Only ASCII keys are permitted.`);
        }
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  });
}

/**
 * s5.7 chain hash: lowercase hex SHA-256 over the JCS bytes of the object
 * exactly as written (for a signed envelope, signature included). Applied
 * uniformly to any receipt-log line (including legacy envelopes and signing
 * tombstones) so a chain can span the migration boundary.
 */
export function receiptHash(obj: unknown): string {
  return bytesToHex(sha256(utf8ToBytes(canonicalize(obj))));
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58(bytes: Uint8Array): string {
  let n = BigInt('0x' + bytesToHex(bytes));
  let out = '';
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out;
}

/**
 * s2.1.1 RECOMMENDED kid format: sb:issuer:<first 12 Base58 chars of the
 * Ed25519 public key>. Existing key files that carry an explicit kid keep it
 * (kid is an opaque string per the draft); this is the default for new keys.
 */
export function computeSbIssuerKid(publicKeyHex: string): string {
  return `sb:issuer:${base58(hexToBytes(publicKeyHex)).slice(0, 12)}`;
}

/**
 * Create a signed draft-02 receipt envelope.
 *
 * The caller provides the payload fields (including `type`); issued_at and
 * issuer_id are filled in if absent, and issuer_id is forced to equal kid
 * per s2.2.
 */
export function createReceiptEnvelope(
  fields: Record<string, unknown> & { type: string },
  privateKeyHex: string,
  kid: string,
  issuedAt?: string,
): { envelope: ActaEnvelope; hash: string } {
  if (!fields.type) throw new Error('receipt payload requires a type');
  if (!kid) throw new Error('kid is required');

  const payload: Record<string, unknown> = {
    ...fields,
    issued_at: (fields.issued_at as string) || issuedAt || new Date().toISOString(),
    issuer_id: kid,
  };

  const sig = bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), hexToBytes(privateKeyHex)));
  const envelope: ActaEnvelope = { payload, signature: { alg: 'EdDSA', kid, sig } };
  return { envelope, hash: receiptHash(envelope) };
}

/**
 * Verify a receipt envelope of any shape this stack has ever emitted.
 *
 *  - acta-02: signature is an object; verify sig over JCS(payload). Only
 *    "EdDSA" is accepted (s2.1.1 MTI; this implementation supports no other).
 *  - legacy (v1 flat / v2 structured): signature is a top-level string;
 *    verify over JCS(envelope minus signature), exactly as
 *    @veritasacta/artifacts <= 0.2.x did.
 */
export function verifyReceipt(
  envelope: unknown,
  publicKeyHex: string,
): { valid: boolean; shape: ReceiptShape | null; hash?: string; error?: string } {
  try {
    if (!envelope || typeof envelope !== 'object') {
      return { valid: false, shape: null, error: 'not_an_object' };
    }
    const env = envelope as Record<string, unknown>;
    const signature = env.signature;

    if (signature && typeof signature === 'object' && !Array.isArray(signature)) {
      const sigObj = signature as Record<string, unknown>;
      if (sigObj.alg !== 'EdDSA') {
        return { valid: false, shape: 'acta-02', error: `unsupported_alg:${String(sigObj.alg)}` };
      }
      if (typeof sigObj.sig !== 'string' || !env.payload || typeof env.payload !== 'object') {
        return { valid: false, shape: 'acta-02', error: 'malformed_envelope' };
      }
      const message = utf8ToBytes(canonicalize(env.payload));
      const valid = ed25519.verify(hexToBytes(sigObj.sig), message, hexToBytes(publicKeyHex));
      return valid
        ? { valid: true, shape: 'acta-02', hash: receiptHash(env) }
        : { valid: false, shape: 'acta-02', error: 'invalid_signature' };
    }

    if (typeof signature === 'string') {
      const rest: Record<string, unknown> = {};
      for (const k of Object.keys(env)) if (k !== 'signature') rest[k] = env[k];
      const message = utf8ToBytes(canonicalize(rest));
      const valid = ed25519.verify(hexToBytes(signature), message, hexToBytes(publicKeyHex));
      const shape: ReceiptShape = env.v === 2 ? 'legacy-v2' : 'legacy-v1';
      return valid
        ? { valid: true, shape, hash: receiptHash(env) }
        : { valid: false, shape, error: 'invalid_signature' };
    }

    return { valid: false, shape: null, error: 'missing_signature' };
  } catch (err) {
    return {
      valid: false,
      shape: null,
      error: `verification_error:${err instanceof Error ? err.message : 'unknown'}`,
    };
  }
}

/** Extract kid/issuer identity from any envelope shape, for display paths. */
export function receiptIdentity(envelope: unknown): { kid: string | null; issuer: string | null; type: string | null } {
  if (!envelope || typeof envelope !== 'object') return { kid: null, issuer: null, type: null };
  const env = envelope as Record<string, unknown>;
  if (env.signature && typeof env.signature === 'object') {
    const payload = (env.payload || {}) as Record<string, unknown>;
    const sig = env.signature as Record<string, unknown>;
    return {
      kid: typeof sig.kid === 'string' ? sig.kid : null,
      issuer: typeof payload.issuer_id === 'string' ? payload.issuer_id
        : typeof payload.issuer_name === 'string' ? payload.issuer_name : null,
      type: typeof payload.type === 'string' ? payload.type : null,
    };
  }
  return {
    kid: typeof env.kid === 'string' ? env.kid : null,
    issuer: typeof env.issuer === 'string' ? env.issuer : null,
    type: typeof env.type === 'string' ? env.type : null,
  };
}
