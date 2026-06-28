/**
 * primitives.ts
 *
 * Core cryptographic building blocks for commitment-based receipts.
 *
 * Commitment construction:  H(salt || value_bytes)  where H = SHA-256.
 *
 * This follows the same salt-hash pattern used in SD-JWT
 * (draft-ietf-oauth-selective-disclosure-jwt), adapted for chained
 * audit logs rather than bearer tokens.
 *
 * Properties:
 *   Hiding:   without the salt, the value cannot be recovered (pre-image resistance).
 *   Binding:  the committer cannot find (value', salt') producing the same hash (collision resistance).
 *   PQ-safe:  SHA-256 provides 128-bit security against quantum pre-image and collision attacks.
 *
 * Salt derivation uses HMAC-SHA256 as a PRF so the receipt owner stores
 * a single master secret rather than per-field salts for every receipt.
 */

import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils";

export { bytesToHex, hexToBytes, randomBytes };

/**
 * Create a hash commitment: H(salt || value_bytes).
 *
 * Salt is prepended (matching SD-JWT convention) so that the commitment
 * is domain-separated by the random bytes before the attacker-controlled
 * value bytes begin.
 */
export function commit(value: string, salt: Uint8Array): string {
  const valueBytes = new TextEncoder().encode(value);
  const payload = new Uint8Array(salt.length + valueBytes.length);
  payload.set(salt);
  payload.set(valueBytes, salt.length);
  return bytesToHex(sha256(payload));
}

/**
 * Verify that a (value, salt) pair opens a commitment.
 * Returns true if H(salt || value) matches the commitment.
 */
export function openCommitment(
  commitment: string,
  value: string,
  salt: Uint8Array,
): boolean {
  return commit(value, salt) === commitment;
}

/**
 * Derive a per-field salt deterministically via HMAC-SHA256.
 *
 *   salt = HMAC-SHA256(masterSecret, "commitment-receipt:{sequence}:{fieldName}")
 *
 * Losing the master secret means all commitments become permanently
 * unopenable. This is a feature for GDPR Article 17 (right to erasure):
 * destroy the master secret and the committed data is cryptographically
 * irrecoverable while the chain remains verifiable.
 */
export function deriveSalt(
  masterSecret: Uint8Array,
  sequence: number,
  fieldName: string,
): Uint8Array {
  const info = new TextEncoder().encode(
    `commitment-receipt:${sequence}:${fieldName}`,
  );
  return hmac(sha256, masterSecret, info);
}

/**
 * Minimal JCS (RFC 8785) canonicalization.
 * Sorts object keys lexicographically at every nesting depth.
 */
export function jcs(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean" || typeof value === "number")
    return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(jcs).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(obj[k])).join(",") + "}"
  );
}
