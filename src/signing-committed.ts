/**
 * @scopeblind/protect-mcp: Commitment-Mode Signing
 *
 * Produces commitment-mode signed receipts per draft-farley-acta-signed-receipts-01
 * §commitment-mode. Each listed field is independently committed via
 * SHA-256(0x00 || JCS({name, salt, value})), arranged into an RFC 6962-style
 * Merkle tree with explicit one-byte domain separation, and the receipt payload
 * carries a single committed_fields_root field instead of the cleartext values.
 *
 * The receipt holder retains openings (value + salt per field) and can selectively
 * disclose any subset to auditors via Merkle inclusion proofs verifiable by
 * @veritasacta/verify@>=0.6.0.
 *
 * This module sits alongside signing.ts (the legacy @veritasacta/artifacts-based
 * cleartext path) and is invoked when SigningConfig.commitment_mode.enabled is
 * true. The two paths are mutually exclusive on a per-receipt basis.
 *
 * @since 0.6.0
 * @standard draft-farley-acta-signed-receipts-01 §commitment-mode
 * @standard RFC 6962 (Certificate Transparency Merkle tree construction)
 * @standard RFC 8032 (Ed25519)
 * @standard RFC 8785 (JCS)
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { hashLeaf, merkleRoot, generateProof, type MerkleProof } from './commitments/merkle.js';
import { encodeLeaf, leavesFromFields, base64urlNoPad, type CommittedField } from './commitments/leaf.js';
import { jcs } from './commitments/primitives.js';
import type { DecisionLog } from './types.js';

// ============================================================
// Types
// ============================================================

/**
 * The opening information for a single committed field. Held by the
 * receipt issuer; never embedded in the published receipt. Required to
 * later produce a selective-disclosure proof.
 */
export interface CommittedFieldOpening {
  /** Field name (matches one of committed_field_names). */
  name: string;
  /** Cleartext value of the field. */
  value: unknown;
  /** Salt bytes (32 random bytes per field per receipt). */
  salt: Uint8Array;
  /** Zero-based index of the field in the canonically-sorted leaf list. */
  index: number;
}

/**
 * The result of signing a decision in commitment mode.
 */
export interface CommittedSignResult {
  /** The signed receipt as a JSON string (canonical wire form). */
  signed: string;
  /** Receipt artifact type, e.g. "decision_receipt_committed_v1". */
  artifact_type: string;
  /**
   * Per-field openings, indexed by field name. The issuer MUST persist
   * these securely if it intends to support selective disclosure later.
   * Storing them is the issuer's responsibility; this library does not
   * write them to disk.
   */
  openings: Record<string, CommittedFieldOpening>;
  /** Lowercase hex SHA-256 of the canonical signed receipt. */
  receipt_hash: string;
}

/**
 * A minimal selective-disclosure envelope. Reveal a single committed field
 * to an auditor by supplying its (name, value, salt, proof). The auditor
 * recomputes the leaf hash and walks the proof to confirm it reconstructs
 * the receipt's committed_fields_root.
 *
 * Compatible with @veritasacta/verify@>=0.6.0.
 */
export interface MinimalDisclosure {
  /** The receipt this disclosure targets, by canonical hash. */
  parent_receipt_hash: string;
  /** Disclosed field name. */
  name: string;
  /** Cleartext value of the disclosed field. */
  value: unknown;
  /** Salt as base64url (no padding). */
  salt: string;
  /** Merkle inclusion proof. */
  proof: MerkleProof;
}

// ============================================================
// Salt generation
// ============================================================

/**
 * Generate a fresh 32-byte random salt for a single field commitment.
 * Per draft-farley-acta-signed-receipts-01 §commitment-salt: per-receipt
 * random salts are RECOMMENDED. Implementations MAY use deterministic
 * derivation but MUST ensure cross-subject erasure isolation.
 */
function freshSalt(): Uint8Array {
  return randomBytes(32);
}

// ============================================================
// Signing
// ============================================================

/**
 * Sign a DecisionLog in commitment mode.
 *
 * @param entry - The decision log entry to sign.
 * @param committedFieldNames - Names of fields to commit. Recommended:
 *   ["tool", "scope", "payload_digest", "swarm"]. Fields not listed
 *   remain cleartext in the signed payload.
 * @param signingKey - Ed25519 private key (32 bytes hex or raw).
 * @param publicKey - Ed25519 public key (32 bytes hex).
 * @param kid - Key identifier (RFC 7638 JWK thumbprint or operator-chosen).
 * @param issuer - Issuer identifier (e.g. "my-gateway.example.com").
 *
 * @returns Signed receipt JSON, openings (per field), and receipt hash.
 *
 * @standard draft-farley-acta-signed-receipts-01 §signature-scope
 *   The signature covers SHA-256(JCS(payload_minus_signature)).
 */
export function signCommittedDecision(
  entry: DecisionLog,
  committedFieldNames: string[],
  signingKey: string,
  publicKey: string,
  kid: string,
  issuer: string,
): CommittedSignResult {
  // 1. Build the field list. Some fields are mandatory in the wire shape;
  //    only the ones in committedFieldNames get committed (replaced by the
  //    Merkle root). Others stay cleartext.
  const allFields: Record<string, unknown> = {
    tool: entry.tool,
    decision: entry.decision,
    reason_code: entry.reason_code,
    policy_digest: entry.policy_digest,
    scope: entry.request_id,
    mode: entry.mode,
    request_id: entry.request_id,
  };

  // Optional fields included only if present.
  if (entry.tier) allFields.tier = entry.tier;
  if (entry.credential_ref) allFields.credential_ref = entry.credential_ref;
  if (entry.rate_limit_remaining !== undefined) {
    allFields.rate_limit_remaining = entry.rate_limit_remaining;
  }
  if (entry.policy_engine) allFields.policy_engine = entry.policy_engine;
  if (entry.hook_event) allFields.hook_event = entry.hook_event;
  if (entry.sandbox_state) allFields.sandbox_state = entry.sandbox_state;
  if (entry.timing) allFields.timing = entry.timing;
  if (entry.swarm) allFields.swarm = entry.swarm;
  if (entry.payload_digest) allFields.payload_digest = entry.payload_digest;
  if (entry.deny_iteration) allFields.deny_iteration = entry.deny_iteration;

  // 2. Partition fields: committed vs cleartext.
  const committedFields: CommittedField[] = [];
  const cleartextFields: Record<string, unknown> = {};
  const openings: Record<string, CommittedFieldOpening> = {};

  for (const [name, value] of Object.entries(allFields)) {
    if (committedFieldNames.includes(name)) {
      const salt = freshSalt();
      committedFields.push({ name, salt, value });
    } else {
      cleartextFields[name] = value;
    }
  }

  // 3. Build the Merkle tree over committed fields (sorted canonically).
  let committedFieldsRoot: string | null = null;
  if (committedFields.length > 0) {
    const { sorted, leafBytes } = leavesFromFields(committedFields);
    const leafHashes = leafBytes.map(hashLeaf);
    const root = merkleRoot(leafHashes);
    committedFieldsRoot = bytesToHex(root);

    // Record openings keyed by field name with sorted index for proof generation.
    sorted.forEach((f, i) => {
      openings[f.name] = { name: f.name, value: f.value, salt: f.salt, index: i };
    });
  }

  // 4. Construct the signable payload.
  const payload: Record<string, unknown> = {
    type: 'scopeblind.receipt.committed.v1',
    spec: 'draft-farley-acta-signed-receipts-01',
    issuer_certification: 'self-signed',
    timestamp: new Date().toISOString(),
    ...cleartextFields,
  };
  if (committedFieldsRoot !== null) {
    payload.committed_fields_root = committedFieldsRoot;
    payload.committed_field_names = committedFields.map((f) => f.name);
  }

  // 5. Sign per draft-01 §signature-scope:
  //    signature = Sign(SHA-256(JCS(payload_minus_signature)))
  const canonical = jcs(payload);
  const messageHash = sha256(new TextEncoder().encode(canonical));
  const signatureBytes = ed25519.sign(messageHash, hexToBytes(signingKey));

  const signedReceipt = {
    ...payload,
    signature: {
      alg: 'EdDSA' as const,
      kid,
      issuer,
      sig: base64urlNoPad(signatureBytes),
      public_key: publicKey, // hex
    },
  };

  const signedJson = JSON.stringify(signedReceipt);
  const receiptHash = bytesToHex(sha256(new TextEncoder().encode(jcs(signedReceipt))));

  return {
    signed: signedJson,
    artifact_type: 'decision_receipt_committed_v1',
    openings,
    receipt_hash: receiptHash,
  };
}

// ============================================================
// Disclosure
// ============================================================

/**
 * Build a minimal selective-disclosure envelope for a single committed
 * field. The envelope can be verified offline by anyone who has the
 * receipt's committed_fields_root (which the receipt itself carries).
 *
 * @param receiptHash - Canonical hash of the receipt the disclosure targets.
 * @param fieldName - Which field to disclose.
 * @param openings - The full openings map produced by signCommittedDecision.
 *
 * @standard draft-farley-acta-signed-receipts-01 §commitment-disclosure
 */
export function discloseField(
  receiptHash: string,
  fieldName: string,
  openings: Record<string, CommittedFieldOpening>,
): MinimalDisclosure {
  const o = openings[fieldName];
  if (!o) {
    throw new Error(`disclose: no opening recorded for field "${fieldName}"`);
  }

  // Reconstruct the canonical leaf list from openings to generate a proof.
  const fields: CommittedField[] = Object.values(openings).map((op) => ({
    name: op.name,
    salt: op.salt,
    value: op.value,
  }));
  const { leafBytes } = leavesFromFields(fields);
  const leafHashes = leafBytes.map(hashLeaf);
  const proof = generateProof(leafHashes, o.index);

  return {
    parent_receipt_hash: receiptHash,
    name: fieldName,
    value: o.value,
    salt: base64urlNoPad(o.salt),
    proof,
  };
}
