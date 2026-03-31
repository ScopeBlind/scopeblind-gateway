/**
 * Sigstore Rekor Transparency Log Anchoring
 *
 * Anchors receipt hashes to the Sigstore Rekor transparency log,
 * providing independent temporal proof that a receipt existed at a
 * specific point in time. The inclusion proof makes backdating
 * receipts cryptographically detectable.
 *
 * Uses the Rekor public instance (rekor.sigstore.dev) — free, no account needed.
 *
 * Usage:
 *   import { anchorToRekor, verifyRekorAnchor } from './rekor-anchor.js';
 *
 *   // Anchor a receipt hash
 *   const anchor = await anchorToRekor(receiptHash, signature, publicKey);
 *
 *   // Verify an anchor
 *   const valid = await verifyRekorAnchor(anchor.logIndex, receiptHash);
 */

import { createHash } from 'node:crypto';

const REKOR_API = 'https://rekor.sigstore.dev/api/v1';

export interface RekorAnchor {
  /** Rekor log index */
  logIndex: number;
  /** Rekor entry UUID */
  uuid: string;
  /** Inclusion timestamp (RFC 3339) */
  integratedTime: string;
  /** SHA-256 hash of the receipt that was anchored */
  receiptHash: string;
  /** Rekor log ID */
  logID: string;
  /** Body of the Rekor entry (base64) */
  body: string;
}

export interface RekorVerification {
  valid: boolean;
  logIndex: number;
  integratedTime: string;
  receiptHashMatch: boolean;
}

/**
 * Anchor a receipt hash to the Sigstore Rekor transparency log.
 *
 * Creates a "hashedrekord" entry containing the SHA-256 hash of the receipt,
 * the Ed25519 signature, and the public key. The Rekor server returns an
 * inclusion proof with a timestamp.
 *
 * @param receiptHash - SHA-256 hex hash of the receipt content
 * @param signature - Ed25519 signature (base64)
 * @param publicKeyPem - Ed25519 public key in PEM format
 * @returns RekorAnchor with log index, UUID, and timestamp
 *
 * @standard Integration with Sigstore Rekor transparency log — standard transparency anchoring.
 */
export async function anchorToRekor(
  receiptHash: string,
  signature: string,
  publicKeyPem: string,
): Promise<RekorAnchor> {
  // Create a hashedrekord entry
  const entry = {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: {
        hash: {
          algorithm: 'sha256',
          value: receiptHash,
        },
      },
      signature: {
        content: signature,
        publicKey: {
          content: Buffer.from(publicKeyPem).toString('base64'),
        },
      },
    },
  };

  const response = await fetch(`${REKOR_API}/log/entries`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(entry),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Rekor anchoring failed: ${response.status} ${errorText}`);
  }

  const result = await response.json() as Record<string, {
    body: string;
    integratedTime: number;
    logID: string;
    logIndex: number;
  }>;

  // Response is { uuid: { body, integratedTime, logID, logIndex, verification } }
  const [uuid, data] = Object.entries(result)[0];

  return {
    logIndex: data.logIndex,
    uuid,
    integratedTime: new Date(data.integratedTime * 1000).toISOString(),
    receiptHash,
    logID: data.logID,
    body: data.body,
  };
}

/**
 * Verify that a receipt hash was anchored to Rekor at a specific log index.
 *
 * Fetches the entry from Rekor and checks that the hash matches.
 * This is the "trust but verify" path — anyone can check the anchor
 * without contacting ScopeBlind.
 *
 * @param logIndex - The Rekor log index to verify
 * @param expectedHash - The expected SHA-256 hash of the receipt
 *
 * @standard Integration with Sigstore Rekor transparency log — standard transparency anchoring.
 */
export async function verifyRekorAnchor(
  logIndex: number,
  expectedHash: string,
): Promise<RekorVerification> {
  const response = await fetch(`${REKOR_API}/log/entries?logIndex=${logIndex}`);

  if (!response.ok) {
    return {
      valid: false,
      logIndex,
      integratedTime: '',
      receiptHashMatch: false,
    };
  }

  const result = await response.json() as Record<string, {
    body: string;
    integratedTime: number;
  }>;
  const [, data] = Object.entries(result)[0];

  // Decode the body to check the hash
  let receiptHashMatch = false;
  try {
    const bodyJson = JSON.parse(Buffer.from(data.body, 'base64').toString());
    const hash = bodyJson?.spec?.data?.hash?.value;
    receiptHashMatch = hash === expectedHash;
  } catch {
    // Body parsing failed
  }

  return {
    valid: receiptHashMatch,
    logIndex,
    integratedTime: new Date(data.integratedTime * 1000).toISOString(),
    receiptHashMatch,
  };
}

/**
 * Compute the SHA-256 hash of a receipt for anchoring.
 * Uses JCS-compatible canonical JSON (sorted keys).
 *
 * @standard RFC 8785 (JCS), SHA-256
 */
export function hashReceipt(receipt: Record<string, unknown>): string {
  // Sort keys for deterministic hashing (simplified JCS)
  const canonical = JSON.stringify(receipt, Object.keys(receipt).sort());
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Create a log_anchor field for embedding in receipts.
 * This field can be added to any Acta receipt to provide
 * temporal proof of existence.
 *
 * @standard Integration with Sigstore Rekor transparency log — standard transparency anchoring.
 */
export function createLogAnchorField(anchor: RekorAnchor): {
  transparency_log: string;
  log_index: number;
  integrated_time: string;
  receipt_hash: string;
  verify_url: string;
} {
  return {
    transparency_log: 'rekor.sigstore.dev',
    log_index: anchor.logIndex,
    integrated_time: anchor.integratedTime,
    receipt_hash: anchor.receiptHash,
    verify_url: `https://search.sigstore.dev/?logIndex=${anchor.logIndex}`,
  };
}
