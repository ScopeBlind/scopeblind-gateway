/**
 * Evidence Authenticity via TLSNotary / zkTLS (Beta)
 *
 * ⚠️ BETA: This module defines the interface for evidence authenticity
 * proofs. The TLSNotary integration is planned for Q3 2026 when the
 * tooling stabilizes. The interface is stable and forward-compatible.
 *
 * Problem: When an agent fetches external data (API calls, web scraping)
 * and submits it as evidence to an Acta receipt, there's currently no
 * proof the data is authentic. The agent could fabricate the response.
 *
 * Solution: TLSNotary (tlsnotary.org) enables an agent to prove it
 * fetched specific data from a specific server without revealing
 * session cookies or API keys. The TLS session is notarized by a
 * third-party verifier, producing a cryptographic proof of authenticity.
 *
 * This module defines:
 * 1. The EvidenceAttestation format (for embedding in receipts)
 * 2. The verification interface (for checking attestations)
 * 3. Placeholder implementations that will be replaced with
 *    real TLSNotary integration when the SDK matures
 *
 * Usage:
 *   import { createEvidenceAttestation, verifyEvidenceAttestation } from './evidence-authenticity.js';
 *
 *   // Create an attestation for data fetched from an API
 *   const attestation = await createEvidenceAttestation({
 *     url: 'https://api.example.com/data',
 *     responseHash: sha256(responseBody),
 *     method: 'GET',
 *     timestamp: new Date().toISOString(),
 *   });
 *
 *   // Embed in receipt
 *   receipt.evidence_attestation = attestation;
 *
 *   // Verify
 *   const valid = await verifyEvidenceAttestation(attestation);
 */

import { createHash } from 'node:crypto';

/**
 * Evidence attestation format — embedded in receipts to prove
 * the authenticity of externally fetched data.
 */
export interface EvidenceAttestation {
  /** Version of the attestation format */
  version: '0.1-beta';
  /** Attestation method */
  method: 'self-reported' | 'tlsnotary' | 'oracle' | 'witness';
  /** URL that was fetched */
  url: string;
  /** HTTP method used */
  httpMethod: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** SHA-256 hash of the response body */
  responseHash: string;
  /** Response status code */
  statusCode: number;
  /** TLS server certificate fingerprint (SHA-256 of DER) */
  serverCertFingerprint?: string;
  /** Timestamp of the fetch */
  fetchedAt: string;
  /** Notary public key (for TLSNotary attestations) */
  notaryPublicKey?: string;
  /** Notary signature over the attestation */
  notarySignature?: string;
  /** Whether this attestation has been cryptographically verified */
  verified: boolean;
  /** Verification details */
  verificationNote: string;
}

/**
 * Input for creating an evidence attestation.
 */
export interface EvidenceAttestationInput {
  /** URL that was fetched */
  url: string;
  /** HTTP method */
  httpMethod?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** SHA-256 hash of the response body */
  responseHash: string;
  /** Response status code */
  statusCode?: number;
  /** Timestamp */
  timestamp?: string;
}

/**
 * Create an evidence attestation for externally fetched data.
 *
 * Current implementation: self-reported (the agent declares what it
 * fetched, but there's no third-party proof). This is clearly marked
 * as `method: 'self-reported'` in the attestation.
 *
 * Future: When TLSNotary SDK matures, this will produce
 * `method: 'tlsnotary'` attestations with cryptographic proofs.
 *
 * @param input - Details of the fetch to attest
 * @returns EvidenceAttestation for embedding in a receipt
 *
 * @patent Patent-protected construction — evidence authenticity attestation with
 * TLSNotary/zkTLS integration. Covered by Apache 2.0 patent grant for users of
 * this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export async function createEvidenceAttestation(
  input: EvidenceAttestationInput,
): Promise<EvidenceAttestation> {
  // Check if TLSNotary is available
  const tlsNotaryAvailable = await isTLSNotaryAvailable();

  if (tlsNotaryAvailable) {
    return createTLSNotaryAttestation(input);
  }

  // Fallback: self-reported attestation
  return {
    version: '0.1-beta',
    method: 'self-reported',
    url: input.url,
    httpMethod: input.httpMethod || 'GET',
    responseHash: input.responseHash,
    statusCode: input.statusCode || 200,
    fetchedAt: input.timestamp || new Date().toISOString(),
    verified: false,
    verificationNote: 'Self-reported attestation. No third-party verification. ' +
      'TLSNotary integration planned for Q3 2026.',
  };
}

/**
 * Verify an evidence attestation.
 *
 * For self-reported attestations, this always returns { valid: false }
 * with a note explaining that self-reported data cannot be verified.
 *
 * For TLSNotary attestations, this will verify the notary's signature
 * over the TLS session transcript.
 *
 * @patent Patent-protected construction — evidence authenticity attestation with
 * TLSNotary/zkTLS integration. Covered by Apache 2.0 patent grant for users of
 * this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export async function verifyEvidenceAttestation(
  attestation: EvidenceAttestation,
): Promise<{
  valid: boolean;
  method: string;
  note: string;
}> {
  switch (attestation.method) {
    case 'self-reported':
      return {
        valid: false,
        method: 'self-reported',
        note: 'Self-reported attestation cannot be independently verified. ' +
          'The response hash is included for integrity checking if the ' +
          'original data is available.',
      };

    case 'tlsnotary':
      // Future: verify notary signature
      if (!attestation.notaryPublicKey || !attestation.notarySignature) {
        return {
          valid: false,
          method: 'tlsnotary',
          note: 'TLSNotary attestation is missing notary public key or signature.',
        };
      }
      // Placeholder for TLSNotary verification
      return {
        valid: false,
        method: 'tlsnotary',
        note: 'TLSNotary verification not yet implemented. ' +
          'Attestation format is correct but signature cannot be checked.',
      };

    case 'oracle':
      return {
        valid: attestation.verified,
        method: 'oracle',
        note: attestation.verified
          ? 'Attestation verified by oracle service.'
          : 'Oracle verification pending or failed.',
      };

    case 'witness':
      return {
        valid: attestation.verified,
        method: 'witness',
        note: attestation.verified
          ? 'Attestation witnessed by independent third party.'
          : 'Witness verification pending.',
      };

    default:
      return {
        valid: false,
        method: 'unknown',
        note: 'Unknown attestation method.',
      };
  }
}

/**
 * Hash a response body for attestation.
 * Uses SHA-256 for consistency with the rest of the receipt format.
 */
export function hashResponseBody(body: string | Buffer): string {
  return createHash('sha256')
    .update(typeof body === 'string' ? body : body)
    .digest('hex');
}

/**
 * Create an attestation field for embedding in a receipt payload.
 * This is the format that goes into the `evidence_attestation`
 * field of an Acta receipt.
 *
 * @patent Patent-protected construction — evidence authenticity attestation with
 * TLSNotary/zkTLS integration. Covered by Apache 2.0 patent grant for users of
 * this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export function createAttestationField(attestation: EvidenceAttestation): {
  evidence_authenticity: {
    version: string;
    method: string;
    url_hash: string; // Hash of URL for privacy
    response_hash: string;
    fetched_at: string;
    verified: boolean;
    note: string;
  };
} {
  return {
    evidence_authenticity: {
      version: attestation.version,
      method: attestation.method,
      url_hash: createHash('sha256').update(attestation.url).digest('hex').slice(0, 16),
      response_hash: attestation.responseHash,
      fetched_at: attestation.fetchedAt,
      verified: attestation.verified,
      note: attestation.verificationNote,
    },
  };
}

// ── Internal helpers ──

async function isTLSNotaryAvailable(): Promise<boolean> {
  // Check if the TLSNotary WASM module is installed
  try {
    await import('tlsn-js' as string);
    return true;
  } catch {
    return false;
  }
}

async function createTLSNotaryAttestation(
  input: EvidenceAttestationInput,
): Promise<EvidenceAttestation> {
  // Placeholder for TLSNotary integration
  // When tlsn-js matures, this will:
  // 1. Create a TLS session with the target server
  // 2. Have a notary co-sign the session transcript
  // 3. Extract the response hash from the notarized transcript
  // 4. Return the attestation with the notary's signature

  return {
    version: '0.1-beta',
    method: 'tlsnotary',
    url: input.url,
    httpMethod: input.httpMethod || 'GET',
    responseHash: input.responseHash,
    statusCode: input.statusCode || 200,
    fetchedAt: input.timestamp || new Date().toISOString(),
    verified: false,
    verificationNote: 'TLSNotary SDK integration in progress. ' +
      'Attestation format is stable; verification will be enabled in a future release.',
  };
}
