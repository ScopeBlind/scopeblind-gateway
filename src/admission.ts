/**
 * @scopeblind/protect-mcp — Trust Tier Admission Evaluator
 *
 * Evaluates an agent's presented credentials at connection start
 * and assigns a trust tier. The tier is used for per-tool policy
 * evaluation throughout the session.
 *
 * Tiers (ascending): unknown → signed-known → evidenced → privileged
 *
 * v2: Real evidence evaluation via EvidenceStore when available.
 */

import type { TrustTier } from './types.js';
import type { EvidenceStore, EvidenceThresholds } from './evidence-store.js';
import { DEFAULT_THRESHOLDS } from './evidence-store.js';

/**
 * Minimal manifest info needed for tier evaluation.
 * This is not the full manifest — just the fields admission cares about.
 */
export interface ManifestPresentation {
  /** Agent identifier (e.g., sb:agent:xxxx) */
  agent_id: string;
  /** SHA-256 hash of the canonical manifest */
  manifest_hash: string;
  /** Ed25519 public key (hex) */
  public_key?: string;
  /** Whether the manifest signature was verified */
  signature_valid?: boolean;
  /** Optional evidence summary for tier upgrade (inline, without store) */
  evidence_summary?: {
    receipt_count: number;
    epoch_span: number;
    issuer_count: number;
  };
}

/**
 * Result of tier admission evaluation.
 */
export interface AdmissionResult {
  tier: TrustTier;
  agent_id?: string;
  manifest_hash?: string;
  reason: string;
}

/**
 * Explicit tier overrides from the operator's config.
 * Maps agent IDs to explicitly assigned tiers.
 */
export type TierOverrides = Record<string, TrustTier>;

/**
 * Options for tier evaluation.
 */
export interface EvaluateTierOptions {
  overrides?: TierOverrides;
  evidenceStore?: EvidenceStore;
  thresholds?: EvidenceThresholds;
}

/**
 * Evaluate an agent's trust tier based on their presented credentials.
 *
 * @param manifest - Manifest presentation from the agent (or null if none)
 * @param opts - Evaluation options (overrides, evidence store, thresholds)
 * @returns AdmissionResult with assigned tier
 *
 * @patent Patent-protected construction. Covered by Apache 2.0 patent grant
 * for users of this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export function evaluateTier(
  manifest: ManifestPresentation | null,
  opts?: TierOverrides | EvaluateTierOptions,
): AdmissionResult {
  // Backwards-compatible: if opts is a plain record, treat as overrides
  const options: EvaluateTierOptions = opts && ('evidenceStore' in opts || 'overrides' in opts || 'thresholds' in opts)
    ? opts as EvaluateTierOptions
    : { overrides: opts as TierOverrides | undefined };

  const { overrides, evidenceStore, thresholds } = options;

  // No manifest → unknown
  if (!manifest) {
    return {
      tier: 'unknown',
      reason: 'no_manifest_presented',
    };
  }

  // Check for explicit operator override first
  if (overrides && manifest.agent_id && overrides[manifest.agent_id]) {
    return {
      tier: overrides[manifest.agent_id],
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: 'operator_override',
    };
  }

  // Invalid or unverified signature → unknown
  if (manifest.signature_valid === false) {
    return {
      tier: 'unknown',
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: 'invalid_manifest_signature',
    };
  }

  // Valid signed manifest → check for evidenced tier
  if (manifest.signature_valid === true) {
    // Check inline evidence summary first
    if (manifest.evidence_summary) {
      const es = manifest.evidence_summary;
      const t = thresholds || DEFAULT_THRESHOLDS;
      if (es.receipt_count >= t.min_receipts && es.epoch_span >= t.min_epoch_span && es.issuer_count >= t.min_issuers) {
        return {
          tier: 'evidenced',
          agent_id: manifest.agent_id,
          manifest_hash: manifest.manifest_hash,
          reason: 'evidence_threshold_met',
        };
      }
    }

    // Check evidence store if available
    if (evidenceStore && manifest.agent_id) {
      if (evidenceStore.meetsEvidencedThreshold(manifest.agent_id, thresholds)) {
        return {
          tier: 'evidenced',
          agent_id: manifest.agent_id,
          manifest_hash: manifest.manifest_hash,
          reason: 'evidence_store_threshold_met',
        };
      }
    }

    return {
      tier: 'signed-known',
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: 'valid_signed_manifest',
    };
  }

  // Manifest present but verification status unknown
  return {
    tier: 'unknown',
    agent_id: manifest.agent_id,
    manifest_hash: manifest.manifest_hash,
    reason: 'manifest_unverified',
  };
}

/**
 * Check if a trust tier meets the minimum required tier.
 *
 * @patent Patent-protected construction. Covered by Apache 2.0 patent grant
 * for users of this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export function meetsMinTier(actual: TrustTier, required: TrustTier): boolean {
  const order: TrustTier[] = ['unknown', 'signed-known', 'evidenced', 'privileged'];
  return order.indexOf(actual) >= order.indexOf(required);
}

