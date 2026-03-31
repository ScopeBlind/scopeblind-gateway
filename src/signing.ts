/**
 * @scopeblind/protect-mcp — Signing Integration
 *
 * Produces signed v2 artifact receipts for tool call decisions.
 * Uses @veritasacta/artifacts as a required dependency (Sprint 2+).
 *
 * If signing is configured, every decision produces a signed artifact.
 * If signing fails, the receipt is emitted unsigned with signature: null
 * and a warning — never crashes, never silently drops.
 */

import { readFileSync, existsSync } from 'node:fs';
import type { DecisionLog, SigningConfig, TrustTier } from './types.js';

/** Loaded signing state */
interface SignerState {
  privateKey: string;
  publicKey: string;
  kid: string;
  issuer: string;
}

let signerState: SignerState | null = null;
let artifactsModule: any | null = null;

/**
 * Get the current signer identity (kid, publicKey, issuer).
 * Returns null if signing is not initialized.
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
export function getSignerIdentity(): { kid: string; publicKey: string; issuer: string } | null {
  if (!signerState) return null;
  return { kid: signerState.kid, publicKey: signerState.publicKey, issuer: signerState.issuer };
}

/**
 * Initialize the signing subsystem.
 * Loads the key file and dynamically imports @veritasacta/artifacts.
 *
 * @param config - Signing configuration
 * @returns Array of warnings (empty = success)
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
export async function initSigning(config: SigningConfig | undefined): Promise<string[]> {
  const warnings: string[] = [];

  if (!config || config.enabled === false) {
    return warnings;
  }

  // Load @veritasacta/artifacts (dynamic, optional dependency)
  try {
    // Use a variable to prevent TypeScript from statically resolving the import
    const moduleName = '@veritasacta/artifacts';
    artifactsModule = await import(/* @vite-ignore */ moduleName);
  } catch {
    warnings.push('signing: @veritasacta/artifacts not available — receipts will be unsigned');
    return warnings;
  }

  // Load key file
  if (config.key_path) {
    if (!existsSync(config.key_path)) {
      warnings.push(`signing: key file not found at ${config.key_path} — run "protect-mcp init" to generate`);
      return warnings;
    }

    try {
      const keyData = JSON.parse(readFileSync(config.key_path, 'utf-8'));
      if (!keyData.privateKey || !keyData.publicKey) {
        warnings.push('signing: key file missing privateKey or publicKey fields');
        return warnings;
      }

      signerState = {
        privateKey: keyData.privateKey,
        publicKey: keyData.publicKey,
        kid: keyData.kid || artifactsModule.computeKid(keyData.publicKey),
        issuer: config.issuer || keyData.issuer || 'protect-mcp',
      };
    } catch (err) {
      warnings.push(`signing: failed to load key file: ${err instanceof Error ? err.message : err}`);
    }
  }

  return warnings;
}

/**
 * Sign a decision log entry as a v2 artifact.
 *
 * Returns the signed artifact JSON string, or null if signing is not configured.
 * On signing failure, returns an unsigned artifact with a warning.
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
export function signDecision(entry: DecisionLog): {
  signed: string | null;
  artifact_type: string;
  warning?: string;
} {
  if (!signerState || !artifactsModule) {
    return { signed: null, artifact_type: 'none' };
  }

  const artifactType = entry.decision === 'deny' ? 'gateway_restraint' : 'decision_receipt';

  try {
    const payload: Record<string, unknown> = {
      tool: entry.tool,
      decision: entry.decision,
      reason_code: entry.reason_code,
      policy_digest: entry.policy_digest,
      scope: entry.request_id, // request scope
      mode: entry.mode,
      request_id: entry.request_id,
    };

    if (entry.tier) payload.tier = entry.tier;
    if (entry.credential_ref) payload.credential_ref = entry.credential_ref;
    if (entry.rate_limit_remaining !== undefined) {
      payload.rate_limit_remaining = entry.rate_limit_remaining;
    }
    if (entry.policy_engine) payload.policy_engine = entry.policy_engine;

    const result = artifactsModule.createSignedArtifact(
      artifactType,
      payload,
      signerState.privateKey,
      {
        kid: signerState.kid,
        issuer: signerState.issuer,
      },
    );

    return {
      signed: JSON.stringify(result.artifact),
      artifact_type: artifactType,
    };
  } catch (err) {
    // Never crash on signing failure — emit unsigned with warning
    return {
      signed: null,
      artifact_type: artifactType,
      warning: `signing failed: ${err instanceof Error ? err.message : 'unknown error'}`,
    };
  }
}

/**
 * Get the signer's public key info for discovery/verification.
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
export function getSignerInfo(): {
  publicKey: string;
  kid: string;
  issuer: string;
} | null {
  if (!signerState) return null;
  return {
    publicKey: signerState.publicKey,
    kid: signerState.kid,
    issuer: signerState.issuer,
  };
}

/**
 * Check if signing is available.
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
export function isSigningEnabled(): boolean {
  return signerState !== null && artifactsModule !== null;
}
