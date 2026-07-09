/**
 * @scopeblind/protect-mcp — Signing Integration
 *
 * Produces signed v2 artifact receipts for tool call decisions.
 * Uses @veritasacta/artifacts as a required dependency (Sprint 2+).
 *
 * If signing is configured, every decision must produce a signed artifact.
 * Initialization and signing failures are returned as explicit errors so the
 * enforce path can deny rather than silently proceeding without evidence.
 */

import { readFileSync, existsSync } from 'node:fs';
import { createReceiptEnvelope, computeSbIssuerKid } from './acta-envelope.js';
import type { DecisionLog, SigningConfig, TrustTier } from './types.js';

/** Loaded signing state */
interface SignerState {
  privateKey: string;
  publicKey: string;
  kid: string;
  issuer: string;
}

let signerState: SignerState | null = null;
let signingConfigured = false;
let signingInitError: string | null = null;

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

  // Initialization is replace-not-merge. A config reload that disables
  // signing must not retain a previous key, and a failed reload must not fall
  // back to the previous signer.
  signerState = null;
  signingConfigured = Boolean(config && config.enabled !== false);
  signingInitError = null;

  if (!config || config.enabled === false) {
    return warnings;
  }

  // Validate and load the configured key before importing the signing library
  // so operators get the actionable configuration error first.
  if (!config.key_path) {
    signingInitError = 'signing enabled but key_path is not configured';
    warnings.push(`signing: ${signingInitError}`);
    return warnings;
  }
  if (!existsSync(config.key_path)) {
    signingInitError = `key file not found at ${config.key_path}`;
    warnings.push(`signing: ${signingInitError} — run "protect-mcp init" to generate`);
    return warnings;
  }

  let keyData: any;
  try {
    keyData = JSON.parse(readFileSync(config.key_path, 'utf-8'));
    if (!keyData.privateKey || !keyData.publicKey) {
      signingInitError = 'key file missing privateKey or publicKey fields';
      warnings.push(`signing: ${signingInitError}`);
      return warnings;
    }
  } catch (err) {
    signingInitError = `failed to load key file: ${err instanceof Error ? err.message : err}`;
    warnings.push(`signing: ${signingInitError}`);
    return warnings;
  }

  try {
    signerState = {
      privateKey: keyData.privateKey,
      publicKey: keyData.publicKey,
      // kid is opaque per draft-02; existing key files keep their explicit kid,
      // and keys without one get the s2.1.1 RECOMMENDED sb:issuer format.
      kid: keyData.kid || computeSbIssuerKid(keyData.publicKey),
      issuer: config.issuer || keyData.issuer || 'protect-mcp',
    };
  } catch (err) {
    signingInitError = `failed to initialize signer: ${err instanceof Error ? err.message : err}`;
    warnings.push(`signing: ${signingInitError} — enforce mode will fail closed`);
  }

  return warnings;
}

/**
 * Sign a decision log entry as a draft-02 Acta receipt envelope
 * ({ payload, signature: { alg, kid, sig } }), signed over the JCS bytes of
 * payload directly per draft s5.6.
 *
 * Returns the signed envelope JSON string, or null if signing is not
 * configured. On signing failure, returns an unsigned result with a warning.
 *
 * @param prevReceiptHash - Optional s5.7 chain link: the receiptHash of the
 *   previous line in the receipt log this envelope will be appended to.
 *
 * @standard draft-farley-acta-signed-receipts-02, RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
export function signDecision(entry: DecisionLog, prevReceiptHash?: string): {
  ok: boolean;            // true only when a signature was actually produced
  signed: string | null;
  artifact_type: string;
  receipt_hash?: string;  // s5.7 hash of the emitted envelope (chain link for the next receipt)
  warning?: string;
  error?: string;         // set only when a signer IS configured but signing failed
} {
  // Internal artifact class, kept for callers that branch on it. On the wire,
  // draft-02 s3.1 covers allow AND deny under one payload type
  // ("protectmcp:decision"); a deny is a first-class decision receipt, not a
  // separate envelope shape.
  const artifactType = entry.decision === 'deny' ? 'gateway_restraint' : 'decision_receipt';

  if (signingConfigured && signingInitError) {
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: `signing initialization failed: ${signingInitError}`,
      error: signingInitError,
    };
  }

  if (signingConfigured && !signerState) {
    const error = 'signing was configured but no signer is ready';
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: error,
      error,
    };
  }

  if (!signerState) {
    // No signer configured: legitimately unsigned (free/shadow tier). This is
    // NOT a failure — callers must not fail closed on it.
    return { ok: false, signed: null, artifact_type: 'none' };
  }

  try {
    const payload: Record<string, unknown> = {
      // draft-02 s3.1 access-decision fields
      type: 'protectmcp:decision',
      tool_name: entry.tool,
      decision: entry.decision,
      reason: entry.reason_code,
      policy_digest: entry.policy_digest,
      // Extension fields (signed alongside the s3.1 core)
      scope: entry.request_id, // request scope
      mode: entry.mode,
      request_id: entry.request_id,
      // Spec version: ties every receipt to the IETF standard
      spec: 'draft-farley-acta-signed-receipts-02',
      // Issuer certification: distinguishes VOPRF-backed receipts from self-signed ones
      // - scopeblind:verified  = issued via ScopeBlind VOPRF backend (paid tier)
      // - self-signed          = signed with local Ed25519 key (free tier, protect-mcp default)
      // - uncertified          = unsigned receipt (shadow mode, no signing configured)
      issuer_certification: signerState ? 'self-signed' : 'uncertified',
      // The signer's PUBLIC key, inside the signed payload, so a receipt is
      // self-contained: any verifier (including the record viewer, in-browser)
      // can check the signature without a side channel. Binding the key inside
      // the signature means it cannot be swapped without breaking the signature;
      // authenticity (that the key is YOUR gate's) still comes from pinning it.
      public_key: signerState.publicKey,
    };

    // Operator-facing issuer label; issuer_id (== kid) is the draft-02
    // identity and is set by createReceiptEnvelope.
    if (signerState.issuer && signerState.issuer !== signerState.kid) {
      payload.issuer_name = signerState.issuer;
    }
    if (prevReceiptHash) payload.previousReceiptHash = prevReceiptHash;

    if (entry.tier) payload.tier = entry.tier;
    if (entry.credential_ref) payload.credential_ref = entry.credential_ref;
    if (entry.rate_limit_remaining !== undefined) {
      payload.rate_limit_remaining = entry.rate_limit_remaining;
    }
    if (entry.policy_engine) payload.policy_engine = entry.policy_engine;

    // Extended fields from hook server
    if (entry.hook_event) payload.hook_event = entry.hook_event;
    if (entry.sandbox_state) payload.sandbox_state = entry.sandbox_state;
    if (entry.timing) payload.timing = entry.timing;
    if (entry.swarm) payload.swarm = entry.swarm;
    if (entry.payload_digest) payload.payload_digest = entry.payload_digest;
    if (entry.enrichment) payload.enrichment = entry.enrichment;
    if (entry.action_readback) payload.action_readback = entry.action_readback;
    if (entry.deny_iteration) payload.deny_iteration = entry.deny_iteration;

    const result = createReceiptEnvelope(
      payload as Record<string, unknown> & { type: string },
      signerState.privateKey,
      signerState.kid,
      Number.isFinite(entry.timestamp) ? new Date(entry.timestamp).toISOString() : undefined,
    );

    return {
      ok: true,
      signed: JSON.stringify(result.envelope),
      artifact_type: artifactType,
      receipt_hash: result.hash,
    };
  } catch (err) {
    // A signer IS configured but signing failed. Do not crash the process, but
    // mark this as a real failure (error set) so the decision path can fail
    // closed and the receipt log can record an auditable tombstone. A configured
    // gateway that cannot prove an action must not silently let it pass.
    const message = err instanceof Error ? err.message : 'unknown error';
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: `signing failed: ${message}`,
      error: message,
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
  return signingConfigured && signingInitError === null && signerState !== null;
}
