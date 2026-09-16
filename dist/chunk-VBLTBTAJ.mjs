import {
  computeSbIssuerKid,
  createReceiptEnvelope
} from "./chunk-6JTYFG2X.mjs";

// src/signing.ts
import { readFileSync, existsSync } from "fs";
var signerState = null;
var signingConfigured = false;
var signingInitError = null;
async function initSigning(config) {
  const warnings = [];
  signerState = null;
  signingConfigured = Boolean(config && config.enabled !== false);
  signingInitError = null;
  if (!config || config.enabled === false) {
    return warnings;
  }
  if (!config.key_path) {
    signingInitError = "signing enabled but key_path is not configured";
    warnings.push(`signing: ${signingInitError}`);
    return warnings;
  }
  if (!existsSync(config.key_path)) {
    signingInitError = `key file not found at ${config.key_path}`;
    warnings.push(`signing: ${signingInitError} \u2014 run "protect-mcp init" to generate`);
    return warnings;
  }
  let keyData;
  try {
    keyData = JSON.parse(readFileSync(config.key_path, "utf-8"));
    if (!keyData.privateKey || !keyData.publicKey) {
      signingInitError = "key file missing privateKey or publicKey fields";
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
      issuer: config.issuer || keyData.issuer || "protect-mcp"
    };
  } catch (err) {
    signingInitError = `failed to initialize signer: ${err instanceof Error ? err.message : err}`;
    warnings.push(`signing: ${signingInitError} \u2014 enforce mode will fail closed`);
  }
  return warnings;
}
function signDecision(entry, prevReceiptHash) {
  const artifactType = entry.decision === "deny" ? "gateway_restraint" : "decision_receipt";
  if (signingConfigured && signingInitError) {
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: `signing initialization failed: ${signingInitError}`,
      error: signingInitError
    };
  }
  if (signingConfigured && !signerState) {
    const error = "signing was configured but no signer is ready";
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: error,
      error
    };
  }
  if (!signerState) {
    return { ok: false, signed: null, artifact_type: "none" };
  }
  try {
    const payload = {
      // draft-02 s3.1 access-decision fields
      type: "protectmcp:decision",
      tool_name: entry.tool,
      decision: entry.decision,
      reason: entry.reason_code,
      policy_digest: entry.policy_digest,
      // Extension fields (signed alongside the s3.1 core)
      scope: entry.request_id,
      // request scope
      mode: entry.mode,
      request_id: entry.request_id,
      // Spec version: ties every receipt to the IETF standard
      spec: "draft-farley-acta-signed-receipts-03",
      // Issuer certification: distinguishes VOPRF-backed receipts from self-signed ones
      // - scopeblind:verified  = issued via ScopeBlind VOPRF backend (paid tier)
      // - self-signed          = signed with local Ed25519 key (free tier, protect-mcp default)
      // - uncertified          = unsigned receipt (shadow mode, no signing configured)
      issuer_certification: signerState ? "self-signed" : "uncertified",
      // The signer's PUBLIC key, inside the signed payload, so a receipt is
      // self-contained: any verifier (including the record viewer, in-browser)
      // can check the signature without a side channel. Binding the key inside
      // the signature means it cannot be swapped without breaking the signature;
      // authenticity (that the key is YOUR gate's) still comes from pinning it.
      public_key: signerState.publicKey
    };
    if (signerState.issuer && signerState.issuer !== signerState.kid) {
      payload.issuer_name = signerState.issuer;
    }
    if (prevReceiptHash) payload.previousReceiptHash = prevReceiptHash;
    if (entry.tier) payload.tier = entry.tier;
    if (entry.credential_ref) payload.credential_ref = entry.credential_ref;
    if (entry.rate_limit_remaining !== void 0) {
      payload.rate_limit_remaining = entry.rate_limit_remaining;
    }
    if (entry.policy_engine) payload.policy_engine = entry.policy_engine;
    if (entry.hook_event) payload.hook_event = entry.hook_event;
    if (entry.sandbox_state) payload.sandbox_state = entry.sandbox_state;
    if (entry.timing) payload.timing = entry.timing;
    if (entry.swarm) payload.swarm = entry.swarm;
    if (entry.payload_digest) payload.payload_digest = entry.payload_digest;
    if (entry.enrichment) payload.enrichment = entry.enrichment;
    if (entry.action_readback) payload.action_readback = entry.action_readback;
    if (entry.deny_iteration) payload.deny_iteration = entry.deny_iteration;
    if (entry.mandate_registry) payload.mandate_registry = entry.mandate_registry;
    if (entry.standard) payload.standard = entry.standard;
    if (entry.approval) payload.approval = entry.approval;
    const result = createReceiptEnvelope(
      payload,
      signerState.privateKey,
      signerState.kid,
      Number.isFinite(entry.timestamp) ? new Date(entry.timestamp).toISOString() : void 0
    );
    return {
      ok: true,
      signed: JSON.stringify(result.envelope),
      artifact_type: artifactType,
      receipt_hash: result.hash
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown error";
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: `signing failed: ${message}`,
      error: message
    };
  }
}
function signGenericArtifact(_artifactType, payload) {
  if (signingConfigured && signingInitError) {
    return { ok: false, signed: null, warning: `signing initialization failed: ${signingInitError}`, error: signingInitError };
  }
  if (signingConfigured && !signerState) {
    const error = "signing was configured but no signer is ready";
    return { ok: false, signed: null, warning: error, error };
  }
  if (!signerState) {
    return { ok: false, signed: null };
  }
  try {
    const full = {
      ...payload,
      type: String(payload.type || "protectmcp:artifact"),
      public_key: signerState.publicKey
    };
    if (signerState.issuer && signerState.issuer !== signerState.kid && full.type !== "scopeblind.egress_summary.v1") {
      full.issuer_name = signerState.issuer;
    }
    const result = createReceiptEnvelope(full, signerState.privateKey, signerState.kid);
    return { ok: true, signed: JSON.stringify(result.envelope) };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown error";
    return { ok: false, signed: null, warning: `signing failed: ${message}`, error: message };
  }
}
function getSignerInfo() {
  if (!signerState) return null;
  return {
    publicKey: signerState.publicKey,
    kid: signerState.kid,
    issuer: signerState.issuer
  };
}
function isSigningEnabled() {
  return signingConfigured && signingInitError === null && signerState !== null;
}

export {
  initSigning,
  signDecision,
  signGenericArtifact,
  getSignerInfo,
  isSigningEnabled
};
