// ============================================================
// Agent Manifest v0.1 — TypeScript types
//
// These types implement the agent-manifest-v0.1-spec.md.
// No runtime code yet — types only. Implementation is gated
// on protect-mcp adoption signals.
//
// @patent Agent manifest format — patent-protected construction for
// portable agent identity with evidence chains. Covered by Apache 2.0
// patent grant for users of this code. Clean-room reimplementation
// requires a patent license.
// @see https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/
// ============================================================

// ============================================================
// Identity
// ============================================================

/**
 * Agent identity format: sb:agent:{first 32 hex chars of SHA-256(public key bytes)}
 * Example: "sb:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
 */
export type AgentId = `sb:agent:${string}`;

/**
 * Builder identity format: sb:builder:{hash}
 */
export type BuilderId = `sb:builder:${string}`;

/**
 * Ed25519 public key in prefixed format: "ed25519:{base64url}"
 */
export type Ed25519PublicKey = `ed25519:${string}`;

/**
 * SHA-256 hash in prefixed format: "sha256:{hex}"
 */
export type SHA256Hash = `sha256:${string}`;

// ============================================================
// Manifest status
// ============================================================

/**
 * Manifest lifecycle status.
 * - active:    Agent is operational. Operators should grant access per policy.
 * - suspended: Temporarily disabled. Builder is investigating. Reversible.
 * - revoked:   Permanently disabled. Irreversible. New keypair needed.
 */
export type ManifestStatus = 'active' | 'suspended' | 'revoked';

// ============================================================
// Disclosure modes
// ============================================================

/**
 * ScopeBlind disclosure modes — governance decision, not implementation detail.
 * - private: Minimum-disclosure. Unlinkable, single-use identity.
 * - scoped:  Pseudonymous. Deterministic per-service hash.
 * - named:   Full attribution. Explicit identifier.
 */
export type DisclosureMode = 'private' | 'scoped' | 'named';

// ============================================================
// Evidence types
// ============================================================

/**
 * The five evidence types in the Agent Economy taxonomy.
 * Evidence and claims/interpretation are ALWAYS separate layers.
 */
export type EvidenceType = 'arena' | 'benchmark' | 'work' | 'restraint' | 'attestation';

// ============================================================
// Agent Manifest
// ============================================================

export interface AgentManifest {
  // === Envelope ===
  /** Spec version. Always "0.1" for this version. */
  manifest_version: '0.1';
  /** Stable agent identity: sb:agent:{public_key_hash} */
  id: AgentId;
  /** Monotonically increasing version number. Starts at 1. */
  version: number;
  /**
   * SHA-256 of the previous manifest version's canonical JSON.
   * Null for the first version. Creates an append-only version chain.
   */
  previous_version: SHA256Hash | null;
  /** ISO 8601 timestamp — when this manifest version was created. */
  created_at: string;
  /** ISO 8601 timestamp — when this manifest was last modified. */
  updated_at: string;
  /** ISO 8601 timestamp — when this manifest expires. Null means no expiry. */
  expires_at: string | null;

  // === Status ===
  /** Lifecycle status of this agent. */
  status: ManifestStatus;
  /** Human-readable reason when suspended or revoked. Null if active. */
  status_reason: string | null;
  /** ISO 8601 timestamp of last status change. Null if always active. */
  status_changed_at: string | null;

  // === Identity ===
  identity: ManifestIdentity;

  // === Capabilities ===
  capabilities: ManifestCapabilities;

  // === Configuration Fingerprint ===
  config: ManifestConfig;

  // === Evidence Summary ===
  evidence_summary: EvidenceSummary;

  // === Lease Compatibility ===
  lease_compatibility: LeaseCompatibility;

  // === Signature ===
  signature: ManifestSignature;
}

// ============================================================
// Manifest sub-types
// ============================================================

export interface ManifestIdentity {
  /** Ed25519 public key: "ed25519:{base64url}" */
  public_key: Ed25519PublicKey;
  /** Key algorithm. Always "Ed25519" in v0.1. */
  key_algorithm: 'Ed25519';
  /** Builder information. All fields optional — builder can remain pseudonymous. */
  builder: ManifestBuilder;
}

export interface ManifestBuilder {
  /** Builder's display name. Optional. */
  name?: string;
  /** Builder's contact information. Optional. */
  contact?: string;
  /** ScopeBlind builder identity. Optional. */
  id?: BuilderId;
}

export interface ManifestCapabilities {
  /**
   * SHA-256 hash of the model identifier string.
   * Hides exact model while allowing change detection.
   */
  model_family_hash: SHA256Hash;
  /** Declared tool usage categories (e.g., "file_read", "web_search"). */
  tool_categories: string[];
  /** Which ScopeBlind disclosure modes this agent supports. */
  supported_disclosure_modes: DisclosureMode[];
  /** Declared maximum context window size. Optional. */
  max_context_tokens?: number;
  /** ISO 639-1 language codes the agent supports. Optional. */
  languages?: string[];
}

export interface ManifestConfig {
  /** SHA-256 of the system prompt text. Config hash, not config. */
  system_prompt_hash: SHA256Hash;
  /** SHA-256 of the canonical JSON of tool definitions. */
  tool_definitions_hash: SHA256Hash;
  /** SHA-256 of the canonical JSON of model parameters. */
  parameters_hash: SHA256Hash;
  /** Builder's internal version label. Optional. */
  config_version?: string;
}

export interface EvidenceSummaryEntry {
  /** Total number of receipts of this type. */
  count: number;
  /** ISO 8601 timestamp of the most recent receipt. */
  latest_at: string;
  /** Identity of the primary issuer for this evidence type. */
  issuer: string;
}

export interface EvidenceSummary {
  arena: EvidenceSummaryEntry;
  benchmark: EvidenceSummaryEntry;
  work: EvidenceSummaryEntry;
  restraint: EvidenceSummaryEntry;
  attestation: EvidenceSummaryEntry;
}

export interface LeaseCompatibility {
  /** Minimum protect-mcp policy version this agent supports. Optional. */
  min_policy_version?: string;
  /** Rate limit thresholds the agent is designed to work within. Optional. */
  accepted_rate_limits?: {
    default?: string;
    max_burst?: string;
  };
  /** Tools the agent must have access to in order to function. Optional. */
  required_tools?: string[];
  /** Tools the agent can use but doesn't require. Optional. */
  optional_tools?: string[];
}

export interface ManifestSignature {
  /** Signature algorithm. Always "Ed25519" in v0.1. */
  algorithm: 'Ed25519';
  /** Identity of the signer. Self-signed in v1 trust model. */
  signer: AgentId | string;
  /** Base64url-encoded signature over canonical JSON of all fields except signature. */
  value: string;
}

// ============================================================
// Evidence Receipt
// ============================================================

/**
 * Issuer type classifies who is signing the evidence receipt.
 * - platform:  Automated platform (arena, benchmark suite, task marketplace)
 * - human:     Individual human attestor
 * - gateway:   protect-mcp or similar gateway (generates restraint evidence)
 * - evaluator: Evaluation framework or benchmarking system
 */
export type IssuerType = 'platform' | 'human' | 'gateway' | 'evaluator';

export interface EvidenceIssuer {
  /** Issuer identity string (domain, sb:user:..., etc.) */
  id: string;
  /** What kind of entity is issuing this evidence. */
  type: IssuerType;
  /** Issuer's Ed25519 public key for signature verification. */
  public_key: Ed25519PublicKey;
}

export interface EvidenceReceiptBase {
  /** Spec version. Always "0.1" for this version. */
  receipt_version: '0.1';
  /** Unique receipt identifier: "ev:{type}:{hash}" */
  receipt_id: string;
  /** Which of the 5 evidence types this receipt represents. */
  evidence_type: EvidenceType;
  /** Which agent this evidence is about. */
  agent_id: AgentId;
  /** Who signed this evidence receipt. */
  issuer: EvidenceIssuer;

  // === Freshness ===
  /** ISO 8601 timestamp — when this receipt was issued. */
  issued_at: string;
  /** ISO 8601 timestamp — hard expiry. Null if using freshness_window. */
  expires_at: string | null;
  /** Freshness window in seconds. Consumer decides if fresh enough. */
  freshness_window_seconds: number;

  // === Signature ===
  signature: {
    algorithm: 'Ed25519';
    signer: string;
    value: string;
  };
}

// ============================================================
// Evidence payloads by type
// ============================================================

export interface ArenaPayload {
  battle_id: string;
  /** SHA-256 hash of opponent agent ID (privacy: don't reveal opponent). */
  opponent_hash: SHA256Hash;
  outcome: 'win' | 'loss' | 'tie';
  /** Optional category tag for the prompt. */
  prompt_category?: string;
  platform: string;
}

export interface BenchmarkPayload {
  suite_id: string;
  suite_version: string;
  scores: {
    overall: number;
    categories?: Record<string, number>;
  };
  run_id: string;
  /** SHA-256 hash of benchmark configuration (reproducibility). */
  run_config_hash?: SHA256Hash;
}

export interface WorkPayload {
  task_id: string;
  task_category: string;
  outcome: 'success' | 'partial' | 'failure';
  /** Optional quantification of work done. */
  item_count?: number;
  error_count?: number;
  /** Link to human reviewer's attestation receipt. */
  reviewer_attestation_id?: string;
}

export interface RestraintPayload {
  policy_digest: string;
  /** ISO 8601 — start of the observation window. */
  window_start: string;
  /** ISO 8601 — end of the observation window. */
  window_end: string;
  total_calls: number;
  allow_count: number;
  deny_count: number;
  deny_reason_codes: string[];
  mode: 'observe' | 'enforce';
}

export interface AttestationPayload {
  /** Narrow, specific statement about observed behavior. NOT a general endorsement. */
  statement: string;
  /** Scope of the attestation (e.g., "invoice_processing"). */
  scope: string;
  /** ISO 8601 — start of the observation period. */
  observed_period_start: string;
  /** ISO 8601 — end of the observation period. */
  observed_period_end: string;
  attestor_type: 'human' | 'organization';
}

// ============================================================
// Typed evidence receipts
// ============================================================

export interface ArenaReceipt extends EvidenceReceiptBase {
  evidence_type: 'arena';
  payload: ArenaPayload;
}

export interface BenchmarkReceipt extends EvidenceReceiptBase {
  evidence_type: 'benchmark';
  payload: BenchmarkPayload;
}

export interface WorkReceipt extends EvidenceReceiptBase {
  evidence_type: 'work';
  payload: WorkPayload;
}

export interface RestraintReceipt extends EvidenceReceiptBase {
  evidence_type: 'restraint';
  payload: RestraintPayload;
}

export interface AttestationReceipt extends EvidenceReceiptBase {
  evidence_type: 'attestation';
  payload: AttestationPayload;
}

/** Union type for all evidence receipt variants. */
export type EvidenceReceipt =
  | ArenaReceipt
  | BenchmarkReceipt
  | WorkReceipt
  | RestraintReceipt
  | AttestationReceipt;

// ============================================================
// Validation helpers (type guards)
// ============================================================

/** Check if a string is a valid agent ID format. */
export function isAgentId(s: string): s is AgentId {
  return /^sb:agent:[a-f0-9]{32}$/.test(s);
}

/** Check if a string is a valid evidence type. */
export function isEvidenceType(s: string): s is EvidenceType {
  return ['arena', 'benchmark', 'work', 'restraint', 'attestation'].includes(s);
}

/** Check if a string is a valid manifest status. */
export function isManifestStatus(s: string): s is ManifestStatus {
  return ['active', 'suspended', 'revoked'].includes(s);
}

/** Check if a string is a valid disclosure mode. */
export function isDisclosureMode(s: string): s is DisclosureMode {
  return ['private', 'scoped', 'named'].includes(s);
}

/**
 * Validate the structural integrity of a manifest (types and required fields).
 * Does NOT verify the cryptographic signature — use verifyManifestSignature() for that.
 *
 * Returns an array of error strings. Empty array = valid.
 *
 * @patent Patent-protected construction — agent manifest format for portable agent
 * identity with evidence chains. Covered by Apache 2.0 patent grant for users of
 * this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export function validateManifest(manifest: unknown): string[] {
  const errors: string[] = [];

  if (!manifest || typeof manifest !== 'object') {
    return ['Manifest must be a non-null object'];
  }

  const m = manifest as Record<string, unknown>;

  // Envelope
  if (m.manifest_version !== '0.1') {
    errors.push(`manifest_version must be "0.1", got "${m.manifest_version}"`);
  }
  if (typeof m.id !== 'string' || !isAgentId(m.id)) {
    errors.push(`id must be a valid AgentId (sb:agent:{32 hex chars}), got "${m.id}"`);
  }
  if (typeof m.version !== 'number' || !Number.isInteger(m.version) || m.version < 1) {
    errors.push(`version must be a positive integer, got ${m.version}`);
  }
  if (m.previous_version !== null && (typeof m.previous_version !== 'string' || !m.previous_version.startsWith('sha256:'))) {
    errors.push(`previous_version must be null or a sha256: prefixed hash`);
  }
  if (typeof m.created_at !== 'string') {
    errors.push('created_at is required (ISO 8601 string)');
  }
  if (typeof m.updated_at !== 'string') {
    errors.push('updated_at is required (ISO 8601 string)');
  }

  // Status
  if (typeof m.status !== 'string' || !isManifestStatus(m.status)) {
    errors.push(`status must be "active", "suspended", or "revoked", got "${m.status}"`);
  }

  // Identity
  if (!m.identity || typeof m.identity !== 'object') {
    errors.push('identity is required');
  } else {
    const id = m.identity as Record<string, unknown>;
    if (typeof id.public_key !== 'string' || !id.public_key.startsWith('ed25519:')) {
      errors.push('identity.public_key must be an ed25519: prefixed key');
    }
    if (id.key_algorithm !== 'Ed25519') {
      errors.push('identity.key_algorithm must be "Ed25519"');
    }
  }

  // Capabilities
  if (!m.capabilities || typeof m.capabilities !== 'object') {
    errors.push('capabilities is required');
  } else {
    const cap = m.capabilities as Record<string, unknown>;
    if (typeof cap.model_family_hash !== 'string' || !cap.model_family_hash.startsWith('sha256:')) {
      errors.push('capabilities.model_family_hash must be a sha256: prefixed hash');
    }
    if (!Array.isArray(cap.tool_categories)) {
      errors.push('capabilities.tool_categories must be an array');
    }
    if (!Array.isArray(cap.supported_disclosure_modes)) {
      errors.push('capabilities.supported_disclosure_modes must be an array');
    } else {
      for (const mode of cap.supported_disclosure_modes as string[]) {
        if (!isDisclosureMode(mode)) {
          errors.push(`Invalid disclosure mode: "${mode}"`);
        }
      }
    }
  }

  // Config
  if (!m.config || typeof m.config !== 'object') {
    errors.push('config is required');
  } else {
    const cfg = m.config as Record<string, unknown>;
    for (const field of ['system_prompt_hash', 'tool_definitions_hash', 'parameters_hash']) {
      if (typeof cfg[field] !== 'string' || !(cfg[field] as string).startsWith('sha256:')) {
        errors.push(`config.${field} must be a sha256: prefixed hash`);
      }
    }
  }

  // Evidence summary
  if (!m.evidence_summary || typeof m.evidence_summary !== 'object') {
    errors.push('evidence_summary is required');
  } else {
    const ev = m.evidence_summary as Record<string, unknown>;
    for (const type of ['arena', 'benchmark', 'work', 'restraint', 'attestation']) {
      if (!ev[type] || typeof ev[type] !== 'object') {
        errors.push(`evidence_summary.${type} is required`);
      } else {
        const entry = ev[type] as Record<string, unknown>;
        if (typeof entry.count !== 'number') errors.push(`evidence_summary.${type}.count must be a number`);
        if (typeof entry.latest_at !== 'string') errors.push(`evidence_summary.${type}.latest_at must be a string`);
        if (typeof entry.issuer !== 'string') errors.push(`evidence_summary.${type}.issuer must be a string`);
      }
    }
  }

  // Signature
  if (!m.signature || typeof m.signature !== 'object') {
    errors.push('signature is required');
  } else {
    const sig = m.signature as Record<string, unknown>;
    if (sig.algorithm !== 'Ed25519') {
      errors.push('signature.algorithm must be "Ed25519"');
    }
    if (typeof sig.signer !== 'string') {
      errors.push('signature.signer is required');
    }
    if (typeof sig.value !== 'string') {
      errors.push('signature.value is required');
    }
  }

  return errors;
}

/**
 * Validate the structural integrity of an evidence receipt.
 * Does NOT verify the cryptographic signature.
 *
 * Returns an array of error strings. Empty array = valid.
 *
 * @patent Patent-protected construction — evidence receipt format for portable agent
 * identity with evidence chains. Covered by Apache 2.0 patent grant for users of
 * this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export function validateEvidenceReceipt(receipt: unknown): string[] {
  const errors: string[] = [];

  if (!receipt || typeof receipt !== 'object') {
    return ['Receipt must be a non-null object'];
  }

  const r = receipt as Record<string, unknown>;

  if (r.receipt_version !== '0.1') {
    errors.push(`receipt_version must be "0.1", got "${r.receipt_version}"`);
  }
  if (typeof r.receipt_id !== 'string') {
    errors.push('receipt_id is required');
  }
  if (typeof r.evidence_type !== 'string' || !isEvidenceType(r.evidence_type)) {
    errors.push(`evidence_type must be one of: arena, benchmark, work, restraint, attestation`);
  }
  if (typeof r.agent_id !== 'string' || !isAgentId(r.agent_id)) {
    errors.push('agent_id must be a valid AgentId');
  }

  // Issuer
  if (!r.issuer || typeof r.issuer !== 'object') {
    errors.push('issuer is required');
  } else {
    const iss = r.issuer as Record<string, unknown>;
    if (typeof iss.id !== 'string') errors.push('issuer.id is required');
    if (typeof iss.type !== 'string') errors.push('issuer.type is required');
    if (typeof iss.public_key !== 'string' || !iss.public_key.startsWith('ed25519:')) {
      errors.push('issuer.public_key must be an ed25519: prefixed key');
    }
  }

  // Freshness
  if (typeof r.issued_at !== 'string') {
    errors.push('issued_at is required (ISO 8601 string)');
  }
  if (typeof r.freshness_window_seconds !== 'number') {
    errors.push('freshness_window_seconds is required');
  }

  // Payload
  if (!r.payload || typeof r.payload !== 'object') {
    errors.push('payload is required');
  }

  // Signature
  if (!r.signature || typeof r.signature !== 'object') {
    errors.push('signature is required');
  }

  return errors;
}
