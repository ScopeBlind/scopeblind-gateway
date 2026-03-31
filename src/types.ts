// ============================================================
// Policy types
// ============================================================

export interface ProtectPolicy {
  tools: Record<string, ToolPolicy>;
  /** Default trust tier for unidentified agents (default: "unknown") */
  default_tier?: TrustTier;
  /** Policy engine mode */
  policy_engine?: PolicyEngineMode;
  /** External PDP endpoint (when policy_engine is "external" or "hybrid") */
  external?: ExternalPDPConfig;
  /** Directory containing .cedar policy files (when policy_engine is "cedar") */
  cedar_dir?: string;
}

export interface ToolPolicy {
  /**
   * Identity requirement for this tool.
   * 'gateway' = must pass through this gateway. 'any' = no restriction. 'none' = no identity needed.
   *
   * NOTE: v1 does not enforce this field — it is metadata only, logged in decision entries
   * for policy documentation purposes. Per-request identity enforcement requires the
   * SSE transport mode planned for v2.
   */
  require?: 'gateway' | 'any' | 'none';
  /** Rate limit spec, e.g. "5/hour", "100/day", "10/minute" */
  rate_limit?: string;
  /** Explicitly block this tool */
  block?: boolean;
  /** Require human approval before executing (non-blocking: returns MCP error for LLM to suspend) */
  require_approval?: boolean;
  /** Minimum trust tier required for this tool (v2) */
  min_tier?: TrustTier;
  /** Tier-specific rate limits (v2) */
  rate_limits?: Partial<Record<TrustTier, { max: number; window: string }>>;
}

// ============================================================
// Trust Tiers
// ============================================================

export type TrustTier = 'unknown' | 'signed-known' | 'evidenced' | 'privileged';

export const TRUST_TIER_ORDER: TrustTier[] = ['unknown', 'signed-known', 'evidenced', 'privileged'];

// ============================================================
// Policy Engine (BYOPE)
// ============================================================

export type PolicyEngineMode = 'built-in' | 'external' | 'hybrid' | 'cedar';

export interface ExternalPDPConfig {
  /** HTTP endpoint for the external policy decision point */
  endpoint: string;
  /** Response format: 'opa' | 'cerbos' | 'cedar' | 'generic' */
  format?: 'opa' | 'cerbos' | 'cedar' | 'generic';
  /** Timeout in milliseconds (default: 500) */
  timeout_ms?: number;
  /** Fallback decision when external PDP is unreachable */
  fallback?: 'allow' | 'deny';
}

/**
 * Decision context sent to external PDPs.
 * Transport-agnostic: works with OPA, Cerbos, or custom engines.
 */
export interface DecisionContext {
  v: 1;
  actor: {
    id?: string;
    tier: TrustTier;
    manifest_hash?: string;
  };
  action: {
    tool: string;
    operation?: string;
  };
  target: {
    service: string;
    resource_id?: string;
  };
  credential_ref?: string;
  mode: 'shadow' | 'enforce';
  request_metadata: Record<string, unknown>;
}

/** Response from an external PDP */
export interface ExternalDecision {
  allowed: boolean;
  reason?: string;
  /** Additional metadata from the PDP */
  metadata?: Record<string, unknown>;
}

// ============================================================
// Credential Vault
// ============================================================

export interface CredentialConfig {
  /** How the credential is injected: header, query, body */
  inject: 'header' | 'query' | 'env';
  /** Header name, query param name, or env var name */
  name: string;
  /** Environment variable that holds the actual secret */
  value_env: string;
}

// ============================================================
// Signing Configuration
// ============================================================

export interface SigningConfig {
  /** Path to the Ed25519 private key file (JSON with privateKey, publicKey) */
  key_path?: string;
  /** Issuer identifier (e.g., "my-gateway.example.com") */
  issuer?: string;
  /** Whether signing is enabled (default: true when key_path is set) */
  enabled?: boolean;
}

// ============================================================
// Parsed rate limit
// ============================================================

export interface RateLimit {
  count: number;
  windowMs: number;
}

// ============================================================
// JSON-RPC 2.0 types (minimal — no SDK dependency)
// ============================================================

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: Record<string, unknown>;
}

// ============================================================
// Decision log entry (v1: unsigned, v2: optionally signed)
// ============================================================

export interface DecisionLog {
  /** Schema version */
  v: 1 | 2;
  /** Tool name that was called */
  tool: string;
  /** Decision: allow or deny */
  decision: 'allow' | 'deny' | 'require_approval';
  /** Why this decision was made */
  reason_code: string;
  /** SHA-256 digest of the canonicalized policy file */
  policy_digest: string;
  /** Which policy engine made the decision */
  policy_engine?: PolicyEngineMode;
  /** Unique request identifier */
  request_id: string;
  /** Unix timestamp (ms) */
  timestamp: number;
  /** Remaining rate limit budget (if rate limit is configured) */
  rate_limit_remaining?: number;
  /** Operating mode */
  mode: 'shadow' | 'enforce';
  /** Trust tier of the agent at decision time (v2) */
  tier?: TrustTier;
  /** Credential label used (v2, never the actual secret) */
  credential_ref?: string;
  /** OpenTelemetry trace ID (32 hex chars) — links receipts to OTel traces */
  otel_trace_id?: string;
  /** OpenTelemetry span ID (16 hex chars) — links this receipt to a specific span */
  otel_span_id?: string;
  /** Rekor transparency log anchor (if anchored) */
  log_anchor?: {
    transparency_log: string;
    log_index: number;
    integrated_time: string;
    receipt_hash: string;
    verify_url: string;
  };
}

// ============================================================
// Gateway configuration
// ============================================================

export interface ProtectConfig {
  /** Command to spawn (first element of child process) */
  command: string;
  /** Arguments for the child process */
  args: string[];
  /** Loaded policy (or null for allow-all) */
  policy: ProtectPolicy | null;
  /** Computed policy digest */
  policyDigest: string;
  /** ScopeBlind tenant slug (optional, for future API integration) */
  slug?: string;
  /** Whether to enforce policy (default: false = shadow mode) */
  enforce?: boolean;
  /** Verbose debug logging to stderr */
  verbose?: boolean;
  /** Signing configuration */
  signing?: SigningConfig;
  /** Credential vault: maps credential labels to injection config */
  credentials?: Record<string, CredentialConfig>;
  /** Multi-agent mode: identify calling agents and apply per-agent policy */
  multiAgent?: MultiAgentConfig;
}

/**
 * Multi-agent mode configuration.
 *
 * When enabled, protect-mcp resolves the calling agent's passport kid
 * from request metadata (x-passport-kid header or _passport_kid param)
 * and applies agent-specific policy overrides.
 */
export interface MultiAgentConfig {
  /** Enable multi-agent mode */
  enabled: boolean;
  /** Registry endpoint for agent manifest lookup */
  registryUrl?: string;
  /** Per-agent policy overrides: maps kid → tool policy overrides */
  agentPolicies?: Record<string, Record<string, ToolPolicy>>;
  /** Default policy for unrecognized agents (default: use base policy) */
  unknownAgentPolicy?: 'base' | 'deny' | 'shadow-only';
  /** Cache TTL for agent manifests in ms (default: 300000 = 5 min) */
  cacheTtlMs?: number;
}
