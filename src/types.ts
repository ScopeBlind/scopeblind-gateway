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

  // ── Enterprise hardening fields (v0.5.0+) ──

  /** Swarm context — present when running inside Claude Code coordinator mode */
  swarm?: SwarmContext;
  /** Operational timing — measures protect-mcp overhead and tool execution */
  timing?: TimingMetrics;
  /** Payload digest — hash of tool input/output when content exceeds 1KB */
  payload_digest?: PayloadDigest;
  /** Iteration count — how many times this tool was denied before allowing */
  deny_iteration?: number;
  /** Sandbox state — whether the calling process has OS-level containment */
  sandbox_state?: 'enabled' | 'disabled' | 'unavailable';
  /** Plan receipt reference — links tool calls back to the approved plan */
  plan_receipt_id?: string;
  /** Hook event that triggered this log entry */
  hook_event?: HookEventName;

  // ── Iteration context (behavioral windowing) ──

  /**
   * Logical iteration identifier for multi-step agent workflows.
   * Enables drift detectors and behavioral monitors to group receipts
   * by execution phase rather than raw sequence.
   *
   * Format: opaque string. Recommended convention: dot-separated
   * hierarchy for nested iterations (e.g., "run_7.sub_3").
   * - Flat: "research_1", "synthesis_2"
   * - Nested: "meta_1.sub_A_1" (parent = "meta_1", depth = 1)
   *
   * When present, consumers SHOULD group receipts by iteration_id
   * prefix and compare within-iteration distributions against baselines.
   * When null/absent, fall back to count-based windowing.
   *
   * Security: agent-declared metadata, not a security boundary.
   * Receipt signatures cover this field (no post-hoc tampering).
   */
  iteration_id?: string | null;

  // ── Standard reference fields (v0.5.2+) ──

  /** IETF specification version — ties every receipt to the standard */
  spec?: string;
  /** Issuer certification level:
   *  - "scopeblind:verified" = VOPRF-backed issuance (paid tier)
   *  - "self-signed"         = local Ed25519 key (free tier, protect-mcp default)
   *  - "uncertified"         = unsigned receipt (shadow mode) */
  issuer_certification?: 'scopeblind:verified' | 'self-signed' | 'uncertified';
}

// ============================================================
// Swarm context (multi-agent coordination)
// ============================================================

export interface SwarmContext {
  /** Team name from CLAUDE_CODE_TEAM_NAME env var */
  team_name?: string;
  /** Agent ID from CLAUDE_CODE_AGENT_ID env var */
  agent_id?: string;
  /** Agent name from CLAUDE_CODE_AGENT_NAME env var */
  agent_name?: string;
  /** Whether this agent is the team leader */
  is_leader?: boolean;
  /** Parent receipt ID — links worker decisions to coordinator */
  parent_receipt_id?: string;
  /** Agent type classification */
  agent_type?: 'coordinator' | 'worker' | 'teammate' | 'standalone';
}

// ============================================================
// Timing metrics
// ============================================================

export interface TimingMetrics {
  /** Time from PreToolUse to PostToolUse (ms) — tool execution duration */
  tool_duration_ms?: number;
  /** protect-mcp's own processing time (ms) — policy eval + receipt signing */
  hook_latency_ms?: number;
  /** Timestamp when the tool call started */
  started_at?: number;
  /** Timestamp when the tool call completed */
  completed_at?: number;
}

// ============================================================
// Payload digest (large content hashing)
// ============================================================

export interface PayloadDigest {
  /** SHA-256 hash of the full tool input */
  input_hash?: string;
  /** SHA-256 hash of the full tool output */
  output_hash?: string;
  /** Size of tool input in bytes */
  input_size?: number;
  /** Size of tool output in bytes */
  output_size?: number;
  /** Whether the content was truncated in the receipt */
  truncated: boolean;
  /** First 256 chars of content (preview) */
  preview?: string;
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

// ============================================================
// Claude Code Hook Types
// ============================================================

/** All supported hook event names from Claude Code's hook taxonomy */
export type HookEventName =
  // Tool lifecycle
  | 'PreToolUse'
  | 'PostToolUse'
  // Permission lifecycle
  | 'PermissionRequest'
  | 'PermissionDenied'
  // Subagent / swarm lifecycle
  | 'SubagentStart'
  | 'SubagentStop'
  | 'TeammateIdle'
  // Task lifecycle
  | 'TaskCreated'
  | 'TaskCompleted'
  // Session lifecycle
  | 'SessionStart'
  | 'SessionEnd'
  // Configuration
  | 'ConfigChange'
  // Content lifecycle
  | 'InstructionsLoaded'
  | 'FileChanged'
  | 'CwdChanged'
  // Stop event
  | 'Stop';

/** Input payload sent by Claude Code to an HTTP hook */
export interface HookInput {
  /** Which event triggered this hook */
  hookEventName: HookEventName;
  /** Tool name (for PreToolUse / PostToolUse) */
  toolName?: string;
  /** Tool input (JSON object) */
  toolInput?: Record<string, unknown>;
  /** Tool result (PostToolUse only) */
  toolResult?: unknown;
  /** Tool use ID (unique per invocation) */
  toolUseId?: string;
  /** Session ID */
  sessionId?: string;
  /** Agent ID (swarm workers) */
  agentId?: string;
  /** Agent name */
  agentName?: string;
  /** Team name (coordinator mode) */
  teamName?: string;
  /** Agent type (coordinator, worker, etc.) */
  agentType?: string;
  /** Task ID (for TaskCreated/TaskCompleted) */
  taskId?: string;
  /** Teammate name (for TaskCreated) */
  teammateName?: string;
  /** Config change source */
  configSource?: string;
  /** Config change path */
  configPath?: string;
  /** Agent transcript path (SubagentStop) */
  agentTranscriptPath?: string;
  /** File path (FileChanged, CwdChanged) */
  filePath?: string;
  /** Whether the session is stopping */
  isStopping?: boolean;
}

/** Response from protect-mcp hook server to Claude Code.
 *
 * Matches Claude Code's SyncHookJSONOutputSchema (coreSchemas.ts line 907-935).
 * The hookSpecificOutput shape varies by event — see the per-event schemas:
 *   - PreToolUse: permissionDecision, permissionDecisionReason, updatedInput, additionalContext
 *   - PostToolUse: additionalContext, updatedMCPToolOutput
 *   - SubagentStart: additionalContext
 *   - SessionStart: additionalContext, initialUserMessage, watchPaths
 *
 * IMPORTANT: additionalContext MUST be inside hookSpecificOutput, NOT at the top level.
 * The async/sync output schemas are mutually exclusive (AsyncHookJSONOutputSchema vs
 * SyncHookJSONOutputSchema). We always return sync responses.
 */
export interface HookResponse {
  /** Whether Claude should continue (false = stop immediately) */
  continue?: boolean;
  /** Stop reason (when continue=false) */
  stopReason?: string;
  /** Top-level decision shorthand (approve/block) */
  decision?: 'approve' | 'block';
  /** Human-readable reason for the decision */
  reason?: string;
  /** System message shown to user (not injected into model context) */
  systemMessage?: string;
  /** Hook-specific output matching Claude Code's per-event schema */
  hookSpecificOutput?: {
    hookEventName: HookEventName;
    /** Permission decision (PreToolUse only) */
    permissionDecision?: 'allow' | 'deny' | 'ask';
    /** Human-readable reason for the decision */
    permissionDecisionReason?: string;
    /** Modified tool input (PreToolUse allow with changes) */
    updatedInput?: Record<string, unknown>;
    /** Additional context injected into the model's conversation */
    additionalContext?: string;
    /** Modified MCP tool output (PostToolUse only) */
    updatedMCPToolOutput?: unknown;
  };
}

// ============================================================
// Plan receipt (Ultraplan integration)
// ============================================================

export interface PlanReceipt {
  /** SHA-256 hash of the approved plan text */
  plan_hash: string;
  /** Number of times the plan was rejected before approval */
  reject_count: number;
  /** Where the plan will execute */
  execution_target: 'local' | 'remote';
  /** When the plan was approved */
  approved_at: string;
  /** Receipt IDs of tool calls executed under this plan */
  child_receipt_ids: string[];
}

// ============================================================
// CCR Connector (Scheduled Remote Agents)
// ============================================================

export interface CCRConnectorConfig {
  /** Connector UUID */
  connector_uuid: string;
  /** Display name */
  name: string;
  /** Connector endpoint URL */
  url: string;
  /** Required policy digest — reject sessions that don't match */
  required_policy_digest?: string;
}

export interface CCRSessionContext {
  /** Trigger ID that initiated this session */
  trigger_id: string;
  /** Environment ID (Anthropic cloud container) */
  environment_id: string;
  /** Model used */
  model: string;
  /** Git sources */
  sources: Array<{ git_repository: { url: string } }>;
  /** Allowed tools */
  allowed_tools: string[];
  /** MCP connections */
  mcp_connections: CCRConnectorConfig[];
}

// ============================================================
// XAA / RFC 7523 Compatibility
// ============================================================

export interface PassportTokenClaims {
  /** Issuer (aisigil.id) */
  iss: string;
  /** Subject (agent kid) */
  sub: string;
  /** Audience (target MCP server) */
  aud: string;
  /** Expiration time */
  exp: number;
  /** Issued at */
  iat: number;
  /** JWT ID */
  jti: string;
  /** Trust tier at issuance */
  tier: TrustTier;
  /** DPoP thumbprint (RFC 9449) */
  cnf?: { jkt: string };
}
