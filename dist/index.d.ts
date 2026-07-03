export { HookServerOptions, startHookServer } from './hook-server.js';
export { BUILTIN_PATTERNS, HookPattern, generateHookSettings, generateSampleCedarPolicy, generateVerifyReceiptSkill } from './hook-patterns.js';
export { createSandboxServer } from './demo-server.js';
import 'node:http';

interface ProtectPolicy {
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
interface ToolPolicy {
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
    rate_limits?: Partial<Record<TrustTier, {
        max: number;
        window: string;
    }>>;
}
type TrustTier = 'unknown' | 'signed-known' | 'evidenced' | 'privileged';
type PolicyEngineMode = 'built-in' | 'external' | 'hybrid' | 'cedar';
interface ExternalPDPConfig {
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
interface DecisionContext {
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
interface ExternalDecision {
    allowed: boolean;
    reason?: string;
    /** Additional metadata from the PDP */
    metadata?: Record<string, unknown>;
}
interface CredentialConfig {
    /** How the credential is injected: header, query, body */
    inject: 'header' | 'query' | 'env';
    /** Header name, query param name, or env var name */
    name: string;
    /** Environment variable that holds the actual secret */
    value_env: string;
}
interface SigningConfig {
    /** Path to the Ed25519 private key file (JSON with privateKey, publicKey) */
    key_path?: string;
    /** Issuer identifier (e.g., "my-gateway.example.com") */
    issuer?: string;
    /** Whether signing is enabled (default: true when key_path is set) */
    enabled?: boolean;
    /**
     * Commitment-mode signing.
     *
     * When enabled, listed fields are committed via SHA-256(salt || JCS({name, salt, value}))
     * and the receipt payload carries a single committed_fields_root (Merkle root) instead
     * of the cleartext field values. Per draft-farley-acta-signed-receipts-01 §commitment-mode.
     *
     * The receipt issuer keeps the openings (value + salt per field) for later selective
     * disclosure. A receipt holder can prove a field's value to an auditor without
     * revealing other committed fields.
     *
     * @since 0.6.0
     */
    commitment_mode?: {
        /** Whether commitment-mode signing is active. Default: false. */
        enabled?: boolean;
        /**
         * Names of payload fields to commit.
         * Recommended defaults: tool, scope, payload_digest, swarm.
         * Other fields remain cleartext.
         */
        committed_field_names?: string[];
    };
}
interface RateLimit {
    count: number;
    windowMs: number;
}
interface JsonRpcRequest {
    jsonrpc: '2.0';
    id: string | number;
    method: string;
    params?: Record<string, unknown>;
}
interface JsonRpcResponse {
    jsonrpc: '2.0';
    id: string | number;
    result?: unknown;
    error?: {
        code: number;
        message: string;
        data?: unknown;
    };
}
interface DecisionLog {
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
    /** Redacted exact-action readback shown to humans before approving */
    action_readback?: {
        tool: string;
        action: string;
        destination?: string;
        payload_preview: unknown;
        payload_hash: string;
        payload_bytes: number;
        disclosed_fields: string[];
        redacted_fields: string[];
        summary: string;
    };
    /** IETF specification version — ties every receipt to the standard */
    spec?: string;
    /** Issuer certification level:
     *  - "scopeblind:verified" = VOPRF-backed issuance (paid tier)
     *  - "self-signed"         = local Ed25519 key (free tier, protect-mcp default)
     *  - "uncertified"         = unsigned receipt (shadow mode) */
    issuer_certification?: 'scopeblind:verified' | 'self-signed' | 'uncertified';
}
interface SwarmContext {
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
interface TimingMetrics {
    /** Time from PreToolUse to PostToolUse (ms) — tool execution duration */
    tool_duration_ms?: number;
    /** protect-mcp's own processing time (ms) — policy eval + receipt signing */
    hook_latency_ms?: number;
    /** Timestamp when the tool call started */
    started_at?: number;
    /** Timestamp when the tool call completed */
    completed_at?: number;
}
interface PayloadDigest {
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
interface ProtectConfig {
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
interface MultiAgentConfig {
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
/** All supported hook event names from Claude Code's hook taxonomy */
type HookEventName = 'PreToolUse' | 'PostToolUse' | 'PermissionRequest' | 'PermissionDenied' | 'SubagentStart' | 'SubagentStop' | 'TeammateIdle' | 'TaskCreated' | 'TaskCompleted' | 'SessionStart' | 'SessionEnd' | 'ConfigChange' | 'InstructionsLoaded' | 'FileChanged' | 'CwdChanged' | 'Stop';
/** Input payload sent by Claude Code to an HTTP hook */
interface HookInput {
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
interface HookResponse {
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
interface PlanReceipt {
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
interface CCRConnectorConfig {
    /** Connector UUID */
    connector_uuid: string;
    /** Display name */
    name: string;
    /** Connector endpoint URL */
    url: string;
    /** Required policy digest — reject sessions that don't match */
    required_policy_digest?: string;
}
interface CCRSessionContext {
    /** Trigger ID that initiated this session */
    trigger_id: string;
    /** Environment ID (Anthropic cloud container) */
    environment_id: string;
    /** Model used */
    model: string;
    /** Git sources */
    sources: Array<{
        git_repository: {
            url: string;
        };
    }>;
    /** Allowed tools */
    allowed_tools: string[];
    /** MCP connections */
    mcp_connections: CCRConnectorConfig[];
}
interface PassportTokenClaims {
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
    cnf?: {
        jkt: string;
    };
}

/**
 * Summary of evidence for tier evaluation.
 */
interface EvidenceSummary$1 {
    receipt_count: number;
    epoch_span: number;
    issuer_count: number;
}
/**
 * Thresholds for the 'evidenced' tier.
 */
interface EvidenceThresholds {
    min_receipts: number;
    min_epoch_span: number;
    min_issuers: number;
}
/**
 * Evidence store — tracks receipt history per agent.
 */
declare class EvidenceStore {
    private agents;
    private filePath;
    private dirty;
    constructor(dir?: string);
    /**
     * Record a receipt observation for an agent.
     */
    record(agentId: string, issuer: string, timestamp?: string): void;
    /**
     * Get the evidence summary for an agent.
     */
    getSummary(agentId: string): EvidenceSummary$1;
    /**
     * Check if an agent meets the evidenced tier thresholds.
     */
    meetsEvidencedThreshold(agentId: string, thresholds?: EvidenceThresholds): boolean;
    /**
     * Persist to disk (call periodically or on shutdown).
     */
    save(): void;
    /**
     * Load from disk.
     */
    private load;
    /**
     * Get total agent count (for status display).
     */
    agentCount(): number;
    /**
     * Get all agent summaries (for status display).
     */
    allSummaries(): Array<{
        agent_id: string;
        summary: EvidenceSummary$1;
    }>;
}

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

/**
 * Minimal manifest info needed for tier evaluation.
 * This is not the full manifest — just the fields admission cares about.
 */
interface ManifestPresentation {
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
interface AdmissionResult {
    tier: TrustTier;
    agent_id?: string;
    manifest_hash?: string;
    reason: string;
}
/**
 * Explicit tier overrides from the operator's config.
 * Maps agent IDs to explicitly assigned tiers.
 */
type TierOverrides = Record<string, TrustTier>;
/**
 * Options for tier evaluation.
 */
interface EvaluateTierOptions {
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
declare function evaluateTier(manifest: ManifestPresentation | null, opts?: TierOverrides | EvaluateTierOptions): AdmissionResult;
/**
 * Check if a trust tier meets the minimum required tier.
 *
 * @patent Patent-protected construction. Covered by Apache 2.0 patent grant
 * for users of this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function meetsMinTier(actual: TrustTier, required: TrustTier): boolean;

/**
 * @scopeblind/protect-mcp — Cedar Policy Evaluator (Local WASM)
 *
 * Evaluates Cedar policies locally using @cedar-policy/cedar-wasm.
 * No external server required. Same deterministic evaluation as
 * AWS Verified Permissions / AgentCore Policy.
 *
 * Cedar is loaded as an optional dependency — if the WASM module
 * isn't installed, this module exports stubs that return fallback decisions.
 */

interface CedarPolicySet {
    /** Raw concatenated Cedar source */
    source: string;
    /** SHA-256 digest of the sorted, concatenated policy source */
    digest: string;
    /** Number of individual .cedar files loaded */
    fileCount: number;
    /** Filenames loaded */
    files: string[];
}
interface CedarEvalRequest {
    /** Tool name being called */
    tool: string;
    /** Trust tier of the agent */
    tier: TrustTier;
    /** Agent ID (optional) */
    agentId?: string;
    /** Additional context fields */
    context?: Record<string, unknown>;
    /** Tool input (for schema-validated evaluation) */
    toolInput?: Record<string, unknown>;
}
/** Cedar schema for typed policy evaluation (generated by cedar-schema.ts) */
interface CedarSchema {
    /** The schema as a JSON object for Cedar WASM */
    schemaJson: Record<string, unknown> | null;
    /** Namespace used in the schema */
    namespace?: string;
}
/**
 * Load all .cedar files from a directory and return a compiled policy set.
 *
 * Files are sorted alphabetically for deterministic digest computation.
 * Throws if the directory doesn't exist or contains no .cedar files.
 */
declare function loadCedarPolicies(dirPath: string): CedarPolicySet;
interface CedarEvalOptions {
    /**
     * Default true (0.7.0+). When true, ANY evaluation error, engine
     * unavailability, malformed result, or per-policy error DENIES. When false
     * (explicit observe/shadow use only), those paths ALLOW but are flagged
     * would_deny:true in the decision metadata so the failure is never silent.
     */
    failClosed?: boolean;
}
/**
 * Evaluate a Cedar policy set against a tool call.
 *
 * FAIL-CLOSED by default (0.7.0+): if Cedar is unavailable, the engine API is
 * unsupported, evaluation throws, the result is malformed, or ANY policy errored
 * during evaluation (which Cedar otherwise silently discards, leaving a residual
 * permit standing), this returns DENY. The allow-on-error behavior is reachable
 * only by explicitly passing { failClosed: false }, and even then it is flagged.
 */
declare function evaluateCedar(policySet: CedarPolicySet, req: CedarEvalRequest, schema?: CedarSchema, options?: CedarEvalOptions): Promise<ExternalDecision>;
/**
 * Validate that Cedar WASM is available.
 * Useful for CLI startup diagnostics.
 */
declare function isCedarAvailable(): Promise<boolean>;
/** Build a CedarPolicySet from inline source (for the self-test). */
declare function policySetFromSource(source: string, name?: string): CedarPolicySet;
interface SelfTestCase {
    name: string;
    expected: 'ALLOW' | 'DENY';
    actual: 'ALLOW' | 'DENY';
    pass: boolean;
    reason?: string;
}
interface SelfTestReport {
    wasmAvailable: boolean;
    passed: boolean;
    cases: SelfTestCase[];
}
/**
 * Run known deny/allow vectors through the LIVE evaluator before the gate is
 * trusted. Always proves the fail-closed invariant (the engine being unable to
 * decide must DENY). When Cedar WASM is present it also proves a real forbid
 * denies, a permit allows, and a policy using the silently-discarded
 * `in`-on-String pattern DENIES rather than permit-all (the 0.6.x regression).
 */
declare function runEvaluatorSelfTest(): Promise<SelfTestReport>;

/**
 * MCP tool-calling gateway that intercepts JSON-RPC requests,
 * evaluates policy, and emits signed decision receipts.
 *
 * @standard Standard MCP proxy pattern — JSON-RPC stdio interception.
 */
declare class ProtectGateway {
    private child;
    private config;
    private rateLimitStore;
    private clientReader;
    private logFilePath;
    private receiptFilePath;
    private evidenceStore;
    private receiptBuffer;
    /** Approval grants keyed by request_id (scoped to the specific action that was requested) */
    private approvalStore;
    /** Random nonce generated at startup — required for approval endpoint authentication */
    private readonly approvalNonce;
    private currentTier;
    private admissionResult;
    /** Notification config for approval gates (SMS, webhook, email) */
    private notificationConfig;
    /** HTTP transport mode: pending response resolvers keyed by JSON-RPC id */
    private pendingResponses;
    private httpMode;
    /** Loaded Cedar policy set (when policy_engine is "cedar") */
    private cedarPolicySet;
    constructor(config: ProtectConfig);
    /**
     * Set the Cedar policy set for local evaluation.
     * Called during CLI startup when --cedar flag is used.
     */
    setCedarPolicies(policySet: CedarPolicySet): void;
    start(): Promise<void>;
    setManifest(manifest: ManifestPresentation | null): AdmissionResult;
    private handleClientMessage;
    private interceptToolCallAsync;
    private handleServerMessage;
    private injectParamsCredentials;
    private interceptToolCall;
    private getTierRateLimit;
    /**
     * Emit a decision log entry with OTel-compatible trace IDs and optional
     * signed receipt generation.
     *
     * @patent Patent-protected construction — decision receipts with configurable
     * disclosure and issuer-blind properties. Covered by Apache 2.0 patent grant
     * for users of this code. Clean-room reimplementation requires a patent license.
     * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
     */
    private emitDecisionLog;
    private makeErrorResponse;
    private sendToChild;
    private sendToClient;
    /**
     * Enable HTTP transport mode.
     * In this mode, sendToClient resolves pending promises instead of
     * writing to stdout, and start() skips stdin reading.
     */
    enableHttpMode(): void;
    /**
     * Start in HTTP mode — spawns child process but does NOT read from
     * process.stdin. Requests come in via processRequest() instead.
     */
    startForHttp(): Promise<void>;
    /**
     * Process a JSON-RPC request programmatically (for HTTP transport).
     * Returns a promise that resolves with the JSON-RPC response string.
     */
    processRequest(jsonRpc: JsonRpcRequest): Promise<string>;
    private log;
    stop(): void;
}

/**
 * Load and validate a policy file. Returns the policy, credentials, signing config, and digest.
 */
declare function loadPolicy(path: string): {
    policy: ProtectPolicy;
    digest: string;
    credentials?: Record<string, CredentialConfig>;
    signing?: SigningConfig;
};
/**
 * Get the policy for a specific tool. Falls back to "*" wildcard, then default-allow.
 *
 * Backwards compatible: old policies with just { block, rate_limit, require }
 * still work. New policies can add { min_tier, rate_limits }.
 */
declare function getToolPolicy(toolName: string, policy: ProtectPolicy | null): ToolPolicy;
/**
 * Parse a rate limit spec like "5/hour", "100/day", "10/minute".
 */
declare function parseRateLimit(spec: string): RateLimit;
/**
 * In-memory sliding window rate limiter.
 * Returns { allowed, remaining } based on recent invocations.
 */
declare function checkRateLimit(key: string, limit: RateLimit, store: Map<string, number[]>): {
    allowed: boolean;
    remaining: number;
};

/**
 * @scopeblind/protect-mcp — Credential Vault
 *
 * Config-driven credential injection for MCP tool calls.
 * The agent NEVER sees the raw credential. protect-mcp holds
 * the secret and injects it into the appropriate context.
 *
 * Credentials are referenced by label in the policy and receipts.
 * The actual secret value is read from environment variables.
 *
 * Example config:
 * {
 *   "credentials": {
 *     "stripe_api": {
 *       "inject": "header",
 *       "name": "Authorization",
 *       "value_env": "STRIPE_KEY"
 *     },
 *     "github_token": {
 *       "inject": "header",
 *       "name": "Authorization",
 *       "value_env": "GITHUB_TOKEN"
 *     }
 *   }
 * }
 */

/**
 * Result of credential resolution.
 */
interface CredentialResolution {
    /** Whether the credential was found and resolved */
    resolved: boolean;
    /** The credential label (safe to log, never the actual value) */
    label: string;
    /** Error message if resolution failed */
    error?: string;
    /** The resolved value (NEVER log this) */
    value?: string;
    /** How the credential should be injected */
    inject?: 'header' | 'query' | 'env';
    /** Injection target name (header name, query param, env var) */
    name?: string;
}
/**
 * Resolve a credential from the vault.
 * Reads the actual secret from the environment variable specified in config.
 *
 * @param label - Credential label (e.g., "stripe_api")
 * @param credentials - Credential configuration map
 * @returns CredentialResolution (value is only populated on success)
 *
 * @patent Patent-protected construction — privacy-preserving credential presentation.
 * Covered by Apache 2.0 patent grant for users of this code. Clean-room
 * reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function resolveCredential(label: string, credentials: Record<string, CredentialConfig> | undefined): CredentialResolution;
/**
 * Get the list of configured credential labels (safe to log).
 *
 * @param credentials - Credential configuration map
 * @returns Array of credential labels
 *
 * @patent Patent-protected construction — privacy-preserving credential presentation.
 * Covered by Apache 2.0 patent grant for users of this code. Clean-room
 * reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function listCredentialLabels(credentials: Record<string, CredentialConfig> | undefined): string[];
/**
 * Validate credential configuration at startup.
 * Checks that all referenced environment variables exist.
 *
 * @param credentials - Credential configuration map
 * @returns Array of warnings for missing env vars
 *
 * @patent Patent-protected construction — privacy-preserving credential presentation.
 * Covered by Apache 2.0 patent grant for users of this code. Clean-room
 * reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function validateCredentials(credentials: Record<string, CredentialConfig> | undefined): string[];

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

/**
 * Initialize the signing subsystem.
 * Loads the key file and dynamically imports @veritasacta/artifacts.
 *
 * @param config - Signing configuration
 * @returns Array of warnings (empty = success)
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
declare function initSigning(config: SigningConfig | undefined): Promise<string[]>;
/**
 * Sign a decision log entry as a v2 artifact.
 *
 * Returns the signed artifact JSON string, or null if signing is not configured.
 * On signing failure, returns an unsigned artifact with a warning.
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
declare function signDecision(entry: DecisionLog): {
    ok: boolean;
    signed: string | null;
    artifact_type: string;
    warning?: string;
    error?: string;
};
/**
 * Get the signer's public key info for discovery/verification.
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
declare function getSignerInfo(): {
    publicKey: string;
    kid: string;
    issuer: string;
} | null;
/**
 * Check if signing is available.
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */
declare function isSigningEnabled(): boolean;

/**
 * A Merkle inclusion proof for a single leaf.
 *
 * The siblings array lists the sibling hashes encountered while walking
 * from the leaf up to the root. Each sibling is hex-encoded SHA-256.
 * The (index, treeSize) pair determines whether the current node is
 * left or right at each level during verification.
 */
interface MerkleProof {
    /** Zero-based index of the leaf in the canonically-sorted leaf list. */
    index: number;
    /** Total number of leaves in the tree. */
    treeSize: number;
    /** Sibling hashes from leaf upward, hex-encoded SHA-256 (lowercase). */
    siblings: string[];
}

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

/**
 * The opening information for a single committed field. Held by the
 * receipt issuer; never embedded in the published receipt. Required to
 * later produce a selective-disclosure proof.
 */
interface CommittedFieldOpening {
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
interface CommittedSignResult {
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
interface MinimalDisclosure {
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
interface SelectiveDisclosurePackageV0 {
    type: 'scopeblind.selective_disclosure.v0';
    version: 0;
    parent_receipt_hash: string;
    committed_fields_root: string;
    disclosed_fields: string[];
    hidden_fields: string[];
    disclosures: MinimalDisclosure[];
    verifier_explanation: {
        summary: string;
        disclosed: string;
        hidden: string;
        limitation: string;
    };
}
interface SelectiveDisclosureVerification {
    valid: boolean;
    receipt_hash_valid: boolean;
    signature_valid: boolean | null;
    commitment_root_valid: boolean;
    disclosed_fields: string[];
    hidden_fields: string[];
    errors: string[];
    explanation: string[];
}
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
declare function signCommittedDecision(entry: DecisionLog, committedFieldNames: string[], signingKey: string, publicKey: string, kid: string, issuer: string): CommittedSignResult;
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
declare function discloseField(receiptHash: string, fieldName: string, openings: Record<string, CommittedFieldOpening>): MinimalDisclosure;
declare function createSelectiveDisclosurePackage(receipt: Record<string, unknown>, fieldNames: string[], openings: Record<string, CommittedFieldOpening>): SelectiveDisclosurePackageV0;
declare function verifySelectiveDisclosurePackage(receipt: Record<string, unknown>, disclosure: SelectiveDisclosurePackageV0): SelectiveDisclosureVerification;

/**
 * @scopeblind/protect-mcp — External PDP Adapter
 *
 * BYOPE (Bring Your Own Policy Engine) — sends decision context
 * to an external Policy Decision Point via HTTP webhook.
 *
 * Supports OPA, Cerbos, Cedar (AWS), and generic JSON formats.
 * ScopeBlind always signs the receipt regardless of who made the decision.
 *
 * Sprint 2: One HTTP webhook adapter. More adapters later.
 */

/**
 * Query an external PDP for a policy decision.
 *
 * @param context - The decision context (transport-agnostic)
 * @param config - External PDP configuration
 * @returns ExternalDecision with allow/deny and optional metadata
 */
declare function queryExternalPDP(context: DecisionContext, config: ExternalPDPConfig): Promise<ExternalDecision>;
/**
 * Build a DecisionContext from a tool call.
 */
declare function buildDecisionContext(toolName: string, tier: TrustTier, opts: {
    agentId?: string;
    manifestHash?: string;
    credentialRef?: string;
    mode: 'shadow' | 'enforce';
    slug?: string;
    requestMetadata?: Record<string, unknown>;
}): DecisionContext;

/**
 * @scopeblind/protect-mcp — Audit Bundle Export
 *
 * Creates self-contained audit bundles that can be verified offline.
 * A bundle includes receipts, optional anchors, and the signing keys
 * needed to verify everything — no network calls required.
 *
 * Format:
 * {
 *   format: "scopeblind:audit-bundle",
 *   version: 1,
 *   exported_at: ISO-8601,
 *   tenant: string,
 *   time_range: { from, to },
 *   receipts: [...signed v2 artifacts...],
 *   anchors: [...optional audit anchors...],
 *   verification: {
 *     algorithm: "ed25519",
 *     signing_keys: [...JWK keys needed to verify all receipts...],
 *     instructions: "..."
 *   }
 * }
 */

interface AuditBundleOptions {
    /** Tenant/service identifier */
    tenant: string;
    /** Time range for exported receipts */
    timeRange?: {
        from: string;
        to: string;
    };
    /** Signed v2 artifacts (decision_receipts and/or gateway_restraints) */
    receipts: Record<string, unknown>[];
    /** Optional audit anchors */
    anchors?: Record<string, unknown>[];
    /** Optional selective-disclosure packages opening selected committed fields */
    selectiveDisclosures?: SelectiveDisclosurePackageV0[];
    /** JWK signing keys used by the receipts */
    signingKeys: Array<{
        kty: string;
        crv: string;
        kid: string;
        x: string;
        use?: string;
    }>;
}
interface AuditBundle {
    format: 'scopeblind:audit-bundle';
    version: 1;
    exported_at: string;
    tenant: string;
    time_range: {
        from: string;
        to: string;
    } | null;
    receipts: Record<string, unknown>[];
    anchors: Record<string, unknown>[];
    selective_disclosures: SelectiveDisclosurePackageV0[];
    privacy: {
        selective_disclosure: {
            supported: true;
            model: 'salted_commitments_merkle_v0';
            statement: string;
        };
    };
    verification: {
        algorithm: 'ed25519';
        signing_keys: Array<{
            kty: string;
            crv: string;
            kid: string;
            x: string;
            use?: string;
        }>;
        instructions: string;
    };
}
/**
 * Create a self-contained audit bundle for offline verification.
 *
 * The bundle contains everything needed to verify all receipts:
 * - The signed receipts themselves
 * - The public keys used to sign them
 * - Verification instructions
 *
 * No network access required to verify.
 */
declare function createAuditBundle(opts: AuditBundleOptions): AuditBundle;
/**
 * Collect decision log entries into signed receipts suitable for bundling.
 * Filters for entries that have attached signed artifacts.
 */
declare function collectSignedReceipts(logs: DecisionLog[]): Record<string, unknown>[];

/**
 * protect-mcp simulate — dry-run policy evaluation
 *
 * Reads a recorded log file (.protect-mcp-log.jsonl) and evaluates
 * each tool call against a policy file. Shows what would have been
 * blocked, rate-limited, or approved — without wrapping a live server.
 *
 * Usage:
 *   npx protect-mcp simulate --policy strict.json [--log .protect-mcp-log.jsonl] [--json]
 */

interface LogEntry {
    v: number;
    tool: string;
    decision: string;
    reason_code: string;
    mode: string;
    timestamp: number;
    tier?: string;
    rate_limit_remaining?: number;
    [key: string]: unknown;
}
interface SimulationResult {
    tool: string;
    calls: number;
    results: {
        allow: number;
        block: number;
        rate_limited: number;
        require_approval: number;
        tier_insufficient: number;
    };
    original: {
        allow: number;
        deny: number;
    };
}
interface SimulationSummary {
    policy_file: string;
    log_file: string;
    total_calls: number;
    results: {
        allow: number;
        block: number;
        rate_limited: number;
        require_approval: number;
        tier_insufficient: number;
    };
    original: {
        allow: number;
        deny: number;
    };
    tool_breakdown: SimulationResult[];
    changes: string[];
}
/**
 * Parse a JSONL log file into log entries.
 */
declare function parseLogFile(path: string): LogEntry[];
/**
 * Simulate a policy against a set of log entries.
 * Evaluates each entry against the policy's per-tool rules,
 * including block, rate_limit, min_tier, and require_approval.
 */
declare function simulate(entries: LogEntry[], policy: ProtectPolicy, tier?: TrustTier): SimulationSummary;
/**
 * Format simulation results for terminal output.
 */
declare function formatSimulation(summary: SimulationSummary): string;

/**
 * protect-mcp report — compliance report generation
 *
 * Generates structured compliance reports from local log and receipt files.
 * Output as JSON (machine-readable) or Markdown (human-readable, PDF-convertible).
 *
 * Usage:
 *   npx protect-mcp report --period 30d --output report.json
 *   npx protect-mcp report --period 30d --format md --output report.md
 */
interface ComplianceReport {
    generated_at: string;
    period: {
        from: string;
        to: string;
    };
    signing_identity: {
        kid: string;
        issuer: string;
    } | null;
    summary: {
        total_decisions: number;
        allowed: number;
        blocked: number;
        rate_limited: number;
        approval_required: number;
        unique_tools: number;
        unique_tiers: number;
    };
    tool_breakdown: Array<{
        tool: string;
        total: number;
        allowed: number;
        blocked: number;
        rate_limited: number;
        approval_required: number;
    }>;
    policy_changes: Array<{
        at: string;
        policy_digest: string;
    }>;
    verification: {
        receipts_signed: number;
        receipts_unsigned: number;
        verify_command: string;
    };
}
/**
 * Generate a compliance report from local log and receipt files.
 */
declare function generateReport(logPath: string, receiptPath: string, periodDays: number): ComplianceReport;
/**
 * Format a compliance report as Markdown.
 */
declare function formatReportMarkdown(report: ComplianceReport): string;

/**
 * Agent identity format: sb:agent:{first 32 hex chars of SHA-256(public key bytes)}
 * Example: "sb:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
 */
type AgentId = `sb:agent:${string}`;
/**
 * Builder identity format: sb:builder:{hash}
 */
type BuilderId = `sb:builder:${string}`;
/**
 * Ed25519 public key in prefixed format: "ed25519:{base64url}"
 */
type Ed25519PublicKey = `ed25519:${string}`;
/**
 * SHA-256 hash in prefixed format: "sha256:{hex}"
 */
type SHA256Hash = `sha256:${string}`;
/**
 * Manifest lifecycle status.
 * - active:    Agent is operational. Operators should grant access per policy.
 * - suspended: Temporarily disabled. Builder is investigating. Reversible.
 * - revoked:   Permanently disabled. Irreversible. New keypair needed.
 */
type ManifestStatus = 'active' | 'suspended' | 'revoked';
/**
 * ScopeBlind disclosure modes — governance decision, not implementation detail.
 * - private: Minimum-disclosure. Unlinkable, single-use identity.
 * - scoped:  Pseudonymous. Deterministic per-service hash.
 * - named:   Full attribution. Explicit identifier.
 */
type DisclosureMode = 'private' | 'scoped' | 'named';
/**
 * The five evidence types in the Agent Economy taxonomy.
 * Evidence and claims/interpretation are ALWAYS separate layers.
 */
type EvidenceType = 'arena' | 'benchmark' | 'work' | 'restraint' | 'attestation';
interface AgentManifest {
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
    /** Lifecycle status of this agent. */
    status: ManifestStatus;
    /** Human-readable reason when suspended or revoked. Null if active. */
    status_reason: string | null;
    /** ISO 8601 timestamp of last status change. Null if always active. */
    status_changed_at: string | null;
    identity: ManifestIdentity;
    capabilities: ManifestCapabilities;
    config: ManifestConfig;
    evidence_summary: EvidenceSummary;
    lease_compatibility: LeaseCompatibility;
    signature: ManifestSignature;
}
interface ManifestIdentity {
    /** Ed25519 public key: "ed25519:{base64url}" */
    public_key: Ed25519PublicKey;
    /** Key algorithm. Always "Ed25519" in v0.1. */
    key_algorithm: 'Ed25519';
    /** Builder information. All fields optional — builder can remain pseudonymous. */
    builder: ManifestBuilder;
}
interface ManifestBuilder {
    /** Builder's display name. Optional. */
    name?: string;
    /** Builder's contact information. Optional. */
    contact?: string;
    /** ScopeBlind builder identity. Optional. */
    id?: BuilderId;
}
interface ManifestCapabilities {
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
interface ManifestConfig {
    /** SHA-256 of the system prompt text. Config hash, not config. */
    system_prompt_hash: SHA256Hash;
    /** SHA-256 of the canonical JSON of tool definitions. */
    tool_definitions_hash: SHA256Hash;
    /** SHA-256 of the canonical JSON of model parameters. */
    parameters_hash: SHA256Hash;
    /** Builder's internal version label. Optional. */
    config_version?: string;
}
interface EvidenceSummaryEntry {
    /** Total number of receipts of this type. */
    count: number;
    /** ISO 8601 timestamp of the most recent receipt. */
    latest_at: string;
    /** Identity of the primary issuer for this evidence type. */
    issuer: string;
}
interface EvidenceSummary {
    arena: EvidenceSummaryEntry;
    benchmark: EvidenceSummaryEntry;
    work: EvidenceSummaryEntry;
    restraint: EvidenceSummaryEntry;
    attestation: EvidenceSummaryEntry;
}
interface LeaseCompatibility {
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
interface ManifestSignature {
    /** Signature algorithm. Always "Ed25519" in v0.1. */
    algorithm: 'Ed25519';
    /** Identity of the signer. Self-signed in v1 trust model. */
    signer: AgentId | string;
    /** Base64url-encoded signature over canonical JSON of all fields except signature. */
    value: string;
}
/**
 * Issuer type classifies who is signing the evidence receipt.
 * - platform:  Automated platform (arena, benchmark suite, task marketplace)
 * - human:     Individual human attestor
 * - gateway:   protect-mcp or similar gateway (generates restraint evidence)
 * - evaluator: Evaluation framework or benchmarking system
 */
type IssuerType = 'platform' | 'human' | 'gateway' | 'evaluator';
interface EvidenceIssuer {
    /** Issuer identity string (domain, sb:user:..., etc.) */
    id: string;
    /** What kind of entity is issuing this evidence. */
    type: IssuerType;
    /** Issuer's Ed25519 public key for signature verification. */
    public_key: Ed25519PublicKey;
}
interface EvidenceReceiptBase {
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
    /** ISO 8601 timestamp — when this receipt was issued. */
    issued_at: string;
    /** ISO 8601 timestamp — hard expiry. Null if using freshness_window. */
    expires_at: string | null;
    /** Freshness window in seconds. Consumer decides if fresh enough. */
    freshness_window_seconds: number;
    signature: {
        algorithm: 'Ed25519';
        signer: string;
        value: string;
    };
}
interface ArenaPayload {
    battle_id: string;
    /** SHA-256 hash of opponent agent ID (privacy: don't reveal opponent). */
    opponent_hash: SHA256Hash;
    outcome: 'win' | 'loss' | 'tie';
    /** Optional category tag for the prompt. */
    prompt_category?: string;
    platform: string;
}
interface BenchmarkPayload {
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
interface WorkPayload {
    task_id: string;
    task_category: string;
    outcome: 'success' | 'partial' | 'failure';
    /** Optional quantification of work done. */
    item_count?: number;
    error_count?: number;
    /** Link to human reviewer's attestation receipt. */
    reviewer_attestation_id?: string;
}
interface RestraintPayload {
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
interface AttestationPayload {
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
interface ArenaReceipt extends EvidenceReceiptBase {
    evidence_type: 'arena';
    payload: ArenaPayload;
}
interface BenchmarkReceipt extends EvidenceReceiptBase {
    evidence_type: 'benchmark';
    payload: BenchmarkPayload;
}
interface WorkReceipt extends EvidenceReceiptBase {
    evidence_type: 'work';
    payload: WorkPayload;
}
interface RestraintReceipt extends EvidenceReceiptBase {
    evidence_type: 'restraint';
    payload: RestraintPayload;
}
interface AttestationReceipt extends EvidenceReceiptBase {
    evidence_type: 'attestation';
    payload: AttestationPayload;
}
/** Union type for all evidence receipt variants. */
type EvidenceReceipt = ArenaReceipt | BenchmarkReceipt | WorkReceipt | RestraintReceipt | AttestationReceipt;
/** Check if a string is a valid agent ID format. */
declare function isAgentId(s: string): s is AgentId;
/** Check if a string is a valid evidence type. */
declare function isEvidenceType(s: string): s is EvidenceType;
/** Check if a string is a valid manifest status. */
declare function isManifestStatus(s: string): s is ManifestStatus;
/** Check if a string is a valid disclosure mode. */
declare function isDisclosureMode(s: string): s is DisclosureMode;
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
declare function validateManifest(manifest: unknown): string[];
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
declare function validateEvidenceReceipt(receipt: unknown): string[];

/**
 * @scopeblind/protect-mcp — Cedar Schema Generator for MCP Tools
 *
 * Auto-generates a Cedar authorization schema from MCP tool descriptions.
 * This enables typed Cedar policies that reference tool input attributes:
 *
 *   permit(principal, action == Action::"read_file", resource)
 *   when { context.input.path like "./workspace/*" };
 *
 * Compatible with cedar-policy/cedar-for-agents schema format.
 * Designed to replace `schema: null` in Cedar WASM evaluations.
 *
 * @see https://github.com/cedar-policy/cedar-for-agents
 * @standard RFC 8785 (JCS), Cedar Policy Language v4
 */
/** MCP tool description from tools/list response */
interface McpToolDescription {
    name: string;
    description?: string;
    inputSchema?: JsonSchema;
}
/** Subset of JSON Schema that MCP tools use */
interface JsonSchema {
    type?: string | string[];
    properties?: Record<string, JsonSchema>;
    required?: string[];
    items?: JsonSchema;
    enum?: (string | number | boolean)[];
    format?: string;
    description?: string;
    additionalProperties?: boolean | JsonSchema;
    anyOf?: JsonSchema[];
    oneOf?: JsonSchema[];
}
/** Generated Cedar schema components */
interface CedarSchemaResult {
    /** The .cedarschema text (human-readable Cedar schema format) */
    schemaText: string;
    /** The schema as a JSON object (for passing to Cedar WASM) */
    schemaJson: Record<string, unknown>;
    /** Number of tools mapped */
    toolCount: number;
    /** Tool names included */
    tools: string[];
}
interface SchemaGeneratorConfig {
    /** Namespace for generated types (default: "ScopeBlind") */
    namespace?: string;
    /** Include agent tier as principal attribute (default: true) */
    includeTier?: boolean;
    /** Include timestamp context (default: true) */
    includeTimestamp?: boolean;
    /** Include agent_id as principal attribute (default: true) */
    includeAgentId?: boolean;
}
/**
 * Generate a Cedar schema from MCP tool descriptions.
 *
 * Produces both human-readable .cedarschema text and the JSON
 * representation that Cedar WASM accepts.
 *
 * The generated schema defines:
 * - Agent entity type (principal) with tier and agent_id attributes
 * - Tool entity type (resource)
 * - One action per MCP tool, with typed input context
 * - A parent action "MCP::Tool::call" for blanket policies
 *
 * This enables policies like:
 *   forbid(principal, action == Action::"execute_command", resource)
 *   when { context.input has "command" && context.input.command like "rm *" };
 */
declare function generateCedarSchema(tools: McpToolDescription[], config?: SchemaGeneratorConfig): CedarSchemaResult;
/**
 * Generate a Cedar schema stub file for customization.
 * This is the starting point for users who want to extend the auto-generated schema.
 */
declare function generateSchemaStub(namespace?: string): string;

interface PolicyPack {
    id: string;
    name: string;
    description: string;
    recommendedMode: 'shadow-first' | 'enforce-ready';
    files: Array<{
        path: string;
        contents: string;
    }>;
}
declare const POLICY_PACKS: PolicyPack[];
declare function getPolicyPack(id: string): PolicyPack | undefined;
declare function policyPackIds(): string[];

type ConnectorPilotId = 'github' | 'email-gmail' | 'filesystem-git' | 'slack-teams' | 'finance-pms';
interface ConnectorEnvVar {
    name: string;
    required: boolean;
    description: string;
}
interface ConnectorAction {
    name: string;
    tool: string;
    risk: 'low' | 'medium' | 'high';
    mode: 'observe' | 'require_approval' | 'deny';
    description: string;
}
interface ConnectorPilot {
    id: ConnectorPilotId;
    category: string;
    name: string;
    status: 'usable-pilot';
    description: string;
    value: string;
    env: ConnectorEnvVar[];
    tools: string[];
    actions: ConnectorAction[];
    setup: string[];
    config: Record<string, unknown>;
    cedar: string;
}
interface InstalledConnectorPilot {
    id: string;
    name: string;
    category: string;
    status: string;
    config_path: string;
    policy_path: string;
}
declare const CONNECTOR_PILOTS: ConnectorPilot[];
declare function connectorPilotIds(): ConnectorPilotId[];
declare function getConnectorPilot(id: string): ConnectorPilot | undefined;
declare function connectorDirectory(dir: string): string;
declare function writeConnectorPilots(opts: {
    dir: string;
    ids?: string[];
    force?: boolean;
}): {
    written: string[];
    pilots: ConnectorPilot[];
    directory: string;
};
declare function readInstalledConnectorPilots(dir: string): InstalledConnectorPilot[];
declare function connectorDoctor(dir: string, env?: NodeJS.ProcessEnv): Array<Record<string, unknown>>;

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
interface RekorAnchor {
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
interface RekorVerification {
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
declare function anchorToRekor(receiptHash: string, signature: string, publicKeyPem: string): Promise<RekorAnchor>;
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
declare function verifyRekorAnchor(logIndex: number, expectedHash: string): Promise<RekorVerification>;
/**
 * Compute the SHA-256 hash of a receipt for anchoring.
 * Uses JCS-compatible canonical JSON (sorted keys).
 *
 * @standard RFC 8785 (JCS), SHA-256
 */
declare function hashReceipt(receipt: Record<string, unknown>): string;
/**
 * Create a log_anchor field for embedding in receipts.
 * This field can be added to any Acta receipt to provide
 * temporal proof of existence.
 *
 * @standard Integration with Sigstore Rekor transparency log — standard transparency anchoring.
 */
declare function createLogAnchorField(anchor: RekorAnchor): {
    transparency_log: string;
    log_index: number;
    integrated_time: string;
    receipt_hash: string;
    verify_url: string;
};

/**
 * Hash-Based Selective Disclosure for Veritas Acta Receipts
 *
 * Enables per-field redaction of receipt payloads while preserving
 * signature validity. Uses salted SHA-256 commitments — the receipt
 * structure and non-redacted fields remain verifiable, but redacted
 * fields are replaced with their salted hash.
 *
 * This is NOT zero-knowledge proof — it's practical, fast, and
 * covers 90% of the privacy use cases:
 * - Prove an agent followed HIPAA policy without revealing patient_id
 * - Prove a tool call was rate-limited without revealing the API endpoint
 * - Prove a deny decision occurred without revealing the prompt
 *
 * The salt is per-field and per-receipt, preventing rainbow table attacks.
 * The field owner (receipt issuer) holds the salts and can selectively
 * reveal fields to specific auditors.
 *
 * Usage:
 *   import { redactFields, revealField, verifyRedactedReceipt } from './selective-disclosure.js';
 *
 *   // Redact sensitive fields
 *   const { redacted, salts } = redactFields(receipt, ['patient_id', 'ssn', 'timestamp']);
 *
 *   // The redacted receipt has: "patient_id": "sha256:salt+..."
 *   // The signature still verifies against the original
 *
 *   // Reveal a specific field to an auditor
 *   const revealed = revealField(redacted, salts, 'patient_id');
 *
 *   // Verify a redacted receipt (checks that redacted fields are valid commitments)
 *   const valid = verifyRedactedReceipt(redacted, originalSignature, publicKey);
 */
interface RedactionSalt {
    field: string;
    salt: string;
    originalValue: unknown;
}
interface RedactedResult {
    /** The receipt with sensitive fields replaced by salted commitments */
    redacted: Record<string, unknown>;
    /** The salts needed to reveal each redacted field */
    salts: RedactionSalt[];
    /** Fields that were redacted */
    redactedFields: string[];
    /** SHA-256 hash of the original (unredacted) receipt for verification */
    originalHash: string;
}
/**
 * Redact specified fields in a receipt payload, replacing them with
 * salted SHA-256 commitments.
 *
 * @param receipt - The full receipt object
 * @param fieldsToRedact - Array of field paths to redact (dot notation for nested: "payload.patient_id")
 * @returns RedactedResult with the redacted receipt and the salts
 *
 * @patent Patent-protected construction. Covered by Apache 2.0 patent grant
 * for users of this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function redactFields(receipt: Record<string, unknown>, fieldsToRedact: string[]): RedactedResult;
/**
 * Reveal a previously redacted field using its salt.
 *
 * @param redactedReceipt - The redacted receipt
 * @param salts - The salt array from redactFields()
 * @param fieldPath - The field to reveal (dot notation)
 * @returns A new receipt with the specified field revealed
 *
 * @patent Patent-protected construction. Covered by Apache 2.0 patent grant
 * for users of this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function revealField(redactedReceipt: Record<string, unknown>, salts: RedactionSalt[], fieldPath: string): Record<string, unknown>;
/**
 * Verify that a redacted field's commitment matches the revealed value.
 *
 * An auditor can check: "does sha256(salt + value) equal the commitment
 * in the receipt?" without needing the issuer's cooperation.
 *
 * @param commitment - The commitment string from _commitments
 * @param salt - The salt (hex)
 * @param value - The claimed original value
 * @returns true if the commitment is valid
 *
 * @patent Patent-protected construction. Covered by Apache 2.0 patent grant
 * for users of this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function verifyCommitment(commitment: string, salt: string, value: unknown): boolean;
/**
 * Verify all commitments in a redacted receipt given a set of salts.
 *
 * @param redactedReceipt - The redacted receipt with _commitments
 * @param salts - The salts for all redacted fields
 * @returns Object with valid flag and per-field results
 *
 * @patent Patent-protected construction. Covered by Apache 2.0 patent grant
 * for users of this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function verifyAllCommitments(redactedReceipt: Record<string, unknown>, salts: RedactionSalt[]): {
    valid: boolean;
    fields: Record<string, boolean>;
};
/**
 * Create a disclosure package for a specific auditor.
 * Contains only the salts for fields the auditor needs to see.
 *
 * @param allSalts - Full salt array from redactFields()
 * @param fieldsToDisclose - Array of field paths to include
 * @returns Disclosure package (JSON-serializable)
 *
 * @patent Patent-protected construction. Covered by Apache 2.0 patent grant
 * for users of this code. Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare function createDisclosurePackage(allSalts: RedactionSalt[], fieldsToDisclose: string[]): {
    version: string;
    disclosed_fields: string[];
    salts: Array<{
        field: string;
        salt: string;
        value: unknown;
    }>;
};

/**
 * Notification system for protect-mcp approval gates.
 * Sends SMS (Twilio), webhook, or browser push notifications
 * when a tool call requires human approval.
 */
interface NotificationConfig {
    /** Twilio SMS notification */
    sms?: {
        accountSid: string;
        authToken: string;
        from: string;
        to: string;
    };
    /** Webhook notification (Slack, PagerDuty, custom) */
    webhook?: {
        url: string;
        method?: "POST" | "PUT";
        headers?: Record<string, string>;
        /** Template: 'slack' | 'pagerduty' | 'custom' */
        template?: "slack" | "pagerduty" | "custom";
    };
    /** Email notification */
    email?: {
        to: string;
        /** Uses Resend API if configured, falls back to SMTP */
        resendApiKey?: string;
    };
}
interface ApprovalNotification {
    requestId: string;
    toolName: string;
    agentId?: string;
    policyName?: string;
    reason: string;
    traceUrl?: string;
    approveUrl?: string;
    timestamp: string;
}
/**
 * Send approval notification through configured channels.
 * Non-blocking — errors are logged, not thrown.
 */
declare function sendApprovalNotification(config: NotificationConfig, notification: ApprovalNotification): Promise<void>;
/**
 * Parse notification config from environment variables.
 * SCOPEBLIND_SMS_TO, SCOPEBLIND_TWILIO_SID, etc.
 */
declare function parseNotificationConfigFromEnv(): NotificationConfig | null;

/**
 * Hugging Face Dataset Export
 *
 * Exports Veritas Acta receipt chains as HF-compatible datasets.
 * Produces JSONL format with structured fields for ML research.
 *
 * Usage:
 *   npx protect-mcp export-hf --output dataset.jsonl
 *   npx protect-mcp export-hf --output dataset.jsonl --format parquet
 */
interface HFReceiptRow {
    /** Unique receipt identifier */
    receipt_id: string;
    /** Receipt type: decision, execution, outcome, policy_load, observation, approval */
    receipt_type: string;
    /** Tool that was called */
    tool_name: string | null;
    /** Decision verdict: allow, deny, null */
    decision: string | null;
    /** Agent identifier (pseudonymous) */
    agent_id: string | null;
    /** Issuer identifier */
    issuer_id: string;
    /** ISO 8601 timestamp */
    timestamp: string;
    /** SHA-256 hash of the active policy at decision time */
    policy_hash: string | null;
    /** Typed causal edges to other receipts */
    edges: Array<{
        receipt_id: string;
        relation: string;
    }>;
    /** Number of edges (for quick filtering) */
    edge_count: number;
    /** Ed25519 signature (hex) */
    signature: string | null;
    /** Whether the receipt has a valid signature */
    signed: boolean;
    /** Context hash for selective disclosure */
    context_hash: string | null;
    /** Chain ID linking related receipts */
    chain_id: string | null;
}
interface HFDatasetMetadata {
    /** Dataset name */
    name: string;
    /** Description */
    description: string;
    /** Number of rows */
    num_rows: number;
    /** Receipt type distribution */
    type_distribution: Record<string, number>;
    /** Decision distribution */
    decision_distribution: Record<string, number>;
    /** Time range */
    time_range: {
        from: string;
        to: string;
    };
    /** Unique agents */
    unique_agents: number;
    /** Unique tools */
    unique_tools: number;
    /** Export timestamp */
    exported_at: string;
    /** License */
    license: "MIT";
    /** Tags for HF Hub */
    tags: string[];
}
/**
 * Convert raw receipt objects to HF-compatible rows.
 */
declare function receiptsToHFRows(receipts: Record<string, unknown>[]): HFReceiptRow[];
/**
 * Generate dataset metadata for HF Hub.
 */
declare function generateHFMetadata(rows: HFReceiptRow[], name?: string): HFDatasetMetadata;
/**
 * Export receipts as JSONL (one JSON object per line).
 */
declare function exportJSONL(rows: HFReceiptRow[]): string;
/**
 * Generate a HuggingFace dataset card (README.md) for the dataset repo.
 */
declare function generateDatasetCard(metadata: HFDatasetMetadata): string;

/**
 * WebAuthn/Passkey Approval for protect-mcp Human-in-the-Loop Gates
 *
 * Enables biometric (FaceID, TouchID, Windows Hello, YubiKey) approval
 * of agent tool calls. When an agent requests a tool that requires
 * human approval, the system generates a WebAuthn challenge. The human
 * authenticates with their biometric device, producing a cryptographic
 * proof that a specific human authorized a specific action.
 *
 * The WebAuthn assertion is embedded in the approval receipt as the
 * `authenticator_data` field, creating an unforgeable binding between
 * biological intent and machine execution.
 *
 * Flow:
 *   1. Agent requests `db_write` → policy says `require_approval`
 *   2. protect-mcp generates a WebAuthn challenge containing the tool
 *      name, request ID, and a timestamp
 *   3. Human receives notification (SMS/Slack/browser) with the challenge
 *   4. Human authenticates with FaceID/TouchID/YubiKey
 *   5. The WebAuthn assertion is verified server-side
 *   6. A signed approval receipt is emitted with the authenticator data
 *   7. The agent's tool call is unblocked
 *
 * Usage:
 *   import { createApprovalChallenge, verifyApprovalAssertion } from './webauthn-approval.js';
 *
 *   // Server-side: create challenge
 *   const challenge = createApprovalChallenge(requestId, toolName, agentId);
 *
 *   // Client-side: browser calls navigator.credentials.get() with challenge
 *   // ... user authenticates with biometric ...
 *
 *   // Server-side: verify the assertion
 *   const result = verifyApprovalAssertion(challenge, assertion, credentialId);
 */
interface ApprovalChallenge {
    /** Random challenge bytes (base64url) */
    challenge: string;
    /** Request ID of the tool call being approved */
    requestId: string;
    /** Tool name being approved */
    toolName: string;
    /** Agent requesting the approval */
    agentId?: string;
    /** Timestamp when challenge was created */
    createdAt: string;
    /** Challenge expiry (seconds) */
    timeoutSeconds: number;
    /** Relying party ID (domain) */
    rpId: string;
    /** SHA-256 hash of the challenge context (for receipt embedding) */
    contextHash: string;
}
interface ApprovalAssertion {
    /** Credential ID used (base64url) */
    credentialId: string;
    /** Authenticator data (base64url) */
    authenticatorData: string;
    /** Client data JSON (base64url) */
    clientDataJSON: string;
    /** Signature (base64url) */
    signature: string;
    /** User handle (base64url, optional) */
    userHandle?: string;
}
interface ApprovalResult {
    /** Whether the assertion is valid */
    valid: boolean;
    /** The credential ID used */
    credentialId: string;
    /** Authenticator type detected */
    authenticatorType: 'platform' | 'cross-platform' | 'unknown';
    /** Whether user verification was performed (biometric) */
    userVerified: boolean;
    /** Signature counter (for cloning detection) */
    signCount: number;
    /** Context hash that was signed */
    contextHash: string;
    /** Timestamp of approval */
    approvedAt: string;
}
/**
 * Create a WebAuthn challenge for approving a tool call.
 *
 * The challenge contains the tool name and request ID so the
 * approval is cryptographically bound to a specific action.
 *
 * @param requestId - The request ID of the pending tool call
 * @param toolName - The tool being approved
 * @param agentId - The agent requesting approval (optional)
 * @param rpId - Relying party ID (default: scopeblind.com)
 * @param timeoutSeconds - Challenge timeout (default: 300 = 5 minutes)
 */
declare function createApprovalChallenge(requestId: string, toolName: string, agentId?: string, rpId?: string, timeoutSeconds?: number): ApprovalChallenge;
/**
 * Generate the WebAuthn PublicKeyCredentialRequestOptions
 * that the browser needs to call navigator.credentials.get().
 *
 * This is sent to the client for the biometric prompt.
 */
declare function toCredentialRequestOptions(challenge: ApprovalChallenge, allowCredentials?: Array<{
    id: string;
    type: 'public-key';
}>): {
    publicKey: {
        challenge: ArrayBuffer;
        rpId: string;
        timeout: number;
        userVerification: 'required';
        allowCredentials?: Array<{
            id: ArrayBuffer;
            type: 'public-key';
        }>;
    };
};
/**
 * Verify a WebAuthn assertion from the client.
 *
 * This is a simplified verification that checks the structure
 * and extracts the authenticator data. For production use with
 * full signature verification, use the @simplewebauthn/server package.
 *
 * @param challenge - The original challenge
 * @param assertion - The assertion from navigator.credentials.get()
 * @returns ApprovalResult with verification details
 */
declare function verifyApprovalAssertion(challenge: ApprovalChallenge, assertion: ApprovalAssertion): ApprovalResult;
/**
 * Create the approval receipt payload for embedding in an Acta receipt.
 *
 * This is the data that gets signed into the DAG as an acta:approval node,
 * proving a human biometrically authorized a specific machine action.
 */
declare function createApprovalReceiptPayload(challenge: ApprovalChallenge, result: ApprovalResult): {
    type: 'acta:approval';
    approval_method: 'webauthn';
    tool_name: string;
    request_id: string;
    agent_id?: string;
    authenticator_type: string;
    user_verified: boolean;
    context_hash: string;
    approved_at: string;
    credential_id_hash: string;
};

/**
 * W3C DID/VC Mapping for ScopeBlind Passport Manifests
 *
 * Maps passport manifests to W3C Verifiable Credential format
 * and generates did:key identifiers from Ed25519 public keys.
 *
 * @standard W3C DID/VC interoperability — standard mapping, not patent-protected.
 * Implements W3C Decentralized Identifiers (DID) v1.0 and Verifiable Credentials
 * Data Model v1.1.
 */
/**
 * Generate a did:key identifier from an Ed25519 public key (hex).
 *
 * @standard W3C DID/VC interoperability — standard mapping, not patent-protected.
 */
declare function ed25519ToDIDKey(publicKeyHex: string): string;
/**
 * Convert a passport manifest to a W3C Verifiable Credential.
 *
 * @standard W3C DID/VC interoperability — standard mapping, not patent-protected.
 */
declare function manifestToVC(manifest: {
    agent_id: string;
    display_name?: string;
    public_key: string;
    capabilities?: string[];
    policy_digest?: string;
    created_at?: string;
    signature?: string;
}): {
    '@context': string[];
    type: string[];
    issuer: string;
    issuanceDate: string;
    credentialSubject: Record<string, unknown>;
    proof?: Record<string, unknown>;
};
/**
 * Convert a decision receipt to a W3C Verifiable Presentation.
 *
 * @standard W3C DID/VC interoperability — standard mapping, not patent-protected.
 */
declare function receiptToVP(receipt: Record<string, unknown>, issuerPublicKey: string): {
    '@context': string[];
    type: string[];
    holder: string;
    verifiableCredential: Record<string, unknown>[];
};

/**
 * E2B MicroVM Sandboxing for Agent Evaluation
 *
 * Provides isolated, disposable execution environments for testing
 * AI agent tool calls safely. Agents can run real MCP tools
 * (including destructive operations) inside sandboxes without
 * affecting the host system.
 *
 * Uses E2B (e2b.dev) for sub-second microVM startup, or falls back
 * to Docker containers for self-hosted deployments.
 *
 * Every tool call inside the sandbox produces a signed receipt,
 * creating a verifiable "safety transcript" of the agent's behavior.
 *
 * Usage:
 *   import { createSandbox, runInSandbox, destroySandbox } from './sandbox.js';
 *
 *   // Create a disposable sandbox
 *   const sandbox = await createSandbox({ template: 'node-20' });
 *
 *   // Run an agent's tool call inside the sandbox
 *   const result = await runInSandbox(sandbox, {
 *     tool: 'execute_command',
 *     args: { command: 'npm test' },
 *   });
 *
 *   // Sandbox is destroyed after evaluation
 *   await destroySandbox(sandbox);
 */
interface SandboxConfig {
    /** E2B template (e.g., 'node-20', 'python-3.11') or Docker image */
    template: string;
    /** Timeout in seconds (default: 300 = 5 minutes) */
    timeoutSeconds?: number;
    /** Maximum memory in MB (default: 512) */
    memoryMB?: number;
    /** Files to mount into the sandbox */
    files?: Array<{
        path: string;
        content: string;
    }>;
    /** Environment variables */
    env?: Record<string, string>;
    /** Whether to use E2B cloud or local Docker (default: 'e2b') */
    runtime?: 'e2b' | 'docker';
    /** E2B API key (from env E2B_API_KEY if not provided) */
    apiKey?: string;
}
interface Sandbox {
    /** Unique sandbox ID */
    id: string;
    /** Runtime type */
    runtime: 'e2b' | 'docker';
    /** Creation timestamp */
    createdAt: string;
    /** Status */
    status: 'running' | 'completed' | 'failed' | 'destroyed';
    /** Tool call receipts generated inside the sandbox */
    receipts: SandboxReceipt[];
}
interface SandboxToolCall {
    /** Tool name to execute */
    tool: string;
    /** Tool arguments */
    args: Record<string, unknown>;
}
interface SandboxResult {
    /** Whether the tool call succeeded */
    success: boolean;
    /** Tool output */
    output: string;
    /** Error message if failed */
    error?: string;
    /** Execution time in milliseconds */
    durationMs: number;
    /** Exit code (for commands) */
    exitCode?: number;
}
interface SandboxReceipt {
    /** Tool that was called */
    tool: string;
    /** Decision (from protect-mcp policy evaluation) */
    decision: 'allow' | 'deny' | 'require_approval';
    /** Whether it was executed */
    executed: boolean;
    /** Result if executed */
    result?: SandboxResult;
    /** Timestamp */
    timestamp: string;
    /** Policy rule that matched */
    policyRule?: string;
}
interface SafetyTranscript {
    /** Sandbox ID */
    sandboxId: string;
    /** Template used */
    template: string;
    /** Total tool calls attempted */
    totalCalls: number;
    /** Calls allowed */
    allowed: number;
    /** Calls denied */
    denied: number;
    /** Calls requiring approval */
    requireApproval: number;
    /** Success rate of executed calls */
    successRate: number;
    /** All receipts */
    receipts: SandboxReceipt[];
    /** Duration of the evaluation */
    durationMs: number;
    /** Timestamp */
    evaluatedAt: string;
    /** Safety score (0-100) */
    safetyScore: number;
}
/**
 * Create a disposable sandbox for agent evaluation.
 *
 * If E2B_API_KEY is set, uses E2B cloud microVMs.
 * Otherwise, falls back to local Docker containers.
 */
declare function createSandbox(config: SandboxConfig): Promise<Sandbox>;
/**
 * Run a tool call inside the sandbox with protect-mcp policy evaluation.
 */
declare function runInSandbox(sandbox: Sandbox, toolCall: SandboxToolCall, policy?: Record<string, unknown>): Promise<SandboxReceipt>;
/**
 * Generate a safety transcript from a sandbox evaluation.
 * This is the "graduation certificate" for an agent.
 */
declare function generateSafetyTranscript(sandbox: Sandbox, template: string): SafetyTranscript;
/**
 * Destroy a sandbox and clean up resources.
 */
declare function destroySandbox(sandbox: Sandbox): Promise<void>;

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
/**
 * Evidence attestation format — embedded in receipts to prove
 * the authenticity of externally fetched data.
 */
interface EvidenceAttestation {
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
interface EvidenceAttestationInput {
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
declare function createEvidenceAttestation(input: EvidenceAttestationInput): Promise<EvidenceAttestation>;
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
declare function verifyEvidenceAttestation(attestation: EvidenceAttestation): Promise<{
    valid: boolean;
    method: string;
    note: string;
}>;
/**
 * Hash a response body for attestation.
 * Uses SHA-256 for consistency with the rest of the receipt format.
 */
declare function hashResponseBody(body: string | Buffer): string;
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
declare function createAttestationField(attestation: EvidenceAttestation): {
    evidence_authenticity: {
        version: string;
        method: string;
        url_hash: string;
        response_hash: string;
        fetched_at: string;
        verified: boolean;
        note: string;
    };
};

/**
 * C2PA Content Credential Integration
 *
 * Embeds Veritas Acta provenance into C2PA (Coalition for Content
 * Provenance and Authenticity) manifest assertions. This enables
 * the "right-click to verify" UX — any content generated during
 * a governed agent session carries its Acta receipt chain as a
 * Content Credential.
 *
 * C2PA is backed by Adobe, Microsoft, BBC, and others. By embedding
 * Acta receipts as C2PA assertions, AI-generated content becomes
 * traceable through the existing content provenance ecosystem.
 *
 * Usage:
 *   import { createC2PAManifest, embedInImage, embedInDocument } from './c2pa-credentials.js';
 *
 *   // Create a C2PA manifest from an Acta receipt chain
 *   const manifest = createC2PAManifest(receipts, {
 *     title: 'AI-generated report',
 *     generator: 'protect-mcp v0.5.3',
 *   });
 *
 *   // The manifest can be embedded in images, PDFs, or documents
 *   // using c2patool or the C2PA Rust/JS SDK
 */
/**
 * C2PA Manifest structure compatible with the C2PA specification.
 * This is the JSON representation that c2patool can consume.
 */
interface C2PAManifest {
    /** C2PA claim generator identifier */
    claim_generator: string;
    /** C2PA claim generator version */
    claim_generator_info: Array<{
        name: string;
        version: string;
        icon?: {
            format: string;
            identifier: string;
        };
    }>;
    /** Title of the content */
    title: string;
    /** Assertions about the content */
    assertions: C2PAAssertion[];
    /** Ingredients (source materials) */
    ingredients?: C2PAIngredient[];
}
interface C2PAAssertion {
    /** Assertion label (URI) */
    label: string;
    /** Assertion data */
    data: Record<string, unknown>;
    /** Whether this assertion is hashed (for privacy) */
    is_hash?: boolean;
}
interface C2PAIngredient {
    /** Title of the ingredient */
    title: string;
    /** Relationship to the output */
    relationship: 'parentOf' | 'componentOf' | 'inputTo';
    /** Hash of the ingredient */
    hash?: string;
}
interface C2PAOptions {
    /** Title of the generated content */
    title: string;
    /** Generator name (default: 'protect-mcp') */
    generator?: string;
    /** Generator version */
    version?: string;
    /** Whether to include full receipt data or only hashes */
    includeFullReceipts?: boolean;
    /** Additional assertions to include */
    additionalAssertions?: C2PAAssertion[];
}
/**
 * Create a C2PA manifest from an Acta receipt chain.
 *
 * The manifest contains:
 * - An `acta.decision-provenance` assertion with the receipt chain summary
 * - An `acta.policy-compliance` assertion showing policy adherence
 * - Standard C2PA actions (c2pa.actions) documenting what the agent did
 *
 * @param receipts - Array of Acta receipts from the agent session
 * @param options - Configuration for the manifest
 * @returns C2PA manifest JSON (compatible with c2patool)
 */
declare function createC2PAManifest(receipts: Array<Record<string, unknown>>, options: C2PAOptions): C2PAManifest;
/**
 * Export the C2PA manifest as JSON for use with c2patool.
 *
 * Usage:
 *   const json = exportC2PAManifestJSON(manifest);
 *   fs.writeFileSync('manifest.json', json);
 *   // Then: c2patool output.jpg -m manifest.json -o signed-output.jpg
 */
declare function exportC2PAManifestJSON(manifest: C2PAManifest): string;
/**
 * Generate a c2patool command for embedding the manifest into a file.
 *
 * @param manifestPath - Path to the manifest JSON file
 * @param inputPath - Path to the input file (image, PDF, etc.)
 * @param outputPath - Path for the signed output file
 * @returns The c2patool command to run
 */
declare function generateC2PACommand(manifestPath: string, inputPath: string, outputPath: string): string;
/**
 * Verify that a file contains valid Acta C2PA assertions.
 *
 * @param c2paManifestJson - The C2PA manifest JSON extracted from a file
 * @returns Verification result
 */
declare function verifyActaC2PAAssertions(c2paManifestJson: string): {
    hasActaProvenance: boolean;
    receiptCount: number;
    merkleRoot: string | null;
    complianceRate: string | null;
    verifyUrl: string | null;
};

/**
 * Prediction Lifecycle Bridge
 *
 * Bridges Veritas Acta prediction receipts to external forecasting
 * platforms (Metaculus, Manifold Markets) for calibration tracking.
 *
 * Status: Experimental
 */
interface PredictionReceipt {
    receipt_id: string;
    receipt_type: 'prediction';
    issuer_id: string;
    event_time: string;
    payload: {
        claim: string;
        probability: number;
        resolution_criteria: string;
        resolution_deadline: string;
        domain?: string;
        tags?: string[];
    };
    signature: string;
}
interface PredictionResolution {
    receipt_id: string;
    receipt_type: 'resolution';
    parent_receipts: string[];
    payload: {
        resolved: boolean;
        resolution_value: 'true' | 'false' | 'ambiguous';
        resolution_source: string;
        resolution_time: string;
    };
    signature: string;
}
interface CalibrationScore {
    total_predictions: number;
    resolved: number;
    brier_score: number;
    calibration_buckets: Array<{
        bucket: string;
        predicted_probability: number;
        actual_frequency: number;
        count: number;
    }>;
}
/**
 * Compute Brier score from a set of predictions and their resolutions
 */
declare function computeCalibration(predictions: PredictionReceipt[], resolutions: Map<string, PredictionResolution>): CalibrationScore;
/**
 * Format prediction for Metaculus API submission (placeholder)
 */
declare function toMetaculusFormat(prediction: PredictionReceipt): {
    question_url?: string;
    prediction_value: number;
    acta_receipt_id: string;
    acta_signature: string;
};
/**
 * Format prediction for Manifold Markets API submission (placeholder)
 */
declare function toManifoldFormat(prediction: PredictionReceipt): {
    probability: number;
    acta_receipt_id: string;
    acta_signature: string;
};

/**
 * Agent-to-Agent Receipt Exchange
 *
 * Middleware for multi-agent systems (CrewAI, LangGraph, AutoGen) that
 * propagates receipts across agent boundaries. Each hop produces a
 * chained receipt, enabling end-to-end accountability tracing.
 *
 * Status: Beta — API may change
 *
 * @example
 * ```typescript
 * import { ReceiptPropagator } from 'protect-mcp/agent-exchange';
 *
 * const propagator = new ReceiptPropagator({ issuer: 'agent-alpha' });
 *
 * // Agent A delegates to Agent B
 * const delegation = propagator.delegate('agent-beta', {
 *   tools: ['read_file', 'search_web'],
 *   scope: 'task-123',
 *   ttl: 3600,
 * });
 *
 * // Agent B receives the delegation and wraps its actions
 * const action = propagator.wrapAction('read_file', {
 *   delegation_receipt: delegation.receipt_id,
 *   args: { path: 'data.json' },
 * });
 *
 * // Verify the full chain
 * const chain = propagator.traceChain(action.receipt_id);
 * // Returns: [delegation_receipt, action_receipt]
 * ```
 */
interface DelegationReceipt {
    receipt_id: string;
    receipt_type: 'delegation';
    issuer_id: string;
    event_time: string;
    payload: {
        /** The agent receiving delegated authority */
        delegate_id: string;
        /** Tools the delegate is authorized to use */
        authorized_tools: string[];
        /** Scope identifier for this delegation */
        scope: string;
        /** Time-to-live in seconds */
        ttl: number;
        /** Expiry timestamp */
        expires_at: string;
        /** Maximum number of tool calls allowed */
        max_calls?: number;
        /** Whether the delegate can further sub-delegate */
        allow_subdelegation: boolean;
    };
    parent_receipts: string[];
    signature?: string;
}
interface ActionReceipt {
    receipt_id: string;
    receipt_type: 'execution';
    issuer_id: string;
    event_time: string;
    payload: {
        tool_name: string;
        decision: 'allow' | 'deny';
        delegation_receipt: string;
        scope: string;
        call_index: number;
    };
    parent_receipts: string[];
    signature?: string;
}
interface PropagatorConfig {
    /** Issuer ID for this agent */
    issuer: string;
    /** Optional signing function (receipt → signed receipt) */
    signer?: (receipt: Record<string, unknown>) => Record<string, unknown>;
}
/**
 * Propagates receipts across agent boundaries in multi-agent systems.
 * Each hop produces a chained receipt enabling end-to-end accountability.
 *
 * @patent Patent-protected construction — delegated signing with receipt chain
 * propagation. Covered by Apache 2.0 patent grant for users of this code.
 * Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
declare class ReceiptPropagator {
    private issuer;
    private signer?;
    private receipts;
    private delegationCallCounts;
    constructor(config: PropagatorConfig);
    /**
     * Create a delegation receipt authorizing another agent to use specific tools.
     *
     * @patent Patent-protected construction — delegated signing with receipt chain
     * propagation. Covered by Apache 2.0 patent grant for users of this code.
     * Clean-room reimplementation requires a patent license.
     * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
     */
    delegate(delegateId: string, options: {
        tools: string[];
        scope: string;
        ttl: number;
        maxCalls?: number;
        allowSubdelegation?: boolean;
        parentReceipts?: string[];
    }): DelegationReceipt;
    /**
     * Wrap a tool call with a receipt that references the delegation.
     * Validates the delegation is still valid (not expired, within call limit,
     * tool is authorized).
     *
     * @patent Patent-protected construction — delegated signing with receipt chain
     * propagation. Covered by Apache 2.0 patent grant for users of this code.
     * Clean-room reimplementation requires a patent license.
     * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
     */
    wrapAction(toolName: string, options: {
        delegation_receipt: string;
        args?: Record<string, unknown>;
    }): ActionReceipt;
    /**
     * Trace the full receipt chain from a given receipt back to the root delegation.
     *
     * @patent Patent-protected construction — delegated signing with receipt chain
     * propagation. Covered by Apache 2.0 patent grant for users of this code.
     * Clean-room reimplementation requires a patent license.
     * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
     */
    traceChain(receiptId: string): Array<DelegationReceipt | ActionReceipt>;
    /**
     * Export all receipts as a JSON array (for verification, archival, or Trace visualization).
     */
    exportAll(): Array<DelegationReceipt | ActionReceipt>;
    /**
     * Validate that a delegation chain is intact and all signatures verify.
     *
     * @patent Patent-protected construction — delegated signing with receipt chain
     * propagation. Covered by Apache 2.0 patent grant for users of this code.
     * Clean-room reimplementation requires a patent license.
     * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
     */
    validateChain(receiptId: string): {
        valid: boolean;
        chain_length: number;
        issues: string[];
    };
}
/**
 * Create a LangGraph-compatible state channel that propagates receipts.
 *
 * Usage with LangGraph:
 * ```typescript
 * import { createReceiptChannel } from 'protect-mcp/agent-exchange';
 *
 * const channel = createReceiptChannel('orchestrator');
 *
 * // In your LangGraph node:
 * const result = await channel.withDelegation('worker-agent', ['read_file'], async (ctx) => {
 *   // ctx.delegation is the delegation receipt
 *   // Agent B's actions will reference this delegation
 *   return await agentB.run(ctx.delegation);
 * });
 * ```
 */
declare function createReceiptChannel(orchestratorId: string): {
    propagator: ReceiptPropagator;
    withDelegation<T>(delegateId: string, tools: string[], fn: (ctx: {
        delegation: DelegationReceipt;
        propagator: ReceiptPropagator;
    }) => Promise<T>, options?: {
        ttl?: number;
        maxCalls?: number;
        scope?: string;
    }): Promise<{
        result: T;
        delegation: DelegationReceipt;
        chain: Array<DelegationReceipt | ActionReceipt>;
    }>;
};

/**
 * Confidential Computing Interface
 *
 * Defines the interface for TEE (Trusted Execution Environment) attestation
 * and confidential inference integration. When enabled, agents must prove
 * they generated their keys inside a secure enclave and their code hasn't
 * been tampered with before receiving elevated trust tiers.
 *
 * Status: Beta — Enterprise feature
 *
 * Supported attestation providers:
 * - AWS Nitro Enclaves (via attestation documents)
 * - Intel TDX (via DCAP quotes)
 * - AMD SEV-SNP (via attestation reports)
 * - Generic COSE-signed attestations
 *
 * @example
 * ```typescript
 * import { ConfidentialGate, verifyAttestation } from 'protect-mcp/confidential';
 *
 * const gate = new ConfidentialGate({
 *   require_attestation: true,
 *   accepted_providers: ['nitro', 'tdx'],
 *   min_trust_tier: 'evidenced',
 * });
 *
 * // Agent presents attestation during handshake
 * const result = gate.evaluateAttestation(attestationDoc);
 * // result: { accepted: true, tier: 'privileged', provider: 'nitro' }
 * ```
 */
type AttestationProvider = 'nitro' | 'tdx' | 'sev_snp' | 'generic';
interface AttestationDocument {
    /** The attestation provider */
    provider: AttestationProvider;
    /** Raw attestation bytes (base64-encoded) */
    attestation: string;
    /** Public key generated inside the enclave */
    enclave_public_key: string;
    /** Measurements / PCR values */
    measurements: Record<string, string>;
    /** Timestamp of attestation */
    timestamp: string;
    /** Optional: Nonce used for freshness */
    nonce?: string;
}
interface AttestationResult {
    /** Whether the attestation was accepted */
    accepted: boolean;
    /** Resulting trust tier */
    tier: 'unknown' | 'signed' | 'evidenced' | 'privileged';
    /** Provider that issued the attestation */
    provider: AttestationProvider;
    /** Reason for acceptance or rejection */
    reason: string;
    /** Receipt documenting the attestation evaluation */
    receipt_id?: string;
}
interface ConfidentialGateConfig {
    /** Require attestation for elevated trust tiers */
    require_attestation: boolean;
    /** Accepted attestation providers */
    accepted_providers: AttestationProvider[];
    /** Minimum trust tier that requires attestation */
    min_trust_tier: 'signed' | 'evidenced' | 'privileged';
    /** Expected measurement values (PCRs) for validation */
    expected_measurements?: Record<string, string>;
    /** Maximum age of attestation document (seconds) */
    max_attestation_age?: number;
}
declare class ConfidentialGate {
    private config;
    constructor(config: ConfidentialGateConfig);
    /**
     * Evaluate an attestation document and determine the resulting trust tier.
     */
    evaluateAttestation(doc: AttestationDocument): AttestationResult;
    /**
     * Check if an agent's current tier requires attestation.
     */
    requiresAttestation(currentTier: string): boolean;
    /**
     * Generate an attestation receipt documenting the evaluation.
     */
    toReceipt(result: AttestationResult, agentId: string): Record<string, unknown>;
}
/**
 * Configuration for confidential model inference.
 * Wraps model API calls to ensure data privacy during evaluation.
 */
interface ConfidentialInferenceConfig {
    /** Provider for confidential inference */
    provider: 'local_tee' | 'homomorphic' | 'secure_enclave';
    /** Whether to encrypt prompts before sending to the model */
    encrypt_prompts: boolean;
    /** Whether to verify model outputs came from the expected enclave */
    verify_outputs: boolean;
    /** Homomorphic encryption key (for 'homomorphic' provider) */
    he_public_key?: string;
}
/**
 * Wraps a model inference call with confidential computing guarantees.
 *
 * In 'local_tee' mode: The model runs inside a TEE and provides attestation
 * that the inference was performed correctly.
 *
 * In 'homomorphic' mode: Prompts are encrypted client-side and the model
 * operates on ciphertext (using Zama Concrete ML or similar).
 *
 * In 'secure_enclave' mode: Uses NVIDIA Confidential Computing or similar
 * hardware to ensure the model cannot see plaintext data.
 *
 * Status: Interface only — implementation requires specific TEE/HE SDK integration
 */
declare function confidentialInference(_prompt: string, _config: ConfidentialInferenceConfig): Promise<{
    response: string;
    attestation?: AttestationDocument;
    encrypted: boolean;
    receipt: Record<string, unknown>;
}>;

/**
 * scopeblind-bridge.ts
 *
 * Optional bridge between protect-mcp (local, MIT) and a paid ScopeBlind
 * tenant. When SCOPEBLIND_TOKEN is set in the environment, every signed
 * receipt that protect-mcp emits also gets forwarded to the tenant's
 * dashboard at https://scopeblind.com/console/<slug>.
 *
 * Lifecycle:
 *   1. On first use, exchange SCOPEBLIND_TOKEN for a short-lived BRASS-v2
 *      auth proof from /fn/brass/issue. Cache the proof in memory until
 *      ~5 minutes before expiry, then refresh.
 *   2. As receipts are emitted by hook-server.ts, push them into an
 *      in-memory batch queue.
 *   3. Flush the queue every 5s (or when it reaches 128 receipts) by POSTing
 *      to /fn/console/<slug>/receipts with Bearer SCOPEBLIND_TOKEN.
 *
 * Failure mode: forward errors NEVER throw upstream. protect-mcp continues
 * to mint and persist receipts locally regardless of dashboard availability.
 * The bridge logs failures to stderr (best-effort) and retries on the next
 * flush.
 *
 * Configuration:
 *   SCOPEBLIND_TOKEN        Tenant bearer token (from welcome email).
 *   SCOPEBLIND_TENANT       Optional slug override. By default we discover
 *                           the slug from the BRASS proof's tenant_id.
 *   SCOPEBLIND_BASE         Defaults to https://scopeblind.com.
 *
 * @license MIT
 */
interface BridgeStats {
    enabled: boolean;
    tenant_slug: string | null;
    forwarded_total: number;
    rejected_total: number;
    last_flush_at: string | null;
    last_error: string | null;
}
declare class ScopeBlindBridge {
    private readonly token;
    private readonly base;
    private readonly tenantOverride;
    private cachedProof;
    private queue;
    private flushTimer;
    private stats;
    private shuttingDown;
    constructor(env?: Record<string, string | undefined>);
    enabled(): boolean;
    /** Push a signed receipt into the queue. Non-blocking. */
    forward(signedReceipt: any): void;
    /** Flush the queue. Safe to call concurrently. */
    flush(): Promise<void>;
    /** Exchange SCOPEBLIND_TOKEN for a BRASS-v2 proof; refresh near expiry. */
    private ensureBrassProof;
    /**
     * Return a snapshot of bridge stats. Useful for `protect-mcp scopeblind status`.
     */
    getStats(): BridgeStats & {
        queued: number;
        brass_proof_expires_at: string | null;
    };
    /** Flush remaining receipts and stop the interval. Called on process exit. */
    shutdown(): Promise<void>;
}
declare function getScopeBlindBridge(): ScopeBlindBridge;
/** Convenience: forward a signed receipt without instantiating yourself. */
declare function forwardReceipt(signedReceipt: any): void;

export { type ActionReceipt, type AdmissionResult, type AgentId, type AgentManifest, type ApprovalAssertion, type ApprovalChallenge, type ApprovalNotification, type ApprovalResult, type ArenaPayload, type ArenaReceipt, type AttestationDocument, type AttestationPayload, type AttestationProvider, type AttestationReceipt, type AttestationResult, type AuditBundle, type AuditBundleOptions, type BenchmarkPayload, type BenchmarkReceipt, type BuilderId, type C2PAAssertion, type C2PAIngredient, type C2PAManifest, type C2PAOptions, type CCRConnectorConfig, type CCRSessionContext, CONNECTOR_PILOTS, type CalibrationScore, type CedarEvalOptions, type CedarEvalRequest, type CedarPolicySet, type CedarSchema, type CedarSchemaResult, type CommittedFieldOpening, type CommittedSignResult, type ComplianceReport, ConfidentialGate, type ConfidentialGateConfig, type ConfidentialInferenceConfig, type ConnectorAction, type ConnectorEnvVar, type ConnectorPilot, type ConnectorPilotId, type CredentialConfig, type DecisionContext, type DecisionLog, type DelegationReceipt, type DisclosureMode, type Ed25519PublicKey, type EvidenceAttestation, type EvidenceAttestationInput, type EvidenceIssuer, type EvidenceReceipt, type EvidenceReceiptBase, type EvidenceSummary, type EvidenceSummaryEntry, type EvidenceType, type ExternalDecision, type ExternalPDPConfig, type HFDatasetMetadata, type HFReceiptRow, type HookEventName, type HookInput, type HookResponse, type InstalledConnectorPilot, type IssuerType, type JsonRpcRequest, type JsonRpcResponse, type LeaseCompatibility, type ManifestBuilder, type ManifestCapabilities, type ManifestConfig, type ManifestIdentity, type ManifestPresentation, type ManifestSignature, type ManifestStatus, type McpToolDescription, type MinimalDisclosure, type NotificationConfig, POLICY_PACKS, type PassportTokenClaims, type PayloadDigest, type PlanReceipt, type PolicyEngineMode, type PolicyPack, type PredictionReceipt, type PredictionResolution, type PropagatorConfig, type ProtectConfig, ProtectGateway, type ProtectPolicy, type RateLimit, ReceiptPropagator, type RedactedResult, type RedactionSalt, type RekorAnchor, type RekorVerification, type RestraintPayload, type RestraintReceipt, type SHA256Hash, type SafetyTranscript, type Sandbox, type SandboxConfig, type SandboxReceipt, type SandboxResult, type SandboxToolCall, type SchemaGeneratorConfig, ScopeBlindBridge, type SelectiveDisclosurePackageV0, type SelectiveDisclosureVerification, type SelfTestCase, type SelfTestReport, type SigningConfig, type SimulationResult, type SimulationSummary, type SwarmContext, type TierOverrides, type TimingMetrics, type ToolPolicy, type TrustTier, type WorkPayload, type WorkReceipt, anchorToRekor, buildDecisionContext, checkRateLimit, collectSignedReceipts, computeCalibration, confidentialInference, connectorDirectory, connectorDoctor, connectorPilotIds, createApprovalChallenge, createApprovalReceiptPayload, createAttestationField, createAuditBundle, createC2PAManifest, createDisclosurePackage, createEvidenceAttestation, createLogAnchorField, createReceiptChannel, createSandbox, createSelectiveDisclosurePackage, destroySandbox, discloseField, ed25519ToDIDKey, evaluateCedar, evaluateTier, exportC2PAManifestJSON, exportJSONL, formatReportMarkdown, formatSimulation, forwardReceipt, generateC2PACommand, generateCedarSchema, generateDatasetCard, generateHFMetadata, generateReport, generateSafetyTranscript, generateSchemaStub, getConnectorPilot, getPolicyPack, getScopeBlindBridge, getSignerInfo, getToolPolicy, hashReceipt, hashResponseBody, initSigning, isAgentId, isCedarAvailable, isDisclosureMode, isEvidenceType, isManifestStatus, isSigningEnabled, listCredentialLabels, loadCedarPolicies, loadPolicy, manifestToVC, meetsMinTier, parseLogFile, parseNotificationConfigFromEnv, parseRateLimit, policyPackIds, policySetFromSource, queryExternalPDP, readInstalledConnectorPilots, receiptToVP, receiptsToHFRows, redactFields, resolveCredential, revealField, runEvaluatorSelfTest, runInSandbox, sendApprovalNotification, signCommittedDecision, signDecision, simulate, toCredentialRequestOptions, toManifoldFormat, toMetaculusFormat, validateCredentials, validateEvidenceReceipt, validateManifest, verifyActaC2PAAssertions, verifyAllCommitments, verifyApprovalAssertion, verifyCommitment, verifyEvidenceAttestation, verifyRekorAnchor, verifySelectiveDisclosurePackage, writeConnectorPilots };
