export { HookServerOptions, startHookServer } from './hook-server.mjs';
export { BUILTIN_PATTERNS, HookPattern, generateHookSettings, generateSampleCedarPolicy, generateVerifyReceiptSkill } from './hook-patterns.mjs';
export { createSandboxServer } from './demo-server.mjs';
import 'node:http';

interface PaymentInfo {
    /** Normalized human amount in `asset` units, when derivable; else null. */
    amount: number | null;
    /** Asset symbol (e.g. 'USDC') or contract address, when derivable; else null. */
    asset: string | null;
    /** SHA-256 (hex) of the lowercased recipient: position-blind, when present. */
    recipient_digest: string | null;
    /** x402 scheme ('exact' | 'upto' | ...) when present. */
    scheme?: string;
}
interface ReceiptEnrichment {
    /** Rule/schema version, so derivations stay reproducible as rules evolve. */
    v: number;
    /** SHA-256 (hex) of the canonical tool input. */
    input_digest: string;
    /** Sorted, deterministic capability tags (heuristic organisation labels). */
    capabilities: string[];
    /** Hashed coarse resource for clustering, when one is derivable. */
    resource?: {
        kind: 'path' | 'host' | 'command';
        digest: string;
    };
    /** Minimum-disclosure facts about a value transfer (x402 / agent payment). */
    payment?: PaymentInfo;
}

interface Money {
    minor: number;
    currency: string;
}
interface StandardGate {
    request_id: string;
    digest: string;
    /** The author's Ed25519 verification key (hex). Approvals on the page are signed with it or with a key the standard's trust block accepts. */
    signer_key: string;
    /** Tools the standard permits; null when the standard names none (a standard without a run block). */
    tools: string[] | null;
    /** The per-instruction limit; null when the standard sets none. */
    amount_max: Money | null;
    /** The amount above which a named person approves; null when the standard needs no person. */
    required_above: Money | null;
    /** The gate policy digest the standard was signed with, when it carries one. */
    policy_digest: string | null;
    /** Plain words for the log line at startup. */
    summary: string;
}
interface HeldDecision {
    decision: 'approve' | 'deny';
    approver_key_id: string;
    digest: string;
    note: string;
}
type FetchLike = (input: string, init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
}) => Promise<{
    ok: boolean;
    status: number;
    json(): Promise<unknown>;
}>;
/**
 * Posts receipts and held actions to the standard's page and reads decisions
 * from it. Every network failure is logged and swallowed: the local chain is
 * the record; the page is where it lands.
 */
declare class RecordReporter {
    readonly url: string;
    readonly sid: string;
    readonly runId: string;
    private readonly token;
    private readonly fetchImpl;
    private readonly log;
    private queue;
    private timer;
    private flushing;
    /** Counts for the startup and shutdown lines. */
    sent: number;
    failed: number;
    constructor(opts: {
        url: string;
        token: string;
        runId: string;
        fetchImpl?: FetchLike;
        log?: (message: string) => void;
    });
    private post;
    /** Queues one receipt line (and its call line) for the next flush. Never throws. */
    record(receipt: string | undefined, call?: string): void;
    /** Sends everything queued, in order, as one append. */
    flush(): Promise<void>;
    /** Posts a held action. Returns the page URL to send the model to, or null when the page could not be reached. */
    hold(held: {
        hid: string;
        request_id: string;
        tool: string;
        readback: {
            summary: string;
            payload_hash: string;
            amount?: number | null;
            currency?: string | null;
        };
        reason: string;
    }): Promise<string | null>;
    /** The decision a person recorded for a held action: approve, deny, none yet (null), or unreachable. */
    decision(hid: string): Promise<HeldDecision | null | 'unreachable'>;
}

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
    /** The signed standard in force when this decision was made (--standard) */
    standard?: {
        request_id: string;
        digest: string;
    };
    /** A named person's signed decision on the standard's page, attached to the receipt of the call it decided */
    approval?: {
        hid: string;
        approver_key_id: string;
        digest: string;
        page: string;
    };
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
    /** Deterministic enrichment (input digest, capability tags, hashed resource) */
    enrichment?: ReceiptEnrichment;
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
    /** Managed-mandate state that governed this decision, signed into the receipt. */
    mandate_registry?: {
        registry_id: string;
        active_policy_digest: string;
        active_transition_hash: string;
        expires_at?: string;
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
    /** How the input was serialised before hashing: 'jcs' (sorted keys, ASCII-only, as `sign` writes) or absent for the hook server's JSON.stringify form. */
    canonical?: 'jcs';
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
    /** The signed standard in force: its tool list, per-instruction limit, and approval threshold (--standard) */
    standard?: StandardGate;
    /** Where the record lands and held actions wait for the named person (--report) */
    reporter?: RecordReporter;
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
    /** "sha256:<64 hex>" under acta-policy-digest-v1 (see policy-digest.ts) */
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
    /**
     * Which Cedar action the tool call is evaluated as. 'mcp' (default) is the
     * runtime model: Action::"MCP::Tool::call" with the tool as the resource.
     * 'tool' uses the tool name itself as the action (Action::"Bash"), which is
     * the model the published conformance policy in
     * agent-governance-testvectors/fixtures/policy is written against.
     */
    actionModel?: 'mcp' | 'tool';
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
    /** s5.7 hash of the last line appended to the receipt file (chain link) */
    private lastReceiptHash;
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
    /** The signed standard in force (--standard) and the page its record lands on (--report) */
    private standard;
    private reporter;
    /** A person's decision on the page, attached to the receipt of the call it decided (keyed by request_id) */
    private approvalsToRecord;
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

/** Explicit trust and room configuration for the installed coordination adapter. */
interface CoordinationConfig {
    endpoint: string;
    roomId: string;
    authorityKey: string;
    token: string;
    runId?: string;
    timeoutMs?: number;
    /** Presentation only; server-side grant checks remain authoritative. */
    purpose?: 'execution' | 'rehearsal' | 'negotiation';
    /** Negotiation identity is pinned by the separate principal-authorized pairing. */
    sessionId?: string;
    principalKey?: string;
}
declare function validateCoordinationConfig(config: CoordinationConfig): CoordinationConfig;
/** Credentials deliberately have no command-line-value flag and are never printed. */
declare function coordinationConfigFromArgs(args: string[], env?: NodeJS.ProcessEnv): CoordinationConfig;

declare const DECISION_ACTIONS: readonly ["decision_inbox", "decision_subscribe", "decision_unsubscribe", "decision_notification_status"];

declare const AGENT_REQUEST_ACTIONS: readonly ["agent_request_create", "agent_request_get", "agent_request_accept", "agent_request_revoke", "agent_request_reconnect", "agent_handoff_get", "agent_handoff_create", "agent_handoff_claim", "agent_handoff_revoke"];

/** Durable client/project context. Membership and preparation authority never replace exact PR approvals. */

declare const REPOSITORY_WORKSPACE_ACTIONS: readonly ["repository_workspace_create", "repository_workspace_get", "repository_workspace_list", "repository_workspace_inbox", "repository_workspace_invite", "repository_workspace_join", "repository_workspace_member_update", "repository_workspace_recovery_enroll", "repository_workspace_recover", "repository_workspace_assign", "repository_workspace_claim", "repository_workspace_task_get", "repository_workspace_mandate", "repository_workspace_adopt", "repository_workspace_mandate_revoke", "repository_workspace_agent_get", "repository_workspace_draft", "repository_workspace_draft_decide"];
type RepositoryWorkspaceAction = typeof REPOSITORY_WORKSPACE_ACTIONS[number];
type WorkspaceRole = 'owner' | 'reviewer' | 'observer';
interface RepositoryWorkspace {
    type: 'scopeblind.repository.workspace.v1';
    id: string;
    title: string;
    client_name: string;
    repository: string;
    base_branch: string;
    receiver_key: string;
    authority_key: string;
    owner_member_id: string;
    owner_key: string;
    issued_at: string;
    expires_at: string;
}
interface WorkspaceInvitation {
    type: 'scopeblind.repository.workspace-invitation.v1';
    id: string;
    workspace_id: string;
    workspace_digest: string;
    member_id: string;
    role: 'reviewer' | 'observer';
    display_name: string;
    issuer_key: string;
    secret_hash: string;
    issued_at: string;
    expires_at: string;
}
interface WorkspaceMemberClaim {
    type: 'scopeblind.repository.workspace-member-claim.v1';
    workspace_id: string;
    invitation_digest: string;
    member_id: string;
    member_key: string;
    issued_at: string;
}
interface WorkspaceMemberUpdate {
    type: 'scopeblind.repository.workspace-member-update.v1';
    id: string;
    workspace_id: string;
    member_id: string;
    expected_revision: number;
    role: 'reviewer' | 'observer';
    status: 'active' | 'revoked';
    issuer_key: string;
    issued_at: string;
}
interface WorkspaceRecovery {
    type: 'scopeblind.repository.workspace-recovery.v1';
    id: string;
    workspace_id: string;
    member_id: string;
    member_key: string;
    recovery_key: string;
    expected_revision: number;
    issued_at: string;
    expires_at: string;
    previous_recovery_digest?: string;
}
interface WorkspaceRotation {
    type: 'scopeblind.repository.workspace-key-rotation.v1';
    id: string;
    workspace_id: string;
    member_id: string;
    previous_key: string;
    new_key: string;
    recovery_digest: string;
    expected_revision: number;
    issued_at: string;
}
interface WorkspaceRotationProof {
    recovery: Signed<WorkspaceRecovery>;
    rotation: Signed<WorkspaceRotation>;
    confirmation: Signed<WorkspaceRotation>;
}
interface WorkspaceMember {
    member_id: string;
    display_name: string;
    role: WorkspaceRole;
    status: 'active' | 'revoked';
    current_key: string;
    revision: number;
    invitation: Signed<WorkspaceInvitation> | null;
    claim: Signed<WorkspaceMemberClaim> | null;
    recovery: Signed<WorkspaceRecovery> | null;
    rotations: WorkspaceRotationProof[];
    updates: Signed<WorkspaceMemberUpdate>[];
}
interface WorkspaceTaskAssignment {
    type: 'scopeblind.repository.workspace-task-assignment.v1';
    workspace_id: string;
    workspace_digest: string;
    task_id: string;
    task_digest: string;
    owner_member_id: string;
    owner_key: string;
    owner_member_revision: number;
    reviewer_member_id: string;
    reviewer_key: string;
    reviewer_member_revision: number;
    review_brief_digest: string;
    source_draft_digest?: string;
    issued_at: string;
    expires_at: string;
}
type WorkspaceAgentPermission = 'prepare_review' | 'read_task' | 'report_criteria' | 'request_revision';
interface WorkspacePreparationMandate {
    type: 'scopeblind.repository.preparation-mandate.v1';
    id: string;
    workspace_id: string;
    workspace_digest: string;
    mode: 'prepare_review';
    owner_member_id: string;
    owner_key: string;
    owner_member_revision: number;
    reviewer_member_id: string;
    reviewer_key: string;
    reviewer_member_revision: number;
    agent_key: string;
    repository: string;
    base_branch: string;
    allowed_paths: string[];
    required_checks: Array<{
        name: string;
        app_id: number;
    }>;
    permissions: WorkspaceAgentPermission[];
    max_requests: number;
    max_open_requests: number;
    issued_at: string;
    expires_at: string;
}
interface WorkspaceMandateRevocation {
    type: 'scopeblind.repository.preparation-revocation.v1';
    mandate_id: string;
    mandate_digest: string;
    workspace_id: string;
    principal_key: string;
    issued_at: string;
}
interface WorkspaceMandateView {
    mandate: Signed<WorkspacePreparationMandate>;
    adoption: Signed<WorkspacePreparationMandate> | null;
    revocation: Signed<WorkspaceMandateRevocation> | null;
    status: 'awaiting_reviewer' | 'active' | 'expired' | 'revoked' | 'membership_changed' | 'exhausted';
    used_requests: number;
    open_requests: number;
}
interface WorkspaceReviewDraft {
    type: 'scopeblind.repository.workspace-review-draft.v1';
    id: string;
    workspace_id: string;
    mandate_digest: string;
    agent_key: string;
    repository: string;
    pull_number: number;
    title: string;
    content: RepositoryReviewContent;
    allowed_paths: string[];
    required_checks: Array<{
        name: string;
        app_id: number;
    }>;
    suggested_preview_url?: string;
    observed_head_sha?: string;
    source?: {
        task_id: string;
        task_digest: string;
        basis_digest: string;
        packet_digest: string;
        feedback_digest: string;
    };
    issued_at: string;
}
interface WorkspaceDraftDecision {
    type: 'scopeblind.repository.workspace-draft-decision.v1';
    workspace_id: string;
    draft_digest: string;
    owner_key: string;
    decision: 'adopt' | 'reject';
    task_id?: string;
    task_digest?: string;
    note: string;
    issued_at: string;
}
interface WorkspaceDraftView {
    draft: Signed<WorkspaceReviewDraft>;
    decision: Signed<WorkspaceDraftDecision> | null;
}
interface RepositoryWorkspaceState {
    type: 'scopeblind.repository.workspace-state.v1';
    workspace: Signed<RepositoryWorkspace>;
    members: WorkspaceMember[];
    invitations: Signed<WorkspaceInvitation>[];
    assignments: Signed<WorkspaceTaskAssignment>[];
    mandates: WorkspaceMandateView[];
    drafts: WorkspaceDraftView[];
    viewer: {
        key: string;
        member_id: string | null;
        role: WorkspaceRole | null;
        capabilities: string[];
    };
    observed_at: string;
}
interface WorkspaceAttentionItem {
    id: string;
    workspace_id: string;
    task_id: string | null;
    title: string;
    state: string;
    who_waits: string;
    action: 'review_draft' | 'join_review' | 'inspect' | 'review_change' | 'accept_result' | 'read_feedback' | 'reconcile' | 'replace_review' | 'adopt_mandate';
    target_digest: string;
    task_digest?: string;
    proposal_digest?: string;
    can_act: boolean;
    disabled_reason: string | null;
    href: string;
    updated_at: string;
}
interface RepositoryWorkspaceInbox {
    type: 'scopeblind.repository.workspace-inbox.v1';
    viewer_key: string;
    items: WorkspaceAttentionItem[];
    has_more: boolean;
    observed_at: string;
}
interface RepositoryWorkspaceAgentState {
    type: 'scopeblind.repository.workspace-agent-state.v1';
    workspace: Signed<RepositoryWorkspace>;
    mandate: WorkspaceMandateView;
    members: WorkspaceMember[];
    drafts: WorkspaceDraftView[];
    observed_at: string;
}
/** Verifies signatures and membership history. Live state remains a service observation, never an effect grant. */
declare function verifyRepositoryWorkspaceState(value: unknown, authorityKey: string, viewerKey?: string): Promise<boolean>;
declare function verifyRepositoryWorkspaceAgentState(value: unknown, authorityKey: string, agentKey?: string): Promise<boolean>;

/** Real repository tasks. Browser/Worker/Node contract; no credentials or I/O. */

declare const REPOSITORY_ACTIONS: readonly ["repository_create", "repository_get", "repository_claim", "repository_propose", "repository_approve", "repository_cancel", "repository_begin", "repository_outcome", "repository_accept", "repository_export"];
type RepositoryAction = typeof REPOSITORY_ACTIONS[number];
interface RepositoryTask {
    type: 'scopeblind.repository.task.v1';
    id: string;
    title: string;
    repository: string;
    pull_number: number;
    base_branch: string;
    owner_key: string;
    receiver_key: string;
    authority_key: string;
    allowed_paths: string[];
    required_checks: Array<{
        name: string;
        app_id: number;
    }>;
    reviewer_secret_hash: string;
    issued_at: string;
    expires_at: string;
}
interface RepositoryClaim {
    type: 'scopeblind.repository.claim.v1';
    task_id: string;
    task_digest: string;
    reviewer_key: string;
    name: string;
    issued_at: string;
}
interface RepositoryFile {
    path: string;
    previous_path?: string;
    status: 'added' | 'modified' | 'removed' | 'renamed';
    mode: '100644' | '100755';
    additions: number;
    deletions: number;
    patch?: string;
    patch_truncated?: true;
}
interface RepositoryCheck {
    id: number;
    name: string;
    app_id: number;
    head_sha: string;
    conclusion: 'success';
}
interface RepositoryProposal {
    type: 'scopeblind.repository.proposal.v1';
    id: string;
    task_id: string;
    task_digest: string;
    repository_id: string;
    base_ref: string;
    head_ref: string;
    base_sha: string;
    head_sha: string;
    merge_sha: string;
    tree_sha: string;
    files: RepositoryFile[];
    checks: RepositoryCheck[];
    observed_at: string;
}
interface RepositoryApproval {
    type: 'scopeblind.repository.approval.v1';
    task_id: string;
    task_digest: string;
    proposal_digest: string;
    role: 'owner' | 'reviewer';
    principal_key: string;
    decision: 'approve' | 'reject';
    issued_at: string;
    expires_at: string;
    note: string;
}
interface RepositoryExecution {
    type: 'scopeblind.repository.execution.v1';
    operation_id: string;
    receiver_attempt_id: string;
    task_id: string;
    task_digest: string;
    proposal_digest: string;
    owner_approval_digest: string;
    reviewer_approval_digest: string;
    receiver_key: string;
    action: 'github.updateRefs';
    issued_at: string;
    expires_at: string;
}
interface RepositoryOutcome {
    type: 'scopeblind.repository.outcome.v1';
    operation_id: string;
    task_id: string;
    task_digest: string;
    proposal_digest: string;
    execution_digest: string;
    status: 'confirmed' | 'failed' | 'unknown';
    observed_base_sha: string | null;
    readback: 'exact_ref' | 'descendant_ref' | 'not_confirmed';
    github_request_id?: string;
    observed_at: string;
    note: string;
}
interface RepositoryAcceptance {
    type: 'scopeblind.repository.acceptance.v1';
    task_id: string;
    task_digest: string;
    outcome_digest: string;
    reviewer_key: string;
    decision: 'accept' | 'request_changes';
    issued_at: string;
    note: string;
}
interface RepositoryState {
    type: 'scopeblind.repository.state.v1';
    task: Signed<RepositoryTask>;
    reviewer: Signed<RepositoryClaim> | null;
    proposal: Signed<RepositoryProposal> | null;
    approvals: Signed<RepositoryApproval>[];
    execution: Signed<RepositoryExecution> | null;
    outcome: Signed<RepositoryOutcome> | null;
    acceptance: Signed<RepositoryAcceptance> | null;
    status: 'awaiting_reviewer' | 'awaiting_snapshot' | 'review' | 'approved' | 'executing' | 'confirmed' | 'unknown' | 'failed' | 'rejected' | 'cancelled' | 'accepted' | 'changes_requested';
    revision: number;
    observed_at: string;
}
interface RepositoryEvidence {
    type: 'scopeblind.repository.evidence.v1';
    state: Signed<RepositoryState>;
}
declare function repositorySnapshotDigest(p: RepositoryProposal): Promise<string>;
/** Verifies recorded signatures and bindings, not GitHub's independent truth.
 * GitHub API observations are attested by the explicitly trusted receiver. */
declare function verifyRepositoryEvidence(value: unknown, pin?: string | {
    authority_key: string;
    owner_key?: string;
    reviewer_key?: string;
    receiver_key?: string;
}): Promise<{
    valid: boolean;
    errors: string[];
    accepted: boolean;
    authorityPinned: boolean;
    limitations: string[];
}>;

declare const REPOSITORY_REVIEW_ACTIONS: readonly ["repository_review_get", "repository_review_packet", "repository_review_feedback", "repository_review_recommendation", "repository_review_export"];
type RepositoryReviewAction = typeof REPOSITORY_REVIEW_ACTIONS[number];
interface RepositoryReviewContent {
    brief: string;
    success_criteria: Array<{
        id: string;
        text: string;
    }>;
    preview_policy?: {
        environment: string;
        check: {
            name: string;
            app_id: number;
        };
        allowed_origins: string[];
        required: boolean;
    };
}
interface RepositoryReviewBrief extends RepositoryReviewContent {
    type: 'scopeblind.repository.review-brief.v1';
    task_id: string;
    task_digest: string;
    owner_key: string;
    issued_at: string;
    expires_at: string;
}
/** The receiver attests to API metadata, not to the bytes served by this mutable URL. */
interface RepositoryDeploymentObservation {
    deployment_id: number;
    status_id: number;
    sha: string;
    environment: string;
    state: 'success';
    environment_url: string;
    deployment_creator_id: number;
    status_creator_id: number;
    created_at: string;
    updated_at: string;
    check: {
        id: number;
        name: string;
        app_id: number;
        head_sha: string;
        conclusion: 'success';
    };
}
/** Separate GitHub Actions artifact metadata. No assertion binds this artifact's bytes to a preview URL. */
interface RepositoryArtifactObservation {
    id: number;
    name: string;
    sha256: string;
    workflow_run_id: number;
    head_sha: string;
    expires_at: string;
}
type RepositoryReviewPreview = {
    status: 'not_requested' | 'missing' | 'pending' | 'failed' | 'unavailable' | 'ambiguous';
    reason: string;
} | {
    status: 'available';
    deployment: RepositoryDeploymentObservation;
    artifact?: RepositoryArtifactObservation;
};
interface RepositoryReviewPacket {
    type: 'scopeblind.repository.review-packet.v1';
    task_id: string;
    task_digest: string;
    brief_digest: string;
    proposal_digest: string;
    base_sha: string;
    head_sha: string;
    merge_sha: string;
    preview: RepositoryReviewPreview;
    observed_at: string;
    expires_at: string;
}
/** Signed together with the ordinary v1 approval; neither signature may be substituted for the other. */
interface RepositoryReviewDecision {
    type: 'scopeblind.repository.review-decision.v1';
    task_id: string;
    task_digest: string;
    brief_digest: string;
    packet_digest: string;
    proposal_digest: string;
    approval_digest: string;
    principal_key: string;
    role: 'owner' | 'reviewer';
    issued_at: string;
    expires_at: string;
}
interface RepositoryReviewFeedback {
    type: 'scopeblind.repository.review-feedback.v1';
    id: string;
    task_id: string;
    task_digest: string;
    basis_digest: string;
    packet_digest: string;
    requester_key: string;
    mandate_digest?: string;
    criterion_ids: string[];
    message: string;
    requested_changes: string;
    issued_at: string;
}
type RepositoryCriterionEvidence = {
    kind: 'check';
    id: number;
} | {
    kind: 'file';
    path: string;
} | {
    kind: 'deployment';
    id: number;
} | {
    kind: 'artifact';
    sha256: string;
};
interface RepositoryReviewRecommendation {
    type: 'scopeblind.repository.review-recommendation.v1';
    id: string;
    task_id: string;
    task_digest: string;
    packet_digest: string;
    proposal_digest: string;
    brief_digest: string;
    agent_key: string;
    mandate_digest: string;
    recommendation: 'ready_for_human_review' | 'changes_recommended' | 'insufficient_evidence';
    criteria: Array<{
        criterion_id: string;
        verdict: 'met' | 'not_met' | 'unknown';
        evidence_refs: RepositoryCriterionEvidence[];
        explanation: string;
    }>;
    source: {
        kind: 'agent';
        model?: string;
    };
    observed_at: string;
}
interface RepositoryReviewAgentUse {
    type: 'scopeblind.repository.review-agent-use.v1';
    task_id: string;
    task_digest: string;
    record_digest: string;
    permission: 'report_criteria' | 'request_revision';
    mandate: Signed<WorkspacePreparationMandate>;
    adoption: Signed<WorkspacePreparationMandate>;
    assignment: Signed<WorkspaceTaskAssignment>;
    checked_at: string;
}
interface RepositoryReviewState {
    type: 'scopeblind.repository.review-state.v1';
    task_id: string;
    task_digest: string;
    origin_digest?: string;
    coding_origin_digest?: string;
    brief: Signed<RepositoryReviewBrief>;
    packet: Signed<RepositoryReviewPacket> | null;
    decisions: Array<Signed<RepositoryReviewDecision>>;
    feedback: Array<Signed<RepositoryReviewFeedback>>;
    recommendations: Array<Signed<RepositoryReviewRecommendation>>;
    history: Array<{
        state: Signed<RepositoryState>;
        packet: Signed<RepositoryReviewPacket>;
        decisions: Array<Signed<RepositoryReviewDecision>>;
    }>;
    agent_uses: Array<Signed<RepositoryReviewAgentUse>>;
    observed_at: string;
}
/** Owner-local import: observed choices only; importing does not authorize a preview or a task. */
interface RepositoryPreviewDiscovery {
    type: 'scopeblind.repository.preview-discovery.v1';
    repository: string;
    pull_number: number;
    head_sha: string;
    owner_key: string;
    receiver_key: string;
    authority_key: string;
    candidates: Array<{
        environment: string;
        origin: string;
        environment_url: string;
        deployment_id: number;
        status_id: number;
    }>;
    checks: Array<{
        name: string;
        app_id: number;
        id: number;
    }>;
    status: 'observed' | 'unavailable';
    observed_at: string;
    expires_at: string;
}

/** Companion records for repository v1 tasks. None widens a v1 human/receiver role. */

declare const REPOSITORY_COLLABORATION_ACTIONS: readonly ["repository_connection_save", "repository_connection_get", "repository_readiness_record", "repository_participants_bind", "repository_collaboration_get", "repository_collaboration_export", "repository_preview_record", "repository_agent_grant", "repository_agent_revoke", "repository_agent_get", "repository_revision_request", "repository_revision_create", "repository_demo_info", "repository_demo_create", "repository_demo_get", "repository_demo_activate", "repository_demo_enqueue", "repository_demo_poll", "repository_demo_complete"];
type RepositoryCollaborationAction = typeof REPOSITORY_COLLABORATION_ACTIONS[number];
interface RepositoryConnection {
    type: 'scopeblind.repository.connection.v1';
    id: string;
    endpoint: string;
    repository: string;
    base_branch: string;
    owner_key: string;
    receiver_key: string;
    authority_key: string;
    issued_at: string;
    expires_at: string;
}
interface RepositoryReadiness {
    type: 'scopeblind.repository.readiness.v1';
    connection_digest: string;
    repository: string;
    base_branch: string;
    owner_key: string;
    receiver_key: string;
    authority_key: string;
    checks: Array<{
        name: string;
        app_id: number;
        app_name?: string;
    }>;
    base_sha: string;
    check_head_sha: string;
    required_checks?: Array<{
        name: string;
        app_id: number | null;
    }>;
    protection: 'observed' | 'unavailable';
    runtime: 'local' | 'github_actions';
    workflow: 'not_checked' | 'missing' | 'matching' | 'different' | 'unavailable';
    workflow_sha?: string;
    observed_at: string;
    expires_at: string;
}
interface RepositoryParticipants {
    type: 'scopeblind.repository.participants.v1';
    task_id: string;
    task_digest: string;
    owner_key: string;
    receiver_key: string;
    reviewer_key: string;
    reviewer_claim_digest: string;
    issued_at: string;
    expires_at: string;
}
interface ContactPage {
    type: 'scopeblind.contact-page.v1';
    button_label: string;
    target: 'broken' | 'contact';
    accent: 'indigo' | 'emerald' | 'rose';
}
interface RepositoryPreview {
    type: 'scopeblind.repository.preview.v1';
    task_id: string;
    task_digest: string;
    proposal_digest: string;
    base_sha: string;
    head_sha: string;
    merge_sha: string;
    tree_sha: string;
    path: 'demo/contact.json';
    before: {
        model: ContactPage;
        blob_sha: string;
        content_sha256: string;
    };
    after: {
        model: ContactPage;
        blob_sha: string;
        content_sha256: string;
    };
    renderer: 'scopeblind.contact-page.v1';
    observed_at: string;
}
interface RepositoryAgentGrant {
    type: 'scopeblind.repository.agent-grant.v1';
    id: string;
    task_id: string;
    task_digest: string;
    issuer_key: string;
    agent_key: string;
    permissions: Array<'read_task' | 'request_revision'>;
    issued_at: string;
    expires_at: string;
}
interface RepositoryRevisionRequest {
    type: 'scopeblind.repository.revision-request.v1';
    id: string;
    task_id: string;
    task_digest: string;
    basis_digest: string;
    requester_key: string;
    grant_digest?: string;
    message: string;
    proposed: ContactPage;
    issued_at: string;
}
interface RepositoryRevisionLink {
    type: 'scopeblind.repository.revision-link.v1';
    id: string;
    parent_task_id: string;
    parent_task_digest: string;
    parent_basis_digest: string;
    request_digest: string;
    child_task_id: string;
    child_task_digest: string;
    owner_key: string;
    issued_at: string;
}
interface RepositoryCollaboration {
    type: 'scopeblind.repository.collaboration.v1';
    task_id: string;
    task_digest: string;
    participants: Signed<RepositoryParticipants> | null;
    preview: Signed<RepositoryPreview> | null;
    requests: Array<Signed<RepositoryRevisionRequest>>;
    revisions: Array<Signed<RepositoryRevisionLink>>;
    agent_grants: Array<{
        grant: Signed<RepositoryAgentGrant>;
        revoked: boolean;
    }>;
    observed_at: string;
}
interface RepositoryDemoRequest {
    type: 'scopeblind.repository.demo-request.v1';
    id: string;
    owner_key: string;
    receiver_key: string;
    authority_key: string;
    title: string;
    goal: string;
    proposed: ContactPage;
    reviewer_secret_hash: string;
    issued_at: string;
    expires_at: string;
    parent_task_id?: string;
    parent_task_digest?: string;
    parent_basis_digest?: string;
    revision_request_digest?: string;
}
interface RepositoryDemoProvision {
    type: 'scopeblind.repository.demo-provision.v1';
    request_id: string;
    request_digest: string;
    repository: string;
    base_branch: string;
    head_branch: string;
    pull_number: number;
    initial_base_sha: string;
    initial_head_sha: string;
    receiver_key: string;
    required_checks: Array<{
        name: string;
        app_id: number;
    }>;
    observed_at: string;
}
interface RepositoryDemoState {
    type: 'scopeblind.repository.demo-state.v1';
    request: Signed<RepositoryDemoRequest>;
    provision: Signed<RepositoryDemoProvision> | null;
    task: Signed<RepositoryTask> | null;
    status: 'queued' | 'provisioning' | 'ready_to_review' | 'active' | 'failed' | 'expired';
    dispatch: 'requested' | 'unconfigured' | 'unavailable';
    error: string | null;
    observed_at: string;
}

/** Guided installation is a connection, never a task approval or a standing effect grant. */

declare const REPOSITORY_SETUP_ACTIONS: readonly ["repository_setup_info", "repository_setup_create", "repository_setup_get", "repository_setup_diagnose", "repository_setup_job_status", "repository_setup_oauth", "repository_setup_enroll", "repository_setup_confirm", "repository_setup_ready", "repository_setup_coding_ready", "repository_setup_refresh", "repository_setup_renew", "repository_setup_revoke", "repository_setup_dispatch", "repository_setup_job_get", "repository_setup_job_complete"];
type RepositorySetupAction = typeof REPOSITORY_SETUP_ACTIONS[number];
declare const REPOSITORY_GUIDED_WORKFLOW = ".github/workflows/scopeblind-connection.yml";
declare const REPOSITORY_SETUP_TTL: number;
declare const REPOSITORY_CODING_IMAGE = "node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752";
interface RepositorySetupRequest {
    type: 'scopeblind.repository.setup-request.v1';
    id: string;
    owner_key: string;
    authority_key: string;
    repository: string;
    pull_number: number;
    mode: 'github_app' | 'owner_local';
    secret_hash: string;
    state_hash: string;
    pkce_challenge: string;
    issued_at: string;
    expires_at: string;
}
interface RepositorySetupInfo {
    type: 'scopeblind.repository.setup-info.v1';
    authority_key: string;
    endpoint: string;
    observed_at: string;
    app: {
        available: boolean;
        slug: string | null;
        client_id: string | null;
        callback_url: string;
        install_url: string | null;
    };
    receiver: {
        version: string;
        url: string;
        sha256: string | null;
    };
    coding_image: string;
}
/** This is a service observation of authenticated GitHub API responses, not a GitHub signature. */
interface RepositorySetupGitHub {
    type: 'scopeblind.repository.setup-github.v1';
    setup_digest: string;
    app_id: number;
    installation_id: number;
    user_id: number;
    login: string;
    repository_id: number;
    repository: string;
    default_branch: string;
    permissions: {
        admin: boolean;
        push: boolean;
    };
    repository_selection: 'selected';
    observed_at: string;
}
/** Read-only preparation before a guest joins; no merge readiness or preview bytes are claimed. */
interface RepositorySetupInspection {
    type: 'scopeblind.repository.setup-inspection.v1';
    setup_digest: string;
    owner_key: string;
    receiver_key: string;
    repository: string;
    repository_id: number;
    pull_number: number;
    title: string;
    url: string;
    base_branch: string;
    head_branch: string;
    base_sha: string;
    head_sha: string;
    draft: boolean;
    mergeable: boolean | null;
    files: Array<{
        path: string;
        previous_path?: string;
        status: 'added' | 'modified' | 'removed' | 'renamed';
        additions: number;
        deletions: number;
        patch?: string;
        patch_truncated?: true;
    }>;
    checks: Array<{
        id: number;
        name: string;
        app_id: number;
        head_sha: string;
        status: 'queued' | 'in_progress' | 'completed';
        conclusion: string | null;
    }>;
    preview: Signed<RepositoryPreviewDiscovery> | null;
    observed_at: string;
    expires_at: string;
}
interface RepositorySetupInstallation {
    workflow_path: typeof REPOSITORY_GUIDED_WORKFLOW;
    workflow: string;
    workflow_sha256: string;
    receiver_url: string;
    receiver_sha256: string;
    secret_name: 'SCOPEBLIND_GUIDED_RECEIVER_KEY';
    variable_name: 'SCOPEBLIND_GUIDED_CONNECTION';
}
interface RepositorySetupEnrollment {
    type: 'scopeblind.repository.setup-enrollment.v1';
    setup_id: string;
    setup_digest: string;
    receiver_key: string;
    connection: RepositoryConnection;
    readiness: Signed<RepositoryReadiness>;
    inspection: Signed<RepositorySetupInspection>;
    installation: RepositorySetupInstallation;
    coding?: RepositorySetupCoding;
    replaces?: RepositoryGuidedReceiverConfig;
    issued_at: string;
}
interface RepositoryCodingConnectionConfig {
    type: 'scopeblind.repository.coding-config.v1';
    endpoint: string;
    authority_key: string;
    worker_key: string;
    repository: string;
    base_branch: string;
    runtime: 'node22-static-v1';
    test_command: string[];
    build_command: string[];
    preview_directory: string;
    docker_image: string;
}
interface RepositorySetupCoding {
    config: RepositoryCodingConnectionConfig;
    workflow: string;
    workflow_sha256: string;
    artifact_url: string;
    artifact_sha256: string;
}
interface RepositorySetupCodingReady {
    type: 'scopeblind.repository.setup-coding-ready.v1';
    setup_id: string;
    setup_digest: string;
    connection_digest: string;
    coding_digest: string;
    worker_key: string;
    challenge_id: string;
    run_id: number;
    run_attempt: number;
    workflow_ref: string;
    workflow_sha: string;
    observed_at: string;
    expires_at: string;
}
/** An explicit owner signature authorizes only these reviewed installation bytes and public pins. */
interface RepositorySetupAuthorization {
    type: 'scopeblind.repository.setup-authorization.v1';
    setup_id: string;
    setup_digest: string;
    enrollment_digest: string;
    connection_digest: string;
    owner_key: string;
    repository_id: number;
    workflow_path: typeof REPOSITORY_GUIDED_WORKFLOW;
    workflow_sha256: string;
    receiver_url: string;
    receiver_sha256: string;
    issued_at: string;
    expires_at: string;
}
interface RepositorySetupRenewal {
    type: 'scopeblind.repository.setup-renewal.v1';
    id: string;
    setup_id: string;
    authorization_digest: string;
    owner_key: string;
    issued_at: string;
    expires_at: string;
}
interface RepositorySetupChallenge {
    id: string;
    audience: string;
    issued_at: string;
    expires_at: string;
}
interface RepositorySetupReady {
    type: 'scopeblind.repository.setup-ready.v1';
    setup_id: string;
    setup_digest: string;
    connection_digest: string;
    authorization_digest: string;
    challenge_id: string;
    receiver_key: string;
    readiness: Signed<RepositoryReadiness>;
    inspection: Signed<RepositorySetupInspection> | null;
    run_id: number;
    run_attempt: number;
    workflow_ref: string;
    workflow_sha: string;
    observed_at: string;
}
interface RepositorySetupWorkflowProof {
    repository_id: number;
    run_id: number;
    run_attempt: number;
    workflow_ref: string;
    workflow_sha: string;
    token_digest: string;
    verified_at: string;
}
type RepositorySetupStatus = 'awaiting_github' | 'awaiting_receiver' | 'awaiting_confirmation' | 'awaiting_workflow' | 'ready' | 'expired' | 'revoked' | 'superseded' | 'replacement_pending' | 'installation_expired';
interface RepositorySetupState {
    type: 'scopeblind.repository.setup-state.v1';
    request: Signed<RepositorySetupRequest>;
    github: Signed<RepositorySetupGitHub> | null;
    enrollment: Signed<RepositorySetupEnrollment> | null;
    connection: Signed<RepositoryConnection> | null;
    authorization: Signed<RepositorySetupAuthorization> | null;
    installation_renewal?: Signed<RepositorySetupRenewal> | null;
    challenge: RepositorySetupChallenge | null;
    ready: Signed<RepositorySetupReady> | null;
    workflow_proof: RepositorySetupWorkflowProof | null;
    initial_ready?: {
        ready: Signed<RepositorySetupReady>;
        workflow_proof: RepositorySetupWorkflowProof;
    } | null;
    coding_ready?: {
        ready: Signed<RepositorySetupCodingReady>;
        workflow_proof: RepositorySetupWorkflowProof;
    } | null;
    superseded_by?: string | null;
    blocking_jobs?: boolean;
    status: RepositorySetupStatus;
    dispatch: 'none' | 'requested' | 'unconfigured' | 'unavailable';
    observed_at: string;
}
interface RepositorySetupJob {
    type: 'scopeblind.repository.setup-job.v1';
    id: string;
    setup_id: string;
    connection_digest: string;
    owner_key: string;
    receiver_key: string;
    requested_by: string;
    operation: 'ready' | 'inspect' | 'execute' | 'reconcile';
    task_id: string | null;
    challenge: RepositorySetupChallenge | null;
    issued_at: string;
    expires_at: string;
}
interface RepositorySetupJobState {
    type: 'scopeblind.repository.setup-job-state.v1';
    job: Signed<RepositorySetupJob>;
    status: 'queued' | 'running' | 'completed' | 'failed';
    run_id: number | null;
    error: string | null;
    observed_at: string;
}
interface RepositorySetupTaskBinding {
    type: 'scopeblind.repository.setup-task-binding.v1';
    task_id: string;
    task_digest: string;
    assignment: Signed<WorkspaceTaskAssignment>;
    active: boolean;
    observed_at: string;
}
interface RepositoryGuidedReceiverConfig {
    type: 'scopeblind.repository.guided-receiver-config.v1';
    endpoint: string;
    authority_key: string;
    connection: Signed<RepositoryConnection>;
    authorization: Signed<RepositorySetupAuthorization>;
}
declare function repositorySetupArtifactUrl(v: unknown): v is string;
declare function validRepositorySetupRequest(v: unknown): v is RepositorySetupRequest;
declare function validRepositorySetupInspection(v: unknown, request: Signed<RepositorySetupRequest>, receiverKey: string): v is RepositorySetupInspection;
declare function validRepositorySetupAuthorization(v: unknown): v is RepositorySetupAuthorization;
declare function validRepositorySetupRenewal(v: unknown): v is RepositorySetupRenewal;
declare function validRepositoryCodingConnectionConfig(v: unknown): v is RepositoryCodingConnectionConfig;
declare function verifyRepositorySetupEnrollment(value: unknown, request: Signed<RepositorySetupRequest>, expectedEndpoint?: string): Promise<boolean>;
declare function verifyRepositorySetupReplacement(value: unknown, next: RepositoryConnection): Promise<boolean>;
declare function verifyRepositorySetupState(value: unknown, authorityKey: string, ownerKey?: string, expectedEndpoint?: string): Promise<boolean>;

/** Offline verification of optional collaboration records around immutable v1 tasks. */

interface RepositoryCollaborationEvidence {
    type: 'scopeblind.repository.collaboration-evidence.v1';
    repository: RepositoryEvidence;
    collaboration: Signed<RepositoryCollaboration>;
    demo?: Signed<RepositoryDemoState>;
    parent?: RepositoryEvidence;
    parent_request?: Signed<RepositoryRevisionRequest>;
    parent_agent_grant?: Signed<RepositoryAgentGrant>;
}
declare function verifyRepositoryCollaborationEvidence(input: unknown, pins?: Parameters<typeof verifyRepositoryEvidence>[1]): Promise<{
    valid: boolean;
    accepted: boolean;
    authorityPinned: boolean;
    previewVerified: boolean;
    revisionLinked: boolean;
    errors: string[];
    limitations: string[];
}>;

interface RepositoryReviewOrigin {
    draft: Signed<WorkspaceReviewDraft>;
    assignment: Signed<WorkspaceTaskAssignment>;
    parent_assignment: Signed<WorkspaceTaskAssignment>;
    parent: Omit<RepositoryReviewEvidence, 'origin'>;
    preparation: {
        mandate: Signed<WorkspacePreparationMandate>;
        adoption: Signed<WorkspacePreparationMandate>;
    };
}
interface RepositoryCodingOrigin {
    job: RepositoryCodingEvidence;
    assignment: Signed<WorkspaceTaskAssignment>;
}
interface RepositoryReviewEvidence {
    type: 'scopeblind.repository.review-evidence.v1';
    repository: RepositoryEvidence | RepositoryCollaborationEvidence;
    review: Signed<RepositoryReviewState>;
    origin?: RepositoryReviewOrigin;
    coding_origin?: RepositoryCodingOrigin;
}
type RepositoryReviewPins = string | {
    authority_key: string;
    owner_key?: string;
    reviewer_key?: string;
    receiver_key?: string;
};
/** Historical signatures remain checkable after expiry. This function never reports an assessment as code correctness. */
declare function verifyRepositoryReviewEvidence(value: unknown, pins?: RepositoryReviewPins): Promise<{
    valid: boolean;
    errors: string[];
    originVerified: boolean;
    codingOriginVerified: boolean;
    accepted: boolean;
    authorityPinned: boolean;
    packetVerified: boolean;
    previewAvailable: boolean;
    decisionsVerified: boolean;
    limitations: string[];
}>;

/** Explicit code-edit authority. Preparation grants never authorize these operations. */

declare const REPOSITORY_CODING_ACTIONS: readonly ["repository_coding_info", "repository_coding_mandate", "repository_coding_adopt", "repository_coding_revoke", "repository_coding_start", "repository_coding_get", "repository_coding_list", "repository_coding_cancel", "repository_coding_reconcile", "repository_coding_poll", "repository_coding_heartbeat", "repository_coding_model", "repository_coding_publish", "repository_coding_preview", "repository_coding_complete"];
type RepositoryCodingAction = typeof REPOSITORY_CODING_ACTIONS[number];
interface RepositoryCodingSource {
    task_id: string;
    task_digest: string;
    basis_digest: string;
    packet_digest: string;
    feedback_digest: string;
}
interface RepositoryCodingMandate {
    type: 'scopeblind.repository.coding-mandate.v1';
    id: string;
    workspace_id: string;
    workspace_digest: string;
    mode: 'edit_code';
    owner_member_id: string;
    owner_key: string;
    owner_member_revision: number;
    reviewer_member_id: string;
    reviewer_key: string;
    reviewer_member_revision: number;
    worker_key: string;
    repository: string;
    base_branch: string;
    allowed_paths: string[];
    required_checks: Array<{
        name: string;
        app_id: number;
    }>;
    runtime: 'node22-static-v1';
    docker_image: string;
    test_command: string[];
    build_command: string[];
    preview_directory: string;
    max_jobs: number;
    max_attempts: number;
    max_model_calls: number;
    max_tokens: number;
    max_seconds: number;
    max_changed_files: number;
    max_changed_bytes: number;
    permissions: ['read_source', 'edit_code', 'run_tests', 'open_pull_request', 'publish_preview'];
    issued_at: string;
    expires_at: string;
}
/** Historical installed connections may be refreshed; this record grants no work authority. */
interface RepositoryCodingRefreshableConnection {
    setup_id: string;
    worker_key: string;
}
interface RepositoryCodingRequest {
    type: 'scopeblind.repository.coding-request.v1';
    id: string;
    workspace_id: string;
    mandate_digest: string;
    source: RepositoryCodingSource;
    owner_key: string;
    issued_at: string;
}
interface RepositoryCodingStop {
    type: 'scopeblind.repository.coding-stop.v1';
    id: string;
    workspace_id: string;
    mandate_digest: string;
    job_id?: string;
    principal_key: string;
    issued_at: string;
}
type RepositoryCodingStatus = 'queued' | 'running' | 'testing' | 'publishing' | 'pr_ready' | 'failed' | 'cancelled' | 'unknown' | 'expired';
interface RepositoryCodingFile {
    path: string;
    before_sha: string | null;
    content: string | null;
}
interface RepositoryCodingTest {
    command_digest: string;
    exit_code: number;
    output_sha256: string;
    duration_ms: number;
}
interface RepositoryCodingPlan {
    type: 'scopeblind.repository.coding-plan.v1';
    job_id: string;
    request_digest: string;
    mandate_digest: string;
    source_head_sha: string;
    source_base_sha: string;
    branch: string;
    commit_sha: string;
    tree_sha: string;
    files: Array<{
        path: string;
        before_sha: string | null;
        after_sha: string | null;
        bytes: number;
    }>;
    tests: RepositoryCodingTest;
    build: RepositoryCodingTest;
    preview_digest: string;
    model_calls: number;
    reserved_tokens: number;
    issued_at: string;
}
interface RepositoryCodingPublication {
    type: 'scopeblind.repository.coding-publication.v1';
    job_id: string;
    plan_digest: string;
    mandate_digest: string;
    request_digest: string;
    worker_key: string;
    lease_id: string;
    issued_at: string;
    expires_at: string;
}
interface RepositoryCodingResult {
    type: 'scopeblind.repository.coding-result.v1';
    job_id: string;
    plan_digest: string;
    publication_digest: string;
    repository: string;
    branch: string;
    head_sha: string;
    pull_number: number;
    pull_url: string;
    preview_url: string;
    preview_digest: string;
    deployment_id: number;
    deployment_status_id: number;
    deployment_environment: 'ScopeBlind coding preview';
    check: {
        id: number;
        name: 'ScopeBlind isolated coding checks';
        app_id: 15368;
        head_sha: string;
        conclusion: 'success';
    };
    observed_at: string;
}
interface RepositoryCodingJob {
    type: 'scopeblind.repository.coding-job.v1';
    request: Signed<RepositoryCodingRequest>;
    mandate: Signed<RepositoryCodingMandate>;
    adoption: Signed<RepositoryCodingMandate>;
    workspace: Signed<RepositoryWorkspaceState>;
    parent: RepositoryReviewEvidence;
    status: RepositoryCodingStatus;
    attempts: number;
    model_calls: number;
    reserved_tokens: number;
    lease_id: string | null;
    lease_expires_at: string | null;
    started_at: string | null;
    plan: Signed<RepositoryCodingPlan> | null;
    publication: Signed<RepositoryCodingPublication> | null;
    result: Signed<RepositoryCodingResult> | null;
    stop: Signed<RepositoryCodingStop> | null;
    error: string | null;
    observed_at: string;
}
interface RepositoryCodingMandateView {
    mandate: Signed<RepositoryCodingMandate>;
    adoption: Signed<RepositoryCodingMandate> | null;
    revocation: Signed<RepositoryCodingStop> | null;
    status: 'awaiting_reviewer' | 'active' | 'expired' | 'revoked' | 'membership_changed' | 'exhausted';
    used_jobs: number;
}
interface RepositoryCodingEvidence {
    type: 'scopeblind.repository.coding-evidence.v1';
    job: Signed<RepositoryCodingJob>;
}
interface RepositoryCodingModelContext {
    files: Array<{
        path: string;
        content: string;
    }>;
    history: Array<{
        action: unknown;
        result: string;
    }>;
}
type RepositoryCodingModelAction = {
    action: 'write_file';
    path: string;
    content: string;
} | {
    action: 'delete_file';
    path: string;
} | {
    action: 'run_tests' | 'finish';
};
declare const CODING_PERMISSIONS: readonly ["read_source", "edit_code", "run_tests", "open_pull_request", "publish_preview"];
declare function validRepositoryCodingRefreshableConnections(v: unknown): v is RepositoryCodingRefreshableConnection[];
declare function codingSafePath(path: unknown): path is string;
declare function codingCommand(v: unknown): v is string[];
declare function validRepositoryCodingSource(v: unknown): v is RepositoryCodingSource;
declare function validRepositoryCodingMandate(v: unknown): v is RepositoryCodingMandate;
declare function validRepositoryCodingRequest(v: unknown): v is RepositoryCodingRequest;
declare function validRepositoryCodingStop(v: unknown): v is RepositoryCodingStop;
declare function validRepositoryCodingPlan(v: unknown, m: RepositoryCodingMandate): v is RepositoryCodingPlan;
declare function codingScopeWithin(paths: string[], m: RepositoryCodingMandate): boolean;
declare function validRepositoryCodingResult(v: unknown): v is RepositoryCodingResult;

/** Managed, disposable repository transport. Human and coding authority remains in the existing protocols. */

declare const REPOSITORY_TRIAL_ACTIONS: readonly ["repository_trial_info", "repository_trial_create", "repository_trial_get", "repository_trial_bind", "repository_trial_dispatch", "repository_trial_poll", "repository_trial_complete"];
type RepositoryTrialAction = typeof REPOSITORY_TRIAL_ACTIONS[number];
declare const TRIAL_REPOSITORY = "ScopeBlind/scopeblind-repository-demo";
declare const TRIAL_WORKFLOW = ".github/workflows/scopeblind-trial.yml";
declare const TRIAL_TEMPLATE = "styled-contact-v1";
declare const TRIAL_SOURCE_CHECK: {
    name: string;
    app_id: number;
};
declare const TRIAL_CODING_CHECK: {
    name: string;
    app_id: number;
};
declare const TRIAL_LIMITS: {
    readonly max_jobs: 1;
    readonly max_attempts: 2;
    readonly max_model_calls: 8;
    readonly max_tokens: 98304;
    readonly max_seconds: 600;
    readonly max_changed_files: 2;
    readonly max_changed_bytes: 32768;
};
declare const TRIAL_DOCKER_IMAGE = "node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752";
declare const trialBase: (id: string) => string;
declare const trialSource: (id: string) => string;
interface RepositoryTrialRequest {
    type: 'scopeblind.repository.trial-request.v1';
    id: string;
    owner_key: string;
    authority_key: string;
    title: string;
    template: typeof TRIAL_TEMPLATE;
    reviewer_secret_hash: string;
    issued_at: string;
    expires_at: string;
}
interface RepositoryTrialHtml {
    html: string;
    sha256: string;
    blob_sha: string;
}
interface RepositoryTrialProvision {
    type: 'scopeblind.repository.trial-provision.v1';
    trial_id: string;
    request_digest: string;
    receiver_key: string;
    repository: typeof TRIAL_REPOSITORY;
    template_sha: string;
    base_branch: string;
    source_branch: string;
    base_sha: string;
    source_sha: string;
    pull_number: number;
    before: RepositoryTrialHtml;
    source: RepositoryTrialHtml;
    source_check: {
        id: number;
        name: string;
        app_id: number;
        head_sha: string;
        conclusion: 'success';
    };
    observed_at: string;
}
interface RepositoryTrialReadiness {
    type: 'scopeblind.repository.trial-readiness.v1';
    receiver_key: string;
    worker_key: string;
    repository: typeof TRIAL_REPOSITORY;
    proof: RepositorySetupWorkflowProof;
    observed_at: string;
    expires_at: string;
}
interface RepositoryTrialInfo {
    type: 'scopeblind.repository.trial-info.v1';
    repository: typeof TRIAL_REPOSITORY;
    template: typeof TRIAL_TEMPLATE;
    receiver_key: string | null;
    worker_key: string | null;
    template_sha: string | null;
    availability: 'ready' | 'starting' | 'setup_required' | 'at_capacity';
    dispatch_available: boolean;
    readiness: Signed<RepositoryTrialReadiness> | null;
    limits: typeof TRIAL_LIMITS;
    source_checks: Array<typeof TRIAL_SOURCE_CHECK>;
    required_checks: Array<typeof TRIAL_CODING_CHECK>;
    allowed_paths: ['site/**'];
    docker_image: string;
    test_command: ['node', '--test', 'tests/contact.test.cjs'];
    build_command: ['node', 'tools/build.cjs'];
    preview_directory: 'dist';
    observed_at: string;
}
type RepositoryTrialJobKind = 'provision' | 'inspect' | 'execute' | 'reconcile' | 'coding' | 'coding_reconcile';
interface RepositoryTrialJobView {
    id: string;
    kind: RepositoryTrialJobKind;
    target_id: string | null;
    status: 'queued' | 'leased' | 'complete' | 'failed' | 'unknown';
    attempts: number;
    error: string | null;
    updated_at: string;
}
interface RepositoryTrialState {
    type: 'scopeblind.repository.trial-state.v1';
    request: Signed<RepositoryTrialRequest>;
    provision: Signed<RepositoryTrialProvision> | null;
    workspace: Signed<RepositoryWorkspace> | null;
    invitation: Signed<WorkspaceInvitation> | null;
    config: RepositoryCodingConnectionConfig;
    receiver_key: string;
    readiness: Signed<RepositoryTrialReadiness> | null;
    status: 'queued' | 'provisioning' | 'ready' | 'active' | 'expired' | 'failed' | 'unknown';
    dispatch_status: 'requested' | 'unconfigured' | 'unavailable';
    jobs: RepositoryTrialJobView[];
    observed_at: string;
}
interface RepositoryTrialJob {
    type: 'scopeblind.repository.trial-job.v1';
    id: string;
    kind: RepositoryTrialJobKind;
    target_id: string | null;
    request: Signed<RepositoryTrialRequest>;
    provision: Signed<RepositoryTrialProvision> | null;
    workspace: Signed<RepositoryWorkspaceState> | null;
    assignment: Signed<WorkspaceTaskAssignment> | null;
    task: Signed<RepositoryState> | null;
    coding: Signed<RepositoryCodingJob> | null;
    config: RepositoryCodingConnectionConfig;
    receiver_key: string;
    template_sha: string;
    lease_id: string;
    lease_expires_at: string;
    proof: RepositorySetupWorkflowProof;
    observed_at: string;
}
interface RepositoryTrialCompletion {
    type: 'scopeblind.repository.trial-completion.v1';
    job_id: string;
    trial_id: string;
    request_digest: string;
    lease_id: string;
    receiver_key: string;
    kind: RepositoryTrialJobKind;
    provision: Signed<RepositoryTrialProvision> | null;
    error: string | null;
    observed_at: string;
}
interface RepositoryTrialPoll {
    type: 'scopeblind.repository.trial-poll.v1';
    lease_id: string;
    challenge: RepositorySetupChallenge;
    job: Signed<RepositoryTrialJob> | null;
    observed_at: string;
}
declare function validRepositoryTrialRequest(v: unknown): v is RepositoryTrialRequest;
declare function validRepositoryTrialProvision(v: unknown): v is RepositoryTrialProvision;
declare function verifyRepositoryTrialState(value: unknown, authority: string): Promise<boolean>;
declare function trialCodingConfig(id: string, endpoint: string, authority: string, worker: string): RepositoryCodingConnectionConfig;
declare function validTrialReadiness(value: unknown): value is RepositoryTrialReadiness;
declare function verifyRepositoryTrialConnection(value: unknown, authority: string): Promise<boolean>;

/** Project-scoped human devices. Device signatures never become principal signatures. */

declare const REPOSITORY_DEVICE_DOMAIN = "scopeblind.repository.device-authorization.v1\n";
declare const REPOSITORY_DEVICE_ACTIONS: readonly ["repository_device_link_request", "repository_device_link_status", "repository_device_authorize", "repository_device_confirm", "repository_device_list", "repository_device_revoke"];
type RepositoryDeviceAction = typeof REPOSITORY_DEVICE_ACTIONS[number];
declare const REPOSITORY_DEVICE_PERMISSIONS: readonly ["read", "claim", "review", "feedback", "accept"];
type RepositoryDevicePermission = typeof REPOSITORY_DEVICE_PERMISSIONS[number];
declare const REPOSITORY_DEVICE_LINK_MS: number;
declare const REPOSITORY_DEVICE_MAX_MS: number;
interface RepositoryDeviceLink {
    type: 'scopeblind.repository.device-link.v1';
    id: string;
    workspace_id: string;
    device_key: string;
    name: string;
    secret_hash: string;
    issued_at: string;
    expires_at: string;
}
interface RepositoryDeviceAuthorization {
    type: 'scopeblind.repository.device-authorization.v1';
    id: string;
    link_id: string;
    workspace_id: string;
    workspace_digest: string;
    member_id: string;
    member_revision: number;
    principal_key: string;
    device_key: string;
    device_name: string;
    actions: RepositoryDevicePermission[];
    authority_key: string;
    issued_at: string;
    expires_at: string;
}
interface RepositoryDeviceConfirmation {
    type: 'scopeblind.repository.device-confirmation.v1';
    authorization_digest: string;
    workspace_id: string;
    device_key: string;
    issued_at: string;
}
interface RepositoryDeviceUse {
    type: 'scopeblind.repository.device-use.v1';
    authorization_digest: string;
    workspace_id: string;
    workspace_digest: string;
    member_id: string;
    member_revision: number;
    principal_key: string;
    device_key: string;
    task_id: string;
    task_digest: string;
    payload_digest: string;
    action: RepositoryDevicePermission;
    recorded_at: string;
}
type RepositoryDeviceStatus = 'pending' | 'active' | 'expired' | 'revoked' | 'membership_changed';
interface RepositoryDeviceView {
    authorization: Signed<RepositoryDeviceAuthorization>;
    status: RepositoryDeviceStatus;
    confirmation: Signed<RepositoryDeviceConfirmation> | null;
    revoked_at?: string;
}
interface RepositoryDeviceLinkState {
    type: 'scopeblind.repository.device-link-state.v1';
    link: Signed<RepositoryDeviceLink>;
    status: 'pending' | 'authorized' | 'expired';
    device: RepositoryDeviceView | null;
    observed_at: string;
}
interface RepositoryDeviceListState {
    type: 'scopeblind.repository.device-list.v1';
    workspace_id: string;
    viewer_key: string;
    devices: RepositoryDeviceView[];
    has_more: boolean;
    observed_at: string;
}
interface RepositoryHumanContext {
    authorityKey: string;
    task?: Signed<RepositoryTask>;
    requireRecordedUse?: boolean;
}
declare function validRepositoryDeviceLink(v: unknown): v is RepositoryDeviceLink;
declare function validRepositoryDeviceAuthorization(v: unknown): v is RepositoryDeviceAuthorization;
declare function validRepositoryDeviceConfirmation(v: unknown): v is RepositoryDeviceConfirmation;
declare function verifyRepositoryDeviceAuthorization(value: unknown): Promise<boolean>;
declare function repositoryDevicePreimage(payloadDigest: string, authorizationDigest: string): string;
declare function repositoryHumanPrincipal(value: Signed<unknown>): string;
declare function sameRepositoryHumanIntent(left: Signed<unknown>, right: Signed<unknown>): boolean;
declare function repositoryDevicePermission(action: string): RepositoryDevicePermission | null;
/** Only these human statements may carry project-device authority. */
declare function repositoryHumanPermission(value: Signed<unknown>): {
    action: RepositoryDevicePermission;
    at: string;
} | null;
declare function validRepositoryHumanEnvelope(value: unknown): value is Signed<unknown>;
/** Offline historical authority check. Live acceptance must also atomically check revocation/membership. */
declare function verifyRepositoryHuman<T>(value: Signed<T>, principal: string, context: RepositoryHumanContext): Promise<boolean>;

/** Explicit, room-bound human device delegation. Raw signature verification stays separate. */

declare const DEVICE_ACTIONS: readonly ["inspect", "decision_inbox", "negotiation_get", "decide", "accept", "negotiation_mandate", "negotiation_approve"];
type DevicePermission = typeof DEVICE_ACTIONS[number];
type DeviceAction = 'device_link_request' | 'device_link_status' | 'device_authorize' | 'device_list' | 'device_revoke';
interface DeviceAuthorization {
    type: 'scopeblind.coordination.device-authorization.v1';
    id: string;
    link_id: string;
    room_id: string;
    agreement_digest: string;
    principal_key: string;
    device_key: string;
    device_name: string;
    actions: DevicePermission[];
    issued_at: string;
    expires_at: string;
    authority_key: string;
}
interface DeviceUse {
    type: 'scopeblind.coordination.device-use.v1';
    authorization_digest: string;
    principal_key: string;
    device_key: string;
    room_id: string;
    payload_digest: string;
    action: DevicePermission;
    recorded_at: string;
}
interface HumanContext {
    authorityKey?: string;
    proposal?: Signed<NegotiationProposal>;
    approval?: Signed<NegotiationApproval>;
    requireRecordedUse?: boolean;
}
/** Claimed principal only. Call verifyHuman before trusting this identity. */
declare function humanPrincipal(value: Signed<unknown>): string;
declare function verifyDeviceAuthorization(value: Signed<DeviceAuthorization>): Promise<boolean>;
/** Offline authorization-at-signing check. Live mutation acceptance must also check storage revocation atomically. */
declare function verifyHuman<T>(value: Signed<T>, expectedPrincipal: string, context?: HumanContext): Promise<boolean>;

interface Signed<T> {
    payload: T;
    signer: string;
    digest: string;
    signature: string;
    authorization?: Signed<DeviceAuthorization>;
    authorization_signature?: string;
    authorization_use?: Signed<DeviceUse>;
    repository_authorization?: Signed<RepositoryDeviceAuthorization>;
    repository_authorization_signature?: string;
    repository_authorization_use?: Signed<RepositoryDeviceUse>;
}
interface SigningIdentity {
    publicKey: string;
    privateKey: CryptoKey;
    deviceAuthorization?: Signed<DeviceAuthorization>;
    repositoryDeviceAuthorization?: Signed<RepositoryDeviceAuthorization>;
}
interface Agreement {
    type: 'scopeblind.coordination.agreement.v1';
    id: string;
    version: 1;
    title: string;
    owner_key: string;
    registrar_key: string;
    currency: 'USD';
    budget_minor: number;
    approval_above_minor: number;
    approval_ttl_seconds: number;
    allowed_destinations: string[];
    issued_at: string;
    mode?: 'guided' | 'live';
    brief?: string;
    preferences?: string[];
    assumptions?: string[];
    require_po_match?: boolean;
}
interface InvitationGrant {
    type: 'scopeblind.coordination.grant.v1';
    grant_id: string;
    room_id: string;
    agreement_digest: string;
    issuer: string;
    registrar_key: string;
    role: 'reviewer';
    actions: Array<'decide' | 'accept'>;
    expires_at: string;
    token_hash: string;
    max_claims: 1;
}
interface ClaimProof {
    type: 'scopeblind.coordination.claim.v1';
    grant_id: string;
    room_id: string;
    guest_key: string;
    name: string;
    issued_at: string;
    nonce: string;
}
interface GuestBinding {
    type: 'scopeblind.coordination.binding.v1';
    grant_id: string;
    grant_digest: string;
    room_id: string;
    guest_key: string;
    name: string;
    issued_at: string;
    expires_at: string;
    claim: Signed<ClaimProof>;
}
interface PaymentInput {
    invoice_id: string;
    amount_minor: number;
    currency: 'USD';
    destination: string;
    fixture_revision?: number;
}
interface Invoice {
    id: string;
    invoice_id: string;
    vendor: string;
    description: string;
    amount_minor: number;
    destination: string;
    duplicate_of?: string;
    purchase_order_id?: string;
}
interface PurchaseOrder {
    id: string;
    vendor: string;
    destination: string;
    amount_minor: number;
    currency: 'USD';
}
interface InvoiceFixtures {
    revision: number;
    invoices: Invoice[];
    purchase_orders: PurchaseOrder[];
}
type OperationStatus = 'held' | 'admitted' | 'confirmed' | 'refused' | 'declined' | 'request_changes' | 'superseded' | 'unknown' | 'failed';
interface Approval {
    type: 'scopeblind.coordination.approval.v1';
    room_id: string;
    run_id: string;
    operation_id: string;
    agreement_digest: string;
    payload_hash: string;
    grant_id: string;
    decision: 'approve' | 'deny' | 'request_changes';
    issued_at: string;
    expires_at: string;
    note: string;
}
interface Admission {
    type: 'scopeblind.coordination.admission.v1';
    room_id: string;
    run_id: string;
    operation_id: string;
    agreement_digest: string;
    payload_hash: string;
    input: PaymentInput;
    destination: string;
    decision: 'admitted' | 'held' | 'refused';
    reason: string;
    issued_at: string;
    expires_at: string;
}
interface Outcome {
    type: 'scopeblind.coordination.outcome.v1';
    room_id: string;
    run_id: string;
    operation_id: string;
    payload_hash: string;
    status: 'confirmed' | 'failed' | 'unknown';
    amount_minor: number;
    destination: string;
    transaction_id?: string;
    observed_by: 'sandbox-ledger' | 'gateway-report';
    issued_at: string;
    note?: string;
}
interface Operation {
    operation_id: string;
    run_id: string;
    tool: 'ledger.pay';
    input: PaymentInput;
    payload_hash: string;
    status: OperationStatus;
    reason: string;
    created_at: string;
    updated_at: string;
    decision?: Signed<Approval>;
    admission?: Signed<Admission>;
    receipt?: Signed<Outcome>;
    supersedes?: string;
    previous_input?: PaymentInput;
}
interface Manifest {
    type: 'scopeblind.coordination.manifest.v1';
    room_id: string;
    run_id: string;
    agreement_digest: string;
    operations: Operation[];
    budget: Budget;
    finalized_at: string;
    summary?: string;
    previous_manifest_digest?: string;
    historical_operations?: Operation[];
    fixtures?: InvoiceFixtures;
}
interface Acceptance {
    type: 'scopeblind.coordination.acceptance.v1';
    room_id: string;
    run_id: string;
    agreement_digest: string;
    manifest_digest: string;
    grant_id: string;
    decision: 'accept' | 'request_changes';
    issued_at: string;
    note: string;
}
interface AcceptanceRecord {
    type: 'scopeblind.coordination.acceptance-record.v1';
    room_id: string;
    run_id: string;
    manifest_digest: string;
    acceptance_digest: string;
    reviewer_key: string;
    recorded_at: string;
}
interface AttemptRevision {
    type: 'scopeblind.coordination.revision.v1';
    room_id: string;
    previous_run_id: string;
    run_id: string;
    previous_manifest_digest: string;
    agreement_digest: string;
    requested_by: string;
    note: string;
    issued_at: string;
}
interface AttemptView {
    manifest: Signed<Manifest>;
    acceptances: Signed<Acceptance>[];
    acceptance_records: Signed<AcceptanceRecord>[];
    revision: Signed<AttemptRevision>;
}
interface Budget {
    limit_minor: number;
    reserved_minor: number;
    spent_minor: number;
    remaining_minor: number;
}
interface GrantView {
    grant: Signed<InvitationGrant>;
    binding?: Signed<GuestBinding>;
    revoked: boolean;
}
type RpcAction = 'create' | 'invite' | 'claim' | 'revoke' | 'admit' | 'execute' | 'outcome' | 'decide' | 'revise' | 'finalize' | 'accept' | 'pause' | 'actor_token' | 'inspect' | 'deliver' | 'fixtures_update' | 'restart' | 'live_start' | 'live_tick' | 'live_retry' | 'pair_create' | 'pair_revoke' | 'pair_claim' | 'brief_draft' | RehearsalAction | 'rehearsal_invite' | 'rehearsal_claim' | 'rehearsal_revoke' | 'rehearsal_adopt' | 'rehearsal_draft' | 'rehearsal_case_review' | NegotiationAction | 'negotiation_share' | 'negotiation_invitation_rotate' | 'result_share' | DeviceAction | RepositoryDeviceAction | RepositoryCodingAction | RepositorySetupAction | RepositoryTrialAction | RepositoryAction | RepositoryCollaborationAction | RepositoryWorkspaceAction | RepositoryReviewAction | typeof AGENT_REQUEST_ACTIONS[number] | typeof DECISION_ACTIONS[number];
interface RpcRequest {
    type: 'scopeblind.coordination.request.v1';
    action: RpcAction;
    room_id: string;
    issued_at: string;
    nonce: string;
    body: Record<string, unknown>;
}
interface EvidenceBundle {
    type: 'scopeblind.coordination.evidence.v1';
    agreement: Signed<Agreement>;
    grants: GrantView[];
    manifest: Signed<Manifest>;
    acceptances: Signed<Acceptance>[];
    acceptance_records?: Signed<AcceptanceRecord>[];
    prior_attempts?: AttemptView[];
    negotiation?: NegotiationExport;
}

declare const REHEARSAL_PAIRING_AUDIENCE: "scopeblind.coordination.rehearsal";
declare const NEGOTIATION_PAIRING_AUDIENCE: "scopeblind.coordination.negotiation";
interface AgentBinding {
    type: 'scopeblind.coordination.agent-binding.v1';
    pair_id: string;
    room_id: string;
    agreement_digest: string;
    owner_key: string;
    agent_key: string;
    name: string;
    scope: readonly string[];
    audience: 'scopeblind.coordination.sample-ledger' | typeof REHEARSAL_PAIRING_AUDIENCE | typeof NEGOTIATION_PAIRING_AUDIENCE;
    principal_key?: string;
    session_id?: string;
    issued_at: string;
    expires_at: string;
    owner_authorization: Signed<RpcRequest>;
}

declare const NEGOTIATION_AGENT_ACTIONS: readonly ["negotiation_get", "negotiation_propose", "negotiation_respond", "negotiation_compare"];
declare const NEGOTIATION_ACTIONS: readonly ["negotiation_get", "negotiation_propose", "negotiation_respond", "negotiation_compare", "negotiation_create", "negotiation_claim", "negotiation_mandate", "negotiation_approve", "negotiation_adopt", "negotiation_pair_create", "negotiation_pair_claim", "negotiation_pair_revoke", "negotiation_step", "negotiation_cancel"];
type NegotiationAction = typeof NEGOTIATION_ACTIONS[number];
type NegotiationAgentMode = 'hosted' | 'own' | 'manual';
interface NegotiationRequirement {
    invoice_id: string;
    expected: 'allow' | 'ask';
}
interface NegotiationMandate {
    type: 'scopeblind.coordination.negotiation-mandate.v1';
    session_id: string;
    room_id: string;
    principal_key: string;
    version: number;
    agreement_digest: string;
    fixture_digest: string;
    min_threshold_minor: number;
    max_threshold_minor: number;
    /** Omitted together in legacy mandates: the source budget is fixed. */
    min_budget_minor?: number;
    max_budget_minor?: number;
    required_invoices: NegotiationRequirement[];
    private_brief_commitment: string;
    agent_mode: NegotiationAgentMode;
    /** Deliberately excludes payment, approval, invitation and onward-delegation powers. */
    actions: readonly (typeof NEGOTIATION_AGENT_ACTIONS[number])[];
    issued_at: string;
    expires_at: string;
}
interface NegotiationInvitation {
    type: 'scopeblind.coordination.negotiation-invitation.v1';
    session_id: string;
    room_id: string;
    agreement_digest: string;
    fixture_digest: string;
    issuer: string;
    registrar_key: string;
    role: 'counterparty';
    token_hash: string;
    max_claims: 1;
    expires_at: string;
    /** Fresh discussion; no mandate or approval carries over. */
    parent_session_id?: string;
    source_operation_id?: string;
}
interface NegotiationClaim {
    type: 'scopeblind.coordination.negotiation-claim.v1';
    session_id: string;
    room_id: string;
    guest_key: string;
    name: string;
    issued_at: string;
    nonce: string;
}
interface NegotiationBinding {
    type: 'scopeblind.coordination.negotiation-binding.v1';
    session_id: string;
    room_id: string;
    invitation_digest: string;
    guest_key: string;
    name: string;
    issued_at: string;
    expires_at: string;
    claim: Signed<NegotiationClaim>;
}
interface NegotiationSession {
    type: 'scopeblind.coordination.negotiation-session.v1';
    id: string;
    room_id: string;
    agreement_digest: string;
    fixture_digest: string;
    owner_key: string;
    registrar_key: string;
    invitation_digest: string;
    created_at: string;
    expires_at: string;
    max_proposals: 3;
    parent_session_id?: string;
    source_operation_id?: string;
    source_invoice_id?: string;
    source_operation_digest?: string;
}
interface NegotiationProposalInput {
    id: string;
    approval_above_minor: number;
    budget_minor?: number;
    exploration?: true;
    parent_digest?: string;
}
interface NegotiationProposal extends NegotiationProposalInput {
    type: 'scopeblind.coordination.negotiation-proposal.v1';
    session_id: string;
    room_id: string;
    round: number;
    principal_key: string;
    agent_key?: string;
    agent_mode: NegotiationAgentMode;
    agreement_digest: string;
    fixture_digest: string;
    mandate_digests: [string, string];
    /** This exact future agreement is shown before either human approves it. */
    next_agreement: Agreement;
    next_agreement_digest: string;
    reviewer_grant: InvitationGrant;
    reviewer_grant_digest: string;
    issued_at: string;
}
interface NegotiationResponse {
    type: 'scopeblind.coordination.negotiation-response.v1';
    session_id: string;
    principal_key: string;
    proposal_digest: string;
    mandate_digest: string;
    decision: 'support' | 'no_agreement';
    agent_key?: string;
    agent_mode: NegotiationAgentMode;
    issued_at: string;
}
interface NegotiationReport {
    type: 'scopeblind.coordination.negotiation-report.v1';
    session_id: string;
    room_id: string;
    proposal_digest: string;
    agreement_digest: string;
    fixture_digest: string;
    mandate_digests: [string, string];
    cases_digest: string;
    runtime_revision: string;
    adapter: 'coordination-d1-sandbox';
    isolation: 'separate-fixture-ledgers';
    issued_at: string;
    before_approval_above_minor: number;
    after_approval_above_minor: number;
    before_budget_minor?: number;
    after_budget_minor?: number;
    results: Array<{
        case: RehearsalCase;
        before: RehearsalObservation;
        after: RehearsalObservation;
    }>;
    required_passed: boolean;
    expectations_met: boolean;
    mandates_met: boolean;
}
interface NegotiationApproval {
    type: 'scopeblind.coordination.negotiation-approval.v1';
    session_id: string;
    principal_key: string;
    proposal_digest: string;
    report_digest: string;
    next_agreement_digest: string;
    mandate_digests: [string, string];
    decision: 'approve' | 'reject';
    selection_basis?: 'human-selected-tested-plan';
    issued_at: string;
    expires_at: string;
}
interface NegotiationAdoption {
    type: 'scopeblind.coordination.negotiation-adoption.v1';
    session_id: string;
    source_room_id: string;
    room_id: string;
    source_agreement_digest: string;
    agreement_digest: string;
    proposal_digest: string;
    report_digest: string;
    approval_digests: [string, string];
    issued_at: string;
    scope: 'new-separate-sample-task';
}
interface NegotiationExport {
    source_negotiation?: NegotiationExport;
    type: 'scopeblind.coordination.negotiation-evidence.v1';
    session: Signed<NegotiationSession>;
    invitation: Signed<NegotiationInvitation>;
    binding: Signed<NegotiationBinding>;
    agreement: Signed<Agreement>;
    fixtures: InvoiceFixtures;
    mandates: [Signed<NegotiationMandate>, Signed<NegotiationMandate>];
    proposals: Signed<NegotiationProposal>[];
    responses: Signed<NegotiationResponse>[];
    report: Signed<NegotiationReport>;
    approvals: Signed<NegotiationApproval>[];
    adoption?: Signed<NegotiationAdoption>;
    adopted_agreement?: Signed<Agreement>;
    reviewer_grant?: Signed<InvitationGrant>;
    reviewer_binding?: Signed<GuestBinding>;
    agent_bindings?: Signed<AgentBinding>[];
}
interface NegotiationVerification {
    valid: boolean;
    checks: Array<{
        name: string;
        passed: boolean;
    }>;
    limitations: string[];
}
/** Portable integrity, authority and relationship checks. Expiry is evaluated at the recorded action, so historical evidence remains checkable. */
declare function verifyNegotiationEvidence(value: unknown, authorityKey?: string, depth?: number): Promise<NegotiationVerification>;

declare const REHEARSAL_ACTIONS: readonly ["rehearsal_get", "rehearsal_case", "rehearsal_run", "rehearsal_propose"];
type RehearsalAction = typeof REHEARSAL_ACTIONS[number];
type RehearsalKind = 'invoice' | 'approved_invoice' | 'duplicate_invoice' | 'changed_approval' | 'changed_destination' | 'expired_approval' | 'budget_cap';
type RehearsalOutcome = 'allow' | 'ask' | 'refuse';
interface RehearsalCase {
    id: string;
    title: string;
    kind: RehearsalKind;
    invoice_id: string;
    /** Invoice AND matching PO override inside the rehearsal; unavailable for controlled approval/budget boundary probes. */
    amount_minor?: number;
    expected: RehearsalOutcome | 'invariant';
    requirement: string;
    /** Reserved for shipped safety cases; callers cannot assign or remove it. */
    required?: boolean;
}
interface RepairProposalInput {
    id: string;
    approval_above_minor: number;
    rationale: string;
}
interface RepairProposal extends RepairProposalInput {
    type: 'scopeblind.coordination.repair-proposal.v1';
    room_id: string;
    author_key: string;
    agreement_digest: string;
    fixture_digest: string;
    cases_digest: string;
    previous_approval_above_minor: number;
    issued_at: string;
}
interface RehearsalStep {
    action: string;
    decision: RehearsalOutcome | 'confirmed' | 'rejected';
    reason: string;
    operation_id?: string;
    payload_hash?: string;
}
interface RehearsalObservation {
    actual: RehearsalOutcome | 'error';
    matched: boolean;
    reason: string;
    steps: RehearsalStep[];
    payments: number;
    spent_minor: number;
    /** Used only for an invariant case, based on actual effects and admissions. */
    invariant_passed?: boolean;
}
interface RehearsalCaseResult {
    case: RehearsalCase;
    before: RehearsalObservation;
    after?: RehearsalObservation;
}
interface RehearsalReport {
    type: 'scopeblind.coordination.rehearsal-report.v1';
    id: string;
    room_id: string;
    agreement_digest: string;
    fixture_digest: string;
    cases_digest: string;
    proposal_digest?: string;
    runtime_revision: string;
    adapter: 'coordination-d1-sandbox';
    issued_at: string;
    isolation: 'separate-fixture-ledgers';
    results: RehearsalCaseResult[];
    required_passed: boolean;
    expectations_met: boolean;
    before_approval_above_minor: number;
    after_approval_above_minor?: number;
}
interface RehearsalAdoption {
    type: 'scopeblind.coordination.rehearsal-adoption.v1';
    source_room_id: string;
    room_id: string;
    source_agreement_digest: string;
    agreement_digest: string;
    report_digest: string;
    proposal_digest: string;
    fixture_digest: string;
    cases_digest: string;
    owner_key: string;
    issued_at: string;
    authorization_digest: string;
    scope: 'new-separate-sample-task';
}
interface RehearsalExport {
    type: 'scopeblind.coordination.rehearsal-evidence.v1';
    agreement: Signed<Agreement>;
    source_negotiation?: NegotiationExport;
    fixtures: InvoiceFixtures;
    cases: RehearsalCase[];
    proposal?: Signed<RepairProposal>;
    report: Signed<RehearsalReport>;
    adoption?: Signed<RehearsalAdoption>;
    adoption_authorization?: Signed<RpcRequest>;
    adopted_agreement?: Signed<Agreement>;
}
interface RehearsalVerification {
    valid: boolean;
    checks: Array<{
        label: string;
        ok: boolean;
    }>;
    errors: string[];
    limitations: string[];
}
/** Offline consistency/identity checks. Execution truth still relies on the named gate operator. */
declare function verifyRehearsalEvidence(bundle: RehearsalExport, pin?: string): Promise<RehearsalVerification>;

declare class CoordinationError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}
interface CoordinationPayment {
    operation_id: string;
    input: PaymentInput;
}
interface CoordinationPaymentResult {
    operation_id: string;
    status: 'held' | 'refused' | 'confirmed' | 'failed' | 'unknown';
    reason: string;
    admission?: Signed<Admission>;
    outcome?: Signed<Outcome>;
    replay?: boolean;
}
interface CoordinationWait {
    after_cursor: number;
    run_id?: string;
    timeout_ms?: number;
}
declare function validateCoordinationPayment(payment: CoordinationPayment): void;
/**
 * An installed, fail-closed adapter for the sample ledger destination.
 * An admission is never a generic permission to call an arbitrary downstream tool.
 * The service owns destination idempotency; retries always retain operation_id.
 */
declare class CoordinationClient {
    #private;
    constructor(config: CoordinationConfig, fetchImpl?: typeof fetch);
    /** Tool visibility is a local convenience; every RPC also checks the persisted grant. */
    get purpose(): 'execution' | 'rehearsal' | 'negotiation';
    /** Acknowledge only a context that this adapter has already verified. Pairing and MCP initialization do not call this. */
    private acknowledgeInspection;
    private negotiationConfig;
    /** Inspect only the scoped negotiation response. Never read the public room to obtain a mandate. */
    private checkedNegotiation;
    private negotiationResult;
    inspectNegotiation(reportDigest?: string, signal?: AbortSignal): Promise<Record<string, unknown>>;
    proposeCandidate(value: NegotiationProposalInput): Promise<Record<string, unknown>>;
    respondCandidate(value: {
        proposal_digest: string;
        decision: 'support' | 'no_agreement';
    }): Promise<Record<string, unknown>>;
    compareCandidate(value: {
        proposal_digest: string;
    }, signal?: AbortSignal): Promise<Record<string, unknown>>;
    waitNegotiation(value: {
        after_digest?: string;
        timeout_ms?: number;
    }, signal?: AbortSignal): Promise<Record<string, unknown>>;
    private checkedRehearsal;
    private rehearsalResult;
    inspectRehearsal(reportDigest?: string): Promise<Record<string, unknown>>;
    proposeCase(value: RehearsalCase): Promise<Record<string, unknown>>;
    proposeRepair(value: RepairProposalInput): Promise<Record<string, unknown>>;
    runRehearsal(value: {
        id: string;
        proposal_id?: string;
    }, signal?: AbortSignal): Promise<Record<string, unknown>>;
    private room;
    /** Live room state is informational; only signed artifacts establish signed claims. */
    inspect(): Promise<Record<string, unknown>>;
    /** Poll inside the tool, without model calls, for at most thirty seconds. */
    wait(input: CoordinationWait, signal?: AbortSignal): Promise<Record<string, unknown>>;
    deliver(runId: string): Promise<Record<string, unknown>>;
    private checkAdmission;
    private checkOutcome;
    pay(payment: CoordinationPayment): Promise<CoordinationPaymentResult>;
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
declare function signDecision(entry: DecisionLog, prevReceiptHash?: string): {
    ok: boolean;
    signed: string | null;
    artifact_type: string;
    receipt_hash?: string;
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
 * @scopeblind/protect-mcp — Acta draft-02 receipt envelope
 *
 * Implements the signed-receipt envelope from draft-farley-acta-signed-receipts-02:
 *
 *   { "payload": { "type", "issued_at", "issuer_id", ... },
 *     "signature": { "alg": "EdDSA", "kid", "sig" } }
 *
 * Conformance points (section references are to the published draft-02 text):
 *  - s2.1/s2.1.1: two-field envelope; alg "EdDSA" is mandatory-to-implement;
 *    sig is 128 lowercase hex chars; kid RECOMMENDED format
 *    sb:issuer:<first 12 Base58 chars of the Ed25519 public key>.
 *  - s2.2: payload common fields type / issued_at / issuer_id, and issuer_id
 *    MUST match signature.kid.
 *  - s4.1/s5.6: the signature covers the JCS-canonical bytes of payload
 *    directly (PureEdDSA, no intermediate hash).
 *  - s5.7: previousReceiptHash is the bare lowercase hex SHA-256 of the JCS
 *    bytes of the predecessor's ENTIRE envelope, signature included.
 *
 * Verification is dual-shape: envelopes produced by protect-mcp <= 0.9.x
 * (flat v1 artifacts and structured v2 artifacts with a top-level signature
 * string) remain checkable. Historical non-JCS numeric-key signatures are
 * identified explicitly and require opt-in compatibility verification.
 */
/** The receipt envelope shape a verification resolved to. */
type ReceiptShape = 'acta-02' | 'legacy-v2' | 'legacy-v1';
interface ActaSignature {
    alg: 'EdDSA';
    kid: string;
    sig: string;
}
interface ActaEnvelope {
    payload: Record<string, unknown>;
    signature: ActaSignature;
}
interface ReceiptVerification {
    valid: boolean;
    shape: ReceiptShape | null;
    hash?: string;
    error?: string;
    canonicalization?: 'jcs' | 'legacy-numeric-key-order';
    warning?: string;
    legacy_signature_valid?: boolean;
    legacy_hash?: string;
}
/**
 * s5.7 chain hash: lowercase hex SHA-256 over the JCS bytes of the object
 * exactly as written (for a signed envelope, signature included). Applied
 * uniformly to any receipt-log line (including legacy envelopes and signing
 * tombstones) so a chain can span the migration boundary.
 */
declare function receiptHash(obj: unknown): string;
/**
 * s2.1.1 RECOMMENDED kid format: sb:issuer:<first 12 Base58 chars of the
 * Ed25519 public key>. Existing key files that carry an explicit kid keep it
 * (kid is an opaque string per the draft); this is the default for new keys.
 */
declare function computeSbIssuerKid(publicKeyHex: string): string;
/**
 * Create a signed draft-02 receipt envelope.
 *
 * The caller provides the payload fields (including `type`); issued_at and
 * issuer_id are filled in if absent, and issuer_id is forced to equal kid
 * per s2.2.
 */
declare function createReceiptEnvelope(fields: Record<string, unknown> & {
    type: string;
}, privateKeyHex: string, kid: string, issuedAt?: string): {
    envelope: ActaEnvelope;
    hash: string;
};
/**
 * Verify a receipt envelope of any shape this stack has ever emitted.
 *
 *  - acta-02: signature is an object; verify sig over JCS(payload). Only
 *    "EdDSA" is accepted (s2.1.1 MTI; this implementation supports no other).
 *  - legacy (v1 flat / v2 structured): signature is a top-level string;
 *    verify over JCS(envelope minus signature), exactly as
 *    @veritasacta/artifacts <= 0.2.x did.
 */
declare function verifyReceipt(envelope: unknown, publicKeyHex: string, options?: {
    allowLegacyNumericKeys?: boolean;
}): ReceiptVerification;
/** Extract kid/issuer identity from any envelope shape, for display paths. */
declare function receiptIdentity(envelope: unknown): {
    kid: string | null;
    issuer: string | null;
    type: string | null;
};

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
 * NOTE: this receipt is NOT accepted by @veritasacta/verify. That verifier
 * handles two shapes: the envelope ({payload, signature:{...}}) and the flat
 * v1 artifact (fields at the top level with a hex-string signature). This
 * receipt is a third, hybrid shape: flat fields with a signature OBJECT and a
 * base64url signature. Making it externally verifiable is a shape change, not
 * a signing change, and is deliberately not attempted here.
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
 * @standard draft-farley-acta-signed-receipts §signature-scope
 *   The signature covers JCS(payload_minus_signature) directly, with no
 *   intermediate hash.
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
declare function verifySelectiveDisclosurePackage(receipt: Record<string, unknown>, disclosure: SelectiveDisclosurePackageV0, publicKeyHex?: string): SelectiveDisclosureVerification;

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

type ConnectorPilotId = 'github' | 'email-gmail' | 'filesystem-git' | 'slack-teams' | 'finance-pms' | 'nautilus-trader';
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
interface ConnectorArtifact {
    path: string;
    contents: string;
    executable?: boolean;
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
    artifacts?: ConnectorArtifact[];
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
    /** On failure, a machine-readable reason (e.g. 'invalid_signature'). */
    reason?: string;
}
/**
 * The registered credential public key, extracted from the COSE_Key at
 * registration. ES256 keys are an uncompressed P-256 point; EdDSA keys are a
 * 32-byte Ed25519 public key.
 */
interface CredentialPublicKey {
    /** COSE algorithm: -7 = ES256 (P-256 / ECDSA), -8 = EdDSA (Ed25519). */
    alg: -7 | -8;
    /** Public key, hex. ES256: 65-byte uncompressed point (0x04 || x || y). EdDSA: 32-byte key. */
    publicKeyHex: string;
}
interface VerifyAssertionOptions {
    /** Allowed origin(s) the assertion must come from, e.g. 'https://app.scopeblind.com'. Defaults to https://<rpId>. */
    expectedOrigin?: string | string[];
    /** Require the UV (user-verified / biometric or PIN) flag. Default true. */
    requireUserVerification?: boolean;
    /** The signCount stored from the previous assertion; a non-increasing counter signals a cloned authenticator. */
    prevSignCount?: number;
    /** Override 'now' (ms) for testing. */
    now?: number;
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
declare function createApprovalChallenge(requestId: string, toolName: string, agentId?: string, rpId?: string, timeoutSeconds?: number, 
/**
 * Optional base64url challenge to use instead of random bytes. Pass a value
 * DERIVED from the exact thing being approved (e.g. a proposal digest) so the
 * passkey signature over the challenge commits to that content, not a bare
 * nonce. It stays per-approval-unique as long as the bound content is unique.
 */
boundChallenge?: string): ApprovalChallenge;
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
 * Verify a WebAuthn assertion: full, fail-closed verification of a passkey or
 * security-key co-sign. This proves a SPECIFIC human authorized a SPECIFIC
 * action with a hardware-held key the host operator cannot exfiltrate. It
 * checks, in order: challenge freshness; clientDataJSON type, challenge, and
 * origin; the rpIdHash; the UP (and, by default, UV) flags; the authenticator
 * signature over authenticatorData || SHA-256(clientDataJSON) using the
 * registered credential public key (ES256 or EdDSA); and signCount monotonicity
 * (clone detection) when a previous count is supplied. Any failure returns
 * valid:false with a reason; nothing is trusted on a partial check.
 *
 * @param challenge - the original challenge
 * @param assertion - the assertion from navigator.credentials.get()
 * @param credentialPublicKey - the registered public key for assertion.credentialId
 * @param opts - origin / UV / signCount / clock options
 */
declare function verifyApprovalAssertion(challenge: ApprovalChallenge, assertion: ApprovalAssertion, credentialPublicKey?: CredentialPublicKey, opts?: VerifyAssertionOptions): ApprovalResult;
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
 * @scopeblind/protect-mcp — Normative policy digest construction
 *
 * The policy_digest a receipt carries must be a recomputable commitment, not
 * the evaluator's name for something. This module defines ONE construction,
 * "acta-policy-digest-v1", used by every policy engine:
 *
 *   M = {
 *     "construction": "acta-policy-digest-v1",
 *     "engine": <engine id, e.g. "cedar" | "builtin">,
 *     "files": [ { "name": <string>, "sha256": <64 lowercase hex over the
 *                  file's exact UTF-8 bytes> }, ... ]   // sorted by name
 *   }
 *   policy_digest = "sha256:" + lowercase_hex(SHA-256(UTF-8(JCS(M))))
 *
 * Design properties, in response to the public review of opaque policy ids:
 *  - Per-file hashing (no concatenation) makes file boundaries unambiguous;
 *    a digest over concatenated sources cannot distinguish ["ab","c"] from
 *    ["a","bc"], and a join delimiter only moves the ambiguity.
 *  - Sorting by name makes the digest independent of directory read order.
 *  - Including names makes renames observable.
 *  - The manifest M is exactly what a policy bundle publishes, so a verifier
 *    who has never talked to the evaluator recomputes the digest from public
 *    bytes alone: hash each published file, build M, JCS, SHA-256.
 *
 * Anything protect-mcp emitted before 0.10.0 used engine-specific preimages
 * truncated to 16 hex chars with no prefix; treat those as opaque labels,
 * not recomputable commitments.
 */
declare const POLICY_DIGEST_CONSTRUCTION = "acta-policy-digest-v1";
declare const POLICY_BUNDLE_SCHEMA = "acta.policy-bundle.v1";
interface PolicyFileEntry {
    name: string;
    /** SHA-256 (lowercase hex) over the file's exact UTF-8 bytes */
    sha256: string;
}
interface PolicyBundle {
    schema: typeof POLICY_BUNDLE_SCHEMA;
    construction: typeof POLICY_DIGEST_CONSTRUCTION;
    engine: string;
    policy_digest: string;
    files: Array<PolicyFileEntry & {
        content: string;
    }>;
    generated_at: string;
}

/**
 * Runtime-enforced mandate lifecycle for protect-mcp.
 *
 * A Cedar directory becomes managed only after `initializeMandateRegistry`.
 * From that point, the gateway accepts a policy head only when it can prove:
 *
 *  1. the exact compiled bytes were signed by the configured gate;
 *  2. any widening was proposed from a signed denial under the prior head;
 *  3. a distinct registered controller approved the exact proposal; and
 *  4. an expiry has not rolled the head back to its baseline.
 *
 * Registry state and policy snapshots stay local. The registry deliberately
 * contains policy bytes so an exported copy is independently verifiable
 * offline; no ScopeBlind service is required to operate the control.
 */

declare const MANDATE_REGISTRY_SCHEMA: "scopeblind.mandate-registry.v1";
declare const MANDATE_PROPOSAL_SCHEMA: "scopeblind.mandate-proposal.v1";
interface GateSigner {
    privateKey: string;
    publicKey: string;
    kid: string;
    issuer?: string;
}
interface DirectController {
    id: string;
    label: string;
    type: 'ed25519';
    public_key: string;
}
interface WebAuthnController {
    id: string;
    label: string;
    type: 'webauthn';
    credential_id: string;
    credential_public_key: CredentialPublicKey;
    sign_count: number;
}
type MandateController = DirectController | WebAuthnController;
interface PolicySnapshot {
    engine: 'cedar';
    policy_digest: string;
    files: Array<{
        name: string;
        content: string;
        sha256: string;
    }>;
    compiled_at: string;
}
interface DenialOrigin {
    /** A signed protect-mcp decision receipt, not an operator-supplied log line. */
    receipt: ActaEnvelope;
    receipt_hash: string;
    request_id: string;
    tool: string;
    reason_code: string;
}
interface PolicyDiff {
    added_statements: string[];
    removed_statements: string[];
    changed_files: Array<{
        name: string;
        before_sha256: string | null;
        after_sha256: string | null;
    }>;
    plain_english: string[];
}
interface MandateProposal {
    schema: typeof MANDATE_PROPOSAL_SCHEMA;
    proposal_id: string;
    proposal_digest: string;
    created_at: string;
    expires_at: string;
    proposed_by: {
        gate_kid: string;
        gate_public_key: string;
    };
    base_policy_digest: string;
    proposed_policy_digest: string;
    denial_origin: DenialOrigin;
    reason: string;
    diff: PolicyDiff;
    candidate: PolicySnapshot;
    proposal_receipt: ActaEnvelope;
}
interface DirectApprovalProof {
    method: 'ed25519';
    controller_id: string;
    controller_label: string;
    approval_receipt: ActaEnvelope;
    approved_at: string;
}
interface WebAuthnApprovalProof {
    method: 'webauthn';
    controller_id: string;
    controller_label: string;
    challenge: ApprovalChallenge;
    assertion: ApprovalAssertion;
    result: ApprovalResult;
    expected_origin: string;
    approved_at: string;
}
type MandateApproval = DirectApprovalProof | WebAuthnApprovalProof;
interface MandateTransition {
    sequence: number;
    event: 'initialized' | 'proposal_created' | 'proposal_approved' | 'policy_activated' | 'policy_expired_reverted';
    occurred_at: string;
    head_before: string | null;
    head_after: string;
    proposal_id?: string;
    approval_digest?: string;
    policy_digest?: string;
    expiry?: string;
    /** Gate-signed digest of the controller SET, carried on the `initialized` transition so injecting or swapping a controller in the plain registry is detected. */
    controllers_digest?: string;
    transition_receipt: ActaEnvelope;
}
interface ActiveMandateHead {
    policy_digest: string;
    baseline_policy_digest: string;
    activated_at: string;
    expires_at?: string;
    proposal_id?: string;
    compilation_receipt: ActaEnvelope;
}
interface PendingWebAuthnChallenge {
    proposal_id: string;
    controller_id: string;
    challenge: ApprovalChallenge;
}
interface MandateRegistry {
    schema: typeof MANDATE_REGISTRY_SCHEMA;
    registry_id: string;
    created_at: string;
    updated_at: string;
    gate: {
        kid: string;
        public_key: string;
        issuer?: string;
    };
    controllers: MandateController[];
    active: ActiveMandateHead;
    policies: Record<string, PolicySnapshot>;
    proposals: Record<string, MandateProposal>;
    approvals: Record<string, MandateApproval>;
    pending_webauthn: Record<string, PendingWebAuthnChallenge>;
    history: MandateTransition[];
}
interface RegistryCheck {
    valid: boolean;
    code?: string;
    message?: string;
    registry?: MandateRegistry;
    expired_reverted?: boolean;
}
interface MandatePaths {
    registry: string;
    snapshots: string;
    auditLog: string;
}
/** Registry metadata lives beside, not inside, the replaceable Cedar directory. */
declare function mandatePaths(cedarDir: string): MandatePaths;
declare function loadGateSigner(keyPath: string): GateSigner;
declare function snapshotFromDirectory(cedarDir: string, compiledAt?: string): PolicySnapshot;
declare function describePolicyDiff(before: PolicySnapshot, after: PolicySnapshot): PolicyDiff;
declare function initializeMandateRegistry(input: {
    cedarDir: string;
    signer: GateSigner;
    controllers: MandateController[];
    now?: Date;
}): MandateRegistry;
declare function loadMandateRegistry(cedarDir: string): MandateRegistry | null;
declare function verifyMandateRegistry(registry: MandateRegistry, now?: Date): RegistryCheck;
declare function createPolicyProposal(input: {
    cedarDir: string;
    signer: GateSigner;
    candidateDir: string;
    denialReceipt: ActaEnvelope;
    reason: string;
    expiresAt: string;
    now?: Date;
}): MandateProposal;
declare function createDirectControllerApproval(input: {
    proposal: MandateProposal;
    controller: DirectController;
    privateKey: string;
    now?: Date;
}): DirectApprovalProof;
declare function createWebAuthnPolicyChallenge(input: {
    cedarDir: string;
    proposalId: string;
    controllerId: string;
    rpId: string;
    timeoutSeconds?: number;
}): ApprovalChallenge;
declare function approvePolicyProposalWithDirectSignature(input: {
    cedarDir: string;
    signer: GateSigner;
    proposalId: string;
    approval: DirectApprovalProof;
    now?: Date;
}): MandateRegistry;
declare function approvePolicyProposalWithWebAuthn(input: {
    cedarDir: string;
    signer: GateSigner;
    proposalId: string;
    assertion: ApprovalAssertion;
    expectedOrigin: string;
    now?: Date;
}): MandateRegistry;
declare function refreshManagedMandate(input: {
    cedarDir: string;
    signer: GateSigner;
    now?: Date;
}): RegistryCheck;
declare function publicMandateStatus(registry: MandateRegistry): Record<string, unknown>;
/**
 * Position-blind Discipline Record attachment. The full registry is retained
 * alongside this summary for an offline verifier, while the summary exposes
 * only the policy-head timeline, controller method, expiry, and signed receipt
 * hashes. It never carries a prompt, portfolio, or tool payload.
 */
declare function exportMandateDisciplineRecord(registry: MandateRegistry, now?: Date): Record<string, unknown>;
/** Offline verifier for a copied registry and its policy bytes. */
declare function verifyMandateLifecycleExport(registry: MandateRegistry, expectedPolicy?: PolicyBundle, now?: Date): RegistryCheck;

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

interface BridgeStats {
    enabled: boolean;
    tenant_slug: string | null;
    forwarded_total: number;
    rejected_total: number;
    blocked_by_egress_guard?: number;
    last_flush_at: string | null;
    last_error: string | null;
}
declare class ScopeBlindBridge {
    private readonly env;
    private readonly token;
    private readonly base;
    private readonly tenantOverride;
    private readonly configuredPseudonymKey;
    private cachedProof;
    /** Raw receipts stay only in this process until minimized at flush time. */
    private queue;
    private flushTimer;
    private stats;
    private shuttingDown;
    constructor(env?: Record<string, string | undefined>);
    enabled(): boolean;
    /** Push a receipt into the local-only queue. Non-blocking. */
    forward(signedReceipt: any): void;
    /** Flush the queue. Safe to call concurrently. */
    flush(): Promise<void>;
    private summaryOptions;
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

declare const EGRESS_SUMMARY_TYPE: "scopeblind.egress_summary.v1";
declare const EGRESS_SUMMARY_VERSION: 1;
/** Exact fields allowed in a summary payload before the signer adds its identity. */
declare const EGRESS_SUMMARY_FIELDS: ReadonlySet<string>;
interface EgressSummary {
    type: typeof EGRESS_SUMMARY_TYPE;
    version: typeof EGRESS_SUMMARY_VERSION;
    /** SHA-256 over the full canonical local receipt envelope. */
    source_receipt_commitment: string;
    /** Local-keyed pseudonym of the local request id; never the id itself. */
    request_pseudonym: string;
    decision: 'allow' | 'deny' | 'approve' | 'other';
    reason_code: string;
    tool_category: ToolCategory;
    policy_commitment: string;
    mode: 'enforce' | 'shadow' | 'audit' | 'other';
    action_commitment?: string;
    output_commitment?: string;
    disclosed_field_count?: number;
    deny_iteration?: number;
}
type ToolCategory = 'communication' | 'source_control' | 'filesystem' | 'database' | 'cloud' | 'browser' | 'finance' | 'other';
interface EgressViolation {
    path: string;
    reason: string;
}
interface EgressCheck {
    safe: boolean;
    violations: EgressViolation[];
}
interface EgressSummaryOptions {
    /**
     * A local-only secret. This is deliberately separate from the receipt key and
     * the tenant bearer token: a hosted-store breach cannot dictionary-check a
     * low-entropy request id or policy reference against this pseudonym.
     */
    pseudonymKey: string | Uint8Array;
    /** Binds a pseudonym to one tenant and hosted destination. */
    tenantScope?: string;
}
/**
 * Create a fixed-schema summary from a complete local receipt. No raw receipt
 * field is copied. Every potentially identifying value is domain-separated and
 * HMAC-pseudonymized with a local-only key before it can cross the boundary.
 */
declare function toEgressSummary(envelope: unknown, opts?: EgressSummaryOptions): EgressSummary | null;
/** Validate a pre-signing summary or a signed summary payload. */
declare function inspectEgress(obj: unknown, opts?: {
    signed?: boolean;
}): EgressCheck;
declare function assertEgressSafe(summary: unknown, opts?: {
    signed?: boolean;
}): void;
interface EgressSelfCheck {
    type: 'scopeblind.egress_self_check.v1';
    generated_at: string;
    summary_fields: string[];
    samples_checked: number;
    all_summaries_safe: boolean;
    raw_content_dropped: boolean;
    private_key_dropped: boolean;
    deny_receipt_forwardable: boolean;
    statement: string;
}
declare function runEgressSelfCheck(sampleReceipts: unknown[], now: string): EgressSelfCheck;

interface SnapshotReceipt {
    type: 'scopeblind.coordination.public-snapshot.v1';
    id: string;
    kind: 'negotiation' | 'result';
    room_id: string;
    session_id?: string;
    proposal_digest?: string;
    target_digest: string;
    evidence_sha256: string;
    authorization_digest: string;
    shared_by: string;
    created_at: string;
    expires_at: string;
    purpose: 'public_read_only_snapshot';
    historical: true;
}
interface SnapshotBase {
    id: string;
    created_at: string;
    expires_at: string;
    receipt: Signed<SnapshotReceipt>;
    authorization: Signed<RpcRequest>;
}
type PublicSnapshot = (SnapshotBase & {
    kind: 'negotiation';
    evidence: NegotiationExport;
}) | (SnapshotBase & {
    kind: 'result';
    evidence: EvidenceBundle;
});
interface SnapshotVerification {
    valid: boolean;
    checks: Array<{
        name: string;
        passed: boolean;
    }>;
    limitations: string[];
}
/** Verifies the saved historical bytes and explicit sharing signature. A link confers no authority. */
declare function verifyPublicSnapshot(value: unknown, authorityKey: string): Promise<SnapshotVerification>;

declare function verifyOwnerAgreement(agreement: Signed<Agreement>, negotiation?: NegotiationExport, depth?: number): Promise<boolean>;

declare function verifyRepositoryCodingEvidence(value: unknown, authorityKey?: string): Promise<{
    valid: boolean;
    errors: string[];
    published: boolean;
    authorityPinned: boolean;
    limitations: string[];
}>;

declare const REPOSITORY_PREVIEW_MAX_BYTES: number;
declare const REPOSITORY_PREVIEW_MAX_FILES = 64;
interface RepositoryPreviewFile {
    path: string;
    content_base64: string;
    sha256: string;
}
interface RepositoryPreviewBundle {
    files: RepositoryPreviewFile[];
    sha256: string;
}
interface RepositoryPreviewEntry {
    path: string;
    sha256: string;
    bytes: number;
}
declare const PREVIEW_TYPES: Record<string, string>;
declare function repositoryPreviewPath(path: unknown): path is string;
declare function validateRepositoryPreviewBundle(value: unknown): Promise<{
    digest: string;
    entries: RepositoryPreviewEntry[];
    files: Array<{
        path: string;
        bytes: Uint8Array;
        sha256: string;
    }>;
}>;

interface RepositoryCodingConfig {
    type: 'scopeblind.repository.coding-config.v1';
    endpoint: string;
    authority_key: string;
    worker_key: string;
    repository: string;
    base_branch: string;
    runtime: 'node22-static-v1';
    test_command: string[];
    build_command: string[];
    preview_directory: string;
    docker_image: string;
}
interface CodingSandbox {
    run(command: string[], timeout: number): Promise<{
        exit_code: number;
        output: string;
        duration_ms: number;
    }>;
    close(): Promise<void>;
}
type DockerExecute = (file: string, args: string[], options: {
    timeout: number;
    killSignal: 'SIGKILL';
    maxBuffer: number;
    env: {
        PATH: string | undefined;
    };
}) => Promise<{
    stdout: string;
    stderr: string;
}>;
declare class DockerCodingSandbox implements CodingSandbox {
    readonly directory: string;
    readonly image: string;
    private dockerExecute;
    private containers;
    private closed;
    constructor(directory: string, image: string, dockerExecute?: DockerExecute);
    run(command: string[], timeout: number): Promise<{
        exit_code: number;
        output: string;
        duration_ms: number;
    }>;
    private remove;
    close(): Promise<void>;
}
declare class RepositoryCodingRunner {
    readonly config: RepositoryCodingConfig;
    private identity;
    private githubToken;
    private fetcher;
    private sandboxFactory;
    private publicationUntil;
    private stopped;
    constructor(config: RepositoryCodingConfig, identity: SigningIdentity, githubToken: string, fetcher?: typeof fetch, sandboxFactory?: (dir: string) => CodingSandbox);
    private rpc;
    private github;
    private checked;
    private readback;
    private result;
    runOne(jobIdFilter?: string): Promise<boolean>;
}

declare const REPOSITORY_RECOVERY_CODES: readonly ["github_connection_required", "local_dispatch", "connection_expired", "connection_revoked", "connection_replaced", "installation_pending", "installation_expired", "receiver_readiness_expired", "coding_readiness_pending", "coding_readiness_expired", "workflow_response_pending", "workflow_approval_required", "workflow_waiting", "workflow_running", "workflow_failed", "workflow_completed_without_response", "provider_unavailable", "provider_observation_incomplete", "pull_draft", "pull_closed", "pull_conflict", "pull_mergeability_pending", "pull_metadata_stale", "base_changed", "head_changed", "required_check_missing", "required_check_pending", "required_check_failed", "inspection_needed", "job_expired"];
type RepositoryRecoveryCode = typeof REPOSITORY_RECOVERY_CODES[number];
interface RepositoryRecoveryIssue {
    code: RepositoryRecoveryCode;
    actor: 'owner' | 'github_reviewer' | 'worker';
    check_name?: string;
    app_id?: number;
}
interface RepositoryRecoveryObservation {
    type: 'scopeblind.repository.recovery-observation.v1';
    setup_id: string;
    setup_digest: string;
    owner_key: string;
    task_id: string | null;
    task_digest: string | null;
    job_id: string | null;
    repository: string;
    pull_number: number;
    observed_at: string;
    expires_at: string;
    issues: RepositoryRecoveryIssue[];
    pull: {
        state: 'open' | 'closed';
        draft: boolean;
        base_sha: string;
        head_sha: string;
        mergeable: boolean | null;
    } | null;
    expected: {
        base_sha: string | null;
        head_sha: string | null;
    };
    workflow: {
        run_id: number;
        status: string;
        conclusion: string | null;
        url: string;
    } | null;
    checks: Array<{
        name: string;
        app_id: number | null;
        state: 'missing' | 'pending' | 'failed' | 'passed';
        run_id: number | null;
    }>;
}
declare function validRepositoryRecoveryObservation(v: unknown): v is RepositoryRecoveryObservation;
declare function verifyRepositoryRecoveryObservation(value: unknown, authorityKey: string, scope: {
    setupId: string;
    ownerKey: string;
    taskId?: string | null;
    jobId?: string | null;
}, now?: number): Promise<boolean>;

/** ScopeBlind-owned fixed-repository controller. No visitor credentials or arbitrary workflow input. */

interface RepositoryTrialRunnerConfig {
    endpoint: string;
    authority_key: string;
    receiver_key: string;
    worker_key: string;
    template_sha: string;
    workflow_sha: string;
}
interface RepositoryTrialRun {
    run_id: number;
    run_attempt: number;
    workflow_ref: string;
    workflow_sha: string;
    oidc: (audience: string) => Promise<string>;
}
declare class RepositoryTrialRunner {
    readonly config: RepositoryTrialRunnerConfig;
    private receiver;
    private worker;
    private token;
    private run;
    private fetcher;
    private sandboxFactory?;
    constructor(config: RepositoryTrialRunnerConfig, receiver: SigningIdentity, worker: SigningIdentity, token: string, run: RepositoryTrialRun, fetcher?: typeof fetch, sandboxFactory?: ((dir: string) => CodingSandbox) | undefined);
    private rpc;
    private github;
    private get repo();
    private ref;
    private blob;
    private ensureRef;
    private checked;
    provision(j: RepositoryTrialJob): Promise<Signed<RepositoryTrialProvision>>;
    private receive;
    private coding;
    runOne(): Promise<boolean>;
}

export { type ActaEnvelope, type ActaSignature, type ActionReceipt, type AdmissionResult, type AgentId, type AgentManifest, type ApprovalAssertion, type ApprovalChallenge, type ApprovalNotification, type ApprovalResult, type ArenaPayload, type ArenaReceipt, type AttestationDocument, type AttestationPayload, type AttestationProvider, type AttestationReceipt, type AttestationResult, type AuditBundle, type AuditBundleOptions, type BenchmarkPayload, type BenchmarkReceipt, type BuilderId, type C2PAAssertion, type C2PAIngredient, type C2PAManifest, type C2PAOptions, type CCRConnectorConfig, type CCRSessionContext, CODING_PERMISSIONS, CONNECTOR_PILOTS, type CalibrationScore, type CedarEvalOptions, type CedarEvalRequest, type CedarPolicySet, type CedarSchema, type CedarSchemaResult, type CodingSandbox, type CommittedFieldOpening, type CommittedSignResult, type ComplianceReport, ConfidentialGate, type ConfidentialGateConfig, type ConfidentialInferenceConfig, type ConnectorAction, type ConnectorEnvVar, type ConnectorPilot, type ConnectorPilotId, CoordinationClient, type CoordinationConfig, CoordinationError, type CoordinationPayment, type CoordinationPaymentResult, type CredentialConfig, type DecisionContext, type DecisionLog, type DelegationReceipt, type DeviceAuthorization, type DevicePermission, type DeviceUse, type DirectController, type DisclosureMode, DockerCodingSandbox, EGRESS_SUMMARY_FIELDS, type Ed25519PublicKey, type EvidenceAttestation, type EvidenceAttestationInput, type EvidenceIssuer, type EvidenceReceipt, type EvidenceReceiptBase, type EvidenceSummary, type EvidenceSummaryEntry, type EvidenceType, type ExternalDecision, type ExternalPDPConfig, type GateSigner, type HFDatasetMetadata, type HFReceiptRow, type HookEventName, type HookInput, type HookResponse, type HumanContext, type InstalledConnectorPilot, type IssuerType, type JsonRpcRequest, type JsonRpcResponse, type LeaseCompatibility, type MandateApproval, type MandateController, type MandateProposal, type MandateRegistry, type MandateTransition, type ManifestBuilder, type ManifestCapabilities, type ManifestConfig, type ManifestIdentity, type ManifestPresentation, type ManifestSignature, type ManifestStatus, type McpToolDescription, type MinimalDisclosure, type NegotiationExport, type NegotiationMandate, type NegotiationProposal, type NegotiationReport, type NegotiationVerification, type NotificationConfig, POLICY_PACKS, PREVIEW_TYPES, type PassportTokenClaims, type PayloadDigest, type PlanReceipt, type PolicyDiff, type PolicyEngineMode, type PolicyPack, type PolicySnapshot, type PredictionReceipt, type PredictionResolution, type PropagatorConfig, type ProtectConfig, ProtectGateway, type ProtectPolicy, type PublicSnapshot, REPOSITORY_CODING_ACTIONS, REPOSITORY_CODING_IMAGE, REPOSITORY_DEVICE_ACTIONS, REPOSITORY_DEVICE_DOMAIN, REPOSITORY_DEVICE_LINK_MS, REPOSITORY_DEVICE_MAX_MS, REPOSITORY_DEVICE_PERMISSIONS, REPOSITORY_GUIDED_WORKFLOW, REPOSITORY_PREVIEW_MAX_BYTES, REPOSITORY_PREVIEW_MAX_FILES, REPOSITORY_RECOVERY_CODES, REPOSITORY_SETUP_ACTIONS, REPOSITORY_SETUP_TTL, REPOSITORY_TRIAL_ACTIONS, type RateLimit, ReceiptPropagator, type ReceiptShape, type ReceiptVerification, type RedactedResult, type RedactionSalt, type RegistryCheck, type RehearsalExport, type RehearsalVerification, type RekorAnchor, type RekorVerification, type RepositoryAcceptance, type RepositoryApproval, type RepositoryClaim, type RepositoryCodingAction, type RepositoryCodingConfig, type RepositoryCodingConnectionConfig, type RepositoryCodingEvidence, type RepositoryCodingFile, type RepositoryCodingJob, type RepositoryCodingMandate, type RepositoryCodingMandateView, type RepositoryCodingModelAction, type RepositoryCodingModelContext, type RepositoryCodingPlan, type RepositoryCodingPublication, type RepositoryCodingRefreshableConnection, type RepositoryCodingRequest, type RepositoryCodingResult, RepositoryCodingRunner, type RepositoryCodingSource, type RepositoryCodingStatus, type RepositoryCodingStop, type RepositoryCodingTest, type RepositoryCollaborationEvidence, type RepositoryDeviceAction, type RepositoryDeviceAuthorization, type RepositoryDeviceConfirmation, type RepositoryDeviceLink, type RepositoryDeviceLinkState, type RepositoryDeviceListState, type RepositoryDevicePermission, type RepositoryDeviceStatus, type RepositoryDeviceUse, type RepositoryDeviceView, type RepositoryEvidence, type RepositoryExecution, type RepositoryGuidedReceiverConfig, type RepositoryHumanContext, type RepositoryOutcome, type RepositoryPreviewBundle, type RepositoryPreviewEntry, type RepositoryPreviewFile, type RepositoryProposal, type RepositoryRecoveryCode, type RepositoryRecoveryIssue, type RepositoryRecoveryObservation, type RepositoryReviewBrief, type RepositoryReviewContent, type RepositoryReviewDecision, type RepositoryReviewEvidence, type RepositoryReviewFeedback, type RepositoryReviewPacket, type RepositoryReviewRecommendation, type RepositoryReviewState, type RepositorySetupAction, type RepositorySetupAuthorization, type RepositorySetupChallenge, type RepositorySetupCoding, type RepositorySetupCodingReady, type RepositorySetupEnrollment, type RepositorySetupGitHub, type RepositorySetupInfo, type RepositorySetupInspection, type RepositorySetupInstallation, type RepositorySetupJob, type RepositorySetupJobState, type RepositorySetupReady, type RepositorySetupRenewal, type RepositorySetupRequest, type RepositorySetupState, type RepositorySetupStatus, type RepositorySetupTaskBinding, type RepositorySetupWorkflowProof, type RepositoryState, type RepositoryTask, type RepositoryTrialAction, type RepositoryTrialCompletion, type RepositoryTrialHtml, type RepositoryTrialInfo, type RepositoryTrialJob, type RepositoryTrialJobKind, type RepositoryTrialJobView, type RepositoryTrialPoll, type RepositoryTrialProvision, type RepositoryTrialReadiness, type RepositoryTrialRequest, RepositoryTrialRunner, type RepositoryTrialState, type RepositoryWorkspace, type RepositoryWorkspaceAgentState, type RepositoryWorkspaceInbox, type RepositoryWorkspaceState, type RestraintPayload, type RestraintReceipt, type SHA256Hash, type SafetyTranscript, type Sandbox, type SandboxConfig, type SandboxReceipt, type SandboxResult, type SandboxToolCall, type SchemaGeneratorConfig, ScopeBlindBridge, type SelectiveDisclosurePackageV0, type SelectiveDisclosureVerification, type SelfTestCase, type SelfTestReport, type SigningConfig, type SimulationResult, type SimulationSummary, type SnapshotReceipt, type SnapshotVerification, type SwarmContext, TRIAL_CODING_CHECK, TRIAL_DOCKER_IMAGE, TRIAL_LIMITS, TRIAL_REPOSITORY, TRIAL_SOURCE_CHECK, TRIAL_TEMPLATE, TRIAL_WORKFLOW, type TierOverrides, type TimingMetrics, type ToolPolicy, type TrustTier, type WebAuthnController, type WorkPayload, type WorkReceipt, type WorkspaceMember, type WorkspacePreparationMandate, type WorkspaceReviewDraft, type WorkspaceTaskAssignment, anchorToRekor, approvePolicyProposalWithDirectSignature, approvePolicyProposalWithWebAuthn, assertEgressSafe, buildDecisionContext, checkRateLimit, codingCommand, codingSafePath, codingScopeWithin, collectSignedReceipts, computeCalibration, computeSbIssuerKid, confidentialInference, connectorDirectory, connectorDoctor, connectorPilotIds, coordinationConfigFromArgs, createApprovalChallenge, createApprovalReceiptPayload, createAttestationField, createAuditBundle, createC2PAManifest, createDirectControllerApproval, createDisclosurePackage, createEvidenceAttestation, createLogAnchorField, createPolicyProposal, createReceiptChannel, createReceiptEnvelope, createSandbox, createSelectiveDisclosurePackage, createWebAuthnPolicyChallenge, describePolicyDiff, destroySandbox, discloseField, ed25519ToDIDKey, evaluateCedar, evaluateTier, exportC2PAManifestJSON, exportJSONL, exportMandateDisciplineRecord, formatReportMarkdown, formatSimulation, forwardReceipt, generateC2PACommand, generateCedarSchema, generateDatasetCard, generateHFMetadata, generateReport, generateSafetyTranscript, generateSchemaStub, getConnectorPilot, getPolicyPack, getScopeBlindBridge, getSignerInfo, getToolPolicy, hashReceipt, hashResponseBody, humanPrincipal, initSigning, initializeMandateRegistry, inspectEgress, isAgentId, isCedarAvailable, isDisclosureMode, isEvidenceType, isManifestStatus, isSigningEnabled, listCredentialLabels, loadCedarPolicies, loadGateSigner, loadMandateRegistry, loadPolicy, mandatePaths, manifestToVC, meetsMinTier, parseLogFile, parseNotificationConfigFromEnv, parseRateLimit, policyPackIds, policySetFromSource, publicMandateStatus, queryExternalPDP, readInstalledConnectorPilots, receiptHash, receiptIdentity, receiptToVP, receiptsToHFRows, redactFields, refreshManagedMandate, repositoryDevicePermission, repositoryDevicePreimage, repositoryHumanPermission, repositoryHumanPrincipal, repositoryPreviewPath, repositorySetupArtifactUrl, repositorySnapshotDigest, resolveCredential, revealField, runEgressSelfCheck, runEvaluatorSelfTest, runInSandbox, sameRepositoryHumanIntent, sendApprovalNotification, signCommittedDecision, signDecision, simulate, snapshotFromDirectory, toCredentialRequestOptions, toEgressSummary, toManifoldFormat, toMetaculusFormat, trialBase, trialCodingConfig, trialSource, validRepositoryCodingConnectionConfig, validRepositoryCodingMandate, validRepositoryCodingPlan, validRepositoryCodingRefreshableConnections, validRepositoryCodingRequest, validRepositoryCodingResult, validRepositoryCodingSource, validRepositoryCodingStop, validRepositoryDeviceAuthorization, validRepositoryDeviceConfirmation, validRepositoryDeviceLink, validRepositoryHumanEnvelope, validRepositoryRecoveryObservation, validRepositorySetupAuthorization, validRepositorySetupInspection, validRepositorySetupRenewal, validRepositorySetupRequest, validRepositoryTrialProvision, validRepositoryTrialRequest, validTrialReadiness, validateCoordinationConfig, validateCoordinationPayment, validateCredentials, validateEvidenceReceipt, validateManifest, validateRepositoryPreviewBundle, verifyActaC2PAAssertions, verifyAllCommitments, verifyApprovalAssertion, verifyCommitment, verifyDeviceAuthorization, verifyEvidenceAttestation, verifyHuman, verifyMandateLifecycleExport, verifyMandateRegistry, verifyNegotiationEvidence, verifyOwnerAgreement, verifyPublicSnapshot, verifyReceipt, verifyRehearsalEvidence, verifyRekorAnchor, verifyRepositoryCodingEvidence, verifyRepositoryCollaborationEvidence, verifyRepositoryDeviceAuthorization, verifyRepositoryEvidence, verifyRepositoryHuman, verifyRepositoryRecoveryObservation, verifyRepositoryReviewEvidence, verifyRepositorySetupEnrollment, verifyRepositorySetupReplacement, verifyRepositorySetupState, verifyRepositoryTrialConnection, verifyRepositoryTrialState, verifyRepositoryWorkspaceAgentState, verifyRepositoryWorkspaceState, verifySelectiveDisclosurePackage, writeConnectorPilots };
