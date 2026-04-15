/**
 * @scopeblind/protect-mcp — Claude Code Hook Server
 *
 * HTTP server that integrates protect-mcp with Claude Code's hook system.
 * Receives hook events via HTTP POST, evaluates Cedar policies, signs
 * receipts, and returns hook responses matching Claude Code's syncHookResponseSchema.
 *
 * Architecture:
 *   - Persistent local server on 127.0.0.1:9377 (configurable)
 *   - Zero cold start (Cedar policies loaded once, cached in memory)
 *   - PreToolUse: synchronous policy check (deny is authoritative)
 *   - PostToolUse: async receipt signing (never blocks tool execution)
 *   - Full swarm lifecycle tracking (7 agent events)
 *   - ConfigChange tamper detection
 *
 * Claude Code hook config (.claude/settings.json):
 *   {
 *     "hooks": {
 *       "PreToolUse": [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:9377/hook" }] }],
 *       "PostToolUse": [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:9377/hook" }] }]
 *     }
 *   }
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { appendFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type {
  HookInput,
  HookResponse,
  HookEventName,
  DecisionLog,
  SwarmContext,
  TimingMetrics,
  PayloadDigest,
  TrustTier,
} from './types.js';
import { loadCedarPolicies, evaluateCedar, isCedarAvailable, type CedarPolicySet } from './cedar-evaluator.js';
import { initSigning, signDecision, isSigningEnabled, getSignerInfo } from './signing.js';
import { loadPolicy, getToolPolicy, parseRateLimit, checkRateLimit } from './policy.js';
import { ReceiptBuffer } from './http-server.js';

// ============================================================
// Constants
// ============================================================

const DEFAULT_PORT = 9377;
const LOG_FILE = '.protect-mcp-log.jsonl';
const RECEIPTS_FILE = '.protect-mcp-receipts.jsonl';
const PAYLOAD_HASH_THRESHOLD = 1024; // bytes

// ============================================================
// Hook Server State
// ============================================================

interface HookServerState {
  /** Cedar policy set (if loaded) */
  cedarPolicies: CedarPolicySet | null;
  /** JSON policy (if loaded) */
  jsonPolicy: ReturnType<typeof loadPolicy> | null;
  /** Rate limit store */
  rateLimitStore: Map<string, number[]>;
  /** Receipt buffer for /receipts endpoint */
  receiptBuffer: ReceiptBuffer;
  /** In-flight tool calls (PreToolUse → PostToolUse timing) */
  inflightTools: Map<string, { tool: string; startedAt: number; requestId: string }>;
  /** Deny iteration counter per tool (tracks retries after denial) */
  denyCounter: Map<string, number>;
  /** Swarm context (detected from env vars or hook events) */
  swarmContext: SwarmContext;
  /** Active plan receipt ID (if Ultraplan is active) */
  activePlanReceiptId: string | null;
  /** Server start time */
  startTime: number;
  /** Port */
  port: number;
  /** Verbose logging */
  verbose: boolean;
  /** Enforce mode */
  enforce: boolean;
  /** Policy digest */
  policyDigest: string;
  /** Log file path */
  logFilePath: string;
  /** Receipt file path */
  receiptFilePath: string;
  /** Permission suggestions accumulated during session */
  permissionSuggestions: Map<string, string>;
  /** Config change alerts issued */
  configAlerts: Array<{ timestamp: number; path: string; source: string }>;
}

// ============================================================
// Swarm Detection
// ============================================================

function detectSwarmContext(): SwarmContext {
  const teamName = process.env.CLAUDE_CODE_TEAM_NAME;
  const agentId = process.env.CLAUDE_CODE_AGENT_ID;
  const agentName = process.env.CLAUDE_CODE_AGENT_NAME;

  if (!teamName && !agentId) {
    return { agent_type: 'standalone' };
  }

  const isLeader = !agentId || agentId === 'team-lead';

  return {
    team_name: teamName,
    agent_id: agentId,
    agent_name: agentName,
    is_leader: isLeader,
    agent_type: isLeader ? 'coordinator' : 'worker',
  };
}

// ============================================================
// Payload Hashing
// ============================================================

function computePayloadDigest(input: unknown): PayloadDigest | undefined {
  const content = typeof input === 'string' ? input : JSON.stringify(input || {});
  const size = Buffer.byteLength(content, 'utf-8');

  if (size <= PAYLOAD_HASH_THRESHOLD) {
    return undefined; // Small enough to include inline
  }

  return {
    input_hash: createHash('sha256').update(content).digest('hex'),
    input_size: size,
    truncated: true,
    preview: content.slice(0, 256),
  };
}

function computeOutputDigest(output: unknown): Partial<PayloadDigest> | undefined {
  const content = typeof output === 'string' ? output : JSON.stringify(output || {});
  const size = Buffer.byteLength(content, 'utf-8');

  if (size <= PAYLOAD_HASH_THRESHOLD) {
    return undefined;
  }

  return {
    output_hash: createHash('sha256').update(content).digest('hex'),
    output_size: size,
  };
}

// ============================================================
// Sandbox Detection
// ============================================================

function detectSandboxState(): 'enabled' | 'disabled' | 'unavailable' {
  // Check for common sandbox indicators
  if (process.env.SANDBOX_ENABLED === '1' || process.env.CLAUDE_CODE_SANDBOX === '1') {
    return 'enabled';
  }
  // Check if we're inside a macOS sandbox profile
  if (process.platform === 'darwin' && process.env.APP_SANDBOX_CONTAINER_ID) {
    return 'enabled';
  }
  // Check for bubblewrap on Linux
  if (process.platform === 'linux') {
    try {
      const procStatus = readFileSync('/proc/self/status', 'utf-8');
      if (procStatus.includes('Seccomp:\t2')) return 'enabled';
    } catch { /* not critical */ }
  }
  return 'unavailable';
}

// ============================================================
// Hook Event Handlers
// ============================================================

async function handlePreToolUse(
  input: HookInput,
  state: HookServerState,
): Promise<HookResponse> {
  const hookStart = Date.now();
  const toolName = input.toolName || 'unknown';
  const requestId = input.toolUseId || randomUUID().slice(0, 12);

  // Track in-flight for timing
  state.inflightTools.set(requestId, {
    tool: toolName,
    startedAt: hookStart,
    requestId,
  });

  // Compute payload digest for large inputs
  const payloadDigest = computePayloadDigest(input.toolInput);

  // Build swarm context from hook input (override env detection)
  const swarm: SwarmContext = {
    ...state.swarmContext,
    ...(input.agentId && { agent_id: input.agentId }),
    ...(input.agentName && { agent_name: input.agentName }),
    ...(input.teamName && { team_name: input.teamName }),
    ...(input.agentType && { agent_type: input.agentType as SwarmContext['agent_type'] }),
  };

  // ── Cedar evaluation ──
  if (state.cedarPolicies) {
    try {
      const cedarDecision = await evaluateCedar(state.cedarPolicies, {
        tool: toolName,
        tier: 'unknown' as TrustTier, // Hook mode doesn't have admission tier yet
        agentId: swarm.agent_id,
        context: {
          hook_event: 'PreToolUse',
          ...(input.toolInput || {}),
        },
      });

      if (!cedarDecision.allowed) {
        const reason = cedarDecision.reason || 'cedar_deny';
        const hookLatency = Date.now() - hookStart;

        // Track deny iteration
        const denyKey = `${toolName}:${input.sessionId || 'default'}`;
        const denyCount = (state.denyCounter.get(denyKey) || 0) + 1;
        state.denyCounter.set(denyKey, denyCount);

        // Generate permission suggestion
        const suggestion = `permit(principal, action == Action::"MCP::Tool::call", resource == Tool::"${toolName}");`;
        state.permissionSuggestions.set(toolName, suggestion);

        emitDecisionLog(state, {
          tool: toolName,
          decision: 'deny',
          reason_code: reason,
          request_id: requestId,
          hook_event: 'PreToolUse',
          swarm: swarm.team_name ? swarm : undefined,
          timing: { hook_latency_ms: hookLatency, started_at: hookStart },
          payload_digest: payloadDigest,
          deny_iteration: denyCount,
          sandbox_state: detectSandboxState(),
          plan_receipt_id: state.activePlanReceiptId || undefined,
        });

        // Log suggestion to stderr
        if (denyCount === 1) {
          process.stderr.write(
            `[PROTECT_MCP] No Cedar permit for "${toolName}" — suggest:\n` +
            `  ${suggestion}\n`,
          );
        }

        return {
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason:
              `[ScopeBlind] Denied by Cedar policy. ${reason}. ` +
              `Forbidden: "${toolName}" is not permitted. Try a read-only alternative.` +
              (denyCount > 1 ? ` (attempt ${denyCount})` : ''),
          },
        };
      }
    } catch (err) {
      if (state.verbose) {
        process.stderr.write(`[PROTECT_MCP] Cedar eval error: ${err instanceof Error ? err.message : err}\n`);
      }
      // Fall through to allow on Cedar errors (fail-open)
    }
  }

  // ── JSON policy evaluation (block / rate-limit / require_approval) ──
  if (state.jsonPolicy?.policy) {
    const toolPolicy = getToolPolicy(toolName, state.jsonPolicy.policy);

    if (toolPolicy.block) {
      const hookLatency = Date.now() - hookStart;
      emitDecisionLog(state, {
        tool: toolName,
        decision: 'deny',
        reason_code: 'policy_block',
        request_id: requestId,
        hook_event: 'PreToolUse',
        swarm: swarm.team_name ? swarm : undefined,
        timing: { hook_latency_ms: hookLatency, started_at: hookStart },
        payload_digest: payloadDigest,
        sandbox_state: detectSandboxState(),
      });

      return {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: `[ScopeBlind] "${toolName}" is blocked by policy.`,
        },
      };
    }

    if (toolPolicy.require_approval) {
      const hookLatency = Date.now() - hookStart;
      emitDecisionLog(state, {
        tool: toolName,
        decision: 'require_approval',
        reason_code: 'requires_human_approval',
        request_id: requestId,
        hook_event: 'PreToolUse',
        swarm: swarm.team_name ? swarm : undefined,
        timing: { hook_latency_ms: hookLatency, started_at: hookStart },
        sandbox_state: detectSandboxState(),
      });

      return {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask',
          permissionDecisionReason:
            `[ScopeBlind] "${toolName}" requires human approval. Policy: ${state.policyDigest}`,
        },
      };
    }

    // Rate limit check
    if (toolPolicy.rate_limit) {
      try {
        const limit = parseRateLimit(toolPolicy.rate_limit);
        const key = `tool:${toolName}:hook`;
        const { allowed, remaining } = checkRateLimit(key, limit, state.rateLimitStore);
        if (!allowed) {
          const hookLatency = Date.now() - hookStart;
          emitDecisionLog(state, {
            tool: toolName,
            decision: 'deny',
            reason_code: 'rate_limit_exceeded',
            request_id: requestId,
            hook_event: 'PreToolUse',
            swarm: swarm.team_name ? swarm : undefined,
            timing: { hook_latency_ms: hookLatency, started_at: hookStart },
            sandbox_state: detectSandboxState(),
          });

          return {
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: 'deny',
              permissionDecisionReason:
                `[ScopeBlind] "${toolName}" rate limit exceeded (${toolPolicy.rate_limit}).`,
            },
          };
        }
      } catch { /* skip bad rate limit spec */ }
    }
  }

  // ── Allow ──
  const hookLatency = Date.now() - hookStart;

  // Reset deny counter on allow
  const denyKey = `${toolName}:${input.sessionId || 'default'}`;
  state.denyCounter.delete(denyKey);

  emitDecisionLog(state, {
    tool: toolName,
    decision: 'allow',
    reason_code: state.cedarPolicies ? 'cedar_allow' : (state.jsonPolicy ? 'policy_allow' : 'observe_mode'),
    request_id: requestId,
    hook_event: 'PreToolUse',
    swarm: swarm.team_name ? swarm : undefined,
    timing: { hook_latency_ms: hookLatency, started_at: hookStart },
    payload_digest: payloadDigest,
    sandbox_state: detectSandboxState(),
    plan_receipt_id: state.activePlanReceiptId || undefined,
  });

  // No hookSpecificOutput → Claude Code treats as implicit allow
  return {};
}

async function handlePostToolUse(
  input: HookInput,
  state: HookServerState,
): Promise<HookResponse> {
  const toolName = input.toolName || 'unknown';
  const requestId = input.toolUseId || randomUUID().slice(0, 12);
  const now = Date.now();

  // Compute timing from in-flight tracking
  const inflight = state.inflightTools.get(requestId);
  const timing: TimingMetrics = {
    completed_at: now,
  };
  if (inflight) {
    timing.tool_duration_ms = now - inflight.startedAt;
    timing.started_at = inflight.startedAt;
    state.inflightTools.delete(requestId);
  }

  // Compute output digest
  const outputDigest = computeOutputDigest(input.toolResult);

  // Build additionalContext feedback
  const receiptId = randomUUID().slice(0, 8);
  const policyName = state.cedarPolicies ? `cedar:${state.policyDigest}` : state.policyDigest;
  const additionalContext =
    `[ScopeBlind] Tool call receipted. Policy: ${policyName}. Decision: allow. Receipt: #${receiptId}.` +
    (timing.tool_duration_ms !== undefined ? ` Duration: ${timing.tool_duration_ms}ms.` : '') +
    (timing.hook_latency_ms !== undefined ? ` Overhead: ${timing.hook_latency_ms}ms.` : '');

  // Emit post-execution receipt
  emitDecisionLog(state, {
    tool: toolName,
    decision: 'allow',
    reason_code: 'post_execution_receipt',
    request_id: requestId,
    hook_event: 'PostToolUse',
    swarm: state.swarmContext.team_name ? state.swarmContext : undefined,
    timing,
    payload_digest: outputDigest ? {
      truncated: true,
      output_hash: outputDigest.output_hash,
      output_size: outputDigest.output_size,
    } : undefined,
    sandbox_state: detectSandboxState(),
  });

  // additionalContext MUST be inside hookSpecificOutput per Claude Code's
  // PostToolUseHookSpecificOutputSchema (coreSchemas.ts line 846-851).
  // The async/sync schemas are mutually exclusive — we return a sync response
  // with hookSpecificOutput containing the feedback context.
  return {
    hookSpecificOutput: {
      hookEventName: 'PostToolUse' as HookEventName,
      additionalContext,
    },
  };
}

function handleSubagentStart(
  input: HookInput,
  state: HookServerState,
): HookResponse {
  const agentId = input.agentId || 'unknown';
  const agentType = input.agentType || 'worker';

  emitDecisionLog(state, {
    tool: `subagent:${agentId}`,
    decision: 'allow',
    reason_code: 'subagent_started',
    request_id: randomUUID().slice(0, 12),
    hook_event: 'SubagentStart',
    swarm: {
      ...state.swarmContext,
      agent_id: agentId,
      agent_name: input.agentName,
      agent_type: agentType as SwarmContext['agent_type'],
    },
  });

  if (state.verbose) {
    process.stderr.write(`[PROTECT_MCP] Subagent started: ${agentId} (${agentType})\n`);
  }

  return {};
}

function handleSubagentStop(
  input: HookInput,
  state: HookServerState,
): HookResponse {
  const agentId = input.agentId || 'unknown';

  emitDecisionLog(state, {
    tool: `subagent:${agentId}`,
    decision: 'allow',
    reason_code: 'subagent_stopped',
    request_id: randomUUID().slice(0, 12),
    hook_event: 'SubagentStop',
    swarm: {
      ...state.swarmContext,
      agent_id: agentId,
      agent_name: input.agentName,
    },
  });

  return {};
}

function handleTaskCreated(input: HookInput, state: HookServerState): HookResponse {
  emitDecisionLog(state, {
    tool: `task:${input.taskId || 'unknown'}`,
    decision: 'allow',
    reason_code: 'task_created',
    request_id: randomUUID().slice(0, 12),
    hook_event: 'TaskCreated',
    swarm: {
      ...state.swarmContext,
      agent_name: input.teammateName,
    },
  });
  return {};
}

function handleTaskCompleted(input: HookInput, state: HookServerState): HookResponse {
  emitDecisionLog(state, {
    tool: `task:${input.taskId || 'unknown'}`,
    decision: 'allow',
    reason_code: 'task_completed',
    request_id: randomUUID().slice(0, 12),
    hook_event: 'TaskCompleted',
    swarm: state.swarmContext,
  });
  return {};
}

function handleSessionStart(input: HookInput, state: HookServerState): HookResponse {
  emitDecisionLog(state, {
    tool: 'session',
    decision: 'allow',
    reason_code: 'session_started',
    request_id: input.sessionId || randomUUID().slice(0, 12),
    hook_event: 'SessionStart',
    swarm: state.swarmContext,
    sandbox_state: detectSandboxState(),
  });
  return {};
}

function handleSessionEnd(input: HookInput, state: HookServerState): HookResponse {
  // Emit session summary
  const suggestions = [...state.permissionSuggestions.entries()];
  if (suggestions.length > 0) {
    process.stderr.write(`\n[PROTECT_MCP] Session summary — ${suggestions.length} policy suggestion(s):\n`);
    for (const [tool, suggestion] of suggestions) {
      process.stderr.write(`  ${tool}: ${suggestion}\n`);
    }
    process.stderr.write('\n');
  }

  emitDecisionLog(state, {
    tool: 'session',
    decision: 'allow',
    reason_code: 'session_ended',
    request_id: input.sessionId || randomUUID().slice(0, 12),
    hook_event: 'SessionEnd',
    swarm: state.swarmContext,
  });
  return {};
}

function handleTeammateIdle(input: HookInput, state: HookServerState): HookResponse {
  emitDecisionLog(state, {
    tool: `teammate:${input.agentId || 'unknown'}`,
    decision: 'allow',
    reason_code: 'teammate_idle',
    request_id: randomUUID().slice(0, 12),
    hook_event: 'TeammateIdle',
    swarm: {
      ...state.swarmContext,
      agent_id: input.agentId,
      agent_name: input.agentName,
    },
  });
  return {};
}

function handleConfigChange(input: HookInput, state: HookServerState): HookResponse {
  // Claude Code sends file_path (→ filePath) for ConfigChange, not config_path
  const configPath = input.filePath || input.configPath || 'unknown';
  const source = input.configSource || 'unknown';

  // Tamper detection: check if protect-mcp's own hook config was modified
  const isSelfModification = configPath.includes('settings.json') || configPath.includes('.claude/');
  if (isSelfModification) {
    state.configAlerts.push({
      timestamp: Date.now(),
      path: configPath,
      source,
    });

    process.stderr.write(
      `[PROTECT_MCP] ⚠️  TAMPER ALERT: Config file modified: ${configPath} (source: ${source})\n`,
    );

    emitDecisionLog(state, {
      tool: 'config',
      decision: 'deny',
      reason_code: 'config_tamper_detected',
      request_id: randomUUID().slice(0, 12),
      hook_event: 'ConfigChange',
      swarm: state.swarmContext,
    });
  } else {
    emitDecisionLog(state, {
      tool: 'config',
      decision: 'allow',
      reason_code: 'config_changed',
      request_id: randomUUID().slice(0, 12),
      hook_event: 'ConfigChange',
    });
  }

  return {};
}

function handleStop(input: HookInput, state: HookServerState): HookResponse {
  // Finalization: flush all pending state
  const suggestions = [...state.permissionSuggestions.entries()];
  if (suggestions.length > 0) {
    process.stderr.write(`\n[PROTECT_MCP] Final policy suggestions:\n`);
    for (const [tool, suggestion] of suggestions) {
      process.stderr.write(`  ${suggestion}\n`);
    }
    process.stderr.write('\n');
  }

  emitDecisionLog(state, {
    tool: 'session',
    decision: 'allow',
    reason_code: 'agent_stopped',
    request_id: randomUUID().slice(0, 12),
    hook_event: 'Stop',
    swarm: state.swarmContext,
  });

  return {};
}

// ============================================================
// Decision Log Emission
// ============================================================

function emitDecisionLog(state: HookServerState, entry: Partial<DecisionLog>): void {
  const mode = state.enforce ? 'enforce' : 'shadow';
  const otelTraceId = randomBytes(16).toString('hex');
  const otelSpanId = randomBytes(8).toString('hex');

  const log: DecisionLog = {
    v: 2,
    tool: entry.tool || 'unknown',
    decision: entry.decision || 'allow',
    reason_code: entry.reason_code || 'default_allow',
    policy_digest: state.policyDigest,
    policy_engine: state.cedarPolicies ? 'cedar' : 'built-in',
    request_id: entry.request_id || randomUUID().slice(0, 12),
    timestamp: Date.now(),
    mode: mode as 'shadow' | 'enforce',
    otel_trace_id: otelTraceId,
    otel_span_id: otelSpanId,
    ...(entry.tier && { tier: entry.tier }),
    ...(entry.hook_event && { hook_event: entry.hook_event }),
    ...(entry.swarm && { swarm: entry.swarm }),
    ...(entry.timing && { timing: entry.timing }),
    ...(entry.payload_digest && { payload_digest: entry.payload_digest }),
    ...(entry.deny_iteration && { deny_iteration: entry.deny_iteration }),
    ...(entry.sandbox_state && { sandbox_state: entry.sandbox_state }),
    ...(entry.plan_receipt_id && { plan_receipt_id: entry.plan_receipt_id }),
  };

  process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}\n`);

  try { appendFileSync(state.logFilePath, JSON.stringify(log) + '\n'); } catch { /* best-effort */ }

  if (isSigningEnabled()) {
    const signed = signDecision(log);
    if (signed.signed) {
      try { appendFileSync(state.receiptFilePath, signed.signed + '\n'); } catch { /* best-effort */ }
      state.receiptBuffer.add(log.request_id, signed.signed);
    } else if (signed.warning) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${signed.warning}\n`);
    }
  }
}

// ============================================================
// HTTP Server
// ============================================================

async function routeHookEvent(input: HookInput, state: HookServerState): Promise<HookResponse> {
  switch (input.hookEventName) {
    case 'PreToolUse':
      return handlePreToolUse(input, state);
    case 'PostToolUse':
      return handlePostToolUse(input, state);
    case 'SubagentStart':
      return handleSubagentStart(input, state);
    case 'SubagentStop':
      return handleSubagentStop(input, state);
    case 'TaskCreated':
      return handleTaskCreated(input, state);
    case 'TaskCompleted':
      return handleTaskCompleted(input, state);
    case 'SessionStart':
      return handleSessionStart(input, state);
    case 'SessionEnd':
      return handleSessionEnd(input, state);
    case 'TeammateIdle':
      return handleTeammateIdle(input, state);
    case 'ConfigChange':
      return handleConfigChange(input, state);
    case 'Stop':
      return handleStop(input, state);
    default:
      // Unknown hook event — log and pass through
      if (state.verbose) {
        process.stderr.write(`[PROTECT_MCP] Unknown hook event: ${input.hookEventName}\n`);
      }
      return {};
  }
}

export interface HookServerOptions {
  port?: number;
  policyPath?: string;
  cedarDir?: string;
  enforce?: boolean;
  verbose?: boolean;
}

export async function startHookServer(options: HookServerOptions = {}): Promise<Server> {
  const port = options.port || DEFAULT_PORT;
  const verbose = options.verbose || false;
  const enforce = options.enforce || false;

  // ── Load policies ──
  let cedarPolicies: CedarPolicySet | null = null;
  let jsonPolicy: ReturnType<typeof loadPolicy> | null = null;
  let policyDigest = 'none';

  // Auto-detect Cedar policies
  const cedarDir = options.cedarDir || findCedarDir();
  if (cedarDir) {
    try {
      cedarPolicies = loadCedarPolicies(cedarDir);
      policyDigest = cedarPolicies.digest;
      process.stderr.write(
        `[PROTECT_MCP] Cedar policies loaded: ${cedarPolicies.fileCount} files from ${cedarDir} ` +
        `(digest: ${policyDigest})\n`,
      );
      const cedarAvailable = await isCedarAvailable();
      if (!cedarAvailable) {
        process.stderr.write(
          '[PROTECT_MCP] Warning: @cedar-policy/cedar-wasm not installed. ' +
          'Cedar policies loaded but evaluation fallback is allow-all.\n',
        );
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Cedar load error: ${err instanceof Error ? err.message : err}\n`);
    }
  }

  // Load JSON policy if specified
  if (options.policyPath) {
    try {
      jsonPolicy = loadPolicy(options.policyPath);
      if (!cedarPolicies) policyDigest = jsonPolicy.digest;
      process.stderr.write(`[PROTECT_MCP] JSON policy loaded from ${options.policyPath}\n`);

      // Initialize signing if configured
      if (jsonPolicy.signing) {
        const warnings = await initSigning(jsonPolicy.signing);
        for (const w of warnings) {
          process.stderr.write(`[PROTECT_MCP] Warning: ${w}\n`);
        }
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Policy load error: ${err instanceof Error ? err.message : err}\n`);
    }
  }

  // Auto-detect signing config if no policy loaded
  if (!jsonPolicy?.signing) {
    const keyPath = join(process.cwd(), 'keys', 'gateway.json');
    if (existsSync(keyPath)) {
      const warnings = await initSigning({ key_path: keyPath, issuer: 'protect-mcp', enabled: true });
      for (const w of warnings) {
        process.stderr.write(`[PROTECT_MCP] Warning: ${w}\n`);
      }
    }
  }

  // ── Build state ──
  const state: HookServerState = {
    cedarPolicies,
    jsonPolicy,
    rateLimitStore: new Map(),
    receiptBuffer: new ReceiptBuffer(),
    inflightTools: new Map(),
    denyCounter: new Map(),
    swarmContext: detectSwarmContext(),
    activePlanReceiptId: null,
    startTime: Date.now(),
    port,
    verbose,
    enforce,
    policyDigest,
    logFilePath: join(process.cwd(), LOG_FILE),
    receiptFilePath: join(process.cwd(), RECEIPTS_FILE),
    permissionSuggestions: new Map(),
    configAlerts: [],
  };

  // ── Create HTTP server ──
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://localhost:${port}`);

    // ── Health endpoint ──
    if (url.pathname === '/health' && req.method === 'GET') {
      const signerInfo = getSignerInfo();
      res.writeHead(200);
      res.end(JSON.stringify({
        status: 'ok',
        server: 'protect-mcp-hooks',
        version: '0.5.0',
        uptime_ms: Date.now() - state.startTime,
        mode: enforce ? 'enforce' : 'shadow',
        policy_digest: policyDigest,
        policy_engine: cedarPolicies ? 'cedar' : (jsonPolicy ? 'built-in' : 'none'),
        signing: isSigningEnabled(),
        swarm: state.swarmContext,
        signer: signerInfo ? { kid: signerInfo.kid, issuer: signerInfo.issuer } : null,
        cedar_files: cedarPolicies?.fileCount || 0,
      }));
      return;
    }

    // ── Receipts endpoint ──
    if (url.pathname === '/receipts' && req.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '20', 10);
      const receipts = state.receiptBuffer.getAll().slice(0, Math.min(limit, 100));
      res.writeHead(200);
      res.end(JSON.stringify({ count: receipts.length, total: state.receiptBuffer.count(), receipts }));
      return;
    }

    if (url.pathname === '/receipts/latest' && req.method === 'GET') {
      const latest = state.receiptBuffer.getLatest();
      if (!latest) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'no_receipts' }));
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify(latest));
      return;
    }

    // ── Suggestions endpoint ──
    if (url.pathname === '/suggestions' && req.method === 'GET') {
      const suggestions = [...state.permissionSuggestions.entries()].map(([tool, rule]) => ({ tool, cedar_rule: rule }));
      res.writeHead(200);
      res.end(JSON.stringify({ count: suggestions.length, suggestions }));
      return;
    }

    // ── Config alerts endpoint ──
    if (url.pathname === '/alerts' && req.method === 'GET') {
      res.writeHead(200);
      res.end(JSON.stringify({ count: state.configAlerts.length, alerts: state.configAlerts }));
      return;
    }

    // ── Main hook endpoint ──
    if (url.pathname === '/hook' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', async () => {
        try {
          const raw = JSON.parse(body) as Record<string, unknown>;

          // Normalize snake_case (from Claude Code) → camelCase (our internal types)
          const input = normalizeHookInput(raw);

          if (!input.hookEventName) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'missing_hook_event_name', hint: 'Expected hook_event_name or hookEventName in POST body' }));
            return;
          }

          const response = await routeHookEvent(input, state);

          res.writeHead(200);
          res.end(JSON.stringify(response));
        } catch (err) {
          if (verbose) {
            process.stderr.write(`[PROTECT_MCP] Hook error: ${err instanceof Error ? err.message : err}\n`);
          }
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'invalid_request' }));
        }
      });
      return;
    }

    // ── 404 ──
    res.writeHead(404);
    res.end(JSON.stringify({
      error: 'not_found',
      endpoints: [
        'POST /hook           — Claude Code hook endpoint',
        'GET  /health         — Health check',
        'GET  /receipts       — Recent receipts',
        'GET  /receipts/latest — Most recent receipt',
        'GET  /suggestions    — Policy suggestions',
        'GET  /alerts         — Config tamper alerts',
      ],
    }));
  });

  server.listen(port, '127.0.0.1', () => {
    const w = (s: string) => process.stderr.write(s);
    const pad = (s: string, n = 46) => s.padEnd(n);
    w(`\n`);
    w(`  protect-mcp v0.5.4\n`);
    w(`  ScopeBlind — https://scopeblind.com\n`);
    w(`\n`);
    w(`  Listening     http://127.0.0.1:${port}\n`);
    w(`  Mode          ${enforce ? 'enforce' : 'shadow'}\n`);
    w(`  Policy        ${cedarPolicies ? `Cedar (${cedarPolicies.fileCount} files)` : (jsonPolicy ? 'JSON' : 'none')}\n`);
    w(`  Signing       ${isSigningEnabled() ? 'Ed25519' : 'disabled'}\n`);
    if (state.swarmContext.team_name) {
      w(`  Swarm         ${state.swarmContext.team_name} (${state.swarmContext.agent_type})\n`);
    }
    w(`\n`);
    w(`  POST /hook         Hook receiver\n`);
    w(`  GET  /health       Health + signer info\n`);
    w(`  GET  /receipts     Signed receipts\n`);
    w(`  GET  /suggestions  Cedar policy suggestions\n`);
    w(`\n`);
    w(`  deny is authoritative — cannot be overridden.\n`);
    w(`\n`);
    // Dashboard hint — only show if not already connected
    const hasSlug = process.env.SCOPEBLIND_SLUG || existsSync(join(process.cwd(), '.scopeblind'));
    if (!hasSlug) {
      w(`  Dashboard  npx protect-mcp connect\n`);
      w(`             Free up to 20,000 receipts/month\n`);
      w(`\n`);
    }
  });

  // Graceful shutdown
  const shutdown = () => {
    process.stderr.write('\n[PROTECT_MCP] Shutting down hook server...\n');
    const suggestions = [...state.permissionSuggestions.entries()];
    if (suggestions.length > 0) {
      process.stderr.write(`[PROTECT_MCP] ${suggestions.length} policy suggestion(s) accumulated:\n`);
      for (const [tool, suggestion] of suggestions) {
        process.stderr.write(`  ${suggestion}\n`);
      }
    }
    server.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return server;
}

// ============================================================
// Helpers
// ============================================================

function findCedarDir(): string | undefined {
  for (const candidate of ['cedar', 'policies', '.']) {
    try {
      if (existsSync(candidate)) {
        const files = readdirSync(candidate, { encoding: 'utf-8' });
        if (files.some(f => f.endsWith('.cedar'))) {
          return candidate;
        }
      }
    } catch { /* skip */ }
  }
  return undefined;
}

// ============================================================
// Snake-case → camelCase normalizer
// ============================================================
// Claude Code sends hook inputs in snake_case (hook_event_name, tool_name, etc.)
// but our HookInput interface uses camelCase. This normalizer converts at the
// HTTP boundary so the rest of the codebase stays clean.
//
// The response (output) is already camelCase — Claude Code expects camelCase
// in hookSpecificOutput (hookEventName, permissionDecision, etc.)

const SNAKE_TO_CAMEL_MAP: Record<string, string> = {
  hook_event_name: 'hookEventName',
  session_id: 'sessionId',
  transcript_path: 'transcriptPath',
  permission_mode: 'permissionMode',
  agent_id: 'agentId',
  agent_type: 'agentType',
  tool_name: 'toolName',
  tool_input: 'toolInput',
  tool_use_id: 'toolUseId',
  tool_response: 'toolResult',  // Claude Code sends tool_response, we read toolResult
  stop_hook_active: 'stopHookActive',
  agent_transcript_path: 'agentTranscriptPath',
  last_assistant_message: 'lastAssistantMessage',
  teammate_name: 'teammateName',
  team_name: 'teamName',
  task_id: 'taskId',
  task_subject: 'taskSubject',
  task_description: 'taskDescription',
  file_path: 'filePath',
  config_path: 'configPath',
  old_cwd: 'oldCwd',
  new_cwd: 'newCwd',
  notification_type: 'notificationType',
  is_interrupt: 'isInterrupt',
  error_details: 'errorDetails',
  compact_summary: 'compactSummary',
  custom_instructions: 'customInstructions',
  worktree_path: 'worktreePath',
  trigger_file_path: 'triggerFilePath',
  parent_file_path: 'parentFilePath',
  memory_type: 'memoryType',
  load_reason: 'loadReason',
  mcp_server_name: 'mcpServerName',
  elicitation_id: 'elicitationId',
  requested_schema: 'requestedSchema',
  permission_suggestions: 'permissionSuggestions',
};

/**
 * Normalize a Claude Code hook input from snake_case to camelCase.
 * Handles nested objects but not arrays-of-objects (tool_input is passed as-is).
 * Unknown keys are passed through unchanged (future-proof).
 */
function normalizeHookInput(raw: Record<string, unknown>): HookInput {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(raw)) {
    const camelKey = SNAKE_TO_CAMEL_MAP[key] || key;
    result[camelKey] = value;
  }
  // Also handle the case where ConfigChange uses 'source' for configSource
  if (raw.source !== undefined && raw.hook_event_name === 'ConfigChange' && !raw.config_source) {
    result['configSource'] = raw.source;
  }
  return result as unknown as HookInput;
}
