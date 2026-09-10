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
import { appendFileSync, readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
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
import { loadCedarPolicies, evaluateCedar, isCedarAvailable, runEvaluatorSelfTest, type CedarPolicySet } from './cedar-evaluator.js';
import { initSigning, signDecision, isSigningEnabled, getSignerInfo } from './signing.js';
import { receiptHash } from './acta-envelope.js';
import { loadPolicy, getToolPolicy, parseRateLimit, checkRateLimit } from './policy.js';
import { ReceiptBuffer } from './http-server.js';
import { getScopeBlindBridge } from './scopeblind-bridge.js';
import { buildActionReadback } from './action-readback.js';
import { buildEnrichment, type ReceiptEnrichment } from './receipt-enrichment.js';
import {
  loadGateSigner,
  loadMandateRegistry,
  publicMandateStatus,
  refreshManagedMandate,
  approvePolicyProposalWithWebAuthn,
  createWebAuthnPolicyChallenge,
  type GateSigner,
  type MandateRegistry,
  type MandateProposal,
} from './mandate-lifecycle.js';
import type { ApprovalAssertion } from './webauthn-approval.js';

// ============================================================
// Constants
// ============================================================

const DEFAULT_PORT = 9377;
const LOG_FILE = '.protect-mcp-log.jsonl';
const RECEIPTS_FILE = '.protect-mcp-receipts.jsonl';
const PAYLOAD_HASH_THRESHOLD = 1024; // bytes

interface ManagedMandateState {
  signer: GateSigner;
  registry: MandateRegistry;
  rpId: string;
  expectedOrigin: string;
  /**
   * Session-scoped anti-rollback: the longest signed transition history this
   * running gate has seen, and the receipt hash at that point. A registry file
   * that is truncated or forked back to an earlier signed-consistent state
   * (which would otherwise re-verify) is caught while the gate is live. Durable,
   * across-restart anti-rollback needs an external append-only anchor and is
   * documented as such, not silently claimed.
   */
  highWaterSequence: number;
  highWaterHash: string;
  /** Monotonic clock floor: the max time seen, so setting the system clock backward cannot un-expire a grant on a running gate. */
  maxSeenTimeMs: number;
}

// ============================================================
// Hook Server State
// ============================================================

interface HookServerState {
  /** Cedar policy set (if loaded) */
  cedarPolicies: CedarPolicySet | null;
  /** Directory the Cedar policies were loaded from (for teaching denies + hot reload) */
  cedarDir: string | null;
  /** Newest .cedar mtime seen, so an on-disk policy edit hot-reloads the cache */
  cedarMtimeMs: number;
  /** Last time we stat-checked the policy dir, to throttle the FS check off the hot path */
  cedarCheckedMs: number;
  /** JSON policy (if loaded) */
  jsonPolicy: ReturnType<typeof loadPolicy> | null;
  /** Rate limit store */
  rateLimitStore: Map<string, number[]>;
  /** Receipt buffer for /receipts endpoint */
  receiptBuffer: ReceiptBuffer;
  /** In-flight tool calls (PreToolUse → PostToolUse timing) */
  inflightTools: Map<string, { tool: string; startedAt: number; requestId: string; enrichment?: ReceiptEnrichment }>;
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
  /** s5.7 hash of the last line appended to the receipt file (chain link), null until known */
  lastReceiptHash: string | null;
  /** Permission suggestions accumulated during session */
  permissionSuggestions: Map<string, string>;
  /** Config change alerts issued */
  configAlerts: Array<{ timestamp: number; path: string; source: string }>;
  /** A signed policy lifecycle, when this Cedar directory is mandate-managed. */
  managedMandate: ManagedMandateState | null;
}

// ============================================================
// Swarm Detection
// ============================================================

/**
 * Resume the s5.7 receipt chain across restarts: hash the last line of the
 * existing receipt log (whatever its shape: draft-02 envelope, legacy
 * envelope, or tombstone) so the next receipt links to it. Returns null for
 * a missing/empty/unparseable log, which starts a fresh chain.
 */
function resumeReceiptChain(receiptFilePath: string): string | null {
  try {
    if (!existsSync(receiptFilePath)) return null;
    const lines = readFileSync(receiptFilePath, 'utf-8').split('\n').filter((l) => l.trim());
    if (lines.length === 0) return null;
    return receiptHash(JSON.parse(lines[lines.length - 1]));
  } catch {
    return null;
  }
}

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
  const actionReadback = buildActionReadback(toolName, input.toolInput || {});

  // A managed mandate is a security boundary, not a convenience layer. Do not
  // evaluate against stale or hand-edited Cedar bytes: an inconsistent policy
  // registry, gate signer, approval chain, or expired grant denies first.
  const mandate = ensureManagedMandate(state);
  if (!mandate.valid) {
    const hookLatency = Date.now() - hookStart;
    emitDecisionLog(state, {
      tool: toolName,
      decision: 'deny',
      reason_code: mandate.code,
      request_id: requestId,
      hook_event: 'PreToolUse',
      timing: { hook_latency_ms: hookLatency, started_at: hookStart },
      action_readback: actionReadback,
      sandbox_state: detectSandboxState(),
    });
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason:
          `[ScopeBlind] Denied "${toolName}": the managed mandate cannot be verified (${mandate.code}). ` +
          `${mandate.message} Failing closed until the signed policy state is restored.`,
      },
    };
  }

  // Deterministic, minimum-disclosure enrichment (input digest, capability tags,
  // hashed resource). Stored on the in-flight record and folded into the signed
  // decision receipt by emitDecisionLog, so it is part of the tamper-evident record.
  const enrichment = buildEnrichment(toolName, input.toolInput || {});
  const inflightRec = state.inflightTools.get(requestId);
  if (inflightRec) inflightRec.enrichment = enrichment;

  // Build swarm context from hook input (override env detection)
  const swarm: SwarmContext = {
    ...state.swarmContext,
    ...(input.agentId && { agent_id: input.agentId }),
    ...(input.agentName && { agent_name: input.agentName }),
    ...(input.teamName && { team_name: input.teamName }),
    ...(input.agentType && { agent_type: input.agentType as SwarmContext['agent_type'] }),
  };

  // ── Cedar evaluation ──
  maybeReloadCedar(state);
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
        // Also expose the raw tool input under context.input so policies written
        // against the documented nested shape match on the hook path too.
        toolInput: input.toolInput || {},
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
          action_readback: actionReadback,
          deny_iteration: denyCount,
          sandbox_state: detectSandboxState(),
          plan_receipt_id: state.activePlanReceiptId || undefined,
        });

        // A deny that teaches: name the policy file and the one command that
        // fixes it, and distinguish default-deny (no permit matched) from an
        // explicit forbid, so the operator knows where to look.
        const isDefaultDeny = !reason || reason === 'cedar_deny' || /reason":\[\]/.test(reason);
        const policyRef = state.cedarDir ? ` Policy: ${state.cedarDir}.` : '';
        const howTo = isDefaultDeny
          ? ` No permit matched (default-deny, fail-closed).${policyRef} Allow it: npx protect-mcp policy allow ${toolName}`
          : ` Blocked by an explicit forbid rule.${policyRef} Review: npx protect-mcp policy show`;

        if (denyCount === 1) {
          process.stderr.write(
            `[PROTECT_MCP] Denied "${toolName}" (${isDefaultDeny ? 'default-deny' : 'forbid'}).\n` +
            `  Allow with: npx protect-mcp policy allow ${toolName}\n`,
          );
        }

        return {
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason:
              `[ScopeBlind] Denied "${toolName}".${howTo}` +
              (denyCount > 1 ? ` (attempt ${denyCount})` : ''),
          },
        };
      }
    } catch (err) {
      // evaluateCedar maps normal eval failures (WASM unavailable, unparseable
      // result, eval error) to a fail-closed DENY by default, so those already
      // return above. This catch only fires on an UNEXPECTED throw, and while a
      // policy is configured that must NOT silently allow a tool call. Fail
      // closed, consistent with the policy-deny path above and the "deny on any
      // error" guarantee.
      const hookLatency = Date.now() - hookStart;
      process.stderr.write(
        `[PROTECT_MCP] Cedar eval threw for "${toolName}", failing closed: ` +
        `${err instanceof Error ? err.message : err}\n`,
      );
      emitDecisionLog(state, {
        tool: toolName,
        decision: 'deny',
        reason_code: 'cedar_eval_error',
        request_id: requestId,
        hook_event: 'PreToolUse',
        swarm: swarm.team_name ? swarm : undefined,
        timing: { hook_latency_ms: hookLatency, started_at: hookStart },
        payload_digest: payloadDigest,
        action_readback: actionReadback,
        sandbox_state: detectSandboxState(),
      });
      return {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason:
            `[ScopeBlind] Denied: the policy engine errored while evaluating "${toolName}", ` +
            `so the gate fails closed rather than allow an unverified call. Check the policy set and server logs.`,
        },
      };
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
        action_readback: actionReadback,
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
        payload_digest: payloadDigest,
        action_readback: actionReadback,
        sandbox_state: detectSandboxState(),
      });

      return {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask',
          permissionDecisionReason:
            `[ScopeBlind] Approval required for exactly this action: ${actionReadback.summary}. ` +
            `Payload hash: ${actionReadback.payload_hash.slice(0, 16)}… Policy: ${state.policyDigest}`,
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

  const emit = emitDecisionLog(state, {
    tool: toolName,
    decision: 'allow',
    reason_code: state.cedarPolicies ? 'cedar_allow' : (state.jsonPolicy ? 'policy_allow' : 'observe_mode'),
    request_id: requestId,
    hook_event: 'PreToolUse',
    swarm: swarm.team_name ? swarm : undefined,
    timing: { hook_latency_ms: hookLatency, started_at: hookStart },
    payload_digest: payloadDigest,
    action_readback: actionReadback,
    sandbox_state: detectSandboxState(),
    plan_receipt_id: state.activePlanReceiptId || undefined,
  });

  // Fail closed: in enforce mode, a configured signer that could not produce a
  // receipt means we cannot prove this action. Deny rather than allow an
  // unprovable tool call. (Shadow mode observes; the unsigned-by-design free
  // tier sets no signer and never reaches here.)
  if (state.enforce && emit.signingFailed) {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason:
          `[ScopeBlind] "${toolName}" was blocked because its receipt could not be signed. ` +
          `Failing closed: a governed action that cannot be proven is not allowed.`,
      },
    };
  }

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

function emitDecisionLog(state: HookServerState, entry: Partial<DecisionLog>): { signingFailed: boolean } {
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
    ...(state.managedMandate ? {
      mandate_registry: {
        registry_id: state.managedMandate.registry.registry_id,
        active_policy_digest: state.managedMandate.registry.active.policy_digest,
        active_transition_hash: receiptHash(state.managedMandate.registry.history.at(-1)?.transition_receipt || {}),
        ...(state.managedMandate.registry.active.expires_at ? { expires_at: state.managedMandate.registry.active.expires_at } : {}),
      },
    } : {}),
  };

  // Fold in the per-call enrichment (set at PreToolUse) BEFORE signing, so the
  // input digest + capability tags + hashed resource are covered by the signature.
  const enr = state.inflightTools.get(log.request_id)?.enrichment;
  if (enr) log.enrichment = enr;

  process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}\n`);

  try { appendFileSync(state.logFilePath, JSON.stringify(log) + '\n'); } catch { /* best-effort */ }

  if (isSigningEnabled()) {
    const signed = signDecision(log, state.lastReceiptHash || undefined);
    if (signed.signed) {
      try {
        appendFileSync(state.receiptFilePath, signed.signed + '\n');
        // Advance the s5.7 chain only when the line actually landed on disk.
        if (signed.receipt_hash) state.lastReceiptHash = signed.receipt_hash;
      } catch { /* best-effort */ }
      state.receiptBuffer.add(log.request_id, signed.signed);

      // Forward to ScopeBlind tenant dashboard when SCOPEBLIND_TOKEN is set.
      // Best-effort: failures never block local receipt emission.
      try {
        const bridge = getScopeBlindBridge();
        if (bridge.enabled()) {
          // signDecision returns the receipt as a JSON string; parse for upload.
          // Local file is the authoritative copy regardless of forward success.
          const parsed = typeof signed.signed === 'string' ? JSON.parse(signed.signed) : signed.signed;
          bridge.forward(parsed);
        }
      } catch (err) {
        process.stderr.write(`[PROTECT_MCP] ScopeBlind forward error: ${err instanceof Error ? err.message : err}\n`);
      }
    } else if (signed.error) {
      // A signer is configured but signing FAILED. Never emit a silent gap:
      // write an auditable tombstone to the receipt log and a distinct marker,
      // then signal the caller so an allow can fail closed.
      const tombstoneObj = {
        type: 'scopeblind.signing_failure.v1',
        request_id: log.request_id, tool: log.tool, decision: log.decision,
        error: signed.error, at: new Date(log.timestamp).toISOString(),
        ...(state.lastReceiptHash ? { previousReceiptHash: state.lastReceiptHash } : {}),
      };
      const tombstone = JSON.stringify(tombstoneObj);
      try {
        appendFileSync(state.receiptFilePath, tombstone + '\n');
        // Tombstones are chain links too: an unsigned gap must not detach the
        // chain, or omission of the gap becomes undetectable.
        state.lastReceiptHash = receiptHash(tombstoneObj);
      } catch { /* best-effort */ }
      process.stderr.write(`[PROTECT_MCP_SIGNING_FAILURE] ${tombstone}\n`);
      return { signingFailed: true };
    }
  }
  return { signingFailed: false };
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
  /** Directory for local keys, receipts, logs, and connection state. Defaults to cwd. */
  dataDir?: string;
  enforce?: boolean;
  verbose?: boolean;
  /** WebAuthn RP ID for local mandate-controller approvals. Defaults to localhost. */
  mandateRelyingPartyId?: string;
  /** Expected browser origin for mandate-controller approvals. Defaults to local hook origin. */
  mandateApprovalOrigin?: string;
}

export async function startHookServer(options: HookServerOptions = {}): Promise<Server> {
  const port = options.port || DEFAULT_PORT;
  const verbose = options.verbose || false;
  const enforce = options.enforce || false;
  const dataDir = options.dataDir || process.cwd();

  // ── Load policies ──
  let cedarPolicies: CedarPolicySet | null = null;
  let jsonPolicy: ReturnType<typeof loadPolicy> | null = null;
  let policyDigest = 'none';
  let gateKeyPath: string | undefined;
  let managedMandate: ManagedMandateState | null = null;

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
        gateKeyPath = jsonPolicy.signing.key_path;
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
    const keyPath = join(dataDir, 'keys', 'gateway.json');
    if (existsSync(keyPath)) {
      gateKeyPath = keyPath;
      const warnings = await initSigning({ key_path: keyPath, issuer: 'protect-mcp', enabled: true });
      for (const w of warnings) {
        process.stderr.write(`[PROTECT_MCP] Warning: ${w}\n`);
      }
    }
  }

  // ── Managed mandate bootstrap ──
  // The registry is intentionally discovered from the Cedar directory. An
  // operator cannot accidentally start an enforcing managed gate in a looser
  // direct-edit mode: invalid lifecycle state is a startup refusal in enforce
  // mode and a visible warning in shadow mode.
  if (cedarDir) {
    const existingRegistry = loadMandateRegistry(cedarDir);
    if (existingRegistry) {
      if (!gateKeyPath) {
        const message = 'managed mandate found but no local gate signing key is configured';
        if (enforce) throw new Error(`enforce mode refused to start: ${message}`);
        process.stderr.write(`[PROTECT_MCP] Warning: ${message}; governed enforcement remains unavailable.\n`);
      } else {
        try {
          const gateSigner = loadGateSigner(gateKeyPath);
          const receiptSigner = getSignerInfo();
          if (!isSigningEnabled() || !receiptSigner || receiptSigner.kid !== gateSigner.kid || receiptSigner.publicKey !== gateSigner.publicKey) {
            throw new Error('managed mandate requires decision receipt signing with the exact gate key pinned in the registry');
          }
          const check = refreshManagedMandate({ cedarDir, signer: gateSigner });
          if (!check.valid || !check.registry) {
            const message = `${check.code || 'mandate_registry_invalid'}: ${check.message || 'registry verification failed'}`;
            if (enforce) throw new Error(`enforce mode refused to start: ${message}`);
            process.stderr.write(`[PROTECT_MCP] Warning: managed mandate invalid (${message}).\n`);
          } else {
            const reloaded = loadCedarPolicies(cedarDir);
            if (reloaded.digest !== check.registry.active.policy_digest) {
              throw new Error('loaded Cedar bytes do not match the signed active mandate head');
            }
            cedarPolicies = reloaded;
            policyDigest = reloaded.digest;
            managedMandate = {
              signer: gateSigner,
              registry: check.registry,
              rpId: options.mandateRelyingPartyId || 'localhost',
              expectedOrigin: options.mandateApprovalOrigin || `http://localhost:${port}`,
              highWaterSequence: check.registry.history.length,
              highWaterHash: check.registry.history.length ? receiptHash(check.registry.history[check.registry.history.length - 1].transition_receipt) : '',
              maxSeenTimeMs: Math.max(Date.now(), check.registry.history.reduce((m, t) => Math.max(m, Date.parse(t.occurred_at) || 0), 0)),
            };
            process.stderr.write(
              `[PROTECT_MCP] Managed mandate loaded: ${check.registry.registry_id} ` +
              `(head: ${check.registry.active.policy_digest}${check.registry.active.expires_at ? `; expires ${check.registry.active.expires_at}` : ''}).\n`,
            );
          }
        } catch (error) {
          if (enforce) throw error;
          process.stderr.write(`[PROTECT_MCP] Warning: managed mandate unavailable: ${error instanceof Error ? error.message : error}\n`);
        }
      }
    }
  }

  // ── Enforce-mode startup self-test (D5) ──
  // A gate that cannot prove it denies must not arm. Before enforce mode
  // accepts a single hook call, run the live evaluator against known
  // deny/allow vectors (the fail-closed invariant, a real forbid, and the
  // in-on-String regression from the 0.6.x advisory), and prove a denial
  // receipt can actually be produced when a signer is configured. Failure
  // refuses startup; shadow mode is never blocked by the self-test.
  if (enforce) {
    const selfTest = await runEvaluatorSelfTest();
    for (const c of selfTest.cases) {
      if (!c.pass) {
        process.stderr.write(
          `[PROTECT_MCP] SELF-TEST FAIL: ${c.name} (expected ${c.expected}, got ${c.actual})\n`,
        );
      }
    }
    if (!selfTest.passed) {
      throw new Error(
        'enforce mode refused to start: the restraint self-test failed. ' +
        'A gate that cannot prove it denies must not arm.',
      );
    }
    const receiptProbe = signDecision({
      v: 2,
      tool: '__protect_mcp_startup_selftest__',
      decision: 'deny',
      reason_code: 'startup_selftest',
      policy_digest: policyDigest,
      request_id: `selftest-${Date.now()}`,
      mode: 'enforce',
      timestamp: Date.now(),
    } as DecisionLog);
    if (receiptProbe.error) {
      throw new Error(
        `enforce mode refused to start: signing is configured but a denial receipt could not be produced (${receiptProbe.error}). ` +
        'An enforcing gate that cannot evidence a denial must not arm.',
      );
    }
    process.stderr.write(
      `[PROTECT_MCP] Restraint self-test passed (${selfTest.cases.length} vectors` +
      `${selfTest.wasmAvailable ? '' : '; Cedar WASM absent, fail-closed invariant verified'})` +
      `${receiptProbe.ok ? '; denial receipt signing verified' : ''}. Arming enforce mode.\n`,
    );
  }

  // ── Build state ──
  const state: HookServerState = {
    cedarPolicies,
    cedarDir: cedarDir || null,
    cedarMtimeMs: cedarDir ? newestCedarMtime(cedarDir) : 0,
    cedarCheckedMs: 0,
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
    logFilePath: join(dataDir, LOG_FILE),
    receiptFilePath: join(dataDir, RECEIPTS_FILE),
    lastReceiptHash: resumeReceiptChain(join(dataDir, RECEIPTS_FILE)),
    permissionSuggestions: new Map(),
    configAlerts: [],
    managedMandate,
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
        version: process.env.PROTECT_MCP_VERSION || 'unknown',
        uptime_ms: Date.now() - state.startTime,
        mode: enforce ? 'enforce' : 'shadow',
        policy_digest: policyDigest,
        policy_engine: cedarPolicies ? 'cedar' : (jsonPolicy ? 'built-in' : 'none'),
        signing: isSigningEnabled(),
        swarm: state.swarmContext,
        signer: signerInfo ? { kid: signerInfo.kid, issuer: signerInfo.issuer } : null,
        cedar_files: cedarPolicies?.fileCount || 0,
        mandate: state.managedMandate ? {
          registry_id: state.managedMandate.registry.registry_id,
          active_policy_digest: state.managedMandate.registry.active.policy_digest,
          ...(state.managedMandate.registry.active.expires_at ? { expires_at: state.managedMandate.registry.active.expires_at } : {}),
          controller_count: state.managedMandate.registry.controllers.length,
        } : null,
      }));
      return;
    }

    // ── Managed-mandate status ──
    if (url.pathname === '/mandate' && req.method === 'GET') {
      const check = ensureManagedMandate(state);
      if (!state.managedMandate) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'no_managed_mandate', hint: 'Run protect-mcp mandate init before requesting lifecycle status.' }));
        return;
      }
      res.writeHead(check.valid ? 200 : 409);
      res.end(JSON.stringify({
        valid: check.valid,
        ...(check.valid ? {} : { error: check.code, message: check.message }),
        mandate: publicMandateStatus(state.managedMandate.registry),
      }));
      return;
    }

    // ── Desktop WebAuthn mandate approval ──
    // This remains local-first: only the controller's browser speaks to the
    // loopback gate, and only the signed policy diff leaves the browser as a
    // WebAuthn assertion. The paired-iPhone transport can surface this same
    // exact protocol later; it does not alter the approval object or receipt.
    const approvalMatch = url.pathname.match(/^\/mandate\/proposals\/([^/]+)\/(approve|webauthn\/challenge)$/);
    if (approvalMatch && req.method === 'GET') {
      const proposalId = decodeURIComponent(approvalMatch[1]);
      const check = ensureManagedMandate(state);
      if (!check.valid || !state.managedMandate) {
        res.writeHead(409);
        res.end(JSON.stringify({ error: check.valid ? 'no_managed_mandate' : check.code, message: check.valid ? 'No managed mandate is active.' : check.message }));
        return;
      }
      const proposal = state.managedMandate.registry.proposals[proposalId];
      if (!proposal) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'unknown_proposal' }));
        return;
      }
      const controllerId = url.searchParams.get('controller_id') || state.managedMandate.registry.controllers.find((item) => item.type === 'webauthn')?.id;
      const controller = state.managedMandate.registry.controllers.find((item) => item.id === controllerId);
      if (!controller || controller.type !== 'webauthn') {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'webauthn_controller_required', hint: 'Register a WebAuthn controller before using browser approval.' }));
        return;
      }
      if (approvalMatch[2] === 'webauthn/challenge') {
        try {
          const challenge = createWebAuthnPolicyChallenge({
            cedarDir: state.cedarDir!, proposalId, controllerId: controller.id,
            rpId: state.managedMandate.rpId,
          });
          state.managedMandate.registry = loadMandateRegistry(state.cedarDir!)!;
          res.writeHead(200);
          res.end(JSON.stringify({
            proposal_id: proposal.proposal_id,
            proposal_digest: proposal.proposal_digest,
            controller: { id: controller.id, label: controller.label },
            publicKey: {
              challenge: challenge.challenge,
              rpId: challenge.rpId,
              timeout: challenge.timeoutSeconds * 1000,
              userVerification: 'required',
              allowCredentials: [{ id: controller.credential_id, type: 'public-key' }],
            },
          }));
        } catch (error) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'challenge_failed', message: error instanceof Error ? error.message : 'Could not create approval challenge.' }));
        }
        return;
      }
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.writeHead(200);
      res.end(renderMandateApprovalPage({ proposal, controller: { id: controller.id, label: controller.label }, port }));
      return;
    }

    const approveMatch = url.pathname.match(/^\/mandate\/proposals\/([^/]+)\/webauthn\/approve$/);
    if (approveMatch && req.method === 'POST') {
      const proposalId = decodeURIComponent(approveMatch[1]);
      if (!state.managedMandate || !state.cedarDir) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'no_managed_mandate' }));
        return;
      }
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body) as { assertion?: ApprovalAssertion };
          if (!parsed.assertion) throw new Error('missing WebAuthn assertion');
          const registry = approvePolicyProposalWithWebAuthn({
            cedarDir: state.cedarDir!, signer: state.managedMandate!.signer,
            proposalId, assertion: parsed.assertion,
            expectedOrigin: state.managedMandate!.expectedOrigin,
          });
          state.managedMandate!.registry = registry;
          const refreshed = ensureManagedMandate(state);
          if (!refreshed.valid) throw new Error(`${refreshed.code}: ${refreshed.message}`);
          res.writeHead(200);
          res.end(JSON.stringify({
            approved: true,
            active_policy_digest: state.managedMandate!.registry.active.policy_digest,
            expires_at: state.managedMandate!.registry.active.expires_at || null,
            mandate: publicMandateStatus(state.managedMandate!.registry),
          }));
        } catch (error) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'approval_rejected', message: error instanceof Error ? error.message : 'Policy approval was rejected.' }));
        }
      });
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
        // Hoisted so the catch can tell an errored TOOL DECISION apart from a
        // malformed request: a decision that throws must fail closed (deny), not
        // return an ambiguous 400 that a PreToolUse hook reads as "no deny".
        let input: HookInput | undefined;
        try {
          const raw = JSON.parse(body) as Record<string, unknown>;

          // Normalize snake_case (from Claude Code) → camelCase (our internal types)
          input = normalizeHookInput(raw);

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
          // Backstop: if we got far enough to know this was a PreToolUse decision,
          // an unexpected throw MUST deny, not fail open. A body we could not even
          // parse into a hook event is a malformed request, not a tool call, so it
          // stays a 400.
          if (input?.hookEventName === 'PreToolUse') {
            res.writeHead(200);
            res.end(JSON.stringify({
              hookSpecificOutput: {
                hookEventName: 'PreToolUse',
                permissionDecision: 'deny',
                permissionDecisionReason:
                  `[ScopeBlind] Denied "${input.toolName || 'unknown'}": the gate hit an unexpected error while deciding, ` +
                  `so it fails closed rather than allow an unverified call. Check the server logs.`,
              },
            }));
            return;
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
    w(process.env.PROTECT_MCP_VERSION ? `  protect-mcp v${process.env.PROTECT_MCP_VERSION}\n` : `  protect-mcp\n`);
    w(`  ScopeBlind · https://scopeblind.com\n`);
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
    w(`  deny is authoritative: it cannot be overridden.\n`);
    w(`\n`);
    w(`  See your record   npx protect-mcp record\n`);
    w(`                    a searchable view of every decision, all on this machine\n`);
    w(`\n`);
    // Dashboard hint — only show if not already connected
    const hasSlug = process.env.SCOPEBLIND_SLUG || existsSync(join(dataDir, '.scopeblind'));
    if (!hasSlug) {
      w(`  Dashboard  npx protect-mcp connect\n`);
      w(`             Sends privacy-safe summaries; raw receipts stay local\n`);
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

/** Newest mtime (ms) across the .cedar files in a dir, for change detection. */
function newestCedarMtime(dir: string): number {
  try {
    let newest = 0;
    for (const f of readdirSync(dir)) {
      if (!f.endsWith('.cedar')) continue;
      const m = statSync(join(dir, f)).mtimeMs;
      if (m > newest) newest = m;
    }
    return newest;
  } catch { return 0; }
}

/**
 * Hot-reload the Cedar policy cache if a .cedar file changed on disk since the
 * last load, so `protect-mcp policy allow/deny` (or a hand edit) takes effect
 * without restarting the gate. Fail-closed: if a reload throws (unparseable
 * policy), the OLD policy stays active rather than opening the gate.
 */
const CEDAR_CHECK_THROTTLE_MS = 2000; // keep policies cached; stat the dir at most this often

/**
 * Refresh the managed policy head before evaluating a tool. This runs before
 * hot reload: a hand edit must produce a denial, never become the new policy
 * merely because its mtime changed. Expiry may atomically restore a signed
 * baseline, after which the Cedar cache is reloaded from that exact head.
 */
function ensureManagedMandate(state: HookServerState): { valid: true } | { valid: false; code: string; message: string } {
  // This runs before every managed decision and MUST NOT throw: an unparseable
  // or unreadable registry (a partial write, disk fault, or an attacker who can
  // corrupt the registry file to invalid JSON) makes refreshManagedMandate /
  // loadMandateRegistry throw, and a throw here escapes the caller's explicit
  // deny and lands in the generic transport catch as a 400 with no
  // permissionDecision — which a PreToolUse hook treats as "no deny" and lets
  // the tool proceed. So we translate ANY exception into a fail-closed deny.
  try {
    if (!state.managedMandate || !state.cedarDir) return { valid: true };
    const mm = state.managedMandate;
    // Monotonic clock floor: a system clock set backward must not revive an
    // expired grant on a running gate.
    const floorMs = Math.max(Date.now(), mm.maxSeenTimeMs);
    const result = refreshManagedMandate({ cedarDir: state.cedarDir, signer: mm.signer, now: new Date(floorMs) });
    if (!result.valid || !result.registry) {
      return {
        valid: false,
        code: result.code || 'mandate_registry_invalid',
        message: result.message || 'The mandate registry could not be verified.',
      };
    }
    // Session anti-rollback: the signed history may only grow and may not have
    // its already-seen prefix rewritten. A truncation or fork back to an earlier
    // (still self-consistent, still gate-signed) state is a rollback attack.
    const history = result.registry.history;
    if (mm.highWaterSequence > 0) {
      if (history.length < mm.highWaterSequence) {
        return { valid: false, code: 'mandate_rollback_detected', message: 'The mandate history is shorter than a state this gate already enforced. The registry was rolled back or truncated.' };
      }
      const atMark = history[mm.highWaterSequence - 1];
      if (!atMark || receiptHash(atMark.transition_receipt) !== mm.highWaterHash) {
        return { valid: false, code: 'mandate_history_forked', message: 'The mandate history diverges from a state this gate already enforced. The registry was forked or rewritten.' };
      }
    }
    mm.highWaterSequence = history.length;
    mm.highWaterHash = history.length ? receiptHash(history[history.length - 1].transition_receipt) : '';
    const latestTransitionMs = history.reduce((m, t) => Math.max(m, Date.parse(t.occurred_at) || 0), 0);
    mm.maxSeenTimeMs = Math.max(mm.maxSeenTimeMs, floorMs, latestTransitionMs);
    state.managedMandate.registry = result.registry;
    if (state.policyDigest !== result.registry.active.policy_digest || result.expired_reverted) {
      const reloaded = loadCedarPolicies(state.cedarDir);
      if (reloaded.digest !== result.registry.active.policy_digest) {
        return { valid: false, code: 'policy_head_mismatch', message: 'Reloaded policy bytes do not match the signed active mandate head.' };
      }
      state.cedarPolicies = reloaded;
      state.policyDigest = reloaded.digest;
      state.cedarMtimeMs = newestCedarMtime(state.cedarDir);
      state.cedarCheckedMs = Date.now();
      if (result.expired_reverted) {
        process.stderr.write(`[PROTECT_MCP] Mandate grant expired; restored signed baseline ${reloaded.digest}.\n`);
      }
    }
    return { valid: true };
  } catch (error) {
    // A managed mandate whose registry cannot even be read/parsed is the most
    // dangerous state, not the safest: deny rather than let the transport turn
    // it into an allow.
    return {
      valid: false,
      code: 'mandate_registry_unreadable',
      message: `The managed mandate registry could not be read or verified (${error instanceof Error ? error.message : 'unknown error'}). Failing closed until the signed policy state is restored.`,
    };
  }
}

function maybeReloadCedar(state: HookServerState): void {
  if (!state.cedarDir) return;
  // Managed directories are refreshed by ensureManagedMandate() and reject
  // direct edits. Hot reload remains only for unmanaged, exploratory policy.
  if (state.managedMandate) return;
  const nowMs = Date.now();
  if (nowMs - state.cedarCheckedMs < CEDAR_CHECK_THROTTLE_MS) return; // off the hot path
  state.cedarCheckedMs = nowMs;
  const m = newestCedarMtime(state.cedarDir);
  if (m <= state.cedarMtimeMs) return;
  try {
    const reloaded = loadCedarPolicies(state.cedarDir);
    state.cedarPolicies = reloaded;
    state.policyDigest = reloaded.digest;
    state.cedarMtimeMs = m;
    process.stderr.write(`[PROTECT_MCP] Cedar policy reloaded (digest: ${reloaded.digest}) after on-disk change.\n`);
  } catch (err) {
    // Keep the prior policy; do not open the gate on a bad edit.
    process.stderr.write(`[PROTECT_MCP] Cedar reload failed, keeping the previous policy: ${err instanceof Error ? err.message : err}\n`);
    state.cedarMtimeMs = m; // avoid retrying the same broken file every request
  }
}

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

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char] || char));
}

/** A deliberately small controller surface: one exact policy change, one passkey. */
function renderMandateApprovalPage(input: { proposal: MandateProposal; controller: { id: string; label: string }; port: number }): string {
  const { proposal, controller } = input;
  const rows = (values: string[], empty: string) => values.length
    ? values.map((value) => `<li><code>${escapeHtml(value)}</code></li>`).join('')
    : `<li class="muted">${escapeHtml(empty)}</li>`;
  const controllerId = JSON.stringify(controller.id);
  const proposalId = JSON.stringify(proposal.proposal_id);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve Policy Change | ScopeBlind</title>
<style>
  :root { color-scheme: light; --ink:#151515; --paper:#f7f5f0; --muted:#6d6b66; --line:#d8d3c9; --warn:#8b2b18; --ok:#22543d; }
  * { box-sizing:border-box; } body { margin:0; background:var(--paper); color:var(--ink); font:15px/1.5 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  main { max-width:860px; margin:0 auto; padding:48px 24px 72px; } .eyebrow { color:var(--muted); font:600 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing:.09em; text-transform:uppercase; }
  h1 { max-width:680px; font:600 clamp(30px,5vw,50px)/1.05 ui-serif, Georgia, serif; letter-spacing:-.035em; margin:12px 0 20px; } h2 { font-size:14px; letter-spacing:.04em; text-transform:uppercase; margin:0 0 12px; }
  .card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:22px; margin:16px 0; } .danger { border-left:4px solid var(--warn); } .meta { display:grid; grid-template-columns:1fr 1fr; gap:12px; font-size:13px; }
  .meta strong { display:block; font-size:11px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); } ul { margin:0; padding-left:20px; } li { margin:7px 0; } code { font:12px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap:anywhere; } .muted { color:var(--muted); }
  button { border:0; border-radius:8px; padding:13px 18px; color:white; background:#151515; cursor:pointer; font:600 15px/1 ui-sans-serif, sans-serif; } button:disabled { cursor:wait; opacity:.6; } #result { min-height:24px; margin:14px 0 0; font-weight:600; } .success { color:var(--ok); } .error { color:var(--warn); }
</style></head><body><main>
  <div class="eyebrow">ScopeBlind Legate · controller approval</div>
  <h1>You are approving exactly this policy change.</h1>
  <p class="muted">This is a time-limited change to a local enforcement gate. Your passkey approves this exact proposal digest, not a general permission for the agent to edit its mandate.</p>
  <section class="card danger"><h2>Why it was proposed</h2><p>${escapeHtml(proposal.reason)}</p><div class="meta"><div><strong>Blocked action</strong>${escapeHtml(proposal.denial_origin.tool)}</div><div><strong>Denied request</strong><code>${escapeHtml(proposal.denial_origin.request_id)}</code></div><div><strong>Current policy</strong><code>${escapeHtml(proposal.base_policy_digest)}</code></div><div><strong>Expires automatically</strong>${escapeHtml(proposal.expires_at)}</div></div></section>
  <section class="card"><h2>Plain-English diff</h2><ul>${rows(proposal.diff.plain_english, 'No interpretable policy change.')}</ul></section>
  <section class="card"><h2>Executable statements added</h2><ul>${rows(proposal.diff.added_statements, 'None.')}</ul></section>
  <section class="card"><h2>Executable statements removed</h2><ul>${rows(proposal.diff.removed_statements, 'None.')}</ul></section>
  <section class="card"><h2>Controller</h2><p><strong>${escapeHtml(controller.label)}</strong><br><span class="muted">A user-verified passkey is required. This local page sends neither a portfolio nor agent prompt to ScopeBlind.</span></p><button id="approve">Approve this exact change</button><div id="result" role="status"></div></section>
<script>
const proposalId = ${proposalId}; const controllerId = ${controllerId};
const result = document.getElementById('result'); const button = document.getElementById('approve');
const toBytes = (s) => { const b = atob(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4 - s.length % 4) % 4)); return Uint8Array.from(b, c => c.charCodeAt(0)); };
const fromBytes = (buffer) => { const b = new Uint8Array(buffer); let out=''; for (const x of b) out += String.fromCharCode(x); return btoa(out).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); };
button.addEventListener('click', async () => { try {
  button.disabled = true; result.className = ''; result.textContent = 'Requesting a passkey for this exact policy diff...';
  const challengeResponse = await fetch('/mandate/proposals/' + encodeURIComponent(proposalId) + '/webauthn/challenge?controller_id=' + encodeURIComponent(controllerId));
  const challenge = await challengeResponse.json(); if (!challengeResponse.ok) throw new Error(challenge.message || challenge.error);
  const p = challenge.publicKey; p.challenge = toBytes(p.challenge); p.allowCredentials = p.allowCredentials.map(c => ({...c, id: toBytes(c.id)}));
  const credential = await navigator.credentials.get({ publicKey:p }); if (!credential) throw new Error('No passkey assertion was returned.');
  const response = credential.response;
  const assertion = { credentialId: fromBytes(credential.rawId), authenticatorData: fromBytes(response.authenticatorData), clientDataJSON: fromBytes(response.clientDataJSON), signature: fromBytes(response.signature), ...(response.userHandle ? { userHandle: fromBytes(response.userHandle) } : {}) };
  const approved = await fetch('/mandate/proposals/' + encodeURIComponent(proposalId) + '/webauthn/approve', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({assertion}) });
  const body = await approved.json(); if (!approved.ok) throw new Error(body.message || body.error);
  result.className = 'success'; result.textContent = 'Approved. The signed policy head is now active' + (body.expires_at ? ' until ' + body.expires_at : '') + '.'; button.remove();
} catch (error) { result.className = 'error'; result.textContent = 'Not approved: ' + (error && error.message ? error.message : String(error)); button.disabled = false; } });
</script></main></body></html>`;
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
