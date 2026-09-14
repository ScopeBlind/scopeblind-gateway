import {
  buildEnrichment
} from "./chunk-KRKZ2YX7.mjs";
import {
  inspectEgress,
  toEgressSummary
} from "./chunk-UJMFRQOL.mjs";
import {
  approvePolicyProposalWithWebAuthn,
  createWebAuthnPolicyChallenge,
  loadGateSigner,
  loadMandateRegistry,
  publicMandateStatus,
  refreshManagedMandate
} from "./chunk-XO3CXSSD.mjs";
import {
  ReceiptBuffer,
  RecordReporter,
  buildActionReadback,
  checkAmount,
  heldIdFor,
  loadStandardFile,
  personRequired,
  readAmount
} from "./chunk-MZOD6A6U.mjs";
import {
  checkRateLimit,
  getToolPolicy,
  loadPolicy,
  parseRateLimit
} from "./chunk-AROKUUGG.mjs";
import {
  getSignerInfo,
  initSigning,
  isSigningEnabled,
  signDecision,
  signGenericArtifact
} from "./chunk-WG5V64D7.mjs";
import {
  evaluateCedar,
  isCedarAvailable,
  loadCedarPolicies,
  runEvaluatorSelfTest
} from "./chunk-PF7HOTBP.mjs";
import {
  receiptHash
} from "./chunk-EIRUB2BZ.mjs";

// src/hook-server.ts
import { createServer } from "http";
import { createHash as createHash2, randomUUID, randomBytes as randomBytes2 } from "crypto";
import { appendFileSync, readFileSync as readFileSync2, existsSync, readdirSync, statSync } from "fs";
import { join as join2 } from "path";

// src/scopeblind-bridge.ts
import { createHash, randomBytes } from "crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
var DEFAULT_BASE = "https://scopeblind.com";
var FLUSH_INTERVAL_MS = 5e3;
var BATCH_MAX = 128;
var BRASS_REFRESH_MARGIN_MS = 5 * 60 * 1e3;
var ScopeBlindBridge = class {
  env;
  token;
  base;
  tenantOverride;
  configuredPseudonymKey;
  cachedProof = null;
  /** Raw receipts stay only in this process until minimized at flush time. */
  queue = [];
  flushTimer = null;
  stats;
  shuttingDown = false;
  constructor(env = process.env) {
    this.env = env;
    this.token = env.SCOPEBLIND_TOKEN || null;
    this.base = (env.SCOPEBLIND_BASE || DEFAULT_BASE).replace(/\/$/, "");
    this.tenantOverride = env.SCOPEBLIND_TENANT || null;
    this.configuredPseudonymKey = env.SCOPEBLIND_EGRESS_HMAC_KEY ? parseConfiguredPseudonymKey(env.SCOPEBLIND_EGRESS_HMAC_KEY) : null;
    this.stats = {
      enabled: Boolean(this.token),
      tenant_slug: this.tenantOverride,
      forwarded_total: 0,
      rejected_total: 0,
      last_flush_at: null,
      last_error: null
    };
    if (this.enabled()) {
      this.flushTimer = setInterval(() => {
        void this.flush();
      }, FLUSH_INTERVAL_MS);
      if (typeof this.flushTimer === "object" && this.flushTimer && "unref" in this.flushTimer) {
        this.flushTimer.unref?.();
      }
      process.on("beforeExit", () => {
        void this.shutdown();
      });
    }
  }
  enabled() {
    return Boolean(this.token);
  }
  /** Push a receipt into the local-only queue. Non-blocking. */
  forward(signedReceipt) {
    if (!this.enabled() || this.shuttingDown) return;
    this.queue.push(signedReceipt);
    if (this.queue.length >= BATCH_MAX) void this.flush();
  }
  /** Flush the queue. Safe to call concurrently. */
  async flush() {
    if (!this.enabled() || this.queue.length === 0) return;
    const localReceipts = this.queue.splice(0, BATCH_MAX);
    try {
      const proof = await this.ensureBrassProof();
      if (!proof) {
        this.queue.unshift(...localReceipts);
        return;
      }
      const slug = this.tenantOverride || proof?.tenant_id;
      if (!slug) {
        this.queue.unshift(...localReceipts);
        return;
      }
      this.stats.tenant_slug = slug;
      let opts;
      try {
        opts = this.summaryOptions(slug);
      } catch (err) {
        this.stats.last_error = `local egress HMAC key: ${String(err?.message || err)}`;
        this.queue.unshift(...localReceipts);
        return;
      }
      const summaries = [];
      for (const receipt of localReceipts) {
        const summary = toEgressSummary(receipt, opts);
        const guard = summary ? inspectEgress(summary) : { safe: false, violations: [{ path: "$", reason: "not a recognized receipt or local HMAC key" }] };
        if (!summary || !guard.safe) {
          this.stats.blocked_by_egress_guard = (this.stats.blocked_by_egress_guard || 0) + 1;
          continue;
        }
        const signed = signGenericArtifact("scopeblind.egress_summary.v1", summary);
        if (!signed.ok || !signed.signed) {
          this.stats.blocked_by_egress_guard = (this.stats.blocked_by_egress_guard || 0) + 1;
          process.stderr.write(`[PROTECT_MCP] egress summary dropped: a locally signed summary is required (${signed.error || signed.warning || "signer unavailable"})
`);
          continue;
        }
        try {
          const envelope = JSON.parse(signed.signed);
          const signedGuard = inspectEgress(envelope?.payload, { signed: true });
          if (!signedGuard.safe || envelope?.signature?.alg !== "EdDSA") {
            throw new Error(signedGuard.violations.slice(0, 2).map((v) => v.path).join(", "));
          }
          summaries.push(envelope);
        } catch (err) {
          this.stats.blocked_by_egress_guard = (this.stats.blocked_by_egress_guard || 0) + 1;
          process.stderr.write(`[PROTECT_MCP] egress summary dropped after signing: ${String(err?.message || err)}
`);
        }
      }
      if (summaries.length === 0) return;
      const res = await fetch(`${this.base}/fn/console/${slug}/summaries`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.token}`,
          "user-agent": "protect-mcp/scopeblind-bridge"
        },
        body: JSON.stringify({ auth_proof: proof, summaries })
      });
      if (!res.ok) {
        const errBody = await res.text().catch(() => "");
        this.stats.last_error = `HTTP ${res.status} ${errBody.slice(0, 160)}`;
        this.stats.rejected_total += summaries.length;
        if (res.status >= 500 && res.status !== 503) {
          this.queue.unshift(...localReceipts);
        }
        return;
      }
      const body = await res.json().catch(() => ({}));
      this.stats.forwarded_total += body?.accepted ?? summaries.length;
      this.stats.rejected_total += body?.rejected ?? 0;
      this.stats.last_flush_at = (/* @__PURE__ */ new Date()).toISOString();
      this.stats.last_error = null;
    } catch (err) {
      this.stats.last_error = String(err?.message || err);
      this.queue.unshift(...localReceipts);
    }
  }
  summaryOptions(slug) {
    const pseudonymKey = this.configuredPseudonymKey || loadOrCreatePseudonymKey(this.env, this.base, slug);
    return { pseudonymKey, tenantScope: `${this.base}\0${slug}` };
  }
  /** Exchange SCOPEBLIND_TOKEN for a BRASS-v2 proof; refresh near expiry. */
  async ensureBrassProof() {
    if (!this.token) return null;
    const now = Date.now();
    if (this.cachedProof && Date.parse(this.cachedProof.expires_at) - now > BRASS_REFRESH_MARGIN_MS) {
      return this.cachedProof;
    }
    try {
      const res = await fetch(`${this.base}/fn/brass/issue`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "user-agent": "protect-mcp/scopeblind-bridge"
        },
        body: JSON.stringify({
          token: this.token,
          scope: "scopeblind-summary-emit",
          ttl_seconds: 3600
        })
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        this.stats.last_error = `brass-issue: HTTP ${res.status} ${text.slice(0, 160)}`;
        return null;
      }
      const body = await res.json();
      if (!body?.auth_proof) {
        this.stats.last_error = "brass-issue: missing auth_proof in response";
        return null;
      }
      this.cachedProof = body.auth_proof;
      return this.cachedProof;
    } catch (err) {
      this.stats.last_error = `brass-issue: ${err?.message || err}`;
      return null;
    }
  }
  /**
   * Return a snapshot of bridge stats. Useful for `protect-mcp scopeblind status`.
   */
  getStats() {
    return {
      ...this.stats,
      queued: this.queue.length,
      brass_proof_expires_at: this.cachedProof?.expires_at || null
    };
  }
  /** Flush remaining receipts and stop the interval. Called on process exit. */
  async shutdown() {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    if (this.flushTimer) clearInterval(this.flushTimer);
    if (this.queue.length > 0) await this.flush();
  }
};
function parseConfiguredPseudonymKey(value) {
  const key = Buffer.from(value, "base64url");
  if (key.length !== 32) throw new Error("SCOPEBLIND_EGRESS_HMAC_KEY must be a base64url-encoded 32-byte key");
  return key;
}
function loadOrCreatePseudonymKey(env, base, slug) {
  const dir = env.SCOPEBLIND_EGRESS_KEY_DIR || join(homedir(), ".protect-mcp", "egress-keys");
  const scopeDigest = createHash("sha256").update(`${base}\0${slug}`).digest("hex");
  const path = join(dir, `${scopeDigest}.key`);
  mkdirSync(dir, { recursive: true, mode: 448 });
  chmodSync(dir, 448);
  try {
    const existing = readFileSync(path);
    if (existing.length !== 32) throw new Error(`local egress key has invalid length: ${path}`);
    chmodSync(path, 384);
    return existing;
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
  }
  const fresh = randomBytes(32);
  try {
    writeFileSync(path, fresh, { mode: 384, flag: "wx" });
    return fresh;
  } catch (err) {
    if (err?.code !== "EEXIST") throw err;
    const existing = readFileSync(path);
    if (existing.length !== 32) throw new Error(`local egress key has invalid length: ${path}`);
    chmodSync(path, 384);
    return existing;
  }
}
var singleton = null;
function getScopeBlindBridge() {
  if (!singleton) singleton = new ScopeBlindBridge();
  return singleton;
}
function forwardReceipt(signedReceipt) {
  getScopeBlindBridge().forward(signedReceipt);
}

// src/hook-server.ts
var DEFAULT_PORT = 9377;
var LOG_FILE = ".protect-mcp-log.jsonl";
var RECEIPTS_FILE = ".protect-mcp-receipts.jsonl";
var PAYLOAD_HASH_THRESHOLD = 1024;
function resumeReceiptChain(receiptFilePath) {
  try {
    if (!existsSync(receiptFilePath)) return null;
    const lines = readFileSync2(receiptFilePath, "utf-8").split("\n").filter((l) => l.trim());
    if (lines.length === 0) return null;
    return receiptHash(JSON.parse(lines[lines.length - 1]));
  } catch {
    return null;
  }
}
function detectSwarmContext() {
  const teamName = process.env.CLAUDE_CODE_TEAM_NAME;
  const agentId = process.env.CLAUDE_CODE_AGENT_ID;
  const agentName = process.env.CLAUDE_CODE_AGENT_NAME;
  if (!teamName && !agentId) {
    return { agent_type: "standalone" };
  }
  const isLeader = !agentId || agentId === "team-lead";
  return {
    team_name: teamName,
    agent_id: agentId,
    agent_name: agentName,
    is_leader: isLeader,
    agent_type: isLeader ? "coordinator" : "worker"
  };
}
function computePayloadDigest(input) {
  const content = typeof input === "string" ? input : JSON.stringify(input || {});
  const size = Buffer.byteLength(content, "utf-8");
  if (size <= PAYLOAD_HASH_THRESHOLD) {
    return void 0;
  }
  return {
    input_hash: createHash2("sha256").update(content).digest("hex"),
    input_size: size,
    truncated: true,
    preview: content.slice(0, 256)
  };
}
function computeOutputDigest(output) {
  const content = typeof output === "string" ? output : JSON.stringify(output || {});
  const size = Buffer.byteLength(content, "utf-8");
  if (size <= PAYLOAD_HASH_THRESHOLD) {
    return void 0;
  }
  return {
    output_hash: createHash2("sha256").update(content).digest("hex"),
    output_size: size
  };
}
function detectSandboxState() {
  if (process.env.SANDBOX_ENABLED === "1" || process.env.CLAUDE_CODE_SANDBOX === "1") {
    return "enabled";
  }
  if (process.platform === "darwin" && process.env.APP_SANDBOX_CONTAINER_ID) {
    return "enabled";
  }
  if (process.platform === "linux") {
    try {
      const procStatus = readFileSync2("/proc/self/status", "utf-8");
      if (procStatus.includes("Seccomp:	2")) return "enabled";
    } catch {
    }
  }
  return "unavailable";
}
async function handlePreToolUse(input, state) {
  const hookStart = Date.now();
  const toolName = input.toolName || "unknown";
  const requestId = input.toolUseId || randomUUID().slice(0, 12);
  state.inflightTools.set(requestId, {
    tool: toolName,
    startedAt: hookStart,
    requestId
  });
  const payloadDigest = computePayloadDigest(input.toolInput);
  const actionReadback = buildActionReadback(toolName, input.toolInput || {});
  const mandate = ensureManagedMandate(state);
  if (!mandate.valid) {
    const hookLatency2 = Date.now() - hookStart;
    emitDecisionLog(state, {
      tool: toolName,
      decision: "deny",
      reason_code: mandate.code,
      request_id: requestId,
      hook_event: "PreToolUse",
      timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
      action_readback: actionReadback,
      sandbox_state: detectSandboxState()
    });
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `[ScopeBlind] Denied "${toolName}": the managed mandate cannot be verified (${mandate.code}). ${mandate.message} Failing closed until the signed policy state is restored.`
      }
    };
  }
  const enrichment = buildEnrichment(toolName, input.toolInput || {});
  const inflightRec = state.inflightTools.get(requestId);
  if (inflightRec) inflightRec.enrichment = enrichment;
  const swarm = {
    ...state.swarmContext,
    ...input.agentId && { agent_id: input.agentId },
    ...input.agentName && { agent_name: input.agentName },
    ...input.teamName && { team_name: input.teamName },
    ...input.agentType && { agent_type: input.agentType }
  };
  if (state.standard) {
    const std = state.standard;
    const common = () => ({ request_id: requestId, hook_event: "PreToolUse", swarm: swarm.team_name ? swarm : void 0, timing: { hook_latency_ms: Date.now() - hookStart, started_at: hookStart }, payload_digest: payloadDigest, action_readback: actionReadback, sandbox_state: detectSandboxState() });
    const refuse = (reason_code, why) => {
      emitDecisionLog(state, { tool: toolName, decision: "deny", reason_code, ...common() });
      if (!state.enforce) return null;
      return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `[ScopeBlind] ${why}` } };
    };
    if (std.tools && !std.tools.includes(toolName)) {
      const r = refuse("standard_tool_not_allowed", `"${toolName}" is not among the tools the standard permits.`);
      if (r) return r;
    } else {
      const amount = checkAmount(std, input.toolInput);
      if (!amount.ok) {
        const r = refuse(amount.reason, `"${toolName}" refused by the standard: ${amount.detail}.`);
        if (r) return r;
      } else {
        const person = personRequired(std, input.toolInput);
        if (person.required) {
          const hid = heldIdFor(state.reporter?.sid ?? std.request_id, toolName, actionReadback.payload_hash);
          const page = state.reporter ? `${new URL(state.reporter.url).origin}/standard?s=${state.reporter.sid}#held-${hid}` : "";
          const verdict = state.reporter ? await state.reporter.decision(hid) : null;
          if (verdict === "unreachable") {
            const r = refuse("standard_page_unreachable", `"${toolName}" needs a named person's approval and the standard's page could not be reached; retry the same call later.`);
            if (r) return r;
          } else if (verdict) {
            state.approvalsToRecord.set(requestId, { hid, approver_key_id: verdict.approver_key_id, digest: verdict.digest, page });
            if (verdict.decision === "deny") {
              const r = refuse("person_denied", `"${toolName}" was denied by ${verdict.approver_key_id} on the standard's page${verdict.note ? `: ${verdict.note}` : ""}.`);
              if (r) return r;
            }
          } else {
            const amt = readAmount(input.toolInput);
            if (state.enforce && state.reporter) {
              await state.reporter.hold({ hid, request_id: requestId, tool: toolName, readback: { summary: actionReadback.summary, payload_hash: actionReadback.payload_hash, amount: amt ? amt.minor / 100 : null, currency: amt?.currency || null }, reason: person.detail });
            }
            emitDecisionLog(state, { tool: toolName, decision: "require_approval", reason_code: "standard_requires_person", ...common() });
            if (state.enforce) {
              return {
                hookSpecificOutput: {
                  hookEventName: "PreToolUse",
                  permissionDecision: "deny",
                  permissionDecisionReason: `[ScopeBlind] ${person.detail}. Exact action: ${actionReadback.summary}. ${page ? `Waiting for the named person at ${page}; retry this exact call once they have decided there. A changed call is a new action.` : "No standard page is configured (--report), so it cannot be decided here."}`
                }
              };
            }
          }
        }
      }
    }
  }
  maybeReloadCedar(state);
  if (state.cedarPolicies) {
    try {
      const cedarDecision = await evaluateCedar(state.cedarPolicies, {
        tool: toolName,
        tier: "unknown",
        // Hook mode doesn't have admission tier yet
        agentId: swarm.agent_id,
        context: {
          hook_event: "PreToolUse",
          ...input.toolInput || {}
        },
        // Also expose the raw tool input under context.input so policies written
        // against the documented nested shape match on the hook path too.
        toolInput: input.toolInput || {}
      });
      if (!cedarDecision.allowed) {
        const reason = cedarDecision.reason || "cedar_deny";
        const hookLatency2 = Date.now() - hookStart;
        const denyKey2 = `${toolName}:${input.sessionId || "default"}`;
        const denyCount = (state.denyCounter.get(denyKey2) || 0) + 1;
        state.denyCounter.set(denyKey2, denyCount);
        const suggestion = `permit(principal, action == Action::"MCP::Tool::call", resource == Tool::"${toolName}");`;
        state.permissionSuggestions.set(toolName, suggestion);
        emitDecisionLog(state, {
          tool: toolName,
          decision: "deny",
          reason_code: reason,
          request_id: requestId,
          hook_event: "PreToolUse",
          swarm: swarm.team_name ? swarm : void 0,
          timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
          payload_digest: payloadDigest,
          action_readback: actionReadback,
          deny_iteration: denyCount,
          sandbox_state: detectSandboxState(),
          plan_receipt_id: state.activePlanReceiptId || void 0
        });
        const isDefaultDeny = !reason || reason === "cedar_deny" || /reason":\[\]/.test(reason);
        const policyRef = state.cedarDir ? ` Policy: ${state.cedarDir}.` : "";
        const howTo = isDefaultDeny ? ` No permit matched (default-deny, fail-closed).${policyRef} Allow it: npx protect-mcp policy allow ${toolName}` : ` Blocked by an explicit forbid rule.${policyRef} Review: npx protect-mcp policy show`;
        if (denyCount === 1) {
          process.stderr.write(
            `[PROTECT_MCP] Denied "${toolName}" (${isDefaultDeny ? "default-deny" : "forbid"}).
  Allow with: npx protect-mcp policy allow ${toolName}
`
          );
        }
        return {
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: `[ScopeBlind] Denied "${toolName}".${howTo}` + (denyCount > 1 ? ` (attempt ${denyCount})` : "")
          }
        };
      }
    } catch (err) {
      const hookLatency2 = Date.now() - hookStart;
      process.stderr.write(
        `[PROTECT_MCP] Cedar eval threw for "${toolName}", failing closed: ${err instanceof Error ? err.message : err}
`
      );
      emitDecisionLog(state, {
        tool: toolName,
        decision: "deny",
        reason_code: "cedar_eval_error",
        request_id: requestId,
        hook_event: "PreToolUse",
        swarm: swarm.team_name ? swarm : void 0,
        timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
        payload_digest: payloadDigest,
        action_readback: actionReadback,
        sandbox_state: detectSandboxState()
      });
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `[ScopeBlind] Denied: the policy engine errored while evaluating "${toolName}", so the gate fails closed rather than allow an unverified call. Check the policy set and server logs.`
        }
      };
    }
  }
  if (state.jsonPolicy?.policy) {
    const toolPolicy = getToolPolicy(toolName, state.jsonPolicy.policy);
    if (toolPolicy.block) {
      const hookLatency2 = Date.now() - hookStart;
      emitDecisionLog(state, {
        tool: toolName,
        decision: "deny",
        reason_code: "policy_block",
        request_id: requestId,
        hook_event: "PreToolUse",
        swarm: swarm.team_name ? swarm : void 0,
        timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
        payload_digest: payloadDigest,
        action_readback: actionReadback,
        sandbox_state: detectSandboxState()
      });
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `[ScopeBlind] "${toolName}" is blocked by policy.`
        }
      };
    }
    if (toolPolicy.require_approval) {
      const hookLatency2 = Date.now() - hookStart;
      emitDecisionLog(state, {
        tool: toolName,
        decision: "require_approval",
        reason_code: "requires_human_approval",
        request_id: requestId,
        hook_event: "PreToolUse",
        swarm: swarm.team_name ? swarm : void 0,
        timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
        payload_digest: payloadDigest,
        action_readback: actionReadback,
        sandbox_state: detectSandboxState()
      });
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "ask",
          permissionDecisionReason: `[ScopeBlind] Approval required for exactly this action: ${actionReadback.summary}. Payload hash: ${actionReadback.payload_hash.slice(0, 16)}\u2026 Policy: ${state.policyDigest}`
        }
      };
    }
    if (toolPolicy.rate_limit) {
      try {
        const limit = parseRateLimit(toolPolicy.rate_limit);
        const key = `tool:${toolName}:hook`;
        const { allowed, remaining } = checkRateLimit(key, limit, state.rateLimitStore);
        if (!allowed) {
          const hookLatency2 = Date.now() - hookStart;
          emitDecisionLog(state, {
            tool: toolName,
            decision: "deny",
            reason_code: "rate_limit_exceeded",
            request_id: requestId,
            hook_event: "PreToolUse",
            swarm: swarm.team_name ? swarm : void 0,
            timing: { hook_latency_ms: hookLatency2, started_at: hookStart },
            sandbox_state: detectSandboxState()
          });
          return {
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "deny",
              permissionDecisionReason: `[ScopeBlind] "${toolName}" rate limit exceeded (${toolPolicy.rate_limit}).`
            }
          };
        }
      } catch {
      }
    }
  }
  const hookLatency = Date.now() - hookStart;
  const denyKey = `${toolName}:${input.sessionId || "default"}`;
  state.denyCounter.delete(denyKey);
  const emit = emitDecisionLog(state, {
    tool: toolName,
    decision: "allow",
    reason_code: state.cedarPolicies ? "cedar_allow" : state.jsonPolicy ? "policy_allow" : "observe_mode",
    request_id: requestId,
    hook_event: "PreToolUse",
    swarm: swarm.team_name ? swarm : void 0,
    timing: { hook_latency_ms: hookLatency, started_at: hookStart },
    payload_digest: payloadDigest,
    action_readback: actionReadback,
    sandbox_state: detectSandboxState(),
    plan_receipt_id: state.activePlanReceiptId || void 0
  });
  if (state.enforce && emit.signingFailed) {
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `[ScopeBlind] "${toolName}" was blocked because its receipt could not be signed. Failing closed: a governed action that cannot be proven is not allowed.`
      }
    };
  }
  return {};
}
async function handlePostToolUse(input, state) {
  const toolName = input.toolName || "unknown";
  const requestId = input.toolUseId || randomUUID().slice(0, 12);
  const now = Date.now();
  const inflight = state.inflightTools.get(requestId);
  const timing = {
    completed_at: now
  };
  if (inflight) {
    timing.tool_duration_ms = now - inflight.startedAt;
    timing.started_at = inflight.startedAt;
    state.inflightTools.delete(requestId);
  }
  const outputDigest = computeOutputDigest(input.toolResult);
  const receiptId = randomUUID().slice(0, 8);
  const policyName = state.cedarPolicies ? `cedar:${state.policyDigest}` : state.policyDigest;
  const additionalContext = `[ScopeBlind] Tool call receipted. Policy: ${policyName}. Decision: allow. Receipt: #${receiptId}.` + (timing.tool_duration_ms !== void 0 ? ` Duration: ${timing.tool_duration_ms}ms.` : "") + (timing.hook_latency_ms !== void 0 ? ` Overhead: ${timing.hook_latency_ms}ms.` : "");
  emitDecisionLog(state, {
    tool: toolName,
    decision: "allow",
    reason_code: "post_execution_receipt",
    request_id: requestId,
    hook_event: "PostToolUse",
    swarm: state.swarmContext.team_name ? state.swarmContext : void 0,
    timing,
    payload_digest: outputDigest ? {
      truncated: true,
      output_hash: outputDigest.output_hash,
      output_size: outputDigest.output_size
    } : void 0,
    sandbox_state: detectSandboxState()
  });
  return {
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext
    }
  };
}
function handleSubagentStart(input, state) {
  const agentId = input.agentId || "unknown";
  const agentType = input.agentType || "worker";
  emitDecisionLog(state, {
    tool: `subagent:${agentId}`,
    decision: "allow",
    reason_code: "subagent_started",
    request_id: randomUUID().slice(0, 12),
    hook_event: "SubagentStart",
    swarm: {
      ...state.swarmContext,
      agent_id: agentId,
      agent_name: input.agentName,
      agent_type: agentType
    }
  });
  if (state.verbose) {
    process.stderr.write(`[PROTECT_MCP] Subagent started: ${agentId} (${agentType})
`);
  }
  return {};
}
function handleSubagentStop(input, state) {
  const agentId = input.agentId || "unknown";
  emitDecisionLog(state, {
    tool: `subagent:${agentId}`,
    decision: "allow",
    reason_code: "subagent_stopped",
    request_id: randomUUID().slice(0, 12),
    hook_event: "SubagentStop",
    swarm: {
      ...state.swarmContext,
      agent_id: agentId,
      agent_name: input.agentName
    }
  });
  return {};
}
function handleTaskCreated(input, state) {
  emitDecisionLog(state, {
    tool: `task:${input.taskId || "unknown"}`,
    decision: "allow",
    reason_code: "task_created",
    request_id: randomUUID().slice(0, 12),
    hook_event: "TaskCreated",
    swarm: {
      ...state.swarmContext,
      agent_name: input.teammateName
    }
  });
  return {};
}
function handleTaskCompleted(input, state) {
  emitDecisionLog(state, {
    tool: `task:${input.taskId || "unknown"}`,
    decision: "allow",
    reason_code: "task_completed",
    request_id: randomUUID().slice(0, 12),
    hook_event: "TaskCompleted",
    swarm: state.swarmContext
  });
  return {};
}
function handleSessionStart(input, state) {
  emitDecisionLog(state, {
    tool: "session",
    decision: "allow",
    reason_code: "session_started",
    request_id: input.sessionId || randomUUID().slice(0, 12),
    hook_event: "SessionStart",
    swarm: state.swarmContext,
    sandbox_state: detectSandboxState()
  });
  return {};
}
function handleSessionEnd(input, state) {
  const suggestions = [...state.permissionSuggestions.entries()];
  if (suggestions.length > 0) {
    process.stderr.write(`
[PROTECT_MCP] Session summary \u2014 ${suggestions.length} policy suggestion(s):
`);
    for (const [tool, suggestion] of suggestions) {
      process.stderr.write(`  ${tool}: ${suggestion}
`);
    }
    process.stderr.write("\n");
  }
  emitDecisionLog(state, {
    tool: "session",
    decision: "allow",
    reason_code: "session_ended",
    request_id: input.sessionId || randomUUID().slice(0, 12),
    hook_event: "SessionEnd",
    swarm: state.swarmContext
  });
  return {};
}
function handleTeammateIdle(input, state) {
  emitDecisionLog(state, {
    tool: `teammate:${input.agentId || "unknown"}`,
    decision: "allow",
    reason_code: "teammate_idle",
    request_id: randomUUID().slice(0, 12),
    hook_event: "TeammateIdle",
    swarm: {
      ...state.swarmContext,
      agent_id: input.agentId,
      agent_name: input.agentName
    }
  });
  return {};
}
function handleConfigChange(input, state) {
  const configPath = input.filePath || input.configPath || "unknown";
  const source = input.configSource || "unknown";
  const isSelfModification = configPath.includes("settings.json") || configPath.includes(".claude/");
  if (isSelfModification) {
    state.configAlerts.push({
      timestamp: Date.now(),
      path: configPath,
      source
    });
    process.stderr.write(
      `[PROTECT_MCP] \u26A0\uFE0F  TAMPER ALERT: Config file modified: ${configPath} (source: ${source})
`
    );
    emitDecisionLog(state, {
      tool: "config",
      decision: "deny",
      reason_code: "config_tamper_detected",
      request_id: randomUUID().slice(0, 12),
      hook_event: "ConfigChange",
      swarm: state.swarmContext
    });
  } else {
    emitDecisionLog(state, {
      tool: "config",
      decision: "allow",
      reason_code: "config_changed",
      request_id: randomUUID().slice(0, 12),
      hook_event: "ConfigChange"
    });
  }
  return {};
}
function handleStop(input, state) {
  const suggestions = [...state.permissionSuggestions.entries()];
  if (suggestions.length > 0) {
    process.stderr.write(`
[PROTECT_MCP] Final policy suggestions:
`);
    for (const [tool, suggestion] of suggestions) {
      process.stderr.write(`  ${suggestion}
`);
    }
    process.stderr.write("\n");
  }
  emitDecisionLog(state, {
    tool: "session",
    decision: "allow",
    reason_code: "agent_stopped",
    request_id: randomUUID().slice(0, 12),
    hook_event: "Stop",
    swarm: state.swarmContext
  });
  return {};
}
function emitDecisionLog(state, entry) {
  const mode = state.enforce ? "enforce" : "shadow";
  const otelTraceId = randomBytes2(16).toString("hex");
  const otelSpanId = randomBytes2(8).toString("hex");
  const log = {
    v: 2,
    tool: entry.tool || "unknown",
    decision: entry.decision || "allow",
    reason_code: entry.reason_code || "default_allow",
    policy_digest: state.policyDigest,
    policy_engine: state.cedarPolicies ? "cedar" : "built-in",
    request_id: entry.request_id || randomUUID().slice(0, 12),
    timestamp: Date.now(),
    mode,
    otel_trace_id: otelTraceId,
    otel_span_id: otelSpanId,
    ...entry.tier && { tier: entry.tier },
    ...entry.hook_event && { hook_event: entry.hook_event },
    ...entry.swarm && { swarm: entry.swarm },
    ...entry.timing && { timing: entry.timing },
    ...entry.payload_digest && { payload_digest: entry.payload_digest },
    ...entry.deny_iteration && { deny_iteration: entry.deny_iteration },
    ...entry.sandbox_state && { sandbox_state: entry.sandbox_state },
    ...entry.plan_receipt_id && { plan_receipt_id: entry.plan_receipt_id },
    ...state.managedMandate ? {
      mandate_registry: {
        registry_id: state.managedMandate.registry.registry_id,
        active_policy_digest: state.managedMandate.registry.active.policy_digest,
        active_transition_hash: receiptHash(state.managedMandate.registry.history.at(-1)?.transition_receipt || {}),
        ...state.managedMandate.registry.active.expires_at ? { expires_at: state.managedMandate.registry.active.expires_at } : {}
      }
    } : {}
  };
  const enr = state.inflightTools.get(log.request_id)?.enrichment;
  if (enr) log.enrichment = enr;
  if (state.standard) log.standard = { request_id: state.standard.request_id, digest: state.standard.digest };
  const approval = state.approvalsToRecord.get(log.request_id);
  if (approval) {
    log.approval = approval;
    state.approvalsToRecord.delete(log.request_id);
  }
  const callLine = state.reporter ? JSON.stringify({ tool: log.tool, input: log.action_readback?.payload_preview ?? {}, decision: log.decision, request_id: log.request_id, at: new Date(log.timestamp).toISOString() }) : void 0;
  if (state.reporter && !isSigningEnabled()) state.reporter.record(void 0, callLine);
  process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}
`);
  try {
    appendFileSync(state.logFilePath, JSON.stringify(log) + "\n");
  } catch {
  }
  if (isSigningEnabled()) {
    const signed = signDecision(log, state.lastReceiptHash || void 0);
    if (signed.signed) {
      try {
        appendFileSync(state.receiptFilePath, signed.signed + "\n");
        if (signed.receipt_hash) state.lastReceiptHash = signed.receipt_hash;
      } catch {
      }
      state.receiptBuffer.add(log.request_id, signed.signed);
      state.reporter?.record(signed.signed, callLine);
      try {
        const bridge = getScopeBlindBridge();
        if (bridge.enabled()) {
          const parsed = typeof signed.signed === "string" ? JSON.parse(signed.signed) : signed.signed;
          bridge.forward(parsed);
        }
      } catch (err) {
        process.stderr.write(`[PROTECT_MCP] ScopeBlind forward error: ${err instanceof Error ? err.message : err}
`);
      }
    } else if (signed.error) {
      const tombstoneObj = {
        type: "scopeblind.signing_failure.v1",
        request_id: log.request_id,
        tool: log.tool,
        decision: log.decision,
        error: signed.error,
        at: new Date(log.timestamp).toISOString(),
        ...state.lastReceiptHash ? { previousReceiptHash: state.lastReceiptHash } : {}
      };
      const tombstone = JSON.stringify(tombstoneObj);
      try {
        appendFileSync(state.receiptFilePath, tombstone + "\n");
        state.lastReceiptHash = receiptHash(tombstoneObj);
      } catch {
      }
      process.stderr.write(`[PROTECT_MCP_SIGNING_FAILURE] ${tombstone}
`);
      return { signingFailed: true };
    }
  }
  return { signingFailed: false };
}
async function routeHookEvent(input, state) {
  switch (input.hookEventName) {
    case "PreToolUse":
      return handlePreToolUse(input, state);
    case "PostToolUse":
      return handlePostToolUse(input, state);
    case "SubagentStart":
      return handleSubagentStart(input, state);
    case "SubagentStop":
      return handleSubagentStop(input, state);
    case "TaskCreated":
      return handleTaskCreated(input, state);
    case "TaskCompleted":
      return handleTaskCompleted(input, state);
    case "SessionStart":
      return handleSessionStart(input, state);
    case "SessionEnd":
      return handleSessionEnd(input, state);
    case "TeammateIdle":
      return handleTeammateIdle(input, state);
    case "ConfigChange":
      return handleConfigChange(input, state);
    case "Stop":
      return handleStop(input, state);
    default:
      if (state.verbose) {
        process.stderr.write(`[PROTECT_MCP] Unknown hook event: ${input.hookEventName}
`);
      }
      return {};
  }
}
async function startHookServer(options = {}) {
  const port = options.port || DEFAULT_PORT;
  const verbose = options.verbose || false;
  const enforce = options.enforce || false;
  const dataDir = options.dataDir || process.cwd();
  let cedarPolicies = null;
  let jsonPolicy = null;
  let policyDigest = "none";
  let gateKeyPath;
  let managedMandate = null;
  const cedarDir = options.cedarDir || findCedarDir();
  if (cedarDir) {
    try {
      cedarPolicies = loadCedarPolicies(cedarDir);
      policyDigest = cedarPolicies.digest;
      process.stderr.write(
        `[PROTECT_MCP] Cedar policies loaded: ${cedarPolicies.fileCount} files from ${cedarDir} (digest: ${policyDigest})
`
      );
      const cedarAvailable = await isCedarAvailable();
      if (!cedarAvailable) {
        process.stderr.write(
          "[PROTECT_MCP] Warning: @cedar-policy/cedar-wasm not installed. Cedar policies loaded but evaluation fallback is allow-all.\n"
        );
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Cedar load error: ${err instanceof Error ? err.message : err}
`);
    }
  }
  if (options.policyPath) {
    try {
      jsonPolicy = loadPolicy(options.policyPath);
      if (!cedarPolicies) policyDigest = jsonPolicy.digest;
      process.stderr.write(`[PROTECT_MCP] JSON policy loaded from ${options.policyPath}
`);
      if (jsonPolicy.signing) {
        gateKeyPath = jsonPolicy.signing.key_path;
        const warnings = await initSigning(jsonPolicy.signing);
        for (const w of warnings) {
          process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
        }
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Policy load error: ${err instanceof Error ? err.message : err}
`);
    }
  }
  if (!jsonPolicy?.signing) {
    const keyPath = join2(dataDir, "keys", "gateway.json");
    if (existsSync(keyPath)) {
      gateKeyPath = keyPath;
      const warnings = await initSigning({ key_path: keyPath, issuer: "protect-mcp", enabled: true });
      for (const w of warnings) {
        process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
      }
    }
  }
  if (cedarDir) {
    const existingRegistry = loadMandateRegistry(cedarDir);
    if (existingRegistry) {
      if (!gateKeyPath) {
        const message = "managed mandate found but no local gate signing key is configured";
        if (enforce) throw new Error(`enforce mode refused to start: ${message}`);
        process.stderr.write(`[PROTECT_MCP] Warning: ${message}; governed enforcement remains unavailable.
`);
      } else {
        try {
          const gateSigner = loadGateSigner(gateKeyPath);
          const receiptSigner = getSignerInfo();
          if (!isSigningEnabled() || !receiptSigner || receiptSigner.kid !== gateSigner.kid || receiptSigner.publicKey !== gateSigner.publicKey) {
            throw new Error("managed mandate requires decision receipt signing with the exact gate key pinned in the registry");
          }
          const check = refreshManagedMandate({ cedarDir, signer: gateSigner });
          if (!check.valid || !check.registry) {
            const message = `${check.code || "mandate_registry_invalid"}: ${check.message || "registry verification failed"}`;
            if (enforce) throw new Error(`enforce mode refused to start: ${message}`);
            process.stderr.write(`[PROTECT_MCP] Warning: managed mandate invalid (${message}).
`);
          } else {
            const reloaded = loadCedarPolicies(cedarDir);
            if (reloaded.digest !== check.registry.active.policy_digest) {
              throw new Error("loaded Cedar bytes do not match the signed active mandate head");
            }
            cedarPolicies = reloaded;
            policyDigest = reloaded.digest;
            managedMandate = {
              signer: gateSigner,
              registry: check.registry,
              rpId: options.mandateRelyingPartyId || "localhost",
              expectedOrigin: options.mandateApprovalOrigin || `http://localhost:${port}`,
              highWaterSequence: check.registry.history.length,
              highWaterHash: check.registry.history.length ? receiptHash(check.registry.history[check.registry.history.length - 1].transition_receipt) : "",
              maxSeenTimeMs: Math.max(Date.now(), check.registry.history.reduce((m, t) => Math.max(m, Date.parse(t.occurred_at) || 0), 0))
            };
            process.stderr.write(
              `[PROTECT_MCP] Managed mandate loaded: ${check.registry.registry_id} (head: ${check.registry.active.policy_digest}${check.registry.active.expires_at ? `; expires ${check.registry.active.expires_at}` : ""}).
`
            );
          }
        } catch (error) {
          if (enforce) throw error;
          process.stderr.write(`[PROTECT_MCP] Warning: managed mandate unavailable: ${error instanceof Error ? error.message : error}
`);
        }
      }
    }
  }
  if (enforce) {
    const selfTest = await runEvaluatorSelfTest();
    for (const c of selfTest.cases) {
      if (!c.pass) {
        process.stderr.write(
          `[PROTECT_MCP] SELF-TEST FAIL: ${c.name} (expected ${c.expected}, got ${c.actual})
`
        );
      }
    }
    if (!selfTest.passed) {
      throw new Error(
        "enforce mode refused to start: the restraint self-test failed. A gate that cannot prove it denies must not arm."
      );
    }
    const receiptProbe = signDecision({
      v: 2,
      tool: "__protect_mcp_startup_selftest__",
      decision: "deny",
      reason_code: "startup_selftest",
      policy_digest: policyDigest,
      request_id: `selftest-${Date.now()}`,
      mode: "enforce",
      timestamp: Date.now()
    });
    if (receiptProbe.error) {
      throw new Error(
        `enforce mode refused to start: signing is configured but a denial receipt could not be produced (${receiptProbe.error}). An enforcing gate that cannot evidence a denial must not arm.`
      );
    }
    process.stderr.write(
      `[PROTECT_MCP] Restraint self-test passed (${selfTest.cases.length} vectors${selfTest.wasmAvailable ? "" : "; Cedar WASM absent, fail-closed invariant verified"})${receiptProbe.ok ? "; denial receipt signing verified" : ""}. Arming enforce mode.
`
    );
  }
  let standard = null;
  let reporter = null;
  if (options.standardPath) {
    standard = loadStandardFile(options.standardPath);
    process.stderr.write(`[PROTECT_MCP] Standard in force: ${standard.request_id} (${standard.summary})
`);
  }
  if (options.reportUrl) {
    if (!standard) throw new Error("--report needs --standard <standard.json>; the page belongs to a signed standard");
    const token = options.reportToken || process.env.PROTECT_MCP_REPORT_TOKEN || "";
    if (!token) throw new Error("--report needs the page's write token: --report-token <token> or PROTECT_MCP_REPORT_TOKEN");
    reporter = new RecordReporter({ url: options.reportUrl, token, runId: options.runId || `run-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace(/[-:T]/g, "")}` });
    process.stderr.write(`[PROTECT_MCP] Record lands on ${new URL(reporter.url).origin}/standard?s=${reporter.sid} as run ${reporter.runId}
`);
    if (!isSigningEnabled()) process.stderr.write("[PROTECT_MCP] Warning: signing is not configured, so only unsigned call lines reach the page; add a signing key for receipts\n");
  }
  const state = {
    cedarPolicies,
    cedarDir: cedarDir || null,
    cedarMtimeMs: cedarDir ? newestCedarMtime(cedarDir) : 0,
    cedarCheckedMs: 0,
    jsonPolicy,
    rateLimitStore: /* @__PURE__ */ new Map(),
    receiptBuffer: new ReceiptBuffer(),
    inflightTools: /* @__PURE__ */ new Map(),
    denyCounter: /* @__PURE__ */ new Map(),
    swarmContext: detectSwarmContext(),
    activePlanReceiptId: null,
    startTime: Date.now(),
    port,
    verbose,
    enforce,
    policyDigest,
    logFilePath: join2(dataDir, LOG_FILE),
    receiptFilePath: join2(dataDir, RECEIPTS_FILE),
    lastReceiptHash: resumeReceiptChain(join2(dataDir, RECEIPTS_FILE)),
    permissionSuggestions: /* @__PURE__ */ new Map(),
    configAlerts: [],
    managedMandate,
    standard,
    reporter,
    approvalsToRecord: /* @__PURE__ */ new Map()
  };
  const server = createServer(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Content-Type", "application/json");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url || "/", `http://localhost:${port}`);
    if (url.pathname === "/health" && req.method === "GET") {
      const signerInfo = getSignerInfo();
      res.writeHead(200);
      res.end(JSON.stringify({
        status: "ok",
        server: "protect-mcp-hooks",
        version: process.env.PROTECT_MCP_VERSION || "unknown",
        uptime_ms: Date.now() - state.startTime,
        mode: enforce ? "enforce" : "shadow",
        policy_digest: policyDigest,
        policy_engine: cedarPolicies ? "cedar" : jsonPolicy ? "built-in" : "none",
        signing: isSigningEnabled(),
        swarm: state.swarmContext,
        signer: signerInfo ? { kid: signerInfo.kid, issuer: signerInfo.issuer } : null,
        cedar_files: cedarPolicies?.fileCount || 0,
        mandate: state.managedMandate ? {
          registry_id: state.managedMandate.registry.registry_id,
          active_policy_digest: state.managedMandate.registry.active.policy_digest,
          ...state.managedMandate.registry.active.expires_at ? { expires_at: state.managedMandate.registry.active.expires_at } : {},
          controller_count: state.managedMandate.registry.controllers.length
        } : null
      }));
      return;
    }
    if (url.pathname === "/mandate" && req.method === "GET") {
      const check = ensureManagedMandate(state);
      if (!state.managedMandate) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "no_managed_mandate", hint: "Run protect-mcp mandate init before requesting lifecycle status." }));
        return;
      }
      res.writeHead(check.valid ? 200 : 409);
      res.end(JSON.stringify({
        valid: check.valid,
        ...check.valid ? {} : { error: check.code, message: check.message },
        mandate: publicMandateStatus(state.managedMandate.registry)
      }));
      return;
    }
    const approvalMatch = url.pathname.match(/^\/mandate\/proposals\/([^/]+)\/(approve|webauthn\/challenge)$/);
    if (approvalMatch && req.method === "GET") {
      const proposalId = decodeURIComponent(approvalMatch[1]);
      const check = ensureManagedMandate(state);
      if (!check.valid || !state.managedMandate) {
        res.writeHead(409);
        res.end(JSON.stringify({ error: check.valid ? "no_managed_mandate" : check.code, message: check.valid ? "No managed mandate is active." : check.message }));
        return;
      }
      const proposal = state.managedMandate.registry.proposals[proposalId];
      if (!proposal) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "unknown_proposal" }));
        return;
      }
      const controllerId = url.searchParams.get("controller_id") || state.managedMandate.registry.controllers.find((item) => item.type === "webauthn")?.id;
      const controller = state.managedMandate.registry.controllers.find((item) => item.id === controllerId);
      if (!controller || controller.type !== "webauthn") {
        res.writeHead(400);
        res.end(JSON.stringify({ error: "webauthn_controller_required", hint: "Register a WebAuthn controller before using browser approval." }));
        return;
      }
      if (approvalMatch[2] === "webauthn/challenge") {
        try {
          const challenge = createWebAuthnPolicyChallenge({
            cedarDir: state.cedarDir,
            proposalId,
            controllerId: controller.id,
            rpId: state.managedMandate.rpId
          });
          state.managedMandate.registry = loadMandateRegistry(state.cedarDir);
          res.writeHead(200);
          res.end(JSON.stringify({
            proposal_id: proposal.proposal_id,
            proposal_digest: proposal.proposal_digest,
            controller: { id: controller.id, label: controller.label },
            publicKey: {
              challenge: challenge.challenge,
              rpId: challenge.rpId,
              timeout: challenge.timeoutSeconds * 1e3,
              userVerification: "required",
              allowCredentials: [{ id: controller.credential_id, type: "public-key" }]
            }
          }));
        } catch (error) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: "challenge_failed", message: error instanceof Error ? error.message : "Could not create approval challenge." }));
        }
        return;
      }
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.writeHead(200);
      res.end(renderMandateApprovalPage({ proposal, controller: { id: controller.id, label: controller.label }, port }));
      return;
    }
    const approveMatch = url.pathname.match(/^\/mandate\/proposals\/([^/]+)\/webauthn\/approve$/);
    if (approveMatch && req.method === "POST") {
      const proposalId = decodeURIComponent(approveMatch[1]);
      if (!state.managedMandate || !state.cedarDir) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "no_managed_mandate" }));
        return;
      }
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          if (!parsed.assertion) throw new Error("missing WebAuthn assertion");
          const registry = approvePolicyProposalWithWebAuthn({
            cedarDir: state.cedarDir,
            signer: state.managedMandate.signer,
            proposalId,
            assertion: parsed.assertion,
            expectedOrigin: state.managedMandate.expectedOrigin
          });
          state.managedMandate.registry = registry;
          const refreshed = ensureManagedMandate(state);
          if (!refreshed.valid) throw new Error(`${refreshed.code}: ${refreshed.message}`);
          res.writeHead(200);
          res.end(JSON.stringify({
            approved: true,
            active_policy_digest: state.managedMandate.registry.active.policy_digest,
            expires_at: state.managedMandate.registry.active.expires_at || null,
            mandate: publicMandateStatus(state.managedMandate.registry)
          }));
        } catch (error) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: "approval_rejected", message: error instanceof Error ? error.message : "Policy approval was rejected." }));
        }
      });
      return;
    }
    if (url.pathname === "/receipts" && req.method === "GET") {
      const limit = parseInt(url.searchParams.get("limit") || "20", 10);
      const receipts = state.receiptBuffer.getAll().slice(0, Math.min(limit, 100));
      res.writeHead(200);
      res.end(JSON.stringify({ count: receipts.length, total: state.receiptBuffer.count(), receipts }));
      return;
    }
    if (url.pathname === "/receipts/latest" && req.method === "GET") {
      const latest = state.receiptBuffer.getLatest();
      if (!latest) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "no_receipts" }));
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify(latest));
      return;
    }
    if (url.pathname === "/suggestions" && req.method === "GET") {
      const suggestions = [...state.permissionSuggestions.entries()].map(([tool, rule]) => ({ tool, cedar_rule: rule }));
      res.writeHead(200);
      res.end(JSON.stringify({ count: suggestions.length, suggestions }));
      return;
    }
    if (url.pathname === "/alerts" && req.method === "GET") {
      res.writeHead(200);
      res.end(JSON.stringify({ count: state.configAlerts.length, alerts: state.configAlerts }));
      return;
    }
    if (url.pathname === "/hook" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", async () => {
        let input;
        try {
          const raw = JSON.parse(body);
          input = normalizeHookInput(raw);
          if (!input.hookEventName) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: "missing_hook_event_name", hint: "Expected hook_event_name or hookEventName in POST body" }));
            return;
          }
          const response = await routeHookEvent(input, state);
          res.writeHead(200);
          res.end(JSON.stringify(response));
        } catch (err) {
          if (verbose) {
            process.stderr.write(`[PROTECT_MCP] Hook error: ${err instanceof Error ? err.message : err}
`);
          }
          if (input?.hookEventName === "PreToolUse") {
            res.writeHead(200);
            res.end(JSON.stringify({
              hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "deny",
                permissionDecisionReason: `[ScopeBlind] Denied "${input.toolName || "unknown"}": the gate hit an unexpected error while deciding, so it fails closed rather than allow an unverified call. Check the server logs.`
              }
            }));
            return;
          }
          res.writeHead(400);
          res.end(JSON.stringify({ error: "invalid_request" }));
        }
      });
      return;
    }
    res.writeHead(404);
    res.end(JSON.stringify({
      error: "not_found",
      endpoints: [
        "POST /hook           \u2014 Claude Code hook endpoint",
        "GET  /health         \u2014 Health check",
        "GET  /receipts       \u2014 Recent receipts",
        "GET  /receipts/latest \u2014 Most recent receipt",
        "GET  /suggestions    \u2014 Policy suggestions",
        "GET  /alerts         \u2014 Config tamper alerts"
      ]
    }));
  });
  server.listen(port, "127.0.0.1", () => {
    const w = (s) => process.stderr.write(s);
    const pad = (s, n = 46) => s.padEnd(n);
    w(`
`);
    w(process.env.PROTECT_MCP_VERSION ? `  protect-mcp v${process.env.PROTECT_MCP_VERSION}
` : `  protect-mcp
`);
    w(`  ScopeBlind \xB7 https://scopeblind.com
`);
    w(`
`);
    w(`  Listening     http://127.0.0.1:${port}
`);
    w(`  Mode          ${enforce ? "enforce" : "shadow"}
`);
    w(`  Policy        ${cedarPolicies ? `Cedar (${cedarPolicies.fileCount} files)` : jsonPolicy ? "JSON" : "none"}
`);
    w(`  Signing       ${isSigningEnabled() ? "Ed25519" : "disabled"}
`);
    if (state.swarmContext.team_name) {
      w(`  Swarm         ${state.swarmContext.team_name} (${state.swarmContext.agent_type})
`);
    }
    w(`
`);
    w(`  POST /hook         Hook receiver
`);
    w(`  GET  /health       Health + signer info
`);
    w(`  GET  /receipts     Signed receipts
`);
    w(`  GET  /suggestions  Cedar policy suggestions
`);
    w(`
`);
    w(`  deny is authoritative: it cannot be overridden.
`);
    w(`
`);
    w(`  See your record   npx protect-mcp record
`);
    w(`                    a searchable view of every decision, all on this machine
`);
    w(`
`);
    const hasSlug = process.env.SCOPEBLIND_SLUG || existsSync(join2(dataDir, ".scopeblind"));
    if (!hasSlug) {
      w(`  Dashboard  npx protect-mcp connect
`);
      w(`             Sends privacy-safe summaries; raw receipts stay local
`);
      w(`
`);
    }
  });
  const shutdown = () => {
    process.stderr.write("\n[PROTECT_MCP] Shutting down hook server...\n");
    const suggestions = [...state.permissionSuggestions.entries()];
    if (suggestions.length > 0) {
      process.stderr.write(`[PROTECT_MCP] ${suggestions.length} policy suggestion(s) accumulated:
`);
      for (const [tool, suggestion] of suggestions) {
        process.stderr.write(`  ${suggestion}
`);
      }
    }
    server.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  return server;
}
function newestCedarMtime(dir) {
  try {
    let newest = 0;
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".cedar")) continue;
      const m = statSync(join2(dir, f)).mtimeMs;
      if (m > newest) newest = m;
    }
    return newest;
  } catch {
    return 0;
  }
}
var CEDAR_CHECK_THROTTLE_MS = 2e3;
function ensureManagedMandate(state) {
  try {
    if (!state.managedMandate || !state.cedarDir) return { valid: true };
    const mm = state.managedMandate;
    const floorMs = Math.max(Date.now(), mm.maxSeenTimeMs);
    const result = refreshManagedMandate({ cedarDir: state.cedarDir, signer: mm.signer, now: new Date(floorMs) });
    if (!result.valid || !result.registry) {
      return {
        valid: false,
        code: result.code || "mandate_registry_invalid",
        message: result.message || "The mandate registry could not be verified."
      };
    }
    const history = result.registry.history;
    if (mm.highWaterSequence > 0) {
      if (history.length < mm.highWaterSequence) {
        return { valid: false, code: "mandate_rollback_detected", message: "The mandate history is shorter than a state this gate already enforced. The registry was rolled back or truncated." };
      }
      const atMark = history[mm.highWaterSequence - 1];
      if (!atMark || receiptHash(atMark.transition_receipt) !== mm.highWaterHash) {
        return { valid: false, code: "mandate_history_forked", message: "The mandate history diverges from a state this gate already enforced. The registry was forked or rewritten." };
      }
    }
    mm.highWaterSequence = history.length;
    mm.highWaterHash = history.length ? receiptHash(history[history.length - 1].transition_receipt) : "";
    const latestTransitionMs = history.reduce((m, t) => Math.max(m, Date.parse(t.occurred_at) || 0), 0);
    mm.maxSeenTimeMs = Math.max(mm.maxSeenTimeMs, floorMs, latestTransitionMs);
    state.managedMandate.registry = result.registry;
    if (state.policyDigest !== result.registry.active.policy_digest || result.expired_reverted) {
      const reloaded = loadCedarPolicies(state.cedarDir);
      if (reloaded.digest !== result.registry.active.policy_digest) {
        return { valid: false, code: "policy_head_mismatch", message: "Reloaded policy bytes do not match the signed active mandate head." };
      }
      state.cedarPolicies = reloaded;
      state.policyDigest = reloaded.digest;
      state.cedarMtimeMs = newestCedarMtime(state.cedarDir);
      state.cedarCheckedMs = Date.now();
      if (result.expired_reverted) {
        process.stderr.write(`[PROTECT_MCP] Mandate grant expired; restored signed baseline ${reloaded.digest}.
`);
      }
    }
    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      code: "mandate_registry_unreadable",
      message: `The managed mandate registry could not be read or verified (${error instanceof Error ? error.message : "unknown error"}). Failing closed until the signed policy state is restored.`
    };
  }
}
function maybeReloadCedar(state) {
  if (!state.cedarDir) return;
  if (state.managedMandate) return;
  const nowMs = Date.now();
  if (nowMs - state.cedarCheckedMs < CEDAR_CHECK_THROTTLE_MS) return;
  state.cedarCheckedMs = nowMs;
  const m = newestCedarMtime(state.cedarDir);
  if (m <= state.cedarMtimeMs) return;
  try {
    const reloaded = loadCedarPolicies(state.cedarDir);
    state.cedarPolicies = reloaded;
    state.policyDigest = reloaded.digest;
    state.cedarMtimeMs = m;
    process.stderr.write(`[PROTECT_MCP] Cedar policy reloaded (digest: ${reloaded.digest}) after on-disk change.
`);
  } catch (err) {
    process.stderr.write(`[PROTECT_MCP] Cedar reload failed, keeping the previous policy: ${err instanceof Error ? err.message : err}
`);
    state.cedarMtimeMs = m;
  }
}
function findCedarDir() {
  for (const candidate of ["cedar", "policies", "."]) {
    try {
      if (existsSync(candidate)) {
        const files = readdirSync(candidate, { encoding: "utf-8" });
        if (files.some((f) => f.endsWith(".cedar"))) {
          return candidate;
        }
      }
    } catch {
    }
  }
  return void 0;
}
function escapeHtml(value) {
  return value.replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char] || char);
}
function renderMandateApprovalPage(input) {
  const { proposal, controller } = input;
  const rows = (values, empty) => values.length ? values.map((value) => `<li><code>${escapeHtml(value)}</code></li>`).join("") : `<li class="muted">${escapeHtml(empty)}</li>`;
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
  <div class="eyebrow">ScopeBlind Legate \xB7 controller approval</div>
  <h1>You are approving exactly this policy change.</h1>
  <p class="muted">This is a time-limited change to a local enforcement gate. Your passkey approves this exact proposal digest, not a general permission for the agent to edit its mandate.</p>
  <section class="card danger"><h2>Why it was proposed</h2><p>${escapeHtml(proposal.reason)}</p><div class="meta"><div><strong>Blocked action</strong>${escapeHtml(proposal.denial_origin.tool)}</div><div><strong>Denied request</strong><code>${escapeHtml(proposal.denial_origin.request_id)}</code></div><div><strong>Current policy</strong><code>${escapeHtml(proposal.base_policy_digest)}</code></div><div><strong>Expires automatically</strong>${escapeHtml(proposal.expires_at)}</div></div></section>
  <section class="card"><h2>Plain-English diff</h2><ul>${rows(proposal.diff.plain_english, "No interpretable policy change.")}</ul></section>
  <section class="card"><h2>Executable statements added</h2><ul>${rows(proposal.diff.added_statements, "None.")}</ul></section>
  <section class="card"><h2>Executable statements removed</h2><ul>${rows(proposal.diff.removed_statements, "None.")}</ul></section>
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
var SNAKE_TO_CAMEL_MAP = {
  hook_event_name: "hookEventName",
  session_id: "sessionId",
  transcript_path: "transcriptPath",
  permission_mode: "permissionMode",
  agent_id: "agentId",
  agent_type: "agentType",
  tool_name: "toolName",
  tool_input: "toolInput",
  tool_use_id: "toolUseId",
  tool_response: "toolResult",
  // Claude Code sends tool_response, we read toolResult
  stop_hook_active: "stopHookActive",
  agent_transcript_path: "agentTranscriptPath",
  last_assistant_message: "lastAssistantMessage",
  teammate_name: "teammateName",
  team_name: "teamName",
  task_id: "taskId",
  task_subject: "taskSubject",
  task_description: "taskDescription",
  file_path: "filePath",
  config_path: "configPath",
  old_cwd: "oldCwd",
  new_cwd: "newCwd",
  notification_type: "notificationType",
  is_interrupt: "isInterrupt",
  error_details: "errorDetails",
  compact_summary: "compactSummary",
  custom_instructions: "customInstructions",
  worktree_path: "worktreePath",
  trigger_file_path: "triggerFilePath",
  parent_file_path: "parentFilePath",
  memory_type: "memoryType",
  load_reason: "loadReason",
  mcp_server_name: "mcpServerName",
  elicitation_id: "elicitationId",
  requested_schema: "requestedSchema",
  permission_suggestions: "permissionSuggestions"
};
function normalizeHookInput(raw) {
  const result = {};
  for (const [key, value] of Object.entries(raw)) {
    const camelKey = SNAKE_TO_CAMEL_MAP[key] || key;
    result[camelKey] = value;
  }
  if (raw.source !== void 0 && raw.hook_event_name === "ConfigChange" && !raw.config_source) {
    result["configSource"] = raw.source;
  }
  return result;
}

export {
  ScopeBlindBridge,
  getScopeBlindBridge,
  forwardReceipt,
  startHookServer
};
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
 *   3. After the tenant is known, reduce each local receipt to a pseudonymous
 *      egress summary using a tenant-scoped, local-only HMAC key; sign that
 *      separate summary envelope locally, and POST it to /summaries. The raw
 *      signed receipt endpoint is intentionally not used by this bridge.
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
 *   SCOPEBLIND_EGRESS_HMAC_KEY
 *                           Optional base64url 32-byte local-only HMAC key.
 *                           If omitted, protect-mcp creates a per-tenant key
 *                           in ~/.protect-mcp/egress-keys (mode 0600).
 *   SCOPEBLIND_EGRESS_KEY_DIR
 *                           Optional local directory for generated HMAC keys.
 *
 * @license MIT
 */
