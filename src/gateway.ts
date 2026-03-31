import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID, randomBytes } from 'node:crypto';
import { createInterface, type Interface } from 'node:readline';
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import type {
  ProtectConfig,
  JsonRpcRequest,
  JsonRpcResponse,
  DecisionLog,
  TrustTier,
  ToolPolicy,
} from './types.js';
import { getToolPolicy, parseRateLimit, checkRateLimit } from './policy.js';
import { evaluateTier, meetsMinTier, type ManifestPresentation, type AdmissionResult } from './admission.js';
import { resolveCredential } from './credentials.js';
import { signDecision, isSigningEnabled } from './signing.js';
import { queryExternalPDP, buildDecisionContext } from './external-pdp.js';
import { evaluateCedar, type CedarPolicySet } from './cedar-evaluator.js';
import { EvidenceStore } from './evidence-store.js';
import { sendApprovalNotification, parseNotificationConfigFromEnv, type NotificationConfig } from './notifications.js';
import { ReceiptBuffer, startStatusServer } from './http-server.js';

/** JSONL log file name written to cwd */
const LOG_FILE = '.protect-mcp-log.jsonl';
const RECEIPTS_FILE = '.protect-mcp-receipts.jsonl';

/**
 * MCP tool-calling gateway that intercepts JSON-RPC requests,
 * evaluates policy, and emits signed decision receipts.
 *
 * @standard Standard MCP proxy pattern — JSON-RPC stdio interception.
 */
export class ProtectGateway {
  private child: ChildProcess | null = null;
  private config: ProtectConfig;
  private rateLimitStore = new Map<string, number[]>();
  private clientReader: Interface | null = null;
  private logFilePath: string;
  private receiptFilePath: string;
  private evidenceStore: EvidenceStore;
  private receiptBuffer: ReceiptBuffer;

  /** Approval grants keyed by request_id (scoped to the specific action that was requested) */
  private approvalStore = new Map<string, { tool: string; mode: 'once' | 'always'; expires_at: number }>();

  /** Random nonce generated at startup — required for approval endpoint authentication */
  private readonly approvalNonce: string = randomBytes(16).toString('hex');

  private currentTier: TrustTier = 'unknown';
  private admissionResult: AdmissionResult | null = null;

  /** Notification config for approval gates (SMS, webhook, email) */
  private notificationConfig: NotificationConfig | null = null;

  /** HTTP transport mode: pending response resolvers keyed by JSON-RPC id */
  private pendingResponses = new Map<string | number, {
    resolve: (response: string) => void;
    timeout: ReturnType<typeof setTimeout>;
  }>();
  private httpMode = false;

  /** Loaded Cedar policy set (when policy_engine is "cedar") */
  private cedarPolicySet: CedarPolicySet | null = null;

  constructor(config: ProtectConfig) {
    this.config = config;
    this.logFilePath = join(process.cwd(), LOG_FILE);
    this.receiptFilePath = join(process.cwd(), RECEIPTS_FILE);
    this.evidenceStore = new EvidenceStore();
    this.receiptBuffer = new ReceiptBuffer();
    this.notificationConfig = parseNotificationConfigFromEnv();
  }

  /**
   * Set the Cedar policy set for local evaluation.
   * Called during CLI startup when --cedar flag is used.
   */
  setCedarPolicies(policySet: CedarPolicySet): void {
    this.cedarPolicySet = policySet;
  }

  async start(): Promise<void> {
    const { command, args, verbose } = this.config;
    const mode = this.config.enforce ? 'enforce' : 'shadow';

    if (verbose) {
      this.log(`Starting gateway in ${mode} mode`);
      this.log(`Wrapping: ${command} ${args.join(' ')}`);
      if (this.config.policy) {
        this.log(`Policy digest: ${this.config.policyDigest}`);
      }
      if (isSigningEnabled()) {
        this.log('Signing: enabled (receipts will be signed)');
      }
      if (this.config.credentials) {
        const labels = Object.keys(this.config.credentials);
        this.log(`Credential vault: ${labels.length} credential(s) configured [${labels.join(', ')}]`);
      }
      if (this.config.policy?.policy_engine === 'external' || this.config.policy?.policy_engine === 'hybrid') {
        this.log(`External PDP: ${this.config.policy.external?.endpoint || 'not configured'}`);
      }
    }

    // Log approval nonce (required for POST /approve authentication)
    this.log(`Approval nonce: ${this.approvalNonce}`);

    // Start HTTP status server (best-effort, don't crash if port is taken)
    const httpPort = parseInt(process.env.PROTECT_MCP_HTTP_PORT || '9876', 10);
    if (httpPort > 0) {
      try {
        startStatusServer(
          { port: httpPort, mode: mode as 'shadow' | 'enforce', verbose },
          this.receiptBuffer,
          this.approvalStore,
          this.approvalNonce,
        );
      } catch {
        if (verbose) this.log(`HTTP status server could not start on port ${httpPort}`);
      }
    }

    // Build child process env with credential injection (inject: "env")
    const childEnv = { ...process.env };
    if (this.config.credentials) {
      for (const [label, credConfig] of Object.entries(this.config.credentials)) {
        if (credConfig.inject === 'env' && credConfig.name && credConfig.value_env) {
          const envValue = process.env[credConfig.value_env];
          if (envValue) {
            childEnv[credConfig.name] = envValue;
            if (verbose) this.log(`Credential "${label}": injected as env var "${credConfig.name}"`);
          }
        }
      }
    }

    this.child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], env: childEnv });

    if (!this.child.stdin || !this.child.stdout || !this.child.stderr) {
      throw new Error('Failed to create pipes to child process');
    }

    this.child.stderr.on('data', (data: Buffer) => { process.stderr.write(data); });

    const childReader = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    childReader.on('line', (line: string) => { this.handleServerMessage(line); });

    this.clientReader = createInterface({ input: process.stdin, crlfDelay: Infinity });
    this.clientReader.on('line', (line: string) => { this.handleClientMessage(line); });

    this.child.on('exit', (code, signal) => {
      if (verbose) this.log(`Child process exited (code=${code}, signal=${signal})`);
      this.evidenceStore.save();
      process.exit(code ?? 1);
    });

    this.child.on('error', (err) => {
      this.log(`Child process error: ${err.message}`);
      process.exit(1);
    });

    process.on('SIGINT', () => this.stop());
    process.on('SIGTERM', () => this.stop());

    process.stdin.on('end', () => {
      if (verbose) this.log('Client stdin closed, closing child stdin');
      if (this.child?.stdin?.writable) this.child.stdin.end();
    });
  }

  setManifest(manifest: ManifestPresentation | null): AdmissionResult {
    this.admissionResult = evaluateTier(manifest, { evidenceStore: this.evidenceStore });
    this.currentTier = this.admissionResult.tier;
    if (this.config.verbose) {
      this.log(`Admission: tier=${this.currentTier} agent=${this.admissionResult.agent_id || 'none'}`);
    }
    return this.admissionResult;
  }

  private handleClientMessage(raw: string): void {
    const trimmed = raw.trim();
    if (!trimmed) return;

    let message: JsonRpcRequest;
    try { message = JSON.parse(trimmed); } catch { this.sendToChild(trimmed); return; }

    if (message.method === 'tools/call' && message.id !== undefined) {
      this.interceptToolCallAsync(message, trimmed);
      return;
    }
    this.sendToChild(trimmed);
  }

  private async interceptToolCallAsync(request: JsonRpcRequest, raw: string): Promise<void> {
    const result = await this.interceptToolCall(request);
    if (result) {
      this.sendToClient(JSON.stringify(result));
    } else {
      const modified = this.injectParamsCredentials(request);
      this.sendToChild(JSON.stringify(modified));
    }
  }

  private handleServerMessage(raw: string): void {
    this.sendToClient(raw);
  }

  private injectParamsCredentials(request: JsonRpcRequest): JsonRpcRequest {
    if (!this.config.credentials) return request;
    const injections: Record<string, string> = {};
    for (const [label, credConfig] of Object.entries(this.config.credentials)) {
      if (credConfig.inject === 'header' || credConfig.inject === 'query') {
        const cred = resolveCredential(label, this.config.credentials);
        if (cred.resolved && cred.value && cred.name) {
          injections[cred.name] = cred.value;
        }
      }
    }
    if (Object.keys(injections).length === 0) return request;
    return { ...request, params: { ...request.params, _credentials: injections } };
  }

  private async interceptToolCall(request: JsonRpcRequest): Promise<JsonRpcResponse | null> {
    const toolName = (request.params?.name as string) || 'unknown';
    const requestId = randomUUID().slice(0, 12);
    const mode = this.config.enforce ? 'enforce' : 'shadow';

    // ── Multi-agent resolution ──
    // When multi-agent mode is enabled, resolve the calling agent's kid
    // and apply agent-specific policy overrides.
    let resolvedAgentKid = this.admissionResult?.agent_id;
    let effectiveToolPolicy: ToolPolicy;

    if (this.config.multiAgent?.enabled) {
      // Extract kid from request params (set by SDK wrappers)
      const paramKid = request.params?._passport_kid as string | undefined;
      if (paramKid) resolvedAgentKid = paramKid;

      // Check for agent-specific policy overrides
      const agentOverrides = resolvedAgentKid
        ? this.config.multiAgent.agentPolicies?.[resolvedAgentKid]
        : undefined;

      if (agentOverrides && agentOverrides[toolName]) {
        // Merge: agent-specific overrides take precedence
        effectiveToolPolicy = { ...getToolPolicy(toolName, this.config.policy), ...agentOverrides[toolName] };
      } else if (!resolvedAgentKid && this.config.multiAgent.unknownAgentPolicy === 'deny') {
        // Unknown agent + deny policy
        this.emitDecisionLog({ tool: toolName, decision: 'deny', reason_code: 'unknown_agent_denied', request_id: requestId, tier: this.currentTier });
        if (this.config.enforce) {
          return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" denied: unidentified agent`);
        }
        return null;
      } else {
        effectiveToolPolicy = getToolPolicy(toolName, this.config.policy);
      }

      if (this.config.verbose && resolvedAgentKid) {
        this.log(`Multi-agent: resolved kid=${resolvedAgentKid} for tool=${toolName}`);
      }
    } else {
      effectiveToolPolicy = getToolPolicy(toolName, this.config.policy);
    }

    const toolPolicy = effectiveToolPolicy;

    let credentialRef: string | undefined;
    if (this.config.credentials) {
      const cred = resolveCredential(toolName, this.config.credentials);
      if (cred.resolved) {
        credentialRef = cred.label;
      } else if (cred.error && !cred.error.includes('not configured')) {
        this.emitDecisionLog({ tool: toolName, decision: 'deny', reason_code: 'credential_error', request_id: requestId, tier: this.currentTier, credential_ref: toolName });
        if (this.config.enforce) {
          return this.makeErrorResponse(request.id, -32600, `Credential error for tool "${toolName}"`);
        }
      }
    }

    // Check Cedar local evaluation if configured
    if (this.config.policy?.policy_engine === 'cedar' && this.cedarPolicySet) {
      try {
        const cedarDecision = await evaluateCedar(this.cedarPolicySet, {
          tool: toolName,
          tier: this.currentTier,
          agentId: this.admissionResult?.agent_id,
        });
        if (!cedarDecision.allowed) {
          const reason = cedarDecision.reason || 'cedar_deny';
          this.emitDecisionLog({ tool: toolName, decision: 'deny', reason_code: reason, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });
          if (this.config.enforce) {
            return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" denied by Cedar policy`);
          }
          return null;
        }
        // Cedar allowed — emit allow log and continue
        this.emitDecisionLog({ tool: toolName, decision: 'allow', reason_code: 'cedar_allow', request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });
        return null;
      } catch (err) {
        if (this.config.verbose) this.log(`Cedar evaluation error: ${err instanceof Error ? err.message : err}`);
        // Fall through to built-in policy on Cedar errors
      }
    }

    // Check external PDP if configured (BYOPE)
    if (this.config.policy?.external && (this.config.policy.policy_engine === 'external' || this.config.policy.policy_engine === 'hybrid')) {
      try {
        const ctx = buildDecisionContext(toolName, this.currentTier, {
          agentId: this.admissionResult?.agent_id,
          manifestHash: this.admissionResult?.manifest_hash,
          credentialRef, mode: mode as 'shadow' | 'enforce', slug: this.config.slug,
        });
        const externalDecision = await queryExternalPDP(ctx, this.config.policy.external);
        if (!externalDecision.allowed) {
          const reason = `external_pdp_deny${externalDecision.reason ? ': ' + externalDecision.reason : ''}`;
          this.emitDecisionLog({ tool: toolName, decision: 'deny', reason_code: reason, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });
          if (this.config.enforce) {
            return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" denied by external policy engine`);
          }
          if (this.config.policy.policy_engine === 'external') return null;
        }
      } catch (err) {
        if (this.config.verbose) this.log(`External PDP error: ${err instanceof Error ? err.message : err}`);
      }
    }

    // Check minimum tier
    if (toolPolicy.min_tier) {
      if (!meetsMinTier(this.currentTier, toolPolicy.min_tier)) {
        this.emitDecisionLog({ tool: toolName, decision: 'deny', reason_code: 'tier_insufficient', request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });
        if (this.config.enforce) {
          return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" requires tier "${toolPolicy.min_tier}"`);
        }
        return null;
      }
    }

    // Check if blocked
    if (toolPolicy.block) {
      this.emitDecisionLog({ tool: toolName, decision: 'deny', reason_code: 'policy_block', request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });
      if (this.config.enforce) {
        return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" is blocked by policy`);
      }
      return null;
    }

    // Check if approval required (non-blocking: returns tool result, NOT error)
    if (toolPolicy.require_approval) {
      // Check if already approved by request_id (exact match to the action that was requested)
      const grant = this.approvalStore.get(requestId);
      // Also check for 'always' grants keyed by tool name
      const alwaysGrant = this.approvalStore.get(`always:${toolName}`);
      if ((grant && Date.now() < grant.expires_at) || (alwaysGrant && Date.now() < alwaysGrant.expires_at)) {
        // Consume 'once' grants
        if (grant && grant.mode === 'once') this.approvalStore.delete(requestId);
        this.emitDecisionLog({ tool: toolName, decision: 'allow', reason_code: 'approval_granted', request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });
        return null; // Allow through
      }

      this.emitDecisionLog({ tool: toolName, decision: 'require_approval', reason_code: 'requires_human_approval', request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });

      // Send notification (non-blocking — errors are logged, not thrown)
      if (this.notificationConfig) {
        sendApprovalNotification(this.notificationConfig, {
          requestId,
          toolName,
          agentId: this.admissionResult?.agentId,
          policyName: this.config.policy?.name || 'default',
          reason: `Policy requires human approval for "${toolName}"`,
          traceUrl: `https://scopeblind.com/trace`,
          approveUrl: undefined, // Approve URL provided when HTTP transport is active
          timestamp: new Date().toISOString(),
        }).catch(() => {}); // Fire and forget
      }

      if (this.config.enforce) {
        // Return a tool result (not an error) so the LLM can gracefully handle it.
        // MCP JSON-RPC is synchronous — blocking here would crash the LLM connection.
        return {
          jsonrpc: '2.0',
          id: request.id,
          result: {
            content: [
              {
                type: 'text',
                text: `REQUIRES_APPROVAL: The tool "${toolName}" requires human approval before execution. ` +
                  `Request ID: ${requestId}. Approval nonce: ${this.approvalNonce}. ` +
                  `Tell the user you need their approval to use "${toolName}" and will retry when granted. ` +
                  `Do NOT retry this tool call until the user explicitly approves it.`,
              },
            ],
            isError: true,
          },
        };
      }
      return null;
    }

    // Check rate limit
    const rateSpec = this.getTierRateLimit(toolPolicy, this.currentTier);
    if (rateSpec) {
      try {
        const limit = parseRateLimit(rateSpec);
        const key = `tool:${toolName}:${this.currentTier}`;
        const { allowed, remaining } = checkRateLimit(key, limit, this.rateLimitStore);
        if (!allowed) {
          this.emitDecisionLog({ tool: toolName, decision: 'deny', reason_code: 'rate_limit_exceeded', request_id: requestId, rate_limit_remaining: 0, tier: this.currentTier, credential_ref: credentialRef });
          if (this.config.enforce) {
            return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" rate limit exceeded (${rateSpec})`);
          }
          return null;
        }
        this.emitDecisionLog({ tool: toolName, decision: 'allow', reason_code: 'policy_allow', request_id: requestId, rate_limit_remaining: remaining, tier: this.currentTier, credential_ref: credentialRef });
      } catch {
        this.emitDecisionLog({ tool: toolName, decision: 'allow', reason_code: 'default_allow', request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });
      }
    } else {
      const reasonCode = this.config.enforce ? 'policy_allow' : 'observe_mode';
      this.emitDecisionLog({ tool: toolName, decision: 'allow', reason_code: reasonCode, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef });
    }

    return null;
  }

  private getTierRateLimit(policy: ToolPolicy, tier: TrustTier): string | undefined {
    if (policy.rate_limits && policy.rate_limits[tier]) {
      const tierLimit = policy.rate_limits[tier]!;
      return `${tierLimit.max}/${tierLimit.window}`;
    }
    return policy.rate_limit;
  }

  /**
   * Emit a decision log entry with OTel-compatible trace IDs and optional
   * signed receipt generation.
   *
   * @patent Patent-protected construction — decision receipts with configurable
   * disclosure and issuer-blind properties. Covered by Apache 2.0 patent grant
   * for users of this code. Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  private emitDecisionLog(entry: Partial<DecisionLog>): void {
    const mode = this.config.enforce ? 'enforce' : 'shadow';
    // Generate OTel-compatible trace and span IDs
    const otelTraceId = entry.otel_trace_id || randomBytes(16).toString('hex'); // 32 hex chars
    const otelSpanId = entry.otel_span_id || randomBytes(8).toString('hex');    // 16 hex chars

    const log: DecisionLog = {
      v: 2, tool: entry.tool || 'unknown', decision: entry.decision || 'allow',
      reason_code: entry.reason_code || 'default_allow',
      policy_digest: this.config.policyDigest,
      policy_engine: this.config.policy?.policy_engine || 'built-in',
      request_id: entry.request_id || randomUUID().slice(0, 12),
      timestamp: Date.now(), mode: mode as 'shadow' | 'enforce',
      ...(entry.rate_limit_remaining !== undefined && { rate_limit_remaining: entry.rate_limit_remaining }),
      ...(entry.tier && { tier: entry.tier }),
      ...(entry.credential_ref && { credential_ref: entry.credential_ref }),
      otel_trace_id: otelTraceId,
      otel_span_id: otelSpanId,
    };

    process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}\n`);

    try { appendFileSync(this.logFilePath, JSON.stringify(log) + '\n'); } catch { /* best-effort */ }

    if (isSigningEnabled()) {
      const signed = signDecision(log);
      if (signed.signed) {
        process.stderr.write(`[PROTECT_MCP_RECEIPT] ${signed.signed}\n`);
        try { appendFileSync(this.receiptFilePath, signed.signed + '\n'); } catch { /* best-effort */ }
        // Feed to HTTP receipt buffer
        this.receiptBuffer.add(log.request_id, signed.signed);
        // Record in evidence store
        if (this.admissionResult?.agent_id) {
          this.evidenceStore.record(this.admissionResult.agent_id, this.config.signing?.issuer || 'protect-mcp');
          if (this.evidenceStore.getSummary(this.admissionResult.agent_id).receipt_count % 10 === 0) {
            this.evidenceStore.save();
          }
        }
      } else if (signed.warning) {
        process.stderr.write(`[PROTECT_MCP] Warning: ${signed.warning}\n`);
      }
    }
  }

  private makeErrorResponse(id: string | number, code: number, message: string): JsonRpcResponse {
    return { jsonrpc: '2.0', id, error: { code, message } };
  }

  private sendToChild(message: string): void {
    if (this.child?.stdin?.writable) this.child.stdin.write(message + '\n');
  }

  private sendToClient(message: string): void {
    if (this.httpMode) {
      // In HTTP mode, resolve pending response promises instead of writing to stdout
      try {
        const parsed = JSON.parse(message);
        if (parsed.id !== undefined && parsed.id !== null) {
          const pending = this.pendingResponses.get(parsed.id);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingResponses.delete(parsed.id);
            pending.resolve(message);
            return;
          }
        }
      } catch { /* not JSON, ignore */ }
    }
    process.stdout.write(message + '\n');
  }

  /**
   * Enable HTTP transport mode.
   * In this mode, sendToClient resolves pending promises instead of
   * writing to stdout, and start() skips stdin reading.
   */
  enableHttpMode(): void {
    this.httpMode = true;
  }

  /**
   * Start in HTTP mode — spawns child process but does NOT read from
   * process.stdin. Requests come in via processRequest() instead.
   */
  async startForHttp(): Promise<void> {
    this.httpMode = true;

    const { command, args, verbose } = this.config;
    const mode = this.config.enforce ? 'enforce' : 'shadow';

    if (verbose) {
      this.log(`Starting gateway in ${mode} mode (HTTP transport)`);
      this.log(`Wrapping: ${command} ${args.join(' ')}`);
    }

    this.log(`Approval nonce: ${this.approvalNonce}`);

    // Build child process env with credential injection
    const childEnv = { ...process.env };
    if (this.config.credentials) {
      for (const [label, credConfig] of Object.entries(this.config.credentials)) {
        if (credConfig.inject === 'env' && credConfig.name && credConfig.value_env) {
          const envValue = process.env[credConfig.value_env];
          if (envValue) {
            childEnv[credConfig.name] = envValue;
            if (verbose) this.log(`Credential "${label}": injected as env var "${credConfig.name}"`);
          }
        }
      }
    }

    this.child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], env: childEnv });

    if (!this.child.stdin || !this.child.stdout || !this.child.stderr) {
      throw new Error('Failed to create pipes to child process');
    }

    this.child.stderr.on('data', (data: Buffer) => { process.stderr.write(data); });

    const childReader = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    childReader.on('line', (line: string) => { this.handleServerMessage(line); });

    // Do NOT read from process.stdin in HTTP mode

    this.child.on('exit', (code, signal) => {
      if (verbose) this.log(`Child process exited (code=${code}, signal=${signal})`);
      this.evidenceStore.save();
    });

    this.child.on('error', (err) => {
      this.log(`Child process error: ${err.message}`);
    });
  }

  /**
   * Process a JSON-RPC request programmatically (for HTTP transport).
   * Returns a promise that resolves with the JSON-RPC response string.
   */
  async processRequest(jsonRpc: JsonRpcRequest): Promise<string> {
    const REQUEST_TIMEOUT_MS = 30_000;

    // If it's a tools/call, run through policy interception first
    if (jsonRpc.method === 'tools/call' && jsonRpc.id !== undefined) {
      const blocked = await this.interceptToolCall(jsonRpc);
      if (blocked) {
        return JSON.stringify(blocked);
      }
    }

    // Forward to child and wait for response
    return new Promise<string>((resolve, reject) => {
      const id = jsonRpc.id;
      if (id === undefined || id === null) {
        // Notifications don't expect responses
        const modified = this.injectParamsCredentials(jsonRpc);
        this.sendToChild(JSON.stringify(modified));
        resolve(JSON.stringify({ jsonrpc: '2.0', result: {}, id: null }));
        return;
      }

      const timeout = setTimeout(() => {
        this.pendingResponses.delete(id);
        resolve(JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Request timeout (30s)' },
          id,
        }));
      }, REQUEST_TIMEOUT_MS);

      this.pendingResponses.set(id, { resolve, timeout });

      // Forward (with credential injection) to child
      const modified = this.injectParamsCredentials(jsonRpc);
      this.sendToChild(JSON.stringify(modified));
    });
  }

  private log(message: string): void {
    process.stderr.write(`[PROTECT_MCP] ${message}\n`);
  }

  stop(): void {
    this.evidenceStore.save();
    if (this.clientReader) this.clientReader.close();
    if (this.child) { this.child.kill('SIGTERM'); this.child = null; }
    process.exit(0);
  }
}
