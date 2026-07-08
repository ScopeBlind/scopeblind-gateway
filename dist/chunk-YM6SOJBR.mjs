import {
  ReceiptBuffer,
  buildActionReadback,
  checkRateLimit,
  getToolPolicy,
  isSigningEnabled,
  parseRateLimit,
  signDecision,
  startStatusServer
} from "./chunk-G6X763MH.mjs";
import {
  evaluateCedar
} from "./chunk-MWXDXYWH.mjs";

// src/evidence-store.ts
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
var DEFAULT_THRESHOLDS = {
  min_receipts: 10,
  min_epoch_span: 3,
  min_issuers: 2
};
var EvidenceStore = class {
  agents = /* @__PURE__ */ new Map();
  filePath;
  dirty = false;
  constructor(dir) {
    this.filePath = join(dir || process.cwd(), ".protect-mcp-evidence.json");
    this.load();
  }
  /**
   * Record a receipt observation for an agent.
   */
  record(agentId, issuer, timestamp) {
    const ts = timestamp || (/* @__PURE__ */ new Date()).toISOString();
    const epochHour = Math.floor(new Date(ts).getTime() / (3600 * 1e3));
    const existing = this.agents.get(agentId);
    const observation = {
      issuer,
      timestamp: ts,
      epoch_hour: epochHour
    };
    if (existing) {
      existing.receipts.push(observation);
      existing.last_seen = ts;
      if (existing.receipts.length > 200) {
        existing.receipts = existing.receipts.slice(-200);
      }
    } else {
      this.agents.set(agentId, {
        agent_id: agentId,
        receipts: [observation],
        first_seen: ts,
        last_seen: ts
      });
    }
    this.dirty = true;
  }
  /**
   * Get the evidence summary for an agent.
   */
  getSummary(agentId) {
    const record = this.agents.get(agentId);
    if (!record || record.receipts.length === 0) {
      return { receipt_count: 0, epoch_span: 0, issuer_count: 0 };
    }
    const uniqueIssuers = new Set(record.receipts.map((r) => r.issuer));
    const uniqueEpochs = new Set(record.receipts.map((r) => r.epoch_hour));
    return {
      receipt_count: record.receipts.length,
      epoch_span: uniqueEpochs.size,
      issuer_count: uniqueIssuers.size
    };
  }
  /**
   * Check if an agent meets the evidenced tier thresholds.
   */
  meetsEvidencedThreshold(agentId, thresholds = DEFAULT_THRESHOLDS) {
    const summary = this.getSummary(agentId);
    return summary.receipt_count >= thresholds.min_receipts && summary.epoch_span >= thresholds.min_epoch_span && summary.issuer_count >= thresholds.min_issuers;
  }
  /**
   * Persist to disk (call periodically or on shutdown).
   */
  save() {
    if (!this.dirty) return;
    const data = {};
    for (const [id, record] of this.agents) {
      data[id] = record;
    }
    try {
      writeFileSync(this.filePath, JSON.stringify({ v: 1, agents: data }, null, 2) + "\n");
      this.dirty = false;
    } catch {
    }
  }
  /**
   * Load from disk.
   */
  load() {
    if (!existsSync(this.filePath)) return;
    try {
      const raw = readFileSync(this.filePath, "utf-8");
      const parsed = JSON.parse(raw);
      if (parsed.agents && typeof parsed.agents === "object") {
        for (const [id, record] of Object.entries(parsed.agents)) {
          this.agents.set(id, record);
        }
      }
    } catch {
    }
  }
  /**
   * Get total agent count (for status display).
   */
  agentCount() {
    return this.agents.size;
  }
  /**
   * Get all agent summaries (for status display).
   */
  allSummaries() {
    const result = [];
    for (const [id] of this.agents) {
      result.push({ agent_id: id, summary: this.getSummary(id) });
    }
    return result;
  }
};

// src/admission.ts
function evaluateTier(manifest, opts) {
  const options = opts && ("evidenceStore" in opts || "overrides" in opts || "thresholds" in opts) ? opts : { overrides: opts };
  const { overrides, evidenceStore, thresholds } = options;
  if (!manifest) {
    return {
      tier: "unknown",
      reason: "no_manifest_presented"
    };
  }
  if (overrides && manifest.agent_id && overrides[manifest.agent_id]) {
    return {
      tier: overrides[manifest.agent_id],
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: "operator_override"
    };
  }
  if (manifest.signature_valid === false) {
    return {
      tier: "unknown",
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: "invalid_manifest_signature"
    };
  }
  if (manifest.signature_valid === true) {
    if (manifest.evidence_summary) {
      const es = manifest.evidence_summary;
      const t = thresholds || DEFAULT_THRESHOLDS;
      if (es.receipt_count >= t.min_receipts && es.epoch_span >= t.min_epoch_span && es.issuer_count >= t.min_issuers) {
        return {
          tier: "evidenced",
          agent_id: manifest.agent_id,
          manifest_hash: manifest.manifest_hash,
          reason: "evidence_threshold_met"
        };
      }
    }
    if (evidenceStore && manifest.agent_id) {
      if (evidenceStore.meetsEvidencedThreshold(manifest.agent_id, thresholds)) {
        return {
          tier: "evidenced",
          agent_id: manifest.agent_id,
          manifest_hash: manifest.manifest_hash,
          reason: "evidence_store_threshold_met"
        };
      }
    }
    return {
      tier: "signed-known",
      agent_id: manifest.agent_id,
      manifest_hash: manifest.manifest_hash,
      reason: "valid_signed_manifest"
    };
  }
  return {
    tier: "unknown",
    agent_id: manifest.agent_id,
    manifest_hash: manifest.manifest_hash,
    reason: "manifest_unverified"
  };
}
function meetsMinTier(actual, required) {
  const order = ["unknown", "signed-known", "evidenced", "privileged"];
  return order.indexOf(actual) >= order.indexOf(required);
}

// src/credentials.ts
function resolveCredential(label, credentials) {
  if (!credentials || !credentials[label]) {
    return {
      resolved: false,
      label,
      error: `credential "${label}" not configured`
    };
  }
  const config = credentials[label];
  const value = process.env[config.value_env];
  if (!value) {
    return {
      resolved: false,
      label,
      error: `environment variable "${config.value_env}" for credential "${label}" is not set`
    };
  }
  return {
    resolved: true,
    label,
    value,
    inject: config.inject,
    name: config.name
  };
}
function listCredentialLabels(credentials) {
  if (!credentials) return [];
  return Object.keys(credentials);
}
function validateCredentials(credentials) {
  const warnings = [];
  if (!credentials) return warnings;
  for (const [label, config] of Object.entries(credentials)) {
    if (!config.value_env) {
      warnings.push(`credential "${label}": missing value_env`);
      continue;
    }
    if (!config.inject) {
      warnings.push(`credential "${label}": missing inject type`);
      continue;
    }
    if (!process.env[config.value_env]) {
      warnings.push(`credential "${label}": env var "${config.value_env}" not set`);
    }
  }
  return warnings;
}

// src/external-pdp.ts
async function queryExternalPDP(context, config) {
  const timeout = config.timeout_ms || 500;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const body = formatRequest(context, config.format || "generic");
    const response = await fetch(config.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!response.ok) {
      return fallbackDecision(config, `PDP returned HTTP ${response.status}`);
    }
    const result = await response.json();
    return parseResponse(result, config.format || "generic");
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      return fallbackDecision(config, `PDP timeout after ${timeout}ms`);
    }
    return fallbackDecision(config, `PDP error: ${err instanceof Error ? err.message : "unknown"}`);
  }
}
function formatRequest(context, format) {
  switch (format) {
    case "opa":
      return {
        input: {
          actor: context.actor,
          action: context.action,
          target: context.target,
          credential_ref: context.credential_ref,
          mode: context.mode,
          metadata: context.request_metadata
        }
      };
    case "cerbos":
      return {
        principal: {
          id: context.actor.id || "unknown",
          roles: [context.actor.tier],
          attr: {
            manifest_hash: context.actor.manifest_hash
          }
        },
        resource: {
          kind: "tool",
          id: context.action.tool,
          attr: context.target
        },
        actions: [context.action.operation || "call"]
      };
    case "cedar":
      return {
        principal: {
          type: "Agent",
          id: context.actor.id || "unknown"
        },
        action: {
          type: "Action",
          id: `MCP::Tool::${context.action.operation || "call"}`
        },
        resource: {
          type: "Tool",
          id: context.action.tool
        },
        context: {
          tier: context.actor.tier,
          manifest_hash: context.actor.manifest_hash || null,
          service: context.target.service || "default",
          mode: context.mode,
          credential_ref: context.credential_ref || null
        }
      };
    case "generic":
    default:
      return context;
  }
}
function parseResponse(result, format) {
  switch (format) {
    case "opa":
      if (typeof result.result === "boolean") {
        return { allowed: result.result };
      }
      if (result.result && typeof result.result === "object") {
        const r = result.result;
        return {
          allowed: Boolean(r.allow),
          reason: r.reason,
          metadata: r
        };
      }
      return { allowed: false, reason: "unrecognized OPA response" };
    case "cerbos":
      if (Array.isArray(result.results) && result.results.length > 0) {
        const actions = result.results[0].actions;
        if (actions) {
          const effect = Object.values(actions)[0];
          return { allowed: effect === "EFFECT_ALLOW" };
        }
      }
      return { allowed: false, reason: "unrecognized Cerbos response" };
    case "cedar":
      if (typeof result.decision === "string") {
        return {
          allowed: result.decision === "Allow",
          reason: result.decision === "Deny" ? `cedar_deny${result.diagnostics ? ": " + JSON.stringify(result.diagnostics) : ""}` : void 0,
          metadata: result.diagnostics
        };
      }
      if (Array.isArray(result.results) && result.results.length > 0) {
        const first = result.results[0];
        return {
          allowed: first.decision === "Allow",
          reason: first.decision === "Deny" ? "cedar_deny" : void 0
        };
      }
      return { allowed: false, reason: "unrecognized Cedar response" };
    case "generic":
    default:
      return {
        allowed: Boolean(result.allowed),
        reason: result.reason,
        metadata: result.metadata
      };
  }
}
function fallbackDecision(config, reason) {
  const fallback = config.fallback || "deny";
  return {
    allowed: fallback === "allow",
    reason: `fallback_${fallback}: ${reason}`
  };
}
function buildDecisionContext(toolName, tier, opts) {
  return {
    v: 1,
    actor: {
      id: opts.agentId,
      tier,
      manifest_hash: opts.manifestHash
    },
    action: {
      tool: toolName,
      operation: "call"
    },
    target: {
      service: opts.slug || "default"
    },
    credential_ref: opts.credentialRef,
    mode: opts.mode,
    request_metadata: opts.requestMetadata || {}
  };
}

// src/notifications.ts
async function sendApprovalNotification(config, notification) {
  const promises = [];
  if (config.sms) {
    promises.push(sendSms(config.sms, notification));
  }
  if (config.webhook) {
    promises.push(sendWebhook(config.webhook, notification));
  }
  if (config.email) {
    promises.push(sendEmail(config.email, notification));
  }
  const results = await Promise.allSettled(promises);
  for (const result of results) {
    if (result.status === "rejected") {
      console.error(`[protect-mcp] Notification failed: ${result.reason}`);
    }
  }
}
async function sendSms(config, notification) {
  const body = [
    `\u{1F512} Approval Required`,
    `Tool: ${notification.toolName}`,
    notification.agentId ? `Agent: ${notification.agentId}` : null,
    `Reason: ${notification.reason}`,
    notification.approveUrl ? `Approve: ${notification.approveUrl}` : null,
    notification.traceUrl ? `Trace: ${notification.traceUrl}` : null
  ].filter(Boolean).join("\n");
  const params = new URLSearchParams({
    To: config.to,
    From: config.from,
    Body: body
  });
  const response = await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${config.accountSid}/Messages.json`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${config.accountSid}:${config.authToken}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params.toString()
    }
  );
  if (!response.ok) {
    throw new Error(`Twilio SMS failed: ${response.status} ${await response.text()}`);
  }
}
async function sendWebhook(config, notification) {
  let payload;
  if (config.template === "slack") {
    payload = {
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: "\u{1F512} Agent Approval Required" }
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Tool:*
\`${notification.toolName}\`` },
            { type: "mrkdwn", text: `*Agent:*
${notification.agentId || "unknown"}` },
            { type: "mrkdwn", text: `*Policy:*
${notification.policyName || "default"}` },
            { type: "mrkdwn", text: `*Time:*
${notification.timestamp}` }
          ]
        },
        {
          type: "section",
          text: { type: "mrkdwn", text: `*Reason:* ${notification.reason}` }
        },
        ...notification.approveUrl || notification.traceUrl ? [
          {
            type: "actions",
            elements: [
              ...notification.approveUrl ? [{ type: "button", text: { type: "plain_text", text: "\u2705 Approve" }, url: notification.approveUrl, style: "primary" }] : [],
              ...notification.traceUrl ? [{ type: "button", text: { type: "plain_text", text: "\u{1F50D} View Trace" }, url: notification.traceUrl }] : []
            ]
          }
        ] : []
      ]
    };
  } else if (config.template === "pagerduty") {
    payload = {
      routing_key: config.headers?.["X-Routing-Key"] || "",
      event_action: "trigger",
      payload: {
        summary: `Agent approval required: ${notification.toolName}`,
        source: "protect-mcp",
        severity: "warning",
        custom_details: {
          tool: notification.toolName,
          agent: notification.agentId,
          policy: notification.policyName,
          reason: notification.reason,
          trace_url: notification.traceUrl,
          approve_url: notification.approveUrl
        }
      }
    };
  } else {
    payload = notification;
  }
  const response = await fetch(config.url, {
    method: config.method || "POST",
    headers: {
      "Content-Type": "application/json",
      ...config.headers
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error(`Webhook failed: ${response.status}`);
  }
}
async function sendEmail(config, notification) {
  if (!config.resendApiKey) {
    console.warn("[protect-mcp] Email notification skipped: no resendApiKey configured");
    return;
  }
  const html = `
    <div style="font-family: monospace; padding: 20px; background: #0d1117; color: #c9d1d9; border-radius: 8px;">
      <h2 style="color: #10b981;">\u{1F512} Agent Approval Required</h2>
      <table style="font-size: 14px; margin: 16px 0;">
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Tool:</td><td>${notification.toolName}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Agent:</td><td>${notification.agentId || "unknown"}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Reason:</td><td>${notification.reason}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Time:</td><td>${notification.timestamp}</td></tr>
      </table>
      ${notification.approveUrl ? `<a href="${notification.approveUrl}" style="background: #10b981; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; margin-right: 8px;">\u2705 Approve</a>` : ""}
      ${notification.traceUrl ? `<a href="${notification.traceUrl}" style="background: #1f2937; color: #c9d1d9; padding: 8px 16px; border-radius: 6px; text-decoration: none; border: 1px solid #374151;">\u{1F50D} View Trace</a>` : ""}
    </div>
  `;
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.resendApiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "ScopeBlind <noreply@scopeblind.com>",
      to: config.to,
      subject: `\u{1F512} Approval required: ${notification.toolName}`,
      html
    })
  });
  if (!response.ok) {
    throw new Error(`Resend email failed: ${response.status}`);
  }
}
function parseNotificationConfigFromEnv() {
  const config = {};
  let hasConfig = false;
  const smsTo = process.env.SCOPEBLIND_SMS_TO;
  const twilioSid = process.env.TWILIO_ACCOUNT_SID;
  const twilioToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioFrom = process.env.TWILIO_FROM_NUMBER;
  if (smsTo && twilioSid && twilioToken && twilioFrom) {
    config.sms = { accountSid: twilioSid, authToken: twilioToken, from: twilioFrom, to: smsTo };
    hasConfig = true;
  }
  const webhookUrl = process.env.SCOPEBLIND_WEBHOOK_URL;
  if (webhookUrl) {
    config.webhook = {
      url: webhookUrl,
      template: process.env.SCOPEBLIND_WEBHOOK_TEMPLATE || "custom"
    };
    hasConfig = true;
  }
  const emailTo = process.env.SCOPEBLIND_EMAIL_TO;
  if (emailTo) {
    config.email = { to: emailTo, resendApiKey: process.env.RESEND_API_KEY };
    hasConfig = true;
  }
  return hasConfig ? config : null;
}

// src/gateway.ts
import { spawn } from "child_process";
import { randomUUID, randomBytes } from "crypto";
import { createInterface } from "readline";
import { appendFileSync } from "fs";
import { join as join2 } from "path";
var LOG_FILE = ".protect-mcp-log.jsonl";
var RECEIPTS_FILE = ".protect-mcp-receipts.jsonl";
var ProtectGateway = class {
  child = null;
  config;
  rateLimitStore = /* @__PURE__ */ new Map();
  clientReader = null;
  logFilePath;
  receiptFilePath;
  evidenceStore;
  receiptBuffer;
  /** Approval grants keyed by request_id (scoped to the specific action that was requested) */
  approvalStore = /* @__PURE__ */ new Map();
  /** Random nonce generated at startup — required for approval endpoint authentication */
  approvalNonce = randomBytes(16).toString("hex");
  currentTier = "unknown";
  admissionResult = null;
  /** Notification config for approval gates (SMS, webhook, email) */
  notificationConfig = null;
  /** HTTP transport mode: pending response resolvers keyed by JSON-RPC id */
  pendingResponses = /* @__PURE__ */ new Map();
  httpMode = false;
  /** Loaded Cedar policy set (when policy_engine is "cedar") */
  cedarPolicySet = null;
  constructor(config) {
    this.config = config;
    this.logFilePath = join2(process.cwd(), LOG_FILE);
    this.receiptFilePath = join2(process.cwd(), RECEIPTS_FILE);
    this.evidenceStore = new EvidenceStore();
    this.receiptBuffer = new ReceiptBuffer();
    this.notificationConfig = parseNotificationConfigFromEnv();
  }
  /**
   * Set the Cedar policy set for local evaluation.
   * Called during CLI startup when --cedar flag is used.
   */
  setCedarPolicies(policySet) {
    this.cedarPolicySet = policySet;
  }
  async start() {
    const { command, args, verbose } = this.config;
    const mode = this.config.enforce ? "enforce" : "shadow";
    if (verbose) {
      this.log(`Starting gateway in ${mode} mode`);
      this.log(`Wrapping: ${command} ${args.join(" ")}`);
      if (this.config.policy) {
        this.log(`Policy digest: ${this.config.policyDigest}`);
      }
      if (isSigningEnabled()) {
        this.log("Signing: enabled (receipts will be signed)");
      }
      if (this.config.credentials) {
        const labels = Object.keys(this.config.credentials);
        this.log(`Credential vault: ${labels.length} credential(s) configured [${labels.join(", ")}]`);
      }
      if (this.config.policy?.policy_engine === "external" || this.config.policy?.policy_engine === "hybrid") {
        this.log(`External PDP: ${this.config.policy.external?.endpoint || "not configured"}`);
      }
    }
    this.log(`Approval nonce: ${this.approvalNonce}`);
    const httpPort = parseInt(process.env.PROTECT_MCP_HTTP_PORT || "9876", 10);
    if (httpPort > 0) {
      try {
        startStatusServer(
          { port: httpPort, mode, verbose },
          this.receiptBuffer,
          this.approvalStore,
          this.approvalNonce
        );
      } catch {
        if (verbose) this.log(`HTTP status server could not start on port ${httpPort}`);
      }
    }
    const childEnv = { ...process.env };
    if (this.config.credentials) {
      for (const [label, credConfig] of Object.entries(this.config.credentials)) {
        if (credConfig.inject === "env" && credConfig.name && credConfig.value_env) {
          const envValue = process.env[credConfig.value_env];
          if (envValue) {
            childEnv[credConfig.name] = envValue;
            if (verbose) this.log(`Credential "${label}": injected as env var "${credConfig.name}"`);
          }
        }
      }
    }
    this.child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"], env: childEnv });
    if (!this.child.stdin || !this.child.stdout || !this.child.stderr) {
      throw new Error("Failed to create pipes to child process");
    }
    this.child.stderr.on("data", (data) => {
      process.stderr.write(data);
    });
    const childReader = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    childReader.on("line", (line) => {
      this.handleServerMessage(line);
    });
    this.clientReader = createInterface({ input: process.stdin, crlfDelay: Infinity });
    this.clientReader.on("line", (line) => {
      this.handleClientMessage(line);
    });
    this.child.on("exit", (code, signal) => {
      if (verbose) this.log(`Child process exited (code=${code}, signal=${signal})`);
      this.evidenceStore.save();
      process.exit(code ?? 1);
    });
    this.child.on("error", (err) => {
      this.log(`Child process error: ${err.message}`);
      process.exit(1);
    });
    process.on("SIGINT", () => this.stop());
    process.on("SIGTERM", () => this.stop());
    process.stdin.on("end", () => {
      if (verbose) this.log("Client stdin closed, closing child stdin");
      if (this.child?.stdin?.writable) this.child.stdin.end();
    });
  }
  setManifest(manifest) {
    this.admissionResult = evaluateTier(manifest, { evidenceStore: this.evidenceStore });
    this.currentTier = this.admissionResult.tier;
    if (this.config.verbose) {
      this.log(`Admission: tier=${this.currentTier} agent=${this.admissionResult.agent_id || "none"}`);
    }
    return this.admissionResult;
  }
  handleClientMessage(raw) {
    const trimmed = raw.trim();
    if (!trimmed) return;
    let message;
    try {
      message = JSON.parse(trimmed);
    } catch {
      this.sendToChild(trimmed);
      return;
    }
    if (message.method === "tools/call" && message.id !== void 0) {
      this.interceptToolCallAsync(message, trimmed);
      return;
    }
    this.sendToChild(trimmed);
  }
  async interceptToolCallAsync(request, raw) {
    const result = await this.interceptToolCall(request);
    if (result) {
      this.sendToClient(JSON.stringify(result));
    } else {
      const modified = this.injectParamsCredentials(request);
      this.sendToChild(JSON.stringify(modified));
    }
  }
  handleServerMessage(raw) {
    this.sendToClient(raw);
  }
  injectParamsCredentials(request) {
    if (!this.config.credentials) return request;
    const injections = {};
    for (const [label, credConfig] of Object.entries(this.config.credentials)) {
      if (credConfig.inject === "header" || credConfig.inject === "query") {
        const cred = resolveCredential(label, this.config.credentials);
        if (cred.resolved && cred.value && cred.name) {
          injections[cred.name] = cred.value;
        }
      }
    }
    if (Object.keys(injections).length === 0) return request;
    return { ...request, params: { ...request.params, _credentials: injections } };
  }
  async interceptToolCall(request) {
    const toolName = request.params?.name || "unknown";
    const requestId = randomUUID().slice(0, 12);
    const mode = this.config.enforce ? "enforce" : "shadow";
    const toolInput = request.params?.arguments && typeof request.params.arguments === "object" ? request.params.arguments : request.params || {};
    const actionReadback = buildActionReadback(toolName, toolInput);
    let resolvedAgentKid = this.admissionResult?.agent_id;
    let effectiveToolPolicy;
    if (this.config.multiAgent?.enabled) {
      const paramKid = request.params?._passport_kid;
      if (paramKid) resolvedAgentKid = paramKid;
      const agentOverrides = resolvedAgentKid ? this.config.multiAgent.agentPolicies?.[resolvedAgentKid] : void 0;
      if (agentOverrides && agentOverrides[toolName]) {
        effectiveToolPolicy = { ...getToolPolicy(toolName, this.config.policy), ...agentOverrides[toolName] };
      } else if (!resolvedAgentKid && this.config.multiAgent.unknownAgentPolicy === "deny") {
        this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "unknown_agent_denied", request_id: requestId, tier: this.currentTier, action_readback: actionReadback });
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
    let credentialRef;
    if (this.config.credentials) {
      const cred = resolveCredential(toolName, this.config.credentials);
      if (cred.resolved) {
        credentialRef = cred.label;
      } else if (cred.error && !cred.error.includes("not configured")) {
        this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "credential_error", request_id: requestId, tier: this.currentTier, credential_ref: toolName, action_readback: actionReadback });
        if (this.config.enforce) {
          return this.makeErrorResponse(request.id, -32600, `Credential error for tool "${toolName}"`);
        }
      }
    }
    if (this.config.policy?.policy_engine === "cedar" && this.cedarPolicySet) {
      try {
        const cedarDecision = await evaluateCedar(this.cedarPolicySet, {
          tool: toolName,
          tier: this.currentTier,
          agentId: this.admissionResult?.agent_id
        });
        if (!cedarDecision.allowed) {
          const reason = cedarDecision.reason || "cedar_deny";
          this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: reason, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
          if (this.config.enforce) {
            return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" denied by Cedar policy`);
          }
          return null;
        }
        this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: "cedar_allow", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
        return null;
      } catch (err) {
        if (this.config.verbose) this.log(`Cedar evaluation error: ${err instanceof Error ? err.message : err}`);
      }
    }
    if (this.config.policy?.external && (this.config.policy.policy_engine === "external" || this.config.policy.policy_engine === "hybrid")) {
      try {
        const ctx = buildDecisionContext(toolName, this.currentTier, {
          agentId: this.admissionResult?.agent_id,
          manifestHash: this.admissionResult?.manifest_hash,
          credentialRef,
          mode,
          slug: this.config.slug
        });
        const externalDecision = await queryExternalPDP(ctx, this.config.policy.external);
        if (!externalDecision.allowed) {
          const reason = `external_pdp_deny${externalDecision.reason ? ": " + externalDecision.reason : ""}`;
          this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: reason, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
          if (this.config.enforce) {
            return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" denied by external policy engine`);
          }
          if (this.config.policy.policy_engine === "external") return null;
        }
      } catch (err) {
        if (this.config.verbose) this.log(`External PDP error: ${err instanceof Error ? err.message : err}`);
      }
    }
    if (toolPolicy.min_tier) {
      if (!meetsMinTier(this.currentTier, toolPolicy.min_tier)) {
        this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "tier_insufficient", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
        if (this.config.enforce) {
          return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" requires tier "${toolPolicy.min_tier}"`);
        }
        return null;
      }
    }
    if (toolPolicy.block) {
      this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "policy_block", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
      if (this.config.enforce) {
        return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" is blocked by policy`);
      }
      return null;
    }
    if (toolPolicy.require_approval) {
      const grant = this.approvalStore.get(requestId);
      const alwaysGrant = this.approvalStore.get(`always:${toolName}`);
      if (grant && Date.now() < grant.expires_at || alwaysGrant && Date.now() < alwaysGrant.expires_at) {
        if (grant && grant.mode === "once") this.approvalStore.delete(requestId);
        this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: "approval_granted", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
        return null;
      }
      this.emitDecisionLog({ tool: toolName, decision: "require_approval", reason_code: "requires_human_approval", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
      if (this.notificationConfig) {
        sendApprovalNotification(this.notificationConfig, {
          requestId,
          toolName,
          agentId: this.admissionResult?.agent_id,
          policyName: "default",
          reason: `Policy requires human approval for "${toolName}"`,
          traceUrl: `https://scopeblind.com/trace`,
          approveUrl: void 0,
          // Approve URL provided when HTTP transport is active
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        }).catch(() => {
        });
      }
      if (this.config.enforce) {
        return {
          jsonrpc: "2.0",
          id: request.id,
          result: {
            content: [
              {
                type: "text",
                text: `REQUIRES_APPROVAL: The tool "${toolName}" requires human approval before execution. Exact action: ${actionReadback.summary}. Payload hash: ${actionReadback.payload_hash.slice(0, 16)}\u2026 Request ID: ${requestId}. Approval nonce: ${this.approvalNonce}. Tell the user you need their approval to use "${toolName}" and will retry when granted. Do NOT retry this tool call until the user explicitly approves it.`
              }
            ],
            isError: true
          }
        };
      }
      return null;
    }
    const rateSpec = this.getTierRateLimit(toolPolicy, this.currentTier);
    if (rateSpec) {
      try {
        const limit = parseRateLimit(rateSpec);
        const key = `tool:${toolName}:${this.currentTier}`;
        const { allowed, remaining } = checkRateLimit(key, limit, this.rateLimitStore);
        if (!allowed) {
          this.emitDecisionLog({ tool: toolName, decision: "deny", reason_code: "rate_limit_exceeded", request_id: requestId, rate_limit_remaining: 0, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
          if (this.config.enforce) {
            return this.makeErrorResponse(request.id, -32600, `Tool "${toolName}" rate limit exceeded (${rateSpec})`);
          }
          return null;
        }
        this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: "policy_allow", request_id: requestId, rate_limit_remaining: remaining, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
      } catch {
        this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: "default_allow", request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
      }
    } else {
      const reasonCode = this.config.enforce ? "policy_allow" : "observe_mode";
      this.emitDecisionLog({ tool: toolName, decision: "allow", reason_code: reasonCode, request_id: requestId, tier: this.currentTier, credential_ref: credentialRef, action_readback: actionReadback });
    }
    return null;
  }
  getTierRateLimit(policy, tier) {
    if (policy.rate_limits && policy.rate_limits[tier]) {
      const tierLimit = policy.rate_limits[tier];
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
  emitDecisionLog(entry) {
    const mode = this.config.enforce ? "enforce" : "shadow";
    const otelTraceId = entry.otel_trace_id || randomBytes(16).toString("hex");
    const otelSpanId = entry.otel_span_id || randomBytes(8).toString("hex");
    const log = {
      v: 2,
      tool: entry.tool || "unknown",
      decision: entry.decision || "allow",
      reason_code: entry.reason_code || "default_allow",
      policy_digest: this.config.policyDigest,
      policy_engine: this.config.policy?.policy_engine || "built-in",
      request_id: entry.request_id || randomUUID().slice(0, 12),
      timestamp: Date.now(),
      mode,
      ...entry.rate_limit_remaining !== void 0 && { rate_limit_remaining: entry.rate_limit_remaining },
      ...entry.tier && { tier: entry.tier },
      ...entry.credential_ref && { credential_ref: entry.credential_ref },
      ...entry.action_readback && { action_readback: entry.action_readback },
      otel_trace_id: otelTraceId,
      otel_span_id: otelSpanId
    };
    process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}
`);
    try {
      appendFileSync(this.logFilePath, JSON.stringify(log) + "\n");
    } catch {
    }
    if (isSigningEnabled()) {
      const signed = signDecision(log);
      if (signed.signed) {
        process.stderr.write(`[PROTECT_MCP_RECEIPT] ${signed.signed}
`);
        try {
          appendFileSync(this.receiptFilePath, signed.signed + "\n");
        } catch {
        }
        this.receiptBuffer.add(log.request_id, signed.signed);
        if (this.admissionResult?.agent_id) {
          this.evidenceStore.record(this.admissionResult.agent_id, this.config.signing?.issuer || "protect-mcp");
          if (this.evidenceStore.getSummary(this.admissionResult.agent_id).receipt_count % 10 === 0) {
            this.evidenceStore.save();
          }
        }
      } else if (signed.error) {
        const tombstone = JSON.stringify({
          type: "scopeblind.signing_failure.v1",
          request_id: log.request_id,
          tool: log.tool,
          decision: log.decision,
          error: signed.error,
          at: new Date(log.timestamp).toISOString()
        });
        try {
          appendFileSync(this.receiptFilePath, tombstone + "\n");
        } catch {
        }
        process.stderr.write(`[PROTECT_MCP_SIGNING_FAILURE] ${tombstone}
`);
      }
    }
  }
  makeErrorResponse(id, code, message) {
    return { jsonrpc: "2.0", id, error: { code, message } };
  }
  sendToChild(message) {
    if (this.child?.stdin?.writable) this.child.stdin.write(message + "\n");
  }
  sendToClient(message) {
    if (this.httpMode) {
      try {
        const parsed = JSON.parse(message);
        if (parsed.id !== void 0 && parsed.id !== null) {
          const pending = this.pendingResponses.get(parsed.id);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingResponses.delete(parsed.id);
            pending.resolve(message);
            return;
          }
        }
      } catch {
      }
    }
    process.stdout.write(message + "\n");
  }
  /**
   * Enable HTTP transport mode.
   * In this mode, sendToClient resolves pending promises instead of
   * writing to stdout, and start() skips stdin reading.
   */
  enableHttpMode() {
    this.httpMode = true;
  }
  /**
   * Start in HTTP mode — spawns child process but does NOT read from
   * process.stdin. Requests come in via processRequest() instead.
   */
  async startForHttp() {
    this.httpMode = true;
    const { command, args, verbose } = this.config;
    const mode = this.config.enforce ? "enforce" : "shadow";
    if (verbose) {
      this.log(`Starting gateway in ${mode} mode (HTTP transport)`);
      this.log(`Wrapping: ${command} ${args.join(" ")}`);
    }
    this.log(`Approval nonce: ${this.approvalNonce}`);
    const childEnv = { ...process.env };
    if (this.config.credentials) {
      for (const [label, credConfig] of Object.entries(this.config.credentials)) {
        if (credConfig.inject === "env" && credConfig.name && credConfig.value_env) {
          const envValue = process.env[credConfig.value_env];
          if (envValue) {
            childEnv[credConfig.name] = envValue;
            if (verbose) this.log(`Credential "${label}": injected as env var "${credConfig.name}"`);
          }
        }
      }
    }
    this.child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"], env: childEnv });
    if (!this.child.stdin || !this.child.stdout || !this.child.stderr) {
      throw new Error("Failed to create pipes to child process");
    }
    this.child.stderr.on("data", (data) => {
      process.stderr.write(data);
    });
    const childReader = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    childReader.on("line", (line) => {
      this.handleServerMessage(line);
    });
    this.child.on("exit", (code, signal) => {
      if (verbose) this.log(`Child process exited (code=${code}, signal=${signal})`);
      this.evidenceStore.save();
    });
    this.child.on("error", (err) => {
      this.log(`Child process error: ${err.message}`);
    });
  }
  /**
   * Process a JSON-RPC request programmatically (for HTTP transport).
   * Returns a promise that resolves with the JSON-RPC response string.
   */
  async processRequest(jsonRpc) {
    const REQUEST_TIMEOUT_MS = 3e4;
    if (jsonRpc.method === "tools/call" && jsonRpc.id !== void 0) {
      const blocked = await this.interceptToolCall(jsonRpc);
      if (blocked) {
        return JSON.stringify(blocked);
      }
    }
    return new Promise((resolve, reject) => {
      const id = jsonRpc.id;
      if (id === void 0 || id === null) {
        const modified2 = this.injectParamsCredentials(jsonRpc);
        this.sendToChild(JSON.stringify(modified2));
        resolve(JSON.stringify({ jsonrpc: "2.0", result: {}, id: null }));
        return;
      }
      const timeout = setTimeout(() => {
        this.pendingResponses.delete(id);
        resolve(JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32e3, message: "Request timeout (30s)" },
          id
        }));
      }, REQUEST_TIMEOUT_MS);
      this.pendingResponses.set(id, { resolve, timeout });
      const modified = this.injectParamsCredentials(jsonRpc);
      this.sendToChild(JSON.stringify(modified));
    });
  }
  log(message) {
    process.stderr.write(`[PROTECT_MCP] ${message}
`);
  }
  stop() {
    this.evidenceStore.save();
    if (this.clientReader) this.clientReader.close();
    if (this.child) {
      this.child.kill("SIGTERM");
      this.child = null;
    }
    process.exit(0);
  }
};

export {
  evaluateTier,
  meetsMinTier,
  resolveCredential,
  listCredentialLabels,
  validateCredentials,
  queryExternalPDP,
  buildDecisionContext,
  sendApprovalNotification,
  parseNotificationConfigFromEnv,
  ProtectGateway
};
