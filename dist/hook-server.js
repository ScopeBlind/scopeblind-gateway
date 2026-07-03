"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/hook-server.ts
var hook_server_exports = {};
__export(hook_server_exports, {
  startHookServer: () => startHookServer
});
module.exports = __toCommonJS(hook_server_exports);
var import_node_http2 = require("http");
var import_node_crypto4 = require("crypto");
var import_node_fs5 = require("fs");
var import_node_path3 = require("path");

// src/cedar-evaluator.ts
var import_node_crypto = require("crypto");
var import_node_fs = require("fs");
var import_node_path = require("path");
var cedarWasm = null;
var loadAttempted = false;
async function ensureCedarWasm() {
  if (cedarWasm) return true;
  if (loadAttempted) return false;
  loadAttempted = true;
  try {
    const moduleName = "@cedar-policy/cedar-wasm";
    cedarWasm = await import(
      /* @vite-ignore */
      moduleName
    );
    return true;
  } catch {
    return false;
  }
}
function loadCedarPolicies(dirPath) {
  if (!(0, import_node_fs.existsSync)(dirPath)) {
    throw new Error(`Cedar policy directory not found: ${dirPath}`);
  }
  const entries = (0, import_node_fs.readdirSync)(dirPath).filter((f) => (0, import_node_path.extname)(f) === ".cedar").sort();
  if (entries.length === 0) {
    throw new Error(`No .cedar files found in: ${dirPath}`);
  }
  const sources = [];
  for (const file of entries) {
    const content = (0, import_node_fs.readFileSync)((0, import_node_path.join)(dirPath, file), "utf-8");
    sources.push(content);
  }
  const concatenated = sources.join("\n\n");
  const digest = (0, import_node_crypto.createHash)("sha256").update(concatenated).digest("hex").slice(0, 16);
  return {
    source: concatenated,
    digest,
    fileCount: entries.length,
    files: entries
  };
}
function buildEntities(req) {
  const agentId = req.agentId || req.tier;
  return [
    {
      uid: { type: "Agent", id: agentId },
      attrs: {
        tier: req.tier,
        ...req.agentId ? { agent_id: req.agentId } : {}
      },
      parents: []
    },
    {
      uid: { type: "Tool", id: req.tool },
      attrs: {},
      parents: []
    }
  ];
}
function onEvalError(reason, failClosed, extra) {
  return {
    allowed: !failClosed,
    reason: failClosed ? reason : `${reason} (observe mode; would DENY under enforcement)`,
    metadata: { error: true, fail_closed: failClosed, would_deny: true, ...extra || {} }
  };
}
async function evaluateCedar(policySet, req, schema, options) {
  const failClosed = options?.failClosed ?? true;
  const available = await ensureCedarWasm();
  if (!available) {
    return onEvalError("cedar_wasm_not_available", failClosed, { fallback: true });
  }
  try {
    const agentId = req.agentId || req.tier;
    const context = {
      tier: req.tier,
      ...req.context || {}
    };
    if (req.toolInput && Object.keys(req.toolInput).length > 0) {
      context.input = req.toolInput;
    }
    const authRequest = {
      principal: { type: "Agent", id: agentId },
      action: { type: "Action", id: "MCP::Tool::call" },
      resource: { type: "Tool", id: req.tool },
      context
    };
    const entities = buildEntities(req);
    const cedarSchema = schema?.schemaJson ?? null;
    let result;
    if (typeof cedarWasm.isAuthorized === "function") {
      result = cedarWasm.isAuthorized({
        policies: { staticPolicies: policySet.source },
        entities,
        principal: authRequest.principal,
        action: authRequest.action,
        resource: authRequest.resource,
        context: authRequest.context,
        schema: cedarSchema
      });
    } else if (typeof cedarWasm.checkAuthorization === "function") {
      result = cedarWasm.checkAuthorization(
        policySet.source,
        JSON.stringify(entities),
        JSON.stringify(authRequest)
      );
    } else {
      const cedarEngine = cedarWasm.default || cedarWasm;
      if (typeof cedarEngine.isAuthorized === "function") {
        result = cedarEngine.isAuthorized({
          policies: { staticPolicies: policySet.source },
          entities,
          principal: authRequest.principal,
          action: authRequest.action,
          resource: authRequest.resource,
          context: authRequest.context,
          schema: cedarSchema
        });
      } else {
        return onEvalError("cedar_wasm_api_unsupported", failClosed, { exports: Object.keys(cedarWasm) });
      }
    }
    const parsed = parseWasmResult(result);
    const policyErrors = extractPolicyErrors(result);
    if (parsed.kind === "error") {
      return onEvalError(`cedar_unparseable_result: ${parsed.diagnostics}`, failClosed);
    }
    if (policyErrors.length > 0) {
      return onEvalError(
        `cedar_policy_errored: ${policyErrors.length} policy error(s); decision is unsound`,
        failClosed,
        { policy_errors: policyErrors.slice(0, 5), policy_digest: policySet.digest }
      );
    }
    return {
      allowed: parsed.kind === "allow",
      reason: parsed.kind === "allow" ? void 0 : `cedar_deny${parsed.diagnostics ? ": " + parsed.diagnostics : ""}`,
      metadata: {
        policy_digest: policySet.digest,
        ...parsed.matchedPolicies ? { matched_policies: parsed.matchedPolicies } : {}
      }
    };
  } catch (err) {
    return onEvalError(`cedar_eval_error: ${err instanceof Error ? err.message : "unknown"}`, failClosed);
  }
}
function parseWasmResult(result) {
  if (!result) return { kind: "error", diagnostics: "null result from Cedar WASM" };
  if (result.type === "failure") {
    return { kind: "error", diagnostics: `cedar failure: ${JSON.stringify(result.errors ?? [])}` };
  }
  if (result.type === "success" && result.response) {
    const dec = result.response.decision;
    const reasons = result.response.diagnostics?.reason;
    if (dec === "allow" || dec === "Allow") return { kind: "allow", matchedPolicies: reasons };
    if (dec === "deny" || dec === "Deny") {
      return { kind: "deny", diagnostics: result.response.diagnostics ? JSON.stringify(result.response.diagnostics) : void 0, matchedPolicies: reasons };
    }
  }
  if (result.type === "allow" || result.decision === "Allow") return { kind: "allow" };
  if (result.type === "deny" || result.decision === "Deny") return { kind: "deny" };
  if (typeof result === "boolean") return result ? { kind: "allow" } : { kind: "deny" };
  return { kind: "error", diagnostics: `unknown result format: ${JSON.stringify(result)}` };
}
function extractPolicyErrors(result) {
  if (!result || typeof result !== "object") return [];
  const raw = result.errors ?? result.response?.diagnostics?.errors ?? result.diagnostics?.errors ?? [];
  if (!Array.isArray(raw)) return [];
  return raw.map((e) => typeof e === "string" ? e : e?.message ?? e?.error ?? JSON.stringify(e)).filter(Boolean);
}
async function isCedarAvailable() {
  return ensureCedarWasm();
}

// src/signing.ts
var import_node_fs2 = require("fs");
var signerState = null;
var artifactsModule = null;
var signingConfigured = false;
var signingInitError = null;
async function initSigning(config) {
  const warnings = [];
  signerState = null;
  artifactsModule = null;
  signingConfigured = Boolean(config && config.enabled !== false);
  signingInitError = null;
  if (!config || config.enabled === false) {
    return warnings;
  }
  if (!config.key_path) {
    signingInitError = "signing enabled but key_path is not configured";
    warnings.push(`signing: ${signingInitError}`);
    return warnings;
  }
  if (!(0, import_node_fs2.existsSync)(config.key_path)) {
    signingInitError = `key file not found at ${config.key_path}`;
    warnings.push(`signing: ${signingInitError} \u2014 run "protect-mcp init" to generate`);
    return warnings;
  }
  let keyData;
  try {
    keyData = JSON.parse((0, import_node_fs2.readFileSync)(config.key_path, "utf-8"));
    if (!keyData.privateKey || !keyData.publicKey) {
      signingInitError = "key file missing privateKey or publicKey fields";
      warnings.push(`signing: ${signingInitError}`);
      return warnings;
    }
  } catch (err) {
    signingInitError = `failed to load key file: ${err instanceof Error ? err.message : err}`;
    warnings.push(`signing: ${signingInitError}`);
    return warnings;
  }
  try {
    const moduleName = "@veritasacta/artifacts";
    artifactsModule = await import(
      /* @vite-ignore */
      moduleName
    );
  } catch {
    signingInitError = "@veritasacta/artifacts not available";
    warnings.push(`signing: ${signingInitError} \u2014 enforce mode will fail closed`);
    return warnings;
  }
  try {
    signerState = {
      privateKey: keyData.privateKey,
      publicKey: keyData.publicKey,
      kid: keyData.kid || artifactsModule.computeKid(keyData.publicKey),
      issuer: config.issuer || keyData.issuer || "protect-mcp"
    };
  } catch (err) {
    signingInitError = `failed to initialize signer: ${err instanceof Error ? err.message : err}`;
    artifactsModule = null;
    warnings.push(`signing: ${signingInitError} \u2014 enforce mode will fail closed`);
  }
  return warnings;
}
function signDecision(entry) {
  const artifactType = entry.decision === "deny" ? "gateway_restraint" : "decision_receipt";
  if (signingConfigured && signingInitError) {
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: `signing initialization failed: ${signingInitError}`,
      error: signingInitError
    };
  }
  if (signingConfigured && (!signerState || !artifactsModule)) {
    const error = "signing was configured but no signer is ready";
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: error,
      error
    };
  }
  if (!signerState || !artifactsModule) {
    return { ok: false, signed: null, artifact_type: "none" };
  }
  try {
    const payload = {
      tool: entry.tool,
      decision: entry.decision,
      reason_code: entry.reason_code,
      policy_digest: entry.policy_digest,
      scope: entry.request_id,
      // request scope
      mode: entry.mode,
      request_id: entry.request_id,
      // Spec version: ties every receipt to the IETF standard
      spec: "draft-farley-acta-signed-receipts-01",
      // Issuer certification: distinguishes VOPRF-backed receipts from self-signed ones
      // - scopeblind:verified  = issued via ScopeBlind VOPRF backend (paid tier)
      // - self-signed          = signed with local Ed25519 key (free tier, protect-mcp default)
      // - uncertified          = unsigned receipt (shadow mode, no signing configured)
      issuer_certification: signerState ? "self-signed" : "uncertified"
    };
    if (entry.tier) payload.tier = entry.tier;
    if (entry.credential_ref) payload.credential_ref = entry.credential_ref;
    if (entry.rate_limit_remaining !== void 0) {
      payload.rate_limit_remaining = entry.rate_limit_remaining;
    }
    if (entry.policy_engine) payload.policy_engine = entry.policy_engine;
    if (entry.hook_event) payload.hook_event = entry.hook_event;
    if (entry.sandbox_state) payload.sandbox_state = entry.sandbox_state;
    if (entry.timing) payload.timing = entry.timing;
    if (entry.swarm) payload.swarm = entry.swarm;
    if (entry.payload_digest) payload.payload_digest = entry.payload_digest;
    if (entry.action_readback) payload.action_readback = entry.action_readback;
    if (entry.deny_iteration) payload.deny_iteration = entry.deny_iteration;
    const result = artifactsModule.createSignedArtifact(
      artifactType,
      payload,
      signerState.privateKey,
      {
        kid: signerState.kid,
        issuer: signerState.issuer
      }
    );
    return {
      ok: true,
      signed: JSON.stringify(result.artifact),
      artifact_type: artifactType
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown error";
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: `signing failed: ${message}`,
      error: message
    };
  }
}
function getSignerInfo() {
  if (!signerState) return null;
  return {
    publicKey: signerState.publicKey,
    kid: signerState.kid,
    issuer: signerState.issuer
  };
}
function isSigningEnabled() {
  return signingConfigured && signingInitError === null && signerState !== null && artifactsModule !== null;
}

// src/policy.ts
var import_node_crypto2 = require("crypto");
var import_node_fs3 = require("fs");
function loadPolicy(path) {
  const raw = (0, import_node_fs3.readFileSync)(path, "utf-8");
  const parsed = JSON.parse(raw);
  if (!parsed.tools || typeof parsed.tools !== "object") {
    throw new Error(`Invalid policy file: missing "tools" object in ${path}`);
  }
  const policy = {
    tools: parsed.tools,
    default_tier: parsed.default_tier || "unknown",
    policy_engine: parsed.policy_engine || "built-in",
    ...parsed.external ? { external: parsed.external } : {}
  };
  const digest = computePolicyDigest(policy);
  return {
    policy,
    digest,
    credentials: parsed.credentials,
    signing: parsed.signing
  };
}
function computePolicyDigest(policy) {
  const canonical = JSON.stringify(sortKeysDeep(policy));
  return (0, import_node_crypto2.createHash)("sha256").update(canonical).digest("hex").slice(0, 16);
}
function sortKeysDeep(obj) {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sortKeysDeep);
  const sorted = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = sortKeysDeep(obj[key]);
  }
  return sorted;
}
function getToolPolicy(toolName, policy) {
  if (!policy) {
    return { require: "any" };
  }
  if (policy.tools[toolName]) {
    return policy.tools[toolName];
  }
  if (policy.tools["*"]) {
    return policy.tools["*"];
  }
  return { require: "any" };
}
function parseRateLimit(spec) {
  const match = spec.match(/^(\d+)\/(second|minute|hour|day)$/);
  if (!match) {
    throw new Error(`Invalid rate limit format: "${spec}". Expected "N/unit" (e.g. "5/hour")`);
  }
  const count = parseInt(match[1], 10);
  const unit = match[2];
  const windowMs = {
    second: 1e3,
    minute: 6e4,
    hour: 36e5,
    day: 864e5
  };
  return { count, windowMs: windowMs[unit] };
}
function checkRateLimit(key, limit, store) {
  const now = Date.now();
  const windowStart = now - limit.windowMs;
  const timestamps = (store.get(key) || []).filter((t) => t > windowStart);
  if (timestamps.length >= limit.count) {
    store.set(key, timestamps);
    return { allowed: false, remaining: 0 };
  }
  timestamps.push(now);
  store.set(key, timestamps);
  return { allowed: true, remaining: limit.count - timestamps.length };
}

// src/http-server.ts
var import_node_http = require("http");
var import_node_fs4 = require("fs");
var import_node_path2 = require("path");
var MAX_RECEIPTS = 100;
var ReceiptBuffer = class {
  receipts = [];
  add(requestId, receipt) {
    this.receipts.push({
      request_id: requestId,
      receipt,
      timestamp: Date.now()
    });
    if (this.receipts.length > MAX_RECEIPTS) {
      this.receipts = this.receipts.slice(-MAX_RECEIPTS);
    }
  }
  getAll() {
    return [...this.receipts].reverse();
  }
  getById(requestId) {
    return this.receipts.find((r) => r.request_id === requestId);
  }
  count() {
    return this.receipts.length;
  }
  getLatest() {
    return this.receipts.length > 0 ? this.receipts[this.receipts.length - 1] : void 0;
  }
};

// src/scopeblind-bridge.ts
var DEFAULT_BASE = "https://scopeblind.com";
var FLUSH_INTERVAL_MS = 5e3;
var BATCH_MAX = 128;
var BRASS_REFRESH_MARGIN_MS = 5 * 60 * 1e3;
var ScopeBlindBridge = class {
  token;
  base;
  tenantOverride;
  cachedProof = null;
  queue = [];
  flushTimer = null;
  stats;
  shuttingDown = false;
  constructor(env = process.env) {
    this.token = env.SCOPEBLIND_TOKEN || null;
    this.base = (env.SCOPEBLIND_BASE || DEFAULT_BASE).replace(/\/$/, "");
    this.tenantOverride = env.SCOPEBLIND_TENANT || null;
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
  /** Push a signed receipt into the queue. Non-blocking. */
  forward(signedReceipt) {
    if (!this.enabled() || this.shuttingDown) return;
    this.queue.push(signedReceipt);
    if (this.queue.length >= BATCH_MAX) void this.flush();
  }
  /** Flush the queue. Safe to call concurrently. */
  async flush() {
    if (!this.enabled() || this.queue.length === 0) return;
    const batch = this.queue.splice(0, BATCH_MAX);
    try {
      const proof = await this.ensureBrassProof();
      const slug = this.tenantOverride || proof?.tenant_id;
      if (!slug) {
        this.queue.unshift(...batch);
        return;
      }
      this.stats.tenant_slug = slug;
      const res = await fetch(`${this.base}/fn/console/${slug}/receipts`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.token}`,
          "user-agent": "protect-mcp/scopeblind-bridge"
        },
        body: JSON.stringify({ receipts: batch })
      });
      if (!res.ok) {
        const errBody = await res.text().catch(() => "");
        this.stats.last_error = `HTTP ${res.status} ${errBody.slice(0, 160)}`;
        this.stats.rejected_total += batch.length;
        if (res.status >= 500 && res.status !== 503) {
          this.queue.unshift(...batch);
        }
        return;
      }
      const body = await res.json().catch(() => ({}));
      this.stats.forwarded_total += body?.accepted ?? batch.length;
      this.stats.rejected_total += body?.rejected ?? 0;
      this.stats.last_flush_at = (/* @__PURE__ */ new Date()).toISOString();
      this.stats.last_error = null;
    } catch (err) {
      this.stats.last_error = String(err?.message || err);
      this.queue.unshift(...batch);
    }
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
          scope: "protect-mcp-receipt-emit",
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
var singleton = null;
function getScopeBlindBridge() {
  if (!singleton) singleton = new ScopeBlindBridge();
  return singleton;
}

// src/action-readback.ts
var import_node_crypto3 = require("crypto");
var SECRET_KEY_RE = /(api[_-]?key|authorization|bearer|credential|password|secret|session|token|private[_-]?key)/i;
var DESTINATION_KEYS = [
  "path",
  "file_path",
  "filePath",
  "url",
  "uri",
  "endpoint",
  "host",
  "hostname",
  "repo",
  "repository",
  "branch",
  "channel",
  "to",
  "recipient",
  "symbol",
  "account",
  "bucket",
  "database",
  "table",
  "service"
];
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(",")}}`;
}
function redact(value, path = [], redacted = [], disclosed = [], depth = 0) {
  if (depth > 4) return "[truncated-depth]";
  if (value === null || value === void 0) return value;
  if (typeof value !== "object") {
    if (path.length > 0) disclosed.push(path.join("."));
    if (typeof value === "string" && value.length > 240) return `${value.slice(0, 240)}...`;
    return value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item, idx) => redact(item, [...path, String(idx)], redacted, disclosed, depth + 1));
  }
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    const childPath = [...path, key];
    if (SECRET_KEY_RE.test(key)) {
      redacted.push(childPath.join("."));
      out[key] = "[redacted]";
      continue;
    }
    out[key] = redact(child, childPath, redacted, disclosed, depth + 1);
  }
  return out;
}
function firstStringValue(input, keys) {
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" || typeof value === "boolean") return String(value);
  }
  return void 0;
}
function actionFor(tool, input) {
  const explicit = firstStringValue(input, ["action", "operation", "method", "verb", "command"]);
  if (explicit) return explicit.length > 90 ? `${explicit.slice(0, 90)}...` : explicit;
  return tool;
}
function buildActionReadback(tool, input) {
  const normalized = input && typeof input === "object" && !Array.isArray(input) ? input : { value: input };
  const canonical = stableStringify(normalized);
  const redactedFields = [];
  const disclosedFields = [];
  const payloadPreview = redact(normalized, [], redactedFields, disclosedFields);
  const action = actionFor(tool, normalized);
  const destination = firstStringValue(normalized, DESTINATION_KEYS);
  const summary = destination ? `${tool} -> ${destination}` : `${tool} request`;
  return {
    tool,
    action,
    destination,
    payload_preview: payloadPreview,
    payload_hash: (0, import_node_crypto3.createHash)("sha256").update(canonical).digest("hex"),
    payload_bytes: Buffer.byteLength(canonical, "utf-8"),
    disclosed_fields: [...new Set(disclosedFields)].slice(0, 80),
    redacted_fields: [...new Set(redactedFields)].slice(0, 80),
    summary
  };
}

// src/hook-server.ts
var DEFAULT_PORT = 9377;
var LOG_FILE = ".protect-mcp-log.jsonl";
var RECEIPTS_FILE = ".protect-mcp-receipts.jsonl";
var PAYLOAD_HASH_THRESHOLD = 1024;
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
    input_hash: (0, import_node_crypto4.createHash)("sha256").update(content).digest("hex"),
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
    output_hash: (0, import_node_crypto4.createHash)("sha256").update(content).digest("hex"),
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
      const procStatus = (0, import_node_fs5.readFileSync)("/proc/self/status", "utf-8");
      if (procStatus.includes("Seccomp:	2")) return "enabled";
    } catch {
    }
  }
  return "unavailable";
}
async function handlePreToolUse(input, state) {
  const hookStart = Date.now();
  const toolName = input.toolName || "unknown";
  const requestId = input.toolUseId || (0, import_node_crypto4.randomUUID)().slice(0, 12);
  state.inflightTools.set(requestId, {
    tool: toolName,
    startedAt: hookStart,
    requestId
  });
  const payloadDigest = computePayloadDigest(input.toolInput);
  const actionReadback = buildActionReadback(toolName, input.toolInput || {});
  const swarm = {
    ...state.swarmContext,
    ...input.agentId && { agent_id: input.agentId },
    ...input.agentName && { agent_name: input.agentName },
    ...input.teamName && { team_name: input.teamName },
    ...input.agentType && { agent_type: input.agentType }
  };
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
        if (denyCount === 1) {
          process.stderr.write(
            `[PROTECT_MCP] No Cedar permit for "${toolName}" \u2014 suggest:
  ${suggestion}
`
          );
        }
        return {
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: `[ScopeBlind] Denied by Cedar policy. ${reason}. Forbidden: "${toolName}" is not permitted. Try a read-only alternative.` + (denyCount > 1 ? ` (attempt ${denyCount})` : "")
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
  const requestId = input.toolUseId || (0, import_node_crypto4.randomUUID)().slice(0, 12);
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
  const receiptId = (0, import_node_crypto4.randomUUID)().slice(0, 8);
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
    request_id: (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
    request_id: input.sessionId || (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
    request_id: input.sessionId || (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
      request_id: (0, import_node_crypto4.randomUUID)().slice(0, 12),
      hook_event: "ConfigChange",
      swarm: state.swarmContext
    });
  } else {
    emitDecisionLog(state, {
      tool: "config",
      decision: "allow",
      reason_code: "config_changed",
      request_id: (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto4.randomUUID)().slice(0, 12),
    hook_event: "Stop",
    swarm: state.swarmContext
  });
  return {};
}
function emitDecisionLog(state, entry) {
  const mode = state.enforce ? "enforce" : "shadow";
  const otelTraceId = (0, import_node_crypto4.randomBytes)(16).toString("hex");
  const otelSpanId = (0, import_node_crypto4.randomBytes)(8).toString("hex");
  const log = {
    v: 2,
    tool: entry.tool || "unknown",
    decision: entry.decision || "allow",
    reason_code: entry.reason_code || "default_allow",
    policy_digest: state.policyDigest,
    policy_engine: state.cedarPolicies ? "cedar" : "built-in",
    request_id: entry.request_id || (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
    ...entry.plan_receipt_id && { plan_receipt_id: entry.plan_receipt_id }
  };
  process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}
`);
  try {
    (0, import_node_fs5.appendFileSync)(state.logFilePath, JSON.stringify(log) + "\n");
  } catch {
  }
  if (isSigningEnabled()) {
    const signed = signDecision(log);
    if (signed.signed) {
      try {
        (0, import_node_fs5.appendFileSync)(state.receiptFilePath, signed.signed + "\n");
      } catch {
      }
      state.receiptBuffer.add(log.request_id, signed.signed);
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
      const tombstone = JSON.stringify({
        type: "scopeblind.signing_failure.v1",
        request_id: log.request_id,
        tool: log.tool,
        decision: log.decision,
        error: signed.error,
        at: new Date(log.timestamp).toISOString()
      });
      try {
        (0, import_node_fs5.appendFileSync)(state.receiptFilePath, tombstone + "\n");
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
  let cedarPolicies = null;
  let jsonPolicy = null;
  let policyDigest = "none";
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
    const keyPath = (0, import_node_path3.join)(process.cwd(), "keys", "gateway.json");
    if ((0, import_node_fs5.existsSync)(keyPath)) {
      const warnings = await initSigning({ key_path: keyPath, issuer: "protect-mcp", enabled: true });
      for (const w of warnings) {
        process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
      }
    }
  }
  const state = {
    cedarPolicies,
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
    logFilePath: (0, import_node_path3.join)(process.cwd(), LOG_FILE),
    receiptFilePath: (0, import_node_path3.join)(process.cwd(), RECEIPTS_FILE),
    permissionSuggestions: /* @__PURE__ */ new Map(),
    configAlerts: []
  };
  const server = (0, import_node_http2.createServer)(async (req, res) => {
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
        version: "0.5.0",
        uptime_ms: Date.now() - state.startTime,
        mode: enforce ? "enforce" : "shadow",
        policy_digest: policyDigest,
        policy_engine: cedarPolicies ? "cedar" : jsonPolicy ? "built-in" : "none",
        signing: isSigningEnabled(),
        swarm: state.swarmContext,
        signer: signerInfo ? { kid: signerInfo.kid, issuer: signerInfo.issuer } : null,
        cedar_files: cedarPolicies?.fileCount || 0
      }));
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
        try {
          const raw = JSON.parse(body);
          const input = normalizeHookInput(raw);
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
    w(`  protect-mcp v0.5.4
`);
    w(`  ScopeBlind \u2014 https://scopeblind.com
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
    w(`  deny is authoritative \u2014 cannot be overridden.
`);
    w(`
`);
    const hasSlug = process.env.SCOPEBLIND_SLUG || (0, import_node_fs5.existsSync)((0, import_node_path3.join)(process.cwd(), ".scopeblind"));
    if (!hasSlug) {
      w(`  Dashboard  npx protect-mcp connect
`);
      w(`             Free up to 20,000 receipts/month
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
function findCedarDir() {
  for (const candidate of ["cedar", "policies", "."]) {
    try {
      if ((0, import_node_fs5.existsSync)(candidate)) {
        const files = (0, import_node_fs5.readdirSync)(candidate, { encoding: "utf-8" });
        if (files.some((f) => f.endsWith(".cedar"))) {
          return candidate;
        }
      }
    } catch {
    }
  }
  return void 0;
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  startHookServer
});
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
