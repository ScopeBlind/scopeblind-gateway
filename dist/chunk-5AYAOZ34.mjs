import {
  digestBuiltinPolicy
} from "./chunk-FGCNKEEW.mjs";
import {
  computeSbIssuerKid,
  createReceiptEnvelope
} from "./chunk-XOP3PEBM.mjs";

// src/policy.ts
import { readFileSync } from "fs";
function loadPolicy(path) {
  const raw = readFileSync(path, "utf-8");
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
  return digestBuiltinPolicy(policy).policy_digest;
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

// src/signing.ts
import { readFileSync as readFileSync2, existsSync } from "fs";
var signerState = null;
var signingConfigured = false;
var signingInitError = null;
async function initSigning(config) {
  const warnings = [];
  signerState = null;
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
  if (!existsSync(config.key_path)) {
    signingInitError = `key file not found at ${config.key_path}`;
    warnings.push(`signing: ${signingInitError} \u2014 run "protect-mcp init" to generate`);
    return warnings;
  }
  let keyData;
  try {
    keyData = JSON.parse(readFileSync2(config.key_path, "utf-8"));
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
    signerState = {
      privateKey: keyData.privateKey,
      publicKey: keyData.publicKey,
      // kid is opaque per draft-02; existing key files keep their explicit kid,
      // and keys without one get the s2.1.1 RECOMMENDED sb:issuer format.
      kid: keyData.kid || computeSbIssuerKid(keyData.publicKey),
      issuer: config.issuer || keyData.issuer || "protect-mcp"
    };
  } catch (err) {
    signingInitError = `failed to initialize signer: ${err instanceof Error ? err.message : err}`;
    warnings.push(`signing: ${signingInitError} \u2014 enforce mode will fail closed`);
  }
  return warnings;
}
function signDecision(entry, prevReceiptHash) {
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
  if (signingConfigured && !signerState) {
    const error = "signing was configured but no signer is ready";
    return {
      ok: false,
      signed: null,
      artifact_type: artifactType,
      warning: error,
      error
    };
  }
  if (!signerState) {
    return { ok: false, signed: null, artifact_type: "none" };
  }
  try {
    const payload = {
      // draft-02 s3.1 access-decision fields
      type: "protectmcp:decision",
      tool_name: entry.tool,
      decision: entry.decision,
      reason: entry.reason_code,
      policy_digest: entry.policy_digest,
      // Extension fields (signed alongside the s3.1 core)
      scope: entry.request_id,
      // request scope
      mode: entry.mode,
      request_id: entry.request_id,
      // Spec version: ties every receipt to the IETF standard
      spec: "draft-farley-acta-signed-receipts-02",
      // Issuer certification: distinguishes VOPRF-backed receipts from self-signed ones
      // - scopeblind:verified  = issued via ScopeBlind VOPRF backend (paid tier)
      // - self-signed          = signed with local Ed25519 key (free tier, protect-mcp default)
      // - uncertified          = unsigned receipt (shadow mode, no signing configured)
      issuer_certification: signerState ? "self-signed" : "uncertified",
      // The signer's PUBLIC key, inside the signed payload, so a receipt is
      // self-contained: any verifier (including the record viewer, in-browser)
      // can check the signature without a side channel. Binding the key inside
      // the signature means it cannot be swapped without breaking the signature;
      // authenticity (that the key is YOUR gate's) still comes from pinning it.
      public_key: signerState.publicKey
    };
    if (signerState.issuer && signerState.issuer !== signerState.kid) {
      payload.issuer_name = signerState.issuer;
    }
    if (prevReceiptHash) payload.previousReceiptHash = prevReceiptHash;
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
    if (entry.enrichment) payload.enrichment = entry.enrichment;
    if (entry.action_readback) payload.action_readback = entry.action_readback;
    if (entry.deny_iteration) payload.deny_iteration = entry.deny_iteration;
    const result = createReceiptEnvelope(
      payload,
      signerState.privateKey,
      signerState.kid,
      Number.isFinite(entry.timestamp) ? new Date(entry.timestamp).toISOString() : void 0
    );
    return {
      ok: true,
      signed: JSON.stringify(result.envelope),
      artifact_type: artifactType,
      receipt_hash: result.hash
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
  return signingConfigured && signingInitError === null && signerState !== null;
}

// src/http-server.ts
import { createServer } from "http";
import { readFileSync as readFileSync3, existsSync as existsSync2 } from "fs";
import { join } from "path";
var LOG_FILE = ".protect-mcp-log.jsonl";
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
function startStatusServer(config, receiptBuffer, approvalStore, approvalNonce) {
  const startTime = Date.now();
  const logDir = process.cwd();
  const server = createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Content-Type", "application/json");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url || "/", `http://localhost:${config.port}`);
    const path = url.pathname;
    try {
      if (path === "/health") {
        handleHealth(res, startTime, config);
      } else if (path === "/status") {
        handleStatus(res, logDir);
      } else if (path === "/receipts") {
        handleReceipts(res, receiptBuffer, url);
      } else if (path === "/receipts/latest") {
        handleReceiptLatest(res, receiptBuffer);
      } else if (path.startsWith("/receipts/")) {
        const id = path.slice("/receipts/".length);
        handleReceiptById(res, receiptBuffer, id);
      } else if (path === "/approve" && req.method === "POST") {
        handleApprove(req, res, approvalStore, approvalNonce);
      } else if (path === "/approvals" && req.method === "GET") {
        handleListApprovals(res, approvalStore);
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "not_found", endpoints: ["/health", "/status", "/receipts", "/receipts/latest", "/receipts/:id", "/approve", "/approvals"] }));
      }
    } catch (err) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  });
  server.on("error", (err) => {
    if (config.verbose) {
      process.stderr.write(`[PROTECT_MCP] HTTP status server error: ${err.message}
`);
    }
  });
  server.listen(config.port, "127.0.0.1", () => {
    if (config.verbose) {
      process.stderr.write(`[PROTECT_MCP] HTTP status server listening on http://127.0.0.1:${config.port}
`);
    }
  });
  server.unref();
  return server;
}
function handleHealth(res, startTime, config) {
  res.writeHead(200);
  res.end(JSON.stringify({
    status: "ok",
    uptime_ms: Date.now() - startTime,
    mode: config.mode,
    version: process.env.PROTECT_MCP_VERSION || "unknown"
  }));
}
function handleStatus(res, logDir) {
  const logPath = join(logDir, LOG_FILE);
  if (!existsSync2(logPath)) {
    res.writeHead(200);
    res.end(JSON.stringify({ entries: 0, message: "no log file yet" }));
    return;
  }
  const raw = readFileSync3(logPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  const entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
    }
  }
  const toolCounts = {};
  let allowCount = 0, denyCount = 0;
  const tierCounts = {};
  for (const e of entries) {
    toolCounts[e.tool] = (toolCounts[e.tool] || 0) + 1;
    if (e.decision === "allow") allowCount++;
    else denyCount++;
    if (e.tier) tierCounts[e.tier] = (tierCounts[e.tier] || 0) + 1;
  }
  res.writeHead(200);
  res.end(JSON.stringify({
    entries: entries.length,
    allow: allowCount,
    deny: denyCount,
    tools: toolCounts,
    tiers: tierCounts,
    first_timestamp: entries.length > 0 ? entries[0].timestamp : null,
    last_timestamp: entries.length > 0 ? entries[entries.length - 1].timestamp : null
  }));
}
function handleReceipts(res, buffer, url) {
  const limit = parseInt(url.searchParams.get("limit") || "20", 10);
  const receipts = buffer.getAll().slice(0, Math.min(limit, MAX_RECEIPTS));
  res.writeHead(200);
  res.end(JSON.stringify({
    count: receipts.length,
    total: buffer.count(),
    receipts
  }));
}
function handleReceiptLatest(res, buffer) {
  const latest = buffer.getLatest();
  if (!latest) {
    res.writeHead(404);
    res.end(JSON.stringify({ error: "no_receipts", message: "No receipts yet. Make a tool call through protect-mcp first." }));
    return;
  }
  res.writeHead(200);
  res.end(JSON.stringify(latest));
}
function handleReceiptById(res, buffer, id) {
  const receipt = buffer.getById(id);
  if (!receipt) {
    res.writeHead(404);
    res.end(JSON.stringify({ error: "receipt_not_found", request_id: id }));
    return;
  }
  res.writeHead(200);
  res.end(JSON.stringify(receipt));
}
function handleApprove(req, res, approvalStore, expectedNonce) {
  if (!approvalStore) {
    res.writeHead(503);
    res.end(JSON.stringify({ error: "approval_store_not_available" }));
    return;
  }
  let body = "";
  req.on("data", (chunk) => {
    body += chunk.toString();
  });
  req.on("end", () => {
    try {
      const { request_id, tool, mode, nonce } = JSON.parse(body);
      if (expectedNonce && nonce !== expectedNonce) {
        res.writeHead(403);
        res.end(JSON.stringify({ error: "invalid_nonce", message: "Approval nonce does not match. Check stderr output for the correct nonce." }));
        return;
      }
      if (!tool || typeof tool !== "string") {
        res.writeHead(400);
        res.end(JSON.stringify({ error: "missing_tool", usage: '{"request_id":"abc123","tool":"send_email","mode":"once|always","nonce":"..."}' }));
        return;
      }
      const grantMode = mode === "always" ? "always" : "once";
      const ttlMs = grantMode === "once" ? 5 * 60 * 1e3 : 24 * 60 * 60 * 1e3;
      const grantEntry = { tool, mode: grantMode, expires_at: Date.now() + ttlMs };
      if (grantMode === "always") {
        approvalStore.set(`always:${tool}`, grantEntry);
      } else if (request_id) {
        approvalStore.set(request_id, grantEntry);
      } else {
        approvalStore.set(tool, grantEntry);
      }
      res.writeHead(200);
      res.end(JSON.stringify({
        approved: true,
        request_id: request_id || null,
        tool,
        mode: grantMode,
        expires_in_seconds: ttlMs / 1e3
      }));
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "invalid_json", usage: '{"request_id":"abc123","tool":"send_email","mode":"once","nonce":"..."}' }));
    }
  });
}
function handleListApprovals(res, approvalStore) {
  if (!approvalStore) {
    res.writeHead(200);
    res.end(JSON.stringify({ grants: [] }));
    return;
  }
  const now = Date.now();
  const grants = [];
  for (const [key, grant] of approvalStore) {
    if (now < grant.expires_at) {
      grants.push({ key, tool: grant.tool, mode: grant.mode, expires_in_seconds: Math.round((grant.expires_at - now) / 1e3) });
    }
  }
  res.writeHead(200);
  res.end(JSON.stringify({ grants }));
}

// src/action-readback.ts
import { createHash } from "crypto";
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
    payload_hash: createHash("sha256").update(canonical).digest("hex"),
    payload_bytes: Buffer.byteLength(canonical, "utf-8"),
    disclosed_fields: [...new Set(disclosedFields)].slice(0, 80),
    redacted_fields: [...new Set(redactedFields)].slice(0, 80),
    summary
  };
}

export {
  loadPolicy,
  getToolPolicy,
  parseRateLimit,
  checkRateLimit,
  initSigning,
  signDecision,
  getSignerInfo,
  isSigningEnabled,
  ReceiptBuffer,
  startStatusServer,
  buildActionReadback
};
