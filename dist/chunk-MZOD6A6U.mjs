// src/http-server.ts
import { createServer } from "http";
import { readFileSync, existsSync } from "fs";
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
  if (!existsSync(logPath)) {
    res.writeHead(200);
    res.end(JSON.stringify({ entries: 0, message: "no log file yet" }));
    return;
  }
  const raw = readFileSync(logPath, "utf-8");
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

// src/standard-gate.ts
import { createHash as createHash2 } from "crypto";
import { readFileSync as readFileSync2 } from "fs";
var isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
function moneyFrom(v) {
  if (!isObj(v) || typeof v.amount !== "number" || !(v.amount >= 0) || typeof v.currency !== "string" || !/^[A-Z]{3}$/.test(v.currency)) return null;
  return { minor: Math.round(v.amount * 100), currency: v.currency };
}
var fmt = (m) => `${m.currency} ${(m.minor / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
function parseStandard(value) {
  if (!isObj(value) || value.type !== "scopeblind.proof_request.v1") throw new Error("not a signed standard (scopeblind.proof_request.v1)");
  if (typeof value.request_id !== "string" || typeof value.digest !== "string") throw new Error("the standard has no request_id or digest");
  const recipient = isObj(value.recipient) ? value.recipient : null;
  if (!recipient || typeof recipient.verification_key !== "string" || !/^[0-9a-f]{64}$/i.test(recipient.verification_key)) throw new Error("the standard names no signer key");
  if (!isObj(value.signature) || typeof value.signature.value !== "string") throw new Error("the standard is not signed");
  const q = isObj(value.requirements) ? value.requirements : {};
  const run = isObj(q.run) ? q.run : null;
  const tools = run && Array.isArray(run.allowed_tools) ? run.allowed_tools.filter((t) => typeof t === "string") : null;
  const limits = isObj(q.action_limits) ? q.action_limits : null;
  const amount_max = limits ? moneyFrom(limits.amount_max) : null;
  const approval = isObj(q.human_approval) ? q.human_approval : null;
  const required_above = approval ? moneyFrom(approval.required_above) : null;
  const enforcement = isObj(value.enforcement) ? value.enforcement : null;
  const policy_digest = enforcement && typeof enforcement.policy_digest === "string" ? enforcement.policy_digest : null;
  const parts = [tools ? `${tools.length} tool${tools.length === 1 ? "" : "s"}` : "no tool list", amount_max ? `at most ${fmt(amount_max)} per instruction` : "no amount limit", required_above ? `a person approves above ${fmt(required_above)}` : "no approval threshold"];
  return { request_id: value.request_id, digest: value.digest, signer_key: recipient.verification_key.toLowerCase(), tools, amount_max, required_above, policy_digest, summary: parts.join(", ") };
}
function loadStandardFile(path) {
  return parseStandard(JSON.parse(readFileSync2(path, "utf-8")));
}
function readAmount(input) {
  if (!isObj(input)) return null;
  const currency = typeof input.currency === "string" && /^[A-Za-z]{3}$/.test(input.currency) ? input.currency.toUpperCase() : null;
  if (typeof input.amount_minor === "number" && Number.isFinite(input.amount_minor)) return { minor: Math.round(input.amount_minor), currency: currency ?? "" };
  if (typeof input.amount === "number" && Number.isFinite(input.amount)) return { minor: Math.round(input.amount * 100), currency: currency ?? "" };
  return null;
}
function checkAmount(gate, input) {
  if (!gate.amount_max) return { ok: true };
  const amount = readAmount(input);
  if (!amount) return { ok: true };
  if (amount.currency !== gate.amount_max.currency) return { ok: false, reason: "standard_currency_not_permitted", detail: `the standard permits ${gate.amount_max.currency} only; this call is in ${amount.currency || "no named currency"}` };
  if (amount.minor > gate.amount_max.minor) return { ok: false, reason: "standard_amount_over_limit", detail: `${fmt(amount)} is over the standard's limit of ${fmt(gate.amount_max)} per instruction` };
  return { ok: true };
}
function personRequired(gate, input) {
  if (!gate.required_above) return { required: false };
  const amount = readAmount(input);
  if (!amount) return { required: false };
  if (amount.currency !== gate.required_above.currency) return { required: true, detail: `${fmt(amount)} cannot be compared with the standard's threshold of ${fmt(gate.required_above)}` };
  if (amount.minor > gate.required_above.minor) return { required: true, detail: `${fmt(amount)} is above ${fmt(gate.required_above)}, so a named person approves it` };
  return { required: false };
}
function heldIdFor(sid, tool, payloadHash) {
  return createHash2("sha256").update(`scopeblind.held_action.v1\0${sid}\0${tool}\0${payloadHash}`).digest("hex").slice(0, 24);
}
function sidFromReportUrl(url) {
  try {
    const s = new URL(url).searchParams.get("s");
    return s && /^[0-9a-f]{24}$/.test(s) ? s : null;
  } catch {
    return null;
  }
}
var RecordReporter = class {
  url;
  sid;
  runId;
  token;
  fetchImpl;
  log;
  queue = [];
  timer = null;
  flushing = Promise.resolve();
  /** Counts for the startup and shutdown lines. */
  sent = 0;
  failed = 0;
  constructor(opts) {
    const sid = sidFromReportUrl(opts.url);
    if (!sid) throw new Error("--report must be the standard page's report URL (https://scopeblind.com/api/standard?s=<id>)");
    this.url = opts.url;
    this.sid = sid;
    this.token = opts.token;
    this.runId = opts.runId;
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
    this.log = opts.log ?? ((m) => process.stderr.write(`[PROTECT_MCP] ${m}
`));
  }
  async post(op, body) {
    const resp = await this.fetchImpl(`${this.url}&op=${op}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${this.token}` }, body: JSON.stringify({ sid: this.sid, ...body }), signal: AbortSignal.timeout(8e3) });
    const parsed = await resp.json().catch(() => ({}));
    return { ok: resp.ok, status: resp.status, body: parsed };
  }
  /** Queues one receipt line (and its call line) for the next flush. Never throws. */
  record(receipt, call) {
    this.queue.push({ receipt, call });
    if (!this.timer) this.timer = setTimeout(() => {
      this.timer = null;
      void this.flush();
    }, 800);
    this.timer.unref?.();
  }
  /** Sends everything queued, in order, as one append. */
  flush() {
    this.flushing = this.flushing.then(async () => {
      if (this.queue.length === 0) return;
      const batch = this.queue;
      this.queue = [];
      const receipts = batch.map((b) => b.receipt).filter((r) => !!r).join("\n");
      const calls = batch.map((b) => b.call).filter((c) => !!c).join("\n");
      try {
        const r = await this.post("record", { run_id: this.runId, receipts, calls, append: true });
        if (r.ok) this.sent += batch.length;
        else {
          this.failed += batch.length;
          this.log(`Record not accepted by the standard's page (${r.status} ${String(r.body.error ?? "")}); the local chain is intact`);
        }
      } catch (err) {
        this.failed += batch.length;
        this.log(`Record could not reach the standard's page (${err instanceof Error ? err.message : String(err)}); the local chain is intact`);
      }
    });
    return this.flushing;
  }
  /** Posts a held action. Returns the page URL to send the model to, or null when the page could not be reached. */
  async hold(held) {
    try {
      const r = await this.post("held", { ...held, run_id: this.runId });
      if (r.ok && typeof r.body.url === "string") return r.body.url;
      this.log(`Held action not accepted by the standard's page (${r.status} ${String(r.body.error ?? "")})`);
      return null;
    } catch (err) {
      this.log(`Held action could not reach the standard's page (${err instanceof Error ? err.message : String(err)})`);
      return null;
    }
  }
  /** The decision a person recorded for a held action: approve, deny, none yet (null), or unreachable. */
  async decision(hid) {
    try {
      const resp = await this.fetchImpl(`${this.url}&held=${hid}`, { method: "GET", headers: { accept: "application/json" }, signal: AbortSignal.timeout(8e3) });
      if (resp.status === 404) return null;
      const body = await resp.json().catch(() => ({}));
      if (!resp.ok || !body.ok || !body.held) return "unreachable";
      const d = body.held.decision;
      if (!d || d.decision !== "approve" && d.decision !== "deny") return null;
      return { decision: d.decision, approver_key_id: d.approver?.key_id ?? "unknown", digest: d.digest ?? "", note: d.note ?? "" };
    } catch {
      return "unreachable";
    }
  }
};

export {
  ReceiptBuffer,
  startStatusServer,
  buildActionReadback,
  loadStandardFile,
  readAmount,
  checkAmount,
  personRequired,
  heldIdFor,
  RecordReporter
};
