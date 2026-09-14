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
var import_node_crypto8 = require("crypto");
var import_node_fs9 = require("fs");
var import_node_path6 = require("path");

// src/cedar-evaluator.ts
var import_node_fs2 = require("fs");
var import_node_path2 = require("path");

// src/policy-digest.ts
var import_node_crypto = require("crypto");
var import_node_fs = require("fs");
var import_node_path = require("path");

// src/acta-envelope.ts
var import_ed25519 = require("@noble/curves/ed25519");
var import_sha256 = require("@noble/hashes/sha256");
var import_utils = require("@noble/hashes/utils");
function canonicalize(obj) {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const sorted = {};
      for (const k of Object.keys(value).sort()) {
        if (!/^[\x20-\x7E]*$/.test(k)) {
          throw new Error(`Non-ASCII key "${k}" in receipt payload. Only ASCII keys are permitted.`);
        }
        sorted[k] = value[k];
      }
      return sorted;
    }
    return value;
  });
}
function receiptHash(obj) {
  return (0, import_utils.bytesToHex)((0, import_sha256.sha256)((0, import_utils.utf8ToBytes)(canonicalize(obj))));
}
var B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let n = BigInt("0x" + (0, import_utils.bytesToHex)(bytes));
  let out = "";
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}
function computeSbIssuerKid(publicKeyHex) {
  return `sb:issuer:${base58((0, import_utils.hexToBytes)(publicKeyHex)).slice(0, 12)}`;
}
function createReceiptEnvelope(fields, privateKeyHex, kid, issuedAt) {
  if (!fields.type) throw new Error("receipt payload requires a type");
  if (!kid) throw new Error("kid is required");
  const payload = {
    ...fields,
    issued_at: fields.issued_at || issuedAt || (/* @__PURE__ */ new Date()).toISOString(),
    issuer_id: kid
  };
  const sig = (0, import_utils.bytesToHex)(import_ed25519.ed25519.sign((0, import_utils.utf8ToBytes)(canonicalize(payload)), (0, import_utils.hexToBytes)(privateKeyHex)));
  const envelope = { payload, signature: { alg: "EdDSA", kid, sig } };
  return { envelope, hash: receiptHash(envelope) };
}
function verifyReceipt(envelope, publicKeyHex) {
  try {
    if (!envelope || typeof envelope !== "object") {
      return { valid: false, shape: null, error: "not_an_object" };
    }
    const env = envelope;
    const signature = env.signature;
    if (signature && typeof signature === "object" && !Array.isArray(signature)) {
      const sigObj = signature;
      if (sigObj.alg !== "EdDSA") {
        return { valid: false, shape: "acta-02", error: `unsupported_alg:${String(sigObj.alg)}` };
      }
      if (typeof sigObj.sig !== "string" || !env.payload || typeof env.payload !== "object") {
        return { valid: false, shape: "acta-02", error: "malformed_envelope" };
      }
      const message = (0, import_utils.utf8ToBytes)(canonicalize(env.payload));
      const valid = import_ed25519.ed25519.verify((0, import_utils.hexToBytes)(sigObj.sig), message, (0, import_utils.hexToBytes)(publicKeyHex));
      return valid ? { valid: true, shape: "acta-02", hash: receiptHash(env) } : { valid: false, shape: "acta-02", error: "invalid_signature" };
    }
    if (typeof signature === "string") {
      const rest = {};
      for (const k of Object.keys(env)) if (k !== "signature") rest[k] = env[k];
      const message = (0, import_utils.utf8ToBytes)(canonicalize(rest));
      const valid = import_ed25519.ed25519.verify((0, import_utils.hexToBytes)(signature), message, (0, import_utils.hexToBytes)(publicKeyHex));
      const shape = env.v === 2 ? "legacy-v2" : "legacy-v1";
      return valid ? { valid: true, shape, hash: receiptHash(env) } : { valid: false, shape, error: "invalid_signature" };
    }
    return { valid: false, shape: null, error: "missing_signature" };
  } catch (err) {
    return {
      valid: false,
      shape: null,
      error: `verification_error:${err instanceof Error ? err.message : "unknown"}`
    };
  }
}

// src/policy-digest.ts
var POLICY_DIGEST_CONSTRUCTION = "acta-policy-digest-v1";
var sha256hex = (data) => (0, import_node_crypto.createHash)("sha256").update(data).digest("hex");
function digestPolicyFiles(engine, files) {
  if (files.length === 0) throw new Error("policy digest requires at least one file");
  const names = /* @__PURE__ */ new Set();
  for (const f of files) {
    if (!f.name) throw new Error("policy file entries require a name");
    if (names.has(f.name)) throw new Error(`duplicate policy file name: ${f.name}`);
    names.add(f.name);
  }
  const entries = files.map((f) => ({ name: f.name, sha256: sha256hex(Buffer.from(f.content, "utf-8")) })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  const manifest = { construction: POLICY_DIGEST_CONSTRUCTION, engine, files: entries };
  return {
    policy_digest: `sha256:${sha256hex(Buffer.from(canonicalize(manifest), "utf-8"))}`,
    construction: POLICY_DIGEST_CONSTRUCTION,
    engine,
    files: entries
  };
}
function digestCedarSource(source) {
  return digestPolicyFiles("cedar", [{ name: "policy.cedar", content: source }]);
}
function digestBuiltinPolicy(policy) {
  return digestPolicyFiles("builtin", [{ name: "policy.json", content: canonicalize(policy) }]);
}

// src/cedar-evaluator.ts
var cedarWasm = null;
var loadAttempted = false;
var cedarWasmSpecifier = null;
var cedarWasmLoadError = null;
var CEDAR_WASM_SPECIFIERS = ["@cedar-policy/cedar-wasm/nodejs", "@cedar-policy/cedar-wasm"];
async function ensureCedarWasm() {
  if (cedarWasm) return true;
  if (loadAttempted) return false;
  loadAttempted = true;
  const errors = [];
  for (const moduleName of CEDAR_WASM_SPECIFIERS) {
    try {
      const mod = await import(
        /* @vite-ignore */
        moduleName
      );
      const engine = mod && (mod.default || mod);
      if (!engine || typeof engine.isAuthorized !== "function") {
        errors.push(`${moduleName}: loaded but has no isAuthorized`);
        continue;
      }
      cedarWasm = mod;
      cedarWasmSpecifier = moduleName;
      return true;
    } catch (err) {
      const msg = err instanceof Error ? `${err.code ? err.code + " " : ""}${err.message.split("\n")[0]}` : String(err);
      errors.push(`${moduleName}: ${msg}`);
    }
  }
  cedarWasmLoadError = errors.join("; ");
  return false;
}
function loadCedarPolicies(dirPath) {
  if (!(0, import_node_fs2.existsSync)(dirPath)) {
    throw new Error(`Cedar policy directory not found: ${dirPath}`);
  }
  const entries = (0, import_node_fs2.readdirSync)(dirPath).filter((f) => (0, import_node_path2.extname)(f) === ".cedar").sort();
  if (entries.length === 0) {
    throw new Error(`No .cedar files found in: ${dirPath}`);
  }
  const files = [];
  for (const file of entries) {
    files.push({ name: file, content: (0, import_node_fs2.readFileSync)((0, import_node_path2.join)(dirPath, file), "utf-8") });
  }
  const concatenated = files.map((f) => f.content).join("\n\n");
  const digest = digestPolicyFiles("cedar", files).policy_digest;
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
    return onEvalError(`cedar_wasm_not_available: ${cedarWasmLoadError || "unknown load failure"}`, failClosed, { fallback: true });
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
      action: { type: "Action", id: req.actionModel === "tool" ? req.tool : "MCP::Tool::call" },
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
function policySetFromSource(source, name = "inline") {
  const digest = digestCedarSource(source).policy_digest;
  return { source, digest, fileCount: 1, files: [name] };
}
async function runEvaluatorSelfTest() {
  const wasmAvailable = await isCedarAvailable();
  const cases = [];
  const run = async (name, expected, policy, context) => {
    const d = await evaluateCedar(policy, { tool: "Bash", tier: "unknown", context }, void 0, { failClosed: true });
    const actual = d.allowed ? "ALLOW" : "DENY";
    cases.push({ name, expected, actual, pass: actual === expected, reason: d.reason });
  };
  if (!wasmAvailable) {
    await run("engine unavailable denies", "DENY", policySetFromSource("permit(principal, action, resource);"), {});
    return { wasmAvailable, passed: cases.every((c) => c.pass), cases };
  }
  const correct = policySetFromSource(
    'forbid(principal, action, resource) when { ["rm", "dd", "mkfs"].contains(context.command) };\npermit(principal, action, resource);'
  );
  await run("forbid denies rm", "DENY", correct, { command: "rm" });
  await run("permit allows ls", "ALLOW", correct, { command: "ls" });
  const broken = policySetFromSource(
    'forbid(principal, action, resource) when { context.command in ["rm", "dd"] };\npermit(principal, action, resource);'
  );
  await run("in-on-String forbid does not permit-all", "DENY", broken, { command: "rm" });
  return { wasmAvailable, passed: cases.every((c) => c.pass), cases };
}

// src/standard-gate.ts
var import_node_crypto2 = require("crypto");
var import_node_fs3 = require("fs");
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
  return parseStandard(JSON.parse((0, import_node_fs3.readFileSync)(path, "utf-8")));
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
  return (0, import_node_crypto2.createHash)("sha256").update(`scopeblind.held_action.v1\0${sid}\0${tool}\0${payloadHash}`).digest("hex").slice(0, 24);
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

// src/signing.ts
var import_node_fs4 = require("fs");
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
  if (!(0, import_node_fs4.existsSync)(config.key_path)) {
    signingInitError = `key file not found at ${config.key_path}`;
    warnings.push(`signing: ${signingInitError} \u2014 run "protect-mcp init" to generate`);
    return warnings;
  }
  let keyData;
  try {
    keyData = JSON.parse((0, import_node_fs4.readFileSync)(config.key_path, "utf-8"));
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
      spec: "draft-farley-acta-signed-receipts-03",
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
    if (entry.mandate_registry) payload.mandate_registry = entry.mandate_registry;
    if (entry.standard) payload.standard = entry.standard;
    if (entry.approval) payload.approval = entry.approval;
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
function signGenericArtifact(_artifactType, payload) {
  if (signingConfigured && signingInitError) {
    return { ok: false, signed: null, warning: `signing initialization failed: ${signingInitError}`, error: signingInitError };
  }
  if (signingConfigured && !signerState) {
    const error = "signing was configured but no signer is ready";
    return { ok: false, signed: null, warning: error, error };
  }
  if (!signerState) {
    return { ok: false, signed: null };
  }
  try {
    const full = {
      ...payload,
      type: String(payload.type || "protectmcp:artifact"),
      public_key: signerState.publicKey
    };
    if (signerState.issuer && signerState.issuer !== signerState.kid && full.type !== "scopeblind.egress_summary.v1") {
      full.issuer_name = signerState.issuer;
    }
    const result = createReceiptEnvelope(full, signerState.privateKey, signerState.kid);
    return { ok: true, signed: JSON.stringify(result.envelope) };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown error";
    return { ok: false, signed: null, warning: `signing failed: ${message}`, error: message };
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

// src/policy.ts
var import_node_fs5 = require("fs");
function loadPolicy(path) {
  const raw = (0, import_node_fs5.readFileSync)(path, "utf-8");
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

// src/http-server.ts
var import_node_http = require("http");
var import_node_fs6 = require("fs");
var import_node_path3 = require("path");
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
var import_node_crypto4 = require("crypto");
var import_node_fs7 = require("fs");
var import_node_os = require("os");
var import_node_path4 = require("path");

// src/egress-guard.ts
var import_node_crypto3 = require("crypto");
var EGRESS_SUMMARY_TYPE = "scopeblind.egress_summary.v1";
var EGRESS_SUMMARY_VERSION = 1;
var EGRESS_SUMMARY_FIELDS = /* @__PURE__ */ new Set([
  "type",
  "version",
  "source_receipt_commitment",
  "request_pseudonym",
  "decision",
  "reason_code",
  "tool_category",
  "policy_commitment",
  "mode",
  "action_commitment",
  "output_commitment",
  "disclosed_field_count",
  "deny_iteration"
]);
var EGRESS_SIGNED_PAYLOAD_FIELDS = /* @__PURE__ */ new Set([
  ...EGRESS_SUMMARY_FIELDS,
  "public_key",
  "issuer_id",
  "issued_at"
]);
var KNOWN_RECEIPT_TYPES = /* @__PURE__ */ new Set(["protectmcp:decision", "protectmcp:artifact", "scopeblind.coverage_statement.v1"]);
var DECISIONS = /* @__PURE__ */ new Set(["allow", "deny", "approve"]);
var MODES = /* @__PURE__ */ new Set(["enforce", "shadow", "audit"]);
var REASON_CODES = /* @__PURE__ */ new Set([
  "cedar_allow",
  "cedar_deny",
  "policy_allow",
  "policy_deny",
  "policy_head_mismatch",
  "mandate_expired",
  "mandate_missing",
  "mandate_denied",
  "approval_required",
  "approval_denied",
  "signing_error",
  "rate_limited",
  "other"
]);
function str(v) {
  return typeof v === "string" && v.length ? v : void 0;
}
function integer(v) {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : void 0;
}
function hmacCommitment(domain, value, opts) {
  return `hmac-sha256:${(0, import_node_crypto3.createHmac)("sha256", opts.pseudonymKey).update(`${domain}\0${opts.tenantScope || ""}\0${String(value ?? "")}`).digest("hex")}`;
}
function isReceiptCommitment(value) {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
}
function isPseudonym(value) {
  return typeof value === "string" && /^hmac-sha256:[0-9a-f]{64}$/.test(value);
}
function isPublicKey(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
function isIssuedAt(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function code(value) {
  const leading = (str(value) || "").split(/[\s:]/)[0].toLowerCase().slice(0, 64);
  return REASON_CODES.has(leading) ? leading : "other";
}
function category(tool) {
  const value = (str(tool) || "").toLowerCase();
  if (/(email|mail|slack|teams|message)/.test(value)) return "communication";
  if (/(github|git|commit|pull_request)/.test(value)) return "source_control";
  if (/(file|bash|shell|terminal|directory)/.test(value)) return "filesystem";
  if (/(sql|database|query)/.test(value)) return "database";
  if (/(aws|gcp|azure|cloud|deploy)/.test(value)) return "cloud";
  if (/(browser|web|fetch|http)/.test(value)) return "browser";
  if (/(trade|order|pms|broker|position)/.test(value)) return "finance";
  return "other";
}
function toEgressSummary(envelope, opts) {
  if (!opts?.pseudonymKey || typeof opts.pseudonymKey === "string" && !opts.pseudonymKey.length || opts.pseudonymKey instanceof Uint8Array && !opts.pseudonymKey.length) return null;
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) return null;
  const env = envelope;
  const p = env.payload;
  if (!p || typeof p !== "object" || typeof p.type !== "string" || !KNOWN_RECEIPT_TYPES.has(p.type)) return null;
  const ar = p.action_readback;
  const pd = p.payload_digest;
  const disclosed = ar && Array.isArray(ar.disclosed_fields) ? ar.disclosed_fields.length : void 0;
  const rawDecision = str(p.decision);
  const summary = {
    type: EGRESS_SUMMARY_TYPE,
    version: EGRESS_SUMMARY_VERSION,
    source_receipt_commitment: `sha256:${receiptHash(envelope)}`,
    request_pseudonym: hmacCommitment("scopeblind.egress.request.v1", p.request_id || p.scope || "", opts),
    decision: rawDecision && DECISIONS.has(rawDecision) ? rawDecision : "other",
    reason_code: code(p.reason),
    tool_category: category(p.tool_name),
    policy_commitment: hmacCommitment("scopeblind.egress.policy.v1", p.policy_digest || "", opts),
    mode: str(p.mode) && MODES.has(str(p.mode)) ? str(p.mode) : "other",
    ...ar && str(ar.payload_hash) ? { action_commitment: hmacCommitment("scopeblind.egress.action.v1", ar.payload_hash, opts) } : {},
    ...pd && str(pd.output_hash) ? { output_commitment: hmacCommitment("scopeblind.egress.output.v1", pd.output_hash, opts) } : {},
    ...disclosed !== void 0 ? { disclosed_field_count: disclosed } : {},
    ...integer(p.deny_iteration) !== void 0 ? { deny_iteration: integer(p.deny_iteration) } : {}
  };
  return summary;
}
function inspectEgress(obj, opts = {}) {
  const violations = [];
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return { safe: false, violations: [{ path: "$", reason: "not an egress summary object" }] };
  const o = obj;
  const allowed = opts.signed ? EGRESS_SIGNED_PAYLOAD_FIELDS : EGRESS_SUMMARY_FIELDS;
  for (const [key, value] of Object.entries(o)) {
    if (!allowed.has(key)) {
      violations.push({ path: `$.${key}`, reason: "field is not allowed in an egress summary" });
      continue;
    }
    if (value === null || value === void 0) {
      violations.push({ path: `$.${key}`, reason: "null and undefined are not permitted" });
      continue;
    }
    if (typeof value === "object") violations.push({ path: `$.${key}`, reason: "nested objects and arrays are not permitted" });
  }
  if (o.type !== EGRESS_SUMMARY_TYPE) violations.push({ path: "$.type", reason: "wrong egress summary type" });
  if (o.version !== EGRESS_SUMMARY_VERSION) violations.push({ path: "$.version", reason: "unsupported egress summary version" });
  if (!isReceiptCommitment(o.source_receipt_commitment)) violations.push({ path: "$.source_receipt_commitment", reason: "must be a sha256 receipt commitment" });
  for (const field of ["request_pseudonym", "policy_commitment"]) if (!isPseudonym(o[field])) violations.push({ path: `$.${field}`, reason: "must be a local hmac-sha256 pseudonym" });
  for (const field of ["action_commitment", "output_commitment"]) if (o[field] !== void 0 && !isPseudonym(o[field])) violations.push({ path: `$.${field}`, reason: "must be a local hmac-sha256 pseudonym" });
  if (!["allow", "deny", "approve", "other"].includes(String(o.decision))) violations.push({ path: "$.decision", reason: "invalid decision enum" });
  if (!REASON_CODES.has(String(o.reason_code))) violations.push({ path: "$.reason_code", reason: "invalid reason code enum" });
  if (!["communication", "source_control", "filesystem", "database", "cloud", "browser", "finance", "other"].includes(String(o.tool_category))) violations.push({ path: "$.tool_category", reason: "invalid tool category enum" });
  if (!["enforce", "shadow", "audit", "other"].includes(String(o.mode))) violations.push({ path: "$.mode", reason: "invalid mode enum" });
  for (const field of ["disclosed_field_count", "deny_iteration"]) if (o[field] !== void 0 && (!Number.isSafeInteger(o[field]) || Number(o[field]) < 0 || Number(o[field]) > 1e6)) violations.push({ path: `$.${field}`, reason: "must be a bounded non-negative integer" });
  if (opts.signed) {
    if (!isPublicKey(o.public_key)) violations.push({ path: "$.public_key", reason: "must be a 32-byte Ed25519 public key" });
    if (typeof o.issuer_id !== "string" || !/^[\x21-\x7e]{1,160}$/.test(o.issuer_id)) violations.push({ path: "$.issuer_id", reason: "must be a compact issuer id" });
    if (!isIssuedAt(o.issued_at)) violations.push({ path: "$.issued_at", reason: "must be an ISO timestamp" });
  }
  return { safe: violations.length === 0, violations };
}

// src/scopeblind-bridge.ts
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
  const dir = env.SCOPEBLIND_EGRESS_KEY_DIR || (0, import_node_path4.join)((0, import_node_os.homedir)(), ".protect-mcp", "egress-keys");
  const scopeDigest = (0, import_node_crypto4.createHash)("sha256").update(`${base}\0${slug}`).digest("hex");
  const path = (0, import_node_path4.join)(dir, `${scopeDigest}.key`);
  (0, import_node_fs7.mkdirSync)(dir, { recursive: true, mode: 448 });
  (0, import_node_fs7.chmodSync)(dir, 448);
  try {
    const existing = (0, import_node_fs7.readFileSync)(path);
    if (existing.length !== 32) throw new Error(`local egress key has invalid length: ${path}`);
    (0, import_node_fs7.chmodSync)(path, 384);
    return existing;
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
  }
  const fresh = (0, import_node_crypto4.randomBytes)(32);
  try {
    (0, import_node_fs7.writeFileSync)(path, fresh, { mode: 384, flag: "wx" });
    return fresh;
  } catch (err) {
    if (err?.code !== "EEXIST") throw err;
    const existing = (0, import_node_fs7.readFileSync)(path);
    if (existing.length !== 32) throw new Error(`local egress key has invalid length: ${path}`);
    (0, import_node_fs7.chmodSync)(path, 384);
    return existing;
  }
}
var singleton = null;
function getScopeBlindBridge() {
  if (!singleton) singleton = new ScopeBlindBridge();
  return singleton;
}

// src/action-readback.ts
var import_node_crypto5 = require("crypto");
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
    payload_hash: (0, import_node_crypto5.createHash)("sha256").update(canonical).digest("hex"),
    payload_bytes: Buffer.byteLength(canonical, "utf-8"),
    disclosed_fields: [...new Set(disclosedFields)].slice(0, 80),
    redacted_fields: [...new Set(redactedFields)].slice(0, 80),
    summary
  };
}

// src/receipt-enrichment.ts
var import_sha2562 = require("@noble/hashes/sha256");
var import_utils2 = require("@noble/hashes/utils");
var ENRICHMENT_VERSION = 2;
function canonicalJson(value) {
  const seen = /* @__PURE__ */ new WeakSet();
  const enc = (v) => {
    if (v === null || v === void 0) return "null";
    const t = typeof v;
    if (t === "number") return Number.isFinite(v) ? JSON.stringify(v) : "null";
    if (t === "boolean" || t === "string") return JSON.stringify(v);
    if (t === "bigint") return JSON.stringify(v.toString());
    if (t === "function" || t === "symbol") return "null";
    if (Array.isArray(v)) return "[" + v.map(enc).join(",") + "]";
    if (t === "object") {
      const o = v;
      if (seen.has(o)) return '"[circular]"';
      seen.add(o);
      const body = Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + enc(o[k])).join(",");
      seen.delete(o);
      return "{" + body + "}";
    }
    return "null";
  };
  return enc(value);
}
function sha256Hex(s) {
  return (0, import_utils2.bytesToHex)((0, import_sha2562.sha256)(new TextEncoder().encode(s)));
}
var RULES = [
  { cap: "exec.shell", tool: /bash|shell|exec|terminal|run_command|command/ },
  { cap: "fs.read", tool: /(^|[_.])(read|cat|glob|grep|search|ls|view|list_files|open)/ },
  { cap: "fs.write", tool: /write|create_file|save|append|edit|patch|replace|update_file|multiedit|notebook/ },
  { cap: "fs.delete", tool: /delete|remove|unlink|trash|(^|[_.])rm/ },
  { cap: "net.egress", tool: /fetch|http|curl|wget|request|download|browse|navigate|webfetch|web_search|scrape/ },
  { cap: "vcs", tool: /(^|[_.])git/, text: /\bgit\s+(commit|push|pull|clone|reset|checkout|branch|rebase|merge|tag)\b/ },
  { cap: "package.install", text: /\b(npm|pnpm|yarn)\s+(i|install|add)\b|\bpip3?\s+install\b|\bgo\s+get\b|\bcargo\s+add\b|\bbrew\s+install\b|\bapt(-get)?\s+install\b|\bgem\s+install\b/ },
  { cap: "secret.adjacent", text: /\.env\b|secret|credential|passwd|password|api[_-]?key|private[_-]?key|\.pem\b|\.key\b|id_rsa|bearer\s|aws_(access|secret)|authorization/ },
  { cap: "destructive", text: /rm\s+-[a-z]*[rf]|\brmdir\b|drop\s+table|truncate\s+table|delete\s+from|reset\s+--hard|--force\b|\bmkfs\b|\bdd\s+if=|shutdown|reboot|kill\s+-9|>\s*\/dev\/sd/ },
  { cap: "financial", text: /\b(order|trade|buy|sell|transfer|wire|payment|withdraw|deposit|swap|invoice|charge|refund|settle)\b/ },
  { cap: "data.query", text: /\bselect\s+[\s\S]+\bfrom\b|\binsert\s+into\b|\bupdate\s+[\s\S]+\bset\b|\bdelete\s+from\b/ },
  // Agent payments (x402 / value transfer). Deliberately BROAD: a false positive
  // only makes a `claim --no payment` harder to assert (conservative); a false
  // negative would let a real payment escape the record's payment claims.
  { cap: "payment", tool: /(^|[_.-])(pay|payment|x402|checkout)($|[_.-])|wallet.*send|send.*payment/, text: /x402|x-payment|paymentrequirements|maxamountrequired|payto|"pay_to"|eip-3009|transferwithauthorization|payment_intent|send_payment|create_payment/ }
];
function deriveCapabilities(tool, input) {
  const t = String(tool || "").toLowerCase();
  let text = "";
  try {
    text = canonicalJson(input).toLowerCase();
  } catch {
  }
  const caps = /* @__PURE__ */ new Set();
  for (const r of RULES) {
    if (r.tool && r.tool.test(t)) caps.add(r.cap);
    if (r.text && r.text.test(text)) caps.add(r.cap);
  }
  return Array.from(caps).sort();
}
function deriveResource(input) {
  const o = input && typeof input === "object" ? input : {};
  const path = o.file_path ?? o.path ?? o.filePath ?? o.notebook_path ?? o.filename;
  if (typeof path === "string" && path.trim()) return { kind: "path", digest: sha256Hex(path.replace(/\\/g, "/")) };
  const url = o.url ?? o.uri ?? o.endpoint ?? o.href;
  if (typeof url === "string" && url.trim()) {
    try {
      return { kind: "host", digest: sha256Hex(new URL(url).host.toLowerCase()) };
    } catch {
    }
  }
  const cmd = o.command ?? o.cmd ?? o.script;
  if (typeof cmd === "string" && cmd.trim()) {
    const first = cmd.trim().split(/\s+/)[0];
    if (first) return { kind: "command", digest: sha256Hex(first) };
  }
  return void 0;
}
function findField(input, names, depth = 0) {
  if (depth > 4 || input === null || typeof input !== "object") return void 0;
  const o = input;
  const keys = Object.keys(o).sort();
  for (const k of keys) {
    if (names.indexOf(k.toLowerCase()) >= 0 && o[k] !== void 0 && o[k] !== null) return o[k];
  }
  for (const k of keys) {
    const v = findField(o[k], names, depth + 1);
    if (v !== void 0) return v;
  }
  return void 0;
}
function derivePayment(tool, input) {
  if (deriveCapabilities(tool, input).indexOf("payment") < 0) return void 0;
  const p = { amount: null, asset: null, recipient_digest: null };
  const amt = findField(input, ["amount"]);
  if (typeof amt === "number" && Number.isFinite(amt) && amt >= 0) p.amount = amt;
  else if (typeof amt === "string" && /^\d{1,15}(\.\d{1,18})?$/.test(amt.trim()) && amt.indexOf(".") >= 0) p.amount = parseFloat(amt);
  const asset = findField(input, ["asset", "currency", "token"]);
  if (typeof asset === "string" && asset.trim()) p.asset = asset.trim().slice(0, 64);
  const to = findField(input, ["payto", "pay_to", "recipient", "destination", "to"]);
  if (typeof to === "string" && to.trim()) p.recipient_digest = sha256Hex(to.trim().toLowerCase());
  const scheme = findField(input, ["scheme"]);
  if (typeof scheme === "string" && scheme.trim()) p.scheme = scheme.trim().slice(0, 32);
  return p;
}
function buildEnrichment(tool, input) {
  const e = {
    v: ENRICHMENT_VERSION,
    input_digest: sha256Hex(canonicalJson(input ?? {})),
    capabilities: deriveCapabilities(tool, input)
  };
  const resource = deriveResource(input);
  if (resource) e.resource = resource;
  const payment = derivePayment(tool, input);
  if (payment) e.payment = payment;
  return e;
}

// src/mandate-lifecycle.ts
var import_node_crypto7 = require("crypto");
var import_node_fs8 = require("fs");
var import_node_path5 = require("path");

// src/webauthn-approval.ts
var import_node_crypto6 = require("crypto");
var import_p256 = require("@noble/curves/p256");
var import_ed255192 = require("@noble/curves/ed25519");
var import_sha2563 = require("@noble/hashes/sha256");
var import_utils3 = require("@noble/hashes/utils");
function createApprovalChallenge(requestId, toolName, agentId, rpId = "scopeblind.com", timeoutSeconds = 300, boundChallenge) {
  const challenge = boundChallenge ?? base64urlEncode((0, import_node_crypto6.randomBytes)(32));
  const contextHash = (0, import_node_crypto6.createHash)("sha256").update(JSON.stringify({ requestId, toolName, agentId, timestamp: Date.now() })).digest("hex");
  return {
    challenge,
    requestId,
    toolName,
    agentId,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    timeoutSeconds,
    rpId,
    contextHash
  };
}
function verifyApprovalAssertion(challenge, assertion, credentialPublicKey, opts = {}) {
  const now = opts.now ?? Date.now();
  const fail = (reason, partial = {}) => ({
    valid: false,
    reason,
    credentialId: assertion.credentialId,
    authenticatorType: "unknown",
    userVerified: false,
    signCount: 0,
    contextHash: challenge.contextHash,
    approvedAt: new Date(now).toISOString(),
    ...partial
  });
  const createdAt = new Date(challenge.createdAt).getTime();
  if (now - createdAt > challenge.timeoutSeconds * 1e3) return fail("challenge_expired");
  if (!credentialPublicKey?.publicKeyHex) return fail("missing_credential_public_key");
  const clientDataBytes = base64urlDecode(assertion.clientDataJSON);
  let clientData;
  try {
    clientData = JSON.parse(Buffer.from(clientDataBytes).toString("utf8"));
  } catch {
    return fail("client_data_parse_error");
  }
  if (clientData.type !== "webauthn.get") return fail("wrong_client_data_type");
  if (!constantTimeStrEqual(clientData.challenge ?? "", challenge.challenge)) return fail("challenge_mismatch");
  const allowedOrigins = opts.expectedOrigin ? Array.isArray(opts.expectedOrigin) ? opts.expectedOrigin : [opts.expectedOrigin] : [`https://${challenge.rpId}`];
  if (!clientData.origin || !allowedOrigins.includes(clientData.origin)) return fail("origin_mismatch");
  const authData = base64urlDecode(assertion.authenticatorData);
  if (authData.length < 37) return fail("authenticator_data_too_short");
  const rpIdHash = authData.slice(0, 32);
  const expectedRpIdHash = (0, import_sha2563.sha256)(new TextEncoder().encode(challenge.rpId));
  if (!bytesEqual(rpIdHash, expectedRpIdHash)) return fail("rp_id_hash_mismatch");
  const flags = authData[32];
  const userPresent = !!(flags & 1);
  const userVerified = !!(flags & 4);
  if (!userPresent) return fail("user_not_present");
  if ((opts.requireUserVerification ?? true) && !userVerified) return fail("user_verification_required", { userVerified });
  const signCount = authData[33] << 24 | authData[34] << 16 | authData[35] << 8 | authData[36];
  if (typeof opts.prevSignCount === "number" && signCount !== 0 && signCount <= opts.prevSignCount) {
    return fail("sign_count_regression", { userVerified, signCount });
  }
  const signedData = concatBytes(authData, (0, import_sha2563.sha256)(clientDataBytes));
  const sigBytes = base64urlDecode(assertion.signature);
  let sigOk = false;
  try {
    if (credentialPublicKey.alg === -7) {
      sigOk = import_p256.p256.verify(sigBytes, (0, import_sha2563.sha256)(signedData), (0, import_utils3.hexToBytes)(credentialPublicKey.publicKeyHex), { format: "der" });
    } else if (credentialPublicKey.alg === -8) {
      sigOk = import_ed255192.ed25519.verify(sigBytes, signedData, (0, import_utils3.hexToBytes)(credentialPublicKey.publicKeyHex));
    } else {
      return fail("unsupported_algorithm", { userVerified, signCount });
    }
  } catch {
    sigOk = false;
  }
  if (!sigOk) return fail("invalid_signature", { userVerified, signCount });
  return {
    valid: true,
    credentialId: assertion.credentialId,
    // Heuristic: platform authenticators (TouchID/FaceID/Hello) report UV; roaming
    // keys without a PIN are UP-only. Attachment is authoritative only at registration.
    authenticatorType: userVerified ? "platform" : "cross-platform",
    userVerified,
    signCount,
    contextHash: challenge.contextHash,
    approvedAt: new Date(now).toISOString()
  };
}
function base64urlEncode(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(str2) {
  const base64 = str2.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  return (0, import_node_crypto6.timingSafeEqual)(Buffer.from(a), Buffer.from(b));
}
function constantTimeStrEqual(a, b) {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return (0, import_node_crypto6.timingSafeEqual)(ab, bb);
}

// src/mandate-lifecycle.ts
var MANDATE_REGISTRY_SCHEMA = "scopeblind.mandate-registry.v1";
var MANDATE_PROPOSAL_SCHEMA = "scopeblind.mandate-proposal.v1";
var MANDATE_APPROVAL_SCHEMA = "scopeblind.mandate-approval.v1";
var SHA256 = (value) => (0, import_node_crypto7.createHash)("sha256").update(value).digest("hex");
function nowIso(now) {
  return (now || /* @__PURE__ */ new Date()).toISOString();
}
function safePolicyFileName(name) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*\.cedar$/.test(name) && !name.includes("..");
}
function stableDigest(value) {
  return `sha256:${SHA256(Buffer.from(canonicalize(value), "utf-8"))}`;
}
function controllerIdentity(c) {
  return c.type === "ed25519" ? { id: c.id, label: c.label, type: c.type, public_key: c.public_key.toLowerCase() } : { id: c.id, label: c.label, type: c.type, credential_id: c.credential_id, credential_public_key: c.credential_public_key };
}
function controllersDigest(controllers) {
  const identities = controllers.map(controllerIdentity).sort((a, b) => String(a.id) < String(b.id) ? -1 : String(a.id) > String(b.id) ? 1 : 0);
  return stableDigest(identities);
}
function controllerKeyMaterial(c) {
  return (c.type === "ed25519" ? c.public_key : c.credential_public_key?.publicKeyHex || "").toLowerCase();
}
function policyApprovalChallenge(proposal, controllerId) {
  return (0, import_node_crypto7.createHash)("sha256").update(Buffer.from(canonicalize({
    purpose: "scopeblind:policy-change",
    proposed_by: proposal.proposed_by,
    proposal_id: proposal.proposal_id,
    proposal_digest: proposal.proposal_digest,
    base_policy_digest: proposal.base_policy_digest,
    proposed_policy_digest: proposal.proposed_policy_digest,
    expires_at: proposal.expires_at,
    controller_id: controllerId
  }), "utf-8")).digest("base64url");
}
function mandatePaths(cedarDir) {
  const absolute = (0, import_node_path5.resolve)(cedarDir);
  const parent = (0, import_node_path5.dirname)(absolute);
  const base = (0, import_node_path5.basename)(absolute);
  return {
    registry: (0, import_node_path5.join)(parent, `.${base}.scopeblind-mandate-registry.json`),
    snapshots: (0, import_node_path5.join)(parent, `.${base}.scopeblind-mandate-snapshots`),
    auditLog: (0, import_node_path5.join)(parent, `.${base}.scopeblind-mandate-history.jsonl`)
  };
}
function loadGateSigner(keyPath) {
  const raw = JSON.parse((0, import_node_fs8.readFileSync)(keyPath, "utf-8"));
  if (typeof raw.privateKey !== "string" || !/^[0-9a-f]{64}$/i.test(raw.privateKey)) {
    throw new Error("gate key must contain a 32-byte hexadecimal privateKey");
  }
  if (typeof raw.publicKey !== "string" || !/^[0-9a-f]{64}$/i.test(raw.publicKey)) {
    throw new Error("gate key must contain a 32-byte hexadecimal publicKey");
  }
  if (typeof raw.kid !== "string" || raw.kid.length === 0) {
    throw new Error("gate key must contain a non-empty kid");
  }
  return {
    privateKey: raw.privateKey.toLowerCase(),
    publicKey: raw.publicKey.toLowerCase(),
    kid: raw.kid,
    ...typeof raw.issuer === "string" ? { issuer: raw.issuer } : {}
  };
}
function snapshotFromDirectory(cedarDir, compiledAt) {
  const entries = (0, import_node_fs8.readdirSync)(cedarDir, { encoding: "utf-8" }).filter((name) => name.endsWith(".cedar")).sort();
  if (entries.length === 0) throw new Error(`no Cedar policy files found in ${cedarDir}`);
  const files = entries.map((name) => {
    if (!safePolicyFileName(name)) throw new Error(`unsafe Cedar policy filename: ${name}`);
    const content = (0, import_node_fs8.readFileSync)((0, import_node_path5.join)(cedarDir, name), "utf-8");
    return { name, content, sha256: SHA256(Buffer.from(content, "utf-8")) };
  });
  const digest = digestPolicyFiles("cedar", files).policy_digest;
  return { engine: "cedar", policy_digest: digest, files, compiled_at: compiledAt || nowIso() };
}
function assertSnapshot(snapshot) {
  if (!snapshot || snapshot.engine !== "cedar" || !Array.isArray(snapshot.files) || snapshot.files.length === 0) {
    throw new Error("invalid Cedar policy snapshot");
  }
  for (const file of snapshot.files) {
    if (!safePolicyFileName(file.name)) throw new Error(`unsafe policy filename: ${file.name}`);
    if (SHA256(Buffer.from(file.content, "utf-8")) !== file.sha256) {
      throw new Error(`policy snapshot content hash mismatch: ${file.name}`);
    }
  }
  const actual = digestPolicyFiles("cedar", snapshot.files).policy_digest;
  if (actual !== snapshot.policy_digest) throw new Error("policy snapshot digest mismatch");
}
function signLifecycleEvent(signer, fields, issuedAt) {
  return createReceiptEnvelope({
    type: "scopeblind.mandate-transition.v1",
    ...fields,
    gate_public_key: signer.publicKey,
    ...signer.issuer ? { gate_issuer: signer.issuer } : {}
  }, signer.privateKey, signer.kid, issuedAt).envelope;
}
function verifyGateEnvelope(envelope, gate) {
  const check = verifyReceipt(envelope, gate.public_key);
  if (!check.valid) return false;
  const payload = envelope.payload;
  return payload.issuer_id === gate.kid && payload.gate_public_key === gate.public_key;
}
function writeAtomic(path, contents) {
  const parent = (0, import_node_path5.dirname)(path);
  (0, import_node_fs8.mkdirSync)(parent, { recursive: true });
  const temp = (0, import_node_path5.join)(parent, `.${(0, import_node_path5.basename)(path)}.${process.pid}.${(0, import_node_crypto7.randomUUID)()}.tmp`);
  try {
    (0, import_node_fs8.writeFileSync)(temp, contents, { encoding: "utf-8", mode: 384 });
    (0, import_node_fs8.renameSync)(temp, path);
  } finally {
    if ((0, import_node_fs8.existsSync)(temp)) (0, import_node_fs8.rmSync)(temp, { force: true });
  }
}
function persistRegistry(cedarDir, registry) {
  registry.updated_at = nowIso();
  const paths = mandatePaths(cedarDir);
  writeAtomic(paths.registry, JSON.stringify(registry, null, 2) + "\n");
  const last = registry.history[registry.history.length - 1];
  if (last) {
    (0, import_node_fs8.writeFileSync)(paths.auditLog, JSON.stringify(last) + "\n", { encoding: "utf-8", flag: "a", mode: 384 });
  }
}
function assertController(controller) {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(controller.id)) throw new Error("controller id is invalid");
  if (!controller.label.trim()) throw new Error("controller label is required");
  if (controller.type === "ed25519" && !/^[0-9a-f]{64}$/i.test(controller.public_key)) {
    throw new Error(`controller ${controller.id} requires a 32-byte Ed25519 public key`);
  }
  if (controller.type === "webauthn" && (!controller.credential_id || !controller.credential_public_key?.publicKeyHex)) {
    throw new Error(`controller ${controller.id} requires a registered WebAuthn credential`);
  }
}
function proposalUnsigned(input) {
  return {
    schema: input.schema,
    proposal_id: input.proposal_id,
    created_at: input.created_at,
    expires_at: input.expires_at,
    proposed_by: input.proposed_by,
    base_policy_digest: input.base_policy_digest,
    proposed_policy_digest: input.proposed_policy_digest,
    denial_origin: input.denial_origin,
    reason: input.reason,
    diff: input.diff,
    candidate: input.candidate
  };
}
function approvalDigest(approval) {
  return stableDigest(approval);
}
function transition(registry, signer, event, headBefore, headAfter, fields = {}, at = nowIso()) {
  const sequence = registry.history.length + 1;
  const body = {
    event,
    registry_id: registry.registry_id,
    sequence,
    head_before: headBefore,
    head_after: headAfter,
    ...fields
  };
  return {
    sequence,
    event,
    occurred_at: at,
    head_before: headBefore,
    head_after: headAfter,
    ...fields,
    transition_receipt: signLifecycleEvent(signer, body, at)
  };
}
function loadMandateRegistry(cedarDir) {
  const path = mandatePaths(cedarDir).registry;
  if (!(0, import_node_fs8.existsSync)(path)) return null;
  try {
    return JSON.parse((0, import_node_fs8.readFileSync)(path, "utf-8"));
  } catch (error) {
    throw new Error(`could not parse mandate registry: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}
function verifyDirectApproval(registry, proposal, approval) {
  const controller = registry.controllers.find((candidate) => candidate.id === approval.controller_id);
  if (!controller || controller.type !== "ed25519") return "controller_not_registered";
  const check = verifyReceipt(approval.approval_receipt, controller.public_key);
  if (!check.valid) return `approval_${check.error || "signature_invalid"}`;
  const payload = approval.approval_receipt.payload;
  if (payload.type !== MANDATE_APPROVAL_SCHEMA) return "approval_schema_invalid";
  if (payload.proposal_id !== proposal.proposal_id || payload.proposal_digest !== proposal.proposal_digest) return "approval_not_bound_to_proposal";
  if (payload.controller_id !== controller.id || payload.decision !== "approve") return "approval_controller_or_decision_invalid";
  if (approval.approval_receipt.signature.kid !== controller.id) return "approval_signer_kid_invalid";
  return null;
}
function verifyWebAuthnApproval(registry, proposal, approval) {
  const controller = registry.controllers.find((candidate) => candidate.id === approval.controller_id);
  if (!controller || controller.type !== "webauthn") return "controller_not_registered";
  if (approval.challenge.requestId !== proposal.proposal_id || approval.challenge.toolName !== "scopeblind:policy-change" || approval.challenge.challenge !== policyApprovalChallenge(proposal, controller.id)) {
    return "approval_not_bound_to_proposal";
  }
  if (approval.assertion.credentialId !== controller.credential_id) return "approval_credential_not_registered";
  const verified = verifyApprovalAssertion(approval.challenge, approval.assertion, controller.credential_public_key, {
    expectedOrigin: approval.expected_origin,
    requireUserVerification: true,
    now: Date.parse(approval.approved_at)
  });
  if (!verified.valid || !verified.userVerified) return `approval_${verified.reason || "webauthn_invalid"}`;
  if (!approval.result.valid || approval.result.contextHash !== verified.contextHash) return "approval_result_invalid";
  return null;
}
function verifyProposal(registry, proposal) {
  if (proposal.schema !== MANDATE_PROPOSAL_SCHEMA) return "proposal_schema_invalid";
  const unsigned = proposalUnsigned(proposal);
  if (stableDigest(unsigned) !== proposal.proposal_digest) return "proposal_digest_invalid";
  if (!verifyGateEnvelope(proposal.proposal_receipt, registry.gate)) return "proposal_signature_invalid";
  const payload = proposal.proposal_receipt.payload;
  if (payload.type !== MANDATE_PROPOSAL_SCHEMA || payload.proposal_id !== proposal.proposal_id || payload.proposal_digest !== proposal.proposal_digest) {
    return "proposal_receipt_binding_invalid";
  }
  if (payload.registry_id !== registry.registry_id) return "proposal_registry_mismatch";
  if (proposal.proposed_by.gate_kid !== registry.gate.kid || proposal.proposed_by.gate_public_key !== registry.gate.public_key) {
    return "proposal_gate_identity_invalid";
  }
  const denialCheck = verifyReceipt(proposal.denial_origin.receipt, registry.gate.public_key);
  if (!denialCheck.valid || proposal.denial_origin.receipt_hash !== (denialCheck.hash || receiptHash(proposal.denial_origin.receipt))) {
    return "proposal_denial_receipt_invalid";
  }
  const denialPayload = proposal.denial_origin.receipt.payload;
  if (denialPayload.type !== "protectmcp:decision" || denialPayload.decision !== "deny" || denialPayload.policy_digest !== proposal.base_policy_digest || denialPayload.request_id !== proposal.denial_origin.request_id || denialPayload.tool_name !== proposal.denial_origin.tool) {
    return "proposal_denial_binding_invalid";
  }
  try {
    assertSnapshot(proposal.candidate);
  } catch {
    return "proposal_snapshot_invalid";
  }
  if (proposal.candidate.policy_digest !== proposal.proposed_policy_digest) return "proposal_snapshot_digest_invalid";
  return null;
}
function verifyMandateRegistry(registry, now = /* @__PURE__ */ new Date()) {
  try {
    if (!registry || registry.schema !== MANDATE_REGISTRY_SCHEMA) return { valid: false, code: "unknown_registry_schema", message: "Registry schema is not recognised." };
    if (!registry.gate?.kid || !/^[0-9a-f]{64}$/i.test(registry.gate.public_key)) return { valid: false, code: "gate_identity_invalid", message: "Registry gate identity is malformed." };
    const controllerIds = /* @__PURE__ */ new Set();
    for (const controller of registry.controllers || []) {
      assertController(controller);
      if (controllerIds.has(controller.id)) return { valid: false, code: "duplicate_controller", message: `Controller ${controller.id} appears more than once.` };
      if (controller.id === registry.gate.kid || controllerKeyMaterial(controller) === registry.gate.public_key.toLowerCase()) {
        return { valid: false, code: "gate_is_controller", message: "The gate signer cannot be a mandate controller." };
      }
      controllerIds.add(controller.id);
    }
    if (!registry.controllers.length) return { valid: false, code: "missing_controller", message: "Managed policy has no controller." };
    for (const [digest, snapshot] of Object.entries(registry.policies || {})) {
      assertSnapshot(snapshot);
      if (digest !== snapshot.policy_digest) return { valid: false, code: "snapshot_map_mismatch", message: "A stored policy snapshot is addressed by the wrong digest." };
    }
    const activeSnapshot = registry.policies?.[registry.active?.policy_digest];
    if (!activeSnapshot) return { valid: false, code: "active_snapshot_missing", message: "The active policy head has no compiled snapshot." };
    if (!verifyGateEnvelope(registry.active.compilation_receipt, registry.gate)) return { valid: false, code: "active_compilation_signature_invalid", message: "The active compiled policy is not signed by the configured gate." };
    const compilationPayload = registry.active.compilation_receipt.payload;
    if (compilationPayload.policy_digest !== registry.active.policy_digest) return { valid: false, code: "active_compilation_binding_invalid", message: "The signed compiled policy does not bind the active head." };
    let priorHash = null;
    let currentHead = null;
    let currentExpiry = null;
    let currentBaseline = null;
    let currentProposalId = null;
    for (let index = 0; index < registry.history.length; index += 1) {
      const item = registry.history[index];
      if (item.sequence !== index + 1 || !verifyGateEnvelope(item.transition_receipt, registry.gate)) {
        return { valid: false, code: "transition_signature_invalid", message: "A policy transition is missing or has an invalid gate signature." };
      }
      const payload = item.transition_receipt.payload;
      if (payload.registry_id !== registry.registry_id || payload.sequence !== item.sequence || payload.event !== item.event) {
        return { valid: false, code: "transition_binding_invalid", message: "A signed transition does not bind this registry state." };
      }
      if ((payload.head_before ?? null) !== (item.head_before ?? null) || (payload.head_after ?? null) !== (item.head_after ?? null) || (payload.proposal_id ?? null) !== (item.proposal_id ?? null) || (payload.approval_digest ?? null) !== (item.approval_digest ?? null) || (payload.policy_digest ?? null) !== (item.policy_digest ?? null) || (payload.controllers_digest ?? null) !== (item.controllers_digest ?? null) || (payload.expiry ?? null) !== (item.expiry ?? null)) {
        return { valid: false, code: "transition_state_mismatch", message: "Displayed policy transition state does not match the signed transition." };
      }
      if (item.event === "initialized") {
        const derived = controllersDigest(registry.controllers);
        if (!payload.controllers_digest || payload.controllers_digest !== derived) {
          return { valid: false, code: "controller_set_unanchored", message: "The controller set does not match the gate-signed controller-set digest. A controller may have been injected or a key swapped." };
        }
      }
      if (item.head_before !== currentHead) {
        return { valid: false, code: "transition_head_chain_invalid", message: "Policy transition heads are discontinuous." };
      }
      const hash = stableDigest(item.transition_receipt);
      if (priorHash && payload.previous_transition_hash !== priorHash) {
        return { valid: false, code: "transition_chain_invalid", message: "Policy transition chain is discontinuous." };
      }
      priorHash = hash;
      currentHead = item.head_after;
      const pExpiry = payload.expiry || null;
      const pProposalId = payload.proposal_id || null;
      const pHeadBefore = payload.head_before ?? null;
      const pHeadAfter = payload.head_after || "";
      if (item.event === "initialized") {
        currentBaseline = pHeadAfter;
        currentExpiry = null;
        currentProposalId = null;
      } else if (item.event === "policy_activated") {
        currentBaseline = pHeadBefore;
        currentExpiry = pExpiry;
        currentProposalId = pProposalId;
      } else if (item.event === "policy_expired_reverted") {
        currentBaseline = pHeadAfter;
        currentExpiry = null;
        currentProposalId = null;
      }
    }
    if (currentHead !== registry.active.policy_digest) return { valid: false, code: "active_head_transition_mismatch", message: "Active policy head does not match the signed transition chain." };
    if ((registry.active.expires_at || null) !== currentExpiry) {
      return { valid: false, code: "active_expiry_mismatch", message: "The active grant expiry does not match the gate-signed transition chain (stripped or extended)." };
    }
    if (registry.active.baseline_policy_digest !== currentBaseline) {
      return { valid: false, code: "active_baseline_mismatch", message: "The active baseline policy digest does not match the gate-signed transition chain." };
    }
    if ((registry.active.proposal_id || null) !== currentProposalId) {
      return { valid: false, code: "active_proposal_mismatch", message: "The active proposal id does not match the gate-signed transition chain." };
    }
    const usedDenials = /* @__PURE__ */ new Set();
    for (const proposal of Object.values(registry.proposals || {})) {
      const error = verifyProposal(registry, proposal);
      if (error) return { valid: false, code: error, message: "A policy proposal cannot be verified." };
      if (usedDenials.has(proposal.denial_origin.receipt_hash)) {
        return { valid: false, code: "denial_receipt_reused", message: "A denial receipt was used for more than one policy proposal." };
      }
      usedDenials.add(proposal.denial_origin.receipt_hash);
    }
    for (const [proposalId, approval] of Object.entries(registry.approvals || {})) {
      const proposal = registry.proposals[proposalId];
      if (!proposal) return { valid: false, code: "approval_without_proposal", message: "A controller approval refers to no proposal." };
      const error = approval.method === "ed25519" ? verifyDirectApproval(registry, proposal, approval) : verifyWebAuthnApproval(registry, proposal, approval);
      if (error) return { valid: false, code: error, message: "A controller approval cannot be verified." };
    }
    for (const item of registry.history) {
      if (item.event !== "proposal_approved" && item.event !== "policy_activated") continue;
      if (!item.proposal_id || !item.approval_digest) return { valid: false, code: "activation_approval_missing", message: "A policy activation lacks its proposal or controller approval reference." };
      const approval = registry.approvals[item.proposal_id];
      const proposal = registry.proposals[item.proposal_id];
      if (!approval || !proposal || approvalDigest(approval) !== item.approval_digest) {
        return { valid: false, code: "activation_approval_mismatch", message: "A policy activation does not bind the exact verified controller approval." };
      }
      if (item.event === "policy_activated" && (item.head_before !== proposal.base_policy_digest || item.head_after !== proposal.proposed_policy_digest)) {
        return { valid: false, code: "activation_policy_mismatch", message: "A policy activation does not bind the proposed policy transition." };
      }
    }
    if (registry.active.expires_at && Date.parse(registry.active.expires_at) <= now.getTime()) {
      return { valid: false, code: "active_grant_expired", message: "The active widened policy has expired and must be reverted before enforcement." };
    }
    return { valid: true, registry };
  } catch (error) {
    return { valid: false, code: "registry_verification_error", message: error instanceof Error ? error.message : "Registry verification failed." };
  }
}
function installSnapshotAtomically(cedarDir, snapshot) {
  assertSnapshot(snapshot);
  const target = (0, import_node_path5.resolve)(cedarDir);
  const parent = (0, import_node_path5.dirname)(target);
  const base = (0, import_node_path5.basename)(target);
  if (!(0, import_node_fs8.existsSync)(target) || !(0, import_node_fs8.statSync)(target).isDirectory()) throw new Error(`managed Cedar directory is missing: ${target}`);
  const stage = (0, import_node_path5.join)(parent, `.${base}.scopeblind-stage-${process.pid}-${(0, import_node_crypto7.randomUUID)()}`);
  const backup = (0, import_node_path5.join)(parent, `.${base}.scopeblind-backup-${process.pid}-${(0, import_node_crypto7.randomUUID)()}`);
  (0, import_node_fs8.mkdirSync)(stage, { recursive: true, mode: 448 });
  try {
    for (const file of snapshot.files) (0, import_node_fs8.writeFileSync)((0, import_node_path5.join)(stage, file.name), file.content, { encoding: "utf-8", mode: 384 });
    (0, import_node_fs8.renameSync)(target, backup);
    try {
      (0, import_node_fs8.renameSync)(stage, target);
    } catch (error) {
      (0, import_node_fs8.renameSync)(backup, target);
      throw error;
    }
    (0, import_node_fs8.rmSync)(backup, { recursive: true, force: true });
  } finally {
    if ((0, import_node_fs8.existsSync)(stage)) (0, import_node_fs8.rmSync)(stage, { recursive: true, force: true });
    if ((0, import_node_fs8.existsSync)(backup) && !(0, import_node_fs8.existsSync)(target)) (0, import_node_fs8.renameSync)(backup, target);
  }
}
function addTransition(registry, signer, item, at) {
  const previous = registry.history[registry.history.length - 1];
  const previousTransitionHash = previous ? stableDigest(previous.transition_receipt) : void 0;
  const trans = transition(registry, signer, item.event, item.head_before, item.head_after, {
    ...item.proposal_id ? { proposal_id: item.proposal_id } : {},
    ...item.approval_digest ? { approval_digest: item.approval_digest } : {},
    ...item.policy_digest ? { policy_digest: item.policy_digest } : {},
    ...item.expiry ? { expiry: item.expiry } : {},
    ...previousTransitionHash ? { previous_transition_hash: previousTransitionHash } : {}
  }, at || item.occurred_at);
  registry.history.push(trans);
  return trans;
}
function createWebAuthnPolicyChallenge(input) {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error("managed mandate registry not initialized");
  const proposal = registry.proposals[input.proposalId];
  if (!proposal) throw new Error("unknown policy proposal");
  const controller = registry.controllers.find((item) => item.id === input.controllerId);
  if (!controller || controller.type !== "webauthn") throw new Error("selected controller has no registered WebAuthn credential");
  const challenge = createApprovalChallenge(proposal.proposal_id, "scopeblind:policy-change", controller.id, input.rpId, input.timeoutSeconds || 300, policyApprovalChallenge(proposal, controller.id));
  registry.pending_webauthn[proposal.proposal_id] = { proposal_id: proposal.proposal_id, controller_id: controller.id, challenge };
  persistRegistry(input.cedarDir, registry);
  return challenge;
}
function activateApprovedProposal(cedarDir, registry, signer, proposal, approval, at) {
  const integrity = verifyMandateRegistry(registry, new Date(Date.parse(at)));
  if (!integrity.valid && integrity.code !== "active_grant_expired") throw new Error(`cannot activate against invalid registry: ${integrity.code}`);
  if (registry.active.policy_digest !== proposal.base_policy_digest) throw new Error("active policy changed after proposal; create a new proposal against the current head");
  if (Date.parse(proposal.expires_at) <= Date.parse(at)) throw new Error("proposal expired before approval; it cannot be activated");
  const controller = registry.controllers.find((item) => item.id === approval.controller_id);
  if (!controller) throw new Error("approval controller is not registered");
  const error = approval.method === "ed25519" ? verifyDirectApproval(registry, proposal, approval) : verifyWebAuthnApproval(registry, proposal, approval);
  if (error) throw new Error(`controller approval rejected: ${error}`);
  if (controller.id === registry.gate.kid) throw new Error("the gate cannot approve its own policy proposal");
  const before = registry.active.policy_digest;
  const candidate = registry.policies[proposal.proposed_policy_digest] || proposal.candidate;
  assertSnapshot(candidate);
  installSnapshotAtomically(cedarDir, candidate);
  const compilationReceipt = signLifecycleEvent(signer, {
    event: "compiled",
    registry_id: registry.registry_id,
    policy_digest: candidate.policy_digest,
    snapshot_digest: stableDigest(candidate),
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval)
  }, at);
  registry.policies[candidate.policy_digest] = candidate;
  registry.approvals[proposal.proposal_id] = approval;
  registry.active = {
    policy_digest: candidate.policy_digest,
    baseline_policy_digest: before,
    activated_at: at,
    expires_at: proposal.expires_at,
    proposal_id: proposal.proposal_id,
    compilation_receipt: compilationReceipt
  };
  addTransition(registry, signer, {
    event: "proposal_approved",
    occurred_at: at,
    head_before: before,
    head_after: before,
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval)
  }, at);
  addTransition(registry, signer, {
    event: "policy_activated",
    occurred_at: at,
    head_before: before,
    head_after: candidate.policy_digest,
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval),
    policy_digest: candidate.policy_digest,
    expiry: proposal.expires_at
  }, at);
  delete registry.pending_webauthn[proposal.proposal_id];
  persistRegistry(cedarDir, registry);
  return registry;
}
function approvePolicyProposalWithWebAuthn(input) {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error("managed mandate registry not initialized");
  const proposal = registry.proposals[input.proposalId];
  const pending = registry.pending_webauthn[input.proposalId];
  if (!proposal || !pending) throw new Error("no pending WebAuthn approval exists for this proposal");
  const controller = registry.controllers.find((item) => item.id === pending.controller_id);
  if (!controller || controller.type !== "webauthn") throw new Error("pending approval controller is not registered for WebAuthn");
  if (pending.challenge.challenge !== policyApprovalChallenge(proposal, controller.id)) {
    throw new Error("pending WebAuthn challenge is not bound to this proposal");
  }
  const at = nowIso(input.now);
  const result = verifyApprovalAssertion(pending.challenge, input.assertion, controller.credential_public_key, {
    expectedOrigin: input.expectedOrigin,
    requireUserVerification: true,
    prevSignCount: controller.sign_count,
    now: Date.parse(at)
  });
  if (!result.valid || !result.userVerified) throw new Error(`WebAuthn approval rejected: ${result.reason || "user verification required"}`);
  controller.sign_count = result.signCount;
  const approval = {
    method: "webauthn",
    controller_id: controller.id,
    controller_label: controller.label,
    challenge: pending.challenge,
    assertion: input.assertion,
    result,
    expected_origin: input.expectedOrigin,
    approved_at: at
  };
  return activateApprovedProposal(input.cedarDir, registry, input.signer, proposal, approval, at);
}
function refreshManagedMandate(input) {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) return { valid: true };
  if (registry.gate.kid !== input.signer.kid || registry.gate.public_key !== input.signer.publicKey) {
    return { valid: false, code: "gate_signer_mismatch", message: "The local gate signer does not match the signer pinned in the mandate registry." };
  }
  const now = input.now || /* @__PURE__ */ new Date();
  const structural = verifyMandateRegistry(registry, now);
  if (!structural.valid && structural.code !== "active_grant_expired") return structural;
  const savedExpiry = registry.active.expires_at;
  if (savedExpiry && Date.parse(savedExpiry) <= now.getTime()) {
    const baseline = registry.policies[registry.active.baseline_policy_digest];
    if (!baseline) return { valid: false, code: "expiry_baseline_missing", message: "Expired policy has no baseline snapshot to restore." };
    try {
      installSnapshotAtomically(input.cedarDir, baseline);
      const at = nowIso(now);
      const before = registry.active.policy_digest;
      const compilationReceipt = signLifecycleEvent(input.signer, {
        event: "compiled",
        registry_id: registry.registry_id,
        policy_digest: baseline.policy_digest,
        snapshot_digest: stableDigest(baseline),
        reverted_from: before
      }, at);
      registry.active = {
        policy_digest: baseline.policy_digest,
        baseline_policy_digest: baseline.policy_digest,
        activated_at: at,
        compilation_receipt: compilationReceipt
      };
      addTransition(registry, input.signer, {
        event: "policy_expired_reverted",
        occurred_at: at,
        head_before: before,
        head_after: baseline.policy_digest,
        policy_digest: baseline.policy_digest,
        expiry: savedExpiry
      }, at);
      persistRegistry(input.cedarDir, registry);
      return { valid: true, registry, expired_reverted: true };
    } catch (error) {
      return { valid: false, code: "expiry_revert_failed", message: error instanceof Error ? error.message : "Failed to restore the expired policy baseline." };
    }
  }
  const check = verifyMandateRegistry(registry, now);
  if (!check.valid) return check;
  try {
    const current = snapshotFromDirectory(input.cedarDir);
    if (current.policy_digest !== registry.active.policy_digest) {
      return { valid: false, code: "policy_head_mismatch", message: "Policy files differ from the signed active registry head. The gate refuses to enforce an unauthorised edit." };
    }
  } catch (error) {
    return { valid: false, code: "policy_read_failed", message: error instanceof Error ? error.message : "Could not read active policy files." };
  }
  return check;
}
function publicMandateStatus(registry) {
  return {
    schema: registry.schema,
    registry_id: registry.registry_id,
    gate: { kid: registry.gate.kid, public_key: registry.gate.public_key, ...registry.gate.issuer ? { issuer: registry.gate.issuer } : {} },
    active: {
      policy_digest: registry.active.policy_digest,
      baseline_policy_digest: registry.active.baseline_policy_digest,
      activated_at: registry.active.activated_at,
      ...registry.active.expires_at ? { expires_at: registry.active.expires_at } : {},
      ...registry.active.proposal_id ? { proposal_id: registry.active.proposal_id } : {}
    },
    controllers: registry.controllers.map((controller) => ({ id: controller.id, label: controller.label, type: controller.type })),
    proposals: Object.values(registry.proposals).map((proposal) => ({
      proposal_id: proposal.proposal_id,
      proposal_digest: proposal.proposal_digest,
      base_policy_digest: proposal.base_policy_digest,
      proposed_policy_digest: proposal.proposed_policy_digest,
      expires_at: proposal.expires_at,
      reason: proposal.reason,
      diff: proposal.diff,
      approved: Boolean(registry.approvals[proposal.proposal_id])
    })),
    transitions: registry.history.map((entry) => ({
      sequence: entry.sequence,
      event: entry.event,
      occurred_at: entry.occurred_at,
      head_before: entry.head_before,
      head_after: entry.head_after,
      ...entry.proposal_id ? { proposal_id: entry.proposal_id } : {},
      ...entry.expiry ? { expiry: entry.expiry } : {},
      transition_receipt_hash: stableDigest(entry.transition_receipt)
    }))
  };
}

// src/hook-server.ts
var DEFAULT_PORT = 9377;
var LOG_FILE = ".protect-mcp-log.jsonl";
var RECEIPTS_FILE = ".protect-mcp-receipts.jsonl";
var PAYLOAD_HASH_THRESHOLD = 1024;
function resumeReceiptChain(receiptFilePath) {
  try {
    if (!(0, import_node_fs9.existsSync)(receiptFilePath)) return null;
    const lines = (0, import_node_fs9.readFileSync)(receiptFilePath, "utf-8").split("\n").filter((l) => l.trim());
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
    input_hash: (0, import_node_crypto8.createHash)("sha256").update(content).digest("hex"),
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
    output_hash: (0, import_node_crypto8.createHash)("sha256").update(content).digest("hex"),
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
      const procStatus = (0, import_node_fs9.readFileSync)("/proc/self/status", "utf-8");
      if (procStatus.includes("Seccomp:	2")) return "enabled";
    } catch {
    }
  }
  return "unavailable";
}
async function handlePreToolUse(input, state) {
  const hookStart = Date.now();
  const toolName = input.toolName || "unknown";
  const requestId = input.toolUseId || (0, import_node_crypto8.randomUUID)().slice(0, 12);
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
  const requestId = input.toolUseId || (0, import_node_crypto8.randomUUID)().slice(0, 12);
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
  const receiptId = (0, import_node_crypto8.randomUUID)().slice(0, 8);
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
    request_id: (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
    request_id: input.sessionId || (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
    request_id: input.sessionId || (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
      request_id: (0, import_node_crypto8.randomUUID)().slice(0, 12),
      hook_event: "ConfigChange",
      swarm: state.swarmContext
    });
  } else {
    emitDecisionLog(state, {
      tool: "config",
      decision: "allow",
      reason_code: "config_changed",
      request_id: (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto8.randomUUID)().slice(0, 12),
    hook_event: "Stop",
    swarm: state.swarmContext
  });
  return {};
}
function emitDecisionLog(state, entry) {
  const mode = state.enforce ? "enforce" : "shadow";
  const otelTraceId = (0, import_node_crypto8.randomBytes)(16).toString("hex");
  const otelSpanId = (0, import_node_crypto8.randomBytes)(8).toString("hex");
  const log = {
    v: 2,
    tool: entry.tool || "unknown",
    decision: entry.decision || "allow",
    reason_code: entry.reason_code || "default_allow",
    policy_digest: state.policyDigest,
    policy_engine: state.cedarPolicies ? "cedar" : "built-in",
    request_id: entry.request_id || (0, import_node_crypto8.randomUUID)().slice(0, 12),
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
    (0, import_node_fs9.appendFileSync)(state.logFilePath, JSON.stringify(log) + "\n");
  } catch {
  }
  if (isSigningEnabled()) {
    const signed = signDecision(log, state.lastReceiptHash || void 0);
    if (signed.signed) {
      try {
        (0, import_node_fs9.appendFileSync)(state.receiptFilePath, signed.signed + "\n");
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
        (0, import_node_fs9.appendFileSync)(state.receiptFilePath, tombstone + "\n");
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
    const keyPath = (0, import_node_path6.join)(dataDir, "keys", "gateway.json");
    if ((0, import_node_fs9.existsSync)(keyPath)) {
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
    logFilePath: (0, import_node_path6.join)(dataDir, LOG_FILE),
    receiptFilePath: (0, import_node_path6.join)(dataDir, RECEIPTS_FILE),
    lastReceiptHash: resumeReceiptChain((0, import_node_path6.join)(dataDir, RECEIPTS_FILE)),
    permissionSuggestions: /* @__PURE__ */ new Map(),
    configAlerts: [],
    managedMandate,
    standard,
    reporter,
    approvalsToRecord: /* @__PURE__ */ new Map()
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
    const hasSlug = process.env.SCOPEBLIND_SLUG || (0, import_node_fs9.existsSync)((0, import_node_path6.join)(dataDir, ".scopeblind"));
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
    for (const f of (0, import_node_fs9.readdirSync)(dir)) {
      if (!f.endsWith(".cedar")) continue;
      const m = (0, import_node_fs9.statSync)((0, import_node_path6.join)(dir, f)).mtimeMs;
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
      if ((0, import_node_fs9.existsSync)(candidate)) {
        const files = (0, import_node_fs9.readdirSync)(candidate, { encoding: "utf-8" });
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
