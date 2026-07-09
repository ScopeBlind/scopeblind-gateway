#!/usr/bin/env node
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

// src/mcp-server.ts
var mcp_server_exports = {};
__export(mcp_server_exports, {
  runMcpServer: () => runMcpServer
});
module.exports = __toCommonJS(mcp_server_exports);
var import_node_readline = require("readline");

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
function receiptIdentity(envelope) {
  if (!envelope || typeof envelope !== "object") return { kid: null, issuer: null, type: null };
  const env = envelope;
  if (env.signature && typeof env.signature === "object") {
    const payload = env.payload || {};
    const sig = env.signature;
    return {
      kid: typeof sig.kid === "string" ? sig.kid : null,
      issuer: typeof payload.issuer_id === "string" ? payload.issuer_id : typeof payload.issuer_name === "string" ? payload.issuer_name : null,
      type: typeof payload.type === "string" ? payload.type : null
    };
  }
  return {
    kid: typeof env.kid === "string" ? env.kid : null,
    issuer: typeof env.issuer === "string" ? env.issuer : null,
    type: typeof env.type === "string" ? env.type : null
  };
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

// src/cedar-evaluator.ts
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
function policySetFromSource(source, name = "inline") {
  const digest = digestCedarSource(source).policy_digest;
  return { source, digest, fileCount: 1, files: [name] };
}

// src/mcp-server.ts
var artifacts = null;
async function loadArtifacts() {
  if (artifacts) return artifacts;
  const moduleName = "@veritasacta/artifacts";
  const mod = await import(
    /* @vite-ignore */
    moduleName
  );
  artifacts = mod;
  return mod;
}
var RO = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
var TOOLS = [
  {
    name: "evaluate_action",
    description: `Decide whether a proposed agent tool call is allowed by a Cedar policy, fail-closed. Evaluates the call against the policy the same way the protect-mcp gate does at runtime, and on any policy error the decision is DENY (never a silent allow). Inputs: tool (the tool name, e.g. "Bash" or "send_email"), input (the tool's arguments object; the policy sees it at context.input.*), and policy (inline Cedar source text). Returns JSON { allowed: boolean, decision: "allow" | "deny", reason: string, policy_digest: string (sha256 prefix of the policy) }. A missing or unparseable policy denies. Use this before an agent acts; pair with sign_decision to make the decision auditable.`,
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: 'The tool name being evaluated, e.g. "Bash", "Write", "send_email".' },
        input: { type: "object", description: "The tool's arguments. Reachable in the policy at context.input.* (e.g. context.input.command)." },
        policy: { type: "string", description: 'Inline Cedar policy source. Use MCP::Tool::call as the action and Tool::"<name>" as the resource.' }
      },
      required: ["tool", "policy"]
    },
    annotations: { title: "Evaluate an action against a Cedar policy", idempotentHint: true, ...RO }
  },
  {
    name: "sign_decision",
    description: `Turn a gate decision into an Ed25519 signed receipt (Veritas Acta format, JCS-canonical). A denial signs a gateway_restraint artifact; an allow signs a decision_receipt. This is what makes 'what the agent was blocked from doing' provable after the fact. Inputs: tool (required), decision ("allow" | "deny", required), reason_code (optional), policy_digest (optional), and private_key_hex (optional 64-hex Ed25519 secret; if omitted, an ephemeral keypair is generated and its public key is returned so the receipt still verifies). Returns JSON { receipt: object (the signed artifact), artifact_type: "decision_receipt" | "gateway_restraint", public_key: string (hex, pass this to verify_receipt or pin it), ephemeral: boolean }. Writes nothing to disk and contacts no network.`,
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: "The tool the decision is about." },
        decision: { type: "string", enum: ["allow", "deny"], description: "The gate decision to receipt." },
        reason_code: { type: "string", description: 'Optional machine reason, e.g. "restricted_list" or "post_execution_receipt".' },
        policy_digest: { type: "string", description: "Optional digest of the policy that produced the decision (e.g. from evaluate_action)." },
        private_key_hex: { type: "string", description: "Optional 64-character hex Ed25519 secret key. If omitted, an ephemeral key is generated and its public key is returned." }
      },
      required: ["tool", "decision"]
    },
    // Not idempotent: an ephemeral key and a fresh request_id are minted per call.
    annotations: { title: "Sign a decision into a receipt", idempotentHint: false, ...RO }
  },
  {
    name: "verify_receipt",
    description: 'Verify a signed receipt offline against a public key. No network, no accounts: the Ed25519 signature is checked over the canonical bytes. Inputs: receipt (the signed artifact object, required) and public_key_hex (optional; falls back to a public_key embedded in the receipt payload). Returns JSON { valid: boolean, error: string | null (e.g. "invalid_signature", "no_public_key"), type: string, kid: string | null, issuer: string | null }. For authenticity you should verify against a key you pinned out of band, not only the one carried inside the receipt.',
    inputSchema: {
      type: "object",
      properties: {
        receipt: { type: "object", description: "The signed receipt/artifact to verify." },
        public_key_hex: { type: "string", description: "Optional Ed25519 public key hex to verify against. Defaults to a key embedded in the receipt payload." }
      },
      required: ["receipt"]
    },
    annotations: { title: "Verify a receipt offline", idempotentHint: true, ...RO }
  },
  {
    name: "self_test",
    description: "Prove the gate works, end to end, with no inputs. Runs a known-forbidden action (rm -rf) against a sample deny policy and asserts it is DENIED, then signs a decision and verifies the receipt round-trips. Returns JSON { ok: boolean, gate_denies_forbidden: boolean, sign_verify_roundtrip: boolean, details: object }. This is the 'a gate that cannot prove it denies does not start' check, exposed as a callable tool. Contacts no network.",
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "Prove the gate denies and receipts verify", idempotentHint: true, ...RO }
  }
];
function buildReceiptPayload(args) {
  return {
    // draft-02 s3.1 access-decision fields
    type: "protectmcp:decision",
    tool_name: args.tool,
    decision: args.decision,
    reason: args.reason_code ?? (args.decision === "deny" ? "policy_denied" : "post_execution_receipt"),
    policy_digest: args.policy_digest ?? "none",
    // Extension fields (signed alongside the s3.1 core)
    scope: args.request_id,
    mode: "enforce",
    request_id: args.request_id,
    spec: "draft-farley-acta-signed-receipts-02",
    issuer_certification: "self-signed",
    public_key: args.public_key
  };
}
function newRequestId() {
  return `mcp-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
}
async function callEvaluate(args) {
  const tool = typeof args.tool === "string" ? args.tool : "";
  const policySource = typeof args.policy === "string" ? args.policy : "";
  const input = args.input && typeof args.input === "object" ? args.input : {};
  if (!tool) return { error: "missing_tool" };
  if (!policySource.trim()) return { allowed: false, decision: "deny", reason: "no policy provided (fail-closed)", policy_digest: "none" };
  const policySet = policySetFromSource(policySource);
  const decision = await evaluateCedar(
    policySet,
    { tool, tier: "unknown", context: { ...input, input }, toolInput: input },
    void 0,
    { failClosed: true }
  );
  return {
    allowed: decision.allowed,
    decision: decision.allowed ? "allow" : "deny",
    reason: decision.reason || (decision.allowed ? "allowed" : "denied by policy"),
    policy_digest: policySet.digest
  };
}
async function callSign(args) {
  const tool = typeof args.tool === "string" ? args.tool : "";
  const decision = args.decision === "deny" ? "deny" : args.decision === "allow" ? "allow" : null;
  if (!tool) return { error: "missing_tool" };
  if (!decision) return { error: 'decision must be "allow" or "deny"' };
  const a = await loadArtifacts();
  let privateKey = typeof args.private_key_hex === "string" ? args.private_key_hex : "";
  let publicKey;
  let ephemeral = false;
  if (privateKey) {
    publicKey = a.getPublicKey(privateKey);
  } else {
    const kp = a.generateKeypair();
    privateKey = kp.privateKey;
    publicKey = kp.publicKey;
    ephemeral = true;
  }
  const requestId = newRequestId();
  const payload = buildReceiptPayload({
    tool,
    decision,
    reason_code: typeof args.reason_code === "string" ? args.reason_code : void 0,
    policy_digest: typeof args.policy_digest === "string" ? args.policy_digest : void 0,
    request_id: requestId,
    public_key: publicKey
  });
  const artifactType = decision === "deny" ? "gateway_restraint" : "decision_receipt";
  const { envelope } = createReceiptEnvelope(payload, privateKey, computeSbIssuerKid(publicKey));
  return { receipt: envelope, artifact_type: artifactType, public_key: publicKey, ephemeral };
}
async function callVerify(args) {
  const receipt = args.receipt;
  if (!receipt || typeof receipt !== "object") return { valid: false, error: "missing_receipt" };
  const identity = receiptIdentity(receipt);
  const embedded = receipt.payload?.public_key;
  const key = typeof args.public_key_hex === "string" && args.public_key_hex ? args.public_key_hex : typeof embedded === "string" ? embedded : null;
  if (!key) {
    return { valid: false, error: "no_public_key", type: identity.type ?? "unknown", kid: identity.kid, issuer: identity.issuer };
  }
  const result = verifyReceipt(receipt, key);
  return {
    valid: result.valid,
    error: result.valid ? null : result.error || "invalid_signature",
    shape: result.shape,
    type: identity.type ?? "unknown",
    kid: identity.kid,
    issuer: identity.issuer
  };
}
var SELF_TEST_POLICY = `
permit(principal, action == Action::"MCP::Tool::call", resource);
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")
  when {
    context has input && context.input has command &&
    (context.input.command like "*rm -rf*" || context.input.command like "*mkfs*")
  };
`;
async function callSelfTest() {
  const details = {};
  const denied = await callEvaluate({ tool: "Bash", input: { command: "rm -rf /" }, policy: SELF_TEST_POLICY });
  const gateDeniesForbidden = denied.allowed === false;
  details.forbidden_action = { tool: "Bash", command: "rm -rf /", allowed: denied.allowed, reason: denied.reason };
  const allowed = await callEvaluate({ tool: "Read", input: { path: "./notes.txt" }, policy: SELF_TEST_POLICY });
  details.safe_action = { tool: "Read", allowed: allowed.allowed };
  let signVerifyRoundtrip = false;
  try {
    const signed = await callSign({ tool: "Bash", decision: "deny", reason_code: "self_test" });
    if (signed.receipt && signed.public_key) {
      const ok = await callVerify({ receipt: signed.receipt, public_key_hex: signed.public_key });
      const tampered = JSON.parse(JSON.stringify(signed.receipt));
      if (tampered.payload) tampered.payload.tool_name = "tampered";
      const bad = await callVerify({ receipt: tampered, public_key_hex: signed.public_key });
      signVerifyRoundtrip = ok.valid === true && bad.valid === false;
      details.sign_verify = { valid_verifies: ok.valid, tampered_rejected: bad.valid === false };
    }
  } catch (err) {
    details.sign_verify_error = err instanceof Error ? err.message : String(err);
  }
  return {
    ok: gateDeniesForbidden && allowed.allowed === true && signVerifyRoundtrip,
    gate_denies_forbidden: gateDeniesForbidden,
    sign_verify_roundtrip: signVerifyRoundtrip,
    details,
    note: "No network was contacted."
  };
}
function textResult(id, value) {
  return JSON.stringify({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] } });
}
async function handleRequest(request) {
  if (request.method === "initialize") {
    return JSON.stringify({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "protect-mcp", version: process.env.PROTECT_MCP_VERSION || "0.9.7" },
        capabilities: { tools: {} }
      }
    });
  }
  if (request.method === "notifications/initialized") return "";
  if (request.method === "tools/list") {
    return JSON.stringify({ jsonrpc: "2.0", id: request.id, result: { tools: TOOLS } });
  }
  if (request.method === "tools/call") {
    const name = request.params?.name || "";
    const args = request.params?.arguments || {};
    try {
      let value;
      switch (name) {
        case "evaluate_action":
          value = await callEvaluate(args);
          break;
        case "sign_decision":
          value = await callSign(args);
          break;
        case "verify_receipt":
          value = await callVerify(args);
          break;
        case "self_test":
          value = await callSelfTest();
          break;
        default:
          value = { error: `unknown tool: ${name}` };
      }
      return textResult(request.id, value);
    } catch (err) {
      return textResult(request.id, { error: err instanceof Error ? err.message : String(err) });
    }
  }
  if (request.id !== void 0) {
    return JSON.stringify({ jsonrpc: "2.0", id: request.id, error: { code: -32601, message: `Method not found: ${request.method}` } });
  }
  return "";
}
async function runMcpServer() {
  const rl = (0, import_node_readline.createInterface)({ input: process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    chain = chain.then(async () => {
      try {
        const request = JSON.parse(trimmed);
        const response = await handleRequest(request);
        if (response) process.stdout.write(response + "\n");
      } catch {
      }
    });
  });
  process.stderr.write("[PROTECT_MCP] gate MCP server started \u2014 4 tools: evaluate_action, sign_decision, verify_receipt, self_test\n");
  await new Promise((resolve) => rl.on("close", () => resolve()));
}
if (process.argv[1] && /mcp-server\.(js|mjs|cjs|ts)$/.test(process.argv[1])) {
  runMcpServer();
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  runMcpServer
});
