#!/usr/bin/env node
import {
  evaluateCedar,
  policySetFromSource
} from "./chunk-MWXDXYWH.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/mcp-server.ts
import { createInterface } from "readline";
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
    tool: args.tool,
    decision: args.decision,
    reason_code: args.reason_code ?? (args.decision === "deny" ? "policy_denied" : "post_execution_receipt"),
    policy_digest: args.policy_digest ?? "none",
    scope: args.request_id,
    mode: "enforce",
    request_id: args.request_id,
    spec: "draft-farley-acta-signed-receipts-01",
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
  const { artifact } = a.createSignedArtifact(artifactType, payload, privateKey, { kid: "mcp", issuer: "protect-mcp" });
  return { receipt: artifact, artifact_type: artifactType, public_key: publicKey, ephemeral };
}
async function callVerify(args) {
  const receipt = args.receipt;
  if (!receipt || typeof receipt !== "object") return { valid: false, error: "missing_receipt" };
  const a = await loadArtifacts();
  const embedded = receipt.payload?.public_key;
  const key = typeof args.public_key_hex === "string" && args.public_key_hex ? args.public_key_hex : typeof embedded === "string" ? embedded : null;
  if (!key) {
    return { valid: false, error: "no_public_key", type: receipt.type ?? "unknown", kid: null, issuer: null };
  }
  const result = a.verifyArtifact(receipt, key);
  return {
    valid: !!result.valid,
    error: result.valid ? null : result.error || "invalid_signature",
    type: receipt.type ?? "unknown",
    kid: receipt.kid ?? null,
    issuer: receipt.issuer ?? null
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
      if (tampered.payload) tampered.payload.tool = "tampered";
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
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
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
export {
  runMcpServer
};
