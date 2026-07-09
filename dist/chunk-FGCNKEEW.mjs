import {
  canonicalize
} from "./chunk-XOP3PEBM.mjs";

// src/policy-digest.ts
import { createHash } from "crypto";
import { readFileSync, readdirSync, existsSync } from "fs";
import { join, extname } from "path";
var POLICY_DIGEST_CONSTRUCTION = "acta-policy-digest-v1";
var POLICY_BUNDLE_SCHEMA = "acta.policy-bundle.v1";
var sha256hex = (data) => createHash("sha256").update(data).digest("hex");
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
function digestCedarDir(dirPath) {
  if (!existsSync(dirPath)) throw new Error(`Cedar policy directory not found: ${dirPath}`);
  const names = readdirSync(dirPath).filter((f) => extname(f) === ".cedar").sort();
  if (names.length === 0) throw new Error(`No .cedar files found in: ${dirPath}`);
  const files = names.map((name) => ({ name, content: readFileSync(join(dirPath, name), "utf-8") }));
  return { ...digestPolicyFiles("cedar", files), dir: dirPath };
}
function digestCedarSource(source) {
  return digestPolicyFiles("cedar", [{ name: "policy.cedar", content: source }]);
}
function digestBuiltinPolicy(policy) {
  return digestPolicyFiles("builtin", [{ name: "policy.json", content: canonicalize(policy) }]);
}
function shortPolicyLabel(result) {
  return `${result.engine}:${result.policy_digest.replace(/^sha256:/, "").slice(0, 16)}`;
}
function buildPolicyBundle(engine, files, generatedAt) {
  const d = digestPolicyFiles(engine, files);
  const byName = new Map(files.map((f) => [f.name, f.content]));
  return {
    schema: POLICY_BUNDLE_SCHEMA,
    construction: POLICY_DIGEST_CONSTRUCTION,
    engine,
    policy_digest: d.policy_digest,
    files: d.files.map((e) => ({ ...e, content: byName.get(e.name) })),
    generated_at: generatedAt || (/* @__PURE__ */ new Date()).toISOString()
  };
}
function verifyPolicyBundle(bundle) {
  try {
    const b = bundle;
    if (!b || b.schema !== POLICY_BUNDLE_SCHEMA) return { valid: false, error: "unknown_schema" };
    if (b.construction !== POLICY_DIGEST_CONSTRUCTION) return { valid: false, error: "unknown_construction" };
    if (!Array.isArray(b.files) || b.files.length === 0) return { valid: false, error: "missing_files" };
    for (const f of b.files) {
      if (sha256hex(Buffer.from(f.content, "utf-8")) !== f.sha256) {
        return { valid: false, error: `file_hash_mismatch:${f.name}` };
      }
    }
    const recomputed = digestPolicyFiles(b.engine, b.files.map((f) => ({ name: f.name, content: f.content }))).policy_digest;
    return recomputed === b.policy_digest ? { valid: true, recomputed } : { valid: false, recomputed, error: "digest_mismatch" };
  } catch (err) {
    return { valid: false, error: `verify_error:${err instanceof Error ? err.message : "unknown"}` };
  }
}

// src/cedar-evaluator.ts
import { readFileSync as readFileSync2, readdirSync as readdirSync2, existsSync as existsSync2 } from "fs";
import { join as join2, extname as extname2 } from "path";
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
  if (!existsSync2(dirPath)) {
    throw new Error(`Cedar policy directory not found: ${dirPath}`);
  }
  const entries = readdirSync2(dirPath).filter((f) => extname2(f) === ".cedar").sort();
  if (entries.length === 0) {
    throw new Error(`No .cedar files found in: ${dirPath}`);
  }
  const files = [];
  for (const file of entries) {
    files.push({ name: file, content: readFileSync2(join2(dirPath, file), "utf-8") });
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

export {
  digestCedarDir,
  digestBuiltinPolicy,
  shortPolicyLabel,
  buildPolicyBundle,
  verifyPolicyBundle,
  loadCedarPolicies,
  evaluateCedar,
  isCedarAvailable,
  policySetFromSource,
  runEvaluatorSelfTest
};
