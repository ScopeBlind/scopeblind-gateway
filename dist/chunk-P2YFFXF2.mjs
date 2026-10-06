import {
  canonicalize
} from "./chunk-SRLE63GU.mjs";

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
var CEDAR_ESCAPE_KEYS = /* @__PURE__ */ new Set(["__entity", "__extn", "__expr"]);
var CEDAR_LONG_LIMIT = 2 ** 63;
function cedarSafeValue(value) {
  if (value === null || value === void 0) return void 0;
  switch (typeof value) {
    case "string":
    case "boolean":
      return value;
    case "number":
      return Number.isInteger(value) && Math.abs(value) < CEDAR_LONG_LIMIT ? value : String(value);
    case "bigint":
      return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
    case "object": {
      if (Array.isArray(value)) {
        const items = [];
        for (const item of value) {
          const safe = cedarSafeValue(item);
          if (safe !== void 0) items.push(safe);
        }
        return items;
      }
      const record = {};
      for (const [key, item] of Object.entries(value)) {
        if (CEDAR_ESCAPE_KEYS.has(key)) continue;
        const safe = cedarSafeValue(item);
        if (safe !== void 0) Object.defineProperty(record, key, { value: safe, enumerable: true, writable: true, configurable: true });
      }
      return record;
    }
    default:
      return void 0;
  }
}
function cedarSafeContext(context) {
  return cedarSafeValue(context);
}
var preparedPolicies = /* @__PURE__ */ new Map();
var PREPARED_CACHE_LIMIT = 32;
function oneLine(text, max = 400) {
  const line = text.replace(/\s+/g, " ").trim();
  return line.length > max ? `${line.slice(0, max - 3)}...` : line;
}
function preparePolicies(engine, source) {
  const cached = preparedPolicies.get(source);
  if (cached) return cached;
  let prepared = { staticPolicies: source, names: /* @__PURE__ */ new Map() };
  try {
    if (typeof engine?.policySetTextToParts === "function" && typeof engine?.policyToJson === "function") {
      const parts = engine.policySetTextToParts(source);
      const texts = parts?.policies;
      const templates = parts?.policy_templates;
      if (parts?.type === "success" && Array.isArray(texts) && texts.length > 0 && (!Array.isArray(templates) || templates.length === 0) && texts.every((text) => typeof text === "string" && source.includes(text))) {
        const positional = texts.map((_, i) => `policy${i}`).sort();
        const annotations = texts.map((text) => {
          const json = engine.policyToJson(text);
          return json?.type === "success" ? json.json?.annotations ?? {} : null;
        });
        if (annotations.every((a) => a !== null)) {
          const idOf = (a) => a && typeof a.id === "string" ? a.id : "";
          const counts = /* @__PURE__ */ new Map();
          for (const a of annotations) {
            const id = idOf(a);
            if (id) counts.set(id, (counts.get(id) || 0) + 1);
          }
          const keyed = /* @__PURE__ */ Object.create(null);
          const names = /* @__PURE__ */ new Map();
          texts.forEach((text, k) => {
            const a = annotations[k];
            const id = idOf(a);
            const usable = id.trim() !== "" && counts.get(id) === 1 && !/^policy\d+$/.test(id) && id !== "__proto__";
            const key = usable ? id : positional[k];
            const reason = a && typeof a.reason === "string" && a.reason.trim() !== "" ? oneLine(a.reason) : void 0;
            keyed[key] = text;
            names.set(key, { id: key, ...reason ? { reason } : {}, order: Number(positional[k].slice("policy".length)) });
          });
          if (Object.keys(keyed).length === texts.length && names.size === texts.length) {
            prepared = { staticPolicies: { ...keyed }, names };
          }
        }
      }
    }
  } catch {
    prepared = { staticPolicies: source, names: /* @__PURE__ */ new Map() };
  }
  if (preparedPolicies.size >= PREPARED_CACHE_LIMIT) {
    const oldest = preparedPolicies.keys().next().value;
    if (oldest !== void 0) preparedPolicies.delete(oldest);
  }
  preparedPolicies.set(source, prepared);
  return prepared;
}
function namedPolicies(ids, prepared) {
  const list = Array.isArray(ids) ? ids.filter((id) => typeof id === "string") : [];
  return list.map((id) => prepared.names.get(id) ?? { id, order: Number.MAX_SAFE_INTEGER }).sort((a, b) => a.order - b.order || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map(({ id, reason }) => reason ? { id, reason } : { id });
}
function denyReason(deniedBy) {
  if (deniedBy.length === 0) return "cedar_deny: no permit matched (default deny)";
  return `cedar_deny: ${deniedBy.map((p) => p.reason ? `${p.id}: ${p.reason}` : p.id).join("; ")}`;
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
      // Only values Cedar can hold: a fraction, a null or an escape key in the
      // input no longer makes the engine refuse the whole call (see cedarSafeValue).
      context: cedarSafeContext(context)
    };
    const entities = buildEntities(req);
    const cedarSchema = schema?.schemaJson ?? null;
    let result;
    let prepared = { staticPolicies: policySet.source, names: /* @__PURE__ */ new Map() };
    if (typeof cedarWasm.isAuthorized === "function") {
      prepared = preparePolicies(cedarWasm, policySet.source);
      result = cedarWasm.isAuthorized({
        policies: { staticPolicies: prepared.staticPolicies },
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
        prepared = preparePolicies(cedarEngine, policySet.source);
        result = cedarEngine.isAuthorized({
          policies: { staticPolicies: prepared.staticPolicies },
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
    if (parsed.kind === "allow") {
      return {
        allowed: true,
        reason: void 0,
        metadata: {
          policy_digest: policySet.digest,
          ...parsed.matchedPolicies ? { matched_policies: namedPolicies(parsed.matchedPolicies, prepared).map((p) => p.id) } : {}
        }
      };
    }
    if (!parsed.matchedPolicies && parsed.diagnostics === void 0) {
      return { allowed: false, reason: "cedar_deny", metadata: { policy_digest: policySet.digest } };
    }
    const deniedBy = namedPolicies(parsed.matchedPolicies, prepared);
    return {
      allowed: false,
      reason: denyReason(deniedBy),
      metadata: {
        policy_digest: policySet.digest,
        matched_policies: deniedBy.map((p) => p.id),
        denied_by: deniedBy,
        default_deny: deniedBy.length === 0
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
async function checkCedarPolicyText(source) {
  if (!await ensureCedarWasm()) return { checked: false, ok: true };
  const engine = typeof cedarWasm.checkParsePolicySet === "function" ? cedarWasm : cedarWasm.default;
  if (!engine || typeof engine.checkParsePolicySet !== "function") return { checked: false, ok: true };
  try {
    const answer = engine.checkParsePolicySet({ staticPolicies: source });
    if (answer?.type === "success") return { checked: true, ok: true };
    const first = Array.isArray(answer?.errors) ? answer.errors[0] : void 0;
    return { checked: true, ok: false, error: oneLine(String(first?.message ?? JSON.stringify(answer))) };
  } catch (err) {
    return { checked: true, ok: false, error: err instanceof Error ? oneLine(err.message) : "unknown parse error" };
  }
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
  digestPolicyFiles,
  digestCedarDir,
  digestBuiltinPolicy,
  shortPolicyLabel,
  buildPolicyBundle,
  verifyPolicyBundle,
  loadCedarPolicies,
  cedarSafeValue,
  cedarSafeContext,
  evaluateCedar,
  isCedarAvailable,
  checkCedarPolicyText,
  policySetFromSource,
  runEvaluatorSelfTest
};
