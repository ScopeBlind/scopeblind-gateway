#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
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
var __toESM = (mod2, isNodeMode, target) => (target = mod2 != null ? __create(__getProtoOf(mod2)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod2 || !mod2.__esModule ? __defProp(target, "default", { value: mod2, enumerable: true }) : target,
  mod2
));

// src/policy.ts
function loadPolicy(path) {
  const raw = (0, import_node_fs.readFileSync)(path, "utf-8");
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
  return (0, import_node_crypto.createHash)("sha256").update(canonical).digest("hex").slice(0, 16);
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
var import_node_crypto, import_node_fs;
var init_policy = __esm({
  "src/policy.ts"() {
    "use strict";
    import_node_crypto = require("crypto");
    import_node_fs = require("fs");
  }
});

// src/evidence-store.ts
var import_node_fs2, import_node_path, DEFAULT_THRESHOLDS, EvidenceStore;
var init_evidence_store = __esm({
  "src/evidence-store.ts"() {
    "use strict";
    import_node_fs2 = require("fs");
    import_node_path = require("path");
    DEFAULT_THRESHOLDS = {
      min_receipts: 10,
      min_epoch_span: 3,
      min_issuers: 2
    };
    EvidenceStore = class {
      agents = /* @__PURE__ */ new Map();
      filePath;
      dirty = false;
      constructor(dir) {
        this.filePath = (0, import_node_path.join)(dir || process.cwd(), ".protect-mcp-evidence.json");
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
          (0, import_node_fs2.writeFileSync)(this.filePath, JSON.stringify({ v: 1, agents: data }, null, 2) + "\n");
          this.dirty = false;
        } catch {
        }
      }
      /**
       * Load from disk.
       */
      load() {
        if (!(0, import_node_fs2.existsSync)(this.filePath)) return;
        try {
          const raw = (0, import_node_fs2.readFileSync)(this.filePath, "utf-8");
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
  }
});

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
var init_admission = __esm({
  "src/admission.ts"() {
    "use strict";
    init_evidence_store();
  }
});

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
var init_credentials = __esm({
  "src/credentials.ts"() {
    "use strict";
  }
});

// src/signing.ts
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
  if (!(0, import_node_fs3.existsSync)(config.key_path)) {
    signingInitError = `key file not found at ${config.key_path}`;
    warnings.push(`signing: ${signingInitError} \u2014 run "protect-mcp init" to generate`);
    return warnings;
  }
  let keyData;
  try {
    keyData = JSON.parse((0, import_node_fs3.readFileSync)(config.key_path, "utf-8"));
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
      issuer_certification: signerState ? "self-signed" : "uncertified",
      // The signer's PUBLIC key, inside the signed payload, so a receipt is
      // self-contained: any verifier (including the record viewer, in-browser)
      // can check the signature without a side channel. Binding the key inside
      // the signature means it cannot be swapped without breaking the signature;
      // authenticity (that the key is YOUR gate's) still comes from pinning it.
      public_key: signerState.publicKey
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
    if (entry.enrichment) payload.enrichment = entry.enrichment;
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
var import_node_fs3, signerState, artifactsModule, signingConfigured, signingInitError;
var init_signing = __esm({
  "src/signing.ts"() {
    "use strict";
    import_node_fs3 = require("fs");
    signerState = null;
    artifactsModule = null;
    signingConfigured = false;
    signingInitError = null;
  }
});

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
var init_external_pdp = __esm({
  "src/external-pdp.ts"() {
    "use strict";
  }
});

// src/cedar-evaluator.ts
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
  if (!(0, import_node_fs4.existsSync)(dirPath)) {
    throw new Error(`Cedar policy directory not found: ${dirPath}`);
  }
  const entries = (0, import_node_fs4.readdirSync)(dirPath).filter((f) => (0, import_node_path2.extname)(f) === ".cedar").sort();
  if (entries.length === 0) {
    throw new Error(`No .cedar files found in: ${dirPath}`);
  }
  const sources = [];
  for (const file of entries) {
    const content = (0, import_node_fs4.readFileSync)((0, import_node_path2.join)(dirPath, file), "utf-8");
    sources.push(content);
  }
  const concatenated = sources.join("\n\n");
  const digest = (0, import_node_crypto2.createHash)("sha256").update(concatenated).digest("hex").slice(0, 16);
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
  const digest = (0, import_node_crypto2.createHash)("sha256").update(source).digest("hex").slice(0, 16);
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
var import_node_crypto2, import_node_fs4, import_node_path2, cedarWasm, loadAttempted;
var init_cedar_evaluator = __esm({
  "src/cedar-evaluator.ts"() {
    "use strict";
    import_node_crypto2 = require("crypto");
    import_node_fs4 = require("fs");
    import_node_path2 = require("path");
    cedarWasm = null;
    loadAttempted = false;
  }
});

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
var init_notifications = __esm({
  "src/notifications.ts"() {
    "use strict";
  }
});

// src/http-server.ts
function startStatusServer(config, receiptBuffer, approvalStore, approvalNonce) {
  const startTime = Date.now();
  const logDir = process.cwd();
  const server = (0, import_node_http.createServer)((req, res) => {
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
  const logPath = (0, import_node_path3.join)(logDir, LOG_FILE);
  if (!(0, import_node_fs5.existsSync)(logPath)) {
    res.writeHead(200);
    res.end(JSON.stringify({ entries: 0, message: "no log file yet" }));
    return;
  }
  const raw = (0, import_node_fs5.readFileSync)(logPath, "utf-8");
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
var import_node_http, import_node_fs5, import_node_path3, LOG_FILE, MAX_RECEIPTS, ReceiptBuffer;
var init_http_server = __esm({
  "src/http-server.ts"() {
    "use strict";
    import_node_http = require("http");
    import_node_fs5 = require("fs");
    import_node_path3 = require("path");
    LOG_FILE = ".protect-mcp-log.jsonl";
    MAX_RECEIPTS = 100;
    ReceiptBuffer = class {
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
  }
});

// src/action-readback.ts
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
var import_node_crypto3, SECRET_KEY_RE, DESTINATION_KEYS;
var init_action_readback = __esm({
  "src/action-readback.ts"() {
    "use strict";
    import_node_crypto3 = require("crypto");
    SECRET_KEY_RE = /(api[_-]?key|authorization|bearer|credential|password|secret|session|token|private[_-]?key)/i;
    DESTINATION_KEYS = [
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
  }
});

// src/gateway.ts
var import_node_child_process, import_node_crypto4, import_node_readline, import_node_fs6, import_node_path4, LOG_FILE2, RECEIPTS_FILE, ProtectGateway;
var init_gateway = __esm({
  "src/gateway.ts"() {
    "use strict";
    import_node_child_process = require("child_process");
    import_node_crypto4 = require("crypto");
    import_node_readline = require("readline");
    import_node_fs6 = require("fs");
    import_node_path4 = require("path");
    init_policy();
    init_admission();
    init_credentials();
    init_signing();
    init_external_pdp();
    init_cedar_evaluator();
    init_evidence_store();
    init_notifications();
    init_http_server();
    init_action_readback();
    LOG_FILE2 = ".protect-mcp-log.jsonl";
    RECEIPTS_FILE = ".protect-mcp-receipts.jsonl";
    ProtectGateway = class {
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
      approvalNonce = (0, import_node_crypto4.randomBytes)(16).toString("hex");
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
        this.logFilePath = (0, import_node_path4.join)(process.cwd(), LOG_FILE2);
        this.receiptFilePath = (0, import_node_path4.join)(process.cwd(), RECEIPTS_FILE);
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
        this.child = (0, import_node_child_process.spawn)(command, args, { stdio: ["pipe", "pipe", "pipe"], env: childEnv });
        if (!this.child.stdin || !this.child.stdout || !this.child.stderr) {
          throw new Error("Failed to create pipes to child process");
        }
        this.child.stderr.on("data", (data) => {
          process.stderr.write(data);
        });
        const childReader = (0, import_node_readline.createInterface)({ input: this.child.stdout, crlfDelay: Infinity });
        childReader.on("line", (line) => {
          this.handleServerMessage(line);
        });
        this.clientReader = (0, import_node_readline.createInterface)({ input: process.stdin, crlfDelay: Infinity });
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
        const requestId = (0, import_node_crypto4.randomUUID)().slice(0, 12);
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
        const otelTraceId = entry.otel_trace_id || (0, import_node_crypto4.randomBytes)(16).toString("hex");
        const otelSpanId = entry.otel_span_id || (0, import_node_crypto4.randomBytes)(8).toString("hex");
        const log = {
          v: 2,
          tool: entry.tool || "unknown",
          decision: entry.decision || "allow",
          reason_code: entry.reason_code || "default_allow",
          policy_digest: this.config.policyDigest,
          policy_engine: this.config.policy?.policy_engine || "built-in",
          request_id: entry.request_id || (0, import_node_crypto4.randomUUID)().slice(0, 12),
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
          (0, import_node_fs6.appendFileSync)(this.logFilePath, JSON.stringify(log) + "\n");
        } catch {
        }
        if (isSigningEnabled()) {
          const signed = signDecision(log);
          if (signed.signed) {
            process.stderr.write(`[PROTECT_MCP_RECEIPT] ${signed.signed}
`);
            try {
              (0, import_node_fs6.appendFileSync)(this.receiptFilePath, signed.signed + "\n");
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
              (0, import_node_fs6.appendFileSync)(this.receiptFilePath, tombstone + "\n");
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
        this.child = (0, import_node_child_process.spawn)(command, args, { stdio: ["pipe", "pipe", "pipe"], env: childEnv });
        if (!this.child.stdin || !this.child.stdout || !this.child.stderr) {
          throw new Error("Failed to create pipes to child process");
        }
        this.child.stderr.on("data", (data) => {
          process.stderr.write(data);
        });
        const childReader = (0, import_node_readline.createInterface)({ input: this.child.stdout, crlfDelay: Infinity });
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
  }
});

// node_modules/@noble/hashes/esm/cryptoNode.js
var nc, crypto;
var init_cryptoNode = __esm({
  "node_modules/@noble/hashes/esm/cryptoNode.js"() {
    "use strict";
    nc = __toESM(require("crypto"), 1);
    crypto = nc && typeof nc === "object" && "webcrypto" in nc ? nc.webcrypto : nc && typeof nc === "object" && "randomBytes" in nc ? nc : void 0;
  }
});

// node_modules/@noble/hashes/esm/utils.js
var utils_exports = {};
__export(utils_exports, {
  Hash: () => Hash,
  abytes: () => abytes,
  aexists: () => aexists,
  ahash: () => ahash,
  anumber: () => anumber,
  aoutput: () => aoutput,
  asyncLoop: () => asyncLoop,
  byteSwap: () => byteSwap,
  byteSwap32: () => byteSwap32,
  byteSwapIfBE: () => byteSwapIfBE,
  bytesToHex: () => bytesToHex,
  bytesToUtf8: () => bytesToUtf8,
  checkOpts: () => checkOpts,
  clean: () => clean,
  concatBytes: () => concatBytes,
  createHasher: () => createHasher,
  createOptHasher: () => createOptHasher,
  createView: () => createView,
  createXOFer: () => createXOFer,
  hexToBytes: () => hexToBytes,
  isBytes: () => isBytes,
  isLE: () => isLE,
  kdfInputToBytes: () => kdfInputToBytes,
  nextTick: () => nextTick,
  randomBytes: () => randomBytes2,
  rotl: () => rotl,
  rotr: () => rotr,
  swap32IfBE: () => swap32IfBE,
  swap8IfBE: () => swap8IfBE,
  toBytes: () => toBytes,
  u32: () => u32,
  u8: () => u8,
  utf8ToBytes: () => utf8ToBytes,
  wrapConstructor: () => wrapConstructor,
  wrapConstructorWithOpts: () => wrapConstructorWithOpts,
  wrapXOFConstructorWithOpts: () => wrapXOFConstructorWithOpts
});
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function u8(arr) {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function rotl(word, shift) {
  return word << shift | word >>> 32 - shift >>> 0;
}
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
async function asyncLoop(iters, tick, cb) {
  let ts = Date.now();
  for (let i = 0; i < iters; i++) {
    cb(i);
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < tick)
      continue;
    await nextTick();
    ts += diff;
  }
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function kdfInputToBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function checkOpts(defaults, opts) {
  if (opts !== void 0 && {}.toString.call(opts) !== "[object Object]")
    throw new Error("options should be object or undefined");
  const merged = Object.assign(defaults, opts);
  return merged;
}
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function createOptHasher(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
function createXOFer(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
function randomBytes2(bytesLength = 32) {
  if (crypto && typeof crypto.getRandomValues === "function") {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto && typeof crypto.randomBytes === "function") {
    return Uint8Array.from(crypto.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}
var isLE, swap8IfBE, byteSwapIfBE, swap32IfBE, hasHexBuiltin, hexes, asciis, nextTick, Hash, wrapConstructor, wrapConstructorWithOpts, wrapXOFConstructorWithOpts;
var init_utils = __esm({
  "node_modules/@noble/hashes/esm/utils.js"() {
    "use strict";
    init_cryptoNode();
    isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
    swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n);
    byteSwapIfBE = swap8IfBE;
    swap32IfBE = isLE ? (u) => u : byteSwap32;
    hasHexBuiltin = /* @__PURE__ */ (() => (
      // @ts-ignore
      typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
    ))();
    hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
    asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
    nextTick = async () => {
    };
    Hash = class {
    };
    wrapConstructor = createHasher;
    wrapConstructorWithOpts = createOptHasher;
    wrapXOFConstructorWithOpts = createXOFer;
  }
});

// node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD, SHA256_IV, SHA512_IV;
var init_md = __esm({
  "node_modules/@noble/hashes/esm/_md.js"() {
    "use strict";
    init_utils();
    HashMD = class extends Hash {
      constructor(blockLen, outputLen, padOffset, isLE2) {
        super();
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE2;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
      }
      update(data) {
        aexists(this);
        data = toBytes(data);
        abytes(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len; ) {
          const take = Math.min(blockLen - this.pos, len - pos);
          if (take === blockLen) {
            const dataView = createView(data);
            for (; blockLen <= len - pos; pos += blockLen)
              this.process(dataView, pos);
            continue;
          }
          buffer.set(data.subarray(pos, pos + take), this.pos);
          this.pos += take;
          pos += take;
          if (this.pos === blockLen) {
            this.process(view, 0);
            this.pos = 0;
          }
        }
        this.length += data.length;
        this.roundClean();
        return this;
      }
      digestInto(out) {
        aexists(this);
        aoutput(out, this);
        this.finished = true;
        const { buffer, view, blockLen, isLE: isLE2 } = this;
        let { pos } = this;
        buffer[pos++] = 128;
        clean(this.buffer.subarray(pos));
        if (this.padOffset > blockLen - pos) {
          this.process(view, 0);
          pos = 0;
        }
        for (let i = pos; i < blockLen; i++)
          buffer[i] = 0;
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
        this.process(view, 0);
        const oview = createView(out);
        const len = this.outputLen;
        if (len % 4)
          throw new Error("_sha2: outputLen should be aligned to 32bit");
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
          throw new Error("_sha2: outputLen bigger than state");
        for (let i = 0; i < outLen; i++)
          oview.setUint32(4 * i, state[i], isLE2);
      }
      digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
      }
      _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        if (length % blockLen)
          to.buffer.set(buffer);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
    };
    SHA256_IV = /* @__PURE__ */ Uint32Array.from([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
    SHA512_IV = /* @__PURE__ */ Uint32Array.from([
      1779033703,
      4089235720,
      3144134277,
      2227873595,
      1013904242,
      4271175723,
      2773480762,
      1595750129,
      1359893119,
      2917565137,
      2600822924,
      725511199,
      528734635,
      4215389547,
      1541459225,
      327033209
    ]);
  }
});

// node_modules/@noble/hashes/esm/_u64.js
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var U32_MASK64, _32n, shrSH, shrSL, rotrSH, rotrSL, rotrBH, rotrBL, add3L, add3H, add4L, add4H, add5L, add5H;
var init_u64 = __esm({
  "node_modules/@noble/hashes/esm/_u64.js"() {
    "use strict";
    U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
    _32n = /* @__PURE__ */ BigInt(32);
    shrSH = (h, _l, s) => h >>> s;
    shrSL = (h, l, s) => h << 32 - s | l >>> s;
    rotrSH = (h, l, s) => h >>> s | l << 32 - s;
    rotrSL = (h, l, s) => h << 32 - s | l >>> s;
    rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
    rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
    add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
    add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
    add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
    add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
    add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
    add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
  }
});

// node_modules/@noble/hashes/esm/sha2.js
var SHA256_K, SHA256_W, SHA256, K512, SHA512_Kh, SHA512_Kl, SHA512_W_H, SHA512_W_L, SHA512, sha256, sha512;
var init_sha2 = __esm({
  "node_modules/@noble/hashes/esm/sha2.js"() {
    "use strict";
    init_md();
    init_u64();
    init_utils();
    SHA256_K = /* @__PURE__ */ Uint32Array.from([
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ]);
    SHA256_W = /* @__PURE__ */ new Uint32Array(64);
    SHA256 = class extends HashMD {
      constructor(outputLen = 32) {
        super(64, outputLen, 8, false);
        this.A = SHA256_IV[0] | 0;
        this.B = SHA256_IV[1] | 0;
        this.C = SHA256_IV[2] | 0;
        this.D = SHA256_IV[3] | 0;
        this.E = SHA256_IV[4] | 0;
        this.F = SHA256_IV[5] | 0;
        this.G = SHA256_IV[6] | 0;
        this.H = SHA256_IV[7] | 0;
      }
      get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
      }
      // prettier-ignore
      set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
          const W15 = SHA256_W[i - 15];
          const W2 = SHA256_W[i - 2];
          const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
          const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
          SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
        }
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
          const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
          const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
          const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
          const T2 = sigma0 + Maj(A, B, C) | 0;
          H = G;
          G = F;
          F = E;
          E = D + T1 | 0;
          D = C;
          C = B;
          B = A;
          A = T1 + T2 | 0;
        }
        A = A + this.A | 0;
        B = B + this.B | 0;
        C = C + this.C | 0;
        D = D + this.D | 0;
        E = E + this.E | 0;
        F = F + this.F | 0;
        G = G + this.G | 0;
        H = H + this.H | 0;
        this.set(A, B, C, D, E, F, G, H);
      }
      roundClean() {
        clean(SHA256_W);
      }
      destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        clean(this.buffer);
      }
    };
    K512 = /* @__PURE__ */ (() => split([
      "0x428a2f98d728ae22",
      "0x7137449123ef65cd",
      "0xb5c0fbcfec4d3b2f",
      "0xe9b5dba58189dbbc",
      "0x3956c25bf348b538",
      "0x59f111f1b605d019",
      "0x923f82a4af194f9b",
      "0xab1c5ed5da6d8118",
      "0xd807aa98a3030242",
      "0x12835b0145706fbe",
      "0x243185be4ee4b28c",
      "0x550c7dc3d5ffb4e2",
      "0x72be5d74f27b896f",
      "0x80deb1fe3b1696b1",
      "0x9bdc06a725c71235",
      "0xc19bf174cf692694",
      "0xe49b69c19ef14ad2",
      "0xefbe4786384f25e3",
      "0x0fc19dc68b8cd5b5",
      "0x240ca1cc77ac9c65",
      "0x2de92c6f592b0275",
      "0x4a7484aa6ea6e483",
      "0x5cb0a9dcbd41fbd4",
      "0x76f988da831153b5",
      "0x983e5152ee66dfab",
      "0xa831c66d2db43210",
      "0xb00327c898fb213f",
      "0xbf597fc7beef0ee4",
      "0xc6e00bf33da88fc2",
      "0xd5a79147930aa725",
      "0x06ca6351e003826f",
      "0x142929670a0e6e70",
      "0x27b70a8546d22ffc",
      "0x2e1b21385c26c926",
      "0x4d2c6dfc5ac42aed",
      "0x53380d139d95b3df",
      "0x650a73548baf63de",
      "0x766a0abb3c77b2a8",
      "0x81c2c92e47edaee6",
      "0x92722c851482353b",
      "0xa2bfe8a14cf10364",
      "0xa81a664bbc423001",
      "0xc24b8b70d0f89791",
      "0xc76c51a30654be30",
      "0xd192e819d6ef5218",
      "0xd69906245565a910",
      "0xf40e35855771202a",
      "0x106aa07032bbd1b8",
      "0x19a4c116b8d2d0c8",
      "0x1e376c085141ab53",
      "0x2748774cdf8eeb99",
      "0x34b0bcb5e19b48a8",
      "0x391c0cb3c5c95a63",
      "0x4ed8aa4ae3418acb",
      "0x5b9cca4f7763e373",
      "0x682e6ff3d6b2b8a3",
      "0x748f82ee5defb2fc",
      "0x78a5636f43172f60",
      "0x84c87814a1f0ab72",
      "0x8cc702081a6439ec",
      "0x90befffa23631e28",
      "0xa4506cebde82bde9",
      "0xbef9a3f7b2c67915",
      "0xc67178f2e372532b",
      "0xca273eceea26619c",
      "0xd186b8c721c0c207",
      "0xeada7dd6cde0eb1e",
      "0xf57d4f7fee6ed178",
      "0x06f067aa72176fba",
      "0x0a637dc5a2c898a6",
      "0x113f9804bef90dae",
      "0x1b710b35131c471b",
      "0x28db77f523047d84",
      "0x32caab7b40c72493",
      "0x3c9ebe0a15c9bebc",
      "0x431d67c49c100d4c",
      "0x4cc5d4becb3e42b6",
      "0x597f299cfc657e2a",
      "0x5fcb6fab3ad6faec",
      "0x6c44198c4a475817"
    ].map((n) => BigInt(n))))();
    SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
    SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
    SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
    SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
    SHA512 = class extends HashMD {
      constructor(outputLen = 64) {
        super(128, outputLen, 16, false);
        this.Ah = SHA512_IV[0] | 0;
        this.Al = SHA512_IV[1] | 0;
        this.Bh = SHA512_IV[2] | 0;
        this.Bl = SHA512_IV[3] | 0;
        this.Ch = SHA512_IV[4] | 0;
        this.Cl = SHA512_IV[5] | 0;
        this.Dh = SHA512_IV[6] | 0;
        this.Dl = SHA512_IV[7] | 0;
        this.Eh = SHA512_IV[8] | 0;
        this.El = SHA512_IV[9] | 0;
        this.Fh = SHA512_IV[10] | 0;
        this.Fl = SHA512_IV[11] | 0;
        this.Gh = SHA512_IV[12] | 0;
        this.Gl = SHA512_IV[13] | 0;
        this.Hh = SHA512_IV[14] | 0;
        this.Hl = SHA512_IV[15] | 0;
      }
      // prettier-ignore
      get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
      }
      // prettier-ignore
      set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4) {
          SHA512_W_H[i] = view.getUint32(offset);
          SHA512_W_L[i] = view.getUint32(offset += 4);
        }
        for (let i = 16; i < 80; i++) {
          const W15h = SHA512_W_H[i - 15] | 0;
          const W15l = SHA512_W_L[i - 15] | 0;
          const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
          const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
          const W2h = SHA512_W_H[i - 2] | 0;
          const W2l = SHA512_W_L[i - 2] | 0;
          const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
          const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
          const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
          const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
          SHA512_W_H[i] = SUMh | 0;
          SHA512_W_L[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        for (let i = 0; i < 80; i++) {
          const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
          const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
          const CHIh = Eh & Fh ^ ~Eh & Gh;
          const CHIl = El & Fl ^ ~El & Gl;
          const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
          const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
          const T1l = T1ll | 0;
          const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
          const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
          const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
          const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
          Hh = Gh | 0;
          Hl = Gl | 0;
          Gh = Fh | 0;
          Gl = Fl | 0;
          Fh = Eh | 0;
          Fl = El | 0;
          ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
          Dh = Ch | 0;
          Dl = Cl | 0;
          Ch = Bh | 0;
          Cl = Bl | 0;
          Bh = Ah | 0;
          Bl = Al | 0;
          const All = add3L(T1l, sigma0l, MAJl);
          Ah = add3H(All, T1h, sigma0h, MAJh);
          Al = All | 0;
        }
        ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
      }
      roundClean() {
        clean(SHA512_W_H, SHA512_W_L);
      }
      destroy() {
        clean(this.buffer);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      }
    };
    sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
    sha512 = /* @__PURE__ */ createHasher(() => new SHA512());
  }
});

// node_modules/@noble/curves/esm/utils.js
function _abool2(value, title = "") {
  if (typeof value !== "boolean") {
    const prefix = title && `"${title}"`;
    throw new Error(prefix + "expected boolean, got type=" + typeof value);
  }
  return value;
}
function _abytes2(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  abytes(bytes);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
    }
  } else if (isBytes(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + " must be hex string or Uint8Array");
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(title + " of length " + expectedLength + " expected, got " + len);
  return res;
}
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(bytes);
}
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new Error("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  let len;
  for (len = 0; n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}
function isHash(val) {
  return typeof val === "function" && Number.isSafeInteger(val.outputLen);
}
function _validateObject(object, fields, optFields = {}) {
  if (!object || typeof object !== "object")
    throw new Error("expected valid options object");
  function checkField(fieldName, expectedType, isOpt) {
    const val = object[fieldName];
    if (isOpt && val === void 0)
      return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new Error(`param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`);
  }
  Object.entries(fields).forEach(([k, v]) => checkField(k, v, false));
  Object.entries(optFields).forEach(([k, v]) => checkField(k, v, true));
}
function memoized(fn) {
  const map = /* @__PURE__ */ new WeakMap();
  return (arg, ...args) => {
    const val = map.get(arg);
    if (val !== void 0)
      return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}
var _0n, _1n, isPosBig, bitMask, notImplemented;
var init_utils2 = __esm({
  "node_modules/@noble/curves/esm/utils.js"() {
    "use strict";
    init_utils();
    init_utils();
    _0n = /* @__PURE__ */ BigInt(0);
    _1n = /* @__PURE__ */ BigInt(1);
    isPosBig = (n) => typeof n === "bigint" && _0n <= n;
    bitMask = (n) => (_1n << BigInt(n)) - _1n;
    notImplemented = () => {
      throw new Error("not implemented");
    };
  }
});

// node_modules/@noble/curves/esm/abstract/modular.js
function mod(a, b) {
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow2(x, power, modulo) {
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n2)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n2, y = _1n2, u = _1n2, v = _0n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function assertIsSquare(Fp2, root, n) {
  if (!Fp2.eql(Fp2.sqr(root), n))
    throw new Error("Cannot find square root");
}
function sqrt3mod4(Fp2, n) {
  const p1div4 = (Fp2.ORDER + _1n2) / _4n;
  const root = Fp2.pow(n, p1div4);
  assertIsSquare(Fp2, root, n);
  return root;
}
function sqrt5mod8(Fp2, n) {
  const p5div8 = (Fp2.ORDER - _5n) / _8n;
  const n2 = Fp2.mul(n, _2n);
  const v = Fp2.pow(n2, p5div8);
  const nv = Fp2.mul(n, v);
  const i = Fp2.mul(Fp2.mul(nv, _2n), v);
  const root = Fp2.mul(nv, Fp2.sub(i, Fp2.ONE));
  assertIsSquare(Fp2, root, n);
  return root;
}
function sqrt9mod16(P) {
  const Fp_ = Field(P);
  const tn = tonelliShanks(P);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P + _7n) / _16n;
  return (Fp2, n) => {
    let tv1 = Fp2.pow(n, c4);
    let tv2 = Fp2.mul(tv1, c1);
    const tv3 = Fp2.mul(tv1, c2);
    const tv4 = Fp2.mul(tv1, c3);
    const e1 = Fp2.eql(Fp2.sqr(tv2), n);
    const e2 = Fp2.eql(Fp2.sqr(tv3), n);
    tv1 = Fp2.cmov(tv1, tv2, e1);
    tv2 = Fp2.cmov(tv4, tv3, e2);
    const e3 = Fp2.eql(Fp2.sqr(tv2), n);
    const root = Fp2.cmov(tv1, tv2, e3);
    assertIsSquare(Fp2, root, n);
    return root;
  };
}
function tonelliShanks(P) {
  if (P < _3n)
    throw new Error("sqrt is not defined for small field");
  let Q = P - _1n2;
  let S = 0;
  while (Q % _2n === _0n2) {
    Q /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n2) / _2n;
  return function tonelliSlow(Fp2, n) {
    if (Fp2.is0(n))
      return n;
    if (FpLegendre(Fp2, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = Fp2.mul(Fp2.ONE, cc);
    let t = Fp2.pow(n, Q);
    let R = Fp2.pow(n, Q1div2);
    while (!Fp2.eql(t, Fp2.ONE)) {
      if (Fp2.is0(t))
        return Fp2.ZERO;
      let i = 1;
      let t_tmp = Fp2.sqr(t);
      while (!Fp2.eql(t_tmp, Fp2.ONE)) {
        i++;
        t_tmp = Fp2.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n2 << BigInt(M - i - 1);
      const b = Fp2.pow(c, exponent);
      M = i;
      c = Fp2.sqr(b);
      t = Fp2.mul(t, c);
      R = Fp2.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  if (P % _16n === _9n)
    return sqrt9mod16(P);
  return tonelliShanks(P);
}
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "number",
    BITS: "number"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  _validateObject(field, opts);
  return field;
}
function FpPow(Fp2, num, power) {
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return Fp2.ONE;
  if (power === _1n2)
    return num;
  let p = Fp2.ONE;
  let d = num;
  while (power > _0n2) {
    if (power & _1n2)
      p = Fp2.mul(p, d);
    d = Fp2.sqr(d);
    power >>= _1n2;
  }
  return p;
}
function FpInvertBatch(Fp2, nums, passZero = false) {
  const inverted = new Array(nums.length).fill(passZero ? Fp2.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i] = acc;
    return Fp2.mul(acc, num);
  }, Fp2.ONE);
  const invertedAcc = Fp2.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i] = Fp2.mul(acc, inverted[i]);
    return Fp2.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp2, n) {
  const p1mod2 = (Fp2.ORDER - _1n2) / _2n;
  const powered = Fp2.pow(n, p1mod2);
  const yes = Fp2.eql(powered, Fp2.ONE);
  const zero = Fp2.eql(powered, Fp2.ZERO);
  const no = Fp2.eql(powered, Fp2.neg(Fp2.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber(nBitLength);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
function Field(ORDER, bitLenOrOpts, isLE2 = false, opts = {}) {
  if (ORDER <= _0n2)
    throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
  let _nbitLength = void 0;
  let _sqrt = void 0;
  let modFromBytes = false;
  let allowedLengths = void 0;
  if (typeof bitLenOrOpts === "object" && bitLenOrOpts != null) {
    if (opts.sqrt || isLE2)
      throw new Error("cannot specify opts in two arguments");
    const _opts = bitLenOrOpts;
    if (_opts.BITS)
      _nbitLength = _opts.BITS;
    if (_opts.sqrt)
      _sqrt = _opts.sqrt;
    if (typeof _opts.isLE === "boolean")
      isLE2 = _opts.isLE;
    if (typeof _opts.modFromBytes === "boolean")
      modFromBytes = _opts.modFromBytes;
    allowedLengths = _opts.allowedLengths;
  } else {
    if (typeof bitLenOrOpts === "number")
      _nbitLength = bitLenOrOpts;
    if (opts.sqrt)
      _sqrt = opts.sqrt;
  }
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, _nbitLength);
  if (BYTES > 2048)
    throw new Error("invalid field: expected ORDER of <= 2048 bytes");
  let sqrtP;
  const f = Object.freeze({
    ORDER,
    isLE: isLE2,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n2,
    ONE: _1n2,
    allowedLengths,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== "bigint")
        throw new Error("invalid field element: expected bigint, got " + typeof num);
      return _0n2 <= num && num < ORDER;
    },
    is0: (num) => num === _0n2,
    // is valid and invertible
    isValidNot0: (num) => !f.is0(num) && f.isValid(num),
    isOdd: (num) => (num & _1n2) === _1n2,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,
    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
    // Same as above, but doesn't normalize
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,
    inv: (num) => invert(num, ORDER),
    sqrt: _sqrt || ((n) => {
      if (!sqrtP)
        sqrtP = FpSqrt(ORDER);
      return sqrtP(f, n);
    }),
    toBytes: (num) => isLE2 ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes, skipValidation = true) => {
      if (allowedLengths) {
        if (!allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
          throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
        }
        const padded = new Uint8Array(BYTES);
        padded.set(bytes, isLE2 ? 0 : padded.length - bytes.length);
        bytes = padded;
      }
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      let scalar = isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
      if (modFromBytes)
        scalar = mod(scalar, ORDER);
      if (!skipValidation) {
        if (!f.isValid(scalar))
          throw new Error("invalid field element: outside of range 0..ORDER");
      }
      return scalar;
    },
    // TODO: we don't need it here, move out to separate fn
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov: (a, b, c) => c ? b : a
  });
  return Object.freeze(f);
}
function FpSqrtEven(Fp2, elm) {
  if (!Fp2.isOdd)
    throw new Error("Field doesn't have isOdd");
  const root = Fp2.sqrt(elm);
  return Fp2.isOdd(root) ? Fp2.neg(root) : root;
}
var _0n2, _1n2, _2n, _3n, _4n, _5n, _7n, _8n, _9n, _16n, isNegativeLE, FIELD_FIELDS;
var init_modular = __esm({
  "node_modules/@noble/curves/esm/abstract/modular.js"() {
    "use strict";
    init_utils2();
    _0n2 = BigInt(0);
    _1n2 = BigInt(1);
    _2n = /* @__PURE__ */ BigInt(2);
    _3n = /* @__PURE__ */ BigInt(3);
    _4n = /* @__PURE__ */ BigInt(4);
    _5n = /* @__PURE__ */ BigInt(5);
    _7n = /* @__PURE__ */ BigInt(7);
    _8n = /* @__PURE__ */ BigInt(8);
    _9n = /* @__PURE__ */ BigInt(9);
    _16n = /* @__PURE__ */ BigInt(16);
    isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n2) === _1n2;
    FIELD_FIELDS = [
      "create",
      "isValid",
      "is0",
      "neg",
      "inv",
      "sqrt",
      "sqr",
      "eql",
      "add",
      "sub",
      "mul",
      "pow",
      "div",
      "addN",
      "subN",
      "mulN",
      "sqrN"
    ];
  }
});

// node_modules/@noble/curves/esm/abstract/curve.js
function negateCt(condition, item) {
  const neg = item.negate();
  return condition ? neg : item;
}
function normalizeZ(c, points) {
  const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}
function validateW(W, bits) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
    throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
}
function calcWOpts(W, scalarBits) {
  validateW(W, scalarBits);
  const windows = Math.ceil(scalarBits / W) + 1;
  const windowSize = 2 ** (W - 1);
  const maxNumber = 2 ** W;
  const mask = bitMask(W);
  const shiftBy = BigInt(W);
  return { windows, windowSize, mask, maxNumber, shiftBy };
}
function calcOffsets(n, window, wOpts) {
  const { windowSize, mask, maxNumber, shiftBy } = wOpts;
  let wbits = Number(n & mask);
  let nextN = n >> shiftBy;
  if (wbits > windowSize) {
    wbits -= maxNumber;
    nextN += _1n3;
  }
  const offsetStart = window * windowSize;
  const offset = offsetStart + Math.abs(wbits) - 1;
  const isZero = wbits === 0;
  const isNeg = wbits < 0;
  const isNegF = window % 2 !== 0;
  const offsetF = offsetStart;
  return { nextN, offset, isZero, isNeg, isNegF, offsetF };
}
function validateMSMPoints(points, c) {
  if (!Array.isArray(points))
    throw new Error("array expected");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    if (!field.isValid(s))
      throw new Error("invalid scalar at index " + i);
  });
}
function getW(P) {
  return pointWindowSizes.get(P) || 1;
}
function assert0(n) {
  if (n !== _0n3)
    throw new Error("invalid wNAF");
}
function pippenger(c, fieldN, points, scalars) {
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  const plength = points.length;
  const slength = scalars.length;
  if (plength !== slength)
    throw new Error("arrays of points and scalars must have equal length");
  const zero = c.ZERO;
  const wbits = bitLen(BigInt(plength));
  let windowSize = 1;
  if (wbits > 12)
    windowSize = wbits - 3;
  else if (wbits > 4)
    windowSize = wbits - 2;
  else if (wbits > 0)
    windowSize = 2;
  const MASK = bitMask(windowSize);
  const buckets = new Array(Number(MASK) + 1).fill(zero);
  const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
  let sum = zero;
  for (let i = lastBits; i >= 0; i -= windowSize) {
    buckets.fill(zero);
    for (let j = 0; j < slength; j++) {
      const scalar = scalars[j];
      const wbits2 = Number(scalar >> BigInt(i) & MASK);
      buckets[wbits2] = buckets[wbits2].add(points[j]);
    }
    let resI = zero;
    for (let j = buckets.length - 1, sumI = zero; j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i !== 0)
      for (let j = 0; j < windowSize; j++)
        sum = sum.double();
  }
  return sum;
}
function createField(order, field, isLE2) {
  if (field) {
    if (field.ORDER !== order)
      throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
    validateField(field);
    return field;
  } else {
    return Field(order, { isLE: isLE2 });
  }
}
function _createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
  if (FpFnLE === void 0)
    FpFnLE = type === "edwards";
  if (!CURVE || typeof CURVE !== "object")
    throw new Error(`expected valid ${type} CURVE object`);
  for (const p of ["p", "n", "h"]) {
    const val = CURVE[p];
    if (!(typeof val === "bigint" && val > _0n3))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp2 = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn2 = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b = type === "weierstrass" ? "b" : "d";
  const params = ["Gx", "Gy", "a", _b];
  for (const p of params) {
    if (!Fp2.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp: Fp2, Fn: Fn2 };
}
var _0n3, _1n3, pointPrecomputes, pointWindowSizes, wNAF;
var init_curve = __esm({
  "node_modules/@noble/curves/esm/abstract/curve.js"() {
    "use strict";
    init_utils2();
    init_modular();
    _0n3 = BigInt(0);
    _1n3 = BigInt(1);
    pointPrecomputes = /* @__PURE__ */ new WeakMap();
    pointWindowSizes = /* @__PURE__ */ new WeakMap();
    wNAF = class {
      // Parametrized with a given Point class (not individual point)
      constructor(Point, bits) {
        this.BASE = Point.BASE;
        this.ZERO = Point.ZERO;
        this.Fn = Point.Fn;
        this.bits = bits;
      }
      // non-const time multiplication ladder
      _unsafeLadder(elm, n, p = this.ZERO) {
        let d = elm;
        while (n > _0n3) {
          if (n & _1n3)
            p = p.add(d);
          d = d.double();
          n >>= _1n3;
        }
        return p;
      }
      /**
       * Creates a wNAF precomputation window. Used for caching.
       * Default window size is set by `utils.precompute()` and is equal to 8.
       * Number of precomputed points depends on the curve size:
       * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
       * - 𝑊 is the window size
       * - 𝑛 is the bitlength of the curve order.
       * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
       * @param point Point instance
       * @param W window size
       * @returns precomputed point tables flattened to a single array
       */
      precomputeWindow(point, W) {
        const { windows, windowSize } = calcWOpts(W, this.bits);
        const points = [];
        let p = point;
        let base = p;
        for (let window = 0; window < windows; window++) {
          base = p;
          points.push(base);
          for (let i = 1; i < windowSize; i++) {
            base = base.add(p);
            points.push(base);
          }
          p = base.double();
        }
        return points;
      }
      /**
       * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
       * More compact implementation:
       * https://github.com/paulmillr/noble-secp256k1/blob/47cb1669b6e506ad66b35fe7d76132ae97465da2/index.ts#L502-L541
       * @returns real and fake (for const-time) points
       */
      wNAF(W, precomputes, n) {
        if (!this.Fn.isValid(n))
          throw new Error("invalid scalar");
        let p = this.ZERO;
        let f = this.BASE;
        const wo = calcWOpts(W, this.bits);
        for (let window = 0; window < wo.windows; window++) {
          const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
          n = nextN;
          if (isZero) {
            f = f.add(negateCt(isNegF, precomputes[offsetF]));
          } else {
            p = p.add(negateCt(isNeg, precomputes[offset]));
          }
        }
        assert0(n);
        return { p, f };
      }
      /**
       * Implements ec unsafe (non const-time) multiplication using precomputed tables and w-ary non-adjacent form.
       * @param acc accumulator point to add result of multiplication
       * @returns point
       */
      wNAFUnsafe(W, precomputes, n, acc = this.ZERO) {
        const wo = calcWOpts(W, this.bits);
        for (let window = 0; window < wo.windows; window++) {
          if (n === _0n3)
            break;
          const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
          n = nextN;
          if (isZero) {
            continue;
          } else {
            const item = precomputes[offset];
            acc = acc.add(isNeg ? item.negate() : item);
          }
        }
        assert0(n);
        return acc;
      }
      getPrecomputes(W, point, transform) {
        let comp = pointPrecomputes.get(point);
        if (!comp) {
          comp = this.precomputeWindow(point, W);
          if (W !== 1) {
            if (typeof transform === "function")
              comp = transform(comp);
            pointPrecomputes.set(point, comp);
          }
        }
        return comp;
      }
      cached(point, scalar, transform) {
        const W = getW(point);
        return this.wNAF(W, this.getPrecomputes(W, point, transform), scalar);
      }
      unsafe(point, scalar, transform, prev) {
        const W = getW(point);
        if (W === 1)
          return this._unsafeLadder(point, scalar, prev);
        return this.wNAFUnsafe(W, this.getPrecomputes(W, point, transform), scalar, prev);
      }
      // We calculate precomputes for elliptic curve point multiplication
      // using windowed method. This specifies window size and
      // stores precomputed values. Usually only base point would be precomputed.
      createCache(P, W) {
        validateW(W, this.bits);
        pointWindowSizes.set(P, W);
        pointPrecomputes.delete(P);
      }
      hasCache(elm) {
        return getW(elm) !== 1;
      }
    };
  }
});

// node_modules/@noble/curves/esm/abstract/edwards.js
function isEdValidXY(Fp2, CURVE, x, y) {
  const x2 = Fp2.sqr(x);
  const y2 = Fp2.sqr(y);
  const left = Fp2.add(Fp2.mul(CURVE.a, x2), y2);
  const right = Fp2.add(Fp2.ONE, Fp2.mul(CURVE.d, Fp2.mul(x2, y2)));
  return Fp2.eql(left, right);
}
function edwards(params, extraOpts = {}) {
  const validated = _createCurveFields("edwards", params, extraOpts, extraOpts.FpFnLE);
  const { Fp: Fp2, Fn: Fn2 } = validated;
  let CURVE = validated.CURVE;
  const { h: cofactor } = CURVE;
  _validateObject(extraOpts, {}, { uvRatio: "function" });
  const MASK = _2n2 << BigInt(Fn2.BYTES * 8) - _1n4;
  const modP = (n) => Fp2.create(n);
  const uvRatio2 = extraOpts.uvRatio || ((u, v) => {
    try {
      return { isValid: true, value: Fp2.sqrt(Fp2.div(u, v)) };
    } catch (e) {
      return { isValid: false, value: _0n4 };
    }
  });
  if (!isEdValidXY(Fp2, CURVE, CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  function acoord(title, n, banZero = false) {
    const min = banZero ? _1n4 : _0n4;
    aInRange("coordinate " + title, n, min, MASK);
    return n;
  }
  function aextpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ExtendedPoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { X, Y, Z } = p;
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? _8n2 : Fp2.inv(Z);
    const x = modP(X * iz);
    const y = modP(Y * iz);
    const zz = Fp2.mul(Z, iz);
    if (is0)
      return { x: _0n4, y: _1n4 };
    if (zz !== _1n4)
      throw new Error("invZ was invalid");
    return { x, y };
  });
  const assertValidMemo = memoized((p) => {
    const { a, d } = CURVE;
    if (p.is0())
      throw new Error("bad point: ZERO");
    const { X, Y, Z, T } = p;
    const X2 = modP(X * X);
    const Y2 = modP(Y * Y);
    const Z2 = modP(Z * Z);
    const Z4 = modP(Z2 * Z2);
    const aX2 = modP(X2 * a);
    const left = modP(Z2 * modP(aX2 + Y2));
    const right = modP(Z4 + modP(d * modP(X2 * Y2)));
    if (left !== right)
      throw new Error("bad point: equation left != right (1)");
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT)
      throw new Error("bad point: equation left != right (2)");
    return true;
  });
  class Point {
    constructor(X, Y, Z, T) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y);
      this.Z = acoord("z", Z, true);
      this.T = acoord("t", T);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    static fromAffine(p) {
      if (p instanceof Point)
        throw new Error("extended point not allowed");
      const { x, y } = p || {};
      acoord("x", x);
      acoord("y", y);
      return new Point(x, y, _1n4, modP(x * y));
    }
    // Uses algo from RFC8032 5.1.3.
    static fromBytes(bytes, zip215 = false) {
      const len = Fp2.BYTES;
      const { a, d } = CURVE;
      bytes = copyBytes(_abytes2(bytes, len, "point"));
      _abool2(zip215, "zip215");
      const normed = copyBytes(bytes);
      const lastByte = bytes[len - 1];
      normed[len - 1] = lastByte & ~128;
      const y = bytesToNumberLE(normed);
      const max = zip215 ? MASK : Fp2.ORDER;
      aInRange("point.y", y, _0n4, max);
      const y2 = modP(y * y);
      const u = modP(y2 - _1n4);
      const v = modP(d * y2 - a);
      let { isValid, value: x } = uvRatio2(u, v);
      if (!isValid)
        throw new Error("bad point: invalid y coordinate");
      const isXOdd = (x & _1n4) === _1n4;
      const isLastByteOdd = (lastByte & 128) !== 0;
      if (!zip215 && x === _0n4 && isLastByteOdd)
        throw new Error("bad point: x=0 and x_0=1");
      if (isLastByteOdd !== isXOdd)
        x = modP(-x);
      return Point.fromAffine({ x, y });
    }
    static fromHex(bytes, zip215 = false) {
      return Point.fromBytes(ensureBytes("point", bytes), zip215);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    precompute(windowSize = 8, isLazy = true) {
      wnaf.createCache(this, windowSize);
      if (!isLazy)
        this.multiply(_2n2);
      return this;
    }
    // Useful in fromAffine() - not for fromBytes(), which always created valid points.
    assertValidity() {
      assertValidMemo(this);
    }
    // Compare one point to another.
    equals(other) {
      aextpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const X1Z2 = modP(X1 * Z2);
      const X2Z1 = modP(X2 * Z1);
      const Y1Z2 = modP(Y1 * Z2);
      const Y2Z1 = modP(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    negate() {
      return new Point(modP(-this.X), this.Y, this.Z, modP(-this.T));
    }
    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double() {
      const { a } = CURVE;
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const A = modP(X1 * X1);
      const B = modP(Y1 * Y1);
      const C = modP(_2n2 * modP(Z1 * Z1));
      const D = modP(a * A);
      const x1y1 = X1 + Y1;
      const E = modP(modP(x1y1 * x1y1) - A - B);
      const G = D + B;
      const F = G - C;
      const H = D - B;
      const X3 = modP(E * F);
      const Y3 = modP(G * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G);
      return new Point(X3, Y3, Z3, T3);
    }
    // Fast algo for adding 2 Extended Points.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // Cost: 9M + 1*a + 1*d + 7add.
    add(other) {
      aextpoint(other);
      const { a, d } = CURVE;
      const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
      const { X: X2, Y: Y2, Z: Z2, T: T2 } = other;
      const A = modP(X1 * X2);
      const B = modP(Y1 * Y2);
      const C = modP(T1 * d * T2);
      const D = modP(Z1 * Z2);
      const E = modP((X1 + Y1) * (X2 + Y2) - A - B);
      const F = D - C;
      const G = D + C;
      const H = modP(B - a * A);
      const X3 = modP(E * F);
      const Y3 = modP(G * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G);
      return new Point(X3, Y3, Z3, T3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    // Constant-time multiplication.
    multiply(scalar) {
      if (!Fn2.isValidNot0(scalar))
        throw new Error("invalid scalar: expected 1 <= sc < curve.n");
      const { p, f } = wnaf.cached(this, scalar, (p2) => normalizeZ(Point, p2));
      return normalizeZ(Point, [p, f])[0];
    }
    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Does NOT allow scalars higher than CURVE.n.
    // Accepts optional accumulator to merge with multiply (important for sparse scalars)
    multiplyUnsafe(scalar, acc = Point.ZERO) {
      if (!Fn2.isValid(scalar))
        throw new Error("invalid scalar: expected 0 <= sc < curve.n");
      if (scalar === _0n4)
        return Point.ZERO;
      if (this.is0() || scalar === _1n4)
        return this;
      return wnaf.unsafe(this, scalar, (p) => normalizeZ(Point, p), acc);
    }
    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Multiplies point by cofactor and checks if the result is 0.
    isSmallOrder() {
      return this.multiplyUnsafe(cofactor).is0();
    }
    // Multiplies point by curve order and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree() {
      return wnaf.unsafe(this, CURVE.n).is0();
    }
    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(invertedZ) {
      return toAffineMemo(this, invertedZ);
    }
    clearCofactor() {
      if (cofactor === _1n4)
        return this;
      return this.multiplyUnsafe(cofactor);
    }
    toBytes() {
      const { x, y } = this.toAffine();
      const bytes = Fp2.toBytes(y);
      bytes[bytes.length - 1] |= x & _1n4 ? 128 : 0;
      return bytes;
    }
    toHex() {
      return bytesToHex(this.toBytes());
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
    // TODO: remove
    get ex() {
      return this.X;
    }
    get ey() {
      return this.Y;
    }
    get ez() {
      return this.Z;
    }
    get et() {
      return this.T;
    }
    static normalizeZ(points) {
      return normalizeZ(Point, points);
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn2, points, scalars);
    }
    _setWindowSize(windowSize) {
      this.precompute(windowSize);
    }
    toRawBytes() {
      return this.toBytes();
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, _1n4, modP(CURVE.Gx * CURVE.Gy));
  Point.ZERO = new Point(_0n4, _1n4, _1n4, _0n4);
  Point.Fp = Fp2;
  Point.Fn = Fn2;
  const wnaf = new wNAF(Point, Fn2.BITS);
  Point.BASE.precompute(8);
  return Point;
}
function eddsa(Point, cHash, eddsaOpts = {}) {
  if (typeof cHash !== "function")
    throw new Error('"hash" function param is required');
  _validateObject(eddsaOpts, {}, {
    adjustScalarBytes: "function",
    randomBytes: "function",
    domain: "function",
    prehash: "function",
    mapToCurve: "function"
  });
  const { prehash } = eddsaOpts;
  const { BASE, Fp: Fp2, Fn: Fn2 } = Point;
  const randomBytes4 = eddsaOpts.randomBytes || randomBytes2;
  const adjustScalarBytes2 = eddsaOpts.adjustScalarBytes || ((bytes) => bytes);
  const domain = eddsaOpts.domain || ((data, ctx, phflag) => {
    _abool2(phflag, "phflag");
    if (ctx.length || phflag)
      throw new Error("Contexts/pre-hash are not supported");
    return data;
  });
  function modN_LE(hash) {
    return Fn2.create(bytesToNumberLE(hash));
  }
  function getPrivateScalar(key) {
    const len = lengths.secretKey;
    key = ensureBytes("private key", key, len);
    const hashed = ensureBytes("hashed private key", cHash(key), 2 * len);
    const head = adjustScalarBytes2(hashed.slice(0, len));
    const prefix = hashed.slice(len, 2 * len);
    const scalar = modN_LE(head);
    return { head, prefix, scalar };
  }
  function getExtendedPublicKey(secretKey) {
    const { head, prefix, scalar } = getPrivateScalar(secretKey);
    const point = BASE.multiply(scalar);
    const pointBytes = point.toBytes();
    return { head, prefix, scalar, point, pointBytes };
  }
  function getPublicKey(secretKey) {
    return getExtendedPublicKey(secretKey).pointBytes;
  }
  function hashDomainToScalar(context = Uint8Array.of(), ...msgs) {
    const msg = concatBytes(...msgs);
    return modN_LE(cHash(domain(msg, ensureBytes("context", context), !!prehash)));
  }
  function sign(msg, secretKey, options = {}) {
    msg = ensureBytes("message", msg);
    if (prehash)
      msg = prehash(msg);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(secretKey);
    const r = hashDomainToScalar(options.context, prefix, msg);
    const R = BASE.multiply(r).toBytes();
    const k = hashDomainToScalar(options.context, R, pointBytes, msg);
    const s = Fn2.create(r + k * scalar);
    if (!Fn2.isValid(s))
      throw new Error("sign failed: invalid s");
    const rs = concatBytes(R, Fn2.toBytes(s));
    return _abytes2(rs, lengths.signature, "result");
  }
  const verifyOpts = { zip215: true };
  function verify(sig, msg, publicKey, options = verifyOpts) {
    const { context, zip215 } = options;
    const len = lengths.signature;
    sig = ensureBytes("signature", sig, len);
    msg = ensureBytes("message", msg);
    publicKey = ensureBytes("publicKey", publicKey, lengths.publicKey);
    if (zip215 !== void 0)
      _abool2(zip215, "zip215");
    if (prehash)
      msg = prehash(msg);
    const mid = len / 2;
    const r = sig.subarray(0, mid);
    const s = bytesToNumberLE(sig.subarray(mid, len));
    let A, R, SB;
    try {
      A = Point.fromBytes(publicKey, zip215);
      R = Point.fromBytes(r, zip215);
      SB = BASE.multiplyUnsafe(s);
    } catch (error) {
      return false;
    }
    if (!zip215 && A.isSmallOrder())
      return false;
    const k = hashDomainToScalar(context, R.toBytes(), A.toBytes(), msg);
    const RkA = R.add(A.multiplyUnsafe(k));
    return RkA.subtract(SB).clearCofactor().is0();
  }
  const _size = Fp2.BYTES;
  const lengths = {
    secretKey: _size,
    publicKey: _size,
    signature: 2 * _size,
    seed: _size
  };
  function randomSecretKey(seed = randomBytes4(lengths.seed)) {
    return _abytes2(seed, lengths.seed, "seed");
  }
  function keygen(seed) {
    const secretKey = utils.randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  }
  function isValidSecretKey(key) {
    return isBytes(key) && key.length === Fn2.BYTES;
  }
  function isValidPublicKey(key, zip215) {
    try {
      return !!Point.fromBytes(key, zip215);
    } catch (error) {
      return false;
    }
  }
  const utils = {
    getExtendedPublicKey,
    randomSecretKey,
    isValidSecretKey,
    isValidPublicKey,
    /**
     * Converts ed public key to x public key. Uses formula:
     * - ed25519:
     *   - `(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)`
     *   - `(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))`
     * - ed448:
     *   - `(u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)`
     *   - `(x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))`
     */
    toMontgomery(publicKey) {
      const { y } = Point.fromBytes(publicKey);
      const size = lengths.publicKey;
      const is25519 = size === 32;
      if (!is25519 && size !== 57)
        throw new Error("only defined for 25519 and 448");
      const u = is25519 ? Fp2.div(_1n4 + y, _1n4 - y) : Fp2.div(y - _1n4, y + _1n4);
      return Fp2.toBytes(u);
    },
    toMontgomerySecret(secretKey) {
      const size = lengths.secretKey;
      _abytes2(secretKey, size);
      const hashed = cHash(secretKey.subarray(0, size));
      return adjustScalarBytes2(hashed).subarray(0, size);
    },
    /** @deprecated */
    randomPrivateKey: randomSecretKey,
    /** @deprecated */
    precompute(windowSize = 8, point = Point.BASE) {
      return point.precompute(windowSize, false);
    }
  };
  return Object.freeze({
    keygen,
    getPublicKey,
    sign,
    verify,
    utils,
    Point,
    lengths
  });
}
function _eddsa_legacy_opts_to_new(c) {
  const CURVE = {
    a: c.a,
    d: c.d,
    p: c.Fp.ORDER,
    n: c.n,
    h: c.h,
    Gx: c.Gx,
    Gy: c.Gy
  };
  const Fp2 = c.Fp;
  const Fn2 = Field(CURVE.n, c.nBitLength, true);
  const curveOpts = { Fp: Fp2, Fn: Fn2, uvRatio: c.uvRatio };
  const eddsaOpts = {
    randomBytes: c.randomBytes,
    adjustScalarBytes: c.adjustScalarBytes,
    domain: c.domain,
    prehash: c.prehash,
    mapToCurve: c.mapToCurve
  };
  return { CURVE, curveOpts, hash: c.hash, eddsaOpts };
}
function _eddsa_new_output_to_legacy(c, eddsa2) {
  const Point = eddsa2.Point;
  const legacy = Object.assign({}, eddsa2, {
    ExtendedPoint: Point,
    CURVE: c,
    nBitLength: Point.Fn.BITS,
    nByteLength: Point.Fn.BYTES
  });
  return legacy;
}
function twistedEdwards(c) {
  const { CURVE, curveOpts, hash, eddsaOpts } = _eddsa_legacy_opts_to_new(c);
  const Point = edwards(CURVE, curveOpts);
  const EDDSA = eddsa(Point, hash, eddsaOpts);
  return _eddsa_new_output_to_legacy(c, EDDSA);
}
var _0n4, _1n4, _2n2, _8n2, PrimeEdwardsPoint;
var init_edwards = __esm({
  "node_modules/@noble/curves/esm/abstract/edwards.js"() {
    "use strict";
    init_utils2();
    init_curve();
    init_modular();
    _0n4 = BigInt(0);
    _1n4 = BigInt(1);
    _2n2 = BigInt(2);
    _8n2 = BigInt(8);
    PrimeEdwardsPoint = class {
      constructor(ep) {
        this.ep = ep;
      }
      // Static methods that must be implemented by subclasses
      static fromBytes(_bytes) {
        notImplemented();
      }
      static fromHex(_hex) {
        notImplemented();
      }
      get x() {
        return this.toAffine().x;
      }
      get y() {
        return this.toAffine().y;
      }
      // Common implementations
      clearCofactor() {
        return this;
      }
      assertValidity() {
        this.ep.assertValidity();
      }
      toAffine(invertedZ) {
        return this.ep.toAffine(invertedZ);
      }
      toHex() {
        return bytesToHex(this.toBytes());
      }
      toString() {
        return this.toHex();
      }
      isTorsionFree() {
        return true;
      }
      isSmallOrder() {
        return false;
      }
      add(other) {
        this.assertSame(other);
        return this.init(this.ep.add(other.ep));
      }
      subtract(other) {
        this.assertSame(other);
        return this.init(this.ep.subtract(other.ep));
      }
      multiply(scalar) {
        return this.init(this.ep.multiply(scalar));
      }
      multiplyUnsafe(scalar) {
        return this.init(this.ep.multiplyUnsafe(scalar));
      }
      double() {
        return this.init(this.ep.double());
      }
      negate() {
        return this.init(this.ep.negate());
      }
      precompute(windowSize, isLazy) {
        return this.init(this.ep.precompute(windowSize, isLazy));
      }
      /** @deprecated use `toBytes` */
      toRawBytes() {
        return this.toBytes();
      }
    };
  }
});

// node_modules/@noble/curves/esm/abstract/hash-to-curve.js
function i2osp(value, length) {
  anum(value);
  anum(length);
  if (value < 0 || value >= 1 << 8 * length)
    throw new Error("invalid I2OSP input: " + value);
  const res = Array.from({ length }).fill(0);
  for (let i = length - 1; i >= 0; i--) {
    res[i] = value & 255;
    value >>>= 8;
  }
  return new Uint8Array(res);
}
function strxor(a, b) {
  const arr = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    arr[i] = a[i] ^ b[i];
  }
  return arr;
}
function anum(item) {
  if (!Number.isSafeInteger(item))
    throw new Error("number expected");
}
function normDST(DST) {
  if (!isBytes(DST) && typeof DST !== "string")
    throw new Error("DST must be Uint8Array or string");
  return typeof DST === "string" ? utf8ToBytes(DST) : DST;
}
function expand_message_xmd(msg, DST, lenInBytes, H) {
  abytes(msg);
  anum(lenInBytes);
  DST = normDST(DST);
  if (DST.length > 255)
    DST = H(concatBytes(utf8ToBytes("H2C-OVERSIZE-DST-"), DST));
  const { outputLen: b_in_bytes, blockLen: r_in_bytes } = H;
  const ell = Math.ceil(lenInBytes / b_in_bytes);
  if (lenInBytes > 65535 || ell > 255)
    throw new Error("expand_message_xmd: invalid lenInBytes");
  const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
  const Z_pad = i2osp(0, r_in_bytes);
  const l_i_b_str = i2osp(lenInBytes, 2);
  const b = new Array(ell);
  const b_0 = H(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
  b[0] = H(concatBytes(b_0, i2osp(1, 1), DST_prime));
  for (let i = 1; i <= ell; i++) {
    const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
    b[i] = H(concatBytes(...args));
  }
  const pseudo_random_bytes = concatBytes(...b);
  return pseudo_random_bytes.slice(0, lenInBytes);
}
function expand_message_xof(msg, DST, lenInBytes, k, H) {
  abytes(msg);
  anum(lenInBytes);
  DST = normDST(DST);
  if (DST.length > 255) {
    const dkLen = Math.ceil(2 * k / 8);
    DST = H.create({ dkLen }).update(utf8ToBytes("H2C-OVERSIZE-DST-")).update(DST).digest();
  }
  if (lenInBytes > 65535 || DST.length > 255)
    throw new Error("expand_message_xof: invalid lenInBytes");
  return H.create({ dkLen: lenInBytes }).update(msg).update(i2osp(lenInBytes, 2)).update(DST).update(i2osp(DST.length, 1)).digest();
}
function hash_to_field(msg, count, options) {
  _validateObject(options, {
    p: "bigint",
    m: "number",
    k: "number",
    hash: "function"
  });
  const { p, k, m, hash, expand, DST } = options;
  if (!isHash(options.hash))
    throw new Error("expected valid hash");
  abytes(msg);
  anum(count);
  const log2p = p.toString(2).length;
  const L = Math.ceil((log2p + k) / 8);
  const len_in_bytes = count * m * L;
  let prb;
  if (expand === "xmd") {
    prb = expand_message_xmd(msg, DST, len_in_bytes, hash);
  } else if (expand === "xof") {
    prb = expand_message_xof(msg, DST, len_in_bytes, k, hash);
  } else if (expand === "_internal_pass") {
    prb = msg;
  } else {
    throw new Error('expand must be "xmd" or "xof"');
  }
  const u = new Array(count);
  for (let i = 0; i < count; i++) {
    const e = new Array(m);
    for (let j = 0; j < m; j++) {
      const elm_offset = L * (j + i * m);
      const tv = prb.subarray(elm_offset, elm_offset + L);
      e[j] = mod(os2ip(tv), p);
    }
    u[i] = e;
  }
  return u;
}
function createHasher2(Point, mapToCurve, defaults) {
  if (typeof mapToCurve !== "function")
    throw new Error("mapToCurve() must be defined");
  function map(num) {
    return Point.fromAffine(mapToCurve(num));
  }
  function clear(initial) {
    const P = initial.clearCofactor();
    if (P.equals(Point.ZERO))
      return Point.ZERO;
    P.assertValidity();
    return P;
  }
  return {
    defaults,
    hashToCurve(msg, options) {
      const opts = Object.assign({}, defaults, options);
      const u = hash_to_field(msg, 2, opts);
      const u0 = map(u[0]);
      const u1 = map(u[1]);
      return clear(u0.add(u1));
    },
    encodeToCurve(msg, options) {
      const optsDst = defaults.encodeDST ? { DST: defaults.encodeDST } : {};
      const opts = Object.assign({}, defaults, optsDst, options);
      const u = hash_to_field(msg, 1, opts);
      const u0 = map(u[0]);
      return clear(u0);
    },
    /** See {@link H2CHasher} */
    mapToCurve(scalars) {
      if (!Array.isArray(scalars))
        throw new Error("expected array of bigints");
      for (const i of scalars)
        if (typeof i !== "bigint")
          throw new Error("expected array of bigints");
      return clear(map(scalars));
    },
    // hash_to_scalar can produce 0: https://www.rfc-editor.org/errata/eid8393
    // RFC 9380, draft-irtf-cfrg-bbs-signatures-08
    hashToScalar(msg, options) {
      const N = Point.Fn.ORDER;
      const opts = Object.assign({}, defaults, { p: N, m: 1, DST: _DST_scalar }, options);
      return hash_to_field(msg, 1, opts)[0][0];
    }
  };
}
var os2ip, _DST_scalar;
var init_hash_to_curve = __esm({
  "node_modules/@noble/curves/esm/abstract/hash-to-curve.js"() {
    "use strict";
    init_utils2();
    init_modular();
    os2ip = bytesToNumberBE;
    _DST_scalar = utf8ToBytes("HashToScalar-");
  }
});

// node_modules/@noble/curves/esm/abstract/montgomery.js
function validateOpts(curve) {
  _validateObject(curve, {
    adjustScalarBytes: "function",
    powPminus2: "function"
  });
  return Object.freeze({ ...curve });
}
function montgomery(curveDef) {
  const CURVE = validateOpts(curveDef);
  const { P, type, adjustScalarBytes: adjustScalarBytes2, powPminus2, randomBytes: rand } = CURVE;
  const is25519 = type === "x25519";
  if (!is25519 && type !== "x448")
    throw new Error("invalid type");
  const randomBytes_ = rand || randomBytes2;
  const montgomeryBits = is25519 ? 255 : 448;
  const fieldLen = is25519 ? 32 : 56;
  const Gu = is25519 ? BigInt(9) : BigInt(5);
  const a24 = is25519 ? BigInt(121665) : BigInt(39081);
  const minScalar = is25519 ? _2n3 ** BigInt(254) : _2n3 ** BigInt(447);
  const maxAdded = is25519 ? BigInt(8) * _2n3 ** BigInt(251) - _1n5 : BigInt(4) * _2n3 ** BigInt(445) - _1n5;
  const maxScalar = minScalar + maxAdded + _1n5;
  const modP = (n) => mod(n, P);
  const GuBytes = encodeU(Gu);
  function encodeU(u) {
    return numberToBytesLE(modP(u), fieldLen);
  }
  function decodeU(u) {
    const _u = ensureBytes("u coordinate", u, fieldLen);
    if (is25519)
      _u[31] &= 127;
    return modP(bytesToNumberLE(_u));
  }
  function decodeScalar(scalar) {
    return bytesToNumberLE(adjustScalarBytes2(ensureBytes("scalar", scalar, fieldLen)));
  }
  function scalarMult(scalar, u) {
    const pu = montgomeryLadder(decodeU(u), decodeScalar(scalar));
    if (pu === _0n5)
      throw new Error("invalid private or public key received");
    return encodeU(pu);
  }
  function scalarMultBase(scalar) {
    return scalarMult(scalar, GuBytes);
  }
  function cswap(swap, x_2, x_3) {
    const dummy = modP(swap * (x_2 - x_3));
    x_2 = modP(x_2 - dummy);
    x_3 = modP(x_3 + dummy);
    return { x_2, x_3 };
  }
  function montgomeryLadder(u, scalar) {
    aInRange("u", u, _0n5, P);
    aInRange("scalar", scalar, minScalar, maxScalar);
    const k = scalar;
    const x_1 = u;
    let x_2 = _1n5;
    let z_2 = _0n5;
    let x_3 = u;
    let z_3 = _1n5;
    let swap = _0n5;
    for (let t = BigInt(montgomeryBits - 1); t >= _0n5; t--) {
      const k_t = k >> t & _1n5;
      swap ^= k_t;
      ({ x_2, x_3 } = cswap(swap, x_2, x_3));
      ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
      swap = k_t;
      const A = x_2 + z_2;
      const AA = modP(A * A);
      const B = x_2 - z_2;
      const BB = modP(B * B);
      const E = AA - BB;
      const C = x_3 + z_3;
      const D = x_3 - z_3;
      const DA = modP(D * A);
      const CB = modP(C * B);
      const dacb = DA + CB;
      const da_cb = DA - CB;
      x_3 = modP(dacb * dacb);
      z_3 = modP(x_1 * modP(da_cb * da_cb));
      x_2 = modP(AA * BB);
      z_2 = modP(E * (AA + modP(a24 * E)));
    }
    ({ x_2, x_3 } = cswap(swap, x_2, x_3));
    ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
    const z2 = powPminus2(z_2);
    return modP(x_2 * z2);
  }
  const lengths = {
    secretKey: fieldLen,
    publicKey: fieldLen,
    seed: fieldLen
  };
  const randomSecretKey = (seed = randomBytes_(fieldLen)) => {
    abytes(seed, lengths.seed);
    return seed;
  };
  function keygen(seed) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: scalarMultBase(secretKey) };
  }
  const utils = {
    randomSecretKey,
    randomPrivateKey: randomSecretKey
  };
  return {
    keygen,
    getSharedSecret: (secretKey, publicKey) => scalarMult(secretKey, publicKey),
    getPublicKey: (secretKey) => scalarMultBase(secretKey),
    scalarMult,
    scalarMultBase,
    utils,
    GuBytes: GuBytes.slice(),
    lengths
  };
}
var _0n5, _1n5, _2n3;
var init_montgomery = __esm({
  "node_modules/@noble/curves/esm/abstract/montgomery.js"() {
    "use strict";
    init_utils2();
    init_modular();
    _0n5 = BigInt(0);
    _1n5 = BigInt(1);
    _2n3 = BigInt(2);
  }
});

// node_modules/@noble/curves/esm/ed25519.js
var ed25519_exports = {};
__export(ed25519_exports, {
  ED25519_TORSION_SUBGROUP: () => ED25519_TORSION_SUBGROUP,
  RistrettoPoint: () => RistrettoPoint,
  ed25519: () => ed25519,
  ed25519_hasher: () => ed25519_hasher,
  ed25519ctx: () => ed25519ctx,
  ed25519ph: () => ed25519ph,
  edwardsToMontgomery: () => edwardsToMontgomery,
  edwardsToMontgomeryPriv: () => edwardsToMontgomeryPriv,
  edwardsToMontgomeryPub: () => edwardsToMontgomeryPub,
  encodeToCurve: () => encodeToCurve,
  hashToCurve: () => hashToCurve,
  hashToRistretto255: () => hashToRistretto255,
  hash_to_ristretto255: () => hash_to_ristretto255,
  ristretto255: () => ristretto255,
  ristretto255_hasher: () => ristretto255_hasher,
  x25519: () => x25519
});
function ed25519_pow_2_252_3(x) {
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P = ed25519_CURVE_p;
  const x2 = x * x % P;
  const b2 = x2 * x % P;
  const b4 = pow2(b2, _2n4, P) * b2 % P;
  const b5 = pow2(b4, _1n6, P) * x % P;
  const b10 = pow2(b5, _5n2, P) * b5 % P;
  const b20 = pow2(b10, _10n, P) * b10 % P;
  const b40 = pow2(b20, _20n, P) * b20 % P;
  const b80 = pow2(b40, _40n, P) * b40 % P;
  const b160 = pow2(b80, _80n, P) * b80 % P;
  const b240 = pow2(b160, _80n, P) * b80 % P;
  const b250 = pow2(b240, _10n, P) * b10 % P;
  const pow_p_5_8 = pow2(b250, _2n4, P) * x % P;
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes) {
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}
function uvRatio(u, v) {
  const P = ed25519_CURVE_p;
  const v3 = mod(v * v * v, P);
  const v7 = mod(v3 * v3 * v, P);
  const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow, P);
  const vx2 = mod(v * x * x, P);
  const root1 = x;
  const root2 = mod(x * ED25519_SQRT_M1, P);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === mod(-u, P);
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if (isNegativeLE(x, P))
    x = mod(-x, P);
  return { isValid: useRoot1 || useRoot2, value: x };
}
function ed25519_domain(data, ctx, phflag) {
  if (ctx.length > 255)
    throw new Error("Context is too big");
  return concatBytes(utf8ToBytes("SigEd25519 no Ed25519 collisions"), new Uint8Array([phflag ? 1 : 0, ctx.length]), ctx, data);
}
function map_to_curve_elligator2_curve25519(u) {
  const ELL2_C4 = (ed25519_CURVE_p - _5n2) / _8n3;
  const ELL2_J = BigInt(486662);
  let tv1 = Fp.sqr(u);
  tv1 = Fp.mul(tv1, _2n4);
  let xd = Fp.add(tv1, Fp.ONE);
  let x1n = Fp.neg(ELL2_J);
  let tv2 = Fp.sqr(xd);
  let gxd = Fp.mul(tv2, xd);
  let gx1 = Fp.mul(tv1, ELL2_J);
  gx1 = Fp.mul(gx1, x1n);
  gx1 = Fp.add(gx1, tv2);
  gx1 = Fp.mul(gx1, x1n);
  let tv3 = Fp.sqr(gxd);
  tv2 = Fp.sqr(tv3);
  tv3 = Fp.mul(tv3, gxd);
  tv3 = Fp.mul(tv3, gx1);
  tv2 = Fp.mul(tv2, tv3);
  let y11 = Fp.pow(tv2, ELL2_C4);
  y11 = Fp.mul(y11, tv3);
  let y12 = Fp.mul(y11, ELL2_C3);
  tv2 = Fp.sqr(y11);
  tv2 = Fp.mul(tv2, gxd);
  let e1 = Fp.eql(tv2, gx1);
  let y1 = Fp.cmov(y12, y11, e1);
  let x2n = Fp.mul(x1n, tv1);
  let y21 = Fp.mul(y11, u);
  y21 = Fp.mul(y21, ELL2_C2);
  let y22 = Fp.mul(y21, ELL2_C3);
  let gx2 = Fp.mul(gx1, tv1);
  tv2 = Fp.sqr(y21);
  tv2 = Fp.mul(tv2, gxd);
  let e2 = Fp.eql(tv2, gx2);
  let y2 = Fp.cmov(y22, y21, e2);
  tv2 = Fp.sqr(y1);
  tv2 = Fp.mul(tv2, gxd);
  let e3 = Fp.eql(tv2, gx1);
  let xn = Fp.cmov(x2n, x1n, e3);
  let y = Fp.cmov(y2, y1, e3);
  let e4 = Fp.isOdd(y);
  y = Fp.cmov(y, Fp.neg(y), e3 !== e4);
  return { xMn: xn, xMd: xd, yMn: y, yMd: _1n6 };
}
function map_to_curve_elligator2_edwards25519(u) {
  const { xMn, xMd, yMn, yMd } = map_to_curve_elligator2_curve25519(u);
  let xn = Fp.mul(xMn, yMd);
  xn = Fp.mul(xn, ELL2_C1_EDWARDS);
  let xd = Fp.mul(xMd, yMn);
  let yn = Fp.sub(xMn, xMd);
  let yd = Fp.add(xMn, xMd);
  let tv1 = Fp.mul(xd, yd);
  let e = Fp.eql(tv1, Fp.ZERO);
  xn = Fp.cmov(xn, Fp.ZERO, e);
  xd = Fp.cmov(xd, Fp.ONE, e);
  yn = Fp.cmov(yn, Fp.ONE, e);
  yd = Fp.cmov(yd, Fp.ONE, e);
  const [xd_inv, yd_inv] = FpInvertBatch(Fp, [xd, yd], true);
  return { x: Fp.mul(xn, xd_inv), y: Fp.mul(yn, yd_inv) };
}
function calcElligatorRistrettoMap(r0) {
  const { d } = ed25519_CURVE;
  const P = ed25519_CURVE_p;
  const mod2 = (n) => Fp.create(n);
  const r = mod2(SQRT_M1 * r0 * r0);
  const Ns = mod2((r + _1n6) * ONE_MINUS_D_SQ);
  let c = BigInt(-1);
  const D = mod2((c - d * r) * mod2(r + d));
  let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D);
  let s_ = mod2(s * r0);
  if (!isNegativeLE(s_, P))
    s_ = mod2(-s_);
  if (!Ns_D_is_sq)
    s = s_;
  if (!Ns_D_is_sq)
    c = r;
  const Nt = mod2(c * (r - _1n6) * D_MINUS_ONE_SQ - D);
  const s2 = s * s;
  const W0 = mod2((s + s) * D);
  const W1 = mod2(Nt * SQRT_AD_MINUS_ONE);
  const W2 = mod2(_1n6 - s2);
  const W3 = mod2(_1n6 + s2);
  return new ed25519.Point(mod2(W0 * W3), mod2(W2 * W1), mod2(W1 * W3), mod2(W0 * W2));
}
function ristretto255_map(bytes) {
  abytes(bytes, 64);
  const r1 = bytes255ToNumberLE(bytes.subarray(0, 32));
  const R1 = calcElligatorRistrettoMap(r1);
  const r2 = bytes255ToNumberLE(bytes.subarray(32, 64));
  const R2 = calcElligatorRistrettoMap(r2);
  return new _RistrettoPoint(R1.add(R2));
}
function edwardsToMontgomeryPub(edwardsPub) {
  return ed25519.utils.toMontgomery(ensureBytes("pub", edwardsPub));
}
function edwardsToMontgomeryPriv(edwardsPriv) {
  return ed25519.utils.toMontgomerySecret(ensureBytes("pub", edwardsPriv));
}
var _0n6, _1n6, _2n4, _3n2, _5n2, _8n3, ed25519_CURVE_p, ed25519_CURVE, ED25519_SQRT_M1, Fp, Fn, ed25519Defaults, ed25519, ed25519ctx, ed25519ph, x25519, ELL2_C1, ELL2_C2, ELL2_C3, ELL2_C1_EDWARDS, ed25519_hasher, SQRT_M1, SQRT_AD_MINUS_ONE, INVSQRT_A_MINUS_D, ONE_MINUS_D_SQ, D_MINUS_ONE_SQ, invertSqrt, MAX_255B, bytes255ToNumberLE, _RistrettoPoint, ristretto255, ristretto255_hasher, ED25519_TORSION_SUBGROUP, edwardsToMontgomery, RistrettoPoint, hashToCurve, encodeToCurve, hashToRistretto255, hash_to_ristretto255;
var init_ed25519 = __esm({
  "node_modules/@noble/curves/esm/ed25519.js"() {
    "use strict";
    init_sha2();
    init_utils();
    init_curve();
    init_edwards();
    init_hash_to_curve();
    init_modular();
    init_montgomery();
    init_utils2();
    _0n6 = /* @__PURE__ */ BigInt(0);
    _1n6 = BigInt(1);
    _2n4 = BigInt(2);
    _3n2 = BigInt(3);
    _5n2 = BigInt(5);
    _8n3 = BigInt(8);
    ed25519_CURVE_p = BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
    ed25519_CURVE = /* @__PURE__ */ (() => ({
      p: ed25519_CURVE_p,
      n: BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
      h: _8n3,
      a: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
      d: BigInt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
      Gx: BigInt("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
      Gy: BigInt("0x6666666666666666666666666666666666666666666666666666666666666658")
    }))();
    ED25519_SQRT_M1 = /* @__PURE__ */ BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
    Fp = /* @__PURE__ */ (() => Field(ed25519_CURVE.p, { isLE: true }))();
    Fn = /* @__PURE__ */ (() => Field(ed25519_CURVE.n, { isLE: true }))();
    ed25519Defaults = /* @__PURE__ */ (() => ({
      ...ed25519_CURVE,
      Fp,
      hash: sha512,
      adjustScalarBytes,
      // dom2
      // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
      // Constant-time, u/√v
      uvRatio
    }))();
    ed25519 = /* @__PURE__ */ (() => twistedEdwards(ed25519Defaults))();
    ed25519ctx = /* @__PURE__ */ (() => twistedEdwards({
      ...ed25519Defaults,
      domain: ed25519_domain
    }))();
    ed25519ph = /* @__PURE__ */ (() => twistedEdwards(Object.assign({}, ed25519Defaults, {
      domain: ed25519_domain,
      prehash: sha512
    })))();
    x25519 = /* @__PURE__ */ (() => {
      const P = Fp.ORDER;
      return montgomery({
        P,
        type: "x25519",
        powPminus2: (x) => {
          const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
          return mod(pow2(pow_p_5_8, _3n2, P) * b2, P);
        },
        adjustScalarBytes
      });
    })();
    ELL2_C1 = /* @__PURE__ */ (() => (ed25519_CURVE_p + _3n2) / _8n3)();
    ELL2_C2 = /* @__PURE__ */ (() => Fp.pow(_2n4, ELL2_C1))();
    ELL2_C3 = /* @__PURE__ */ (() => Fp.sqrt(Fp.neg(Fp.ONE)))();
    ELL2_C1_EDWARDS = /* @__PURE__ */ (() => FpSqrtEven(Fp, Fp.neg(BigInt(486664))))();
    ed25519_hasher = /* @__PURE__ */ (() => createHasher2(ed25519.Point, (scalars) => map_to_curve_elligator2_edwards25519(scalars[0]), {
      DST: "edwards25519_XMD:SHA-512_ELL2_RO_",
      encodeDST: "edwards25519_XMD:SHA-512_ELL2_NU_",
      p: ed25519_CURVE_p,
      m: 1,
      k: 128,
      expand: "xmd",
      hash: sha512
    }))();
    SQRT_M1 = ED25519_SQRT_M1;
    SQRT_AD_MINUS_ONE = /* @__PURE__ */ BigInt("25063068953384623474111414158702152701244531502492656460079210482610430750235");
    INVSQRT_A_MINUS_D = /* @__PURE__ */ BigInt("54469307008909316920995813868745141605393597292927456921205312896311721017578");
    ONE_MINUS_D_SQ = /* @__PURE__ */ BigInt("1159843021668779879193775521855586647937357759715417654439879720876111806838");
    D_MINUS_ONE_SQ = /* @__PURE__ */ BigInt("40440834346308536858101042469323190826248399146238708352240133220865137265952");
    invertSqrt = (number) => uvRatio(_1n6, number);
    MAX_255B = /* @__PURE__ */ BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    bytes255ToNumberLE = (bytes) => ed25519.Point.Fp.create(bytesToNumberLE(bytes) & MAX_255B);
    _RistrettoPoint = class __RistrettoPoint extends PrimeEdwardsPoint {
      constructor(ep) {
        super(ep);
      }
      static fromAffine(ap) {
        return new __RistrettoPoint(ed25519.Point.fromAffine(ap));
      }
      assertSame(other) {
        if (!(other instanceof __RistrettoPoint))
          throw new Error("RistrettoPoint expected");
      }
      init(ep) {
        return new __RistrettoPoint(ep);
      }
      /** @deprecated use `import { ristretto255_hasher } from '@noble/curves/ed25519.js';` */
      static hashToCurve(hex) {
        return ristretto255_map(ensureBytes("ristrettoHash", hex, 64));
      }
      static fromBytes(bytes) {
        abytes(bytes, 32);
        const { a, d } = ed25519_CURVE;
        const P = ed25519_CURVE_p;
        const mod2 = (n) => Fp.create(n);
        const s = bytes255ToNumberLE(bytes);
        if (!equalBytes(Fp.toBytes(s), bytes) || isNegativeLE(s, P))
          throw new Error("invalid ristretto255 encoding 1");
        const s2 = mod2(s * s);
        const u1 = mod2(_1n6 + a * s2);
        const u2 = mod2(_1n6 - a * s2);
        const u1_2 = mod2(u1 * u1);
        const u2_2 = mod2(u2 * u2);
        const v = mod2(a * d * u1_2 - u2_2);
        const { isValid, value: I } = invertSqrt(mod2(v * u2_2));
        const Dx = mod2(I * u2);
        const Dy = mod2(I * Dx * v);
        let x = mod2((s + s) * Dx);
        if (isNegativeLE(x, P))
          x = mod2(-x);
        const y = mod2(u1 * Dy);
        const t = mod2(x * y);
        if (!isValid || isNegativeLE(t, P) || y === _0n6)
          throw new Error("invalid ristretto255 encoding 2");
        return new __RistrettoPoint(new ed25519.Point(x, y, _1n6, t));
      }
      /**
       * Converts ristretto-encoded string to ristretto point.
       * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-decode).
       * @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
       */
      static fromHex(hex) {
        return __RistrettoPoint.fromBytes(ensureBytes("ristrettoHex", hex, 32));
      }
      static msm(points, scalars) {
        return pippenger(__RistrettoPoint, ed25519.Point.Fn, points, scalars);
      }
      /**
       * Encodes ristretto point to Uint8Array.
       * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-encode).
       */
      toBytes() {
        let { X, Y, Z, T } = this.ep;
        const P = ed25519_CURVE_p;
        const mod2 = (n) => Fp.create(n);
        const u1 = mod2(mod2(Z + Y) * mod2(Z - Y));
        const u2 = mod2(X * Y);
        const u2sq = mod2(u2 * u2);
        const { value: invsqrt } = invertSqrt(mod2(u1 * u2sq));
        const D1 = mod2(invsqrt * u1);
        const D2 = mod2(invsqrt * u2);
        const zInv = mod2(D1 * D2 * T);
        let D;
        if (isNegativeLE(T * zInv, P)) {
          let _x = mod2(Y * SQRT_M1);
          let _y = mod2(X * SQRT_M1);
          X = _x;
          Y = _y;
          D = mod2(D1 * INVSQRT_A_MINUS_D);
        } else {
          D = D2;
        }
        if (isNegativeLE(X * zInv, P))
          Y = mod2(-Y);
        let s = mod2((Z - Y) * D);
        if (isNegativeLE(s, P))
          s = mod2(-s);
        return Fp.toBytes(s);
      }
      /**
       * Compares two Ristretto points.
       * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-equals).
       */
      equals(other) {
        this.assertSame(other);
        const { X: X1, Y: Y1 } = this.ep;
        const { X: X2, Y: Y2 } = other.ep;
        const mod2 = (n) => Fp.create(n);
        const one = mod2(X1 * Y2) === mod2(Y1 * X2);
        const two = mod2(Y1 * Y2) === mod2(X1 * X2);
        return one || two;
      }
      is0() {
        return this.equals(__RistrettoPoint.ZERO);
      }
    };
    _RistrettoPoint.BASE = /* @__PURE__ */ (() => new _RistrettoPoint(ed25519.Point.BASE))();
    _RistrettoPoint.ZERO = /* @__PURE__ */ (() => new _RistrettoPoint(ed25519.Point.ZERO))();
    _RistrettoPoint.Fp = /* @__PURE__ */ (() => Fp)();
    _RistrettoPoint.Fn = /* @__PURE__ */ (() => Fn)();
    ristretto255 = { Point: _RistrettoPoint };
    ristretto255_hasher = {
      hashToCurve(msg, options) {
        const DST = options?.DST || "ristretto255_XMD:SHA-512_R255MAP_RO_";
        const xmd = expand_message_xmd(msg, DST, 64, sha512);
        return ristretto255_map(xmd);
      },
      hashToScalar(msg, options = { DST: _DST_scalar }) {
        const xmd = expand_message_xmd(msg, options.DST, 64, sha512);
        return Fn.create(bytesToNumberLE(xmd));
      }
    };
    ED25519_TORSION_SUBGROUP = [
      "0100000000000000000000000000000000000000000000000000000000000000",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "0000000000000000000000000000000000000000000000000000000000000080",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
    ];
    edwardsToMontgomery = edwardsToMontgomeryPub;
    RistrettoPoint = _RistrettoPoint;
    hashToCurve = /* @__PURE__ */ (() => ed25519_hasher.hashToCurve)();
    encodeToCurve = /* @__PURE__ */ (() => ed25519_hasher.encodeToCurve)();
    hashToRistretto255 = /* @__PURE__ */ (() => ristretto255_hasher.hashToCurve)();
    hash_to_ristretto255 = /* @__PURE__ */ (() => ristretto255_hasher.hashToCurve)();
  }
});

// src/receipt-registry.ts
var receipt_registry_exports = {};
__export(receipt_registry_exports, {
  ORG_IDENTITY_FILE: () => ORG_IDENTITY_FILE,
  REGISTRY_FILE: () => REGISTRY_FILE,
  VERIFIER_PAGE_FILE: () => VERIFIER_PAGE_FILE,
  createOrgIdentity: () => createOrgIdentity,
  createReceiptRegistry: () => createReceiptRegistry,
  readReceiptDigestRecords: () => readReceiptDigestRecords,
  renderVerifierPage: () => renderVerifierPage,
  writeOrgIdentity: () => writeOrgIdentity
});
function sha256Hex(input) {
  return (0, import_node_crypto5.createHash)("sha256").update(input).digest("hex");
}
function stableStringify2(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify2).join(",")}]`;
  const obj = value;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${stableStringify2(obj[key])}`).join(",")}}`;
}
function safeReadJson(path) {
  try {
    if (!(0, import_node_fs9.existsSync)(path)) return null;
    return JSON.parse((0, import_node_fs9.readFileSync)(path, "utf-8"));
  } catch {
    return null;
  }
}
function requestIdFromReceipt(receipt) {
  const direct = receipt.request_id || receipt.scope;
  if (typeof direct === "string") return direct;
  const payload = receipt.payload;
  if (payload && typeof payload === "object") {
    const candidate = payload.request_id || payload.scope;
    if (typeof candidate === "string") return candidate;
  }
  return void 0;
}
function keyIdFromReceipt(receipt) {
  const kid = receipt.kid;
  if (typeof kid === "string") return kid;
  const signature = receipt.signature;
  if (signature && typeof signature === "object") {
    const nested = signature.kid;
    if (typeof nested === "string") return nested;
  }
  return void 0;
}
function issuerFromReceipt(receipt) {
  const issuer = receipt.issuer;
  if (typeof issuer === "string") return issuer;
  const signature = receipt.signature;
  if (signature && typeof signature === "object") {
    const nested = signature.issuer;
    if (typeof nested === "string") return nested;
  }
  return void 0;
}
function receiptType(receipt) {
  return String(receipt.type || receipt.artifact_type || receipt.v || "receipt");
}
function readReceiptDigestRecords(dir) {
  const receiptPath = (0, import_node_path6.join)(dir, ".protect-mcp-receipts.jsonl");
  if (!(0, import_node_fs9.existsSync)(receiptPath)) return [];
  const raw = (0, import_node_fs9.readFileSync)(receiptPath, "utf-8");
  return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
    try {
      const receipt = JSON.parse(line);
      const publicKey = (() => {
        const sig = receipt.signature;
        if (sig && typeof sig === "object" && typeof sig.public_key === "string") {
          return String(sig.public_key);
        }
        return void 0;
      })();
      return [{
        type: "scopeblind.receipt_digest.v1",
        receipt_hash: sha256Hex(line),
        receipt_bytes: Buffer.byteLength(line, "utf-8"),
        receipt_type: receiptType(receipt),
        request_id: requestIdFromReceipt(receipt),
        local_issuer: issuerFromReceipt(receipt),
        local_kid: keyIdFromReceipt(receipt),
        local_public_key_hint: publicKey ? `${publicKey.slice(0, 12)}...${publicKey.slice(-8)}` : void 0,
        observed_at: (/* @__PURE__ */ new Date()).toISOString(),
        source_file: receiptPath
      }];
    } catch {
      return [];
    }
  });
}
function createOrgIdentity(opts) {
  const now = (opts.now || /* @__PURE__ */ new Date()).toISOString();
  const existing = safeReadJson((0, import_node_path6.join)(opts.dir, ORG_IDENTITY_FILE));
  const keyData = safeReadJson((0, import_node_path6.join)(opts.dir, "keys", "gateway.json")) || {};
  const orgId = opts.orgId || String(existing?.org_id || `org_${(0, import_node_crypto5.randomUUID)().slice(0, 12)}`);
  const orgName = opts.orgName || String(existing?.org_name || "Local ScopeBlind Org");
  const billingAccountId = opts.billingAccountId || String(existing?.billing_account_id || `billing_${orgId}`);
  const publicKey = typeof keyData.publicKey === "string" ? keyData.publicKey : "";
  const kid = typeof keyData.kid === "string" ? keyData.kid : publicKey ? `kid_${publicKey.slice(0, 12)}` : "local-key";
  const issuer = typeof keyData.issuer === "string" ? keyData.issuer : "protect-mcp";
  return {
    type: "scopeblind.org_identity.v1",
    org_id: orgId,
    org_name: orgName,
    billing_account_id: billingAccountId,
    created_at: typeof existing?.created_at === "string" ? existing.created_at : now,
    public_key_directory: publicKey ? [{
      type: "scopeblind.org_public_key.v1",
      org_id: orgId,
      key_id: kid,
      issuer,
      algorithm: "Ed25519",
      public_key_hex: publicKey,
      created_at: now,
      source: "local_gateway_key"
    }] : [],
    privacy: {
      raw_prompt_upload: false,
      raw_tool_payload_upload: false,
      raw_receipt_upload: false,
      digest_only: true
    }
  };
}
function writeOrgIdentity(dir, identity) {
  const path = (0, import_node_path6.join)(dir, ORG_IDENTITY_FILE);
  (0, import_node_fs9.writeFileSync)(path, JSON.stringify(identity, null, 2) + "\n");
  return path;
}
function localAnchors(records, org, now, verifierBaseUrl) {
  return records.map((record) => ({
    type: "scopeblind.timestamp_anchor.v1",
    anchor_id: `local_${record.receipt_hash.slice(0, 16)}`,
    receipt_hash: record.receipt_hash,
    org_id: org.org_id,
    timestamp_utc: now.toISOString(),
    timestamp_source: "local-preview-not-independent",
    verifier_url: verifierBaseUrl ? `${verifierBaseUrl.replace(/\/$/, "")}/verify?digest=${record.receipt_hash}` : void 0
  }));
}
async function hostedAnchors(opts) {
  const endpoint = opts.endpoint.replace(/\/$/, "") + "/v1/receipt-registry/anchor";
  const payload = {
    type: "scopeblind.receipt_registry_anchor_request.v1",
    org: {
      org_id: opts.org.org_id,
      org_name: opts.org.org_name,
      billing_account_id: opts.org.billing_account_id,
      public_key_directory: opts.org.public_key_directory
    },
    privacy: opts.org.privacy,
    billing: {
      metered_unit: "receipt_digest_anchor",
      count: opts.records.length,
      raw_prompt_upload: false,
      raw_data_upload: false
    },
    receipt_digests: opts.records.map((record) => ({
      receipt_hash: record.receipt_hash,
      receipt_bytes: record.receipt_bytes,
      receipt_type: record.receipt_type,
      request_id: record.request_id,
      local_issuer: record.local_issuer,
      local_kid: record.local_kid
    }))
  };
  const bodyText = stableStringify2(payload);
  for (const forbidden of ["payload_preview", "raw_receipt", "prompt", "tool_output", "privateKey"]) {
    if (bodyText.includes(`${JSON.stringify(forbidden)}:`)) throw new Error(`hosted anchor payload contains forbidden field: ${forbidden}`);
  }
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${opts.token}`,
      "user-agent": "protect-mcp/receipt-registry"
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`hosted anchor failed: HTTP ${res.status} ${text.slice(0, 200)}`);
  }
  const response = await res.json().catch(() => ({}));
  const anchors = Array.isArray(response.anchors) ? response.anchors : [];
  return opts.records.map((record, index) => {
    const anchor = anchors[index] || anchors.find((candidate) => candidate.receipt_hash === record.receipt_hash) || {};
    return {
      type: "scopeblind.timestamp_anchor.v1",
      anchor_id: String(anchor.anchor_id || `hosted_${record.receipt_hash.slice(0, 16)}`),
      receipt_hash: record.receipt_hash,
      org_id: opts.org.org_id,
      timestamp_utc: String(anchor.timestamp_utc || anchor.anchored_at || (/* @__PURE__ */ new Date()).toISOString()),
      timestamp_source: "scopeblind-hosted",
      registry_url: typeof response.registry_url === "string" ? response.registry_url : void 0,
      verifier_url: typeof anchor.verifier_url === "string" ? anchor.verifier_url : opts.verifierBaseUrl ? `${opts.verifierBaseUrl.replace(/\/$/, "")}/verify?digest=${record.receipt_hash}` : void 0,
      signature: anchor.signature
    };
  });
}
async function createReceiptRegistry(opts) {
  const now = opts.now || /* @__PURE__ */ new Date();
  const org = createOrgIdentity(opts);
  const records = readReceiptDigestRecords(opts.dir);
  if (records.length === 0) throw new Error("No signed receipts found. Run protect-mcp with signing enabled first.");
  let anchors;
  let uploaded = false;
  if (opts.hosted || opts.endpoint || opts.token) {
    if (!opts.endpoint) throw new Error("Hosted anchoring requires --endpoint or SCOPEBLIND_REGISTRY_ENDPOINT.");
    if (!opts.token) throw new Error("Hosted anchoring requires --token or SCOPEBLIND_TOKEN.");
    anchors = await hostedAnchors({ endpoint: opts.endpoint, token: opts.token, org, records, verifierBaseUrl: opts.verifierBaseUrl });
    uploaded = true;
  } else {
    anchors = localAnchors(records, org, now, opts.verifierBaseUrl);
  }
  const registry = {
    type: "scopeblind.receipt_registry.v1",
    version: 1,
    generated_at: now.toISOString(),
    org,
    billing: {
      billing_account_id: org.billing_account_id,
      metered_unit: "receipt_digest_anchor",
      charge_basis: "anchored_receipt_digest_count",
      raw_prompt_upload: false,
      raw_data_upload: false
    },
    privacy: {
      statement: uploaded ? "ScopeBlind hosted registry received receipt digests and public identity metadata only." : "Local preview registry only. No independent timestamp exists until hosted anchoring succeeds.",
      uploaded_fields: ["receipt_hash", "receipt_bytes", "receipt_type", "request_id", "local_issuer", "local_kid", "org_id", "billing_account_id", "org_public_keys"],
      excluded_fields: ["raw_prompt", "raw_tool_payload", "payload_preview", "raw_receipt", "tool_output", "private_key"]
    },
    records,
    anchors,
    verifier: {
      local_page: (0, import_node_path6.join)(opts.dir, VERIFIER_PAGE_FILE),
      shareable_url_template: opts.verifierBaseUrl ? `${opts.verifierBaseUrl.replace(/\/$/, "")}/verify?digest={receipt_hash}` : "file://scopeblind-verifier.html#digest={receipt_hash}"
    }
  };
  writeOrgIdentity(opts.dir, org);
  const registryPath = opts.outPath || (0, import_node_path6.join)(opts.dir, REGISTRY_FILE);
  (0, import_node_fs9.mkdirSync)((0, import_node_path6.dirname)(registryPath), { recursive: true });
  (0, import_node_fs9.writeFileSync)(registryPath, JSON.stringify(registry, null, 2) + "\n");
  const verifierPath = (0, import_node_path6.join)(opts.dir, VERIFIER_PAGE_FILE);
  (0, import_node_fs9.writeFileSync)(verifierPath, renderVerifierPage(registry));
  return { registry, registryPath, verifierPath, uploaded };
}
function renderVerifierPage(registry) {
  const embedded = JSON.stringify(registry).replace(/</g, "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScopeBlind Receipt Verifier</title>
<style>
:root{--ink:#11110f;--muted:#6d675d;--line:#ded7c9;--paper:#f7f3ea;--card:#fffdf7;--ok:#2f6f4e;--warn:#8d620f;--bad:#8f241c}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top left,#fffdf7,#f7f3ea 48%,#e8dfce);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{width:min(1040px,calc(100vw - 32px));margin:32px auto}.card{background:rgba(255,253,247,.94);border:1px solid var(--line);border-radius:24px;padding:22px;box-shadow:0 24px 70px rgba(36,30,18,.10);margin-bottom:16px}.kicker{text-transform:uppercase;letter-spacing:.17em;color:var(--muted);font-size:11px;font-weight:900}h1{font:520 clamp(36px,6vw,72px)/.94 ui-serif,Georgia,serif;letter-spacing:-.05em;margin:12px 0}input{width:100%;border:1px solid var(--line);border-radius:14px;padding:13px;background:#fffaf0;font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.pill{display:inline-flex;border-radius:999px;padding:5px 9px;font-size:11px;font-weight:900}.ok{background:#dcebdd;color:var(--ok)}.warn{background:#f4e5bd;color:var(--warn)}.bad{background:#f7d9d3;color:var(--bad)}pre{white-space:pre-wrap;background:#181712;color:#f8f1df;border-radius:16px;padding:14px;overflow:auto}.muted{color:var(--muted)}code{background:#f2eadc;border:1px solid var(--line);border-radius:8px;padding:2px 6px}</style>
</head>
<body><main>
<section class="card"><div class="kicker">ScopeBlind verifier</div><h1>Verify that an independent registry saw this receipt digest.</h1><p class="muted">This page contains receipt digests, anchors, public key metadata, and billing metadata. It does not contain raw prompts, payloads, tool outputs, or raw receipts.</p></section>
<section class="card"><label class="kicker" for="digest">Receipt digest</label><input id="digest" placeholder="Paste receipt SHA-256 digest" oninput="render()"><div id="result" style="margin-top:16px"></div></section>
<section class="card"><div class="kicker">Org public key directory</div><pre id="keys"></pre></section>
</main><script>
const registry=${embedded};
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function render(){const q=document.getElementById('digest').value.trim()||new URLSearchParams(location.search).get('digest')||location.hash.replace(/^#digest=/,'');const rec=registry.records.find(r=>r.receipt_hash===q);const anchor=registry.anchors.find(a=>a.receipt_hash===q);const el=document.getElementById('result');if(!q){el.innerHTML='<p class="muted">Paste a digest to verify registry inclusion.</p>';return;}if(!rec){el.innerHTML='<span class="pill bad">not found</span><p>No matching digest in this registry export.</p>';return;}const independent=anchor&&anchor.timestamp_source==='scopeblind-hosted';el.innerHTML='<span class="pill '+(independent?'ok':'warn')+'">'+(independent?'anchored by ScopeBlind':'local preview only')+'</span><pre>'+esc(JSON.stringify({receipt:rec,anchor:anchor||null,billing:registry.billing,privacy:registry.privacy},null,2))+'</pre>';}
document.getElementById('keys').textContent=JSON.stringify(registry.org.public_key_directory,null,2);render();
</script></body></html>`;
}
var import_node_crypto5, import_node_fs9, import_node_path6, ORG_IDENTITY_FILE, REGISTRY_FILE, VERIFIER_PAGE_FILE;
var init_receipt_registry = __esm({
  "src/receipt-registry.ts"() {
    "use strict";
    import_node_crypto5 = require("crypto");
    import_node_fs9 = require("fs");
    import_node_path6 = require("path");
    ORG_IDENTITY_FILE = ".protect-mcp-org.json";
    REGISTRY_FILE = ".protect-mcp-registry.json";
    VERIFIER_PAGE_FILE = "scopeblind-verifier.html";
  }
});

// src/bundle.ts
var bundle_exports = {};
__export(bundle_exports, {
  collectSignedReceipts: () => collectSignedReceipts,
  createAuditBundle: () => createAuditBundle
});
function createAuditBundle(opts) {
  const receipts = opts.receipts.filter(
    (r) => r && typeof r === "object" && (typeof r.signature === "string" || r.signature !== null && typeof r.signature === "object")
  );
  if (receipts.length === 0) {
    throw new Error("Audit bundle requires at least one signed receipt");
  }
  const keyMap = /* @__PURE__ */ new Map();
  for (const key of opts.signingKeys) {
    if (!keyMap.has(key.kid)) {
      keyMap.set(key.kid, key);
    }
  }
  let timeRange = opts.timeRange || null;
  if (!timeRange) {
    const timestamps = receipts.map((r) => r.issued_at || r.timestamp).filter(Boolean).sort();
    if (timestamps.length > 0) {
      timeRange = {
        from: timestamps[0],
        to: timestamps[timestamps.length - 1]
      };
    }
  }
  return {
    format: "scopeblind:audit-bundle",
    version: 1,
    exported_at: (/* @__PURE__ */ new Date()).toISOString(),
    tenant: opts.tenant,
    time_range: timeRange,
    receipts,
    anchors: opts.anchors || [],
    selective_disclosures: opts.selectiveDisclosures || [],
    privacy: {
      selective_disclosure: {
        supported: true,
        model: "salted_commitments_merkle_v0",
        statement: "Committed receipts may disclose selected fields with salted Merkle openings. Undisclosed committed fields remain hidden while staying bound to the signed commitment root."
      }
    },
    verification: {
      algorithm: "ed25519",
      signing_keys: Array.from(keyMap.values()),
      instructions: `Verify each receipt by: (1) remove the "signature" field, (2) canonicalize the remaining object with JCS (sorted keys at every level), (3) encode as UTF-8 bytes, (4) verify the Ed25519 signature using the signing key matching the receipt's "kid" field. For scopeblind.selective_disclosure.v0 packages, recompute each disclosed leaf and verify it against the receipt committed_fields_root; fields not disclosed remain hidden. CLI: npx @veritasacta/verify bundle.json --bundle`
    }
  };
}
function collectSignedReceipts(logs) {
  return logs.filter((log) => log.v === 2).map((log) => {
    const logRecord = log;
    if (logRecord.receipt) {
      return logRecord.receipt;
    }
    return logRecord;
  }).filter((r) => typeof r.signature === "string");
}
var init_bundle = __esm({
  "src/bundle.ts"() {
    "use strict";
  }
});

// node_modules/@noble/hashes/esm/sha256.js
var sha2562;
var init_sha256 = __esm({
  "node_modules/@noble/hashes/esm/sha256.js"() {
    "use strict";
    init_sha2();
    sha2562 = sha256;
  }
});

// src/receipt-enrichment.ts
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
function sha256Hex2(s) {
  return bytesToHex(sha2562(new TextEncoder().encode(s)));
}
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
  if (typeof path === "string" && path.trim()) return { kind: "path", digest: sha256Hex2(path.replace(/\\/g, "/")) };
  const url = o.url ?? o.uri ?? o.endpoint ?? o.href;
  if (typeof url === "string" && url.trim()) {
    try {
      return { kind: "host", digest: sha256Hex2(new URL(url).host.toLowerCase()) };
    } catch {
    }
  }
  const cmd = o.command ?? o.cmd ?? o.script;
  if (typeof cmd === "string" && cmd.trim()) {
    const first = cmd.trim().split(/\s+/)[0];
    if (first) return { kind: "command", digest: sha256Hex2(first) };
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
  if (typeof to === "string" && to.trim()) p.recipient_digest = sha256Hex2(to.trim().toLowerCase());
  const scheme = findField(input, ["scheme"]);
  if (typeof scheme === "string" && scheme.trim()) p.scheme = scheme.trim().slice(0, 32);
  return p;
}
function buildEnrichment(tool, input) {
  const e = {
    v: ENRICHMENT_VERSION,
    input_digest: sha256Hex2(canonicalJson(input ?? {})),
    capabilities: deriveCapabilities(tool, input)
  };
  const resource = deriveResource(input);
  if (resource) e.resource = resource;
  const payment = derivePayment(tool, input);
  if (payment) e.payment = payment;
  return e;
}
var ENRICHMENT_VERSION, RULES;
var init_receipt_enrichment = __esm({
  "src/receipt-enrichment.ts"() {
    "use strict";
    init_sha256();
    init_utils();
    ENRICHMENT_VERSION = 2;
    RULES = [
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
  }
});

// src/claim.ts
var claim_exports = {};
__export(claim_exports, {
  ANCHOR_SCHEMA: () => ANCHOR_SCHEMA,
  CHECKPOINT_SCHEMA: () => CHECKPOINT_SCHEMA,
  CLAIM_TYPE: () => CLAIM_TYPE,
  DEFAULT_LOG: () => DEFAULT_LOG,
  anchorClaim: () => anchorClaim,
  anchorRecordCheckpoint: () => anchorRecordCheckpoint,
  buildAnchorEnvelope: () => buildAnchorEnvelope,
  buildClaim: () => buildClaim,
  buildRecordCheckpoint: () => buildRecordCheckpoint,
  checkClaimAnchor: () => checkClaimAnchor,
  claimDigest: () => claimDigest,
  evaluate: () => evaluate,
  leafHash: () => leafHash,
  lookupPinnedIdentity: () => lookupPinnedIdentity,
  merkleRoot: () => merkleRoot,
  receiptToLeaf: () => receiptToLeaf,
  verifyAnchorEnvelope: () => verifyAnchorEnvelope,
  verifyClaim: () => verifyClaim
});
function sha256Hex3(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return bytesToHex(sha2562(bytes));
}
function receiptToLeaf(e) {
  const p = e && typeof e.payload === "object" && e.payload || e;
  const dec = String(p.decision || e.decision || "").toLowerCase();
  const v = /den|block|reject|refus/.test(dec) ? "blocked" : /ask|approv|hold|escal|review|pending/.test(dec) ? "held" : "allowed";
  const enr = p.enrichment;
  const c = enr && Array.isArray(enr.capabilities) ? enr.capabilities.map(String).sort() : [];
  const tsRaw = e.issued_at || p.timestamp || p.issued_at;
  const ms = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "string" ? Date.parse(tsRaw) : NaN;
  const t = isFinite(ms) ? new Date(ms).toISOString() : "";
  const d = sha256Hex3(canonicalJson(e));
  const leaf = { d, v, c, t };
  const pay = enr && enr.payment;
  if (pay && typeof pay === "object") {
    const amt = pay.amount;
    leaf.p = typeof amt === "number" && Number.isFinite(amt) ? amt : null;
  }
  return leaf;
}
function leafHash(leaf) {
  return sha256Hex3(canonicalJson(leaf));
}
function merkleRoot(leafHashes) {
  if (leafHashes.length === 0) return sha256Hex3("scopeblind.claim.empty");
  let level = [...leafHashes].sort();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(sha256Hex3(a + b));
    }
    level = next;
  }
  return level[0];
}
function evaluate(pred, leaves) {
  if (pred.kind === "no_capability") {
    const matched2 = leaves.filter((l) => l.c.indexOf(pred.capability) >= 0).length;
    return { statement: `No action used capability "${pred.capability}"`, holds: matched2 === 0, matched: matched2 };
  }
  if (pred.kind === "only_capabilities") {
    const allow = new Set(pred.capabilities);
    const matched2 = leaves.filter((l) => !l.c.every((c) => allow.has(c))).length;
    return { statement: `All actions were confined to capabilities {${pred.capabilities.join(", ")}}`, holds: matched2 === 0, matched: matched2 };
  }
  if (pred.kind === "no_verdict") {
    const matched2 = leaves.filter((l) => l.v === pred.verdict).length;
    return { statement: `No action was ${pred.verdict}`, holds: matched2 === 0, matched: matched2 };
  }
  if (pred.kind === "payment_under") {
    const matched2 = leaves.filter((l) => "p" in l && (l.p === null || l.p >= pred.cap)).length;
    return { statement: `Every payment stayed under ${pred.cap} (unknown amounts count as over)`, holds: matched2 === 0, matched: matched2 };
  }
  const matched = leaves.filter((l) => l.v === pred.verdict).length;
  return { statement: `${matched} action${matched === 1 ? " was" : "s were"} ${pred.verdict}`, holds: true, matched };
}
function messageHash(unsigned) {
  return sha2562(new TextEncoder().encode(canonicalJson(unsigned)));
}
function buildClaim(receipts, predicate, key, issuedAt) {
  const leaves = receipts.map(receiptToLeaf);
  const root = merkleRoot(leaves.map(leafHash));
  const claim = evaluate(predicate, leaves);
  const times = leaves.map((l) => l.t).filter(Boolean).sort();
  const unsigned = {
    type: CLAIM_TYPE,
    predicate,
    claim,
    scope: { total: leaves.length, from: times[0] || "", to: times[times.length - 1] || "" },
    record: { root },
    leaves,
    issuer: { kid: key.kid, publicKey: key.publicKey, issuer: key.issuer || "protect-mcp" },
    issued_at: issuedAt
  };
  const signature = bytesToHex(ed25519.sign(messageHash(unsigned), hexToBytes(key.privateKey)));
  return { ...unsigned, signature };
}
function verifyClaim(pack, overridePublicKey) {
  const reasons = [];
  const leaves = Array.isArray(pack.leaves) ? pack.leaves : [];
  const recomputedRoot = merkleRoot(leaves.map(leafHash));
  const root_ok = !!pack.record && recomputedRoot === pack.record.root;
  if (!root_ok) reasons.push("record commitment (Merkle root) does not match the disclosed decisions");
  const recomputed = evaluate(pack.predicate, leaves);
  const predicate_ok = !!pack.claim && recomputed.holds === pack.claim.holds && recomputed.matched === pack.claim.matched;
  if (!predicate_ok) reasons.push("claim result does not match the predicate recomputed over the disclosed decisions");
  let authentic = false;
  try {
    const { signature, ...unsigned } = pack;
    const pub = overridePublicKey || pack.issuer && pack.issuer.publicKey;
    if (pub && signature) {
      authentic = ed25519.verify(hexToBytes(signature), messageHash(unsigned), hexToBytes(pub));
    }
  } catch {
  }
  if (!authentic) reasons.push("signature does not verify against the issuer public key");
  return {
    valid: authentic && root_ok && predicate_ok,
    authentic,
    root_ok,
    predicate_ok,
    holds: !!(pack.claim && pack.claim.holds),
    matched: pack.claim ? pack.claim.matched : recomputed.matched,
    total: leaves.length,
    statement: pack.claim ? pack.claim.statement : recomputed.statement,
    reasons
  };
}
function anchorDeepSort(o) {
  if (o === null || typeof o !== "object") return o;
  if (Array.isArray(o)) return o.map(anchorDeepSort);
  const src = o;
  const out = {};
  for (const k of Object.keys(src).sort()) out[k] = anchorDeepSort(src[k]);
  return out;
}
function toBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function claimDigest(pack) {
  return sha256Hex3(canonicalJson(pack));
}
function buildAnchorEnvelope(pack, key, issuedAt) {
  const signed = {
    type: "evidence_pack",
    schema: ANCHOR_SCHEMA,
    anchors: "protect-mcp-claim",
    claim_digest: claimDigest(pack),
    record_root: pack.record.root,
    statement: pack.claim.statement,
    holds: pack.claim.holds,
    matched: pack.claim.matched,
    total: pack.scope.total,
    issued_at: issuedAt,
    verification_key: key.publicKey,
    disclosure: "internal"
  };
  const hash = sha2562(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
  const digest = bytesToHex(hash);
  const signature = bytesToHex(ed25519.sign(hash, hexToBytes(key.privateKey)));
  return { ...signed, signature, digest };
}
function verifyAnchorEnvelope(pack, envelope) {
  const reasons = [];
  if (!envelope || envelope.type !== "evidence_pack" || envelope.anchors !== "protect-mcp-claim") {
    return { ok: false, reasons: ["sidecar does not contain a protect-mcp claim anchor envelope"] };
  }
  const expected = claimDigest(pack);
  if (envelope.claim_digest !== expected) {
    reasons.push("anchored envelope binds a DIFFERENT claim (claim_digest mismatch)");
  }
  if (envelope.record_root !== pack.record.root) {
    reasons.push("anchored envelope commits to a different record root");
  }
  if (pack.issuer && envelope.verification_key !== pack.issuer.publicKey) {
    reasons.push("anchor was signed by a different key than the claim issuer");
  }
  try {
    const { signature, digest, ...signed } = envelope;
    const hash = sha2562(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
    if (bytesToHex(hash) !== String(digest).toLowerCase()) {
      reasons.push("envelope digest does not match its contents");
    } else if (!ed25519.verify(hexToBytes(String(signature)), hash, hexToBytes(envelope.verification_key))) {
      reasons.push("envelope signature does not verify");
    }
  } catch {
    reasons.push("envelope signature does not verify");
  }
  return { ok: reasons.length === 0, reasons };
}
async function checkClaimAnchor(pack, sidecar, opts) {
  const reasons = [];
  const envelope = sidecar && sidecar.envelope;
  if (!envelope) {
    return { local_ok: false, log_ok: null, reasons: ["sidecar has no anchor envelope"] };
  }
  const local = verifyAnchorEnvelope(pack, envelope);
  reasons.push(...local.reasons);
  const base = (sidecar.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out = {
    local_ok: local.ok,
    log_ok: null,
    seq: sidecar.seq,
    anchored_at: sidecar.anchored_at,
    entry_url: sidecar.entry_url || (typeof sidecar.seq === "number" ? `${base}/fn/log/${sidecar.seq}` : void 0),
    reasons
  };
  if (opts?.offline) return out;
  const doFetch = opts?.fetchImpl || globalThis.fetch;
  if (!doFetch) return out;
  try {
    const resp = await doFetch(`${base}/fn/log/digest/sha256:${envelope.digest}`, { headers: { accept: "application/json" } });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data) {
      out.log_ok = null;
      return out;
    }
    if (data.anchored !== true) {
      out.log_ok = false;
      out.reasons.push("the public log does not contain this anchor digest");
      return out;
    }
    if (typeof sidecar.seq === "number" && typeof data.seq === "number" && data.seq !== sidecar.seq) {
      out.log_ok = false;
      out.reasons.push(`log holds the digest at entry #${data.seq}, sidecar says #${sidecar.seq}`);
      return out;
    }
    out.log_ok = true;
    if (typeof data.seq === "number") out.seq = data.seq;
    return out;
  } catch {
    out.log_ok = null;
    return out;
  }
}
async function submitEnvelope(envelope, base, fetchImpl) {
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) return { ok: false, error: "fetch_unavailable" };
  const encoded = toBase64(new TextEncoder().encode(JSON.stringify(envelope)));
  try {
    const resp = await doFetch(`${base}/fn/log/anchor-pack`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ encoded })
    });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data || !data.ok || typeof data.seq !== "number") {
      return { ok: false, error: data && data.error || `http_${resp.status}` };
    }
    return { ok: true, seq: data.seq, anchored_at: data.anchored_at, already_anchored: !!data.already_anchored };
  } catch {
    return { ok: false, error: "network_error" };
  }
}
async function anchorClaim(pack, key, opts) {
  const envelope = buildAnchorEnvelope(pack, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out = await submitEnvelope(envelope, base, opts.fetchImpl);
  if (!out.ok) return { ok: false, claim_digest: envelope.claim_digest, error: out.error, envelope };
  return {
    ok: true,
    claim_digest: envelope.claim_digest,
    seq: out.seq,
    entry_url: `${base}/fn/log/${out.seq}`,
    anchored_at: out.anchored_at,
    already_anchored: out.already_anchored,
    envelope
  };
}
function buildRecordCheckpoint(receipts, key, issuedAt) {
  const leaves = receipts.map(receiptToLeaf);
  const times = leaves.map((l) => l.t).filter(Boolean).sort();
  const signed = {
    type: "evidence_pack",
    schema: CHECKPOINT_SCHEMA,
    anchors: "protect-mcp-record",
    record_root: merkleRoot(leaves.map(leafHash)),
    total: leaves.length,
    from: times[0] || "",
    to: times[times.length - 1] || "",
    issued_at: issuedAt,
    verification_key: key.publicKey,
    disclosure: "internal"
  };
  const hash = sha2562(new TextEncoder().encode(JSON.stringify(anchorDeepSort(signed))));
  const digest = bytesToHex(hash);
  const signature = bytesToHex(ed25519.sign(hash, hexToBytes(key.privateKey)));
  return { ...signed, signature, digest };
}
async function anchorRecordCheckpoint(receipts, key, opts) {
  const checkpoint = buildRecordCheckpoint(receipts, key, opts.issuedAt);
  const base = (opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const out = await submitEnvelope(checkpoint, base, opts.fetchImpl);
  if (!out.ok) return { ok: false, record_root: checkpoint.record_root, total: checkpoint.total, checkpoint, error: out.error };
  return {
    ok: true,
    record_root: checkpoint.record_root,
    total: checkpoint.total,
    seq: out.seq,
    entry_url: `${base}/fn/log/${out.seq}`,
    anchored_at: out.anchored_at,
    already_anchored: out.already_anchored,
    checkpoint
  };
}
async function lookupPinnedIdentity(publicKey, opts) {
  const base = (opts && opts.log || DEFAULT_LOG).replace(/\/+$/, "");
  const doFetch = opts && opts.fetchImpl || globalThis.fetch;
  if (!doFetch || !/^[0-9a-f]{64}$/i.test(publicKey)) return null;
  try {
    const resp = await doFetch(`${base}/fn/log/keys/lookup/${publicKey.toLowerCase()}`, { headers: { accept: "application/json" } });
    const data = await resp.json().catch(() => null);
    if (!data || data.ok !== true) return null;
    if (!data.found) return { found: false };
    return {
      found: true,
      name: data.name,
      slug: data.slug,
      kid: data.kid,
      enrolled_at: data.enrolled_at,
      revoked: !!(data.revoked || data.revoked_at)
    };
  } catch {
    return null;
  }
}
var CLAIM_TYPE, ANCHOR_SCHEMA, DEFAULT_LOG, CHECKPOINT_SCHEMA;
var init_claim = __esm({
  "src/claim.ts"() {
    "use strict";
    init_sha256();
    init_utils();
    init_ed25519();
    init_receipt_enrichment();
    CLAIM_TYPE = "scopeblind.claim.v1";
    ANCHOR_SCHEMA = "scopeblind.protect-mcp.anchor.v1";
    DEFAULT_LOG = "https://scopeblind.com";
    CHECKPOINT_SCHEMA = "scopeblind.protect-mcp.record-checkpoint.v1";
  }
});

// src/commitments/merkle.ts
function hashLeaf(leafBytes) {
  const buf = new Uint8Array(leafBytes.length + 1);
  buf[0] = DOMAIN_LEAF;
  buf.set(leafBytes, 1);
  return sha2562(buf);
}
function hashInternal(left, right) {
  const buf = new Uint8Array(left.length + right.length + 1);
  buf[0] = DOMAIN_INTERNAL;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha2562(buf);
}
function merkleRoot2(leafHashes) {
  if (leafHashes.length === 0) {
    throw new Error("merkleRoot: cannot compute root of empty leaf set");
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }
  const n = leafHashes.length;
  const k = largestPowerOfTwoLessThan(n);
  const left = merkleRoot2(leafHashes.slice(0, k));
  const right = merkleRoot2(leafHashes.slice(k));
  return hashInternal(left, right);
}
function generateProof(leafHashes, index) {
  if (leafHashes.length === 0) {
    throw new Error("generateProof: empty tree");
  }
  if (index < 0 || index >= leafHashes.length) {
    throw new Error(
      `generateProof: index ${index} out of range [0, ${leafHashes.length})`
    );
  }
  const siblings = [];
  collectPath(leafHashes, index, siblings);
  return {
    index,
    treeSize: leafHashes.length,
    siblings: siblings.map((s) => bytesToHex(s))
  };
}
function collectPath(leaves, index, out) {
  if (leaves.length === 1) return;
  const n = leaves.length;
  const k = largestPowerOfTwoLessThan(n);
  if (index < k) {
    collectPath(leaves.slice(0, k), index, out);
    out.push(merkleRoot2(leaves.slice(k)));
  } else {
    collectPath(leaves.slice(k), index - k, out);
    out.push(merkleRoot2(leaves.slice(0, k)));
  }
}
function verifyProof(expectedRootHex, leafHash2, proof) {
  if (proof.index < 0 || proof.index >= proof.treeSize) return false;
  if (proof.treeSize === 1) {
    return proof.siblings.length === 0 && bytesToHex(leafHash2).toLowerCase() === expectedRootHex.toLowerCase();
  }
  let result;
  try {
    result = reconstructRoot(
      leafHash2,
      proof.index,
      proof.treeSize,
      proof.siblings
    );
  } catch {
    return false;
  }
  return bytesToHex(result).toLowerCase() === expectedRootHex.toLowerCase();
}
function reconstructRoot(leafHash2, index, treeSize, siblings) {
  if (treeSize === 1) {
    if (siblings.length !== 0) {
      throw new Error("reconstructRoot: extra siblings at single-leaf level");
    }
    return leafHash2;
  }
  if (siblings.length === 0) {
    throw new Error("reconstructRoot: ran out of siblings before single-leaf");
  }
  const k = largestPowerOfTwoLessThan(treeSize);
  const outermostSibling = hexToBytes(siblings[siblings.length - 1]);
  const innerSiblings = siblings.slice(0, -1);
  if (index < k) {
    const leftHash = reconstructRoot(leafHash2, index, k, innerSiblings);
    return hashInternal(leftHash, outermostSibling);
  } else {
    const rightHash = reconstructRoot(
      leafHash2,
      index - k,
      treeSize - k,
      innerSiblings
    );
    return hashInternal(outermostSibling, rightHash);
  }
}
function largestPowerOfTwoLessThan(n) {
  if (n < 2) {
    throw new Error(`largestPowerOfTwoLessThan: n must be >= 2 (got ${n})`);
  }
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
var DOMAIN_LEAF, DOMAIN_INTERNAL;
var init_merkle = __esm({
  "src/commitments/merkle.ts"() {
    "use strict";
    init_sha256();
    init_utils();
    DOMAIN_LEAF = 0;
    DOMAIN_INTERNAL = 1;
  }
});

// src/commitments/primitives.ts
function jcs(value) {
  if (value === null || value === void 0) return "null";
  if (typeof value === "boolean" || typeof value === "number")
    return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(jcs).join(",") + "]";
  const obj = value;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(obj[k])).join(",") + "}";
}
var init_primitives = __esm({
  "src/commitments/primitives.ts"() {
    "use strict";
  }
});

// src/commitments/leaf.ts
function base64urlNoPad(bytes) {
  const std = typeof Buffer !== "undefined" ? Buffer.from(bytes).toString("base64") : btoa(String.fromCharCode(...bytes));
  return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(s) {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - std.length % 4) % 4);
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function encodeLeaf(field) {
  const obj = {
    name: field.name,
    salt: base64urlNoPad(field.salt),
    value: field.value
  };
  const canonical = jcs(obj);
  return new TextEncoder().encode(canonical);
}
function sortFields(fields) {
  const encoder = new TextEncoder();
  const decorated = fields.map((f) => ({
    field: f,
    nameBytes: encoder.encode(f.name)
  }));
  decorated.sort((a, b) => compareBytes(a.nameBytes, b.nameBytes));
  return decorated.map((d) => d.field);
}
function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
function leavesFromFields(fields) {
  const sorted = sortFields(fields);
  const leafBytes = sorted.map(encodeLeaf);
  return { sorted, leafBytes };
}
var init_leaf = __esm({
  "src/commitments/leaf.ts"() {
    "use strict";
    init_primitives();
  }
});

// src/signing-committed.ts
var signing_committed_exports = {};
__export(signing_committed_exports, {
  createSelectiveDisclosurePackage: () => createSelectiveDisclosurePackage,
  discloseField: () => discloseField,
  signCommittedDecision: () => signCommittedDecision,
  verifySelectiveDisclosurePackage: () => verifySelectiveDisclosurePackage
});
function freshSalt() {
  return randomBytes2(32);
}
function signCommittedDecision(entry, committedFieldNames, signingKey, publicKey, kid, issuer) {
  const allFields = {
    tool: entry.tool,
    decision: entry.decision,
    reason_code: entry.reason_code,
    policy_digest: entry.policy_digest,
    scope: entry.request_id,
    mode: entry.mode,
    request_id: entry.request_id
  };
  if (entry.tier) allFields.tier = entry.tier;
  if (entry.credential_ref) allFields.credential_ref = entry.credential_ref;
  if (entry.rate_limit_remaining !== void 0) {
    allFields.rate_limit_remaining = entry.rate_limit_remaining;
  }
  if (entry.policy_engine) allFields.policy_engine = entry.policy_engine;
  if (entry.hook_event) allFields.hook_event = entry.hook_event;
  if (entry.sandbox_state) allFields.sandbox_state = entry.sandbox_state;
  if (entry.timing) allFields.timing = entry.timing;
  if (entry.swarm) allFields.swarm = entry.swarm;
  if (entry.payload_digest) allFields.payload_digest = entry.payload_digest;
  if (entry.deny_iteration) allFields.deny_iteration = entry.deny_iteration;
  const committedFields = [];
  const cleartextFields = {};
  const openings = {};
  for (const [name, value] of Object.entries(allFields)) {
    if (committedFieldNames.includes(name)) {
      const salt = freshSalt();
      committedFields.push({ name, salt, value });
    } else {
      cleartextFields[name] = value;
    }
  }
  let committedFieldsRoot = null;
  if (committedFields.length > 0) {
    const { sorted, leafBytes } = leavesFromFields(committedFields);
    const leafHashes = leafBytes.map(hashLeaf);
    const root = merkleRoot2(leafHashes);
    committedFieldsRoot = bytesToHex(root);
    sorted.forEach((f, i) => {
      openings[f.name] = { name: f.name, value: f.value, salt: f.salt, index: i };
    });
  }
  const payload = {
    type: "scopeblind.receipt.committed.v1",
    spec: "draft-farley-acta-signed-receipts-01",
    issuer_certification: "self-signed",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    ...cleartextFields
  };
  if (committedFieldsRoot !== null) {
    payload.committed_fields_root = committedFieldsRoot;
    payload.committed_field_names = committedFields.map((f) => f.name);
  }
  const canonical = jcs(payload);
  const messageHash2 = sha2562(new TextEncoder().encode(canonical));
  const signatureBytes = ed25519.sign(messageHash2, hexToBytes(signingKey));
  const signedReceipt = {
    ...payload,
    signature: {
      alg: "EdDSA",
      kid,
      issuer,
      sig: base64urlNoPad(signatureBytes),
      public_key: publicKey
      // hex
    }
  };
  const signedJson = JSON.stringify(signedReceipt);
  const receiptHash = bytesToHex(sha2562(new TextEncoder().encode(jcs(signedReceipt))));
  return {
    signed: signedJson,
    artifact_type: "decision_receipt_committed_v1",
    openings,
    receipt_hash: receiptHash
  };
}
function discloseField(receiptHash, fieldName, openings) {
  const o = openings[fieldName];
  if (!o) {
    throw new Error(`disclose: no opening recorded for field "${fieldName}"`);
  }
  const fields = Object.values(openings).map((op) => ({
    name: op.name,
    salt: op.salt,
    value: op.value
  }));
  const { leafBytes } = leavesFromFields(fields);
  const leafHashes = leafBytes.map(hashLeaf);
  const proof = generateProof(leafHashes, o.index);
  return {
    parent_receipt_hash: receiptHash,
    name: fieldName,
    value: o.value,
    salt: base64urlNoPad(o.salt),
    proof
  };
}
function createSelectiveDisclosurePackage(receipt, fieldNames, openings) {
  const receiptHash = receiptHashHex(receipt);
  const committedFieldsRoot = typeof receipt.committed_fields_root === "string" ? receipt.committed_fields_root : "";
  if (!committedFieldsRoot) {
    throw new Error("selective disclosure requires a committed receipt with committed_fields_root");
  }
  const committedFieldNames = committedFieldNamesFromReceipt(receipt, openings);
  const uniqueFields = Array.from(new Set(fieldNames));
  for (const fieldName of uniqueFields) {
    if (!committedFieldNames.includes(fieldName)) {
      throw new Error(`selective disclosure: field "${fieldName}" is not committed by this receipt`);
    }
  }
  const disclosures = uniqueFields.map((fieldName) => discloseField(receiptHash, fieldName, openings));
  const hiddenFields = committedFieldNames.filter((fieldName) => !uniqueFields.includes(fieldName));
  return {
    type: "scopeblind.selective_disclosure.v0",
    version: 0,
    parent_receipt_hash: receiptHash,
    committed_fields_root: committedFieldsRoot,
    disclosed_fields: uniqueFields,
    hidden_fields: hiddenFields,
    disclosures,
    verifier_explanation: {
      summary: "This package opens selected committed receipt fields and leaves the rest hidden.",
      disclosed: uniqueFields.length ? `Disclosed fields: ${uniqueFields.join(", ")}.` : "No fields were disclosed.",
      hidden: hiddenFields.length ? `Hidden committed fields: ${hiddenFields.join(", ")}. Their salted commitments remain bound to the signed receipt root.` : "No committed fields remain hidden.",
      limitation: "Selective Disclosure v0 uses salted SHA-256 commitments and Merkle proofs. It is not a full zero-knowledge proof."
    }
  };
}
function verifySelectiveDisclosurePackage(receipt, disclosure) {
  const errors = [];
  if (disclosure.type !== "scopeblind.selective_disclosure.v0") {
    errors.push("disclosure.type is not scopeblind.selective_disclosure.v0");
  }
  const actualReceiptHash = receiptHashHex(receipt);
  const receiptHashValid = disclosure.parent_receipt_hash === actualReceiptHash;
  if (!receiptHashValid) {
    errors.push("parent_receipt_hash does not match the supplied receipt");
  }
  const root = typeof receipt.committed_fields_root === "string" ? receipt.committed_fields_root : "";
  const commitmentRootValid = Boolean(root) && disclosure.committed_fields_root === root;
  if (!commitmentRootValid) {
    errors.push("committed_fields_root does not match the supplied receipt");
  }
  const signatureValid = verifyCommittedReceiptSignature(receipt);
  if (signatureValid === false) {
    errors.push("receipt signature failed verification");
  }
  const committedFieldNames = committedFieldNamesFromReceipt(receipt, {});
  const disclosed = /* @__PURE__ */ new Set();
  for (const item of disclosure.disclosures || []) {
    if (item.parent_receipt_hash !== disclosure.parent_receipt_hash) {
      errors.push(`disclosure for "${item.name}" targets a different receipt hash`);
      continue;
    }
    if (!committedFieldNames.includes(item.name)) {
      errors.push(`field "${item.name}" is not listed in committed_field_names`);
      continue;
    }
    const leafBytes = encodeLeaf({
      name: item.name,
      salt: base64urlDecode(item.salt),
      value: item.value
    });
    const ok = root ? verifyProof(root, hashLeaf(leafBytes), item.proof) : false;
    if (!ok) {
      errors.push(`field "${item.name}" failed Merkle inclusion verification`);
    } else {
      disclosed.add(item.name);
    }
  }
  const disclosedFields = Array.from(disclosed);
  const hiddenFields = committedFieldNames.filter((fieldName) => !disclosed.has(fieldName));
  const valid = errors.length === 0 && receiptHashValid && commitmentRootValid && signatureValid !== false;
  const explanation = [
    valid ? "Selective disclosure verified: the disclosed fields open to the signed receipt commitment root." : "Selective disclosure failed verification.",
    signatureValid === true ? "Receipt signature verified against the embedded Ed25519 public key." : signatureValid === null ? "Receipt signature was not checked because the committed receipt did not carry an embedded Ed25519 signature object." : "Receipt signature did not verify.",
    disclosedFields.length ? `Disclosed fields: ${disclosedFields.join(", ")}.` : "No fields were disclosed.",
    hiddenFields.length ? `Hidden fields: ${hiddenFields.join(", ")}. These remain private but bound to the same commitment root.` : "No committed fields remain hidden.",
    "Limitation: this is salted commitment disclosure, not full zero-knowledge."
  ];
  return {
    valid,
    receipt_hash_valid: receiptHashValid,
    signature_valid: signatureValid,
    commitment_root_valid: commitmentRootValid,
    disclosed_fields: disclosedFields,
    hidden_fields: hiddenFields,
    errors,
    explanation
  };
}
function committedFieldNamesFromReceipt(receipt, openings) {
  const fromReceipt = Array.isArray(receipt.committed_field_names) ? receipt.committed_field_names.filter((fieldName) => typeof fieldName === "string") : [];
  const names = fromReceipt.length ? fromReceipt : Object.keys(openings);
  return Array.from(new Set(names)).sort();
}
function receiptHashHex(receipt) {
  return bytesToHex(sha2562(new TextEncoder().encode(jcs(receipt))));
}
function verifyCommittedReceiptSignature(receipt) {
  const signature = receipt.signature;
  if (!signature || typeof signature !== "object") return null;
  const sig = signature;
  if (sig.alg !== "EdDSA" || typeof sig.sig !== "string" || typeof sig.public_key !== "string") {
    return null;
  }
  const { signature: _signature, ...payloadWithoutSig } = receipt;
  const messageHash2 = sha2562(new TextEncoder().encode(jcs(payloadWithoutSig)));
  try {
    return ed25519.verify(base64urlDecode(sig.sig), messageHash2, hexToBytes(sig.public_key));
  } catch {
    return false;
  }
}
var init_signing_committed = __esm({
  "src/signing-committed.ts"() {
    "use strict";
    init_ed25519();
    init_sha256();
    init_utils();
    init_merkle();
    init_leaf();
    init_primitives();
  }
});

// src/hook-patterns.ts
var hook_patterns_exports = {};
__export(hook_patterns_exports, {
  BUILTIN_PATTERNS: () => BUILTIN_PATTERNS,
  generateHookSettings: () => generateHookSettings,
  generateSampleCedarPolicy: () => generateSampleCedarPolicy,
  generateVerifyReceiptSkill: () => generateVerifyReceiptSkill
});
function generateHookSettings(hookUrl, patterns = BUILTIN_PATTERNS) {
  const preToolUseEntries = [];
  preToolUseEntries.push({
    matcher: "",
    hooks: [{
      type: "http",
      url: hookUrl
    }]
  });
  const postToolUseEntries = [{
    matcher: "",
    hooks: [{
      type: "http",
      url: hookUrl
    }]
  }];
  const lifecycleEvents = {};
  for (const event of [
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "SessionStart",
    "SessionEnd",
    "TeammateIdle",
    "ConfigChange",
    "Stop"
  ]) {
    lifecycleEvents[event] = [{
      matcher: "",
      hooks: [{
        type: "http",
        url: hookUrl
      }]
    }];
  }
  return {
    hooks: {
      PreToolUse: preToolUseEntries,
      PostToolUse: postToolUseEntries,
      ...lifecycleEvents
    }
  };
}
function generateSampleCedarPolicy() {
  const lines = [
    "// Generated by protect-mcp init-hooks",
    "// Customize these policies to match your security requirements.",
    "// Cedar deny decisions are AUTHORITATIVE \u2014 they cannot be overridden.",
    "",
    "// Allow all read-only tools by default",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Read"',
    ");",
    "",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Glob"',
    ");",
    "",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Grep"',
    ");",
    "",
    "// Allow write/edit tools (remove these to require explicit approval)",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Write"',
    ");",
    "",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Edit"',
    ");",
    "",
    "// Allow Bash with caution (Cedar evaluates before hook patterns)",
    "permit(",
    "  principal,",
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Bash"',
    ");",
    "",
    "// Block dangerous tools entirely",
    "// Uncomment any of these to block specific tools:",
    "// forbid(",
    "//   principal,",
    '//   action == Action::"MCP::Tool::call",',
    '//   resource == Tool::"delete_file"',
    "// );",
    ""
  ];
  return lines.join("\n");
}
function generateVerifyReceiptSkill() {
  return `---
name: verify-receipt
description: Verify ScopeBlind receipt chain integrity and display audit trail
allowed-tools: [Read, Bash(npx:@veritasacta/verify*), Bash(cat:*protect-mcp*), Bash(jq:*)]
when_to_use: "Use when the user asks to verify receipts, check audit trails, validate decision logs, or see what tools were called"
context: inline
---

# ScopeBlind Receipt Verification

Every AI agent tool call gets a cryptographic receipt. Verify offline. No vendor trust required.

When the user asks to verify receipts or check the audit trail:

1. **Check for receipt files:**
   - Look for \`.protect-mcp-receipts.jsonl\` in the project root
   - Look for \`.protect-mcp-log.jsonl\` for decision history

2. **Display recent activity:**
   \`\`\`bash
   tail -n 20 .protect-mcp-log.jsonl | jq -r '[.tool, .decision, .reason_code, .hook_event // "stdio"] | @tsv'
   \`\`\`

3. **Verify receipt signatures:**
   \`\`\`bash
   npx @veritasacta/verify .protect-mcp-receipts.jsonl --format jsonl
   \`\`\`

4. **Show swarm topology (if multi-agent):**
   \`\`\`bash
   cat .protect-mcp-log.jsonl | jq -r 'select(.swarm != null) | [.swarm.agent_id, .swarm.agent_type, .tool, .decision] | @tsv'
   \`\`\`

5. **Show policy suggestions:**
   \`\`\`bash
   curl -s http://127.0.0.1:9377/suggestions | jq '.suggestions[]'
   \`\`\`

6. **Show config tamper alerts:**
   \`\`\`bash
   curl -s http://127.0.0.1:9377/alerts | jq '.alerts[]'
   \`\`\`

7. **Export audit bundle:**
   \`\`\`bash
   npx protect-mcp bundle --output audit-bundle.json
   \`\`\`

Present results in a clear, formatted table showing: timestamp, tool, decision, reason, and receipt ID.
If swarm data exists, show the agent topology (coordinator \u2192 workers).
`;
}
var BUILTIN_PATTERNS;
var init_hook_patterns = __esm({
  "src/hook-patterns.ts"() {
    "use strict";
    BUILTIN_PATTERNS = [
      // ── Destructive filesystem operations ──
      {
        matcher: "Bash",
        condition: "Bash(rm -rf *)",
        decision: "deny",
        description: "Recursive force-delete",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(rm -r *)",
        decision: "ask",
        description: "Recursive delete",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(chmod 777 *)",
        decision: "deny",
        description: "World-writable permissions",
        category: "privilege_escalation"
      },
      {
        matcher: "Bash",
        condition: "Bash(chmod -R *)",
        decision: "ask",
        description: "Recursive permission change",
        category: "privilege_escalation"
      },
      // ── SQL destruction ──
      {
        matcher: "Bash",
        condition: "Bash(DROP TABLE *)",
        decision: "deny",
        description: "SQL DROP TABLE",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(DROP DATABASE *)",
        decision: "deny",
        description: "SQL DROP DATABASE",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(TRUNCATE *)",
        decision: "deny",
        description: "SQL TRUNCATE",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(DELETE FROM *)",
        decision: "ask",
        description: "SQL DELETE (mass deletion)",
        category: "destructive"
      },
      // ── Network exfiltration ──
      {
        matcher: "Bash",
        condition: "Bash(curl * --upload-file *)",
        decision: "deny",
        description: "Upload file via curl",
        category: "exfiltration"
      },
      {
        matcher: "Bash",
        condition: "Bash(wget --post-file *)",
        decision: "deny",
        description: "Upload file via wget",
        category: "exfiltration"
      },
      {
        matcher: "Bash",
        condition: "Bash(scp * *:*)",
        decision: "ask",
        description: "Remote file copy",
        category: "exfiltration"
      },
      // ── Sensitive file access ──
      {
        matcher: "Write",
        condition: "Write(*.env)",
        decision: "ask",
        description: "Write to .env file",
        category: "sensitive_file"
      },
      {
        matcher: "Write",
        condition: "Write(*.key)",
        decision: "deny",
        description: "Write to key file",
        category: "sensitive_file"
      },
      {
        matcher: "Write",
        condition: "Write(*.pem)",
        decision: "deny",
        description: "Write to certificate file",
        category: "sensitive_file"
      },
      {
        matcher: "Edit",
        condition: "Edit(*.env)",
        decision: "ask",
        description: "Edit .env file",
        category: "sensitive_file"
      },
      {
        matcher: "Write",
        condition: "Write(*id_rsa*)",
        decision: "deny",
        description: "Write to SSH key",
        category: "sensitive_file"
      },
      {
        matcher: "Read",
        condition: "Read(*id_rsa*)",
        decision: "ask",
        description: "Read SSH private key",
        category: "sensitive_file"
      },
      // ── Privilege escalation ──
      {
        matcher: "Bash",
        condition: "Bash(sudo *)",
        decision: "ask",
        description: "Sudo execution",
        category: "privilege_escalation"
      },
      {
        matcher: "Bash",
        condition: "Bash(su *)",
        decision: "deny",
        description: "Switch user",
        category: "privilege_escalation"
      },
      // ── Package/system modification ──
      {
        matcher: "Bash",
        condition: "Bash(npm publish *)",
        decision: "ask",
        description: "Publish npm package",
        category: "destructive"
      },
      {
        matcher: "Bash",
        condition: "Bash(pip install *)",
        decision: "ask",
        description: "Install Python package",
        category: "network"
      },
      {
        matcher: "Bash",
        condition: "Bash(git push --force*)",
        decision: "ask",
        description: "Force push to git",
        category: "destructive"
      }
    ];
  }
});

// src/sample.ts
var sample_exports = {};
__export(sample_exports, {
  SAMPLE_KID: () => SAMPLE_KID,
  buildSampleKit: () => buildSampleKit
});
function signEnvelope(unsigned, privHex) {
  const msg = new TextEncoder().encode(canonicalJson(unsigned));
  const signature = bytesToHex(ed25519.sign(msg, hexToBytes(privHex)));
  return { ...unsigned, signature };
}
function buildSampleKit(dir, opts) {
  const receiptsPath = (0, import_node_path7.join)(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = (0, import_node_path7.join)(dir, "keys", "gateway.json");
  if (!opts?.force && ((0, import_node_fs10.existsSync)(receiptsPath) || (0, import_node_fs10.existsSync)(keyPath))) {
    throw Object.assign(
      new Error(`refusing to overwrite an existing record or signing key in ${dir}`),
      { code: "SAMPLE_EXISTS" }
    );
  }
  (0, import_node_fs10.mkdirSync)((0, import_node_path7.join)(dir, "keys"), { recursive: true });
  const priv = ed25519.utils.randomPrivateKey();
  const privHex = bytesToHex(priv);
  const pub = bytesToHex(ed25519.getPublicKey(priv));
  (0, import_node_fs10.writeFileSync)(keyPath, JSON.stringify({ privateKey: privHex, publicKey: pub, kid: SAMPLE_KID }, null, 2));
  (0, import_node_fs10.writeFileSync)((0, import_node_path7.join)(dir, "keys", ".gitignore"), "# Never commit signing keys\n*.json\n");
  const now = opts?.now ?? /* @__PURE__ */ new Date();
  const stamp = (i) => new Date(now.getTime() - (7 - i) * 5 * 6e4).toISOString();
  const receipt = (i, tool, decision, caps, extra) => {
    const ts = stamp(i);
    const payload = {
      tool,
      decision,
      reason_code: decision === "deny" ? "policy_deny" : "policy_ok",
      policy_digest: SAMPLE_KID,
      scope: `${tool}-${ts}`,
      mode: "enforce",
      request_id: `${tool}-${ts}`,
      spec: "draft-farley-acta-signed-receipts-01",
      issuer_certification: "self-signed",
      public_key: pub,
      hook_event: "PreToolUse",
      enrichment: { v: 2, input_digest: sha256Hex4(tool + ts), capabilities: caps, ...extra || {} }
    };
    return signEnvelope({
      v: 2,
      type: decision === "deny" ? "gateway_restraint" : "decision_receipt",
      algorithm: "ed25519",
      kid: SAMPLE_KID,
      issuer: "protect-mcp",
      issued_at: ts,
      payload
    }, privHex);
  };
  const pay = (amount) => ({
    payment: { amount, asset: "USDC", recipient_digest: sha256Hex4("sample-merchant"), scheme: "exact" }
  });
  const rows = [
    receipt(0, "Read", "allow", ["fs.read"]),
    receipt(1, "Bash", "allow", ["exec.shell"]),
    receipt(2, "Write", "allow", ["fs.write"]),
    receipt(3, "WebFetch", "deny", ["net.egress"]),
    receipt(4, "x402_pay", "allow", ["financial", "payment"], pay(0.02)),
    receipt(5, "Read", "allow", ["fs.read", "secret.adjacent"]),
    receipt(6, "wallet_send_payment", "allow", ["financial", "payment"], pay(12.5)),
    receipt(7, "Bash", "allow", ["exec.shell", "vcs"])
  ];
  (0, import_node_fs10.writeFileSync)(receiptsPath, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const tampered = rows.map((r) => JSON.parse(JSON.stringify(r)));
  tampered[3].payload.decision = "allow";
  (0, import_node_fs10.writeFileSync)((0, import_node_path7.join)(dir, "demo-tampered.jsonl"), tampered.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return {
    dir,
    publicKey: pub,
    kid: SAMPLE_KID,
    receipts: rows,
    paymentsUsd: [0.02, 12.5],
    files: [".protect-mcp-receipts.jsonl", "demo-tampered.jsonl", "keys/gateway.json"]
  };
}
var import_node_fs10, import_node_path7, SAMPLE_KID, sha256Hex4;
var init_sample = __esm({
  "src/sample.ts"() {
    "use strict";
    import_node_fs10 = require("fs");
    import_node_path7 = require("path");
    init_sha256();
    init_utils();
    init_ed25519();
    init_receipt_enrichment();
    SAMPLE_KID = "sample-demo";
    sha256Hex4 = (s) => bytesToHex(sha2562(new TextEncoder().encode(s)));
  }
});

// src/scopeblind-bridge.ts
function getScopeBlindBridge() {
  if (!singleton) singleton = new ScopeBlindBridge();
  return singleton;
}
var DEFAULT_BASE, FLUSH_INTERVAL_MS, BATCH_MAX, BRASS_REFRESH_MARGIN_MS, ScopeBlindBridge, singleton;
var init_scopeblind_bridge = __esm({
  "src/scopeblind-bridge.ts"() {
    "use strict";
    DEFAULT_BASE = "https://scopeblind.com";
    FLUSH_INTERVAL_MS = 5e3;
    BATCH_MAX = 128;
    BRASS_REFRESH_MARGIN_MS = 5 * 60 * 1e3;
    ScopeBlindBridge = class {
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
    singleton = null;
  }
});

// src/hook-server.ts
var hook_server_exports = {};
__export(hook_server_exports, {
  startHookServer: () => startHookServer
});
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
    input_hash: (0, import_node_crypto6.createHash)("sha256").update(content).digest("hex"),
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
    output_hash: (0, import_node_crypto6.createHash)("sha256").update(content).digest("hex"),
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
      const procStatus = (0, import_node_fs11.readFileSync)("/proc/self/status", "utf-8");
      if (procStatus.includes("Seccomp:	2")) return "enabled";
    } catch {
    }
  }
  return "unavailable";
}
async function handlePreToolUse(input, state) {
  const hookStart = Date.now();
  const toolName = input.toolName || "unknown";
  const requestId = input.toolUseId || (0, import_node_crypto6.randomUUID)().slice(0, 12);
  state.inflightTools.set(requestId, {
    tool: toolName,
    startedAt: hookStart,
    requestId
  });
  const payloadDigest = computePayloadDigest(input.toolInput);
  const actionReadback = buildActionReadback(toolName, input.toolInput || {});
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
  const requestId = input.toolUseId || (0, import_node_crypto6.randomUUID)().slice(0, 12);
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
  const receiptId = (0, import_node_crypto6.randomUUID)().slice(0, 8);
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
    request_id: (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
    request_id: input.sessionId || (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
    request_id: input.sessionId || (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
      request_id: (0, import_node_crypto6.randomUUID)().slice(0, 12),
      hook_event: "ConfigChange",
      swarm: state.swarmContext
    });
  } else {
    emitDecisionLog(state, {
      tool: "config",
      decision: "allow",
      reason_code: "config_changed",
      request_id: (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
    request_id: (0, import_node_crypto6.randomUUID)().slice(0, 12),
    hook_event: "Stop",
    swarm: state.swarmContext
  });
  return {};
}
function emitDecisionLog(state, entry) {
  const mode = state.enforce ? "enforce" : "shadow";
  const otelTraceId = (0, import_node_crypto6.randomBytes)(16).toString("hex");
  const otelSpanId = (0, import_node_crypto6.randomBytes)(8).toString("hex");
  const log = {
    v: 2,
    tool: entry.tool || "unknown",
    decision: entry.decision || "allow",
    reason_code: entry.reason_code || "default_allow",
    policy_digest: state.policyDigest,
    policy_engine: state.cedarPolicies ? "cedar" : "built-in",
    request_id: entry.request_id || (0, import_node_crypto6.randomUUID)().slice(0, 12),
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
  const enr = state.inflightTools.get(log.request_id)?.enrichment;
  if (enr) log.enrichment = enr;
  process.stderr.write(`[PROTECT_MCP] ${JSON.stringify(log)}
`);
  try {
    (0, import_node_fs11.appendFileSync)(state.logFilePath, JSON.stringify(log) + "\n");
  } catch {
  }
  if (isSigningEnabled()) {
    const signed = signDecision(log);
    if (signed.signed) {
      try {
        (0, import_node_fs11.appendFileSync)(state.receiptFilePath, signed.signed + "\n");
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
        (0, import_node_fs11.appendFileSync)(state.receiptFilePath, tombstone + "\n");
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
    const keyPath = (0, import_node_path8.join)(process.cwd(), "keys", "gateway.json");
    if ((0, import_node_fs11.existsSync)(keyPath)) {
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
    logFilePath: (0, import_node_path8.join)(process.cwd(), LOG_FILE3),
    receiptFilePath: (0, import_node_path8.join)(process.cwd(), RECEIPTS_FILE2),
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
        version: process.env.PROTECT_MCP_VERSION || "unknown",
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
    const hasSlug = process.env.SCOPEBLIND_SLUG || (0, import_node_fs11.existsSync)((0, import_node_path8.join)(process.cwd(), ".scopeblind"));
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
      if ((0, import_node_fs11.existsSync)(candidate)) {
        const files = (0, import_node_fs11.readdirSync)(candidate, { encoding: "utf-8" });
        if (files.some((f) => f.endsWith(".cedar"))) {
          return candidate;
        }
      }
    } catch {
    }
  }
  return void 0;
}
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
var import_node_http2, import_node_crypto6, import_node_fs11, import_node_path8, DEFAULT_PORT, LOG_FILE3, RECEIPTS_FILE2, PAYLOAD_HASH_THRESHOLD, SNAKE_TO_CAMEL_MAP;
var init_hook_server = __esm({
  "src/hook-server.ts"() {
    "use strict";
    import_node_http2 = require("http");
    import_node_crypto6 = require("crypto");
    import_node_fs11 = require("fs");
    import_node_path8 = require("path");
    init_cedar_evaluator();
    init_signing();
    init_policy();
    init_http_server();
    init_scopeblind_bridge();
    init_action_readback();
    init_receipt_enrichment();
    DEFAULT_PORT = 9377;
    LOG_FILE3 = ".protect-mcp-log.jsonl";
    RECEIPTS_FILE2 = ".protect-mcp-receipts.jsonl";
    PAYLOAD_HASH_THRESHOLD = 1024;
    SNAKE_TO_CAMEL_MAP = {
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
  }
});

// src/http-transport.ts
var http_transport_exports = {};
__export(http_transport_exports, {
  startHttpTransport: () => startHttpTransport
});
async function startHttpTransport(options) {
  const { port, config, serverCommand } = options;
  const sseClients = /* @__PURE__ */ new Set();
  const httpConfig = {
    ...config,
    command: serverCommand[0],
    args: serverCommand.slice(1)
  };
  const gateway = new ProtectGateway(httpConfig);
  await gateway.startForHttp();
  const server = (0, import_node_http3.createServer)(async (req, res) => {
    const origin = req.headers.origin || "*";
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url || "/", `http://localhost:${port}`);
    if (url.pathname === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        server: "protect-mcp",
        version: process.env.PROTECT_MCP_VERSION || "unknown",
        transport: "streamable-http",
        mode: config.policy ? config.enforce ? "enforce" : "shadow" : "shadow",
        wrapping: serverCommand.join(" ")
      }));
      return;
    }
    if (url.pathname === "/mcp/sse" && req.method === "GET") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      });
      res.write(`data: ${JSON.stringify({ type: "connected", server: "protect-mcp" })}

`);
      sseClients.add(res);
      req.on("close", () => sseClients.delete(res));
      return;
    }
    if (url.pathname === "/mcp" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", async () => {
        try {
          const jsonRpc = JSON.parse(body);
          const acceptSSE = (req.headers.accept || "").includes("text/event-stream");
          const responseStr = await gateway.processRequest(jsonRpc);
          const response = JSON.parse(responseStr);
          if (acceptSSE) {
            res.writeHead(200, {
              "Content-Type": "text/event-stream",
              "Cache-Control": "no-cache"
            });
            res.write(`data: ${JSON.stringify(response)}

`);
            res.end();
          } else {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(response));
          }
          if (jsonRpc.method === "tools/call") {
            const event = {
              type: "decision",
              tool: jsonRpc.params?.name,
              timestamp: (/* @__PURE__ */ new Date()).toISOString()
            };
            for (const client of sseClients) {
              try {
                client.write(`data: ${JSON.stringify(event)}

`);
              } catch {
                sseClients.delete(client);
              }
            }
          }
        } catch (err) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32700, message: "Parse error" },
            id: null
          }));
        }
      });
      return;
    }
    if (url.pathname === "/mcp" && req.method === "DELETE") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "session_closed" }));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: "not_found",
      endpoints: [
        "POST /mcp          \u2014 JSON-RPC endpoint (Streamable HTTP)",
        "GET  /mcp/sse      \u2014 Server-Sent Events stream",
        "GET  /health       \u2014 Health check",
        "DELETE /mcp        \u2014 Close session"
      ]
    }));
  });
  server.listen(port, () => {
    process.stderr.write(`
[PROTECT_MCP] HTTP transport listening on http://0.0.0.0:${port}
`);
    process.stderr.write(`  POST   /mcp        \u2014 JSON-RPC (Streamable HTTP)
`);
    process.stderr.write(`  GET    /mcp/sse    \u2014 Server-Sent Events
`);
    process.stderr.write(`  GET    /health     \u2014 Health check
`);
    process.stderr.write(`  DELETE /mcp        \u2014 Close session
`);
    process.stderr.write(`
  Wrapping: ${serverCommand.join(" ")}
`);
    process.stderr.write(`  Mode: ${config.enforce ? "enforce" : "shadow"}

`);
  });
  const shutdown = () => {
    process.stderr.write("\n[PROTECT_MCP] Shutting down HTTP transport...\n");
    for (const client of sseClients) {
      try {
        client.end();
      } catch {
      }
    }
    server.close();
    gateway.stop();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
var import_node_http3;
var init_http_transport = __esm({
  "src/http-transport.ts"() {
    "use strict";
    import_node_http3 = require("http");
    init_gateway();
  }
});

// src/report.ts
var report_exports = {};
__export(report_exports, {
  formatReportMarkdown: () => formatReportMarkdown,
  generateReport: () => generateReport
});
function generateReport(logPath, receiptPath, periodDays) {
  const now = /* @__PURE__ */ new Date();
  const from = new Date(now.getTime() - periodDays * 864e5);
  const entries = [];
  if ((0, import_node_fs12.existsSync)(logPath)) {
    const raw = (0, import_node_fs12.readFileSync)(logPath, "utf-8");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const jsonStr = trimmed.replace(/^\[PROTECT_MCP\]\s*/, "");
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed.tool && parsed.decision && parsed.timestamp) {
          const entryTime = typeof parsed.timestamp === "number" && parsed.timestamp > 1e12 ? parsed.timestamp : parsed.timestamp * 1e3;
          if (entryTime >= from.getTime()) {
            entries.push(parsed);
          }
        }
      } catch {
      }
    }
  }
  let receiptsSigned = 0;
  let signerKid = "";
  let signerIssuer = "";
  if ((0, import_node_fs12.existsSync)(receiptPath)) {
    const raw = (0, import_node_fs12.readFileSync)(receiptPath, "utf-8");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.signature) {
          receiptsSigned++;
          if (parsed.kid && !signerKid) signerKid = parsed.kid;
          if (parsed.issuer && !signerIssuer) signerIssuer = parsed.issuer;
        }
      } catch {
      }
    }
  }
  const toolMap = /* @__PURE__ */ new Map();
  const tiers = /* @__PURE__ */ new Set();
  const policyDigests = /* @__PURE__ */ new Map();
  let allowed = 0;
  let blocked = 0;
  let rateLimited = 0;
  let approvalRequired = 0;
  for (const entry of entries) {
    const tool = entry.tool;
    if (!toolMap.has(tool)) {
      toolMap.set(tool, { total: 0, allowed: 0, blocked: 0, rate_limited: 0, approval_required: 0 });
    }
    const tm = toolMap.get(tool);
    tm.total++;
    if (entry.decision === "allow") {
      allowed++;
      tm.allowed++;
    } else if (entry.decision === "deny" && entry.reason_code === "rate_limit_exceeded") {
      rateLimited++;
      tm.rate_limited++;
    } else if (entry.decision === "deny" && entry.reason_code === "require_approval") {
      approvalRequired++;
      tm.approval_required++;
    } else {
      blocked++;
      tm.blocked++;
    }
    if (entry.tier) tiers.add(entry.tier);
    if (entry.policy_digest && !policyDigests.has(entry.policy_digest)) {
      policyDigests.set(entry.policy_digest, new Date(entry.timestamp).toISOString());
    }
  }
  const policyChanges = Array.from(policyDigests.entries()).map(([digest, at]) => ({
    at,
    policy_digest: digest
  })).sort((a, b) => a.at.localeCompare(b.at));
  return {
    generated_at: now.toISOString(),
    period: { from: from.toISOString(), to: now.toISOString() },
    signing_identity: signerKid ? { kid: signerKid, issuer: signerIssuer } : null,
    summary: {
      total_decisions: entries.length,
      allowed,
      blocked,
      rate_limited: rateLimited,
      approval_required: approvalRequired,
      unique_tools: toolMap.size,
      unique_tiers: tiers.size
    },
    tool_breakdown: Array.from(toolMap.entries()).map(([tool, stats]) => ({ tool, ...stats })).sort((a, b) => b.total - a.total),
    policy_changes: policyChanges,
    verification: {
      receipts_signed: receiptsSigned,
      receipts_unsigned: entries.length - receiptsSigned,
      verify_command: "npx @veritasacta/verify audit-bundle.json --bundle"
    }
  };
}
function formatReportMarkdown(report) {
  const lines = [];
  lines.push("# ScopeBlind Compliance Report");
  lines.push("");
  lines.push(`**Generated:** ${report.generated_at}`);
  lines.push(`**Period:** ${report.period.from.split("T")[0]} to ${report.period.to.split("T")[0]}`);
  if (report.signing_identity) {
    lines.push(`**Signing identity:** kid \`${report.signing_identity.kid}\`, issuer \`${report.signing_identity.issuer}\``);
  }
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total decisions | ${report.summary.total_decisions} |`);
  lines.push(`| Allowed | ${report.summary.allowed} |`);
  lines.push(`| Blocked | ${report.summary.blocked} |`);
  lines.push(`| Rate-limited | ${report.summary.rate_limited} |`);
  lines.push(`| Approval required | ${report.summary.approval_required} |`);
  lines.push(`| Unique tools | ${report.summary.unique_tools} |`);
  lines.push(`| Unique tiers | ${report.summary.unique_tiers} |`);
  lines.push("");
  if (report.tool_breakdown.length > 0) {
    lines.push("## Tool Breakdown");
    lines.push("");
    lines.push("| Tool | Total | Allowed | Blocked | Rate-limited | Approval |");
    lines.push("|------|-------|---------|---------|--------------|----------|");
    for (const t of report.tool_breakdown) {
      lines.push(`| \`${t.tool}\` | ${t.total} | ${t.allowed} | ${t.blocked} | ${t.rate_limited} | ${t.approval_required} |`);
    }
    lines.push("");
  }
  if (report.policy_changes.length > 0) {
    lines.push("## Policy History");
    lines.push("");
    lines.push("| Timestamp | Policy Digest |");
    lines.push("|-----------|--------------|");
    for (const pc of report.policy_changes) {
      lines.push(`| ${pc.at} | \`${pc.policy_digest}\` |`);
    }
    lines.push("");
  }
  lines.push("## Verification");
  lines.push("");
  lines.push(`- Receipts signed: **${report.verification.receipts_signed}**`);
  lines.push(`- Receipts unsigned: **${report.verification.receipts_unsigned}**`);
  lines.push("");
  lines.push("Verify the audit bundle:");
  lines.push("");
  lines.push("```bash");
  lines.push(report.verification.verify_command);
  lines.push("```");
  lines.push("");
  lines.push("The verifier is MIT-licensed and works offline. No ScopeBlind account required.");
  lines.push("");
  lines.push("---");
  lines.push("*Generated by protect-mcp \xB7 scopeblind.com*");
  return lines.join("\n");
}
var import_node_fs12;
var init_report = __esm({
  "src/report.ts"() {
    "use strict";
    import_node_fs12 = require("fs");
  }
});

// src/cli.ts
init_gateway();
init_policy();
init_signing();
init_credentials();

// src/simulate.ts
var import_node_fs7 = require("fs");
init_policy();
init_admission();
function parseLogFile(path) {
  const raw = (0, import_node_fs7.readFileSync)(path, "utf-8");
  const entries = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const jsonStr = trimmed.replace(/^\[PROTECT_MCP\]\s*/, "");
    try {
      const parsed = JSON.parse(jsonStr);
      if (parsed.tool && parsed.decision) {
        entries.push(parsed);
      }
    } catch {
    }
  }
  return entries;
}
function simulate(entries, policy, tier = "unknown") {
  const rateLimitStore = /* @__PURE__ */ new Map();
  const toolResults = /* @__PURE__ */ new Map();
  const totals = {
    allow: 0,
    block: 0,
    rate_limited: 0,
    require_approval: 0,
    tier_insufficient: 0
  };
  const originalTotals = { allow: 0, deny: 0 };
  const changes = [];
  for (const entry of entries) {
    const toolName = entry.tool;
    const toolPolicy = getToolPolicy(toolName, policy);
    if (entry.decision === "allow") {
      originalTotals.allow++;
    } else {
      originalTotals.deny++;
    }
    let newDecision;
    if (toolPolicy.block) {
      newDecision = "block";
    } else if (toolPolicy.min_tier && !meetsMinTier(tier, toolPolicy.min_tier)) {
      newDecision = "tier_insufficient";
    } else if (toolPolicy.require_approval) {
      newDecision = "require_approval";
    } else if (toolPolicy.rate_limit) {
      const limit = parseRateLimit(toolPolicy.rate_limit);
      const result = checkRateLimit(toolName, limit, rateLimitStore);
      newDecision = result.allowed ? "allow" : "rate_limited";
    } else {
      newDecision = "allow";
    }
    totals[newDecision]++;
    if (!toolResults.has(toolName)) {
      toolResults.set(toolName, {
        tool: toolName,
        calls: 0,
        results: { allow: 0, block: 0, rate_limited: 0, require_approval: 0, tier_insufficient: 0 },
        original: { allow: 0, deny: 0 }
      });
    }
    const tr = toolResults.get(toolName);
    tr.calls++;
    tr.results[newDecision]++;
    if (entry.decision === "allow") {
      tr.original.allow++;
    } else {
      tr.original.deny++;
    }
  }
  for (const [tool, result] of toolResults) {
    const wasAllBlocked = result.original.allow === 0;
    const nowAllBlocked = result.results.allow === 0;
    const wasAllAllowed = result.original.deny === 0;
    if (wasAllAllowed && result.results.block > 0) {
      changes.push(`${tool}: ${result.results.block} calls would be blocked (was: all allowed)`);
    }
    if (wasAllAllowed && result.results.rate_limited > 0) {
      changes.push(`${tool}: ${result.results.rate_limited} calls would be rate-limited (was: all allowed)`);
    }
    if (wasAllAllowed && result.results.require_approval > 0) {
      changes.push(`${tool}: ${result.results.require_approval} calls would require approval (was: all allowed)`);
    }
    if (wasAllAllowed && result.results.tier_insufficient > 0) {
      changes.push(`${tool}: ${result.results.tier_insufficient} calls would fail tier check (was: all allowed)`);
    }
    if (wasAllBlocked && result.results.allow > 0 && !nowAllBlocked) {
      changes.push(`${tool}: ${result.results.allow} calls would now be allowed (was: all blocked)`);
    }
  }
  return {
    policy_file: "",
    log_file: "",
    total_calls: entries.length,
    results: totals,
    original: originalTotals,
    tool_breakdown: Array.from(toolResults.values()).sort((a, b) => b.calls - a.calls),
    changes
  };
}
function formatSimulation(summary) {
  const lines = [];
  lines.push(`Simulating ${summary.policy_file} against ${summary.total_calls} recorded tool calls:
`);
  const maxToolLen = Math.max(...summary.tool_breakdown.map((t) => t.tool.length), 4);
  for (const tr of summary.tool_breakdown) {
    const parts = [];
    if (tr.results.allow > 0) parts.push(`${tr.results.allow} allow`);
    if (tr.results.block > 0) parts.push(`\x1B[31m${tr.results.block} blocked\x1B[0m`);
    if (tr.results.rate_limited > 0) parts.push(`\x1B[33m${tr.results.rate_limited} rate_limited\x1B[0m`);
    if (tr.results.require_approval > 0) parts.push(`\x1B[36m${tr.results.require_approval} require_approval\x1B[0m`);
    if (tr.results.tier_insufficient > 0) parts.push(`\x1B[35m${tr.results.tier_insufficient} tier_insufficient\x1B[0m`);
    const originalParts = [];
    if (tr.original.allow > 0) originalParts.push(`${tr.original.allow} allow`);
    if (tr.original.deny > 0) originalParts.push(`${tr.original.deny} deny`);
    lines.push(`  ${tr.tool.padEnd(maxToolLen)}  \xD7 ${String(tr.calls).padStart(3)} \u2192 ${parts.join(", ")}  (was: ${originalParts.join(", ")})`);
  }
  lines.push("");
  lines.push(`Summary: ${summary.results.allow} allow, ${summary.results.block} blocked, ${summary.results.rate_limited} rate_limited, ${summary.results.require_approval} require_approval, ${summary.results.tier_insufficient} tier_insufficient`);
  lines.push(`  vs original: ${summary.original.allow} allow, ${summary.original.deny} deny`);
  if (summary.changes.length > 0) {
    lines.push("");
    lines.push("Changes:");
    for (const change of summary.changes) {
      lines.push(`  \u2022 ${change}`);
    }
  }
  return lines.join("\n");
}

// src/cli.ts
init_action_readback();
init_cedar_evaluator();

// src/policy-packs.ts
var header = (id, description) => `// ScopeBlind protect-mcp policy pack: ${id}
// ${description}
// Start in shadow mode, review receipts, then run with --enforce.

`;
var defaultPermit = `
// Default posture: allow non-matching calls so teams can start in shadow mode.
// Tighten this after reviewing your local action dashboard.
permit(principal, action == Action::"MCP::Tool::call", resource);
`;
var filesystemSafe = `${header("filesystem-safe", "Block common destructive filesystem and secret-file access patterns.")}// Destructive file tools are never safe as an unattended default.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"delete_file");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"remove_file");

// Secret-like reads by path.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/id_rsa*" ||
    context.input.path like "*/.ssh/*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*credential*"
  )
};

// Dangerous shell operations that mutate or destroy local state.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*rm -rf*" ||
    context.command like "*mkfs*" ||
    context.command like "*dd if=*" ||
    context.command like "*chmod -R 777*" ||
    context.command like "*chown -R*"
  )
};
${defaultPermit}`;
var gitSafe = `${header("git-safe", "Prevent unattended history rewrites, force pushes, and destructive repo cleanup.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*git push --force*" ||
    context.command like "*git push -f*" ||
    context.command like "*git reset --hard*" ||
    context.command like "*git clean -fd*" ||
    context.command like "*git checkout --*" ||
    context.command like "*git branch -D*" ||
    context.command like "*gh repo delete*"
  )
};
${defaultPermit}`;
var emailSafe = `${header("email-safe", "Permit drafting but block unattended external sends.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"mail.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"email.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"send_email");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"gmail.send");

// Shell fallbacks that send mail are blocked too.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*sendmail*" ||
    context.command like "*mailx*" ||
    context.command like "*smtp*"
  )
};
${defaultPermit}`;
var databaseSafe = `${header("database-safe", "Allow reads, block write/admin SQL unless explicitly approved elsewhere.")}forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "query" && (
    context.input.query like "*DROP *" ||
    context.input.query like "*TRUNCATE *" ||
    context.input.query like "*DELETE *" ||
    context.input.query like "*UPDATE *" ||
    context.input.query like "*INSERT *" ||
    context.input.query like "*ALTER *" ||
    context.input.query like "*GRANT *" ||
    context.input.query like "*REVOKE *"
  )
};
${defaultPermit}`;
var cloudSpendSafe = `${header("cloud-spend-safe", "Block cloud actions that can create spend or destroy infrastructure.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*terraform destroy*" ||
    context.command like "*terraform apply*" ||
    context.command like "*pulumi up*" ||
    context.command like "*pulumi destroy*" ||
    context.command like "*aws ec2 run-instances*" ||
    context.command like "*aws rds create*" ||
    context.command like "*gcloud compute instances create*" ||
    context.command like "*az vm create*" ||
    context.command like "*kubectl delete*"
  )
};
${defaultPermit}`;
var secretsSafe = `${header("secrets-safe", "Block secret exfiltration from files, env, shell, and common credential tools.")}forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/.aws/credentials*" ||
    context.input.path like "*/.npmrc*" ||
    context.input.path like "*/.netrc*" ||
    context.input.path like "*/id_rsa*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*token*"
  )
};

forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*printenv*" ||
    context.command like "*env |*" ||
    context.command like "*security find-generic-password*" ||
    context.command like "*aws secretsmanager get-secret-value*" ||
    context.command like "*gcloud secrets versions access*" ||
    context.command like "*op read*"
  )
};
${defaultPermit}`;
var financeMandateSafe = `${header("finance-mandate-safe", "Block restricted-list and concentration-limit breaches in booking tools.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"pms.book") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"booking.execute") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"booking.ticket") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};

// Default example caps: single-name > 10%, gross > 200%, net > 100%.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_weight_bps" && context.input.post_trade_weight_bps > 1000
};
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_gross_exposure_bps" && context.input.post_trade_gross_exposure_bps > 20000
};
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_net_exposure_bps" && context.input.post_trade_net_exposure_bps > 10000
};
${defaultPermit}`;
var POLICY_PACKS = [
  {
    id: "filesystem-safe",
    name: "Filesystem Safe",
    description: "Blocks destructive filesystem calls and secret-like path reads.",
    recommendedMode: "shadow-first",
    files: [{ path: "filesystem-safe.cedar", contents: filesystemSafe }]
  },
  {
    id: "git-safe",
    name: "Git Safe",
    description: "Blocks force pushes, hard resets, destructive cleanup, and repo deletion.",
    recommendedMode: "shadow-first",
    files: [{ path: "git-safe.cedar", contents: gitSafe }]
  },
  {
    id: "email-safe",
    name: "Email Safe",
    description: "Allows drafting workflows while blocking unattended sends.",
    recommendedMode: "shadow-first",
    files: [{ path: "email-safe.cedar", contents: emailSafe }]
  },
  {
    id: "database-safe",
    name: "Database Safe",
    description: "Allows read-oriented DB tools while blocking mutating/admin SQL.",
    recommendedMode: "shadow-first",
    files: [{ path: "database-safe.cedar", contents: databaseSafe }]
  },
  {
    id: "cloud-spend-safe",
    name: "Cloud Spend Safe",
    description: "Blocks obvious cloud spend creation and infrastructure destruction.",
    recommendedMode: "shadow-first",
    files: [{ path: "cloud-spend-safe.cedar", contents: cloudSpendSafe }]
  },
  {
    id: "secrets-safe",
    name: "Secrets Safe",
    description: "Blocks common file, env, shell, and cloud secret exfiltration paths.",
    recommendedMode: "enforce-ready",
    files: [{ path: "secrets-safe.cedar", contents: secretsSafe }]
  },
  {
    id: "finance-mandate-safe",
    name: "Finance Mandate Safe",
    description: "Blocks restricted-list and concentration breaches in booking flows.",
    recommendedMode: "shadow-first",
    files: [{ path: "finance-mandate-safe.cedar", contents: financeMandateSafe }]
  }
];
function getPolicyPack(id) {
  return POLICY_PACKS.find((pack) => pack.id === id);
}
function policyPackIds() {
  return POLICY_PACKS.map((pack) => pack.id);
}

// src/connector-pilots.ts
var import_node_fs8 = require("fs");
var import_node_path5 = require("path");
var defaultPermit2 = `
// Default posture: observe all non-matching tools so the connector can be piloted in shadow mode.
permit(principal, action == Action::"MCP::Tool::call", resource);
`;
var nautilusBridgePy = String.raw`#!/usr/bin/env python3
"""
ScopeBlind external bridge for NautilusTrader-compatible pilots.

This file is intentionally outside NautilusTrader. It gives protect-mcp a stable
JSONL command boundary for staging, approval-gated submission, cancellation, and
event export while keeping the trading engine customer-owned.

Mock mode runs without NautilusTrader installed. Real mode is enabled by setting
NAUTILUS_BRIDGE_MODULE to "module.path:ClassName"; the class may implement:
  submit_order(order), modify_order(order), cancel_order(order), reconcile(order),
  export_events(since=None)
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class BridgeState:
    root: Path = field(default_factory=lambda: Path(os.environ.get("SCOPEBLIND_NAUTILUS_STATE_DIR", ".protect-mcp/nautilus")))

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.orders_path.touch(exist_ok=True)
        self.events_path.touch(exist_ok=True)

    @property
    def orders_path(self) -> Path:
        return self.root / "orders.jsonl"

    @property
    def events_path(self) -> Path:
        return self.root / "events.jsonl"

    def append_order(self, order: dict[str, Any]) -> None:
        with self.orders_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(order) + "\n")

    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        enriched = {
            "event_id": event.get("event_id") or f"nt-{now_ms()}-{len(event)}",
            "observed_at_ms": now_ms(),
            **event,
        }
        enriched["event_digest"] = sha256_json(enriched)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(enriched) + "\n")
        return enriched

    def events(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        with self.events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    rows.append(json.loads(line))
        return rows


class ScopeBlindNautilusBridge:
    def __init__(self) -> None:
        self.state = BridgeState()
        self.real = self._load_real_bridge()

    def _load_real_bridge(self) -> Any | None:
        target = os.environ.get("NAUTILUS_BRIDGE_MODULE")
        if not target:
            return None
        module_name, _, class_name = target.partition(":")
        if not module_name or not class_name:
            raise ValueError("NAUTILUS_BRIDGE_MODULE must be module.path:ClassName")
        module = importlib.import_module(module_name)
        return getattr(module, class_name)()

    def handle(self, command: dict[str, Any]) -> dict[str, Any]:
        action = command.get("action")
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "stage_order": self.stage_order,
            "submit_order": self.submit_order,
            "modify_order": self.modify_order,
            "cancel_order": self.cancel_order,
            "reconcile": self.reconcile,
            "export_events": self.export_events,
        }
        if action not in handlers:
            return self.error(command, "unknown_action", f"Unsupported action: {action}")
        try:
            return handlers[action](command)
        except Exception as exc:
            return self.error(command, "bridge_error", str(exc))

    def require(self, command: dict[str, Any], *fields: str) -> None:
        missing = [field for field in fields if command.get(field) in (None, "")]
        if missing:
            raise ValueError(f"missing required field(s): {', '.join(missing)}")

    def require_approved(self, command: dict[str, Any]) -> None:
        self.require(command, "approval_receipt")
        if command.get("mandate_passed") is not True:
            raise ValueError("mandate_passed must be true before live order mutation")

    def stage_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require(command, "client_order_id", "instrument_id", "side", "quantity")
        order = self.order_projection(command, status="staged")
        self.state.append_order(order)
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_staged.v1",
            "client_order_id": order["client_order_id"],
            "order_digest": sha256_json(order),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "staged", "order": order, "event": event})

    def submit_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        order = self.order_projection(command, status="submitted")
        if self.real and hasattr(self.real, "submit_order"):
            external = self.real.submit_order(order)
        else:
            external = {"mode": "mock", "external_order_id": f"MOCK-{order['client_order_id']}"}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_submitted.v1",
            "client_order_id": order["client_order_id"],
            "order_digest": sha256_json(order),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "submitted", "order": order, "external": external, "event": event})

    def modify_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "modify_order"):
            external = self.real.modify_order(command)
        else:
            external = {"mode": "mock", "modified": command["client_order_id"]}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_modified.v1",
            "client_order_id": command["client_order_id"],
            "command_digest": sha256_json(command),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "modified", "external": external, "event": event})

    def cancel_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "cancel_order"):
            external = self.real.cancel_order(command)
        else:
            external = {"mode": "mock", "cancelled": command["client_order_id"]}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_cancelled.v1",
            "client_order_id": command["client_order_id"],
            "command_digest": sha256_json(command),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "cancelled", "external": external, "event": event})

    def reconcile(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "reconcile"):
            external = self.real.reconcile(command)
        else:
            external = {"mode": "mock", "client_order_id": command["client_order_id"], "state": "accepted"}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.reconciled.v1",
            "client_order_id": command["client_order_id"],
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "reconciled", "external": external, "event": event})

    def export_events(self, command: dict[str, Any]) -> dict[str, Any]:
        if self.real and hasattr(self.real, "export_events"):
            external_events = self.real.export_events(command.get("since"))
        else:
            external_events = self.state.events()
        return self.ok(command, {
            "status": "exported",
            "event_count": len(external_events),
            "commitment_root": sha256_json(external_events),
            "events": external_events,
        })

    def order_projection(self, command: dict[str, Any], status: str) -> dict[str, Any]:
        return {
            "client_order_id": command["client_order_id"],
            "instrument_id": command["instrument_id"],
            "side": command["side"],
            "quantity": command["quantity"],
            "price": command.get("price"),
            "time_in_force": command.get("time_in_force", "GTC"),
            "strategy_id": command.get("strategy_id"),
            "mandate_digest": command.get("mandate_digest"),
            "approval_receipt": command.get("approval_receipt"),
            "status": status,
            "created_at_ms": now_ms(),
        }

    def ok(self, command: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "bridge": "scopeblind.nautilus.external.v1",
            "mode": "real" if self.real else "mock",
            "request_digest": sha256_json(command),
            **result,
        }

    def error(self, command: dict[str, Any], code: str, message: str) -> dict[str, Any]:
        return {
            "ok": False,
            "bridge": "scopeblind.nautilus.external.v1",
            "mode": "real" if self.real else "mock",
            "error": {"code": code, "message": message},
            "request_digest": sha256_json(command),
        }


def main() -> int:
    bridge = ScopeBlindNautilusBridge()
    for line in sys.stdin:
        if not line.strip():
            continue
        command = json.loads(line)
        print(canonical_json(bridge.handle(command)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
`;
var nautilusAdapterReadme = `# NautilusTrader-compatible external bridge

This connector is intentionally external to NautilusTrader. It lets protect-mcp
control and receipt high-risk order actions while a customer-owned Nautilus
process remains the trading engine.

## Local mock run

\`\`\`bash
python3 .protect-mcp/connectors/nautilus-trader/bridge.py <<'JSONL'
{"action":"stage_order","client_order_id":"SB-1","instrument_id":"AAPL.NASDAQ","side":"BUY","quantity":"50","price":"182.40","mandate_digest":"demo"}
{"action":"submit_order","client_order_id":"SB-1","instrument_id":"AAPL.NASDAQ","side":"BUY","quantity":"50","price":"182.40","mandate_digest":"demo","mandate_passed":true,"approval_receipt":"receipt-demo"}
{"action":"export_events"}
JSONL
\`\`\`

## Real mode

Set \`NAUTILUS_BRIDGE_MODULE=customer_module:BridgeClass\`. The class can
implement \`submit_order\`, \`modify_order\`, \`cancel_order\`, \`reconcile\`,
and \`export_events\`. Keep that glue in the customer's repository so Nautilus
licensing, credentials, and trading logic stay outside ScopeBlind.

## Upstream contribution posture

The best NautilusTrader contribution is not this bridge or a UI. It is a small,
vendor-neutral audit/event sink RFC: a documented way to export normalized order
commands, execution reports, fills, cancels, and reconciliation events so
external compliance wrappers can prove what happened without mutating the
engine.
`;
var CONNECTOR_PILOTS = [
  {
    id: "github",
    category: "code",
    name: "GitHub pull-request control",
    status: "usable-pilot",
    description: "Controls GitHub REST/MCP calls for issue, PR, branch, and workflow actions.",
    value: "Useful when agents already have repo access through GitHub MCP, gh, or a GitHub-backed tool server.",
    env: [
      { name: "GITHUB_TOKEN", required: true, description: "Fine-grained token scoped to the pilot repo." },
      { name: "GITHUB_REPOSITORY", required: true, description: "owner/repo target for the pilot." }
    ],
    tools: ["github.rest.request", "github.issue.create", "github.pull_request.merge", "github.workflow.dispatch"],
    actions: [
      { name: "Read repo metadata", tool: "github.rest.request", risk: "low", mode: "observe", description: "GET-only repository and PR inspection." },
      { name: "Create issue or comment", tool: "github.issue.create", risk: "medium", mode: "require_approval", description: "External write to the system of record." },
      { name: "Merge PR / dispatch workflow", tool: "github.pull_request.merge", risk: "high", mode: "require_approval", description: "Code-changing or CI-triggering action." }
    ],
    setup: [
      "Create a fine-grained GitHub token for one repository.",
      "Set GITHUB_TOKEN and GITHUB_REPOSITORY.",
      "Run the agent through protect-mcp and review GitHub tool calls in the dashboard."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "github",
      target_env: ["GITHUB_TOKEN", "GITHUB_REPOSITORY"],
      safe_read_probe: "GET /repos/{GITHUB_REPOSITORY}",
      controlled_tools: ["github.rest.request", "github.issue.create", "github.pull_request.merge", "github.workflow.dispatch"],
      approval_required_for: ["POST", "PATCH", "PUT", "DELETE", "merge", "workflow_dispatch"],
      receipt_fields: ["method", "path", "repo", "actor", "payload_hash", "approval_reason"]
    },
    cedar: `${defaultPermit2}
// GitHub pilot: reads are observed; writes and merges need exact-action approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.pull_request.merge" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.workflow.dispatch" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.issue.create" && !context.approved };
`
  },
  {
    id: "email-gmail",
    category: "communications",
    name: "Gmail self-send / draft approval",
    status: "usable-pilot",
    description: "Uses the existing Gmail OAuth connector path and restricts send mode to email.self for the first production pilot.",
    value: "Makes external communications reviewable before an agent can send mail.",
    env: [
      { name: "GOOGLE_CLIENT_ID", required: true, description: "OAuth client for Gmail." },
      { name: "GOOGLE_CLIENT_SECRET", required: true, description: "OAuth client secret." },
      { name: "CONNECTOR_TOKEN_KEY", required: true, description: "AES-GCM key material for sealed connector tokens." }
    ],
    tools: ["gmail.draft.create", "gmail.send.email_self", "email.send"],
    actions: [
      { name: "Create draft", tool: "gmail.draft.create", risk: "medium", mode: "require_approval", description: "Draft content can leak sensitive information." },
      { name: "Self-send test", tool: "gmail.send.email_self", risk: "medium", mode: "require_approval", description: "First release allows only sending to the account owner." },
      { name: "External send", tool: "email.send", risk: "high", mode: "deny", description: "Direct external send stays blocked until a customer-specific allowlist exists." }
    ],
    setup: [
      "Configure Google OAuth redirect /fn/connectors/gmail/callback.",
      "Connect Gmail through the hosted console or local connector flow.",
      "Keep send mode to email.self until the customer approves recipient allowlists."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "gmail",
      hosted_functions: ["/fn/connectors/gmail/start", "/fn/connectors/gmail/callback", "/fn/connectors/gmail/send", "/fn/connectors/gmail/status"],
      first_release_scope: "email.self",
      denied_until_configured: ["email.send.external", "email.bulk_send"],
      receipt_fields: ["to_hash", "subject_hash", "body_hash", "approval_reason", "gmail_message_id"]
    },
    cedar: `${defaultPermit2}
// Email pilot: no direct external send. Draft/self-send require exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "email.send" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.draft.create" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.send.email_self" && !context.approved };
`
  },
  {
    id: "filesystem-git",
    category: "local-computer",
    name: "Filesystem and Git control",
    status: "usable-pilot",
    description: "Controls reads, writes, shell commands, and Git mutation in the local project.",
    value: "Immediately useful with Claude Code, Codex, Cursor, and any agent that edits files or runs shell commands.",
    env: [],
    tools: ["Read", "Write", "Edit", "MultiEdit", "Bash", "git.commit", "git.push"],
    actions: [
      { name: "Read files", tool: "Read", risk: "low", mode: "observe", description: "Observe file reads for audit context." },
      { name: "Write/edit files", tool: "Write", risk: "medium", mode: "require_approval", description: "Require approval for sensitive paths or broad rewrites." },
      { name: "Git push/reset", tool: "Bash", risk: "high", mode: "require_approval", description: "Commands that publish, reset, or delete require exact-action approval." }
    ],
    setup: [
      "Run protect-mcp init-hooks in the project.",
      "Install filesystem-safe and Git-safe policy packs.",
      "Review the dashboard before turning on enforce mode."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "filesystem-git",
      local_only: true,
      protected_paths: [".env", ".ssh", "keys/", "secrets/", "node_modules/"],
      dangerous_command_patterns: ["rm -rf", "git push", "git reset --hard", "curl | sh", "chmod 777"],
      receipt_fields: ["tool", "path_hash", "command_hash", "diff_hash", "approval_reason"]
    },
    cedar: `${defaultPermit2}
// Filesystem/Git pilot: dangerous shell and protected-path writes need approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git reset --hard") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git push") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["Write", "Edit", "MultiEdit"].contains(context.tool) && context.path.contains(".env") && !context.approved };
`
  },
  {
    id: "slack-teams",
    category: "communications",
    name: "Slack or Teams outbound approval",
    status: "usable-pilot",
    description: "Controls messages to Slack channels or Microsoft Teams webhooks.",
    value: "Makes high-impact internal broadcasts and client channels approval-gated.",
    env: [
      { name: "SLACK_BOT_TOKEN", required: false, description: "Slack bot token for chat.postMessage pilots." },
      { name: "SLACK_CHANNEL_ID", required: false, description: "Default Slack channel for the pilot." },
      { name: "TEAMS_WEBHOOK_URL", required: false, description: "Teams incoming webhook URL if Teams is preferred." }
    ],
    tools: ["slack.chat.postMessage", "slack.files.upload", "teams.webhook.post"],
    actions: [
      { name: "Post internal message", tool: "slack.chat.postMessage", risk: "medium", mode: "require_approval", description: "Message text and channel are read back before send." },
      { name: "Upload file", tool: "slack.files.upload", risk: "high", mode: "require_approval", description: "Files can leak customer data and need explicit approval." },
      { name: "Teams webhook post", tool: "teams.webhook.post", risk: "medium", mode: "require_approval", description: "Webhook destination and payload hash are receipted." }
    ],
    setup: [
      "Choose Slack or Teams for the first pilot, not both.",
      "Set the relevant token/webhook environment variables.",
      "Start with a private test channel and exact-action approval for every send."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "slack-or-teams",
      supported_modes: ["slack.chat.postMessage", "teams.webhook.post"],
      require_channel_allowlist: true,
      receipt_fields: ["channel_hash", "message_hash", "file_hash", "approval_reason", "provider_message_id"]
    },
    cedar: `${defaultPermit2}
// Slack/Teams pilot: all outbound posts and uploads require approval by default.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["slack.chat.postMessage", "slack.files.upload", "teams.webhook.post"].contains(context.tool) && !context.approved };
`
  },
  {
    id: "finance-pms",
    category: "finance",
    name: "Finance PMS mock-to-real adapter",
    status: "usable-pilot",
    description: "Stages orders into a PMS adapter contract, with mock mode locally and real mode through PMS_ADAPTER_URL.",
    value: "Gives hedge funds the controlled booking path: parse, mandate-check, approve, book, corroborate, receipt.",
    env: [
      { name: "PMS_ADAPTER_URL", required: false, description: "Customer-owned adapter endpoint. Omit for local mock mode." },
      { name: "PMS_ADAPTER_TOKEN", required: false, description: "Bearer token for the customer-owned PMS adapter." }
    ],
    tools: ["pms.order.stage", "pms.order.book", "pms.order.cancel", "pms.reconcile"],
    actions: [
      { name: "Stage order", tool: "pms.order.stage", risk: "medium", mode: "require_approval", description: "Creates a booking ticket but does not execute." },
      { name: "Book order", tool: "pms.order.book", risk: "high", mode: "require_approval", description: "Must pass mandate checks and human readback." },
      { name: "Cancel/order correction", tool: "pms.order.cancel", risk: "high", mode: "require_approval", description: "Mutates book state and requires approval." }
    ],
    setup: [
      "Run local mock mode first with the Legate finance pilot pack.",
      "Point PMS_ADAPTER_URL at a customer-owned bridge when ready.",
      "Require mandate checks and exact-action approval before pms.order.book."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "finance-pms",
      mode: "mock-first",
      adapter_contract: {
        stage: "POST /orders/stage",
        book: "POST /orders/book",
        cancel: "POST /orders/{client_order_id}/cancel",
        reconcile: "GET /orders/{client_order_id}"
      },
      receipt_fields: ["client_order_id", "side", "symbol_hash", "qty", "price", "mandate_digest", "approval_reason", "external_confirmation_hash"]
    },
    cedar: `${defaultPermit2}
// Finance/PMS pilot: booking actions require mandate pass and exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["pms.order.stage", "pms.order.book", "pms.order.cancel"].contains(context.tool) && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "pms.order.book" && context.mandate_passed != true };
`
  },
  {
    id: "nautilus-trader",
    category: "finance",
    name: "NautilusTrader-compatible external bridge",
    status: "usable-pilot",
    description: "Controls NautilusTrader-compatible staged orders through an external JSONL bridge, with local mock mode and customer-owned real mode.",
    value: "Turns Nautilus into a strong Legate demo target: mandate-check, exact approval, external order event, position-blind audit bundle, and later reconciliation.",
    env: [
      { name: "NAUTILUS_BRIDGE_MODULE", required: false, description: "Optional customer glue in module.path:ClassName form for real Nautilus submission." },
      { name: "SCOPEBLIND_NAUTILUS_STATE_DIR", required: false, description: "Optional state directory for local mock events. Defaults to .protect-mcp/nautilus." },
      { name: "NAUTILUS_TRADER_PROJECT", required: false, description: "Optional path to the customer Nautilus project when running real mode." }
    ],
    tools: [
      "nautilus.order.stage",
      "nautilus.order.submit",
      "nautilus.order.modify",
      "nautilus.order.cancel",
      "nautilus.strategy.deploy",
      "nautilus.event.export",
      "nautilus.reconcile"
    ],
    actions: [
      { name: "Stage order", tool: "nautilus.order.stage", risk: "medium", mode: "require_approval", description: "Creates a position-blind booking intent and event commitment." },
      { name: "Submit order", tool: "nautilus.order.submit", risk: "high", mode: "require_approval", description: "Requires mandate pass plus exact approval before live order mutation." },
      { name: "Modify or cancel order", tool: "nautilus.order.modify", risk: "high", mode: "require_approval", description: "Mutates live order state and must carry a fresh approval receipt." },
      { name: "Deploy strategy", tool: "nautilus.strategy.deploy", risk: "high", mode: "require_approval", description: "Requires signed strategy pack, mandate scope, and operator approval." },
      { name: "Export event log", tool: "nautilus.event.export", risk: "low", mode: "observe", description: "Exports normalized event commitments for receipt corroboration." }
    ],
    setup: [
      "Run mock mode first: protect-mcp connectors init nautilus-trader --force.",
      "Pipe stage/submit/reconcile JSONL through .protect-mcp/connectors/nautilus-trader/bridge.py.",
      "For real mode, set NAUTILUS_BRIDGE_MODULE to customer-owned glue that calls NautilusTrader APIs.",
      "Open an upstream NautilusTrader RFC for a neutral audit/event sink before proposing any PR."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "nautilus-trader-compatible",
      mode: "external-bridge-mock-first",
      license_boundary: "No NautilusTrader code is bundled. Real mode calls a customer-owned process/module.",
      adapter_contract: {
        protocol: "stdin/stdout JSONL",
        bridge: ".protect-mcp/connectors/nautilus-trader/bridge.py",
        real_mode_env: "NAUTILUS_BRIDGE_MODULE=module.path:ClassName",
        actions: ["stage_order", "submit_order", "modify_order", "cancel_order", "reconcile", "export_events"]
      },
      controlled_tools: [
        "nautilus.order.stage",
        "nautilus.order.submit",
        "nautilus.order.modify",
        "nautilus.order.cancel",
        "nautilus.strategy.deploy",
        "nautilus.event.export",
        "nautilus.reconcile"
      ],
      approval_required_for: ["submit_order", "modify_order", "cancel_order", "strategy_deploy"],
      receipt_fields: [
        "client_order_id",
        "instrument_id_hash",
        "side",
        "quantity",
        "price",
        "mandate_digest",
        "approval_receipt",
        "external_event_digest",
        "commitment_root"
      ],
      upstream_rfc: {
        title: "[RFC] Add a vendor-neutral order/execution audit event sink",
        non_goals: ["ScopeBlind dependency", "UI dashboard", "AI tooling", "new venue adapter"]
      }
    },
    artifacts: [
      { path: "nautilus-trader/bridge.py", contents: nautilusBridgePy, executable: true },
      { path: "nautilus-trader/README.md", contents: nautilusAdapterReadme }
    ],
    cedar: `${defaultPermit2}
// NautilusTrader-compatible pilot: stage can be observed, but any live mutation requires exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["nautilus.order.submit", "nautilus.order.modify", "nautilus.order.cancel", "nautilus.strategy.deploy"].contains(context.tool) && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["nautilus.order.submit", "nautilus.order.modify", "nautilus.order.cancel"].contains(context.tool) && context.mandate_passed != true };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "nautilus.strategy.deploy" && context.strategy_pack_signed != true };
`
  }
];
function getConnectorPilot(id) {
  return CONNECTOR_PILOTS.find((pilot) => pilot.id === id);
}
function connectorDirectory(dir) {
  return (0, import_node_path5.join)(dir, ".protect-mcp", "connectors");
}
function writeConnectorPilots(opts) {
  const directory = connectorDirectory(opts.dir);
  (0, import_node_fs8.mkdirSync)(directory, { recursive: true });
  const selected = opts.ids && opts.ids.length > 0 && !opts.ids.includes("all") ? opts.ids.map((id) => {
    const pilot = getConnectorPilot(id);
    if (!pilot) throw new Error(`Unknown connector pilot: ${id}`);
    return pilot;
  }) : CONNECTOR_PILOTS;
  const written = [];
  for (const pilot of selected) {
    const configPath = (0, import_node_path5.join)(directory, `${pilot.id}.json`);
    const policyPath = (0, import_node_path5.join)(directory, `${pilot.id}.cedar`);
    if (!opts.force && ((0, import_node_fs8.existsSync)(configPath) || (0, import_node_fs8.existsSync)(policyPath))) {
      throw new Error(`Refusing to overwrite ${pilot.id}. Re-run with --force if intentional.`);
    }
    (0, import_node_fs8.writeFileSync)(configPath, JSON.stringify({ ...pilot.config, id: pilot.id, name: pilot.name, category: pilot.category, tools: pilot.tools, actions: pilot.actions, setup: pilot.setup }, null, 2) + "\n");
    (0, import_node_fs8.writeFileSync)(policyPath, pilot.cedar.endsWith("\n") ? pilot.cedar : `${pilot.cedar}
`);
    written.push(configPath, policyPath);
    for (const artifact of pilot.artifacts || []) {
      const artifactPath = connectorArtifactPath(directory, artifact.path);
      (0, import_node_fs8.mkdirSync)((0, import_node_path5.dirname)(artifactPath), { recursive: true });
      (0, import_node_fs8.writeFileSync)(artifactPath, artifact.contents.endsWith("\n") ? artifact.contents : `${artifact.contents}
`);
      if (artifact.executable) (0, import_node_fs8.chmodSync)(artifactPath, 493);
      written.push(artifactPath);
    }
  }
  (0, import_node_fs8.writeFileSync)((0, import_node_path5.join)(directory, "README.md"), renderConnectorReadme(selected));
  written.push((0, import_node_path5.join)(directory, "README.md"));
  return { written, pilots: selected, directory };
}
function connectorArtifactPath(directory, relativePath) {
  const clean2 = (0, import_node_path5.normalize)(relativePath).replace(/^(\.\.(\/|\\|$))+/, "");
  if (clean2.startsWith("/") || clean2.includes("..")) {
    throw new Error(`Unsafe connector artifact path: ${relativePath}`);
  }
  return (0, import_node_path5.join)(directory, clean2);
}
function readInstalledConnectorPilots(dir) {
  const directory = connectorDirectory(dir);
  if (!(0, import_node_fs8.existsSync)(directory)) return [];
  return (0, import_node_fs8.readdirSync)(directory).filter((name) => name.endsWith(".json")).map((name) => {
    const configPath = (0, import_node_path5.join)(directory, name);
    try {
      const parsed = JSON.parse((0, import_node_fs8.readFileSync)(configPath, "utf-8"));
      const id = String(parsed.id || name.replace(/\.json$/, ""));
      const pilot = getConnectorPilot(id);
      return {
        id,
        name: String(parsed.name || pilot?.name || id),
        category: String(parsed.category || pilot?.category || "unknown"),
        status: String(parsed.status || parsed.type || "installed"),
        config_path: configPath,
        policy_path: (0, import_node_path5.join)(directory, `${id}.cedar`)
      };
    } catch {
      return null;
    }
  }).filter(Boolean);
}
function connectorDoctor(dir, env = process.env) {
  const installed = new Set(readInstalledConnectorPilots(dir).map((pilot) => pilot.id));
  return CONNECTOR_PILOTS.map((pilot) => {
    const envRows = pilot.env.map((item) => ({
      name: item.name,
      required: item.required,
      present: Boolean(env[item.name]),
      description: item.description
    }));
    const missingRequired = envRows.filter((item) => item.required && !item.present).map((item) => item.name);
    const optionalPresent = envRows.filter((item) => !item.required && item.present).map((item) => item.name);
    const optionalProviderReady = pilot.id === "slack-teams" ? Boolean(env.SLACK_BOT_TOKEN || env.TEAMS_WEBHOOK_URL) : pilot.id === "finance-pms" ? Boolean(env.PMS_ADAPTER_URL) : pilot.id === "nautilus-trader" ? Boolean(env.NAUTILUS_BRIDGE_MODULE || env.NAUTILUS_TRADER_PROJECT) : false;
    const mockModeReady = pilot.id === "finance-pms" || pilot.id === "nautilus-trader";
    return {
      id: pilot.id,
      name: pilot.name,
      category: pilot.category,
      installed: installed.has(pilot.id),
      usable: missingRequired.length === 0 && (pilot.env.some((item) => item.required) || pilot.env.length === 0 || optionalProviderReady || mockModeReady),
      mode: pilot.id === "finance-pms" && !env.PMS_ADAPTER_URL ? "mock" : pilot.id === "nautilus-trader" && !env.NAUTILUS_BRIDGE_MODULE ? "mock_bridge" : pilot.id === "slack-teams" && !env.SLACK_BOT_TOKEN && !env.TEAMS_WEBHOOK_URL ? "needs_provider_choice" : "configured_or_local",
      missing_required: missingRequired,
      optional_present: optionalPresent,
      tools: pilot.tools,
      next: missingRequired.length > 0 ? `Set ${missingRequired.join(", ")}` : installed.has(pilot.id) ? "Run through protect-mcp and inspect the dashboard." : `Install with protect-mcp connectors init ${pilot.id}`
    };
  });
}
function renderConnectorReadme(pilots) {
  return `# protect-mcp connector pilots

These files make real tool classes visible and controllable without uploading raw prompts or payloads.

${pilots.map((pilot) => `## ${pilot.name}

${pilot.description}

Value: ${pilot.value}

Tools: ${pilot.tools.map((tool) => `\`${tool}\``).join(", ")}

Setup:
${pilot.setup.map((step) => `- ${step}`).join("\n")}
${pilot.artifacts?.length ? `
Generated files:
${pilot.artifacts.map((artifact) => `- \`${artifact.path}\``).join("\n")}
` : ""}`).join("\n")}
Next: run \`npx protect-mcp dashboard --open\` and review tool inventory, policy coverage, approvals, and receipts.
`;
}

// src/cli.ts
var import_node_crypto7 = require("crypto");
var import_node_fs13 = require("fs");
var import_node_path9 = require("path");
var import_node_os = require("os");
function printHelp() {
  process.stderr.write(`
protect-mcp: Enterprise security gateway for MCP servers & Claude Code hooks

Usage:
  protect-mcp [options] -- <command> [args...]
  protect-mcp serve [--port <port>] [--enforce] [--policy <path>] [--cedar <dir>]
  protect-mcp init-hooks [--dir <path>] [--port <port>]
  protect-mcp quickstart [--connect]
  protect-mcp wrap [--write] [--claude-desktop] [-- <command>]
  protect-mcp dashboard [--port <port>] [--dir <path>] [--open]
  protect-mcp recommend [--dir <path>] [--output <path>] [--write]
  protect-mcp registry init|anchor|status [--dir <path>] [--org <name>] [--hosted]
  protect-mcp trial [--dir <path>] [--hosted]
  protect-mcp killer-demo [--dir <path>] [--hosted]
  protect-mcp connectors list|show|init|doctor [connector|all] [--dir <path>] [--force]
  protect-mcp verify-disclosure --receipt <path> --disclosure <path>
  protect-mcp policy-packs list|show|install [pack] [--dir ./cedar] [--force]
  protect-mcp connect
  protect-mcp init [--dir <path>]
  protect-mcp sample [--dir <path>] [--force]
  protect-mcp demo
  protect-mcp trace <receipt_id> [--endpoint <url>] [--depth <n>]
  protect-mcp status [--dir <path>]
  protect-mcp digest [--today] [--dir <path>]
  protect-mcp receipts [--last <n>] [--dir <path>]
  protect-mcp record [--dir <path>] [--live] [--no-open]
  protect-mcp claim [--no <cap>] [--only <c,c>] [--count <verdict>] [--payment-under <amount>] [--anchor] [--dir <path>] [--output <path>]
  protect-mcp verify-claim <claim.json> [--key <public-hex>] [--check-anchor] [--offline]
  protect-mcp anchor-record [--dir <path>] [--force]
  protect-mcp bundle [--output <path>] [--dir <path>]
  protect-mcp simulate --policy <path> [--log <path>] [--tier <tier>] [--json]
  protect-mcp report [--period <days>d] [--format md|json] [--output <path>] [--dir <path>]

Options:
  --policy <path>   Policy/config JSON file (default: allow-all)
  --cedar <dir>     Cedar policy directory (alternative to --policy, evaluates locally via WASM)
  --slug <slug>     ScopeBlind tenant slug (optional)
  --enforce         Enable enforcement mode (default: shadow mode)
  --http            Start HTTP/SSE server instead of stdio proxy
  --port <port>     HTTP server port (default: 3000 for --http, 9377 for serve)
  --verbose         Enable debug logging to stderr
  --help            Show this help
  --version         Print the installed version

Commands:
  serve             Start HTTP hook server for Claude Code integration (port 9377)
  evaluate          Evaluate one tool call against a Cedar policy (PreToolUse gate; exit 2 = deny, fail-closed)
  sign              Sign one tool call into a receipt (PostToolUse)
  init-hooks        Generate Claude Code hook config + skill + sample Cedar policy
  quickstart        Zero-config onboarding: init + demo + show receipts in one command
  wrap              Print or install a protect-mcp wrapper for MCP servers
  dashboard         Start a local-only action dashboard from logs/receipts
  recommend         Draft a policy from shadow-mode call inventory
  registry          Paid-boundary receipt digest registry and verifier page
  trial             Build the 10-minute self-serve proof path locally
  killer-demo       Build a 3-minute shadow\u2192policy\u2192approval\u2192receipt demo pack
  connectors        Install and inspect real connector pilots
  verify-disclosure Verify a v0 selective-disclosure package and explain hidden fields
  policy-packs      List, inspect, or install starter Cedar policy packs
  connect           Create a ScopeBlind sandbox dashboard and configure receipt upload
  init              Generate config template, Ed25519 keypair, and sample policy
  demo              Start a demo server wrapped with protect-mcp (see receipts instantly)
  doctor            Check your setup: keys, policies, verifier, API connectivity
  trace <id>        Visualize the receipt DAG from a given receipt_id (ASCII tree)
  status            Show tool call statistics from the local decision log
  digest            Generate a human-readable summary of agent activity
  receipts          Show recent persisted signed receipts
  record            Open a local, searchable view of your record in the browser
  claim             Attest a signed, position-blind claim over your record (e.g. no egress,
                    no payment, every payment under a cap)
  verify-claim      Verify a claim attestation offline (signature + predicate + commitment
                    + the anchor sidecar and issuer identity when present)
  anchor-record     Checkpoint the record's Merkle root + count into the public log
                    (heartbeat-friendly: skips when unchanged; only hashes leave)
  bundle            Export an offline-verifiable audit bundle

Examples:
  protect-mcp serve                           # Start hook server (Claude Code)
  protect-mcp serve --enforce --cedar ./cedar  # Enforce Cedar policies
  protect-mcp init-hooks                       # One-command Claude Code setup
  protect-mcp quickstart
  protect-mcp quickstart --connect               # Quickstart + create dashboard
  protect-mcp wrap -- node my-server.js          # Print wrapped MCP command
  protect-mcp wrap --claude-desktop --write      # Patch Claude Desktop MCP config
  protect-mcp dashboard --open                   # Local risk/inventory dashboard
  protect-mcp recommend --write                  # Draft a policy from observed calls
  protect-mcp registry anchor --hosted           # Upload only receipt digests for anchoring
  protect-mcp trial --dir ./scopeblind-trial     # Generate self-serve trial artifacts
  protect-mcp killer-demo --dir ./scopeblind-demo # Generate sales-demo artifacts
  protect-mcp connectors init all --force        # Install connector pilot configs
  protect-mcp connectors doctor                  # Check connector credentials safely
  protect-mcp verify-disclosure --receipt committed.json --disclosure tool-only.json
  protect-mcp policy-packs install filesystem-safe --dir ./cedar
  protect-mcp connect                             # Connect existing setup to dashboard
  protect-mcp -- node my-server.js
  protect-mcp init
  protect-mcp demo
  protect-mcp trace sha256:abc123 --depth 5
  protect-mcp status
  protect-mcp bundle --output audit.json

Dashboard:
  npx protect-mcp dashboard      Local-only dashboard (127.0.0.1; no account)
  npx protect-mcp connect        Create a free ScopeBlind dashboard
                                  Free up to 20,000 receipts/month

  https://scopeblind.com          Docs, pricing, enterprise

`);
}
function parseArgs(argv) {
  let policyPath;
  let cedarDir;
  let slug;
  let enforce = false;
  let verbose = false;
  let childCommand = [];
  const separatorIndex = argv.indexOf("--");
  if (separatorIndex === -1) {
    process.stderr.write(
      '[PROTECT_MCP] Error: Missing "--" separator before the command to wrap.\nUsage: protect-mcp [options] -- <command> [args...]\nExample: protect-mcp --policy policy.json -- node my-server.js\n'
    );
    process.exit(1);
  }
  childCommand = argv.slice(separatorIndex + 1);
  if (childCommand.length === 0) {
    process.stderr.write('[PROTECT_MCP] Error: No command specified after "--"\n');
    process.exit(1);
  }
  const options = argv.slice(0, separatorIndex);
  for (let i = 0; i < options.length; i++) {
    const arg = options[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else if (arg === "--policy" && i + 1 < options.length) {
      policyPath = options[++i];
    } else if (arg === "--cedar" && i + 1 < options.length) {
      cedarDir = options[++i];
    } else if (arg === "--slug" && i + 1 < options.length) {
      slug = options[++i];
    } else if (arg === "--enforce") {
      enforce = true;
    } else if (arg === "--verbose" || arg === "-v") {
      verbose = true;
    } else {
      process.stderr.write(`[PROTECT_MCP] Warning: Unknown option "${arg}"
`);
    }
  }
  return { policyPath, cedarDir, slug, enforce, verbose, childCommand };
}
async function handleInit(argv) {
  const { writeFileSync: writeFileSync5, existsSync: existsSync10, mkdirSync: mkdirSync4 } = await import("fs");
  const { join: join9 } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) {
    dir = argv[dirIdx + 1];
  }
  const configPath = join9(dir, "protect-mcp.json");
  const keysDir = join9(dir, "keys");
  const keyPath = join9(keysDir, "gateway.json");
  if (existsSync10(configPath)) {
    process.stderr.write(`[PROTECT_MCP] Config already exists at ${configPath}
`);
    process.stderr.write("[PROTECT_MCP] Delete it first if you want to regenerate.\n");
    process.exit(1);
  }
  let keypair;
  {
    const { randomBytes: randomBytes4 } = await import("crypto");
    const { ed25519: ed255192 } = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
    const { bytesToHex: bytesToHex2 } = await Promise.resolve().then(() => (init_utils(), utils_exports));
    const privateKey = randomBytes4(32);
    const publicKey = ed255192.getPublicKey(privateKey);
    keypair = {
      privateKey: bytesToHex2(privateKey),
      publicKey: bytesToHex2(publicKey),
      kid: "generated"
    };
  }
  if (!existsSync10(keysDir)) {
    mkdirSync4(keysDir, { recursive: true });
  }
  writeFileSync5(keyPath, JSON.stringify({
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    kid: keypair.kid,
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    warning: "KEEP THIS FILE SECRET. Never commit to version control."
  }, null, 2) + "\n");
  const gitignorePath = join9(keysDir, ".gitignore");
  if (!existsSync10(gitignorePath)) {
    writeFileSync5(gitignorePath, "# Never commit signing keys\n*.json\n");
  }
  const config = {
    tools: {
      "*": {
        rate_limit: "100/hour"
      },
      "delete_file": {
        block: true,
        min_tier: "privileged"
      },
      "write_file": {
        min_tier: "signed-known",
        rate_limit: "10/minute"
      },
      "read_file": {
        rate_limit: "50/minute"
      }
    },
    default_tier: "unknown",
    signing: {
      key_path: "./keys/gateway.json",
      issuer: "protect-mcp",
      enabled: true
    },
    credentials: {
      _example_api: {
        inject: "env",
        name: "EXAMPLE_API_KEY",
        value_env: "EXAMPLE_API_KEY",
        _comment: "Remove the underscore prefix and set EXAMPLE_API_KEY in your environment"
      }
    }
  };
  writeFileSync5(configPath, JSON.stringify(config, null, 2) + "\n");
  const claudeConfig = {
    "mcpServers": {
      "my-server": {
        "command": "npx",
        "args": ["protect-mcp", "--policy", configPath, "--", "node", "my-server.js"]
      }
    }
  };
  process.stderr.write(`
${bold("protect-mcp initialized!")}

Created:
  ${configPath}     Config with shadow mode + local signing
  ${keyPath}       Ed25519 signing keypair

${bold("Next steps:")}
  1. Edit protect-mcp.json to match your MCP server's tools
  2. Set any credential environment variables
  3. Run: protect-mcp --policy protect-mcp.json -- <your-mcp-server>

${bold("Your gateway public key:")}
  ${keypair.publicKey}

${bold("Key ID (kid):")}
  ${keypair.kid}

${bold("Claude Desktop config snippet")} (add to claude_desktop_config.json):
${dim(JSON.stringify(claudeConfig, null, 2))}

${bold("Quick demo:")}
  protect-mcp demo

Shadow mode is the default \u2014 all tool calls are logged and nothing is blocked.
Add --enforce when ready to block policy violations.
`);
}
async function handleDemo() {
  const { existsSync: existsSync10 } = await import("fs");
  const { join: join9, dirname: dirname3, resolve } = await import("path");
  const { realpathSync } = await import("fs");
  const cliPath = resolve(process.argv[1] || "dist/cli.js");
  let cliDir;
  try {
    cliDir = dirname3(realpathSync(cliPath));
  } catch {
    cliDir = dirname3(cliPath);
  }
  const demoServerPath = join9(cliDir, "demo-server.js");
  const configPath = join9(process.cwd(), "protect-mcp.json");
  const hasConfig = existsSync10(configPath);
  if (!hasConfig) {
    process.stderr.write(`
${bold("protect-mcp demo")}

Starting demo with default shadow mode (no signing).
For signed receipts, run ${dim("npx protect-mcp init")} first.

`);
  } else {
    process.stderr.write(`
${bold("protect-mcp demo")}

Using config from ${configPath}
Starting demo server with 5 tools...

`);
  }
  let policy = null;
  let policyDigest = "none";
  let credentials;
  let signing;
  if (hasConfig) {
    try {
      const loaded = loadPolicy(configPath);
      policy = loaded.policy;
      policyDigest = loaded.digest;
      credentials = loaded.credentials;
      signing = loaded.signing;
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Warning: Could not load config: ${err instanceof Error ? err.message : err}
`);
    }
  }
  if (signing) {
    const warnings = await initSigning(signing);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  if (credentials) {
    const warnings = validateCredentials(credentials);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  const config = {
    command: process.execPath,
    // node
    args: [demoServerPath],
    policy,
    policyDigest,
    enforce: false,
    // Demo always runs in shadow mode
    verbose: true,
    signing,
    credentials
  };
  const gateway = new ProtectGateway(config);
  process.stderr.write(`${bold("Demo ready!")} The demo server is running.
`);
  process.stderr.write(`Send JSON-RPC tool calls on stdin, or use an MCP client.

`);
  process.stderr.write(`${dim("Example (paste into stdin):")}
`);
  process.stderr.write(`${dim('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}')}

`);
  await gateway.start();
}
async function handleStatus2(argv) {
  const { readFileSync: readFileSync11, existsSync: existsSync10 } = await import("fs");
  const { join: join9 } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) {
    dir = argv[dirIdx + 1];
  }
  const logPath = join9(dir, ".protect-mcp-log.jsonl");
  if (!existsSync10(logPath)) {
    process.stderr.write(`${bold("protect-mcp status")}

`);
    process.stderr.write(`No log file found at ${logPath}
`);
    process.stderr.write(`Run protect-mcp with a wrapped server first to generate logs.
`);
    process.exit(0);
  }
  const raw = readFileSync11(logPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  if (lines.length === 0) {
    process.stderr.write(`${bold("protect-mcp status")}

No entries in log file.
`);
    process.exit(0);
  }
  const entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
    }
  }
  if (entries.length === 0) {
    process.stderr.write(`${bold("protect-mcp status")}

No valid entries in log file.
`);
    process.exit(0);
  }
  const toolCounts = /* @__PURE__ */ new Map();
  let allowCount = 0;
  let denyCount = 0;
  let rateLimitCount = 0;
  const tierCounts = /* @__PURE__ */ new Map();
  const reasonCounts = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    toolCounts.set(entry.tool, (toolCounts.get(entry.tool) || 0) + 1);
    if (entry.decision === "allow") allowCount++;
    else if (entry.decision === "deny") denyCount++;
    if (entry.reason_code === "rate_limit_exceeded") rateLimitCount++;
    if (entry.tier) tierCounts.set(entry.tier, (tierCounts.get(entry.tier) || 0) + 1);
    reasonCounts.set(entry.reason_code, (reasonCounts.get(entry.reason_code) || 0) + 1);
  }
  const firstTs = new Date(Math.min(...entries.map((e) => e.timestamp)));
  const lastTs = new Date(Math.max(...entries.map((e) => e.timestamp)));
  const sortedTools = [...toolCounts.entries()].sort((a, b) => b[1] - a[1]);
  process.stdout.write(`
${bold("protect-mcp status")}

`);
  process.stdout.write(`  Total decisions: ${bold(String(entries.length))}
`);
  process.stdout.write(`  ${green("\u2713 Allow")}: ${allowCount}    ${red("\u2717 Deny")}: ${denyCount}    ${yellow("\u2298 Rate-limited")}: ${rateLimitCount}

`);
  process.stdout.write(`  ${bold("Time range:")}
`);
  process.stdout.write(`    First: ${firstTs.toISOString()}
`);
  process.stdout.write(`    Last:  ${lastTs.toISOString()}

`);
  process.stdout.write(`  ${bold("Top tools:")}
`);
  for (const [tool, count] of sortedTools.slice(0, 10)) {
    const bar = "\u2588".repeat(Math.min(Math.ceil(count / entries.length * 30), 30));
    process.stdout.write(`    ${tool.padEnd(20)} ${String(count).padStart(4)}  ${dim(bar)}
`);
  }
  if (tierCounts.size > 0) {
    process.stdout.write(`
  ${bold("Trust tiers seen:")}
`);
    for (const [tier, count] of tierCounts) {
      process.stdout.write(`    ${tier.padEnd(15)} ${count}
`);
    }
  }
  process.stdout.write(`
  ${bold("Decision reasons:")}
`);
  for (const [reason, count] of [...reasonCounts.entries()].sort((a, b) => b[1] - a[1])) {
    process.stdout.write(`    ${reason.padEnd(25)} ${count}
`);
  }
  const evidencePath = join9(dir, ".protect-mcp-evidence.json");
  if (existsSync10(evidencePath)) {
    try {
      const evidenceRaw = readFileSync11(evidencePath, "utf-8");
      const evidence = JSON.parse(evidenceRaw);
      const agentCount = Object.keys(evidence.agents || {}).length;
      process.stdout.write(`
  ${bold("Evidence store:")} ${agentCount} agent(s) tracked
`);
    } catch {
    }
  }
  const keyPath = join9(dir, "keys", "gateway.json");
  if (existsSync10(keyPath)) {
    try {
      const keyData = JSON.parse(readFileSync11(keyPath, "utf-8"));
      if (keyData.publicKey) {
        const fingerprint = keyData.publicKey.slice(0, 16) + "...";
        process.stdout.write(`
  ${bold("\u{1F6E1}\uFE0F Passport identity:")}
`);
        process.stdout.write(`    Public key:  ${fingerprint}
`);
        if (keyData.kid) process.stdout.write(`    Key ID:      ${keyData.kid}
`);
        process.stdout.write(`    Issuer:      ${keyData.issuer || "protect-mcp"}
`);
        process.stdout.write(`    Verify:      ${dim("npx @veritasacta/verify <receipt.json>")}
`);
      }
    } catch {
    }
  }
  process.stdout.write(`
  Log file: ${dim(logPath)}

`);
}
function commandNeedsValue(argv, flag) {
  const value = flagValue(argv, flag);
  return Boolean(value && !value.startsWith("--"));
}
function absoluteOrCwd(pathValue) {
  return (0, import_node_path9.resolve)(process.cwd(), pathValue);
}
function shellQuoteArg(arg) {
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}
function shellCommand(command, args) {
  return [command, ...args].map(shellQuoteArg).join(" ");
}
function wrapperArgsFor(command, opts) {
  const args = ["-y", "protect-mcp@latest"];
  if (opts.cedarDir) args.push("--cedar", opts.cedarDir);
  else args.push("--policy", opts.configPath || absoluteOrCwd("protect-mcp.json"));
  if (opts.enforce) args.push("--enforce");
  args.push("--", ...command);
  return args;
}
function claudeDesktopConfigPath() {
  if (process.platform === "darwin") {
    return (0, import_node_path9.join)((0, import_node_os.homedir)(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
  }
  if (process.platform === "win32") {
    return (0, import_node_path9.join)(process.env.APPDATA || (0, import_node_path9.join)((0, import_node_os.homedir)(), "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
  }
  return (0, import_node_path9.join)((0, import_node_os.homedir)(), ".config", "Claude", "claude_desktop_config.json");
}
async function ensureLocalConfig(dir = process.cwd()) {
  const { existsSync: existsSync10 } = await import("fs");
  const { join: join9, resolve } = await import("path");
  const configPath = join9(dir, "protect-mcp.json");
  if (!existsSync10(configPath)) {
    process.stderr.write(`${bold("protect-mcp wrap")}

No protect-mcp.json found; creating local shadow-mode config first.

`);
    await handleInit(["--dir", dir]);
  }
  return resolve(configPath);
}
function parseJsonlFile(pathValue) {
  try {
    const raw = (0, import_node_fs13.readFileSync)(pathValue, "utf-8");
    return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
  } catch {
    return [];
  }
}
function parseJsonlRecords(pathValue) {
  try {
    const raw = (0, import_node_fs13.readFileSync)(pathValue, "utf-8");
    return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
      try {
        return [{
          value: JSON.parse(line),
          raw: line,
          hash: (0, import_node_crypto7.createHash)("sha256").update(line).digest("hex")
        }];
      } catch {
        return [];
      }
    });
  } catch {
    return [];
  }
}
function loadPolicyJson(policyPath) {
  try {
    if (!(0, import_node_fs13.existsSync)(policyPath)) return null;
    return JSON.parse((0, import_node_fs13.readFileSync)(policyPath, "utf-8"));
  } catch {
    return null;
  }
}
function policyCoverageForTool(tool, policy) {
  const tools = policy?.tools && typeof policy.tools === "object" ? policy.tools : {};
  if (tools[tool]) {
    return { status: "exact", label: "Exact rule", policy: tools[tool] };
  }
  if (tools["*"]) {
    return { status: "wildcard", label: "Wildcard fallback", policy: tools["*"] };
  }
  return { status: "none", label: "No rule" };
}
function receiptRequestId(receipt) {
  const direct = receipt.request_id || receipt.scope;
  if (typeof direct === "string") return direct;
  const payload = receipt.payload;
  if (payload && typeof payload === "object") {
    const candidate = payload.request_id || payload.scope;
    if (typeof candidate === "string") return candidate;
  }
  const claims = receipt.signed_claims;
  if (claims && typeof claims === "object") {
    const nestedClaims = claims.claims;
    if (nestedClaims && typeof nestedClaims === "object") {
      const candidate = nestedClaims.request_id || nestedClaims.scope;
      if (typeof candidate === "string") return candidate;
    }
  }
  return void 0;
}
function buildReceiptChains(entries, receipts) {
  const receiptMap = /* @__PURE__ */ new Map();
  for (const receipt of receipts) {
    const requestId = receiptRequestId(receipt.value);
    if (!requestId) continue;
    const rows = receiptMap.get(requestId) || [];
    rows.push(receipt);
    receiptMap.set(requestId, rows);
  }
  const logMap = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    if (!entry.request_id) continue;
    const rows = logMap.get(entry.request_id) || [];
    rows.push(entry);
    logMap.set(entry.request_id, rows);
  }
  return [...logMap.entries()].map(([requestId, logs]) => {
    const relatedReceipts = receiptMap.get(requestId) || [];
    const latest = logs[logs.length - 1];
    return {
      request_id: requestId,
      tool: latest?.tool || "unknown",
      decision: latest?.decision || "unknown",
      reason_code: latest?.reason_code || "",
      action_readback: latest?.action_readback,
      log_events: logs.map((log) => ({
        decision: log.decision,
        reason_code: log.reason_code,
        timestamp: log.timestamp,
        hook_event: log.hook_event
      })),
      receipts: relatedReceipts.map((receipt) => ({
        hash: receipt.hash,
        type: String(receipt.value.type || receipt.value.artifact_type || "receipt")
      })),
      complete: relatedReceipts.length > 0
    };
  }).sort((a, b) => {
    const at = a.log_events[0]?.timestamp || 0;
    const bt = b.log_events[0]?.timestamp || 0;
    return bt - at;
  }).slice(0, 80);
}
function riskForTool(toolRaw) {
  const tool = toolRaw.toLowerCase();
  const reasons = [];
  const highPatterns = [
    ["delete", "delete/destructive"],
    ["remove", "delete/destructive"],
    ["rm", "delete/destructive"],
    ["write", "writes data"],
    ["send", "external send"],
    ["email", "external comms"],
    ["slack", "external comms"],
    ["teams", "external comms"],
    ["github", "source-control mutation"],
    ["commit", "source-control mutation"],
    ["push", "source-control mutation"],
    ["deploy", "deployment"],
    ["terraform", "cloud infrastructure"],
    ["aws", "cloud infrastructure"],
    ["gcp", "cloud infrastructure"],
    ["azure", "cloud infrastructure"],
    ["sql", "database access"],
    ["database", "database access"],
    ["payment", "spend/payment"],
    ["order", "order/transaction"],
    ["trade", "trade/transaction"],
    ["pms", "portfolio-system mutation"],
    ["book", "portfolio-system mutation"],
    ["fill", "portfolio-system mutation"],
    ["secret", "secrets"],
    ["token", "secrets"]
  ];
  for (const [needle, label] of highPatterns) {
    if (tool.includes(needle) && !reasons.includes(label)) reasons.push(label);
  }
  if (reasons.length > 0) return { tier: "high", reasons };
  if (tool.includes("read") || tool.includes("search") || tool.includes("list") || tool.includes("fetch")) {
    return { tier: "medium", reasons: ["data access"] };
  }
  return { tier: "low", reasons: ["observed"] };
}
function suggestedGuardrailFor(_tool, risk, reasons) {
  const reasonSet = new Set(reasons);
  if (reasonSet.has("delete/destructive") || reasonSet.has("secrets")) {
    return {
      action: "Block by default",
      reason: "Destructive and secret-handling tools should start deny-first.",
      policy: { block: true, min_tier: "privileged" }
    };
  }
  if (reasonSet.has("order/transaction") || reasonSet.has("trade/transaction") || reasonSet.has("spend/payment") || reasonSet.has("portfolio-system mutation") || reasonSet.has("deployment") || reasonSet.has("cloud infrastructure") || reasonSet.has("database access") || reasonSet.has("external send") || reasonSet.has("source-control mutation")) {
    return {
      action: "Require approval",
      reason: "Consequential tools should require a human approval receipt before enforce mode.",
      policy: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" }
    };
  }
  if (risk === "medium") {
    return {
      action: "Rate-limit and identify",
      reason: "Read/search/fetch tools can leak data at scale; keep them visible and bounded.",
      policy: { min_tier: "signed-known", rate_limit: "60/hour" }
    };
  }
  return {
    action: "Observe",
    reason: "Low-risk observed tool. Keep receipts and a broad rate limit.",
    policy: { rate_limit: "100/hour" }
  };
}
function buildDashboardSummary(dir, policyPath = (0, import_node_path9.join)(dir, "protect-mcp.json")) {
  const logPath = (0, import_node_path9.join)(dir, ".protect-mcp-log.jsonl");
  const receiptPath = (0, import_node_path9.join)(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = (0, import_node_path9.join)(dir, "keys", "gateway.json");
  const entries = parseJsonlFile(logPath);
  const receiptRecords = parseJsonlRecords(receiptPath);
  const receipts = receiptRecords.map((record) => record.value);
  const activePolicy = loadPolicyJson(policyPath);
  const tools = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    const tool = String(entry.tool || "unknown");
    const risk = riskForTool(tool);
    const current = tools.get(tool) || {
      tool,
      calls: 0,
      allows: 0,
      denies: 0,
      reviews: 0,
      risk: risk.tier,
      reasons: risk.reasons
    };
    current.calls += 1;
    if (entry.decision === "allow") current.allows += 1;
    else if (entry.decision === "deny") current.denies += 1;
    else if (entry.decision === "require_approval") current.reviews += 1;
    if (risk.tier === "high" || risk.tier === "medium" && current.risk === "low") current.risk = risk.tier;
    current.reasons = [.../* @__PURE__ */ new Set([...current.reasons, ...risk.reasons])];
    if (typeof entry.timestamp === "number") current.last_seen = new Date(entry.timestamp).toISOString();
    tools.set(tool, current);
  }
  const toolRows = [...tools.values()].sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 };
    return order[a.risk] - order[b.risk] || b.calls - a.calls || a.tool.localeCompare(b.tool);
  }).map((tool) => ({
    ...tool,
    suggestion: suggestedGuardrailFor(tool.tool, tool.risk, tool.reasons),
    policy_coverage: policyCoverageForTool(tool.tool, activePolicy)
  }));
  const highRisk = toolRows.filter((t) => t.risk === "high");
  const uncovered = toolRows.filter((t) => t.policy_coverage.status === "none").length;
  const exactCovered = toolRows.filter((t) => t.policy_coverage.status === "exact").length;
  const wildcardCovered = toolRows.filter((t) => t.policy_coverage.status === "wildcard").length;
  const allowed = entries.filter((e) => e.decision === "allow").length;
  const denied = entries.filter((e) => e.decision === "deny").length;
  const review = entries.filter((e) => e.decision === "require_approval").length;
  const pendingApprovals = entries.filter((e) => e.decision === "require_approval").slice(-25).reverse();
  const chains = buildReceiptChains(entries, receiptRecords);
  let key = null;
  if ((0, import_node_fs13.existsSync)(keyPath)) {
    try {
      const parsed = JSON.parse((0, import_node_fs13.readFileSync)(keyPath, "utf-8"));
      key = {
        kid: parsed.kid || null,
        issuer: parsed.issuer || "protect-mcp",
        publicKeyPrefix: typeof parsed.publicKey === "string" ? `${parsed.publicKey.slice(0, 16)}...` : null
      };
    } catch {
    }
  }
  return {
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    dir,
    files: {
      log: logPath,
      receipts: receiptPath,
      key: keyPath,
      policy: policyPath,
      log_exists: (0, import_node_fs13.existsSync)(logPath),
      receipts_exist: (0, import_node_fs13.existsSync)(receiptPath),
      key_exists: (0, import_node_fs13.existsSync)(keyPath),
      policy_exists: (0, import_node_fs13.existsSync)(policyPath)
    },
    totals: {
      decisions: entries.length,
      receipts: receipts.length,
      tools: toolRows.length,
      high_risk_tools: highRisk.length,
      exact_covered: exactCovered,
      wildcard_covered: wildcardCovered,
      uncovered,
      allowed,
      denied,
      review
    },
    key,
    policy: activePolicy ? {
      path: policyPath,
      digest: (0, import_node_crypto7.createHash)("sha256").update(JSON.stringify(activePolicy)).digest("hex").slice(0, 16),
      default_tier: activePolicy.default_tier || "unknown",
      tools: activePolicy.tools || {}
    } : null,
    tools: toolRows,
    pending_approvals: pendingApprovals,
    receipt_chains: chains,
    recent: entries.slice(-50).reverse(),
    policy_packs: {
      directory: policyPackDirectory(dir),
      installed: installedPolicyPackIds(dir),
      available: POLICY_PACKS.map((pack) => ({
        id: pack.id,
        name: pack.name,
        description: pack.description,
        recommendedMode: pack.recommendedMode,
        files: pack.files.map((file) => ({ path: file.path, contents: file.contents }))
      }))
    },
    connector_pilots: {
      directory: (0, import_node_path9.join)(dir, ".protect-mcp", "connectors"),
      installed: readInstalledConnectorPilots(dir),
      doctor: connectorDoctor(dir),
      available: CONNECTOR_PILOTS.map((pilot) => ({
        id: pilot.id,
        name: pilot.name,
        category: pilot.category,
        description: pilot.description,
        value: pilot.value,
        tools: pilot.tools,
        actions: pilot.actions,
        setup: pilot.setup
      }))
    },
    registry: dashboardRegistryStatus(dir),
    recommendations: [
      entries.length === 0 ? "Run in shadow mode first: npx protect-mcp -- node your-mcp-server.js" : "",
      highRisk.length > 0 ? "Run npx protect-mcp recommend --write, review the generated policy, then restart your wrapper with --enforce." : "",
      receipts.length === 0 ? "Run npx protect-mcp init so decisions are signed into local receipts." : "",
      "Install a starter policy pack from this dashboard when you know the tool class: filesystem, Git, email, database, cloud spend, secrets, or finance.",
      "Create a registry preview locally, then use hosted digest anchoring when you need independent timestamp evidence.",
      "Export an audit bundle with: npx protect-mcp bundle --output audit.json"
    ].filter(Boolean)
  };
}
function dashboardHtml() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>protect-mcp local action dashboard</title>
<style>
:root {
  color-scheme: light;
  --ink:#12110e; --muted:#6f6b61; --soft:#9a9488; --line:#ded7c9;
  --paper:#f7f3ea; --card:#fffdf7; --black:#11110f;
  --bad:#8f241c; --warn:#8d620f; --ok:#2f6f4e;
  --shadow: 0 22px 70px rgba(36,30,18,.10);
}
* { box-sizing: border-box; }
body { margin:0; background:radial-gradient(circle at top left,#fffdf7 0,#f7f3ea 34%,#e8dfce 100%); color:var(--ink); font:14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
main { width:min(1380px, calc(100vw - 32px)); margin:24px auto 60px; }
.hero { display:grid; grid-template-columns:1.35fr .65fr; gap:16px; align-items:stretch; }
.card { background:rgba(255,253,247,.92); border:1px solid var(--line); border-radius:24px; padding:22px; box-shadow:var(--shadow); }
.kicker { text-transform:uppercase; letter-spacing:.18em; font-size:11px; color:var(--muted); font-weight:800; }
h1 { font-family: ui-serif, Georgia, serif; font-weight:520; font-size:clamp(38px,5vw,76px); line-height:.92; letter-spacing:-.045em; margin:12px 0 14px; max-width:980px; }
h2 { margin:0 0 12px; font-size:17px; letter-spacing:-.01em; }
h3 { margin:0 0 8px; font-size:14px; }
p { color:var(--muted); margin:0; }
small { color:var(--muted); }
.layout { display:grid; grid-template-columns:1.28fr .72fr; gap:16px; margin-top:16px; }
.stack { display:grid; gap:16px; }
.stats { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:16px 0; }
.stat { background:#fffaf0; border:1px solid var(--line); border-radius:18px; padding:13px; min-height:86px; }
.stat strong { display:block; font-size:26px; letter-spacing:-.04em; }
.actions { display:flex; flex-wrap:wrap; gap:9px; margin-top:16px; }
button, a.btn { appearance:none; border:1px solid var(--black); background:var(--black); color:#fff; text-decoration:none; border-radius:999px; padding:9px 12px; cursor:pointer; font-weight:800; font-size:13px; }
button.secondary, a.btn.secondary { background:transparent; color:var(--black); }
button.ghost { border-color:var(--line); background:#fffaf0; color:var(--ink); }
button.danger { background:#7f1d18; border-color:#7f1d18; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:12px 9px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-size:11px; letter-spacing:.09em; text-transform:uppercase; }
.pill { display:inline-flex; align-items:center; border-radius:999px; padding:4px 9px; font-size:11px; font-weight:900; white-space:nowrap; }
.high { background:#f7d9d3; color:var(--bad); }
.medium { background:#f4e5bd; color:var(--warn); }
.low { background:#dcebdd; color:var(--ok); }
.exact { background:#dcebdd; color:var(--ok); }
.wildcard { background:#e5decc; color:#5e5545; }
.none { background:#f7d9d3; color:var(--bad); }
.allow { color:var(--ok); } .deny { color:var(--bad); } .require_approval { color:var(--warn); }
code { background:#f2eadc; border:1px solid var(--line); border-radius:8px; padding:2px 6px; }
pre { white-space:pre-wrap; background:#181712; color:#f8f1df; border-radius:16px; padding:14px; overflow:auto; font-size:12px; }
.muted { color:var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.approval { border:1px solid var(--line); background:#fffaf0; border-radius:18px; padding:14px; margin-bottom:10px; }
.readback { background:#181712; color:#f8f1df; border-radius:16px; padding:12px; margin:10px 0; }
.readback .label { color:#bdb49f; font-size:11px; text-transform:uppercase; letter-spacing:.12em; }
.preview { max-height:180px; overflow:auto; }
.row-actions { display:flex; flex-wrap:wrap; gap:6px; }
.chain { display:grid; gap:8px; }
.chain-item { border:1px solid var(--line); border-radius:16px; padding:12px; background:#fffaf0; }
.pack-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; margin-top:12px; }
.pack { border:1px solid var(--line); border-radius:16px; padding:12px; background:#fffaf0; display:grid; gap:8px; }
.pack.installed { border-color:rgba(47,111,78,.35); background:#f3f8ef; }
.divider { border:0; border-top:1px solid var(--line); margin:14px 0; }
.field { display:grid; gap:5px; margin-top:9px; }
.field label { font-size:11px; text-transform:uppercase; letter-spacing:.09em; color:var(--muted); font-weight:900; }
input { border:1px solid var(--line); border-radius:12px; background:#fffaf0; color:var(--ink); padding:10px; font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
.toast { position:fixed; right:18px; bottom:18px; background:#111; color:#fff; padding:12px 14px; border-radius:14px; box-shadow:var(--shadow); display:none; max-width:360px; }
@media (max-width: 980px) { .hero,.layout { grid-template-columns:1fr; } .stats { grid-template-columns:repeat(2,1fr); } main { width:min(100vw - 20px, 1380px); margin-top:14px; } }
</style>
</head>
<body>
<main>
  <section class="hero">
    <div class="card">
      <div class="kicker">Local Action Dashboard</div>
      <h1>See what agents can do. Control dangerous actions. Prove what happened.</h1>
      <p>Runs on <code>127.0.0.1</code>. Start in shadow mode, switch risky tools to exact-action approval, then export signed evidence without uploading sensitive data.</p>
      <div class="actions">
        <button onclick="refresh()">Refresh</button>
        <button class="secondary" onclick="exportBundle()">Export audit bundle</button>
        <a class="btn secondary" href="/api/summary">Raw JSON</a>
      </div>
    </div>
    <div class="card">
      <div class="kicker">Next move</div>
      <h2>Shadow, review, then enforce</h2>
      <pre>npx protect-mcp wrap -- node your-server.js
npx protect-mcp dashboard --open
npx protect-mcp recommend --write
npx protect-mcp --policy protect-mcp.json --enforce -- node your-server.js</pre>
      <p class="muted" id="dir"></p>
      <p class="muted" id="policy"></p>
    </div>
  </section>

  <section class="stats" id="stats"></section>

  <section class="layout">
    <div class="stack">
      <section class="card">
        <h2>Tool Inventory</h2>
        <p>Risk, policy coverage, and one-click guardrail drafting for each observed tool.</p>
        <div style="overflow:auto; margin-top:12px"><table id="tools"></table></div>
      </section>
      <section class="card">
        <h2>Policy Packs</h2>
        <p>Install a starter Cedar pack from the dashboard. This removes the blank-policy problem while keeping final enforcement local and reviewable.</p>
        <div id="policy-packs" class="pack-grid"></div>
      </section>
      <section class="card">
        <h2>Connector Pilots</h2>
        <p>Real tool categories teams already use: GitHub, Gmail/email, filesystem/Git, Slack or Teams, and finance/PMS. Install a pilot, check credentials, then watch those tools in the dashboard.</p>
        <div id="connector-pilots" class="pack-grid"></div>
      </section>
      <section class="card">
        <h2>Call History</h2>
        <p>What agents actually tried to do, including exact-action readbacks when available.</p>
        <div id="recent" style="margin-top:12px"></div>
      </section>
    </div>
    <div class="stack">
      <section class="card">
        <h2>Approval Queue</h2>
        <p>Desktop fallback approval surface. If you start this dashboard with <code>--approval-endpoint</code> and <code>--approval-nonce</code>, Approve forwards to the live local gateway.</p>
        <div id="approvals" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Receipt Chain</h2>
        <p>Decision logs correlated with signed receipts by request id.</p>
        <div id="chains" class="chain" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Paid Boundary</h2>
        <p>Free local receipts stay local. The paid line starts when a ScopeBlind org identity independently timestamps receipt digests without raw prompt, payload, or receipt upload.</p>
        <div id="registry" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Recommendations</h2>
        <div id="recommendations"></div>
      </section>
    </div>
  </section>
</main>
<div class="toast" id="toast"></div>
<script>
var state = null;
async function refresh(){
  state = await fetch('/api/summary').then(function(r){ return r.json(); });
  render(state);
}
function render(data){
  document.getElementById('dir').textContent = 'Reading: ' + data.dir;
  document.getElementById('policy').textContent = 'Policy: ' + ((data.files || {}).policy || 'protect-mcp.json');
  var t = data.totals || {};
  document.getElementById('stats').innerHTML = [
    ['Decisions', t.decisions || 0, 'All observed tool decisions'],
    ['High risk', t.high_risk_tools || 0, 'Tools that can mutate, send, trade, deploy, or expose secrets'],
    ['Exact rules', t.exact_covered || 0, 'Tools with explicit policy entries'],
    ['Uncovered', t.uncovered || 0, 'Tools falling through without exact policy'],
    ['Receipts', t.receipts || 0, 'Signed proof records available for audit']
  ].map(function(x){ return '<div class="stat"><span class="muted">'+escapeHtml(x[0])+'</span><strong>'+x[1]+'</strong><small>'+escapeHtml(x[2])+'</small></div>'; }).join('');
  renderTools(data.tools || []);
  renderApprovals(data.pending_approvals || []);
  renderRecent(data.recent || []);
  renderChains(data.receipt_chains || []);
  renderPolicyPacks(data.policy_packs || {});
  renderConnectorPilots(data.connector_pilots || {});
  renderRegistry(data.registry || {});
  document.getElementById('recommendations').innerHTML = (data.recommendations || []).map(function(r){ return '<p style="margin:0 0 10px">* '+escapeHtml(r)+'</p>'; }).join('') || '<p class="muted">No recommendations yet.</p>';
}
function renderTools(tools){
  document.getElementById('tools').innerHTML = '<thead><tr><th>Risk</th><th>Tool</th><th>Coverage</th><th>Observed</th><th>Suggested guardrail</th><th>Actions</th></tr></thead><tbody>' +
    tools.map(function(t){
      var cov = t.policy_coverage || { status:'none', label:'No rule' };
      var s = t.suggestion || { action:'Observe', reason:'' };
      return '<tr><td><span class="pill '+t.risk+'">'+escapeHtml(t.risk)+'</span></td>'+
        '<td><strong>'+escapeHtml(t.tool)+'</strong><br><span class="muted">'+escapeHtml((t.reasons || []).join(', '))+'</span></td>'+
        '<td><span class="pill '+escapeHtml(cov.status)+'">'+escapeHtml(cov.label)+'</span><br><span class="muted mono">'+escapeHtml(JSON.stringify(cov.policy || {}))+'</span></td>'+
        '<td>'+t.calls+' calls<br><span class="allow">'+t.allows+' allow</span> \xB7 <span class="deny">'+t.denies+' deny</span> \xB7 <span class="require_approval">'+t.reviews+' review</span></td>'+
        '<td><strong>'+escapeHtml(s.action)+'</strong><br><span class="muted">'+escapeHtml(s.reason)+'</span></td>'+
        '<td><div class="row-actions"><button data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="require_approval">Require approval</button><button class="danger" data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="block">Block</button><button class="ghost" data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="observe">Observe</button></div></td></tr>';
    }).join('') + (tools.length ? '' : '<tr><td colspan="6" class="muted">No tool calls yet. Wrap an MCP server or run the demo.</td></tr>') + '</tbody>';
}
function renderApprovals(rows){
  document.getElementById('approvals').innerHTML = rows.map(function(r){
    var rb = r.action_readback || {};
    var id = r.request_id || '';
    return '<div class="approval"><div class="kicker">Pending exact-action review</div><h3>'+escapeHtml(rb.summary || r.tool || 'Unknown action')+'</h3>'+
      '<div class="readback"><div class="label">You are approving exactly this</div><div><strong>Tool</strong>: '+escapeHtml(r.tool || 'unknown')+'</div><div><strong>Action</strong>: '+escapeHtml(rb.action || r.tool || 'unknown')+'</div><div><strong>Destination</strong>: '+escapeHtml(rb.destination || 'not declared')+'</div><div><strong>Payload hash</strong>: <span class="mono">'+escapeHtml(rb.payload_hash || 'not available')+'</span></div><div><strong>Policy basis</strong>: '+escapeHtml(r.reason_code || 'requires approval')+'</div><div class="preview"><pre>'+escapeHtml(JSON.stringify(rb.payload_preview || {}, null, 2))+'</pre></div></div>'+
      '<textarea id="reason-'+escapeAttr(id)+'" placeholder="Reason or instruction" style="width:100%; min-height:64px; border:1px solid var(--line); border-radius:12px; padding:10px"></textarea>'+
      '<div class="row-actions" style="margin-top:10px"><button data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="approve">Approve</button><button class="danger" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="deny">Deny</button><button class="ghost" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="edit">Edit</button><button class="ghost" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="take_over">Take over</button></div></div>';
  }).join('') || '<p class="muted">No approval-required calls in the local log yet.</p>';
}
function renderRecent(rows){
  document.getElementById('recent').innerHTML = rows.slice(0,20).map(function(r){
    var rb = r.action_readback || {};
    return '<div class="chain-item"><strong class="'+escapeHtml(r.decision || '')+'">'+escapeHtml(r.decision || 'unknown')+'</strong> \xB7 '+escapeHtml(r.tool || 'unknown')+'<br><span class="muted">'+escapeHtml(rb.summary || r.reason_code || '')+'</span><br><span class="muted mono">'+escapeHtml(r.request_id || '')+'</span></div>';
  }).join('') || '<p class="muted">No decisions yet.</p>';
}
function renderChains(rows){
  document.getElementById('chains').innerHTML = rows.slice(0,12).map(function(c){
    var hashes = (c.receipts || []).map(function(r){ return '<span class="mono">'+escapeHtml((r.hash || '').slice(0,16))+'...</span>'; }).join('<br>');
    return '<div class="chain-item"><strong>'+escapeHtml(c.tool || 'unknown')+'</strong> <span class="pill '+(c.complete ? 'exact' : 'none')+'">'+(c.complete ? 'receipt linked' : 'no receipt')+'</span><br><span class="muted">'+escapeHtml(((c.action_readback || {}).summary) || c.reason_code || '')+'</span><br><span class="muted mono">request '+escapeHtml(c.request_id || '')+'</span><div style="margin-top:8px">'+(hashes || '<span class="muted">No signed receipt hash found</span>')+'</div></div>';
  }).join('') || '<p class="muted">No receipt chains yet.</p>';
}
function renderPolicyPacks(info){
  var available = info.available || [];
  var installed = new Set(info.installed || []);
  document.getElementById('policy-packs').innerHTML = available.map(function(pack){
    var isInstalled = installed.has(pack.id);
    var files = (pack.files || []).map(function(f){ return f.path; }).join(', ');
    return '<div class="pack '+(isInstalled ? 'installed' : '')+'">'+
      '<div style="display:flex;gap:8px;align-items:center"><strong>'+escapeHtml(pack.name)+'</strong><span class="pill '+(isInstalled ? 'exact' : 'wildcard')+'">'+(isInstalled ? 'installed' : escapeHtml(pack.recommendedMode || 'shadow-first'))+'</span></div>'+
      '<p>'+escapeHtml(pack.description || '')+'</p>'+
      '<small>Writes to <code>'+escapeHtml((info.directory || './cedar') + '/' + files)+'</code></small>'+
      '<div class="row-actions"><button data-pack-install="'+escapeHtml(pack.id)+'">'+(isInstalled ? 'Reinstall' : 'Install')+'</button><button class="ghost" data-pack-preview="'+escapeHtml(pack.id)+'">Preview</button></div>'+
      '<pre id="pack-preview-'+escapeAttr(pack.id)+'" style="display:none;max-height:240px">'+escapeHtml((pack.files || []).map(function(f){ return '--- '+f.path+' ---\\n'+f.contents; }).join('\\n\\n'))+'</pre>'+
    '</div>';
  }).join('') || '<p class="muted">No policy packs bundled.</p>';
}
function renderConnectorPilots(info){
  var available = info.available || [];
  var installed = new Set((info.installed || []).map(function(row){ return row.id; }));
  var doctor = {};
  (info.doctor || []).forEach(function(row){ doctor[row.id] = row; });
  document.getElementById('connector-pilots').innerHTML = available.map(function(pilot){
    var row = doctor[pilot.id] || {};
    var isInstalled = installed.has(pilot.id);
    var status = row.installed ? (row.usable ? 'installed' : 'needs env') : 'not installed';
    var statusClass = row.installed ? (row.usable ? 'exact' : 'wildcard') : 'none';
    var missing = (row.missing_required || []).join(', ');
    var tools = (pilot.tools || []).slice(0,4).map(function(tool){ return '<code>'+escapeHtml(tool)+'</code>'; }).join(' ');
    return '<div class="pack '+(isInstalled ? 'installed' : '')+'">'+
      '<div style="display:flex;gap:8px;align-items:center"><strong>'+escapeHtml(pilot.name)+'</strong><span class="pill '+statusClass+'">'+escapeHtml(status)+'</span></div>'+
      '<p>'+escapeHtml(pilot.description || '')+'</p>'+
      '<small>'+escapeHtml(pilot.value || '')+'</small>'+
      '<div>'+tools+'</div>'+
      (missing ? '<small>Missing: <code>'+escapeHtml(missing)+'</code></small>' : '<small>'+escapeHtml(row.next || 'Ready for shadow-mode review.')+'</small>')+
      '<details><summary>Details</summary><pre>'+escapeHtml(JSON.stringify({ setup: pilot.setup, actions: pilot.actions, doctor: row }, null, 2))+'</pre></details>'+
      '<div class="row-actions"><button data-connector-install="'+escapeHtml(pilot.id)+'">'+(isInstalled ? 'Reinstall' : 'Install')+'</button><button class="ghost" data-connector-doctor="1">Run doctor</button></div>'+
    '</div>';
  }).join('') || '<p class="muted">No connector pilots bundled.</p>';
}
function renderRegistry(reg){
  var boundaryClass = reg.hosted ? 'exact' : reg.registry_exists ? 'wildcard' : 'none';
  document.getElementById('registry').innerHTML =
    '<div class="chain-item"><span class="pill '+boundaryClass+'">'+escapeHtml(reg.boundary || 'not configured')+'</span>'+
    '<p style="margin-top:8px"><strong>'+escapeHtml(reg.org_name || 'No org identity yet')+'</strong></p>'+
    '<p class="muted">Digests: '+(reg.records || 0)+' \xB7 Anchors: '+(reg.anchors || 0)+'</p>'+
    '<p class="muted mono" style="margin-top:6px">'+escapeHtml(reg.registry_path || '')+'</p></div>'+
    '<div class="field"><label>Org name</label><input id="registry-org" placeholder="Meridian Global Macro" value="'+escapeHtml(reg.org_name || '')+'"></div>'+
    '<div class="field"><label>Hosted token (optional, not stored)</label><input id="registry-token" type="password" placeholder="SCOPEBLIND_TOKEN for hosted digest anchoring"></div>'+
    '<div class="row-actions" style="margin-top:10px"><button data-registry-anchor="local">Create local registry preview</button><button class="secondary" data-registry-anchor="hosted">Hosted digest anchor</button></div>'+
    '<small style="display:block;margin-top:8px">Hosted mode uploads digest metadata only: receipt hash, byte count, receipt type, request id, local issuer/kid, org id, billing account, and public keys. It does not upload prompts, tool payloads, outputs, raw receipts, or private keys.</small>';
}
async function setPolicy(tool, action){
  var res = await fetch('/api/tool-policy', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ tool: tool, action: action }) });
  if(!res.ok){ toast('Policy update failed'); return; }
  toast('Policy updated: '+tool+' -> '+action+'. Restart the wrapper to apply.');
  await refresh();
}
async function resolveApproval(requestId, tool, resolution){
  var reasonEl = document.getElementById('reason-'+escapeAttr(requestId));
  var reason = reasonEl ? reasonEl.value : '';
  var edited = undefined;
  if(resolution === 'edit'){
    var raw = prompt('Paste edited JSON payload. This records the edit instruction; rerun the tool with the edited payload.');
    if(raw){ try { edited = JSON.parse(raw); } catch(e){ toast('Edit payload is not valid JSON'); return; } }
  }
  var res = await fetch('/api/approval/resolve', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ request_id: requestId, tool: tool, resolution: resolution, reason: reason, edited_payload: edited }) });
  var body = await res.json().catch(function(){ return {}; });
  toast(resolution+' recorded'+(body.forwarded && body.forwarded.ok ? ' and forwarded to live gateway' : ' locally'));
}
async function installPack(pack){
  var res = await fetch('/api/policy-packs/install', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ pack: pack, force: true }) });
  var body = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(body.error || 'Policy pack install failed'); return; }
  toast('Installed '+pack+' into '+body.dir);
  await refresh();
}
async function installConnector(pilot){
  var res = await fetch('/api/connectors/install', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ pilot: pilot, force: true }) });
  var body = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(body.error || 'Connector install failed'); return; }
  toast('Installed '+pilot+' into '+body.dir);
  await refresh();
}
function togglePackPreview(pack){
  var el = document.getElementById('pack-preview-'+escapeAttr(pack));
  if(el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
async function anchorRegistry(mode){
  var org = document.getElementById('registry-org') ? document.getElementById('registry-org').value : '';
  var token = document.getElementById('registry-token') ? document.getElementById('registry-token').value : '';
  var body = { org_name: org, hosted: mode === 'hosted', token: token };
  var res = await fetch('/api/registry/anchor', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body) });
  var out = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(out.error || 'Registry anchor failed'); return; }
  toast((out.uploaded ? 'Hosted anchor complete' : 'Local registry preview written') + ': ' + out.records + ' digest(s)');
  await refresh();
}
async function exportBundle(){
  var res = await fetch('/api/audit-bundle');
  if(!res.ok){
    var err = await res.json().catch(function(){ return {}; });
    toast(err.message || 'Audit bundle export requires signed receipts');
    return;
  }
  var blob = await res.blob();
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'protect-mcp-audit-bundle.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
}
document.addEventListener('click', function(ev){
  var target = ev.target && ev.target.closest ? ev.target.closest('[data-policy-tool],[data-approval-id],[data-pack-install],[data-pack-preview],[data-registry-anchor],[data-connector-install],[data-connector-doctor]') : null;
  if(!target) return;
  var connectorInstall = target.getAttribute('data-connector-install');
  if(connectorInstall){ installConnector(connectorInstall); return; }
  if(target.getAttribute('data-connector-doctor')){ toast('Connector doctor refreshed. Missing secrets are shown as names only, never values.'); refresh(); return; }
  var packInstall = target.getAttribute('data-pack-install');
  if(packInstall){ installPack(packInstall); return; }
  var packPreview = target.getAttribute('data-pack-preview');
  if(packPreview){ togglePackPreview(packPreview); return; }
  var anchorMode = target.getAttribute('data-registry-anchor');
  if(anchorMode){ anchorRegistry(anchorMode); return; }
  var policyTool = target.getAttribute('data-policy-tool');
  if(policyTool){
    setPolicy(policyTool, target.getAttribute('data-policy-action') || 'require_approval');
    return;
  }
  var approvalId = target.getAttribute('data-approval-id');
  if(approvalId){
    resolveApproval(approvalId, target.getAttribute('data-approval-tool') || '', target.getAttribute('data-approval-resolution') || 'deny');
  }
});
function toast(msg){ var el=document.getElementById('toast'); el.textContent=msg; el.style.display='block'; setTimeout(function(){el.style.display='none';}, 4200); }
function escapeHtml(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function escapeAttr(v){ return String(v || '').replace(/[^A-Za-z0-9_-]/g,'_'); }
refresh();
</script>
</body>
</html>`;
}
async function handleDashboard(argv) {
  const { createServer: createServer4 } = await import("http");
  const { execFile } = await import("child_process");
  const { resolve } = await import("path");
  const port = commandNeedsValue(argv, "--port") ? parseInt(flagValue(argv, "--port") || "9877", 10) : 9877;
  const dir = resolve(commandNeedsValue(argv, "--dir") ? flagValue(argv, "--dir") || process.cwd() : process.cwd());
  const policyPath = resolve(flagValue(argv, "--policy") || (0, import_node_path9.join)(dir, "protect-mcp.json"));
  const approvalEndpoint = flagValue(argv, "--approval-endpoint");
  const approvalNonce = flagValue(argv, "--approval-nonce");
  const open = argv.includes("--open");
  const server = createServer4((req, res) => {
    void (async () => {
      try {
        const url2 = new URL(req.url || "/", "http://127.0.0.1");
        if (url2.pathname === "/api/summary") {
          const body = JSON.stringify(buildDashboardSummary(dir, policyPath), null, 2);
          res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
          res.end(body);
          return;
        }
        if (url2.pathname === "/api/tool-policy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const tool = typeof body.tool === "string" ? body.tool : "";
          const action = body.action === "block" || body.action === "observe" ? body.action : "require_approval";
          if (!tool) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_tool" }));
            return;
          }
          const policy = writeToolPolicy(policyPath, tool, action);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, policy_path: policyPath, policy }));
          return;
        }
        if (url2.pathname === "/api/policy-packs/install" && req.method === "POST") {
          const body = await readJsonBody(req);
          const pack = typeof body.pack === "string" ? body.pack : "";
          if (!pack) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_policy_pack" }));
            return;
          }
          const installed = installPolicyPackToDir(dir, pack, Boolean(body.force));
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            ok: true,
            ...installed,
            installed: installedPolicyPackIds(dir)
          }));
          return;
        }
        if (url2.pathname === "/api/connectors/install" && req.method === "POST") {
          const body = await readJsonBody(req);
          const pilot = typeof body.pilot === "string" ? body.pilot : "";
          if (!pilot) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_connector_pilot" }));
            return;
          }
          const installed = writeConnectorPilots({ dir, ids: [pilot], force: Boolean(body.force) });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            ok: true,
            dir: installed.directory,
            written: installed.written,
            installed: readInstalledConnectorPilots(dir),
            doctor: connectorDoctor(dir)
          }));
          return;
        }
        if (url2.pathname === "/api/registry/anchor" && req.method === "POST") {
          const body = await readJsonBody(req);
          const { createReceiptRegistry: createReceiptRegistry2 } = await Promise.resolve().then(() => (init_receipt_registry(), receipt_registry_exports));
          try {
            const hosted = Boolean(body.hosted);
            const result = await createReceiptRegistry2({
              dir,
              orgName: typeof body.org_name === "string" && body.org_name.trim() ? body.org_name.trim() : void 0,
              orgId: typeof body.org_id === "string" && body.org_id.trim() ? body.org_id.trim() : void 0,
              billingAccountId: typeof body.billing_account_id === "string" && body.billing_account_id.trim() ? body.billing_account_id.trim() : void 0,
              hosted,
              token: typeof body.token === "string" && body.token.trim() ? body.token.trim() : process.env.SCOPEBLIND_TOKEN,
              endpoint: typeof body.endpoint === "string" && body.endpoint.trim() ? body.endpoint.trim() : hosted ? process.env.SCOPEBLIND_REGISTRY_ENDPOINT || "https://api.scopeblind.com" : void 0,
              verifierBaseUrl: typeof body.verifier_base === "string" && body.verifier_base.trim() ? body.verifier_base.trim() : process.env.SCOPEBLIND_VERIFIER_BASE || "https://legate.scopeblind.com"
            });
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({
              ok: true,
              uploaded: result.uploaded,
              records: result.registry.records.length,
              anchors: result.registry.anchors.length,
              registry_path: result.registryPath,
              verifier_path: result.verifierPath,
              registry: dashboardRegistryStatus(dir)
            }));
          } catch (err) {
            res.writeHead(409, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
            res.end(JSON.stringify({
              error: "registry_anchor_unavailable",
              message: err instanceof Error ? err.message : String(err),
              next_step: "Run protect-mcp with signing enabled so decisions are written as signed receipts, then try again."
            }));
          }
          return;
        }
        if (url2.pathname === "/api/approval/resolve" && req.method === "POST") {
          const body = await readJsonBody(req);
          const result = await recordApprovalResolution({ dir, approvalEndpoint, approvalNonce, body });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(result));
          return;
        }
        if (url2.pathname === "/api/audit-bundle") {
          let bundle;
          try {
            bundle = await buildAuditBundleForDir(dir);
          } catch (err) {
            res.writeHead(409, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
            res.end(JSON.stringify({
              error: "audit_bundle_unavailable",
              message: err instanceof Error ? err.message : String(err),
              next_step: "Run protect-mcp with signing enabled so decisions are written as signed receipts, then export again."
            }));
            return;
          }
          res.writeHead(200, {
            "content-type": "application/json; charset=utf-8",
            "content-disposition": 'attachment; filename="protect-mcp-audit-bundle.json"',
            "cache-control": "no-store"
          });
          res.end(JSON.stringify(bundle, null, 2) + "\n");
          return;
        }
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        });
        res.end(dashboardHtml());
      } catch (err) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
    })();
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(port, "127.0.0.1", () => resolveListen());
  });
  const url = `http://127.0.0.1:${port}`;
  process.stderr.write(`
${bold("protect-mcp dashboard")}

`);
  process.stderr.write(`  Local URL: ${url}
`);
  process.stderr.write(`  Reading:   ${dir}
`);
  process.stderr.write(`  Policy:    ${policyPath}
`);
  process.stderr.write(`  Network:   127.0.0.1 only; no uploads

`);
  if (open) {
    const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
    const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
    execFile(opener, args, () => {
    });
  }
}
function draftPolicyFromSummary(summary) {
  const files = summary.files || {};
  const rows = Array.isArray(summary.tools) ? summary.tools : [];
  const tools = {
    "*": { rate_limit: "100/hour" }
  };
  for (const row of rows) {
    if (!row.tool || row.tool === "unknown") continue;
    const suggestion = row.suggestion || suggestedGuardrailFor(row.tool, row.risk || "low", row.reasons || []);
    tools[row.tool] = suggestion.policy;
  }
  return {
    tools,
    default_tier: "unknown",
    signing: files.key_exists ? {
      key_path: "./keys/gateway.json",
      issuer: "protect-mcp"
    } : void 0,
    notes: [
      "Generated from local shadow-mode inventory.",
      "Review before running with --enforce.",
      "High-risk transaction, deployment, external-send, and database tools require approval.",
      "Destructive and secret-handling tools are blocked by default."
    ]
  };
}
function writeToolPolicy(policyPath, tool, action) {
  const existing = loadPolicyJson(policyPath) || { tools: {}, default_tier: "unknown" };
  const tools = existing.tools && typeof existing.tools === "object" ? { ...existing.tools } : {};
  if (action === "require_approval") {
    tools[tool] = { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" };
  } else if (action === "block") {
    tools[tool] = { block: true, min_tier: "privileged" };
  } else {
    tools[tool] = { rate_limit: "100/hour" };
  }
  const next = {
    ...existing,
    tools,
    default_tier: existing.default_tier || "unknown"
  };
  (0, import_node_fs13.writeFileSync)(policyPath, JSON.stringify(next, null, 2) + "\n");
  return next;
}
function policyPackDirectory(dir) {
  return (0, import_node_path9.join)(dir, "cedar");
}
function installedPolicyPackIds(dir) {
  const cedarDir = policyPackDirectory(dir);
  return POLICY_PACKS.filter(
    (pack) => pack.files.every((file) => (0, import_node_fs13.existsSync)((0, import_node_path9.join)(cedarDir, file.path)))
  ).map((pack) => pack.id);
}
function installPolicyPackToDir(dir, packId, force = false) {
  const packs = packId === "all" ? POLICY_PACKS : [getPolicyPack(packId)].filter(Boolean);
  if (packs.length === 0) throw new Error(`Unknown policy pack: ${packId}`);
  const outDir = policyPackDirectory(dir);
  (0, import_node_fs13.mkdirSync)(outDir, { recursive: true });
  const written = [];
  for (const pack of packs) {
    for (const file of pack.files) {
      const outPath = (0, import_node_path9.join)(outDir, file.path);
      if ((0, import_node_fs13.existsSync)(outPath) && !force) {
        throw new Error(`Refusing to overwrite ${outPath}. Pass force=true if intentional.`);
      }
      (0, import_node_fs13.mkdirSync)((0, import_node_path9.dirname)(outPath), { recursive: true });
      (0, import_node_fs13.writeFileSync)(outPath, file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
      written.push(outPath);
    }
  }
  return { dir: outDir, written, packs: packs.map((pack) => pack.id) };
}
function dashboardRegistryStatus(dir) {
  const identityPath = (0, import_node_path9.join)(dir, ".protect-mcp-org.json");
  const registryPath = (0, import_node_path9.join)(dir, ".protect-mcp-registry.json");
  const verifierPath = (0, import_node_path9.join)(dir, "scopeblind-verifier.html");
  const identity = (0, import_node_fs13.existsSync)(identityPath) ? (() => {
    try {
      return JSON.parse((0, import_node_fs13.readFileSync)(identityPath, "utf-8"));
    } catch {
      return null;
    }
  })() : null;
  const registry = (0, import_node_fs13.existsSync)(registryPath) ? (() => {
    try {
      return JSON.parse((0, import_node_fs13.readFileSync)(registryPath, "utf-8"));
    } catch {
      return null;
    }
  })() : null;
  const anchors = Array.isArray(registry?.anchors) ? registry.anchors : [];
  const hosted = anchors.some((anchor) => anchor.timestamp_source === "scopeblind-hosted");
  return {
    identity_exists: (0, import_node_fs13.existsSync)(identityPath),
    registry_exists: (0, import_node_fs13.existsSync)(registryPath),
    verifier_exists: (0, import_node_fs13.existsSync)(verifierPath),
    identity_path: identityPath,
    registry_path: registryPath,
    verifier_path: verifierPath,
    org_name: identity?.org_name || (registry?.org && typeof registry.org === "object" ? registry.org.org_name : null),
    org_id: identity?.org_id || (registry?.org && typeof registry.org === "object" ? registry.org.org_id : null),
    billing_account_id: identity?.billing_account_id || (registry?.billing && typeof registry.billing === "object" ? registry.billing.billing_account_id : null),
    records: Array.isArray(registry?.records) ? registry.records.length : 0,
    anchors: anchors.length,
    hosted,
    boundary: hosted ? "hosted digest anchor" : registry ? "local preview only" : "not configured"
  };
}
async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  const raw = Buffer.concat(chunks).toString("utf-8").trim();
  return raw ? JSON.parse(raw) : {};
}
async function buildAuditBundleForDir(dir) {
  const { createAuditBundle: createAuditBundle2 } = await Promise.resolve().then(() => (init_bundle(), bundle_exports));
  const receiptPath = (0, import_node_path9.join)(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = (0, import_node_path9.join)(dir, "keys", "gateway.json");
  if (!(0, import_node_fs13.existsSync)(receiptPath)) throw new Error("No receipt file found.");
  if (!(0, import_node_fs13.existsSync)(keyPath)) throw new Error("No signing key found.");
  const receipts = parseJsonlFile(receiptPath);
  if (receipts.length === 0) throw new Error("No signed receipts found.");
  const keyData = JSON.parse((0, import_node_fs13.readFileSync)(keyPath, "utf-8"));
  return createAuditBundle2({
    tenant: keyData.issuer || "protect-mcp",
    receipts,
    selectiveDisclosures: collectSelectiveDisclosurePackages(dir),
    signingKeys: [{
      kty: "OKP",
      crv: "Ed25519",
      kid: keyData.kid || "unknown",
      x: Buffer.from(keyData.publicKey || "", "hex").toString("base64url"),
      use: "sig"
    }]
  });
}
function collectSelectiveDisclosurePackages(dir) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  const candidates = [];
  const receiptsDir = (0, import_node_path9.join)(dir, "receipts");
  if ((0, import_node_fs13.existsSync)(receiptsDir)) {
    for (const name of (0, import_node_fs13.readdirSync)(receiptsDir)) {
      if (name.includes("selective-disclosure") && name.endsWith(".json")) {
        candidates.push((0, import_node_path9.join)(receiptsDir, name));
      }
    }
  }
  const jsonlPath = (0, import_node_path9.join)(dir, ".protect-mcp-selective-disclosures.jsonl");
  if ((0, import_node_fs13.existsSync)(jsonlPath)) {
    for (const line of (0, import_node_fs13.readFileSync)(jsonlPath, "utf-8").split("\n").map((s) => s.trim()).filter(Boolean)) {
      try {
        const parsed = JSON.parse(line);
        addSelectiveDisclosure(out, seen, parsed);
      } catch {
      }
    }
  }
  for (const path of candidates) {
    try {
      const parsed = JSON.parse((0, import_node_fs13.readFileSync)(path, "utf-8"));
      addSelectiveDisclosure(out, seen, parsed);
    } catch {
    }
  }
  return out;
}
function addSelectiveDisclosure(out, seen, parsed) {
  if (parsed?.type !== "scopeblind.selective_disclosure.v0") return;
  const key = [
    parsed.parent_receipt_hash || "",
    Array.isArray(parsed.disclosed_fields) ? parsed.disclosed_fields.slice().sort().join(",") : "",
    Array.isArray(parsed.hidden_fields) ? parsed.hidden_fields.slice().sort().join(",") : ""
  ].join("|");
  if (seen.has(key)) return;
  seen.add(key);
  out.push(parsed);
}
async function recordApprovalResolution(opts) {
  const resolution = String(opts.body.resolution || "deny");
  const requestId = String(opts.body.request_id || "");
  const tool = String(opts.body.tool || "unknown");
  const record = {
    type: "scopeblind.approval_resolution.v1",
    at: (/* @__PURE__ */ new Date()).toISOString(),
    request_id: requestId,
    tool,
    resolution,
    reason: typeof opts.body.reason === "string" ? opts.body.reason.slice(0, 1e3) : "",
    edited_payload: opts.body.edited_payload || void 0,
    takeover_note: opts.body.takeover_note || void 0,
    payload_hash: opts.body.payload_hash || void 0
  };
  (0, import_node_fs13.appendFileSync)((0, import_node_path9.join)(opts.dir, ".protect-mcp-approval-resolutions.jsonl"), JSON.stringify(record) + "\n");
  let forwarded = null;
  if (resolution === "approve" && opts.approvalEndpoint && opts.approvalNonce) {
    const endpoint = opts.approvalEndpoint.replace(/\/$/, "") + "/approve";
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        request_id: requestId,
        tool,
        mode: "once",
        nonce: opts.approvalNonce
      })
    });
    forwarded = {
      ok: response.ok,
      status: response.status,
      body: await response.text().catch(() => "")
    };
  }
  return { recorded: true, resolution: record, forwarded };
}
async function handleRecommend(argv) {
  const { writeFileSync: writeFileSync5 } = await import("fs");
  const { resolve } = await import("path");
  const dir = resolve(commandNeedsValue(argv, "--dir") ? flagValue(argv, "--dir") || process.cwd() : process.cwd());
  const outputPath = resolve(flagValue(argv, "--output") || "protect-mcp.recommended.json");
  const write = argv.includes("--write");
  const summary = buildDashboardSummary(dir);
  const totals = summary.totals;
  const policy = draftPolicyFromSummary(summary);
  const rows = Array.isArray(summary.tools) ? summary.tools : [];
  process.stdout.write(`
${bold("protect-mcp recommend")}

`);
  process.stdout.write(`  Source:    ${dir}
`);
  process.stdout.write(`  Decisions: ${totals.decisions || 0}
`);
  process.stdout.write(`  Tools:     ${totals.tools || 0}

`);
  if (rows.length === 0) {
    process.stdout.write(`No tool calls found yet. First run:

`);
    process.stdout.write(`  ${dim("npx protect-mcp wrap -- node your-mcp-server.js")}
`);
    process.stdout.write(`  ${dim("npx protect-mcp dashboard --open")}

`);
    return;
  }
  for (const row of rows) {
    const suggestion = row.suggestion || suggestedGuardrailFor(row.tool, row.risk, row.reasons);
    process.stdout.write(`  - ${row.tool}: ${bold(suggestion.action)} (${row.risk})
`);
    process.stdout.write(`    ${dim(suggestion.reason)}
`);
  }
  const body = JSON.stringify(policy, null, 2) + "\n";
  if (!write) {
    process.stdout.write(`
Dry run only. Write the policy with:
`);
    process.stdout.write(`  ${dim("npx protect-mcp recommend --write")}

`);
    process.stdout.write(dim(body));
    return;
  }
  writeFileSync5(outputPath, body);
  process.stdout.write(`
${green("\u2713 Wrote recommended policy")}
`);
  process.stdout.write(`  Output: ${outputPath}
`);
  process.stdout.write(`  Review it, then restart your wrapper with:
`);
  process.stdout.write(`  ${dim(shellCommand("npx", ["protect-mcp", "--policy", outputPath, "--enforce", "--", "node", "your-mcp-server.js"]))}

`);
}
async function handleWrap(argv) {
  const { existsSync: existsSync10, readFileSync: readFileSync11, writeFileSync: writeFileSync5 } = await import("fs");
  const { resolve } = await import("path");
  const configFlag = flagValue(argv, "--config");
  const cedarFlag = flagValue(argv, "--cedar");
  const enforce = argv.includes("--enforce");
  const write = argv.includes("--write");
  const claudeDesktop = argv.includes("--claude-desktop") || argv.includes("--claude");
  const serverName = flagValue(argv, "--server");
  const separator = argv.indexOf("--");
  const childCommand = separator >= 0 ? argv.slice(separator + 1).filter(Boolean) : [];
  const configPath = cedarFlag ? void 0 : resolve(configFlag || await ensureLocalConfig(process.cwd()));
  const cedarDir = cedarFlag ? resolve(cedarFlag) : void 0;
  if (childCommand.length > 0) {
    const args = wrapperArgsFor(childCommand, { configPath, cedarDir, enforce });
    process.stdout.write(`
${bold("protect-mcp wrap")}

`);
    process.stdout.write(`Use this command in your MCP client config:

`);
    process.stdout.write(`  ${shellCommand("npx", args)}

`);
    process.stdout.write(`Claude Desktop JSON snippet:

`);
    process.stdout.write(dim(JSON.stringify({
      command: "npx",
      args
    }, null, 2)) + "\n\n");
    process.stdout.write(`Then inspect calls with: ${dim("npx protect-mcp dashboard --open")}

`);
    return;
  }
  const claudePath = resolve(flagValue(argv, "--path") || claudeDesktopConfigPath());
  if (!claudeDesktop && !existsSync10(claudePath)) {
    process.stdout.write(`
${bold("protect-mcp wrap")}

`);
    process.stdout.write(`No command was passed after "--" and no Claude Desktop config was found.

`);
    process.stdout.write(`Examples:
`);
    process.stdout.write(`  ${dim("npx protect-mcp wrap -- node server.js")}
`);
    process.stdout.write(`  ${dim("npx protect-mcp wrap --claude-desktop --write")}

`);
    return;
  }
  if (!existsSync10(claudePath)) {
    process.stderr.write(`protect-mcp wrap: Claude Desktop config not found at ${claudePath}
`);
    process.exit(1);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync11(claudePath, "utf-8"));
  } catch (err) {
    process.stderr.write(`protect-mcp wrap: could not parse ${claudePath}: ${err instanceof Error ? err.message : err}
`);
    process.exit(1);
  }
  const servers = parsed.mcpServers || {};
  const names = Object.keys(servers).filter((name) => !serverName || name === serverName);
  if (names.length === 0) {
    process.stderr.write(`protect-mcp wrap: no MCP servers found${serverName ? ` matching "${serverName}"` : ""}.
`);
    process.exit(1);
  }
  const next = { ...parsed, mcpServers: { ...servers } };
  const changes = [];
  for (const name of names) {
    const before = servers[name] || {};
    const originalCommand = before.command;
    const originalArgs = Array.isArray(before.args) ? before.args : [];
    if (!originalCommand) {
      changes.push({ name, before, after: before, skipped: "missing command" });
      continue;
    }
    if (originalCommand === "npx" && originalArgs.some((arg) => String(arg).includes("protect-mcp"))) {
      changes.push({ name, before, after: before, skipped: "already wrapped" });
      continue;
    }
    const wrappedArgs = wrapperArgsFor([originalCommand, ...originalArgs], { configPath, cedarDir, enforce });
    const after = { ...before, command: "npx", args: wrappedArgs };
    next.mcpServers[name] = after;
    changes.push({ name, before, after });
  }
  process.stdout.write(`
${bold("protect-mcp wrap: Claude Desktop")}

`);
  process.stdout.write(`Config: ${claudePath}
`);
  process.stdout.write(`Mode:   ${enforce ? "enforce" : "shadow"}

`);
  for (const change of changes) {
    if (change.skipped) {
      process.stdout.write(`  - ${change.name}: ${yellow(change.skipped)}
`);
    } else {
      process.stdout.write(`  - ${change.name}: ${green("will wrap")}
`);
      process.stdout.write(`    ${dim(`${change.before.command || ""} ${(change.before.args || []).join(" ")}`)}
`);
      process.stdout.write(`    ${dim(shellCommand("npx", change.after.args || []))}
`);
    }
  }
  if (!write) {
    process.stdout.write(`
Dry run only. Apply with:
`);
    process.stdout.write(`  ${dim("npx protect-mcp wrap --claude-desktop --write")}

`);
    return;
  }
  const backupPath = `${claudePath}.bak.${Date.now()}`;
  writeFileSync5(backupPath, readFileSync11(claudePath, "utf-8"));
  writeFileSync5(claudePath, JSON.stringify(next, null, 2) + "\n");
  process.stdout.write(`
${green("\u2713 Claude Desktop config updated")}
`);
  process.stdout.write(`  Backup: ${backupPath}
`);
  process.stdout.write(`  Restart Claude Desktop, then run: ${dim("npx protect-mcp dashboard --open")}

`);
}
function bold(s) {
  return process.env.NO_COLOR ? s : `\x1B[1m${s}\x1B[0m`;
}
function dim(s) {
  return process.env.NO_COLOR ? s : `\x1B[2m${s}\x1B[0m`;
}
function green(s) {
  return process.env.NO_COLOR ? s : `\x1B[32m${s}\x1B[0m`;
}
function red(s) {
  return process.env.NO_COLOR ? s : `\x1B[31m${s}\x1B[0m`;
}
function yellow(s) {
  return process.env.NO_COLOR ? s : `\x1B[33m${s}\x1B[0m`;
}
async function handleDigest(argv) {
  const { readFileSync: readFileSync11, existsSync: existsSync10 } = await import("fs");
  const { join: join9 } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const today = argv.includes("--today");
  const logPath = join9(dir, ".protect-mcp-log.jsonl");
  if (!existsSync10(logPath)) {
    process.stderr.write(`${bold("protect-mcp digest")}

No log file found. Run protect-mcp first.
`);
    process.exit(0);
  }
  const raw = readFileSync11(logPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  let entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
    }
  }
  if (today) {
    const todayStart = /* @__PURE__ */ new Date();
    todayStart.setHours(0, 0, 0, 0);
    entries = entries.filter((e) => e.timestamp >= todayStart.getTime());
  }
  if (entries.length === 0) {
    process.stdout.write(`
${bold("\u{1F6E1}\uFE0F Agent Digest")}

  No activity${today ? " today" : ""}.

`);
    process.exit(0);
  }
  const allowed = entries.filter((e) => e.decision === "allow").length;
  const denied = entries.filter((e) => e.decision === "deny").length;
  const approvalRequired = entries.filter((e) => e.decision === "require_approval").length;
  const toolUsage = /* @__PURE__ */ new Map();
  for (const e of entries) {
    toolUsage.set(e.tool, (toolUsage.get(e.tool) || 0) + 1);
  }
  const sortedTools = [...toolUsage.entries()].sort((a, b) => b[1] - a[1]);
  const currentTier = entries[entries.length - 1]?.tier || "unknown";
  const firstTime = new Date(Math.min(...entries.map((e) => e.timestamp)));
  const lastTime = new Date(Math.max(...entries.map((e) => e.timestamp)));
  const durationMs = lastTime.getTime() - firstTime.getTime();
  const durationStr = durationMs < 6e4 ? `${Math.round(durationMs / 1e3)}s` : durationMs < 36e5 ? `${Math.round(durationMs / 6e4)}m` : `${(durationMs / 36e5).toFixed(1)}h`;
  process.stdout.write(`
${bold("\u{1F6E1}\uFE0F Agent Daily Digest")}

`);
  process.stdout.write(`  \u{1F4CA} ${bold(String(entries.length))} actions | `);
  process.stdout.write(`${green("\u2713 " + allowed)} allowed | `);
  process.stdout.write(`${red("\u2717 " + denied)} blocked`);
  if (approvalRequired > 0) process.stdout.write(` | ${yellow("\u23F3 " + approvalRequired)} awaiting approval`);
  process.stdout.write(`
`);
  process.stdout.write(`  \u{1F3C5} Trust tier: ${bold(currentTier)} | \u23F1 Active: ${durationStr}

`);
  process.stdout.write(`  ${bold("Tools used:")}
`);
  for (const [tool, count] of sortedTools.slice(0, 8)) {
    process.stdout.write(`    ${tool.padEnd(22)} ${count}x
`);
  }
  if (denied > 0) {
    const deniedTools = entries.filter((e) => e.decision === "deny");
    const deniedToolNames = [...new Set(deniedTools.map((e) => e.tool))];
    process.stdout.write(`
  ${bold(red("Blocked tools:"))}
`);
    for (const tool of deniedToolNames) {
      const reason = deniedTools.find((e) => e.tool === tool)?.reason_code || "policy";
      process.stdout.write(`    ${red("\u2717")} ${tool} (${reason})
`);
    }
  }
  process.stdout.write(`
  ${dim("Latest receipt: curl -s http://127.0.0.1:9876/receipts/latest | jq -r .receipt > receipt.json")}
`);
  process.stdout.write(`  ${dim("Verify: npx @veritasacta/verify receipt.json --key <public-key-hex>")}
`);
  process.stdout.write(`  ${dim("Export: npx protect-mcp bundle --output audit.json")}

`);
}
async function handleReceipts2(argv) {
  const { readFileSync: readFileSync11, existsSync: existsSync10 } = await import("fs");
  const { join: join9 } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const lastIdx = argv.indexOf("--last");
  const count = lastIdx !== -1 && argv[lastIdx + 1] ? parseInt(argv[lastIdx + 1], 10) : 20;
  const receiptsPath = join9(dir, ".protect-mcp-receipts.jsonl");
  if (!existsSync10(receiptsPath)) {
    process.stderr.write(`${bold("protect-mcp receipts")}

No signed receipt file found. Run protect-mcp with signing enabled first.
`);
    process.exit(0);
  }
  const raw = readFileSync11(receiptsPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  const recent = lines.slice(-count);
  process.stdout.write(`
${bold("\u{1F6E1}\uFE0F Recent Receipts")} (last ${recent.length})

`);
  for (const line of recent) {
    try {
      const entry = JSON.parse(line);
      const payload = entry.payload || {};
      const time = typeof entry.issued_at === "string" ? new Date(entry.issued_at).toLocaleTimeString() : "unknown";
      const decision = payload.decision || "unknown";
      const icon = decision === "allow" ? green("\u2713") : decision === "require_approval" ? yellow("\u23F3") : red("\u2717");
      process.stdout.write(`  ${dim(time)} ${icon} ${String(payload.tool || "unknown").padEnd(22)} ${String(entry.type || "receipt").padEnd(18)} ${dim(String(payload.reason_code || "signed"))}
`);
    } catch {
    }
  }
  process.stdout.write(`
`);
}
var _pkgV = null;
async function pkgVersion() {
  if (_pkgV) return _pkgV;
  let v = "0.0.0";
  try {
    const { readFileSync: readFileSync11, existsSync: existsSync10, realpathSync } = await import("fs");
    const { dirname: dirname3, join: join9, resolve } = await import("path");
    let base = "";
    try {
      base = dirname3(realpathSync(resolve(process.argv[1] || "")));
    } catch {
    }
    const candidates = [
      base ? join9(base, "..", "package.json") : "",
      base ? join9(base, "package.json") : ""
    ].filter(Boolean);
    for (const p of candidates) {
      if (existsSync10(p)) {
        const parsed = JSON.parse(readFileSync11(p, "utf-8"));
        if (parsed && parsed.name === "protect-mcp" && parsed.version) {
          v = parsed.version;
          break;
        }
      }
    }
  } catch {
  }
  _pkgV = v;
  return v;
}
function mapRecordEntry(e) {
  const p = e && e.payload && typeof e.payload === "object" ? e.payload : e;
  const dec = String(p.decision || e.decision || "").toLowerCase();
  const verdict = /den|block|reject|refus/.test(dec) ? "blocked" : /ask|approv|hold|escal|review|pending/.test(dec) ? "held" : "allowed";
  const tsRaw = e.issued_at || e.timestamp || p.timestamp || p.issued_at;
  const ms = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "string" ? Date.parse(tsRaw) : NaN;
  const ts = isFinite(ms) ? new Date(ms).toISOString() : "";
  const tool = String(p.tool || e.tool || "action");
  const reason = String(p.reason_code || e.reason_code || p.policy_engine || "signed");
  const hook = String(p.hook_event || e.hook_event || "");
  const signed = !!(e.signature || e.sig || e.receipt_hash || typeof e.type === "string" && e.type.indexOf("receipt") >= 0);
  let digest = "";
  if (e.receipt_hash) digest = String(e.receipt_hash);
  else if (e.digest) digest = String(e.digest);
  else if (p.payload_digest && p.payload_digest.output_hash) digest = String(p.payload_digest.output_hash);
  const enr = p && typeof p.enrichment === "object" && p.enrichment || typeof e.enrichment === "object" && e.enrichment || null;
  const caps = enr && Array.isArray(enr.capabilities) ? enr.capabilities.map(String) : [];
  const sw = p && typeof p.swarm === "object" && p.swarm || null;
  const agent = sw && (sw.agent_name || sw.agent_id || sw.agent_type) ? String(sw.agent_name || sw.agent_id || sw.agent_type) : "main agent";
  const tm = p && typeof p.timing === "object" && p.timing || null;
  const dur = tm && typeof tm.tool_duration_ms === "number" ? tm.tool_duration_ms : 0;
  return { ts, tool, verdict, reason, hook, signed, caps, agent, dur, id: String(e.request_id || p.request_id || ""), digest, raw: e };
}
async function handleRecord(argv) {
  const { readFileSync: readFileSync11, existsSync: existsSync10, writeFileSync: writeFileSync5 } = await import("fs");
  const { join: join9 } = await import("path");
  const osMod = await import("os");
  const cp = await import("child_process");
  let dir = process.cwd();
  const di = argv.indexOf("--dir");
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  const recPath = join9(dir, ".protect-mcp-receipts.jsonl");
  const logPath = join9(dir, ".protect-mcp-log.jsonl");
  const pick = () => existsSync10(recPath) ? recPath : existsSync10(logPath) ? logPath : null;
  const chosen = pick();
  if (!chosen) {
    process.stderr.write(`
${bold("protect-mcp record")}

No record found in ${dir}.
Start the gate with ${bold("npx protect-mcp serve")}, use your agent, then run this again.
`);
    process.stderr.write(`Tip: run this in the directory where your gate is signing (where .protect-mcp-receipts.jsonl lives), or pass ${bold("--dir <path>")}.

`);
    process.exit(0);
    return;
  }
  const readRecs = (file) => readFileSync11(file, "utf-8").split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter((x) => x !== null).map(mapRecordEntry);
  let pinnedKey = "";
  let pinnedKid = "";
  try {
    const kd = JSON.parse(readFileSync11(join9(dir, "keys", "gateway.json"), "utf-8"));
    if (kd && typeof kd.publicKey === "string" && /^[0-9a-f]{64}$/i.test(kd.publicKey)) {
      pinnedKey = kd.publicKey;
      pinnedKid = typeof kd.kid === "string" ? kd.kid : "";
    }
  } catch {
  }
  const openTarget = (target) => {
    if (argv.includes("--no-open")) return;
    const platform = process.platform;
    const opener = platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
    const openArgs = platform === "win32" ? ["/c", "start", "", target] : [target];
    try {
      const child = cp.spawn(opener, openArgs, { stdio: "ignore", detached: true });
      child.unref();
    } catch {
    }
  };
  if (argv.includes("--live") || argv.includes("--watch")) {
    const http = await import("http");
    const pi = argv.indexOf("--port");
    const port = pi !== -1 && argv[pi + 1] ? parseInt(argv[pi + 1], 10) : 9378;
    const server = http.createServer((req, res) => {
      if (req.url && req.url.indexOf("/data") === 0) {
        let recs2 = [];
        const f = pick();
        try {
          if (f) recs2 = readRecs(f);
        } catch {
        }
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ recs: recs2, signed: f === recPath }));
        return;
      }
      const meta2 = { file: chosen, signed: pick() === recPath, count: 0, live: true, pinned_key: pinnedKey, pinned_kid: pinnedKid };
      const page = RECORD_HTML.replace("__DATA__", () => "[]").replace("__META__", () => JSON.stringify(meta2));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(page);
    });
    server.on("error", (e) => {
      process.stderr.write(`
protect-mcp record --live: could not start on port ${port}${e && e.code ? ` (${e.code})` : ""}. Try ${bold("--port <n>")}.

`);
      process.exit(1);
    });
    server.listen(port, "127.0.0.1", () => {
      const url = `http://127.0.0.1:${port}`;
      openTarget(url);
      process.stdout.write(`
${bold("\u{1F6E1}\uFE0F  Your record")} ${dim("\xB7")} live at ${url}
`);
      process.stdout.write(`  Updates as your agent runs. All local, nothing uploaded. ${dim("Ctrl-C to stop.")}

`);
    });
    return;
  }
  const recs = readRecs(chosen);
  const meta = { file: chosen, signed: chosen === recPath, count: recs.length, live: false, pinned_key: pinnedKey, pinned_kid: pinnedKid };
  const html = RECORD_HTML.replace("__DATA__", () => JSON.stringify(recs)).replace("__META__", () => JSON.stringify(meta));
  const out = join9(osMod.tmpdir(), "protect-mcp-record-" + Date.now() + ".html");
  writeFileSync5(out, html);
  openTarget(out);
  process.stdout.write(`
${bold("\u{1F6E1}\uFE0F  Your record")} ${dim("\xB7")} ${recs.length} decision${recs.length === 1 ? "" : "s"}, all on this machine
`);
  if (!meta.signed) process.stdout.write(`  ${dim("(decision log; signed receipts appear in .protect-mcp-receipts.jsonl once signing is on)")}
`);
  const fileUrl = "file://" + encodeURI(out);
  if (process.stdout.isTTY) {
    process.stdout.write(`  Opened in your browser. If it did not open, click: \x1B]8;;${fileUrl}\x1B\\${bold("your record")}\x1B]8;;\x1B\\
`);
  } else {
    process.stdout.write(`  Opened in your browser. If it did not open, open: ${out}
`);
  }
  process.stdout.write(`  ${dim("Want it to update live as your agent runs? npx protect-mcp record --live")}

`);
  process.exit(0);
}
var RECORD_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>protect-mcp record</title>
<style>
:root{--paper:#f6f4ef;--ink:#1b1815;--soft:#524d46;--faint:#8a837a;--line:#ddd7c9;--g:#3f6146;--gb:#e7eee3;--a:#8f6216;--ab:#f2e8d3;--r:#7d3535;--rb:#f2e0dc}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto;padding:26px 22px 60px}
h1{font-size:24px;margin:0 0 4px;letter-spacing:-.012em}
.meta{color:var(--faint);font-size:12.5px;font-family:ui-monospace,Menlo,Consolas,monospace;display:flex;align-items:center}
.pulse{width:7px;height:7px;border-radius:100px;background:var(--g);display:inline-block;margin-left:8px;animation:pl 1.6s ease-in-out infinite}
@keyframes pl{0%,100%{opacity:.3}50%{opacity:1}}
@media (prefers-reduced-motion:reduce){.pulse{animation:none}}
.stats{display:flex;gap:15px;flex-wrap:wrap;align-items:center;margin:14px 0 10px;font-size:13px}
.stat{display:flex;align-items:center;gap:6px;color:var(--soft)}
.stat b{color:var(--ink);font-weight:680}
.dot{width:8px;height:8px;border-radius:100px;display:inline-block}
.dot.g{background:var(--g)}.dot.a{background:var(--a)}.dot.r{background:var(--r)}
.stat.sig{margin-left:auto;color:var(--g);font-weight:600}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 16px}
.btn{cursor:pointer;font:inherit;font-size:12.5px;padding:7px 13px;border-radius:8px;border:1px solid var(--line);background:#fff;color:var(--ink);transition:border-color .12s}
.btn:hover{border-color:var(--ink)}
.btn.p{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.btn:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.vhint{font-size:12px;color:var(--faint);margin-left:auto;font-family:ui-monospace,Menlo,monospace}
.attest{margin:0 0 12px;font-size:12.5px;color:var(--soft);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cmd{font-family:ui-monospace,Menlo,monospace;font-size:12px;background:#efece4;border:1px solid var(--line);border-radius:6px;padding:3px 8px;color:var(--ink)}
.btn2{cursor:pointer;font:inherit;font-size:12px;padding:4px 9px;border-radius:7px;border:1px solid var(--line);background:#fff;color:var(--ink)}
.btn2:hover{border-color:var(--ink)}
.bar{margin:6px 0 12px}
input{width:100%;padding:10px 13px;border:1px solid var(--line);border-radius:9px;background:#fff;font:inherit}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.chip{cursor:pointer;font-size:12px;padding:3px 10px;border-radius:100px;border:1px solid var(--line);background:#fff;color:var(--soft)}
.chip.on{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.count{color:var(--faint);font-size:12px;font-family:ui-monospace,Menlo,monospace;margin-bottom:8px}
.row{border:1px solid var(--line);border-radius:9px;background:#fcfbf7;padding:11px 13px;margin-bottom:8px;cursor:pointer}
.row.blocked{background:#fbf3f0}.row.held{background:#fbf7ee}
.top{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.pill{font-size:11px;font-weight:600;padding:2px 9px;border-radius:100px}
.pill.allowed{background:var(--gb);color:var(--g)}.pill.held{background:var(--ab);color:var(--a)}.pill.blocked{background:var(--rb);color:var(--r)}
.tag{font-size:11px;padding:1px 7px;border-radius:100px;background:var(--paper);border:1px solid var(--line);color:var(--faint)}
.cap{font-size:10px;padding:1px 6px;border-radius:100px;background:#eef0ea;border:1px solid var(--line);color:var(--soft)}
.badge{font-size:10.5px;font-weight:600;padding:1px 7px;border-radius:100px}
.badge.sgn{background:var(--gb);color:var(--g)}
.badge.log{background:var(--paper);color:var(--faint);border:1px solid var(--line)}
.badge.vbad{background:#fbecec;color:#b3382f;border:1px solid #edc6c2}
.badge.vfor{background:#fbf3df;color:#8a6d1a;border:1px solid #e8d8ae}
.stat .badk{color:#b3382f;font-weight:680}.stat .warnk{color:#8a6d1a}.stat .dim2{color:var(--faint);font-weight:400}
.dg{font-size:10.5px;color:var(--faint);font-family:ui-monospace,Menlo,monospace}
.when{margin-left:auto;font-size:12px;color:var(--faint);font-family:ui-monospace,Menlo,monospace}
.det{margin-top:8px;padding-top:8px;border-top:1px solid var(--line);font-size:12px;color:var(--soft);font-family:ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-all;display:none}
.row.open .det{display:block}
.foot{margin-top:22px;color:var(--faint);font-size:12px;line-height:1.6;border-top:1px solid var(--line);padding-top:14px}
.foot b{color:var(--soft)}
.viewtoggle{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.viewtoggle button{border:0;background:#fff;color:var(--soft);font:inherit;font-size:12.5px;padding:7px 12px;cursor:pointer}
.viewtoggle button.on{background:var(--ink);color:var(--paper)}
.agent{border:1px solid var(--line);border-radius:10px;background:#fcfbf7;margin-bottom:10px;overflow:hidden}
.ahead{display:flex;gap:9px;align-items:center;flex-wrap:wrap;padding:11px 13px;cursor:pointer}
.atwist{color:var(--faint);font-size:11px;transition:transform .12s;display:inline-block}
.agent.open .atwist{transform:rotate(90deg)}
.acount{font-size:12px;color:var(--faint)}
.akids{display:none;padding:2px 12px 12px 24px;border-top:1px solid var(--line)}
.agent.open .akids{display:block}
.act{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:9px 4px;cursor:pointer;border-bottom:1px solid var(--line)}
.akids .act:last-child{border-bottom:0}
.act:hover{background:rgba(0,0,0,.02)}
.act.blocked{background:#fbf3f0}.act.held{background:#fbf7ee}
.act .det{flex-basis:100%}
.act.open .det{display:block}
.ev{display:flex;gap:8px;align-items:center;font-size:12px;color:var(--faint);padding:5px 10px;margin-top:6px}
.evdot{width:6px;height:6px;border-radius:100px;background:var(--faint);display:inline-block}
.evre{color:var(--soft)}
.badge.blk{background:var(--rb);color:var(--r)}
</style></head><body><div class="wrap">
<h1>Your record</h1>
<div class="meta"><span id="meta"></span><span id="live"></span></div>
<div class="stats" id="stats"></div>
<div class="actions">
<div class="viewtoggle"><button id="vlist" class="on" onclick="setView('list')">List</button><button id="vtree" onclick="setView('tree')">Tree</button></div>
<button class="btn p" onclick="exportJsonl()">Export receipts (.jsonl)</button>
<button class="btn" onclick="exportMd()">Export report (.md)</button>
<button class="btn" id="cpv" onclick="copyVerify()">Copy verify command</button>
<span class="vhint">verify offline: npx @veritasacta/verify</span>
</div>
<div class="bar"><input id="q" placeholder="Search your record: tool, reason, verdict"></div>
<div class="chips" id="chips"></div>
<div class="count" id="count"></div>
<div class="attest" id="attest"></div>
<div id="list"></div>
<div class="foot">Signed decisions from your own gate, on this machine. Nothing was uploaded. Each row is Ed25519-signed, and the exports carry the signatures, so anyone you hand them to (an allocator, an auditor, a counterparty) verifies offline with <b>npx @veritasacta/verify</b>, our code removed. For a Merkle-rooted evidence pack: <b>npx protect-mcp bundle</b>. To prove a claim over this record without revealing it (e.g. no egress): <b>npx protect-mcp claim --no net.egress</b>, checked offline with <b>npx protect-mcp verify-claim</b>. protect-mcp governs proposed actions before they run.</div>
</div>
<script>
var RECORDS=__DATA__;var META=__META__;var Q="",ACT={},VIEW="list",OPEN={};var NL=String.fromCharCode(10);
// In-browser signature verification. Mirrors @veritasacta/artifacts exactly:
// preimage = JCS-style canonical JSON (sorted keys) of the receipt minus its
// signature, verified with WebCrypto Ed25519. Pinned key (your keys/gateway.json
// public half, injected by the CLI) = authenticity; key embedded in the receipt
// payload (0.9.3+) = self-consistency. Everything runs locally.
var VSTATE={},VDONE=false,VBUSY=false,VUNSUP=false;
function vkey(r){return "row:"+(r.id||"")+"|"+(r.ts||"")}
function hexb(h){h=String(h||"");var a=new Uint8Array(h.length>>1);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a}
function canon(v){return JSON.stringify(v,function(k,x){if(x&&typeof x==="object"&&!Array.isArray(x)){var s={},ks=Object.keys(x).sort();for(var i=0;i<ks.length;i++)s[ks[i]]=x[ks[i]];return s}return x})}
async function edv(sig,msg,pub){var key=await crypto.subtle.importKey("raw",hexb(pub),{name:"Ed25519"},false,["verify"]);return crypto.subtle.verify({name:"Ed25519"},key,hexb(sig),msg)}
async function verifyRow(r){var raw=r.raw;if(!raw||typeof raw.signature!=="string")return"unsigned";
var rest={},k;for(k in raw)if(k!=="signature")rest[k]=raw[k];
var msg=new TextEncoder().encode(canon(rest));
var pin=String(META.pinned_key||"").toLowerCase();
var emb=String((raw.payload&&raw.payload.public_key)||raw.public_key||"").toLowerCase();
if(!/^[0-9a-f]{64}$/.test(emb))emb="";
if(pin){if(await edv(raw.signature,msg,pin))return"ok";if(emb&&emb!==pin&&await edv(raw.signature,msg,emb))return"foreign";return"bad"}
if(emb)return(await edv(raw.signature,msg,emb))?"ok":"bad";
return"nokey"}
function vsum(){var s={ok:0,bad:0,foreign:0,nokey:0};RECORDS.forEach(function(r){if(!r.signed)return;var v=VSTATE[vkey(r)];if(v&&s[v]!==undefined)s[v]++});return s}
async function kickVerify(){if(VBUSY||VUNSUP||!(window.crypto&&crypto.subtle))return;VBUSY=true;
try{var rows=RECORDS.slice(0,1500);for(var i=0;i<rows.length;i++){var r=rows[i],kk=vkey(r);if(VSTATE[kk])continue;
try{VSTATE[kk]=await verifyRow(r)}catch(e){if(e&&e.name==="NotSupportedError"){VUNSUP=true;break}VSTATE[kk]="bad"}}}
finally{VDONE=true;VBUSY=false;render()}}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
function vlabel(v){return v==="allowed"?"Allowed":v==="held"?"Held":"Blocked"}
function when(ts){if(!ts)return"";var d=new Date(ts);return d.toLocaleDateString(undefined,{month:"short",day:"numeric"})+" "+d.toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit"})}
function counts(rows){var c={allowed:0,held:0,blocked:0,signed:0};rows.forEach(function(r){c[r.verdict]=(c[r.verdict]||0)+1;if(r.signed)c.signed++});return c}
function fvals(key){var m={};RECORDS.forEach(function(r){var vs=key==="Decision"?[vlabel(r.verdict)]:(key==="Capability"?(r.caps||[]):[r[key.toLowerCase()]]);vs.forEach(function(v){if(v){m[v]=(m[v]||0)+1}})});return Object.keys(m).sort(function(a,b){return m[b]-m[a]}).slice(0,10).map(function(v){return[v,m[v]]})}
function match(r){if(ACT.Decision&&vlabel(r.verdict)!==ACT.Decision)return false;if(ACT.Tool&&r.tool!==ACT.Tool)return false;if(ACT.Reason&&r.reason!==ACT.Reason)return false;if(ACT.Capability&&(r.caps||[]).indexOf(ACT.Capability)<0)return false;if(Q){var h=(r.tool+" "+r.reason+" "+vlabel(r.verdict)+" "+r.hook+" "+(r.caps||[]).join(" ")).toLowerCase();if(h.indexOf(Q)<0)return false}return true}
function filtered(){return RECORDS.filter(match)}
function dl(name,text,type){var b=new Blob([text],{type:type||"text/plain"});var u=URL.createObjectURL(b);var a=document.createElement("a");a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(u)},1500)}
function stamp(){return new Date().toISOString().replace(/[:.]/g,"-").slice(0,19)}
function exportJsonl(){var rows=filtered();if(!rows.length)return;var lines=rows.map(function(r){return JSON.stringify(r.raw||r)}).join(NL);dl("protect-mcp-record-"+stamp()+".jsonl",lines,"application/x-ndjson")}
function exportMd(){var rows=filtered();if(!rows.length)return;var c=counts(rows);var head=["# Agent decision record","",rows.length+" decisions from "+META.file,c.allowed+" allowed, "+c.held+" held, "+c.blocked+" blocked, "+c.signed+" signed.","","Generated locally by protect-mcp. These are signed receipts; verify offline with npx @veritasacta/verify (our code removed).","","| When | Decision | Tool | Reason | Hook | Signed |","|---|---|---|---|---|---|"];var body=rows.slice(0,3000).map(function(r){return "| "+(r.ts||"")+" | "+vlabel(r.verdict)+" | "+String(r.tool||"").replace(/\\|/g,"/")+" | "+String(r.reason||"").replace(/\\|/g,"/")+" | "+(r.hook||"")+" | "+(r.signed?"yes":"no")+" |"});dl("protect-mcp-record-"+stamp()+".md",head.concat(body).join(NL)+NL,"text/markdown")}
function copyAttest(){var a=document.getElementById("attest");var cmd=a?a.getAttribute("data-cmd"):"";try{navigator.clipboard&&cmd&&navigator.clipboard.writeText(cmd)}catch(e){}var b=document.getElementById("cpa");if(b){var t=b.textContent;b.textContent="Copied";setTimeout(function(){b.textContent=t},1200)}}
function copyVerify(){var cmd="npx @veritasacta/verify";try{navigator.clipboard&&navigator.clipboard.writeText(cmd)}catch(e){}var b=document.getElementById("cpv");if(b){var t=b.textContent;b.textContent="Copied";setTimeout(function(){b.textContent=t},1200)}}
function renderStats(){var c=counts(RECORDS);var p=[];p.push('<span class="stat"><b>'+RECORDS.length+'</b> decisions</span>');p.push('<span class="stat"><span class="dot g"></span>'+c.allowed+' allowed</span>');if(c.held)p.push('<span class="stat"><span class="dot a"></span>'+c.held+' held</span>');p.push('<span class="stat"><span class="dot r"></span>'+c.blocked+' blocked</span>');var st;if(!c.signed){st='0 signed, verifiable offline'}else if(VUNSUP||!(window.crypto&&crypto.subtle)){st=c.signed+' signed, verifiable offline <span class="dim2">(in-browser check unavailable here; run npx protect-mcp receipts)</span>'}else if(!VDONE){st=c.signed+' signed \xB7 verifying in your browser\u2026'}else{var s=vsum();st=s.ok+' of '+c.signed+' signatures verified in your browser';if(s.foreign)st+=' <span class="warnk">\xB7 '+s.foreign+' signed by an unpinned key</span>';if(s.bad)st+=' <span class="badk">\xB7 '+s.bad+' INVALID</span>';if(s.nokey)st+=' <span class="dim2">\xB7 '+s.nokey+' need a key to check</span>'}
p.push('<span class="stat sig">'+st+'</span>');document.getElementById("stats").innerHTML=p.join("")}
function renderList(rows){var html="";rows.slice(0,800).forEach(function(r){var vs=VSTATE[vkey(r)];var sig=!r.signed?'<span class="badge log">log</span>':vs==="ok"?'<span class="badge sgn">\u2713 verified</span>':vs==="bad"?'<span class="badge vbad">\u2717 invalid signature</span>':vs==="foreign"?'<span class="badge vfor">signed \xB7 unpinned key</span>':'<span class="badge sgn">signed</span>';var dg=r.digest?'<span class="dg">'+esc(String(r.digest).slice(0,10))+'</span>':'';var ct=(r.caps||[]).map(function(c){return '<span class="cap">'+esc(c)+'</span>'}).join('');var rk="row:"+(r.id||"")+"|"+(r.ts||"");html+='<div class="row '+r.verdict+(OPEN[rk]?" open":"")+'" data-k="'+esc(rk)+'"><div class="top"><span class="pill '+r.verdict+'">'+vlabel(r.verdict)+"</span><b>"+esc(r.tool)+'</b><span class="tag">'+esc(r.reason)+"</span>"+ct+(r.hook?'<span class="tag">'+esc(r.hook)+"</span>":"")+sig+dg+'<span class="when">'+esc(when(r.ts))+'</span></div><div class="det">'+esc(JSON.stringify(r.raw||r,null,2))+"</div></div>"});document.getElementById("list").innerHTML=html||'<p style="color:#8a837a">No records match.</p>';}
function isLifecycle(r){var h=r.hook||"";return h==="SessionStart"||h==="SessionEnd"||h==="Stop"||h==="SubagentStart"||h==="SubagentStop"||h==="TaskCreated"||h==="TaskCompleted"||h==="ConfigChange"||h==="Notification"||h==="PreCompact";}
function buildTree(rows){var ags={},order=[];rows.forEach(function(r){var a=r.agent||"main agent";if(!ags[a]){ags[a]={name:a,byId:{},items:[],caps:{},blocked:0,actions:0};order.push(a);}var g=ags[a];(r.caps||[]).forEach(function(c){g.caps[c]=(g.caps[c]||0)+1;});if(isLifecycle(r)){g.items.push({t:"e",ts:r.ts,r:r});return;}var id=r.id||("_"+r.ts);var n=g.byId[id];if(!n){n={t:"a",id:id,tool:r.tool,verdict:r.verdict,caps:(r.caps||[]).slice(),ts:r.ts,dur:0,signed:!!r.signed,raw:r.raw};g.byId[id]=n;g.items.push(n);g.actions++;}if(r.hook==="PostToolUse"){if(r.dur)n.dur=r.dur;if(!n.raw)n.raw=r.raw;}else{n.verdict=r.verdict;if((r.caps||[]).length)n.caps=r.caps.slice();n.raw=r.raw;n.ts=r.ts;}if(r.signed)n.signed=true;});order.forEach(function(a){var g=ags[a];g.blocked=g.items.filter(function(it){return it.t==="a"&&it.verdict==="blocked";}).length;g.items.sort(function(x,y){return (x.ts<y.ts)?-1:1;});});return order.map(function(a){return ags[a];});}
function renderTree(ags){if(!ags.length){document.getElementById("list").innerHTML='<p style="color:#8a837a">No records match.</p>';return;}var html="",N=0;ags.forEach(function(g,gi){var capstr=Object.keys(g.caps).sort(function(a,b){return g.caps[b]-g.caps[a];}).slice(0,5).map(function(c){return '<span class="cap">'+esc(c)+'</span>';}).join('');var ak="ag:"+g.name;var op=(OPEN.hasOwnProperty(ak)?OPEN[ak]:(ags.length===1||gi===0))?" open":"";html+='<div class="agent'+op+'" data-k="'+esc(ak)+'"><div class="ahead"><span class="atwist">\u25B8</span><b>'+esc(g.name)+'</b><span class="acount">'+g.actions+' action'+(g.actions===1?'':'s')+'</span>'+(g.blocked?'<span class="badge blk">'+g.blocked+' blocked</span>':'')+capstr+'</div><div class="akids">';g.items.forEach(function(it){if(N++>1500)return;if(it.t==="e"){var r=it.r;html+='<div class="ev"><span class="evdot"></span>'+esc(r.hook||r.tool)+' <span class="evre">'+esc(r.reason)+'</span><span class="when">'+esc(when(r.ts))+'</span></div>';}else{var ct=(it.caps||[]).map(function(c){return '<span class="cap">'+esc(c)+'</span>';}).join('');var dur=it.dur?'<span class="dg">'+it.dur+'ms</span>':'';var ik="act:"+it.id;html+='<div class="act '+it.verdict+(OPEN[ik]?" open":"")+'" data-k="'+esc(ik)+'"><span class="pill '+it.verdict+'">'+vlabel(it.verdict)+'</span><b>'+esc(it.tool)+'</b>'+ct+(it.signed?'<span class="badge sgn">signed</span>':'')+dur+'<span class="when">'+esc(when(it.ts))+'</span><div class="det">'+esc(JSON.stringify(it.raw||{},null,2))+'</div></div>';}});html+='</div></div>';});if(N>1500)html+='<p style="color:#8a837a;font-size:12px;margin-top:10px">Showing the first 1500 items. Search or pick a facet to narrow.</p>';document.getElementById("list").innerHTML=html;}
function setView(v){VIEW=v;document.getElementById("vlist").className=v==="list"?"on":"";document.getElementById("vtree").className=v==="tree"?"on":"";render();}
function render(){
document.getElementById("meta").textContent=META.count+" decisions from "+META.file+(META.signed?" (signed)":" (decision log)")+" - all local"+(META.live?" \xB7 live, updating":"");
document.getElementById("live").innerHTML=META.live?'<span class="pulse"></span>':"";
renderStats();
var chips="";["Decision","Tool","Reason","Capability"].forEach(function(key){fvals(key).forEach(function(p){var on=ACT[key]===p[0];chips+='<span class="chip'+(on?" on":"")+'" data-k="'+key+'" data-v="'+esc(p[0])+'">'+esc(p[0])+" "+p[1]+"</span>"})});
document.getElementById("chips").innerHTML=chips;
var rows=RECORDS.filter(match);
document.getElementById("count").textContent=rows.length+" of "+RECORDS.length+" records"+(VIEW==="tree"?" \xB7 grouped by agent":"");
var _at=document.getElementById("attest");if(ACT.Capability){var _cmd="npx protect-mcp claim --no "+ACT.Capability;_at.setAttribute("data-cmd",_cmd);_at.innerHTML='Prove it over this record, revealing nothing: <span class="cmd">'+esc(_cmd)+'</span><button class="btn2" id="cpa" onclick="copyAttest()">Copy</button>';}else{_at.innerHTML="";_at.removeAttribute("data-cmd");}
if(VIEW==="tree"){renderTree(buildTree(rows));}else{renderList(rows);}}
document.getElementById("q").addEventListener("input",function(e){Q=e.target.value.toLowerCase().trim();render()});
document.getElementById("chips").addEventListener("click",function(e){var c=e.target.closest(".chip");if(!c)return;var k=c.getAttribute("data-k"),v=c.getAttribute("data-v");ACT[k]=ACT[k]===v?undefined:v;render()});
document.getElementById("list").addEventListener("click",function(e){var ah=e.target.closest(".ahead");if(ah){var ag=ah.parentNode;ag.classList.toggle("open");var ak=ag.getAttribute("data-k");if(ak)OPEN[ak]=ag.classList.contains("open");return;}var el=e.target.closest(".act")||e.target.closest(".row");if(el){el.classList.toggle("open");var k=el.getAttribute("data-k");if(k)OPEN[k]=el.classList.contains("open");}});
render();kickVerify();
if(META.live){var poll=function(){fetch('/data',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){var nr=d.recs||[];var changed=nr.length!==RECORDS.length;RECORDS=nr;META.count=RECORDS.length;if(typeof d.signed==='boolean')META.signed=d.signed;if(changed){render();kickVerify()}}).catch(function(){})};poll();setInterval(poll,2000);}
</script></body></html>`;
async function handleClaim(argv) {
  const { readFileSync: readFileSync11, existsSync: existsSync10, writeFileSync: writeFileSync5 } = await import("fs");
  const { join: join9 } = await import("path");
  const { buildClaim: buildClaim2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
  let dir = process.cwd();
  const di = argv.indexOf("--dir");
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  let predicate = null;
  const noIdx = argv.indexOf("--no"), onlyIdx = argv.indexOf("--only"), nvIdx = argv.indexOf("--no-verdict"), cvIdx = argv.indexOf("--count"), puIdx = argv.indexOf("--payment-under");
  if (noIdx !== -1 && argv[noIdx + 1]) predicate = { kind: "no_capability", capability: argv[noIdx + 1] };
  else if (onlyIdx !== -1 && argv[onlyIdx + 1]) predicate = { kind: "only_capabilities", capabilities: argv[onlyIdx + 1].split(",").map((s) => s.trim()).filter(Boolean) };
  else if (nvIdx !== -1 && argv[nvIdx + 1]) predicate = { kind: "no_verdict", verdict: argv[nvIdx + 1] };
  else if (cvIdx !== -1 && argv[cvIdx + 1]) predicate = { kind: "count_verdict", verdict: argv[cvIdx + 1] };
  else if (puIdx !== -1 && argv[puIdx + 1] && isFinite(parseFloat(argv[puIdx + 1]))) predicate = { kind: "payment_under", cap: parseFloat(argv[puIdx + 1]) };
  if (!predicate) {
    process.stderr.write(`
${bold("protect-mcp claim")}

Attest a signed, position-blind claim over your record:
  --no <capability>        no action used it, e.g. ${dim("--no net.egress")} or ${dim("--no payment")}
  --only <c1,c2,...>       all actions confined to these capabilities
  --no-verdict <verdict>   e.g. ${dim("--no-verdict blocked")}
  --count <verdict>        how many, e.g. ${dim("--count blocked")}
  --payment-under <cap>    every agent payment stayed under the cap (amounts the
                           gate could not read count as OVER, so this cannot lie)
  --anchor                 also record the claim digest in the public append-only
                           log so a counterparty can trust it is complete (only the
                           hash is sent; your record stays local)

Example: ${bold("npx protect-mcp claim --no net.egress --anchor")}

`);
    process.exit(0);
    return;
  }
  const keyPath = join9(dir, "keys", "gateway.json");
  if (!existsSync10(keyPath)) {
    process.stderr.write(`
${bold("protect-mcp claim")}

No signing key at ${keyPath}. A claim must be signed. Run ${bold("npx protect-mcp init")} first.

`);
    process.exit(1);
    return;
  }
  let key;
  try {
    key = JSON.parse(readFileSync11(keyPath, "utf-8"));
  } catch {
    process.stderr.write(`
protect-mcp claim: ${keyPath} is not valid JSON.

`);
    process.exit(1);
    return;
  }
  if (!key.privateKey || !key.publicKey) {
    process.stderr.write(`
protect-mcp claim: ${keyPath} is missing privateKey/publicKey.

`);
    process.exit(1);
    return;
  }
  const recPath = join9(dir, ".protect-mcp-receipts.jsonl");
  if (!existsSync10(recPath)) {
    process.stderr.write(`
${bold("protect-mcp claim")}

No signed receipts in ${dir}. Run the gate with signing on, then try again.

`);
    process.exit(0);
    return;
  }
  const receipts = readFileSync11(recPath, "utf-8").split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter((x) => x !== null);
  if (!receipts.length) {
    process.stderr.write(`
protect-mcp claim: no readable receipts in ${recPath}.

`);
    process.exit(0);
    return;
  }
  const pack = buildClaim2(receipts, predicate, { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || "gateway", issuer: "protect-mcp" }, (/* @__PURE__ */ new Date()).toISOString());
  const oi = argv.indexOf("--output");
  const out = oi !== -1 && argv[oi + 1] ? argv[oi + 1] : join9(dir, "claim-" + Date.now() + ".json");
  writeFileSync5(out, JSON.stringify(pack, null, 2) + "\n");
  process.stdout.write(`
${bold("\u{1F6E1}\uFE0F  Signed claim")}
`);
  process.stdout.write(`  ${pack.claim.statement}: ${pack.claim.holds ? green("holds") : yellow("does not hold")}  ${dim("(" + pack.claim.matched + " matched of " + pack.scope.total + " decisions)")}
`);
  process.stdout.write(`  ${dim("Position-blind: reveals decision categories, never tool inputs, outputs, or data. Ed25519-signed.")}
`);
  process.stdout.write(`  Written to ${out}
`);
  process.stdout.write(`  Hand it to anyone. They verify offline: ${bold("npx protect-mcp verify-claim " + out)}
`);
  if (argv.indexOf("--anchor") !== -1) {
    const { anchorClaim: anchorClaim2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
    const li = argv.indexOf("--log");
    const logBase = li !== -1 && argv[li + 1] ? argv[li + 1] : void 0;
    process.stdout.write(`
  ${dim("Anchoring the claim digest to the public append-only log (only the hash leaves your machine)...")}
`);
    const res = await anchorClaim2(
      pack,
      { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || "gateway", issuer: "protect-mcp" },
      { log: logBase, issuedAt: (/* @__PURE__ */ new Date()).toISOString() }
    );
    if (res.ok) {
      const sidecar = out.replace(/\.json$/, "") + ".anchor.json";
      writeFileSync5(sidecar, JSON.stringify({ log: logBase || "https://scopeblind.com", seq: res.seq, entry_url: res.entry_url, anchored_at: res.anchored_at, claim_digest: res.claim_digest, envelope: res.envelope }, null, 2) + "\n");
      process.stdout.write(`  ${green("Anchored")} as log entry ${bold("#" + res.seq)}${res.already_anchored ? dim(" (already present)") : ""}  ${dim(res.entry_url || "")}
`);
      process.stdout.write(`  ${dim("A counterparty can now confirm this exact claim existed at " + (res.anchored_at || "this time") + " and cannot be quietly re-cut.")}
`);
      process.stdout.write(`  ${dim("Anchor record written to " + sidecar + ". Only the digest was sent; your record stayed local.")}
`);
      const { lookupPinnedIdentity: lookupPinnedIdentity2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
      const who = await lookupPinnedIdentity2(key.publicKey, { log: logBase });
      if (who && who.found && !who.revoked) {
        process.stdout.write(`  ${green("Identity:")} anchored as ${bold(who.name || who.slug || "enrolled org")} ${dim("(key pinned in the ScopeBlind directory" + (who.enrolled_at ? ", enrolled " + who.enrolled_at.slice(0, 10) : "") + ")")}
`);
      } else if (who && who.found && who.revoked) {
        process.stdout.write(`  ${red("Identity: this key is REVOKED in the ScopeBlind directory.")}
`);
      } else {
        process.stdout.write(`  ${dim("Identity: anonymous (key not enrolled). To anchor as a named org a counterparty can pin, see")} ${bold("scopeblind.com/enroll")}
`);
      }
    } else {
      process.stdout.write(`  ${yellow("Anchor skipped")} ${dim("(" + (res.error || "unavailable") + "). The claim above is complete and verifiable offline without it.")}
`);
    }
  }
  process.stdout.write(`
`);
  process.exit(0);
}
async function handleAnchorRecord(argv) {
  const { readFileSync: readFileSync11, existsSync: existsSync10, appendFileSync: appendFileSync3 } = await import("fs");
  const { join: join9 } = await import("path");
  const { anchorRecordCheckpoint: anchorRecordCheckpoint2, buildRecordCheckpoint: buildRecordCheckpoint2, lookupPinnedIdentity: lookupPinnedIdentity2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
  let dir = process.cwd();
  const di = argv.indexOf("--dir");
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  const li = argv.indexOf("--log");
  const logBase = li !== -1 && argv[li + 1] ? argv[li + 1] : void 0;
  const keyPath = join9(dir, "keys", "gateway.json");
  if (!existsSync10(keyPath)) {
    process.stderr.write(`
${bold("protect-mcp anchor-record")}

No signing key at ${keyPath}. A checkpoint must be signed. Run ${bold("npx protect-mcp init")} first.

`);
    process.exit(1);
    return;
  }
  let key;
  try {
    key = JSON.parse(readFileSync11(keyPath, "utf-8"));
  } catch {
    process.stderr.write(`
protect-mcp anchor-record: ${keyPath} is not valid JSON.

`);
    process.exit(1);
    return;
  }
  if (!key.privateKey || !key.publicKey) {
    process.stderr.write(`
protect-mcp anchor-record: ${keyPath} is missing privateKey/publicKey.

`);
    process.exit(1);
    return;
  }
  const recPath = join9(dir, ".protect-mcp-receipts.jsonl");
  if (!existsSync10(recPath)) {
    process.stderr.write(`
${bold("protect-mcp anchor-record")}

No signed receipts in ${dir}. Run the gate with signing on, then try again.

`);
    process.exit(0);
    return;
  }
  const receipts = readFileSync11(recPath, "utf-8").split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter((x) => x !== null);
  if (!receipts.length) {
    process.stderr.write(`
protect-mcp anchor-record: no readable receipts in ${recPath}.

`);
    process.exit(0);
    return;
  }
  const claimKey = { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || "gateway", issuer: "protect-mcp" };
  const historyPath = join9(dir, ".protect-mcp-anchors.jsonl");
  const preview = buildRecordCheckpoint2(receipts, claimKey, "preview");
  if (!argv.includes("--force") && existsSync10(historyPath)) {
    const lines = readFileSync11(historyPath, "utf-8").split(/\r?\n/).filter(Boolean);
    const last = lines.length ? (() => {
      try {
        return JSON.parse(lines[lines.length - 1]);
      } catch {
        return null;
      }
    })() : null;
    if (last && last.record_root === preview.record_root && last.total === preview.total) {
      process.stdout.write(`
${bold("\u{1F6E1}\uFE0F  Record checkpoint")}
`);
      process.stdout.write(`  Unchanged since entry ${bold("#" + last.seq)} ${dim("(" + last.total + " receipts, anchored " + (last.anchored_at || "") + ")")}. Nothing new to anchor.
`);
      process.stdout.write(`  ${dim("Use --force to re-anchor anyway.")}

`);
      process.exit(0);
      return;
    }
  }
  const res = await anchorRecordCheckpoint2(receipts, claimKey, { log: logBase, issuedAt: (/* @__PURE__ */ new Date()).toISOString() });
  process.stdout.write(`
${bold("\u{1F6E1}\uFE0F  Record checkpoint")}
`);
  process.stdout.write(`  ${res.total} receipts ${dim("\xB7")} root ${dim(res.record_root.slice(0, 16) + "\u2026")} ${dim("(" + res.checkpoint.from.slice(0, 10) + " \u2192 " + res.checkpoint.to.slice(0, 10) + ")")}
`);
  if (!res.ok) {
    process.stdout.write(`  ${yellow("Anchor failed")} ${dim("(" + (res.error || "unavailable") + "). Nothing was recorded; try again.")}

`);
    process.exit(1);
    return;
  }
  appendFileSync3(historyPath, JSON.stringify({ schema: res.checkpoint.schema, seq: res.seq, anchored_at: res.anchored_at, total: res.total, record_root: res.record_root, entry_url: res.entry_url, digest: res.checkpoint.digest }) + "\n");
  process.stdout.write(`  ${green("Anchored")} as log entry ${bold("#" + res.seq)}  ${dim(res.entry_url || "")}
`);
  process.stdout.write(`  ${dim("Only the root, count, and time range were sent. History: " + historyPath)}
`);
  const who = await lookupPinnedIdentity2(claimKey.publicKey, { log: logBase });
  if (who && who.found && !who.revoked) {
    process.stdout.write(`  ${green("Identity:")} anchored as ${bold(who.name || who.slug || "enrolled org")} ${dim("(key pinned in the ScopeBlind directory)")}
`);
  } else if (who && who.found && who.revoked) {
    process.stdout.write(`  ${red("Identity: this key is REVOKED in the ScopeBlind directory.")}
`);
  } else {
    process.stdout.write(`  ${dim("Identity: anonymous (key not enrolled). Named identity: scopeblind.com/enroll")}
`);
  }
  process.stdout.write(`  ${dim("A claim whose commitment matches this root is provably over the complete record as of")}
`);
  process.stdout.write(`  ${dim("this checkpoint. Run this on a heartbeat (e.g. cron) to keep the anchored history growing.")}

`);
  process.exit(0);
}
async function handleVerifyClaim(argv) {
  const { readFileSync: readFileSync11, existsSync: existsSync10 } = await import("fs");
  const { verifyClaim: verifyClaim2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
  const file = argv.find((a) => !a.startsWith("--"));
  if (!file || !existsSync10(file)) {
    process.stderr.write(`
${bold("protect-mcp verify-claim")} <claim.json> [--key <public-hex>]

Provide a claim pack file.

`);
    process.exit(2);
    return;
  }
  let pack;
  try {
    pack = JSON.parse(readFileSync11(file, "utf-8"));
  } catch {
    process.stderr.write(`
protect-mcp verify-claim: ${file} is not valid JSON.

`);
    process.exit(2);
    return;
  }
  if (!pack || pack.type !== "scopeblind.claim.v1") {
    process.stderr.write(`
protect-mcp verify-claim: not a scopeblind.claim.v1 pack.

`);
    process.exit(2);
    return;
  }
  const ki = argv.indexOf("--key");
  const v = verifyClaim2(pack, ki !== -1 ? argv[ki + 1] : void 0);
  const ok = (b) => b ? green("\u2713") : red("\u2717");
  process.stdout.write(`
${bold("protect-mcp verify-claim")}
`);
  process.stdout.write(`  Claim:      ${pack.claim ? pack.claim.statement : "(none)"}
`);
  process.stdout.write(`  Holds:      ${v.holds ? green("yes") : yellow("no")}  ${dim("(" + v.matched + " matched of " + v.total + " decisions)")}
`);
  process.stdout.write(`  Signature:  ${ok(v.authentic)} ${v.authentic ? "valid" : "INVALID"}  ${dim("issuer kid " + (pack.issuer && pack.issuer.kid || "?"))}
`);
  process.stdout.write(`  Commitment: ${ok(v.root_ok)} ${v.root_ok ? "Merkle root matches the " + v.total + " disclosed decisions" : "MISMATCH"}
`);
  process.stdout.write(`  Predicate:  ${ok(v.predicate_ok)} ${v.predicate_ok ? "recomputed independently and matches" : "MISMATCH"}
`);
  const ai = argv.indexOf("--anchor-file");
  const sidecarPath = ai !== -1 && argv[ai + 1] ? argv[ai + 1] : file.replace(/\.json$/, "") + ".anchor.json";
  const requireAnchor = argv.includes("--check-anchor");
  let anchorOk = true;
  if (existsSync10(sidecarPath)) {
    const { checkClaimAnchor: checkClaimAnchor2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
    let sidecar = null;
    try {
      sidecar = JSON.parse(readFileSync11(sidecarPath, "utf-8"));
    } catch {
    }
    if (!sidecar) {
      anchorOk = false;
      process.stdout.write(`  Anchor:     ${red("\u2717")} ${sidecarPath} is not valid JSON
`);
    } else {
      const a = await checkClaimAnchor2(pack, sidecar, { offline: argv.includes("--offline") });
      anchorOk = a.local_ok && a.log_ok !== false;
      if (a.local_ok) {
        process.stdout.write(`  Anchor:     ${green("\u2713")} anchored envelope binds this exact claim and its record root
`);
        process.stdout.write(`              ${green("\u2713")} envelope signed by the claim issuer's key
`);
      } else {
        for (const r of a.reasons.slice(0, 3)) process.stdout.write(`  Anchor:     ${red("\u2717")} ${r}
`);
      }
      if (a.log_ok === true) {
        process.stdout.write(`              ${green("\u2713")} public log confirms it${typeof a.seq === "number" ? ": entry " + bold("#" + a.seq) : ""}${a.anchored_at ? dim(" \xB7 anchored " + a.anchored_at) : ""}
`);
      } else if (a.log_ok === false) {
        process.stdout.write(`              ${red("\u2717")} ${a.reasons[a.reasons.length - 1]}
`);
      } else if (a.local_ok) {
        process.stdout.write(`              ${yellow("~")} log not checked ${dim(argv.includes("--offline") ? "(--offline)" : "(unreachable; local binding checks stand)")}
`);
      }
      if (!argv.includes("--offline") && sidecar.envelope) {
        const { lookupPinnedIdentity: lookupPinnedIdentity2 } = await Promise.resolve().then(() => (init_claim(), claim_exports));
        const who = await lookupPinnedIdentity2(sidecar.envelope.verification_key, {});
        if (who && who.found && !who.revoked) {
          process.stdout.write(`              ${green("\u2713")} issuer key pinned to ${bold(who.name || who.slug || "an enrolled org")} ${dim("(ScopeBlind key directory)")}
`);
        } else if (who && who.found && who.revoked) {
          anchorOk = false;
          process.stdout.write(`              ${red("\u2717")} issuer key is REVOKED in the ScopeBlind key directory
`);
        } else if (who && !who.found) {
          process.stdout.write(`              ${dim("issuer key not enrolled (anonymous issuer); named identities pin via scopeblind.com/enroll")}
`);
        }
      }
    }
  } else if (requireAnchor) {
    anchorOk = false;
    process.stdout.write(`  Anchor:     ${red("\u2717")} no anchor sidecar at ${sidecarPath} ${dim("(mint with: protect-mcp claim ... --anchor)")}
`);
  } else {
    process.stdout.write(`  Anchor:     ${dim("none found (" + sidecarPath + "). Anchoring proves the claim was fixed at a time: claim ... --anchor")}
`);
  }
  const finalValid = v.valid && anchorOk;
  process.stdout.write(`
  ${finalValid ? green("VALID") : red("INVALID")} attestation${v.valid && !anchorOk ? red(" (anchor check failed)") : ""}.
`);
  process.stdout.write(`  ${dim("Proves the pack came from the issuer key and the claim is true over the disclosed decision")}
`);
  process.stdout.write(`  ${dim("categories (verdict + capabilities), which reveal no tool inputs, outputs, or data. Completeness")}
`);
  process.stdout.write(`  ${dim("of the disclosed set is attested by the issuer; the anchor fixes it in a public append-only log.")}

`);
  process.exit(finalValid ? 0 : 1);
}
async function handleBundle(argv) {
  const { readFileSync: readFileSync11, writeFileSync: writeFileSync5, existsSync: existsSync10 } = await import("fs");
  const { join: join9 } = await import("path");
  const { createAuditBundle: createAuditBundle2 } = await Promise.resolve().then(() => (init_bundle(), bundle_exports));
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const outputIdx = argv.indexOf("--output");
  const outputPath = outputIdx !== -1 && argv[outputIdx + 1] ? argv[outputIdx + 1] : join9(dir, "audit-bundle.json");
  const receiptsPath = join9(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = join9(dir, "keys", "gateway.json");
  if (!existsSync10(receiptsPath)) {
    process.stderr.write(`${bold("protect-mcp bundle")}

No signed receipt file found. Run protect-mcp with signing enabled first.
`);
    process.exit(0);
  }
  if (!existsSync10(keyPath)) {
    process.stderr.write(`${bold("protect-mcp bundle")}

No key file found at ${keyPath}
`);
    process.exit(1);
  }
  const receipts = readFileSync11(receiptsPath, "utf-8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const keyData = JSON.parse(readFileSync11(keyPath, "utf-8"));
  const bundle = createAuditBundle2({
    tenant: keyData.issuer || "protect-mcp",
    receipts,
    selectiveDisclosures: collectSelectiveDisclosurePackages(dir),
    signingKeys: [{
      kty: "OKP",
      crv: "Ed25519",
      kid: keyData.kid || "unknown",
      x: Buffer.from(keyData.publicKey, "hex").toString("base64url"),
      use: "sig"
    }]
  });
  writeFileSync5(outputPath, JSON.stringify(bundle, null, 2) + "\n");
  process.stdout.write(`
${bold("protect-mcp bundle")}

`);
  process.stdout.write(`  Receipts: ${receipts.length}
`);
  process.stdout.write(`  Disclosures: ${collectSelectiveDisclosurePackages(dir).length}
`);
  process.stdout.write(`  Output:   ${outputPath}
`);
  process.stdout.write(`  Verify:   npx @veritasacta/verify ${outputPath} --bundle

`);
}
async function createSandbox() {
  const { mkdirSync: mkdirSync4, writeFileSync: writeFileSync5, existsSync: existsSync10, readFileSync: readFileSync11 } = await import("fs");
  const { join: join9 } = await import("path");
  const { homedir } = await import("os");
  let response;
  try {
    response = await fetch("https://api.scopeblind.com/sandbox/create", { method: "POST" });
  } catch {
    process.stderr.write(yellow("  \u26A0 Could not create dashboard (offline or server unavailable).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  if (!response.ok) {
    process.stderr.write(yellow("  \u26A0 Could not create dashboard (offline or server unavailable).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  let data;
  try {
    data = await response.json();
  } catch {
    process.stderr.write(yellow("  \u26A0 Could not create dashboard (unexpected response).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  const dashboardUrl = `https://scopeblind.com/t/${data.slug}`;
  const configDir = join9(homedir(), ".protect-mcp");
  if (!existsSync10(configDir)) {
    mkdirSync4(configDir, { recursive: true });
  }
  const configPath = join9(configDir, "config.json");
  let existing = {};
  if (existsSync10(configPath)) {
    try {
      existing = JSON.parse(readFileSync11(configPath, "utf-8"));
    } catch {
    }
  }
  writeFileSync5(configPath, JSON.stringify({
    ...existing,
    sandbox_slug: data.slug,
    dashboard_url: dashboardUrl
  }, null, 2) + "\n");
  return dashboardUrl;
}
async function handleConnect() {
  process.stderr.write(`
${bold("protect-mcp connect")}
`);
  process.stderr.write(`${"\u2500".repeat(50)}

`);
  process.stderr.write(`  Creating ScopeBlind sandbox dashboard...

`);
  const dashboardUrl = await createSandbox();
  if (dashboardUrl) {
    process.stderr.write(green(`  \u2713 Dashboard created: ${dashboardUrl}
`));
    process.stderr.write(`    Receipts will be uploaded automatically.
`);
    process.stderr.write(dim(`    Free tier: 20,000 receipts/month, no credit card required.
`));
    process.stderr.write(`
${"\u2500".repeat(50)}

`);
  }
}
async function handleQuickstart(argv) {
  const connectFlag = argv.includes("--connect");
  const { mkdtempSync, writeFileSync: writeFileSync5, existsSync: existsSync10, mkdirSync: mkdirSync4, readFileSync: readFileSync11 } = await import("fs");
  const { join: join9 } = await import("path");
  const { tmpdir } = await import("os");
  const dir = mkdtempSync(join9(tmpdir(), "protect-mcp-quickstart-"));
  process.stdout.write(`
${bold("protect-mcp quickstart")}
`);
  process.stdout.write(`${"\u2500".repeat(50)}

`);
  process.stdout.write(`  This will:
`);
  process.stdout.write(`  1. Generate an Ed25519 signing keypair
`);
  process.stdout.write(`  2. Create a shadow-mode policy
`);
  process.stdout.write(`  3. Start a demo MCP server with protect-mcp wrapping it
`);
  process.stdout.write(`  4. Log signed receipts for every tool call
`);
  if (connectFlag) {
    process.stdout.write(`  5. Create a ScopeBlind dashboard for receipt viewing
`);
  }
  process.stdout.write(`
  Working dir: ${dir}

`);
  const keysDir = join9(dir, "keys");
  mkdirSync4(keysDir, { recursive: true });
  const { randomBytes: randomBytes4 } = await import("crypto");
  let keypair;
  try {
    const { ed25519: ed255192 } = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
    const { bytesToHex: bytesToHex2 } = await Promise.resolve().then(() => (init_utils(), utils_exports));
    const privateKey = randomBytes4(32);
    const publicKey = ed255192.getPublicKey(privateKey);
    keypair = {
      privateKey: bytesToHex2(privateKey),
      publicKey: bytesToHex2(publicKey),
      kid: `quickstart-${Date.now()}`
    };
  } catch {
    keypair = {
      privateKey: randomBytes4(32).toString("hex"),
      publicKey: randomBytes4(32).toString("hex"),
      kid: `quickstart-${Date.now()}`
    };
  }
  writeFileSync5(join9(keysDir, "gateway.json"), JSON.stringify({
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    kid: keypair.kid,
    generated_at: (/* @__PURE__ */ new Date()).toISOString()
  }, null, 2) + "\n");
  const configPath = join9(dir, "protect-mcp.json");
  const config = {
    tools: {
      "*": { rate_limit: "100/hour" },
      "delete_file": { block: true }
    },
    default_tier: "unknown",
    signing: {
      key_path: join9(keysDir, "gateway.json"),
      issuer: "protect-mcp-quickstart",
      enabled: true
    }
  };
  writeFileSync5(configPath, JSON.stringify(config, null, 2) + "\n");
  process.stdout.write(`  \u2713 Keypair generated (kid: ${keypair.kid})
`);
  process.stdout.write(`  \u2713 Policy created (shadow mode, all tools logged)
`);
  process.stdout.write(`  \u2713 Signing enabled (Ed25519)

`);
  if (connectFlag) {
    process.stdout.write(`${bold("Connecting to ScopeBlind dashboard...")}

`);
    const dashboardUrl = await createSandbox();
    if (dashboardUrl) {
      const updatedConfig = { ...config, dashboard_url: dashboardUrl };
      writeFileSync5(configPath, JSON.stringify(updatedConfig, null, 2) + "\n");
      process.stdout.write(green(`  \u2713 Dashboard created: ${dashboardUrl}
`));
      process.stdout.write(`    Receipts will be uploaded automatically.
`);
      process.stdout.write(dim(`    Free tier: 20,000 receipts/month, no credit card required.
`));
      process.stdout.write(`
`);
    }
  }
  process.stdout.write(`${bold("Starting demo server...")}

`);
  process.stdout.write(`  Every tool call will produce a signed receipt.
`);
  process.stdout.write(`  Try it with Claude Desktop or any MCP client.

`);
  process.stdout.write(`  ${bold("To use in production:")}
`);
  process.stdout.write(`    1. Copy ${configPath} to your project
`);
  process.stdout.write(`    2. Edit tool policies to match your server
`);
  process.stdout.write(`    3. Run: protect-mcp --policy protect-mcp.json -- node your-server.js

`);
  process.stdout.write(`${"\u2500".repeat(50)}

`);
  process.env.PROTECT_MCP_CONFIG = configPath;
  await handleDemo();
}
async function handleRegistry(argv) {
  const subcommand = argv[0] || "status";
  const dir = (0, import_node_path9.resolve)(flagValue(argv, "--dir") || process.cwd());
  const orgName = flagValue(argv, "--org") || process.env.SCOPEBLIND_ORG;
  const orgId = flagValue(argv, "--org-id") || process.env.SCOPEBLIND_ORG_ID;
  const billingAccountId = flagValue(argv, "--billing-account") || process.env.SCOPEBLIND_BILLING_ACCOUNT;
  const endpoint = flagValue(argv, "--endpoint") || process.env.SCOPEBLIND_REGISTRY_ENDPOINT || (argv.includes("--hosted") ? "https://api.scopeblind.com" : void 0);
  const token = flagValue(argv, "--token") || process.env.SCOPEBLIND_TOKEN;
  const verifierBaseUrl = flagValue(argv, "--verifier-base") || process.env.SCOPEBLIND_VERIFIER_BASE || "https://legate.scopeblind.com";
  const registryMod = await Promise.resolve().then(() => (init_receipt_registry(), receipt_registry_exports));
  if (subcommand === "init") {
    const identity = registryMod.createOrgIdentity({
      dir,
      orgName,
      orgId,
      billingAccountId
    });
    const path = registryMod.writeOrgIdentity(dir, identity);
    process.stdout.write(`
${bold("protect-mcp registry init")}

`);
    process.stdout.write(`  Org:              ${identity.org_name}
`);
    process.stdout.write(`  Org ID:           ${identity.org_id}
`);
    process.stdout.write(`  Billing account:  ${identity.billing_account_id}
`);
    process.stdout.write(`  Public keys:      ${identity.public_key_directory.length}
`);
    process.stdout.write(`  Wrote:            ${path}

`);
    process.stdout.write(`${dim("No prompts, tool payloads, raw receipts, or private keys are included.")}

`);
    return;
  }
  if (subcommand === "anchor") {
    process.stdout.write(`
${bold("protect-mcp registry anchor")}

`);
    const result = await registryMod.createReceiptRegistry({
      dir,
      orgName,
      orgId,
      billingAccountId,
      endpoint,
      token,
      hosted: argv.includes("--hosted") || Boolean(endpoint || token),
      verifierBaseUrl,
      outPath: flagValue(argv, "--output")
    });
    process.stdout.write(`  Org:              ${result.registry.org.org_name}
`);
    process.stdout.write(`  Billing account:  ${result.registry.billing.billing_account_id}
`);
    process.stdout.write(`  Digests:          ${result.registry.records.length}
`);
    process.stdout.write(`  Anchors:          ${result.registry.anchors.length}
`);
    process.stdout.write(`  Boundary:         ${result.uploaded ? green("hosted digest anchor") : yellow("local preview only")}
`);
    process.stdout.write(`  Registry:         ${result.registryPath}
`);
    process.stdout.write(`  Verifier page:    ${result.verifierPath}

`);
    process.stdout.write(`  Uploaded fields:  ${result.registry.privacy.uploaded_fields.join(", ")}
`);
    process.stdout.write(`  Excluded fields:  ${result.registry.privacy.excluded_fields.join(", ")}

`);
    if (!result.uploaded) {
      process.stdout.write(`${yellow("  This is not an independent timestamp yet.")}
`);
      process.stdout.write(`  Run with ${dim("--hosted --token $SCOPEBLIND_TOKEN")} to make the paid boundary real.

`);
    }
    return;
  }
  if (subcommand === "status") {
    const registryPath = (0, import_node_path9.join)(dir, registryMod.REGISTRY_FILE);
    const identityPath = (0, import_node_path9.join)(dir, registryMod.ORG_IDENTITY_FILE);
    process.stdout.write(`
${bold("protect-mcp registry status")}

`);
    if ((0, import_node_fs13.existsSync)(identityPath)) {
      const identity = JSON.parse((0, import_node_fs13.readFileSync)(identityPath, "utf-8"));
      process.stdout.write(`  Org:              ${identity.org_name || "unknown"}
`);
      process.stdout.write(`  Org ID:           ${identity.org_id || "unknown"}
`);
      process.stdout.write(`  Billing account:  ${identity.billing_account_id || "unknown"}
`);
    } else {
      process.stdout.write(`  Org identity:     ${yellow("missing")} (${identityPath})
`);
    }
    if ((0, import_node_fs13.existsSync)(registryPath)) {
      const registry = JSON.parse((0, import_node_fs13.readFileSync)(registryPath, "utf-8"));
      const hosted = Array.isArray(registry.anchors) && registry.anchors.some((a) => a.timestamp_source === "scopeblind-hosted");
      process.stdout.write(`  Registry:         ${registryPath}
`);
      process.stdout.write(`  Digests:          ${registry.records?.length || 0}
`);
      process.stdout.write(`  Anchors:          ${registry.anchors?.length || 0}
`);
      process.stdout.write(`  Boundary:         ${hosted ? green("hosted digest anchor") : yellow("local preview only")}
`);
      process.stdout.write(`  Verifier page:    ${(0, import_node_path9.join)(dir, registryMod.VERIFIER_PAGE_FILE)}
`);
    } else {
      process.stdout.write(`  Registry:         ${yellow("missing")} (${registryPath})
`);
      process.stdout.write(`  Next:             ${dim("npx protect-mcp registry anchor --hosted")}
`);
    }
    process.stdout.write(`
`);
    return;
  }
  process.stderr.write("Usage: protect-mcp registry init|anchor|status [--dir <path>] [--org <name>] [--hosted]\\n");
  process.exit(1);
}
async function handleKillerDemo(argv) {
  const { mkdtempSync } = await import("fs");
  const { tmpdir } = await import("os");
  const { ed25519: ed255192 } = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
  const { bytesToHex: bytesToHex2 } = await Promise.resolve().then(() => (init_utils(), utils_exports));
  const { randomBytes: randomBytes4 } = await import("crypto");
  const artifacts = await import("@veritasacta/artifacts");
  const {
    createSelectiveDisclosurePackage: createSelectiveDisclosurePackage2,
    signCommittedDecision: signCommittedDecision2,
    verifySelectiveDisclosurePackage: verifySelectiveDisclosurePackage2
  } = await Promise.resolve().then(() => (init_signing_committed(), signing_committed_exports));
  const registryMod = await Promise.resolve().then(() => (init_receipt_registry(), receipt_registry_exports));
  const dir = (0, import_node_path9.resolve)(flagValue(argv, "--dir") || mkdtempSync((0, import_node_path9.join)(tmpdir(), "scopeblind-killer-demo-")));
  (0, import_node_fs13.mkdirSync)(dir, { recursive: true });
  (0, import_node_fs13.mkdirSync)((0, import_node_path9.join)(dir, "keys"), { recursive: true });
  (0, import_node_fs13.mkdirSync)((0, import_node_path9.join)(dir, "receipts"), { recursive: true });
  const privateKeyBytes = randomBytes4(32);
  const publicKeyBytes = ed255192.getPublicKey(privateKeyBytes);
  const keypair = {
    privateKey: bytesToHex2(privateKeyBytes),
    publicKey: bytesToHex2(publicKeyBytes),
    kid: `killer-demo-${Date.now()}`,
    issuer: "scopeblind-killer-demo"
  };
  const keyPath = (0, import_node_path9.join)(dir, "keys", "gateway.json");
  (0, import_node_fs13.writeFileSync)(keyPath, JSON.stringify({
    ...keypair,
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    warning: "Demo key only. Do not use for production."
  }, null, 2) + "\n");
  const shadowConfigPath = (0, import_node_path9.join)(dir, "protect-mcp.shadow.json");
  const policyPackPath = (0, import_node_path9.join)(dir, "protect-mcp.policy-pack.json");
  const config = {
    tools: { "*": { rate_limit: "100/hour" } },
    default_tier: "signed-known",
    signing: { key_path: keyPath, issuer: keypair.issuer, enabled: true }
  };
  const policyPack = {
    tools: {
      "*": { rate_limit: "100/hour" },
      read_file: { rate_limit: "60/hour" },
      github_create_pr: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      send_email: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      pms_book_fill: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      delete_file: { block: true, min_tier: "privileged" }
    },
    default_tier: "signed-known",
    signing: { key_path: keyPath, issuer: keypair.issuer, enabled: true },
    notes: ["Demo policy pack: approvals for GitHub, email, and PMS booking; destructive tools blocked."]
  };
  (0, import_node_fs13.writeFileSync)(shadowConfigPath, JSON.stringify(config, null, 2) + "\n");
  (0, import_node_fs13.writeFileSync)(policyPackPath, JSON.stringify(policyPack, null, 2) + "\n");
  await initSigning({ enabled: true, key_path: keyPath, issuer: keypair.issuer });
  const logPath = (0, import_node_path9.join)(dir, ".protect-mcp-log.jsonl");
  const receiptPath = (0, import_node_path9.join)(dir, ".protect-mcp-receipts.jsonl");
  const shadowCalls = [
    { tool: "read_file", input: { path: "/research/macro-notes.md" }, reason: "observe_mode" },
    { tool: "github_create_pr", input: { repo: "scopeblind/legate", branch: "agent/pms-adapter", title: "Wire mock PMS adapter" }, reason: "observe_mode" },
    { tool: "send_email", input: { to: "ops@examplefund.com", subject: "Booking update", body: "Draft only", api_key: "demo-secret" }, reason: "observe_mode" },
    { tool: "pms_book_fill", input: { account: "Meridian Global Macro", symbol: "AAPL", side: "BUY", quantity: 50, price: 182.4, strategy: "US Large Cap Tactical", bearerToken: "demo-secret" }, reason: "observe_mode" }
  ];
  for (const [idx, call] of shadowCalls.entries()) {
    const requestId2 = `demo-shadow-${idx + 1}`;
    (0, import_node_fs13.appendFileSync)(logPath, JSON.stringify({
      v: 2,
      tool: call.tool,
      decision: "allow",
      reason_code: call.reason,
      request_id: requestId2,
      timestamp: Date.now() + idx,
      mode: "shadow",
      policy_digest: "shadow-policy",
      action_readback: buildActionReadback(call.tool, call.input)
    }) + "\n");
  }
  const sensitiveInput = {
    account: "Meridian Global Macro",
    symbol: "AAPL",
    side: "BUY",
    quantity: 50,
    price: 182.4,
    strategy: "US Large Cap Tactical",
    trader_note: "Do not reveal portfolio context outside the desk.",
    api_key: "demo-pms-secret"
  };
  const readback = buildActionReadback("pms_book_fill", sensitiveInput);
  const requestId = "demo-sensitive-pms-booking";
  const requireApprovalEntry = {
    v: 2,
    tool: "pms_book_fill",
    decision: "require_approval",
    reason_code: "requires_human_approval",
    request_id: requestId,
    timestamp: Date.now() + 10,
    mode: "enforce",
    policy_digest: (0, import_node_crypto7.createHash)("sha256").update(JSON.stringify(policyPack)).digest("hex").slice(0, 16),
    action_readback: readback
  };
  (0, import_node_fs13.appendFileSync)(logPath, JSON.stringify(requireApprovalEntry) + "\n");
  (0, import_node_fs13.appendFileSync)((0, import_node_path9.join)(dir, ".protect-mcp-approval-resolutions.jsonl"), JSON.stringify({
    type: "scopeblind.approval_resolution.v1",
    at: (/* @__PURE__ */ new Date()).toISOString(),
    request_id: requestId,
    tool: "pms_book_fill",
    resolution: "approve",
    reason: "Matches the ticket and stays inside mandate.",
    payload_hash: readback.payload_hash
  }) + "\n");
  const executedEntry = {
    ...requireApprovalEntry,
    decision: "allow",
    reason_code: "approval_granted",
    timestamp: Date.now() + 20,
    payload_digest: {
      output_hash: (0, import_node_crypto7.createHash)("sha256").update("mock-pms-booking-confirmed").digest("hex"),
      output_size: 26,
      truncated: false
    }
  };
  (0, import_node_fs13.appendFileSync)(logPath, JSON.stringify(executedEntry) + "\n");
  const signed = signDecision(executedEntry);
  if (!signed.signed) throw new Error(`demo signing failed: ${signed.warning || signed.error || "unknown"}`);
  (0, import_node_fs13.appendFileSync)(receiptPath, signed.signed + "\n");
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "receipts", "approved-pms-booking.receipt.json"), JSON.stringify(JSON.parse(signed.signed), null, 2) + "\n");
  const receiptArtifact = JSON.parse(signed.signed);
  const tamperedArtifact = JSON.parse(signed.signed);
  if (tamperedArtifact.payload && typeof tamperedArtifact.payload === "object") {
    tamperedArtifact.payload.decision = "deny";
    tamperedArtifact.payload.tool = "send_email";
  } else {
    tamperedArtifact.tool = "send_email";
  }
  const validOriginal = artifacts.verifyArtifact(receiptArtifact, keypair.publicKey);
  const validTampered = artifacts.verifyArtifact(tamperedArtifact, keypair.publicKey);
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "receipts", "tampered.receipt.json"), JSON.stringify(tamperedArtifact, null, 2) + "\n");
  const committed = signCommittedDecision2(
    executedEntry,
    ["tool", "payload_digest", "swarm"],
    keypair.privateKey,
    keypair.publicKey,
    keypair.kid,
    keypair.issuer
  );
  const committedReceipt = JSON.parse(committed.signed);
  const disclosurePackage = createSelectiveDisclosurePackage2(committedReceipt, ["tool"], committed.openings);
  const disclosureVerification = verifySelectiveDisclosurePackage2(committedReceipt, disclosurePackage);
  (0, import_node_fs13.appendFileSync)(receiptPath, committed.signed + "\n");
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "receipts", "selective-disclosure.receipt.json"), JSON.stringify(committedReceipt, null, 2) + "\n");
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "receipts", "selective-disclosure.package.json"), JSON.stringify(disclosurePackage, null, 2) + "\n");
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "receipts", "selective-disclosure.tool-only.json"), JSON.stringify(disclosurePackage, null, 2) + "\n");
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "verification-results.json"), JSON.stringify({
    original_receipt_valid: validOriginal,
    tampered_receipt_valid: validTampered,
    selective_disclosure_valid: disclosureVerification.valid,
    selective_disclosure_explanation: disclosureVerification.explanation
  }, null, 2) + "\n");
  const registry = await registryMod.createReceiptRegistry({
    dir,
    orgName: flagValue(argv, "--org") || "Meridian Global Macro Demo",
    billingAccountId: flagValue(argv, "--billing-account") || "demo_billing_digest_only",
    hosted: argv.includes("--hosted"),
    endpoint: flagValue(argv, "--endpoint") || process.env.SCOPEBLIND_REGISTRY_ENDPOINT || (argv.includes("--hosted") ? "https://api.scopeblind.com" : void 0),
    token: flagValue(argv, "--token") || process.env.SCOPEBLIND_TOKEN,
    verifierBaseUrl: flagValue(argv, "--verifier-base") || "https://legate.scopeblind.com"
  });
  const runbook = [
    "# ScopeBlind Killer Demo",
    "",
    "Three-minute flow, generated locally.",
    "",
    "## 1. Agent has tools",
    "",
    "Mock tools represented: filesystem `read_file`, GitHub `github_create_pr`, email `send_email`, and PMS `pms_book_fill`.",
    "",
    "## 2. Shadow mode shows risk",
    "",
    "Open the dashboard against this directory:",
    "",
    "```bash",
    `npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`,
    "```",
    "",
    "You will see GitHub, email, and PMS calls ranked as high risk.",
    "",
    "## 3. Apply policy pack",
    "",
    `Policy pack: \`${policyPackPath}\`.`,
    "",
    "It requires approval for GitHub PRs, outbound email, and PMS booking; destructive file deletion is blocked.",
    "",
    "## 4. Sensitive action requires exact approval",
    "",
    `Request id: \`${requestId}\``,
    "",
    `Exact readback summary: \`${readback.summary}\``,
    "",
    `Payload hash: \`${readback.payload_hash}\``,
    "",
    "Secret-like fields are redacted from the approval preview but still affect the hash.",
    "",
    "## 5. User approves; tool executes through gateway",
    "",
    "Approval resolution: `.protect-mcp-approval-resolutions.jsonl`",
    "",
    "Signed receipt: `receipts/approved-pms-booking.receipt.json`",
    "",
    "## 6. Offline verification and tamper failure",
    "",
    "Verification result: `verification-results.json`.",
    "",
    "Expected: original valid, tampered invalid.",
    "",
    "## 7. Selective disclosure",
    "",
    "Committed receipt: `receipts/selective-disclosure.receipt.json`",
    "",
    "Tool-only v0 disclosure package: `receipts/selective-disclosure.tool-only.json`",
    "",
    "The disclosure opens only the committed `tool` field. Other committed fields, such as `payload_digest`, remain hidden but bound to the signed `committed_fields_root`.",
    "",
    "This demonstrates hiding sensitive context while revealing the minimum needed proof. It is salted commitment disclosure, not full zero-knowledge.",
    "",
    "## 8. Paid boundary MVP",
    "",
    `Registry: \`${registry.registryPath}\``,
    "",
    `Verifier page: \`${registry.verifierPath}\``,
    "",
    `Boundary: ${registry.uploaded ? "hosted digest anchor with independent timestamp" : "local preview only; hosted anchoring not used"}.`,
    "",
    "No raw prompt, payload, output, private key, or raw receipt is uploaded by the registry flow. Hosted mode submits receipt digests, request ids, org public keys, and billing account metadata only.",
    ""
  ].join("\n");
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "DEMO-RUNBOOK.md"), runbook);
  (0, import_node_fs13.writeFileSync)((0, import_node_path9.join)(dir, "demo-summary.json"), JSON.stringify({
    dir,
    dashboard_command: `npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`,
    policy_pack: policyPackPath,
    receipt: (0, import_node_path9.join)(dir, "receipts", "approved-pms-booking.receipt.json"),
    tampered_receipt: (0, import_node_path9.join)(dir, "receipts", "tampered.receipt.json"),
    selective_disclosure_receipt: (0, import_node_path9.join)(dir, "receipts", "selective-disclosure.receipt.json"),
    selective_disclosure_package: (0, import_node_path9.join)(dir, "receipts", "selective-disclosure.tool-only.json"),
    verification_results: (0, import_node_path9.join)(dir, "verification-results.json"),
    registry: registry.registryPath,
    verifier_page: registry.verifierPath,
    runbook: (0, import_node_path9.join)(dir, "DEMO-RUNBOOK.md"),
    original_valid: validOriginal.valid,
    tampered_valid: validTampered.valid,
    selective_disclosure_valid: disclosureVerification.valid
  }, null, 2) + "\n");
  process.stdout.write(`
${bold("protect-mcp killer-demo")}

`);
  process.stdout.write(`  Demo dir:          ${dir}
`);
  process.stdout.write(`  Dashboard:         ${dim(`npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`)}
`);
  process.stdout.write(`  Runbook:           ${(0, import_node_path9.join)(dir, "DEMO-RUNBOOK.md")}
`);
  process.stdout.write(`  Signed receipt:    ${(0, import_node_path9.join)(dir, "receipts", "approved-pms-booking.receipt.json")}
`);
  process.stdout.write(`  Tamper check:      original=${validOriginal.valid ? green("valid") : red("invalid")} tampered=${validTampered.valid ? red("valid") : green("invalid")}
`);
  process.stdout.write(`  Registry:          ${registry.registryPath}
`);
  process.stdout.write(`  Verifier page:     ${registry.verifierPath}
`);
  process.stdout.write(`  Boundary:          ${registry.uploaded ? green("hosted digest anchor") : yellow("local preview only")}

`);
}
async function handleVerifyDisclosure(argv) {
  const receiptPath = flagValue(argv, "--receipt");
  const disclosurePath = flagValue(argv, "--disclosure");
  if (!receiptPath || !disclosurePath) {
    process.stderr.write("Usage: protect-mcp verify-disclosure --receipt <committed-receipt.json> --disclosure <selective-disclosure.json>\\n");
    process.exit(1);
  }
  const { verifySelectiveDisclosurePackage: verifySelectiveDisclosurePackage2 } = await Promise.resolve().then(() => (init_signing_committed(), signing_committed_exports));
  const receipt = JSON.parse((0, import_node_fs13.readFileSync)((0, import_node_path9.resolve)(receiptPath), "utf-8"));
  const disclosure = JSON.parse((0, import_node_fs13.readFileSync)((0, import_node_path9.resolve)(disclosurePath), "utf-8"));
  const result = verifySelectiveDisclosurePackage2(receipt, disclosure);
  process.stdout.write(`
${bold("protect-mcp verify-disclosure")}

`);
  process.stdout.write(`  Result:           ${result.valid ? green("valid") : red("invalid")}
`);
  process.stdout.write(`  Receipt hash:     ${result.receipt_hash_valid ? green("matches") : red("mismatch")}
`);
  process.stdout.write(`  Signature:        ${result.signature_valid === true ? green("valid") : result.signature_valid === null ? yellow("not checked") : red("invalid")}
`);
  process.stdout.write(`  Commitment root:  ${result.commitment_root_valid ? green("matches") : red("mismatch")}
`);
  process.stdout.write(`  Disclosed fields: ${result.disclosed_fields.length ? result.disclosed_fields.join(", ") : "none"}
`);
  process.stdout.write(`  Hidden fields:    ${result.hidden_fields.length ? result.hidden_fields.join(", ") : "none"}

`);
  for (const line of result.explanation) {
    process.stdout.write(`  - ${line}
`);
  }
  if (result.errors.length > 0) {
    process.stdout.write(`
${red("Errors:")}
`);
    for (const err of result.errors) process.stdout.write(`  - ${err}
`);
  }
  process.stdout.write("\n");
  if (!result.valid) process.exit(2);
}
async function handlePolicyPacks(argv) {
  const subcommand = argv[0] || "list";
  const packArg = argv[1];
  const dir = (0, import_node_path9.resolve)(flagValue(argv, "--dir") || "./cedar");
  const force = argv.includes("--force");
  if (subcommand === "list") {
    process.stdout.write(`
${bold("protect-mcp policy-packs")}

`);
    for (const pack of POLICY_PACKS) {
      process.stdout.write(`  ${bold(pack.id.padEnd(22))} ${pack.name}
`);
      process.stdout.write(`  ${dim(" ".repeat(24) + pack.description)}
`);
      process.stdout.write(`  ${dim(" ".repeat(24) + `recommended: ${pack.recommendedMode}`)}

`);
    }
    process.stdout.write(`Install one: ${dim("protect-mcp policy-packs install filesystem-safe --dir ./cedar")}
`);
    process.stdout.write(`Install all: ${dim("protect-mcp policy-packs install all --dir ./cedar")}

`);
    return;
  }
  if (subcommand === "show") {
    const pack = getPolicyPack(packArg || "");
    if (!pack) {
      process.stderr.write(`Unknown policy pack "${packArg || ""}". Available: ${policyPackIds().join(", ")}
`);
      process.exit(1);
    }
    process.stdout.write(`
${bold(pack.name)} (${pack.id})

`);
    process.stdout.write(`${pack.description}
`);
    process.stdout.write(`Recommended rollout: ${pack.recommendedMode}

`);
    for (const file of pack.files) {
      process.stdout.write(`${dim(`--- ${file.path} ---`)}
`);
      process.stdout.write(file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
      process.stdout.write("\n");
    }
    return;
  }
  if (subcommand === "install") {
    const packs = packArg === "all" ? POLICY_PACKS : [getPolicyPack(packArg || "")].filter(Boolean);
    if (packs.length === 0) {
      process.stderr.write(`Usage: protect-mcp policy-packs install <${policyPackIds().join("|")}|all> [--dir ./cedar] [--force]
`);
      process.exit(1);
    }
    (0, import_node_fs13.mkdirSync)(dir, { recursive: true });
    const written = [];
    for (const pack of packs) {
      for (const file of pack.files) {
        const outPath = (0, import_node_path9.join)(dir, file.path);
        if ((0, import_node_fs13.existsSync)(outPath) && !force) {
          process.stderr.write(`Refusing to overwrite ${outPath}. Re-run with --force if intentional.
`);
          process.exit(1);
        }
        (0, import_node_fs13.writeFileSync)(outPath, file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
        written.push(outPath);
      }
    }
    process.stdout.write(`
${bold("protect-mcp policy-packs install")}

`);
    process.stdout.write(`  Directory: ${dir}
`);
    for (const outPath of written) process.stdout.write(`  Wrote:     ${outPath}
`);
    process.stdout.write(`
Next: ${dim(`protect-mcp serve --cedar ${dir}`)} for shadow mode, then add ${dim("--enforce")} after reviewing receipts.

`);
    return;
  }
  process.stderr.write("Usage: protect-mcp policy-packs list|show|install [pack] [--dir ./cedar] [--force]\n");
  process.exit(1);
}
async function handleConnectors(argv) {
  const subcommand = argv[0] || "list";
  const pilotArg = argv[1];
  const dir = (0, import_node_path9.resolve)(flagValue(argv, "--dir") || process.cwd());
  const force = argv.includes("--force");
  if (subcommand === "list") {
    process.stdout.write(`
${bold("protect-mcp connector pilots")}

`);
    for (const pilot of CONNECTOR_PILOTS) {
      process.stdout.write(`  ${bold(pilot.id.padEnd(18))} ${pilot.name}
`);
      process.stdout.write(`  ${dim(" ".repeat(20) + pilot.description)}
`);
      process.stdout.write(`  ${dim(" ".repeat(20) + `tools: ${pilot.tools.join(", ")}`)}

`);
    }
    process.stdout.write(`Install all: ${dim("protect-mcp connectors init all --force")}
`);
    process.stdout.write(`Check credentials: ${dim("protect-mcp connectors doctor")}

`);
    return;
  }
  if (subcommand === "show") {
    const pilot = getConnectorPilot(pilotArg || "");
    if (!pilot) {
      process.stderr.write(`Unknown connector pilot "${pilotArg || ""}". Available: ${CONNECTOR_PILOTS.map((p) => p.id).join(", ")}
`);
      process.exit(1);
    }
    process.stdout.write(`
${bold(pilot.name)} (${pilot.id})

`);
    process.stdout.write(`${pilot.description}

`);
    process.stdout.write(`${bold("Why it matters:")} ${pilot.value}

`);
    process.stdout.write(`${bold("Tools:")} ${pilot.tools.join(", ")}

`);
    process.stdout.write(`${bold("Setup:")}
`);
    for (const step of pilot.setup) process.stdout.write(`  - ${step}
`);
    process.stdout.write(`
${bold("Starter policy:")}
${pilot.cedar}
`);
    return;
  }
  if (subcommand === "init") {
    const ids = pilotArg ? [pilotArg] : ["all"];
    const installed = writeConnectorPilots({ dir, ids, force });
    process.stdout.write(`
${bold("protect-mcp connectors init")}

`);
    process.stdout.write(`  Directory: ${installed.directory}
`);
    for (const outPath of installed.written) process.stdout.write(`  Wrote:     ${outPath}
`);
    process.stdout.write(`
Next: ${dim("protect-mcp connectors doctor")} then ${dim("protect-mcp dashboard --open")}.

`);
    return;
  }
  if (subcommand === "doctor") {
    let rows = connectorDoctor(dir);
    if (pilotArg && pilotArg !== "all") {
      const pilot = getConnectorPilot(pilotArg);
      if (!pilot) {
        process.stderr.write(`Unknown connector pilot "${pilotArg}". Available: ${CONNECTOR_PILOTS.map((p) => p.id).join(", ")}
`);
        process.exit(1);
      }
      rows = rows.filter((row) => row.id === pilot.id);
    }
    process.stdout.write(`
${bold("protect-mcp connectors doctor")}

`);
    for (const row of rows) {
      const missing = Array.isArray(row.missing_required) && row.missing_required.length > 0 ? row.missing_required.join(", ") : "";
      const status = row.installed ? row.usable ? green("ready") : yellow("needs setup") : dim("not installed");
      process.stdout.write(`  ${bold(String(row.id).padEnd(18))} ${status}
`);
      process.stdout.write(`  ${dim(" ".repeat(20) + `mode: ${String(row.mode || "unknown")}`)}
`);
      if (missing) process.stdout.write(`  ${yellow(" ".repeat(20) + `missing: ${missing}`)}
`);
      process.stdout.write(`  ${dim(" ".repeat(20) + String(row.next || ""))}

`);
    }
    process.stdout.write(`${dim("Secret values are never printed; only missing variable names are shown.")}

`);
    return;
  }
  process.stderr.write("Usage: protect-mcp connectors list|show|init|doctor [connector|all] [--dir <path>] [--force]\n");
  process.exit(1);
}
async function handleTrace(argv) {
  const receiptId = argv[0];
  if (!receiptId) {
    process.stderr.write("[PROTECT_MCP] Usage: protect-mcp trace <receipt_id> [--endpoint <url>] [--depth <n>]\n");
    process.exit(1);
  }
  let endpoint = "https://api.scopeblind.com/evidence";
  let depth = 3;
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === "--endpoint" && argv[i + 1]) {
      endpoint = argv[++i];
    } else if (argv[i] === "--depth" && argv[i + 1]) {
      depth = Math.min(10, Math.max(1, parseInt(argv[++i], 10) || 3));
    }
  }
  process.stdout.write(`
${bold("protect-mcp trace")}
`);
  process.stdout.write(`${"\u2500".repeat(60)}

`);
  process.stdout.write(`  Root:     ${receiptId}
`);
  process.stdout.write(`  Endpoint: ${endpoint}
`);
  process.stdout.write(`  Depth:    ${depth}

`);
  const url = `${endpoint}/evidence/graph/${encodeURIComponent(receiptId)}?depth=${depth}&direction=both&max=50`;
  let graphData;
  try {
    const resp = await fetch(url);
    if (!resp.ok) {
      const body = await resp.text();
      process.stderr.write(`[PROTECT_MCP] Error fetching graph: ${resp.status} ${body}
`);
      process.exit(1);
    }
    graphData = await resp.json();
  } catch (err) {
    process.stderr.write(`[PROTECT_MCP] Could not reach evidence indexer at ${endpoint}
`);
    process.stderr.write(`[PROTECT_MCP] Trying local receipts...

`);
    await traceLocal(receiptId);
    return;
  }
  if (!graphData.nodes || graphData.nodes.length === 0) {
    process.stdout.write(`  No receipts found for ${receiptId}

`);
    return;
  }
  process.stdout.write(`  ${bold("Evidence DAG")} (${graphData.node_count} nodes, ${graphData.edge_count} edges)

`);
  const nodeMap = /* @__PURE__ */ new Map();
  for (const node of graphData.nodes) {
    nodeMap.set(node.receipt_id, node);
  }
  const childMap = /* @__PURE__ */ new Map();
  for (const edge of graphData.edges) {
    if (!childMap.has(edge.from)) childMap.set(edge.from, []);
    childMap.get(edge.from).push({ to: edge.to, relation: edge.relation });
  }
  const rendered = /* @__PURE__ */ new Set();
  function renderNode(id, prefix, isLast) {
    const node = nodeMap.get(id);
    const connector = isLast ? "\u2514\u2500\u2500 " : "\u251C\u2500\u2500 ";
    const childPrefix = isLast ? "    " : "\u2502   ";
    const typeEmoji = getTypeEmoji(node?.receipt_type || "unknown");
    const shortId = id.length > 16 ? id.slice(0, 12) + "\u2026" : id;
    const time = node?.event_time ? new Date(node.event_time).toLocaleTimeString() : "?";
    const type = node?.receipt_type?.replace("acta:", "") || "unknown";
    process.stdout.write(`${prefix}${connector}${typeEmoji} ${bold(type)} ${dim(shortId)} ${dim(time)}
`);
    if (rendered.has(id)) {
      process.stdout.write(`${prefix}${childPrefix}${dim("(cycle: already rendered)")}
`);
      return;
    }
    rendered.add(id);
    const children = childMap.get(id) || [];
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const edgeLabel = dim(`\u2500\u2500[${child.relation}]\u2500\u2500\u25B6`);
      process.stdout.write(`${prefix}${childPrefix}${edgeLabel}
`);
      renderNode(child.to, prefix + childPrefix, i === children.length - 1);
    }
  }
  const rootNode = nodeMap.get(receiptId);
  if (rootNode) {
    const typeEmoji = getTypeEmoji(rootNode.receipt_type);
    const type = rootNode.receipt_type?.replace("acta:", "") || "unknown";
    const time = rootNode.event_time ? new Date(rootNode.event_time).toLocaleTimeString() : "?";
    process.stdout.write(`  ${typeEmoji} ${bold(type)} ${dim(receiptId.slice(0, 16) + "\u2026")} ${dim(time)} ${bold("(root)")}
`);
    rendered.add(receiptId);
    const children = childMap.get(receiptId) || [];
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const edgeLabel = dim(`\u2500\u2500[${child.relation}]\u2500\u2500\u25B6`);
      process.stdout.write(`  ${edgeLabel}
`);
      renderNode(child.to, "  ", i === children.length - 1);
    }
    const incomingEdges = (graphData.edges || []).filter((e) => e.to === receiptId);
    if (incomingEdges.length > 0) {
      process.stdout.write(`
  ${bold("Incoming edges:")}
`);
      for (const edge of incomingEdges) {
        const fromNode = nodeMap.get(edge.from);
        const fromType = fromNode?.receipt_type?.replace("acta:", "") || "unknown";
        process.stdout.write(`  \u25C0\u2500\u2500[${edge.relation}]\u2500\u2500 ${getTypeEmoji(fromNode?.receipt_type)} ${fromType} ${dim(edge.from.slice(0, 16) + "\u2026")}
`);
      }
    }
  } else {
    for (const node of graphData.nodes) {
      const typeEmoji = getTypeEmoji(node.receipt_type);
      const type = node.receipt_type?.replace("acta:", "") || "unknown";
      process.stdout.write(`  ${typeEmoji} ${bold(type)} ${dim(node.receipt_id.slice(0, 16) + "\u2026")}
`);
    }
  }
  process.stdout.write(`
${"\u2500".repeat(60)}
`);
  process.stdout.write(`  ${dim(`Fetched from ${endpoint}`)}

`);
}
async function traceLocal(receiptId) {
  const { readFileSync: readFileSync11, existsSync: existsSync10 } = await import("fs");
  const { join: join9 } = await import("path");
  const dir = process.cwd();
  const receiptsDir = join9(dir, ".protect-mcp", "receipts");
  if (!existsSync10(receiptsDir)) {
    process.stdout.write(`  No local receipts found in ${receiptsDir}

`);
    return;
  }
  const { readdirSync: readdirSync4 } = await import("fs");
  const files = readdirSync4(receiptsDir).filter((f) => f.endsWith(".json"));
  process.stdout.write(`  Scanning ${files.length} local receipts...

`);
  const receipts = [];
  for (const file of files) {
    try {
      const content = readFileSync11(join9(receiptsDir, file), "utf-8");
      const receipt = JSON.parse(content);
      receipts.push(receipt);
    } catch {
    }
  }
  const match = receipts.find(
    (r) => r.signed_claims?.claims?.receipt_id === receiptId || r.receipt_id === receiptId
  );
  if (match) {
    const claims = match.signed_claims?.claims || match;
    process.stdout.write(`  Found: ${getTypeEmoji(claims.receipt_type)} ${bold(claims.receipt_type?.replace("acta:", "") || "unknown")}
`);
    process.stdout.write(`  Event:  ${claims.event_id || "?"}
`);
    process.stdout.write(`  Issuer: ${claims.issuer_id || "?"}
`);
    process.stdout.write(`  Time:   ${claims.event_time || "?"}
`);
    if (claims.edges && claims.edges.length > 0) {
      process.stdout.write(`
  ${bold("Edges:")}
`);
      for (const edge of claims.edges) {
        process.stdout.write(`    \u2500\u2500[${edge.relation}]\u2500\u2500\u25B6 ${dim(edge.receipt_id?.slice(0, 16) + "\u2026")}
`);
      }
    }
  } else {
    process.stdout.write(`  Receipt ${receiptId} not found locally.
`);
  }
  process.stdout.write("\n");
}
function getTypeEmoji(type) {
  switch (type) {
    case "acta:observation":
      return "\u{1F441} ";
    case "acta:policy-load":
      return "\u{1F4CB}";
    case "acta:approval":
      return "\u2705";
    case "acta:decision":
      return "\u2696\uFE0F ";
    case "acta:execution":
      return "\u26A1";
    case "acta:outcome":
      return "\u{1F4E6}";
    case "acta:delegation":
      return "\u{1F91D}";
    case "acta:capability-attestation":
      return "\u{1F3C5}";
    default:
      return "\u{1F4C4}";
  }
}
async function handleInitHooks(argv) {
  const { writeFileSync: writeFileSync5, existsSync: existsSync10, mkdirSync: mkdirSync4, readFileSync: readFileSync11 } = await import("fs");
  const { join: join9 } = await import("path");
  const { generateHookSettings: generateHookSettings2, generateSampleCedarPolicy: generateSampleCedarPolicy2, generateVerifyReceiptSkill: generateVerifyReceiptSkill2 } = await Promise.resolve().then(() => (init_hook_patterns(), hook_patterns_exports));
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const portIdx = argv.indexOf("--port");
  const port = portIdx >= 0 && argv[portIdx + 1] ? parseInt(argv[portIdx + 1]) : 9377;
  const hookUrl = `http://127.0.0.1:${port}/hook`;
  process.stdout.write(`
${bold("protect-mcp init-hooks")}
`);
  process.stdout.write(`${"\u2500".repeat(55)}

`);
  const claudeDir = join9(dir, ".claude");
  const settingsPath = join9(claudeDir, "settings.json");
  let existingSettings = {};
  if (!existsSync10(claudeDir)) {
    mkdirSync4(claudeDir, { recursive: true });
  }
  if (existsSync10(settingsPath)) {
    try {
      existingSettings = JSON.parse(readFileSync11(settingsPath, "utf-8"));
    } catch {
      process.stderr.write(`[PROTECT_MCP] Warning: Could not parse existing ${settingsPath}
`);
    }
  }
  const hookSettings = generateHookSettings2(hookUrl);
  const mergedSettings = {
    ...existingSettings,
    hooks: {
      ...existingSettings.hooks || {},
      ...hookSettings.hooks
    }
  };
  writeFileSync5(settingsPath, JSON.stringify(mergedSettings, null, 2) + "\n");
  process.stdout.write(`  ${green("\u2713")} ${settingsPath}
`);
  process.stdout.write(`    Hook URL: ${dim(hookUrl)}
`);
  process.stdout.write(`    Events: PreToolUse, PostToolUse, SubagentStart/Stop, Task, Session, Config, Stop

`);
  const keysDir = join9(dir, "keys");
  const keyPath = join9(keysDir, "gateway.json");
  if (!existsSync10(keyPath)) {
    if (!existsSync10(keysDir)) mkdirSync4(keysDir, { recursive: true });
    const { randomBytes: rb } = await import("crypto");
    try {
      const { ed25519: ed255192 } = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
      const { bytesToHex: bytesToHex2 } = await Promise.resolve().then(() => (init_utils(), utils_exports));
      const privateKey = rb(32);
      const publicKey = ed255192.getPublicKey(privateKey);
      writeFileSync5(keyPath, JSON.stringify({
        privateKey: bytesToHex2(privateKey),
        publicKey: bytesToHex2(publicKey),
        kid: `hook-${Date.now()}`,
        generated_at: (/* @__PURE__ */ new Date()).toISOString(),
        warning: "KEEP THIS FILE SECRET. Never commit to version control."
      }, null, 2) + "\n");
      const gitignorePath = join9(keysDir, ".gitignore");
      if (!existsSync10(gitignorePath)) {
        writeFileSync5(gitignorePath, "# Never commit signing keys\n*.json\n");
      }
      process.stdout.write(`  ${green("\u2713")} ${keyPath} (Ed25519 keypair)

`);
    } catch {
      process.stdout.write(`  ${yellow("\u26A0")} Could not generate Ed25519 keys, signing disabled

`);
    }
  } else {
    process.stdout.write(`  ${green("\u2713")} ${keyPath} (existing keys found)

`);
  }
  const policiesDir = join9(dir, "policies");
  const cedarPath = join9(policiesDir, "agent.cedar");
  if (!existsSync10(cedarPath)) {
    if (!existsSync10(policiesDir)) mkdirSync4(policiesDir, { recursive: true });
    writeFileSync5(cedarPath, generateSampleCedarPolicy2());
    process.stdout.write(`  ${green("\u2713")} ${cedarPath}
`);
    process.stdout.write(`    Edit to customize tool permissions. Cedar deny is AUTHORITATIVE.

`);
  } else {
    process.stdout.write(`  ${green("\u2713")} ${cedarPath} (existing policy found)

`);
  }
  const configPath = join9(dir, "protect-mcp.json");
  if (!existsSync10(configPath)) {
    const config = {
      tools: { "*": { rate_limit: "100/hour" } },
      default_tier: "unknown",
      signing: {
        key_path: "./keys/gateway.json",
        issuer: "protect-mcp",
        enabled: true
      }
    };
    writeFileSync5(configPath, JSON.stringify(config, null, 2) + "\n");
    process.stdout.write(`  ${green("\u2713")} ${configPath}

`);
  }
  const skillsDir = join9(dir, ".claude", "skills", "verify-receipt");
  const skillPath = join9(skillsDir, "SKILL.md");
  if (!existsSync10(skillPath)) {
    mkdirSync4(skillsDir, { recursive: true });
    writeFileSync5(skillPath, generateVerifyReceiptSkill2());
    process.stdout.write(`  ${green("\u2713")} ${skillPath}
`);
    process.stdout.write(`    Use ${dim("/verify-receipt")} in Claude Code to check audit trails.

`);
  } else {
    process.stdout.write(`  ${green("\u2713")} ${skillPath} (existing skill found)

`);
  }
  process.stdout.write(`${"\u2500".repeat(55)}

`);
  process.stdout.write(`${bold("Next steps:")}

`);
  process.stdout.write(`  1. Start the hook server:
`);
  process.stdout.write(`     ${dim(`npx protect-mcp serve`)}

`);
  process.stdout.write(`  2. Open a Claude Code session in this project.
`);
  process.stdout.write(`     Every tool call will be receipted automatically.

`);
  process.stdout.write(`  3. See your record: a searchable view of every decision.
`);
  process.stdout.write(`     ${dim(`npx protect-mcp record`)}
`);
  process.stdout.write(`     ${dim(`Everything stays on this machine. Nothing is uploaded.`)}

`);
  process.stdout.write(`     Prefer the terminal? ${dim(`npx protect-mcp receipts`)}, or ${dim("/verify-receipt")} in Claude Code.

`);
  process.stdout.write(`  4. View policy suggestions:
`);
  process.stdout.write(`     ${dim(`curl http://127.0.0.1:${port}/suggestions`)}

`);
  process.stdout.write(`${bold("Key facts:")}
`);
  process.stdout.write(`  \u2022 deny decisions are ${bold("AUTHORITATIVE")}: they cannot be overridden
`);
  process.stdout.write(`  \u2022 PostToolUse runs ${bold("async")}, so there is zero latency impact on tool execution
`);
  process.stdout.write(`  \u2022 Receipts are Ed25519-signed and append-only
`);
  process.stdout.write(`  \u2022 Swarm topology (coordinator/workers) is tracked automatically

`);
}
async function sendInstallTelemetry() {
  try {
    const { existsSync: existsSync10, mkdirSync: mkdirSync4, writeFileSync: writeFileSync5, readFileSync: readFileSync11 } = await import("fs");
    const { join: join9, dirname: dirname3 } = await import("path");
    const { homedir } = await import("os");
    const { fileURLToPath } = await import("url");
    const markerDir = join9(homedir(), ".protect-mcp");
    const markerFile = join9(markerDir, ".telemetry-sent");
    if (existsSync10(markerFile) || process.env.PROTECT_MCP_TELEMETRY === "off") {
      return;
    }
    const version = await pkgVersion();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3e3);
    fetch("https://api.scopeblind.com/telemetry/install", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: "protect-mcp",
        version,
        os: process.platform,
        arch: process.arch,
        node: process.version,
        ts: Date.now()
      }),
      signal: controller.signal
    }).catch(() => {
    }).finally(() => clearTimeout(timeout));
    if (!existsSync10(markerDir)) {
      mkdirSync4(markerDir, { recursive: true });
    }
    writeFileSync5(markerFile, String(Date.now()), "utf-8");
    process.stderr.write(
      "[protect-mcp] Thanks for installing! Anonymous telemetry sent (disable: PROTECT_MCP_TELEMETRY=off)\n[protect-mcp] Free dashboard: npx protect-mcp connect | https://scopeblind.com\n"
    );
  } catch {
  }
}
function flagValue(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : void 0;
}
function loadPolicyArg(argv) {
  const cedarDir = flagValue(argv, "--cedar");
  const policyFile = flagValue(argv, "--policy");
  try {
    if (cedarDir) return loadCedarPolicies(cedarDir);
    if (policyFile && (0, import_node_fs13.existsSync)(policyFile)) {
      return policySetFromSource((0, import_node_fs13.readFileSync)(policyFile, "utf-8"), (0, import_node_path9.basename)(policyFile));
    }
  } catch {
  }
  return null;
}
async function readHookStdin() {
  if (process.stdin.isTTY) return null;
  try {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf-8").trim();
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function mapHookPayload(j) {
  const tool = j.tool_name ?? j.toolName;
  const input = j.tool_input ?? j.toolInput;
  if (input === void 0 && j.command !== void 0) {
    return { tool: tool ?? "Bash", input: { command: j.command } };
  }
  return { tool, input };
}
function emitDecision(format, allowed, reason) {
  if (format === "hermes") {
    process.stdout.write(JSON.stringify(allowed ? {} : { decision: "block", reason }) + "\n");
    process.exit(0);
  }
  if (allowed) {
    process.stdout.write(JSON.stringify({ allowed: true, reason }) + "\n");
    process.exit(0);
  }
  if (format === "cursor") {
    process.stdout.write(JSON.stringify({ permission: "deny", userMessage: reason }) + "\n");
  } else if (format === "gemini") {
    process.stdout.write(JSON.stringify({ decision: "deny", reason }) + "\n");
  }
  process.stderr.write(`protect-mcp denied: ${reason}
`);
  process.exit(2);
}
async function handleEvaluate(argv) {
  const format = flagValue(argv, "--format");
  let tool = flagValue(argv, "--tool") || "";
  let inputRaw = flagValue(argv, "--input") || "{}";
  const contextRaw = flagValue(argv, "--context");
  const failOnMissing = flagValue(argv, "--fail-on-missing-policy") !== "false";
  if (format) {
    const j = await readHookStdin();
    if (j) {
      const m = mapHookPayload(j);
      if (m.tool) tool = m.tool;
      if (m.input !== void 0) inputRaw = JSON.stringify(m.input);
    }
  }
  const policySet = loadPolicyArg(argv);
  if (!policySet) {
    if (failOnMissing) {
      if (format) emitDecision(format, false, "policy not found (fail-closed)");
      process.stderr.write("protect-mcp evaluate: policy not found; denying (fail-closed). Pass --fail-on-missing-policy false to allow.\n");
      process.exit(2);
    }
    if (format) emitDecision(format, true, "no_policy_configured");
    process.stdout.write(JSON.stringify({ allowed: true, reason: "no_policy_configured" }) + "\n");
    process.exit(0);
  }
  let input = {};
  try {
    input = JSON.parse(inputRaw);
  } catch {
  }
  let extra = {};
  if (contextRaw) {
    try {
      extra = JSON.parse(contextRaw);
    } catch {
    }
  }
  const context = { ...input, ...extra };
  if (typeof input.command === "string" && context.command_pattern === void 0) {
    context.command_pattern = input.command;
  }
  const decision = await evaluateCedar(policySet, { tool, tier: "unknown", context, toolInput: input }, void 0, { failClosed: true });
  if (format) emitDecision(format, decision.allowed, decision.reason || (decision.allowed ? "allowed" : "denied by policy"));
  process.stdout.write(JSON.stringify({ allowed: decision.allowed, reason: decision.reason, policy_digest: policySet.digest }) + "\n");
  process.exit(decision.allowed ? 0 : 2);
}
async function handleSign(argv) {
  const format = flagValue(argv, "--format");
  let tool = flagValue(argv, "--tool") || "";
  const receiptsDir = flagValue(argv, "--receipts") || "./receipts/";
  const keyPath = flagValue(argv, "--key");
  if (format) {
    const j = await readHookStdin();
    if (j) {
      const m = mapHookPayload(j);
      if (m.tool) tool = m.tool;
    }
  }
  if (keyPath && (0, import_node_fs13.existsSync)(keyPath)) {
    try {
      await initSigning({ enabled: true, key_path: keyPath });
    } catch {
    }
  }
  const requestId = `tu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const signed = signDecision({
    tool,
    decision: "allow",
    reason_code: "post_execution_receipt",
    policy_digest: "none",
    request_id: requestId,
    mode: "enforce",
    timestamp: Date.now()
  });
  try {
    (0, import_node_fs13.mkdirSync)(receiptsDir, { recursive: true });
  } catch {
  }
  const line = signed.signed ?? JSON.stringify({ tool, request_id: requestId, signed: false, note: signed.warning || "no signer configured" });
  try {
    (0, import_node_fs13.appendFileSync)((0, import_node_path9.join)(receiptsDir, "receipts.jsonl"), line + "\n");
  } catch {
  }
  if (format === "hermes") {
    process.stdout.write("{}\n");
    process.exit(0);
  }
  process.stdout.write(JSON.stringify({ signed: Boolean(signed.signed), artifact_type: signed.artifact_type, request_id: requestId }) + "\n");
  process.exit(0);
}
async function handleSample(argv) {
  const dir = flagValue(argv, "--dir") || process.cwd();
  const { buildSampleKit: buildSampleKit2 } = await Promise.resolve().then(() => (init_sample(), sample_exports));
  let kit;
  try {
    kit = buildSampleKit2(dir, { force: argv.includes("--force") });
  } catch (err) {
    if (err?.code === "SAMPLE_EXISTS") {
      process.stderr.write(
        "\nprotect-mcp sample: this folder already has a record or signing key.\nThis command seeds a LABELED SAMPLE record and will not touch a real one.\nRun it in an empty folder, or pass --force to overwrite.\n\n"
      );
      process.exit(1);
    }
    throw err;
  }
  process.stdout.write(`
${bold("\u{1F6E1} Sample record seeded")} \xB7 8 decisions (1 blocked, 2 payments), signed with a fresh key ${dim(`(kid ${kit.kid})`)}

`);
  process.stdout.write("  .protect-mcp-receipts.jsonl   the signed sample record\n");
  process.stdout.write("  demo-tampered.jsonl           the same record with ONE decision edited after signing\n");
  process.stdout.write(`  keys/gateway.json             sample keypair ${dim("(never commit)")}

`);
  process.stdout.write(`${bold("Replay the demo")} ${dim("(the film: legate.scopeblind.com/record)")}
`);
  process.stdout.write("  npx protect-mcp record\n");
  process.stdout.write("  npx protect-mcp claim --payment-under 100 --anchor --output payments-under-100.json\n");
  process.stdout.write("  npx protect-mcp verify-claim payments-under-100.json\n");
  process.stdout.write("  npx protect-mcp anchor-record\n\n");
  process.stdout.write(`${dim("Drop demo-tampered.jsonl into the record page to watch tampering get caught.")}
`);
  process.stdout.write(`${dim("Everything runs locally; --anchor publishes only a digest to the public log.")}

`);
  process.exit(0);
}
async function main() {
  sendInstallTelemetry().catch(() => {
  });
  const args = process.argv.slice(2);
  process.env.PROTECT_MCP_VERSION = process.env.PROTECT_MCP_VERSION || await pkgVersion();
  const preSep = args.includes("--") ? args.slice(0, args.indexOf("--")) : args;
  if (args[0] === "version" || preSep.includes("--version") || preSep.includes("-V")) {
    process.stdout.write(`${process.env.PROTECT_MCP_VERSION || "unknown"}
`);
    process.exit(0);
  }
  if (args.length === 0 || args[0] === "help" || preSep.includes("--help") || preSep.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  if (args[0] === "evaluate") {
    await handleEvaluate(args.slice(1));
    return;
  }
  if (args[0] === "sign") {
    await handleSign(args.slice(1));
    return;
  }
  if (args[0] === "serve") {
    const { startHookServer: startHookServer2 } = await Promise.resolve().then(() => (init_hook_server(), hook_server_exports));
    const portIdx = args.indexOf("--port");
    const port = portIdx >= 0 && args[portIdx + 1] ? parseInt(args[portIdx + 1]) : 9377;
    const policyIdx = args.indexOf("--policy");
    const policyPath2 = policyIdx >= 0 && args[policyIdx + 1] ? args[policyIdx + 1] : void 0;
    const cedarIdx = args.indexOf("--cedar");
    const cedarDir2 = cedarIdx >= 0 && args[cedarIdx + 1] ? args[cedarIdx + 1] : void 0;
    const enforce2 = args.includes("--enforce");
    const verbose2 = args.includes("--verbose") || args.includes("-v");
    if (enforce2) {
      const selfTest = await runEvaluatorSelfTest();
      if (!selfTest.passed) {
        process.stderr.write("protect-mcp serve --enforce: the policy-engine restraint self-test FAILED. Refusing to arm the gate.\n");
        for (const c of selfTest.cases.filter((c2) => !c2.pass)) {
          process.stderr.write(`  [FAIL] ${c.name}: expected ${c.expected}, got ${c.actual}
`);
        }
        process.exit(1);
      }
      if (verbose2) process.stderr.write(`protect-mcp: restraint self-test passed (${selfTest.cases.length} vectors). Arming gate.
`);
    }
    await startHookServer2({ port, policyPath: policyPath2, cedarDir: cedarDir2, enforce: enforce2, verbose: verbose2 });
    return;
  }
  if (args[0] === "record") {
    await handleRecord(args.slice(1));
    return;
  }
  if (args[0] === "claim") {
    await handleClaim(args.slice(1));
    return;
  }
  if (args[0] === "verify-claim") {
    await handleVerifyClaim(args.slice(1));
    return;
  }
  if (args[0] === "anchor-record") {
    await handleAnchorRecord(args.slice(1));
    return;
  }
  if (args[0] === "sample") {
    await handleSample(args.slice(1));
    return;
  }
  if (args[0] === "init-hooks") {
    await handleInitHooks(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "quickstart") {
    await handleQuickstart(args.slice(1));
    return;
  }
  if (args[0] === "wrap") {
    await handleWrap(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "dashboard") {
    await handleDashboard(args.slice(1));
    return;
  }
  if (args[0] === "recommend") {
    await handleRecommend(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "registry") {
    await handleRegistry(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "trial") {
    await handleKillerDemo(args.slice(1));
    process.stdout.write(`${bold("Next: open the local dashboard")}
`);
    process.stdout.write(`  npx protect-mcp dashboard --dir ${dim(flagValue(args.slice(1), "--dir") || "<demo dir printed above>")} --open

`);
    process.stdout.write(`${dim("No ScopeBlind account is required for local receipts. Add --hosted with SCOPEBLIND_TOKEN when you want independent digest anchoring.")}

`);
    process.exit(0);
  }
  if (args[0] === "killer-demo") {
    await handleKillerDemo(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "verify-disclosure") {
    await handleVerifyDisclosure(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "policy-packs") {
    await handlePolicyPacks(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "connectors") {
    await handleConnectors(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "connect") {
    await handleConnect();
    process.exit(0);
  }
  if (args[0] === "init") {
    await handleInit(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "demo") {
    await handleDemo();
    return;
  }
  if (args[0] === "status") {
    await handleStatus2(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "digest") {
    await handleDigest(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "receipts") {
    await handleReceipts2(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "bundle") {
    await handleBundle(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "trace") {
    await handleTrace(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "simulate") {
    await handleSimulate(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "report") {
    await handleReport(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "doctor") {
    await handleDoctor();
    process.exit(0);
  }
  const { policyPath, cedarDir, slug, enforce, verbose, childCommand } = parseArgs(args);
  let policy = null;
  let policyDigest = "none";
  let credentials;
  let signing;
  let cedarPolicySet = null;
  let effectiveCedarDir = cedarDir;
  if (!effectiveCedarDir && !policyPath) {
    const { existsSync: existsSync10, readdirSync: readdirSync4 } = await import("fs");
    for (const candidate of ["cedar", "policies", "."]) {
      try {
        if (existsSync10(candidate) && readdirSync4(candidate).some((f) => f.endsWith(".cedar"))) {
          effectiveCedarDir = candidate;
          process.stderr.write(`[PROTECT_MCP] Auto-detected Cedar policies in ./${candidate}/
`);
          break;
        }
      } catch {
      }
    }
  }
  if (effectiveCedarDir) {
    try {
      const cedarAvailable = await isCedarAvailable();
      if (!cedarAvailable) {
        process.stderr.write("[PROTECT_MCP] Warning: @cedar-policy/cedar-wasm not installed. Install with: npm install @cedar-policy/cedar-wasm\n");
        process.stderr.write("[PROTECT_MCP] Cedar policies will be loaded but evaluated with fallback (allow-all).\n");
      }
      cedarPolicySet = loadCedarPolicies(effectiveCedarDir);
      policyDigest = cedarPolicySet.digest;
      policy = {
        tools: { "*": { require: "any" } },
        policy_engine: "cedar",
        cedar_dir: effectiveCedarDir
      };
      process.stderr.write(`[PROTECT_MCP] Cedar policy engine: loaded ${cedarPolicySet.fileCount} policies from ${effectiveCedarDir} (digest: ${policyDigest})
`);
      if (verbose) {
        process.stderr.write(`[PROTECT_MCP] Cedar files: ${cedarPolicySet.files.join(", ")}
`);
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading Cedar policies: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
  } else if (policyPath) {
    try {
      const loaded = loadPolicy(policyPath);
      policy = loaded.policy;
      policyDigest = loaded.digest;
      credentials = loaded.credentials;
      signing = loaded.signing;
      if (verbose) {
        process.stderr.write(`[PROTECT_MCP] Loaded policy from ${policyPath} (digest: ${policyDigest})
`);
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading policy: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
  }
  if (signing) {
    const warnings = await initSigning(signing);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  if (credentials) {
    const warnings = validateCredentials(credentials);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  const config = {
    command: childCommand[0],
    args: childCommand.slice(1),
    policy,
    policyDigest,
    slug,
    enforce,
    verbose,
    signing,
    credentials
  };
  const useHttp = args.includes("--http");
  if (useHttp) {
    const portIdx = args.indexOf("--port");
    const httpPort = portIdx >= 0 && args[portIdx + 1] ? parseInt(args[portIdx + 1]) : 3e3;
    const { startHttpTransport: startHttpTransport2 } = await Promise.resolve().then(() => (init_http_transport(), http_transport_exports));
    startHttpTransport2({ port: httpPort, config, serverCommand: childCommand });
    return;
  }
  const gateway = new ProtectGateway(config);
  if (cedarPolicySet) {
    gateway.setCedarPolicies(cedarPolicySet);
  }
  await gateway.start();
}
async function handleSimulate(args) {
  let policyPath = "";
  let logPath = ".protect-mcp-log.jsonl";
  let tier = "unknown";
  let jsonOutput = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--policy" && args[i + 1]) {
      policyPath = args[++i];
    } else if (args[i] === "--log" && args[i + 1]) {
      logPath = args[++i];
    } else if (args[i] === "--tier" && args[i + 1]) {
      tier = args[++i];
    } else if (args[i] === "--json") {
      jsonOutput = true;
    }
  }
  if (!policyPath) {
    process.stderr.write("Usage: protect-mcp simulate --policy <path> [--log <path>] [--tier <tier>] [--json]\n");
    process.exit(1);
  }
  const { existsSync: existsSync10 } = await import("fs");
  if (!existsSync10(logPath)) {
    process.stderr.write(`Log file not found: ${logPath}
`);
    process.stderr.write("Run protect-mcp in shadow mode first to generate a log file.\n");
    process.exit(1);
  }
  const { policy } = loadPolicy(policyPath);
  const entries = parseLogFile(logPath);
  if (entries.length === 0) {
    process.stderr.write("No tool call entries found in log file.\n");
    process.exit(1);
  }
  const summary = simulate(entries, policy, tier);
  summary.policy_file = policyPath;
  summary.log_file = logPath;
  if (jsonOutput) {
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  } else {
    process.stdout.write(formatSimulation(summary) + "\n");
  }
}
async function handleDoctor() {
  const { existsSync: existsSync10, readFileSync: readFileSync11, readdirSync: readdirSync4 } = await import("fs");
  const { join: join9 } = await import("path");
  const { execSync } = await import("child_process");
  const green2 = (s) => `\x1B[32m\u2713\x1B[0m ${s}`;
  const red2 = (s) => `\x1B[31m\u2717\x1B[0m ${s}`;
  const yellow2 = (s) => `\x1B[33m\u26A0\x1B[0m ${s}`;
  const dim2 = (s) => `\x1B[2m${s}\x1B[0m`;
  process.stdout.write("\n\x1B[1mprotect-mcp doctor\x1B[0m\n");
  process.stdout.write(dim2("Checking your ScopeBlind setup...\n\n"));
  let issues = 0;
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1));
  if (major >= 18) {
    process.stdout.write(green2(`Node.js ${nodeVersion}
`));
  } else {
    process.stdout.write(red2(`Node.js ${nodeVersion}, requires >= 18
`));
    issues++;
  }
  const configPath = join9(process.cwd(), "scopeblind.config.json");
  if (existsSync10(configPath)) {
    try {
      const config = JSON.parse(readFileSync11(configPath, "utf-8"));
      if (config.signing?.private_key || config.signing?.key_file) {
        process.stdout.write(green2("Signing keys configured\n"));
      } else {
        process.stdout.write(yellow2("Config found but no signing keys. Run: protect-mcp init\n"));
        issues++;
      }
    } catch {
      process.stdout.write(red2("Invalid scopeblind.config.json\n"));
      issues++;
    }
  } else {
    process.stdout.write(yellow2("No scopeblind.config.json. Run: protect-mcp init\n"));
  }
  let policyFound = false;
  for (const dir of ["cedar", "policies", "."]) {
    try {
      if (existsSync10(dir) && readdirSync4(dir).some((f) => f.endsWith(".cedar"))) {
        process.stdout.write(green2(`Cedar policies found in ./${dir}/
`));
        policyFound = true;
        break;
      }
    } catch {
    }
  }
  if (!policyFound) {
    for (const name of ["policy.json", "protect-mcp.policy.json", "scopeblind-policy.json"]) {
      if (existsSync10(name)) {
        process.stdout.write(green2(`JSON policy found: ${name}
`));
        policyFound = true;
        break;
      }
    }
  }
  if (!policyFound) {
    process.stdout.write(yellow2("No policy files found, running in shadow mode (allow all)\n"));
  }
  try {
    const cedarAvailable = await isCedarAvailable();
    if (cedarAvailable) {
      process.stdout.write(green2("Cedar WASM engine available\n"));
    } else {
      process.stdout.write(dim2("  Cedar WASM not installed. Install: npm install @cedar-policy/cedar-wasm\n"));
    }
  } catch {
    process.stdout.write(dim2("  Cedar WASM not installed\n"));
  }
  const logFile = join9(process.cwd(), "protect-mcp-decisions.jsonl");
  const receiptFile = join9(process.cwd(), "protect-mcp-receipts.jsonl");
  if (existsSync10(logFile)) {
    try {
      const lines = readFileSync11(logFile, "utf-8").trim().split("\n").length;
      process.stdout.write(green2(`Decision log: ${lines} entries
`));
    } catch {
      process.stdout.write(green2("Decision log exists\n"));
    }
  } else {
    process.stdout.write(dim2("  No decision log yet, will be created on first tool call\n"));
  }
  if (existsSync10(receiptFile)) {
    try {
      const lines = readFileSync11(receiptFile, "utf-8").trim().split("\n").length;
      process.stdout.write(green2(`Receipt file: ${lines} signed receipts
`));
    } catch {
      process.stdout.write(green2("Receipt file exists\n"));
    }
  }
  try {
    execSync("npx @veritasacta/verify --version 2>/dev/null", { stdio: "pipe", timeout: 1e4 });
    process.stdout.write(green2("Verifier available: @veritasacta/verify\n"));
  } catch {
    process.stdout.write(dim2("  Verifier not cached. Install: npm install -g @veritasacta/verify\n"));
  }
  try {
    const res = await fetch("https://api.scopeblind.com/health", { signal: AbortSignal.timeout(5e3) });
    if (res.ok) {
      process.stdout.write(green2("ScopeBlind API reachable\n"));
    } else {
      process.stdout.write(yellow2("ScopeBlind API returned non-200, receipts will be stored locally\n"));
    }
  } catch {
    process.stdout.write(dim2("  ScopeBlind API not reachable, offline mode (receipts stored locally)\n"));
  }
  process.stdout.write("\nRestraint self-test:\n");
  try {
    const st = await runEvaluatorSelfTest();
    if (!st.wasmAvailable) {
      process.stdout.write(dim2("  Cedar WASM not installed; the gate fails closed (denies) until it is.\n"));
    }
    for (const c of st.cases) {
      process.stdout.write(c.pass ? green2(`  ${c.name}
`) : `\x1B[31m  FAIL: ${c.name} (expected ${c.expected}, got ${c.actual})
\x1B[0m`);
    }
    if (!st.passed) issues++;
    else process.stdout.write(green2("  the gate denies what it should and allows what it should\n"));
  } catch (err) {
    process.stdout.write(yellow2(`  self-test could not run: ${err instanceof Error ? err.message : "unknown"}
`));
    issues++;
  }
  process.stdout.write("\n");
  if (issues === 0) {
    process.stdout.write("\x1B[32m\x1B[1mAll checks passed.\x1B[0m Ready to wrap MCP servers.\n");
    process.stdout.write(dim2("\n  npx protect-mcp -- node your-server.js\n\n"));
  } else {
    process.stdout.write(`\x1B[33m\x1B[1m${issues} issue(s) found.\x1B[0m Fix them and run doctor again.

`);
  }
}
async function handleReport(args) {
  let period = 30;
  let format = "json";
  let outputPath = "";
  let dir = process.cwd();
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--period" && args[i + 1]) {
      const match = args[++i].match(/^(\d+)d$/);
      if (match) period = parseInt(match[1], 10);
    } else if (args[i] === "--format" && args[i + 1]) {
      format = args[++i];
    } else if (args[i] === "--output" && args[i + 1]) {
      outputPath = args[++i];
    } else if (args[i] === "--dir" && args[i + 1]) {
      dir = args[++i];
    }
  }
  const { generateReport: generateReport2, formatReportMarkdown: formatReportMarkdown2 } = await Promise.resolve().then(() => (init_report(), report_exports));
  const { join: join9 } = await import("path");
  const logPath = join9(dir, ".protect-mcp-log.jsonl");
  const receiptPath = join9(dir, ".protect-mcp-receipts.jsonl");
  const report = generateReport2(logPath, receiptPath, period);
  let output;
  if (format === "md") {
    output = formatReportMarkdown2(report);
  } else {
    output = JSON.stringify(report, null, 2);
  }
  if (outputPath) {
    const { writeFileSync: writeFileSync5 } = await import("fs");
    writeFileSync5(outputPath, output, "utf-8");
    process.stderr.write(`Report written to ${outputPath}
`);
  } else {
    process.stdout.write(output + "\n");
  }
}
main().catch((err) => {
  process.stderr.write(`[PROTECT_MCP] Fatal error: ${err instanceof Error ? err.message : err}
`);
  process.exit(1);
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
/*! Bundled license information:

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/utils.js:
@noble/curves/esm/abstract/modular.js:
@noble/curves/esm/abstract/curve.js:
@noble/curves/esm/abstract/edwards.js:
@noble/curves/esm/abstract/montgomery.js:
@noble/curves/esm/ed25519.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
