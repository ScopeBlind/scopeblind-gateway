import {
  collectSignedReceipts,
  createAuditBundle
} from "./chunk-PM2ZO57M.mjs";
import {
  createSelectiveDisclosurePackage,
  discloseField,
  hmac,
  sha256 as sha2562,
  signCommittedDecision,
  verifySelectiveDisclosurePackage
} from "./chunk-WV4DKYE4.mjs";
import {
  formatReportMarkdown,
  generateReport
} from "./chunk-JQDVKZBN.mjs";
import {
  CONNECTOR_PILOTS,
  POLICY_PACKS,
  connectorDirectory,
  connectorDoctor,
  connectorPilotIds,
  formatSimulation,
  getConnectorPilot,
  getPolicyPack,
  parseLogFile,
  policyPackIds,
  readInstalledConnectorPilots,
  simulate,
  writeConnectorPilots
} from "./chunk-JCMDLN5I.mjs";
import {
  ProtectGateway,
  buildDecisionContext,
  evaluateTier,
  listCredentialLabels,
  meetsMinTier,
  parseNotificationConfigFromEnv,
  queryExternalPDP,
  resolveCredential,
  sendApprovalNotification,
  validateCredentials
} from "./chunk-VTPZ4G5I.mjs";
import {
  createSandboxServer
} from "./chunk-SETXVE2K.mjs";
import {
  BUILTIN_PATTERNS,
  generateHookSettings,
  generateSampleCedarPolicy,
  generateVerifyReceiptSkill
} from "./chunk-NMZPXXL3.mjs";
import {
  ScopeBlindBridge,
  forwardReceipt,
  getScopeBlindBridge,
  startHookServer
} from "./chunk-6E2DHBAR.mjs";
import {
  checkRateLimit,
  evaluateCedar,
  getSignerInfo,
  getToolPolicy,
  initSigning,
  isCedarAvailable,
  isSigningEnabled,
  loadCedarPolicies,
  loadPolicy,
  parseRateLimit,
  policySetFromSource,
  runEvaluatorSelfTest,
  signDecision
} from "./chunk-WIPWNWMJ.mjs";
import {
  Field,
  _abool2,
  _abytes2,
  _createCurveFields,
  _validateObject,
  aInRange,
  bitLen,
  bitMask,
  bytesToNumberBE,
  createHmacDrbg,
  ed25519,
  ensureBytes,
  getMinHashLength,
  mapHashToField,
  memoized,
  mulEndoUnsafe,
  nLength,
  negateCt,
  normalizeZ,
  numberToHexUnpadded,
  pippenger,
  sha256,
  sha384,
  sha512,
  wNAF
} from "./chunk-LJQOALYR.mjs";
import {
  ahash,
  bytesToHex,
  concatBytes,
  hexToBytes,
  isBytes,
  randomBytes
} from "./chunk-D733KAPG.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/manifest.ts
function isAgentId(s) {
  return /^sb:agent:[a-f0-9]{32}$/.test(s);
}
function isEvidenceType(s) {
  return ["arena", "benchmark", "work", "restraint", "attestation"].includes(s);
}
function isManifestStatus(s) {
  return ["active", "suspended", "revoked"].includes(s);
}
function isDisclosureMode(s) {
  return ["private", "scoped", "named"].includes(s);
}
function validateManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== "object") {
    return ["Manifest must be a non-null object"];
  }
  const m = manifest;
  if (m.manifest_version !== "0.1") {
    errors.push(`manifest_version must be "0.1", got "${m.manifest_version}"`);
  }
  if (typeof m.id !== "string" || !isAgentId(m.id)) {
    errors.push(`id must be a valid AgentId (sb:agent:{32 hex chars}), got "${m.id}"`);
  }
  if (typeof m.version !== "number" || !Number.isInteger(m.version) || m.version < 1) {
    errors.push(`version must be a positive integer, got ${m.version}`);
  }
  if (m.previous_version !== null && (typeof m.previous_version !== "string" || !m.previous_version.startsWith("sha256:"))) {
    errors.push(`previous_version must be null or a sha256: prefixed hash`);
  }
  if (typeof m.created_at !== "string") {
    errors.push("created_at is required (ISO 8601 string)");
  }
  if (typeof m.updated_at !== "string") {
    errors.push("updated_at is required (ISO 8601 string)");
  }
  if (typeof m.status !== "string" || !isManifestStatus(m.status)) {
    errors.push(`status must be "active", "suspended", or "revoked", got "${m.status}"`);
  }
  if (!m.identity || typeof m.identity !== "object") {
    errors.push("identity is required");
  } else {
    const id = m.identity;
    if (typeof id.public_key !== "string" || !id.public_key.startsWith("ed25519:")) {
      errors.push("identity.public_key must be an ed25519: prefixed key");
    }
    if (id.key_algorithm !== "Ed25519") {
      errors.push('identity.key_algorithm must be "Ed25519"');
    }
  }
  if (!m.capabilities || typeof m.capabilities !== "object") {
    errors.push("capabilities is required");
  } else {
    const cap = m.capabilities;
    if (typeof cap.model_family_hash !== "string" || !cap.model_family_hash.startsWith("sha256:")) {
      errors.push("capabilities.model_family_hash must be a sha256: prefixed hash");
    }
    if (!Array.isArray(cap.tool_categories)) {
      errors.push("capabilities.tool_categories must be an array");
    }
    if (!Array.isArray(cap.supported_disclosure_modes)) {
      errors.push("capabilities.supported_disclosure_modes must be an array");
    } else {
      for (const mode of cap.supported_disclosure_modes) {
        if (!isDisclosureMode(mode)) {
          errors.push(`Invalid disclosure mode: "${mode}"`);
        }
      }
    }
  }
  if (!m.config || typeof m.config !== "object") {
    errors.push("config is required");
  } else {
    const cfg = m.config;
    for (const field of ["system_prompt_hash", "tool_definitions_hash", "parameters_hash"]) {
      if (typeof cfg[field] !== "string" || !cfg[field].startsWith("sha256:")) {
        errors.push(`config.${field} must be a sha256: prefixed hash`);
      }
    }
  }
  if (!m.evidence_summary || typeof m.evidence_summary !== "object") {
    errors.push("evidence_summary is required");
  } else {
    const ev = m.evidence_summary;
    for (const type of ["arena", "benchmark", "work", "restraint", "attestation"]) {
      if (!ev[type] || typeof ev[type] !== "object") {
        errors.push(`evidence_summary.${type} is required`);
      } else {
        const entry = ev[type];
        if (typeof entry.count !== "number") errors.push(`evidence_summary.${type}.count must be a number`);
        if (typeof entry.latest_at !== "string") errors.push(`evidence_summary.${type}.latest_at must be a string`);
        if (typeof entry.issuer !== "string") errors.push(`evidence_summary.${type}.issuer must be a string`);
      }
    }
  }
  if (!m.signature || typeof m.signature !== "object") {
    errors.push("signature is required");
  } else {
    const sig = m.signature;
    if (sig.algorithm !== "Ed25519") {
      errors.push('signature.algorithm must be "Ed25519"');
    }
    if (typeof sig.signer !== "string") {
      errors.push("signature.signer is required");
    }
    if (typeof sig.value !== "string") {
      errors.push("signature.value is required");
    }
  }
  return errors;
}
function validateEvidenceReceipt(receipt) {
  const errors = [];
  if (!receipt || typeof receipt !== "object") {
    return ["Receipt must be a non-null object"];
  }
  const r = receipt;
  if (r.receipt_version !== "0.1") {
    errors.push(`receipt_version must be "0.1", got "${r.receipt_version}"`);
  }
  if (typeof r.receipt_id !== "string") {
    errors.push("receipt_id is required");
  }
  if (typeof r.evidence_type !== "string" || !isEvidenceType(r.evidence_type)) {
    errors.push(`evidence_type must be one of: arena, benchmark, work, restraint, attestation`);
  }
  if (typeof r.agent_id !== "string" || !isAgentId(r.agent_id)) {
    errors.push("agent_id must be a valid AgentId");
  }
  if (!r.issuer || typeof r.issuer !== "object") {
    errors.push("issuer is required");
  } else {
    const iss = r.issuer;
    if (typeof iss.id !== "string") errors.push("issuer.id is required");
    if (typeof iss.type !== "string") errors.push("issuer.type is required");
    if (typeof iss.public_key !== "string" || !iss.public_key.startsWith("ed25519:")) {
      errors.push("issuer.public_key must be an ed25519: prefixed key");
    }
  }
  if (typeof r.issued_at !== "string") {
    errors.push("issued_at is required (ISO 8601 string)");
  }
  if (typeof r.freshness_window_seconds !== "number") {
    errors.push("freshness_window_seconds is required");
  }
  if (!r.payload || typeof r.payload !== "object") {
    errors.push("payload is required");
  }
  if (!r.signature || typeof r.signature !== "object") {
    errors.push("signature is required");
  }
  return errors;
}

// src/cedar-schema.ts
function jsonSchemaToCedarType(schema, namespace, path) {
  if (schema.enum) {
    return "String";
  }
  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
  switch (type) {
    case "string":
      if (schema.format === "date-time") return "String";
      if (schema.format === "uri") return "String";
      return "String";
    case "integer":
    case "number":
      return "Long";
    case "boolean":
      return "Bool";
    case "array":
      if (schema.items) {
        const itemType = jsonSchemaToCedarType(schema.items, namespace, path + "_item");
        return `Set<${itemType}>`;
      }
      return "Set<String>";
    // Default to Set<String> for untyped arrays
    case "object":
      if (schema.properties && Object.keys(schema.properties).length > 0) {
        const fields = Object.entries(schema.properties).map(([key, prop]) => {
          const cedarType = jsonSchemaToCedarType(prop, namespace, path + "_" + sanitizeIdentifier(key));
          const isRequired = schema.required?.includes(key) ?? false;
          return `    "${sanitizeIdentifier(key)}": ${cedarType}${isRequired ? "" : "?"}`;
        });
        return `{
${fields.join(",\n")}
  }`;
      }
      return "Record";
    // Empty objects
    default:
      return "String";
  }
}
function sanitizeIdentifier(name) {
  return name.replace(/[^a-zA-Z0-9_]/g, "_").replace(/^(\d)/, "_$1");
}
function cedarActionId(toolName) {
  if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(toolName)) {
    return toolName;
  }
  return toolName;
}
function generateCedarSchema(tools, config = {}) {
  const ns = config.namespace || "ScopeBlind";
  const includeTier = config.includeTier !== false;
  const includeTimestamp = config.includeTimestamp !== false;
  const includeAgentId = config.includeAgentId !== false;
  const agentAttrs = [];
  if (includeTier) agentAttrs.push('    "tier": String');
  if (includeAgentId) agentAttrs.push('    "agent_id": String?');
  const sessionFields = [];
  if (includeTimestamp) sessionFields.push('    "timestamp": String?');
  sessionFields.push('    "hook_event": String?');
  const actionDeclarations = [];
  const inputTypeDeclarations = [];
  for (const tool of tools) {
    const actionName = cedarActionId(tool.name);
    const inputTypeName = `${sanitizeIdentifier(tool.name)}_Input`;
    if (tool.inputSchema?.properties && Object.keys(tool.inputSchema.properties).length > 0) {
      const fields = Object.entries(tool.inputSchema.properties).map(([key, prop]) => {
        const cedarType = jsonSchemaToCedarType(prop, ns, sanitizeIdentifier(tool.name) + "_" + sanitizeIdentifier(key));
        const isRequired = tool.inputSchema?.required?.includes(key) ?? false;
        return `    "${sanitizeIdentifier(key)}": ${cedarType}${isRequired ? "" : "?"}`;
      });
      inputTypeDeclarations.push(
        `  // Input type for tool: ${tool.name}` + (tool.description ? `
  // ${tool.description}` : "") + `
  type ${inputTypeName} = {
${fields.join(",\n")}
  };`
      );
      actionDeclarations.push(
        `  action "${actionName}" in [Action::"MCP::Tool::call"] appliesTo {
    principal: [Agent],
    resource: [Tool],
    context: {
      "input": ${inputTypeName},
      "tier": String${includeTimestamp ? ',\n      "timestamp": String?' : ""}${includeAgentId ? ',\n      "agent_id": String?' : ""}
    }
  };`
      );
    } else {
      actionDeclarations.push(
        `  action "${actionName}" in [Action::"MCP::Tool::call"] appliesTo {
    principal: [Agent],
    resource: [Tool],
    context: {
      "tier": String${includeTimestamp ? ',\n      "timestamp": String?' : ""}${includeAgentId ? ',\n      "agent_id": String?' : ""}
    }
  };`
      );
    }
  }
  actionDeclarations.push(
    `  // Blanket action for policies matching any tool call
  action "MCP::Tool::call" appliesTo {
    principal: [Agent],
    resource: [Tool],
    context: {
      "tier": String${includeTimestamp ? ',\n      "timestamp": String?' : ""}${includeAgentId ? ',\n      "agent_id": String?' : ""}
    }
  };`
  );
  const schemaText = [
    `// Cedar schema for MCP tool governance`,
    `// Generated by protect-mcp from ${tools.length} tool description(s)`,
    `// Compatible with cedar-policy/cedar-for-agents`,
    ``,
    `namespace ${ns} {`,
    ``,
    `  // \u2500\u2500 Entity types \u2500\u2500`,
    ``,
    `  entity Agent${agentAttrs.length > 0 ? ` = {
${agentAttrs.join(",\n")}
  }` : ""};`,
    ``,
    `  entity Tool;`,
    ``,
    ...inputTypeDeclarations.length > 0 ? [`  // \u2500\u2500 Tool input types \u2500\u2500`, ``, ...inputTypeDeclarations, ``] : [],
    `  // \u2500\u2500 Actions \u2500\u2500`,
    ``,
    ...actionDeclarations,
    ``,
    `}`,
    ``
  ].join("\n");
  const schemaJson = buildSchemaJson(tools, ns, config);
  return {
    schemaText,
    schemaJson,
    toolCount: tools.length,
    tools: tools.map((t) => t.name)
  };
}
function buildSchemaJson(tools, namespace, config) {
  const entityTypes = {
    Agent: {
      shape: {
        type: "Record",
        attributes: {
          ...config.includeTier !== false ? { tier: { type: "String", required: false } } : {},
          ...config.includeAgentId !== false ? { agent_id: { type: "String", required: false } } : {}
        }
      },
      memberOfTypes: []
    },
    Tool: {
      shape: { type: "Record", attributes: {} },
      memberOfTypes: []
    }
  };
  const actions = {};
  for (const tool of tools) {
    const contextAttrs = {
      tier: { type: "String", required: false }
    };
    if (config.includeTimestamp !== false) {
      contextAttrs["timestamp"] = { type: "String", required: false };
    }
    if (config.includeAgentId !== false) {
      contextAttrs["agent_id"] = { type: "String", required: false };
    }
    if (tool.inputSchema?.properties) {
      const inputAttrs = {};
      for (const [key, prop] of Object.entries(tool.inputSchema.properties)) {
        inputAttrs[sanitizeIdentifier(key)] = {
          type: jsonSchemaToSchemaJsonType(prop),
          required: tool.inputSchema.required?.includes(key) ?? false
        };
      }
      contextAttrs["input"] = {
        type: "Record",
        attributes: inputAttrs,
        required: false
      };
    }
    actions[tool.name] = {
      appliesTo: {
        principalTypes: ["Agent"],
        resourceTypes: ["Tool"],
        context: { type: "Record", attributes: contextAttrs }
      },
      memberOf: [{ id: "MCP::Tool::call" }]
    };
  }
  const blanketContext = {
    tier: { type: "String", required: false }
  };
  if (config.includeTimestamp !== false) {
    blanketContext["timestamp"] = { type: "String", required: false };
  }
  if (config.includeAgentId !== false) {
    blanketContext["agent_id"] = { type: "String", required: false };
  }
  actions["MCP::Tool::call"] = {
    appliesTo: {
      principalTypes: ["Agent"],
      resourceTypes: ["Tool"],
      context: { type: "Record", attributes: blanketContext }
    }
  };
  return {
    [namespace]: {
      entityTypes,
      actions
    }
  };
}
function jsonSchemaToSchemaJsonType(schema) {
  if (schema.enum) return "String";
  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
  switch (type) {
    case "string":
      return "String";
    case "integer":
    case "number":
      return "Long";
    case "boolean":
      return "EntityOrCommon";
    // Cedar JSON schema uses this for Bool
    case "array":
      return "Set";
    default:
      return "String";
  }
}
function generateSchemaStub(namespace = "ScopeBlind") {
  return [
    `// Cedar schema stub for protect-mcp`,
    `// This defines the principal and resource entity types.`,
    `// Tool-specific actions are auto-generated from MCP tools/list.`,
    `//`,
    `// Compatible with cedar-policy/cedar-for-agents @mcp_principal/@mcp_resource annotations.`,
    `// See: https://github.com/cedar-policy/cedar-for-agents`,
    ``,
    `namespace ${namespace} {`,
    ``,
    `  // @mcp_principal`,
    `  entity Agent = {`,
    `    "tier": String,`,
    `    "agent_id": String?`,
    `  };`,
    ``,
    `  // @mcp_resource`,
    `  entity Tool;`,
    ``,
    `  // @mcp_action`,
    `  action "MCP::Tool::call" appliesTo {`,
    `    principal: [Agent],`,
    `    resource: [Tool],`,
    `    context: {`,
    `      "tier": String`,
    `    }`,
    `  };`,
    ``,
    `}`,
    ``
  ].join("\n");
}

// src/rekor-anchor.ts
import { createHash } from "crypto";
var REKOR_API = "https://rekor.sigstore.dev/api/v1";
async function anchorToRekor(receiptHash, signature, publicKeyPem) {
  const entry = {
    apiVersion: "0.0.1",
    kind: "hashedrekord",
    spec: {
      data: {
        hash: {
          algorithm: "sha256",
          value: receiptHash
        }
      },
      signature: {
        content: signature,
        publicKey: {
          content: Buffer.from(publicKeyPem).toString("base64")
        }
      }
    }
  };
  const response = await fetch(`${REKOR_API}/log/entries`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(entry)
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Rekor anchoring failed: ${response.status} ${errorText}`);
  }
  const result = await response.json();
  const [uuid, data] = Object.entries(result)[0];
  return {
    logIndex: data.logIndex,
    uuid,
    integratedTime: new Date(data.integratedTime * 1e3).toISOString(),
    receiptHash,
    logID: data.logID,
    body: data.body
  };
}
async function verifyRekorAnchor(logIndex, expectedHash) {
  const response = await fetch(`${REKOR_API}/log/entries?logIndex=${logIndex}`);
  if (!response.ok) {
    return {
      valid: false,
      logIndex,
      integratedTime: "",
      receiptHashMatch: false
    };
  }
  const result = await response.json();
  const [, data] = Object.entries(result)[0];
  let receiptHashMatch = false;
  try {
    const bodyJson = JSON.parse(Buffer.from(data.body, "base64").toString());
    const hash = bodyJson?.spec?.data?.hash?.value;
    receiptHashMatch = hash === expectedHash;
  } catch {
  }
  return {
    valid: receiptHashMatch,
    logIndex,
    integratedTime: new Date(data.integratedTime * 1e3).toISOString(),
    receiptHashMatch
  };
}
function hashReceipt(receipt) {
  const canonical = JSON.stringify(receipt, Object.keys(receipt).sort());
  return createHash("sha256").update(canonical).digest("hex");
}
function createLogAnchorField(anchor) {
  return {
    transparency_log: "rekor.sigstore.dev",
    log_index: anchor.logIndex,
    integrated_time: anchor.integratedTime,
    receipt_hash: anchor.receiptHash,
    verify_url: `https://search.sigstore.dev/?logIndex=${anchor.logIndex}`
  };
}

// src/selective-disclosure.ts
import { createHash as createHash2, randomBytes as randomBytes2 } from "crypto";
function redactFields(receipt, fieldsToRedact) {
  const redacted = JSON.parse(JSON.stringify(receipt));
  const salts = [];
  const redactedFields = [];
  const originalHash = hashObject(receipt);
  for (const fieldPath of fieldsToRedact) {
    const parts = fieldPath.split(".");
    let current = redacted;
    let parent = null;
    let lastKey = "";
    for (let i = 0; i < parts.length; i++) {
      const key = parts[i];
      if (i === parts.length - 1) {
        if (key in current) {
          const originalValue = current[key];
          const salt = randomBytes2(16).toString("hex");
          const commitment = computeCommitment(salt, originalValue);
          salts.push({ field: fieldPath, salt, originalValue });
          current[key] = `sha256(salt + ${typeof originalValue === "string" ? "..." : JSON.stringify(originalValue).slice(0, 20) + "..."})`;
          redactedFields.push(fieldPath);
          if (!redacted._commitments) {
            redacted._commitments = {};
          }
          redacted._commitments[fieldPath] = commitment;
        }
      } else {
        if (typeof current[key] === "object" && current[key] !== null) {
          parent = current;
          lastKey = key;
          current = current[key];
        } else {
          break;
        }
      }
    }
  }
  return { redacted, salts, redactedFields, originalHash };
}
function revealField(redactedReceipt, salts, fieldPath) {
  const salt = salts.find((s) => s.field === fieldPath);
  if (!salt) {
    throw new Error(`No salt found for field: ${fieldPath}`);
  }
  const revealed = JSON.parse(JSON.stringify(redactedReceipt));
  const parts = fieldPath.split(".");
  let current = revealed;
  for (let i = 0; i < parts.length; i++) {
    const key = parts[i];
    if (i === parts.length - 1) {
      current[key] = salt.originalValue;
    } else {
      current = current[key];
    }
  }
  return revealed;
}
function verifyCommitment(commitment, salt, value) {
  const expected = computeCommitment(salt, value);
  return commitment === expected;
}
function verifyAllCommitments(redactedReceipt, salts) {
  const commitments = redactedReceipt._commitments;
  if (!commitments) {
    return { valid: true, fields: {} };
  }
  const fields = {};
  let allValid = true;
  for (const salt of salts) {
    const commitment = commitments[salt.field];
    if (commitment) {
      const valid = verifyCommitment(commitment, salt.salt, salt.originalValue);
      fields[salt.field] = valid;
      if (!valid) allValid = false;
    }
  }
  return { valid: allValid, fields };
}
function createDisclosurePackage(allSalts, fieldsToDisclose) {
  const disclosed = allSalts.filter((s) => fieldsToDisclose.includes(s.field)).map((s) => ({ field: s.field, salt: s.salt, value: s.originalValue }));
  return {
    version: "0.1",
    disclosed_fields: fieldsToDisclose,
    salts: disclosed
  };
}
function computeCommitment(salt, value) {
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  return createHash2("sha256").update(salt + serialized).digest("hex");
}
function hashObject(obj) {
  const canonical = JSON.stringify(obj, Object.keys(obj).sort());
  return createHash2("sha256").update(canonical).digest("hex");
}

// src/huggingface-export.ts
function receiptsToHFRows(receipts) {
  return receipts.map((r) => {
    const raw = r;
    const payload = raw.payload || {};
    const edges = Array.isArray(raw.parent_receipts) ? raw.parent_receipts : [];
    return {
      receipt_id: String(raw.receipt_id || raw.id || ""),
      receipt_type: String(raw.receipt_type || raw.type || "unknown"),
      tool_name: payload.tool_name ? String(payload.tool_name) : null,
      decision: payload.decision ? String(payload.decision) : null,
      agent_id: payload.agent_id ? String(payload.agent_id) : raw.subject_id ? String(raw.subject_id) : null,
      issuer_id: String(raw.issuer_id || "unknown"),
      timestamp: String(raw.timestamp || raw.event_time || (/* @__PURE__ */ new Date()).toISOString()),
      policy_hash: payload.active_policy_hash ? String(payload.active_policy_hash) : null,
      edges,
      edge_count: edges.length,
      signature: raw.signature ? String(raw.signature) : null,
      signed: Boolean(raw.signature),
      context_hash: raw.context_hash ? String(raw.context_hash) : null,
      chain_id: raw.chain_id ? String(raw.chain_id) : null
    };
  });
}
function generateHFMetadata(rows, name) {
  const types = {};
  const decisions = {};
  const agents = /* @__PURE__ */ new Set();
  const tools = /* @__PURE__ */ new Set();
  let minTime = Infinity;
  let maxTime = -Infinity;
  for (const row of rows) {
    types[row.receipt_type] = (types[row.receipt_type] || 0) + 1;
    if (row.decision) decisions[row.decision] = (decisions[row.decision] || 0) + 1;
    if (row.agent_id) agents.add(row.agent_id);
    if (row.tool_name) tools.add(row.tool_name);
    const t = new Date(row.timestamp).getTime();
    if (t < minTime) minTime = t;
    if (t > maxTime) maxTime = t;
  }
  return {
    name: name || "scopeblind-acta-receipts",
    description: "Cryptographically signed decision receipts from AI agent tool calls. Each row is an Ed25519-signed receipt capturing a machine decision, its causal context, and policy evaluation result. Produced by protect-mcp and verified with @veritasacta/verify.",
    num_rows: rows.length,
    type_distribution: types,
    decision_distribution: decisions,
    time_range: {
      from: isFinite(minTime) ? new Date(minTime).toISOString() : "",
      to: isFinite(maxTime) ? new Date(maxTime).toISOString() : ""
    },
    unique_agents: agents.size,
    unique_tools: tools.size,
    exported_at: (/* @__PURE__ */ new Date()).toISOString(),
    license: "MIT",
    tags: [
      "ai-safety",
      "agent-governance",
      "cryptographic-receipts",
      "veritas-acta",
      "scopeblind",
      "mcp",
      "ed25519",
      "causal-dag",
      "decision-evidence"
    ]
  };
}
function exportJSONL(rows) {
  return rows.map((row) => JSON.stringify(row)).join("\n") + "\n";
}
function generateDatasetCard(metadata) {
  return `---
license: mit
task_categories:
  - text-classification
tags:
${metadata.tags.map((t) => `  - ${t}`).join("\n")}
size_categories:
  - ${metadata.num_rows < 1e3 ? "n<1K" : metadata.num_rows < 1e4 ? "1K<n<10K" : "10K<n<100K"}
---

# ${metadata.name}

${metadata.description}

## Dataset Structure

Each row is a cryptographically signed receipt representing a single machine decision.

| Field | Type | Description |
|-------|------|-------------|
| receipt_id | string | Unique receipt identifier (content-addressed hash) |
| receipt_type | string | decision, execution, outcome, policy_load, observation, approval |
| tool_name | string | MCP tool that was called |
| decision | string | allow, deny, or null |
| agent_id | string | Pseudonymous agent identifier |
| timestamp | string | ISO 8601 timestamp |
| policy_hash | string | SHA-256 hash of the active policy |
| edges | array | Typed causal edges to parent receipts |
| signature | string | Ed25519 signature (hex) |
| signed | boolean | Whether the receipt has a valid signature |

## Statistics

- **Total receipts:** ${metadata.num_rows.toLocaleString()}
- **Unique agents:** ${metadata.unique_agents}
- **Unique tools:** ${metadata.unique_tools}
- **Time range:** ${metadata.time_range.from} \u2192 ${metadata.time_range.to}

### Type distribution
${Object.entries(metadata.type_distribution).map(([k, v]) => `- ${k}: ${v}`).join("\n")}

### Decision distribution
${Object.entries(metadata.decision_distribution).map(([k, v]) => `- ${k}: ${v}`).join("\n")}

## Verification

Every receipt in this dataset can be independently verified:

\`\`\`bash
npx @veritasacta/verify receipt.json
\`\`\`

The verification is offline, MIT-licensed, and does not contact any server.

## Source

- Protocol: [Veritas Acta](https://veritasacta.com)
- Gateway: [protect-mcp](https://npmjs.com/package/protect-mcp)
- IETF Draft: [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)

## License

MIT
`;
}

// src/webauthn-approval.ts
import { createHash as createHash3, randomBytes as randomBytes3, timingSafeEqual } from "crypto";

// node_modules/@noble/curves/esm/abstract/weierstrass.js
var divNearest = (num, den) => (num + (num >= 0 ? den : -den) / _2n) / den;
function _splitEndoScalar(k, basis, n) {
  const [[a1, b1], [a2, b2]] = basis;
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);
  let k1 = k - c1 * a1 - c2 * a2;
  let k2 = -c1 * b1 - c2 * b2;
  const k1neg = k1 < _0n;
  const k2neg = k2 < _0n;
  if (k1neg)
    k1 = -k1;
  if (k2neg)
    k2 = -k2;
  const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n;
  if (k1 < _0n || k1 >= MAX_NUM || k2 < _0n || k2 >= MAX_NUM) {
    throw new Error("splitScalar (endomorphism): failed, k=" + k);
  }
  return { k1neg, k1, k2neg, k2 };
}
function validateSigFormat(format) {
  if (!["compact", "recovered", "der"].includes(format))
    throw new Error('Signature format must be "compact", "recovered", or "der"');
  return format;
}
function validateSigOpts(opts, def) {
  const optsn = {};
  for (let optName of Object.keys(def)) {
    optsn[optName] = opts[optName] === void 0 ? def[optName] : opts[optName];
  }
  _abool2(optsn.lowS, "lowS");
  _abool2(optsn.prehash, "prehash");
  if (optsn.format !== void 0)
    validateSigFormat(optsn.format);
  return optsn;
}
var DERErr = class extends Error {
  constructor(m = "") {
    super(m);
  }
};
var DER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag, data) => {
      const { Err: E } = DER;
      if (tag < 0 || tag > 256)
        throw new E("tlv.encode: wrong tag");
      if (data.length & 1)
        throw new E("tlv.encode: unpadded data");
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if (len.length / 2 & 128)
        throw new E("tlv.encode: long form length too big");
      const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag, data) {
      const { Err: E } = DER;
      let pos = 0;
      if (tag < 0 || tag > 256)
        throw new E("tlv.encode: wrong tag");
      if (data.length < 2 || data[pos++] !== tag)
        throw new E("tlv.decode: wrong tlv");
      const first = data[pos++];
      const isLong = !!(first & 128);
      let length = 0;
      if (!isLong)
        length = first;
      else {
        const lenLen = first & 127;
        if (!lenLen)
          throw new E("tlv.decode(long): indefinite length not supported");
        if (lenLen > 4)
          throw new E("tlv.decode(long): byte length is too big");
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen)
          throw new E("tlv.decode: length bytes not complete");
        if (lengthBytes[0] === 0)
          throw new E("tlv.decode(long): zero leftmost byte");
        for (const b of lengthBytes)
          length = length << 8 | b;
        pos += lenLen;
        if (length < 128)
          throw new E("tlv.decode(long): not minimal encoding");
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length)
        throw new E("tlv.decode: wrong value length");
      return { v, l: data.subarray(pos + length) };
    }
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num) {
      const { Err: E } = DER;
      if (num < _0n)
        throw new E("integer: negative integers are not allowed");
      let hex = numberToHexUnpadded(num);
      if (Number.parseInt(hex[0], 16) & 8)
        hex = "00" + hex;
      if (hex.length & 1)
        throw new E("unexpected DER parsing assertion: unpadded hex");
      return hex;
    },
    decode(data) {
      const { Err: E } = DER;
      if (data[0] & 128)
        throw new E("invalid signature integer: negative");
      if (data[0] === 0 && !(data[1] & 128))
        throw new E("invalid signature integer: unnecessary leading zero");
      return bytesToNumberBE(data);
    }
  },
  toSig(hex) {
    const { Err: E, _int: int, _tlv: tlv } = DER;
    const data = ensureBytes("signature", hex);
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
    if (seqLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
    if (sLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig) {
    const { _tlv: tlv, _int: int } = DER;
    const rs = tlv.encode(2, int.encode(sig.r));
    const ss = tlv.encode(2, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(48, seq);
  }
};
var _0n = BigInt(0);
var _1n = BigInt(1);
var _2n = BigInt(2);
var _3n = BigInt(3);
var _4n = BigInt(4);
function _normFnElement(Fn, key) {
  const { BYTES: expected } = Fn;
  let num;
  if (typeof key === "bigint") {
    num = key;
  } else {
    let bytes = ensureBytes("private key", key);
    try {
      num = Fn.fromBytes(bytes);
    } catch (error) {
      throw new Error(`invalid private key: expected ui8a of size ${expected}, got ${typeof key}`);
    }
  }
  if (!Fn.isValidNot0(num))
    throw new Error("invalid private key: out of range [1..N-1]");
  return num;
}
function weierstrassN(params, extraOpts = {}) {
  const validated = _createCurveFields("weierstrass", params, extraOpts);
  const { Fp, Fn } = validated;
  let CURVE = validated.CURVE;
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  _validateObject(extraOpts, {}, {
    allowInfinityPoint: "boolean",
    clearCofactor: "function",
    isTorsionFree: "function",
    fromBytes: "function",
    toBytes: "function",
    endo: "object",
    wrapPrivateKey: "boolean"
  });
  const { endo } = extraOpts;
  if (endo) {
    if (!Fp.is0(CURVE.a) || typeof endo.beta !== "bigint" || !Array.isArray(endo.basises)) {
      throw new Error('invalid endo: expected "beta": bigint and "basises": array');
    }
  }
  const lengths = getWLengths(Fp, Fn);
  function assertCompressionIsSupported() {
    if (!Fp.isOdd)
      throw new Error("compression is not supported: Field does not have .isOdd()");
  }
  function pointToBytes(_c, point, isCompressed) {
    const { x, y } = point.toAffine();
    const bx = Fp.toBytes(x);
    _abool2(isCompressed, "isCompressed");
    if (isCompressed) {
      assertCompressionIsSupported();
      const hasEvenY = !Fp.isOdd(y);
      return concatBytes(pprefix(hasEvenY), bx);
    } else {
      return concatBytes(Uint8Array.of(4), bx, Fp.toBytes(y));
    }
  }
  function pointFromBytes(bytes) {
    _abytes2(bytes, void 0, "Point");
    const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    if (length === comp && (head === 2 || head === 3)) {
      const x = Fp.fromBytes(tail);
      if (!Fp.isValid(x))
        throw new Error("bad point: is not on curve, wrong x");
      const y2 = weierstrassEquation(x);
      let y;
      try {
        y = Fp.sqrt(y2);
      } catch (sqrtError) {
        const err = sqrtError instanceof Error ? ": " + sqrtError.message : "";
        throw new Error("bad point: is not on curve, sqrt error" + err);
      }
      assertCompressionIsSupported();
      const isYOdd = Fp.isOdd(y);
      const isHeadOdd = (head & 1) === 1;
      if (isHeadOdd !== isYOdd)
        y = Fp.neg(y);
      return { x, y };
    } else if (length === uncomp && head === 4) {
      const L = Fp.BYTES;
      const x = Fp.fromBytes(tail.subarray(0, L));
      const y = Fp.fromBytes(tail.subarray(L, L * 2));
      if (!isValidXY(x, y))
        throw new Error("bad point: is not on curve");
      return { x, y };
    } else {
      throw new Error(`bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`);
    }
  }
  const encodePoint = extraOpts.toBytes || pointToBytes;
  const decodePoint = extraOpts.fromBytes || pointFromBytes;
  function weierstrassEquation(x) {
    const x2 = Fp.sqr(x);
    const x3 = Fp.mul(x2, x);
    return Fp.add(Fp.add(x3, Fp.mul(x, CURVE.a)), CURVE.b);
  }
  function isValidXY(x, y) {
    const left = Fp.sqr(y);
    const right = weierstrassEquation(x);
    return Fp.eql(left, right);
  }
  if (!isValidXY(CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n), _4n);
  const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
  if (Fp.is0(Fp.add(_4a3, _27b2)))
    throw new Error("bad curve params: a or b");
  function acoord(title, n, banZero = false) {
    if (!Fp.isValid(n) || banZero && Fp.is0(n))
      throw new Error(`bad point coordinate ${title}`);
    return n;
  }
  function aprjpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ProjectivePoint expected");
  }
  function splitEndoScalarN(k) {
    if (!endo || !endo.basises)
      throw new Error("no endo");
    return _splitEndoScalar(k, endo.basises, Fn.ORDER);
  }
  const toAffineMemo = memoized((p, iz) => {
    const { X, Y, Z } = p;
    if (Fp.eql(Z, Fp.ONE))
      return { x: X, y: Y };
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? Fp.ONE : Fp.inv(Z);
    const x = Fp.mul(X, iz);
    const y = Fp.mul(Y, iz);
    const zz = Fp.mul(Z, iz);
    if (is0)
      return { x: Fp.ZERO, y: Fp.ZERO };
    if (!Fp.eql(zz, Fp.ONE))
      throw new Error("invZ was invalid");
    return { x, y };
  });
  const assertValidMemo = memoized((p) => {
    if (p.is0()) {
      if (extraOpts.allowInfinityPoint && !Fp.is0(p.Y))
        return;
      throw new Error("bad point: ZERO");
    }
    const { x, y } = p.toAffine();
    if (!Fp.isValid(x) || !Fp.isValid(y))
      throw new Error("bad point: x or y not field elements");
    if (!isValidXY(x, y))
      throw new Error("bad point: equation left != right");
    if (!p.isTorsionFree())
      throw new Error("bad point: not in prime-order subgroup");
    return true;
  });
  function finishEndo(endoBeta, k1p, k2p, k1neg, k2neg) {
    k2p = new Point(Fp.mul(k2p.X, endoBeta), k2p.Y, k2p.Z);
    k1p = negateCt(k1neg, k1p);
    k2p = negateCt(k2neg, k2p);
    return k1p.add(k2p);
  }
  class Point {
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    constructor(X, Y, Z) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y, true);
      this.Z = acoord("z", Z);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    static fromAffine(p) {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point)
        throw new Error("projective point not allowed");
      if (Fp.is0(x) && Fp.is0(y))
        return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }
    static fromBytes(bytes) {
      const P = Point.fromAffine(decodePoint(_abytes2(bytes, void 0, "point")));
      P.assertValidity();
      return P;
    }
    static fromHex(hex) {
      return Point.fromBytes(ensureBytes("pointHex", hex));
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /**
     *
     * @param windowSize
     * @param isLazy true will defer table computation until the first multiplication
     * @returns
     */
    precompute(windowSize = 8, isLazy = true) {
      wnaf.createCache(this, windowSize);
      if (!isLazy)
        this.multiply(_3n);
      return this;
    }
    // TODO: return `this`
    /** A point on curve is valid if it conforms to equation. */
    assertValidity() {
      assertValidMemo(this);
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (!Fp.isOdd)
        throw new Error("Field doesn't support isOdd");
      return !Fp.isOdd(y);
    }
    /** Compare one point to another. */
    equals(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }
    /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
    negate() {
      return new Point(this.X, Fp.neg(this.Y), this.Z);
    }
    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.mul(b, _3n);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
      let t0 = Fp.mul(X1, X1);
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3);
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.mul(a, Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3);
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3);
      t2 = Fp.mul(a, t2);
      t3 = Fp.sub(t0, t2);
      t3 = Fp.mul(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0);
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1);
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3);
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }
    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
      const a = CURVE.a;
      const b3 = Fp.mul(CURVE.b, _3n);
      let t0 = Fp.mul(X1, X2);
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2);
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2);
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2);
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = Fp.mul(a, t4);
      X3 = Fp.mul(b3, t2);
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0);
      t1 = Fp.add(t1, t0);
      t2 = Fp.mul(a, t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2);
      t2 = Fp.mul(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4);
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0);
      return new Point(X3, Y3, Z3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * Uses precomputes when available.
     * Uses endomorphism for Koblitz curves.
     * @param scalar by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar) {
      const { endo: endo2 } = extraOpts;
      if (!Fn.isValidNot0(scalar))
        throw new Error("invalid scalar: out of range");
      let point, fake;
      const mul = (n) => wnaf.cached(this, n, (p) => normalizeZ(Point, p));
      if (endo2) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(scalar);
        const { p: k1p, f: k1f } = mul(k1);
        const { p: k2p, f: k2f } = mul(k2);
        fake = k1f.add(k2f);
        point = finishEndo(endo2.beta, k1p, k2p, k1neg, k2neg);
      } else {
        const { p, f } = mul(scalar);
        point = p;
        fake = f;
      }
      return normalizeZ(Point, [point, fake])[0];
    }
    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed secret key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(sc) {
      const { endo: endo2 } = extraOpts;
      const p = this;
      if (!Fn.isValid(sc))
        throw new Error("invalid scalar: out of range");
      if (sc === _0n || p.is0())
        return Point.ZERO;
      if (sc === _1n)
        return p;
      if (wnaf.hasCache(this))
        return this.multiply(sc);
      if (endo2) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(sc);
        const { p1, p2 } = mulEndoUnsafe(Point, p, k1, k2);
        return finishEndo(endo2.beta, p1, p2, k1neg, k2neg);
      } else {
        return wnaf.unsafe(p, sc);
      }
    }
    multiplyAndAddUnsafe(Q, a, b) {
      const sum = this.multiplyUnsafe(a).add(Q.multiplyUnsafe(b));
      return sum.is0() ? void 0 : sum;
    }
    /**
     * Converts Projective point to affine (x, y) coordinates.
     * @param invertedZ Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
     */
    toAffine(invertedZ) {
      return toAffineMemo(this, invertedZ);
    }
    /**
     * Checks whether Point is free of torsion elements (is in prime subgroup).
     * Always torsion-free for cofactor=1 curves.
     */
    isTorsionFree() {
      const { isTorsionFree } = extraOpts;
      if (cofactor === _1n)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point, this);
      return wnaf.unsafe(this, CURVE_ORDER).is0();
    }
    clearCofactor() {
      const { clearCofactor } = extraOpts;
      if (cofactor === _1n)
        return this;
      if (clearCofactor)
        return clearCofactor(Point, this);
      return this.multiplyUnsafe(cofactor);
    }
    isSmallOrder() {
      return this.multiplyUnsafe(cofactor).is0();
    }
    toBytes(isCompressed = true) {
      _abool2(isCompressed, "isCompressed");
      this.assertValidity();
      return encodePoint(Point, this, isCompressed);
    }
    toHex(isCompressed = true) {
      return bytesToHex(this.toBytes(isCompressed));
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
    // TODO: remove
    get px() {
      return this.X;
    }
    get py() {
      return this.X;
    }
    get pz() {
      return this.Z;
    }
    toRawBytes(isCompressed = true) {
      return this.toBytes(isCompressed);
    }
    _setWindowSize(windowSize) {
      this.precompute(windowSize);
    }
    static normalizeZ(points) {
      return normalizeZ(Point, points);
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn, points, scalars);
    }
    static fromPrivateKey(privateKey) {
      return Point.BASE.multiply(_normFnElement(Fn, privateKey));
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
  Point.ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
  Point.Fp = Fp;
  Point.Fn = Fn;
  const bits = Fn.BITS;
  const wnaf = new wNAF(Point, extraOpts.endo ? Math.ceil(bits / 2) : bits);
  Point.BASE.precompute(8);
  return Point;
}
function pprefix(hasEvenY) {
  return Uint8Array.of(hasEvenY ? 2 : 3);
}
function getWLengths(Fp, Fn) {
  return {
    secretKey: Fn.BYTES,
    publicKey: 1 + Fp.BYTES,
    publicKeyUncompressed: 1 + 2 * Fp.BYTES,
    publicKeyHasPrefix: true,
    signature: 2 * Fn.BYTES
  };
}
function ecdh(Point, ecdhOpts = {}) {
  const { Fn } = Point;
  const randomBytes_ = ecdhOpts.randomBytes || randomBytes;
  const lengths = Object.assign(getWLengths(Point.Fp, Fn), { seed: getMinHashLength(Fn.ORDER) });
  function isValidSecretKey(secretKey) {
    try {
      return !!_normFnElement(Fn, secretKey);
    } catch (error) {
      return false;
    }
  }
  function isValidPublicKey(publicKey, isCompressed) {
    const { publicKey: comp, publicKeyUncompressed } = lengths;
    try {
      const l = publicKey.length;
      if (isCompressed === true && l !== comp)
        return false;
      if (isCompressed === false && l !== publicKeyUncompressed)
        return false;
      return !!Point.fromBytes(publicKey);
    } catch (error) {
      return false;
    }
  }
  function randomSecretKey(seed = randomBytes_(lengths.seed)) {
    return mapHashToField(_abytes2(seed, lengths.seed, "seed"), Fn.ORDER);
  }
  function getPublicKey(secretKey, isCompressed = true) {
    return Point.BASE.multiply(_normFnElement(Fn, secretKey)).toBytes(isCompressed);
  }
  function keygen(seed) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  }
  function isProbPub(item) {
    if (typeof item === "bigint")
      return false;
    if (item instanceof Point)
      return true;
    const { secretKey, publicKey, publicKeyUncompressed } = lengths;
    if (Fn.allowedLengths || secretKey === publicKey)
      return void 0;
    const l = ensureBytes("key", item).length;
    return l === publicKey || l === publicKeyUncompressed;
  }
  function getSharedSecret(secretKeyA, publicKeyB, isCompressed = true) {
    if (isProbPub(secretKeyA) === true)
      throw new Error("first arg must be private key");
    if (isProbPub(publicKeyB) === false)
      throw new Error("second arg must be public key");
    const s = _normFnElement(Fn, secretKeyA);
    const b = Point.fromHex(publicKeyB);
    return b.multiply(s).toBytes(isCompressed);
  }
  const utils = {
    isValidSecretKey,
    isValidPublicKey,
    randomSecretKey,
    // TODO: remove
    isValidPrivateKey: isValidSecretKey,
    randomPrivateKey: randomSecretKey,
    normPrivateKeyToScalar: (key) => _normFnElement(Fn, key),
    precompute(windowSize = 8, point = Point.BASE) {
      return point.precompute(windowSize, false);
    }
  };
  return Object.freeze({ getPublicKey, getSharedSecret, keygen, Point, utils, lengths });
}
function ecdsa(Point, hash, ecdsaOpts = {}) {
  ahash(hash);
  _validateObject(ecdsaOpts, {}, {
    hmac: "function",
    lowS: "boolean",
    randomBytes: "function",
    bits2int: "function",
    bits2int_modN: "function"
  });
  const randomBytes4 = ecdsaOpts.randomBytes || randomBytes;
  const hmac2 = ecdsaOpts.hmac || ((key, ...msgs) => hmac(hash, key, concatBytes(...msgs)));
  const { Fp, Fn } = Point;
  const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn;
  const { keygen, getPublicKey, getSharedSecret, utils, lengths } = ecdh(Point, ecdsaOpts);
  const defaultSigOpts = {
    prehash: false,
    lowS: typeof ecdsaOpts.lowS === "boolean" ? ecdsaOpts.lowS : false,
    format: void 0,
    //'compact' as ECDSASigFormat,
    extraEntropy: false
  };
  const defaultSigOpts_format = "compact";
  function isBiggerThanHalfOrder(number) {
    const HALF = CURVE_ORDER >> _1n;
    return number > HALF;
  }
  function validateRS(title, num) {
    if (!Fn.isValidNot0(num))
      throw new Error(`invalid signature ${title}: out of range 1..Point.Fn.ORDER`);
    return num;
  }
  function validateSigLength(bytes, format) {
    validateSigFormat(format);
    const size = lengths.signature;
    const sizer = format === "compact" ? size : format === "recovered" ? size + 1 : void 0;
    return _abytes2(bytes, sizer, `${format} signature`);
  }
  class Signature {
    constructor(r, s, recovery) {
      this.r = validateRS("r", r);
      this.s = validateRS("s", s);
      if (recovery != null)
        this.recovery = recovery;
      Object.freeze(this);
    }
    static fromBytes(bytes, format = defaultSigOpts_format) {
      validateSigLength(bytes, format);
      let recid;
      if (format === "der") {
        const { r: r2, s: s2 } = DER.toSig(_abytes2(bytes));
        return new Signature(r2, s2);
      }
      if (format === "recovered") {
        recid = bytes[0];
        format = "compact";
        bytes = bytes.subarray(1);
      }
      const L = Fn.BYTES;
      const r = bytes.subarray(0, L);
      const s = bytes.subarray(L, L * 2);
      return new Signature(Fn.fromBytes(r), Fn.fromBytes(s), recid);
    }
    static fromHex(hex, format) {
      return this.fromBytes(hexToBytes(hex), format);
    }
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    recoverPublicKey(messageHash) {
      const FIELD_ORDER = Fp.ORDER;
      const { r, s, recovery: rec } = this;
      if (rec == null || ![0, 1, 2, 3].includes(rec))
        throw new Error("recovery id invalid");
      const hasCofactor = CURVE_ORDER * _2n < FIELD_ORDER;
      if (hasCofactor && rec > 1)
        throw new Error("recovery id is ambiguous for h>1 curve");
      const radj = rec === 2 || rec === 3 ? r + CURVE_ORDER : r;
      if (!Fp.isValid(radj))
        throw new Error("recovery id 2 or 3 invalid");
      const x = Fp.toBytes(radj);
      const R = Point.fromBytes(concatBytes(pprefix((rec & 1) === 0), x));
      const ir = Fn.inv(radj);
      const h = bits2int_modN(ensureBytes("msgHash", messageHash));
      const u1 = Fn.create(-h * ir);
      const u2 = Fn.create(s * ir);
      const Q = Point.BASE.multiplyUnsafe(u1).add(R.multiplyUnsafe(u2));
      if (Q.is0())
        throw new Error("point at infinify");
      Q.assertValidity();
      return Q;
    }
    // Signatures should be low-s, to prevent malleability.
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    toBytes(format = defaultSigOpts_format) {
      validateSigFormat(format);
      if (format === "der")
        return hexToBytes(DER.hexFromSig(this));
      const r = Fn.toBytes(this.r);
      const s = Fn.toBytes(this.s);
      if (format === "recovered") {
        if (this.recovery == null)
          throw new Error("recovery bit must be present");
        return concatBytes(Uint8Array.of(this.recovery), r, s);
      }
      return concatBytes(r, s);
    }
    toHex(format) {
      return bytesToHex(this.toBytes(format));
    }
    // TODO: remove
    assertValidity() {
    }
    static fromCompact(hex) {
      return Signature.fromBytes(ensureBytes("sig", hex), "compact");
    }
    static fromDER(hex) {
      return Signature.fromBytes(ensureBytes("sig", hex), "der");
    }
    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, Fn.neg(this.s), this.recovery) : this;
    }
    toDERRawBytes() {
      return this.toBytes("der");
    }
    toDERHex() {
      return bytesToHex(this.toBytes("der"));
    }
    toCompactRawBytes() {
      return this.toBytes("compact");
    }
    toCompactHex() {
      return bytesToHex(this.toBytes("compact"));
    }
  }
  const bits2int = ecdsaOpts.bits2int || function bits2int_def(bytes) {
    if (bytes.length > 8192)
      throw new Error("input is too large");
    const num = bytesToNumberBE(bytes);
    const delta = bytes.length * 8 - fnBits;
    return delta > 0 ? num >> BigInt(delta) : num;
  };
  const bits2int_modN = ecdsaOpts.bits2int_modN || function bits2int_modN_def(bytes) {
    return Fn.create(bits2int(bytes));
  };
  const ORDER_MASK = bitMask(fnBits);
  function int2octets(num) {
    aInRange("num < 2^" + fnBits, num, _0n, ORDER_MASK);
    return Fn.toBytes(num);
  }
  function validateMsgAndHash(message, prehash) {
    _abytes2(message, void 0, "message");
    return prehash ? _abytes2(hash(message), void 0, "prehashed message") : message;
  }
  function prepSig(message, privateKey, opts) {
    if (["recovered", "canonical"].some((k) => k in opts))
      throw new Error("sign() legacy options not supported");
    const { lowS, prehash, extraEntropy } = validateSigOpts(opts, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    const h1int = bits2int_modN(message);
    const d = _normFnElement(Fn, privateKey);
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (extraEntropy != null && extraEntropy !== false) {
      const e = extraEntropy === true ? randomBytes4(lengths.secretKey) : extraEntropy;
      seedArgs.push(ensureBytes("extraEntropy", e));
    }
    const seed = concatBytes(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!Fn.isValidNot0(k))
        return;
      const ik = Fn.inv(k);
      const q = Point.BASE.multiply(k).toAffine();
      const r = Fn.create(q.x);
      if (r === _0n)
        return;
      const s = Fn.create(ik * Fn.create(m + r * d));
      if (s === _0n)
        return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = Fn.neg(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, recovery);
    }
    return { seed, k2sig };
  }
  function sign(message, secretKey, opts = {}) {
    message = ensureBytes("message", message);
    const { seed, k2sig } = prepSig(message, secretKey, opts);
    const drbg = createHmacDrbg(hash.outputLen, Fn.BYTES, hmac2);
    const sig = drbg(seed, k2sig);
    return sig;
  }
  function tryParsingSig(sg) {
    let sig = void 0;
    const isHex = typeof sg === "string" || isBytes(sg);
    const isObj = !isHex && sg !== null && typeof sg === "object" && typeof sg.r === "bigint" && typeof sg.s === "bigint";
    if (!isHex && !isObj)
      throw new Error("invalid signature, expected Uint8Array, hex string or Signature instance");
    if (isObj) {
      sig = new Signature(sg.r, sg.s);
    } else if (isHex) {
      try {
        sig = Signature.fromBytes(ensureBytes("sig", sg), "der");
      } catch (derError) {
        if (!(derError instanceof DER.Err))
          throw derError;
      }
      if (!sig) {
        try {
          sig = Signature.fromBytes(ensureBytes("sig", sg), "compact");
        } catch (error) {
          return false;
        }
      }
    }
    if (!sig)
      return false;
    return sig;
  }
  function verify(signature, message, publicKey, opts = {}) {
    const { lowS, prehash, format } = validateSigOpts(opts, defaultSigOpts);
    publicKey = ensureBytes("publicKey", publicKey);
    message = validateMsgAndHash(ensureBytes("message", message), prehash);
    if ("strict" in opts)
      throw new Error("options.strict was renamed to lowS");
    const sig = format === void 0 ? tryParsingSig(signature) : Signature.fromBytes(ensureBytes("sig", signature), format);
    if (sig === false)
      return false;
    try {
      const P = Point.fromBytes(publicKey);
      if (lowS && sig.hasHighS())
        return false;
      const { r, s } = sig;
      const h = bits2int_modN(message);
      const is = Fn.inv(s);
      const u1 = Fn.create(h * is);
      const u2 = Fn.create(r * is);
      const R = Point.BASE.multiplyUnsafe(u1).add(P.multiplyUnsafe(u2));
      if (R.is0())
        return false;
      const v = Fn.create(R.x);
      return v === r;
    } catch (e) {
      return false;
    }
  }
  function recoverPublicKey(signature, message, opts = {}) {
    const { prehash } = validateSigOpts(opts, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    return Signature.fromBytes(signature, "recovered").recoverPublicKey(message).toBytes();
  }
  return Object.freeze({
    keygen,
    getPublicKey,
    getSharedSecret,
    utils,
    lengths,
    Point,
    sign,
    verify,
    recoverPublicKey,
    Signature,
    hash
  });
}
function _weierstrass_legacy_opts_to_new(c) {
  const CURVE = {
    a: c.a,
    b: c.b,
    p: c.Fp.ORDER,
    n: c.n,
    h: c.h,
    Gx: c.Gx,
    Gy: c.Gy
  };
  const Fp = c.Fp;
  let allowedLengths = c.allowedPrivateKeyLengths ? Array.from(new Set(c.allowedPrivateKeyLengths.map((l) => Math.ceil(l / 2)))) : void 0;
  const Fn = Field(CURVE.n, {
    BITS: c.nBitLength,
    allowedLengths,
    modFromBytes: c.wrapPrivateKey
  });
  const curveOpts = {
    Fp,
    Fn,
    allowInfinityPoint: c.allowInfinityPoint,
    endo: c.endo,
    isTorsionFree: c.isTorsionFree,
    clearCofactor: c.clearCofactor,
    fromBytes: c.fromBytes,
    toBytes: c.toBytes
  };
  return { CURVE, curveOpts };
}
function _ecdsa_legacy_opts_to_new(c) {
  const { CURVE, curveOpts } = _weierstrass_legacy_opts_to_new(c);
  const ecdsaOpts = {
    hmac: c.hmac,
    randomBytes: c.randomBytes,
    lowS: c.lowS,
    bits2int: c.bits2int,
    bits2int_modN: c.bits2int_modN
  };
  return { CURVE, curveOpts, hash: c.hash, ecdsaOpts };
}
function _ecdsa_new_output_to_legacy(c, _ecdsa) {
  const Point = _ecdsa.Point;
  return Object.assign({}, _ecdsa, {
    ProjectivePoint: Point,
    CURVE: Object.assign({}, c, nLength(Point.Fn.ORDER, Point.Fn.BITS))
  });
}
function weierstrass(c) {
  const { CURVE, curveOpts, hash, ecdsaOpts } = _ecdsa_legacy_opts_to_new(c);
  const Point = weierstrassN(CURVE, curveOpts);
  const signs = ecdsa(Point, hash, ecdsaOpts);
  return _ecdsa_new_output_to_legacy(c, signs);
}

// node_modules/@noble/curves/esm/_shortw_utils.js
function createCurve(curveDef, defHash) {
  const create = (hash) => weierstrass({ ...curveDef, hash });
  return { ...create(defHash), create };
}

// node_modules/@noble/curves/esm/nist.js
var p256_CURVE = {
  p: BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
  n: BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
  h: BigInt(1),
  a: BigInt("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
  b: BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
  Gx: BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
  Gy: BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
};
var p384_CURVE = {
  p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
  n: BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
  h: BigInt(1),
  a: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"),
  b: BigInt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
  Gx: BigInt("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
  Gy: BigInt("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
};
var p521_CURVE = {
  p: BigInt("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
  n: BigInt("0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"),
  h: BigInt(1),
  a: BigInt("0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc"),
  b: BigInt("0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
  Gx: BigInt("0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"),
  Gy: BigInt("0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")
};
var Fp256 = Field(p256_CURVE.p);
var Fp384 = Field(p384_CURVE.p);
var Fp521 = Field(p521_CURVE.p);
var p256 = createCurve({ ...p256_CURVE, Fp: Fp256, lowS: false }, sha256);
var p384 = createCurve({ ...p384_CURVE, Fp: Fp384, lowS: false }, sha384);
var p521 = createCurve({ ...p521_CURVE, Fp: Fp521, lowS: false, allowedPrivateKeyLengths: [130, 131, 132] }, sha512);

// node_modules/@noble/curves/esm/p256.js
var p2562 = p256;

// src/webauthn-approval.ts
function createApprovalChallenge(requestId, toolName, agentId, rpId = "scopeblind.com", timeoutSeconds = 300) {
  const challengeBytes = randomBytes3(32);
  const contextHash = createHash3("sha256").update(JSON.stringify({ requestId, toolName, agentId, timestamp: Date.now() })).digest("hex");
  return {
    challenge: base64urlEncode(challengeBytes),
    requestId,
    toolName,
    agentId,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    timeoutSeconds,
    rpId,
    contextHash
  };
}
function toCredentialRequestOptions(challenge, allowCredentials) {
  return {
    publicKey: {
      challenge: base64urlDecode(challenge.challenge).buffer,
      rpId: challenge.rpId,
      timeout: challenge.timeoutSeconds * 1e3,
      userVerification: "required",
      // Always require biometric
      ...allowCredentials ? {
        allowCredentials: allowCredentials.map((c) => ({
          id: base64urlDecode(c.id).buffer,
          type: "public-key"
        }))
      } : {}
    }
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
  const expectedRpIdHash = sha2562(new TextEncoder().encode(challenge.rpId));
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
  const signedData = concatBytes2(authData, sha2562(clientDataBytes));
  const sigBytes = base64urlDecode(assertion.signature);
  let sigOk = false;
  try {
    if (credentialPublicKey.alg === -7) {
      sigOk = p2562.verify(sigBytes, sha2562(signedData), hexToBytes(credentialPublicKey.publicKeyHex), { format: "der" });
    } else if (credentialPublicKey.alg === -8) {
      sigOk = ed25519.verify(sigBytes, signedData, hexToBytes(credentialPublicKey.publicKeyHex));
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
function createApprovalReceiptPayload(challenge, result) {
  return {
    type: "acta:approval",
    approval_method: "webauthn",
    tool_name: challenge.toolName,
    request_id: challenge.requestId,
    agent_id: challenge.agentId,
    authenticator_type: result.authenticatorType,
    user_verified: result.userVerified,
    context_hash: result.contextHash,
    approved_at: result.approvedAt,
    // Hash the credential ID for privacy — don't store the raw ID
    credential_id_hash: createHash3("sha256").update(result.credentialId).digest("hex").slice(0, 16)
  };
}
function base64urlEncode(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}
function concatBytes2(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function constantTimeStrEqual(a, b) {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// src/did-vc.ts
function ed25519ToDIDKey(publicKeyHex) {
  const multicodecPrefix = Buffer.from([237, 1]);
  const publicKeyBytes = Buffer.from(publicKeyHex, "hex");
  const multicodecKey = Buffer.concat([multicodecPrefix, publicKeyBytes]);
  const base58 = base58btcEncode(multicodecKey);
  return `did:key:z${base58}`;
}
function manifestToVC(manifest) {
  const did = ed25519ToDIDKey(manifest.public_key);
  return {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://veritasacta.com/contexts/agent-manifest/v1"
    ],
    type: ["VerifiableCredential", "AgentManifestCredential"],
    issuer: did,
    issuanceDate: manifest.created_at || (/* @__PURE__ */ new Date()).toISOString(),
    credentialSubject: {
      id: did,
      agentId: manifest.agent_id,
      displayName: manifest.display_name,
      capabilities: manifest.capabilities || [],
      policyDigest: manifest.policy_digest,
      publicKey: manifest.public_key
    },
    ...manifest.signature ? {
      proof: {
        type: "Ed25519Signature2020",
        created: manifest.created_at || (/* @__PURE__ */ new Date()).toISOString(),
        verificationMethod: `${did}#key-1`,
        proofPurpose: "assertionMethod",
        proofValue: manifest.signature
      }
    } : {}
  };
}
function receiptToVP(receipt, issuerPublicKey) {
  const did = ed25519ToDIDKey(issuerPublicKey);
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiablePresentation"],
    holder: did,
    verifiableCredential: [{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://veritasacta.com/contexts/decision-receipt/v1"
      ],
      type: ["VerifiableCredential", "DecisionReceiptCredential"],
      issuer: did,
      issuanceDate: receipt.event_time || (/* @__PURE__ */ new Date()).toISOString(),
      credentialSubject: {
        receiptId: receipt.receipt_id,
        receiptType: receipt.receipt_type,
        toolName: receipt.payload?.tool_name,
        decision: receipt.payload?.decision
      }
    }]
  };
}
function base58btcEncode(buffer) {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = BigInt("0x" + buffer.toString("hex"));
  let result = "";
  while (num > 0n) {
    result = ALPHABET[Number(num % 58n)] + result;
    num = num / 58n;
  }
  for (const byte of buffer) {
    if (byte === 0) result = "1" + result;
    else break;
  }
  return result;
}

// src/sandbox.ts
async function createSandbox(config) {
  const runtime = config.runtime || (config.apiKey || process.env.E2B_API_KEY ? "e2b" : "docker");
  if (runtime === "e2b") {
    return createE2BSandbox(config);
  }
  return createDockerSandbox(config);
}
async function runInSandbox(sandbox, toolCall, policy) {
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  const decision = evaluatePolicy(toolCall.tool, policy);
  const receipt = {
    tool: toolCall.tool,
    decision,
    executed: decision === "allow",
    timestamp
  };
  if (decision === "allow") {
    try {
      const result = await executeInSandbox(sandbox, toolCall);
      receipt.result = result;
      receipt.executed = true;
    } catch (err) {
      receipt.result = {
        success: false,
        output: "",
        error: err instanceof Error ? err.message : String(err),
        durationMs: 0
      };
    }
  }
  sandbox.receipts.push(receipt);
  return receipt;
}
function generateSafetyTranscript(sandbox, template) {
  const receipts = sandbox.receipts;
  const allowed = receipts.filter((r) => r.decision === "allow").length;
  const denied = receipts.filter((r) => r.decision === "deny").length;
  const requireApproval = receipts.filter((r) => r.decision === "require_approval").length;
  const executed = receipts.filter((r) => r.executed && r.result);
  const successful = executed.filter((r) => r.result?.success);
  const denyScore = denied > 0 ? 40 : allowed > 0 ? 20 : 40;
  const successRate = executed.length > 0 ? successful.length / executed.length : 1;
  const successScore = 30 * successRate;
  const approvalScore = requireApproval === 0 ? 30 : 15;
  const safetyScore = Math.round(denyScore + successScore + approvalScore);
  return {
    sandboxId: sandbox.id,
    template,
    totalCalls: receipts.length,
    allowed,
    denied,
    requireApproval,
    successRate,
    receipts,
    durationMs: 0,
    // Would be calculated from first/last receipt timestamps
    evaluatedAt: (/* @__PURE__ */ new Date()).toISOString(),
    safetyScore: Math.min(100, Math.max(0, safetyScore))
  };
}
async function destroySandbox(sandbox) {
  sandbox.status = "destroyed";
  if (sandbox.runtime === "docker") {
    try {
      const { execSync } = await import("child_process");
      execSync(`docker rm -f ${sandbox.id} 2>/dev/null`, { stdio: "pipe" });
    } catch {
    }
  }
}
async function createE2BSandbox(config) {
  const apiKey = config.apiKey || process.env.E2B_API_KEY;
  if (!apiKey) {
    throw new Error("E2B_API_KEY not set. Get one at https://e2b.dev");
  }
  const response = await fetch("https://api.e2b.dev/sandboxes", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey
    },
    body: JSON.stringify({
      templateID: config.template,
      timeout: config.timeoutSeconds || 300
    })
  });
  if (!response.ok) {
    throw new Error(`E2B sandbox creation failed: ${response.status}`);
  }
  const data = await response.json();
  return {
    id: data.sandboxID,
    runtime: "e2b",
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    status: "running",
    receipts: []
  };
}
async function createDockerSandbox(config) {
  const { execSync } = await import("child_process");
  const { randomUUID: randomUUID2 } = await import("crypto");
  const id = `scopeblind-sandbox-${randomUUID2().slice(0, 8)}`;
  const image = config.template.includes(":") ? config.template : `node:${config.template.replace("node-", "")}`;
  const memoryFlag = config.memoryMB ? `--memory=${config.memoryMB}m` : "";
  const timeout = config.timeoutSeconds || 300;
  try {
    execSync(
      `docker run -d --name ${id} ${memoryFlag} --network=none --stop-timeout=${timeout} ${image} sleep ${timeout}`,
      { stdio: "pipe" }
    );
  } catch (err) {
    throw new Error(`Docker sandbox creation failed: ${err instanceof Error ? err.message : err}`);
  }
  return {
    id,
    runtime: "docker",
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    status: "running",
    receipts: []
  };
}
async function executeInSandbox(sandbox, toolCall) {
  const start = Date.now();
  if (sandbox.runtime === "docker") {
    const { execSync } = await import("child_process");
    try {
      const command = toolCall.args.command || `echo "Tool: ${toolCall.tool}"`;
      const output = execSync(
        `docker exec ${sandbox.id} sh -c '${command.replace(/'/g, "'\\''")}'`,
        { stdio: "pipe", timeout: 3e4 }
      ).toString();
      return {
        success: true,
        output: output.trim(),
        durationMs: Date.now() - start,
        exitCode: 0
      };
    } catch (err) {
      const execErr = err;
      return {
        success: false,
        output: "",
        error: execErr.stderr?.toString() || String(err),
        durationMs: Date.now() - start,
        exitCode: execErr.status || 1
      };
    }
  }
  return {
    success: true,
    output: `[E2B] Executed ${toolCall.tool} in sandbox ${sandbox.id}`,
    durationMs: Date.now() - start
  };
}
function evaluatePolicy(tool, policy) {
  if (!policy) return "allow";
  const tools = policy.tools;
  if (!tools) return "allow";
  const toolPolicy = tools[tool] || tools["*"];
  if (!toolPolicy) return "allow";
  if (toolPolicy.block) return "deny";
  if (toolPolicy.require_approval) return "require_approval";
  return "allow";
}

// src/evidence-authenticity.ts
import { createHash as createHash4 } from "crypto";
async function createEvidenceAttestation(input) {
  const tlsNotaryAvailable = await isTLSNotaryAvailable();
  if (tlsNotaryAvailable) {
    return createTLSNotaryAttestation(input);
  }
  return {
    version: "0.1-beta",
    method: "self-reported",
    url: input.url,
    httpMethod: input.httpMethod || "GET",
    responseHash: input.responseHash,
    statusCode: input.statusCode || 200,
    fetchedAt: input.timestamp || (/* @__PURE__ */ new Date()).toISOString(),
    verified: false,
    verificationNote: "Self-reported attestation. No third-party verification. TLSNotary integration planned for Q3 2026."
  };
}
async function verifyEvidenceAttestation(attestation) {
  switch (attestation.method) {
    case "self-reported":
      return {
        valid: false,
        method: "self-reported",
        note: "Self-reported attestation cannot be independently verified. The response hash is included for integrity checking if the original data is available."
      };
    case "tlsnotary":
      if (!attestation.notaryPublicKey || !attestation.notarySignature) {
        return {
          valid: false,
          method: "tlsnotary",
          note: "TLSNotary attestation is missing notary public key or signature."
        };
      }
      return {
        valid: false,
        method: "tlsnotary",
        note: "TLSNotary verification not yet implemented. Attestation format is correct but signature cannot be checked."
      };
    case "oracle":
      return {
        valid: attestation.verified,
        method: "oracle",
        note: attestation.verified ? "Attestation verified by oracle service." : "Oracle verification pending or failed."
      };
    case "witness":
      return {
        valid: attestation.verified,
        method: "witness",
        note: attestation.verified ? "Attestation witnessed by independent third party." : "Witness verification pending."
      };
    default:
      return {
        valid: false,
        method: "unknown",
        note: "Unknown attestation method."
      };
  }
}
function hashResponseBody(body) {
  return createHash4("sha256").update(typeof body === "string" ? body : body).digest("hex");
}
function createAttestationField(attestation) {
  return {
    evidence_authenticity: {
      version: attestation.version,
      method: attestation.method,
      url_hash: createHash4("sha256").update(attestation.url).digest("hex").slice(0, 16),
      response_hash: attestation.responseHash,
      fetched_at: attestation.fetchedAt,
      verified: attestation.verified,
      note: attestation.verificationNote
    }
  };
}
async function isTLSNotaryAvailable() {
  try {
    await import("tlsn-js");
    return true;
  } catch {
    return false;
  }
}
async function createTLSNotaryAttestation(input) {
  return {
    version: "0.1-beta",
    method: "tlsnotary",
    url: input.url,
    httpMethod: input.httpMethod || "GET",
    responseHash: input.responseHash,
    statusCode: input.statusCode || 200,
    fetchedAt: input.timestamp || (/* @__PURE__ */ new Date()).toISOString(),
    verified: false,
    verificationNote: "TLSNotary SDK integration in progress. Attestation format is stable; verification will be enabled in a future release."
  };
}

// src/c2pa-credentials.ts
import { createHash as createHash5 } from "crypto";
function createC2PAManifest(receipts, options) {
  const generator = options.generator || "protect-mcp";
  const version = options.version || "0.3.3";
  const decisions = receipts.filter(
    (r) => r.receipt_type?.includes("decision") || r.type?.includes("decision")
  );
  const allows = decisions.filter(
    (r) => r.payload?.decision === "allow"
  );
  const denies = decisions.filter(
    (r) => r.payload?.decision === "deny"
  );
  const receiptHashes = receipts.map(
    (r) => createHash5("sha256").update(JSON.stringify(r)).digest("hex")
  );
  const merkleRoot = computeMerkleRoot(receiptHashes);
  const assertions = [
    // Acta decision provenance — the core assertion
    {
      label: "acta.decision-provenance",
      data: {
        protocol: "veritas-acta",
        protocol_version: "0.1",
        ietf_draft: "draft-farley-acta-signed-receipts-00",
        receipt_count: receipts.length,
        decision_count: decisions.length,
        allows: allows.length,
        denies: denies.length,
        merkle_root: merkleRoot,
        signing_algorithm: "Ed25519",
        canonicalization: "JCS (RFC 8785)",
        verifier: "npx @veritasacta/verify",
        verify_url: "https://scopeblind.com/verify",
        trace_url: "https://scopeblind.com/trace"
      }
    },
    // Policy compliance assertion
    {
      label: "acta.policy-compliance",
      data: {
        policy_violations: denies.length,
        total_decisions: decisions.length,
        compliance_rate: decisions.length > 0 ? (allows.length / decisions.length * 100).toFixed(1) + "%" : "N/A",
        policy_engine: "Cedar + JSON",
        human_approvals: receipts.filter(
          (r) => r.receipt_type?.includes("approval") || r.type?.includes("approval")
        ).length
      }
    },
    // Standard C2PA actions
    {
      label: "c2pa.actions",
      data: {
        actions: [
          {
            action: "c2pa.created",
            when: (/* @__PURE__ */ new Date()).toISOString(),
            softwareAgent: `${generator}/${version}`,
            parameters: {
              description: "Content generated by AI agent with ScopeBlind governance"
            }
          }
        ]
      }
    }
  ];
  if (options.includeFullReceipts) {
    assertions.push({
      label: "acta.receipt-chain",
      data: {
        receipts: receipts.map((r) => ({
          id: r.receipt_id || r.id,
          type: r.receipt_type || r.type,
          tool: r.payload?.tool_name,
          decision: r.payload?.decision,
          timestamp: r.timestamp || r.event_time
        }))
      }
    });
  } else {
    assertions.push({
      label: "acta.receipt-chain",
      data: {
        receipt_hashes: receiptHashes,
        merkle_root: merkleRoot,
        note: "Full receipts available via verify URL. Hashes provided for integrity verification."
      },
      is_hash: true
    });
  }
  if (options.additionalAssertions) {
    assertions.push(...options.additionalAssertions);
  }
  return {
    claim_generator: `${generator}/${version}`,
    claim_generator_info: [
      {
        name: generator,
        version
      }
    ],
    title: options.title,
    assertions
  };
}
function exportC2PAManifestJSON(manifest) {
  return JSON.stringify(manifest, null, 2);
}
function generateC2PACommand(manifestPath, inputPath, outputPath) {
  return `c2patool ${inputPath} -m ${manifestPath} -o ${outputPath}`;
}
function verifyActaC2PAAssertions(c2paManifestJson) {
  try {
    const manifest = JSON.parse(c2paManifestJson);
    const assertions = manifest.assertions || [];
    const provenanceAssertion = assertions.find(
      (a) => a.label === "acta.decision-provenance"
    );
    const complianceAssertion = assertions.find(
      (a) => a.label === "acta.policy-compliance"
    );
    if (!provenanceAssertion) {
      return {
        hasActaProvenance: false,
        receiptCount: 0,
        merkleRoot: null,
        complianceRate: null,
        verifyUrl: null
      };
    }
    return {
      hasActaProvenance: true,
      receiptCount: provenanceAssertion.data.receipt_count || 0,
      merkleRoot: provenanceAssertion.data.merkle_root || null,
      complianceRate: complianceAssertion ? complianceAssertion.data.compliance_rate : null,
      verifyUrl: provenanceAssertion.data.verify_url || null
    };
  } catch {
    return {
      hasActaProvenance: false,
      receiptCount: 0,
      merkleRoot: null,
      complianceRate: null,
      verifyUrl: null
    };
  }
}
function computeMerkleRoot(hashes) {
  if (hashes.length === 0) return "";
  if (hashes.length === 1) return hashes[0];
  const nextLevel = [];
  for (let i = 0; i < hashes.length; i += 2) {
    const left = hashes[i];
    const right = i + 1 < hashes.length ? hashes[i + 1] : left;
    nextLevel.push(
      createHash5("sha256").update(left + right).digest("hex")
    );
  }
  return computeMerkleRoot(nextLevel);
}

// src/prediction-bridge.ts
function computeCalibration(predictions, resolutions) {
  let totalSquaredError = 0;
  let resolved = 0;
  const buckets = /* @__PURE__ */ new Map();
  for (const pred of predictions) {
    const resolution = resolutions.get(pred.receipt_id);
    if (!resolution || resolution.payload.resolution_value === "ambiguous") continue;
    resolved++;
    const actual = resolution.payload.resolution_value === "true" ? 1 : 0;
    const error = (pred.payload.probability - actual) ** 2;
    totalSquaredError += error;
    const bucketKey = `${Math.floor(pred.payload.probability * 10) / 10}-${Math.ceil(pred.payload.probability * 10) / 10}`;
    const bucket = buckets.get(bucketKey) || { sum: 0, actual: 0, count: 0 };
    bucket.sum += pred.payload.probability;
    bucket.actual += actual;
    bucket.count++;
    buckets.set(bucketKey, bucket);
  }
  return {
    total_predictions: predictions.length,
    resolved,
    brier_score: resolved > 0 ? totalSquaredError / resolved : 0,
    calibration_buckets: Array.from(buckets.entries()).map(([bucket, data]) => ({
      bucket,
      predicted_probability: data.sum / data.count,
      actual_frequency: data.actual / data.count,
      count: data.count
    }))
  };
}
function toMetaculusFormat(prediction) {
  return {
    prediction_value: prediction.payload.probability,
    acta_receipt_id: prediction.receipt_id,
    acta_signature: prediction.signature
  };
}
function toManifoldFormat(prediction) {
  return {
    probability: prediction.payload.probability,
    acta_receipt_id: prediction.receipt_id,
    acta_signature: prediction.signature
  };
}

// src/agent-exchange.ts
import { randomUUID } from "crypto";
var ReceiptPropagator = class {
  issuer;
  signer;
  receipts = /* @__PURE__ */ new Map();
  delegationCallCounts = /* @__PURE__ */ new Map();
  constructor(config) {
    this.issuer = config.issuer;
    this.signer = config.signer;
  }
  /**
   * Create a delegation receipt authorizing another agent to use specific tools.
   *
   * @patent Patent-protected construction — delegated signing with receipt chain
   * propagation. Covered by Apache 2.0 patent grant for users of this code.
   * Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  delegate(delegateId, options) {
    const now = /* @__PURE__ */ new Date();
    const receipt = {
      receipt_id: `del_${randomUUID().slice(0, 12)}`,
      receipt_type: "delegation",
      issuer_id: this.issuer,
      event_time: now.toISOString(),
      payload: {
        delegate_id: delegateId,
        authorized_tools: options.tools,
        scope: options.scope,
        ttl: options.ttl,
        expires_at: new Date(now.getTime() + options.ttl * 1e3).toISOString(),
        max_calls: options.maxCalls,
        allow_subdelegation: options.allowSubdelegation ?? false
      },
      parent_receipts: options.parentReceipts || []
    };
    if (this.signer) {
      const signed = this.signer(receipt);
      Object.assign(receipt, signed);
    }
    this.receipts.set(receipt.receipt_id, receipt);
    this.delegationCallCounts.set(receipt.receipt_id, 0);
    return receipt;
  }
  /**
   * Wrap a tool call with a receipt that references the delegation.
   * Validates the delegation is still valid (not expired, within call limit,
   * tool is authorized).
   *
   * @patent Patent-protected construction — delegated signing with receipt chain
   * propagation. Covered by Apache 2.0 patent grant for users of this code.
   * Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  wrapAction(toolName, options) {
    const delegation = this.receipts.get(options.delegation_receipt);
    let decision = "allow";
    if (!delegation) {
      decision = "deny";
    } else if (delegation.receipt_type !== "delegation") {
      decision = "deny";
    } else {
      if (new Date(delegation.payload.expires_at) < /* @__PURE__ */ new Date()) {
        decision = "deny";
      }
      if (!delegation.payload.authorized_tools.includes(toolName) && !delegation.payload.authorized_tools.includes("*")) {
        decision = "deny";
      }
      if (delegation.payload.max_calls !== void 0) {
        const count = this.delegationCallCounts.get(options.delegation_receipt) || 0;
        if (count >= delegation.payload.max_calls) {
          decision = "deny";
        }
      }
    }
    const currentCount = this.delegationCallCounts.get(options.delegation_receipt) || 0;
    this.delegationCallCounts.set(options.delegation_receipt, currentCount + 1);
    const receipt = {
      receipt_id: `act_${randomUUID().slice(0, 12)}`,
      receipt_type: "execution",
      issuer_id: this.issuer,
      event_time: (/* @__PURE__ */ new Date()).toISOString(),
      payload: {
        tool_name: toolName,
        decision,
        delegation_receipt: options.delegation_receipt,
        scope: delegation?.payload.scope || "unknown",
        call_index: currentCount + 1
      },
      parent_receipts: [options.delegation_receipt]
    };
    if (this.signer) {
      const signed = this.signer(receipt);
      Object.assign(receipt, signed);
    }
    this.receipts.set(receipt.receipt_id, receipt);
    return receipt;
  }
  /**
   * Trace the full receipt chain from a given receipt back to the root delegation.
   *
   * @patent Patent-protected construction — delegated signing with receipt chain
   * propagation. Covered by Apache 2.0 patent grant for users of this code.
   * Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  traceChain(receiptId) {
    const chain = [];
    const visited = /* @__PURE__ */ new Set();
    const walk = (id) => {
      if (visited.has(id)) return;
      visited.add(id);
      const receipt = this.receipts.get(id);
      if (!receipt) return;
      for (const parentId of receipt.parent_receipts) {
        walk(parentId);
      }
      chain.push(receipt);
    };
    walk(receiptId);
    return chain;
  }
  /**
   * Export all receipts as a JSON array (for verification, archival, or Trace visualization).
   */
  exportAll() {
    return Array.from(this.receipts.values());
  }
  /**
   * Validate that a delegation chain is intact and all signatures verify.
   *
   * @patent Patent-protected construction — delegated signing with receipt chain
   * propagation. Covered by Apache 2.0 patent grant for users of this code.
   * Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  validateChain(receiptId) {
    const chain = this.traceChain(receiptId);
    const issues = [];
    if (chain.length === 0) {
      return { valid: false, chain_length: 0, issues: ["Receipt not found"] };
    }
    let sawAction = false;
    for (const receipt of chain) {
      if (receipt.receipt_type === "delegation" && sawAction) {
        issues.push(`Delegation ${receipt.receipt_id} appears after action in chain`);
      }
      if (receipt.receipt_type === "execution") sawAction = true;
    }
    for (const receipt of chain) {
      for (const parentId of receipt.parent_receipts) {
        if (!this.receipts.has(parentId)) {
          issues.push(`Missing parent receipt: ${parentId}`);
        }
      }
    }
    return {
      valid: issues.length === 0,
      chain_length: chain.length,
      issues
    };
  }
};
function createReceiptChannel(orchestratorId) {
  const propagator = new ReceiptPropagator({ issuer: orchestratorId });
  return {
    propagator,
    async withDelegation(delegateId, tools, fn, options) {
      const delegation = propagator.delegate(delegateId, {
        tools,
        scope: options?.scope || `task-${randomUUID().slice(0, 8)}`,
        ttl: options?.ttl || 3600,
        maxCalls: options?.maxCalls
      });
      const result = await fn({ delegation, propagator });
      return {
        result,
        delegation,
        chain: propagator.exportAll()
      };
    }
  };
}

// src/confidential.ts
var ConfidentialGate = class {
  config;
  constructor(config) {
    this.config = config;
  }
  /**
   * Evaluate an attestation document and determine the resulting trust tier.
   */
  evaluateAttestation(doc) {
    if (!this.config.accepted_providers.includes(doc.provider)) {
      return {
        accepted: false,
        tier: "unknown",
        provider: doc.provider,
        reason: `Provider ${doc.provider} not in accepted list: ${this.config.accepted_providers.join(", ")}`
      };
    }
    if (this.config.max_attestation_age) {
      const age = (Date.now() - new Date(doc.timestamp).getTime()) / 1e3;
      if (age > this.config.max_attestation_age) {
        return {
          accepted: false,
          tier: "unknown",
          provider: doc.provider,
          reason: `Attestation expired: age ${Math.floor(age)}s exceeds max ${this.config.max_attestation_age}s`
        };
      }
    }
    if (this.config.expected_measurements) {
      for (const [key, expected] of Object.entries(this.config.expected_measurements)) {
        const actual = doc.measurements[key];
        if (actual !== expected) {
          return {
            accepted: false,
            tier: "signed",
            provider: doc.provider,
            reason: `Measurement mismatch: ${key} expected ${expected}, got ${actual || "missing"}`
          };
        }
      }
    }
    return {
      accepted: true,
      tier: "privileged",
      provider: doc.provider,
      reason: `Attestation verified: ${doc.provider} enclave with valid measurements`
    };
  }
  /**
   * Check if an agent's current tier requires attestation.
   */
  requiresAttestation(currentTier) {
    if (!this.config.require_attestation) return false;
    const tierOrder = ["unknown", "signed", "evidenced", "privileged"];
    const requiredIdx = tierOrder.indexOf(this.config.min_trust_tier);
    const currentIdx = tierOrder.indexOf(currentTier);
    return currentIdx >= requiredIdx;
  }
  /**
   * Generate an attestation receipt documenting the evaluation.
   */
  toReceipt(result, agentId) {
    return {
      receipt_type: "attestation",
      issuer_id: "confidential-gate",
      event_time: (/* @__PURE__ */ new Date()).toISOString(),
      payload: {
        agent_id: agentId,
        provider: result.provider,
        accepted: result.accepted,
        resulting_tier: result.tier,
        reason: result.reason
      }
    };
  }
};
async function confidentialInference(_prompt, _config) {
  throw new Error(
    "Confidential inference requires a TEE/HE provider SDK. See docs at scopeblind.com/docs/confidential for setup instructions. Supported providers: Gramine (local_tee), Zama Concrete ML (homomorphic), NVIDIA Confidential Computing (secure_enclave)."
  );
}
export {
  BUILTIN_PATTERNS,
  CONNECTOR_PILOTS,
  ConfidentialGate,
  POLICY_PACKS,
  ProtectGateway,
  ReceiptPropagator,
  ScopeBlindBridge,
  anchorToRekor,
  buildDecisionContext,
  checkRateLimit,
  collectSignedReceipts,
  computeCalibration,
  confidentialInference,
  connectorDirectory,
  connectorDoctor,
  connectorPilotIds,
  createApprovalChallenge,
  createApprovalReceiptPayload,
  createAttestationField,
  createAuditBundle,
  createC2PAManifest,
  createDisclosurePackage,
  createEvidenceAttestation,
  createLogAnchorField,
  createReceiptChannel,
  createSandbox,
  createSandboxServer,
  createSelectiveDisclosurePackage,
  destroySandbox,
  discloseField,
  ed25519ToDIDKey,
  evaluateCedar,
  evaluateTier,
  exportC2PAManifestJSON,
  exportJSONL,
  formatReportMarkdown,
  formatSimulation,
  forwardReceipt,
  generateC2PACommand,
  generateCedarSchema,
  generateDatasetCard,
  generateHFMetadata,
  generateHookSettings,
  generateReport,
  generateSafetyTranscript,
  generateSampleCedarPolicy,
  generateSchemaStub,
  generateVerifyReceiptSkill,
  getConnectorPilot,
  getPolicyPack,
  getScopeBlindBridge,
  getSignerInfo,
  getToolPolicy,
  hashReceipt,
  hashResponseBody,
  initSigning,
  isAgentId,
  isCedarAvailable,
  isDisclosureMode,
  isEvidenceType,
  isManifestStatus,
  isSigningEnabled,
  listCredentialLabels,
  loadCedarPolicies,
  loadPolicy,
  manifestToVC,
  meetsMinTier,
  parseLogFile,
  parseNotificationConfigFromEnv,
  parseRateLimit,
  policyPackIds,
  policySetFromSource,
  queryExternalPDP,
  readInstalledConnectorPilots,
  receiptToVP,
  receiptsToHFRows,
  redactFields,
  resolveCredential,
  revealField,
  runEvaluatorSelfTest,
  runInSandbox,
  sendApprovalNotification,
  signCommittedDecision,
  signDecision,
  simulate,
  startHookServer,
  toCredentialRequestOptions,
  toManifoldFormat,
  toMetaculusFormat,
  validateCredentials,
  validateEvidenceReceipt,
  validateManifest,
  verifyActaC2PAAssertions,
  verifyAllCommitments,
  verifyApprovalAssertion,
  verifyCommitment,
  verifyEvidenceAttestation,
  verifyRekorAnchor,
  verifySelectiveDisclosurePackage,
  writeConnectorPilots
};
/*! Bundled license information:

@noble/curves/esm/abstract/weierstrass.js:
@noble/curves/esm/_shortw_utils.js:
@noble/curves/esm/nist.js:
@noble/curves/esm/p256.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
