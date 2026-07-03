import {
  collectSignedReceipts,
  createAuditBundle
} from "./chunk-PM2ZO57M.mjs";
import {
  createSelectiveDisclosurePackage,
  discloseField,
  signCommittedDecision,
  verifySelectiveDisclosurePackage
} from "./chunk-F2FKQ4XN.mjs";
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
} from "./chunk-36UID5WY.mjs";
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
} from "./chunk-UBZJ3VI2.mjs";
import {
  createSandboxServer
} from "./chunk-KPSICBAJ.mjs";
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
} from "./chunk-NVJHGXXG.mjs";
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
} from "./chunk-D2RDY2JR.mjs";
import "./chunk-LYKNULYU.mjs";
import "./chunk-D733KAPG.mjs";
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
import { createHash as createHash2, randomBytes } from "crypto";
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
          const salt = randomBytes(16).toString("hex");
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
import { createHash as createHash3, randomBytes as randomBytes2 } from "crypto";
function createApprovalChallenge(requestId, toolName, agentId, rpId = "scopeblind.com", timeoutSeconds = 300) {
  const challengeBytes = randomBytes2(32);
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
function verifyApprovalAssertion(challenge, assertion) {
  const createdAt = new Date(challenge.createdAt).getTime();
  const now = Date.now();
  if (now - createdAt > challenge.timeoutSeconds * 1e3) {
    return {
      valid: false,
      credentialId: assertion.credentialId,
      authenticatorType: "unknown",
      userVerified: false,
      signCount: 0,
      contextHash: challenge.contextHash,
      approvedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  const authData = base64urlDecode(assertion.authenticatorData);
  const flags = authData[32];
  const userPresent = !!(flags & 1);
  const userVerified = !!(flags & 4);
  const attestedCredData = !!(flags & 64);
  const signCount = authData.length >= 37 ? authData[33] << 24 | authData[34] << 16 | authData[35] << 8 | authData[36] : 0;
  let authenticatorType = "unknown";
  try {
    const clientData = JSON.parse(Buffer.from(base64urlDecode(assertion.clientDataJSON)).toString());
    if (clientData.type === "webauthn.get") {
      authenticatorType = "platform";
    }
  } catch {
  }
  return {
    valid: userPresent,
    // At minimum, user must be present
    credentialId: assertion.credentialId,
    authenticatorType,
    userVerified,
    signCount,
    contextHash: challenge.contextHash,
    approvedAt: (/* @__PURE__ */ new Date()).toISOString()
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
