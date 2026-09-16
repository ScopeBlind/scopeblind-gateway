import {
  NEGOTIATION_AGENT_ACTIONS,
  REHEARSAL_ACTIONS,
  validateCoordinationConfig
} from "./chunk-PUKT6ZUQ.mjs";
import {
  bytesToHex,
  canonical,
  importIdentity,
  makeRequest,
  sha256,
  sign,
  verify
} from "./chunk-O3K3FPBT.mjs";

// src/coordination-pair-cli.ts
import { createInterface } from "readline";
import { Writable } from "stream";
import { constants, openSync, readFileSync, closeSync, fstatSync, writeFileSync, mkdirSync, renameSync, unlinkSync, chmodSync } from "fs";
import { dirname, resolve } from "path";
import { homedir } from "os";
import { randomBytes, webcrypto } from "crypto";

// src/coordination-pairing.ts
var PAIRING_SCOPE = ["inspect", "admit", "execute", "outcome", "deliver"];
var REHEARSAL_PAIRING_SCOPE = REHEARSAL_ACTIONS;
var REHEARSAL_PAIRING_AUDIENCE = "scopeblind.coordination.rehearsal";
var NEGOTIATION_PAIRING_SCOPE = NEGOTIATION_AGENT_ACTIONS;
var NEGOTIATION_PAIRING_AUDIENCE = "scopeblind.coordination.negotiation";
function isRehearsalPairingScope(scope) {
  return Array.isArray(scope) && JSON.stringify(scope) === JSON.stringify(REHEARSAL_PAIRING_SCOPE);
}
function isNegotiationPairingScope(scope) {
  return Array.isArray(scope) && JSON.stringify(scope) === JSON.stringify(NEGOTIATION_PAIRING_SCOPE);
}
function pairingScope(code) {
  return code.version === 3 ? NEGOTIATION_PAIRING_SCOPE : code.version === 2 ? REHEARSAL_PAIRING_SCOPE : PAIRING_SCOPE;
}
function pairingAudience(code) {
  return code.version === 3 ? NEGOTIATION_PAIRING_AUDIENCE : code.version === 2 ? REHEARSAL_PAIRING_AUDIENCE : "scopeblind.coordination.sample-ledger";
}
function decodePairingCode(value) {
  if (!/^sbp[123]\.[A-Za-z0-9_-]{100,4000}$/.test(value)) throw new Error("The pairing code is incomplete. Copy a fresh code from the room.");
  try {
    const raw = value.slice(5).replace(/-/g, "+").replace(/_/g, "/");
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(Uint8Array.from(atob(raw), (c) => c.charCodeAt(0))));
    const keys = parsed?.version === 3 ? "audience,authority_key,endpoint,pair_id,principal_key,room_id,scope,secret,session_id,version" : parsed?.version === 2 ? "audience,authority_key,endpoint,pair_id,room_id,scope,secret,version" : "authority_key,endpoint,pair_id,room_id,secret,version";
    if (!parsed || Object.keys(parsed).sort().join(",") !== keys || ![1, 2, 3].includes(parsed.version) || value.slice(0, 5) !== `sbp${parsed.version}.` || parsed.version === 3 && (!isNegotiationPairingScope(parsed.scope) || parsed.audience !== NEGOTIATION_PAIRING_AUDIENCE || !/^[0-9a-f]{64}$/.test(parsed.principal_key) || !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.session_id)) || parsed.version === 2 && (!isRehearsalPairingScope(parsed.scope) || parsed.audience !== REHEARSAL_PAIRING_AUDIENCE) || !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.room_id) || !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.pair_id) || !/^[0-9a-f]{64}$/.test(parsed.authority_key) || !/^[0-9a-f]{64}$/.test(parsed.secret) || typeof parsed.endpoint !== "string") throw new Error();
    return parsed;
  } catch {
    throw new Error("The pairing code is invalid. Copy a fresh code from the room.");
  }
}

// src/coordination-agent-setup.ts
var AGENT_PACKAGE_URL = "protect-mcp@0.24.0";
var AGENT_CLIENTS = [
  { id: "claude-code", label: "Claude Code" },
  { id: "codex", label: "Codex CLI" },
  { id: "json", label: "Other MCP client" }
];
var shellQuote = (value) => "'" + value.replace(/'/g, "'\\''") + "'";
function agentClient(value) {
  if (!AGENT_CLIENTS.some((client) => client.id === value)) throw new Error("Supported setup clients: claude-code, codex, or json.");
  return value;
}
function agentServerName(purpose, roomId, pairId, principalKey) {
  const suffix = (pairId || roomId).replace(/[^A-Za-z0-9_-]/g, "").slice(0, 12);
  return purpose === "negotiation" ? `scopeblind-negotiate-${principalKey?.slice(0, 8) || "agent"}-${suffix}` : `scopeblind-${purpose === "rehearsal" ? "test" : "work"}-${suffix}`;
}
function agentRegistration(client, serverName, configPath) {
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(serverName)) throw new Error("Invalid MCP server name.");
  const launch = `npx --yes ${AGENT_PACKAGE_URL} coordination --config ${shellQuote(configPath)}`;
  if (client === "claude-code") return `claude mcp add --transport stdio --scope local ${serverName} -- ${launch}`;
  if (client === "codex") return `codex mcp add ${serverName} -- ${launch}`;
  return JSON.stringify({ mcpServers: { [serverName]: { command: "npx", args: ["--yes", AGENT_PACKAGE_URL, "coordination", "--config", configPath] } } }, null, 2);
}
function agentProfileRegistration(client, serverName, profilePath) {
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(serverName)) throw new Error("Invalid MCP server name.");
  const args = ["--yes", AGENT_PACKAGE_URL, "coordination", "agent", "--profile", profilePath];
  const launch = `npx --yes ${AGENT_PACKAGE_URL} coordination agent --profile ${shellQuote(profilePath)}`;
  if (client === "claude-code") return `claude mcp add --transport stdio --scope local ${serverName} -- ${launch}`;
  if (client === "codex") return `codex mcp add ${serverName} -- ${launch}`;
  return JSON.stringify({ mcpServers: { [serverName]: { command: "npx", args } } }, null, 2);
}
function agentPrompt(purpose, roomId, sessionId) {
  const subject = purpose === "negotiation" ? `ScopeBlind negotiation ${sessionId || "(the paired session)"} in room ${roomId}` : `ScopeBlind ${purpose === "rehearsal" ? "rehearsal" : "room"} ${roomId}`;
  if (purpose === "negotiation") return `Resume ${subject}. First call coordination.inspect_negotiation to read my current signed mandate, my private instructions, and the shared state. Summarize my hard limits without disclosing my private brief. Take only my next permitted action: propose within my limits, respond to the exact candidate, or compare it in isolation. Keep stable IDs when retrying. Use coordination.wait_negotiation when waiting for the other participant. Stop at a human decision, an unmet hard limit, or the round limit. Recommendations are not human approval; do not pay, adopt terms, or claim to run after this agent session ends.`;
  if (purpose === "rehearsal") return `Resume ${subject}. First call coordination.inspect_rehearsal to read the current signed rules, sample records, and test history. Help test my expectations and compare a proposed repair using isolated ledgers. Explain observed tradeoffs. Keep stable case, proposal, and run IDs across retries. Leave adoption and approvals to me; this connection cannot pay or change the active rules.`;
  return `Resume ${subject}. First call coordination.inspect to read the current signed agreement, sample records, and recorded operations. Reconcile the invoices within those rules. Reuse existing operation IDs; check uncertain outcomes before retrying. Use coordination.wait for reviewer decisions while this agent session is active. Stop when human action is required, the room is paused, or the result is delivered. Do not approve your own exceptions or change the rules.`;
}

// src/coordination-pair-cli.ts
if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
var DEFAULT_COORDINATION_CONFIG = resolve(homedir(), ".scopeblind", "coordination.json");
function readPrivateConfig(path) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    throw new Error("The agent connection file could not be opened. Pair from the room first.");
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 64e3 || process.platform !== "win32" && ((stat.mode & 63) !== 0 || process.getuid && stat.uid !== process.getuid())) throw new Error("The connection file must be owned by you, with permissions 600.");
    let data;
    try {
      data = JSON.parse(readFileSync(fd, "utf8"));
    } catch {
      throw new Error("The agent connection file is not valid JSON.");
    }
    if (data.type !== "scopeblind.coordination.config.v1" || data.setupVersion !== void 0 && data.setupVersion !== 2 || !/^[0-9a-f]{64}$/.test(data.agentKey)) throw new Error("The agent connection file is invalid.");
    validateCoordinationConfig(data);
    return data;
  } finally {
    closeSync(fd);
  }
}
function coordinationConfigFromFile(path) {
  const data = readPrivateConfig(resolve(path));
  if (!data.binding || data.pending) throw new Error("Pairing has not completed. Run the pair command again with the same --config file.");
  const binding = data.binding.payload;
  const purpose = binding.audience === NEGOTIATION_PAIRING_AUDIENCE ? "negotiation" : binding.audience === REHEARSAL_PAIRING_AUDIENCE ? "rehearsal" : "execution";
  return validateCoordinationConfig({ ...data, purpose, ...purpose === "negotiation" ? { sessionId: binding.session_id, principalKey: binding.principal_key } : {} });
}
function savePrivateConfig(path, data, create) {
  mkdirSync(dirname(path), { recursive: true, mode: 448 });
  if (create) {
    const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 384);
    try {
      writeFileSync(fd, JSON.stringify(data) + "\n");
    } finally {
      closeSync(fd);
    }
    return;
  }
  readPrivateConfig(path);
  const temporary = `${path}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    writeFileSync(temporary, JSON.stringify(data) + "\n", { flag: "wx", mode: 384 });
    renameSync(temporary, path);
    chmodSync(path, 384);
  } finally {
    try {
      unlinkSync(temporary);
    } catch {
    }
  }
}
async function codeFromInput(variable) {
  if (process.env[variable]) return process.env[variable].trim();
  process.stderr.write("Paste the private pairing code from your room, then press Enter:\n");
  const silent = new Writable({ write(_chunk, _encoding, callback) {
    callback();
  } });
  const lines = createInterface({ input: process.stdin, output: silent, terminal: !!process.stdin.isTTY });
  try {
    for await (const line of lines) {
      if (line.trim()) {
        if (line.length > 4096) throw new Error("The pairing code is too long.");
        return line.trim();
      }
    }
  } finally {
    lines.close();
  }
  throw new Error("No pairing code was provided. Copy a new code from your room.");
}
var safeMessage = {
  pairing_not_found: "This pairing code could not be matched. Create a new code in the room.",
  pairing_expired_or_revoked: "This pairing has expired or was revoked. Create a new code in the room.",
  pairing_already_claimed: "This pairing code has already enrolled another agent. Create a new code in the room.",
  run_finalized: "This result is already delivered. Start an authorized revision before connecting another agent."
};
async function claimPairing(config, fetchImpl = fetch) {
  if (!config.pending) return config;
  const { code, privateKey } = config.pending;
  validateCoordinationConfig(config);
  if (code.endpoint !== config.endpoint || code.room_id !== config.roomId || code.authority_key !== config.authorityKey) throw new Error("The saved pairing destination does not match its authority pin.");
  if (code.version === 3 && (config.purpose !== "negotiation" || config.sessionId !== code.session_id || config.principalKey !== code.principal_key)) throw new Error("The saved pairing does not match its negotiation session and principal.");
  const identity = await importIdentity(privateKey, config.agentKey);
  const request = await sign(makeRequest(code.version === 3 ? "negotiation_pair_claim" : "pair_claim", code.room_id, { ...code.version === 3 ? { session_id: code.session_id } : {}, pair_id: code.pair_id, secret: code.secret, executor_token: config.token, name: config.name }), identity);
  const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 2e4);
  try {
    const response = await fetchImpl(config.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", signal: abort.signal });
    const raw = await response.text();
    if (raw.length > 64e3) throw new Error("Pairing returned an oversized response.");
    const result = JSON.parse(raw);
    if (!response.ok || !result.ok) throw new Error(safeMessage[result.error || ""] || "The room refused this pairing. Check its state before retrying.");
    const binding = result.binding, b = binding?.payload;
    if (!binding || !b || !await verify(binding, config.authorityKey) || b.type !== "scopeblind.coordination.agent-binding.v1" || b.room_id !== code.room_id || b.pair_id !== code.pair_id || b.agent_key !== config.agentKey || b.name !== config.name || b.audience !== pairingAudience(code) || canonical(b.scope) !== canonical(pairingScope(code)) || result.executor_token !== config.token || !Number.isFinite(Date.parse(b.expires_at)) || Date.parse(b.expires_at) <= Date.now() || !/^[0-9a-f]{64}$/.test(b.agreement_digest)) throw new Error("The pairing acknowledgment did not match the pinned authority and exact scope.");
    if (code.version === 3 && (b.session_id !== code.session_id || b.principal_key !== code.principal_key || b.owner_key !== code.principal_key)) throw new Error("The pairing acknowledgment names another negotiation session or principal.");
    const owner = b.owner_authorization, grant = owner?.payload;
    if (!await verify(owner, b.owner_key) || grant?.action !== (code.version === 3 ? "negotiation_pair_create" : "pair_create") || grant.room_id !== code.room_id || grant.body.pair_id !== code.pair_id || grant.body.secret_hash !== await sha256(code.secret) || grant.body.token_expires_at !== b.expires_at || (code.version === 3 ? !isNegotiationPairingScope(grant.body.scope) || grant.body.session_id !== code.session_id : code.version === 2 ? !isRehearsalPairingScope(grant.body.scope) : grant.body.scope !== void 0)) throw new Error("The owner authorization for this connection could not be verified.");
    if (grant.body.expected_agent_key !== void 0 && (code.version !== 3 || grant.body.expected_agent_key !== config.agentKey)) throw new Error("The owner authorization is bound to another agent key.");
    const { pending: _pending, ...ready } = config;
    return { ...ready, purpose: code.version === 3 ? "negotiation" : code.version === 2 ? "rehearsal" : "execution", binding };
  } catch (error) {
    if (error instanceof Error && error.name !== "AbortError" && !/fetch|connect|JSON|Unexpected|network/i.test(error.message)) throw error;
    throw new Error("The pairing response could not be verified. Rerun the same command and config to recover safely.");
  } finally {
    clearTimeout(timer);
  }
}
function configArgs(args, pairing) {
  const options = /* @__PURE__ */ new Map(), allowed = new Set(pairing ? ["--config", "--name", "--code-env", "--client"] : ["--config", "--client"]);
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.has(args[i]) || options.has(args[i]) || !args[i + 1] || args[i + 1].startsWith("--")) throw new Error("Unsupported, repeated, or incomplete connection option.");
    options.set(args[i], args[i + 1]);
  }
  return options;
}
async function runCoordinationPair(args) {
  const options = configArgs(args, true), path = resolve(options.get("--config") || DEFAULT_COORDINATION_CONFIG);
  const client = agentClient(options.get("--client") || "claude-code");
  let config;
  try {
    config = readPrivateConfig(path);
  } catch (error) {
    try {
      const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      closeSync(fd);
      throw error;
    } catch (check) {
      if (check.code !== "ENOENT") throw error;
    }
  }
  if (config?.binding && !config.pending) {
    if (Date.parse(config.binding.payload.expires_at) <= Date.now()) throw new Error("This saved connection has expired. Create a fresh pairing in the room and use its new config filename.");
    process.stdout.write("This config is already paired. Its existing identity and scope are unchanged. Reuse the setup below to reconnect; the room will confirm readiness only after a successful tool inspection. A revoked connection needs a fresh code and config filename.\n");
    runCoordinationSetup(["--config", path, "--client", client]);
    const existing = coordinationConfigFromFile(path);
    process.stdout.write("\nAsk your agent:\n" + agentPrompt(existing.purpose || "execution", existing.roomId, existing.sessionId) + "\n");
    return;
  }
  if (!config) {
    const variable = options.get("--code-env") || "PROTECT_MCP_PAIRING_CODE";
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) throw new Error("--code-env must name an environment variable.");
    const code = decodePairingCode(await codeFromInput(variable));
    const name = options.get("--name") || "My agent";
    if (!name.trim() || name !== name.trim() || name.length > 60 || /[\u0000-\u001f]/.test(name)) throw new Error("Agent name must contain 1\u201360 printable characters.");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const token = randomBytes(32).toString("hex");
    config = {
      type: "scopeblind.coordination.config.v1",
      setupVersion: 2,
      ...validateCoordinationConfig({ endpoint: code.endpoint, roomId: code.room_id, authorityKey: code.authority_key, token, ...code.version === 3 ? { purpose: "negotiation", sessionId: code.session_id, principalKey: code.principal_key } : {} }),
      agentKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))),
      name,
      pending: { code: { ...code, endpoint: new URL(code.endpoint).href }, privateKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))) }
    };
    savePrivateConfig(path, config, true);
  }
  const ready = await claimPairing(config);
  savePrivateConfig(path, ready, false);
  if (ready.purpose === "negotiation") process.stdout.write(`Connected ${ready.name} for one principal\u2019s bounded negotiation until ${ready.binding.payload.expires_at}. This agent can read its principal\u2019s mandate and shared proposals, propose or support a candidate, compare it in isolation, and wait. It cannot inspect the other private brief, pay, approve, adopt, or run a hosted agent.
Connection saved privately. Each principal needs a separate pairing and config.
`);
  else if (ready.purpose === "rehearsal") process.stdout.write(`Connected ${ready.name} to test these rules until ${ready.binding.payload.expires_at}. This agent can inspect rules, add cases, propose repairs, and run isolated tests. It cannot pay, approve, or activate changes.
Connection saved privately. Return to the room to see or revoke this agent.
`);
  else process.stdout.write(`Connected ${ready.name}. This independently keyed agent can inspect records, request permitted sandbox payments, and deliver results until ${ready.binding.payload.expires_at}. It cannot approve exceptions or change the rules.
Connection saved privately. Return to the room to see or revoke this agent.
`);
  process.stdout.write(client === "json" ? "Merge this entry into your MCP client\u2019s local configuration; preserve existing servers:\n" : client === "codex" ? "Run this command to add the connection to your Codex configuration:\n" : "Run this command in the project where you use Claude Code:\n");
  runCoordinationSetup(["--config", path, "--client", client]);
  process.stdout.write("\nOpen or restart the selected client, then ask:\n" + agentPrompt(ready.purpose || "execution", ready.roomId, ready.sessionId) + "\n");
  process.stdout.write("The room will show \u201CRead current instructions\u201D only after your agent successfully inspects and verifies its signed context. Pairing alone does not start an agent. Resume requires an active agent session.\n");
}
function runCoordinationSetup(args) {
  const options = configArgs(args, false), path = resolve(options.get("--config") || DEFAULT_COORDINATION_CONFIG);
  const stored = readPrivateConfig(path), config = coordinationConfigFromFile(path);
  if (Date.parse(stored.binding.payload.expires_at) <= Date.now()) throw new Error("This saved connection has expired. Create a fresh pairing in the room and use its new config filename.");
  const serverName = stored.setupVersion === 2 ? agentServerName(config.purpose || "execution", config.roomId, stored.binding?.payload.pair_id, config.principalKey) : config.purpose === "negotiation" ? `scopeblind-negotiate-${config.principalKey.slice(0, 8)}` : config.purpose === "rehearsal" ? "scopeblind-test" : "scopeblind";
  process.stdout.write(agentRegistration(agentClient(options.get("--client") || "claude-code"), serverName, path) + "\n");
}

export {
  PAIRING_SCOPE,
  NEGOTIATION_PAIRING_SCOPE,
  NEGOTIATION_PAIRING_AUDIENCE,
  shellQuote,
  agentClient,
  agentProfileRegistration,
  DEFAULT_COORDINATION_CONFIG,
  readPrivateConfig,
  coordinationConfigFromFile,
  claimPairing,
  runCoordinationPair,
  runCoordinationSetup
};
