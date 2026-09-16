import {
  COORDINATION_TOOLS,
  NEGOTIATION_TOOLS,
  REHEARSAL_TOOLS,
  handleCoordinationRequest
} from "./chunk-XIOEXN3S.mjs";
import {
  NEGOTIATION_PAIRING_AUDIENCE,
  NEGOTIATION_PAIRING_SCOPE,
  PAIRING_SCOPE,
  agentClient,
  agentProfileRegistration,
  claimPairing,
  coordinationConfigFromFile,
  readPrivateConfig
} from "./chunk-7LONQW6Q.mjs";
import {
  verifyRepositoryCollaborationEvidence
} from "./chunk-H64HVW5K.mjs";
import {
  CoordinationClient,
  CoordinationError
} from "./chunk-2SYSTEXK.mjs";
import {
  validateCoordinationConfig
} from "./chunk-ZSS4X3C3.mjs";
import {
  repositoryRevisionBasis,
  validContactPage,
  validRepositoryAgentGrant,
  validRepositoryRevisionRequest
} from "./chunk-62IJNG3V.mjs";
import {
  bytesToHex,
  canonical,
  importIdentity,
  makeRequest,
  sha256,
  sign,
  verify
} from "./chunk-VS4TVKA7.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/coordination-agent-server.ts
import { createInterface } from "readline";
import { resolve as resolve2 } from "path";

// src/coordination-agent-client.ts
import { randomBytes as randomBytes2 } from "crypto";

// src/coordination-agent-requests.ts
var DRAFT_KEYS = ["type", "title", "goal", "counterparty_name", "budget_minor", "approval_above_minor", "approval_ttl_seconds", "require_po_match", "min_budget_minor", "max_budget_minor", "min_threshold_minor", "max_threshold_minor", "private_brief", "preference", "budget_preference", "assumptions"].sort().join(",");
var text = (value, min, max) => typeof value === "string" && value.length >= min && value.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value);
var amount = (value, min = 0) => Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= 1e7;
function parseAgentTaskDraft(value) {
  const invalid = () => {
    throw new Error("Use a bounded invoice-task draft with explicit suggested limits and assumptions. No authority has been granted.");
  };
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalid();
  const v = value;
  if (Object.keys(v).sort().join(",") !== DRAFT_KEYS || v.type !== "scopeblind.coordination.agent-task-draft.v1" || !text(v.title, 1, 100) || !v.title.trim() || !text(v.goal, 1, 2e3) || !v.goal.trim() || !text(v.counterparty_name, 0, 60) || !text(v.private_brief, 0, 2e3) || !amount(v.budget_minor, 1) || !amount(v.approval_above_minor) || v.approval_above_minor > v.budget_minor || !Number.isSafeInteger(v.approval_ttl_seconds) || v.approval_ttl_seconds < 30 || v.approval_ttl_seconds > 900 || v.require_po_match !== true || !amount(v.min_budget_minor, 1) || !amount(v.max_budget_minor, 1) || v.min_budget_minor > v.max_budget_minor || !amount(v.min_threshold_minor) || !amount(v.max_threshold_minor) || v.min_threshold_minor > v.max_threshold_minor || v.max_threshold_minor > v.max_budget_minor || typeof v.preference !== "string" || !["fewer_reviews", "more_review", "balanced"].includes(v.preference) || typeof v.budget_preference !== "string" || !["preserve_budget", "lower_budget", "more_capacity"].includes(v.budget_preference) || !Array.isArray(v.assumptions) || v.assumptions.length > 12 || !v.assumptions.every((item) => text(item, 1, 300))) return invalid();
  return structuredClone(v);
}
function prepareAgentTaskDraft(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Provide a task title and goal for human review.");
  const v = value;
  if (Object.keys(v).some((key) => !DRAFT_KEYS.split(",").includes(key))) throw new Error("The draft contains a rule this invoice trial cannot enforce. Explain it to the person instead of granting it.");
  if (v.type !== void 0 && v.type !== "scopeblind.coordination.agent-task-draft.v1" || v.assumptions !== void 0 && !Array.isArray(v.assumptions)) throw new Error("The draft type or assumptions are invalid.");
  const assumptions = [...v.assumptions || []];
  const fallback = (key, supplied, defaultValue, note) => {
    if (supplied !== void 0) return supplied;
    assumptions.push(note);
    return defaultValue;
  };
  const budget = fallback("budget_minor", v.budget_minor, 2e5, "Total budget was not supplied: $2,000 is suggested for review.");
  const threshold = fallback("approval_above_minor", v.approval_above_minor, Math.min(5e4, budget), "Review threshold was not supplied: up to $500 is suggested for review.");
  const draft = {
    type: "scopeblind.coordination.agent-task-draft.v1",
    title: v.title,
    goal: v.goal,
    counterparty_name: v.counterparty_name ?? "",
    budget_minor: budget,
    approval_above_minor: threshold,
    approval_ttl_seconds: fallback("approval_ttl_seconds", v.approval_ttl_seconds, 900, "Approval expiry was not supplied: 15 minutes is suggested."),
    require_po_match: v.require_po_match ?? true,
    min_budget_minor: fallback("min_budget_minor", v.min_budget_minor, budget, "Minimum negotiable budget defaults to the suggested total; review before signing."),
    max_budget_minor: fallback("max_budget_minor", v.max_budget_minor, budget, "Maximum negotiable budget defaults to the suggested total; review before signing."),
    min_threshold_minor: fallback("min_threshold_minor", v.min_threshold_minor, threshold, "Minimum review threshold defaults to the suggested threshold; review before signing."),
    max_threshold_minor: fallback("max_threshold_minor", v.max_threshold_minor, threshold, "Maximum review threshold defaults to the suggested threshold; review before signing."),
    private_brief: v.private_brief ?? "",
    preference: v.preference ?? "balanced",
    budget_preference: v.budget_preference ?? "preserve_budget",
    assumptions
  };
  if (!assumptions.includes("This draft uses fictional USD invoices and fixed sample destinations. No real payment service is connected.")) assumptions.push("This draft uses fictional USD invoices and fixed sample destinations. No real payment service is connected.");
  return parseAgentTaskDraft(draft);
}

// src/coordination-agent-profile.ts
import { constants, openSync, readFileSync, closeSync, fstatSync, writeFileSync, mkdirSync, renameSync, unlinkSync, rmdirSync } from "fs";
import { dirname, resolve } from "path";
import { homedir } from "os";
import { randomBytes } from "crypto";
var DEFAULT_AGENT_PROFILE = resolve(homedir(), ".scopeblind", "agent.json");
var profileId = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(value);
function profileEntry(entries, id2) {
  return entries && Object.hasOwn(entries, id2) ? entries[id2] : void 0;
}
function validateProfileDestination(endpoint, authorityKey) {
  const checked = validateCoordinationConfig({ endpoint, authorityKey, roomId: "profile-placeholder", token: "profile-placeholder" });
  return { endpoint: checked.endpoint, authorityKey: checked.authorityKey };
}
function readAgentProfile(path) {
  let fd;
  try {
    fd = openSync(resolve(path), constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    throw new Error("The private agent profile could not be opened. Run coordination agent setup first.");
  }
  try {
    const file = fstatSync(fd);
    if (!file.isFile() || file.size > 2e6 || process.platform !== "win32" && ((file.mode & 63) !== 0 || process.getuid && file.uid !== process.getuid())) throw new Error("The agent profile must be owned by you with permissions 600.");
    let value;
    try {
      value = JSON.parse(readFileSync(fd, "utf8"));
    } catch {
      throw new Error("The private agent profile is not valid JSON.");
    }
    if (value?.type !== "scopeblind.coordination.agent-profile.v1" || !/^[a-f0-9]{64}$/.test(value.agentKey) || !/^[a-f0-9]{96,256}$/.test(value.privateKey) || [value.requests, value.connections, value.pendingHandoffs].some((v) => !v || typeof v !== "object" || Array.isArray(v))) throw new Error("The private agent profile has an unsupported format.");
    validateProfileDestination(value.endpoint, value.authorityKey);
    if (Object.keys(value.requests).length > 50 || Object.keys(value.connections).length > 50 || Object.keys(value.pendingHandoffs).length > 50) throw new Error("This private profile reached its connection limit. Use a separate profile for new work.");
    for (const entries of [value.repositoryConnections, value.repositoryRevisions]) if (entries !== void 0 && (!entries || typeof entries !== "object" || Array.isArray(entries) || Object.keys(entries).length > 50)) throw new Error("The private repository profile has an unsupported format or reached its connection limit.");
    for (const [id2, connection] of Object.entries(value.connections)) {
      validateCoordinationConfig(connection);
      if (!profileId(id2) || connection.endpoint !== value.endpoint || connection.authorityKey !== value.authorityKey || !connection.binding || connection.binding.payload.pair_id !== id2 || connection.binding.payload.agent_key !== connection.agentKey) throw new Error("A saved connection does not match this private profile.");
    }
    for (const [id2, connection] of Object.entries(value.repositoryConnections ?? {})) {
      const grant = connection?.grant?.payload;
      if (!profileId(id2) || !validRepositoryAgentGrant(grant) || grant.id !== id2 || grant.agent_key !== value.agentKey || grant.task_id !== connection.taskId || grant.task_digest !== connection.taskDigest) throw new Error("A saved repository grant does not match this private profile.");
    }
    for (const [id2, revision] of Object.entries(value.repositoryRevisions ?? {})) {
      const r = revision?.request?.payload, c = profileEntry(value.repositoryConnections, revision?.connectionId);
      if (!profileId(id2) || !c || !validRepositoryRevisionRequest(r) || r.id !== id2 || r.requester_key !== value.agentKey || r.task_id !== c.taskId || r.task_digest !== c.taskDigest || r.grant_digest !== c.grant.digest) throw new Error("A saved repository revision does not match its exact grant.");
    }
    return value;
  } finally {
    closeSync(fd);
  }
}
async function updateAgentProfile(path, change) {
  path = resolve(path);
  const lock = path + ".lock";
  let locked = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      mkdirSync(lock, { mode: 448 });
      locked = true;
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw new Error("The private profile could not be locked.");
    }
    await new Promise((resolve3) => setTimeout(resolve3, 50));
  }
  if (!locked) throw new Error("Another process is updating this profile. Retry after it finishes; no credentials were changed.");
  const temporary = path + "." + randomBytes(8).toString("hex") + ".tmp";
  try {
    const profile = readAgentProfile(path), result2 = change(profile);
    if ([profile.requests, profile.connections, profile.pendingHandoffs, profile.repositoryConnections ?? {}, profile.repositoryRevisions ?? {}].some((entries) => Object.keys(entries).length > 50)) throw new Error("This private profile reached its connection limit. Use a separate profile for new work.");
    const serialized = JSON.stringify(profile) + "\n";
    if (Buffer.byteLength(serialized) > 2e6) throw new Error("This private profile reached its storage limit. Use a separate profile for new work.");
    writeFileSync(temporary, serialized, { flag: "wx", mode: 384 });
    renameSync(temporary, path);
    return result2;
  } finally {
    try {
      unlinkSync(temporary);
    } catch {
    }
    try {
      rmdirSync(lock);
    } catch {
    }
  }
}
async function ensureAgentProfile(path, endpoint, authorityKey) {
  path = resolve(path);
  try {
    const value = readAgentProfile(path);
    if (endpoint !== void 0 && validateProfileDestination(endpoint, authorityKey || value.authorityKey).endpoint !== value.endpoint || authorityKey !== void 0 && authorityKey.toLowerCase() !== value.authorityKey) throw new Error("This profile is pinned to another authority or endpoint. Use its original settings or a separate profile.");
    await importIdentity(value.privateKey, value.agentKey);
    return value;
  } catch (error) {
    try {
      const fd2 = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      closeSync(fd2);
      throw error;
    } catch (check) {
      if (check.code !== "ENOENT") throw error;
    }
  }
  if (!endpoint || !authorityKey) throw new Error("A new profile needs --endpoint and an independently pinned --authority-key.");
  const destination = validateProfileDestination(endpoint, authorityKey), pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const profile = { type: "scopeblind.coordination.agent-profile.v1", ...destination, agentKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), privateKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))), requests: {}, connections: {}, pendingHandoffs: {} };
  mkdirSync(dirname(path), { recursive: true, mode: 448 });
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 384);
  try {
    writeFileSync(fd, JSON.stringify(profile) + "\n");
  } finally {
    closeSync(fd);
  }
  return profile;
}
async function importProfileConnection(profilePath, configPath) {
  const stored = readPrivateConfig(configPath), config = coordinationConfigFromFile(configPath), binding = stored.binding;
  if (!await verify(binding, config.authorityKey) || !await verify(binding.payload.owner_authorization, binding.payload.owner_key)) throw new Error("The saved connection signatures could not be verified.");
  await updateAgentProfile(profilePath, (profile) => {
    if (config.endpoint !== profile.endpoint || config.authorityKey !== profile.authorityKey) throw new Error("Import requires the same pinned endpoint and authority.");
    const id2 = binding.payload.pair_id, existing = profile.connections[id2];
    if (existing && existing.binding.digest !== binding.digest) throw new Error("This connection ID already names another signed grant.");
    profile.connections[id2] = { ...config, type: stored.type, setupVersion: stored.setupVersion, agentKey: stored.agentKey, name: stored.name, binding };
  });
  return binding.payload.pair_id;
}

// src/coordination-repository-agent.ts
var exact = (v, keys) => !!v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
function fail(code, message) {
  throw new CoordinationError(code, message);
}
var hex = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
function repositoryConnectionSummary(id2, c, agentKey) {
  return { connection_id: id2, purpose: "repository", room_id: c.taskId, task_id: c.taskId, task_digest: c.taskDigest, principal_key: c.grant.payload.issuer_key, agent_key: agentKey, expires_at: c.grant.payload.expires_at, locally_expired: Date.parse(c.grant.payload.expires_at) <= Date.now(), same_profile_key: true, scope: c.grant.payload.permissions };
}
var RepositoryAgentClient = class {
  constructor(profilePath, transport) {
    this.profilePath = profilePath;
    this.transport = transport;
  }
  profile() {
    return readAgentProfile(this.profilePath);
  }
  async checked(response, taskId, grantId) {
    const profile = this.profile(), e = response.evidence;
    const checked = await verifyRepositoryCollaborationEvidence(e, profile.authorityKey);
    if (!checked.valid || !checked.authorityPinned || !response.repository_task || !response.collaboration || canonical(response.repository_task) !== canonical(e.repository.state) || canonical(response.collaboration) !== canonical(e.collaboration)) fail("repository_evidence_invalid", "The repository evidence did not verify against this profile\u2019s pinned authority. No grant was saved or revision reported as recorded.");
    const s = e.repository.state.payload, c = e.collaboration.payload, task = s.task.payload, now = Date.now();
    if (task.id !== taskId || Math.abs(now - Date.parse(s.observed_at)) > 12e4 || Math.abs(now - Date.parse(c.observed_at)) > 12e4) fail("repository_state_stale", "Inspect this exact repository task again; the signed observation is stale or belongs to another task.");
    const entries = c.agent_grants.filter((entry2) => entry2.grant.payload.id === grantId);
    if (entries.length !== 1) fail("repository_agent_grant_missing", "The signed task does not contain this exact agent grant. Ask your person to authorize this profile\u2019s public key.");
    const entry = entries[0], grant = entry.grant, g = grant.payload;
    if (entry.revoked || g.agent_key !== profile.agentKey || !g.permissions.includes("read_task") || Date.parse(g.issued_at) > now + 6e4 || Date.parse(g.expires_at) <= now || Date.parse(task.expires_at) <= now) fail("repository_agent_grant_inactive", "The exact repository grant is inactive, revoked, expired or belongs to another agent. No authority is inherited from another connection.");
    const saved = profileEntry(profile.repositoryConnections, grantId);
    if (saved && (saved.taskId !== taskId || saved.taskDigest !== s.task.digest || saved.grant.digest !== grant.digest)) fail("repository_agent_grant_conflict", "This connection ID already names a different signed repository grant.");
    return { evidence: e, grant, connection: { taskId, taskDigest: s.task.digest, grant } };
  }
  async read(taskId, grantId) {
    if (!profileId(taskId) || !profileId(grantId)) fail("invalid_repository_connection", "Use the task_id and grant_id supplied by the person after they authorize this profile key.");
    const response = await this.transport("repository_agent_get", taskId, { grant_id: grantId });
    return this.checked(response, taskId, grantId);
  }
  summary(e) {
    const s = e.repository.state.payload, c = e.collaboration.payload;
    return { task: s.task.payload, status: s.status, reviewer_key: s.reviewer?.payload.reviewer_key ?? null, proposal: s.proposal?.payload ?? null, preview: c.preview?.payload ?? null, current_basis_digest: repositoryRevisionBasis(s), approvals: s.approvals.map((a) => ({ principal_key: a.payload.principal_key, decision: a.payload.decision, expires_at: a.payload.expires_at })), outcome: s.outcome?.payload ?? null, acceptance: s.acceptance?.payload ?? null, revision_requests: c.requests.map((r) => ({ ...r.payload, digest: r.digest })), revisions: c.revisions.map((r) => r.payload), observed_at: s.observed_at };
  }
  async inspect(taskId, grantId) {
    const checked = await this.read(taskId, grantId);
    await updateAgentProfile(this.profilePath, (p) => {
      const prior = profileEntry(p.repositoryConnections, grantId);
      if (prior && prior.grant.digest !== checked.grant.digest) fail("repository_agent_grant_conflict", "A different repository grant was saved concurrently.");
      p.repositoryConnections ??= /* @__PURE__ */ Object.create(null);
      Object.defineProperty(p.repositoryConnections, grantId, { value: checked.connection, enumerable: true, writable: true, configurable: true });
    });
    return { ...repositoryConnectionSummary(grantId, checked.connection, this.profile().agentKey), ...this.summary(checked.evidence), evidence: checked.evidence, next_step: "Read the verified task and exact current_basis_digest. If this grant permits request_revision, you may suggest only the supported contact-page model. Humans must review the suggestion, create any revision task, and approve its fresh exact snapshot. You cannot claim a human role, approve, accept, install a receiver, or execute a branch update." };
  }
  async requestRevision(input) {
    if (!exact(input, ["connection_id", "request_id", "basis_digest", "message", "proposed"]) || !profileId(input.connection_id) || !profileId(input.request_id) || !hex(input.basis_digest) || typeof input.message !== "string" || !input.message.trim() || input.message.length > 600 || /[\u0000-\u001f\u007f]/.test(input.message) || !validContactPage(input.proposed)) fail("invalid_repository_revision", "Use a stable request_id, the exact inspected basis_digest, a brief message, and only the supported contact-page model.");
    const p = this.profile(), saved = profileEntry(p.repositoryConnections, input.connection_id);
    if (!saved) fail("unknown_repository_connection", "Call coordination.inspect_repository with the person\u2019s exact task and grant IDs first.");
    const pending = profileEntry(p.repositoryRevisions, input.request_id);
    if (pending && (pending.connectionId !== input.connection_id || pending.request.payload.basis_digest !== input.basis_digest || pending.request.payload.message !== input.message || canonical(pending.request.payload.proposed) !== canonical(input.proposed))) fail("repository_revision_id_conflict", "This request ID already names another exact suggestion. Preserve it for retries; use a new ID for a different intended revision.");
    const checked = await this.read(saved.taskId, input.connection_id), c = checked.evidence.collaboration.payload;
    if (!checked.grant.payload.permissions.includes("request_revision")) fail("repository_revision_outside_grant", "This connection permits reading only. Ask the person to review any additional revision permission.");
    if (pending) {
      if (!await verify(pending.request, p.agentKey)) fail("repository_revision_invalid", "The locally saved revision signature is invalid; it cannot be replayed.");
      if (c.requests.some((r) => r.digest === pending.request.digest)) return this.recorded(input.connection_id, pending.request);
    }
    if (repositoryRevisionBasis(checked.evidence.repository.state.payload) !== input.basis_digest) fail("repository_revision_basis_stale", "The task now has a different inspected change or result. Inspect it and ask whether a new suggestion is still appropriate; the saved suggestion was not rewritten.");
    if (!pending) {
      const payload = { type: "scopeblind.repository.revision-request.v1", id: input.request_id, task_id: saved.taskId, task_digest: saved.taskDigest, basis_digest: input.basis_digest, requester_key: p.agentKey, grant_digest: checked.grant.digest, message: input.message, proposed: input.proposed, issued_at: (/* @__PURE__ */ new Date()).toISOString() };
      if (!validRepositoryRevisionRequest(payload)) fail("invalid_repository_revision", "The proposed revision cannot be represented by this bounded protocol.");
      const request2 = await sign(payload, await importIdentity(p.privateKey, p.agentKey));
      await updateAgentProfile(this.profilePath, (current) => {
        const prior = profileEntry(current.repositoryRevisions, input.request_id);
        if (prior && (prior.connectionId !== input.connection_id || prior.request.payload.basis_digest !== input.basis_digest || prior.request.payload.message !== input.message || canonical(prior.request.payload.proposed) !== canonical(input.proposed))) fail("repository_revision_id_conflict", "Another writer used this request ID for a different exact suggestion.");
        current.repositoryRevisions ??= /* @__PURE__ */ Object.create(null);
        if (!prior) Object.defineProperty(current.repositoryRevisions, input.request_id, { value: { connectionId: input.connection_id, request: request2 }, enumerable: true, writable: true, configurable: true });
      });
    }
    const request = profileEntry(this.profile().repositoryRevisions, input.request_id).request;
    const response = await this.transport("repository_revision_request", saved.taskId, { request });
    const recorded = await this.checked(response, saved.taskId, input.connection_id);
    if (!recorded.evidence.collaboration.payload.requests.some((r) => r.digest === request.digest && canonical(r) === canonical(request))) fail("repository_revision_unverified", "The reply did not include this exact signed revision request. Retry the same request_id; its original signature is saved locally.");
    return this.recorded(input.connection_id, request);
  }
  recorded(connectionId, request) {
    return { connection_id: connectionId, request_id: request.payload.id, request_digest: request.digest, basis_digest: request.payload.basis_digest, status: "recorded", next_step: "The signed suggestion is recorded for human review. It did not create or approve a task, execute a change, or accept a result. Keep this request_id for retries." };
  }
};

// src/coordination-agent-client.ts
var hex2 = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
var exact2 = (value, required, optional = []) => !!value && typeof value === "object" && !Array.isArray(value) && required.every((k) => Object.hasOwn(value, k)) && Object.keys(value).every((k) => required.includes(k) || optional.includes(k));
function fail2(code, message) {
  throw new CoordinationError(code, message);
}
var envelope = (value) => exact2(value, ["payload", "signer", "digest", "signature"]);
var CoordinationAgentClient = class {
  constructor(profilePath, fetchImpl = fetch) {
    this.profilePath = profilePath;
    this.fetchImpl = fetchImpl;
  }
  profile() {
    return readAgentProfile(this.profilePath);
  }
  async request(action, roomId, body) {
    const profile = this.profile(), identity = await importIdentity(profile.privateKey, profile.agentKey);
    const request = await sign(makeRequest(action, roomId, body), identity);
    const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 25e3);
    try {
      const response = await this.fetchImpl(profile.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", cache: "no-store", signal: abort.signal });
      const raw = await response.text();
      if (raw.length > 2e6) fail2("invalid_agent_response", "The service response was too large.");
      let result2;
      try {
        result2 = JSON.parse(raw);
      } catch {
        fail2("invalid_agent_response", "The service did not return a readable response.");
      }
      if (!response.ok || result2.ok !== true) {
        const code = typeof result2.error === "string" && /^[a-z_]{3,80}$/.test(result2.error) ? result2.error : "agent_request_refused";
        fail2(code, "The service refused this agent request. Inspect the current task or ask the person to review its permissions; no authority was added.");
      }
      return result2;
    } catch (error) {
      if (error instanceof CoordinationError) throw error;
      fail2("agent_connection_interrupted", "The reply was interrupted. Retry the same request or grant ID; its private recovery state is saved locally.");
    } finally {
      clearTimeout(timer);
    }
  }
  async checkedRequest(value, id2) {
    const profile = this.profile(), pending = profile.requests[id2];
    if (!pending || !exact2(value, ["request_id", "agent_key", "pairing_secret_hash", "status", "expires_at", "draft"], ["accepted", "connection"])) fail2("invalid_agent_request", "The returned draft does not match this profile.");
    const v = value;
    if (v.request_id !== id2 || v.agent_key !== profile.agentKey || v.pairing_secret_hash !== await sha256(pending.pairingSecret) || v.expires_at !== pending.expiresAt || !["pending", "accepted", "ready", "revoked", "expired"].includes(v.status) || canonical(parseAgentTaskDraft(v.draft)) !== canonical(pending.draft)) fail2("invalid_agent_request", "The returned draft does not match the exact request prepared here.");
    if (v.accepted) {
      const a = v.accepted;
      if (!exact2(a, ["owner_key", "room_id", "session_id", "pair_id", "reviewed_draft", "digest"]) || !hex2(a.owner_key) || a.owner_key === profile.agentKey || ![a.room_id, a.session_id, a.pair_id].every(profileId) || !hex2(a.digest)) fail2("invalid_agent_request", "The reviewed draft does not name a valid independent principal.");
      if (a.digest !== await sha256(canonical(parseAgentTaskDraft(a.reviewed_draft)))) fail2("invalid_agent_request", "The reviewed draft digest does not match its exact content.");
    }
    if (v.connection) {
      const c = v.connection, a = v.accepted;
      if (!a || !exact2(c, ["purpose", "room_id", "session_id", "pair_id", "principal_key", "authority_key"], ["binding"]) || c.purpose !== "negotiation" || c.room_id !== a.room_id || c.session_id !== a.session_id || c.pair_id !== a.pair_id || c.principal_key !== a.owner_key || c.authority_key !== profile.authorityKey) fail2("invalid_agent_request", "The offered connection does not match the person\u2019s reviewed task.");
    }
    if (v.status === "ready" && !v.connection) fail2("invalid_agent_request", "A ready connection must name its exact signed task.");
    return v;
  }
  reviewLink(id2, secret) {
    const url = new URL("/standard", this.profile().endpoint);
    url.searchParams.set("trial", "new");
    url.hash = "agent_request=" + id2 + "." + secret;
    return url.href;
  }
  async prepareTask(input) {
    if (!exact2(input, ["request_id", "draft"]) || !profileId(input.request_id)) fail2("invalid_agent_draft", "Use one stable request_id and an explicit draft.");
    const draft = prepareAgentTaskDraft(input.draft), id2 = input.request_id;
    await updateAgentProfile(this.profilePath, (profile) => {
      if (profile.requests[id2]) {
        if (canonical(profile.requests[id2].draft) !== canonical(draft)) fail2("agent_request_id_conflict", "This request ID already names a different draft. Keep it for retries; use a new ID only for a different intended task.");
        return;
      }
      if (Object.keys(profile.requests).length >= 50) fail2("agent_profile_limit", "This profile has 50 saved requests. Use a separate profile for new work.");
      profile.requests[id2] = { draft, reviewSecret: randomBytes2(32).toString("hex"), pairingSecret: randomBytes2(32).toString("hex"), expiresAt: new Date(Date.now() + 30 * 60 * 1e3).toISOString() };
    });
    const saved = this.profile().requests[id2];
    const response = await this.request("agent_request_create", id2, { request_id: id2, secret_hash: await sha256(saved.reviewSecret), pairing_secret_hash: await sha256(saved.pairingSecret), draft: saved.draft, expires_at: saved.expiresAt });
    const request = await this.checkedRequest(response.agent_request, id2);
    return { request_id: id2, status: request.status, private_review_link: this.reviewLink(id2, saved.reviewSecret), draft: { ...draft, private_brief: void 0 }, assumptions: draft.assumptions, scope: "Unsigned suggestions only. Show this private review link to your own person; it includes access to their private draft instructions. They must review the draft, create the shared task, and sign a mandate. This does not create owner authority, invite the colleague, or start a model or payment." };
  }
  async inspectTaskRequest(id2) {
    if (!profileId(id2) || !this.profile().requests[id2]) fail2("unknown_agent_request", "This profile has no saved request with that ID.");
    const response = await this.request("agent_request_get", id2, { request_id: id2 }), request = await this.checkedRequest(response.agent_request, id2);
    return { request_id: id2, status: request.status, expires_at: request.expires_at, title: request.draft.title, ...request.accepted ? { reviewed_draft: request.accepted.reviewed_draft, owner_key: request.accepted.owner_key, room_id: request.accepted.room_id, session_id: request.accepted.session_id } : {}, ...request.connection ? { connection_id: request.connection.pair_id } : {}, next_step: request.status === "ready" ? "Call coordination.claim_task_connection with this request_id. Then inspect the exact mandate through the returned connection_id." : request.status === "pending" ? "Your person must open and review the private link. No authority is granted." : request.status === "accepted" ? "The person reviewed the draft. Wait for their signed mandate and explicit agent connection; acceptance of a draft is not an agent grant." : "This request is inactive. Keep its history; ask the person before preparing a new task." };
  }
  async claimTaskConnection(id2) {
    if (!profileId(id2) || !this.profile().requests[id2]) fail2("unknown_agent_request", "This profile has no saved request with that ID.");
    const response = await this.request("agent_request_get", id2, { request_id: id2 }), view = await this.checkedRequest(response.agent_request, id2);
    if (view.status !== "ready" || !view.connection) fail2("agent_grant_not_ready", "The person has not yet signed an active negotiation grant. A reviewed draft alone is not permission.");
    const c = view.connection;
    const existing = this.profile().connections[c.pair_id];
    if (existing) return this.connectionSummary(c.pair_id, existing);
    await updateAgentProfile(this.profilePath, (profile2) => {
      const saved2 = profile2.requests[id2];
      if (saved2.pendingPairId !== c.pair_id || !saved2.pendingToken) {
        saved2.pendingPairId = c.pair_id;
        saved2.pendingToken = randomBytes2(32).toString("hex");
      }
    });
    const profile = this.profile(), saved = profile.requests[id2];
    const ready = await claimPairing({ type: "scopeblind.coordination.config.v1", setupVersion: 2, endpoint: profile.endpoint, authorityKey: profile.authorityKey, agentKey: profile.agentKey, token: saved.pendingToken, roomId: c.room_id, purpose: "negotiation", sessionId: c.session_id, principalKey: c.principal_key, name: "My agent", pending: { privateKey: profile.privateKey, code: { version: 3, endpoint: profile.endpoint, authority_key: profile.authorityKey, room_id: c.room_id, session_id: c.session_id, principal_key: c.principal_key, pair_id: c.pair_id, secret: saved.pairingSecret, scope: NEGOTIATION_PAIRING_SCOPE, audience: NEGOTIATION_PAIRING_AUDIENCE } } }, this.fetchImpl);
    if (ready.binding?.payload.owner_authorization.payload.body.expected_agent_key !== profile.agentKey) fail2("agent_grant_wrong_key", "This grant must explicitly name the profile\u2019s agent key.");
    await updateAgentProfile(this.profilePath, (current) => {
      const prior = current.connections[c.pair_id];
      if (prior && prior.binding.digest !== ready.binding.digest) fail2("agent_grant_conflict", "The connection ID already belongs to another signed grant.");
      current.connections[c.pair_id] = ready;
      delete current.requests[id2].pendingToken;
      delete current.requests[id2].pendingPairId;
    });
    return { ...this.connectionSummary(c.pair_id, ready), next_step: "Call coordination.inspect_negotiation with this connection_id before taking any next action. Claiming does not establish readiness or start background work." };
  }
  connectionSummary(id2, connection) {
    return { connection_id: id2, purpose: connection.purpose || "execution", room_id: connection.roomId, ...connection.sessionId ? { session_id: connection.sessionId, principal_key: connection.principalKey } : {}, agent_key: connection.agentKey, expires_at: connection.binding.payload.expires_at, locally_expired: Date.parse(connection.binding.payload.expires_at) <= Date.now(), same_profile_key: connection.agentKey === this.profile().agentKey, scope: connection.binding.payload.scope };
  }
  connections() {
    const profile = this.profile();
    return { agent_key: profile.agentKey, connections: [...Object.entries(profile.connections).map(([id2, c]) => this.connectionSummary(id2, c)), ...Object.entries(profile.repositoryConnections ?? {}).map(([id2, c]) => repositoryConnectionSummary(id2, c, profile.agentKey))], scope: "Saved grants only; connection listings do not prove that authority remains active. Inspect the intended connection before acting. Every action is still checked by the service." };
  }
  repositoryClient() {
    return new RepositoryAgentClient(this.profilePath, (action, taskId, body) => this.request(action, taskId, body));
  }
  inspectRepository(taskId, grantId) {
    return this.repositoryClient().inspect(taskId, grantId);
  }
  requestRepositoryRevision(input) {
    return this.repositoryClient().requestRevision(input);
  }
  clientFor(id2) {
    if (!profileId(id2)) fail2("unknown_agent_connection", "Use an exact connection_id from coordination.connections.");
    const c = this.profile().connections[id2];
    if (!c) fail2("unknown_agent_connection", "This profile does not hold that connection.");
    return new CoordinationClient(c, this.fetchImpl);
  }
  sourceConnection(id2) {
    const profile = this.profile(), source = profile.connections[id2];
    if (!source || source.purpose !== "negotiation" || !source.sessionId || !source.principalKey || source.agentKey !== profile.agentKey) fail2("handoff_profile_key_required", "Seamless execution handoff needs a negotiation connection enrolled with this profile\u2019s own key. Imported legacy connections retain their original scope; their discarded private key cannot be recreated.");
    return source;
  }
  async checkedHandoff(value, source) {
    const p = this.profile();
    if (!exact2(value, ["pair_id", "room_id", "source_room_id", "session_id", "source_pair_id", "agent_key", "name", "status", "expires_at", "token_expires_at", "authorization"], ["binding"])) fail2("invalid_handoff", "The offered execution connection has an unsupported shape.");
    const h = value, q = h.authorization?.payload, b = q?.body;
    if (![h.pair_id, h.room_id].every(profileId) || h.source_room_id !== source.roomId || h.session_id !== source.sessionId || h.source_pair_id !== source.binding.payload.pair_id || h.agent_key !== p.agentKey || typeof h.name !== "string" || !h.name.length || h.name.length > 60 || !["waiting", "connected", "revoked", "expired"].includes(h.status) || ![h.expires_at, h.token_expires_at].every((t) => Number.isFinite(Date.parse(t))) || Date.parse(h.token_expires_at) < Date.parse(h.expires_at) || !envelope(h.authorization) || !await verify(h.authorization, source.principalKey)) fail2("invalid_handoff", "The execution handoff is not signed by the expected human principal for this exact source connection.");
    if (!exact2(q, ["type", "action", "room_id", "body", "issued_at", "nonce"]) || q.type !== "scopeblind.coordination.request.v1" || q.action !== "agent_handoff_create" || q.room_id !== h.room_id || !profileId(q.nonce) || !exact2(b, ["session_id", "source_pair_id", "pair_id", "agent_key", "agreement_digest", "scope", "name", "expires_at", "token_expires_at"]) || b.session_id !== h.session_id || b.source_pair_id !== h.source_pair_id || b.pair_id !== h.pair_id || b.agent_key !== h.agent_key || !hex2(b.agreement_digest) || canonical(b.scope) !== canonical(PAIRING_SCOPE) || b.name !== h.name || b.expires_at !== h.expires_at || b.token_expires_at !== h.token_expires_at) fail2("invalid_handoff", "The human authorization does not match the exact execution scope and target agreement.");
    return h;
  }
  async checkHandoffs(id2) {
    const source = this.sourceConnection(id2), response = await this.request("agent_handoff_get", source.roomId, { session_id: source.sessionId, source_pair_id: source.binding.payload.pair_id });
    if (!Array.isArray(response.handoffs) || response.handoffs.length > 50) fail2("invalid_handoff", "The handoff response is invalid.");
    const handoffs = await Promise.all(response.handoffs.map((v) => this.checkedHandoff(v, source)));
    return { source_connection_id: id2, handoffs: handoffs.map((h) => ({ handoff_id: h.pair_id, room_id: h.room_id, name: h.name, status: h.status, expires_at: h.expires_at, token_expires_at: h.token_expires_at, agreement_digest: h.authorization.payload.body.agreement_digest })), next_step: "Only an active, separately human-authorized handoff can be claimed. Claiming never spends money or transfers human approval powers." };
  }
  async claimExecutionConnection(id2, handoffId) {
    if (!profileId(handoffId)) fail2("invalid_handoff", "Use the exact handoff_id returned by coordination.check_handoffs.");
    const source = this.sourceConnection(id2), response = await this.request("agent_handoff_get", source.roomId, { session_id: source.sessionId, source_pair_id: source.binding.payload.pair_id });
    if (!Array.isArray(response.handoffs)) fail2("invalid_handoff", "The handoff response is invalid.");
    const offered = response.handoffs.find((v) => v?.pair_id === handoffId);
    if (!offered) fail2("handoff_not_found", "No execution grant with that ID belongs to this source connection.");
    const handoff = await this.checkedHandoff(offered, source);
    if (["revoked", "expired"].includes(handoff.status) || Date.parse(handoff.token_expires_at) <= Date.now()) fail2("handoff_inactive", "This execution grant is expired or revoked. The person must decide whether to grant new access.");
    const prior = this.profile().connections[handoffId];
    if (prior) return this.connectionSummary(handoffId, prior);
    if (handoff.status === "waiting" && Date.parse(handoff.expires_at) <= Date.now()) fail2("handoff_inactive", "This unclaimed execution grant expired.");
    await updateAgentProfile(this.profilePath, (profile2) => {
      const pending = profile2.pendingHandoffs[handoffId];
      if (pending && pending.handoff.authorization.digest !== handoff.authorization.digest) fail2("handoff_conflict", "The saved handoff ID names a different authorization.");
      profile2.pendingHandoffs[handoffId] ??= { handoff, token: randomBytes2(32).toString("hex") };
    });
    const profile = this.profile(), token = profile.pendingHandoffs[handoffId].token, claimed = await this.request("agent_handoff_claim", handoff.room_id, { pair_id: handoffId, executor_token: token, name: handoff.name });
    const binding = claimed.binding, b = binding?.payload;
    if (claimed.executor_token !== token || !envelope(binding) || !b || !await verify(binding, profile.authorityKey) || !exact2(b, ["type", "pair_id", "room_id", "agreement_digest", "owner_key", "agent_key", "name", "scope", "audience", "issued_at", "expires_at", "owner_authorization"]) || b.type !== "scopeblind.coordination.agent-binding.v1" || b.pair_id !== handoffId || b.room_id !== handoff.room_id || b.agreement_digest !== handoff.authorization.payload.body.agreement_digest || b.owner_key !== source.principalKey || b.agent_key !== profile.agentKey || b.name !== handoff.name || b.audience !== "scopeblind.coordination.sample-ledger" || canonical(b.scope) !== canonical(PAIRING_SCOPE) || b.expires_at !== handoff.token_expires_at || !Number.isFinite(Date.parse(b.issued_at)) || Date.parse(b.issued_at) >= Date.parse(b.expires_at) || Date.parse(b.issued_at) > Date.now() + 3e5 || canonical(b.owner_authorization) !== canonical(handoff.authorization)) fail2("invalid_handoff_binding", "The claimed execution grant did not verify against the pinned authority and exact human authorization. Retry the same ID; no connection is presented as verified.");
    const config = { type: "scopeblind.coordination.config.v1", setupVersion: 2, endpoint: profile.endpoint, authorityKey: profile.authorityKey, roomId: handoff.room_id, agentKey: profile.agentKey, token, name: handoff.name, purpose: "execution", binding };
    await updateAgentProfile(this.profilePath, (current) => {
      current.connections[handoffId] = config;
      delete current.pendingHandoffs[handoffId];
    });
    return { ...this.connectionSummary(handoffId, config), next_step: "Call coordination.inspect with this NEW connection_id to verify the adopted agreement and current work before acting. The negotiation connection remains separately scoped; no action was executed." };
  }
};

// src/coordination-agent-server.ts
var id = { type: "string", pattern: "^[A-Za-z0-9_-]{8,100}$" };
var amount2 = { type: "integer", minimum: 0, maximum: 1e7 };
var contactPageSchema = { type: "object", additionalProperties: false, properties: { type: { type: "string", const: "scopeblind.contact-page.v1" }, button_label: { type: "string", minLength: 1, maxLength: 40 }, target: { type: "string", enum: ["broken", "contact"] }, accent: { type: "string", enum: ["indigo", "emerald", "rose"] } }, required: ["type", "button_label", "target", "accent"] };
var draftSchema = { type: "object", additionalProperties: false, properties: {
  title: { type: "string", minLength: 1, maxLength: 100 },
  goal: { type: "string", minLength: 1, maxLength: 2e3 },
  counterparty_name: { type: "string", maxLength: 60 },
  budget_minor: { ...amount2, minimum: 1 },
  approval_above_minor: amount2,
  approval_ttl_seconds: { type: "integer", minimum: 30, maximum: 900 },
  require_po_match: { type: "boolean", const: true },
  min_budget_minor: { ...amount2, minimum: 1 },
  max_budget_minor: { ...amount2, minimum: 1 },
  min_threshold_minor: amount2,
  max_threshold_minor: amount2,
  private_brief: { type: "string", maxLength: 2e3 },
  preference: { type: "string", enum: ["fewer_reviews", "more_review", "balanced"] },
  budget_preference: { type: "string", enum: ["preserve_budget", "lower_budget", "more_capacity"] },
  assumptions: { type: "array", maxItems: 12, items: { type: "string", minLength: 1, maxLength: 300 } }
}, required: ["title", "goal"] };
var AGENT_PROFILE_TOOLS = [
  { name: "coordination.prepare_task", description: "Prepare an unsigned shared invoice-task draft for your own person to review. Use a stable request_id for retries. Proposed limits, preferences, and assumptions grant no authority. Returns a private review link intended only for the requesting person; they review and sign in the browser, invite the other person, and explicitly authorize a scoped agent. Do not put unsupported hard rules into a preference. No room, human signature, payment, or hosted model is created by this tool.", inputSchema: { type: "object", additionalProperties: false, properties: { request_id: id, draft: draftSchema }, required: ["request_id", "draft"] }, annotations: { title: "Prepare a shared task for human review", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: "coordination.inspect_task_request", description: "Check a draft prepared by this profile. An accepted draft is still not an agent grant. Ready means the person separately signed the named negotiation grant; use claim_task_connection and inspect the mandate before acting. Does not poll in the background or reveal the draft to another principal.", inputSchema: { type: "object", additionalProperties: false, properties: { request_id: id }, required: ["request_id"] }, annotations: { title: "Check the person\u2019s review and agent grant", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: "coordination.claim_task_connection", description: "Claim the exact negotiation connection explicitly authorized for this profile\u2019s key after human review. Saves its separate token locally and returns a connection_id. Does not sign a mandate, establish readiness, execute, approve, or grant ownership. Inspect the returned connection before taking its next permitted action.", inputSchema: { type: "object", additionalProperties: false, properties: { request_id: id }, required: ["request_id"] }, annotations: { title: "Connect to the human-authorized task", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: "coordination.connections", description: "List saved purpose-scoped connections without credentials. A saved grant may have expired or been revoked: inspect before acting. Every scoped tool requires its explicit connection_id so another task or purpose cannot be selected implicitly.", inputSchema: { type: "object", additionalProperties: false, properties: {} }, annotations: { title: "List this agent\u2019s separate connections", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: "coordination.check_handoffs", description: "Check whether the organizer separately authorized this same agent to execute the exact jointly adopted task. Requires the original negotiation connection_id. Uses the profile key, never broadens the old negotiation token, and performs no payment. Legacy imported connections without the original private agent key cannot claim this continuity.", inputSchema: { type: "object", additionalProperties: false, properties: { connection_id: id }, required: ["connection_id"] }, annotations: { title: "Check for a separately authorized execution handoff", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: "coordination.claim_execution_connection", description: "Claim one exact owner-signed execution handoff discovered by check_handoffs. Returns a NEW execution connection_id while preserving the negotiation grant separately. The local token is persisted before claiming so a lost reply can be retried with the same handoff_id. Does not execute or approve anything; inspect the new room before acting.", inputSchema: { type: "object", additionalProperties: false, properties: { connection_id: id, handoff_id: id }, required: ["connection_id", "handoff_id"] }, annotations: { title: "Claim the approved execution handoff", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: "coordination.inspect_repository", description: "Inspect a repository task using the exact human-signed grant for this profile\u2019s public agent key. Get that public key from coordination.connections and give it to your person; they must explicitly authorize read_task and optionally request_revision in the repository task. Verifies pinned service, task, receiver, human grant and collaboration signatures, then saves a separate repository connection_id. Returns the exact current_basis_digest and bounded preview, never a human claim, approval, acceptance or receiver execution capability.", inputSchema: { type: "object", additionalProperties: false, properties: { task_id: id, grant_id: id }, required: ["task_id", "grant_id"] }, annotations: { title: "Inspect the authorized repository task", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: "coordination.request_repository_revision", description: "Suggest a bounded contact-page revision under an existing repository connection with request_revision permission. Use a stable request_id and the exact current_basis_digest from inspect_repository. Persists the signed request before transport and reuses it after a lost reply; a changed basis requires fresh inspection and a new deliberate suggestion. Only the fixed contact-page data model is supported, not arbitrary code or permissions. Records a suggestion for humans; never creates or approves a task, updates a branch, or accepts a result.", inputSchema: { type: "object", additionalProperties: false, properties: { connection_id: id, request_id: id, basis_digest: { type: "string", pattern: "^[a-f0-9]{64}$" }, message: { type: "string", minLength: 1, maxLength: 600 }, proposed: contactPageSchema }, required: ["connection_id", "request_id", "basis_digest", "message", "proposed"] }, annotations: { title: "Request a repository revision for human review", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } }
];
var scopedTools = [...COORDINATION_TOOLS, ...REHEARSAL_TOOLS, ...NEGOTIATION_TOOLS].map((tool) => ({ ...tool, description: tool.description + " Select the exact saved connection_id for this purpose; permissions are never combined across connections.", inputSchema: { ...tool.inputSchema, properties: { ...tool.inputSchema.properties, connection_id: id }, required: [..."required" in tool.inputSchema ? tool.inputSchema.required ?? [] : [], "connection_id"] } }));
var result = (request, value, error = false) => ({ jsonrpc: "2.0", id: request.id, result: { content: [{ type: "text", text: JSON.stringify(value) }], ...error ? { isError: true } : {} } });
async function handleAgentProfileRequest(client, request, signal) {
  if (!request || request.jsonrpc !== "2.0" || typeof request.method !== "string") return { jsonrpc: "2.0", id: request?.id ?? null, error: { code: -32600, message: "Invalid JSON-RPC request." } };
  if (request.id === void 0) return void 0;
  if (request.method === "initialize") return { jsonrpc: "2.0", id: request.id, result: { protocolVersion: "2024-11-05", serverInfo: { name: "protect-mcp-agent", version: process.env.PROTECT_MCP_VERSION || "0.22.0" }, capabilities: { tools: {} } } };
  if (request.method === "ping") return { jsonrpc: "2.0", id: request.id, result: {} };
  if (request.method === "tools/list") return { jsonrpc: "2.0", id: request.id, result: { tools: [...AGENT_PROFILE_TOOLS, ...scopedTools] } };
  if (request.method !== "tools/call") return { jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found." } };
  try {
    const args = request.params?.arguments ?? {};
    if (!args || typeof args !== "object" || Array.isArray(args)) throw new CoordinationError("invalid_input", "Tool arguments must be an object.");
    const fields = args, name = request.params?.name;
    const only = (...keys) => {
      if (Object.keys(fields).sort().join(",") !== keys.sort().join(",")) throw new CoordinationError("invalid_input", "Use only the exact fields required by this tool.");
    };
    if (name === "coordination.prepare_task") {
      only("request_id", "draft");
      return result(request, await client.prepareTask(fields));
    }
    if (name === "coordination.inspect_task_request") {
      only("request_id");
      return result(request, await client.inspectTaskRequest(fields.request_id));
    }
    if (name === "coordination.claim_task_connection") {
      only("request_id");
      return result(request, await client.claimTaskConnection(fields.request_id));
    }
    if (name === "coordination.connections") {
      only();
      return result(request, client.connections());
    }
    if (name === "coordination.check_handoffs") {
      only("connection_id");
      return result(request, await client.checkHandoffs(fields.connection_id));
    }
    if (name === "coordination.claim_execution_connection") {
      only("connection_id", "handoff_id");
      return result(request, await client.claimExecutionConnection(fields.connection_id, fields.handoff_id));
    }
    if (name === "coordination.inspect_repository") {
      only("task_id", "grant_id");
      return result(request, await client.inspectRepository(fields.task_id, fields.grant_id));
    }
    if (name === "coordination.request_repository_revision") {
      only("connection_id", "request_id", "basis_digest", "message", "proposed");
      return result(request, await client.requestRepositoryRevision(fields));
    }
    if (!scopedTools.some((tool) => tool.name === name)) throw new CoordinationError("unknown_tool", "This profile does not expose that tool.");
    const { connection_id, ...scoped } = fields;
    return await handleCoordinationRequest(client.clientFor(connection_id), { ...request, params: { name, arguments: scoped } }, signal);
  } catch (error) {
    return result(request, { code: error instanceof CoordinationError ? error.code : "agent_request_error", error: error instanceof Error ? error.message : "The agent request could not be completed." }, true);
  }
}
function options(args, mode) {
  const allowed = /* @__PURE__ */ new Set(["--profile", "--endpoint", "--authority-key", ...mode === "setup" ? ["--client"] : [], ...mode === "import" ? ["--config"] : []]), values = /* @__PURE__ */ new Map();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index], value = args[index + 1];
    if (!allowed.has(flag) || values.has(flag) || !value || value.startsWith("--")) throw new Error("Use --profile, optional --endpoint/--authority-key for first setup, and the documented setup/import options.");
    values.set(flag, value);
  }
  return values;
}
async function runCoordinationAgent(args) {
  const mode = args[0] === "setup" ? "setup" : args[0] === "import" ? "import" : "server";
  const values = options(mode === "server" ? args : args.slice(1), mode), path = resolve2(values.get("--profile") || DEFAULT_AGENT_PROFILE);
  const selected = mode === "setup" ? agentClient(values.get("--client") || "claude-code") : void 0;
  const profile = await ensureAgentProfile(path, values.get("--endpoint"), values.get("--authority-key"));
  if (mode === "setup") {
    process.stdout.write(agentProfileRegistration(selected, `scopeblind-agent-${profile.agentKey.slice(0, 12)}`, path) + "\n");
    process.stdout.write("Register this server once, then ask your agent to prepare a shared task with coordination.prepare_task. The profile is an agent identity only; each person reviews and signs their own authority. Existing connections stay separately scoped.\n");
    return;
  }
  if (mode === "import") {
    if (!values.get("--config")) throw new Error("Import needs the existing --config file.");
    const id2 = await importProfileConnection(path, values.get("--config"));
    process.stdout.write(`Saved existing scoped connection ${id2}. Its authority is unchanged. Imported legacy keys cannot be recreated for automatic execution handoff.
`);
    return;
  }
  const client = new CoordinationAgentClient(path), lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();
  const waits = /* @__PURE__ */ new Map(), cancel = () => {
    for (const controller of waits.values()) controller.abort();
  };
  lines.on("close", cancel);
  process.stdout.on("error", cancel);
  lines.on("line", (line) => {
    if (!line.trim()) return;
    let request;
    try {
      if (line.length > 1e6) throw new Error();
      request = JSON.parse(line);
    } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Invalid or oversized JSON-RPC message." } }) + "\n");
      return;
    }
    if (request?.jsonrpc === "2.0" && request.method === "notifications/cancelled") {
      const id2 = request.params?.requestId;
      if (typeof id2 === "string" || typeof id2 === "number") waits.get(id2)?.abort();
      return;
    }
    const controller = request?.method === "tools/call" && ["coordination.wait", "coordination.run_rehearsal", "coordination.wait_negotiation", "coordination.compare_candidate"].includes(String(request.params?.name)) ? new AbortController() : void 0;
    if (controller) waits.set(request.id, controller);
    chain = chain.then(async () => {
      try {
        const response = await handleAgentProfileRequest(client, request, controller?.signal);
        if (response !== void 0) process.stdout.write(JSON.stringify(response) + "\n");
      } finally {
        if (controller && waits.get(request.id) === controller) waits.delete(request.id);
      }
    });
  });
  process.stderr.write("[PROTECT_MCP] Agent profile ready. Drafts confer no authority. Every scoped tool needs a separately authorized connection_id. No background model work is started.\n");
  await new Promise((resolve3) => lines.on("close", resolve3));
  await chain;
  process.stdout.removeListener("error", cancel);
}
export {
  AGENT_PROFILE_TOOLS,
  handleAgentProfileRequest,
  runCoordinationAgent
};
