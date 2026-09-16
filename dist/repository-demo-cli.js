"use strict";

// src/coordination-protocol.ts
var COORDINATION_DOMAIN = "scopeblind.coordination.v1\n";
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex2) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(hex2)) throw new Error("Invalid hexadecimal data");
  return Uint8Array.from(hex2.match(/../g).map((x) => parseInt(x, 16)));
}
function validUnicode(value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 55296 && c <= 56319) {
      const n = value.charCodeAt(++i);
      if (!(n >= 56320 && n <= 57343)) return false;
    } else if (c >= 56320 && c <= 57343) return false;
  }
  return true;
}
function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "string") {
    if (!validUnicode(value)) throw new Error("Invalid Unicode");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) if (!Object.hasOwn(value, i)) throw new Error("Sparse arrays are not JSON");
    return "[" + value.map(canonical).join(",") + "]";
  }
  if (typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new Error("Expected a plain JSON object");
    const object3 = value;
    return "{" + Object.keys(object3).sort().map((k) => canonical(k) + ":" + canonical(object3[k])).join(",") + "}";
  }
  throw new Error("Not a JSON value");
}
async function sha256(value) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}
async function importIdentity(pkcs8Hex, publicKey) {
  if (!/^[0-9a-f]{64}$/.test(publicKey)) throw new Error("Invalid public key");
  const privateKey = await crypto.subtle.importKey("pkcs8", hexToBytes(pkcs8Hex), { name: "Ed25519" }, false, ["sign"]);
  const identity = { publicKey, privateKey };
  const check = await sign({ type: "scopeblind.coordination.key-check.v1" }, identity);
  if (!await verify(check, publicKey)) throw new Error("Signing key does not match authority key");
  return identity;
}
async function sign(payload, identity) {
  const preimage = COORDINATION_DOMAIN + canonical(payload);
  const signature = await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(preimage));
  const envelope = { payload, signer: identity.publicKey, digest: await sha256(preimage), signature: bytesToHex(new Uint8Array(signature)) };
  if (identity.deviceAuthorization) {
    envelope.authorization = identity.deviceAuthorization;
    const binding = "scopeblind.coordination.device-authorization.v1\n" + envelope.digest + "\n" + identity.deviceAuthorization.digest;
    envelope.authorization_signature = bytesToHex(new Uint8Array(await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(binding))));
  }
  return envelope;
}
async function verify(envelope, expectedSigner) {
  try {
    if (!envelope || !/^[0-9a-f]{64}$/.test(envelope.signer) || !/^[0-9a-f]{64}$/.test(envelope.digest) || !/^[0-9a-f]{128}$/.test(envelope.signature)) return false;
    if (expectedSigner && expectedSigner !== envelope.signer) return false;
    const preimage = COORDINATION_DOMAIN + canonical(envelope.payload);
    if (await sha256(preimage) !== envelope.digest) return false;
    const key = await crypto.subtle.importKey("raw", hexToBytes(envelope.signer), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, hexToBytes(envelope.signature), new TextEncoder().encode(preimage));
  } catch {
    return false;
  }
}
function makeRequest(action, room_id, body2) {
  return { type: "scopeblind.coordination.request.v1", action, room_id, body: body2, issued_at: (/* @__PURE__ */ new Date()).toISOString(), nonce: crypto.randomUUID() };
}

// src/coordination-repository.ts
var REPOSITORY_HEX = /^[0-9a-f]{64}$/;
var REPOSITORY_SHA = /^[0-9a-f]{40}$/;
var REPOSITORY_ID = /^[A-Za-z0-9_-]{8,100}$/;
var object = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var text = (v, n) => typeof v === "string" && v.length > 0 && v.length <= n && !/[\u0000-\u001f\u007f]/.test(v);
var time = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
var exact = (v, required, optional = []) => required.every((k) => k in v) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
function repositoryPath(path) {
  return text(path, 300) && !path.startsWith("/") && !path.endsWith("/") && !path.includes("\\") && !path.split("/").some((p) => !p || p === "." || p === ".." || p.toLowerCase() === ".git");
}
function repositoryBranch(branch) {
  return text(branch, 150) && !branch.includes("..") && !/[~^:?*\[\\\s]/.test(branch) && !branch.startsWith("/") && !branch.endsWith("/") && !branch.endsWith(".lock") && !branch.includes("@{") && !branch.split("/").some((p) => !p || p.startsWith(".") || p.endsWith("."));
}
function pathAllowed(path, allowed) {
  if (!repositoryPath(path) || /^\.github(?:\/|$)/i.test(path) || /(^|\/)(?:\.gitmodules|CODEOWNERS)$/i.test(path)) return false;
  return allowed.some((rule) => rule.endsWith("/**") ? path.startsWith(rule.slice(0, -2)) : path === rule);
}
function validRepositoryTask(v) {
  if (!object(v) || !exact(v, ["type", "id", "title", "repository", "pull_number", "base_branch", "owner_key", "receiver_key", "authority_key", "allowed_paths", "required_checks", "reviewer_secret_hash", "issued_at", "expires_at"])) return false;
  return v.type === "scopeblind.repository.task.v1" && REPOSITORY_ID.test(String(v.id)) && text(v.title, 140) && typeof v.repository === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v.repository) && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key, v.reviewer_secret_hash].every((x) => typeof x === "string" && REPOSITORY_HEX.test(x)) && v.owner_key !== v.receiver_key && v.owner_key !== v.authority_key && v.receiver_key !== v.authority_key && Array.isArray(v.allowed_paths) && v.allowed_paths.length > 0 && v.allowed_paths.length <= 12 && new Set(v.allowed_paths).size === v.allowed_paths.length && v.allowed_paths.every((p) => typeof p === "string" && repositoryPath(p.endsWith("/**") ? p.slice(0, -3) : p) && pathAllowed(p.endsWith("/**") ? p.slice(0, -2) + "placeholder" : p, [p])) && Array.isArray(v.required_checks) && v.required_checks.length > 0 && v.required_checks.length <= 12 && v.required_checks.every((c) => object(c) && exact(c, ["name", "app_id"]) && text(c.name, 100) && Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0) && new Set(v.required_checks.map((c) => canonical(c))).size === v.required_checks.length && time(v.issued_at) && time(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 7 * 864e5;
}
function validRepositoryProposal(v, task, taskDigest) {
  if (!object(v) || !exact(v, ["type", "id", "task_id", "task_digest", "repository_id", "base_ref", "head_ref", "base_sha", "head_sha", "merge_sha", "tree_sha", "files", "checks", "observed_at"])) return false;
  if (v.type !== "scopeblind.repository.proposal.v1" || !REPOSITORY_ID.test(String(v.id)) || v.task_id !== task.id || v.task_digest !== taskDigest || !text(v.repository_id, 100) || v.base_ref !== `refs/heads/${task.base_branch}` || typeof v.head_ref !== "string" || !v.head_ref.startsWith("refs/heads/") || !repositoryBranch(v.head_ref.slice(11)) || v.head_ref === v.base_ref || ![v.base_sha, v.head_sha, v.merge_sha, v.tree_sha].every((s) => typeof s === "string" && REPOSITORY_SHA.test(s)) || v.base_sha === v.head_sha || v.merge_sha === v.base_sha || !time(v.observed_at)) return false;
  if (!Array.isArray(v.files) || !v.files.length || v.files.length > 50 || new Set(v.files.map((f) => object(f) ? f.path : null)).size !== v.files.length || !v.files.every((f) => object(f) && exact(f, ["path", "status", "mode", "additions", "deletions"], ["previous_path", "patch", "patch_truncated"]) && typeof f.path === "string" && pathAllowed(f.path, task.allowed_paths) && ["added", "modified", "removed", "renamed"].includes(String(f.status)) && ["100644", "100755"].includes(String(f.mode)) && Number.isSafeInteger(f.additions) && Number(f.additions) >= 0 && Number.isSafeInteger(f.deletions) && Number(f.deletions) >= 0 && (f.patch === void 0 || typeof f.patch === "string" && f.patch.length <= 400) && (f.patch_truncated === void 0 || f.patch_truncated === true) && (f.status === "renamed" ? typeof f.previous_path === "string" && pathAllowed(f.previous_path, task.allowed_paths) : f.previous_path === void 0))) return false;
  return Array.isArray(v.checks) && v.checks.length === task.required_checks.length && v.checks.every((c) => object(c) && exact(c, ["id", "name", "app_id", "head_sha", "conclusion"]) && Number.isSafeInteger(c.id) && Number(c.id) > 0 && c.head_sha === v.head_sha && c.conclusion === "success" && task.required_checks.some((r) => r.name === c.name && r.app_id === c.app_id)) && new Set(v.checks.map((c) => `${c.name}:${c.app_id}`)).size === v.checks.length;
}
async function repositorySnapshotDigest(p) {
  const { id: id2, observed_at, ...snapshot } = p;
  return sha256(canonical(snapshot));
}
function validRepositoryRecord(v, kind) {
  if (!object(v) || v.type !== `scopeblind.repository.${kind}.v1` || !REPOSITORY_ID.test(String(v.task_id)) || !REPOSITORY_HEX.test(String(v.task_digest))) return false;
  const common = ["type", "task_id", "task_digest"];
  if (kind === "claim") return exact(v, [...common, "reviewer_key", "name", "issued_at"]) && REPOSITORY_HEX.test(String(v.reviewer_key)) && text(v.name, 60) && time(v.issued_at);
  const note = (v2) => typeof v2 === "string" && v2.length <= 600;
  if (kind === "approval") return exact(v, [...common, "proposal_digest", "role", "principal_key", "decision", "issued_at", "expires_at", "note"]) && REPOSITORY_HEX.test(String(v.proposal_digest)) && REPOSITORY_HEX.test(String(v.principal_key)) && ["owner", "reviewer"].includes(String(v.role)) && ["approve", "reject"].includes(String(v.decision)) && time(v.issued_at) && time(v.expires_at) && note(v.note) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 9e5;
  if (kind === "execution") return exact(v, [...common, "operation_id", "receiver_attempt_id", "proposal_digest", "owner_approval_digest", "reviewer_approval_digest", "receiver_key", "action", "issued_at", "expires_at"]) && [v.operation_id, v.receiver_attempt_id].every((x) => REPOSITORY_ID.test(String(x))) && [v.proposal_digest, v.owner_approval_digest, v.reviewer_approval_digest, v.receiver_key].every((x) => REPOSITORY_HEX.test(String(x))) && v.action === "github.updateRefs" && time(v.issued_at) && time(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 12e4;
  if (kind === "outcome") return exact(v, [...common, "operation_id", "proposal_digest", "execution_digest", "status", "observed_base_sha", "readback", "observed_at", "note"], ["github_request_id"]) && REPOSITORY_ID.test(String(v.operation_id)) && [v.proposal_digest, v.execution_digest].every((x) => REPOSITORY_HEX.test(String(x))) && ["confirmed", "failed", "unknown"].includes(String(v.status)) && (v.observed_base_sha === null || REPOSITORY_SHA.test(String(v.observed_base_sha))) && ["exact_ref", "descendant_ref", "not_confirmed"].includes(String(v.readback)) && (v.status === "confirmed" ? v.readback !== "not_confirmed" && v.observed_base_sha !== null : v.readback === "not_confirmed") && time(v.observed_at) && note(v.note) && (v.github_request_id === void 0 || text(v.github_request_id, 200));
  return exact(v, [...common, "outcome_digest", "reviewer_key", "decision", "issued_at", "note"]) && [v.outcome_digest, v.reviewer_key].every((x) => REPOSITORY_HEX.test(String(x))) && ["accept", "request_changes"].includes(String(v.decision)) && time(v.issued_at) && note(v.note);
}
var validRepositoryEnvelope = (e) => object(e) && exact(e, ["payload", "signer", "digest", "signature"]);
async function verifyRepositoryEvidence(value, pin) {
  const pins = typeof pin === "string" ? { authority_key: pin } : pin ?? { authority_key: value?.state?.payload?.task?.payload?.authority_key };
  const errors = [];
  let accepted = false;
  const check = (condition, message) => {
    if (!condition) errors.push(message);
  };
  try {
    const e = value, s = e.state?.payload, t = s?.task?.payload;
    check(object(e) && exact(e, ["type", "state"]) && e.type === "scopeblind.repository.evidence.v1" && validRepositoryEnvelope(e.state) && !!s && s.type === "scopeblind.repository.state.v1" && exact(s, ["type", "task", "reviewer", "proposal", "approvals", "execution", "outcome", "acceptance", "status", "revision", "observed_at"]) && Number.isSafeInteger(s.revision) && s.revision > 0 && time(s.observed_at) && await verify(e.state, pins.authority_key), "Service state signature or shape is invalid");
    check(validRepositoryEnvelope(s.task) && validRepositoryTask(t) && await verify(s.task, t.owner_key) && t.authority_key === pins.authority_key && (!pins.owner_key || pins.owner_key === t.owner_key) && (!pins.receiver_key || pins.receiver_key === t.receiver_key) && Date.parse(s.observed_at) >= Date.parse(t.issued_at), "Task or pinned owner/receiver is invalid");
    const reviewer = s.reviewer?.payload;
    if (s.reviewer) check(validRepositoryEnvelope(s.reviewer) && validRepositoryRecord(reviewer, "claim") && reviewer.task_id === t.id && reviewer.task_digest === s.task.digest && ![t.owner_key, t.receiver_key, t.authority_key].includes(reviewer.reviewer_key) && await verify(s.reviewer, reviewer.reviewer_key) && (!pins.reviewer_key || pins.reviewer_key === reviewer.reviewer_key) && Date.parse(reviewer.issued_at) >= Date.parse(t.issued_at) && Date.parse(reviewer.issued_at) < Date.parse(t.expires_at), "Reviewer role is invalid");
    if (s.proposal) check(!!reviewer && validRepositoryEnvelope(s.proposal) && validRepositoryProposal(s.proposal.payload, t, s.task.digest) && await verify(s.proposal, t.receiver_key) && Date.parse(s.proposal.payload.observed_at) >= Date.parse(reviewer.issued_at) && Date.parse(s.proposal.payload.observed_at) < Date.parse(t.expires_at), "Repository snapshot is invalid");
    check(Array.isArray(s.approvals) && s.approvals.length <= 2 && new Set(s.approvals.map((a) => a.payload.role)).size === s.approvals.length, "Approval roles are invalid");
    for (const approval of s.approvals) {
      const a = approval.payload, key = a.role === "owner" ? t.owner_key : reviewer?.reviewer_key;
      check(!!s.proposal && validRepositoryEnvelope(approval) && validRepositoryRecord(a, "approval") && a.principal_key === key && a.task_id === t.id && a.task_digest === s.task.digest && a.proposal_digest === s.proposal.digest && await verify(approval, key) && Date.parse(a.issued_at) >= Date.parse(s.proposal.payload.observed_at) && Date.parse(a.expires_at) <= Date.parse(t.expires_at), "Exact proposal approval is invalid");
    }
    if (s.execution) {
      const x = s.execution.payload, owner = s.approvals.find((a) => a.payload.role === "owner"), review = s.approvals.find((a) => a.payload.role === "reviewer");
      check(!!s.proposal && !!owner && !!review && validRepositoryEnvelope(s.execution) && validRepositoryRecord(x, "execution") && x.task_id === t.id && x.task_digest === s.task.digest && x.proposal_digest === s.proposal.digest && x.receiver_key === t.receiver_key && x.owner_approval_digest === owner?.digest && x.reviewer_approval_digest === review?.digest && owner?.payload.decision === "approve" && review?.payload.decision === "approve" && [owner, review].every((a) => a && Date.parse(a.payload.expires_at) >= Date.parse(x.expires_at) && Date.parse(a.payload.issued_at) <= Date.parse(x.issued_at)) && Date.parse(x.expires_at) <= Date.parse(t.expires_at) && await verify(s.execution, pins.authority_key), "Execution authority is invalid");
    }
    if (s.outcome) {
      const o = s.outcome.payload;
      check(!!s.execution && validRepositoryEnvelope(s.outcome) && validRepositoryRecord(o, "outcome") && o.task_id === t.id && o.task_digest === s.task.digest && o.proposal_digest === s.proposal?.digest && o.execution_digest === s.execution?.digest && o.operation_id === s.execution?.payload.operation_id && await verify(s.outcome, t.receiver_key) && Date.parse(o.observed_at) >= Date.parse(s.execution.payload.issued_at), "Receiver outcome is invalid");
      check(o.status !== "confirmed" || o.readback !== "exact_ref" || o.observed_base_sha === s.proposal?.payload.merge_sha, "Confirmed readback is invalid");
    }
    if (s.acceptance) {
      const a = s.acceptance.payload;
      check(s.outcome?.payload.status === "confirmed" && validRepositoryEnvelope(s.acceptance) && validRepositoryRecord(a, "acceptance") && a.task_id === t.id && a.task_digest === s.task.digest && a.outcome_digest === s.outcome.digest && a.reviewer_key === reviewer?.reviewer_key && await verify(s.acceptance, reviewer?.reviewer_key) && Date.parse(a.issued_at) >= Date.parse(s.outcome.payload.observed_at), "Recipient acceptance is invalid");
      accepted = a.decision === "accept";
    }
    const expected = s.acceptance ? s.acceptance.payload.decision === "accept" ? "accepted" : "changes_requested" : s.outcome ? s.outcome.payload.status : s.execution ? "executing" : !reviewer ? "awaiting_reviewer" : !s.proposal ? "awaiting_snapshot" : s.approvals.some((a) => a.payload.decision === "reject") ? "rejected" : s.approvals.length === 2 && s.approvals.every((a) => Date.parse(a.payload.expires_at) > Date.parse(s.observed_at)) ? "approved" : "review";
    check(s.status === expected || s.status === "cancelled" && !s.execution && !s.outcome && !s.acceptance, "State status is inconsistent with the signed records");
    for (const record of [s.reviewer, s.proposal, ...s.approvals, s.execution, s.outcome, s.acceptance]) if (record) check(Date.parse(record.payload.issued_at ?? record.payload.observed_at) <= Date.parse(s.observed_at), "A signed record is later than the state observation");
  } catch {
    errors.push("Malformed repository evidence");
  }
  return { valid: errors.length === 0, errors, accepted: accepted && errors.length === 0, authorityPinned: !!pin && errors.length === 0, limitations: ["The pinned receiver attests to GitHub API observations; this is not a GitHub-signed receipt.", "This controls the installed receiver\u2019s exact branch update. Other credentials and repository actions are outside its coverage.", "Destination readback establishes resulting repository state. After a lost reply it does not establish which actor caused that state.", "The checked files, commits and named checks do not prove the code is safe or universally correct.", "Signatures identify keys, not a person\u2019s legal identity.", ...!pin ? ["No independent authority key was supplied. Only consistency with the included authority was checked."] : []] };
}

// src/repository-receiver.ts
var RepositoryReceiverError = class extends Error {
  constructor(code, message = code, uncertain = false) {
    super(message);
    this.code = code;
    this.uncertain = uncertain;
  }
};
function requireValue(value, code) {
  if (!value) throw new RepositoryReceiverError(code);
}
function parseRepositoryReceiverConfig(value) {
  const c = value;
  requireValue(c && typeof c === "object" && Object.keys(c).sort().join(",") === "authority_key,base_branch,endpoint,owner_key,receiver_key,repository,reviewer_key,type" && c.type === "scopeblind.repository.receiver-config.v1", "invalid_receiver_config");
  let url;
  try {
    url = new URL(c.endpoint);
  } catch {
    throw new RepositoryReceiverError("invalid_receiver_endpoint");
  }
  requireValue(url.protocol === "https:" && url.pathname === "/api/coordination" && !url.search && !url.hash && !url.username && !url.password && c.endpoint === url.href, "invalid_receiver_endpoint");
  requireValue(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(c.repository) && repositoryBranch(c.base_branch) && [c.authority_key, c.owner_key, c.reviewer_key, c.receiver_key].every((k) => REPOSITORY_HEX.test(k)) && (/* @__PURE__ */ new Set([c.authority_key, c.owner_key, c.reviewer_key, c.receiver_key])).size === 4, "invalid_receiver_pins");
  return c;
}
async function json(response, max = 2e6) {
  const reader = response.body?.getReader();
  requireValue(reader, "empty_http_response");
  let length = 0;
  const chunks = [];
  try {
    for (; ; ) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > max) {
        await reader.cancel();
        throw new RepositoryReceiverError("response_too_large");
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const combined = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder().decode(combined));
  } catch {
    throw new RepositoryReceiverError("invalid_json_response");
  }
}
var RepositoryReceiver = class {
  constructor(config, identity, githubToken, fetchImpl = fetch) {
    this.identity = identity;
    this.githubToken = githubToken;
    this.fetchImpl = fetchImpl;
    this.config = parseRepositoryReceiverConfig(config);
    requireValue(identity.publicKey === config.receiver_key && !identity.deviceAuthorization, "receiver_key_mismatch");
    requireValue(typeof githubToken === "string" && githubToken.length > 0, "github_token_required");
  }
  config;
  async rpc(action, taskId, body2 = {}) {
    const request = await sign(makeRequest(action, taskId, body2), this.identity);
    let response;
    try {
      response = await this.fetchImpl(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(2e4) });
    } catch {
      throw new RepositoryReceiverError("repository_service_unavailable", "The signed request may have been recorded. Inspect its current state before continuing.", true);
    }
    const data = await json(response, 15e4);
    requireValue(response.ok && data.ok === true, typeof data.error === "string" ? data.error : "repository_service_error");
    const state = data.repository_task;
    await this.validateState(state, taskId);
    return state;
  }
  async validateState(state, taskId) {
    const checked = await verifyRepositoryEvidence({ type: "scopeblind.repository.evidence.v1", state }, this.config);
    requireValue(checked.valid, "repository_evidence_invalid");
    const task = state.payload.task.payload;
    requireValue(task.id === taskId && task.repository === this.config.repository && task.base_branch === this.config.base_branch && task.owner_key === this.config.owner_key && task.receiver_key === this.config.receiver_key && state.payload.reviewer?.payload.reviewer_key === this.config.reviewer_key, "repository_scope_mismatch");
    requireValue(Math.abs(Date.now() - Date.parse(state.payload.observed_at)) <= 12e4, "repository_state_stale");
  }
  async github(path, init = {}) {
    let response;
    try {
      response = await this.fetchImpl(`https://api.github.com${path}`, { ...init, headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${this.githubToken}`, "X-GitHub-Api-Version": "2026-03-10", "content-type": "application/json" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
    } catch {
      throw new RepositoryReceiverError("github_connection_interrupted", "GitHub did not return a definite response.", init.method === "POST");
    }
    const body2 = await json(response);
    if (!response.ok) throw new RepositoryReceiverError(`github_http_${response.status}`, "GitHub refused the request; no repository rules are bypassed.", false);
    return { body: body2, requestId: response.headers.get("x-github-request-id") || "" };
  }
  get repo() {
    return `/repos/${this.config.repository.split("/").map(encodeURIComponent).join("/")}`;
  }
  async ref(branch) {
    const r = (await this.github(`${this.repo}/git/ref/heads/${branch.split("/").map(encodeURIComponent).join("/")}`)).body;
    requireValue(r.ref === `refs/heads/${branch}` && r.object?.type === "commit" && REPOSITORY_SHA.test(r.object.sha), "invalid_github_ref");
    return r.object.sha;
  }
  async pull(number) {
    const pr = (await this.github(`${this.repo}/pulls/${number}`)).body;
    if (pr.merge_commit_sha === void 0 && pr.state === "open" && pr.mergeable === true) {
      const ref = (await this.github(`${this.repo}/git/ref/pull/${number}/merge`)).body;
      requireValue(ref.ref === `refs/pull/${number}/merge` && ref.object?.type === "commit" && REPOSITORY_SHA.test(ref.object.sha), "repository_merge_ref_invalid");
      return { ...pr, merge_commit_sha: ref.object.sha };
    }
    return pr;
  }
  async tree(sha2) {
    const body2 = (await this.github(`${this.repo}/git/trees/${sha2}?recursive=1`)).body;
    requireValue(body2.sha === sha2 && !body2.truncated && Array.isArray(body2.tree) && body2.tree.length <= 1e4, "repository_tree_incomplete");
    return new Map(body2.tree.map((v) => [v.path, { type: v.type, mode: v.mode, sha: v.sha }]));
  }
  async snapshot(task, proposalId = crypto.randomUUID()) {
    const t = task.payload, pr = await this.pull(t.pull_number);
    requireValue(pr.number === t.pull_number && pr.state === "open" && !pr.draft && !pr.merged && pr.mergeable === true && pr.base?.repo?.full_name === t.repository && pr.head?.repo?.full_name === t.repository && pr.base.ref === t.base_branch && repositoryBranch(pr.head.ref) && pr.head.ref !== pr.base.ref && [pr.base.sha, pr.head.sha, pr.merge_commit_sha].every((s) => REPOSITORY_SHA.test(s)), "repository_pr_not_ready");
    const [repo, base, merge, comparison, runs, currentBase, currentHead] = await Promise.all([
      this.github(this.repo),
      this.github(`${this.repo}/git/commits/${pr.base.sha}`),
      this.github(`${this.repo}/git/commits/${pr.merge_commit_sha}`),
      this.github(`${this.repo}/compare/${pr.base.sha}...${pr.merge_commit_sha}`),
      this.github(`${this.repo}/commits/${pr.head.sha}/check-runs?per_page=100&filter=latest`),
      this.ref(t.base_branch),
      this.ref(pr.head.ref)
    ]);
    requireValue(currentBase === pr.base.sha && currentHead === pr.head.sha, "repository_changed_during_inspection");
    requireValue(repo.body.full_name === t.repository && typeof repo.body.node_id === "string" && base.body.sha === pr.base.sha && REPOSITORY_SHA.test(base.body.tree?.sha) && merge.body.sha === pr.merge_commit_sha && Array.isArray(merge.body.parents) && canonical(merge.body.parents.map((p) => p.sha)) === canonical([pr.base.sha, pr.head.sha]) && REPOSITORY_SHA.test(merge.body.tree?.sha), "repository_merge_mismatch");
    requireValue(comparison.body.base_commit?.sha === pr.base.sha && comparison.body.merge_base_commit?.sha === pr.base.sha && comparison.body.status === "ahead" && Array.isArray(comparison.body.files) && comparison.body.files.length > 0 && comparison.body.files.length <= 50, "repository_diff_incomplete");
    const [oldTree, newTree] = await Promise.all([this.tree(base.body.tree.sha), this.tree(merge.body.tree.sha)]);
    const files = comparison.body.files.map((file) => {
      requireValue(["added", "modified", "removed", "renamed"].includes(file.status) && typeof file.filename === "string" && pathAllowed(file.filename, t.allowed_paths) && (file.status !== "renamed" || typeof file.previous_filename === "string" && pathAllowed(file.previous_filename, t.allowed_paths)), "repository_path_not_allowed");
      const before = oldTree.get(file.previous_filename || file.filename), after = newTree.get(file.filename), entry = file.status === "removed" ? before : after;
      requireValue(entry?.type === "blob" && ["100644", "100755"].includes(entry.mode) && (!before || before.type === "blob" && ["100644", "100755"].includes(before.mode)) && (!after || after.type === "blob" && ["100644", "100755"].includes(after.mode)), "repository_unsafe_file_type");
      requireValue(Number.isSafeInteger(file.additions) && file.additions >= 0 && Number.isSafeInteger(file.deletions) && file.deletions >= 0, "invalid_repository_diff");
      return { path: file.filename, status: file.status, mode: entry.mode, additions: file.additions, deletions: file.deletions, ...file.status === "renamed" ? { previous_path: file.previous_filename } : {}, ...typeof file.patch === "string" ? { patch: file.patch.slice(0, 400), ...file.patch.length > 400 ? { patch_truncated: true } : {} } : {} };
    }).sort((a, b) => a.path.localeCompare(b.path));
    const actual = [.../* @__PURE__ */ new Set([...oldTree.keys(), ...newTree.keys()])].filter((path) => oldTree.get(path)?.type !== "tree" && newTree.get(path)?.type !== "tree" && canonical(oldTree.get(path) ?? null) !== canonical(newTree.get(path) ?? null)).sort();
    const listed = [...new Set(files.flatMap((f) => [f.path, ...f.previous_path ? [f.previous_path] : []]))].sort();
    requireValue(canonical(actual) === canonical(listed), "repository_diff_incomplete");
    requireValue(Number.isSafeInteger(runs.body.total_count) && runs.body.total_count <= 100 && Array.isArray(runs.body.check_runs) && runs.body.check_runs.length === runs.body.total_count, "repository_checks_incomplete");
    const checks = t.required_checks.map((required) => {
      const matching = runs.body.check_runs.filter((c) => c.name === required.name && c.app?.id === required.app_id).sort((a, b) => b.id - a.id), run = matching[0];
      requireValue(run && run.head_sha === pr.head.sha && run.status === "completed" && run.conclusion === "success" && Number.isSafeInteger(run.id) && run.id > 0, "repository_check_not_passed");
      return { id: run.id, name: run.name, app_id: run.app.id, head_sha: run.head_sha, conclusion: "success" };
    }).sort((a, b) => a.name.localeCompare(b.name) || a.app_id - b.app_id);
    const current = await this.pull(t.pull_number);
    requireValue(current.state === "open" && !current.merged && !current.draft && current.head?.sha === pr.head.sha && current.base?.sha === pr.base.sha && current.merge_commit_sha === pr.merge_commit_sha && current.head?.repo?.full_name === t.repository && current.base?.repo?.full_name === t.repository, "repository_changed_during_inspection");
    const proposal = { type: "scopeblind.repository.proposal.v1", id: proposalId, task_id: t.id, task_digest: task.digest, repository_id: repo.body.node_id, base_ref: `refs/heads/${pr.base.ref}`, head_ref: `refs/heads/${pr.head.ref}`, base_sha: pr.base.sha, head_sha: pr.head.sha, merge_sha: pr.merge_commit_sha, tree_sha: merge.body.tree.sha, files, checks, observed_at: (/* @__PURE__ */ new Date()).toISOString() };
    requireValue(validRepositoryProposal(proposal, t, task.digest), "invalid_repository_proposal");
    return proposal;
  }
  async inspect(taskId) {
    requireValue(REPOSITORY_ID.test(taskId), "invalid_repository_task_id");
    const state = await this.rpc("repository_get", taskId);
    requireValue(!state.payload.execution && state.payload.status !== "cancelled" && Date.parse(state.payload.task.payload.expires_at) > Date.now(), "repository_task_inactive");
    const proposal = await sign(await this.snapshot(state.payload.task), this.identity);
    return this.rpc("repository_propose", taskId, { proposal });
  }
  async execute(taskId) {
    requireValue(REPOSITORY_ID.test(taskId), "invalid_repository_task_id");
    let state = await this.rpc("repository_get", taskId);
    if (state.payload.execution) return this.reconcileState(state);
    requireValue(state.payload.status === "approved" && state.payload.proposal && Date.parse(state.payload.task.payload.expires_at) > Date.now(), "repository_joint_approval_required");
    const approved = state.payload.proposal, observed = await this.snapshot(state.payload.task);
    requireValue(await repositorySnapshotDigest(approved.payload) === await repositorySnapshotDigest(observed), "repository_approval_stale");
    const operationId = `repo-${taskId}`, attemptId = crypto.randomUUID();
    state = await this.rpc("repository_begin", taskId, { proposal_digest: approved.digest, operation_id: operationId, attempt_id: attemptId });
    const execution = state.payload.execution;
    requireValue(execution && execution.payload.receiver_attempt_id === attemptId && execution.payload.operation_id === operationId && execution.payload.proposal_digest === approved.digest, "repository_execution_mismatch");
    requireValue(Date.parse(execution.payload.expires_at) > Date.now(), "repository_execution_expired");
    let sent = false, requestId = "", note = "";
    try {
      const final = await this.snapshot(state.payload.task);
      requireValue(await repositorySnapshotDigest(final) === await repositorySnapshotDigest(approved.payload), "repository_approval_stale");
      requireValue(Date.parse(execution.payload.expires_at) > Date.now() && state.payload.approvals.every((a) => Date.parse(a.payload.expires_at) > Date.now()), "repository_execution_expired");
      sent = true;
      const response = await this.github("/graphql", { method: "POST", body: JSON.stringify({ query: "mutation ScopeBlindApply($input: UpdateRefsInput!) { updateRefs(input: $input) { clientMutationId } }", variables: { input: { repositoryId: approved.payload.repository_id, clientMutationId: execution.payload.operation_id, refUpdates: [{ name: approved.payload.base_ref, beforeOid: approved.payload.base_sha, afterOid: approved.payload.merge_sha, force: false }, { name: approved.payload.head_ref, beforeOid: approved.payload.head_sha, afterOid: approved.payload.head_sha, force: false }] } } }) });
      requestId = response.requestId;
      if (response.body.errors?.length) throw new RepositoryReceiverError("github_atomic_update_rejected", "GitHub refused the atomic reference update.");
      requireValue(response.body.data?.updateRefs?.clientMutationId === execution.payload.operation_id, "github_update_response_unverified");
      note = "GitHub accepted the exact atomic reference update. The receiver then read back the destination.";
    } catch (error) {
      note = error instanceof RepositoryReceiverError ? error.message : "The receiver could not establish the operation outcome.";
      if (!sent) return this.report(state, { status: "failed", observed_base_sha: null, readback: "not_confirmed", note });
    }
    return this.reconcileState(state, note, requestId);
  }
  async reconcile(taskId) {
    return this.reconcileState(await this.rpc("repository_get", taskId));
  }
  async reconcileState(state, note = "Reconciled the existing operation by reading GitHub; no new reference update was sent.", requestId = "") {
    requireValue(state.payload.execution && state.payload.proposal, "repository_execution_missing");
    if (state.payload.outcome && state.payload.outcome.payload.status !== "unknown") return state;
    let sha2 = null, readback = "not_confirmed";
    try {
      sha2 = await this.ref(state.payload.task.payload.base_branch);
      if (sha2 === state.payload.proposal.payload.merge_sha) readback = "exact_ref";
      else if (sha2 !== state.payload.proposal.payload.base_sha) {
        const compare = (await this.github(`${this.repo}/compare/${state.payload.proposal.payload.merge_sha}...${sha2}`)).body;
        if (compare.base_commit?.sha === state.payload.proposal.payload.merge_sha && compare.merge_base_commit?.sha === state.payload.proposal.payload.merge_sha && ["ahead", "identical"].includes(compare.status)) readback = "descendant_ref";
      }
    } catch {
      note = "GitHub readback was unavailable. Keep this operation unresolved; do not dispatch a replacement.";
    }
    return this.report(state, { status: readback === "not_confirmed" ? "unknown" : "confirmed", observed_base_sha: sha2, readback, note, ...requestId ? { github_request_id: requestId } : {} });
  }
  async report(state, result) {
    const s = state.payload, x = s.execution;
    const outcome = await sign({ type: "scopeblind.repository.outcome.v1", operation_id: x.payload.operation_id, task_id: s.task.payload.id, task_digest: s.task.digest, proposal_digest: s.proposal.digest, execution_digest: x.digest, ...result, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
    return this.rpc("repository_outcome", s.task.payload.id, { outcome });
  }
};

// src/coordination-repository-collaboration.ts
var DEMO_REPOSITORY = "ScopeBlind/scopeblind-repository-demo";
var DEMO_CHECK = { name: "ScopeBlind contact validation", app_id: 4962726 };
var object2 = (value) => !!value && typeof value === "object" && !Array.isArray(value);
var shape = (value, required, optional = []) => object2(value) && required.every((key) => key in value) && Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
var text2 = (value, max, empty = false) => typeof value === "string" && (empty || value.trim().length > 0) && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
var hex = (value) => typeof value === "string" && REPOSITORY_HEX.test(value);
var id = (value) => typeof value === "string" && REPOSITORY_ID.test(value);
var sha = (value) => typeof value === "string" && REPOSITORY_SHA.test(value);
var at = (value) => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
var span = (issued, expires, max) => at(issued) && at(expires) && Date.parse(String(expires)) > Date.parse(String(issued)) && Date.parse(String(expires)) - Date.parse(String(issued)) <= max;
function validContactPage(value) {
  return shape(value, ["type", "button_label", "target", "accent"]) && value.type === "scopeblind.contact-page.v1" && text2(value.button_label, 40) && ["broken", "contact"].includes(String(value.target)) && ["indigo", "emerald", "rose"].includes(String(value.accent));
}
function contactPageBytes(value) {
  if (!validContactPage(value))
    throw new Error("invalid_contact_page");
  return canonical(value) + "\n";
}
function parseContactPageJson(source) {
  if (typeof source !== "string" || new TextEncoder().encode(source).length > 1024)
    throw new Error("invalid_contact_page");
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error("invalid_contact_page");
  }
  if (!validContactPage(value) || contactPageBytes(value) !== source)
    throw new Error("noncanonical_contact_page");
  return value;
}
function validRepositoryParticipants(v) {
  return shape(v, ["type", "task_id", "task_digest", "owner_key", "receiver_key", "reviewer_key", "reviewer_claim_digest", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.participants.v1" && id(v.task_id) && [v.task_digest, v.owner_key, v.receiver_key, v.reviewer_key, v.reviewer_claim_digest].every(hex) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.reviewer_key])).size === 3 && span(v.issued_at, v.expires_at, 7 * 864e5);
}
function validRepositoryDemoRequest(v) {
  if (!shape(v, ["type", "id", "owner_key", "receiver_key", "authority_key", "title", "goal", "proposed", "reviewer_secret_hash", "issued_at", "expires_at"], ["parent_task_id", "parent_task_digest", "parent_basis_digest", "revision_request_digest"]))
    return false;
  const parent = ["parent_task_id", "parent_task_digest", "parent_basis_digest", "revision_request_digest"];
  return v.type === "scopeblind.repository.demo-request.v1" && id(v.id) && [v.owner_key, v.receiver_key, v.authority_key, v.reviewer_secret_hash].every(hex) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.authority_key])).size === 3 && text2(v.title, 140) && text2(v.goal, 600) && validContactPage(v.proposed) && span(v.issued_at, v.expires_at, 864e5) && (parent.every((k) => v[k] === void 0) || id(v.parent_task_id) && [v.parent_task_digest, v.parent_basis_digest, v.revision_request_digest].every(hex));
}
function validRepositoryDemoProvision(v) {
  return shape(v, ["type", "request_id", "request_digest", "repository", "base_branch", "head_branch", "pull_number", "initial_base_sha", "initial_head_sha", "receiver_key", "required_checks", "observed_at"]) && v.type === "scopeblind.repository.demo-provision.v1" && id(v.request_id) && [v.request_digest, v.receiver_key].every(hex) && v.repository === DEMO_REPOSITORY && v.base_branch === `scopeblind/demo/${v.request_id}/base` && v.head_branch === `scopeblind/demo/${v.request_id}/change` && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && sha(v.initial_base_sha) && sha(v.initial_head_sha) && Array.isArray(v.required_checks) && canonical(v.required_checks) === canonical([DEMO_CHECK]) && at(v.observed_at);
}
function repositoryRevisionBasis(state) {
  return state.acceptance?.digest ?? state.outcome?.digest ?? state.proposal?.digest ?? null;
}

// src/repository-demo-runner.ts
var PATH = "demo/contact.json";
var ID = /^[A-Za-z0-9_-]{8,100}$/;
function need(ok, code) {
  if (!ok) throw new RepositoryReceiverError(code);
}
function contactModel(value) {
  need(validContactPage(value), "demo_contact_model_invalid");
  return value;
}
async function body(response, max = 5e5) {
  const reader = response.body?.getReader();
  need(reader, "demo_empty_response");
  let total = 0;
  const chunks = [];
  try {
    for (; ; ) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.length;
      need(total <= max, "demo_response_too_large");
      chunks.push(part.value);
    }
  } finally {
    await reader.cancel().catch(() => {
    });
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new RepositoryReceiverError("demo_invalid_response");
  }
}
var RepositoryDemoRunner = class {
  constructor(config, identity, githubToken, fetchImpl = fetch) {
    this.config = config;
    this.identity = identity;
    this.githubToken = githubToken;
    this.fetchImpl = fetchImpl;
    const u = new URL(config.endpoint);
    need(u.protocol === "https:" && u.pathname === "/api/coordination" && !u.username && !u.password && !u.search && !u.hash && u.href === config.endpoint, "demo_endpoint_invalid");
    need(/^[a-f0-9]{64}$/.test(config.authority_key) && identity.publicKey === config.receiver_key && identity.publicKey !== config.authority_key && REPOSITORY_SHA.test(config.template_sha) && githubToken, "demo_runner_pins_invalid");
  }
  async rpc(action, roomId, values = {}) {
    const request = await sign(makeRequest(action, roomId, values), this.identity);
    const response = await this.fetchImpl(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(2e4) });
    const result = await body(response, 75e4);
    need(response.ok && result.ok === true, typeof result.error === "string" ? result.error : "demo_service_refused");
    return result;
  }
  async github(path, init = {}, allowMissing = false) {
    const response = await this.fetchImpl("https://api.github.com" + path, { ...init, headers: { accept: "application/vnd.github+json", authorization: `Bearer ${this.githubToken}`, "x-github-api-version": "2026-03-10", "content-type": "application/json" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
    if (allowMissing && response.status === 404) {
      await response.body?.cancel();
      return null;
    }
    const result = await body(response);
    need(response.ok, `demo_github_${response.status}`);
    return result;
  }
  get repo() {
    return "/repos/" + DEMO_REPOSITORY;
  }
  async ref(name) {
    const ref = await this.github(`${this.repo}/git/ref/heads/${name}`, {}, true);
    if (ref === null) return null;
    need(ref.ref === "refs/heads/" + name && ref.object?.type === "commit" && REPOSITORY_SHA.test(ref.object.sha), "demo_ref_invalid");
    return ref.object.sha;
  }
  async modelAt(commit) {
    need(REPOSITORY_SHA.test(commit), "demo_commit_invalid");
    const value = await this.github(`${this.repo}/contents/${PATH}?ref=${commit}`);
    need(value.type === "file" && value.path === PATH && value.encoding === "base64" && typeof value.content === "string" && value.size <= 1024 && REPOSITORY_SHA.test(value.sha), "demo_file_invalid");
    const bytes = Buffer.from(value.content, "base64"), text3 = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    need(bytes.length === value.size, "demo_file_size_mismatch");
    const model = parseContactPageJson(text3);
    return { model, blob_sha: value.sha, content_sha256: await sha256(text3) };
  }
  async verifiedTask(state, owner, taskId) {
    need((await verifyRepositoryEvidence({ type: "scopeblind.repository.evidence.v1", state }, this.config.authority_key)).valid, "demo_task_evidence_invalid");
    const t = state.payload.task.payload;
    need(t.id === taskId && t.owner_key === owner && t.receiver_key === this.config.receiver_key && t.repository === DEMO_REPOSITORY && t.allowed_paths.length === 1 && t.allowed_paths[0] === PATH, "demo_task_scope_invalid");
    return state;
  }
  async startingCommit(job) {
    const request = job.request.payload;
    if (!request.parent_task_id) return this.config.template_sha;
    need(job.parent_state, "demo_parent_evidence_required");
    const parent = await this.verifiedTask(job.parent_state, request.owner_key, request.parent_task_id), revision = job.revision_request;
    need(parent.payload.task.digest === request.parent_task_digest && parent.payload.proposal, "demo_parent_proposal_required");
    need(revision && revision.digest === request.revision_request_digest && await verify(revision, revision.payload.requester_key) && revision.payload.task_digest === parent.payload.task.digest && canonical(revision.payload.proposed) === canonical(request.proposed), "demo_parent_revision_invalid");
    need(revision.payload.basis_digest === repositoryRevisionBasis(parent.payload) && request.parent_basis_digest === revision.payload.basis_digest, "demo_parent_feedback_changed");
    need(!parent.payload.execution || parent.payload.outcome?.payload.status === "confirmed", "demo_parent_unresolved");
    if (parent.payload.outcome) {
      need(parent.payload.outcome.payload.status === "confirmed" && parent.payload.outcome.payload.readback === "exact_ref", "demo_parent_exact_outcome_required");
      return parent.payload.proposal.payload.merge_sha;
    }
    return parent.payload.proposal.payload.base_sha;
  }
  async provision(job) {
    const request = job.request.payload, base = `scopeblind/demo/${request.id}/base`, head = `scopeblind/demo/${request.id}/change`;
    const initialBase = await this.startingCommit(job), before = await this.modelAt(initialBase), proposed = contactModel(request.proposed);
    need(canonical(before.model) !== canonical(proposed), "demo_change_required");
    let baseSha = await this.ref(base);
    if (!baseSha) {
      await this.github(`${this.repo}/git/refs`, { method: "POST", body: JSON.stringify({ ref: "refs/heads/" + base, sha: initialBase }) });
      baseSha = initialBase;
    }
    need(baseSha === initialBase, "demo_base_changed");
    let headSha = await this.ref(head);
    if (headSha) {
      need(canonical((await this.modelAt(headSha)).model) === canonical(proposed), "demo_retry_content_conflict");
      const commit = await this.github(`${this.repo}/git/commits/${headSha}`);
      need(commit.parents?.length === 1 && commit.parents[0].sha === initialBase, "demo_retry_parent_conflict");
    } else {
      const commit = await this.github(`${this.repo}/git/commits/${initialBase}`);
      need(commit.sha === initialBase && REPOSITORY_SHA.test(commit.tree?.sha), "demo_template_invalid");
      const tree = await this.github(`${this.repo}/git/trees`, { method: "POST", body: JSON.stringify({ base_tree: commit.tree.sha, tree: [{ path: PATH, mode: "100644", type: "blob", content: canonical(proposed) + "\n" }] }) });
      need(REPOSITORY_SHA.test(tree.sha), "demo_tree_invalid");
      const change = await this.github(`${this.repo}/git/commits`, { method: "POST", body: JSON.stringify({ message: "ScopeBlind disposable contact-page change " + request.id, tree: tree.sha, parents: [initialBase] }) });
      need(REPOSITORY_SHA.test(change.sha), "demo_commit_invalid");
      await this.github(`${this.repo}/git/refs`, { method: "POST", body: JSON.stringify({ ref: "refs/heads/" + head, sha: change.sha }) });
      headSha = change.sha;
    }
    need(canonical((await this.modelAt(headSha)).model) === canonical(proposed), "demo_head_model_mismatch");
    await this.github(`${this.repo}/check-runs`, { method: "POST", body: JSON.stringify({ name: DEMO_CHECK.name, head_sha: headSha, status: "completed", conclusion: "success", completed_at: (/* @__PURE__ */ new Date()).toISOString(), output: { title: "Contact-page data checks passed", summary: "Validated the fixed contact-page JSON schema and canonical bytes. No pull-request code ran." } }) });
    const pulls = await this.github(`${this.repo}/pulls?state=all&head=ScopeBlind:${encodeURIComponent(head)}&base=${encodeURIComponent(base)}&per_page=100`);
    need(Array.isArray(pulls) && pulls.length <= 1, "demo_pull_ambiguous");
    let pull = pulls[0];
    if (!pull) pull = await this.github(`${this.repo}/pulls`, { method: "POST", body: JSON.stringify({ title: "ScopeBlind contact-page demo " + request.id, head, base, body: "Disposable ScopeBlind-owned workspace. Both browser participants must approve the exact snapshot before the receiver applies this change.", draft: false }) });
    need(pull.state === "open" && pull.head?.ref === head && pull.head?.sha === headSha && pull.base?.ref === base && pull.base?.sha === initialBase && Number.isSafeInteger(pull.number) && pull.number > 0, "demo_pull_conflict");
    return sign({ type: "scopeblind.repository.demo-provision.v1", request_id: request.id, request_digest: job.request.digest, repository: DEMO_REPOSITORY, base_branch: base, head_branch: head, pull_number: pull.number, initial_base_sha: initialBase, initial_head_sha: headSha, receiver_key: this.config.receiver_key, required_checks: [DEMO_CHECK], observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
  }
  async receiver(job) {
    const task = job.task, participants = job.participants, provision = job.provision;
    need(task && provision, "demo_task_required");
    const t = task.payload, r = job.request.payload;
    need(validRepositoryTask(t) && validRepositoryDemoProvision(provision.payload) && await verify(task, t.owner_key) && await verify(provision, this.config.receiver_key), "demo_task_signature_invalid");
    need(t.id === job.request_id && t.id === r.id && provision.payload.request_id === r.id && provision.payload.request_digest === job.request.digest && provision.payload.receiver_key === this.config.receiver_key && t.owner_key === r.owner_key && t.title === r.title && t.reviewer_secret_hash === r.reviewer_secret_hash && Date.parse(t.expires_at) <= Date.parse(r.expires_at) && canonical(t.allowed_paths) === canonical([PATH]) && canonical(t.required_checks) === canonical(provision.payload.required_checks) && t.repository === DEMO_REPOSITORY && t.base_branch === provision.payload.base_branch && t.pull_number === provision.payload.pull_number && t.receiver_key === this.config.receiver_key && t.authority_key === this.config.authority_key, "demo_task_binding_invalid");
    const current = (await this.rpc("repository_get", t.id)).repository_task;
    await this.verifiedTask(current, t.owner_key, t.id);
    need(current.payload.task.digest === task.digest && current.payload.reviewer, "demo_reviewer_required");
    if (job.kind === "reconcile") need(current.payload.execution, "demo_existing_execution_required");
    if (job.kind !== "inspect") {
      const p = participants?.payload;
      need(participants && validRepositoryParticipants(p) && await verify(participants, t.owner_key) && p.task_id === t.id && p.task_digest === task.digest && p.owner_key === t.owner_key && p.receiver_key === this.config.receiver_key && Date.parse(p.issued_at) <= Date.now() && Date.parse(p.issued_at) >= Date.parse(current.payload.reviewer.payload.issued_at) && Date.parse(p.expires_at) <= Date.parse(t.expires_at) && (job.kind === "reconcile" || Date.parse(p.expires_at) > Date.now()), "demo_participants_binding_invalid");
      need(current.payload.reviewer.digest === p.reviewer_claim_digest && current.payload.reviewer.payload.reviewer_key === p.reviewer_key, "demo_reviewer_binding_changed");
    }
    const config = { type: "scopeblind.repository.receiver-config.v1", endpoint: this.config.endpoint, repository: t.repository, base_branch: t.base_branch, authority_key: t.authority_key, owner_key: t.owner_key, reviewer_key: current.payload.reviewer.payload.reviewer_key, receiver_key: t.receiver_key };
    return new RepositoryReceiver(config, this.identity, this.githubToken, this.fetchImpl);
  }
  async preview(state) {
    const p = state.payload.proposal;
    need(p, "demo_proposal_required");
    const [before, after] = await Promise.all([this.modelAt(p.payload.base_sha), this.modelAt(p.payload.merge_sha)]);
    const preview = await sign({ type: "scopeblind.repository.preview.v1", task_id: state.payload.task.payload.id, task_digest: state.payload.task.digest, proposal_digest: p.digest, base_sha: p.payload.base_sha, head_sha: p.payload.head_sha, merge_sha: p.payload.merge_sha, tree_sha: p.payload.tree_sha, path: PATH, before, after, renderer: "scopeblind.contact-page.v1", observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
    await this.rpc("repository_preview_record", state.payload.task.payload.id, { preview });
    return preview;
  }
  async runOne() {
    const leaseId = crypto.randomUUID(), response = await this.rpc("repository_demo_poll", "repository-demo", { lease_id: leaseId });
    if (response.job === null) return false;
    const signed = response.job;
    need(signed && await verify(signed, this.config.authority_key), "demo_job_signature_invalid");
    const job = signed.payload, r = job.request?.payload;
    need(job.type === "scopeblind.repository.demo-job.v1" && ID.test(job.id) && ID.test(job.request_id) && job.lease_id === leaseId && Date.parse(job.lease_expires_at) > Date.now() && Date.parse(job.issued_at) > Date.now() - 12e4 && ["provision", "inspect", "execute", "reconcile"].includes(job.kind), "demo_job_invalid");
    need(validRepositoryDemoRequest(r) && r.id === job.request_id && await verify(job.request, r.owner_key) && r.receiver_key === this.config.receiver_key && r.authority_key === this.config.authority_key && (job.kind === "reconcile" || Date.parse(r.expires_at) > Date.now()), "demo_owner_request_invalid");
    contactModel(r.proposed);
    let result;
    try {
      if (job.kind === "provision") result = { status: "complete", provision: await this.provision(job) };
      else {
        const receiver = await this.receiver(job), taskId = job.task.payload.id;
        const state = job.kind === "inspect" ? await receiver.inspect(taskId) : job.kind === "execute" ? await receiver.execute(taskId) : await receiver.reconcile(taskId);
        if (job.kind === "inspect") await this.preview(state);
        result = { status: "complete", task_state: state };
      }
    } catch (error) {
      result = { status: "failed", error: error instanceof RepositoryReceiverError && /^[a-z0-9_]{3,80}$/.test(error.code) ? error.code : "demo_runner_interrupted" };
    }
    const completion = await sign({ type: "scopeblind.repository.demo-completion.v1", job_id: job.id, lease_id: leaseId, request_id: job.request_id, kind: job.kind, ...result, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
    await this.rpc("repository_demo_complete", "repository-demo", { completion });
    return true;
  }
};
async function runRepositoryDemo() {
  need(process.env.GITHUB_ACTIONS === "true" && process.env.GITHUB_REPOSITORY === DEMO_REPOSITORY && process.env.GITHUB_REF === "refs/heads/main" && ["workflow_dispatch", "schedule"].includes(process.env.GITHUB_EVENT_NAME || ""), "demo_trusted_workflow_required");
  const publicKey = process.env.SCOPEBLIND_DEMO_RECEIVER_KEY || "", privateKey = process.env.SCOPEBLIND_RECEIVER_PRIVATE_KEY || "";
  const runner = new RepositoryDemoRunner({ endpoint: process.env.SCOPEBLIND_DEMO_ENDPOINT || "https://scopeblind.com/api/coordination", authority_key: process.env.SCOPEBLIND_DEMO_AUTHORITY_KEY || "", receiver_key: publicKey, template_sha: process.env.SCOPEBLIND_DEMO_TEMPLATE_SHA || "" }, await importIdentity(privateKey, publicKey), process.env.GITHUB_TOKEN || "");
  let idle = 0, completed = 0;
  for (let attempt = 0; attempt < 12 && idle < 3; attempt++) {
    if (await runner.runOne()) {
      completed++;
      idle = 0;
    } else {
      idle++;
      if (idle < 3) await new Promise((resolve) => setTimeout(resolve, 5e3));
    }
  }
  process.stdout.write(`Demo runner finished ${completed} queued jobs. No pull-request code was executed.
`);
}

// src/repository-demo-cli.ts
runRepositoryDemo().catch(() => {
  process.stderr.write("The demo runner did not complete. Check its durable job state before retrying.\n");
  process.exitCode = 1;
});
