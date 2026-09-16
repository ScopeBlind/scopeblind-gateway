#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/coordination-protocol.ts
var COORDINATION_DOMAIN = "scopeblind.coordination.v1\n";
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(hex)) throw new Error("Invalid hexadecimal data");
  return Uint8Array.from(hex.match(/../g).map((x) => parseInt(x, 16)));
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
    const object2 = value;
    return "{" + Object.keys(object2).sort().map((k) => canonical(k) + ":" + canonical(object2[k])).join(",") + "}";
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
function makeRequest(action, room_id, body) {
  return { type: "scopeblind.coordination.request.v1", action, room_id, body, issued_at: (/* @__PURE__ */ new Date()).toISOString(), nonce: crypto.randomUUID() };
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
  const { id, observed_at, ...snapshot } = p;
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
  async rpc(action, taskId, body = {}) {
    const request = await sign(makeRequest(action, taskId, body), this.identity);
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
    const body = await json(response);
    if (!response.ok) throw new RepositoryReceiverError(`github_http_${response.status}`, "GitHub refused the request; no repository rules are bypassed.", false);
    return { body, requestId: response.headers.get("x-github-request-id") || "" };
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
  async tree(sha) {
    const body = (await this.github(`${this.repo}/git/trees/${sha}?recursive=1`)).body;
    requireValue(body.sha === sha && !body.truncated && Array.isArray(body.tree) && body.tree.length <= 1e4, "repository_tree_incomplete");
    return new Map(body.tree.map((v) => [v.path, { type: v.type, mode: v.mode, sha: v.sha }]));
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
    let sha = null, readback = "not_confirmed";
    try {
      sha = await this.ref(state.payload.task.payload.base_branch);
      if (sha === state.payload.proposal.payload.merge_sha) readback = "exact_ref";
      else if (sha !== state.payload.proposal.payload.base_sha) {
        const compare = (await this.github(`${this.repo}/compare/${state.payload.proposal.payload.merge_sha}...${sha}`)).body;
        if (compare.base_commit?.sha === state.payload.proposal.payload.merge_sha && compare.merge_base_commit?.sha === state.payload.proposal.payload.merge_sha && ["ahead", "identical"].includes(compare.status)) readback = "descendant_ref";
      }
    } catch {
      note = "GitHub readback was unavailable. Keep this operation unresolved; do not dispatch a replacement.";
    }
    return this.report(state, { status: readback === "not_confirmed" ? "unknown" : "confirmed", observed_base_sha: sha, readback, note, ...requestId ? { github_request_id: requestId } : {} });
  }
  async report(state, result) {
    const s = state.payload, x = s.execution;
    const outcome = await sign({ type: "scopeblind.repository.outcome.v1", operation_id: x.payload.operation_id, task_id: s.task.payload.id, task_digest: s.task.digest, proposal_digest: s.proposal.digest, execution_digest: x.digest, ...result, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
    return this.rpc("repository_outcome", s.task.payload.id, { outcome });
  }
};
async function runRepositoryReceiver(args) {
  const { readFile, writeFile } = await import("fs/promises");
  const action = args[0], option = (name) => {
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : void 0;
  };
  if (action === "keygen") {
    const output = option("--output");
    requireValue(output, "receiver_key_output_required");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]), publicKey = bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), privateKey2 = bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
    const identity = { publicKey };
    await writeFile(output, JSON.stringify({ type: "scopeblind.repository.receiver-key.v1", public_key: identity.publicKey, private_key: privateKey2 }, null, 2) + "\n", { mode: 384, flag: "wx" });
    process.stdout.write(`Receiver public key: ${identity.publicKey}
Private key saved to the requested owner-only file.
`);
    return;
  }
  requireValue(["inspect", "execute", "reconcile"].includes(action), "repository_command_required");
  const file = option("--config"), task = option("--task");
  requireValue(file && task && REPOSITORY_ID.test(task), "repository_config_and_task_required");
  const config = parseRepositoryReceiverConfig(JSON.parse(await readFile(file, "utf8")));
  let privateKey = process.env.SCOPEBLIND_RECEIVER_PRIVATE_KEY;
  if (option("--key-file")) {
    const key = JSON.parse(await readFile(option("--key-file"), "utf8"));
    requireValue(key.type === "scopeblind.repository.receiver-key.v1" && key.public_key === config.receiver_key, "receiver_key_mismatch");
    privateKey = key.private_key;
  }
  requireValue(privateKey && /^[0-9a-f]{96,300}$/.test(privateKey), "receiver_private_key_required");
  if (process.env.GITHUB_ACTIONS === "true") requireValue(process.env.GITHUB_REPOSITORY === config.repository && process.env.GITHUB_EVENT_NAME === "workflow_dispatch" && process.env.GITHUB_REF === `refs/heads/${config.base_branch}`, "receiver_trusted_workflow_required");
  const receiver = new RepositoryReceiver(config, await importIdentity(privateKey, config.receiver_key), process.env.GITHUB_TOKEN || ""), result = action === "inspect" ? await receiver.inspect(task) : action === "execute" ? await receiver.execute(task) : await receiver.reconcile(task);
  const out = option("--output");
  if (out) await writeFile(out, JSON.stringify({ type: "scopeblind.repository.evidence.v1", state: result }, null, 2) + "\n", { mode: 384 });
  process.stdout.write(`Repository task ${task}: ${result.payload.status}. No PR code was executed by this receiver.
`);
}

// src/repository-receiver-cli.ts
runRepositoryReceiver(process.argv.slice(2)).catch((error) => {
  const message = error instanceof RepositoryReceiverError ? error.message : "The receiver could not complete this request. Inspect the existing task before continuing.";
  process.stderr.write(`${message}
`);
  process.exitCode = 1;
});
