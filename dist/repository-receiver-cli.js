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
  for (var name2 in all)
    __defProp(target, name2, { get: all[name2], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key4 of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key4) && key4 !== except)
        __defProp(to, key4, { get: () => from[key4], enumerable: !(desc = __getOwnPropDesc(from, key4)) || desc.enumerable });
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
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex4) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(hex4)) throw new Error("Invalid hexadecimal data");
  return Uint8Array.from(hex4.match(/../g).map((x) => parseInt(x, 16)));
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
    const object7 = value;
    return "{" + Object.keys(object7).sort().map((k) => canonical(k) + ":" + canonical(object7[k])).join(",") + "}";
  }
  throw new Error("Not a JSON value");
}
async function sha256(value) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}
async function importIdentity(pkcs8Hex, publicKey) {
  if (!/^[0-9a-f]{64}$/.test(publicKey)) throw new Error("Invalid public key");
  const privateKey2 = await crypto.subtle.importKey("pkcs8", hexToBytes(pkcs8Hex), { name: "Ed25519" }, false, ["sign"]);
  const identity = { publicKey, privateKey: privateKey2 };
  const check = await sign({ type: "scopeblind.coordination.key-check.v1" }, identity);
  if (!await verify(check, publicKey)) throw new Error("Signing key does not match authority key");
  return identity;
}
async function sign(payload, identity) {
  if (identity.deviceAuthorization && identity.repositoryDeviceAuthorization) throw new Error("A signature cannot combine room and project device authority");
  const preimage = COORDINATION_DOMAIN + canonical(payload);
  const signature = await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(preimage));
  const envelope2 = { payload, signer: identity.publicKey, digest: await sha256(preimage), signature: bytesToHex(new Uint8Array(signature)) };
  if (identity.deviceAuthorization) {
    envelope2.authorization = identity.deviceAuthorization;
    const binding = "scopeblind.coordination.device-authorization.v1\n" + envelope2.digest + "\n" + identity.deviceAuthorization.digest;
    envelope2.authorization_signature = bytesToHex(new Uint8Array(await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(binding))));
  }
  if (identity.repositoryDeviceAuthorization) {
    envelope2.repository_authorization = identity.repositoryDeviceAuthorization;
    const binding = "scopeblind.repository.device-authorization.v1\n" + envelope2.digest + "\n" + identity.repositoryDeviceAuthorization.digest;
    envelope2.repository_authorization_signature = bytesToHex(new Uint8Array(await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(binding))));
  }
  return envelope2;
}
async function verify(envelope2, expectedSigner) {
  try {
    if (!envelope2 || !/^[0-9a-f]{64}$/.test(envelope2.signer) || !/^[0-9a-f]{64}$/.test(envelope2.digest) || !/^[0-9a-f]{128}$/.test(envelope2.signature)) return false;
    if (expectedSigner && expectedSigner !== envelope2.signer) return false;
    const preimage = COORDINATION_DOMAIN + canonical(envelope2.payload);
    if (await sha256(preimage) !== envelope2.digest) return false;
    const key4 = await crypto.subtle.importKey("raw", hexToBytes(envelope2.signer), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key4, hexToBytes(envelope2.signature), new TextEncoder().encode(preimage));
  } catch {
    return false;
  }
}
function makeRequest(action, room_id, body) {
  return { type: "scopeblind.coordination.request.v1", action, room_id, body, issued_at: (/* @__PURE__ */ new Date()).toISOString(), nonce: crypto.randomUUID() };
}
var COORDINATION_DOMAIN;
var init_coordination_protocol = __esm({
  "src/coordination-protocol.ts"() {
    "use strict";
    COORDINATION_DOMAIN = "scopeblind.coordination.v1\n";
  }
});

// src/coordination-repository-devices.ts
function validRepositoryDeviceAuthorization(v) {
  return obj(v) && exact(v, ["type", "id", "link_id", "workspace_id", "workspace_digest", "member_id", "member_revision", "principal_key", "device_key", "device_name", "actions", "authority_key", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.device-authorization.v1" && [v.id, v.link_id, v.workspace_id, v.member_id].every(id) && [v.workspace_digest, v.principal_key, v.device_key, v.authority_key].every(key) && (/* @__PURE__ */ new Set([v.principal_key, v.device_key, v.authority_key])).size === 3 && Number.isSafeInteger(v.member_revision) && Number(v.member_revision) > 0 && name(v.device_name) && Array.isArray(v.actions) && v.actions.includes("read") && v.actions.length <= REPOSITORY_DEVICE_PERMISSIONS.length && new Set(v.actions).size === v.actions.length && v.actions.every((a) => REPOSITORY_DEVICE_PERMISSIONS.includes(a)) && period(v, REPOSITORY_DEVICE_MAX_MS);
}
async function verifyRepositoryDeviceAuthorization(value) {
  return clean(value) && validRepositoryDeviceAuthorization(value.payload) && await verify(value, value.payload.principal_key);
}
function repositoryDevicePreimage(payloadDigest, authorizationDigest) {
  return REPOSITORY_DEVICE_DOMAIN + payloadDigest + "\n" + authorizationDigest;
}
function repositoryDevicePermission(action) {
  if (["repository_workspace_list", "repository_workspace_get", "repository_workspace_inbox", "repository_workspace_task_get", "repository_get", "repository_export", "repository_review_get", "repository_review_export", "repository_collaboration_get", "repository_collaboration_export"].includes(action)) return "read";
  if (action === "repository_workspace_claim") return "claim";
  if (action === "repository_approve") return "review";
  if (action === "repository_review_feedback") return "feedback";
  if (action === "repository_accept") return "accept";
  return null;
}
function repositoryHumanPermission(value) {
  const p = value.payload, g = value.repository_authorization?.payload;
  if (!obj(p) || !g || !time(p.issued_at)) return null;
  if (p.type === "scopeblind.coordination.request.v1") {
    const action2 = typeof p.action === "string" ? repositoryDevicePermission(p.action) : null;
    return action2 ? { action: action2, at: p.issued_at } : null;
  }
  const action = p.type === "scopeblind.repository.claim.v1" && p.reviewer_key === g.principal_key ? "claim" : ["scopeblind.repository.approval.v1", "scopeblind.repository.review-decision.v1"].includes(String(p.type)) && p.principal_key === g.principal_key ? "review" : p.type === "scopeblind.repository.acceptance.v1" && p.reviewer_key === g.principal_key ? "accept" : p.type === "scopeblind.repository.review-feedback.v1" && p.requester_key === g.principal_key && !p.mandate_digest ? "feedback" : null;
  return action && id(p.task_id) && key(p.task_digest) ? { action, at: p.issued_at } : null;
}
function validRepositoryHumanEnvelope(value) {
  if (!obj(value)) return false;
  if (!Object.hasOwn(value, "repository_authorization")) return clean(value);
  return exact(value, ["payload", "signer", "digest", "signature", "repository_authorization", "repository_authorization_signature"], ["repository_authorization_use"]);
}
async function verifyRepositoryHuman(value, principal, context) {
  try {
    if (!validRepositoryHumanEnvelope(value) || !key(principal)) return false;
    if (!value.repository_authorization) return await verify(value, principal);
    const authorization = value.repository_authorization, g = authorization.payload;
    if (!await verifyRepositoryDeviceAuthorization(authorization) || g.authority_key !== context.authorityKey || g.principal_key !== principal || g.device_key !== value.signer || !await verify(value) || typeof value.repository_authorization_signature !== "string" || !/^[a-f0-9]{128}$/.test(value.repository_authorization_signature)) return false;
    const publicKey = await crypto.subtle.importKey("raw", hexToBytes(value.signer), { name: "Ed25519" }, false, ["verify"]);
    if (!await crypto.subtle.verify("Ed25519", publicKey, hexToBytes(value.repository_authorization_signature), new TextEncoder().encode(repositoryDevicePreimage(value.digest, authorization.digest)))) return false;
    const permission = repositoryHumanPermission(value), p = value.payload;
    if (!permission || !g.actions.includes(permission.action) || Date.parse(permission.at) < Date.parse(g.issued_at) || Date.parse(permission.at) >= Date.parse(g.expires_at)) return false;
    if (p.expires_at !== void 0 && (!time(p.expires_at) || Date.parse(p.expires_at) > Date.parse(g.expires_at))) return false;
    if (context.task && (p.task_id !== context.task.payload.id || p.task_digest !== context.task.digest || context.task.payload.authority_key !== g.authority_key)) return false;
    const use = value.repository_authorization_use;
    if (!use) return !context.requireRecordedUse;
    const u = use.payload;
    return clean(use) && obj(u) && exact(u, ["type", "authorization_digest", "workspace_id", "workspace_digest", "member_id", "member_revision", "principal_key", "device_key", "task_id", "task_digest", "payload_digest", "action", "recorded_at"]) && u.type === "scopeblind.repository.device-use.v1" && await verify(use, g.authority_key) && u.authorization_digest === authorization.digest && u.workspace_id === g.workspace_id && u.workspace_digest === g.workspace_digest && u.member_id === g.member_id && u.member_revision === g.member_revision && u.principal_key === g.principal_key && u.device_key === g.device_key && u.task_id === p.task_id && u.task_digest === p.task_digest && u.payload_digest === value.digest && u.action === permission.action && time(u.recorded_at) && Date.parse(u.recorded_at) >= Date.parse(permission.at) && Date.parse(u.recorded_at) < Date.parse(g.expires_at);
  } catch {
    return false;
  }
}
var REPOSITORY_DEVICE_DOMAIN, REPOSITORY_DEVICE_PERMISSIONS, REPOSITORY_DEVICE_LINK_MS, REPOSITORY_DEVICE_MAX_MS, obj, exact, key, id, name, time, period, clean;
var init_coordination_repository_devices = __esm({
  "src/coordination-repository-devices.ts"() {
    "use strict";
    init_coordination_protocol();
    REPOSITORY_DEVICE_DOMAIN = "scopeblind.repository.device-authorization.v1\n";
    REPOSITORY_DEVICE_PERMISSIONS = ["read", "claim", "review", "feedback", "accept"];
    REPOSITORY_DEVICE_LINK_MS = 10 * 60 * 1e3;
    REPOSITORY_DEVICE_MAX_MS = 7 * 864e5;
    obj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    exact = (v, required, optional = []) => required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
    key = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
    id = (v) => typeof v === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(v);
    name = (v) => typeof v === "string" && v === v.trim() && v.length > 0 && v.length <= 60 && !/[\u0000-\u001f\u007f]/.test(v);
    time = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
    period = (v, max) => time(v.issued_at) && time(v.expires_at) && Date.parse(v.expires_at) > Date.parse(v.issued_at) && Date.parse(v.expires_at) - Date.parse(v.issued_at) <= max;
    clean = (v) => obj(v) && exact(v, ["payload", "signer", "digest", "signature"]);
  }
});

// src/coordination-repository.ts
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
  if (!object(v) || !exact2(v, ["type", "id", "title", "repository", "pull_number", "base_branch", "owner_key", "receiver_key", "authority_key", "allowed_paths", "required_checks", "reviewer_secret_hash", "issued_at", "expires_at"])) return false;
  return v.type === "scopeblind.repository.task.v1" && REPOSITORY_ID.test(String(v.id)) && text(v.title, 140) && typeof v.repository === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v.repository) && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key, v.reviewer_secret_hash].every((x) => typeof x === "string" && REPOSITORY_HEX.test(x)) && v.owner_key !== v.receiver_key && v.owner_key !== v.authority_key && v.receiver_key !== v.authority_key && Array.isArray(v.allowed_paths) && v.allowed_paths.length > 0 && v.allowed_paths.length <= 12 && new Set(v.allowed_paths).size === v.allowed_paths.length && v.allowed_paths.every((p) => typeof p === "string" && repositoryPath(p.endsWith("/**") ? p.slice(0, -3) : p) && pathAllowed(p.endsWith("/**") ? p.slice(0, -2) + "placeholder" : p, [p])) && Array.isArray(v.required_checks) && v.required_checks.length > 0 && v.required_checks.length <= 12 && v.required_checks.every((c) => object(c) && exact2(c, ["name", "app_id"]) && text(c.name, 100) && Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0) && new Set(v.required_checks.map((c) => canonical(c))).size === v.required_checks.length && time2(v.issued_at) && time2(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 7 * 864e5;
}
function validRepositoryProposal(v, task, taskDigest) {
  if (!object(v) || !exact2(v, ["type", "id", "task_id", "task_digest", "repository_id", "base_ref", "head_ref", "base_sha", "head_sha", "merge_sha", "tree_sha", "files", "checks", "observed_at"])) return false;
  if (v.type !== "scopeblind.repository.proposal.v1" || !REPOSITORY_ID.test(String(v.id)) || v.task_id !== task.id || v.task_digest !== taskDigest || !text(v.repository_id, 100) || v.base_ref !== `refs/heads/${task.base_branch}` || typeof v.head_ref !== "string" || !v.head_ref.startsWith("refs/heads/") || !repositoryBranch(v.head_ref.slice(11)) || v.head_ref === v.base_ref || ![v.base_sha, v.head_sha, v.merge_sha, v.tree_sha].every((s) => typeof s === "string" && REPOSITORY_SHA.test(s)) || v.base_sha === v.head_sha || v.merge_sha === v.base_sha || !time2(v.observed_at)) return false;
  if (!Array.isArray(v.files) || !v.files.length || v.files.length > 50 || new Set(v.files.map((f) => object(f) ? f.path : null)).size !== v.files.length || !v.files.every((f) => object(f) && exact2(f, ["path", "status", "mode", "additions", "deletions"], ["previous_path", "patch", "patch_truncated"]) && typeof f.path === "string" && pathAllowed(f.path, task.allowed_paths) && ["added", "modified", "removed", "renamed"].includes(String(f.status)) && ["100644", "100755"].includes(String(f.mode)) && Number.isSafeInteger(f.additions) && Number(f.additions) >= 0 && Number.isSafeInteger(f.deletions) && Number(f.deletions) >= 0 && (f.patch === void 0 || typeof f.patch === "string" && f.patch.length <= 400) && (f.patch_truncated === void 0 || f.patch_truncated === true) && (f.status === "renamed" ? typeof f.previous_path === "string" && pathAllowed(f.previous_path, task.allowed_paths) : f.previous_path === void 0))) return false;
  return Array.isArray(v.checks) && v.checks.length === task.required_checks.length && v.checks.every((c) => object(c) && exact2(c, ["id", "name", "app_id", "head_sha", "conclusion"]) && Number.isSafeInteger(c.id) && Number(c.id) > 0 && c.head_sha === v.head_sha && c.conclusion === "success" && task.required_checks.some((r) => r.name === c.name && r.app_id === c.app_id)) && new Set(v.checks.map((c) => `${c.name}:${c.app_id}`)).size === v.checks.length;
}
async function repositorySnapshotDigest(p) {
  const { id: id7, observed_at, ...snapshot } = p;
  return sha256(canonical(snapshot));
}
function validRepositoryRecord(v, kind) {
  if (!object(v) || v.type !== `scopeblind.repository.${kind}.v1` || !REPOSITORY_ID.test(String(v.task_id)) || !REPOSITORY_HEX.test(String(v.task_digest))) return false;
  const common = ["type", "task_id", "task_digest"];
  if (kind === "claim") return exact2(v, [...common, "reviewer_key", "name", "issued_at"]) && REPOSITORY_HEX.test(String(v.reviewer_key)) && text(v.name, 60) && time2(v.issued_at);
  const note = (v2) => typeof v2 === "string" && v2.length <= 600;
  if (kind === "approval") return exact2(v, [...common, "proposal_digest", "role", "principal_key", "decision", "issued_at", "expires_at", "note"]) && REPOSITORY_HEX.test(String(v.proposal_digest)) && REPOSITORY_HEX.test(String(v.principal_key)) && ["owner", "reviewer"].includes(String(v.role)) && ["approve", "reject"].includes(String(v.decision)) && time2(v.issued_at) && time2(v.expires_at) && note(v.note) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 9e5;
  if (kind === "execution") return exact2(v, [...common, "operation_id", "receiver_attempt_id", "proposal_digest", "owner_approval_digest", "reviewer_approval_digest", "receiver_key", "action", "issued_at", "expires_at"]) && [v.operation_id, v.receiver_attempt_id].every((x) => REPOSITORY_ID.test(String(x))) && [v.proposal_digest, v.owner_approval_digest, v.reviewer_approval_digest, v.receiver_key].every((x) => REPOSITORY_HEX.test(String(x))) && v.action === "github.updateRefs" && time2(v.issued_at) && time2(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 12e4;
  if (kind === "outcome") return exact2(v, [...common, "operation_id", "proposal_digest", "execution_digest", "status", "observed_base_sha", "readback", "observed_at", "note"], ["github_request_id"]) && REPOSITORY_ID.test(String(v.operation_id)) && [v.proposal_digest, v.execution_digest].every((x) => REPOSITORY_HEX.test(String(x))) && ["confirmed", "failed", "unknown"].includes(String(v.status)) && (v.observed_base_sha === null || REPOSITORY_SHA.test(String(v.observed_base_sha))) && ["exact_ref", "descendant_ref", "not_confirmed"].includes(String(v.readback)) && (v.status === "confirmed" ? v.readback !== "not_confirmed" && v.observed_base_sha !== null : v.readback === "not_confirmed") && time2(v.observed_at) && note(v.note) && (v.github_request_id === void 0 || text(v.github_request_id, 200));
  return exact2(v, [...common, "outcome_digest", "reviewer_key", "decision", "issued_at", "note"]) && [v.outcome_digest, v.reviewer_key].every((x) => REPOSITORY_HEX.test(String(x))) && ["accept", "request_changes"].includes(String(v.decision)) && time2(v.issued_at) && note(v.note);
}
async function verifyRepositoryEvidence(value, pin) {
  const pins = typeof pin === "string" ? { authority_key: pin } : pin ?? { authority_key: value?.state?.payload?.task?.payload?.authority_key };
  const errors = [];
  let accepted = false;
  const check = (condition, message) => {
    if (!condition) errors.push(message);
  };
  try {
    const e = value, s = e.state?.payload, t = s?.task?.payload;
    check(object(e) && exact2(e, ["type", "state"]) && e.type === "scopeblind.repository.evidence.v1" && validRepositoryEnvelope(e.state) && !!s && s.type === "scopeblind.repository.state.v1" && exact2(s, ["type", "task", "reviewer", "proposal", "approvals", "execution", "outcome", "acceptance", "status", "revision", "observed_at"]) && Number.isSafeInteger(s.revision) && s.revision > 0 && time2(s.observed_at) && await verify(e.state, pins.authority_key), "Service state signature or shape is invalid");
    check(validRepositoryEnvelope(s.task) && validRepositoryTask(t) && await verify(s.task, t.owner_key) && t.authority_key === pins.authority_key && (!pins.owner_key || pins.owner_key === t.owner_key) && (!pins.receiver_key || pins.receiver_key === t.receiver_key) && Date.parse(s.observed_at) >= Date.parse(t.issued_at), "Task or pinned owner/receiver is invalid");
    const reviewer = s.reviewer?.payload;
    if (s.reviewer) check(validRepositoryHumanEnvelope(s.reviewer) && validRepositoryRecord(reviewer, "claim") && reviewer.task_id === t.id && reviewer.task_digest === s.task.digest && ![t.owner_key, t.receiver_key, t.authority_key].includes(reviewer.reviewer_key) && await verifyRepositoryHuman(s.reviewer, reviewer.reviewer_key, { authorityKey: pins.authority_key, task: s.task, requireRecordedUse: true }) && (!pins.reviewer_key || pins.reviewer_key === reviewer.reviewer_key) && Date.parse(reviewer.issued_at) >= Date.parse(t.issued_at) && Date.parse(reviewer.issued_at) < Date.parse(t.expires_at), "Reviewer role is invalid");
    if (s.proposal) check(!!reviewer && validRepositoryEnvelope(s.proposal) && validRepositoryProposal(s.proposal.payload, t, s.task.digest) && await verify(s.proposal, t.receiver_key) && Date.parse(s.proposal.payload.observed_at) >= Date.parse(reviewer.issued_at) && Date.parse(s.proposal.payload.observed_at) < Date.parse(t.expires_at), "Repository snapshot is invalid");
    check(Array.isArray(s.approvals) && s.approvals.length <= 2 && new Set(s.approvals.map((a) => a.payload.role)).size === s.approvals.length, "Approval roles are invalid");
    for (const approval of s.approvals) {
      const a = approval.payload, key4 = a.role === "owner" ? t.owner_key : reviewer?.reviewer_key;
      check(!!s.proposal && validRepositoryHumanEnvelope(approval) && validRepositoryRecord(a, "approval") && a.principal_key === key4 && a.task_id === t.id && a.task_digest === s.task.digest && a.proposal_digest === s.proposal.digest && await verifyRepositoryHuman(approval, key4, { authorityKey: pins.authority_key, task: s.task, requireRecordedUse: true }) && Date.parse(a.issued_at) >= Date.parse(s.proposal.payload.observed_at) && Date.parse(a.expires_at) <= Date.parse(t.expires_at), "Exact proposal approval is invalid");
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
      check(s.outcome?.payload.status === "confirmed" && validRepositoryHumanEnvelope(s.acceptance) && validRepositoryRecord(a, "acceptance") && a.task_id === t.id && a.task_digest === s.task.digest && a.outcome_digest === s.outcome.digest && a.reviewer_key === reviewer?.reviewer_key && await verifyRepositoryHuman(s.acceptance, reviewer?.reviewer_key, { authorityKey: pins.authority_key, task: s.task, requireRecordedUse: true }) && Date.parse(a.issued_at) >= Date.parse(s.outcome.payload.observed_at), "Recipient acceptance is invalid");
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
var REPOSITORY_HEX, REPOSITORY_SHA, REPOSITORY_ID, object, text, time2, exact2, validRepositoryEnvelope;
var init_coordination_repository = __esm({
  "src/coordination-repository.ts"() {
    "use strict";
    init_coordination_repository_devices();
    init_coordination_protocol();
    REPOSITORY_HEX = /^[0-9a-f]{64}$/;
    REPOSITORY_SHA = /^[0-9a-f]{40}$/;
    REPOSITORY_ID = /^[A-Za-z0-9_-]{8,100}$/;
    object = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    text = (v, n) => typeof v === "string" && v.length > 0 && v.length <= n && !/[\u0000-\u001f\u007f]/.test(v);
    time2 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
    exact2 = (v, required, optional = []) => required.every((k) => k in v) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
    validRepositoryEnvelope = (e) => object(e) && exact2(e, ["payload", "signer", "digest", "signature"]);
  }
});

// src/coordination-repository-review.ts
function safeRepositoryPreviewUrl(value) {
  if (typeof value !== "string" || value.length > 2e3 || /[\s\u0000-\u001f\u007f]/.test(value)) return false;
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !u.username && !u.password && u.href === value && !u.hash && !u.search && u.hostname !== "localhost" && !u.hostname.endsWith(".localhost") && u.hostname.includes(".") && !/^\d+(?:\.\d+){3}$/.test(u.hostname) && !u.hostname.includes(":");
  } catch {
    return false;
  }
}
function content(v) {
  if (!text2(v.brief, 4e3) || !Array.isArray(v.success_criteria) || v.success_criteria.length < 1 || v.success_criteria.length > 20 || !v.success_criteria.every((c) => shape(c, ["id", "text"]) && id2(c.id) && text2(c.text, 600)) || new Set(v.success_criteria.map((c) => c.id)).size !== v.success_criteria.length) return false;
  const p = v.preview_policy;
  return p === void 0 || shape(p, ["environment", "check", "allowed_origins", "required"]) && line(p.environment, 100) && shape(p.check, ["name", "app_id"]) && line(p.check.name, 100) && num(p.check.app_id) && typeof p.required === "boolean" && Array.isArray(p.allowed_origins) && p.allowed_origins.length > 0 && p.allowed_origins.length <= 8 && new Set(p.allowed_origins).size === p.allowed_origins.length && p.allowed_origins.every((origin) => typeof origin === "string" && safeRepositoryPreviewUrl(origin + "/") && new URL(origin).origin === origin);
}
function validRepositoryReviewContent(v) {
  return shape(v, ["brief", "success_criteria"], ["preview_policy"]) && content(v);
}
function validRepositoryReviewBrief(v, task, taskDigest) {
  return shape(v, ["type", "task_id", "task_digest", "owner_key", "brief", "success_criteria", "issued_at", "expires_at"], ["preview_policy"]) && v.type === "scopeblind.repository.review-brief.v1" && v.task_id === task.id && v.task_digest === taskDigest && v.owner_key === task.owner_key && content(v) && span(v.issued_at, v.expires_at, 7 * 864e5) && Date.parse(String(v.issued_at)) >= Date.parse(task.issued_at) && Date.parse(String(v.expires_at)) <= Date.parse(task.expires_at);
}
function validRepositoryReviewPacket(v, brief, proposal) {
  if (!shape(v, ["type", "task_id", "task_digest", "brief_digest", "proposal_digest", "base_sha", "head_sha", "merge_sha", "preview", "observed_at", "expires_at"]) || v.type !== "scopeblind.repository.review-packet.v1" || v.task_id !== brief.payload.task_id || v.task_digest !== brief.payload.task_digest || v.brief_digest !== brief.digest || v.proposal_digest !== proposal.digest || v.base_sha !== proposal.payload.base_sha || v.head_sha !== proposal.payload.head_sha || v.merge_sha !== proposal.payload.merge_sha || !span(v.observed_at, v.expires_at, 9e5) || Date.parse(String(v.observed_at)) < Math.max(Date.parse(brief.payload.issued_at), Date.parse(proposal.payload.observed_at)) || Date.parse(String(v.expires_at)) > Date.parse(brief.payload.expires_at)) return false;
  const p = v.preview, policy = brief.payload.preview_policy;
  if (!object2(p)) return false;
  if (p.status !== "available") return shape(p, ["status", "reason"]) && ["not_requested", "missing", "pending", "failed", "unavailable", "ambiguous"].includes(String(p.status)) && text2(p.reason, 600) && p.status === "not_requested" === !policy;
  if (!policy || !shape(p, ["status", "deployment"], ["artifact"])) return false;
  const d = p.deployment;
  if (!shape(d, ["deployment_id", "status_id", "sha", "environment", "state", "environment_url", "deployment_creator_id", "status_creator_id", "created_at", "updated_at", "check"]) || ![d.deployment_id, d.status_id, d.deployment_creator_id, d.status_creator_id].every(num) || d.sha !== v.head_sha || d.environment !== policy.environment || d.state !== "success" || !safeRepositoryPreviewUrl(d.environment_url) || !policy.allowed_origins.includes(new URL(d.environment_url).origin) || !at(d.created_at) || !at(d.updated_at) || Date.parse(d.updated_at) < Date.parse(d.created_at) || Date.parse(d.updated_at) > Date.parse(String(v.observed_at)) || !shape(d.check, ["id", "name", "app_id", "head_sha", "conclusion"]) || !num(d.check.id) || d.check.name !== policy.check.name || d.check.app_id !== policy.check.app_id || d.check.head_sha !== v.head_sha || d.check.conclusion !== "success") return false;
  const a = p.artifact;
  return a === void 0 || shape(a, ["id", "name", "sha256", "workflow_run_id", "head_sha", "expires_at"]) && num(a.id) && line(a.name, 200) && hex(a.sha256) && num(a.workflow_run_id) && a.head_sha === v.head_sha && at(a.expires_at) && Date.parse(a.expires_at) > Date.parse(String(v.observed_at));
}
function validRepositoryReviewDecision(v, brief, packet, approval) {
  return shape(v, ["type", "task_id", "task_digest", "brief_digest", "packet_digest", "proposal_digest", "approval_digest", "principal_key", "role", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.review-decision.v1" && v.task_id === brief.payload.task_id && v.task_digest === brief.payload.task_digest && v.brief_digest === brief.digest && v.packet_digest === packet.digest && v.proposal_digest === packet.payload.proposal_digest && v.approval_digest === approval.digest && v.principal_key === approval.payload.principal_key && v.role === approval.payload.role && v.issued_at === approval.payload.issued_at && v.expires_at === approval.payload.expires_at && at(v.issued_at) && at(v.expires_at) && Date.parse(v.issued_at) >= Date.parse(packet.payload.observed_at) && Date.parse(v.expires_at) <= Date.parse(packet.payload.expires_at) && (!brief.payload.preview_policy?.required || packet.payload.preview.status === "available" || approval.payload.decision === "reject");
}
function validRepositoryReviewFeedback(v, brief, packet) {
  return shape(v, ["type", "id", "task_id", "task_digest", "basis_digest", "packet_digest", "requester_key", "criterion_ids", "message", "requested_changes", "issued_at"], ["mandate_digest"]) && v.type === "scopeblind.repository.review-feedback.v1" && id2(v.id) && v.task_id === brief.payload.task_id && v.task_digest === brief.payload.task_digest && hex(v.basis_digest) && v.packet_digest === packet.digest && hex(v.requester_key) && (v.mandate_digest === void 0 || hex(v.mandate_digest)) && Array.isArray(v.criterion_ids) && v.criterion_ids.length <= 20 && new Set(v.criterion_ids).size === v.criterion_ids.length && v.criterion_ids.every((cid) => brief.payload.success_criteria.some((c) => c.id === cid)) && text2(v.message, 2e3) && text2(v.requested_changes, 4e3, true) && at(v.issued_at) && Date.parse(v.issued_at) >= Date.parse(packet.payload.observed_at);
}
function validRepositoryReviewRecommendation(v, brief, packet, proposal) {
  if (!shape(v, ["type", "id", "task_id", "task_digest", "packet_digest", "proposal_digest", "brief_digest", "agent_key", "mandate_digest", "recommendation", "criteria", "source", "observed_at"]) || v.type !== "scopeblind.repository.review-recommendation.v1" || !id2(v.id) || v.task_id !== brief.payload.task_id || v.task_digest !== brief.payload.task_digest || v.packet_digest !== packet.digest || v.proposal_digest !== proposal.digest || v.brief_digest !== brief.digest || !hex(v.agent_key) || !hex(v.mandate_digest) || !["ready_for_human_review", "changes_recommended", "insufficient_evidence"].includes(String(v.recommendation)) || !shape(v.source, ["kind"], ["model"]) || v.source.kind !== "agent" || v.source.model !== void 0 && !line(v.source.model, 120) || !at(v.observed_at) || Date.parse(v.observed_at) < Date.parse(packet.payload.observed_at) || !Array.isArray(v.criteria) || v.criteria.length !== brief.payload.success_criteria.length) return false;
  if (new Set(v.criteria.map((c) => object2(c) ? c.criterion_id : null)).size !== v.criteria.length) return false;
  return v.criteria.every((c) => shape(c, ["criterion_id", "verdict", "evidence_refs", "explanation"]) && brief.payload.success_criteria.some((b) => b.id === c.criterion_id) && ["met", "not_met", "unknown"].includes(String(c.verdict)) && text2(c.explanation, 1e3) && Array.isArray(c.evidence_refs) && c.evidence_refs.length <= 12 && c.evidence_refs.every((r) => {
    if (!object2(r)) return false;
    if (r.kind === "check") return shape(r, ["kind", "id"]) && proposal.payload.checks.some((check) => check.id === r.id);
    if (r.kind === "file") return shape(r, ["kind", "path"]) && proposal.payload.files.some((file) => file.path === r.path);
    if (r.kind === "deployment") return shape(r, ["kind", "id"]) && packet.payload.preview.status === "available" && packet.payload.preview.deployment.deployment_id === r.id;
    return r.kind === "artifact" && shape(r, ["kind", "sha256"]) && packet.payload.preview.status === "available" && packet.payload.preview.artifact?.sha256 === r.sha256;
  }));
}
async function verifyRepositoryPreviewDiscovery(value, pins, now = Date.now()) {
  try {
    const e = value, v = e.payload;
    return validRepositoryEnvelope(e) && shape(v, ["type", "repository", "pull_number", "head_sha", "owner_key", "receiver_key", "authority_key", "candidates", "checks", "status", "observed_at", "expires_at"]) && v.type === "scopeblind.repository.preview-discovery.v1" && v.repository === pins.repository && num(v.pull_number) && (pins.pull_number === void 0 || v.pull_number === pins.pull_number) && sha(v.head_sha) && v.owner_key === pins.owner_key && v.receiver_key === pins.receiver_key && v.authority_key === pins.authority_key && span(v.observed_at, v.expires_at, 864e5) && Date.parse(v.observed_at) <= now + 1e3 && Date.parse(v.expires_at) > now && ["observed", "unavailable"].includes(v.status) && Array.isArray(v.candidates) && v.candidates.length <= 20 && v.candidates.every((c) => shape(c, ["environment", "origin", "environment_url", "deployment_id", "status_id"]) && line(c.environment, 100) && safeRepositoryPreviewUrl(c.environment_url) && new URL(c.environment_url).origin === c.origin && num(c.deployment_id) && num(c.status_id)) && new Set(v.candidates.map((c) => c.deployment_id)).size === v.candidates.length && Array.isArray(v.checks) && v.checks.length <= 100 && v.checks.every((c) => shape(c, ["name", "app_id", "id"]) && line(c.name, 100) && num(c.app_id) && num(c.id)) && new Set(v.checks.map((c) => c.name + ":" + c.app_id)).size === v.checks.length && (v.status !== "unavailable" || v.candidates.length === 0) && await verify(e, pins.receiver_key);
  } catch {
    return false;
  }
}
var object2, shape, text2, line, hex, id2, sha, num, at, span;
var init_coordination_repository_review = __esm({
  "src/coordination-repository-review.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    object2 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    shape = (v, required, optional = []) => object2(v) && required.every((k) => Object.prototype.hasOwnProperty.call(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
    text2 = (v, max, empty = false) => typeof v === "string" && (empty || v.trim().length > 0) && v.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);
    line = (v, max) => text2(v, max) && !/[\r\n\t]/.test(String(v));
    hex = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
    id2 = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
    sha = (v) => typeof v === "string" && REPOSITORY_SHA.test(v);
    num = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
    at = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
    span = (a, b, max) => at(a) && at(b) && Date.parse(b) > Date.parse(a) && Date.parse(b) - Date.parse(a) <= max;
  }
});

// src/coordination-repository-workspace.ts
function workspacePathsWithin(proposed, allowed) {
  return proposed.every((path) => path.endsWith("/**") ? allowed.some((rule) => rule.endsWith("/**") && (path === rule || path.slice(0, -3).startsWith(rule.slice(0, -2)))) : pathAllowed(path, allowed));
}
function validRepositoryWorkspace(v) {
  return obj2(v) && exact3(v, ["type", "id", "title", "client_name", "repository", "base_branch", "receiver_key", "authority_key", "owner_member_id", "owner_key", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.workspace.v1" && id3(v.id) && id3(v.owner_member_id) && text3(v.title, 100) && text3(v.client_name, 100) && repo(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(key2) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.authority_key])).size === 3 && period2(v, 365 * 864e5);
}
function validWorkspaceInvitation(v) {
  return obj2(v) && exact3(v, ["type", "id", "workspace_id", "workspace_digest", "member_id", "role", "display_name", "issuer_key", "secret_hash", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.workspace-invitation.v1" && [v.id, v.workspace_id, v.member_id].every(id3) && [v.workspace_digest, v.issuer_key, v.secret_hash].every(key2) && ["reviewer", "observer"].includes(String(v.role)) && text3(v.display_name, 60) && period2(v, 7 * 864e5);
}
function validWorkspaceMemberClaim(v) {
  return obj2(v) && exact3(v, ["type", "workspace_id", "invitation_digest", "member_id", "member_key", "issued_at"]) && v.type === "scopeblind.repository.workspace-member-claim.v1" && [v.workspace_id, v.member_id].every(id3) && [v.invitation_digest, v.member_key].every(key2) && at2(v.issued_at);
}
function validWorkspaceMemberUpdate(v) {
  return obj2(v) && exact3(v, ["type", "id", "workspace_id", "member_id", "expected_revision", "role", "status", "issuer_key", "issued_at"]) && v.type === "scopeblind.repository.workspace-member-update.v1" && [v.id, v.workspace_id, v.member_id].every(id3) && key2(v.issuer_key) && revision(v.expected_revision) && ["reviewer", "observer"].includes(String(v.role)) && ["active", "revoked"].includes(String(v.status)) && at2(v.issued_at);
}
function validWorkspaceRecovery(v) {
  return obj2(v) && exact3(v, ["type", "id", "workspace_id", "member_id", "member_key", "recovery_key", "expected_revision", "issued_at", "expires_at"], ["previous_recovery_digest"]) && v.type === "scopeblind.repository.workspace-recovery.v1" && [v.id, v.workspace_id, v.member_id].every(id3) && [v.member_key, v.recovery_key].every(key2) && v.member_key !== v.recovery_key && revision(v.expected_revision) && (v.previous_recovery_digest === void 0 || key2(v.previous_recovery_digest)) && period2(v, 365 * 864e5);
}
function validWorkspaceRotation(v) {
  return obj2(v) && exact3(v, ["type", "id", "workspace_id", "member_id", "previous_key", "new_key", "recovery_digest", "expected_revision", "issued_at"]) && v.type === "scopeblind.repository.workspace-key-rotation.v1" && [v.id, v.workspace_id, v.member_id].every(id3) && [v.previous_key, v.new_key, v.recovery_digest].every(key2) && v.previous_key !== v.new_key && revision(v.expected_revision) && at2(v.issued_at);
}
function validWorkspaceTaskAssignment(v) {
  return obj2(v) && exact3(v, ["type", "workspace_id", "workspace_digest", "task_id", "task_digest", "owner_member_id", "owner_key", "owner_member_revision", "reviewer_member_id", "reviewer_key", "reviewer_member_revision", "review_brief_digest", "issued_at", "expires_at"], ["source_draft_digest"]) && v.type === "scopeblind.repository.workspace-task-assignment.v1" && [v.workspace_id, v.task_id, v.owner_member_id, v.reviewer_member_id].every(id3) && [v.workspace_digest, v.task_digest, v.owner_key, v.reviewer_key, v.review_brief_digest].every(key2) && v.owner_key !== v.reviewer_key && v.owner_member_id !== v.reviewer_member_id && revision(v.owner_member_revision) && revision(v.reviewer_member_revision) && (v.source_draft_digest === void 0 || key2(v.source_draft_digest)) && period2(v, 7 * 864e5);
}
function validWorkspacePreparationMandate(v) {
  return obj2(v) && exact3(v, ["type", "id", "workspace_id", "workspace_digest", "mode", "owner_member_id", "owner_key", "owner_member_revision", "reviewer_member_id", "reviewer_key", "reviewer_member_revision", "agent_key", "repository", "base_branch", "allowed_paths", "required_checks", "permissions", "max_requests", "max_open_requests", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.preparation-mandate.v1" && v.mode === "prepare_review" && [v.id, v.workspace_id, v.owner_member_id, v.reviewer_member_id].every(id3) && [v.workspace_digest, v.owner_key, v.reviewer_key, v.agent_key].every(key2) && (/* @__PURE__ */ new Set([v.owner_key, v.reviewer_key, v.agent_key])).size === 3 && revision(v.owner_member_revision) && revision(v.reviewer_member_revision) && repo(v.repository) && repositoryBranch(v.base_branch) && paths(v.allowed_paths) && checks(v.required_checks) && Array.isArray(v.permissions) && v.permissions.includes("prepare_review") && v.permissions.length <= 4 && new Set(v.permissions).size === v.permissions.length && v.permissions.every((p) => ["prepare_review", "read_task", "report_criteria", "request_revision"].includes(String(p))) && Number.isSafeInteger(v.max_requests) && Number(v.max_requests) > 0 && Number(v.max_requests) <= 20 && Number.isSafeInteger(v.max_open_requests) && Number(v.max_open_requests) > 0 && Number(v.max_open_requests) <= 3 && Number(v.max_open_requests) <= Number(v.max_requests) && period2(v, 7 * 864e5);
}
function validWorkspaceMandateRevocation(v) {
  return obj2(v) && exact3(v, ["type", "mandate_id", "mandate_digest", "workspace_id", "principal_key", "issued_at"]) && v.type === "scopeblind.repository.preparation-revocation.v1" && [v.mandate_id, v.workspace_id].every(id3) && [v.mandate_digest, v.principal_key].every(key2) && at2(v.issued_at);
}
function validWorkspaceReviewDraft(v) {
  return obj2(v) && exact3(v, ["type", "id", "workspace_id", "mandate_digest", "agent_key", "repository", "pull_number", "title", "content", "allowed_paths", "required_checks", "issued_at"], ["suggested_preview_url", "observed_head_sha", "source"]) && v.type === "scopeblind.repository.workspace-review-draft.v1" && [v.id, v.workspace_id].every(id3) && [v.mandate_digest, v.agent_key].every(key2) && repo(v.repository) && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && text3(v.title, 140) && validRepositoryReviewContent(v.content) && paths(v.allowed_paths) && checks(v.required_checks) && at2(v.issued_at) && (v.source === void 0 || obj2(v.source) && exact3(v.source, ["task_id", "task_digest", "basis_digest", "packet_digest", "feedback_digest"]) && id3(v.source.task_id) && [v.source.task_digest, v.source.basis_digest, v.source.packet_digest, v.source.feedback_digest].every(key2)) && (v.observed_head_sha === void 0 || typeof v.observed_head_sha === "string" && /^[a-f0-9]{40}$/.test(v.observed_head_sha)) && (v.suggested_preview_url === void 0 || typeof v.suggested_preview_url === "string" && v.suggested_preview_url.length <= 2e3 && safeWorkspacePreview(v.suggested_preview_url));
}
function safeWorkspacePreview(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !u.username && !u.password && !u.hash;
  } catch {
    return false;
  }
}
function validWorkspaceDraftDecision(v) {
  return obj2(v) && exact3(v, ["type", "workspace_id", "draft_digest", "owner_key", "decision", "note", "issued_at"], ["task_id", "task_digest"]) && v.type === "scopeblind.repository.workspace-draft-decision.v1" && id3(v.workspace_id) && [v.draft_digest, v.owner_key].every(key2) && ["adopt", "reject"].includes(String(v.decision)) && typeof v.note === "string" && v.note.length <= 600 && at2(v.issued_at) && (v.decision === "adopt" ? id3(v.task_id) && key2(v.task_digest) : v.task_id === void 0 && v.task_digest === void 0);
}
function memberAt(member, time4, workspace) {
  let current = member.claim?.payload.member_key ?? workspace.owner_key, role = member.invitation?.payload.role ?? "owner", status2 = "active", revision2 = 1;
  const events = [...member.rotations.map((p) => ({ at: p.rotation.payload.issued_at, revision: p.rotation.payload.expected_revision, rotation: p.rotation.payload, update: null })), ...member.updates.map((u) => ({ at: u.payload.issued_at, revision: u.payload.expected_revision, rotation: null, update: u.payload }))].sort((a, b) => a.revision - b.revision);
  for (const e of events) if (before(e.at, time4)) {
    if (e.rotation) current = e.rotation.new_key;
    if (e.update) {
      role = e.update.role;
      status2 = e.update.status;
    }
    revision2 = e.revision + 1;
  }
  return { key: current, role, status: status2, revision: revision2 };
}
function memberRevisionAt(member, wanted, time4, workspace) {
  if (!Number.isSafeInteger(wanted) || wanted < 1 || wanted > member.revision) return null;
  let current = member.claim?.payload.member_key ?? workspace.owner_key, role = member.invitation?.payload.role ?? "owner", status2 = "active", start = member.claim?.payload.issued_at ?? workspace.issued_at;
  const events = [...member.rotations.map((p) => ({ at: p.rotation.payload.issued_at, revision: p.rotation.payload.expected_revision, rotation: p.rotation.payload, update: null })), ...member.updates.map((u) => ({ at: u.payload.issued_at, revision: u.payload.expected_revision, rotation: null, update: u.payload }))].sort((a, b) => a.revision - b.revision);
  for (const e of events) {
    if (e.revision >= wanted) {
      if (Date.parse(time4) > Date.parse(e.at)) return null;
      break;
    }
    if (e.rotation) current = e.rotation.new_key;
    if (e.update) {
      role = e.update.role;
      status2 = e.update.status;
    }
    start = e.at;
  }
  return Date.parse(time4) >= Date.parse(start) ? { key: current, role, status: status2, revision: wanted } : null;
}
function historicalMemberKeys(member, workspace) {
  return [.../* @__PURE__ */ new Set([member.claim?.payload.member_key ?? workspace.owner_key, member.current_key, ...member.rotations.flatMap((p) => [p.rotation.payload.previous_key, p.rotation.payload.new_key])])];
}
function memberRecoveryKeys(member) {
  return [.../* @__PURE__ */ new Set([...member.recovery ? [member.recovery.payload.recovery_key] : [], ...member.rotations.map((p) => p.recovery.payload.recovery_key)])];
}
function ownerKeyAt(owner, key4, time4, workspace) {
  for (let r = 1; r <= owner.revision; r++) {
    const state = memberRevisionAt(owner, r, time4, workspace);
    if (state?.key === key4 && state.role === "owner" && state.status === "active") return true;
  }
  return false;
}
async function checkedMembers(workspace, members, observation) {
  const w = workspace.payload;
  if (!cleanEnvelope(workspace) || !validRepositoryWorkspace(w) || !await verify(workspace, w.owner_key) || !at2(observation) || !before(w.issued_at, observation) || !Array.isArray(members) || !members.length || members.length > 20 || new Set(members.map((m) => m.member_id)).size !== members.length || new Set(members.map((m) => m.current_key)).size !== members.length) return false;
  const humans = members.flatMap((m) => historicalMemberKeys(m, w)), recoveries = members.flatMap(memberRecoveryKeys);
  if (new Set(humans).size !== humans.length || humans.some((k) => [w.authority_key, w.receiver_key].includes(k)) || recoveries.some((k) => [w.authority_key, w.receiver_key, ...humans].includes(k))) return false;
  const owner = members.find((m) => m.member_id === w.owner_member_id);
  if (!owner || owner.invitation || owner.claim || owner.role !== "owner" || owner.updates.length) return false;
  for (const m of [owner, ...members.filter((m2) => m2 !== owner)]) {
    if (!exact3(m, ["member_id", "display_name", "role", "status", "current_key", "revision", "invitation", "claim", "recovery", "rotations", "updates"]) || !id3(m.member_id) || !text3(m.display_name, 60) || !key2(m.current_key) || !revision(m.revision) || !["owner", "reviewer", "observer"].includes(m.role) || !["active", "revoked"].includes(m.status) || !Array.isArray(m.rotations) || m.rotations.length > 12 || !Array.isArray(m.updates) || m.updates.length > 40) return false;
    let current = w.owner_key, previousAt = w.issued_at;
    if (m !== owner) {
      const invitation = m.invitation, claim = m.claim;
      if (!invitation || !claim || !cleanEnvelope(invitation) || !cleanEnvelope(claim) || !validWorkspaceInvitation(invitation.payload) || !validWorkspaceMemberClaim(claim.payload)) return false;
      const i = invitation.payload, c = claim.payload;
      if (i.workspace_id !== w.id || i.workspace_digest !== workspace.digest || i.member_id !== m.member_id || !ownerKeyAt(owner, i.issuer_key, i.issued_at, w) || c.workspace_id !== w.id || c.member_id !== m.member_id || c.invitation_digest !== invitation.digest || Date.parse(c.issued_at) < Date.parse(i.issued_at) || Date.parse(c.issued_at) >= Date.parse(i.expires_at) || !before(c.issued_at, observation) || !await verify(invitation, i.issuer_key) || !await verify(claim, c.member_key)) return false;
      current = c.member_key;
      previousAt = c.issued_at;
    }
    const events = [...m.rotations.map((p) => ({ revision: p.rotation.payload.expected_revision, rotation: p, update: null })), ...m.updates.map((u) => ({ revision: u.payload.expected_revision, rotation: null, update: u }))].sort((a, b) => a.revision - b.revision);
    if (events.length !== m.revision - 1) return false;
    for (let index = 0; index < events.length; index++) {
      const event = events[index];
      if (event.revision !== index + 1) return false;
      if (event.rotation) {
        const p = event.rotation, r = p.rotation.payload, g = p.recovery.payload;
        if (!exact3(p, ["recovery", "rotation", "confirmation"]) || ![p.recovery, p.rotation, p.confirmation].every(cleanEnvelope) || !validWorkspaceRecovery(g) || !validWorkspaceRotation(r) || g.workspace_id !== w.id || g.member_id !== m.member_id || g.member_key !== current || g.expected_revision > r.expected_revision || memberRevisionAt(m, g.expected_revision, g.issued_at, w)?.key !== g.member_key || memberRevisionAt(m, g.expected_revision, g.issued_at, w)?.status !== "active" || r.workspace_id !== w.id || r.member_id !== m.member_id || r.previous_key !== current || r.recovery_digest !== p.recovery.digest || p.confirmation.digest !== p.rotation.digest || Date.parse(r.issued_at) < Date.parse(g.issued_at) || Date.parse(r.issued_at) < Date.parse(previousAt) || Date.parse(r.issued_at) >= Date.parse(g.expires_at) || !before(r.issued_at, observation) || !await verify(p.recovery, current) || !await verify(p.rotation, g.recovery_key) || !await verify(p.confirmation, r.new_key)) return false;
        current = r.new_key;
        previousAt = r.issued_at;
      } else {
        const u = event.update, p = u.payload;
        if (!cleanEnvelope(u) || !validWorkspaceMemberUpdate(p) || p.workspace_id !== w.id || p.member_id !== m.member_id || !ownerKeyAt(owner, p.issuer_key, p.issued_at, w) || Date.parse(p.issued_at) < Date.parse(previousAt) || !before(p.issued_at, observation) || !await verify(u, p.issuer_key)) return false;
        previousAt = p.issued_at;
      }
    }
    const observed = memberAt(m, observation, w);
    if (current !== m.current_key || observed.role !== m.role || observed.status !== m.status || observed.revision !== m.revision) return false;
    if (m.recovery) {
      const g = m.recovery.payload;
      if (!cleanEnvelope(m.recovery) || !validWorkspaceRecovery(g) || g.workspace_id !== w.id || g.member_id !== m.member_id || g.member_key !== m.current_key || g.expected_revision > m.revision || memberRevisionAt(m, g.expected_revision, g.issued_at, w)?.key !== g.member_key || memberRevisionAt(m, g.expected_revision, g.issued_at, w)?.status !== "active" || !before(g.issued_at, observation) || !await verify(m.recovery, m.current_key)) return false;
    }
  }
  return true;
}
async function checkedMandate(view, workspace, members, observation) {
  if (!obj2(view) || !exact3(view, ["mandate", "adoption", "revocation", "status", "used_requests", "open_requests"]) || !cleanEnvelope(view.mandate) || !validWorkspacePreparationMandate(view.mandate.payload)) return false;
  const p = view.mandate.payload, w = workspace.payload, o = members.find((m) => m.member_id === p.owner_member_id), r = members.find((m) => m.member_id === p.reviewer_member_id);
  if (!o || !r) return false;
  const owner = memberRevisionAt(o, p.owner_member_revision, p.issued_at, w), reviewer = memberRevisionAt(r, p.reviewer_member_revision, p.issued_at, w);
  if (!owner || !reviewer || p.workspace_id !== w.id || p.workspace_digest !== workspace.digest || p.repository !== w.repository || p.base_branch !== w.base_branch || p.owner_key !== owner.key || p.reviewer_key !== reviewer.key || owner.role !== "owner" || reviewer.role !== "reviewer" || owner.status !== "active" || reviewer.status !== "active" || [w.receiver_key, w.authority_key, ...members.flatMap((m) => historicalMemberKeys(m, w)), ...members.flatMap(memberRecoveryKeys)].includes(p.agent_key) || !before(p.issued_at, observation) || Date.parse(p.expires_at) > Date.parse(w.expires_at) || !await verify(view.mandate, p.owner_key) || !Number.isSafeInteger(view.used_requests) || view.used_requests < 0 || view.used_requests > p.max_requests || !Number.isSafeInteger(view.open_requests) || view.open_requests < 0 || view.open_requests > p.max_open_requests || view.open_requests > view.used_requests) return false;
  if (view.adoption && (!cleanEnvelope(view.adoption) || view.adoption.digest !== view.mandate.digest || canonical(view.adoption.payload) !== canonical(p) || !await verify(view.adoption, p.reviewer_key))) return false;
  if (view.revocation) {
    const rev = view.revocation.payload;
    if (!cleanEnvelope(view.revocation) || !validWorkspaceMandateRevocation(rev) || rev.workspace_id !== w.id || rev.mandate_id !== p.id || rev.mandate_digest !== view.mandate.digest || ![p.owner_key, p.reviewer_key].includes(rev.principal_key) || !before(rev.issued_at, observation) || !await verify(view.revocation, rev.principal_key)) return false;
  }
  const nowO = memberAt(o, observation, w), nowR = memberAt(r, observation, w), expected = view.revocation ? "revoked" : nowO.key !== p.owner_key || nowR.key !== p.reviewer_key || nowO.revision !== p.owner_member_revision || nowR.revision !== p.reviewer_member_revision || nowO.role !== "owner" || nowR.role !== "reviewer" || nowO.status !== "active" || nowR.status !== "active" ? "membership_changed" : Date.parse(p.expires_at) <= Date.parse(observation) ? "expired" : !view.adoption ? "awaiting_reviewer" : view.used_requests >= p.max_requests ? "exhausted" : "active";
  return view.status === expected;
}
async function checkedDraft(view, workspace, members, mandates, observation) {
  if (!obj2(view) || !exact3(view, ["draft", "decision"]) || !cleanEnvelope(view.draft) || !validWorkspaceReviewDraft(view.draft.payload)) return false;
  const p = view.draft.payload, m = mandates.find((m2) => m2.mandate.digest === p.mandate_digest), g = m?.mandate.payload;
  if (!g || !m?.adoption || p.workspace_id !== workspace.payload.id || p.agent_key !== g.agent_key || p.repository !== g.repository || Date.parse(p.issued_at) < Date.parse(g.issued_at) || Date.parse(p.issued_at) >= Date.parse(g.expires_at) || !before(p.issued_at, observation) || !await verify(view.draft, g.agent_key) || !workspacePathsWithin(p.allowed_paths, g.allowed_paths) || !g.required_checks.every((c) => p.required_checks.some((r) => canonical(r) === canonical(c))) || p.required_checks.some((c) => g.required_checks.some((r) => r.name === c.name && r.app_id !== c.app_id))) return false;
  if (view.decision) {
    const d = view.decision.payload, owner = members.find((m2) => m2.member_id === workspace.payload.owner_member_id);
    if (!owner || !cleanEnvelope(view.decision) || !validWorkspaceDraftDecision(d) || d.workspace_id !== workspace.payload.id || d.draft_digest !== view.draft.digest || !ownerKeyAt(owner, d.owner_key, d.issued_at, workspace.payload) || !before(d.issued_at, observation) || !await verify(view.decision, d.owner_key)) return false;
  }
  return true;
}
async function verifyRepositoryWorkspaceState(value, authorityKey, viewerKey) {
  try {
    const e = value, s = e.payload;
    if (!cleanEnvelope(e) || !s || !exact3(s, ["type", "workspace", "members", "invitations", "assignments", "mandates", "drafts", "viewer", "observed_at"]) || s.type !== "scopeblind.repository.workspace-state.v1" || !await verify(e, authorityKey) || s.workspace.payload.authority_key !== authorityKey || viewerKey && s.viewer.key !== viewerKey || !await checkedMembers(s.workspace, s.members, s.observed_at) || !Array.isArray(s.invitations) || s.invitations.length > 40 || !Array.isArray(s.assignments) || s.assignments.length > 100 || !Array.isArray(s.mandates) || s.mandates.length > 40 || !Array.isArray(s.drafts) || s.drafts.length > 100) return false;
    const viewer = s.members.find((m) => m.current_key === s.viewer.key);
    if (!obj2(s.viewer) || !exact3(s.viewer, ["key", "member_id", "role", "capabilities"]) || !viewer || viewer.status !== "active" || s.viewer.member_id !== viewer.member_id || s.viewer.role !== viewer.role || canonical(s.viewer.capabilities) !== canonical(viewer.role === "owner" ? ["read", "invite", "assign", "prepare_mandate", "review_draft", "recover"] : viewer.role === "reviewer" ? ["read", "review", "adopt_mandate", "recover"] : ["read", "recover"])) return false;
    const owner = s.members.find((m) => m.member_id === s.workspace.payload.owner_member_id);
    for (const i of s.invitations) if (!cleanEnvelope(i) || !validWorkspaceInvitation(i.payload) || i.payload.workspace_id !== s.workspace.payload.id || i.payload.workspace_digest !== s.workspace.digest || !ownerKeyAt(owner, i.payload.issuer_key, i.payload.issued_at, s.workspace.payload) || !before(i.payload.issued_at, s.observed_at) || !await verify(i, i.payload.issuer_key)) return false;
    for (const a of s.assignments) {
      const p = a.payload, o = s.members.find((m) => m.member_id === p.owner_member_id), r = s.members.find((m) => m.member_id === p.reviewer_member_id);
      if (!cleanEnvelope(a) || !validWorkspaceTaskAssignment(p) || !o || !r || p.workspace_id !== s.workspace.payload.id || p.workspace_digest !== s.workspace.digest || p.owner_key !== memberRevisionAt(o, p.owner_member_revision, p.issued_at, s.workspace.payload)?.key || p.reviewer_key !== memberRevisionAt(r, p.reviewer_member_revision, p.issued_at, s.workspace.payload)?.key || memberRevisionAt(o, p.owner_member_revision, p.issued_at, s.workspace.payload)?.role !== "owner" || memberRevisionAt(o, p.owner_member_revision, p.issued_at, s.workspace.payload)?.status !== "active" || memberRevisionAt(r, p.reviewer_member_revision, p.issued_at, s.workspace.payload)?.role !== "reviewer" || memberRevisionAt(r, p.reviewer_member_revision, p.issued_at, s.workspace.payload)?.status !== "active" || !before(p.issued_at, s.observed_at) || !await verify(a, p.owner_key)) return false;
    }
    for (const m of s.mandates) if (!await checkedMandate(m, s.workspace, s.members, s.observed_at)) return false;
    for (const d of s.drafts) if (!await checkedDraft(d, s.workspace, s.members, s.mandates, s.observed_at)) return false;
    return true;
  } catch {
    return false;
  }
}
var obj2, exact3, text3, key2, id3, at2, period2, repo, paths, checks, revision, cleanEnvelope, before;
var init_coordination_repository_workspace = __esm({
  "src/coordination-repository-workspace.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_review();
    obj2 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    exact3 = (v, req, opt = []) => req.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => req.includes(k) || opt.includes(k));
    text3 = (v, max) => typeof v === "string" && v.trim().length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
    key2 = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
    id3 = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
    at2 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
    period2 = (v, max) => at2(v.issued_at) && at2(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= max;
    repo = (v) => typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v);
    paths = (v) => Array.isArray(v) && v.length > 0 && v.length <= 12 && new Set(v).size === v.length && v.every((p) => typeof p === "string" && repositoryPath(p.endsWith("/**") ? p.slice(0, -3) : p) && pathAllowed(p.endsWith("/**") ? p.slice(0, -2) + "placeholder" : p, [p]));
    checks = (v) => Array.isArray(v) && v.length > 0 && v.length <= 12 && v.every((c) => obj2(c) && exact3(c, ["name", "app_id"]) && text3(c.name, 100) && Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0) && new Set(v.map((c) => c.name)).size === v.length;
    revision = (v) => Number.isSafeInteger(v) && Number(v) > 0;
    cleanEnvelope = (v) => obj2(v) && exact3(v, ["payload", "signer", "digest", "signature"]);
    before = (time4, observation) => Date.parse(time4) <= Date.parse(observation);
  }
});

// src/coordination-repository-coding.ts
function codingSafePath(path) {
  return typeof path === "string" && repositoryPath(path) && !path.toLowerCase().split("/").some((p) => p === "node_modules" || p === ".git" || p === ".github" || p === ".env" || p.startsWith(".env.") || p === ".npmrc" || p === ".yarnrc" || p === ".netrc") && !/\.(pem|key|p12|pfx)$/i.test(path);
}
function codingCommand(v) {
  return Array.isArray(v) && v.length >= 2 && v.length <= 8 && v[0] === "node" && v.slice(1).every((x) => typeof x === "string" && x.length <= 200) && (v[1] === "--test" && v.length >= 3 && v.slice(2).every(codingSafePath) || v.length === 2 && codingSafePath(v[1]));
}
function validRepositoryCodingSource(v) {
  return object3(v) && exact4(v, ["task_id", "task_digest", "basis_digest", "packet_digest", "feedback_digest"]) && id4(v.task_id) && [v.task_digest, v.basis_digest, v.packet_digest, v.feedback_digest].every(key3);
}
function validRepositoryCodingMandate(v) {
  if (!object3(v) || !exact4(v, ["type", "id", "workspace_id", "workspace_digest", "mode", "owner_member_id", "owner_key", "owner_member_revision", "reviewer_member_id", "reviewer_key", "reviewer_member_revision", "worker_key", "repository", "base_branch", "allowed_paths", "required_checks", "runtime", "docker_image", "test_command", "build_command", "preview_directory", "max_jobs", "max_attempts", "max_model_calls", "max_tokens", "max_seconds", "max_changed_files", "max_changed_bytes", "permissions", "issued_at", "expires_at"])) return false;
  return v.type === "scopeblind.repository.coding-mandate.v1" && v.mode === "edit_code" && [v.id, v.workspace_id, v.owner_member_id, v.reviewer_member_id].every(id4) && [v.workspace_digest, v.owner_key, v.reviewer_key, v.worker_key].every(key3) && (/* @__PURE__ */ new Set([v.owner_key, v.reviewer_key, v.worker_key])).size === 3 && v.owner_member_id !== v.reviewer_member_id && number(v.owner_member_revision, 1, 1e3) && number(v.reviewer_member_revision, 1, 1e3) && typeof v.repository === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v.repository) && repositoryBranch(v.base_branch) && Array.isArray(v.allowed_paths) && v.allowed_paths.length > 0 && v.allowed_paths.length <= 12 && new Set(v.allowed_paths).size === v.allowed_paths.length && v.allowed_paths.every((p) => typeof p === "string" && codingSafePath(p.endsWith("/**") ? p.slice(0, -3) : p)) && Array.isArray(v.required_checks) && v.required_checks.length > 0 && v.required_checks.length <= 12 && new Set(v.required_checks.map((c) => object3(c) ? c.name : null)).size === v.required_checks.length && v.required_checks.every((c) => object3(c) && exact4(c, ["name", "app_id"]) && typeof c.name === "string" && c.name.length > 0 && c.name.length <= 100 && number(c.app_id, 1, Number.MAX_SAFE_INTEGER)) && v.runtime === "node22-static-v1" && typeof v.docker_image === "string" && /^node@sha256:[a-f0-9]{64}$/.test(v.docker_image) && codingCommand(v.test_command) && codingCommand(v.build_command) && codingSafePath(v.preview_directory) && !pathAllowed(v.preview_directory, v.allowed_paths) && v.allowed_paths.every((p) => p !== v.preview_directory && !p.startsWith(String(v.preview_directory) + "/")) && v.test_command.slice(1).filter((p) => !p.startsWith("--")).every((p) => !pathAllowed(p, v.allowed_paths)) && v.build_command.slice(1).every((p) => !pathAllowed(p, v.allowed_paths)) && number(v.max_jobs, 1, 3) && number(v.max_attempts, 1, 2) && number(v.max_model_calls, 1, 12) && number(v.max_tokens, 4096, 524288) && number(v.max_seconds, 60, 900) && number(v.max_changed_files, 1, 20) && number(v.max_changed_bytes, 1, 262144) && JSON.stringify(v.permissions) === JSON.stringify(CODING_PERMISSIONS) && at3(v.issued_at) && at3(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 864e5;
}
function validRepositoryCodingRequest(v) {
  return object3(v) && exact4(v, ["type", "id", "workspace_id", "mandate_digest", "source", "owner_key", "issued_at"]) && v.type === "scopeblind.repository.coding-request.v1" && [v.id, v.workspace_id].every(id4) && [v.mandate_digest, v.owner_key].every(key3) && validRepositoryCodingSource(v.source) && at3(v.issued_at);
}
function validRepositoryCodingStop(v) {
  return object3(v) && exact4(v, ["type", "id", "workspace_id", "mandate_digest", "principal_key", "issued_at"], ["job_id"]) && v.type === "scopeblind.repository.coding-stop.v1" && [v.id, v.workspace_id].every(id4) && [v.mandate_digest, v.principal_key].every(key3) && (v.job_id === void 0 || id4(v.job_id)) && at3(v.issued_at);
}
function validRepositoryCodingPlan(v, m) {
  return object3(v) && exact4(v, ["type", "job_id", "request_digest", "mandate_digest", "source_head_sha", "source_base_sha", "branch", "commit_sha", "tree_sha", "files", "tests", "build", "preview_digest", "model_calls", "reserved_tokens", "issued_at"]) && v.type === "scopeblind.repository.coding-plan.v1" && id4(v.job_id) && [v.request_digest, v.mandate_digest, v.preview_digest].every(key3) && [v.source_head_sha, v.source_base_sha, v.commit_sha, v.tree_sha].every(hex40) && v.branch === "scopeblind/code/" + v.job_id && Array.isArray(v.files) && v.files.length > 0 && v.files.length <= m.max_changed_files && new Set(v.files.map((f) => object3(f) ? f.path : null)).size === v.files.length && v.files.every((f) => object3(f) && exact4(f, ["path", "before_sha", "after_sha", "bytes"]) && codingSafePath(f.path) && pathAllowed(f.path, m.allowed_paths) && (f.before_sha === null || hex40(f.before_sha)) && (f.after_sha === null || hex40(f.after_sha)) && f.before_sha !== f.after_sha && number(f.bytes, 0, m.max_changed_bytes)) && v.files.reduce((n, f) => n + Number(f.bytes), 0) <= m.max_changed_bytes && [v.tests, v.build].every((t) => object3(t) && exact4(t, ["command_digest", "exit_code", "output_sha256", "duration_ms"]) && key3(t.command_digest) && key3(t.output_sha256) && t.exit_code === 0 && number(t.duration_ms, 0, m.max_seconds * 1e3)) && number(v.model_calls, 1, m.max_model_calls) && number(v.reserved_tokens, 4096, m.max_tokens) && at3(v.issued_at);
}
function validRepositoryCodingResult(v) {
  return object3(v) && exact4(v, ["type", "job_id", "plan_digest", "publication_digest", "repository", "branch", "head_sha", "pull_number", "pull_url", "preview_url", "preview_digest", "deployment_id", "deployment_status_id", "deployment_environment", "check", "observed_at"]) && v.type === "scopeblind.repository.coding-result.v1" && id4(v.job_id) && [v.plan_digest, v.publication_digest, v.preview_digest].every(key3) && hex40(v.head_sha) && typeof v.repository === "string" && typeof v.branch === "string" && number(v.pull_number, 1, Number.MAX_SAFE_INTEGER) && v.pull_url === `https://github.com/${v.repository}/pull/${v.pull_number}` && typeof v.preview_url === "string" && v.preview_url.startsWith("https://") && number(v.deployment_id, 1, Number.MAX_SAFE_INTEGER) && number(v.deployment_status_id, 1, Number.MAX_SAFE_INTEGER) && v.deployment_environment === "ScopeBlind coding preview" && object3(v.check) && exact4(v.check, ["id", "name", "app_id", "head_sha", "conclusion"]) && number(v.check.id, 1, Number.MAX_SAFE_INTEGER) && v.check.name === "ScopeBlind isolated coding checks" && v.check.app_id === 15368 && v.check.head_sha === v.head_sha && v.check.conclusion === "success" && at3(v.observed_at);
}
var CODING_PERMISSIONS, object3, exact4, key3, id4, number, at3, hex40;
var init_coordination_repository_coding = __esm({
  "src/coordination-repository-coding.ts"() {
    "use strict";
    init_coordination_repository();
    init_coordination_repository_workspace();
    CODING_PERMISSIONS = ["read_source", "edit_code", "run_tests", "open_pull_request", "publish_preview"];
    object3 = (x) => !!x && typeof x === "object" && !Array.isArray(x);
    exact4 = (v, required, optional = []) => required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
    key3 = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
    id4 = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
    number = (v, min, max) => Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max;
    at3 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
    hex40 = (v) => typeof v === "string" && REPOSITORY_SHA.test(v);
  }
});

// src/coordination-repository-coding-evidence.ts
async function verifyRepositoryCodingEvidence(value, authorityKey) {
  const errors = [];
  let published = false;
  function check(ok, message) {
    if (!ok) throw Error(message);
  }
  try {
    check(object4(value) && shape2(value, ["type", "job"]) && value.type === "scopeblind.repository.coding-evidence.v1", "Unrecognized coding evidence");
    const e = value, j = e.job?.payload, m = j?.mandate?.payload, r = j?.request?.payload;
    check(validRepositoryEnvelope(e.job) && object4(j) && shape2(j, ["type", "request", "mandate", "adoption", "workspace", "parent", "status", "attempts", "model_calls", "reserved_tokens", "lease_id", "lease_expires_at", "started_at", "plan", "publication", "result", "stop", "error", "observed_at"]) && j.type === "scopeblind.repository.coding-job.v1" && status.includes(j.status) && at4(j.observed_at), "Invalid coding state");
    const key4 = authorityKey || j.workspace?.signer;
    check(await verify(e.job, key4), "Coding service signature invalid");
    check(await verifyRepositoryWorkspaceState(j.workspace, key4), "Coding workspace proof invalid");
    const w = j.workspace.payload.workspace.payload;
    check(validRepositoryEnvelope(j.mandate) && validRepositoryCodingMandate(m) && await verify(j.mandate, m.owner_key) && validRepositoryEnvelope(j.adoption) && j.adoption.digest === j.mandate.digest && canonical(j.adoption.payload) === canonical(m) && await verify(j.adoption, m.reviewer_key), "Separate dual-signed code-edit authority required");
    check(m.workspace_id === w.id && m.workspace_digest === j.workspace.payload.workspace.digest && m.repository === w.repository && m.base_branch === w.base_branch && m.worker_key !== key4 && m.worker_key !== w.receiver_key, "Coding project scope mismatch");
    for (const [id7, k, revision2, role] of [[m.owner_member_id, m.owner_key, m.owner_member_revision, "owner"], [m.reviewer_member_id, m.reviewer_key, m.reviewer_member_revision, "reviewer"]]) {
      const member = j.workspace.payload.members.find((x) => x.member_id === id7);
      check(member && member.current_key === k && member.revision === revision2 && member.status === "active" && member.role === role, "Coding member revision mismatch");
    }
    check(validRepositoryEnvelope(j.request) && validRepositoryCodingRequest(r) && await verify(j.request, m.owner_key) && r.owner_key === m.owner_key && r.workspace_id === m.workspace_id && r.mandate_digest === j.mandate.digest && before2(m.issued_at, r.issued_at) && before2(r.issued_at, m.expires_at) && before2(r.issued_at, j.observed_at) && before2(r.issued_at, j.workspace.payload.observed_at) && before2(j.workspace.payload.observed_at, j.observed_at), "Coding request authority mismatch");
    check(!j.parent.origin && !j.parent.coding_origin && (await verifyRepositoryReviewEvidence(j.parent, key4)).valid, "Invalid frozen coding source");
    const core = j.parent.repository.type === "scopeblind.repository.evidence.v1" ? j.parent.repository.state : j.parent.repository.repository.state, source = r.source, feedback = j.parent.review.payload.feedback.find((f) => f.digest === source.feedback_digest);
    check(core.payload.task.digest === source.task_digest && core.payload.task.payload.id === source.task_id && core.payload.task.payload.repository === m.repository && core.payload.task.payload.base_branch === m.base_branch && feedback && feedback.payload.basis_digest === source.basis_digest && feedback.payload.packet_digest === source.packet_digest && before2(feedback.payload.issued_at, r.issued_at) && core.payload.proposal, "Coding source feedback mismatch");
    check(Number.isSafeInteger(j.attempts) && j.attempts >= 0 && j.attempts <= m.max_attempts && Number.isSafeInteger(j.model_calls) && j.model_calls >= 0 && j.model_calls <= m.max_model_calls && Number.isSafeInteger(j.reserved_tokens) && j.reserved_tokens >= 0 && j.reserved_tokens <= m.max_tokens, "Coding work limits exceeded");
    check((j.started_at === null || at4(j.started_at) && before2(r.issued_at, j.started_at) && before2(j.started_at, j.observed_at)) && (j.lease_id === null ? j.lease_expires_at === null : typeof j.lease_id === "string" && at4(j.lease_expires_at)) && (j.error === null || typeof j.error === "string" && /^[a-z0-9_]{3,80}$/.test(j.error)), "Invalid coding lifecycle");
    if (j.stop) {
      check(validRepositoryEnvelope(j.stop) && validRepositoryCodingStop(j.stop.payload) && [m.owner_key, m.reviewer_key].includes(j.stop.payload.principal_key) && await verify(j.stop, j.stop.payload.principal_key) && j.stop.payload.job_id === r.id && j.stop.payload.mandate_digest === j.mandate.digest && j.stop.payload.workspace_id === m.workspace_id && before2(j.stop.payload.issued_at, j.observed_at), "Invalid coding cancellation");
    }
    if (j.plan) {
      const p = j.plan.payload;
      check(validRepositoryEnvelope(j.plan) && validRepositoryCodingPlan(p, m) && await verify(j.plan, m.worker_key) && p.job_id === r.id && p.request_digest === j.request.digest && p.mandate_digest === j.mandate.digest && p.source_head_sha === core.payload.proposal.payload.head_sha && p.source_base_sha === core.payload.proposal.payload.base_sha && p.tests.command_digest === await sha256(canonical(m.test_command)) && p.build.command_digest === await sha256(canonical(m.build_command)) && p.model_calls === j.model_calls && p.reserved_tokens === j.reserved_tokens && before2(p.issued_at, j.observed_at), "Coding plan scope or tests invalid");
    }
    if (j.publication) {
      const p = j.publication.payload;
      check(j.plan && validRepositoryEnvelope(j.publication) && object4(p) && shape2(p, ["type", "job_id", "plan_digest", "mandate_digest", "request_digest", "worker_key", "lease_id", "issued_at", "expires_at"]) && p.type === "scopeblind.repository.coding-publication.v1" && await verify(j.publication, key4) && p.job_id === r.id && p.plan_digest === j.plan.digest && p.mandate_digest === j.mandate.digest && p.request_digest === j.request.digest && p.worker_key === m.worker_key && at4(p.issued_at) && at4(p.expires_at) && before2(j.plan.payload.issued_at, p.issued_at) && Date.parse(p.expires_at) > Date.parse(p.issued_at) && Date.parse(p.expires_at) - Date.parse(p.issued_at) <= 12e4 && before2(p.expires_at, m.expires_at) && before2(p.issued_at, j.observed_at), "Invalid exact publication gate");
    }
    if (j.result) {
      const result = j.result.payload;
      check(j.plan && j.publication && validRepositoryEnvelope(j.result) && validRepositoryCodingResult(result) && result.type === "scopeblind.repository.coding-result.v1" && await verify(j.result, m.worker_key) && result.job_id === r.id && result.plan_digest === j.plan.digest && result.publication_digest === j.publication.digest && result.repository === m.repository && result.branch === j.plan.payload.branch && result.head_sha === j.plan.payload.commit_sha && Number.isSafeInteger(result.pull_number) && result.pull_number > 0 && result.pull_url === `https://github.com/${m.repository}/pull/${result.pull_number}` && result.preview_digest === j.plan.payload.preview_digest && Number.isSafeInteger(result.deployment_id) && result.deployment_id > 0 && Number.isSafeInteger(result.deployment_status_id) && result.deployment_status_id > 0 && at4(result.observed_at) && before2(j.publication.payload.issued_at, result.observed_at) && before2(result.observed_at, j.observed_at), "Invalid coding publication readback");
      const u = new URL(result.preview_url);
      check(u.protocol === "https:" && !u.username && !u.password && !u.search && !u.hash && u.pathname === `/v1/${r.id}/${result.head_sha}/${result.preview_digest}/index.html`, "Preview must identify the immutable content");
      published = true;
    }
    check(j.status === "pr_ready" === !!j.result && (!j.publication || j.plan) && (!["publishing", "unknown"].includes(j.status) || !!j.publication), "Contradictory coding status");
  } catch (error) {
    errors.push(error instanceof Error ? error.message : "Malformed coding evidence");
  }
  return { valid: errors.length === 0, errors, published: errors.length === 0 && published, authorityPinned: !!authorityKey, limitations: ["Code-edit authority permits only bounded work and a new pull request; no merge or recipient acceptance is inherited.", "The service attests live membership, revocation, spending reservations and the publication gate. The worker attests model work, isolated test results and GitHub readbacks.", "A content-addressed preview identifies the published bundle; verification does not execute it or prove that the code satisfies the brief."] };
}
var object4, shape2, at4, before2, status;
var init_coordination_repository_coding_evidence = __esm({
  "src/coordination-repository-coding-evidence.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_workspace();
    init_coordination_repository_review_evidence();
    init_coordination_repository_coding();
    object4 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    shape2 = (v, keys) => Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
    at4 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
    before2 = (a, b) => Date.parse(a) <= Date.parse(b);
    status = ["queued", "running", "testing", "publishing", "pr_ready", "failed", "cancelled", "unknown", "expired"];
  }
});

// src/coordination-repository-collaboration.ts
function validContactPage(value) {
  return shape3(value, ["type", "button_label", "target", "accent"]) && value.type === "scopeblind.contact-page.v1" && text4(value.button_label, 40) && ["broken", "contact"].includes(String(value.target)) && ["indigo", "emerald", "rose"].includes(String(value.accent));
}
function contactPageBytes(value) {
  if (!validContactPage(value))
    throw new Error("invalid_contact_page");
  return canonical(value) + "\n";
}
function validRepositoryConnection(v) {
  if (!shape3(v, ["type", "id", "endpoint", "repository", "base_branch", "owner_key", "receiver_key", "authority_key", "issued_at", "expires_at"]))
    return false;
  let endpoint2;
  try {
    endpoint2 = new URL(String(v.endpoint));
  } catch {
    return false;
  }
  return v.type === "scopeblind.repository.connection.v1" && id5(v.id) && endpoint2.protocol === "https:" && endpoint2.pathname === "/api/coordination" && !endpoint2.search && !endpoint2.hash && !endpoint2.username && !endpoint2.password && endpoint2.href === v.endpoint && repository(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(hex2) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.authority_key])).size === 3 && span2(v.issued_at, v.expires_at, 30 * 864e5);
}
function validRepositoryReadiness(v) {
  if (!shape3(v, ["type", "connection_digest", "repository", "base_branch", "owner_key", "receiver_key", "authority_key", "checks", "base_sha", "check_head_sha", "protection", "runtime", "workflow", "observed_at", "expires_at"], ["required_checks", "workflow_sha"]))
    return false;
  return v.type === "scopeblind.repository.readiness.v1" && hex2(v.connection_digest) && repository(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(hex2) && sha2(v.base_sha) && sha2(v.check_head_sha) && ["observed", "unavailable"].includes(String(v.protection)) && ["local", "github_actions"].includes(String(v.runtime)) && ["not_checked", "missing", "matching", "different", "unavailable"].includes(String(v.workflow)) && (v.workflow_sha === void 0 || sha2(v.workflow_sha)) && span2(v.observed_at, v.expires_at, 864e5) && Array.isArray(v.checks) && v.checks.length <= 100 && v.checks.every((c) => shape3(c, ["name", "app_id"], ["app_name"]) && text4(c.name, 100) && Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0 && (c.app_name === void 0 || text4(c.app_name, 100))) && (v.required_checks === void 0 || Array.isArray(v.required_checks) && v.required_checks.length <= 100 && v.required_checks.every((c) => shape3(c, ["name", "app_id"]) && text4(c.name, 100) && (c.app_id === null || Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0)));
}
function validRepositoryParticipants(v) {
  return shape3(v, ["type", "task_id", "task_digest", "owner_key", "receiver_key", "reviewer_key", "reviewer_claim_digest", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.participants.v1" && id5(v.task_id) && [v.task_digest, v.owner_key, v.receiver_key, v.reviewer_key, v.reviewer_claim_digest].every(hex2) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.reviewer_key])).size === 3 && span2(v.issued_at, v.expires_at, 7 * 864e5);
}
function validRepositoryPreview(v) {
  return shape3(v, ["type", "task_id", "task_digest", "proposal_digest", "base_sha", "head_sha", "merge_sha", "tree_sha", "path", "before", "after", "renderer", "observed_at"]) && v.type === "scopeblind.repository.preview.v1" && id5(v.task_id) && hex2(v.task_digest) && hex2(v.proposal_digest) && [v.base_sha, v.head_sha, v.merge_sha, v.tree_sha].every(sha2) && v.path === CONTACT_PATH && v.renderer === "scopeblind.contact-page.v1" && at5(v.observed_at) && [v.before, v.after].every((side) => shape3(side, ["model", "blob_sha", "content_sha256"]) && validContactPage(side.model) && sha2(side.blob_sha) && hex2(side.content_sha256));
}
function validRepositoryAgentGrant(v) {
  return shape3(v, ["type", "id", "task_id", "task_digest", "issuer_key", "agent_key", "permissions", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.agent-grant.v1" && id5(v.id) && id5(v.task_id) && [v.task_digest, v.issuer_key, v.agent_key].every(hex2) && v.issuer_key !== v.agent_key && Array.isArray(v.permissions) && v.permissions.length > 0 && v.permissions.length <= 2 && new Set(v.permissions).size === v.permissions.length && v.permissions.every((p) => p === "read_task" || p === "request_revision") && v.permissions.includes("read_task") && span2(v.issued_at, v.expires_at, 36e5);
}
function validRepositoryRevisionRequest(v) {
  return shape3(v, ["type", "id", "task_id", "task_digest", "basis_digest", "requester_key", "message", "proposed", "issued_at"], ["grant_digest"]) && v.type === "scopeblind.repository.revision-request.v1" && id5(v.id) && id5(v.task_id) && [v.task_digest, v.basis_digest, v.requester_key].every(hex2) && (v.grant_digest === void 0 || hex2(v.grant_digest)) && text4(v.message, 600) && validContactPage(v.proposed) && at5(v.issued_at);
}
function validRepositoryRevisionLink(v) {
  return shape3(v, ["type", "id", "parent_task_id", "parent_task_digest", "parent_basis_digest", "request_digest", "child_task_id", "child_task_digest", "owner_key", "issued_at"]) && v.type === "scopeblind.repository.revision-link.v1" && [v.id, v.parent_task_id, v.child_task_id].every(id5) && v.parent_task_id !== v.child_task_id && [v.parent_task_digest, v.parent_basis_digest, v.request_digest, v.child_task_digest, v.owner_key].every(hex2) && at5(v.issued_at);
}
function validRepositoryDemoRequest(v) {
  if (!shape3(v, ["type", "id", "owner_key", "receiver_key", "authority_key", "title", "goal", "proposed", "reviewer_secret_hash", "issued_at", "expires_at"], ["parent_task_id", "parent_task_digest", "parent_basis_digest", "revision_request_digest"]))
    return false;
  const parent = ["parent_task_id", "parent_task_digest", "parent_basis_digest", "revision_request_digest"];
  return v.type === "scopeblind.repository.demo-request.v1" && id5(v.id) && [v.owner_key, v.receiver_key, v.authority_key, v.reviewer_secret_hash].every(hex2) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.authority_key])).size === 3 && text4(v.title, 140) && text4(v.goal, 600) && validContactPage(v.proposed) && span2(v.issued_at, v.expires_at, 864e5) && (parent.every((k) => v[k] === void 0) || id5(v.parent_task_id) && [v.parent_task_digest, v.parent_basis_digest, v.revision_request_digest].every(hex2));
}
function validRepositoryDemoProvision(v) {
  return shape3(v, ["type", "request_id", "request_digest", "repository", "base_branch", "head_branch", "pull_number", "initial_base_sha", "initial_head_sha", "receiver_key", "required_checks", "observed_at"]) && v.type === "scopeblind.repository.demo-provision.v1" && id5(v.request_id) && [v.request_digest, v.receiver_key].every(hex2) && v.repository === DEMO_REPOSITORY && v.base_branch === `scopeblind/demo/${v.request_id}/base` && v.head_branch === `scopeblind/demo/${v.request_id}/change` && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && sha2(v.initial_base_sha) && sha2(v.initial_head_sha) && Array.isArray(v.required_checks) && canonical(v.required_checks) === canonical([DEMO_CHECK]) && at5(v.observed_at);
}
function repositoryRevisionBasis(state) {
  return state.acceptance?.digest ?? state.outcome?.digest ?? state.proposal?.digest ?? null;
}
var DEMO_REPOSITORY, DEMO_CHECK, CONTACT_PATH, object5, shape3, text4, hex2, id5, sha2, at5, span2, repository;
var init_coordination_repository_collaboration = __esm({
  "src/coordination-repository-collaboration.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    DEMO_REPOSITORY = "ScopeBlind/scopeblind-repository-demo";
    DEMO_CHECK = { name: "ScopeBlind contact validation", app_id: 4962726 };
    CONTACT_PATH = "demo/contact.json";
    object5 = (value) => !!value && typeof value === "object" && !Array.isArray(value);
    shape3 = (value, required, optional = []) => object5(value) && required.every((key4) => key4 in value) && Object.keys(value).every((key4) => required.includes(key4) || optional.includes(key4));
    text4 = (value, max, empty = false) => typeof value === "string" && (empty || value.trim().length > 0) && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
    hex2 = (value) => typeof value === "string" && REPOSITORY_HEX.test(value);
    id5 = (value) => typeof value === "string" && REPOSITORY_ID.test(value);
    sha2 = (value) => typeof value === "string" && REPOSITORY_SHA.test(value);
    at5 = (value) => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
    span2 = (issued, expires, max) => at5(issued) && at5(expires) && Date.parse(String(expires)) > Date.parse(String(issued)) && Date.parse(String(expires)) - Date.parse(String(issued)) <= max;
    repository = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value);
  }
});

// src/coordination-repository-collaboration-evidence.ts
function requireValid(condition, message) {
  if (!condition) throw new Error(message);
}
async function verifyRepositoryCollaborationEvidence(input, pins) {
  const result = { valid: false, accepted: false, authorityPinned: false, previewVerified: false, revisionLinked: false, errors: [], limitations: [...baseLimitations] };
  try {
    requireValid(shape4(input, ["type", "repository", "collaboration"], ["demo", "parent", "parent_request", "parent_agent_grant"]) && input.type === "scopeblind.repository.collaboration-evidence.v1", "Unsupported collaboration evidence shape.");
    const bundle = input;
    const core = await verifyRepositoryEvidence(bundle.repository, pins);
    result.limitations.push(...core.limitations);
    requireValid(core.valid, core.errors.join("; "));
    result.authorityPinned = core.authorityPinned;
    const state = bundle.repository.state.payload, task = state.task.payload, collaboration = bundle.collaboration, c = collaboration?.payload;
    requireValid(envelope(collaboration) && await verify(collaboration, task.authority_key) && shape4(c, ["type", "task_id", "task_digest", "participants", "preview", "requests", "revisions", "agent_grants", "observed_at"]) && c.type === "scopeblind.repository.collaboration.v1" && c.task_id === task.id && c.task_digest === state.task.digest && time3(c.observed_at), "Collaboration must be signed by this task\u2019s authority and name the exact task.");
    const principals = [task.owner_key, ...state.reviewer ? [state.reviewer.payload.reviewer_key] : []];
    if (c.participants !== null) {
      const signed = c.participants, p = signed?.payload;
      requireValid(envelope(signed) && validRepositoryParticipants(p) && await verify(signed, task.owner_key) && p.task_id === task.id && p.task_digest === state.task.digest && p.owner_key === task.owner_key && p.receiver_key === task.receiver_key && p.reviewer_key === state.reviewer?.payload.reviewer_key && p.reviewer_claim_digest === state.reviewer?.digest && within(p.issued_at, task.issued_at, task.expires_at) && Date.parse(p.expires_at) <= Date.parse(task.expires_at), "The owner\u2019s participant binding does not match this task and enrolled reviewer.");
    }
    if (c.preview !== null) {
      const signed = c.preview, p = signed?.payload, proposal = state.proposal;
      requireValid(envelope(signed) && validRepositoryPreview(p) && await verify(signed, task.receiver_key) && proposal && p.task_id === task.id && p.task_digest === state.task.digest && p.proposal_digest === proposal.digest && ["base_sha", "head_sha", "merge_sha", "tree_sha"].every((k) => p[k] === proposal.payload[k]) && proposal.payload.files.some((f) => f.path === CONTACT_PATH), "The preview is not bound to this exact receiver-reviewed proposal.");
      for (const side of [p.before, p.after]) {
        const bytes = new TextEncoder().encode(contactPageBytes(side.model)), header = new TextEncoder().encode(`blob ${bytes.length}\0`), blob = new Uint8Array(header.length + bytes.length);
        blob.set(header);
        blob.set(bytes, header.length);
        const gitSha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", blob)), (n) => n.toString(16).padStart(2, "0")).join("");
        requireValid(await sha256(contactPageBytes(side.model)) === side.content_sha256 && gitSha === side.blob_sha, "Preview content does not match its canonical bytes and Git blob digest.");
      }
      requireValid(Date.parse(p.observed_at) >= Date.parse(proposal.payload.observed_at) && Date.parse(p.observed_at) <= Date.parse(c.observed_at), "Preview timing does not follow the reviewed proposal.");
      result.previewVerified = true;
    }
    requireValid(Array.isArray(c.agent_grants) && c.agent_grants.length <= 100 && Array.isArray(c.requests) && c.requests.length <= 100 && Array.isArray(c.revisions) && c.revisions.length <= 100, "Collaboration collections exceed their supported bounds.");
    const incomingLinks = c.revisions.filter((link) => link?.payload?.child_task_id === task.id);
    requireValid(incomingLinks.length <= 1 && (incomingLinks.length === 1 || !["parent", "parent_request", "parent_agent_grant"].some((key4) => Object.hasOwn(bundle, key4))), "Predecessor records must be consumed by exactly one incoming revision link.");
    const grants = /* @__PURE__ */ new Map(), requestIds = /* @__PURE__ */ new Set(), requests = /* @__PURE__ */ new Map();
    for (const entry of c.agent_grants) {
      const signed = entry.grant, g = signed?.payload;
      requireValid(shape4(entry, ["grant", "revoked"]) && typeof entry.revoked === "boolean" && envelope(signed) && validRepositoryAgentGrant(g) && await verify(signed, g.issuer_key) && principals.includes(g.issuer_key) && ![...principals, task.receiver_key, task.authority_key].includes(g.agent_key) && g.task_id === task.id && g.task_digest === state.task.digest && within(g.issued_at, task.issued_at, task.expires_at) && Date.parse(g.issued_at) <= Date.parse(c.observed_at) && Date.parse(g.expires_at) <= Date.parse(task.expires_at) && !grants.has(signed.digest), "An agent grant is invalid, duplicated, or crosses a human/receiver boundary.");
      grants.set(signed.digest, entry);
    }
    for (const signed of c.requests) {
      const r = signed?.payload;
      requireValid(envelope(signed) && validRepositoryRevisionRequest(r) && await verify(signed, r.requester_key) && r.task_id === task.id && r.task_digest === state.task.digest && within(r.issued_at, task.issued_at, task.expires_at) && Date.parse(r.issued_at) <= Date.parse(c.observed_at) && !requestIds.has(r.id) && !requests.has(signed.digest), "A revision request is invalid or duplicated.");
      requestIds.add(r.id);
      requests.set(signed.digest, signed);
      if (principals.includes(r.requester_key)) requireValid(r.grant_digest === void 0, "A human revision must not borrow an agent grant.");
      else {
        const g = r.grant_digest ? grants.get(r.grant_digest)?.grant.payload : void 0;
        requireValid(g && g.agent_key === r.requester_key && g.permissions.includes("request_revision") && within(r.issued_at, g.issued_at, g.expires_at), "The suggesting agent did not hold the exact recorded revision scope.");
      }
    }
    let parent;
    if (bundle.parent) {
      const checked = await verifyRepositoryEvidence(bundle.parent, pins);
      requireValid(checked.valid, "The predecessor repository evidence does not verify.");
      parent = bundle.parent.state.payload;
      requireValid(parent.task.payload.owner_key === task.owner_key && parent.task.payload.receiver_key === task.receiver_key && parent.task.payload.authority_key === task.authority_key && parent.task.payload.repository === task.repository, "The predecessor crosses this repository or participant authority.");
    }
    const linkIds = /* @__PURE__ */ new Set();
    for (const signed of c.revisions) {
      const l = signed?.payload;
      requireValid(envelope(signed) && validRepositoryRevisionLink(l) && await verify(signed, task.owner_key) && l.owner_key === task.owner_key && time3(l.issued_at) && Date.parse(l.issued_at) <= Date.parse(c.observed_at) && !linkIds.has(l.id), "A revision link is invalid or duplicated.");
      linkIds.add(l.id);
      if (l.child_task_id === task.id) {
        requireValid(l.child_task_digest === state.task.digest && parent && l.parent_task_id === parent.task.payload.id && l.parent_task_digest === parent.task.digest && l.parent_basis_digest === repositoryRevisionBasis(parent), "The child revision does not bind the included predecessor and exact feedback.");
        const signedRequest = bundle.parent_request, r = signedRequest?.payload, pt = parent.task.payload;
        requireValid(envelope(signedRequest) && validRepositoryRevisionRequest(r) && await verify(signedRequest, r.requester_key) && signedRequest.digest === l.request_digest && r.task_id === pt.id && r.task_digest === parent.task.digest && r.basis_digest === l.parent_basis_digest && within(r.issued_at, pt.issued_at, pt.expires_at) && Date.parse(r.issued_at) <= Date.parse(l.issued_at), "The original signed feedback is missing or does not match this revision.");
        const parentPrincipals = [pt.owner_key, ...parent.reviewer ? [parent.reviewer.payload.reviewer_key] : []];
        if (parentPrincipals.includes(r.requester_key)) requireValid(r.grant_digest === void 0 && bundle.parent_agent_grant === void 0, "Human feedback must not borrow an agent grant.");
        else {
          const signedGrant = bundle.parent_agent_grant, g = signedGrant?.payload;
          requireValid(envelope(signedGrant) && validRepositoryAgentGrant(g) && await verify(signedGrant, g.issuer_key) && signedGrant.digest === r.grant_digest && parentPrincipals.includes(g.issuer_key) && ![...parentPrincipals, pt.receiver_key, pt.authority_key].includes(g.agent_key) && g.agent_key === r.requester_key && g.task_id === pt.id && g.task_digest === parent.task.digest && g.permissions.includes("request_revision") && within(g.issued_at, pt.issued_at, pt.expires_at) && Date.parse(g.expires_at) <= Date.parse(pt.expires_at) && within(r.issued_at, g.issued_at, g.expires_at), "The original feedback agent\u2019s exact human-signed scope is missing or invalid.");
        }
        result.revisionLinked = true;
      } else {
        requireValid(l.parent_task_id === task.id && l.parent_task_digest === state.task.digest && requests.has(l.request_digest) && requests.get(l.request_digest).payload.basis_digest === l.parent_basis_digest, "The outgoing revision link does not name this task and an included suggestion.");
      }
    }
    if (bundle.demo) {
      const signed = bundle.demo, d = signed?.payload, r = d?.request?.payload, p = d?.provision?.payload;
      requireValid(envelope(signed) && await verify(signed, task.authority_key) && shape4(d, ["type", "request", "provision", "task", "status", "dispatch", "error", "observed_at"]) && d.type === "scopeblind.repository.demo-state.v1" && ["queued", "provisioning", "ready_to_review", "active", "failed", "expired"].includes(d.status) && ["requested", "unconfigured", "unavailable"].includes(d.dispatch) && (d.error === null || typeof d.error === "string" && d.error.length <= 100) && time3(d.observed_at), "The demo\u2019s service record is invalid.");
      requireValid(envelope(d.request) && validRepositoryDemoRequest(r) && await verify(d.request, task.owner_key) && r.id === task.id && r.owner_key === task.owner_key && r.authority_key === task.authority_key && r.receiver_key === task.receiver_key && r.reviewer_secret_hash === task.reviewer_secret_hash && r.title === task.title && Date.parse(task.expires_at) <= Date.parse(r.expires_at), "The demo request is not the task owner\u2019s exact provisioning authority.");
      requireValid(d.task && canonical(d.task) === canonical(state.task) && envelope(d.provision) && validRepositoryDemoProvision(p) && await verify(d.provision, task.receiver_key) && p.request_id === task.id && p.request_digest === d.request.digest && p.repository === task.repository && p.base_branch === task.base_branch && p.pull_number === task.pull_number && p.receiver_key === task.receiver_key && canonical(p.required_checks) === canonical(task.required_checks) && canonical(task.allowed_paths) === canonical([CONTACT_PATH]), "The provisioned workspace does not match the signed task.");
      if (c.preview) requireValid(c.preview.payload.base_sha === p.initial_base_sha && c.preview.payload.head_sha === p.initial_head_sha && canonical(c.preview.payload.after.model) === canonical(r.proposed), "The demo preview differs from the exact requested and provisioned change.");
      if (r.parent_task_id) requireValid(result.revisionLinked && parent && r.parent_task_id === parent.task.payload.id && r.parent_task_digest === parent.task.digest && r.parent_basis_digest === repositoryRevisionBasis(parent) && canonical(bundle.parent_request?.payload.proposed) === canonical(r.proposed) && c.revisions.some((l) => l.payload.child_task_id === task.id && l.payload.request_digest === r.revision_request_digest), "The demo revision lacks its exact predecessor link.");
    }
    result.valid = true;
    result.accepted = core.accepted;
  } catch (error) {
    result.errors.push(error instanceof Error ? error.message : "The collaboration evidence could not be verified.");
    result.previewVerified = false;
    result.revisionLinked = false;
    result.accepted = false;
  }
  return result;
}
var shape4, envelope, time3, within, baseLimitations;
var init_coordination_repository_collaboration_evidence = __esm({
  "src/coordination-repository-collaboration-evidence.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_collaboration();
    shape4 = (v, required, optional = []) => !!v && typeof v === "object" && !Array.isArray(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
    envelope = (v) => shape4(v, ["payload", "signer", "digest", "signature"]);
    time3 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
    within = (at8, start, end) => Date.parse(at8) >= Date.parse(start) && Date.parse(at8) <= Date.parse(end);
    baseLimitations = [
      "A preview is the receiver\u2019s signed observation of canonical contact-page data, rendered by ScopeBlind\u2019s fixed template. It does not execute repository code or prove a deployed website.",
      "Agent grants allow only the recorded reading and revision suggestions. They do not convey human approval or receiver execution authority.",
      "Revocation flags and the completeness of the collaboration history are statements by the service. The included record does not prove a currently live grant."
    ];
  }
});

// src/coordination-repository-review-evidence.ts
function repositoryReviewCore(e) {
  return e.repository.type === "scopeblind.repository.evidence.v1" ? e.repository : e.repository.repository;
}
async function verifyRepositoryReviewEvidence(value, pins) {
  const errors = [], check = (condition, message) => {
    if (!condition) errors.push(message);
  };
  let codingOriginVerified = false, originVerified = false, accepted = false, packetVerified = false, decisionsVerified = false, previewAvailable = false, authorityPinned = false;
  try {
    const e = value;
    check((shape5(e, ["type", "repository", "review"]) || shape5(e, ["type", "repository", "review", "origin"]) || shape5(e, ["type", "repository", "review", "coding_origin"])) && e.type === "scopeblind.repository.review-evidence.v1", "Review evidence shape is invalid");
    const core = repositoryReviewCore(e), base = e.repository.type === "scopeblind.repository.evidence.v1" ? await verifyRepositoryEvidence(e.repository, pins) : await verifyRepositoryCollaborationEvidence(e.repository, pins), s = core.state.payload, r = e.review.payload, t = s.task.payload, key4 = typeof pins === "string" ? pins : pins?.authority_key ?? t.authority_key;
    check(base.valid, "Underlying repository evidence is invalid");
    accepted = base.accepted;
    authorityPinned = base.authorityPinned;
    check(validRepositoryEnvelope(e.review) && shape5(r, ["type", "task_id", "task_digest", "brief", "packet", "decisions", "feedback", "recommendations", "history", "agent_uses", "observed_at"], ["origin_digest", "coding_origin_digest"]) && r.type === "scopeblind.repository.review-state.v1" && r.task_id === t.id && r.task_digest === s.task.digest && at6(r.observed_at) && Date.parse(r.observed_at) >= Date.parse(s.observed_at) && await verify(e.review, key4), "Review service state is invalid");
    check(validRepositoryEnvelope(r.brief) && validRepositoryReviewBrief(r.brief.payload, t, s.task.digest) && Date.parse(r.brief.payload.issued_at) <= Date.parse(r.observed_at) && await verify(r.brief, t.owner_key), "Owner review brief is invalid");
    check(Array.isArray(r.decisions) && r.decisions.length <= 2 && new Set(r.decisions.map((d) => d.payload.role)).size === r.decisions.length && Array.isArray(r.feedback) && r.feedback.length <= 20 && new Set(r.feedback.map((f) => f.payload.id)).size === r.feedback.length && Array.isArray(r.recommendations) && r.recommendations.length <= 20 && new Set(r.recommendations.map((f) => f.payload.id)).size === r.recommendations.length && Array.isArray(r.history) && r.history.length <= 40 && new Set(r.history.map((h) => h.state.digest + ":" + h.packet.digest)).size === r.history.length, "Review record bounds are invalid");
    check(Array.isArray(r.agent_uses) && r.agent_uses.length <= 40 && new Set(r.agent_uses.map((u) => u.payload.record_digest)).size === r.agent_uses.length, "Agent-use record bounds are invalid");
    if (r.packet) {
      packetVerified = !!s.proposal && validRepositoryEnvelope(r.packet) && validRepositoryReviewPacket(r.packet.payload, r.brief, s.proposal) && Date.parse(r.packet.payload.observed_at) <= Date.parse(r.observed_at) && await verify(r.packet, t.receiver_key);
      check(packetVerified, "Receiver review packet is invalid");
      previewAvailable = packetVerified && r.packet.payload.preview.status === "available";
    } else check(!r.decisions.length && !s.execution, "Exact packet decisions require a current packet");
    for (const decision of r.decisions) {
      const a = s.approvals.find((a2) => a2.payload.role === decision.payload.role), principal = decision.payload.role === "owner" ? t.owner_key : s.reviewer?.payload.reviewer_key;
      check(a && r.packet && validRepositoryHumanEnvelope(decision) && validRepositoryReviewDecision(decision.payload, r.brief, r.packet, a) && decision.payload.principal_key === principal && await verifyRepositoryHuman(decision, principal, { authorityKey: key4, task: s.task, requireRecordedUse: true }) && Date.parse(decision.payload.issued_at) <= Date.parse(r.observed_at), "Exact packet decision is invalid");
    }
    check(r.decisions.length === s.approvals.length && s.approvals.every((a) => r.decisions.some((d) => d.payload.role === a.payload.role && d.payload.approval_digest === a.digest)), "Each ordinary approval requires its exact packet decision");
    decisionsVerified = packetVerified && r.decisions.length === 2 && s.approvals.length === 2 && s.approvals.every((a) => a.payload.decision === "approve");
    if (s.execution) check(decisionsVerified && r.packet && Date.parse(s.execution.payload.expires_at) <= Date.parse(r.packet.payload.expires_at), "Execution lacks both exact current packet decisions");
    const contexts = r.packet ? [{ state: core.state, packet: r.packet }] : [];
    for (const h of r.history) {
      check(shape5(h, ["state", "packet", "decisions"]) && (await verifyRepositoryEvidence({ type: "scopeblind.repository.evidence.v1", state: h.state }, pins ?? key4)).valid && h.state.payload.task.digest === s.task.digest && h.state.payload.reviewer?.digest === s.reviewer?.digest && Date.parse(h.state.payload.observed_at) <= Date.parse(r.observed_at) && h.state.payload.proposal && validRepositoryEnvelope(h.packet) && validRepositoryReviewPacket(h.packet.payload, r.brief, h.state.payload.proposal) && await verify(h.packet, t.receiver_key), "Historical review basis is invalid");
      contexts.push(h);
      check(Array.isArray(h.decisions) && h.decisions.length <= 2 && new Set(h.decisions.map((d) => d.payload.role)).size === h.decisions.length, "Historical packet decisions are invalid");
      for (const decision of h.decisions) {
        const approval = h.state.payload.approvals.find((a) => a.payload.role === decision.payload.role), principal = decision.payload.role === "owner" ? t.owner_key : s.reviewer?.payload.reviewer_key;
        check(approval && validRepositoryHumanEnvelope(decision) && validRepositoryReviewDecision(decision.payload, r.brief, h.packet, approval) && decision.payload.principal_key === principal && await verifyRepositoryHuman(decision, principal, { authorityKey: key4, task: s.task, requireRecordedUse: true }), "Historical exact packet decision is invalid");
      }
      check(h.decisions.length === h.state.payload.approvals.length && h.state.payload.approvals.every((a) => h.decisions.some((d) => d.payload.role === a.payload.role && d.payload.approval_digest === a.digest)), "Each historical approval requires its exact packet decision");
      if (h.state.payload.execution) check(h.decisions.length === 2 && Date.parse(h.state.payload.execution.payload.expires_at) <= Date.parse(h.packet.payload.expires_at), "Historical execution lacks both exact packet decisions");
      check(r.feedback.some((f) => f.payload.packet_digest === h.packet.digest && (f.payload.basis_digest === h.state.payload.proposal?.digest || f.payload.basis_digest === h.state.payload.outcome?.digest || f.payload.basis_digest === h.state.payload.acceptance?.digest)) || r.recommendations.some((a) => a.payload.packet_digest === h.packet.digest && a.payload.proposal_digest === h.state.payload.proposal?.digest), "Unreferenced review history is invalid");
    }
    const uses = /* @__PURE__ */ new Map();
    for (const use of r.agent_uses) {
      const u = use.payload, m = u.mandate?.payload, a = u.assignment?.payload, record = [...r.feedback, ...r.recommendations].find((x) => x.digest === u.record_digest), recordTime = record ? record.payload.issued_at ?? record.payload.observed_at : "";
      check(validRepositoryEnvelope(use) && shape5(u, ["type", "task_id", "task_digest", "record_digest", "permission", "mandate", "adoption", "assignment", "checked_at"]) && u.type === "scopeblind.repository.review-agent-use.v1" && u.task_id === t.id && u.task_digest === s.task.digest && await verify(use, key4) && record && at6(u.checked_at) && Date.parse(u.checked_at) <= Date.parse(r.observed_at) && Date.parse(u.checked_at) >= Date.parse(recordTime), "Agent-use service attestation is invalid");
      check(validRepositoryEnvelope(u.mandate) && validRepositoryEnvelope(u.adoption) && validWorkspacePreparationMandate(m) && m.owner_key === t.owner_key && m.reviewer_key === s.reviewer?.payload.reviewer_key && !["", t.owner_key, t.receiver_key, t.authority_key, s.reviewer?.payload.reviewer_key].includes(m.agent_key) && m.repository === t.repository && m.base_branch === t.base_branch && u.adoption.digest === u.mandate.digest && canonical(u.adoption.payload) === canonical(m) && await verify(u.mandate, t.owner_key) && await verify(u.adoption, m.reviewer_key) && m.permissions.includes(u.permission) && ["report_criteria", "request_revision"].includes(u.permission) && Date.parse(m.issued_at) <= Date.parse(recordTime) && Date.parse(m.expires_at) >= Date.parse(u.checked_at) && t.allowed_paths.every((p) => m.allowed_paths.includes(p) || m.allowed_paths.some((scope) => scope.endsWith("/**") && p.startsWith(scope.slice(0, -2)))) && m.required_checks.every((c) => t.required_checks.some((tc) => tc.name === c.name && tc.app_id === c.app_id)), "Dual-signed preparation mandate is invalid");
      check(validRepositoryEnvelope(u.assignment) && validWorkspaceTaskAssignment(a) && a.task_id === t.id && a.task_digest === s.task.digest && a.review_brief_digest === r.brief.digest && a.workspace_id === m.workspace_id && a.workspace_digest === m.workspace_digest && a.owner_key === t.owner_key && a.reviewer_key === s.reviewer?.payload.reviewer_key && a.owner_member_id === m.owner_member_id && a.reviewer_member_id === m.reviewer_member_id && a.owner_member_revision === m.owner_member_revision && a.reviewer_member_revision === m.reviewer_member_revision && Date.parse(a.issued_at) <= Date.parse(recordTime) && Date.parse(a.expires_at) >= Date.parse(u.checked_at) && await verify(u.assignment, t.owner_key), "Task assignment for the agent use is invalid");
      uses.set(u.record_digest, use);
    }
    for (const feedback of r.feedback) {
      const f = feedback.payload, c = contexts.find((c2) => c2.packet.digest === f.packet_digest && [c2.state.payload.proposal?.digest, c2.state.payload.outcome?.digest, c2.state.payload.acceptance?.digest].includes(f.basis_digest));
      check(c && validRepositoryHumanEnvelope(feedback) && validRepositoryReviewFeedback(f, r.brief, c.packet) && await verifyRepositoryHuman(feedback, f.requester_key, { authorityKey: key4, task: s.task, requireRecordedUse: true }) && Date.parse(f.issued_at) <= Date.parse(r.observed_at), "Review feedback is invalid");
      const use = uses.get(feedback.digest)?.payload;
      check(f.mandate_digest ? use && use.permission === "request_revision" && use.mandate.digest === f.mandate_digest && use.mandate.payload.agent_key === f.requester_key : !use && [t.owner_key, s.reviewer?.payload.reviewer_key].includes(f.requester_key), "Review feedback lacks independently verifiable human or scoped-agent authority");
    }
    for (const recommendation of r.recommendations) {
      const a = recommendation.payload, c = contexts.find((c2) => c2.packet.digest === a.packet_digest && c2.state.payload.proposal?.digest === a.proposal_digest);
      check(c && validRepositoryEnvelope(recommendation) && validRepositoryReviewRecommendation(a, r.brief, c.packet, c.state.payload.proposal) && await verify(recommendation, a.agent_key) && Date.parse(a.observed_at) <= Date.parse(r.observed_at), "Criterion recommendation is invalid");
      const use = uses.get(recommendation.digest)?.payload;
      check(use && use.permission === "report_criteria" && use.mandate.digest === a.mandate_digest && use.mandate.payload.agent_key === a.agent_key, "Recommendation lacks independently verifiable scoped-agent authority");
    }
    check(e.origin ? r.origin_digest === await sha256(canonical(e.origin)) : r.origin_digest === void 0, "Registered origin commitment is missing or mismatched");
    check(e.coding_origin ? r.coding_origin_digest === await sha256(canonical(e.coding_origin)) : r.coding_origin_digest === void 0, "Registered coding origin commitment is missing or mismatched");
    if (e.coding_origin) {
      const o = e.coding_origin, j = o.job?.job?.payload, a = o.assignment?.payload;
      check(!e.origin && shape5(o, ["job", "assignment"]) && (await verifyRepositoryCodingEvidence(o.job, key4)).published, "Coding origin is not a verified completed code job");
      check(j?.result && j.request.payload.source.task_id !== t.id && j.result.payload.repository === t.repository && j.result.payload.pull_number === t.pull_number && j.mandate.payload.base_branch === t.base_branch, "Coding result does not match the fresh review");
      check(validRepositoryEnvelope(o.assignment) && validWorkspaceTaskAssignment(a) && a.task_id === t.id && a.task_digest === s.task.digest && a.review_brief_digest === r.brief.digest && !a.source_draft_digest && a.workspace_id === j.mandate.payload.workspace_id && a.workspace_digest === j.mandate.payload.workspace_digest && a.owner_key === t.owner_key && (!s.reviewer || a.reviewer_key === s.reviewer.payload.reviewer_key) && Date.parse(a.issued_at) >= Date.parse(j.result.payload.observed_at) && Date.parse(a.issued_at) <= Date.parse(r.observed_at) && await verify(o.assignment, t.owner_key), "Coding result assignment is invalid");
      if (s.proposal) check(s.proposal.payload.head_sha === j.result.payload.head_sha, "Fresh review changed beyond the registered coding result");
      codingOriginVerified = true;
    }
    if (e.origin) {
      const o = e.origin;
      check(shape5(o, ["draft", "assignment", "parent_assignment", "parent", "preparation"]) && !Object.prototype.hasOwnProperty.call(o.parent, "origin") && shape5(o.preparation, ["mandate", "adoption"]), "Review origin shape or depth is invalid");
      if (!shape5(o.parent, ["type", "repository", "review"])) throw Error("Nested origin is forbidden");
      const parent = await verifyRepositoryReviewEvidence(o.parent, key4), ps = repositoryReviewCore(o.parent).state.payload, d = o.draft.payload, a = o.assignment.payload, m = o.preparation.mandate.payload, source = d.source;
      check(parent.valid && validRepositoryEnvelope(o.draft) && validWorkspaceReviewDraft(d) && source && d.repository === t.repository && d.pull_number === t.pull_number && d.workspace_id === a.workspace_id && d.mandate_digest === o.preparation.mandate.digest && d.agent_key === m.agent_key && await verify(o.draft, d.agent_key), "Incoming review draft is invalid");
      const pa = o.parent_assignment?.payload;
      check(validRepositoryEnvelope(o.parent_assignment) && validWorkspaceTaskAssignment(pa) && pa.task_id === ps.task.payload.id && pa.task_digest === ps.task.digest && pa.review_brief_digest === o.parent.review.payload.brief.digest && pa.workspace_id === a.workspace_id && pa.workspace_digest === a.workspace_digest && pa.owner_key === ps.task.payload.owner_key && pa.reviewer_key === ps.reviewer?.payload.reviewer_key && await verify(o.parent_assignment, ps.task.payload.owner_key), "Source task project assignment is invalid");
      const feedback = source ? o.parent.review.payload.feedback.find((f) => f.digest === source.feedback_digest) : void 0;
      check(source && ps.task.payload.id === source.task_id && ps.task.digest === source.task_digest && ps.task.payload.repository === t.repository && ps.task.payload.authority_key === t.authority_key && ps.task.payload.receiver_key === t.receiver_key && o.parent.review.payload.packet?.digest === source.packet_digest && feedback && feedback.payload.basis_digest === source.basis_digest && feedback.payload.packet_digest === source.packet_digest && Date.parse(feedback.payload.issued_at) <= Date.parse(d.issued_at) && Date.parse(ps.observed_at) <= Date.parse(d.issued_at) && o.parent.review.payload.feedback.length === 1 && o.parent.review.payload.recommendations.length === 0, "Incoming source feedback does not match the frozen parent");
      check(validRepositoryEnvelope(o.assignment) && validWorkspaceTaskAssignment(a) && a.task_id === t.id && a.task_digest === s.task.digest && a.review_brief_digest === r.brief.digest && a.source_draft_digest === o.draft.digest && a.owner_key === t.owner_key && a.reviewer_key === m.reviewer_key && (!s.reviewer || a.reviewer_key === s.reviewer.payload.reviewer_key) && a.workspace_id === m.workspace_id && a.workspace_digest === m.workspace_digest && a.owner_member_id === m.owner_member_id && a.reviewer_member_id === m.reviewer_member_id && a.owner_member_revision === m.owner_member_revision && a.reviewer_member_revision === m.reviewer_member_revision && Date.parse(a.issued_at) >= Date.parse(d.issued_at) && Date.parse(a.issued_at) <= Date.parse(r.observed_at) && await verify(o.assignment, t.owner_key), "Incoming task assignment is invalid");
      check(validRepositoryEnvelope(o.preparation.mandate) && validRepositoryEnvelope(o.preparation.adoption) && validWorkspacePreparationMandate(m) && m.owner_key === t.owner_key && m.repository === t.repository && m.base_branch === t.base_branch && m.permissions.includes("prepare_review") && ![t.owner_key, t.receiver_key, t.authority_key, m.reviewer_key].includes(d.agent_key) && canonical(o.preparation.adoption.payload) === canonical(m) && o.preparation.adoption.digest === o.preparation.mandate.digest && await verify(o.preparation.mandate, m.owner_key) && await verify(o.preparation.adoption, m.reviewer_key) && Date.parse(d.issued_at) >= Date.parse(m.issued_at) && Date.parse(d.issued_at) <= Date.parse(m.expires_at) && d.allowed_paths.every((p) => m.allowed_paths.includes(p) || m.allowed_paths.some((scope) => scope.endsWith("/**") && p.startsWith(scope.slice(0, -2)))) && m.required_checks.every((c) => d.required_checks.some((dc) => dc.name === c.name && dc.app_id === c.app_id)), "Incoming draft preparation authority is invalid");
      originVerified = true;
    }
  } catch {
    errors.push("Malformed review evidence");
  }
  return { valid: errors.length === 0, errors, originVerified: originVerified && errors.length === 0, codingOriginVerified: codingOriginVerified && errors.length === 0, accepted: accepted && errors.length === 0, authorityPinned: authorityPinned && errors.length === 0, packetVerified: packetVerified && errors.length === 0, previewAvailable: previewAvailable && errors.length === 0, decisionsVerified: decisionsVerified && errors.length === 0, limitations: ["A receiver signature records GitHub API metadata; it is not a GitHub-signed receipt.", "An external preview URL is mutable. Its observed commit association does not pin the bytes the browser later receives.", "An observed artifact digest does not prove that a preview URL serves that artifact.", "A pinned check provider identifies the check issuer, not necessarily the deployment publisher.", "Agent criterion assessments are recommendations, not independent proof, human review, or execution authority.", "The service attests that membership, revocation and counters were checked atomically when each recorded agent use was accepted. This is historical authority, not a current grant.", "This controls only the installed receiver. Other repository credentials and actions remain outside its coverage.", ...!pins ? ["No independent authority key was supplied. Only consistency with the included authority was checked."] : []] };
}
var shape5, at6;
var init_coordination_repository_review_evidence = __esm({
  "src/coordination-repository-review-evidence.ts"() {
    "use strict";
    init_coordination_repository_coding_evidence();
    init_coordination_repository_devices();
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_collaboration_evidence();
    init_coordination_repository_review();
    init_coordination_repository_workspace();
    shape5 = (v, keys, optional = []) => !!v && typeof v === "object" && !Array.isArray(v) && keys.every((k) => Object.prototype.hasOwnProperty.call(v, k)) && Object.keys(v).every((k) => keys.includes(k) || optional.includes(k));
    at6 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
  }
});

// src/repository-review-preview.ts
async function observeRepositoryReviewPreview(get, repository2, brief, proposal, now = Date.now()) {
  const policy = brief.payload.preview_policy;
  if (!policy) return { status: "not_requested", reason: "This brief does not require or identify a deployment preview." };
  const repo3 = `/repos/${repository2.split("/").map(encodeURIComponent).join("/")}`, head = proposal.payload.head_sha;
  try {
    const deployments = (await get(`${repo3}/deployments?sha=${head}&environment=${encodeURIComponent(policy.environment)}&per_page=100`)).body;
    if (!Array.isArray(deployments) || deployments.length >= 100) return unavailable();
    if (!deployments.length) return { status: "missing", reason: "GitHub has no deployment for the exact proposed head and selected environment." };
    if (!deployments.every((d) => positive(d.id) && d.sha === head && d.environment === policy.environment && timestamp(d.created_at) && positive(d.creator?.id) && Date.parse(d.created_at) <= now)) return unavailable();
    const sorted = [...deployments].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id), deployment = sorted[0];
    if (new Set(sorted.map((d) => d.id)).size !== sorted.length) return unavailable();
    const statuses = (await get(`${repo3}/deployments/${deployment.id}/statuses?per_page=100`)).body;
    if (!Array.isArray(statuses) || statuses.length >= 100) return unavailable();
    if (!statuses.length) return { status: "pending", reason: "The newest matching deployment has not reported a status." };
    if (!statuses.every((s) => positive(s.id) && timestamp(s.created_at) && timestamp(s.updated_at) && Date.parse(s.updated_at) >= Date.parse(s.created_at) && Date.parse(s.updated_at) <= now && positive(s.creator?.id))) return unavailable();
    const status2 = [...statuses].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id)[0];
    if (["pending", "queued", "in_progress"].includes(status2.state)) return { status: "pending", reason: "The newest matching deployment is still in progress." };
    if (["failure", "error", "inactive"].includes(status2.state)) return { status: "failed", reason: "The newest matching deployment is not a successful active preview." };
    if (status2.state !== "success" || status2.environment !== policy.environment || !safeRepositoryPreviewUrl(status2.environment_url) || !policy.allowed_origins.includes(new URL(status2.environment_url).origin)) return unavailable();
    const body = (await get(`${repo3}/commits/${head}/check-runs?per_page=100&filter=latest`)).body;
    if (!body || !Number.isSafeInteger(body.total_count) || body.total_count < 0 || body.total_count > 100 || !Array.isArray(body.check_runs) || body.check_runs.length !== body.total_count) return unavailable();
    const matching = body.check_runs.filter((c) => c.name === policy.check.name && c.app?.id === policy.check.app_id);
    if (!matching.length) return { status: "unavailable", reason: "The named check from the pinned GitHub App was not observed at this head." };
    if (!matching.every((c) => positive(c.id) && c.head_sha === head)) return unavailable();
    const check = matching.sort((a, b) => b.id - a.id)[0];
    if (check.status !== "completed") return { status: "pending", reason: "The pinned preview check has not completed at the proposed head." };
    if (check.conclusion !== "success") return { status: "failed", reason: "The pinned preview check did not succeed at the proposed head." };
    return { status: "available", deployment: { deployment_id: deployment.id, status_id: status2.id, sha: head, environment: policy.environment, state: "success", environment_url: status2.environment_url, deployment_creator_id: deployment.creator.id, status_creator_id: status2.creator.id, created_at: new Date(deployment.created_at).toISOString(), updated_at: new Date(status2.updated_at).toISOString(), check: { id: check.id, name: policy.check.name, app_id: policy.check.app_id, head_sha: head, conclusion: "success" } } };
  } catch {
    return unavailable();
  }
}
async function discoverRepositoryPreviewChoices(get, repository2, head, now = Date.now()) {
  const repo3 = `/repos/${repository2.split("/").map(encodeURIComponent).join("/")}`;
  try {
    const [deployments, runs] = await Promise.all([get(`${repo3}/deployments?sha=${head}&per_page=100`).then((r) => r.body), get(`${repo3}/commits/${head}/check-runs?per_page=100&filter=latest`).then((r) => r.body)]);
    if (!Array.isArray(deployments) || deployments.length >= 100 || !runs || !Number.isSafeInteger(runs.total_count) || runs.total_count > 100 || !Array.isArray(runs.check_runs) || runs.check_runs.length !== runs.total_count) throw Error();
    const selected = /* @__PURE__ */ new Map();
    for (const d of deployments) {
      if (!positive(d.id) || d.sha !== head || typeof d.environment !== "string" || !d.environment.trim() || d.environment.length > 100 || /[\u0000-\u001f\u007f]/.test(d.environment) || !timestamp(d.created_at) || Date.parse(d.created_at) > now) throw Error();
      const prior = selected.get(d.environment);
      if (!prior || Date.parse(d.created_at) > Date.parse(prior.created_at) || d.created_at === prior.created_at && d.id > prior.id) selected.set(d.environment, d);
    }
    if (selected.size > 20) throw Error();
    const candidates = [];
    for (const d of selected.values()) {
      const rows = (await get(`${repo3}/deployments/${d.id}/statuses?per_page=100`)).body;
      if (!Array.isArray(rows) || rows.length >= 100) throw Error();
      if (!rows.length) continue;
      const sorted = [...rows].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id), s = sorted[0];
      if (!positive(s.id) || !timestamp(s.created_at) || !timestamp(s.updated_at) || Date.parse(s.updated_at) > now) throw Error();
      if (s.state === "success" && s.environment === d.environment && safeRepositoryPreviewUrl(s.environment_url)) candidates.push({ environment: d.environment, origin: new URL(s.environment_url).origin, environment_url: s.environment_url, deployment_id: d.id, status_id: s.id });
    }
    const checks2 = [];
    for (const c of runs.check_runs) {
      if (c.status !== "completed" || c.conclusion !== "success") continue;
      if (c.head_sha !== head || !positive(c.id) || !positive(c.app?.id) || typeof c.name !== "string" || !c.name.trim() || c.name.length > 100 || /[\u0000-\u001f\u007f]/.test(c.name)) throw Error();
      const i = checks2.findIndex((x) => x.name === c.name && x.app_id === c.app.id);
      const item = { id: c.id, name: c.name, app_id: c.app.id };
      if (i < 0) checks2.push(item);
      else if (c.id > checks2[i].id) checks2[i] = item;
    }
    return { status: "observed", candidates, checks: checks2 };
  } catch {
    return { status: "unavailable", candidates: [], checks: [] };
  }
}
var positive, timestamp, unavailable;
var init_repository_review_preview = __esm({
  "src/repository-review-preview.ts"() {
    "use strict";
    init_coordination_repository_review();
    positive = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
    timestamp = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
    unavailable = () => ({ status: "unavailable", reason: "GitHub did not provide a complete, verifiable preview observation. No preview URL was inferred." });
  }
});

// src/repository-receiver.ts
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
async function runRepositoryReceiver(args) {
  const { readFile, writeFile } = await import("fs/promises");
  const action = args[0], option = (name2) => {
    const index = args.indexOf(name2);
    return index >= 0 ? args[index + 1] : void 0;
  };
  if (action === "keygen") {
    const output = option("--output");
    requireValue(output, "receiver_key_output_required");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]), publicKey = bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), privateKey3 = bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
    const identity = { publicKey };
    await writeFile(output, JSON.stringify({ type: "scopeblind.repository.receiver-key.v1", public_key: identity.publicKey, private_key: privateKey3 }, null, 2) + "\n", { mode: 384, flag: "wx" });
    process.stdout.write(`Receiver public key: ${identity.publicKey}
Private key saved to the requested owner-only file.
`);
    return;
  }
  requireValue(["inspect", "execute", "reconcile"].includes(action), "repository_command_required");
  const file = option("--config"), task = option("--task");
  requireValue(file && task && REPOSITORY_ID.test(task), "repository_config_and_task_required");
  const config = parseRepositoryReceiverConfig(JSON.parse(await readFile(file, "utf8")));
  let privateKey2 = process.env.SCOPEBLIND_RECEIVER_PRIVATE_KEY;
  if (option("--key-file")) {
    const key4 = JSON.parse(await readFile(option("--key-file"), "utf8"));
    requireValue(key4.type === "scopeblind.repository.receiver-key.v1" && key4.public_key === config.receiver_key, "receiver_key_mismatch");
    privateKey2 = key4.private_key;
  }
  requireValue(privateKey2 && /^[0-9a-f]{96,300}$/.test(privateKey2), "receiver_private_key_required");
  if (process.env.GITHUB_ACTIONS === "true") requireValue(process.env.GITHUB_REPOSITORY === config.repository && process.env.GITHUB_EVENT_NAME === "workflow_dispatch" && process.env.GITHUB_REF === `refs/heads/${config.base_branch}`, "receiver_trusted_workflow_required");
  const receiver = new RepositoryReceiver(config, await importIdentity(privateKey2, config.receiver_key), process.env.GITHUB_TOKEN || ""), result = action === "inspect" ? await receiver.inspect(task) : action === "execute" ? await receiver.execute(task) : await receiver.reconcile(task);
  const out = option("--output");
  if (out) await writeFile(out, JSON.stringify(await receiver.reviewEvidence(task), null, 2) + "\n", { mode: 384 });
  process.stdout.write(`Repository task ${task}: ${result.payload.status}. No PR code was executed by this receiver.
`);
}
var RepositoryReceiverError, RepositoryReceiver;
var init_repository_receiver = __esm({
  "src/repository-receiver.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_review();
    init_coordination_repository_review_evidence();
    init_repository_review_preview();
    RepositoryReceiverError = class extends Error {
      constructor(code, message = code, uncertain = false) {
        super(message);
        this.code = code;
        this.uncertain = uncertain;
      }
    };
    RepositoryReceiver = class {
      constructor(config, identity, githubToken3, fetchImpl = fetch) {
        this.identity = identity;
        this.githubToken = githubToken3;
        this.fetchImpl = fetchImpl;
        this.config = parseRepositoryReceiverConfig(config);
        requireValue(identity.publicKey === config.receiver_key && !identity.deviceAuthorization, "receiver_key_mismatch");
        requireValue(typeof githubToken3 === "string" && githubToken3.length > 0, "github_token_required");
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
      async review(taskId) {
        const request = await sign(makeRequest("repository_review_get", taskId, {}), this.identity);
        let response;
        try {
          response = await this.fetchImpl(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(2e4) });
        } catch {
          throw new RepositoryReceiverError("repository_review_unavailable");
        }
        const data = await json(response, 4e6);
        requireValue(response.ok && data.ok === true, "repository_review_unavailable");
        await this.validateState(data.repository_task, taskId);
        if (data.review) {
          const result = await verifyRepositoryReviewEvidence(data.evidence, this.config);
          requireValue(result.valid, "repository_review_evidence_invalid");
          requireValue(data.evidence.review.digest === data.review.digest && data.review.payload.task_digest === data.repository_task.payload.task.digest, "repository_review_scope_mismatch");
        }
        return data;
      }
      async reviewEvidence(taskId) {
        return (await this.review(taskId)).evidence;
      }
      async recordPacket(taskId, packet) {
        const request = await sign(makeRequest("repository_review_packet", taskId, { packet }), this.identity);
        let response;
        try {
          response = await this.fetchImpl(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(2e4) });
        } catch {
          throw new RepositoryReceiverError("repository_review_record_uncertain", "The exact packet may have been recorded. Inspect the existing task before continuing.", true);
        }
        const data = await json(response, 4e6);
        requireValue(response.ok && data.ok === true, typeof data.error === "string" ? data.error : "repository_review_record_failed");
        await this.validateState(data.repository_task, taskId);
        requireValue((await verifyRepositoryReviewEvidence(data.evidence, this.config)).valid && data.review?.payload.packet?.digest === packet.digest, "repository_review_evidence_invalid");
        return data.repository_task;
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
      async pull(number2) {
        const pr = (await this.github(`${this.repo}/pulls/${number2}`)).body;
        if (pr.merge_commit_sha === void 0 && pr.state === "open" && pr.mergeable === true) {
          const ref = (await this.github(`${this.repo}/git/ref/pull/${number2}/merge`)).body;
          requireValue(ref.ref === `refs/pull/${number2}/merge` && ref.object?.type === "commit" && REPOSITORY_SHA.test(ref.object.sha), "repository_merge_ref_invalid");
          return { ...pr, merge_commit_sha: ref.object.sha };
        }
        return pr;
      }
      async tree(sha4) {
        const body = (await this.github(`${this.repo}/git/trees/${sha4}?recursive=1`)).body;
        requireValue(body.sha === sha4 && !body.truncated && Array.isArray(body.tree) && body.tree.length <= 1e4, "repository_tree_incomplete");
        return new Map(body.tree.map((v) => [v.path, { type: v.type, mode: v.mode, sha: v.sha }]));
      }
      async snapshot(task, proposalId = crypto.randomUUID()) {
        const t = task.payload, pr = await this.pull(t.pull_number);
        requireValue(pr.number === t.pull_number && pr.state === "open" && !pr.draft && !pr.merged && pr.mergeable === true && pr.base?.repo?.full_name === t.repository && pr.head?.repo?.full_name === t.repository && pr.base.ref === t.base_branch && repositoryBranch(pr.head.ref) && pr.head.ref !== pr.base.ref && [pr.base.sha, pr.head.sha, pr.merge_commit_sha].every((s) => REPOSITORY_SHA.test(s)), "repository_pr_not_ready");
        const [repo3, base, merge, comparison, runs, currentBase, currentHead] = await Promise.all([
          this.github(this.repo),
          this.github(`${this.repo}/git/commits/${pr.base.sha}`),
          this.github(`${this.repo}/git/commits/${pr.merge_commit_sha}`),
          this.github(`${this.repo}/compare/${pr.base.sha}...${pr.merge_commit_sha}`),
          this.github(`${this.repo}/commits/${pr.head.sha}/check-runs?per_page=100&filter=latest`),
          this.ref(t.base_branch),
          this.ref(pr.head.ref)
        ]);
        requireValue(currentBase === pr.base.sha && currentHead === pr.head.sha, "repository_changed_during_inspection");
        requireValue(repo3.body.full_name === t.repository && typeof repo3.body.node_id === "string" && base.body.sha === pr.base.sha && REPOSITORY_SHA.test(base.body.tree?.sha) && merge.body.sha === pr.merge_commit_sha && Array.isArray(merge.body.parents) && canonical(merge.body.parents.map((p) => p.sha)) === canonical([pr.base.sha, pr.head.sha]) && REPOSITORY_SHA.test(merge.body.tree?.sha), "repository_merge_mismatch");
        requireValue(comparison.body.base_commit?.sha === pr.base.sha && comparison.body.merge_base_commit?.sha === pr.base.sha && comparison.body.status === "ahead" && Array.isArray(comparison.body.files) && comparison.body.files.length > 0 && comparison.body.files.length <= 50, "repository_diff_incomplete");
        const [oldTree, newTree] = await Promise.all([this.tree(base.body.tree.sha), this.tree(merge.body.tree.sha)]);
        const files = comparison.body.files.map((file) => {
          requireValue(["added", "modified", "removed", "renamed"].includes(file.status) && typeof file.filename === "string" && pathAllowed(file.filename, t.allowed_paths) && (file.status !== "renamed" || typeof file.previous_filename === "string" && pathAllowed(file.previous_filename, t.allowed_paths)), "repository_path_not_allowed");
          const before3 = oldTree.get(file.previous_filename || file.filename), after = newTree.get(file.filename), entry = file.status === "removed" ? before3 : after;
          requireValue(entry?.type === "blob" && ["100644", "100755"].includes(entry.mode) && (!before3 || before3.type === "blob" && ["100644", "100755"].includes(before3.mode)) && (!after || after.type === "blob" && ["100644", "100755"].includes(after.mode)), "repository_unsafe_file_type");
          requireValue(Number.isSafeInteger(file.additions) && file.additions >= 0 && Number.isSafeInteger(file.deletions) && file.deletions >= 0, "invalid_repository_diff");
          return { path: file.filename, status: file.status, mode: entry.mode, additions: file.additions, deletions: file.deletions, ...file.status === "renamed" ? { previous_path: file.previous_filename } : {}, ...typeof file.patch === "string" ? { patch: file.patch.slice(0, 400), ...file.patch.length > 400 ? { patch_truncated: true } : {} } : {} };
        }).sort((a, b) => a.path.localeCompare(b.path));
        const actual = [.../* @__PURE__ */ new Set([...oldTree.keys(), ...newTree.keys()])].filter((path) => oldTree.get(path)?.type !== "tree" && newTree.get(path)?.type !== "tree" && canonical(oldTree.get(path) ?? null) !== canonical(newTree.get(path) ?? null)).sort();
        const listed = [...new Set(files.flatMap((f) => [f.path, ...f.previous_path ? [f.previous_path] : []]))].sort();
        requireValue(canonical(actual) === canonical(listed), "repository_diff_incomplete");
        requireValue(Number.isSafeInteger(runs.body.total_count) && runs.body.total_count <= 100 && Array.isArray(runs.body.check_runs) && runs.body.check_runs.length === runs.body.total_count, "repository_checks_incomplete");
        const checks2 = t.required_checks.map((required) => {
          const matching = runs.body.check_runs.filter((c) => c.name === required.name && c.app?.id === required.app_id).sort((a, b) => b.id - a.id), run = matching[0];
          requireValue(run && run.head_sha === pr.head.sha && run.status === "completed" && run.conclusion === "success" && Number.isSafeInteger(run.id) && run.id > 0, "repository_check_not_passed");
          return { id: run.id, name: run.name, app_id: run.app.id, head_sha: run.head_sha, conclusion: "success" };
        }).sort((a, b) => a.name.localeCompare(b.name) || a.app_id - b.app_id);
        const current = await this.pull(t.pull_number);
        requireValue(current.state === "open" && !current.merged && !current.draft && current.head?.sha === pr.head.sha && current.base?.sha === pr.base.sha && current.merge_commit_sha === pr.merge_commit_sha && current.head?.repo?.full_name === t.repository && current.base?.repo?.full_name === t.repository, "repository_changed_during_inspection");
        const proposal = { type: "scopeblind.repository.proposal.v1", id: proposalId, task_id: t.id, task_digest: task.digest, repository_id: repo3.body.node_id, base_ref: `refs/heads/${pr.base.ref}`, head_ref: `refs/heads/${pr.head.ref}`, base_sha: pr.base.sha, head_sha: pr.head.sha, merge_sha: pr.merge_commit_sha, tree_sha: merge.body.tree.sha, files, checks: checks2, observed_at: (/* @__PURE__ */ new Date()).toISOString() };
        requireValue(validRepositoryProposal(proposal, t, task.digest), "invalid_repository_proposal");
        return proposal;
      }
      async inspect(taskId, proposalId) {
        if (proposalId !== void 0) requireValue(REPOSITORY_ID.test(proposalId), "invalid_repository_proposal_id");
        requireValue(REPOSITORY_ID.test(taskId), "invalid_repository_task_id");
        const current = await this.review(taskId), state = current.repository_task;
        requireValue(!state.payload.execution && state.payload.status !== "cancelled" && Date.parse(state.payload.task.payload.expires_at) > Date.now(), "repository_task_inactive");
        const prior = proposalId && state.payload.proposal?.payload.id === proposalId ? state.payload.proposal : null;
        if (prior && (!current.review || current.review.payload.packet?.payload.proposal_digest === prior.digest)) return state;
        const observed = await this.snapshot(state.payload.task, proposalId);
        if (prior) requireValue(await repositorySnapshotDigest(prior.payload) === await repositorySnapshotDigest(observed), "repository_approval_stale");
        const proposal = prior ?? await sign(observed, this.identity), saved = prior ? state : await this.rpc("repository_propose", taskId, { proposal });
        if (!current.review) return saved;
        const brief = current.review.payload.brief;
        requireValue(validRepositoryReviewBrief(brief.payload, state.payload.task.payload, state.payload.task.digest) && await verify(brief, this.config.owner_key), "repository_review_brief_invalid");
        const preview = await observeRepositoryReviewPreview((path) => this.github(path), this.config.repository, brief, proposal), observedAt = (/* @__PURE__ */ new Date()).toISOString(), expiresAt = new Date(Math.min(Date.parse(observedAt) + 9e5, Date.parse(brief.payload.expires_at))).toISOString();
        const packet = await sign({ type: "scopeblind.repository.review-packet.v1", task_id: taskId, task_digest: state.payload.task.digest, brief_digest: brief.digest, proposal_digest: proposal.digest, base_sha: proposal.payload.base_sha, head_sha: proposal.payload.head_sha, merge_sha: proposal.payload.merge_sha, preview, observed_at: observedAt, expires_at: expiresAt }, this.identity);
        requireValue(validRepositoryReviewPacket(packet.payload, brief, proposal), "repository_review_packet_invalid");
        return this.recordPacket(taskId, packet);
      }
      async execute(taskId) {
        requireValue(REPOSITORY_ID.test(taskId), "invalid_repository_task_id");
        let state = await this.rpc("repository_get", taskId);
        if (state.payload.execution) return this.reconcileState(state);
        requireValue(state.payload.status === "approved" && state.payload.proposal && Date.parse(state.payload.task.payload.expires_at) > Date.now(), "repository_joint_approval_required");
        const reviewed = await this.review(taskId);
        if (reviewed.review) {
          requireValue(reviewed.repository_task.payload.proposal?.digest === state.payload.proposal.digest && reviewed.review.payload.decisions.length === 2 && reviewed.review.payload.packet && Date.parse(reviewed.review.payload.packet.payload.expires_at) > Date.now(), "repository_review_joint_decision_required");
        }
        if (reviewed.review) await this.checkReviewObservation(reviewed.review, state.payload.proposal);
        const approved = state.payload.proposal, observed = await this.snapshot(state.payload.task);
        requireValue(await repositorySnapshotDigest(approved.payload) === await repositorySnapshotDigest(observed), "repository_approval_stale");
        const operationId = `repo-${taskId}`, attemptId = crypto.randomUUID();
        state = await this.rpc("repository_begin", taskId, { proposal_digest: approved.digest, operation_id: operationId, attempt_id: attemptId });
        const execution = state.payload.execution;
        requireValue(execution && execution.payload.receiver_attempt_id === attemptId && execution.payload.operation_id === operationId && execution.payload.proposal_digest === approved.digest, "repository_execution_mismatch");
        requireValue(Date.parse(execution.payload.expires_at) > Date.now(), "repository_execution_expired");
        let sent = false, requestId = "", note = "";
        try {
          if (reviewed.review) await this.checkReviewObservation(reviewed.review, approved);
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
      async checkReviewObservation(review, proposal) {
        requireValue(review.payload.packet && Date.parse(review.payload.packet.payload.expires_at) > Date.now(), "repository_review_packet_expired");
        const observed = await observeRepositoryReviewPreview((path) => this.github(path), this.config.repository, review.payload.brief, proposal);
        requireValue(canonical(observed) === canonical(review.payload.packet.payload.preview), "repository_review_preview_changed");
      }
      async reconcile(taskId) {
        return this.reconcileState(await this.rpc("repository_get", taskId));
      }
      async reconcileState(state, note = "Reconciled the existing operation by reading GitHub; no new reference update was sent.", requestId = "") {
        requireValue(state.payload.execution && state.payload.proposal, "repository_execution_missing");
        if (state.payload.outcome && state.payload.outcome.payload.status !== "unknown") return state;
        let sha4 = null, readback = "not_confirmed";
        try {
          sha4 = await this.ref(state.payload.task.payload.base_branch);
          if (sha4 === state.payload.proposal.payload.merge_sha) readback = "exact_ref";
          else if (sha4 !== state.payload.proposal.payload.base_sha) {
            const compare = (await this.github(`${this.repo}/compare/${state.payload.proposal.payload.merge_sha}...${sha4}`)).body;
            if (compare.base_commit?.sha === state.payload.proposal.payload.merge_sha && compare.merge_base_commit?.sha === state.payload.proposal.payload.merge_sha && ["ahead", "identical"].includes(compare.status)) readback = "descendant_ref";
          }
        } catch {
          note = "GitHub readback was unavailable. Keep this operation unresolved; do not dispatch a replacement.";
        }
        return this.report(state, { status: readback === "not_confirmed" ? "unknown" : "confirmed", observed_base_sha: sha4, readback, note, ...requestId ? { github_request_id: requestId } : {} });
      }
      async report(state, result) {
        const s = state.payload, x = s.execution;
        const outcome = await sign({ type: "scopeblind.repository.outcome.v1", operation_id: x.payload.operation_id, task_id: s.task.payload.id, task_digest: s.task.digest, proposal_digest: s.proposal.digest, execution_digest: x.digest, ...result, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
        return this.rpc("repository_outcome", s.task.payload.id, { outcome });
      }
    };
  }
});

// src/coordination-repository-connection.ts
function repositorySetupArtifactUrl(v) {
  return typeof v === "string" && /^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(v);
}
function validRepositorySetupRequest(v) {
  return shape6(v, ["type", "id", "owner_key", "authority_key", "repository", "pull_number", "mode", "secret_hash", "state_hash", "pkce_challenge", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.setup-request.v1" && id6(v.id) && hex3(v.owner_key) && hex3(v.authority_key) && v.owner_key !== v.authority_key && repo2(v.repository) && num2(v.pull_number) && ["github_app", "owner_local"].includes(String(v.mode)) && hex3(v.secret_hash) && hex3(v.state_hash) && typeof v.pkce_challenge === "string" && /^[A-Za-z0-9_-]{43}$/.test(v.pkce_challenge) && span3(v.issued_at, v.expires_at, REPOSITORY_SETUP_TTL);
}
function validRepositorySetupInspection(v, request, receiverKey) {
  if (!shape6(v, ["type", "setup_digest", "owner_key", "receiver_key", "repository", "repository_id", "pull_number", "title", "url", "base_branch", "head_branch", "base_sha", "head_sha", "draft", "mergeable", "files", "checks", "preview", "observed_at", "expires_at"]) || v.type !== "scopeblind.repository.setup-inspection.v1" || v.setup_digest !== request.digest || v.owner_key !== request.payload.owner_key || v.receiver_key !== receiverKey || v.repository !== request.payload.repository || !num2(v.repository_id) || v.pull_number !== request.payload.pull_number || !line2(v.title, 300) || v.url !== `https://github.com/${v.repository}/pull/${v.pull_number}` || !repositoryBranch(String(v.base_branch)) || !repositoryBranch(String(v.head_branch)) || !sha3(v.base_sha) || !sha3(v.head_sha) || typeof v.draft !== "boolean" || v.mergeable !== null && typeof v.mergeable !== "boolean" || !span3(v.observed_at, v.expires_at, 864e5)) return false;
  if (!Array.isArray(v.files) || v.files.length > 50 || !v.files.every((f) => shape6(f, ["path", "status", "additions", "deletions"], ["previous_path", "patch", "patch_truncated"]) && line2(f.path, 500) && ["added", "modified", "removed", "renamed"].includes(String(f.status)) && Number.isSafeInteger(f.additions) && Number(f.additions) >= 0 && Number.isSafeInteger(f.deletions) && Number(f.deletions) >= 0 && (f.previous_path === void 0 || line2(f.previous_path, 500)) && f.status === "renamed" === (f.previous_path !== void 0) && (f.patch === void 0 || typeof f.patch === "string" && f.patch.length <= 4e3) && (f.patch_truncated === void 0 || f.patch_truncated === true && typeof f.patch === "string")) || new Set(v.files.map((f) => f.path)).size !== v.files.length) return false;
  return Array.isArray(v.checks) && v.checks.length <= 100 && v.checks.every((c) => shape6(c, ["id", "name", "app_id", "head_sha", "status", "conclusion"]) && num2(c.id) && line2(c.name, 100) && num2(c.app_id) && c.head_sha === v.head_sha && ["queued", "in_progress", "completed"].includes(String(c.status)) && (c.conclusion === null || line2(c.conclusion, 100))) && new Set(v.checks.map((c) => c.id)).size === v.checks.length && (v.preview === null || validRepositoryEnvelope(v.preview));
}
function validRepositorySetupAuthorization(v) {
  return shape6(v, ["type", "setup_id", "setup_digest", "enrollment_digest", "connection_digest", "owner_key", "repository_id", "workflow_path", "workflow_sha256", "receiver_url", "receiver_sha256", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.setup-authorization.v1" && id6(v.setup_id) && [v.setup_digest, v.enrollment_digest, v.connection_digest, v.owner_key, v.workflow_sha256, v.receiver_sha256].every(hex3) && num2(v.repository_id) && v.workflow_path === REPOSITORY_GUIDED_WORKFLOW && repositorySetupArtifactUrl(v.receiver_url) && span3(v.issued_at, v.expires_at, REPOSITORY_SETUP_TTL);
}
function validRepositorySetupRenewal(v) {
  return shape6(v, ["type", "id", "setup_id", "authorization_digest", "owner_key", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.setup-renewal.v1" && id6(v.id) && id6(v.setup_id) && hex3(v.authorization_digest) && hex3(v.owner_key) && span3(v.issued_at, v.expires_at, REPOSITORY_SETUP_TTL);
}
function validRepositoryCodingConnectionConfig(v) {
  if (!obj3(v) || typeof v.endpoint !== "string") return false;
  let endpoint2;
  try {
    endpoint2 = new URL(v.endpoint);
  } catch {
    return false;
  }
  if (endpoint2.protocol !== "https:" || endpoint2.pathname !== "/api/coordination" || endpoint2.search || endpoint2.hash || endpoint2.username || endpoint2.password || endpoint2.href !== v.endpoint) return false;
  return shape6(v, ["type", "endpoint", "authority_key", "worker_key", "repository", "base_branch", "runtime", "test_command", "build_command", "preview_directory", "docker_image"]) && v.type === "scopeblind.repository.coding-config.v1" && typeof v.endpoint === "string" && /^https:\/\/[^/?#]+\/api\/coordination$/.test(v.endpoint) && hex3(v.authority_key) && hex3(v.worker_key) && repo2(v.repository) && repositoryBranch(String(v.base_branch)) && v.runtime === "node22-static-v1" && codingCommand(v.test_command) && codingCommand(v.build_command) && codingSafePath(v.preview_directory) && typeof v.docker_image === "string" && /^node@sha256:[a-f0-9]{64}$/.test(v.docker_image);
}
async function verifyRepositorySetupEnrollment(value, request, expectedEndpoint = "https://scopeblind.com/api/coordination") {
  try {
    if (!validRepositoryEnvelope(value)) return false;
    const e = value, v = e.payload, c = v.connection;
    if (!shape6(v, ["type", "setup_id", "setup_digest", "receiver_key", "connection", "readiness", "inspection", "installation", "issued_at"], ["coding", "replaces"]) || v.type !== "scopeblind.repository.setup-enrollment.v1" || v.setup_id !== request.payload.id || v.setup_digest !== request.digest || !hex3(v.receiver_key) || [request.payload.owner_key, request.payload.authority_key].includes(v.receiver_key) || !at7(v.issued_at) || !validRepositoryConnection(c) || c.id !== request.payload.id || c.owner_key !== request.payload.owner_key || c.authority_key !== request.payload.authority_key || c.receiver_key !== v.receiver_key || c.repository !== request.payload.repository || c.endpoint !== expectedEndpoint) return false;
    const i = v.installation;
    if (!shape6(i, ["workflow_path", "workflow", "workflow_sha256", "receiver_url", "receiver_sha256", "secret_name", "variable_name"]) || i.workflow_path !== REPOSITORY_GUIDED_WORKFLOW || !text5(i.workflow, 3e4) || !hex3(i.workflow_sha256) || await sha256(i.workflow) !== i.workflow_sha256 || !repositorySetupArtifactUrl(i.receiver_url) || !hex3(i.receiver_sha256) || i.secret_name !== "SCOPEBLIND_GUIDED_RECEIVER_KEY" || i.variable_name !== "SCOPEBLIND_GUIDED_CONNECTION") return false;
    if (!validRepositoryEnvelope(v.readiness) || !validRepositoryReadiness(v.readiness.payload) || v.readiness.payload.runtime !== "local" || v.readiness.payload.connection_digest !== await sha256(COORDINATION_DOMAIN + canonical(c)) || !validRepositoryEnvelope(v.inspection) || !validRepositorySetupInspection(v.inspection.payload, request, v.receiver_key)) return false;
    const r = v.readiness.payload, s = v.inspection.payload;
    if (Date.parse(v.issued_at) < Date.parse(request.payload.issued_at) - 1e3 || Date.parse(v.issued_at) > Date.parse(request.payload.expires_at) || Date.parse(c.issued_at) < Date.parse(request.payload.issued_at) - 1e3 || [r.observed_at, s.observed_at].some((t) => Date.parse(t) > Date.parse(v.issued_at) + 1e3 || Date.parse(v.issued_at) - Date.parse(t) > 3e5) || Date.parse(r.expires_at) > Date.parse(c.expires_at) || ["repository", "base_branch", "owner_key", "receiver_key", "authority_key"].some((k) => r[k] !== c[k]) || s.base_branch !== c.base_branch || r.base_sha !== s.base_sha || r.check_head_sha !== s.head_sha) return false;
    if (s.preview && (s.preview.payload.head_sha !== s.head_sha || !await verifyRepositoryPreviewDiscovery(s.preview, { owner_key: c.owner_key, receiver_key: c.receiver_key, authority_key: c.authority_key, repository: c.repository, pull_number: request.payload.pull_number }, Date.parse(s.observed_at)))) return false;
    if (v.coding) {
      const k = v.coding;
      if (!shape6(k, ["config", "workflow", "workflow_sha256", "artifact_url", "artifact_sha256"]) || !validRepositoryCodingConnectionConfig(k.config) || k.config.endpoint !== c.endpoint || k.config.repository !== c.repository || k.config.base_branch !== c.base_branch || k.config.authority_key !== c.authority_key || [c.owner_key, c.receiver_key, c.authority_key].includes(k.config.worker_key) || !text5(k.workflow, 3e4) || !hex3(k.workflow_sha256) || await sha256(k.workflow) !== k.workflow_sha256 || !/^https:\/\/scopeblind\.com\/releases\/repository-coding-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(k.artifact_url) || !hex3(k.artifact_sha256)) return false;
    }
    if (v.replaces && !await verifyRepositorySetupReplacement(v.replaces, c)) return false;
    return await verify(e, v.receiver_key) && await verify(v.readiness, v.receiver_key) && await verify(v.inspection, v.receiver_key);
  } catch {
    return false;
  }
}
async function verifyRepositorySetupReplacement(value, next) {
  try {
    if (!shape6(value, ["type", "endpoint", "authority_key", "connection", "authorization"]) || value.type !== "scopeblind.repository.guided-receiver-config.v1" || !validRepositoryEnvelope(value.connection) || !validRepositoryEnvelope(value.authorization)) return false;
    const c = value.connection, a = value.authorization;
    return validRepositoryConnection(c.payload) && validRepositorySetupAuthorization(a.payload) && value.endpoint === next.endpoint && value.authority_key === next.authority_key && c.payload.id !== next.id && ["endpoint", "repository", "base_branch", "owner_key", "receiver_key", "authority_key"].every((k) => c.payload[k] === next[k]) && a.payload.connection_digest === c.digest && a.payload.setup_id === c.payload.id && a.payload.owner_key === next.owner_key && await verify(c, next.owner_key) && await verify(a, next.owner_key);
  } catch {
    return false;
  }
}
function validWorkflowProof(proof, ready, repositoryId, workflowRef, observedAt) {
  return shape6(proof, ["repository_id", "run_id", "run_attempt", "workflow_ref", "workflow_sha", "token_digest", "verified_at"]) && proof.repository_id === repositoryId && num2(proof.run_id) && num2(proof.run_attempt) && proof.run_id === ready.run_id && proof.run_attempt === ready.run_attempt && proof.workflow_ref === workflowRef && ready.workflow_ref === workflowRef && sha3(proof.workflow_sha) && proof.workflow_sha === ready.workflow_sha && hex3(proof.token_digest) && at7(proof.verified_at) && at7(ready.observed_at) && Date.parse(proof.verified_at) >= Date.parse(ready.observed_at) - 1e3 && Date.parse(proof.verified_at) - Date.parse(ready.observed_at) <= 3e5 && Date.parse(proof.verified_at) <= Date.parse(observedAt) + 1e3;
}
async function verifyRepositorySetupState(value, authorityKey, ownerKey, expectedEndpoint = "https://scopeblind.com/api/coordination") {
  try {
    if (!validRepositoryEnvelope(value)) return false;
    const signed = value;
    if (!await verify(signed, authorityKey)) return false;
    const s = signed.payload, r = s.request;
    if (!shape6(s, ["type", "request", "github", "enrollment", "connection", "authorization", "challenge", "ready", "workflow_proof", "status", "dispatch", "observed_at"], ["coding_ready", "superseded_by", "blocking_jobs", "initial_ready", "installation_renewal"]) || s.type !== "scopeblind.repository.setup-state.v1" || !validRepositoryEnvelope(r) || !validRepositorySetupRequest(r.payload) || r.payload.authority_key !== authorityKey || ownerKey && r.payload.owner_key !== ownerKey || !await verify(r, r.payload.owner_key) || !at7(s.observed_at) || Date.parse(s.observed_at) < Date.parse(r.payload.issued_at) - 1e3 || !["awaiting_github", "awaiting_receiver", "awaiting_confirmation", "awaiting_workflow", "ready", "expired", "revoked", "superseded", "replacement_pending", "installation_expired"].includes(s.status) || !["none", "requested", "unconfigured", "unavailable"].includes(s.dispatch)) return false;
    if (s.blocking_jobs !== void 0 && typeof s.blocking_jobs !== "boolean" || s.superseded_by !== void 0 && s.superseded_by !== null && (!id6(s.superseded_by) || s.superseded_by === r.payload.id)) return false;
    const observed = Date.parse(s.observed_at);
    if (s.github) {
      const g = s.github.payload;
      if (!validRepositoryEnvelope(s.github) || !await verify(s.github, authorityKey) || !shape6(g, ["type", "setup_digest", "app_id", "installation_id", "user_id", "login", "repository_id", "repository", "default_branch", "permissions", "repository_selection", "observed_at"]) || g.type !== "scopeblind.repository.setup-github.v1" || g.setup_digest !== r.digest || g.repository !== r.payload.repository || g.repository_selection !== "selected" || ![g.app_id, g.installation_id, g.user_id, g.repository_id].every(num2) || !line2(g.login, 100) || !repositoryBranch(g.default_branch) || !shape6(g.permissions, ["admin", "push"]) || typeof g.permissions.admin !== "boolean" || g.permissions.push !== true || !at7(g.observed_at) || Date.parse(g.observed_at) > observed + 1e3 || Date.parse(g.observed_at) < Date.parse(r.payload.issued_at) - 1e3) return false;
    }
    if (s.enrollment) {
      if (!await verifyRepositorySetupEnrollment(s.enrollment, r, expectedEndpoint) || Date.parse(s.enrollment.payload.issued_at) > observed + 1e3) return false;
      if (r.payload.mode === "github_app" && (!s.github || s.github.payload.repository_id !== s.enrollment.payload.inspection.payload.repository_id || s.github.payload.default_branch !== s.enrollment.payload.connection.base_branch)) return false;
    }
    if (!!s.connection !== !!s.authorization) return false;
    if (s.connection && (!s.enrollment || !validRepositoryEnvelope(s.connection) || !await verify(s.connection, r.payload.owner_key) || canonical(s.connection.payload) !== canonical(s.enrollment.payload.connection))) return false;
    if (s.authorization) {
      const a = s.authorization;
      if (!s.connection || !s.enrollment || !validRepositoryEnvelope(a) || !validRepositorySetupAuthorization(a.payload) || !await verify(a, r.payload.owner_key) || a.payload.setup_id !== r.payload.id || a.payload.setup_digest !== r.digest || a.payload.enrollment_digest !== s.enrollment.digest || a.payload.connection_digest !== s.connection.digest || a.payload.owner_key !== r.payload.owner_key || a.payload.repository_id !== s.enrollment.payload.inspection.payload.repository_id || a.payload.workflow_sha256 !== s.enrollment.payload.installation.workflow_sha256 || a.payload.receiver_url !== s.enrollment.payload.installation.receiver_url || a.payload.receiver_sha256 !== s.enrollment.payload.installation.receiver_sha256 || Date.parse(a.payload.issued_at) < Date.parse(s.enrollment.payload.issued_at) - 1e3 || Date.parse(a.payload.issued_at) > observed + 1e3 || Date.parse(a.payload.expires_at) > Date.parse(r.payload.expires_at)) return false;
    }
    if (s.installation_renewal) {
      const renewal = s.installation_renewal;
      if (!s.authorization || !s.connection || !validRepositoryEnvelope(renewal) || !validRepositorySetupRenewal(renewal.payload) || renewal.payload.setup_id !== r.payload.id || renewal.payload.authorization_digest !== s.authorization.digest || renewal.payload.owner_key !== r.payload.owner_key || !await verify(renewal, r.payload.owner_key) || Date.parse(renewal.payload.issued_at) < Date.parse(s.authorization.payload.issued_at) || Date.parse(renewal.payload.issued_at) > observed + 1e3 || Date.parse(renewal.payload.expires_at) > Date.parse(s.connection.payload.expires_at)) return false;
    }
    if (s.challenge && (!s.authorization || !shape6(s.challenge, ["id", "audience", "issued_at", "expires_at"]) || !id6(s.challenge.id) || !span3(s.challenge.issued_at, s.challenge.expires_at, 6e5) || Date.parse(s.challenge.issued_at) > observed + 1e3 || !s.challenge.audience.startsWith(`https://scopeblind.com/repository-setup/${r.payload.id}/`) || !id6(s.challenge.audience.slice(s.challenge.audience.lastIndexOf("/") + 1)))) return false;
    if (!!s.ready !== !!s.workflow_proof) return false;
    if (s.initial_ready && (!shape6(s.initial_ready, ["ready", "workflow_proof"]) || !validRepositoryEnvelope(s.initial_ready.ready) || !s.initial_ready.ready.payload.inspection)) return false;
    const readinessRecords = [...s.initial_ready ? [s.initial_ready] : [], ...s.ready ? [{ ready: s.ready, workflow_proof: s.workflow_proof }] : []];
    for (const record of readinessRecords) {
      const q = record.ready, p = q.payload, c = s.connection?.payload;
      if (!s.authorization || !s.connection || !s.enrollment || !c || !validRepositoryEnvelope(q) || !shape6(p, ["type", "setup_id", "setup_digest", "connection_digest", "authorization_digest", "challenge_id", "receiver_key", "readiness", "inspection", "run_id", "run_attempt", "workflow_ref", "workflow_sha", "observed_at"]) || p.type !== "scopeblind.repository.setup-ready.v1" || !await verify(q, c.receiver_key) || p.setup_id !== r.payload.id || p.setup_digest !== r.digest || p.connection_digest !== s.connection.digest || p.authorization_digest !== s.authorization.digest || p.receiver_key !== c.receiver_key || !id6(p.challenge_id) || !validWorkflowProof(record.workflow_proof, p, s.enrollment.payload.inspection.payload.repository_id, `${c.repository}/${REPOSITORY_GUIDED_WORKFLOW}@refs/heads/${c.base_branch}`, s.observed_at) || !validRepositoryEnvelope(p.readiness) || !validRepositoryReadiness(p.readiness.payload) || p.readiness.payload.runtime !== "github_actions" || p.readiness.payload.workflow !== "matching" || p.readiness.payload.connection_digest !== s.connection.digest || !await verify(p.readiness, c.receiver_key)) return false;
      const ready = p.readiness.payload;
      if (p.inspection === null && (!s.initial_ready || Date.parse(p.observed_at) < Date.parse(s.initial_ready.ready.payload.observed_at))) return false;
      if (p.inspection !== null && (!validRepositoryEnvelope(p.inspection) || !validRepositorySetupInspection(p.inspection.payload, r, c.receiver_key) || !await verify(p.inspection, c.receiver_key))) return false;
      const i = p.inspection?.payload;
      if (["repository", "base_branch", "owner_key", "receiver_key", "authority_key"].some((k) => ready[k] !== c[k]) || i && (i.repository_id !== s.enrollment.payload.inspection.payload.repository_id || i.base_branch !== c.base_branch || ready.base_sha !== i.base_sha || ready.check_head_sha !== i.head_sha) || Date.parse(ready.expires_at) > Date.parse(c.expires_at) || Date.parse(p.observed_at) < Date.parse(s.authorization.payload.issued_at) - 1e3 || [ready.observed_at, ...i ? [i.observed_at] : []].some((t) => Date.parse(t) > Date.parse(p.observed_at) + 1e3 || Date.parse(p.observed_at) - Date.parse(t) > 3e5)) return false;
      if (i?.preview && (i.preview.payload.head_sha !== i.head_sha || !await verifyRepositoryPreviewDiscovery(i.preview, { owner_key: c.owner_key, receiver_key: c.receiver_key, authority_key: c.authority_key, repository: c.repository, pull_number: r.payload.pull_number }, Date.parse(i.observed_at)))) return false;
    }
    if (s.coding_ready) {
      const bundle = s.coding_ready, q = bundle.ready, p = q?.payload, c = s.connection?.payload, k = s.enrollment?.payload.coding;
      if (!shape6(bundle, ["ready", "workflow_proof"]) || !c || !k || !s.authorization || !validRepositoryEnvelope(q) || !shape6(p, ["type", "setup_id", "setup_digest", "connection_digest", "coding_digest", "worker_key", "challenge_id", "run_id", "run_attempt", "workflow_ref", "workflow_sha", "observed_at", "expires_at"]) || p.type !== "scopeblind.repository.setup-coding-ready.v1" || p.setup_id !== r.payload.id || p.setup_digest !== r.digest || p.connection_digest !== s.connection.digest || p.coding_digest !== await sha256(canonical(k.config)) || p.worker_key !== k.config.worker_key || !id6(p.challenge_id) || !span3(p.observed_at, p.expires_at, 864e5) || Date.parse(p.expires_at) > Date.parse(c.expires_at) || Date.parse(p.observed_at) < Date.parse(s.authorization.payload.issued_at) - 1e3 || !await verify(q, k.config.worker_key) || !validWorkflowProof(bundle.workflow_proof, p, s.enrollment.payload.inspection.payload.repository_id, `${c.repository}/.github/workflows/scopeblind-coding.yml@refs/heads/${c.base_branch}`, s.observed_at)) return false;
    }
    if (s.status === "revoked") return true;
    if (s.status === "superseded" || s.status === "replacement_pending") return !!s.superseded_by;
    if (s.superseded_by) return false;
    const expired = Date.parse(s.connection?.payload.expires_at ?? r.payload.expires_at) <= observed;
    const expected = expired ? "expired" : s.ready && Date.parse(s.ready.payload.readiness.payload.expires_at) > observed ? "ready" : r.payload.mode === "github_app" && !s.github ? "awaiting_github" : !s.enrollment ? "awaiting_receiver" : !s.authorization ? "awaiting_confirmation" : !s.initial_ready && !s.ready && Date.parse(s.installation_renewal?.payload.expires_at ?? s.authorization.payload.expires_at) <= observed ? "installation_expired" : "awaiting_workflow";
    return s.status === expected;
  } catch {
    return false;
  }
}
var REPOSITORY_GUIDED_WORKFLOW, REPOSITORY_SETUP_TTL, obj3, shape6, hex3, id6, sha3, num2, at7, text5, line2, repo2, span3;
var init_coordination_repository_connection = __esm({
  "src/coordination-repository-connection.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_collaboration();
    init_coordination_repository_review();
    init_coordination_repository_coding();
    REPOSITORY_GUIDED_WORKFLOW = ".github/workflows/scopeblind-connection.yml";
    REPOSITORY_SETUP_TTL = 30 * 6e4;
    obj3 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    shape6 = (v, keys, optional = []) => obj3(v) && keys.every((k) => k in v) && Object.keys(v).every((k) => keys.includes(k) || optional.includes(k));
    hex3 = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
    id6 = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
    sha3 = (v) => typeof v === "string" && REPOSITORY_SHA.test(v);
    num2 = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
    at7 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
    text5 = (v, max) => typeof v === "string" && v.trim().length > 0 && v.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);
    line2 = (v, max) => text5(v, max) && !/[\r\n\t]/.test(v);
    repo2 = (v) => typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v) && !v.split("/").some((x) => x === "." || x === "..");
    span3 = (a, b, max) => at7(a) && at7(b) && Date.parse(b) > Date.parse(a) && Date.parse(b) - Date.parse(a) <= max;
  }
});

// src/repository-connect-workflow.ts
function renderGuidedReceiverWorkflow(artifact2) {
  if (!repositorySetupArtifactUrl(artifact2.url) || !hash(artifact2.sha256)) throw new Error("setup_invalid_artifact");
  return `# Owner-reviewed installation; no PR checkout, imported code, or implicit approval.
name: ScopeBlind connected receiver
on:
  workflow_dispatch:
    inputs:
      job_id:
        description: Exact signed ScopeBlind connection job
        type: string
        required: true
permissions:
  contents: write
  pull-requests: read
  checks: read
  deployments: read
  id-token: write
concurrency:
  group: scopeblind-connection-\${{ inputs.job_id }}
  cancel-in-progress: false
jobs:
  receiver:
    if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - name: Use the reviewed Node runtime
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          node-version: '22.22.3'
      - name: Verify the reviewed receiver artifact
        env:
          RECEIVER_URL: ${artifact2.url}
          RECEIVER_SHA256: ${artifact2.sha256}
        shell: bash
        run: |
          set -euo pipefail
          curl --fail --silent --show-error --proto '=https' --max-time 30 "$RECEIVER_URL" --output receiver.cjs
          printf '%s  receiver.cjs\\n' "$RECEIVER_SHA256" | sha256sum --check --strict
      - name: Run only the signed connection job
        env:
          GITHUB_TOKEN: \${{ github.token }}
          SCOPEBLIND_RECEIVER_PRIVATE_KEY: \${{ secrets.SCOPEBLIND_GUIDED_RECEIVER_KEY }}
          CONNECTION_CONFIG: \${{ vars.SCOPEBLIND_GUIDED_CONNECTION }}
          JOB_ID: \${{ inputs.job_id }}
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          node -e 'require("node:fs").writeFileSync("connection.json",process.env.CONNECTION_CONFIG,{mode:0o600,flag:"wx"})'
          node receiver.cjs connection-job --connection connection.json --job "$JOB_ID"
`;
}
function renderGuidedCodingWorkflow(artifact2, receiver) {
  if (!/^https:\/\/scopeblind\.com\/releases\/repository-coding-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(artifact2.url) || !hash(artifact2.sha256) || !repositorySetupArtifactUrl(receiver.url) || !hash(receiver.sha256)) throw new Error("setup_invalid_coding_artifact");
  return `# Trusted controller only; proposed code runs in a separate credential-free networkless container.
name: ScopeBlind bounded coding worker
on:
  workflow_dispatch:
    inputs:
      job_id:
        description: Connection setup ID for readiness, or an authorized coding job ID
        type: string
        required: true
permissions:
  contents: write
  pull-requests: write
  checks: write
  deployments: write
  id-token: write
concurrency:
  group: scopeblind-coding-controller
  cancel-in-progress: false
jobs:
  coding:
    if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - name: Use the reviewed Node runtime
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          node-version: '22.22.3'
      - name: Verify the reviewed controller artifacts
        env:
          RECEIVER_URL: ${receiver.url}
          RECEIVER_SHA256: ${receiver.sha256}
          CODING_URL: ${artifact2.url}
          CODING_SHA256: ${artifact2.sha256}
        shell: bash
        run: |
          set -euo pipefail
          curl --fail --silent --show-error --proto '=https' --max-time 30 "$RECEIVER_URL" --output receiver.cjs
          curl --fail --silent --show-error --proto '=https' --max-time 30 "$CODING_URL" --output coding.cjs
          printf '%s  receiver.cjs\\n%s  coding.cjs\\n' "$RECEIVER_SHA256" "$CODING_SHA256" | sha256sum --check --strict
      - name: Confirm the exact worker then run bounded work
        env:
          GITHUB_TOKEN: \${{ github.token }}
          SCOPEBLIND_CODING_WORKER_KEY: \${{ secrets.SCOPEBLIND_CODING_WORKER_KEY }}
          CODING_CONFIG: \${{ vars.SCOPEBLIND_CODING_CONNECTION }}
          CONNECTION_CONFIG: \${{ vars.SCOPEBLIND_GUIDED_CONNECTION }}
          JOB_ID: \${{ inputs.job_id }}
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          node -e 'require("node:fs").writeFileSync("coding.json",process.env.CODING_CONFIG,{mode:0o600,flag:"wx"});require("node:fs").writeFileSync("connection.json",process.env.CONNECTION_CONFIG,{mode:0o600,flag:"wx"})'
          node receiver.cjs coding-ready --connection connection.json --coding coding.json
          SETUP_ID="$(node -e 'process.stdout.write(JSON.parse(require("node:fs").readFileSync("connection.json","utf8")).authorization.payload.setup_id)')"
          if [ "$JOB_ID" = "$SETUP_ID" ]; then
            printf '%s\\n' 'Connection readiness refreshed. No coding job was run.'
          else
            node coding.cjs --config coding.json
          fi
`;
}
var hash;
var init_repository_connect_workflow = __esm({
  "src/repository-connect-workflow.ts"() {
    "use strict";
    init_coordination_repository_connection();
    hash = (v) => /^[a-f0-9]{64}$/.test(v);
  }
});

// src/repository-connect.ts
var repository_connect_exports = {};
__export(repository_connect_exports, {
  currentGuidedCodingReady: () => currentGuidedCodingReady,
  inspectRepositorySetup: () => inspectRepositorySetup,
  installReviewedConnection: () => installReviewedConnection,
  observeGuidedReadiness: () => observeGuidedReadiness,
  parseRepositoryConnectLink: () => parseRepositoryConnectLink,
  runRepositoryConnect: () => runRepositoryConnect,
  uncommittedSetupEnrollmentStale: () => uncommittedSetupEnrollmentStale
});
function need(v, code) {
  if (!v) throw new RepositoryReceiverError(code);
}
async function json2(response, max = 2e6) {
  const reader = response.body?.getReader();
  need(reader, "connect_empty_response");
  const parts = [];
  let size = 0;
  try {
    for (; ; ) {
      const p = await reader.read();
      if (p.done) break;
      size += p.value.length;
      need(size <= max, "connect_response_too_large");
      parts.push(p.value);
    }
  } finally {
    await reader.cancel().catch(() => {
    });
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const p of parts) {
    bytes.set(p, offset);
    offset += p.length;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new RepositoryReceiverError("connect_response_invalid");
  }
}
async function github(path, token, fetchImpl, method = "GET", body) {
  const r = await fetchImpl("https://api.github.com" + path, { method, headers: { authorization: "Bearer " + token, accept: "application/vnd.github+json", "content-type": "application/json", "x-github-api-version": "2026-03-10" }, ...body ? { body: JSON.stringify(body) } : {}, redirect: "error", signal: AbortSignal.timeout(2e4) });
  if (r.status === 404 || r.status === 403) {
    await r.body?.cancel();
    return { status: r.status, body: null };
  }
  need(r.ok, "connect_github_refused");
  return { status: r.status, body: await json2(r) };
}
async function preflightCodingPullRequests(repository2, read) {
  let value;
  try {
    value = await read();
  } catch {
  }
  const settings = `https://github.com/${repository2}/settings/actions`;
  if (!object6(value) || typeof value.can_approve_pull_request_reviews !== "boolean") throw new RepositoryReceiverError("connect_coding_pull_request_policy_unverified", `Could not verify whether GitHub Actions can create pull requests in ${repository2}. Ask a repository administrator to check Settings > Actions > General > Workflow permissions at ${settings}, then rerun with a credential that can read this repository's Administration permission (or repo scope for a classic token). Coding setup cannot continue; no repository setting was changed.`);
  if (!value.can_approve_pull_request_reviews) throw new RepositoryReceiverError("connect_coding_pull_requests_disabled", `GitHub Actions cannot create pull requests in ${repository2}. Ask a repository administrator to enable "Allow GitHub Actions to create and approve pull requests" under Settings > Actions > General > Workflow permissions at ${settings}. An organization administrator may need to allow this policy first. Then rerun the same setup command. Coding setup cannot continue; no repository setting was changed.`);
}
function parseRepositoryConnectLink(value) {
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new RepositoryReceiverError("connect_private_link_invalid");
  }
  const id7 = u.searchParams.get("setup"), secret = new URLSearchParams(u.hash.slice(1)).get("setup");
  need(u.origin === "https://scopeblind.com" && u.pathname === "/standard" && !u.username && !u.password && id7 && REPOSITORY_ID.test(id7) && secret && REPOSITORY_HEX.test(secret) && [...u.searchParams.keys()].every((k) => ["setup", "trial", "view"].includes(k)) && [...new URLSearchParams(u.hash.slice(1)).keys()].length === 1, "connect_private_link_invalid");
  return { id: id7, secret };
}
async function rpc(identity, action, id7, body, fetchImpl, endpoint2 = ENDPOINT) {
  const request = await sign(makeRequest(action, id7, body), identity), r = await fetchImpl(endpoint2, { method: "POST", headers: { "content-type": "application/json", "x-scopeblind-action": action }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(25e3) }), v = await json2(r, 4e6);
  need(object6(v), "connect_service_invalid");
  if (!r.ok || v.ok !== true) throw new RepositoryReceiverError(typeof v.error === "string" && /^[a-z0-9_]{1,100}$/.test(v.error) ? v.error : "connect_service_refused");
  return v;
}
async function checkedState(v, pin, owner) {
  need(await verifyRepositorySetupState(v, pin, owner), "connect_state_unverified");
  return v;
}
async function privateKey(path, required = false) {
  const { readFile, lstat, writeFile } = await import("fs/promises");
  try {
    const s = await lstat(path);
    need(s.isFile() && !s.isSymbolicLink() && (process.platform === "win32" || (s.mode & 63) === 0), "connect_key_permissions");
    const key5 = JSON.parse(await readFile(path, "utf8"));
    need(object6(key5) && key5.type === "scopeblind.repository.receiver-key.v1" && typeof key5.private_key === "string" && typeof key5.public_key === "string", "connect_key_invalid");
    await importIdentity(key5.private_key, key5.public_key);
    return key5;
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    need(!required, "connect_existing_key_missing");
  }
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]), key4 = { type: "scopeblind.repository.receiver-key.v1", public_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), private_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))) };
  await writeFile(path, JSON.stringify(key4) + "\n", { mode: 384, flag: "wx" });
  return key4;
}
async function githubToken(env) {
  const token = env.GITHUB_TOKEN ?? env.GH_TOKEN;
  if (token) {
    need(!/[\r\n\u0000]/.test(token), "connect_github_token_invalid");
    return token;
  }
  const { execFileSync } = await import("child_process");
  try {
    return execFileSync("gh", ["auth", "token", "--hostname", "github.com"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 1e4, env }).trim();
  } catch {
    throw new RepositoryReceiverError("connect_github_login_required", "Sign in on this trusted machine with gh auth login before connecting.");
  }
}
async function artifact(url, fetchImpl) {
  const r = await fetchImpl(url + ".sha256", { redirect: "error", signal: AbortSignal.timeout(2e4) });
  need(r.ok, "connect_release_unavailable");
  const t = await r.text();
  need(t.length < 1e3 && /^[a-f0-9]{64}(?:\s+[^\r\n]+)?\s*$/.test(t), "connect_release_checksum_invalid");
  return t.slice(0, 64);
}
async function inspectRepositorySetup(request, identity, token, fetchImpl = fetch, workflowPath = REPOSITORY_GUIDED_WORKFLOW) {
  const p = request.payload, discovery = await discoverRepository({ repository: p.repository, pull_number: p.pull_number, workflow_path: workflowPath }, token, fetchImpl), base = "/repos/" + p.repository.split("/").map(encodeURIComponent).join("/");
  const [repo3, pr, files, runs] = await Promise.all([github(base, token, fetchImpl), github(`${base}/pulls/${p.pull_number}`, token, fetchImpl), github(`${base}/pulls/${p.pull_number}/files?per_page=100`, token, fetchImpl), github(`${base}/commits/${discovery.observed_head_sha}/check-runs?per_page=100&filter=latest`, token, fetchImpl)]);
  const r = repo3.body, v = pr.body;
  need(object6(r) && Number.isSafeInteger(r.id) && Number(r.id) > 0 && object6(v) && v.state === "open" && !v.merged && v.number === p.pull_number && object6(v.base) && object6(v.head) && object6(v.base.repo) && object6(v.head.repo) && v.base.repo.full_name === p.repository && v.head.repo.full_name === p.repository && v.base.ref === discovery.base_branch && v.base.sha === discovery.base_sha && v.head.sha === discovery.observed_head_sha && typeof v.head.ref === "string" && typeof v.title === "string" && typeof v.draft === "boolean" && (v.mergeable === null || typeof v.mergeable === "boolean"), "connect_pull_changed");
  need(Array.isArray(files.body) && Number.isSafeInteger(v.changed_files) && Number(v.changed_files) <= 50 && files.body.length === v.changed_files, "connect_files_incomplete");
  let excerptBytes = 128 * 1024, remainingPatches = files.body.filter((f) => object6(f) && typeof f.patch === "string").length;
  const changes = files.body.map((f) => {
    need(object6(f) && typeof f.filename === "string" && ["added", "modified", "removed", "renamed"].includes(String(f.status)) && Number.isSafeInteger(f.additions) && Number.isSafeInteger(f.deletions), "connect_file_invalid");
    let excerpt;
    if (typeof f.patch === "string") {
      const budget = Math.floor(excerptBytes / remainingPatches--);
      let patch = "", used = 0;
      for (const character of f.patch) {
        const bytes = new TextEncoder().encode(JSON.stringify(character)).byteLength - 2;
        if (patch.length + character.length > 4e3 || used + bytes > budget) break;
        patch += character;
        used += bytes;
      }
      excerptBytes -= used;
      excerpt = { patch, ...patch.length < f.patch.length ? { patch_truncated: true } : {} };
    }
    return { path: f.filename, status: f.status, additions: Number(f.additions), deletions: Number(f.deletions), ...typeof f.previous_filename === "string" ? { previous_path: f.previous_filename } : {}, ...excerpt };
  });
  need(object6(runs.body) && Array.isArray(runs.body.check_runs) && runs.body.check_runs.length === runs.body.total_count && runs.body.check_runs.length <= 100, "connect_checks_incomplete");
  const checks2 = runs.body.check_runs.map((c) => {
    need(object6(c) && object6(c.app), "connect_check_invalid");
    return { id: Number(c.id), name: String(c.name), app_id: Number(c.app.id), head_sha: String(c.head_sha), status: c.status, conclusion: c.conclusion === null ? null : String(c.conclusion) };
  });
  const choices = await discoverRepositoryPreviewChoices((path) => github(path, token, fetchImpl), p.repository, discovery.observed_head_sha), observed = date(), expires = new Date(Date.now() + 864e5).toISOString(), preview = await sign({ type: "scopeblind.repository.preview-discovery.v1", repository: p.repository, pull_number: p.pull_number, head_sha: discovery.observed_head_sha, owner_key: p.owner_key, receiver_key: identity.publicKey, authority_key: p.authority_key, ...choices, observed_at: observed, expires_at: expires }, identity);
  const latest = (await github(`${base}/pulls/${p.pull_number}`, token, fetchImpl)).body;
  need(object6(latest) && object6(latest.head) && object6(latest.base) && latest.head.sha === v.head.sha && latest.base.sha === v.base.sha && latest.state === "open" && !latest.merged, "connect_pull_changed");
  const inspection = await sign({ type: "scopeblind.repository.setup-inspection.v1", setup_digest: request.digest, owner_key: p.owner_key, receiver_key: identity.publicKey, repository: p.repository, repository_id: Number(r.id), pull_number: p.pull_number, title: v.title, url: `https://github.com/${p.repository}/pull/${p.pull_number}`, base_branch: discovery.base_branch, head_branch: v.head.ref, base_sha: discovery.base_sha, head_sha: discovery.observed_head_sha, draft: v.draft, mergeable: v.mergeable, files: changes, checks: checks2, preview, observed_at: observed, expires_at: expires }, identity);
  need(validRepositorySetupInspection(inspection.payload, request, identity.publicKey), "connect_inspection_invalid");
  return { discovery, inspection };
}
function uncommittedSetupEnrollmentStale(local, state, now = Date.now()) {
  return !state.payload.enrollment && local.payload.setup_digest === state.payload.request.digest && [local.payload.issued_at, local.payload.inspection.payload.observed_at, local.payload.readiness.payload.observed_at].some((time4) => now - Date.parse(time4) > 3e5);
}
function currentGuidedCodingReady(state, now = Date.now()) {
  return !state.payload.enrollment?.payload.coding || !!state.payload.coding_ready && Date.parse(state.payload.coding_ready.ready.payload.expires_at) > now;
}
async function stdinLink(stdout) {
  stdout("Paste the private connection link, then press Enter (it is not placed in the command or shell history):\n");
  const { createInterface } = await import("readline");
  const reader = createInterface({ input: process.stdin, terminal: false });
  for await (const line3 of reader) {
    reader.close();
    need(line3.length <= 8e3, "connect_private_link_invalid");
    return line3.trim();
  }
  throw new RepositoryReceiverError("connect_private_link_required");
}
async function installReviewedConnection(state, receiver, coding, env, execute, readyJobId) {
  const execFileSync = execute ?? (await import("child_process")).execFileSync, s = state.payload, e = s.enrollment.payload, c = s.connection, a = s.authorization;
  need(c && a && Math.max(Date.parse(a.payload.expires_at), Date.parse(s.installation_renewal?.payload.expires_at ?? a.payload.expires_at)) > Date.now(), "connect_install_authorization_expired");
  need(await verifyRepositorySetupState(state, s.request.payload.authority_key, s.request.payload.owner_key) && receiver.public_key === c.payload.receiver_key, "connect_install_state_invalid");
  await importIdentity(receiver.private_key, receiver.public_key);
  const config = { type: "scopeblind.repository.guided-receiver-config.v1", endpoint: c.payload.endpoint, authority_key: c.payload.authority_key, connection: c, authorization: a };
  const gh = (args, input) => {
    try {
      return execFileSync("gh", args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 3e4, env });
    } catch {
      throw new RepositoryReceiverError("connect_install_refused", "GitHub refused an installation step. Repository protections are respected; rerun the same private checkpoint after resolving the reported repository access or workflow permissions.");
    }
  };
  const api = (path, method = "GET", input) => JSON.parse(gh(["api", "--method", method, path, ...input === void 0 ? [] : ["--input", "-"]], input === void 0 ? void 0 : JSON.stringify(input)) || "null");
  const repo3 = c.payload.repository, root = "/repos/" + repo3, installationFiles = [{ path: REPOSITORY_GUIDED_WORKFLOW, content: e.installation.workflow }, ...e.coding ? [{ path: ".github/workflows/scopeblind-coding.yml", content: e.coding.workflow }] : []];
  const metadata = api(root);
  need(object6(metadata) && object6(metadata.permissions) && metadata.permissions.admin === true && metadata.default_branch === c.payload.base_branch, "connect_install_repository_admin_required");
  if (e.coding) await preflightCodingPullRequests(repo3, () => api(root + "/actions/permissions/workflow"));
  const variables = api(root + "/actions/variables?per_page=30");
  need(object6(variables) && Array.isArray(variables.variables) && Number(variables.total_count) <= 30, "connect_variables_incomplete");
  const variableRows = variables.variables;
  const planned = [{ name: "SCOPEBLIND_GUIDED_CONNECTION", value: JSON.stringify(config) }, ...e.coding ? [{ name: "SCOPEBLIND_CODING_CONNECTION", value: JSON.stringify(e.coding.config) }] : []];
  const prior = e.replaces;
  need(!prior || await verifyRepositorySetupReplacement(prior, c.payload), "connect_replacement_invalid");
  for (const v of planned) {
    const old = variableRows.find((x) => object6(x) && x.name === v.name);
    need(!old || object6(old) && (old.value === v.value || v.name === "SCOPEBLIND_GUIDED_CONNECTION" && prior && old.value === JSON.stringify(prior)), "connect_existing_config_conflict");
  }
  const existing = /* @__PURE__ */ new Map();
  for (const file of installationFiles) {
    let value;
    try {
      value = api(root + "/contents/" + file.path + "?ref=" + encodeURIComponent(c.payload.base_branch));
    } catch (error) {
      const tree = api(root + "/git/trees/" + encodeURIComponent(c.payload.base_branch) + "?recursive=1");
      need(object6(tree) && tree.truncated === false && Array.isArray(tree.tree) && !tree.tree.some((x) => object6(x) && x.path === file.path), "connect_existing_workflow_unreadable");
      value = null;
    }
    if (value) {
      need(object6(value) && value.type === "file" && value.encoding === "base64" && typeof value.content === "string", "connect_existing_workflow_conflict");
      const oldBytes = Buffer.from(value.content, "base64").toString("utf8"), same = oldBytes === file.content;
      need(same || prior && file.path === REPOSITORY_GUIDED_WORKFLOW && await sha256(oldBytes) === prior.authorization.payload.workflow_sha256, "connect_existing_workflow_conflict");
      existing.set(file.path, { sha: String(value.sha), replace: !same });
    }
  }
  const secrets = api(root + "/actions/secrets?per_page=100");
  need(object6(secrets) && Array.isArray(secrets.secrets) && Number(secrets.total_count) <= 100, "connect_secrets_incomplete");
  for (const name2 of ["SCOPEBLIND_GUIDED_RECEIVER_KEY", ...e.coding ? ["SCOPEBLIND_CODING_WORKER_KEY"] : []]) {
    const exists = secrets.secrets.some((x) => object6(x) && x.name === name2);
    need(!exists || name2 === "SCOPEBLIND_GUIDED_RECEIVER_KEY" && prior || planned.every((v) => variableRows.some((x) => object6(x) && x.name === v.name && x.value === v.value)), "connect_existing_secret_conflict");
  }
  for (const file of installationFiles) if (!existing.has(file.path) || existing.get(file.path).replace) api(root + "/contents/" + file.path, "PUT", { message: "Install explicitly reviewed ScopeBlind connection", content: Buffer.from(file.content, "utf8").toString("base64"), branch: c.payload.base_branch, ...existing.has(file.path) ? { sha: existing.get(file.path).sha } : {} });
  for (const v of planned) gh(["variable", "set", v.name, "--repo", repo3], v.value);
  gh(["secret", "set", "SCOPEBLIND_GUIDED_RECEIVER_KEY", "--repo", repo3], receiver.private_key);
  if (e.coding) {
    need(coding && coding.public_key === e.coding.config.worker_key, "connect_coding_key_missing");
    gh(["secret", "set", "SCOPEBLIND_CODING_WORKER_KEY", "--repo", repo3], coding.private_key);
  }
  gh(["workflow", "run", "scopeblind-connection.yml", "--repo", repo3, "--ref", c.payload.base_branch, "-f", "job_id=" + (readyJobId ?? "ready-" + s.request.payload.id)]);
  if (e.coding) gh(["workflow", "run", "scopeblind-coding.yml", "--repo", repo3, "--ref", c.payload.base_branch, "-f", "job_id=" + s.request.payload.id]);
}
async function runRepositoryConnect(args, dependencies = {}) {
  const env = dependencies.env ?? process.env, fetchImpl = dependencies.fetchImpl ?? fetch, stdout = dependencies.stdout ?? ((s) => process.stdout.write(s));
  if (args[0] === "connection-job") return runConnectionJob(args.slice(1), env, fetchImpl, stdout);
  if (args[0] === "coding-ready") return runCodingReady(args.slice(1), env, fetchImpl, stdout);
  const flags = /* @__PURE__ */ new Set(), opts = /* @__PURE__ */ new Map();
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    if (["--link-stdin", "--install", "--replace-connection"].includes(flag)) {
      need(!flags.has(flag), "connect_duplicate_argument");
      flags.add(flag);
    } else {
      need(["--link", "--output", "--coding-test", "--coding-build", "--coding-preview", "--docker-image", "--receiver-key-file"].includes(flag) && !opts.has(flag) && !!args[i + 1], "connect_invalid_arguments");
      opts.set(flag, args[++i]);
    }
  }
  need(flags.has("--link-stdin") !== opts.has("--link"), "connect_private_link_required");
  const link = parseRepositoryConnectLink(flags.has("--link-stdin") ? await stdinLink(stdout) : opts.get("--link")), { mkdir, readFile, writeFile, rename, lstat } = await import("fs/promises"), { join, resolve } = await import("path"), { homedir } = await import("os");
  const dir = resolve(opts.get("--output") ?? join(homedir(), ".scopeblind", "connections", link.id));
  await mkdir(dir, { recursive: true, mode: 448 });
  const directory = await lstat(dir);
  need(directory.isDirectory() && !directory.isSymbolicLink() && (process.platform === "win32" || (directory.mode & 63) === 0), "connect_directory_permissions");
  need(!flags.has("--replace-connection") || opts.has("--receiver-key-file"), "connect_replacement_key_required");
  if (opts.has("--receiver-key-file")) {
    const imported = await privateKey(resolve(opts.get("--receiver-key-file")), true);
    try {
      const existing = await privateKey(join(dir, "receiver-key.json"), true);
      need(existing.public_key === imported.public_key, "connect_existing_key_conflict");
    } catch (error) {
      if (!(error instanceof RepositoryReceiverError) || error.code !== "connect_existing_key_missing") throw error;
      await writeFile(join(dir, "receiver-key.json"), JSON.stringify(imported) + "\n", { mode: 384, flag: "wx" });
    }
  }
  const key4 = await privateKey(join(dir, "receiver-key.json")), identity = await importIdentity(key4.private_key, key4.public_key), infoResponse = await fetchImpl(ENDPOINT + "?op=info", { redirect: "error", signal: AbortSignal.timeout(2e4) }), info = await json2(infoResponse, 1e4);
  need(infoResponse.ok && object6(info) && info.ok === true && typeof info.authority_key === "string" && REPOSITORY_HEX.test(info.authority_key), "connect_service_pin_invalid");
  const pin = info.authority_key;
  let state = await checkedState((await rpc(identity, "repository_setup_get", link.id, { secret: link.secret }, fetchImpl)).setup, pin), cp;
  const checkpoint = join(dir, "checkpoint.json");
  try {
    const stat = await lstat(checkpoint);
    need(stat.isFile() && !stat.isSymbolicLink() && (stat.mode & 63) === 0, "connect_checkpoint_permissions");
    cp = JSON.parse(await readFile(checkpoint, "utf8"));
    need(cp.setup_id === link.id && cp.authority_key === pin && cp.owner_key === state.payload.request.payload.owner_key && cp.secret === link.secret, "connect_checkpoint_mismatch");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    cp = { type: "scopeblind.repository.connect-checkpoint.v1", setup_id: link.id, authority_key: pin, owner_key: state.payload.request.payload.owner_key, secret: link.secret };
  }
  const persist = async () => {
    const temp = checkpoint + "." + crypto.randomUUID() + ".tmp";
    await writeFile(temp, JSON.stringify(cp) + "\n", { mode: 384, flag: "wx" });
    await rename(temp, checkpoint);
  };
  await persist();
  need(!["revoked", "expired", "replacement_pending", "superseded"].includes(state.payload.status), "connect_setup_inactive");
  if (state.payload.status === "awaiting_github") throw new RepositoryReceiverError("connect_github_authorization_pending", "Finish the GitHub authorization in the original browser, then run this same command again.");
  const token = await githubToken(env), preparedCoding = cp.enrollment?.payload.coding?.config, preparedReplaces = cp.enrollment?.payload.replaces, explicitCoding = ["--coding-test", "--coding-build", "--coding-preview", "--docker-image"].some((k) => opts.has(k)), codingRequested = explicitCoding || !!preparedCoding;
  if (explicitCoding) need(["--coding-test", "--coding-build", "--coding-preview", "--docker-image"].every((k) => opts.has(k)), "connect_complete_coding_config_required");
  if (codingRequested) await preflightCodingPullRequests(state.payload.request.payload.repository, async () => {
    const result = await github("/repos/" + state.payload.request.payload.repository + "/actions/permissions/workflow", token, fetchImpl);
    return result.status === 200 ? result.body : null;
  });
  let codingKey;
  if (codingRequested || cp.enrollment?.payload.coding) codingKey = await privateKey(join(dir, "coding-key.json"));
  const refreshEnrollment = !!cp.enrollment && uncommittedSetupEnrollmentStale(cp.enrollment, state);
  if (refreshEnrollment) {
    stdout("The earlier enrollment was never recorded and its observations are stale. Refreshing the same receiver and repository inspection before browser review.\n");
  }
  if (!cp.enrollment || refreshEnrollment) {
    const request = state.payload.request, { discovery, inspection } = await inspectRepositorySetup(request, identity, token, fetchImpl), issued = Date.now(), connection = { type: "scopeblind.repository.connection.v1", id: link.id, endpoint: ENDPOINT, repository: request.payload.repository, base_branch: discovery.base_branch, owner_key: request.payload.owner_key, receiver_key: identity.publicKey, authority_key: pin, issued_at: new Date(issued).toISOString(), expires_at: new Date(issued + 30 * 864e5).toISOString() }, receiverUrl = "https://scopeblind.com/releases/repository-receiver-0.24.0.cjs", receiverHash = await artifact(receiverUrl, fetchImpl), workflow = renderGuidedReceiverWorkflow({ url: receiverUrl, sha256: receiverHash }), readiness = await createRepositoryReadiness(connection, identity, discovery, { workflow_sha256: await sha256(workflow) });
    let coding;
    if (codingRequested) {
      let test, build;
      try {
        test = opts.has("--coding-test") ? JSON.parse(opts.get("--coding-test")) : preparedCoding.test_command;
        build = opts.has("--coding-build") ? JSON.parse(opts.get("--coding-build")) : preparedCoding.build_command;
      } catch {
        throw new RepositoryReceiverError("connect_coding_commands_json_required");
      }
      const config = { type: "scopeblind.repository.coding-config.v1", endpoint: ENDPOINT, authority_key: pin, worker_key: codingKey.public_key, repository: connection.repository, base_branch: connection.base_branch, runtime: "node22-static-v1", test_command: test, build_command: build, preview_directory: opts.get("--coding-preview") ?? preparedCoding.preview_directory, docker_image: opts.get("--docker-image") ?? preparedCoding.docker_image };
      need(validRepositoryCodingConnectionConfig(config), "connect_coding_config_invalid");
      const artifactUrl = "https://scopeblind.com/releases/repository-coding-0.24.0.cjs", artifactHash = await artifact(artifactUrl, fetchImpl), codingWorkflow = renderGuidedCodingWorkflow({ url: artifactUrl, sha256: artifactHash }, { url: receiverUrl, sha256: receiverHash });
      coding = { config, workflow: codingWorkflow, workflow_sha256: await sha256(codingWorkflow), artifact_url: artifactUrl, artifact_sha256: artifactHash };
    }
    let replaces;
    if (flags.has("--replace-connection") || preparedReplaces) {
      const current = (await github("/repos/" + connection.repository + "/actions/variables/SCOPEBLIND_GUIDED_CONNECTION", token, fetchImpl)).body;
      need(object6(current) && typeof current.value === "string", "connect_replacement_config_missing");
      try {
        replaces = JSON.parse(current.value);
      } catch {
        throw new RepositoryReceiverError("connect_replacement_invalid");
      }
      need(await verifyRepositorySetupReplacement(replaces, connection), "connect_replacement_scope_mismatch");
      const previous = await checkedState((await rpc(identity, "repository_setup_get", replaces.connection.payload.id, {}, fetchImpl)).setup, pin, cp.owner_key);
      need(previous.payload.connection?.digest === replaces.connection.digest && previous.payload.authorization?.digest === replaces.authorization.digest && !previous.payload.blocking_jobs && !previous.payload.enrollment?.payload.coding && !["revoked", "superseded", "replacement_pending"].includes(previous.payload.status), "connect_replacement_busy_or_incompatible");
      stdout(`Replace connection ${replaces.connection.payload.id} with ${connection.id}, retaining receiver ${identity.publicKey}. The browser will show the exact old and new workflow pins before authorizing this transition.
`);
    }
    cp.enrollment = await sign({ type: "scopeblind.repository.setup-enrollment.v1", setup_id: link.id, setup_digest: request.digest, receiver_key: identity.publicKey, connection, readiness: readiness.readiness, inspection, installation: { workflow_path: REPOSITORY_GUIDED_WORKFLOW, workflow, workflow_sha256: await sha256(workflow), receiver_url: receiverUrl, receiver_sha256: receiverHash, secret_name: "SCOPEBLIND_GUIDED_RECEIVER_KEY", variable_name: "SCOPEBLIND_GUIDED_CONNECTION" }, ...coding ? { coding } : {}, ...replaces ? { replaces } : {}, issued_at: date() }, identity);
    await persist();
  }
  need(await verifyRepositorySetupEnrollment(cp.enrollment, state.payload.request), "connect_local_enrollment_invalid");
  if (state.payload.enrollment) {
    need(state.payload.enrollment.digest === cp.enrollment.digest, "connect_enrollment_conflict");
  } else state = await checkedState((await rpc(identity, "repository_setup_enroll", link.id, { secret: link.secret, enrollment: cp.enrollment }, fetchImpl)).setup, pin, cp.owner_key);
  stdout(`Prepared ${cp.enrollment.payload.connection.repository} PR #${state.payload.request.payload.pull_number}. Receiver public key: ${identity.publicKey}
Review the exact workflow, permissions, and repository changes in your original browser. Nothing has been installed yet.
`);
  if (!flags.has("--install")) {
    stdout("To install only after that signed browser confirmation, rerun this command with --install.\n");
    return;
  }
  const deadline = Date.now() + (state.payload.authorization ? 15 * 6e4 : Math.min(15 * 6e4, Math.max(0, Date.parse(state.payload.request.payload.expires_at) - Date.now())));
  if (state.payload.status === "installation_expired") stdout("The exact installation authorization expired. Review and authorize the same installation again in the original browser; this checkpoint and receiver key will be reused.\n");
  while (!state.payload.authorization || !cp.installed && Math.max(Date.parse(state.payload.authorization.payload.expires_at), Date.parse(state.payload.installation_renewal?.payload.expires_at ?? state.payload.authorization.payload.expires_at)) <= Date.now()) {
    need(Date.now() < deadline, "connect_confirmation_timed_out");
    await new Promise((r) => setTimeout(r, 2e3));
    state = await checkedState((await rpc(identity, "repository_setup_get", link.id, {}, fetchImpl)).setup, pin, cp.owner_key);
    need(!["revoked", "expired", "replacement_pending", "superseded"].includes(state.payload.status), "connect_setup_inactive");
  }
  const resumeInstalled = !!cp.installed;
  const prepareReadyJob = async () => {
    if (!cp.readiness_job_id) {
      cp.readiness_job_id = "ready-" + crypto.randomUUID();
      await persist();
    }
    let reply = await rpc(identity, "repository_setup_dispatch", link.id, { operation: "ready", job_id: cp.readiness_job_id }, fetchImpl), job = reply.job;
    need(validRepositoryEnvelope(job) && await verify(job, pin) && job.payload.job.payload.setup_id === link.id, "connect_ready_job_unverified");
    if (Date.parse(job.payload.job.payload.expires_at) <= Date.now() || job.payload.status === "failed") {
      cp.readiness_job_id = "ready-" + crypto.randomUUID();
      await persist();
      reply = await rpc(identity, "repository_setup_dispatch", link.id, { operation: "ready", job_id: cp.readiness_job_id }, fetchImpl);
      job = reply.job;
      need(validRepositoryEnvelope(job) && await verify(job, pin) && job.payload.job.payload.setup_id === link.id && Date.parse(job.payload.job.payload.expires_at) > Date.now(), "connect_ready_job_unverified");
    }
    return cp.readiness_job_id;
  };
  if (!cp.installed) {
    await installReviewedConnection(state, key4, codingKey, env, void 0, await prepareReadyJob());
    cp.installed = true;
    await persist();
    stdout("The reviewed receiver was installed and its readiness workflow was started. Waiting for a signed GitHub Actions response.\n");
  }
  if (resumeInstalled && (state.payload.status !== "ready" || !currentGuidedCodingReady(state))) {
    const recoveryId = await prepareReadyJob();
    const { execFileSync } = await import("child_process");
    execFileSync("gh", ["workflow", "run", "scopeblind-connection.yml", "--repo", cp.enrollment.payload.connection.repository, "--ref", cp.enrollment.payload.connection.base_branch, "-f", "job_id=" + recoveryId], { env, stdio: ["ignore", "pipe", "pipe"], timeout: 3e4 });
    if (cp.enrollment.payload.coding) execFileSync("gh", ["workflow", "run", "scopeblind-coding.yml", "--repo", cp.enrollment.payload.connection.repository, "--ref", cp.enrollment.payload.connection.base_branch, "-f", "job_id=" + link.id], { env, stdio: ["ignore", "pipe", "pipe"], timeout: 3e4 });
  }
  const readyDeadline = Date.now() + 8 * 6e4;
  while (state.payload.status !== "ready" || !currentGuidedCodingReady(state)) {
    need(Date.now() < readyDeadline, "connect_workflow_response_pending");
    await new Promise((r) => setTimeout(r, 3e3));
    state = await checkedState((await rpc(identity, "repository_setup_get", link.id, {}, fetchImpl)).setup, pin, cp.owner_key);
    need(!["revoked", "expired", "replacement_pending", "superseded"].includes(state.payload.status), "connect_setup_inactive");
  }
  stdout("Connection ready. The browser has the real PR inspection and a verified Actions readiness response. No task was approved or merged.\n");
}
function cliOptions(args, allowed) {
  const out = /* @__PURE__ */ new Map();
  for (let i = 0; i < args.length; i += 2) {
    need(allowed.includes(args[i]) && !out.has(args[i]) && !!args[i + 1], "connect_runtime_arguments");
    out.set(args[i], args[i + 1]);
  }
  return out;
}
async function loadGuidedConfig(file) {
  const { readFile } = await import("fs/promises");
  const c = JSON.parse(await readFile(file, "utf8"));
  need(c.type === "scopeblind.repository.guided-receiver-config.v1" && c.endpoint === ENDPOINT && REPOSITORY_HEX.test(c.authority_key) && validRepositoryEnvelope(c.connection) && validRepositoryEnvelope(c.authorization) && c.connection.payload.endpoint === c.endpoint && c.connection.payload.authority_key === c.authority_key && validRepositorySetupAuthorization(c.authorization.payload) && c.authorization.payload.connection_digest === c.connection.digest && c.authorization.payload.owner_key === c.connection.payload.owner_key && await verify(c.connection, c.connection.payload.owner_key) && await verify(c.authorization, c.connection.payload.owner_key), "connect_runtime_config_invalid");
  return c;
}
async function oidc(audience, env, fetchImpl) {
  need(env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, "connect_actions_oidc_required");
  const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  need(url.protocol === "https:" && url.hostname.endsWith(".actions.githubusercontent.com") && !url.username && !url.password, "connect_actions_oidc_url_invalid");
  url.searchParams.set("audience", audience);
  const response = await fetchImpl(url, { headers: { authorization: "Bearer " + env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }, redirect: "error", signal: AbortSignal.timeout(2e4) }), value = await json2(response, 4e4);
  need(response.ok && object6(value) && typeof value.value === "string", "connect_actions_oidc_unavailable");
  return value.value;
}
async function runtimeState(config, identity, fetchImpl) {
  const state = await checkedState((await rpc(identity, "repository_setup_get", config.authorization.payload.setup_id, {}, fetchImpl)).setup, config.authority_key, config.connection.payload.owner_key);
  need(state.payload.connection?.digest === config.connection.digest && state.payload.authorization?.digest === config.authorization.digest && !["expired", "revoked"].includes(state.payload.status), "connect_runtime_scope_mismatch");
  return state;
}
async function observeGuidedReadiness(state, identity, token, fetchImpl = fetch) {
  const s = state.payload, c = s.connection.payload;
  if (s.initial_ready || s.ready) {
    const pull = await github(`/repos/${c.repository}/pulls/${s.request.payload.pull_number}`, token, fetchImpl);
    if (pull.status === 200 && object6(pull.body) && (pull.body.state === "closed" || pull.body.merged === true)) {
      const discovery = await discoverRepository({ repository: c.repository, base_branch: c.base_branch, workflow_path: REPOSITORY_GUIDED_WORKFLOW }, token, fetchImpl);
      return { discovery, inspection: null };
    }
  }
  return inspectRepositorySetup(s.request, identity, token, fetchImpl);
}
async function runReady(config, identity, env, fetchImpl) {
  const state = await runtimeState(config, identity, fetchImpl), s = state.payload, token = await githubToken(env), current = await observeGuidedReadiness(state, identity, token, fetchImpl), c = config.connection.payload, challenge = s.challenge;
  need(challenge && Date.parse(challenge.expires_at) > Date.now() && env.GITHUB_ACTIONS === "true" && env.GITHUB_REPOSITORY === c.repository && env.GITHUB_EVENT_NAME === "workflow_dispatch" && env.GITHUB_REF === `refs/heads/${c.base_branch}` && env.GITHUB_WORKFLOW_REF === `${c.repository}/${REPOSITORY_GUIDED_WORKFLOW}@refs/heads/${c.base_branch}` && current.discovery.workflow_sha256 === config.authorization.payload.workflow_sha256 && env.GITHUB_WORKFLOW_SHA && REPOSITORY_SHA.test(env.GITHUB_WORKFLOW_SHA), "connect_trusted_workflow_required");
  const readiness = await createRepositoryReadiness(c, identity, current.discovery, { runtime: "github_actions", workflow_sha256: config.authorization.payload.workflow_sha256 }), ready = await sign({ type: "scopeblind.repository.setup-ready.v1", setup_id: s.request.payload.id, setup_digest: s.request.digest, connection_digest: config.connection.digest, authorization_digest: config.authorization.digest, challenge_id: challenge.id, receiver_key: identity.publicKey, readiness: readiness.readiness, inspection: current.inspection, run_id: Number(env.GITHUB_RUN_ID), run_attempt: Number(env.GITHUB_RUN_ATTEMPT), workflow_ref: env.GITHUB_WORKFLOW_REF, workflow_sha: env.GITHUB_WORKFLOW_SHA, observed_at: date() }, identity);
  await checkedState((await rpc(identity, "repository_setup_ready", s.request.payload.id, { ready, oidc_token: await oidc(challenge.audience, env, fetchImpl) }, fetchImpl)).setup, config.authority_key, c.owner_key);
}
async function runCodingReady(args, env, fetchImpl, stdout) {
  const opts = cliOptions(args, ["--connection", "--coding"]);
  need(opts.get("--connection") && opts.get("--coding"), "connect_runtime_arguments");
  const config = await loadGuidedConfig(opts.get("--connection")), { readFile } = await import("fs/promises"), coding = JSON.parse(await readFile(opts.get("--coding"), "utf8"));
  need(validRepositoryCodingConnectionConfig(coding) && env.SCOPEBLIND_CODING_WORKER_KEY, "connect_coding_config_invalid");
  const identity = await importIdentity(env.SCOPEBLIND_CODING_WORKER_KEY, coding.worker_key), state = await runtimeState(config, identity, fetchImpl), s = state.payload, e = s.enrollment.payload, challenge = s.challenge;
  need(e.coding && canonical(e.coding.config) === canonical(coding) && challenge && Date.parse(challenge.expires_at) > Date.now(), "connect_coding_scope_mismatch");
  const discovery = await discoverRepository({ repository: coding.repository, base_branch: coding.base_branch, workflow_path: ".github/workflows/scopeblind-coding.yml" }, await githubToken(env), fetchImpl), workflowRef = `${coding.repository}/.github/workflows/scopeblind-coding.yml@refs/heads/${coding.base_branch}`;
  need(env.GITHUB_ACTIONS === "true" && env.GITHUB_REPOSITORY === coding.repository && env.GITHUB_EVENT_NAME === "workflow_dispatch" && env.GITHUB_REF === `refs/heads/${coding.base_branch}` && env.GITHUB_WORKFLOW_REF === workflowRef && discovery.workflow_sha256 === e.coding.workflow_sha256 && env.GITHUB_WORKFLOW_SHA && REPOSITORY_SHA.test(env.GITHUB_WORKFLOW_SHA), "connect_trusted_coding_workflow_required");
  const ready = await sign({ type: "scopeblind.repository.setup-coding-ready.v1", setup_id: s.request.payload.id, setup_digest: s.request.digest, connection_digest: config.connection.digest, coding_digest: await sha256(canonical(coding)), worker_key: coding.worker_key, challenge_id: challenge.id, run_id: Number(env.GITHUB_RUN_ID), run_attempt: Number(env.GITHUB_RUN_ATTEMPT), workflow_ref: workflowRef, workflow_sha: env.GITHUB_WORKFLOW_SHA, observed_at: date(), expires_at: new Date(Math.min(Date.now() + 864e5, Date.parse(config.connection.payload.expires_at))).toISOString() }, identity);
  await checkedState((await rpc(identity, "repository_setup_coding_ready", s.request.payload.id, { ready, oidc_token: await oidc(challenge.audience, env, fetchImpl) }, fetchImpl)).setup, config.authority_key, config.connection.payload.owner_key);
  stdout("The exact coding controller responded from its installed workflow. No code-edit mandate or task approval was granted.\n");
}
async function runConnectionJob(args, env, fetchImpl, stdout) {
  const opts = cliOptions(args, ["--connection", "--job"]);
  need(opts.get("--connection") && opts.get("--job") && REPOSITORY_ID.test(opts.get("--job")), "connect_runtime_arguments");
  const config = await loadGuidedConfig(opts.get("--connection"));
  need(env.SCOPEBLIND_RECEIVER_PRIVATE_KEY, "connect_receiver_key_required");
  const identity = await importIdentity(env.SCOPEBLIND_RECEIVER_PRIVATE_KEY, config.connection.payload.receiver_key), lease = crypto.randomUUID(), jobId = opts.get("--job"), reply = await rpc(identity, "repository_setup_job_get", jobId, { lease_id: lease }, fetchImpl), wrapper = reply.job;
  need(validRepositoryEnvelope(wrapper) && await verify(wrapper, config.authority_key) && Math.abs(Date.now() - Date.parse(wrapper.payload.observed_at)) < 12e4 && validRepositoryEnvelope(wrapper.payload.job) && await verify(wrapper.payload.job, config.authority_key), "connect_job_unverified");
  const j = wrapper.payload.job.payload;
  need(j.id === jobId && j.setup_id === config.authorization.payload.setup_id && j.connection_digest === config.connection.digest && j.owner_key === config.connection.payload.owner_key && j.receiver_key === identity.publicKey, "connect_job_scope_mismatch");
  if (wrapper.payload.status === "completed") {
    stdout("This exact connection job already completed.\n");
    return;
  }
  need(Date.parse(j.expires_at) > Date.now(), "connect_job_expired");
  try {
    if (j.operation === "ready") await runReady(config, identity, env, fetchImpl);
    else {
      need(j.task_id && REPOSITORY_ID.test(j.task_id), "connect_job_task_missing");
      const stateReply = await rpc(identity, "repository_get", j.task_id, {}, fetchImpl), state = stateReply.repository_task;
      need((await verifyRepositoryEvidence({ type: "scopeblind.repository.evidence.v1", state }, config.authority_key)).valid, "connect_task_unverified");
      const t = state.payload.task.payload, reviewer = state.payload.reviewer?.payload.reviewer_key;
      need(t.owner_key === j.owner_key && t.receiver_key === identity.publicKey && t.repository === config.connection.payload.repository && t.base_branch === config.connection.payload.base_branch && reviewer, "connect_task_scope_mismatch");
      const companion = await rpc(identity, "repository_collaboration_get", j.task_id, {}, fetchImpl), collaboration = companion.collaboration;
      need(validRepositoryEnvelope(collaboration) && await verify(collaboration, config.authority_key), "connect_binding_unverified");
      let bound = false;
      const participants = collaboration.payload.participants;
      if (participants) bound = await verify(participants, t.owner_key) && participants.payload.task_digest === state.payload.task.digest && participants.payload.reviewer_key === reviewer && participants.payload.receiver_key === identity.publicKey && participants.payload.owner_key === t.owner_key;
      if (!bound) {
        const context = reply.task_binding;
        if (context && validRepositoryEnvelope(context) && await verify(context, config.authority_key) && context.payload.type === "scopeblind.repository.setup-task-binding.v1" && context.payload.task_id === j.task_id && context.payload.task_digest === state.payload.task.digest && Math.abs(Date.now() - Date.parse(context.payload.observed_at)) < 12e4) {
          const source = context.payload.assignment;
          if (validRepositoryEnvelope(source) && await verify(source, t.owner_key)) {
            const a = source.payload;
            bound = context.payload.active && a.task_id === j.task_id && a.task_digest === state.payload.task.digest && a.owner_key === t.owner_key && a.reviewer_key === reviewer && Date.parse(a.expires_at) > Date.now();
          }
        }
      }
      need(bound || j.operation === "reconcile" && state.payload.execution, "connect_owner_participant_binding_required");
      const receiver = new RepositoryReceiver({ type: "scopeblind.repository.receiver-config.v1", endpoint: config.endpoint, authority_key: config.authority_key, repository: t.repository, base_branch: t.base_branch, owner_key: t.owner_key, reviewer_key: reviewer, receiver_key: identity.publicKey }, identity, await githubToken(env), fetchImpl);
      if (j.operation === "inspect") {
        await receiver.inspect(j.task_id, jobId);
      } else if (j.operation === "execute") await receiver.execute(j.task_id);
      else if (j.operation === "reconcile") await receiver.reconcile(j.task_id);
      else throw new RepositoryReceiverError("connect_job_operation_invalid");
    }
    await rpc(identity, "repository_setup_job_complete", jobId, { lease_id: lease, status: "completed" }, fetchImpl);
    stdout("The exact signed connection job completed.\n");
  } catch (error) {
    await rpc(identity, "repository_setup_job_complete", jobId, { lease_id: lease, status: "failed", error: error instanceof RepositoryReceiverError && /^[a-z0-9_]{1,100}$/.test(error.code) ? error.code : "connect_runtime_failed" }, fetchImpl).catch(() => {
    });
    throw error;
  }
}
var ENDPOINT, object6, date;
var init_repository_connect = __esm({
  "src/repository-connect.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository_connection();
    init_coordination_repository();
    init_repository_receiver();
    init_repository_setup();
    init_repository_review_preview();
    init_repository_connect_workflow();
    ENDPOINT = "https://scopeblind.com/api/coordination";
    object6 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    date = () => (/* @__PURE__ */ new Date()).toISOString();
  }
});

// src/repository-setup.ts
function need2(v, code) {
  if (!v) throw new RepositoryReceiverError(code);
}
async function readJson(response, max = 2e6) {
  const reader = response.body?.getReader();
  need2(reader, "setup_empty_response");
  const parts = [];
  let size = 0;
  try {
    for (; ; ) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.length;
      if (size > max) {
        await reader.cancel();
        throw new RepositoryReceiverError("setup_response_too_large");
      }
      parts.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(out));
  } catch {
    throw new RepositoryReceiverError("setup_invalid_json");
  }
}
async function github2(path, token, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(`https://api.github.com${path}`, { method: "GET", headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2026-03-10" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
  } catch {
    throw new RepositoryReceiverError("setup_github_unavailable");
  }
  if ([403, 404].includes(response.status)) return { status: response.status, body: null };
  need2(response.ok, `setup_github_http_${response.status}`);
  return { status: response.status, body: await readJson(response) };
}
async function discoverRepository(input, token, fetchImpl = fetch) {
  need2(REPO.test(input.repository) && token.length > 0, "setup_repository_and_github_login_required");
  if (input.pull_number !== void 0) need2(Number.isSafeInteger(input.pull_number) && input.pull_number > 0, "setup_invalid_pull_number");
  const path = `/repos/${input.repository.split("/").map(encodeURIComponent).join("/")}`;
  const repo3 = await github2(path, token, fetchImpl);
  need2(repo3.status === 200 && REPO.test(repo3.body.full_name) && repo3.body.full_name.toLowerCase() === input.repository.toLowerCase() && repositoryBranch(repo3.body.default_branch) && !repo3.body.archived && !repo3.body.disabled, "setup_repository_unavailable");
  const base = input.base_branch ?? repo3.body.default_branch;
  need2(repositoryBranch(base) && base === repo3.body.default_branch, "setup_use_trusted_default_branch");
  const branch = await github2(`${path}/branches/${encodeURIComponent(base)}`, token, fetchImpl);
  need2(branch.status === 200 && branch.body.name === base && REPOSITORY_SHA.test(branch.body.commit?.sha), "setup_base_branch_unavailable");
  let head = branch.body.commit.sha;
  if (input.pull_number) {
    const pr = await github2(`${path}/pulls/${input.pull_number}`, token, fetchImpl);
    need2(pr.status === 200 && pr.body.number === input.pull_number && pr.body.state === "open" && !pr.body.merged && pr.body.base?.ref === base && pr.body.base?.repo?.full_name === repo3.body.full_name && pr.body.head?.repo?.full_name === repo3.body.full_name && REPOSITORY_SHA.test(pr.body.head?.sha), "setup_same_repository_pull_required");
    head = pr.body.head.sha;
  }
  const [runs, protection, rules, workflow] = await Promise.all([
    github2(`${path}/commits/${head}/check-runs?per_page=100&filter=latest`, token, fetchImpl),
    github2(`${path}/branches/${encodeURIComponent(base)}/protection`, token, fetchImpl),
    github2(`${path}/rules/branches/${encodeURIComponent(base)}`, token, fetchImpl),
    github2(`${path}/contents/${input.workflow_path ?? WORKFLOW_PATH}?ref=${encodeURIComponent(base)}`, token, fetchImpl)
  ]);
  need2(runs.status === 200 && Number.isSafeInteger(runs.body.total_count) && runs.body.total_count >= 0 && runs.body.total_count <= 100 && Array.isArray(runs.body.check_runs) && runs.body.check_runs.length === runs.body.total_count, "setup_checks_incomplete");
  const checks2 = [];
  for (const run of runs.body.check_runs) {
    need2(run.head_sha === head && safeText(run.name, 100) && Number.isSafeInteger(run.app?.id) && run.app.id > 0, "setup_invalid_check_provider");
    if (!checks2.some((c) => c.name === run.name && c.app_id === run.app.id)) checks2.push({ name: run.name, app_id: run.app.id, ...safeText(run.app.name, 100) ? { app_name: run.app.name } : {} });
  }
  need2(checks2.length <= 100, "setup_checks_incomplete");
  checks2.sort((a, b) => a.name.localeCompare(b.name) || a.app_id - b.app_id);
  const required = [];
  const add = (name2, id7) => {
    need2(safeText(name2, 100) && (id7 === null || id7 === void 0 || id7 === -1 || Number.isSafeInteger(id7) && Number(id7) > 0), "setup_invalid_required_check");
    const check = { name: name2, app_id: Number.isSafeInteger(id7) && Number(id7) > 0 ? Number(id7) : null };
    if (!required.some((c) => c.name === check.name && c.app_id === check.app_id)) required.push(check);
    need2(required.length <= 100, "setup_rules_incomplete");
  };
  if (protection.status === 200) {
    const status2 = protection.body.required_status_checks;
    if (status2) {
      need2(Array.isArray(status2.contexts) && Array.isArray(status2.checks), "setup_invalid_branch_protection");
      for (const c of status2.checks) add(c.context, c.app_id);
      for (const context of status2.contexts) if (!status2.checks.some((c) => c.context === context)) add(context, null);
    }
  }
  if (rules.status === 200) {
    need2(Array.isArray(rules.body) && rules.body.length <= 100, "setup_rules_incomplete");
    for (const rule of rules.body) if (rule.type === "required_status_checks") {
      need2(Array.isArray(rule.parameters?.required_status_checks), "setup_invalid_repository_rules");
      for (const c of rule.parameters.required_status_checks) add(c.context, c.integration_id);
    }
  }
  let workflowSha, workflowHash;
  if (workflow.status === 200) {
    need2(workflow.body.type === "file" && workflow.body.path === (input.workflow_path ?? WORKFLOW_PATH) && REPOSITORY_SHA.test(workflow.body.sha) && workflow.body.encoding === "base64" && typeof workflow.body.content === "string" && workflow.body.content.length <= 1e5, "setup_invalid_workflow_response");
    workflowSha = workflow.body.sha;
    workflowHash = await sha256(Buffer.from(workflow.body.content, "base64").toString("utf8"));
  }
  const warnings = [];
  if (!checks2.length) warnings.push("No check runs were observed on this commit. Run the repository\u2019s existing CI or repeat setup with --pull NUMBER; do not invent a check name or provider.");
  if (protection.status !== 200 || rules.status !== 200) warnings.push("Some repository protection requirements could not be read. This does not mean the branch is unprotected; review its rules in GitHub.");
  if (required.some((c) => c.app_id === null)) warnings.push("Some required status checks do not pin an app. Select the actual observed provider explicitly; setup does not treat an unpinned name as a verified provider.");
  if (required.some((c) => !checks2.some((o) => o.name === c.name && (c.app_id === null || o.app_id === c.app_id)))) warnings.push("Some required checks were not observed on this commit. Repeat discovery on a representative pull request before choosing task requirements.");
  if (checks2.some((c) => checks2.some((other) => other.name === c.name && other.app_id !== c.app_id))) warnings.push("A check name is used by more than one app. Review the provider ID as well as the name.");
  return { repository: repo3.body.full_name, base_branch: base, base_sha: branch.body.commit.sha, observed_head_sha: head, checks: checks2, required_checks: required, protection_read: protection.status === 200 ? "observed" : "unavailable", rules_read: rules.status === 200 ? "observed" : "unavailable", repository_permissions: repo3.body.permissions ? { admin: repo3.body.permissions.admin === true, push: repo3.body.permissions.push === true } : null, workflow_state: workflow.status === 200 ? "present" : workflow.status === 404 ? "absent" : "not_checked", ...workflowSha ? { workflow_sha: workflowSha, workflow_sha256: workflowHash } : {}, warnings };
}
function endpoint(value) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new RepositoryReceiverError("setup_invalid_endpoint");
  }
  need2(url.protocol === "https:" && url.pathname === "/api/coordination" && !url.username && !url.password && !url.search && !url.hash && url.href === value, "setup_invalid_endpoint");
  return url.href;
}
function parseRepositoryConnectionConfig(value) {
  const c = value, t = c?.connection;
  need2(c && Object.keys(c).sort().join(",") === "connection,receiver_sha256,receiver_url,type,workflow_path,workflow_sha256" && c.type === "scopeblind.repository.connection-config.v1" && t && Object.keys(t).sort().join(",") === "authority_key,base_branch,endpoint,expires_at,id,issued_at,owner_key,receiver_key,repository,type", "setup_invalid_connection_config");
  need2(validRepositoryConnection(t), "setup_invalid_connection_config");
  endpoint(t.endpoint);
  need2(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(c.receiver_url) && REPOSITORY_HEX.test(c.receiver_sha256) && c.workflow_path === WORKFLOW_PATH && REPOSITORY_HEX.test(c.workflow_sha256), "setup_invalid_artifact_pin");
  return c;
}
function renderRepositoryWorkflow(artifact2) {
  need2(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(artifact2.url) && REPOSITORY_HEX.test(artifact2.sha256), "setup_invalid_artifact_pin");
  return WORKFLOW_TEMPLATE.replace("__RECEIVER_URL__", artifact2.url).replace("__RECEIVER_SHA256__", artifact2.sha256);
}
async function createRepositoryReadiness(connection, identity, discovery, options = {}) {
  const now = options.now ?? Date.now();
  need2(identity.publicKey === connection.receiver_key && !identity.deviceAuthorization && discovery.repository === connection.repository && discovery.base_branch === connection.base_branch && Date.parse(connection.expires_at) > now, "setup_connection_scope_mismatch");
  const workflow = discovery.workflow_state === "absent" ? "missing" : discovery.workflow_state === "not_checked" ? "unavailable" : !options.workflow_sha256 ? "not_checked" : discovery.workflow_sha256 === options.workflow_sha256 ? "matching" : "different";
  const readiness = { type: "scopeblind.repository.readiness.v1", connection_digest: await sha256(COORDINATION_DOMAIN + canonical(connection)), repository: connection.repository, base_branch: connection.base_branch, owner_key: connection.owner_key, receiver_key: identity.publicKey, authority_key: connection.authority_key, checks: discovery.checks, base_sha: discovery.base_sha, check_head_sha: discovery.observed_head_sha, required_checks: discovery.required_checks, protection: discovery.protection_read, runtime: options.runtime ?? "local", workflow, ...discovery.workflow_sha ? { workflow_sha: discovery.workflow_sha } : {}, observed_at: new Date(now).toISOString(), expires_at: new Date(Math.min(now + 864e5, Date.parse(connection.expires_at))).toISOString() };
  need2(validRepositoryConnection(connection) && validRepositoryReadiness(readiness), "setup_invalid_readiness");
  return { type: "scopeblind.repository.connection-import.v1", connection, readiness: await sign(readiness, identity) };
}
async function githubToken2(env) {
  const value = env.GITHUB_TOKEN || env.GH_TOKEN;
  if (value) {
    need2(!/[\r\n\u0000]/.test(value), "setup_invalid_github_token");
    return value;
  }
  const { execFile } = await import("child_process");
  const token = await new Promise((resolve, reject) => execFile("gh", ["auth", "token", "--hostname", "github.com"], { encoding: "utf8", timeout: 1e4, maxBuffer: 8192, env }, (error, stdout) => error ? reject(new RepositoryReceiverError("setup_github_login_required", "Sign in locally with gh auth login, or set GITHUB_TOKEN on this trusted machine.")) : resolve(stdout.trim())));
  need2(token.length > 0 && !/[\r\n\u0000]/.test(token), "setup_github_login_required");
  return token;
}
async function localIdentity(file, expected, env) {
  const { readFile, stat } = await import("fs/promises");
  let privateKey2 = env.SCOPEBLIND_RECEIVER_PRIVATE_KEY, publicKey = expected;
  if (file) {
    const meta = await stat(file);
    need2(meta.isFile() && (process.platform === "win32" || (meta.mode & 63) === 0), "setup_private_key_permissions");
    let key4;
    try {
      key4 = JSON.parse(await readFile(file, "utf8"));
    } catch {
      throw new RepositoryReceiverError("setup_invalid_private_key_file");
    }
    need2(key4.type === "scopeblind.repository.receiver-key.v1" && (!expected || key4.public_key === expected), "receiver_key_mismatch");
    privateKey2 = key4.private_key;
    publicKey = key4.public_key;
  }
  need2(typeof privateKey2 === "string" && /^[0-9a-f]{96,300}$/.test(privateKey2) && typeof publicKey === "string" && REPOSITORY_HEX.test(publicKey), "receiver_private_key_required");
  try {
    return await importIdentity(privateKey2, publicKey);
  } catch {
    throw new RepositoryReceiverError("receiver_key_mismatch");
  }
}
async function checkServicePin(url, pin, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(`${endpoint(url)}?op=info`, { method: "GET", redirect: "error", signal: AbortSignal.timeout(2e4) });
  } catch {
    throw new RepositoryReceiverError("setup_service_unavailable");
  }
  const info = await readJson(response, 1e4);
  need2(response.ok && info.ok === true && info.authority_key === pin && info.protocol === "scopeblind.coordination.v1", "setup_service_pin_mismatch");
}
async function artifactPin(url, pin, fetchImpl) {
  need2(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(url), "setup_invalid_artifact_pin");
  if (pin) {
    need2(REPOSITORY_HEX.test(pin), "setup_invalid_artifact_pin");
    return pin;
  }
  let response;
  try {
    response = await fetchImpl(`${url}.sha256`, { method: "GET", redirect: "error", signal: AbortSignal.timeout(2e4) });
  } catch {
    throw new RepositoryReceiverError("setup_release_checksum_unavailable");
  }
  need2(response.ok, "setup_release_checksum_unavailable");
  const value = await response.text();
  need2(value.length < 1e3 && /^[0-9a-f]{64}(?:\s+[^\r\n]+)?\s*$/.test(value), "setup_invalid_release_checksum");
  return value.slice(0, 64);
}
async function runRepositoryCommand(args, dependencies = {}) {
  if (["connect", "connection-job", "coding-ready"].includes(args[0])) return (await Promise.resolve().then(() => (init_repository_connect(), repository_connect_exports))).runRepositoryConnect(args, dependencies);
  if (!["setup", "ready"].includes(args[0])) return runRepositoryReceiver(args);
  const { readFile, writeFile, mkdir, stat } = await import("fs/promises"), { resolve, join } = await import("path");
  const options = /* @__PURE__ */ new Map();
  const allowed = args[0] === "setup" ? ["--repository", "--owner-key", "--authority-key", "--endpoint", "--base", "--pull", "--key-file", "--output", "--receiver-url", "--receiver-sha256"] : ["--connection", "--key-file", "--pull", "--output"];
  for (let i = 1; i < args.length; i += 2) {
    need2(allowed.includes(args[i]) && !options.has(args[i]) && typeof args[i + 1] === "string" && !args[i + 1].startsWith("--"), "setup_invalid_arguments");
    options.set(args[i], args[i + 1]);
  }
  const env = dependencies.env ?? process.env, fetchImpl = dependencies.fetchImpl ?? fetch, stdout = dependencies.stdout ?? ((s) => process.stdout.write(s));
  const pull = options.get("--pull");
  if (pull !== void 0) need2(/^[1-9][0-9]*$/.test(pull) && Number.isSafeInteger(Number(pull)), "setup_invalid_pull_number");
  const token = await githubToken2(env);
  if (args[0] === "ready") {
    need2(options.get("--connection") && options.get("--output"), "setup_connection_and_output_required");
    let value;
    try {
      value = JSON.parse(await readFile(options.get("--connection"), "utf8"));
    } catch {
      throw new RepositoryReceiverError("setup_invalid_connection_config");
    }
    const config2 = parseRepositoryConnectionConfig(value), identity2 = await localIdentity(options.get("--key-file"), config2.connection.receiver_key, env);
    await checkServicePin(config2.connection.endpoint, config2.connection.authority_key, fetchImpl);
    const discovery2 = await discoverRepository({ repository: config2.connection.repository, base_branch: config2.connection.base_branch, ...pull ? { pull_number: Number(pull) } : {} }, token, fetchImpl);
    const actions = env.GITHUB_ACTIONS === "true";
    if (actions) need2(env.GITHUB_REPOSITORY === config2.connection.repository && env.GITHUB_EVENT_NAME === "workflow_dispatch" && env.GITHUB_REF === `refs/heads/${config2.connection.base_branch}` && discovery2.workflow_sha256 === config2.workflow_sha256 && env.GITHUB_WORKFLOW_REF === `${config2.connection.repository}/${WORKFLOW_PATH}@refs/heads/${config2.connection.base_branch}`, "receiver_trusted_workflow_required");
    const result2 = await createRepositoryReadiness(config2.connection, identity2, discovery2, { runtime: actions ? "github_actions" : "local", workflow_sha256: config2.workflow_sha256 });
    await writeFile(options.get("--output"), JSON.stringify(result2, null, 2) + "\n", { mode: 384, flag: "wx" });
    stdout(`Read-only readiness recorded for ${config2.connection.repository}. No task was approved or executed. Import the public observation into the repository connection.
`);
    return;
  }
  const repository2 = options.get("--repository"), owner = options.get("--owner-key"), authority = options.get("--authority-key"), output = options.get("--output");
  need2(repository2 && REPO.test(repository2) && owner && REPOSITORY_HEX.test(owner) && authority && REPOSITORY_HEX.test(authority) && owner !== authority && output, "setup_repository_owner_pin_and_output_required");
  const service = endpoint(options.get("--endpoint") ?? "https://scopeblind.com/api/coordination");
  await checkServicePin(service, authority, fetchImpl);
  const discovery = await discoverRepository({ repository: repository2, base_branch: options.get("--base"), ...pull ? { pull_number: Number(pull) } : {} }, token, fetchImpl);
  const url = options.get("--receiver-url") ?? `https://scopeblind.com/releases/repository-receiver-${REPOSITORY_SETUP_VERSION}.cjs`, hash2 = await artifactPin(url, options.get("--receiver-sha256"), fetchImpl), workflow = renderRepositoryWorkflow({ url, sha256: hash2 });
  const directory = resolve(output);
  let exists = false;
  try {
    await stat(directory);
    exists = true;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  need2(!exists, "setup_output_exists");
  await mkdir(directory, { mode: 448 });
  let keyFile = options.get("--key-file");
  if (!keyFile) {
    keyFile = join(directory, "receiver-key.json");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const key4 = { type: "scopeblind.repository.receiver-key.v1", public_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), private_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))) };
    await writeFile(keyFile, JSON.stringify(key4, null, 2) + "\n", { mode: 384, flag: "wx" });
  }
  const identity = await localIdentity(keyFile, void 0, env);
  need2(identity.publicKey !== owner && identity.publicKey !== authority, "setup_independent_receiver_key_required");
  const now = Date.now(), connection = { type: "scopeblind.repository.connection.v1", id: crypto.randomUUID(), endpoint: service, repository: discovery.repository, base_branch: discovery.base_branch, owner_key: owner, receiver_key: identity.publicKey, authority_key: authority, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 30 * 864e5).toISOString() };
  const config = { type: "scopeblind.repository.connection-config.v1", connection, receiver_url: url, receiver_sha256: hash2, workflow_path: WORKFLOW_PATH, workflow_sha256: await sha256(workflow) };
  parseRepositoryConnectionConfig(config);
  const result = await createRepositoryReadiness(connection, identity, discovery, { now, workflow_sha256: config.workflow_sha256 });
  let previewFile = false;
  if (pull) {
    const choices = await discoverRepositoryPreviewChoices((path) => github2(path, token, fetchImpl), discovery.repository, discovery.observed_head_sha), observed = Date.now(), preview = await sign({ type: "scopeblind.repository.preview-discovery.v1", repository: discovery.repository, pull_number: Number(pull), head_sha: discovery.observed_head_sha, owner_key: owner, receiver_key: identity.publicKey, authority_key: authority, ...choices, observed_at: new Date(observed).toISOString(), expires_at: new Date(observed + 864e5).toISOString() }, identity);
    await writeFile(join(directory, "preview-discovery.json"), JSON.stringify(preview, null, 2) + "\n", { mode: 384, flag: "wx" });
    previewFile = true;
  }
  const review = installationReview(config, discovery, !!options.get("--receiver-sha256")) + (previewFile ? "\n\n## Optional observed preview choices\n\npreview-discovery.json is a public receiver-signed observation for this PR head. Import it in the review brief to select an observed environment/origin and a named check provider. The provider check does not prove who published the URL. Importing only fills a draft; the owner must review and sign the policy. URLs with query credentials are omitted. The receiver inspects current metadata again before approval and execution.\n" : "");
  for (const [file, data] of [["connection.json", JSON.stringify(result, null, 2) + "\n"], ["connection-config.json", JSON.stringify(config, null, 2) + "\n"], ["discovery.json", JSON.stringify(discovery, null, 2) + "\n"], ["scopeblind-receiver.yml", workflow], ["INSTALL.md", review]]) await writeFile(join(directory, file), data, { mode: 384, flag: "wx" });
  stdout(`Read-only repository setup prepared for ${discovery.repository}.
Receiver public key: ${identity.publicKey}
Review ${join(directory, "INSTALL.md")} and import ${join(directory, "connection.json")} in your original authorized browser.
No workflow, secret, repository setting, task approval or branch update was installed. Private keys and GitHub credentials stay local.
`);
}
function installationReview(config, d, independentPin) {
  return `# Review this repository connection

Repository: ${d.repository}
Trusted default branch: ${d.base_branch}
Receiver public key: ${config.connection.receiver_key}
Service: ${config.connection.endpoint}
Service authority key: ${config.connection.authority_key}
Connection expires: ${config.connection.expires_at}

This is a signed observation of read access from this machine. It does not prove that a workflow is installed, give a task approval, or establish that branch rules allow an update. Import connection.json and explicitly authorize its exact public fields in your original browser.

## Observed checks

${d.checks.length ? d.checks.map((c) => `- ${JSON.stringify(c.name)} \u2014 app ${c.app_id}${c.app_name ? " " + JSON.stringify(c.app_name) : ""}`).join("\n") : "No check runs were observed."}

These are available observed checks, not a claim that all are required. GitHub requirements observed: ${JSON.stringify(d.required_checks)}. Protection read: ${d.protection_read}; rules read: ${d.rules_read}.

${d.warnings.map((w) => "- " + w).join("\n")}

## Review before installing

1. Keep receiver-key.json private; never upload the setup directory, private key, GitHub token, or an environment file to ScopeBlind or a repository. The public connection import is connection.json. If --pull was supplied, preview-discovery.json is a separate public observation; neither file grants a task.
2. Inspect scopeblind-receiver.yml, then copy just that file to ${WORKFLOW_PATH} on the trusted default branch through your normal repository review. It never checks out or runs PR code. It requests contents:write for a later separately approved update, pull-requests:read, checks:read, and deployments:read for exact-head preview metadata. It cannot bypass repository rules.
3. Set repository Actions variable SCOPEBLIND_CONNECTION_CONFIG to the exact contents of connection-config.json. Set Actions secret SCOPEBLIND_RECEIVER_PRIVATE_KEY to the private_key field using your local secret manager. The GitHub token is provided by Actions; never add a personal token to the workflow.
4. Run the workflow manually on ${d.base_branch}, operation ready. Download its public scopeblind-repository-evidence artifact and import repository-evidence.json. Local discovery and a signed response from the installed workflow are separate observations.
5. For each task, review the exact owner/reviewer binding and download its receiver config. Set SCOPEBLIND_RECEIVER_CONFIG to that config; it does not reuse a previous task's reviewer permission. Inspect, obtain both current exact approvals, then choose execute for that task ID. After an uncertain response use reconcile, never a replacement operation.

## Reproducible receiver artifact

URL: ${config.receiver_url}
SHA-256: ${config.receiver_sha256}
Workflow SHA-256: ${config.workflow_sha256}
Checksum source: ${independentPin ? "explicit --receiver-sha256 pin supplied by the owner" : "published HTTPS checksum; compare with your independently reviewed release before enabling"}

No GitHub changes were made by setup. Re-running setup writes to a new output directory; --key-file reuses the existing private receiver key. To refresh read access without a new connection, run repository ready --connection connection-config.json --key-file PRIVATE_KEY_FILE --output new-readiness.json.
`;
}
var REPOSITORY_SETUP_VERSION, REPO, WORKFLOW_PATH, safeText, WORKFLOW_TEMPLATE;
var init_repository_setup = __esm({
  "src/repository-setup.ts"() {
    "use strict";
    init_coordination_protocol();
    init_coordination_repository();
    init_coordination_repository_collaboration();
    init_repository_review_preview();
    init_repository_receiver();
    REPOSITORY_SETUP_VERSION = "0.24.0";
    REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/;
    WORKFLOW_PATH = ".github/workflows/scopeblind-receiver.yml";
    safeText = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
    WORKFLOW_TEMPLATE = `# Review on the trusted default branch before enabling. Setup grants no task approval.
name: ScopeBlind receiver
on:
  workflow_dispatch:
    inputs:
      operation:
        description: Read-only readiness, inspect, jointly approved execute, or reconcile
        required: true
        default: ready
        type: choice
        options: [ready, inspect, execute, reconcile]
      task_id:
        description: Exact task ID (required except for ready)
        required: false
        type: string
permissions:
  contents: write
  pull-requests: read
  checks: read
  deployments: read
concurrency:
  group: scopeblind-receiver-\${{ inputs.task_id || 'readiness' }}
  cancel-in-progress: false
jobs:
  receiver:
    if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Use the reviewed Node runtime
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: '22.22.3'
      - name: Verify the reviewed receiver artifact
        env:
          RECEIVER_URL: __RECEIVER_URL__
          RECEIVER_SHA256: __RECEIVER_SHA256__
        shell: bash
        run: |
          set -euo pipefail
          curl --fail --silent --show-error --proto '=https' --max-time 30 "$RECEIVER_URL" --output receiver.cjs
          printf '%s  receiver.cjs\\n' "$RECEIVER_SHA256" | sha256sum --check --strict
      - name: Run the constrained receiver
        env:
          GITHUB_TOKEN: \${{ github.token }}
          SCOPEBLIND_RECEIVER_PRIVATE_KEY: \${{ secrets.SCOPEBLIND_RECEIVER_PRIVATE_KEY }}
          CONNECTION_CONFIG: \${{ vars.SCOPEBLIND_CONNECTION_CONFIG }}
          RECEIVER_CONFIG: \${{ vars.SCOPEBLIND_RECEIVER_CONFIG }}
          TASK_ID: \${{ inputs.task_id }}
          OPERATION: \${{ inputs.operation }}
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          if [ "$OPERATION" = ready ]; then
            node -e 'require("node:fs").writeFileSync("connection-config.json",process.env.CONNECTION_CONFIG,{mode:0o600,flag:"wx"})'
            node receiver.cjs ready --connection connection-config.json --output repository-evidence.json
          else
            node -e 'require("node:fs").writeFileSync("receiver-config.json",process.env.RECEIVER_CONFIG,{mode:0o600,flag:"wx"})'
            node receiver.cjs "$OPERATION" --config receiver-config.json --task "$TASK_ID" --output repository-evidence.json
          fi
      - name: Keep the public signed observation
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: scopeblind-repository-evidence
          path: repository-evidence.json
          retention-days: 7
          if-no-files-found: error
`;
  }
});

// src/repository-receiver-cli.ts
init_repository_receiver();
init_repository_setup();
runRepositoryCommand(process.argv.slice(2)).catch((error) => {
  const message = error instanceof RepositoryReceiverError ? error.message : "The receiver could not complete this request. Inspect the existing task before continuing.";
  process.stderr.write(`${message}
`);
  process.exitCode = 1;
});
