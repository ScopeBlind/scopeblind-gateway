"use strict";

// src/coordination-protocol.ts
var COORDINATION_DOMAIN = "scopeblind.coordination.v1\n";
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex3) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(hex3)) throw new Error("Invalid hexadecimal data");
  return Uint8Array.from(hex3.match(/../g).map((x) => parseInt(x, 16)));
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
  const privateKey = await crypto.subtle.importKey("pkcs8", hexToBytes(pkcs8Hex), { name: "Ed25519" }, false, ["sign"]);
  const identity = { publicKey, privateKey };
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
    const key5 = await crypto.subtle.importKey("raw", hexToBytes(envelope2.signer), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key5, hexToBytes(envelope2.signature), new TextEncoder().encode(preimage));
  } catch {
    return false;
  }
}
function makeRequest(action, room_id, body) {
  return { type: "scopeblind.coordination.request.v1", action, room_id, body, issued_at: (/* @__PURE__ */ new Date()).toISOString(), nonce: crypto.randomUUID() };
}

// src/coordination-repository-devices.ts
var REPOSITORY_DEVICE_DOMAIN = "scopeblind.repository.device-authorization.v1\n";
var REPOSITORY_DEVICE_PERMISSIONS = ["read", "claim", "review", "feedback", "accept"];
var REPOSITORY_DEVICE_LINK_MS = 10 * 60 * 1e3;
var REPOSITORY_DEVICE_MAX_MS = 7 * 864e5;
var obj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var exact = (v, required, optional = []) => required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
var key = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
var id = (v) => typeof v === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(v);
var name = (v) => typeof v === "string" && v === v.trim() && v.length > 0 && v.length <= 60 && !/[\u0000-\u001f\u007f]/.test(v);
var time = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
var period = (v, max) => time(v.issued_at) && time(v.expires_at) && Date.parse(v.expires_at) > Date.parse(v.issued_at) && Date.parse(v.expires_at) - Date.parse(v.issued_at) <= max;
var clean = (v) => obj(v) && exact(v, ["payload", "signer", "digest", "signature"]);
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

// src/coordination-repository.ts
var REPOSITORY_HEX = /^[0-9a-f]{64}$/;
var REPOSITORY_SHA = /^[0-9a-f]{40}$/;
var REPOSITORY_ID = /^[A-Za-z0-9_-]{8,100}$/;
var object = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var text = (v, n) => typeof v === "string" && v.length > 0 && v.length <= n && !/[\u0000-\u001f\u007f]/.test(v);
var time2 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
var exact2 = (v, required, optional = []) => required.every((k) => k in v) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
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
var validRepositoryEnvelope = (e) => object(e) && exact2(e, ["payload", "signer", "digest", "signature"]);
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
      const a = approval.payload, key5 = a.role === "owner" ? t.owner_key : reviewer?.reviewer_key;
      check(!!s.proposal && validRepositoryHumanEnvelope(approval) && validRepositoryRecord(a, "approval") && a.principal_key === key5 && a.task_id === t.id && a.task_digest === s.task.digest && a.proposal_digest === s.proposal.digest && await verifyRepositoryHuman(approval, key5, { authorityKey: pins.authority_key, task: s.task, requireRecordedUse: true }) && Date.parse(a.issued_at) >= Date.parse(s.proposal.payload.observed_at) && Date.parse(a.expires_at) <= Date.parse(t.expires_at), "Exact proposal approval is invalid");
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

// src/coordination-repository-review.ts
var object2 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var shape = (v, required, optional = []) => object2(v) && required.every((k) => Object.prototype.hasOwnProperty.call(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
var text2 = (v, max, empty = false) => typeof v === "string" && (empty || v.trim().length > 0) && v.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);
var line = (v, max) => text2(v, max) && !/[\r\n\t]/.test(String(v));
var hex = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
var id2 = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
var num = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
var at = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
var span = (a, b, max) => at(a) && at(b) && Date.parse(b) > Date.parse(a) && Date.parse(b) - Date.parse(a) <= max;
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

// src/coordination-repository-workspace.ts
var obj2 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var exact3 = (v, req, opt = []) => req.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => req.includes(k) || opt.includes(k));
var text3 = (v, max) => typeof v === "string" && v.trim().length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
var key2 = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
var id3 = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
var at2 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
var period2 = (v, max) => at2(v.issued_at) && at2(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= max;
var repo = (v) => typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v);
var paths = (v) => Array.isArray(v) && v.length > 0 && v.length <= 12 && new Set(v).size === v.length && v.every((p) => typeof p === "string" && repositoryPath(p.endsWith("/**") ? p.slice(0, -3) : p) && pathAllowed(p.endsWith("/**") ? p.slice(0, -2) + "placeholder" : p, [p]));
var checks = (v) => Array.isArray(v) && v.length > 0 && v.length <= 12 && v.every((c) => obj2(c) && exact3(c, ["name", "app_id"]) && text3(c.name, 100) && Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0) && new Set(v.map((c) => c.name)).size === v.length;
var revision = (v) => Number.isSafeInteger(v) && Number(v) > 0;
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
var cleanEnvelope = (v) => obj2(v) && exact3(v, ["payload", "signer", "digest", "signature"]);
var before = (time4, observation) => Date.parse(time4) <= Date.parse(observation);
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
function ownerKeyAt(owner, key5, time4, workspace) {
  for (let r = 1; r <= owner.revision; r++) {
    const state = memberRevisionAt(owner, r, time4, workspace);
    if (state?.key === key5 && state.role === "owner" && state.status === "active") return true;
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

// src/coordination-repository-collaboration.ts
var DEMO_REPOSITORY = "ScopeBlind/scopeblind-repository-demo";
var DEMO_CHECK = { name: "ScopeBlind contact validation", app_id: 4962726 };
var CONTACT_PATH = "demo/contact.json";
var object3 = (value) => !!value && typeof value === "object" && !Array.isArray(value);
var shape2 = (value, required, optional = []) => object3(value) && required.every((key5) => key5 in value) && Object.keys(value).every((key5) => required.includes(key5) || optional.includes(key5));
var text4 = (value, max, empty = false) => typeof value === "string" && (empty || value.trim().length > 0) && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
var hex2 = (value) => typeof value === "string" && REPOSITORY_HEX.test(value);
var id4 = (value) => typeof value === "string" && REPOSITORY_ID.test(value);
var sha = (value) => typeof value === "string" && REPOSITORY_SHA.test(value);
var at3 = (value) => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
var span2 = (issued, expires, max) => at3(issued) && at3(expires) && Date.parse(String(expires)) > Date.parse(String(issued)) && Date.parse(String(expires)) - Date.parse(String(issued)) <= max;
function validContactPage(value) {
  return shape2(value, ["type", "button_label", "target", "accent"]) && value.type === "scopeblind.contact-page.v1" && text4(value.button_label, 40) && ["broken", "contact"].includes(String(value.target)) && ["indigo", "emerald", "rose"].includes(String(value.accent));
}
function contactPageBytes(value) {
  if (!validContactPage(value))
    throw new Error("invalid_contact_page");
  return canonical(value) + "\n";
}
function validRepositoryParticipants(v) {
  return shape2(v, ["type", "task_id", "task_digest", "owner_key", "receiver_key", "reviewer_key", "reviewer_claim_digest", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.participants.v1" && id4(v.task_id) && [v.task_digest, v.owner_key, v.receiver_key, v.reviewer_key, v.reviewer_claim_digest].every(hex2) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.reviewer_key])).size === 3 && span2(v.issued_at, v.expires_at, 7 * 864e5);
}
function validRepositoryPreview(v) {
  return shape2(v, ["type", "task_id", "task_digest", "proposal_digest", "base_sha", "head_sha", "merge_sha", "tree_sha", "path", "before", "after", "renderer", "observed_at"]) && v.type === "scopeblind.repository.preview.v1" && id4(v.task_id) && hex2(v.task_digest) && hex2(v.proposal_digest) && [v.base_sha, v.head_sha, v.merge_sha, v.tree_sha].every(sha) && v.path === CONTACT_PATH && v.renderer === "scopeblind.contact-page.v1" && at3(v.observed_at) && [v.before, v.after].every((side) => shape2(side, ["model", "blob_sha", "content_sha256"]) && validContactPage(side.model) && sha(side.blob_sha) && hex2(side.content_sha256));
}
function validRepositoryAgentGrant(v) {
  return shape2(v, ["type", "id", "task_id", "task_digest", "issuer_key", "agent_key", "permissions", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.agent-grant.v1" && id4(v.id) && id4(v.task_id) && [v.task_digest, v.issuer_key, v.agent_key].every(hex2) && v.issuer_key !== v.agent_key && Array.isArray(v.permissions) && v.permissions.length > 0 && v.permissions.length <= 2 && new Set(v.permissions).size === v.permissions.length && v.permissions.every((p) => p === "read_task" || p === "request_revision") && v.permissions.includes("read_task") && span2(v.issued_at, v.expires_at, 36e5);
}
function validRepositoryRevisionRequest(v) {
  return shape2(v, ["type", "id", "task_id", "task_digest", "basis_digest", "requester_key", "message", "proposed", "issued_at"], ["grant_digest"]) && v.type === "scopeblind.repository.revision-request.v1" && id4(v.id) && id4(v.task_id) && [v.task_digest, v.basis_digest, v.requester_key].every(hex2) && (v.grant_digest === void 0 || hex2(v.grant_digest)) && text4(v.message, 600) && validContactPage(v.proposed) && at3(v.issued_at);
}
function validRepositoryRevisionLink(v) {
  return shape2(v, ["type", "id", "parent_task_id", "parent_task_digest", "parent_basis_digest", "request_digest", "child_task_id", "child_task_digest", "owner_key", "issued_at"]) && v.type === "scopeblind.repository.revision-link.v1" && [v.id, v.parent_task_id, v.child_task_id].every(id4) && v.parent_task_id !== v.child_task_id && [v.parent_task_digest, v.parent_basis_digest, v.request_digest, v.child_task_digest, v.owner_key].every(hex2) && at3(v.issued_at);
}
function validRepositoryDemoRequest(v) {
  if (!shape2(v, ["type", "id", "owner_key", "receiver_key", "authority_key", "title", "goal", "proposed", "reviewer_secret_hash", "issued_at", "expires_at"], ["parent_task_id", "parent_task_digest", "parent_basis_digest", "revision_request_digest"]))
    return false;
  const parent = ["parent_task_id", "parent_task_digest", "parent_basis_digest", "revision_request_digest"];
  return v.type === "scopeblind.repository.demo-request.v1" && id4(v.id) && [v.owner_key, v.receiver_key, v.authority_key, v.reviewer_secret_hash].every(hex2) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.authority_key])).size === 3 && text4(v.title, 140) && text4(v.goal, 600) && validContactPage(v.proposed) && span2(v.issued_at, v.expires_at, 864e5) && (parent.every((k) => v[k] === void 0) || id4(v.parent_task_id) && [v.parent_task_digest, v.parent_basis_digest, v.revision_request_digest].every(hex2));
}
function validRepositoryDemoProvision(v) {
  return shape2(v, ["type", "request_id", "request_digest", "repository", "base_branch", "head_branch", "pull_number", "initial_base_sha", "initial_head_sha", "receiver_key", "required_checks", "observed_at"]) && v.type === "scopeblind.repository.demo-provision.v1" && id4(v.request_id) && [v.request_digest, v.receiver_key].every(hex2) && v.repository === DEMO_REPOSITORY && v.base_branch === `scopeblind/demo/${v.request_id}/base` && v.head_branch === `scopeblind/demo/${v.request_id}/change` && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && sha(v.initial_base_sha) && sha(v.initial_head_sha) && Array.isArray(v.required_checks) && canonical(v.required_checks) === canonical([DEMO_CHECK]) && at3(v.observed_at);
}
function repositoryRevisionBasis(state) {
  return state.acceptance?.digest ?? state.outcome?.digest ?? state.proposal?.digest ?? null;
}

// src/coordination-repository-collaboration-evidence.ts
var shape3 = (v, required, optional = []) => !!v && typeof v === "object" && !Array.isArray(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
var envelope = (v) => shape3(v, ["payload", "signer", "digest", "signature"]);
var time3 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
var within = (at8, start, end) => Date.parse(at8) >= Date.parse(start) && Date.parse(at8) <= Date.parse(end);
function requireValid(condition, message) {
  if (!condition) throw new Error(message);
}
var baseLimitations = [
  "A preview is the receiver\u2019s signed observation of canonical contact-page data, rendered by ScopeBlind\u2019s fixed template. It does not execute repository code or prove a deployed website.",
  "Agent grants allow only the recorded reading and revision suggestions. They do not convey human approval or receiver execution authority.",
  "Revocation flags and the completeness of the collaboration history are statements by the service. The included record does not prove a currently live grant."
];
async function verifyRepositoryCollaborationEvidence(input, pins) {
  const result = { valid: false, accepted: false, authorityPinned: false, previewVerified: false, revisionLinked: false, errors: [], limitations: [...baseLimitations] };
  try {
    requireValid(shape3(input, ["type", "repository", "collaboration"], ["demo", "parent", "parent_request", "parent_agent_grant"]) && input.type === "scopeblind.repository.collaboration-evidence.v1", "Unsupported collaboration evidence shape.");
    const bundle = input;
    const core = await verifyRepositoryEvidence(bundle.repository, pins);
    result.limitations.push(...core.limitations);
    requireValid(core.valid, core.errors.join("; "));
    result.authorityPinned = core.authorityPinned;
    const state = bundle.repository.state.payload, task = state.task.payload, collaboration = bundle.collaboration, c = collaboration?.payload;
    requireValid(envelope(collaboration) && await verify(collaboration, task.authority_key) && shape3(c, ["type", "task_id", "task_digest", "participants", "preview", "requests", "revisions", "agent_grants", "observed_at"]) && c.type === "scopeblind.repository.collaboration.v1" && c.task_id === task.id && c.task_digest === state.task.digest && time3(c.observed_at), "Collaboration must be signed by this task\u2019s authority and name the exact task.");
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
    requireValid(incomingLinks.length <= 1 && (incomingLinks.length === 1 || !["parent", "parent_request", "parent_agent_grant"].some((key5) => Object.hasOwn(bundle, key5))), "Predecessor records must be consumed by exactly one incoming revision link.");
    const grants = /* @__PURE__ */ new Map(), requestIds = /* @__PURE__ */ new Set(), requests = /* @__PURE__ */ new Map();
    for (const entry of c.agent_grants) {
      const signed = entry.grant, g = signed?.payload;
      requireValid(shape3(entry, ["grant", "revoked"]) && typeof entry.revoked === "boolean" && envelope(signed) && validRepositoryAgentGrant(g) && await verify(signed, g.issuer_key) && principals.includes(g.issuer_key) && ![...principals, task.receiver_key, task.authority_key].includes(g.agent_key) && g.task_id === task.id && g.task_digest === state.task.digest && within(g.issued_at, task.issued_at, task.expires_at) && Date.parse(g.issued_at) <= Date.parse(c.observed_at) && Date.parse(g.expires_at) <= Date.parse(task.expires_at) && !grants.has(signed.digest), "An agent grant is invalid, duplicated, or crosses a human/receiver boundary.");
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
      requireValid(envelope(signed) && await verify(signed, task.authority_key) && shape3(d, ["type", "request", "provision", "task", "status", "dispatch", "error", "observed_at"]) && d.type === "scopeblind.repository.demo-state.v1" && ["queued", "provisioning", "ready_to_review", "active", "failed", "expired"].includes(d.status) && ["requested", "unconfigured", "unavailable"].includes(d.dispatch) && (d.error === null || typeof d.error === "string" && d.error.length <= 100) && time3(d.observed_at), "The demo\u2019s service record is invalid.");
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

// src/coordination-repository-review-evidence.ts
var shape4 = (v, keys, optional = []) => !!v && typeof v === "object" && !Array.isArray(v) && keys.every((k) => Object.prototype.hasOwnProperty.call(v, k)) && Object.keys(v).every((k) => keys.includes(k) || optional.includes(k));
var at4 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
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
    check((shape4(e, ["type", "repository", "review"]) || shape4(e, ["type", "repository", "review", "origin"]) || shape4(e, ["type", "repository", "review", "coding_origin"])) && e.type === "scopeblind.repository.review-evidence.v1", "Review evidence shape is invalid");
    const core = repositoryReviewCore(e), base = e.repository.type === "scopeblind.repository.evidence.v1" ? await verifyRepositoryEvidence(e.repository, pins) : await verifyRepositoryCollaborationEvidence(e.repository, pins), s = core.state.payload, r = e.review.payload, t = s.task.payload, key5 = typeof pins === "string" ? pins : pins?.authority_key ?? t.authority_key;
    check(base.valid, "Underlying repository evidence is invalid");
    accepted = base.accepted;
    authorityPinned = base.authorityPinned;
    check(validRepositoryEnvelope(e.review) && shape4(r, ["type", "task_id", "task_digest", "brief", "packet", "decisions", "feedback", "recommendations", "history", "agent_uses", "observed_at"], ["origin_digest", "coding_origin_digest"]) && r.type === "scopeblind.repository.review-state.v1" && r.task_id === t.id && r.task_digest === s.task.digest && at4(r.observed_at) && Date.parse(r.observed_at) >= Date.parse(s.observed_at) && await verify(e.review, key5), "Review service state is invalid");
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
      check(a && r.packet && validRepositoryHumanEnvelope(decision) && validRepositoryReviewDecision(decision.payload, r.brief, r.packet, a) && decision.payload.principal_key === principal && await verifyRepositoryHuman(decision, principal, { authorityKey: key5, task: s.task, requireRecordedUse: true }) && Date.parse(decision.payload.issued_at) <= Date.parse(r.observed_at), "Exact packet decision is invalid");
    }
    check(r.decisions.length === s.approvals.length && s.approvals.every((a) => r.decisions.some((d) => d.payload.role === a.payload.role && d.payload.approval_digest === a.digest)), "Each ordinary approval requires its exact packet decision");
    decisionsVerified = packetVerified && r.decisions.length === 2 && s.approvals.length === 2 && s.approvals.every((a) => a.payload.decision === "approve");
    if (s.execution) check(decisionsVerified && r.packet && Date.parse(s.execution.payload.expires_at) <= Date.parse(r.packet.payload.expires_at), "Execution lacks both exact current packet decisions");
    const contexts = r.packet ? [{ state: core.state, packet: r.packet }] : [];
    for (const h of r.history) {
      check(shape4(h, ["state", "packet", "decisions"]) && (await verifyRepositoryEvidence({ type: "scopeblind.repository.evidence.v1", state: h.state }, pins ?? key5)).valid && h.state.payload.task.digest === s.task.digest && h.state.payload.reviewer?.digest === s.reviewer?.digest && Date.parse(h.state.payload.observed_at) <= Date.parse(r.observed_at) && h.state.payload.proposal && validRepositoryEnvelope(h.packet) && validRepositoryReviewPacket(h.packet.payload, r.brief, h.state.payload.proposal) && await verify(h.packet, t.receiver_key), "Historical review basis is invalid");
      contexts.push(h);
      check(Array.isArray(h.decisions) && h.decisions.length <= 2 && new Set(h.decisions.map((d) => d.payload.role)).size === h.decisions.length, "Historical packet decisions are invalid");
      for (const decision of h.decisions) {
        const approval = h.state.payload.approvals.find((a) => a.payload.role === decision.payload.role), principal = decision.payload.role === "owner" ? t.owner_key : s.reviewer?.payload.reviewer_key;
        check(approval && validRepositoryHumanEnvelope(decision) && validRepositoryReviewDecision(decision.payload, r.brief, h.packet, approval) && decision.payload.principal_key === principal && await verifyRepositoryHuman(decision, principal, { authorityKey: key5, task: s.task, requireRecordedUse: true }), "Historical exact packet decision is invalid");
      }
      check(h.decisions.length === h.state.payload.approvals.length && h.state.payload.approvals.every((a) => h.decisions.some((d) => d.payload.role === a.payload.role && d.payload.approval_digest === a.digest)), "Each historical approval requires its exact packet decision");
      if (h.state.payload.execution) check(h.decisions.length === 2 && Date.parse(h.state.payload.execution.payload.expires_at) <= Date.parse(h.packet.payload.expires_at), "Historical execution lacks both exact packet decisions");
      check(r.feedback.some((f) => f.payload.packet_digest === h.packet.digest && (f.payload.basis_digest === h.state.payload.proposal?.digest || f.payload.basis_digest === h.state.payload.outcome?.digest || f.payload.basis_digest === h.state.payload.acceptance?.digest)) || r.recommendations.some((a) => a.payload.packet_digest === h.packet.digest && a.payload.proposal_digest === h.state.payload.proposal?.digest), "Unreferenced review history is invalid");
    }
    const uses = /* @__PURE__ */ new Map();
    for (const use of r.agent_uses) {
      const u = use.payload, m = u.mandate?.payload, a = u.assignment?.payload, record = [...r.feedback, ...r.recommendations].find((x) => x.digest === u.record_digest), recordTime = record ? record.payload.issued_at ?? record.payload.observed_at : "";
      check(validRepositoryEnvelope(use) && shape4(u, ["type", "task_id", "task_digest", "record_digest", "permission", "mandate", "adoption", "assignment", "checked_at"]) && u.type === "scopeblind.repository.review-agent-use.v1" && u.task_id === t.id && u.task_digest === s.task.digest && await verify(use, key5) && record && at4(u.checked_at) && Date.parse(u.checked_at) <= Date.parse(r.observed_at) && Date.parse(u.checked_at) >= Date.parse(recordTime), "Agent-use service attestation is invalid");
      check(validRepositoryEnvelope(u.mandate) && validRepositoryEnvelope(u.adoption) && validWorkspacePreparationMandate(m) && m.owner_key === t.owner_key && m.reviewer_key === s.reviewer?.payload.reviewer_key && !["", t.owner_key, t.receiver_key, t.authority_key, s.reviewer?.payload.reviewer_key].includes(m.agent_key) && m.repository === t.repository && m.base_branch === t.base_branch && u.adoption.digest === u.mandate.digest && canonical(u.adoption.payload) === canonical(m) && await verify(u.mandate, t.owner_key) && await verify(u.adoption, m.reviewer_key) && m.permissions.includes(u.permission) && ["report_criteria", "request_revision"].includes(u.permission) && Date.parse(m.issued_at) <= Date.parse(recordTime) && Date.parse(m.expires_at) >= Date.parse(u.checked_at) && t.allowed_paths.every((p) => m.allowed_paths.includes(p) || m.allowed_paths.some((scope) => scope.endsWith("/**") && p.startsWith(scope.slice(0, -2)))) && m.required_checks.every((c) => t.required_checks.some((tc) => tc.name === c.name && tc.app_id === c.app_id)), "Dual-signed preparation mandate is invalid");
      check(validRepositoryEnvelope(u.assignment) && validWorkspaceTaskAssignment(a) && a.task_id === t.id && a.task_digest === s.task.digest && a.review_brief_digest === r.brief.digest && a.workspace_id === m.workspace_id && a.workspace_digest === m.workspace_digest && a.owner_key === t.owner_key && a.reviewer_key === s.reviewer?.payload.reviewer_key && a.owner_member_id === m.owner_member_id && a.reviewer_member_id === m.reviewer_member_id && a.owner_member_revision === m.owner_member_revision && a.reviewer_member_revision === m.reviewer_member_revision && Date.parse(a.issued_at) <= Date.parse(recordTime) && Date.parse(a.expires_at) >= Date.parse(u.checked_at) && await verify(u.assignment, t.owner_key), "Task assignment for the agent use is invalid");
      uses.set(u.record_digest, use);
    }
    for (const feedback of r.feedback) {
      const f = feedback.payload, c = contexts.find((c2) => c2.packet.digest === f.packet_digest && [c2.state.payload.proposal?.digest, c2.state.payload.outcome?.digest, c2.state.payload.acceptance?.digest].includes(f.basis_digest));
      check(c && validRepositoryHumanEnvelope(feedback) && validRepositoryReviewFeedback(f, r.brief, c.packet) && await verifyRepositoryHuman(feedback, f.requester_key, { authorityKey: key5, task: s.task, requireRecordedUse: true }) && Date.parse(f.issued_at) <= Date.parse(r.observed_at), "Review feedback is invalid");
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
      check(!e.origin && shape4(o, ["job", "assignment"]) && (await verifyRepositoryCodingEvidence(o.job, key5)).published, "Coding origin is not a verified completed code job");
      check(j?.result && j.request.payload.source.task_id !== t.id && j.result.payload.repository === t.repository && j.result.payload.pull_number === t.pull_number && j.mandate.payload.base_branch === t.base_branch, "Coding result does not match the fresh review");
      check(validRepositoryEnvelope(o.assignment) && validWorkspaceTaskAssignment(a) && a.task_id === t.id && a.task_digest === s.task.digest && a.review_brief_digest === r.brief.digest && !a.source_draft_digest && a.workspace_id === j.mandate.payload.workspace_id && a.workspace_digest === j.mandate.payload.workspace_digest && a.owner_key === t.owner_key && (!s.reviewer || a.reviewer_key === s.reviewer.payload.reviewer_key) && Date.parse(a.issued_at) >= Date.parse(j.result.payload.observed_at) && Date.parse(a.issued_at) <= Date.parse(r.observed_at) && await verify(o.assignment, t.owner_key), "Coding result assignment is invalid");
      if (s.proposal) check(s.proposal.payload.head_sha === j.result.payload.head_sha, "Fresh review changed beyond the registered coding result");
      codingOriginVerified = true;
    }
    if (e.origin) {
      const o = e.origin;
      check(shape4(o, ["draft", "assignment", "parent_assignment", "parent", "preparation"]) && !Object.prototype.hasOwnProperty.call(o.parent, "origin") && shape4(o.preparation, ["mandate", "adoption"]), "Review origin shape or depth is invalid");
      if (!shape4(o.parent, ["type", "repository", "review"])) throw Error("Nested origin is forbidden");
      const parent = await verifyRepositoryReviewEvidence(o.parent, key5), ps = repositoryReviewCore(o.parent).state.payload, d = o.draft.payload, a = o.assignment.payload, m = o.preparation.mandate.payload, source = d.source;
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

// src/coordination-repository-coding.ts
var CODING_PERMISSIONS = ["read_source", "edit_code", "run_tests", "open_pull_request", "publish_preview"];
var object4 = (x) => !!x && typeof x === "object" && !Array.isArray(x);
var exact4 = (v, required, optional = []) => required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
var key3 = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
var id5 = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
var number = (v, min, max) => Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max;
var at5 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
var hex40 = (v) => typeof v === "string" && REPOSITORY_SHA.test(v);
function codingSafePath(path) {
  return typeof path === "string" && repositoryPath(path) && !path.toLowerCase().split("/").some((p) => p === "node_modules" || p === ".git" || p === ".github" || p === ".env" || p.startsWith(".env.") || p === ".npmrc" || p === ".yarnrc" || p === ".netrc") && !/\.(pem|key|p12|pfx)$/i.test(path);
}
function codingCommand(v) {
  return Array.isArray(v) && v.length >= 2 && v.length <= 8 && v[0] === "node" && v.slice(1).every((x) => typeof x === "string" && x.length <= 200) && (v[1] === "--test" && v.length >= 3 && v.slice(2).every(codingSafePath) || v.length === 2 && codingSafePath(v[1]));
}
function validRepositoryCodingSource(v) {
  return object4(v) && exact4(v, ["task_id", "task_digest", "basis_digest", "packet_digest", "feedback_digest"]) && id5(v.task_id) && [v.task_digest, v.basis_digest, v.packet_digest, v.feedback_digest].every(key3);
}
function validRepositoryCodingMandate(v) {
  if (!object4(v) || !exact4(v, ["type", "id", "workspace_id", "workspace_digest", "mode", "owner_member_id", "owner_key", "owner_member_revision", "reviewer_member_id", "reviewer_key", "reviewer_member_revision", "worker_key", "repository", "base_branch", "allowed_paths", "required_checks", "runtime", "docker_image", "test_command", "build_command", "preview_directory", "max_jobs", "max_attempts", "max_model_calls", "max_tokens", "max_seconds", "max_changed_files", "max_changed_bytes", "permissions", "issued_at", "expires_at"])) return false;
  return v.type === "scopeblind.repository.coding-mandate.v1" && v.mode === "edit_code" && [v.id, v.workspace_id, v.owner_member_id, v.reviewer_member_id].every(id5) && [v.workspace_digest, v.owner_key, v.reviewer_key, v.worker_key].every(key3) && (/* @__PURE__ */ new Set([v.owner_key, v.reviewer_key, v.worker_key])).size === 3 && v.owner_member_id !== v.reviewer_member_id && number(v.owner_member_revision, 1, 1e3) && number(v.reviewer_member_revision, 1, 1e3) && typeof v.repository === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v.repository) && repositoryBranch(v.base_branch) && Array.isArray(v.allowed_paths) && v.allowed_paths.length > 0 && v.allowed_paths.length <= 12 && new Set(v.allowed_paths).size === v.allowed_paths.length && v.allowed_paths.every((p) => typeof p === "string" && codingSafePath(p.endsWith("/**") ? p.slice(0, -3) : p)) && Array.isArray(v.required_checks) && v.required_checks.length > 0 && v.required_checks.length <= 12 && new Set(v.required_checks.map((c) => object4(c) ? c.name : null)).size === v.required_checks.length && v.required_checks.every((c) => object4(c) && exact4(c, ["name", "app_id"]) && typeof c.name === "string" && c.name.length > 0 && c.name.length <= 100 && number(c.app_id, 1, Number.MAX_SAFE_INTEGER)) && v.runtime === "node22-static-v1" && typeof v.docker_image === "string" && /^node@sha256:[a-f0-9]{64}$/.test(v.docker_image) && codingCommand(v.test_command) && codingCommand(v.build_command) && codingSafePath(v.preview_directory) && !pathAllowed(v.preview_directory, v.allowed_paths) && v.allowed_paths.every((p) => p !== v.preview_directory && !p.startsWith(String(v.preview_directory) + "/")) && v.test_command.slice(1).filter((p) => !p.startsWith("--")).every((p) => !pathAllowed(p, v.allowed_paths)) && v.build_command.slice(1).every((p) => !pathAllowed(p, v.allowed_paths)) && number(v.max_jobs, 1, 3) && number(v.max_attempts, 1, 2) && number(v.max_model_calls, 1, 12) && number(v.max_tokens, 4096, 524288) && number(v.max_seconds, 60, 900) && number(v.max_changed_files, 1, 20) && number(v.max_changed_bytes, 1, 262144) && JSON.stringify(v.permissions) === JSON.stringify(CODING_PERMISSIONS) && at5(v.issued_at) && at5(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 864e5;
}
function validRepositoryCodingRequest(v) {
  return object4(v) && exact4(v, ["type", "id", "workspace_id", "mandate_digest", "source", "owner_key", "issued_at"]) && v.type === "scopeblind.repository.coding-request.v1" && [v.id, v.workspace_id].every(id5) && [v.mandate_digest, v.owner_key].every(key3) && validRepositoryCodingSource(v.source) && at5(v.issued_at);
}
function validRepositoryCodingStop(v) {
  return object4(v) && exact4(v, ["type", "id", "workspace_id", "mandate_digest", "principal_key", "issued_at"], ["job_id"]) && v.type === "scopeblind.repository.coding-stop.v1" && [v.id, v.workspace_id].every(id5) && [v.mandate_digest, v.principal_key].every(key3) && (v.job_id === void 0 || id5(v.job_id)) && at5(v.issued_at);
}
function validRepositoryCodingPlan(v, m) {
  return object4(v) && exact4(v, ["type", "job_id", "request_digest", "mandate_digest", "source_head_sha", "source_base_sha", "branch", "commit_sha", "tree_sha", "files", "tests", "build", "preview_digest", "model_calls", "reserved_tokens", "issued_at"]) && v.type === "scopeblind.repository.coding-plan.v1" && id5(v.job_id) && [v.request_digest, v.mandate_digest, v.preview_digest].every(key3) && [v.source_head_sha, v.source_base_sha, v.commit_sha, v.tree_sha].every(hex40) && v.branch === "scopeblind/code/" + v.job_id && Array.isArray(v.files) && v.files.length > 0 && v.files.length <= m.max_changed_files && new Set(v.files.map((f) => object4(f) ? f.path : null)).size === v.files.length && v.files.every((f) => object4(f) && exact4(f, ["path", "before_sha", "after_sha", "bytes"]) && codingSafePath(f.path) && pathAllowed(f.path, m.allowed_paths) && (f.before_sha === null || hex40(f.before_sha)) && (f.after_sha === null || hex40(f.after_sha)) && f.before_sha !== f.after_sha && number(f.bytes, 0, m.max_changed_bytes)) && v.files.reduce((n, f) => n + Number(f.bytes), 0) <= m.max_changed_bytes && [v.tests, v.build].every((t) => object4(t) && exact4(t, ["command_digest", "exit_code", "output_sha256", "duration_ms"]) && key3(t.command_digest) && key3(t.output_sha256) && t.exit_code === 0 && number(t.duration_ms, 0, m.max_seconds * 1e3)) && number(v.model_calls, 1, m.max_model_calls) && number(v.reserved_tokens, 4096, m.max_tokens) && at5(v.issued_at);
}
function validRepositoryCodingResult(v) {
  return object4(v) && exact4(v, ["type", "job_id", "plan_digest", "publication_digest", "repository", "branch", "head_sha", "pull_number", "pull_url", "preview_url", "preview_digest", "deployment_id", "deployment_status_id", "deployment_environment", "check", "observed_at"]) && v.type === "scopeblind.repository.coding-result.v1" && id5(v.job_id) && [v.plan_digest, v.publication_digest, v.preview_digest].every(key3) && hex40(v.head_sha) && typeof v.repository === "string" && typeof v.branch === "string" && number(v.pull_number, 1, Number.MAX_SAFE_INTEGER) && v.pull_url === `https://github.com/${v.repository}/pull/${v.pull_number}` && typeof v.preview_url === "string" && v.preview_url.startsWith("https://") && number(v.deployment_id, 1, Number.MAX_SAFE_INTEGER) && number(v.deployment_status_id, 1, Number.MAX_SAFE_INTEGER) && v.deployment_environment === "ScopeBlind coding preview" && object4(v.check) && exact4(v.check, ["id", "name", "app_id", "head_sha", "conclusion"]) && number(v.check.id, 1, Number.MAX_SAFE_INTEGER) && v.check.name === "ScopeBlind isolated coding checks" && v.check.app_id === 15368 && v.check.head_sha === v.head_sha && v.check.conclusion === "success" && at5(v.observed_at);
}

// src/coordination-repository-coding-evidence.ts
var object5 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var shape5 = (v, keys) => Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
var at6 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
var before2 = (a, b) => Date.parse(a) <= Date.parse(b);
var status = ["queued", "running", "testing", "publishing", "pr_ready", "failed", "cancelled", "unknown", "expired"];
async function verifyRepositoryCodingEvidence(value, authorityKey) {
  const errors = [];
  let published = false;
  function check(ok, message) {
    if (!ok) throw Error(message);
  }
  try {
    check(object5(value) && shape5(value, ["type", "job"]) && value.type === "scopeblind.repository.coding-evidence.v1", "Unrecognized coding evidence");
    const e = value, j = e.job?.payload, m = j?.mandate?.payload, r = j?.request?.payload;
    check(validRepositoryEnvelope(e.job) && object5(j) && shape5(j, ["type", "request", "mandate", "adoption", "workspace", "parent", "status", "attempts", "model_calls", "reserved_tokens", "lease_id", "lease_expires_at", "started_at", "plan", "publication", "result", "stop", "error", "observed_at"]) && j.type === "scopeblind.repository.coding-job.v1" && status.includes(j.status) && at6(j.observed_at), "Invalid coding state");
    const key5 = authorityKey || j.workspace?.signer;
    check(await verify(e.job, key5), "Coding service signature invalid");
    check(await verifyRepositoryWorkspaceState(j.workspace, key5), "Coding workspace proof invalid");
    const w = j.workspace.payload.workspace.payload;
    check(validRepositoryEnvelope(j.mandate) && validRepositoryCodingMandate(m) && await verify(j.mandate, m.owner_key) && validRepositoryEnvelope(j.adoption) && j.adoption.digest === j.mandate.digest && canonical(j.adoption.payload) === canonical(m) && await verify(j.adoption, m.reviewer_key), "Separate dual-signed code-edit authority required");
    check(m.workspace_id === w.id && m.workspace_digest === j.workspace.payload.workspace.digest && m.repository === w.repository && m.base_branch === w.base_branch && m.worker_key !== key5 && m.worker_key !== w.receiver_key, "Coding project scope mismatch");
    for (const [id7, k, revision2, role] of [[m.owner_member_id, m.owner_key, m.owner_member_revision, "owner"], [m.reviewer_member_id, m.reviewer_key, m.reviewer_member_revision, "reviewer"]]) {
      const member = j.workspace.payload.members.find((x) => x.member_id === id7);
      check(member && member.current_key === k && member.revision === revision2 && member.status === "active" && member.role === role, "Coding member revision mismatch");
    }
    check(validRepositoryEnvelope(j.request) && validRepositoryCodingRequest(r) && await verify(j.request, m.owner_key) && r.owner_key === m.owner_key && r.workspace_id === m.workspace_id && r.mandate_digest === j.mandate.digest && before2(m.issued_at, r.issued_at) && before2(r.issued_at, m.expires_at) && before2(r.issued_at, j.observed_at) && before2(r.issued_at, j.workspace.payload.observed_at) && before2(j.workspace.payload.observed_at, j.observed_at), "Coding request authority mismatch");
    check(!j.parent.origin && !j.parent.coding_origin && (await verifyRepositoryReviewEvidence(j.parent, key5)).valid, "Invalid frozen coding source");
    const core = j.parent.repository.type === "scopeblind.repository.evidence.v1" ? j.parent.repository.state : j.parent.repository.repository.state, source = r.source, feedback = j.parent.review.payload.feedback.find((f) => f.digest === source.feedback_digest);
    check(core.payload.task.digest === source.task_digest && core.payload.task.payload.id === source.task_id && core.payload.task.payload.repository === m.repository && core.payload.task.payload.base_branch === m.base_branch && feedback && feedback.payload.basis_digest === source.basis_digest && feedback.payload.packet_digest === source.packet_digest && before2(feedback.payload.issued_at, r.issued_at) && core.payload.proposal, "Coding source feedback mismatch");
    check(Number.isSafeInteger(j.attempts) && j.attempts >= 0 && j.attempts <= m.max_attempts && Number.isSafeInteger(j.model_calls) && j.model_calls >= 0 && j.model_calls <= m.max_model_calls && Number.isSafeInteger(j.reserved_tokens) && j.reserved_tokens >= 0 && j.reserved_tokens <= m.max_tokens, "Coding work limits exceeded");
    check((j.started_at === null || at6(j.started_at) && before2(r.issued_at, j.started_at) && before2(j.started_at, j.observed_at)) && (j.lease_id === null ? j.lease_expires_at === null : typeof j.lease_id === "string" && at6(j.lease_expires_at)) && (j.error === null || typeof j.error === "string" && /^[a-z0-9_]{3,80}$/.test(j.error)), "Invalid coding lifecycle");
    if (j.stop) {
      check(validRepositoryEnvelope(j.stop) && validRepositoryCodingStop(j.stop.payload) && [m.owner_key, m.reviewer_key].includes(j.stop.payload.principal_key) && await verify(j.stop, j.stop.payload.principal_key) && j.stop.payload.job_id === r.id && j.stop.payload.mandate_digest === j.mandate.digest && j.stop.payload.workspace_id === m.workspace_id && before2(j.stop.payload.issued_at, j.observed_at), "Invalid coding cancellation");
    }
    if (j.plan) {
      const p = j.plan.payload;
      check(validRepositoryEnvelope(j.plan) && validRepositoryCodingPlan(p, m) && await verify(j.plan, m.worker_key) && p.job_id === r.id && p.request_digest === j.request.digest && p.mandate_digest === j.mandate.digest && p.source_head_sha === core.payload.proposal.payload.head_sha && p.source_base_sha === core.payload.proposal.payload.base_sha && p.tests.command_digest === await sha256(canonical(m.test_command)) && p.build.command_digest === await sha256(canonical(m.build_command)) && p.model_calls === j.model_calls && p.reserved_tokens === j.reserved_tokens && before2(p.issued_at, j.observed_at), "Coding plan scope or tests invalid");
    }
    if (j.publication) {
      const p = j.publication.payload;
      check(j.plan && validRepositoryEnvelope(j.publication) && object5(p) && shape5(p, ["type", "job_id", "plan_digest", "mandate_digest", "request_digest", "worker_key", "lease_id", "issued_at", "expires_at"]) && p.type === "scopeblind.repository.coding-publication.v1" && await verify(j.publication, key5) && p.job_id === r.id && p.plan_digest === j.plan.digest && p.mandate_digest === j.mandate.digest && p.request_digest === j.request.digest && p.worker_key === m.worker_key && at6(p.issued_at) && at6(p.expires_at) && before2(j.plan.payload.issued_at, p.issued_at) && Date.parse(p.expires_at) > Date.parse(p.issued_at) && Date.parse(p.expires_at) - Date.parse(p.issued_at) <= 12e4 && before2(p.expires_at, m.expires_at) && before2(p.issued_at, j.observed_at), "Invalid exact publication gate");
    }
    if (j.result) {
      const result = j.result.payload;
      check(j.plan && j.publication && validRepositoryEnvelope(j.result) && validRepositoryCodingResult(result) && result.type === "scopeblind.repository.coding-result.v1" && await verify(j.result, m.worker_key) && result.job_id === r.id && result.plan_digest === j.plan.digest && result.publication_digest === j.publication.digest && result.repository === m.repository && result.branch === j.plan.payload.branch && result.head_sha === j.plan.payload.commit_sha && Number.isSafeInteger(result.pull_number) && result.pull_number > 0 && result.pull_url === `https://github.com/${m.repository}/pull/${result.pull_number}` && result.preview_digest === j.plan.payload.preview_digest && Number.isSafeInteger(result.deployment_id) && result.deployment_id > 0 && Number.isSafeInteger(result.deployment_status_id) && result.deployment_status_id > 0 && at6(result.observed_at) && before2(j.publication.payload.issued_at, result.observed_at) && before2(result.observed_at, j.observed_at), "Invalid coding publication readback");
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

// src/repository-review-preview.ts
var positive = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
var timestamp = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
var unavailable = () => ({ status: "unavailable", reason: "GitHub did not provide a complete, verifiable preview observation. No preview URL was inferred." });
async function observeRepositoryReviewPreview(get, repository, brief, proposal, now = Date.now()) {
  const policy = brief.payload.preview_policy;
  if (!policy) return { status: "not_requested", reason: "This brief does not require or identify a deployment preview." };
  const repo2 = `/repos/${repository.split("/").map(encodeURIComponent).join("/")}`, head = proposal.payload.head_sha;
  try {
    const deployments = (await get(`${repo2}/deployments?sha=${head}&environment=${encodeURIComponent(policy.environment)}&per_page=100`)).body;
    if (!Array.isArray(deployments) || deployments.length >= 100) return unavailable();
    if (!deployments.length) return { status: "missing", reason: "GitHub has no deployment for the exact proposed head and selected environment." };
    if (!deployments.every((d) => positive(d.id) && d.sha === head && d.environment === policy.environment && timestamp(d.created_at) && positive(d.creator?.id) && Date.parse(d.created_at) <= now)) return unavailable();
    const sorted = [...deployments].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id), deployment = sorted[0];
    if (new Set(sorted.map((d) => d.id)).size !== sorted.length) return unavailable();
    const statuses = (await get(`${repo2}/deployments/${deployment.id}/statuses?per_page=100`)).body;
    if (!Array.isArray(statuses) || statuses.length >= 100) return unavailable();
    if (!statuses.length) return { status: "pending", reason: "The newest matching deployment has not reported a status." };
    if (!statuses.every((s) => positive(s.id) && timestamp(s.created_at) && timestamp(s.updated_at) && Date.parse(s.updated_at) >= Date.parse(s.created_at) && Date.parse(s.updated_at) <= now && positive(s.creator?.id))) return unavailable();
    const status2 = [...statuses].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id)[0];
    if (["pending", "queued", "in_progress"].includes(status2.state)) return { status: "pending", reason: "The newest matching deployment is still in progress." };
    if (["failure", "error", "inactive"].includes(status2.state)) return { status: "failed", reason: "The newest matching deployment is not a successful active preview." };
    if (status2.state !== "success" || status2.environment !== policy.environment || !safeRepositoryPreviewUrl(status2.environment_url) || !policy.allowed_origins.includes(new URL(status2.environment_url).origin)) return unavailable();
    const body = (await get(`${repo2}/commits/${head}/check-runs?per_page=100&filter=latest`)).body;
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
  async tree(sha3) {
    const body = (await this.github(`${this.repo}/git/trees/${sha3}?recursive=1`)).body;
    requireValue(body.sha === sha3 && !body.truncated && Array.isArray(body.tree) && body.tree.length <= 1e4, "repository_tree_incomplete");
    return new Map(body.tree.map((v) => [v.path, { type: v.type, mode: v.mode, sha: v.sha }]));
  }
  async snapshot(task, proposalId = crypto.randomUUID()) {
    const t = task.payload, pr = await this.pull(t.pull_number);
    requireValue(pr.number === t.pull_number && pr.state === "open" && !pr.draft && !pr.merged && pr.mergeable === true && pr.base?.repo?.full_name === t.repository && pr.head?.repo?.full_name === t.repository && pr.base.ref === t.base_branch && repositoryBranch(pr.head.ref) && pr.head.ref !== pr.base.ref && [pr.base.sha, pr.head.sha, pr.merge_commit_sha].every((s) => REPOSITORY_SHA.test(s)), "repository_pr_not_ready");
    const [repo2, base, merge, comparison, runs, currentBase, currentHead] = await Promise.all([
      this.github(this.repo),
      this.github(`${this.repo}/git/commits/${pr.base.sha}`),
      this.github(`${this.repo}/git/commits/${pr.merge_commit_sha}`),
      this.github(`${this.repo}/compare/${pr.base.sha}...${pr.merge_commit_sha}`),
      this.github(`${this.repo}/commits/${pr.head.sha}/check-runs?per_page=100&filter=latest`),
      this.ref(t.base_branch),
      this.ref(pr.head.ref)
    ]);
    requireValue(currentBase === pr.base.sha && currentHead === pr.head.sha, "repository_changed_during_inspection");
    requireValue(repo2.body.full_name === t.repository && typeof repo2.body.node_id === "string" && base.body.sha === pr.base.sha && REPOSITORY_SHA.test(base.body.tree?.sha) && merge.body.sha === pr.merge_commit_sha && Array.isArray(merge.body.parents) && canonical(merge.body.parents.map((p) => p.sha)) === canonical([pr.base.sha, pr.head.sha]) && REPOSITORY_SHA.test(merge.body.tree?.sha), "repository_merge_mismatch");
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
    const proposal = { type: "scopeblind.repository.proposal.v1", id: proposalId, task_id: t.id, task_digest: task.digest, repository_id: repo2.body.node_id, base_ref: `refs/heads/${pr.base.ref}`, head_ref: `refs/heads/${pr.head.ref}`, base_sha: pr.base.sha, head_sha: pr.head.sha, merge_sha: pr.merge_commit_sha, tree_sha: merge.body.tree.sha, files, checks: checks2, observed_at: (/* @__PURE__ */ new Date()).toISOString() };
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
    let sha3 = null, readback = "not_confirmed";
    try {
      sha3 = await this.ref(state.payload.task.payload.base_branch);
      if (sha3 === state.payload.proposal.payload.merge_sha) readback = "exact_ref";
      else if (sha3 !== state.payload.proposal.payload.base_sha) {
        const compare = (await this.github(`${this.repo}/compare/${state.payload.proposal.payload.merge_sha}...${sha3}`)).body;
        if (compare.base_commit?.sha === state.payload.proposal.payload.merge_sha && compare.merge_base_commit?.sha === state.payload.proposal.payload.merge_sha && ["ahead", "identical"].includes(compare.status)) readback = "descendant_ref";
      }
    } catch {
      note = "GitHub readback was unavailable. Keep this operation unresolved; do not dispatch a replacement.";
    }
    return this.report(state, { status: readback === "not_confirmed" ? "unknown" : "confirmed", observed_base_sha: sha3, readback, note, ...requestId ? { github_request_id: requestId } : {} });
  }
  async report(state, result) {
    const s = state.payload, x = s.execution;
    const outcome = await sign({ type: "scopeblind.repository.outcome.v1", operation_id: x.payload.operation_id, task_id: s.task.payload.id, task_digest: s.task.digest, proposal_digest: s.proposal.digest, execution_digest: x.digest, ...result, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
    return this.rpc("repository_outcome", s.task.payload.id, { outcome });
  }
};

// src/repository-coding-runner.ts
var import_promises = require("fs/promises");
var import_node_os = require("os");
var import_node_path = require("path");
var import_node_child_process = require("child_process");
var import_node_util = require("util");
var import_node_crypto = require("crypto");
var execute = (0, import_node_util.promisify)(import_node_child_process.execFile);
var hash = (v) => (0, import_node_crypto.createHash)("sha1").update(v).digest("hex");
var gitBlob = (b) => hash(Buffer.concat([Buffer.from(`blob ${b.length}\0`), b]));
var DockerCodingSandbox = class {
  constructor(directory, image, dockerExecute = execute) {
    this.directory = directory;
    this.image = image;
    this.dockerExecute = dockerExecute;
    if (!/^node@sha256:[a-f0-9]{64}$/.test(image)) throw Error("coding_image_pin_required");
  }
  containers = /* @__PURE__ */ new Set();
  closed = false;
  async run(command, timeout) {
    if (this.closed) throw Error("coding_sandbox_closed");
    if (!codingCommand(command)) throw Error("coding_command_invalid");
    const name2 = "scopeblind-coding-" + (0, import_node_crypto.randomUUID)(), started = Date.now(), args = ["run", "--name", name2, "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--user", `${process.getuid?.() ?? 1e3}:${process.getgid?.() ?? 1e3}`, "--mount", `type=bind,source=${this.directory},target=/workspace`, "--workdir", "/workspace", this.image, ...command];
    this.containers.add(name2);
    try {
      const r = await this.dockerExecute("docker", args, { timeout, killSignal: "SIGKILL", maxBuffer: 65536, env: { PATH: process.env.PATH } });
      return { exit_code: 0, output: r.stdout + "\n" + r.stderr, duration_ms: Date.now() - started };
    } catch (e) {
      const error = e;
      return { exit_code: Number.isSafeInteger(error.code) ? Number(error.code) : 124, output: (error.stdout || "") + "\n" + (error.stderr || ""), duration_ms: Date.now() - started };
    } finally {
      await this.remove(name2);
    }
  }
  async remove(name2) {
    try {
      await this.dockerExecute("docker", ["rm", "--force", name2], { timeout: 1e4, killSignal: "SIGKILL", maxBuffer: 4096, env: { PATH: process.env.PATH } });
    } catch (error) {
      const e = error;
      if (e.code !== 1 || e.stderr?.trim() !== `Error response from daemon: No such container: ${name2}`) {
        this.closed = true;
        throw Error("coding_sandbox_cleanup_failed");
      }
    }
    this.containers.delete(name2);
  }
  async close() {
    this.closed = true;
    const results = await Promise.allSettled([...this.containers].map((name2) => this.remove(name2)));
    if (results.some((r) => r.status === "rejected")) throw Error("coding_sandbox_cleanup_failed");
  }
};
async function bounded(response, max = 4e6) {
  const reader = response.body?.getReader();
  if (!reader) throw Error("coding_empty_response");
  let n = 0, parts = [];
  try {
    for (; ; ) {
      const p = await reader.read();
      if (p.done) break;
      n += p.value.length;
      if (n > max) throw Error("coding_response_limit");
      parts.push(p.value);
    }
  } finally {
    await reader.cancel().catch(() => {
    });
  }
  return JSON.parse(Buffer.concat(parts).toString("utf8"));
}
function need(ok, code) {
  if (!ok) throw Error(code);
}
async function safeWrite(root, path, content2) {
  need(codingSafePath(path), "coding_path_forbidden");
  const parts = path.split("/");
  let current = root;
  for (const p of parts.slice(0, -1)) {
    current = (0, import_node_path.join)(current, p);
    try {
      const s = await (0, import_promises.lstat)(current);
      need(s.isDirectory() && !s.isSymbolicLink(), "coding_symlink_forbidden");
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
      await (0, import_promises.mkdir)(current);
    }
  }
  const file = (0, import_node_path.join)(root, path);
  try {
    const s = await (0, import_promises.lstat)(file);
    need(s.isFile() && !s.isSymbolicLink(), "coding_symlink_forbidden");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  if (content2 === null) await (0, import_promises.rm)(file, { force: true });
  else await (0, import_promises.writeFile)(file, content2, { mode: 384 });
}
async function scanCodingWorkspace(root) {
  const found = /* @__PURE__ */ new Map();
  let nodes = 0, bytes = 0;
  const visit = async (dir, depth) => {
    need(depth <= 10, "coding_directory_depth_limit");
    for await (const entry of await (0, import_promises.opendir)(dir)) {
      need(++nodes <= 1200, "coding_node_limit");
      const path = (0, import_node_path.join)(dir, entry.name), s = await (0, import_promises.lstat)(path), rel = (0, import_node_path.relative)(root, path);
      need(rel.length <= 200 && !s.isSymbolicLink(), "coding_symlink_forbidden");
      if (s.isDirectory()) await visit(path, depth + 1);
      else {
        need(s.isFile() && s.size <= 524288, "coding_file_limit");
        need(bytes + s.size <= 2 * 1024 * 1024, "coding_workspace_byte_limit");
        const content2 = await (0, import_promises.readFile)(path);
        bytes += content2.length;
        need(bytes <= 2 * 1024 * 1024 && content2.length === s.size, "coding_workspace_byte_limit");
        found.set(rel, content2);
        need(found.size <= 1e3, "coding_file_count_limit");
      }
    }
  };
  await visit(root, 0);
  return found;
}
function assertCodingWorkspaceUnchanged(before3, after, previewDirectory) {
  for (const path of /* @__PURE__ */ new Set([...before3.keys(), ...after.keys()])) {
    if (previewDirectory && (path === previewDirectory || path.startsWith(previewDirectory + "/"))) continue;
    const a = before3.get(path), b = after.get(path);
    need(a && b && Buffer.compare(a, b) === 0, "coding_test_or_build_modified_source");
  }
}
function codingChanges(before3, after, m) {
  const changes = [];
  for (const p of /* @__PURE__ */ new Set([...before3.keys(), ...after.keys()])) {
    if (p === m.preview_directory || p.startsWith(m.preview_directory + "/")) continue;
    const a = before3.get(p), b = after.get(p);
    if (a && b && Buffer.compare(a, b) === 0) continue;
    need(codingSafePath(p) && pathAllowed(p, m.allowed_paths), "coding_diff_outside_scope");
    changes.push({ path: p, before_sha: a ? gitBlob(a) : null, after_sha: b ? gitBlob(b) : null, bytes: Math.max(a?.length ?? 0, b?.length ?? 0) });
  }
  need(changes.length > 0 && changes.length <= m.max_changed_files && changes.reduce((n, f) => n + f.bytes, 0) <= m.max_changed_bytes, "coding_diff_limit");
  return changes.sort((a, b) => a.path.localeCompare(b.path));
}
function codingTree(entries, changes) {
  const files = new Map(entries.map((x) => [x.path, x]));
  for (const c of changes) if (c.after_sha) files.set(c.path, { path: c.path, mode: files.get(c.path)?.mode || "100644", sha: c.after_sha });
  else files.delete(c.path);
  const objects = [];
  const tree = (prefix) => {
    const rows = [], dirs = /* @__PURE__ */ new Set();
    for (const f of files.values()) {
      if (!f.path.startsWith(prefix)) continue;
      const rest = f.path.slice(prefix.length), slash = rest.indexOf("/");
      if (slash >= 0) dirs.add(rest.slice(0, slash));
      else rows.push({ path: rest, mode: f.mode, type: "blob", sha: f.sha });
    }
    for (const d of dirs) rows.push({ path: d, mode: "040000", type: "tree", sha: tree(prefix + d + "/") });
    rows.sort((a, b) => Buffer.compare(Buffer.from(a.path + (a.type === "tree" ? "/" : "")), Buffer.from(b.path + (b.type === "tree" ? "/" : ""))));
    const data = Buffer.concat(rows.map((r) => Buffer.concat([Buffer.from(`${r.type === "tree" ? "40000" : r.mode} ${r.path}\0`), Buffer.from(r.sha, "hex")]))), sha3 = hash(Buffer.concat([Buffer.from(`tree ${data.length}\0`), data]));
    objects.push({ path: prefix, sha: sha3, entries: rows });
    return sha3;
  };
  return { sha: tree(""), objects };
}
var RepositoryCodingRunner = class {
  constructor(config, identity, githubToken, fetcher = fetch, sandboxFactory = (dir) => new DockerCodingSandbox(dir, config.docker_image)) {
    this.config = config;
    this.identity = identity;
    this.githubToken = githubToken;
    this.fetcher = fetcher;
    this.sandboxFactory = sandboxFactory;
    const u = new URL(config.endpoint);
    need(u.protocol === "https:" && u.pathname === "/api/coordination" && !u.search && !u.hash && !u.username && !u.password && config.worker_key === identity.publicKey && githubToken, "coding_config_invalid");
  }
  publicationUntil = 0;
  stopped = false;
  async rpc(action, id7, body = {}) {
    const request = await sign(makeRequest(action, id7, body), this.identity), r = await this.fetcher(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json", "x-scopeblind-action": action }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(55e3) }), v = await bounded(r);
    need(r.ok && v.ok === true, typeof v.error === "string" ? v.error : "coding_service_refused");
    return v;
  }
  async github(path, init = {}, missing = false) {
    if (init.method && init.method !== "GET") need(!this.stopped && this.publicationUntil > Date.now(), "coding_publication_expired");
    const r = await this.fetcher("https://api.github.com/repos/" + this.config.repository + path, { ...init, headers: { authorization: "Bearer " + this.githubToken, accept: "application/vnd.github+json", "content-type": "application/json", "x-github-api-version": "2026-03-10" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
    if (missing && r.status === 404) {
      await r.body?.cancel();
      return null;
    }
    const v = await bounded(r);
    need(r.ok, "coding_github_" + r.status);
    return v;
  }
  async checked(reply) {
    const job = reply.job;
    need(job && (await verifyRepositoryCodingEvidence({ type: "scopeblind.repository.coding-evidence.v1", job }, this.config.authority_key)).valid, "coding_job_evidence_invalid");
    const m = job.payload.mandate.payload;
    need(m.worker_key === this.identity.publicKey && m.repository === this.config.repository && m.base_branch === this.config.base_branch && m.docker_image === this.config.docker_image && m.runtime === this.config.runtime && canonical(m.test_command) === canonical(this.config.test_command) && canonical(m.build_command) === canonical(this.config.build_command) && m.preview_directory === this.config.preview_directory, "coding_config_scope_mismatch");
    return job;
  }
  async readback(j) {
    const p = j.plan, result = await this.github("/pulls?state=all&head=" + encodeURIComponent(this.config.repository.split("/")[0] + ":" + p.payload.branch) + "&base=" + encodeURIComponent(this.config.base_branch) + "&per_page=100");
    need(Array.isArray(result) && result.length <= 1, "coding_pull_ambiguous");
    if (!result.length) return null;
    const pull = result[0];
    need(pull.head?.sha === p.payload.commit_sha && pull.head?.ref === p.payload.branch && pull.base?.ref === this.config.base_branch && pull.base?.repo?.full_name === this.config.repository && pull.head?.repo?.full_name === this.config.repository, "coding_pull_conflict");
    return pull;
  }
  async result(j, pull, preview, deployment, status2, check) {
    need(check.name === "ScopeBlind isolated coding checks" && check.app?.id === 15368 && check.head_sha === j.plan.payload.commit_sha && check.conclusion === "success", "coding_check_invalid");
    const result = await sign({ type: "scopeblind.repository.coding-result.v1", job_id: j.request.payload.id, plan_digest: j.plan.digest, publication_digest: j.publication.digest, repository: this.config.repository, branch: j.plan.payload.branch, head_sha: j.plan.payload.commit_sha, pull_number: pull.number, pull_url: `https://github.com/${this.config.repository}/pull/${pull.number}`, preview_url: preview.url, preview_digest: preview.digest, deployment_id: deployment.id, deployment_status_id: status2.id, deployment_environment: "ScopeBlind coding preview", check: { id: check.id, name: "ScopeBlind isolated coding checks", app_id: 15368, head_sha: j.plan.payload.commit_sha, conclusion: "success" }, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
    await this.rpc("repository_coding_complete", j.request.payload.workspace_id, { job_id: j.request.payload.id, lease_id: j.lease_id, result });
  }
  async runOne(jobIdFilter) {
    need(jobIdFilter === void 0 || REPOSITORY_ID.test(jobIdFilter), "invalid_coding_job");
    const lease = crypto.randomUUID(), reply = await this.rpc("repository_coding_poll", "repository-coding", { lease_id: lease, ...jobIdFilter ? { job_id: jobIdFilter } : {} });
    if (reply.job === null) return false;
    let signed = await this.checked(reply), j = signed.payload;
    need(j.lease_id === lease && Date.parse(j.lease_expires_at) > Date.now(), "coding_lease_invalid");
    const jobId = j.request.payload.id, workspaceId = j.request.payload.workspace_id, base = { job_id: jobId, lease_id: lease };
    this.stopped = false;
    let root, sandbox;
    const heartbeat = setInterval(() => {
      void this.rpc("repository_coding_heartbeat", workspaceId, base).then((r) => this.checked(r)).then((state) => {
        if (state.payload.stop || ["cancelled", "expired", "failed", "unknown"].includes(state.payload.status)) throw Error("coding_stopped");
      }).catch(() => {
        this.stopped = true;
        void sandbox?.close();
      });
    }, 2e4);
    try {
      if (j.publication) {
        const pull2 = await this.readback(j);
        need(pull2, "coding_publication_unknown");
        const deployments = await this.github("/deployments?sha=" + j.plan.payload.commit_sha + "&environment=ScopeBlind%20coding%20preview&per_page=100");
        need(Array.isArray(deployments) && deployments.length < 100, "coding_deployment_ambiguous");
        const deployment2 = deployments.find((d) => d.payload?.scopeblind_job_id === jobId && d.sha === j.plan.payload.commit_sha);
        need(deployment2, "coding_publication_unknown");
        const statuses = await this.github("/deployments/" + deployment2.id + "/statuses?per_page=100"), status2 = statuses[0];
        need(status2?.state === "success" && typeof status2.environment_url === "string" && status2.environment_url.includes(j.plan.payload.preview_digest), "coding_publication_unknown");
        const checks2 = await this.github("/commits/" + j.plan.payload.commit_sha + "/check-runs?check_name=ScopeBlind%20isolated%20coding%20checks&per_page=100"), check2 = checks2.check_runs?.find((c) => c.name === "ScopeBlind isolated coding checks" && c.app?.id === 15368 && c.head_sha === j.plan.payload.commit_sha && c.conclusion === "success");
        need(check2, "coding_publication_unknown");
        await this.result(j, pull2, { url: status2.environment_url, digest: j.plan.payload.preview_digest }, deployment2, status2, check2);
        return true;
      }
      const parent = j.parent.repository.type === "scopeblind.repository.evidence.v1" ? j.parent.repository.state : j.parent.repository.repository.state, proposal = parent.payload.proposal, m = j.mandate.payload;
      const currentBase = await this.github("/git/ref/heads/" + encodeURIComponent(m.base_branch));
      need(currentBase.object?.sha === proposal.payload.base_sha, "coding_source_base_changed");
      const head = await this.github("/git/commits/" + proposal.payload.head_sha);
      need(head.sha === proposal.payload.head_sha && REPOSITORY_SHA.test(head.tree?.sha), "coding_source_head_invalid");
      const tree = await this.github("/git/trees/" + head.tree.sha + "?recursive=1");
      need(tree.truncated === false && Array.isArray(tree.tree) && tree.tree.length <= 1e3, "coding_source_tree_limit");
      const entries = tree.tree.filter((f) => f.type !== "tree");
      need(entries.every((f) => f.type === "blob" && ["100644", "100755"].includes(f.mode) && typeof f.path === "string" && REPOSITORY_SHA.test(f.sha)), "coding_source_unsupported");
      root = await (0, import_promises.mkdtemp)((0, import_node_path.join)((0, import_node_os.tmpdir)(), "scopeblind-code-"));
      const before3 = /* @__PURE__ */ new Map();
      let total = 0;
      for (const f of entries) {
        if (!codingSafePath(f.path)) continue;
        need(f.size <= 131072, "coding_source_file_limit");
        const blob = await this.github("/git/blobs/" + f.sha);
        need(blob.encoding === "base64" && typeof blob.content === "string", "coding_source_blob_invalid");
        const bytes = Buffer.from(blob.content, "base64");
        total += bytes.length;
        need(total <= 524288 && bytes.length === blob.size && gitBlob(bytes) === f.sha, "coding_source_integrity");
        before3.set(f.path, bytes);
        await (0, import_promises.mkdir)((0, import_node_path.dirname)((0, import_node_path.join)(root, f.path)), { recursive: true });
        await (0, import_promises.writeFile)((0, import_node_path.join)(root, f.path), bytes, { mode: 384 });
      }
      sandbox = this.sandboxFactory(root);
      const history = [];
      let tests = null, finished = false;
      for (let n = j.model_calls; n < m.max_model_calls; n++) {
        need(!this.stopped && Date.now() < Date.parse(j.started_at) + m.max_seconds * 1e3, "coding_time_limit");
        const files = await scanCodingWorkspace(root), contextFiles = [...files].filter(([p]) => pathAllowed(p, m.allowed_paths) || m.test_command.includes(p) || m.build_command.includes(p)).map(([path, b]) => ({ path, content: new TextDecoder("utf-8", { fatal: true }).decode(b) }));
        const step = await this.rpc("repository_coding_model", workspaceId, { ...base, step_id: jobId + "-" + n, context: { files: contextFiles, history: history.slice(-6) } }), action = step.reply;
        if (action.action === "write_file" || action.action === "delete_file") {
          need(codingSafePath(action.path) && pathAllowed(action.path, m.allowed_paths), "coding_edit_forbidden");
          await safeWrite(root, action.path, action.action === "write_file" ? action.content : null);
          tests = null;
          history.push({ action, result: "Applied to isolated workspace." });
        } else if (action.action === "run_tests") {
          await this.rpc("repository_coding_heartbeat", workspaceId, { ...base, stage: "testing" });
          const testBefore = await scanCodingWorkspace(root), test = await sandbox.run(m.test_command, Math.min(6e4, Math.max(1, Date.parse(j.started_at) + m.max_seconds * 1e3 - Date.now())));
          assertCodingWorkspaceUnchanged(testBefore, await scanCodingWorkspace(root));
          tests = { command_digest: await sha256(canonical(m.test_command)), exit_code: test.exit_code, output_sha256: await sha256(test.output), duration_ms: test.duration_ms };
          history.push({ action, result: test.output.slice(-8e3) });
        } else if (action.action === "finish") {
          need(tests?.exit_code === 0, "coding_tests_required");
          finished = true;
          break;
        } else throw Error("coding_model_action_invalid");
      }
      need(finished && tests?.exit_code === 0, "coding_model_budget_exhausted");
      const buildBefore = await scanCodingWorkspace(root), build = await sandbox.run(m.build_command, Math.min(6e4, Math.max(1, Date.parse(j.started_at) + m.max_seconds * 1e3 - Date.now())));
      need(build.exit_code === 0, "coding_build_failed");
      const built = await scanCodingWorkspace(root);
      assertCodingWorkspaceUnchanged(buildBefore, built, m.preview_directory);
      const finalTest = await sandbox.run(m.test_command, Math.min(6e4, Math.max(1, Date.parse(j.started_at) + m.max_seconds * 1e3 - Date.now())));
      need(finalTest.exit_code === 0, "coding_tests_required");
      const after = await scanCodingWorkspace(root);
      assertCodingWorkspaceUnchanged(built, after);
      tests = { command_digest: await sha256(canonical(m.test_command)), exit_code: 0, output_sha256: await sha256(finalTest.output), duration_ms: finalTest.duration_ms };
      const changes = codingChanges(before3, after, m), previewFiles = [...after].filter(([p]) => p.startsWith(m.preview_directory + "/")).map(([p, b]) => ({ path: p.slice(m.preview_directory.length + 1), content_base64: Buffer.from(b).toString("base64"), sha256: (0, import_node_crypto.createHash)("sha256").update(b).digest("hex") }));
      need(previewFiles.length > 0 && previewFiles.length <= 64 && previewFiles.reduce((n, f) => n + Buffer.from(f.content_base64, "base64").length, 0) <= 524288, "coding_preview_limit");
      previewFiles.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
      const previewDigest = await sha256(canonical(previewFiles.map((f) => ({ path: f.path, sha256: f.sha256, bytes: Buffer.from(f.content_base64, "base64").length })))), bundle = { files: previewFiles, sha256: previewDigest };
      const next = codingTree(entries, changes), seconds = Math.floor(Date.parse(j.request.payload.issued_at) / 1e3), message = "ScopeBlind bounded coding job " + jobId, person = { name: "ScopeBlind Coding Worker", email: "coding@scopeblind.com", date: new Date(seconds * 1e3).toISOString() }, commitBody = `tree ${next.sha}
parent ${proposal.payload.head_sha}
author ${person.name} <${person.email}> ${seconds} +0000
committer ${person.name} <${person.email}> ${seconds} +0000

${message}
`, commitSha = hash(Buffer.concat([Buffer.from(`commit ${Buffer.byteLength(commitBody)}\0`), Buffer.from(commitBody)]));
      signed = await this.checked(await this.rpc("repository_coding_get", workspaceId, { job_id: jobId }));
      j = signed.payload;
      const plan = await sign({ type: "scopeblind.repository.coding-plan.v1", job_id: jobId, request_digest: j.request.digest, mandate_digest: j.mandate.digest, source_head_sha: proposal.payload.head_sha, source_base_sha: proposal.payload.base_sha, branch: "scopeblind/code/" + jobId, commit_sha: commitSha, tree_sha: next.sha, files: changes, tests, build: { command_digest: await sha256(canonical(m.build_command)), exit_code: 0, output_sha256: await sha256(build.output), duration_ms: build.duration_ms }, preview_digest: previewDigest, model_calls: j.model_calls, reserved_tokens: j.reserved_tokens, issued_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
      j = (await this.checked(await this.rpc("repository_coding_publish", workspaceId, { ...base, plan }))).payload;
      need(j.publication && Date.parse(j.publication.payload.expires_at) > Date.now(), "coding_publication_expired");
      this.publicationUntil = Date.parse(j.publication.payload.expires_at);
      const preview = (await this.rpc("repository_coding_preview", workspaceId, { ...base, bundle })).preview;
      for (const change of changes) if (change.after_sha) {
        const bytes = after.get(change.path);
        const blob = await this.github("/git/blobs", { method: "POST", body: JSON.stringify({ encoding: "base64", content: Buffer.from(bytes).toString("base64") }) });
        need(blob.sha === change.after_sha, "coding_blob_mismatch");
      }
      for (const object7 of next.objects) {
        const made = await this.github("/git/trees", { method: "POST", body: JSON.stringify({ tree: object7.entries }) });
        need(made.sha === object7.sha, "coding_tree_mismatch");
      }
      const commit = await this.github("/git/commits", { method: "POST", body: JSON.stringify({ message: message + "\n", tree: next.sha, parents: [proposal.payload.head_sha], author: person, committer: person }) });
      need(commit.sha === commitSha, "coding_commit_mismatch");
      need(Date.parse(j.publication.payload.expires_at) > Date.now(), "coding_publication_expired");
      await this.github("/git/refs", { method: "POST", body: JSON.stringify({ ref: "refs/heads/" + plan.payload.branch, sha: commitSha }) });
      const pull = await this.github("/pulls", { method: "POST", body: JSON.stringify({ title: "Address review feedback " + jobId, head: plan.payload.branch, base: m.base_branch, draft: true, body: "Prepared under a separate bounded code-edit mandate. Requires a new exact human review before any merge. Source feedback: " + j.request.payload.source.feedback_digest }) });
      need(pull.head?.sha === commitSha, "coding_pull_mismatch");
      const check = await this.github("/check-runs", { method: "POST", body: JSON.stringify({ name: "ScopeBlind isolated coding checks", head_sha: commitSha, status: "completed", conclusion: "success", completed_at: (/* @__PURE__ */ new Date()).toISOString(), output: { title: "Fixed isolated tests and build passed", summary: "Executed the owner-reviewed fixed commands inside a networkless container without credentials. Test output SHA256: " + tests.output_sha256 + ". Build output SHA256: " + plan.payload.build.output_sha256 } }) });
      const deployment = await this.github("/deployments", { method: "POST", body: JSON.stringify({ ref: commitSha, auto_merge: false, required_contexts: [], environment: "ScopeBlind coding preview", transient_environment: true, production_environment: false, payload: { scopeblind_job_id: jobId, preview_digest: previewDigest } }) });
      need(Number.isSafeInteger(deployment.id), "coding_deployment_invalid");
      const deploymentStatus = await this.github("/deployments/" + deployment.id + "/statuses", { method: "POST", body: JSON.stringify({ state: "success", environment_url: preview.url, description: "Content-addressed static preview from isolated build.", auto_inactive: false }) });
      need(deploymentStatus.state === "success", "coding_deployment_invalid");
      await this.result(j, pull, preview, deployment, deploymentStatus, check);
      return true;
    } catch (error) {
      const code = error instanceof Error && /^[a-z0-9_]{3,80}$/.test(error.message) ? error.message : "coding_worker_interrupted";
      await this.rpc("repository_coding_complete", workspaceId, { ...base, error: code }).catch(() => {
      });
      return true;
    } finally {
      this.publicationUntil = 0;
      clearInterval(heartbeat);
      await sandbox?.close();
      if (root) await (0, import_promises.rm)(root, { recursive: true, force: true });
    }
  }
};

// src/repository-trial-template.ts
var TRIAL_BEFORE_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <meta name="description" content="Fieldwork is a small independent design studio making useful things for thoughtful people.">\n  <title>Fieldwork \u2014 Useful things, thoughtfully made</title>\n  <style>\n    :root { color-scheme: light; --paper:#f6f4ed; --ink:#263c31; --muted:#58685b; --line:#d7dccf; --accent:#d9e7b6; }\n    * { box-sizing:border-box; }\n    html { scroll-behavior:smooth; }\n    body { margin:0; background:var(--paper); color:var(--ink); font:16px/1.65 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }\n    a { color:inherit; text-underline-offset:4px; }\n    a:focus-visible { outline:3px solid var(--ink); outline-offset:5px; }\n    .wrap { width:min(1120px,calc(100% - 80px)); margin:auto; }\n    .nav { display:flex; justify-content:space-between; align-items:center; gap:24px; padding:30px 0; border-bottom:1px solid var(--line); }\n    .wordmark { font-family:Georgia,serif; font-size:30px; font-weight:700; letter-spacing:-1.5px; }\n    .nav-note,.eyebrow { font-size:11px; font-weight:650; letter-spacing:.15em; text-transform:uppercase; }\n    .nav-note { color:var(--muted); }\n    .hero { display:grid; grid-template-columns:1.35fr .8fr; gap:72px; align-items:center; padding:90px 0 84px; }\n    .eyebrow { margin:0 0 22px; color:var(--muted); }\n    h1,h2,h3,p { margin-top:0; }\n    h1,h2 { font-family:Georgia,"Times New Roman",serif; font-weight:400; letter-spacing:-.05em; }\n    h1 { max-width:720px; font-size:clamp(48px,6.2vw,82px); line-height:1.06; margin-bottom:27px; }\n    h1 em { font-weight:400; }\n    .intro { max-width:460px; font-size:17px; color:var(--muted); margin-bottom:28px; }\n    .contact-button { display:inline-flex; align-items:center; justify-content:space-between; gap:35px; min-height:52px; padding:12px 22px; border-radius:4px; background:var(--ink); color:#fff; text-decoration:none; font-size:14px; font-weight:600; }\n    .contact-button:hover { background:#38503f; }\n    .studio-card { position:relative; min-height:345px; display:flex; flex-direction:column; justify-content:space-between; background:var(--accent); border-radius:48% 48% 5px 5px; padding:48px 34px 28px; overflow:hidden; }\n    .studio-card::before { content:""; width:155px; height:155px; border:1px solid #8b9f70; border-radius:50%; position:absolute; top:69px; right:-36px; }\n    .card-mark { font:italic 100px/.95 Georgia,serif; letter-spacing:-9px; }\n    .card-caption { max-width:200px; margin:50px 0 0; font-size:14px; line-height:1.55; }\n    .work { padding:35px 0 70px; border-top:1px solid var(--line); }\n    .section-heading { display:flex; justify-content:space-between; align-items:baseline; gap:24px; margin-bottom:26px; }\n    h2 { font-size:37px; line-height:1.15; margin-bottom:0; }\n    .section-heading p { color:var(--muted); font-size:13px; margin-bottom:0; }\n    .projects { display:grid; grid-template-columns:repeat(3,1fr); gap:22px; }\n    .project { margin:0; }\n    .project-art { min-height:180px; display:flex; align-items:center; justify-content:center; border-radius:4px; margin-bottom:16px; }\n    .project-art span { font:35px/1.1 Georgia,serif; text-align:center; }\n    .project-art.one { background:#e3ddd0; }\n    .project-art.two { background:#dfe6dc; }\n    .project-art.three { background:#e8d8cd; }\n    h3 { margin:0 0 3px; font-size:14px; font-weight:650; }\n    .project p { color:var(--muted); font-size:12px; margin-bottom:0; }\n    .about { display:grid; grid-template-columns:1fr 1.2fr; gap:55px; border-top:1px solid var(--line); padding:40px 0 58px; }\n    .about p { max-width:500px; margin:0; color:var(--muted); }\n    footer { border-top:1px solid var(--line); padding:24px 0 36px; display:flex; justify-content:space-between; gap:18px; font-size:11px; color:var(--muted); }\n    @media(max-width:700px) { .wrap{width:calc(100% - 40px)} .nav{padding:22px 0} .nav-note{max-width:130px;text-align:right;font-size:9px} .hero{grid-template-columns:1fr;gap:36px;padding:52px 0} .intro{font-size:16px} .studio-card{min-height:245px;max-width:390px;width:100%;border-radius:100px 100px 4px 4px;padding:35px 28px 24px} .card-mark{font-size:72px} .card-caption{margin:24px 0 0;max-width:250px} .section-heading{display:block} .section-heading p{margin-top:10px} .projects{grid-template-columns:1fr;gap:28px} .project-art{min-height:210px} .about{grid-template-columns:1fr;gap:20px} h2{font-size:32px} footer{flex-direction:column;gap:5px} }\n    @media(prefers-reduced-motion:reduce) { html{scroll-behavior:auto} }\n  </style>\n</head>\n<body>\n  <div class="wrap">\n    <header class="nav"><span class="wordmark">fieldwork.</span><span class="nav-note">Small studio.<br>Thoughtful work.</span></header>\n    <main>\n      <section class="hero" aria-labelledby="intro-heading">\n        <div>\n          <p class="eyebrow">Independent design, with purpose</p>\n          <h1 id="intro-heading">Good ideas.<br><em>Made useful.</em></h1>\n          <p class="intro">We help small teams turn thoughtful ideas into identities, websites, and everyday things people love to use.</p>\n        </div>\n        <aside class="studio-card" aria-label="Our approach"><span class="card-mark" aria-hidden="true">f.</span><p class="card-caption">A little clarity.<br>A considered detail.<br>Something worth putting into the world.</p></aside>\n      </section>\n      <section class="work" aria-labelledby="work-heading">\n        <div class="section-heading"><h2 id="work-heading">A few good beginnings.</h2><p>Identity \xB7 Digital \xB7 Everyday</p></div>\n        <div class="projects">\n          <article class="project"><div class="project-art one" aria-hidden="true"><span>Oat<br>&amp; Ember</span></div><h3>Oat &amp; Ember</h3><p>A warm welcome for a neighborhood bakery.</p></article>\n          <article class="project"><div class="project-art two" aria-hidden="true"><span>slow<br>season</span></div><h3>Slow Season</h3><p>A quieter kind of online home.</p></article>\n          <article class="project"><div class="project-art three" aria-hidden="true"><span>common<br>ground.</span></div><h3>Common Ground</h3><p>Making a shared space feel like yours.</p></article>\n        </div>\n      </section>\n      <section class="about" aria-labelledby="about-heading"><h2 id="about-heading">Small on purpose.</h2><p>You work with the people making the work. We listen closely, ask useful questions, and leave room for the details that make your project yours.</p></section>\n    </main>\n    <footer><span>Fieldwork Studio \xB7 A fictional studio for this shared trial.</span><span>Made with care. Ready for a fresh pair of eyes.</span></footer>\n  </div>\n</body>\n</html>\n';
var TRIAL_SOURCE_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <meta name="description" content="Fieldwork is a small independent design studio making useful things for thoughtful people.">\n  <title>Fieldwork \u2014 Useful things, thoughtfully made</title>\n  <style>\n    :root { color-scheme: light; --paper:#f6f4ed; --ink:#263c31; --muted:#58685b; --line:#d7dccf; --accent:#d9e7b6; }\n    * { box-sizing:border-box; }\n    html { scroll-behavior:smooth; }\n    body { margin:0; background:var(--paper); color:var(--ink); font:16px/1.65 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }\n    a { color:inherit; text-underline-offset:4px; }\n    a:focus-visible { outline:3px solid var(--ink); outline-offset:5px; }\n    .wrap { width:min(1120px,calc(100% - 80px)); margin:auto; }\n    .nav { display:flex; justify-content:space-between; align-items:center; gap:24px; padding:30px 0; border-bottom:1px solid var(--line); }\n    .wordmark { font-family:Georgia,serif; font-size:30px; font-weight:700; letter-spacing:-1.5px; }\n    .nav-note,.eyebrow { font-size:11px; font-weight:650; letter-spacing:.15em; text-transform:uppercase; }\n    .nav-note { color:var(--muted); }\n    .hero { display:grid; grid-template-columns:1.35fr .8fr; gap:72px; align-items:center; padding:90px 0 84px; }\n    .eyebrow { margin:0 0 22px; color:var(--muted); }\n    h1,h2,h3,p { margin-top:0; }\n    h1,h2 { font-family:Georgia,"Times New Roman",serif; font-weight:400; letter-spacing:-.05em; }\n    h1 { max-width:720px; font-size:clamp(48px,6.2vw,82px); line-height:1.06; margin-bottom:27px; }\n    h1 em { font-weight:400; }\n    .intro { max-width:460px; font-size:17px; color:var(--muted); margin-bottom:28px; }\n    .contact-button { display:inline-flex; align-items:center; justify-content:space-between; gap:35px; min-height:52px; padding:12px 22px; border-radius:4px; background:var(--ink); color:#fff; text-decoration:none; font-size:14px; font-weight:600; }\n    .contact-button:hover { background:#38503f; }\n    .studio-card { position:relative; min-height:345px; display:flex; flex-direction:column; justify-content:space-between; background:var(--accent); border-radius:48% 48% 5px 5px; padding:48px 34px 28px; overflow:hidden; }\n    .studio-card::before { content:""; width:155px; height:155px; border:1px solid #8b9f70; border-radius:50%; position:absolute; top:69px; right:-36px; }\n    .card-mark { font:italic 100px/.95 Georgia,serif; letter-spacing:-9px; }\n    .card-caption { max-width:200px; margin:50px 0 0; font-size:14px; line-height:1.55; }\n    .work { padding:35px 0 70px; border-top:1px solid var(--line); }\n    .section-heading { display:flex; justify-content:space-between; align-items:baseline; gap:24px; margin-bottom:26px; }\n    h2 { font-size:37px; line-height:1.15; margin-bottom:0; }\n    .section-heading p { color:var(--muted); font-size:13px; margin-bottom:0; }\n    .projects { display:grid; grid-template-columns:repeat(3,1fr); gap:22px; }\n    .project { margin:0; }\n    .project-art { min-height:180px; display:flex; align-items:center; justify-content:center; border-radius:4px; margin-bottom:16px; }\n    .project-art span { font:35px/1.1 Georgia,serif; text-align:center; }\n    .project-art.one { background:#e3ddd0; }\n    .project-art.two { background:#dfe6dc; }\n    .project-art.three { background:#e8d8cd; }\n    h3 { margin:0 0 3px; font-size:14px; font-weight:650; }\n    .project p { color:var(--muted); font-size:12px; margin-bottom:0; }\n    .about { display:grid; grid-template-columns:1fr 1.2fr; gap:55px; border-top:1px solid var(--line); padding:40px 0 58px; }\n    .about p { max-width:500px; margin:0; color:var(--muted); }\n    footer { border-top:1px solid var(--line); padding:24px 0 36px; display:flex; justify-content:space-between; gap:18px; font-size:11px; color:var(--muted); }\n    @media(max-width:700px) { .wrap{width:calc(100% - 40px)} .nav{padding:22px 0} .nav-note{max-width:130px;text-align:right;font-size:9px} .hero{grid-template-columns:1fr;gap:36px;padding:52px 0} .intro{font-size:16px} .studio-card{min-height:245px;max-width:390px;width:100%;border-radius:100px 100px 4px 4px;padding:35px 28px 24px} .card-mark{font-size:72px} .card-caption{margin:24px 0 0;max-width:250px} .section-heading{display:block} .section-heading p{margin-top:10px} .projects{grid-template-columns:1fr;gap:28px} .project-art{min-height:210px} .about{grid-template-columns:1fr;gap:20px} h2{font-size:32px} footer{flex-direction:column;gap:5px} }\n    @media(prefers-reduced-motion:reduce) { html{scroll-behavior:auto} }\n  </style>\n</head>\n<body>\n  <div class="wrap">\n    <header class="nav"><span class="wordmark">fieldwork.</span><span class="nav-note">Small studio.<br>Thoughtful work.</span></header>\n    <main>\n      <section class="hero" aria-labelledby="intro-heading">\n        <div>\n          <p class="eyebrow">Independent design, with purpose</p>\n          <h1 id="intro-heading">Good ideas.<br><em>Made useful.</em></h1>\n          <p class="intro">We help small teams turn thoughtful ideas into identities, websites, and everyday things people love to use.</p>\n          <a class="contact-button" href="#contact">Get in touch <span aria-hidden="true">\u2197</span></a>\n        </div>\n        <aside class="studio-card" aria-label="Our approach"><span class="card-mark" aria-hidden="true">f.</span><p class="card-caption">A little clarity.<br>A considered detail.<br>Something worth putting into the world.</p></aside>\n      </section>\n      <section class="work" aria-labelledby="work-heading">\n        <div class="section-heading"><h2 id="work-heading">A few good beginnings.</h2><p>Identity \xB7 Digital \xB7 Everyday</p></div>\n        <div class="projects">\n          <article class="project"><div class="project-art one" aria-hidden="true"><span>Oat<br>&amp; Ember</span></div><h3>Oat &amp; Ember</h3><p>A warm welcome for a neighborhood bakery.</p></article>\n          <article class="project"><div class="project-art two" aria-hidden="true"><span>slow<br>season</span></div><h3>Slow Season</h3><p>A quieter kind of online home.</p></article>\n          <article class="project"><div class="project-art three" aria-hidden="true"><span>common<br>ground.</span></div><h3>Common Ground</h3><p>Making a shared space feel like yours.</p></article>\n        </div>\n      </section>\n      <section class="about" aria-labelledby="about-heading"><h2 id="about-heading">Small on purpose.</h2><p>You work with the people making the work. We listen closely, ask useful questions, and leave room for the details that make your project yours.</p></section>\n    </main>\n    <footer><span>Fieldwork Studio \xB7 A fictional studio for this shared trial.</span><span>Made with care. Ready for a fresh pair of eyes.</span></footer>\n  </div>\n</body>\n</html>\n';
var TRIAL_TEST_SOURCE = `'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const file = path.resolve(__dirname, '../site/index.html');
const html = fs.readFileSync(file, 'utf8');

test('the studio remains a self-contained static page', () => {
  assert.ok(fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink(), 'Use a regular HTML file.');
  assert.ok(Buffer.byteLength(html) <= 65536, 'Keep this small page within 64 KiB.');
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /<html\\b[^>]*\\blang=["']en["']/i);
  assert.match(html, /<meta\\b[^>]*\\bname=["']viewport["']/i);
  assert.match(html, /<title>[^<]+<\\/title>/i);
  assert.match(html, /<h1\\b[^>]*>[\\s\\S]+?<\\/h1>/i);
  assert.doesNotMatch(html, /<\\s*(?:script|form|iframe|object|embed|base|link|img|video|audio|source|svg)\\b/i, 'No scripts, forms, embedded content, or external assets in this trial.');
  assert.doesNotMatch(html, /\\bon[a-z]+\\s*=|javascript\\s*:|@import\\b|url\\s*\\(/i, 'Keep behavior to native document links and local styles.');
  assert.doesNotMatch(html, /<meta\\b[^>]*http-equiv\\s*=/i, 'No document redirects.');
  for (const match of html.matchAll(/\\bhref\\s*=\\s*(["'])(.*?)\\1/gi)) {
    assert.match(match[2], /^#[A-Za-z][A-Za-z0-9_-]*$/, 'Links in this trial stay within the document.');
  }
});

test('the contact button reaches a useful contact section', () => {
  assert.match(html, /<a\\b[^>]*\\bhref=["']#contact["'][^>]*>[\\s\\S]*?<\\/a>/i, 'Keep the contact button as a native link to #contact.');
  const section = html.match(/<section\\b[^>]*\\bid=["']contact["'][^>]*>([\\s\\S]*?)<\\/section>/i);
  assert.ok(section, 'The contact link needs a matching contact section.');
  assert.match(section[1], /<h[2-3]\\b[^>]*>[^<]+<\\/h[2-3]>/i, 'Give the contact section a visible heading.');
  const text = section[1].replace(/<[^>]*>/g, ' ').replace(/\\s+/g, ' ').trim();
  assert.ok(text.length >= 40, 'Include useful contact information or a clear next step.');
  assert.match(text, /contact|touch|hello|write|email|conversation/i, 'Make the next step understandable.');
  assert.equal([...html.matchAll(/\\bid\\s*=\\s*["']contact["']/gi)].length, 1, 'Use one unambiguous contact destination.');
  assert.doesNotMatch(section[0], /\\bhidden(?:\\s|=|>)|aria-hidden\\s*=\\s*["']true["']/i, 'The destination must be visible.');
});
`;
var TRIAL_BUILD_SOURCE = "'use strict';\nconst fs = require('node:fs');\nconst path = require('node:path');\nconst root = path.resolve(__dirname, '..');\nconst source = path.join(root, 'site', 'index.html');\nconst stat = fs.lstatSync(source);\nif (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw new Error('Expected one regular HTML file no larger than 64 KiB.');\nconst output = path.join(root, 'dist');\nif (fs.existsSync(output)) {\n  const outStat = fs.lstatSync(output);\n  if (!outStat.isDirectory() || outStat.isSymbolicLink()) throw new Error('Build output must be a regular directory.');\n  fs.rmSync(output, { recursive: true });\n}\nfs.mkdirSync(output);\nfs.copyFileSync(source, path.join(output, 'index.html'));\nprocess.stdout.write('Built dist/index.html from site/index.html.\\n');\n";

// src/coordination-repository-trial.ts
var TRIAL_REPOSITORY = "ScopeBlind/scopeblind-repository-demo";
var TRIAL_WORKFLOW = ".github/workflows/scopeblind-trial.yml";
var TRIAL_TEMPLATE = "styled-contact-v1";
var TRIAL_SOURCE_CHECK = { name: "ScopeBlind trial source safety", app_id: 15368 };
var TRIAL_CODING_CHECK = { name: "ScopeBlind isolated coding checks", app_id: 15368 };
var TRIAL_LIMITS = { max_jobs: 1, max_attempts: 2, max_model_calls: 8, max_tokens: 98304, max_seconds: 600, max_changed_files: 2, max_changed_bytes: 32768 };
var TRIAL_DOCKER_IMAGE = "node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752";
var trialBase = (id7) => `scopeblind/trial/${id7}/base`;
var trialSource = (id7) => `scopeblind/trial/${id7}/source`;
var object6 = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var exact5 = (v, keys) => Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
var key4 = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
var id6 = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
var sha2 = (v) => typeof v === "string" && REPOSITORY_SHA.test(v);
var at7 = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
function validRepositoryTrialRequest(v) {
  return object6(v) && exact5(v, ["type", "id", "owner_key", "authority_key", "title", "template", "reviewer_secret_hash", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.trial-request.v1" && id6(v.id) && key4(v.owner_key) && key4(v.authority_key) && v.owner_key !== v.authority_key && key4(v.reviewer_secret_hash) && v.template === TRIAL_TEMPLATE && typeof v.title === "string" && v.title.trim().length > 0 && v.title.length <= 100 && !/[\u0000-\u001f\u007f]/.test(v.title) && at7(v.issued_at) && at7(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 864e5;
}
function validRepositoryTrialProvision(v) {
  return object6(v) && exact5(v, ["type", "trial_id", "request_digest", "receiver_key", "repository", "template_sha", "base_branch", "source_branch", "base_sha", "source_sha", "pull_number", "before", "source", "source_check", "observed_at"]) && v.type === "scopeblind.repository.trial-provision.v1" && id6(v.trial_id) && [v.request_digest, v.receiver_key].every(key4) && v.repository === TRIAL_REPOSITORY && [v.template_sha, v.base_sha, v.source_sha].every(sha2) && v.base_branch === trialBase(String(v.trial_id)) && v.source_branch === trialSource(String(v.trial_id)) && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && [v.before, v.source].every((h) => object6(h) && exact5(h, ["html", "sha256", "blob_sha"]) && typeof h.html === "string" && new TextEncoder().encode(h.html).length <= 32768 && key4(h.sha256) && sha2(h.blob_sha)) && object6(v.source_check) && exact5(v.source_check, ["id", "name", "app_id", "head_sha", "conclusion"]) && Number.isSafeInteger(v.source_check.id) && Number(v.source_check.id) > 0 && v.source_check.name === TRIAL_SOURCE_CHECK.name && v.source_check.app_id === 15368 && v.source_check.head_sha === v.source_sha && v.source_check.conclusion === "success" && at7(v.observed_at);
}
function trialCodingConfig(id7, endpoint, authority, worker) {
  return { type: "scopeblind.repository.coding-config.v1", endpoint, authority_key: authority, worker_key: worker, repository: TRIAL_REPOSITORY, base_branch: trialBase(id7), runtime: "node22-static-v1", docker_image: TRIAL_DOCKER_IMAGE, test_command: ["node", "--test", "tests/contact.test.cjs"], build_command: ["node", "tools/build.cjs"], preview_directory: "dist" };
}

// src/repository-trial-runner.ts
function need2(ok, code) {
  if (!ok) throw Error(code);
}
async function json2(response, max = 4e6) {
  const reader = response.body?.getReader();
  need2(reader, "trial_response_empty");
  const parts = [];
  let size = 0;
  try {
    for (; ; ) {
      const p = await reader.read();
      if (p.done) break;
      size += p.value.length;
      need2(size <= max, "trial_response_limit");
      parts.push(p.value);
    }
  } finally {
    await reader.cancel().catch(() => {
    });
  }
  return JSON.parse(Buffer.concat(parts).toString("utf8"));
}
var RepositoryTrialRunner = class {
  constructor(config, receiver, worker, token, run, fetcher = fetch, sandboxFactory) {
    this.config = config;
    this.receiver = receiver;
    this.worker = worker;
    this.token = token;
    this.run = run;
    this.fetcher = fetcher;
    this.sandboxFactory = sandboxFactory;
    const u = new URL(config.endpoint);
    need2(u.protocol === "https:" && u.pathname === "/api/coordination" && !u.username && !u.password && !u.search && !u.hash, "trial_endpoint_invalid");
    need2([config.authority_key, config.receiver_key, config.worker_key].every((k) => REPOSITORY_HEX.test(k)) && (/* @__PURE__ */ new Set([config.authority_key, config.receiver_key, config.worker_key])).size === 3 && receiver.publicKey === config.receiver_key && worker.publicKey === config.worker_key && REPOSITORY_SHA.test(config.template_sha) && REPOSITORY_SHA.test(config.workflow_sha) && run.workflow_sha === config.workflow_sha && run.workflow_ref === `${TRIAL_REPOSITORY}/${TRIAL_WORKFLOW}@refs/heads/main` && token, "trial_runner_pins_invalid");
  }
  async rpc(action, id7, body, identity = this.receiver) {
    const request = await sign(makeRequest(action, id7, body), identity), r = await this.fetcher(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json", "x-scopeblind-action": action }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(55e3) }), value = await json2(r);
    need2(r.ok && value.ok === true, typeof value.error === "string" ? value.error : "trial_service_refused");
    return value;
  }
  async github(path, init = {}, missing = false) {
    const r = await this.fetcher("https://api.github.com" + path, { ...init, headers: { authorization: "Bearer " + this.token, accept: "application/vnd.github+json", "content-type": "application/json", "x-github-api-version": "2026-03-10" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
    if (missing && r.status === 404) {
      await r.body?.cancel();
      return null;
    }
    const value = await json2(r);
    need2(r.ok, "trial_github_" + r.status);
    return value;
  }
  get repo() {
    return "/repos/" + TRIAL_REPOSITORY;
  }
  async ref(branch) {
    return (await this.github(this.repo + "/git/ref/heads/" + encodeURIComponent(branch), {}, true))?.object?.sha ?? null;
  }
  async blob(path, sha3) {
    const file = await this.github(this.repo + "/contents/" + path + "?ref=" + sha3);
    need2(file.type === "file" && file.encoding === "base64" && file.size <= 65536, "trial_file_invalid");
    const b = Buffer.from(file.content, "base64");
    need2(b.length === file.size && gitBlob(b) === file.sha, "trial_blob_mismatch");
    return { bytes: b, sha: file.sha };
  }
  async ensureRef(branch, sha3) {
    const old = await this.ref(branch);
    if (old) {
      need2(old === sha3, "trial_ref_conflict");
      return;
    }
    try {
      await this.github(this.repo + "/git/refs", { method: "POST", body: JSON.stringify({ ref: "refs/heads/" + branch, sha: sha3 }) });
    } catch (error) {
      if (await this.ref(branch) !== sha3) throw error;
    }
    need2(await this.ref(branch) === sha3, "trial_ref_readback_mismatch");
  }
  async checked(value, lease) {
    need2(value && await verify(value, this.config.authority_key), "trial_job_signature_invalid");
    const j = value.payload, r = j.request?.payload;
    need2(j.type === "scopeblind.repository.trial-job.v1" && validRepositoryTrialRequest(r) && r.authority_key === this.config.authority_key && await verify(j.request, r.owner_key) && j.lease_id === lease && Date.parse(j.lease_expires_at) > Date.now() && j.receiver_key === this.receiver.publicKey && j.template_sha === this.config.template_sha && canonical(j.config) === canonical(trialCodingConfig(r.id, this.config.endpoint, this.config.authority_key, this.worker.publicKey)) && j.proof.workflow_sha === this.config.workflow_sha && j.proof.workflow_ref === this.run.workflow_ref && j.proof.run_id === this.run.run_id && j.proof.run_attempt === this.run.run_attempt, "trial_job_scope_mismatch");
    need2(j.kind === "reconcile" || j.kind === "coding_reconcile" || Date.parse(r.expires_at) > Date.now(), "trial_expired");
    if (j.workspace) {
      need2(await verifyRepositoryWorkspaceState(j.workspace, this.config.authority_key), "trial_workspace_invalid");
      const w = j.workspace.payload.workspace.payload;
      need2(w.owner_key === r.owner_key && w.repository === TRIAL_REPOSITORY && w.base_branch === trialBase(r.id) && w.receiver_key === this.receiver.publicKey, "trial_workspace_mismatch");
    }
    if (j.provision) need2(validRepositoryTrialProvision(j.provision.payload) && await verify(j.provision, this.receiver.publicKey) && j.provision.payload.request_digest === j.request.digest && j.provision.payload.trial_id === r.id, "trial_provision_invalid");
    return j;
  }
  async provision(j) {
    const r = j.request.payload;
    need2(j.kind === "provision" && !j.target_id, "trial_provision_scope_mismatch");
    const template = await this.github(this.repo + "/git/commits/" + this.config.template_sha);
    need2(template.sha === this.config.template_sha && REPOSITORY_SHA.test(template.tree?.sha), "trial_template_invalid");
    for (const [path, expected] of [["site/index.html", TRIAL_BEFORE_HTML], ["tests/contact.test.cjs", TRIAL_TEST_SOURCE], ["tools/build.cjs", TRIAL_BUILD_SOURCE]]) need2((await this.blob(path, this.config.template_sha)).bytes.toString("utf8") === expected, "trial_template_bytes_changed");
    const baseBranch = trialBase(r.id), sourceBranch = trialSource(r.id);
    await this.ensureRef(baseBranch, this.config.template_sha);
    const tree = await this.github(this.repo + "/git/trees", { method: "POST", body: JSON.stringify({ base_tree: template.tree.sha, tree: [{ path: "site/index.html", mode: "100644", type: "blob", content: TRIAL_SOURCE_HTML }] }) });
    need2(REPOSITORY_SHA.test(tree.sha), "trial_tree_invalid");
    const person = { name: "ScopeBlind Trial", email: "trial@scopeblind.com", date: new Date(Math.floor(Date.parse(r.issued_at) / 1e3) * 1e3).toISOString() }, commit = await this.github(this.repo + "/git/commits", { method: "POST", body: JSON.stringify({ message: "Unfinished managed trial " + r.id, tree: tree.sha, parents: [this.config.template_sha], author: person, committer: person }) });
    need2(REPOSITORY_SHA.test(commit.sha) && commit.tree?.sha === tree.sha && commit.parents?.length === 1 && commit.parents[0].sha === this.config.template_sha, "trial_commit_invalid");
    await this.ensureRef(sourceBranch, commit.sha);
    need2((await this.blob("site/index.html", commit.sha)).bytes.toString("utf8") === TRIAL_SOURCE_HTML, "trial_source_bytes_changed");
    let pulls = await this.github(this.repo + "/pulls?state=all&head=" + encodeURIComponent("ScopeBlind:" + sourceBranch) + "&base=" + encodeURIComponent(baseBranch) + "&per_page=100");
    need2(Array.isArray(pulls) && pulls.length <= 1, "trial_pull_ambiguous");
    let pull = pulls[0];
    if (!pull) {
      try {
        pull = await this.github(this.repo + "/pulls", { method: "POST", body: JSON.stringify({ title: r.title, head: sourceBranch, base: baseBranch, draft: false, body: "Disposable styled starter for a shared AI coding trial. This initial change is deterministic and intentionally unfinished. A separate signed coding mandate and later exact review are required." }) });
      } catch (error) {
        pulls = await this.github(this.repo + "/pulls?state=all&head=" + encodeURIComponent("ScopeBlind:" + sourceBranch) + "&base=" + encodeURIComponent(baseBranch) + "&per_page=100");
        if (!Array.isArray(pulls) || pulls.length !== 1) throw error;
        pull = pulls[0];
      }
    }
    need2(pull.state === "open" && !pull.draft && pull.head?.sha === commit.sha && pull.head?.ref === sourceBranch && pull.base?.ref === baseBranch && pull.base?.repo?.full_name === TRIAL_REPOSITORY && pull.head?.repo?.full_name === TRIAL_REPOSITORY, "trial_pull_mismatch");
    const checkRows = await this.github(this.repo + "/commits/" + commit.sha + "/check-runs?per_page=100&filter=latest");
    let check = checkRows.check_runs?.find((c) => c.name === TRIAL_SOURCE_CHECK.name && c.app?.id === 15368 && c.head_sha === commit.sha && c.conclusion === "success");
    if (!check) {
      need2(TRIAL_SOURCE_HTML.includes('href="#contact"') && !/\bid=["']contact["']/.test(TRIAL_SOURCE_HTML) && !/<script\b|<form\b|@import\b|url\s*\(/i.test(TRIAL_SOURCE_HTML), "trial_source_safety_failed");
      check = await this.github(this.repo + "/check-runs", { method: "POST", body: JSON.stringify({ name: TRIAL_SOURCE_CHECK.name, head_sha: commit.sha, status: "completed", conclusion: "success", output: { title: "Reviewed starter bytes match", summary: "The exact fixed static starter and immutable test/build definitions were checked. The contact destination is intentionally absent; improvement tests have not passed and no AI repair is claimed." } }) });
    }
    need2(check.app?.id === 15368 && check.head_sha === commit.sha && check.conclusion === "success", "trial_source_check_invalid");
    const html = async (value) => ({ html: value, sha256: await sha256(value), blob_sha: gitBlob(Buffer.from(value)) });
    return sign({ type: "scopeblind.repository.trial-provision.v1", trial_id: r.id, request_digest: j.request.digest, receiver_key: this.receiver.publicKey, repository: TRIAL_REPOSITORY, template_sha: this.config.template_sha, base_branch: baseBranch, source_branch: sourceBranch, base_sha: this.config.template_sha, source_sha: commit.sha, pull_number: pull.number, before: await html(TRIAL_BEFORE_HTML), source: await html(TRIAL_SOURCE_HTML), source_check: { id: check.id, name: TRIAL_SOURCE_CHECK.name, app_id: 15368, head_sha: commit.sha, conclusion: "success" }, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.receiver);
  }
  async receive(j) {
    need2(j.workspace && j.assignment && j.task && j.provision && j.target_id === j.task.payload.task.payload.id, "trial_task_required");
    need2((await verifyRepositoryEvidence({ type: "scopeblind.repository.evidence.v1", state: j.task }, this.config.authority_key)).valid, "trial_task_invalid");
    const w = j.workspace.payload, a = j.assignment.payload, t = j.task.payload.task.payload, r = j.request.payload;
    need2(await verify(j.assignment, r.owner_key) && a.workspace_id === w.workspace.payload.id && a.workspace_digest === w.workspace.digest && a.task_digest === j.task.payload.task.digest && a.owner_key === r.owner_key && a.reviewer_key === j.task.payload.reviewer?.payload.reviewer_key && w.assignments.some((x) => x.digest === j.assignment.digest), "trial_assignment_invalid");
    if (j.kind !== "reconcile") for (const [memberId, key5, revision2, role] of [[a.owner_member_id, a.owner_key, a.owner_member_revision, "owner"], [a.reviewer_member_id, a.reviewer_key, a.reviewer_member_revision, "reviewer"]]) need2(w.members.some((m) => m.member_id === memberId && m.current_key === key5 && m.revision === revision2 && m.role === role && m.status === "active"), "trial_membership_changed");
    need2(t.repository === TRIAL_REPOSITORY && t.base_branch === trialBase(r.id) && t.owner_key === r.owner_key && t.receiver_key === this.receiver.publicKey && canonical(t.allowed_paths) === canonical(["site/**"]), "trial_task_scope_mismatch");
    const source = t.pull_number === j.provision.payload.pull_number;
    need2(canonical(t.required_checks) === canonical([source ? TRIAL_SOURCE_CHECK : TRIAL_CODING_CHECK]), "trial_checks_mismatch");
    if (!source) need2(j.coding && (await verifyRepositoryCodingEvidence({ type: "scopeblind.repository.coding-evidence.v1", job: j.coding }, this.config.authority_key)).published && j.coding.payload.request.payload.workspace_id === w.workspace.payload.id && j.coding.payload.result.payload.pull_number === t.pull_number, "trial_child_origin_invalid");
    need2(j.kind !== "execute" || !source, "trial_source_effect_refused");
    const receiver = new RepositoryReceiver({ type: "scopeblind.repository.receiver-config.v1", endpoint: this.config.endpoint, authority_key: this.config.authority_key, owner_key: r.owner_key, reviewer_key: a.reviewer_key, receiver_key: this.receiver.publicKey, repository: TRIAL_REPOSITORY, base_branch: trialBase(r.id) }, this.receiver, this.token, this.fetcher);
    if (j.kind === "inspect") await receiver.inspect(t.id);
    else if (j.kind === "execute") await receiver.execute(t.id);
    else await receiver.reconcile(t.id);
  }
  async coding(j) {
    need2(j.coding && j.workspace && j.target_id === j.coding.payload.request.payload.id && (await verifyRepositoryCodingEvidence({ type: "scopeblind.repository.coding-evidence.v1", job: j.coding }, this.config.authority_key)).valid && j.coding.payload.request.payload.workspace_id === j.workspace.payload.workspace.payload.id, "trial_coding_scope_mismatch");
    const m = j.coding.payload.mandate.payload;
    need2(m.owner_key === j.request.payload.owner_key && m.repository === TRIAL_REPOSITORY && m.base_branch === trialBase(j.request.payload.id) && m.worker_key === this.worker.publicKey && canonical(m.allowed_paths) === canonical(["site/**"]) && canonical(m.required_checks) === canonical([TRIAL_CODING_CHECK]) && Object.entries(TRIAL_LIMITS).every(([k, v]) => m[k] <= v), "trial_coding_limits_mismatch");
    need2(j.kind !== "coding_reconcile" || j.coding.payload.publication, "trial_coding_publication_required");
    const runner = new RepositoryCodingRunner(j.config, this.worker, this.token, this.fetcher, this.sandboxFactory);
    await runner.runOne(j.target_id);
    const current = (await this.rpc("repository_coding_get", m.workspace_id, { job_id: j.target_id }, this.worker)).job;
    need2((await verifyRepositoryCodingEvidence({ type: "scopeblind.repository.coding-evidence.v1", job: current }, this.config.authority_key)).published, "trial_coding_not_published");
    const result = current.payload.result.payload, pull = await this.github(this.repo + "/pulls/" + result.pull_number);
    need2(pull.head?.sha === result.head_sha && pull.head?.ref === result.branch && pull.base?.ref === trialBase(j.request.payload.id) && pull.base?.sha === current.payload.plan.payload.source_base_sha && await this.ref(trialBase(j.request.payload.id)) === current.payload.plan.payload.source_base_sha && pull.state === "open" && pull.base?.repo?.full_name === TRIAL_REPOSITORY && pull.head?.repo?.full_name === TRIAL_REPOSITORY, "trial_coding_pull_changed");
    if (pull.draft) {
      need2(typeof pull.node_id === "string", "trial_pull_node_missing");
      const marked = await this.github("/graphql", { method: "POST", body: JSON.stringify({ query: "mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{id isDraft}}}", variables: { id: pull.node_id } }) });
      need2(!marked.errors?.length && marked.data?.markPullRequestReadyForReview?.pullRequest?.id === pull.node_id && marked.data.markPullRequestReadyForReview.pullRequest.isDraft === false, "trial_ready_readback_required");
    }
    const after = await this.github(this.repo + "/pulls/" + result.pull_number);
    need2(after.draft === false && after.head?.sha === result.head_sha && after.base?.ref === trialBase(j.request.payload.id) && after.base?.sha === current.payload.plan.payload.source_base_sha && await this.ref(trialBase(j.request.payload.id)) === current.payload.plan.payload.source_base_sha, "trial_ready_readback_required");
  }
  async runOne() {
    const lease = crypto.randomUUID(), initial = (await this.rpc("repository_trial_poll", "repository-trial", { lease_id: lease })).poll;
    need2(initial && await verify(initial, this.config.authority_key) && initial.payload.lease_id === lease && initial.payload.challenge.audience === "https://scopeblind.com/repository-trial/" + lease, "trial_challenge_invalid");
    const token = await this.run.oidc(initial.payload.challenge.audience), response = (await this.rpc("repository_trial_poll", "repository-trial", { lease_id: lease, run_id: this.run.run_id, run_attempt: this.run.run_attempt, oidc_token: token })).poll;
    need2(response && await verify(response, this.config.authority_key) && response.payload.lease_id === lease, "trial_poll_invalid");
    if (!response.payload.job) return false;
    const j = await this.checked(response.payload.job, lease);
    let provision = null, error = null;
    try {
      if (j.kind === "provision") provision = await this.provision(j);
      else if (j.kind === "coding" || j.kind === "coding_reconcile") await this.coding(j);
      else await this.receive(j);
    } catch (e) {
      error = e instanceof Error && /^[a-z0-9_]{3,100}$/.test(e.message) ? e.message : "trial_runner_interrupted";
    }
    const completion = await sign({ type: "scopeblind.repository.trial-completion.v1", job_id: j.id, trial_id: j.request.payload.id, request_digest: j.request.digest, lease_id: lease, receiver_key: this.receiver.publicKey, kind: j.kind, provision, error, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.receiver);
    await this.rpc("repository_trial_complete", "repository-trial", { completion });
    if (error) throw Error(error);
    return true;
  }
};
async function runRepositoryTrial() {
  const e = process.env;
  need2(e.GITHUB_ACTIONS === "true" && e.GITHUB_REPOSITORY === TRIAL_REPOSITORY && e.GITHUB_REF === "refs/heads/main" && e.GITHUB_EVENT_NAME === "workflow_dispatch", "trial_trusted_workflow_required");
  const config = JSON.parse(e.SCOPEBLIND_TRIAL_CONFIG || "null");
  need2(config && e.SCOPEBLIND_TRIAL_RECEIVER_KEY && e.SCOPEBLIND_TRIAL_WORKER_KEY && e.GITHUB_TOKEN && e.ACTIONS_ID_TOKEN_REQUEST_URL && e.ACTIONS_ID_TOKEN_REQUEST_TOKEN, "trial_configuration_required");
  const run = { run_id: Number(e.GITHUB_RUN_ID), run_attempt: Number(e.GITHUB_RUN_ATTEMPT), workflow_ref: e.GITHUB_WORKFLOW_REF, workflow_sha: e.GITHUB_WORKFLOW_SHA, oidc: async (audience) => {
    const u = new URL(e.ACTIONS_ID_TOKEN_REQUEST_URL);
    need2(u.protocol === "https:" && u.hostname.endsWith(".actions.githubusercontent.com") && !u.username && !u.password, "trial_oidc_endpoint_invalid");
    u.searchParams.set("audience", audience);
    const r = await fetch(u, { headers: { authorization: "Bearer " + e.ACTIONS_ID_TOKEN_REQUEST_TOKEN }, redirect: "error", signal: AbortSignal.timeout(2e4) }), v = await json2(r, 4e4);
    need2(r.ok && typeof v.value === "string", "trial_oidc_unavailable");
    return v.value;
  } };
  const runner = new RepositoryTrialRunner(config, await importIdentity(e.SCOPEBLIND_TRIAL_RECEIVER_KEY, config.receiver_key), await importIdentity(e.SCOPEBLIND_TRIAL_WORKER_KEY, config.worker_key), e.GITHUB_TOKEN, run);
  const leaseUntil = Date.now() + 30 * 6e4;
  for (let count = 0; count < 6 && Date.now() < leaseUntil; count++) if (!await runner.runOne()) break;
  process.stdout.write("The managed trial controller finished its bounded queue pass.\n");
}

// src/repository-trial-cli.ts
runRepositoryTrial().catch((error) => {
  process.stderr.write("Managed trial stopped: " + (error instanceof Error && /^[a-z0-9_]{3,100}$/.test(error.message) ? error.message : "trial_runner_interrupted") + "\n");
  process.exitCode = 1;
});
