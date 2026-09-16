import {
  canonical,
  sha256,
  verify
} from "./chunk-VS4TVKA7.mjs";

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

// src/coordination-repository-collaboration.ts
var DEMO_REPOSITORY = "ScopeBlind/scopeblind-repository-demo";
var DEMO_CHECK = { name: "ScopeBlind contact validation", app_id: 4962726 };
var CONTACT_PATH = "demo/contact.json";
var object2 = (value) => !!value && typeof value === "object" && !Array.isArray(value);
var shape = (value, required, optional = []) => object2(value) && required.every((key) => key in value) && Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
var text2 = (value, max, empty = false) => typeof value === "string" && (empty || value.trim().length > 0) && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
var hex = (value) => typeof value === "string" && REPOSITORY_HEX.test(value);
var id = (value) => typeof value === "string" && REPOSITORY_ID.test(value);
var sha = (value) => typeof value === "string" && REPOSITORY_SHA.test(value);
var at = (value) => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
var span = (issued, expires, max) => at(issued) && at(expires) && Date.parse(String(expires)) > Date.parse(String(issued)) && Date.parse(String(expires)) - Date.parse(String(issued)) <= max;
var repository = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value);
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
function validRepositoryConnection(v) {
  if (!shape(v, ["type", "id", "endpoint", "repository", "base_branch", "owner_key", "receiver_key", "authority_key", "issued_at", "expires_at"]))
    return false;
  let endpoint;
  try {
    endpoint = new URL(String(v.endpoint));
  } catch {
    return false;
  }
  return v.type === "scopeblind.repository.connection.v1" && id(v.id) && endpoint.protocol === "https:" && endpoint.pathname === "/api/coordination" && !endpoint.search && !endpoint.hash && !endpoint.username && !endpoint.password && endpoint.href === v.endpoint && repository(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(hex) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.authority_key])).size === 3 && span(v.issued_at, v.expires_at, 30 * 864e5);
}
function validRepositoryReadiness(v) {
  if (!shape(v, ["type", "connection_digest", "repository", "base_branch", "owner_key", "receiver_key", "authority_key", "checks", "base_sha", "check_head_sha", "protection", "runtime", "workflow", "observed_at", "expires_at"], ["required_checks", "workflow_sha"]))
    return false;
  return v.type === "scopeblind.repository.readiness.v1" && hex(v.connection_digest) && repository(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(hex) && sha(v.base_sha) && sha(v.check_head_sha) && ["observed", "unavailable"].includes(String(v.protection)) && ["local", "github_actions"].includes(String(v.runtime)) && ["not_checked", "missing", "matching", "different", "unavailable"].includes(String(v.workflow)) && (v.workflow_sha === void 0 || sha(v.workflow_sha)) && span(v.observed_at, v.expires_at, 864e5) && Array.isArray(v.checks) && v.checks.length <= 100 && v.checks.every((c) => shape(c, ["name", "app_id"], ["app_name"]) && text2(c.name, 100) && Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0 && (c.app_name === void 0 || text2(c.app_name, 100))) && (v.required_checks === void 0 || Array.isArray(v.required_checks) && v.required_checks.length <= 100 && v.required_checks.every((c) => shape(c, ["name", "app_id"]) && text2(c.name, 100) && (c.app_id === null || Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0)));
}
function validRepositoryParticipants(v) {
  return shape(v, ["type", "task_id", "task_digest", "owner_key", "receiver_key", "reviewer_key", "reviewer_claim_digest", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.participants.v1" && id(v.task_id) && [v.task_digest, v.owner_key, v.receiver_key, v.reviewer_key, v.reviewer_claim_digest].every(hex) && (/* @__PURE__ */ new Set([v.owner_key, v.receiver_key, v.reviewer_key])).size === 3 && span(v.issued_at, v.expires_at, 7 * 864e5);
}
function validRepositoryPreview(v) {
  return shape(v, ["type", "task_id", "task_digest", "proposal_digest", "base_sha", "head_sha", "merge_sha", "tree_sha", "path", "before", "after", "renderer", "observed_at"]) && v.type === "scopeblind.repository.preview.v1" && id(v.task_id) && hex(v.task_digest) && hex(v.proposal_digest) && [v.base_sha, v.head_sha, v.merge_sha, v.tree_sha].every(sha) && v.path === CONTACT_PATH && v.renderer === "scopeblind.contact-page.v1" && at(v.observed_at) && [v.before, v.after].every((side) => shape(side, ["model", "blob_sha", "content_sha256"]) && validContactPage(side.model) && sha(side.blob_sha) && hex(side.content_sha256));
}
function validRepositoryAgentGrant(v) {
  return shape(v, ["type", "id", "task_id", "task_digest", "issuer_key", "agent_key", "permissions", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.agent-grant.v1" && id(v.id) && id(v.task_id) && [v.task_digest, v.issuer_key, v.agent_key].every(hex) && v.issuer_key !== v.agent_key && Array.isArray(v.permissions) && v.permissions.length > 0 && v.permissions.length <= 2 && new Set(v.permissions).size === v.permissions.length && v.permissions.every((p) => p === "read_task" || p === "request_revision") && v.permissions.includes("read_task") && span(v.issued_at, v.expires_at, 36e5);
}
function validRepositoryRevisionRequest(v) {
  return shape(v, ["type", "id", "task_id", "task_digest", "basis_digest", "requester_key", "message", "proposed", "issued_at"], ["grant_digest"]) && v.type === "scopeblind.repository.revision-request.v1" && id(v.id) && id(v.task_id) && [v.task_digest, v.basis_digest, v.requester_key].every(hex) && (v.grant_digest === void 0 || hex(v.grant_digest)) && text2(v.message, 600) && validContactPage(v.proposed) && at(v.issued_at);
}
function validRepositoryRevisionLink(v) {
  return shape(v, ["type", "id", "parent_task_id", "parent_task_digest", "parent_basis_digest", "request_digest", "child_task_id", "child_task_digest", "owner_key", "issued_at"]) && v.type === "scopeblind.repository.revision-link.v1" && [v.id, v.parent_task_id, v.child_task_id].every(id) && v.parent_task_id !== v.child_task_id && [v.parent_task_digest, v.parent_basis_digest, v.request_digest, v.child_task_digest, v.owner_key].every(hex) && at(v.issued_at);
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

export {
  REPOSITORY_HEX,
  REPOSITORY_SHA,
  REPOSITORY_ID,
  repositoryBranch,
  pathAllowed,
  validRepositoryTask,
  validRepositoryProposal,
  repositorySnapshotDigest,
  verifyRepositoryEvidence,
  DEMO_REPOSITORY,
  DEMO_CHECK,
  CONTACT_PATH,
  validContactPage,
  contactPageBytes,
  parseContactPageJson,
  validRepositoryConnection,
  validRepositoryReadiness,
  validRepositoryParticipants,
  validRepositoryPreview,
  validRepositoryAgentGrant,
  validRepositoryRevisionRequest,
  validRepositoryRevisionLink,
  validRepositoryDemoRequest,
  validRepositoryDemoProvision,
  repositoryRevisionBasis
};
