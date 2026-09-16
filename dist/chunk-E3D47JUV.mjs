import {
  REPOSITORY_HEX,
  REPOSITORY_ID,
  REPOSITORY_SHA,
  pathAllowed,
  repositoryBranch,
  repositorySnapshotDigest,
  safeRepositoryPreviewUrl,
  validRepositoryProposal,
  validRepositoryReviewBrief,
  validRepositoryReviewPacket,
  verifyRepositoryEvidence,
  verifyRepositoryReviewEvidence
} from "./chunk-W4EKTNR3.mjs";
import {
  bytesToHex,
  canonical,
  importIdentity,
  makeRequest,
  sign,
  verify
} from "./chunk-O3K3FPBT.mjs";

// src/repository-review-preview.ts
var positive = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
var timestamp = (v) => typeof v === "string" && Number.isFinite(Date.parse(v));
var unavailable = () => ({ status: "unavailable", reason: "GitHub did not provide a complete, verifiable preview observation. No preview URL was inferred." });
async function observeRepositoryReviewPreview(get, repository, brief, proposal, now = Date.now()) {
  const policy = brief.payload.preview_policy;
  if (!policy) return { status: "not_requested", reason: "This brief does not require or identify a deployment preview." };
  const repo = `/repos/${repository.split("/").map(encodeURIComponent).join("/")}`, head = proposal.payload.head_sha;
  try {
    const deployments = (await get(`${repo}/deployments?sha=${head}&environment=${encodeURIComponent(policy.environment)}&per_page=100`)).body;
    if (!Array.isArray(deployments) || deployments.length >= 100) return unavailable();
    if (!deployments.length) return { status: "missing", reason: "GitHub has no deployment for the exact proposed head and selected environment." };
    if (!deployments.every((d) => positive(d.id) && d.sha === head && d.environment === policy.environment && timestamp(d.created_at) && positive(d.creator?.id) && Date.parse(d.created_at) <= now)) return unavailable();
    const sorted = [...deployments].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id), deployment = sorted[0];
    if (new Set(sorted.map((d) => d.id)).size !== sorted.length) return unavailable();
    const statuses = (await get(`${repo}/deployments/${deployment.id}/statuses?per_page=100`)).body;
    if (!Array.isArray(statuses) || statuses.length >= 100) return unavailable();
    if (!statuses.length) return { status: "pending", reason: "The newest matching deployment has not reported a status." };
    if (!statuses.every((s) => positive(s.id) && timestamp(s.created_at) && timestamp(s.updated_at) && Date.parse(s.updated_at) >= Date.parse(s.created_at) && Date.parse(s.updated_at) <= now && positive(s.creator?.id))) return unavailable();
    const status = [...statuses].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id)[0];
    if (["pending", "queued", "in_progress"].includes(status.state)) return { status: "pending", reason: "The newest matching deployment is still in progress." };
    if (["failure", "error", "inactive"].includes(status.state)) return { status: "failed", reason: "The newest matching deployment is not a successful active preview." };
    if (status.state !== "success" || status.environment !== policy.environment || !safeRepositoryPreviewUrl(status.environment_url) || !policy.allowed_origins.includes(new URL(status.environment_url).origin)) return unavailable();
    const body = (await get(`${repo}/commits/${head}/check-runs?per_page=100&filter=latest`)).body;
    if (!body || !Number.isSafeInteger(body.total_count) || body.total_count < 0 || body.total_count > 100 || !Array.isArray(body.check_runs) || body.check_runs.length !== body.total_count) return unavailable();
    const matching = body.check_runs.filter((c) => c.name === policy.check.name && c.app?.id === policy.check.app_id);
    if (!matching.length) return { status: "unavailable", reason: "The named check from the pinned GitHub App was not observed at this head." };
    if (!matching.every((c) => positive(c.id) && c.head_sha === head)) return unavailable();
    const check = matching.sort((a, b) => b.id - a.id)[0];
    if (check.status !== "completed") return { status: "pending", reason: "The pinned preview check has not completed at the proposed head." };
    if (check.conclusion !== "success") return { status: "failed", reason: "The pinned preview check did not succeed at the proposed head." };
    return { status: "available", deployment: { deployment_id: deployment.id, status_id: status.id, sha: head, environment: policy.environment, state: "success", environment_url: status.environment_url, deployment_creator_id: deployment.creator.id, status_creator_id: status.creator.id, created_at: new Date(deployment.created_at).toISOString(), updated_at: new Date(status.updated_at).toISOString(), check: { id: check.id, name: policy.check.name, app_id: policy.check.app_id, head_sha: head, conclusion: "success" } } };
  } catch {
    return unavailable();
  }
}
async function discoverRepositoryPreviewChoices(get, repository, head, now = Date.now()) {
  const repo = `/repos/${repository.split("/").map(encodeURIComponent).join("/")}`;
  try {
    const [deployments, runs] = await Promise.all([get(`${repo}/deployments?sha=${head}&per_page=100`).then((r) => r.body), get(`${repo}/commits/${head}/check-runs?per_page=100&filter=latest`).then((r) => r.body)]);
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
      const rows = (await get(`${repo}/deployments/${d.id}/statuses?per_page=100`)).body;
      if (!Array.isArray(rows) || rows.length >= 100) throw Error();
      if (!rows.length) continue;
      const sorted = [...rows].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id), s = sorted[0];
      if (!positive(s.id) || !timestamp(s.created_at) || !timestamp(s.updated_at) || Date.parse(s.updated_at) > now) throw Error();
      if (s.state === "success" && s.environment === d.environment && safeRepositoryPreviewUrl(s.environment_url)) candidates.push({ environment: d.environment, origin: new URL(s.environment_url).origin, environment_url: s.environment_url, deployment_id: d.id, status_id: s.id });
    }
    const checks = [];
    for (const c of runs.check_runs) {
      if (c.status !== "completed" || c.conclusion !== "success") continue;
      if (c.head_sha !== head || !positive(c.id) || !positive(c.app?.id) || typeof c.name !== "string" || !c.name.trim() || c.name.length > 100 || /[\u0000-\u001f\u007f]/.test(c.name)) throw Error();
      const i = checks.findIndex((x) => x.name === c.name && x.app_id === c.app.id);
      const item = { id: c.id, name: c.name, app_id: c.app.id };
      if (i < 0) checks.push(item);
      else if (c.id > checks[i].id) checks[i] = item;
    }
    return { status: "observed", candidates, checks };
  } catch {
    return { status: "unavailable", candidates: [], checks: [] };
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
    const preview = await observeRepositoryReviewPreview((path) => this.github(path), this.config.repository, brief, proposal), observedAt = (/* @__PURE__ */ new Date()).toISOString(), expiresAt = new Date(Math.min(Date.now() + 9e5, Date.parse(brief.payload.expires_at))).toISOString();
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
  if (out) await writeFile(out, JSON.stringify(await receiver.reviewEvidence(task), null, 2) + "\n", { mode: 384 });
  process.stdout.write(`Repository task ${task}: ${result.payload.status}. No PR code was executed by this receiver.
`);
}

export {
  discoverRepositoryPreviewChoices,
  RepositoryReceiverError,
  RepositoryReceiver,
  runRepositoryReceiver
};
