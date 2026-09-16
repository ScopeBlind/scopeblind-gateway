import {
  RepositoryReceiver,
  RepositoryReceiverError
} from "./chunk-RJYX2HEV.mjs";
import {
  DEMO_CHECK,
  DEMO_REPOSITORY,
  REPOSITORY_SHA,
  parseContactPageJson,
  repositoryRevisionBasis,
  validContactPage,
  validRepositoryDemoProvision,
  validRepositoryDemoRequest,
  validRepositoryParticipants,
  validRepositoryTask,
  verifyRepositoryEvidence
} from "./chunk-W4EKTNR3.mjs";
import {
  canonical,
  importIdentity,
  makeRequest,
  sha256,
  sign,
  verify
} from "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

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
    const bytes = Buffer.from(value.content, "base64"), text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    need(bytes.length === value.size, "demo_file_size_mismatch");
    const model = parseContactPageJson(text);
    return { model, blob_sha: value.sha, content_sha256: await sha256(text) };
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
