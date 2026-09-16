import {
  REPOSITORY_ID,
  REPOSITORY_SHA,
  codingCommand,
  codingSafePath,
  pathAllowed,
  verifyRepositoryCodingEvidence
} from "./chunk-W4EKTNR3.mjs";
import {
  canonical,
  importIdentity,
  makeRequest,
  sha256,
  sign
} from "./chunk-O3K3FPBT.mjs";

// src/repository-coding-runner.ts
import { mkdtemp, readFile, writeFile, mkdir, opendir, lstat, rm } from "fs/promises";
import { tmpdir } from "os";
import { join, dirname, relative } from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { createHash, randomUUID } from "crypto";
var execute = promisify(execFile);
var hash = (v) => createHash("sha1").update(v).digest("hex");
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
    const name = "scopeblind-coding-" + randomUUID(), started = Date.now(), args = ["run", "--name", name, "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--user", `${process.getuid?.() ?? 1e3}:${process.getgid?.() ?? 1e3}`, "--mount", `type=bind,source=${this.directory},target=/workspace`, "--workdir", "/workspace", this.image, ...command];
    this.containers.add(name);
    try {
      const r = await this.dockerExecute("docker", args, { timeout, killSignal: "SIGKILL", maxBuffer: 65536, env: { PATH: process.env.PATH } });
      return { exit_code: 0, output: r.stdout + "\n" + r.stderr, duration_ms: Date.now() - started };
    } catch (e) {
      const error = e;
      return { exit_code: Number.isSafeInteger(error.code) ? Number(error.code) : 124, output: (error.stdout || "") + "\n" + (error.stderr || ""), duration_ms: Date.now() - started };
    } finally {
      await this.remove(name);
    }
  }
  async remove(name) {
    try {
      await this.dockerExecute("docker", ["rm", "--force", name], { timeout: 1e4, killSignal: "SIGKILL", maxBuffer: 4096, env: { PATH: process.env.PATH } });
    } catch (error) {
      const e = error;
      if (e.code !== 1 || e.stderr?.trim() !== `Error response from daemon: No such container: ${name}`) {
        this.closed = true;
        throw Error("coding_sandbox_cleanup_failed");
      }
    }
    this.containers.delete(name);
  }
  async close() {
    this.closed = true;
    const results = await Promise.allSettled([...this.containers].map((name) => this.remove(name)));
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
async function safeWrite(root, path, content) {
  need(codingSafePath(path), "coding_path_forbidden");
  const parts = path.split("/");
  let current = root;
  for (const p of parts.slice(0, -1)) {
    current = join(current, p);
    try {
      const s = await lstat(current);
      need(s.isDirectory() && !s.isSymbolicLink(), "coding_symlink_forbidden");
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
      await mkdir(current);
    }
  }
  const file = join(root, path);
  try {
    const s = await lstat(file);
    need(s.isFile() && !s.isSymbolicLink(), "coding_symlink_forbidden");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  if (content === null) await rm(file, { force: true });
  else await writeFile(file, content, { mode: 384 });
}
async function scanCodingWorkspace(root) {
  const found = /* @__PURE__ */ new Map();
  let nodes = 0, bytes = 0;
  const visit = async (dir, depth) => {
    need(depth <= 10, "coding_directory_depth_limit");
    for await (const entry of await opendir(dir)) {
      need(++nodes <= 1200, "coding_node_limit");
      const path = join(dir, entry.name), s = await lstat(path), rel = relative(root, path);
      need(rel.length <= 200 && !s.isSymbolicLink(), "coding_symlink_forbidden");
      if (s.isDirectory()) await visit(path, depth + 1);
      else {
        need(s.isFile() && s.size <= 524288, "coding_file_limit");
        need(bytes + s.size <= 2 * 1024 * 1024, "coding_workspace_byte_limit");
        const content = await readFile(path);
        bytes += content.length;
        need(bytes <= 2 * 1024 * 1024 && content.length === s.size, "coding_workspace_byte_limit");
        found.set(rel, content);
        need(found.size <= 1e3, "coding_file_count_limit");
      }
    }
  };
  await visit(root, 0);
  return found;
}
function assertCodingWorkspaceUnchanged(before, after, previewDirectory) {
  for (const path of /* @__PURE__ */ new Set([...before.keys(), ...after.keys()])) {
    if (previewDirectory && (path === previewDirectory || path.startsWith(previewDirectory + "/"))) continue;
    const a = before.get(path), b = after.get(path);
    need(a && b && Buffer.compare(a, b) === 0, "coding_test_or_build_modified_source");
  }
}
function codingChanges(before, after, m) {
  const changes = [];
  for (const p of /* @__PURE__ */ new Set([...before.keys(), ...after.keys()])) {
    if (p === m.preview_directory || p.startsWith(m.preview_directory + "/")) continue;
    const a = before.get(p), b = after.get(p);
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
    const data = Buffer.concat(rows.map((r) => Buffer.concat([Buffer.from(`${r.type === "tree" ? "40000" : r.mode} ${r.path}\0`), Buffer.from(r.sha, "hex")]))), sha = hash(Buffer.concat([Buffer.from(`tree ${data.length}\0`), data]));
    objects.push({ path: prefix, sha, entries: rows });
    return sha;
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
  async rpc(action, id, body = {}) {
    const request = await sign(makeRequest(action, id, body), this.identity), r = await this.fetcher(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json", "x-scopeblind-action": action }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(55e3) }), v = await bounded(r);
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
  async result(j, pull, preview, deployment, status, check) {
    need(check.name === "ScopeBlind isolated coding checks" && check.app?.id === 15368 && check.head_sha === j.plan.payload.commit_sha && check.conclusion === "success", "coding_check_invalid");
    const result = await sign({ type: "scopeblind.repository.coding-result.v1", job_id: j.request.payload.id, plan_digest: j.plan.digest, publication_digest: j.publication.digest, repository: this.config.repository, branch: j.plan.payload.branch, head_sha: j.plan.payload.commit_sha, pull_number: pull.number, pull_url: `https://github.com/${this.config.repository}/pull/${pull.number}`, preview_url: preview.url, preview_digest: preview.digest, deployment_id: deployment.id, deployment_status_id: status.id, deployment_environment: "ScopeBlind coding preview", check: { id: check.id, name: "ScopeBlind isolated coding checks", app_id: 15368, head_sha: j.plan.payload.commit_sha, conclusion: "success" }, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.identity);
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
        const statuses = await this.github("/deployments/" + deployment2.id + "/statuses?per_page=100"), status = statuses[0];
        need(status?.state === "success" && typeof status.environment_url === "string" && status.environment_url.includes(j.plan.payload.preview_digest), "coding_publication_unknown");
        const checks = await this.github("/commits/" + j.plan.payload.commit_sha + "/check-runs?check_name=ScopeBlind%20isolated%20coding%20checks&per_page=100"), check2 = checks.check_runs?.find((c) => c.name === "ScopeBlind isolated coding checks" && c.app?.id === 15368 && c.head_sha === j.plan.payload.commit_sha && c.conclusion === "success");
        need(check2, "coding_publication_unknown");
        await this.result(j, pull2, { url: status.environment_url, digest: j.plan.payload.preview_digest }, deployment2, status, check2);
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
      root = await mkdtemp(join(tmpdir(), "scopeblind-code-"));
      const before = /* @__PURE__ */ new Map();
      let total = 0;
      for (const f of entries) {
        if (!codingSafePath(f.path)) continue;
        need(f.size <= 131072, "coding_source_file_limit");
        const blob = await this.github("/git/blobs/" + f.sha);
        need(blob.encoding === "base64" && typeof blob.content === "string", "coding_source_blob_invalid");
        const bytes = Buffer.from(blob.content, "base64");
        total += bytes.length;
        need(total <= 524288 && bytes.length === blob.size && gitBlob(bytes) === f.sha, "coding_source_integrity");
        before.set(f.path, bytes);
        await mkdir(dirname(join(root, f.path)), { recursive: true });
        await writeFile(join(root, f.path), bytes, { mode: 384 });
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
      const changes = codingChanges(before, after, m), previewFiles = [...after].filter(([p]) => p.startsWith(m.preview_directory + "/")).map(([p, b]) => ({ path: p.slice(m.preview_directory.length + 1), content_base64: Buffer.from(b).toString("base64"), sha256: createHash("sha256").update(b).digest("hex") }));
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
      for (const object of next.objects) {
        const made = await this.github("/git/trees", { method: "POST", body: JSON.stringify({ tree: object.entries }) });
        need(made.sha === object.sha, "coding_tree_mismatch");
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
      if (root) await rm(root, { recursive: true, force: true });
    }
  }
};
async function runRepositoryCoding(args = process.argv.slice(2)) {
  let file, jobId = process.env.JOB_ID;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--config" && !file && args[i + 1]) file = args[++i];
    else if (args[i] === "--job" && args[i + 1]) jobId = args[++i];
    else throw Error("coding_argument_invalid");
  }
  const raw = file ? await readFile(file, "utf8") : process.env.SCOPEBLIND_CODING_CONNECTION, key = process.env.SCOPEBLIND_CODING_WORKER_KEY, token = process.env.GITHUB_TOKEN;
  need(raw && key && token, "coding_configuration_required");
  const config = JSON.parse(raw), identity = await importIdentity(key, config.worker_key);
  const runner = new RepositoryCodingRunner(config, identity, token);
  await runner.runOne(jobId);
}

export {
  DockerCodingSandbox,
  RepositoryCodingRunner,
  runRepositoryCoding
};
