import {
  createRepositoryReadiness,
  discoverRepository
} from "./chunk-66FWA2ZU.mjs";
import {
  REPOSITORY_GUIDED_WORKFLOW,
  repositorySetupArtifactUrl,
  validRepositoryCodingConnectionConfig,
  validRepositorySetupAuthorization,
  validRepositorySetupInspection,
  verifyRepositorySetupEnrollment,
  verifyRepositorySetupReplacement,
  verifyRepositorySetupState
} from "./chunk-WAOYTUIJ.mjs";
import {
  RepositoryReceiver,
  RepositoryReceiverError,
  discoverRepositoryPreviewChoices
} from "./chunk-E3D47JUV.mjs";
import {
  REPOSITORY_HEX,
  REPOSITORY_ID,
  REPOSITORY_SHA,
  validRepositoryEnvelope,
  verifyRepositoryEvidence
} from "./chunk-W4EKTNR3.mjs";
import {
  bytesToHex,
  canonical,
  importIdentity,
  makeRequest,
  sha256,
  sign,
  verify
} from "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-connect-workflow.ts
var hash = (v) => /^[a-f0-9]{64}$/.test(v);
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

// src/repository-connect.ts
var ENDPOINT = "https://scopeblind.com/api/coordination";
function need(v, code) {
  if (!v) throw new RepositoryReceiverError(code);
}
var object = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var date = () => (/* @__PURE__ */ new Date()).toISOString();
async function json(response, max = 2e6) {
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
  return { status: r.status, body: await json(r) };
}
function parseRepositoryConnectLink(value) {
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new RepositoryReceiverError("connect_private_link_invalid");
  }
  const id = u.searchParams.get("setup"), secret = new URLSearchParams(u.hash.slice(1)).get("setup");
  need(u.origin === "https://scopeblind.com" && u.pathname === "/standard" && !u.username && !u.password && id && REPOSITORY_ID.test(id) && secret && REPOSITORY_HEX.test(secret) && [...u.searchParams.keys()].every((k) => ["setup", "trial", "view"].includes(k)) && [...new URLSearchParams(u.hash.slice(1)).keys()].length === 1, "connect_private_link_invalid");
  return { id, secret };
}
async function rpc(identity, action, id, body, fetchImpl, endpoint = ENDPOINT) {
  const request = await sign(makeRequest(action, id, body), identity), r = await fetchImpl(endpoint, { method: "POST", headers: { "content-type": "application/json", "x-scopeblind-action": action }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(25e3) }), v = await json(r, 4e6);
  need(object(v), "connect_service_invalid");
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
    const key2 = JSON.parse(await readFile(path, "utf8"));
    need(object(key2) && key2.type === "scopeblind.repository.receiver-key.v1" && typeof key2.private_key === "string" && typeof key2.public_key === "string", "connect_key_invalid");
    await importIdentity(key2.private_key, key2.public_key);
    return key2;
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    need(!required, "connect_existing_key_missing");
  }
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]), key = { type: "scopeblind.repository.receiver-key.v1", public_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), private_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))) };
  await writeFile(path, JSON.stringify(key) + "\n", { mode: 384, flag: "wx" });
  return key;
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
  const [repo, pr, files, runs] = await Promise.all([github(base, token, fetchImpl), github(`${base}/pulls/${p.pull_number}`, token, fetchImpl), github(`${base}/pulls/${p.pull_number}/files?per_page=100`, token, fetchImpl), github(`${base}/commits/${discovery.observed_head_sha}/check-runs?per_page=100&filter=latest`, token, fetchImpl)]);
  const r = repo.body, v = pr.body;
  need(object(r) && Number.isSafeInteger(r.id) && Number(r.id) > 0 && object(v) && v.state === "open" && !v.merged && v.number === p.pull_number && object(v.base) && object(v.head) && object(v.base.repo) && object(v.head.repo) && v.base.repo.full_name === p.repository && v.head.repo.full_name === p.repository && v.base.ref === discovery.base_branch && v.base.sha === discovery.base_sha && v.head.sha === discovery.observed_head_sha && typeof v.head.ref === "string" && typeof v.title === "string" && typeof v.draft === "boolean" && (v.mergeable === null || typeof v.mergeable === "boolean"), "connect_pull_changed");
  need(Array.isArray(files.body) && Number.isSafeInteger(v.changed_files) && Number(v.changed_files) <= 50 && files.body.length === v.changed_files, "connect_files_incomplete");
  let excerptBytes = 128 * 1024, remainingPatches = files.body.filter((f) => object(f) && typeof f.patch === "string").length;
  const changes = files.body.map((f) => {
    need(object(f) && typeof f.filename === "string" && ["added", "modified", "removed", "renamed"].includes(String(f.status)) && Number.isSafeInteger(f.additions) && Number.isSafeInteger(f.deletions), "connect_file_invalid");
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
  need(object(runs.body) && Array.isArray(runs.body.check_runs) && runs.body.check_runs.length === runs.body.total_count && runs.body.check_runs.length <= 100, "connect_checks_incomplete");
  const checks = runs.body.check_runs.map((c) => {
    need(object(c) && object(c.app), "connect_check_invalid");
    return { id: Number(c.id), name: String(c.name), app_id: Number(c.app.id), head_sha: String(c.head_sha), status: c.status, conclusion: c.conclusion === null ? null : String(c.conclusion) };
  });
  const choices = await discoverRepositoryPreviewChoices((path) => github(path, token, fetchImpl), p.repository, discovery.observed_head_sha), observed = date(), expires = new Date(Date.now() + 864e5).toISOString(), preview = await sign({ type: "scopeblind.repository.preview-discovery.v1", repository: p.repository, pull_number: p.pull_number, head_sha: discovery.observed_head_sha, owner_key: p.owner_key, receiver_key: identity.publicKey, authority_key: p.authority_key, ...choices, observed_at: observed, expires_at: expires }, identity);
  const latest = (await github(`${base}/pulls/${p.pull_number}`, token, fetchImpl)).body;
  need(object(latest) && object(latest.head) && object(latest.base) && latest.head.sha === v.head.sha && latest.base.sha === v.base.sha && latest.state === "open" && !latest.merged, "connect_pull_changed");
  const inspection = await sign({ type: "scopeblind.repository.setup-inspection.v1", setup_digest: request.digest, owner_key: p.owner_key, receiver_key: identity.publicKey, repository: p.repository, repository_id: Number(r.id), pull_number: p.pull_number, title: v.title, url: `https://github.com/${p.repository}/pull/${p.pull_number}`, base_branch: discovery.base_branch, head_branch: v.head.ref, base_sha: discovery.base_sha, head_sha: discovery.observed_head_sha, draft: v.draft, mergeable: v.mergeable, files: changes, checks, preview, observed_at: observed, expires_at: expires }, identity);
  need(validRepositorySetupInspection(inspection.payload, request, identity.publicKey), "connect_inspection_invalid");
  return { discovery, inspection };
}
function uncommittedSetupEnrollmentStale(local, state, now = Date.now()) {
  return !state.payload.enrollment && local.payload.setup_digest === state.payload.request.digest && [local.payload.issued_at, local.payload.inspection.payload.observed_at, local.payload.readiness.payload.observed_at].some((time) => now - Date.parse(time) > 3e5);
}
function currentGuidedCodingReady(state, now = Date.now()) {
  return !state.payload.enrollment?.payload.coding || !!state.payload.coding_ready && Date.parse(state.payload.coding_ready.ready.payload.expires_at) > now;
}
async function stdinLink(stdout) {
  stdout("Paste the private connection link, then press Enter (it is not placed in the command or shell history):\n");
  const { createInterface } = await import("readline");
  const reader = createInterface({ input: process.stdin, terminal: false });
  for await (const line of reader) {
    reader.close();
    need(line.length <= 8e3, "connect_private_link_invalid");
    return line.trim();
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
  const repo = c.payload.repository, root = "/repos/" + repo, installationFiles = [{ path: REPOSITORY_GUIDED_WORKFLOW, content: e.installation.workflow }, ...e.coding ? [{ path: ".github/workflows/scopeblind-coding.yml", content: e.coding.workflow }] : []];
  const metadata = api(root);
  need(object(metadata) && object(metadata.permissions) && metadata.permissions.admin === true && metadata.default_branch === c.payload.base_branch, "connect_install_repository_admin_required");
  const variables = api(root + "/actions/variables?per_page=30");
  need(object(variables) && Array.isArray(variables.variables) && Number(variables.total_count) <= 30, "connect_variables_incomplete");
  const variableRows = variables.variables;
  const planned = [{ name: "SCOPEBLIND_GUIDED_CONNECTION", value: JSON.stringify(config) }, ...e.coding ? [{ name: "SCOPEBLIND_CODING_CONNECTION", value: JSON.stringify(e.coding.config) }] : []];
  const prior = e.replaces;
  need(!prior || await verifyRepositorySetupReplacement(prior, c.payload), "connect_replacement_invalid");
  for (const v of planned) {
    const old = variableRows.find((x) => object(x) && x.name === v.name);
    need(!old || object(old) && (old.value === v.value || v.name === "SCOPEBLIND_GUIDED_CONNECTION" && prior && old.value === JSON.stringify(prior)), "connect_existing_config_conflict");
  }
  const existing = /* @__PURE__ */ new Map();
  for (const file of installationFiles) {
    let value;
    try {
      value = api(root + "/contents/" + file.path + "?ref=" + encodeURIComponent(c.payload.base_branch));
    } catch (error) {
      const tree = api(root + "/git/trees/" + encodeURIComponent(c.payload.base_branch) + "?recursive=1");
      need(object(tree) && tree.truncated === false && Array.isArray(tree.tree) && !tree.tree.some((x) => object(x) && x.path === file.path), "connect_existing_workflow_unreadable");
      value = null;
    }
    if (value) {
      need(object(value) && value.type === "file" && value.encoding === "base64" && typeof value.content === "string", "connect_existing_workflow_conflict");
      const oldBytes = Buffer.from(value.content, "base64").toString("utf8"), same = oldBytes === file.content;
      need(same || prior && file.path === REPOSITORY_GUIDED_WORKFLOW && await sha256(oldBytes) === prior.authorization.payload.workflow_sha256, "connect_existing_workflow_conflict");
      existing.set(file.path, { sha: String(value.sha), replace: !same });
    }
  }
  const secrets = api(root + "/actions/secrets?per_page=100");
  need(object(secrets) && Array.isArray(secrets.secrets) && Number(secrets.total_count) <= 100, "connect_secrets_incomplete");
  for (const name of ["SCOPEBLIND_GUIDED_RECEIVER_KEY", ...e.coding ? ["SCOPEBLIND_CODING_WORKER_KEY"] : []]) {
    const exists = secrets.secrets.some((x) => object(x) && x.name === name);
    need(!exists || name === "SCOPEBLIND_GUIDED_RECEIVER_KEY" && prior || planned.every((v) => variableRows.some((x) => object(x) && x.name === v.name && x.value === v.value)), "connect_existing_secret_conflict");
  }
  for (const file of installationFiles) if (!existing.has(file.path) || existing.get(file.path).replace) api(root + "/contents/" + file.path, "PUT", { message: "Install explicitly reviewed ScopeBlind connection", content: Buffer.from(file.content, "utf8").toString("base64"), branch: c.payload.base_branch, ...existing.has(file.path) ? { sha: existing.get(file.path).sha } : {} });
  for (const v of planned) gh(["variable", "set", v.name, "--repo", repo], v.value);
  gh(["secret", "set", "SCOPEBLIND_GUIDED_RECEIVER_KEY", "--repo", repo], receiver.private_key);
  if (e.coding) {
    need(coding && coding.public_key === e.coding.config.worker_key, "connect_coding_key_missing");
    gh(["secret", "set", "SCOPEBLIND_CODING_WORKER_KEY", "--repo", repo], coding.private_key);
  }
  gh(["workflow", "run", "scopeblind-connection.yml", "--repo", repo, "--ref", c.payload.base_branch, "-f", "job_id=" + (readyJobId ?? "ready-" + s.request.payload.id)]);
  if (e.coding) gh(["workflow", "run", "scopeblind-coding.yml", "--repo", repo, "--ref", c.payload.base_branch, "-f", "job_id=" + s.request.payload.id]);
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
  const key = await privateKey(join(dir, "receiver-key.json")), identity = await importIdentity(key.private_key, key.public_key), infoResponse = await fetchImpl(ENDPOINT + "?op=info", { redirect: "error", signal: AbortSignal.timeout(2e4) }), info = await json(infoResponse, 1e4);
  need(infoResponse.ok && object(info) && info.ok === true && typeof info.authority_key === "string" && REPOSITORY_HEX.test(info.authority_key), "connect_service_pin_invalid");
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
      need(object(current) && typeof current.value === "string", "connect_replacement_config_missing");
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
    await installReviewedConnection(state, key, codingKey, env, void 0, await prepareReadyJob());
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
  const response = await fetchImpl(url, { headers: { authorization: "Bearer " + env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }, redirect: "error", signal: AbortSignal.timeout(2e4) }), value = await json(response, 4e4);
  need(response.ok && object(value) && typeof value.value === "string", "connect_actions_oidc_unavailable");
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
    if (pull.status === 200 && object(pull.body) && (pull.body.state === "closed" || pull.body.merged === true)) {
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
export {
  currentGuidedCodingReady,
  inspectRepositorySetup,
  installReviewedConnection,
  observeGuidedReadiness,
  parseRepositoryConnectLink,
  runRepositoryConnect,
  uncommittedSetupEnrollmentStale
};
