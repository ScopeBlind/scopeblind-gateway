import {
  RepositoryReceiverError,
  discoverRepositoryPreviewChoices,
  runRepositoryReceiver
} from "./chunk-RJYX2HEV.mjs";
import {
  REPOSITORY_HEX,
  REPOSITORY_SHA,
  repositoryBranch,
  validRepositoryConnection,
  validRepositoryReadiness
} from "./chunk-W4EKTNR3.mjs";
import {
  COORDINATION_DOMAIN,
  bytesToHex,
  canonical,
  importIdentity,
  sha256,
  sign
} from "./chunk-O3K3FPBT.mjs";

// src/repository-setup.ts
var REPOSITORY_SETUP_VERSION = "0.24.1";
var REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/;
var WORKFLOW_PATH = ".github/workflows/scopeblind-receiver.yml";
var safeText = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
function need(v, code) {
  if (!v) throw new RepositoryReceiverError(code);
}
async function readJson(response, max = 2e6) {
  const reader = response.body?.getReader();
  need(reader, "setup_empty_response");
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
async function github(path, token, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(`https://api.github.com${path}`, { method: "GET", headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2026-03-10" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
  } catch {
    throw new RepositoryReceiverError("setup_github_unavailable");
  }
  if ([403, 404].includes(response.status)) return { status: response.status, body: null };
  need(response.ok, `setup_github_http_${response.status}`);
  return { status: response.status, body: await readJson(response) };
}
async function discoverRepository(input, token, fetchImpl = fetch) {
  need(REPO.test(input.repository) && token.length > 0, "setup_repository_and_github_login_required");
  if (input.pull_number !== void 0) need(Number.isSafeInteger(input.pull_number) && input.pull_number > 0, "setup_invalid_pull_number");
  const path = `/repos/${input.repository.split("/").map(encodeURIComponent).join("/")}`;
  const repo = await github(path, token, fetchImpl);
  need(repo.status === 200 && REPO.test(repo.body.full_name) && repo.body.full_name.toLowerCase() === input.repository.toLowerCase() && repositoryBranch(repo.body.default_branch) && !repo.body.archived && !repo.body.disabled, "setup_repository_unavailable");
  const base = input.base_branch ?? repo.body.default_branch;
  need(repositoryBranch(base) && base === repo.body.default_branch, "setup_use_trusted_default_branch");
  const branch = await github(`${path}/branches/${encodeURIComponent(base)}`, token, fetchImpl);
  need(branch.status === 200 && branch.body.name === base && REPOSITORY_SHA.test(branch.body.commit?.sha), "setup_base_branch_unavailable");
  let head = branch.body.commit.sha;
  if (input.pull_number) {
    const pr = await github(`${path}/pulls/${input.pull_number}`, token, fetchImpl);
    need(pr.status === 200 && pr.body.number === input.pull_number && pr.body.state === "open" && !pr.body.merged && pr.body.base?.ref === base && pr.body.base?.repo?.full_name === repo.body.full_name && pr.body.head?.repo?.full_name === repo.body.full_name && REPOSITORY_SHA.test(pr.body.head?.sha), "setup_same_repository_pull_required");
    head = pr.body.head.sha;
  }
  const [runs, protection, rules, workflow] = await Promise.all([
    github(`${path}/commits/${head}/check-runs?per_page=100&filter=latest`, token, fetchImpl),
    github(`${path}/branches/${encodeURIComponent(base)}/protection`, token, fetchImpl),
    github(`${path}/rules/branches/${encodeURIComponent(base)}`, token, fetchImpl),
    github(`${path}/contents/${input.workflow_path ?? WORKFLOW_PATH}?ref=${encodeURIComponent(base)}`, token, fetchImpl)
  ]);
  need(runs.status === 200 && Number.isSafeInteger(runs.body.total_count) && runs.body.total_count >= 0 && runs.body.total_count <= 100 && Array.isArray(runs.body.check_runs) && runs.body.check_runs.length === runs.body.total_count, "setup_checks_incomplete");
  const checks = [];
  for (const run of runs.body.check_runs) {
    need(run.head_sha === head && safeText(run.name, 100) && Number.isSafeInteger(run.app?.id) && run.app.id > 0, "setup_invalid_check_provider");
    if (!checks.some((c) => c.name === run.name && c.app_id === run.app.id)) checks.push({ name: run.name, app_id: run.app.id, ...safeText(run.app.name, 100) ? { app_name: run.app.name } : {} });
  }
  need(checks.length <= 100, "setup_checks_incomplete");
  checks.sort((a, b) => a.name.localeCompare(b.name) || a.app_id - b.app_id);
  const required = [];
  const add = (name, id) => {
    need(safeText(name, 100) && (id === null || id === void 0 || id === -1 || Number.isSafeInteger(id) && Number(id) > 0), "setup_invalid_required_check");
    const check = { name, app_id: Number.isSafeInteger(id) && Number(id) > 0 ? Number(id) : null };
    if (!required.some((c) => c.name === check.name && c.app_id === check.app_id)) required.push(check);
    need(required.length <= 100, "setup_rules_incomplete");
  };
  if (protection.status === 200) {
    const status = protection.body.required_status_checks;
    if (status) {
      need(Array.isArray(status.contexts) && Array.isArray(status.checks), "setup_invalid_branch_protection");
      for (const c of status.checks) add(c.context, c.app_id);
      for (const context of status.contexts) if (!status.checks.some((c) => c.context === context)) add(context, null);
    }
  }
  if (rules.status === 200) {
    need(Array.isArray(rules.body) && rules.body.length <= 100, "setup_rules_incomplete");
    for (const rule of rules.body) if (rule.type === "required_status_checks") {
      need(Array.isArray(rule.parameters?.required_status_checks), "setup_invalid_repository_rules");
      for (const c of rule.parameters.required_status_checks) add(c.context, c.integration_id);
    }
  }
  let workflowSha, workflowHash;
  if (workflow.status === 200) {
    need(workflow.body.type === "file" && workflow.body.path === (input.workflow_path ?? WORKFLOW_PATH) && REPOSITORY_SHA.test(workflow.body.sha) && workflow.body.encoding === "base64" && typeof workflow.body.content === "string" && workflow.body.content.length <= 1e5, "setup_invalid_workflow_response");
    workflowSha = workflow.body.sha;
    workflowHash = await sha256(Buffer.from(workflow.body.content, "base64").toString("utf8"));
  }
  const warnings = [];
  if (!checks.length) warnings.push("No check runs were observed on this commit. Run the repository\u2019s existing CI or repeat setup with --pull NUMBER; do not invent a check name or provider.");
  if (protection.status !== 200 || rules.status !== 200) warnings.push("Some repository protection requirements could not be read. This does not mean the branch is unprotected; review its rules in GitHub.");
  if (required.some((c) => c.app_id === null)) warnings.push("Some required status checks do not pin an app. Select the actual observed provider explicitly; setup does not treat an unpinned name as a verified provider.");
  if (required.some((c) => !checks.some((o) => o.name === c.name && (c.app_id === null || o.app_id === c.app_id)))) warnings.push("Some required checks were not observed on this commit. Repeat discovery on a representative pull request before choosing task requirements.");
  if (checks.some((c) => checks.some((other) => other.name === c.name && other.app_id !== c.app_id))) warnings.push("A check name is used by more than one app. Review the provider ID as well as the name.");
  return { repository: repo.body.full_name, base_branch: base, base_sha: branch.body.commit.sha, observed_head_sha: head, checks, required_checks: required, protection_read: protection.status === 200 ? "observed" : "unavailable", rules_read: rules.status === 200 ? "observed" : "unavailable", repository_permissions: repo.body.permissions ? { admin: repo.body.permissions.admin === true, push: repo.body.permissions.push === true } : null, workflow_state: workflow.status === 200 ? "present" : workflow.status === 404 ? "absent" : "not_checked", ...workflowSha ? { workflow_sha: workflowSha, workflow_sha256: workflowHash } : {}, warnings };
}
function endpoint(value) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new RepositoryReceiverError("setup_invalid_endpoint");
  }
  need(url.protocol === "https:" && url.pathname === "/api/coordination" && !url.username && !url.password && !url.search && !url.hash && url.href === value, "setup_invalid_endpoint");
  return url.href;
}
function parseRepositoryConnectionConfig(value) {
  const c = value, t = c?.connection;
  need(c && Object.keys(c).sort().join(",") === "connection,receiver_sha256,receiver_url,type,workflow_path,workflow_sha256" && c.type === "scopeblind.repository.connection-config.v1" && t && Object.keys(t).sort().join(",") === "authority_key,base_branch,endpoint,expires_at,id,issued_at,owner_key,receiver_key,repository,type", "setup_invalid_connection_config");
  need(validRepositoryConnection(t), "setup_invalid_connection_config");
  endpoint(t.endpoint);
  need(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(c.receiver_url) && REPOSITORY_HEX.test(c.receiver_sha256) && c.workflow_path === WORKFLOW_PATH && REPOSITORY_HEX.test(c.workflow_sha256), "setup_invalid_artifact_pin");
  return c;
}
function renderRepositoryWorkflow(artifact) {
  need(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(artifact.url) && REPOSITORY_HEX.test(artifact.sha256), "setup_invalid_artifact_pin");
  return WORKFLOW_TEMPLATE.replace("__RECEIVER_URL__", artifact.url).replace("__RECEIVER_SHA256__", artifact.sha256);
}
var WORKFLOW_TEMPLATE = `# Review on the trusted default branch before enabling. Setup grants no task approval.
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
async function createRepositoryReadiness(connection, identity, discovery, options = {}) {
  const now = options.now ?? Date.now();
  need(identity.publicKey === connection.receiver_key && !identity.deviceAuthorization && discovery.repository === connection.repository && discovery.base_branch === connection.base_branch && Date.parse(connection.expires_at) > now, "setup_connection_scope_mismatch");
  const workflow = discovery.workflow_state === "absent" ? "missing" : discovery.workflow_state === "not_checked" ? "unavailable" : !options.workflow_sha256 ? "not_checked" : discovery.workflow_sha256 === options.workflow_sha256 ? "matching" : "different";
  const readiness = { type: "scopeblind.repository.readiness.v1", connection_digest: await sha256(COORDINATION_DOMAIN + canonical(connection)), repository: connection.repository, base_branch: connection.base_branch, owner_key: connection.owner_key, receiver_key: identity.publicKey, authority_key: connection.authority_key, checks: discovery.checks, base_sha: discovery.base_sha, check_head_sha: discovery.observed_head_sha, required_checks: discovery.required_checks, protection: discovery.protection_read, runtime: options.runtime ?? "local", workflow, ...discovery.workflow_sha ? { workflow_sha: discovery.workflow_sha } : {}, observed_at: new Date(now).toISOString(), expires_at: new Date(Math.min(now + 864e5, Date.parse(connection.expires_at))).toISOString() };
  need(validRepositoryConnection(connection) && validRepositoryReadiness(readiness), "setup_invalid_readiness");
  return { type: "scopeblind.repository.connection-import.v1", connection, readiness: await sign(readiness, identity) };
}
async function githubToken(env) {
  const value = env.GITHUB_TOKEN || env.GH_TOKEN;
  if (value) {
    need(!/[\r\n\u0000]/.test(value), "setup_invalid_github_token");
    return value;
  }
  const { execFile } = await import("child_process");
  const token = await new Promise((resolve, reject) => execFile("gh", ["auth", "token", "--hostname", "github.com"], { encoding: "utf8", timeout: 1e4, maxBuffer: 8192, env }, (error, stdout) => error ? reject(new RepositoryReceiverError("setup_github_login_required", "Sign in locally with gh auth login, or set GITHUB_TOKEN on this trusted machine.")) : resolve(stdout.trim())));
  need(token.length > 0 && !/[\r\n\u0000]/.test(token), "setup_github_login_required");
  return token;
}
async function localIdentity(file, expected, env) {
  const { readFile, stat } = await import("fs/promises");
  let privateKey = env.SCOPEBLIND_RECEIVER_PRIVATE_KEY, publicKey = expected;
  if (file) {
    const meta = await stat(file);
    need(meta.isFile() && (process.platform === "win32" || (meta.mode & 63) === 0), "setup_private_key_permissions");
    let key;
    try {
      key = JSON.parse(await readFile(file, "utf8"));
    } catch {
      throw new RepositoryReceiverError("setup_invalid_private_key_file");
    }
    need(key.type === "scopeblind.repository.receiver-key.v1" && (!expected || key.public_key === expected), "receiver_key_mismatch");
    privateKey = key.private_key;
    publicKey = key.public_key;
  }
  need(typeof privateKey === "string" && /^[0-9a-f]{96,300}$/.test(privateKey) && typeof publicKey === "string" && REPOSITORY_HEX.test(publicKey), "receiver_private_key_required");
  try {
    return await importIdentity(privateKey, publicKey);
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
  need(response.ok && info.ok === true && info.authority_key === pin && info.protocol === "scopeblind.coordination.v1", "setup_service_pin_mismatch");
}
async function artifactPin(url, pin, fetchImpl) {
  need(/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(url), "setup_invalid_artifact_pin");
  if (pin) {
    need(REPOSITORY_HEX.test(pin), "setup_invalid_artifact_pin");
    return pin;
  }
  let response;
  try {
    response = await fetchImpl(`${url}.sha256`, { method: "GET", redirect: "error", signal: AbortSignal.timeout(2e4) });
  } catch {
    throw new RepositoryReceiverError("setup_release_checksum_unavailable");
  }
  need(response.ok, "setup_release_checksum_unavailable");
  const value = await response.text();
  need(value.length < 1e3 && /^[0-9a-f]{64}(?:\s+[^\r\n]+)?\s*$/.test(value), "setup_invalid_release_checksum");
  return value.slice(0, 64);
}
async function runRepositoryCommand(args, dependencies = {}) {
  if (["connect", "connection-job", "coding-ready"].includes(args[0])) return (await import("./repository-connect-GYG7BTNM.mjs")).runRepositoryConnect(args, dependencies);
  if (!["setup", "ready"].includes(args[0])) return runRepositoryReceiver(args);
  const { readFile, writeFile, mkdir, stat } = await import("fs/promises"), { resolve, join } = await import("path");
  const options = /* @__PURE__ */ new Map();
  const allowed = args[0] === "setup" ? ["--repository", "--owner-key", "--authority-key", "--endpoint", "--base", "--pull", "--key-file", "--output", "--receiver-url", "--receiver-sha256"] : ["--connection", "--key-file", "--pull", "--output"];
  for (let i = 1; i < args.length; i += 2) {
    need(allowed.includes(args[i]) && !options.has(args[i]) && typeof args[i + 1] === "string" && !args[i + 1].startsWith("--"), "setup_invalid_arguments");
    options.set(args[i], args[i + 1]);
  }
  const env = dependencies.env ?? process.env, fetchImpl = dependencies.fetchImpl ?? fetch, stdout = dependencies.stdout ?? ((s) => process.stdout.write(s));
  const pull = options.get("--pull");
  if (pull !== void 0) need(/^[1-9][0-9]*$/.test(pull) && Number.isSafeInteger(Number(pull)), "setup_invalid_pull_number");
  const token = await githubToken(env);
  if (args[0] === "ready") {
    need(options.get("--connection") && options.get("--output"), "setup_connection_and_output_required");
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
    if (actions) need(env.GITHUB_REPOSITORY === config2.connection.repository && env.GITHUB_EVENT_NAME === "workflow_dispatch" && env.GITHUB_REF === `refs/heads/${config2.connection.base_branch}` && discovery2.workflow_sha256 === config2.workflow_sha256 && env.GITHUB_WORKFLOW_REF === `${config2.connection.repository}/${WORKFLOW_PATH}@refs/heads/${config2.connection.base_branch}`, "receiver_trusted_workflow_required");
    const result2 = await createRepositoryReadiness(config2.connection, identity2, discovery2, { runtime: actions ? "github_actions" : "local", workflow_sha256: config2.workflow_sha256 });
    await writeFile(options.get("--output"), JSON.stringify(result2, null, 2) + "\n", { mode: 384, flag: "wx" });
    stdout(`Read-only readiness recorded for ${config2.connection.repository}. No task was approved or executed. Import the public observation into the repository connection.
`);
    return;
  }
  const repository = options.get("--repository"), owner = options.get("--owner-key"), authority = options.get("--authority-key"), output = options.get("--output");
  need(repository && REPO.test(repository) && owner && REPOSITORY_HEX.test(owner) && authority && REPOSITORY_HEX.test(authority) && owner !== authority && output, "setup_repository_owner_pin_and_output_required");
  const service = endpoint(options.get("--endpoint") ?? "https://scopeblind.com/api/coordination");
  await checkServicePin(service, authority, fetchImpl);
  const discovery = await discoverRepository({ repository, base_branch: options.get("--base"), ...pull ? { pull_number: Number(pull) } : {} }, token, fetchImpl);
  const url = options.get("--receiver-url") ?? `https://scopeblind.com/releases/repository-receiver-${REPOSITORY_SETUP_VERSION}.cjs`, hash = await artifactPin(url, options.get("--receiver-sha256"), fetchImpl), workflow = renderRepositoryWorkflow({ url, sha256: hash });
  const directory = resolve(output);
  let exists = false;
  try {
    await stat(directory);
    exists = true;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  need(!exists, "setup_output_exists");
  await mkdir(directory, { mode: 448 });
  let keyFile = options.get("--key-file");
  if (!keyFile) {
    keyFile = join(directory, "receiver-key.json");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const key = { type: "scopeblind.repository.receiver-key.v1", public_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), private_key: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))) };
    await writeFile(keyFile, JSON.stringify(key, null, 2) + "\n", { mode: 384, flag: "wx" });
  }
  const identity = await localIdentity(keyFile, void 0, env);
  need(identity.publicKey !== owner && identity.publicKey !== authority, "setup_independent_receiver_key_required");
  const now = Date.now(), connection = { type: "scopeblind.repository.connection.v1", id: crypto.randomUUID(), endpoint: service, repository: discovery.repository, base_branch: discovery.base_branch, owner_key: owner, receiver_key: identity.publicKey, authority_key: authority, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 30 * 864e5).toISOString() };
  const config = { type: "scopeblind.repository.connection-config.v1", connection, receiver_url: url, receiver_sha256: hash, workflow_path: WORKFLOW_PATH, workflow_sha256: await sha256(workflow) };
  parseRepositoryConnectionConfig(config);
  const result = await createRepositoryReadiness(connection, identity, discovery, { now, workflow_sha256: config.workflow_sha256 });
  let previewFile = false;
  if (pull) {
    const choices = await discoverRepositoryPreviewChoices((path) => github(path, token, fetchImpl), discovery.repository, discovery.observed_head_sha), observed = Date.now(), preview = await sign({ type: "scopeblind.repository.preview-discovery.v1", repository: discovery.repository, pull_number: Number(pull), head_sha: discovery.observed_head_sha, owner_key: owner, receiver_key: identity.publicKey, authority_key: authority, ...choices, observed_at: new Date(observed).toISOString(), expires_at: new Date(observed + 864e5).toISOString() }, identity);
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

export {
  REPOSITORY_SETUP_VERSION,
  discoverRepository,
  parseRepositoryConnectionConfig,
  renderRepositoryWorkflow,
  createRepositoryReadiness,
  runRepositoryCommand
};
