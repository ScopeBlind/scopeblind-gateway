import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { relay, normalizeInput, validateConfig } from '../plugins/protect-mcp-cursor/hooks/relay.mjs';
import { configure } from '../plugins/protect-mcp-cursor/install-project.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const plugin = join(root, 'plugins/protect-mcp-cursor');
const relayPath = join(plugin, 'hooks/relay.mjs');
const cli = process.env.PROTECT_MCP_TEST_CLI || join(root, 'dist/cli.js');
const healthy = { status: 'ok', server: 'protect-mcp-hooks', mode: 'enforce', policy_engine: 'cedar', policy_digest: 'sha256:test', cedar_files: 1, signing: true, signer: { kid: 'test' } };

async function project(t, port = 9377, config = {}) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'protect-cursor space-')));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, '.cursor'));
  await writeFile(join(dir, '.cursor/protect-mcp.json'), JSON.stringify({ version: 1, port: Number(port), ...config }));
  return dir;
}
function input(dir, event = 'preToolUse', overrides = {}) {
  return { hook_event_name: event, conversation_id: 'cursor-test', generation_id: 'generation-1', cursor_version: '3.17.8', workspace_roots: [dir], tool_use_id: 'call-1', tool_name: 'Shell', cwd: dir, tool_input: { command: 'printf safe' }, ...(event === 'postToolUse' ? { tool_output: '{"exitCode":0,"stdout":"safe"}' } : {}), ...overrides };
}
async function server(t, handler) {
  const instance = http.createServer(handler);
  instance.listen(0, '127.0.0.1');
  await once(instance, 'listening');
  t.after(async () => { instance.closeAllConnections(); await new Promise(resolve => instance.close(resolve)); });
  return String(instance.address().port);
}
function invoke(event, value, { script = relayPath, cwd, leaveOpen = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, event], { cwd, env: { PATH: process.env.PATH }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', value => stdout += value);
    child.stderr.on('data', value => stderr += value);
    child.once('error', reject);
    child.once('close', code => resolve({ code, stdout, stderr }));
    child.stdin.on('error', () => {});
    if (!leaveOpen) child.stdin.end(typeof value === 'string' ? value : JSON.stringify(value));
  });
}
function denied(result, reason) {
  assert.equal(result.code, 2);
  assert.equal(JSON.parse(result.stdout).permission, 'deny');
  if (reason) assert.match(result.stderr, reason);
}

test('self-contained transport is the exact canonical relay and manifest fails closed', async () => {
  assert.equal(await readFile(join(plugin, 'lib/gate-client.mjs'), 'utf8'), await readFile(join(root, 'hooks/relay.mjs'), 'utf8'));
  const hooks = JSON.parse(await readFile(join(plugin, 'hooks/hooks.json')));
  assert.equal(hooks.version, 1);
  assert.deepEqual(Object.keys(hooks.hooks).sort(), ['postToolUse', 'preToolUse']);
  assert.equal(hooks.hooks.preToolUse[0].failClosed, true);
  assert.equal(hooks.hooks.preToolUse[0].timeout, 15);
  assert.doesNotMatch(JSON.stringify(hooks), /npx|npm |curl|--yes|bypass/);
});

test('native names normalize explicitly, MCP needs an exact reviewed mapping, aliases cannot override', () => {
  const config = validateConfig({ version: 1, port: 9377, mcpTools: { 'MCP:demo_lookup': 'demo_lookup' } });
  const base = input('/tmp', 'preToolUse', { toolName: 'Other', toolInput: { command: 'evil' } });
  const normalized = normalizeInput('preToolUse', base, config);
  assert.equal(normalized.tool_name, 'Bash');
  assert.equal(normalized.tool_input.command, 'printf safe');
  assert.equal(normalizeInput('preToolUse', { ...base, tool_name: 'Delete' }, config).tool_name, 'delete_file');
  assert.equal(normalizeInput('preToolUse', { ...base, tool_name: 'MCP:demo_lookup', tool_input: { nested: { price: 25 } } }, config).tool_name, 'demo_lookup');
  for (const name of ['UnknownTool', 'MCP:unreviewed', '__proto__', 'constructor']) assert.throws(() => normalizeInput('preToolUse', { ...base, tool_name: name }, config), /unmapped_tool/);
  assert.throws(() => normalizeInput('preToolUse', { ...base, tool_input: '{"amount":12}' }, config), /invalid_input/);
});

test('project config accepts only bounded loopback ports and explicit MCP mappings', () => {
  for (const value of [
    { version: 1, port: 0 }, { version: 1, port: 65536 }, { version: 1, port: -1 },
    { version: 1, port: '9377' }, { version: 1, port: 9377, url: 'https://other.example' },
    { version: 1, port: 9377, mcpTools: { Shell: 'Bash' } },
    { version: 1, port: 9377, mcpTools: { 'MCP:tool': '' } },
  ]) assert.throws(() => validateConfig(value));
  assert.equal(validateConfig({ version: 1, port: 65535 }).port, 65535);
});

test('healthy gate sees exact nested input and response conforms to Cursor permission schema', async t => {
  const captured = [];
  const port = await server(t, async (request, response) => {
    if (request.url === '/health') return response.end(JSON.stringify(healthy));
    let raw = ''; for await (const chunk of request) raw += chunk;
    captured.push(JSON.parse(raw)); response.end('{}');
  });
  const dir = await project(t, port, { mcpTools: { 'MCP:refund': 'refund' } });
  const value = input(dir, 'preToolUse', { tool_name: 'MCP:refund', tool_input: { payment: { amount: 1200, currency: 'AUD' } } });
  assert.deepEqual(await invoke('preToolUse', value), { code: 0, stdout: '{"permission":"allow"}\n', stderr: '' });
  assert.equal(captured.length, 1);
  assert.equal(captured[0].tool_name, 'refund');
  assert.deepEqual(captured[0].tool_input, value.tool_input);
  assert.equal(captured[0].tool_use_id, JSON.stringify(['cursor', 'cursor-test', 'call-1']));
});

test('captured Cursor 3.17.8 empty cwd uses the single workspace without changing tool arguments', async t => {
  let captured;
  const port = await server(t, async (request, reply) => {
    if (request.url === '/health') return reply.end(JSON.stringify(healthy));
    let raw = ''; for await (const chunk of request) raw += chunk;
    captured = JSON.parse(raw); reply.end('{}');
  });
  const dir = await project(t, port);
  const value = JSON.parse(await readFile(join(plugin, 'tests/fixtures/cursor-3.17.8-shell.json'), 'utf8'));
  value.workspace_roots = [dir];
  assert.equal((await invoke('preToolUse', value)).code, 0);
  assert.equal(captured.cwd, dir);
  assert.deepEqual(captured.tool_input, value.tool_input);
  assert.equal(captured.tool_input.cwd, '');
  for (const cwd of [undefined, null, 'relative/path']) denied(await invoke('preToolUse', { ...value, cwd }), /invalid_workspace/);
});

for (const [label, response, code] of [
  ['deny', { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'private reason' } }, /policy_denied/],
  ['approval', { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: 'private reason' } }, /approval_required/],
  ['explicit host permission grant', { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }, /unexpected_response/],
  ['input rewrite', { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'x', updatedInput: {} } }, /unexpected_response/],
  ['malformed response', ['unexpected'] , /invalid_response/],
]) test(`gate ${label} never becomes a Cursor allow`, async t => {
  const port = await server(t, (request, reply) => reply.end(JSON.stringify(request.url === '/health' ? healthy : response)));
  const dir = await project(t, port);
  const result = await invoke('preToolUse', input(dir));
  denied(result, code);
  assert.doesNotMatch(result.stdout + result.stderr, /private reason/);
  if (label === 'deny') {
    assert.match(JSON.parse(result.stdout).user_message, /project policy denied/);
    assert.doesNotMatch(result.stderr, /gate is unavailable/);
  }
});

for (const [mutation, reason] of [[{ mode: 'shadow' }, /gate_not_enforcing/], [{ signing: false }, /signing_not_configured/], [{ cedar_files: 0 }, /cedar_not_configured/], [{ server: 'other' }, /wrong_server/]]) test(`unready gate is never called: ${JSON.stringify(mutation)}`, async t => {
  let calls = 0;
  const port = await server(t, (request, reply) => { if (request.url === '/hook') calls++; reply.end(JSON.stringify({ ...healthy, ...mutation })); });
  const dir = await project(t, port);
  denied(await invoke('preToolUse', input(dir)), reason);
  assert.equal(calls, 0);
});

test('missing, malformed and wrong-workspace configuration fail before the gate', async t => {
  const dir = await project(t);
  await rm(join(dir, '.cursor/protect-mcp.json'));
  denied(await invoke('preToolUse', input(dir)), /missing_project_config/);
  await writeFile(join(dir, '.cursor/protect-mcp.json'), 'private invalid json');
  const bad = await invoke('preToolUse', input(dir));
  denied(bad, /invalid_project_config/);
  assert.doesNotMatch(bad.stderr, /private invalid/);
  denied(await invoke('preToolUse', input(dir, 'preToolUse', { cwd: dirname(dir) })), /wrong_workspace/);
  denied(await invoke('preToolUse', input(dir, 'preToolUse', { workspace_roots: [dir, '/tmp'] })), /invalid_workspace/);
});

test('invalid or oversized host payloads block without reflecting data', async t => {
  const dir = await project(t);
  for (const value of ['{ private-secret', 'private-secret'.repeat(170000), input(dir, 'preToolUse', { tool_use_id: '' }), input(dir, 'postToolUse')]) {
    const result = await invoke('preToolUse', value);
    denied(result);
    assert.doesNotMatch(result.stdout + result.stderr, /private-secret/);
  }
});

test('stopped and stalled gate fail closed within the request deadline', async t => {
  const dir = await project(t, 1);
  const stopped = await invoke('preToolUse', input(dir));
  denied(stopped, /connection_failed/);
  assert.match(JSON.parse(stopped.stdout).user_message, /local gate is unavailable/);
  assert.doesNotMatch(stopped.stderr, /policy denied/);
  const port = await server(t, () => {});
  await writeFile(join(dir, '.cursor/protect-mcp.json'), JSON.stringify({ version: 1, port: Number(port) }));
  const started = Date.now();
  denied(await relay({ event: 'preToolUse', input: input(dir), timeoutMs: 50 }), /request_timeout/);
  assert.ok(Date.now() - started < 1500);
});

test('relay has a whole-process deadline when the host never closes stdin', { timeout: 11000 }, async () => {
  const started = Date.now();
  denied(await invoke('preToolUse', '', { leaveOpen: true }), /relay_timeout/);
  assert.ok(Date.now() - started < 10500);
});

test('post records the actual JSON output with the same call ID, never rewrites it or claims saved evidence', async t => {
  let captured;
  const port = await server(t, async (request, reply) => {
    if (request.url === '/health') return reply.end(JSON.stringify(healthy));
    let raw = ''; for await (const chunk of request) raw += chunk;
    captured = JSON.parse(raw);
    reply.end(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'Tool call receipted. private output' } }));
  });
  const dir = await project(t, port);
  assert.deepEqual(await invoke('postToolUse', input(dir, 'postToolUse')), { code: 0, stdout: '{}\n', stderr: '' });
  assert.deepEqual(captured.tool_response, { exitCode: 0, stdout: 'safe' });
  assert.equal(captured.tool_use_id, JSON.stringify(['cursor', 'cursor-test', 'call-1']));
  await writeFile(join(dir, '.cursor/protect-mcp.json'), '{"version":1,"port":1}');
  const result = await invoke('postToolUse', input(dir, 'postToolUse'));
  assert.equal(result.code, 2);
  assert.match(result.stderr, /tool already ran/);
  assert.doesNotMatch(result.stderr, /Tool blocked|receipted/);
});

test('project installer plans without mutation, merges idempotently and uninstalls without touching unrelated settings', async t => {
  const dir = await project(t, 1);
  const original = { version: 1, hooks: { preToolUse: [{ command: 'existing-command', failClosed: true }], stop: [{ command: 'existing-stop' }] }, custom: 'preserved' };
  const path = join(dir, '.cursor/hooks.json');
  await writeFile(path, JSON.stringify(original));
  await configure({ project: dir });
  assert.equal(await readFile(path, 'utf8'), JSON.stringify(original));
  await configure({ project: dir, mode: 'install' });
  const installed = await readFile(path, 'utf8');
  await configure({ project: dir, mode: 'install' });
  assert.equal(await readFile(path, 'utf8'), installed);
  assert.equal(JSON.parse(installed).hooks.preToolUse.length, 2);
  // Formatting/key ordering does not make an unchanged managed entry foreign.
  const reordered = JSON.parse(installed);
  const ours = reordered.hooks.preToolUse[1];
  reordered.hooks.preToolUse[1] = { failClosed: ours.failClosed, timeout: ours.timeout, command: ours.command };
  await writeFile(path, JSON.stringify(reordered));
  const result = await invoke('preToolUse', input(dir), { script: join(dir, '.cursor/protect-mcp/hooks/relay.mjs'), cwd: dir });
  denied(result); // Stopped gate also blocks through the copied package.
  await configure({ project: dir, mode: 'uninstall' });
  assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), original);
  assert.equal(JSON.parse(await readFile(join(dir, '.cursor/protect-mcp.json'), 'utf8')).port, 1);
});

test('installer refuses conflicts and symbolic links; uninstall preserves edited hook files', async t => {
  const dir = await project(t);
  await configure({ project: dir, mode: 'install' });
  const managed = join(dir, '.cursor/protect-mcp/hooks/relay.mjs');
  await writeFile(managed, '// user edit');
  await assert.rejects(configure({ project: dir, mode: 'install' }), /differs/);
  assert.ok((await configure({ project: dir, mode: 'uninstall' })).preserved.includes(managed));
  assert.equal(await readFile(managed, 'utf8'), '// user edit');
  const another = await project(t);
  await rm(join(another, '.cursor'), { recursive: true });
  await symlink(join(dir, '.cursor'), join(another, '.cursor'));
  await assert.rejects(configure({ project: another, mode: 'install' }), /symbolic link/);
});

test('uninstall recovers from malformed project configuration and preserves its bytes', async t => {
  for (const malformed of ['{ broken config', '{"version":1,"port":-10}']) {
    const dir = await project(t);
    const hooksPath = join(dir, '.cursor/hooks.json');
    const original = { version: 1, hooks: { stop: [{ command: 'keep-me' }] } };
    await writeFile(hooksPath, JSON.stringify(original));
    await configure({ project: dir, mode: 'install' });
    const configPath = join(dir, '.cursor/protect-mcp.json');
    await writeFile(configPath, malformed);
    await configure({ project: dir, mode: 'uninstall' });
    assert.equal(await readFile(configPath, 'utf8'), malformed);
    assert.deepEqual(JSON.parse(await readFile(hooksPath, 'utf8')), original);
    await assert.rejects(readFile(join(dir, '.cursor/protect-mcp/hooks/relay.mjs')), { code: 'ENOENT' });
  }
});

async function realGate(t) {
  const dir = await project(t);
  await mkdir(join(dir, 'policies'));
  await mkdir(join(dir, 'keys'), { mode: 0o700 });
  await writeFile(join(dir, 'policies/test.cedar'), 'permit(principal, action, resource);\nforbid(principal, action, resource) when { context.input has command && context.input.command == "printf blocked" };\nforbid(principal, action, resource) when { context.input has payment && context.input.payment.amount > 1000 };\n');
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
  const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex');
  await writeFile(join(dir, 'keys/gateway.json'), JSON.stringify({ privateKey, publicKey, kid: 'cursor-fixture' }), { mode: 0o600 });
  const probe = http.createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
  const port = probe.address().port; await new Promise(resolve => probe.close(resolve));
  await writeFile(join(dir, '.cursor/protect-mcp.json'), JSON.stringify({ version: 1, port, mcpTools: { 'MCP:refund': 'refund' } }));
  const child = spawn(process.execPath, [resolve(cli), 'serve', '--enforce', '--cedar', join(dir, 'policies'), '--port', String(port)], { cwd: dir, env: { PATH: process.env.PATH, HOME: dir, NO_COLOR: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.resume(); let errors = ''; child.stderr.on('data', value => errors += value);
  t.after(async () => { if (child.exitCode === null) { const closed = once(child, 'close'); child.kill(); await closed; } });
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`Gate startup failed: ${errors.slice(-1000)}`);
    try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) return { dir, publicKey }; } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('Gate startup timed out');
}

test('actual released gate records signed safe, denied shell and denied nested MCP decisions; tampering fails', async t => {
  const gate = await realGate(t);
  const safe = input(gate.dir);
  assert.equal((await invoke('preToolUse', safe)).code, 0);
  denied(await invoke('preToolUse', input(gate.dir, 'preToolUse', { tool_use_id: 'blocked-1', tool_input: { command: 'printf blocked' } })));
  denied(await invoke('preToolUse', input(gate.dir, 'preToolUse', { tool_use_id: 'blocked-2', tool_name: 'MCP:refund', tool_input: { payment: { amount: 1200 } } })));
  assert.equal((await invoke('postToolUse', input(gate.dir, 'postToolUse'))).code, 0);
  const records = (await readFile(join(gate.dir, '.protect-mcp-receipts.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const { verifyReceipt } = await import(pathToFileURL(join(dirname(cli), 'index.mjs')).href);
  for (const [id, expected] of [['call-1', 'allow'], ['blocked-1', 'deny'], ['blocked-2', 'deny']]) {
    const record = records.find(value => value.payload?.request_id === JSON.stringify(['cursor', 'cursor-test', id]) && value.payload?.hook_event === 'PreToolUse');
    assert.equal(record?.payload?.decision, expected);
    assert.equal(verifyReceipt(record, gate.publicKey).valid, true);
    assert.equal(verifyReceipt({ ...record, payload: { ...record.payload, decision: expected === 'allow' ? 'deny' : 'allow' } }, gate.publicKey).valid, false);
  }
  assert.ok(records.some(value => value.payload?.hook_event === 'PostToolUse' && value.payload?.request_id === JSON.stringify(['cursor', 'cursor-test', 'call-1'])));
});
