/** Run: node --test scripts/claude-plugin-hooks.test.mjs
 * To exercise a clean published install, set PROTECT_MCP_TEST_CLI to its
 * absolute node_modules/protect-mcp/dist/cli.js path. No user config is changed.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, writeFile, rm, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { parsePort, relay, validateInput } from '../hooks/relay.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const relayPath = join(root, 'hooks', 'relay.mjs');
const gateCli = process.env.PROTECT_MCP_TEST_CLI || join(root, 'dist', 'cli.js');
const healthy = { status: 'ok', server: 'protect-mcp-hooks', mode: 'enforce', policy_engine: 'cedar', policy_digest: 'sha256:test', cedar_files: 1, signing: true, signer: { kid: 'test-key' } };
const input = (event = 'PreToolUse', toolInput = { command: 'echo safe' }) => ({
  hook_event_name: event, session_id: 'plugin-test', cwd: '/tmp', tool_name: 'Bash',
  tool_use_id: `plugin-${Math.random().toString(16).slice(2)}`, tool_input: toolInput,
  ...(event === 'PostToolUse' ? { tool_response: { stdout: 'synthetic result' } } : {}),
});

async function server(t, handler) {
  const instance = http.createServer(handler);
  instance.listen(0, '127.0.0.1');
  await once(instance, 'listening');
  t.after(async () => { instance.closeAllConnections(); await new Promise(resolve => instance.close(resolve)); });
  return String(instance.address().port);
}

function invoke(event, payload, port, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [relayPath, event], { env: { PATH: process.env.PATH, PROTECT_MCP_HOOK_PORT: port, ...extraEnv }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout, stderr }));
    child.stdin.on('error', () => {});
    child.stdin.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
  });
}
function denied(result, reason) {
  assert.equal(result.code, 2);
  assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, 'deny');
  if (reason) assert.match(result.stderr, reason);
}

for (const port of ['', '0', '65536', '-1', '1.5', '9377/evil', ' 9377', '09377', 'localhost:9377']) {
  test(`invalid port is rejected: ${JSON.stringify(port)}`, () => assert.throws(() => parsePort(port), /invalid_port/));
}
test('ports include loopback default and valid upper boundary', () => { assert.equal(parsePort(), 9377); assert.equal(parsePort('65535'), 65535); });

test('manifest binds each hook event, time limit and PreToolUse failure mode', async () => {
  const config = JSON.parse(await readFile(join(root, 'hooks/hooks.json'), 'utf8'));
  for (const event of ['PreToolUse', 'PostToolUse']) {
    const hook = config.hooks[event][0].hooks[0];
    assert.equal(hook.command, 'node');
    assert.deepEqual(hook.args, ['${CLAUDE_PLUGIN_ROOT}/hooks/relay.mjs', event]);
    assert.equal(hook.timeout, 15);
    if (event === 'PreToolUse') assert.equal(hook.onFailure, 'block');
  }
});

test('health runs before forwarding input; empty allow does not grant host permission', async t => {
  const paths = [];
  const port = await server(t, async (request, response) => {
    paths.push(request.url);
    if (request.url === '/health') return response.end(JSON.stringify(healthy));
    let body = ''; for await (const chunk of request) body += chunk;
    const parsed = JSON.parse(body);
    assert.equal(parsed.tool_name, 'Bash');
    assert.deepEqual(parsed.tool_input, { command: 'echo safe' });
    response.end('{}');
  });
  const result = await invoke('PreToolUse', input(), port, { HTTP_PROXY: 'http://127.0.0.1:1' });
  assert.deepEqual(result, { code: 0, stdout: '', stderr: '' });
  assert.deepEqual(paths, ['/health', '/hook']);
});

test('camelCase aliases cannot change the event or input checked by the gate', () => {
  const value = input();
  assert.deepEqual(validateInput('PreToolUse', { ...value, hookEventName: 'PostToolUse', toolInput: { command: 'evil' }, toolName: 'Other' }), value);
});

for (const [name, mutation, reason] of [
  ['shadow', { mode: 'shadow' }, /gate_not_enforcing/],
  ['unsigned', { signing: false }, /signing_not_configured/],
  ['missing signer', { signer: null }, /signing_not_configured/],
  ['wrong service', { server: 'other' }, /wrong_server/],
  ['no Cedar', { policy_engine: 'none' }, /cedar_not_configured/],
  ['no policy files', { cedar_files: 0 }, /cedar_not_configured/],
]) test(`unready gate: ${name}`, async t => {
  let hookCalls = 0;
  const port = await server(t, (request, response) => { if (request.url === '/hook') hookCalls++; response.end(JSON.stringify({ ...healthy, ...mutation })); });
  denied(await invoke('PreToolUse', input(), port), reason);
  assert.equal(hookCalls, 0);
});

for (const [name, payload] of [
  ['empty', {}], ['array', []], ['wrong event', input('PostToolUse')],
  ['missing input', { ...input(), tool_input: undefined }],
  ['array tool input', { ...input(), tool_input: [] }],
  ['missing tool id', { ...input(), tool_use_id: '' }], ['invalid JSON', '{ private-secret'],
]) test(`invalid host payload: ${name}`, async () => {
  const result = await invoke('PreToolUse', payload, '1');
  denied(result, /invalid_(input|event)/);
  assert.doesNotMatch(result.stdout + result.stderr, /private-secret/);
});

test('oversized input is denied without reflecting payload', async () => {
  const result = await invoke('PreToolUse', 'secret-data'.repeat(220000), '1');
  denied(result, /input_too_large/);
  assert.doesNotMatch(result.stdout + result.stderr, /secret-data/);
});

test('stopped gate fails closed before tool execution', async () => {
  const instance = http.createServer(); instance.listen(0, '127.0.0.1'); await once(instance, 'listening');
  const port = String(instance.address().port); await new Promise(resolve => instance.close(resolve));
  denied(await invoke('PreToolUse', input(), port), /connection_failed/);
});

for (const [name, body] of [
  ['invalid JSON', 'secret-invalid-json'], ['null', 'null'], ['array', '[]'], ['unknown shape', '{"ok":true}'],
  ['explicit permission grant', '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'],
  ['tool input rewrite', '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"no","updatedInput":{}}}'],
]) test(`unexpected hook response: ${name}`, async t => {
  const port = await server(t, (request, response) => response.end(request.url === '/health' ? JSON.stringify(healthy) : body));
  const result = await invoke('PreToolUse', input(), port);
  denied(result, /response/);
  assert.doesNotMatch(result.stdout + result.stderr, /secret-invalid-json/);
});

test('ask remains ask, never allow', async t => {
  const port = await server(t, (request, response) => response.end(JSON.stringify(request.url === '/health' ? healthy : { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: 'policy' } })));
  const result = await invoke('PreToolUse', input(), port);
  assert.equal(result.code, 0);
  assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, 'ask');
});

test('redirects are refused and never forwarded to a second endpoint', async t => {
  let destinationCalls = 0;
  const destination = await server(t, (_, response) => { destinationCalls++; response.end('{}'); });
  const port = await server(t, (request, response) => {
    if (request.url === '/health') return response.end(JSON.stringify(healthy));
    response.writeHead(302, { Location: `http://127.0.0.1:${destination}/private` }); response.end();
  });
  denied(await invoke('PreToolUse', input(), port), /http_status/);
  assert.equal(destinationCalls, 0);
});

test('HTTP error and oversized reply fail closed', async t => {
  for (const mode of ['500', 'large']) {
    const port = await server(t, (request, response) => {
      if (request.url === '/health') return response.end(JSON.stringify(healthy));
      if (mode === '500') { response.writeHead(500); response.end('private-server-error'); }
      else response.end('x'.repeat(70 * 1024));
    });
    denied(await invoke('PreToolUse', input(), port), /http_status|response_too_large/);
  }
});

test('stalled health or decision request has a bounded denial', async t => {
  for (const stall of ['/health', '/hook']) {
    const port = await server(t, (request, response) => { if (request.url !== stall) response.end(JSON.stringify(healthy)); });
    const started = Date.now();
    denied(await relay({ event: 'PreToolUse', input: input(), port, timeoutMs: 75 }), /request_timeout/);
    assert.ok(Date.now() - started < 2000);
  }
});

test('post failure reports an after-action error and never claims prevention', async () => {
  const result = await invoke('PostToolUse', input('PostToolUse'), '1');
  assert.equal(result.code, 2);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /After-action recording failed/);
  assert.match(result.stderr, /already ran/);
  assert.doesNotMatch(result.stderr, /Tool call blocked/);
});

test('post success suppresses unconfirmed receipt claims from the released server', async t => {
  const port = await server(t, (request, response) => response.end(JSON.stringify(request.url === '/health' ? healthy : { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'Tool call receipted. secret-output' } })));
  assert.deepEqual(await invoke('PostToolUse', input('PostToolUse'), port), { code: 0, stdout: '', stderr: '' });
});

async function realGate(t, { enforce = true, signed = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'protect-plugin-gate-'));
  await mkdir(join(dir, 'policies'));
  await writeFile(join(dir, 'policies', 'test.cedar'), 'permit(principal, action, resource);\nforbid(principal, action, resource) when { context.input has command && context.input.command == "blocked-synthetic-command" };\n');
  let publicKey;
  if (signed) {
    await mkdir(join(dir, 'keys'), { mode: 0o700 });
    const keys = generateKeyPairSync('ed25519');
    publicKey = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
    const privateKey = keys.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('hex');
    await writeFile(join(dir, 'keys', 'gateway.json'), JSON.stringify({ privateKey, publicKey, kid: 'plugin-test' }), { mode: 0o600 });
  }
  const probe = http.createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
  const port = String(probe.address().port); await new Promise(resolve => probe.close(resolve));
  const child = spawn(process.execPath, [resolve(gateCli), 'serve', '--port', port, '--cedar', join(dir, 'policies'), ...(enforce ? ['--enforce'] : [])], {
    cwd: dir, env: { PATH: process.env.PATH, HOME: dir, NO_COLOR: '1', DO_NOT_TRACK: '1' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let errors = ''; child.stdout.resume(); child.stderr.on('data', chunk => { errors += chunk; });
  t.after(async () => {
    if (child.exitCode === null) { const closed = once(child, 'close'); child.kill('SIGTERM'); await closed; }
    await rm(dir, { recursive: true, force: true });
  });
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`Test gate failed to start: ${errors.slice(-2000)}`);
    try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) return { port, dir, publicKey }; } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Test gate did not become healthy');
}

test('real released gate permits safe input with a signed recorded receipt and denies forbidden input', async t => {
  const gate = await realGate(t);
  const safe = input();
  assert.deepEqual(await invoke('PreToolUse', safe, gate.port), { code: 0, stdout: '', stderr: '' });
  const bad = input('PreToolUse', { command: 'blocked-synthetic-command' });
  denied(await invoke('PreToolUse', bad, gate.port));
  const records = (await readFile(join(gate.dir, '.protect-mcp-receipts.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const allowed = records.find(record => record.payload?.request_id === safe.tool_use_id);
  const blocked = records.find(record => record.payload?.request_id === bad.tool_use_id);
  assert.equal(allowed?.payload?.decision, 'allow');
  assert.equal(blocked?.payload?.decision, 'deny');
  const { verifyReceipt } = await import(pathToFileURL(join(dirname(gateCli), 'index.mjs')).href);
  assert.equal(verifyReceipt(allowed, gate.publicKey).valid, true);
  assert.equal(verifyReceipt(blocked, gate.publicKey).valid, true);
  assert.equal(verifyReceipt({ ...allowed, payload: { ...allowed.payload, decision: 'deny' } }, gate.publicKey).valid, false);
  assert.deepEqual(await invoke('PostToolUse', { ...safe, hook_event_name: 'PostToolUse', tool_response: { stdout: 'synthetic-safe-result' } }, gate.port), { code: 0, stdout: '', stderr: '' });
});

for (const [name, options, reason] of [
  ['shadow', { enforce: false }, /gate_not_enforcing/],
  ['unsigned', { signed: false }, /signing_not_configured/],
]) test(`real released ${name} gate is rejected before forwarding a tool call`, async t => {
  const gate = await realGate(t, options);
  denied(await invoke('PreToolUse', input(), gate.port), reason);
});


test('real released gate denies an allow when its signed receipt cannot be recorded', async t => {
  const gate = await realGate(t);
  assert.equal((await invoke('PreToolUse', input(), gate.port)).code, 0);
  const receiptPath = join(gate.dir, '.protect-mcp-receipts.jsonl');
  await rename(receiptPath, receiptPath + '.saved');
  await mkdir(receiptPath);
  denied(await invoke('PreToolUse', input(), gate.port));
});
