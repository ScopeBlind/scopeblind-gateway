// Exercises the actual listing launch configuration against the pinned release.
// Run: node scripts/distribution-smoke.mjs
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('../', import.meta.url);
const read = path => readFile(new URL(path, root), 'utf8');
const json = async path => JSON.parse(await read(path));
const { version } = await json('package.json');
const plugin = await json('.claude-plugin/plugin.json');
const marketplace = await json('.claude-plugin/marketplace.json');
assert.equal(plugin.version, version);
assert.equal(plugin.homepage, 'https://scopeblind.com/protect-mcp');
const entry = marketplace.plugins.find(plugin => plugin.name === 'protect-mcp');
assert.equal(entry.version, version);
assert.equal(entry.homepage, plugin.homepage);
const config = await json('.mcp.json');
assert.deepEqual(await json('mcp.json'), config);
const server = config.mcpServers['protect-mcp'];
assert.equal(server.command, 'npx');
assert.deepEqual(server.args, ['--yes', `protect-mcp@${version}`, 'mcp']);
assert.equal(server.env.PROTECT_MCP_VERSION, version);
const docker = await read('Dockerfile');
assert.ok(docker.includes(`protect-mcp@${version}`));
assert.ok(docker.includes('CMD ["mcp"]'));
assert.ok(docker.includes('https://github.com/ScopeBlind/scopeblind-gateway'));
console.log(`PASS metadata and launch configuration match ${version}`);

// Run as a consumer, outside the source package. npm otherwise tries to use
// this checkout's local bin even when its dependencies have not been installed.
const consumer = await mkdtemp(join(tmpdir(), 'protect-mcp-listing-'));
const child = spawn(server.command, server.args, {
  cwd: consumer, env: { ...process.env, ...server.env }, stdio: ['pipe', 'pipe', 'pipe'],
});
let id = 0;
let stderr = '';
const pending = new Map();
const abort = error => {
  for (const { reject } of pending.values()) reject(error);
  pending.clear();
};
child.on('error', abort);
child.on('exit', code => abort(new Error(`MCP server exited ${code}: ${stderr.slice(-1000)}`)));
child.stderr.on('data', chunk => { stderr += chunk; });
child.stdin.on('error', abort);
const lines = createInterface({ input: child.stdout });
lines.on('line', line => {
  try {
    const response = JSON.parse(line);
    const waiter = pending.get(response.id);
    if (!waiter) return;
    pending.delete(response.id);
    if (response.error) waiter.reject(new Error(JSON.stringify(response.error)));
    else waiter.resolve(response.result);
  } catch (error) { abort(new Error(`Non-JSON MCP output: ${error.message}`)); }
});
function request(method, params) {
  return new Promise((resolve, reject) => {
    const requestId = ++id;
    pending.set(requestId, { resolve, reject });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }) + '\n');
  });
}
const deadline = setTimeout(() => {
  abort(new Error('MCP startup or response exceeded 90 seconds'));
  child.kill();
}, 90_000);
try {
  const init = await request('initialize', {
    protocolVersion: '2024-11-05', capabilities: {},
    clientInfo: { name: 'protect-mcp-distribution-smoke', version: '1.0.0' },
  });
  assert.equal(init.serverInfo.name, 'protect-mcp');
  assert.equal(init.serverInfo.version, version);
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const { tools } = await request('tools/list', {});
  assert.deepEqual(tools.map(tool => tool.name).sort(), ['evaluate_action', 'self_test', 'sign_decision', 'verify_receipt']);
  for (const [policy, expected] of [
    ['permit(principal, action, resource);', 'allow'],
    ['forbid(principal, action, resource);', 'deny'],
  ]) {
    const result = await request('tools/call', { name: 'evaluate_action', arguments: { tool: 'Read', input: { file_path: '/synthetic/README.md' }, policy } });
    assert.notEqual(result.isError, true);
    const decision = JSON.parse(result.content.find(item => item.type === 'text').text);
    assert.equal(decision.decision, expected);
  }
  console.log(`PASS initialize, four-tool discovery and Cedar allow/deny over stdio (${version})`);
} finally {
  clearTimeout(deadline);
  lines.close();
  child.stdin.end();
  const cleanup = setTimeout(() => child.kill(), 2000);
  cleanup.unref();
  await rm(consumer, { recursive: true, force: true });
}
