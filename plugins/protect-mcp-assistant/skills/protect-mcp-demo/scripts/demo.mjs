#!/usr/bin/env node
// Synthetic proposals only. No MCP server, host settings, or real tools.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pluginRoot = resolve(here, '../../..');
const pins = JSON.parse(readFileSync(join(pluginRoot, 'runtime-versions.json'), 'utf8'));
assert.deepEqual(Object.keys(pins).sort(), ['@veritasacta/verify', 'protect-mcp']);
for (const version of Object.values(pins)) assert.match(version, /^\d+\.\d+\.\d+$/);
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--workspace' || !isAbsolute(args[1])) {
  console.error('Usage: node demo.mjs --workspace /absolute/path/to/a/new/directory');
  process.exit(2);
}
if (Number(process.versions.node.split('.')[0]) < 22) {
  console.error('This demo requires Node.js 22 or later.');
  process.exit(2);
}
const workspace = resolve(args[1]);
const env = { ...process.env, NO_COLOR: '1', npm_config_audit: 'false', npm_config_fund: 'false', PROTECT_MCP_TELEMETRY: 'off' };
const localEnv = { ...env, npm_config_offline: 'true', NODE_OPTIONS: `--require ${JSON.stringify(join(here, 'no-network.cjs'))}` };

function run(bin, commandArgs, expected = 0, install = false) {
  const result = spawnSync(bin, commandArgs, {
    cwd: workspace, env: install ? env : localEnv, input: '',
    encoding: 'utf8', timeout: install ? 180_000 : 30_000, maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, expected, `${commandArgs[0]} exited ${result.status}\n${result.stderr}\n${result.stdout}`);
  return result.stdout;
}
const readJSON = path => JSON.parse(readFileSync(join(workspace, path), 'utf8'));
const writeJSON = (path, value) => writeFileSync(join(workspace, path), `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });

try {
  // Non-recursive exclusive creation refuses existing files and directories.
  mkdirSync(workspace, { mode: 0o700 });
  writeJSON('package.json', { name: 'protect-mcp-assistant-demo', version: '0.0.0', private: true });
  writeFileSync(join(workspace, '.gitignore'), 'node_modules/\nprotect-mcp.key\n', { flag: 'wx' });
  console.log('Installing the tested gateway and verifier from npm. No host settings will change.');
  const installArgs = [
    'install', '--registry=https://registry.npmjs.org', '--save-exact', '--ignore-scripts',
    ...Object.entries(pins).map(([name, version]) => `${name}@${version}`),
  ];
  if (process.platform === 'win32') {
    // npm.cmd needs a command interpreter on Windows. All tokens here are
    // fixed options or the allowlisted package names and numeric versions;
    // user paths are passed only as cwd, never interpolated into this string.
    run('cmd.exe', ['/d', '/s', '/c', ['npm.cmd', ...installArgs].join(' ')], 0, true);
  } else {
    run('npm', installArgs, 0, true);
  }
  for (const [name, version] of Object.entries(pins)) {
    assert.equal(readJSON(`node_modules/${name}/package.json`).version, version);
  }
  const gateway = join(workspace, 'node_modules/protect-mcp/dist/cli.js');
  const verifier = join(workspace, 'node_modules/@veritasacta/verify/cli.js');
  const cli = (file, commandArgs, expected) => run(process.execPath, [file, ...commandArgs], expected);
  cli(gateway, ['init', '--starter']);
  mkdirSync(join(workspace, 'policies'));
  writeFileSync(join(workspace, 'policies/demo.cedar'), [
    'permit(principal, action == Action::"MCP::Tool::call", resource == Tool::"Read");',
    'forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"DemoBlocked");',
    '',
  ].join('\n'), { flag: 'wx' });
  const examples = [
    { tool: 'Read', input: { path: 'demo.txt' }, decision: 'allow', exit: 0 },
    { tool: 'DemoBlocked', input: { label: 'harmless-test' }, decision: 'deny', exit: 2 },
  ];
  for (const example of examples) {
    const proposal = ['--cedar', './policies', '--tool', example.tool, '--input', JSON.stringify(example.input)];
    cli(gateway, ['evaluate', ...proposal], example.exit);
    cli(gateway, ['sign', ...proposal, '--key', './protect-mcp.key', '--receipts', './receipts']);
  }
  const receipts = readFileSync(join(workspace, 'receipts/receipts.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(receipts.map(receipt => receipt.payload.decision), ['allow', 'deny']);
  const expectedKey = readJSON('protect-mcp.key').publicKey;
  assert.match(expectedKey, /^[0-9a-f]{64}$/i);
  writeFileSync(join(workspace, 'demo-public-key.txt'), `${expectedKey}\n`, { flag: 'wx' });
  const replay = JSON.parse(cli(verifier, ['--replay-chain', './receipts/receipts.jsonl', '--key', expectedKey, '--json']));
  assert.equal(replay.verified, 2);
  for (const key of ['failed', 'undecidable', 'chainBreaks']) assert.equal(replay[key], 0);
  writeJSON('verification.json', replay);
  writeJSON('original-receipt.json', receipts[1]);
  const changed = structuredClone(receipts[1]);
  changed.payload.decision = 'allow';
  writeJSON('tampered-receipt.json', changed);
  const tampered = JSON.parse(cli(verifier, ['tampered-receipt.json', '--key', expectedKey, '--json'], 1));
  assert.match(JSON.stringify(tampered), /invalid_signature/);
  writeJSON('tamper-verification.json', tampered);
  const missingKey = JSON.parse(cli(verifier, ['original-receipt.json', '--json'], 2));
  assert.equal(missingKey.error, 'embedded_key_rejected');
  cli(verifier, ['original-receipt.json', '--key', '00'.repeat(32), '--json'], 1);
  const summary = {
    schema: 'protect-mcp-assistant-demo/v1',
    packages: pins,
    kind: 'synthetic-policy-and-receipt-test',
    toolsExecuted: false,
    hostConfigured: false,
    decisions: receipts.map(receipt => receipt.payload.decision),
    verifiedReceipts: replay.verified,
    tamperedReceiptRejected: true,
    missingTrustedKeyRejected: true,
    wrongTrustedKeyRejected: true,
    publicKeySource: 'test-key-generated-in-this-workspace',
    artifacts: ['receipts/receipts.jsonl', 'demo-public-key.txt', 'verification.json', 'tamper-verification.json'],
  };
  writeJSON('demo-summary.json', summary);
  console.log('PASS: allow, deny, 2 verified receipts, altered receipt rejected, missing/wrong key rejected.');
  console.log(`Results: ${join(workspace, 'demo-summary.json')}`);
  console.log('This tests synthetic policy decisions and receipt integrity, not host routing or issuer authority.');
} catch (error) {
  console.error(`Demo did not complete: ${error.message}`);
  console.error('Existing files were not overwritten. Inspect the selected workspace before retrying in a new directory.');
  process.exitCode = 1;
}
