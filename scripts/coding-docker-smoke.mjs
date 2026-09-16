/** Real Docker release preflight. Requires a built package and a working local daemon. */
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdtemp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {promisify} from 'node:util';
import {DockerCodingSandbox, REPOSITORY_CODING_IMAGE} from '../dist/index.mjs';

const execute = promisify(execFile);
const docker = (args, timeout = 10_000) => execute('docker', args, {
  timeout, maxBuffer: 256 * 1024, env: {PATH: process.env.PATH},
});
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const credentialNames = [
  'GITHUB_TOKEN', 'GH_TOKEN', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
  'SCOPEBLIND_CODING_WORKER_KEY', 'SCOPEBLIND_RECEIVER_PRIVATE_KEY',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'AWS_SECRET_ACCESS_KEY',
];
const previous = new Map(credentialNames.map(name => [name, process.env[name]]));
let root, sandbox, timeoutRun;
const observedContainers = new Set();

async function checkedRun(command) {
  const result = await sandbox.run(command, 15_000);
  // Do not include untrusted process output or inherited environment in errors.
  assert.equal(result.exit_code, 0, `Isolated command failed: ${command.join(' ')}`);
  return result;
}

async function inspectActiveContainer(directory) {
  const deadline = Date.now() + 3_500;
  while (Date.now() < deadline) {
    const {stdout} = await docker(['ps', '--quiet', '--filter', 'name=scopeblind-coding-']);
    const ids = stdout.trim().split(/\s+/).filter(Boolean);
    assert.ok(ids.length <= 20, 'Unexpected number of active coding containers');
    for (const id of ids) {
      const inspected = JSON.parse((await docker(['inspect', id])).stdout)[0];
      if (!inspected.Mounts?.some(m => m.Source === directory && m.Destination === '/workspace')) continue;
      observedContainers.add(id);
      return inspected;
    }
    await pause(100);
  }
  throw Error('The real timeout probe did not start its container');
}

try {
  assert.equal(typeof DockerCodingSandbox, 'function', 'Build the exported DockerCodingSandbox first');
  assert.match(REPOSITORY_CODING_IMAGE, /^node@sha256:[a-f0-9]{64}$/);
  await docker(['version', '--format', '{{.Server.Version}}']); // Absence is a failure, never a skip.
  await docker(['pull', REPOSITORY_CODING_IMAGE], 120_000);

  root = await mkdtemp(join(tmpdir(), 'scopeblind-docker-smoke-'));
  const workspace = join(root, 'workspace');
  for (const path of ['src', 'tests', 'scripts']) await mkdir(join(workspace, path), {recursive: true});
  const outside = join(root, 'owner-only-sentinel');
  await writeFile(outside, randomUUID(), {mode: 0o600});
  for (const name of credentialNames) process.env[name] = 'smoke-only-' + randomUUID();

  await writeFile(join(workspace, 'src/value.cjs'), 'module.exports = n => n * 2;\n');
  await writeFile(join(workspace, 'tests/value.test.cjs'), `
const test = require('node:test');
const assert = require('node:assert/strict');
const double = require('../src/value.cjs');
test('fixed source produces the requested result', () => assert.equal(double(21), 42));
`);
  await writeFile(join(workspace, 'scripts/build.cjs'), `
const fs = require('node:fs');
const double = require('../src/value.cjs');
fs.mkdirSync('preview', {recursive:true});
fs.writeFileSync('preview/index.html', '<!doctype html><title>Smoke</title><p>' + double(21) + '</p>');
`);
  await writeFile(join(workspace, 'scripts/isolation.cjs'), `
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
(async () => {
  for (const name of ${JSON.stringify(credentialNames)}) {
    assert.ok(process.env[name] === undefined, 'A host credential variable entered the child');
  }
  assert.equal(fs.existsSync(${JSON.stringify(outside)}), false, 'Host files escaped the workspace boundary');
  assert.equal(fs.existsSync('/var/run/docker.sock'), false, 'Docker control socket entered the child');
  const rootMount = fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\\n').find(line => line.split(' ')[4] === '/');
  assert.ok(rootMount?.split(' ')[5].split(',').includes('ro'), 'Root filesystem is not mounted read-only');
  let writeRefused = false;
  try { fs.writeFileSync('/scopeblind-smoke-root-write', 'forbidden'); } catch (e) { writeRefused = ['EROFS','EACCES'].includes(e.code); }
  assert.ok(writeRefused, 'Root filesystem accepted a write');
  assert.ok(Object.values(os.networkInterfaces()).flat().every(n => n.internal), 'External network interface exists');
  await new Promise((resolve, reject) => {
    const socket = net.createConnection({host:'1.1.1.1', port:443});
    socket.setTimeout(1500, () => { socket.destroy(); reject(Error('Network denial was not demonstrated')); });
    socket.once('connect', () => { socket.destroy(); reject(Error('External network connection succeeded')); });
    socket.once('error', error => ['ENETUNREACH','EHOSTUNREACH'].includes(error.code) ? resolve() : reject(Error('Unexpected network probe result')));
  });
  fs.writeFileSync('isolation-result.json', JSON.stringify({credentialsAbsent:true, hostFilesAbsent:true, readOnlyRoot:true, networkDenied:true}));
})().catch(() => { process.stderr.write('Isolation assertion failed\\n'); process.exitCode = 1; });
`);
  await writeFile(join(workspace, 'scripts/heartbeat.cjs'), `
const fs = require('node:fs');
let n = 0; setInterval(() => fs.writeFileSync('heartbeat', String(++n)), 50);
`);
  await writeFile(join(workspace, 'scripts/timeout.cjs'), `
const {spawn} = require('node:child_process');
spawn(process.execPath, ['scripts/heartbeat.cjs'], {stdio:'ignore'});
process.stdout.write('timeout-probe-started\\n');
setInterval(() => {}, 1000);
`);

  sandbox = new DockerCodingSandbox(workspace, REPOSITORY_CODING_IMAGE);
  await checkedRun(['node', 'scripts/isolation.cjs']);
  assert.deepEqual(JSON.parse(await readFile(join(workspace, 'isolation-result.json'), 'utf8')),
    {credentialsAbsent: true, hostFilesAbsent: true, readOnlyRoot: true, networkDenied: true});
  await checkedRun(['node', '--test', 'tests/value.test.cjs']);
  await checkedRun(['node', 'scripts/build.cjs']);
  assert.equal(await readFile(join(workspace, 'preview/index.html'), 'utf8'), '<!doctype html><title>Smoke</title><p>42</p>');

  timeoutRun = sandbox.run(['node', 'scripts/timeout.cjs'], 5_000);
  const container = await inspectActiveContainer(workspace);
  assert.equal(container.HostConfig.NetworkMode, 'none');
  assert.equal(container.HostConfig.ReadonlyRootfs, true);
  assert.ok(container.HostConfig.CapDrop.includes('ALL'));
  assert.ok(container.HostConfig.SecurityOpt.includes('no-new-privileges'));
  assert.deepEqual(container.Mounts.filter(m => m.Type === 'bind').map(m => [m.Source, m.Destination]), [[workspace, '/workspace']]);
  const timed = await timeoutRun;
  assert.equal(timed.exit_code, 124, 'Long-running child was not terminated by the sandbox deadline');
  assert.match(timed.output, /timeout-probe-started/, 'Timeout must follow a started child, not an image/startup failure');
  assert.ok(timed.duration_ms < 15_000, 'Timeout cleanup exceeded its bounded deadline');
  const allContainers = (await docker(['ps', '--all', '--quiet', '--no-trunc'])).stdout.trim().split(/\s+/);
  assert.ok(!allContainers.includes(container.Id), 'Timed-out container remained in Docker');
  const heartbeat = await readFile(join(workspace, 'heartbeat'), 'utf8');
  await pause(200);
  assert.equal(await readFile(join(workspace, 'heartbeat'), 'utf8'), heartbeat, 'A descendant survived container timeout cleanup');
  await sandbox.close();
  await assert.rejects(() => sandbox.run(['node', 'scripts/build.cjs'], 1000), /coding_sandbox_closed/);
  console.log(JSON.stringify({test: 'real-docker-coding-isolation', image: REPOSITORY_CODING_IMAGE, passed: ['fixed-test', 'fixed-build', 'no-host-credentials', 'workspace-only-bind', 'read-only-root', 'no-network', 'timeout-container-and-descendant-cleanup', 'closed-sandbox-refusal']}));
} catch (error) {
  process.stderr.write(`Docker isolation release gate failed: ${error instanceof Error ? error.message.split('\n')[0] : 'unknown error'}\n`);
  process.exitCode = 1;
} finally {
  await sandbox?.close();
  if (timeoutRun) await timeoutRun.catch(() => {});
  for (const id of observedContainers) await docker(['rm', '--force', id]).catch(() => {});
  for (const [name, value] of previous) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  if (root) await rm(root, {recursive: true, force: true});
}
