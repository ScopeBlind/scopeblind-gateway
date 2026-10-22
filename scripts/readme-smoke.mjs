import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const readme = readFileSync(join(root, 'README.md'), 'utf8');
const mode = process.argv[2];
assert.ok(['--packed', '--released'].includes(mode), 'Use --packed or --released');
const example = readme.match(/<!-- readme-smoke:start -->\s*```sh\n([\s\S]*?)\n```\s*<!-- readme-smoke:end -->/);
assert.ok(example, 'README executable example markers must surround one sh block');
const pins = readme.match(/npm install --save-exact (protect-mcp@\d+\.\d+\.\d+) (@veritasacta\/verify@\d+\.\d+\.\d+)/);
assert.ok(pins, 'README must pin the producer and verifier install versions');
const gateway = mode === '--packed'
  ? resolve(root, JSON.parse(readFileSync(join(root, 'packed.json'), 'utf8'))[0].filename)
  : pins[1];
const dir = mkdtempSync(join(tmpdir(), 'protect-mcp-readme-'));
const env = { ...process.env, NO_COLOR: '1', npm_config_audit: 'false', npm_config_fund: 'false' };
try {
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ private: true, name: 'protect-mcp-readme-example', version: '0.0.0' }));
  execFileSync('npm', ['install', '--save-exact', '--ignore-scripts', gateway, pins[2]], {
    cwd: dir, env, stdio: 'inherit', timeout: 180_000,
  });
  // Execute the literal documented commands. bash -e catches unexpected failures;
  // the checks below also catch unexpected success at expected-failure steps.
  execFileSync('bash', ['-e', '-c', example[1]], {
    cwd: dir, env, stdio: ['ignore', 'inherit', 'inherit'], timeout: 120_000,
  });
  const gatewayCli = join(dir, 'node_modules/protect-mcp/dist/cli.js');
  const verifierCli = join(dir, 'node_modules/@veritasacta/verify/cli.js');
  const key = JSON.parse(readFileSync(join(dir, 'protect-mcp.key'), 'utf8')).publicKey;
  const receipts = readFileSync(join(dir, 'receipts/receipts.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(receipts.length, 2, 'README must produce exactly two receipts');
  assert.deepEqual(receipts.map(r => r.payload.decision), ['allow', 'deny']);
  assert.ok(receipts.every(r => r.signature?.alg === 'EdDSA' && /^[a-f0-9]{128}$/.test(r.signature.sig)));
  const run = (bin, args, expectedStatus) => {
    const result = spawnSync(process.execPath, [bin, ...args], {
      cwd: dir, env, encoding: 'utf8', input: '', timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, expectedStatus, result.stderr + result.stdout);
    return result;
  };
  run(gatewayCli, ['evaluate', '--policy', './protect.cedar', '--tool', 'Read', '--input', '{"path":"README.md"}'], 0);
  const deny = run(gatewayCli, ['evaluate', '--policy', './protect.cedar', '--tool', 'Bash', '--input', '{"command":"git push --force origin main"}'], 2);
  assert.match(deny.stderr, /starter\.force-push-main/);
  const chain = run(verifierCli, ['--replay-chain', './receipts/receipts.jsonl', '--key', key, '--json'], 0);
  const chainResult = JSON.parse(chain.stdout);
  assert.equal(chainResult.verified, 2);
  assert.equal(chainResult.failed, 0);
  assert.equal(chainResult.undecidable, 0);
  assert.equal(chainResult.chainBreaks, 0);
  assert.equal(chainResult.chains, 1);
  assert.equal(chainResult.receipts[1].checks.previous.result, 'pass');
  const tampered = run(verifierCli, ['tampered.json', '--key', key, '--json'], 1);
  assert.match(tampered.stdout, /invalid_signature/);
  writeFileSync(join(dir, 'original.json'), JSON.stringify(receipts[0]));
  const noKey = run(verifierCli, ['original.json', '--json'], 2);
  assert.equal(receipts[0].payload.public_key, key, 'Fixture must carry its real signing key');
  assert.equal(JSON.parse(noKey.stdout).error, 'embedded_key_rejected');
  for (const name of mode === '--packed' ? ['LICENSE', 'PATENTS.md'] : ['LICENSE']) {
    assert.ok(readFileSync(join(dir, 'node_modules/protect-mcp', name), 'utf8').length > 0, `Published package is missing ${name}`);
  }
  console.log(`README smoke passed (${mode}): allowed call, denied call, signed chain, rejected tamper and untrusted embedded key.`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
