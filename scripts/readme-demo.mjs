// Capture actual published CLI results for the README illustration.
// No proposed tool is executed. Throwaway signing keys never leave the temp dir.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(process.argv[2] || join(root, 'docs/assets/readme-demo-run.json'));
const pins = { 'protect-mcp': '0.32.2', '@veritasacta/verify': '0.11.0' };
const dir = mkdtempSync(join(tmpdir(), 'protect-mcp-demo-capture-'));
const env = { ...process.env, NO_COLOR: '1', npm_config_audit: 'false', npm_config_fund: 'false' };
const steps = [];
function run(bin, args, expectedStatus, name) {
  const result = spawnSync(bin, args, {
    cwd: dir, env, encoding: 'utf8', input: '', timeout: 180_000, maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(result.error, undefined, `${name}: process failed`);
  assert.equal(result.status, expectedStatus, `${name}: ${result.stderr}\n${result.stdout}`);
  return { name, exitCode: result.status, stdout: result.stdout, stderr: result.stderr };
}
try {
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'protect-mcp-demo-capture', version: '0.0.0', private: true }));
  run('npm', ['install', '--save-exact', '--ignore-scripts', ...Object.entries(pins).map(([name, version]) => `${name}@${version}`)], 0, 'install');
  const lock = JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8'));
  const packages = Object.fromEntries(Object.entries(pins).map(([name, version]) => {
    const pkg = JSON.parse(readFileSync(join(dir, 'node_modules', name, 'package.json'), 'utf8'));
    assert.equal(pkg.version, version);
    return [name, { version, integrity: lock.packages[`node_modules/${name}`].integrity }];
  }));
  const gateway = join(dir, 'node_modules/protect-mcp/dist/cli.js');
  const verifier = join(dir, 'node_modules/@veritasacta/verify/cli.js');
  const cli = (bin, args, expectedStatus, name) => run(process.execPath, [bin, ...args], expectedStatus, name);
  cli(gateway, ['init', '--starter'], 0, 'initialize');
  steps.push(cli(gateway, ['evaluate', '--policy', './protect.cedar', '--tool', 'Read', '--input', '{"path":"README.md"}'], 0, 'allow_read'));
  steps.push(cli(gateway, ['evaluate', '--policy', './protect.cedar', '--tool', 'Bash', '--input', '{"command":"git push --force origin main"}'], 2, 'deny_force_push'));
  assert.match(steps[1].stderr, /starter\.force-push-main/);
  for (const [tool, input, name] of [
    ['Read', '{"path":"README.md"}', 'sign_allow'],
    ['Bash', '{"command":"git push --force origin main"}', 'sign_deny'],
  ]) {
    steps.push(cli(gateway, ['sign', '--cedar', 'builtin:starter', '--tool', tool, '--input', input, '--key', './protect-mcp.key', '--receipts', './receipts'], 0, name));
  }
  const { publicKey, privateKey } = JSON.parse(readFileSync(join(dir, 'protect-mcp.key'), 'utf8'));
  assert.match(publicKey, /^[a-f0-9]{64}$/);
  const receiptBytes = readFileSync(join(dir, 'receipts/receipts.jsonl'), 'utf8');
  const receipts = receiptBytes.trim().split('\n').map(JSON.parse);
  assert.equal(receipts.length, 2);
  assert.deepEqual(receipts.map(receipt => receipt.payload.decision), ['allow', 'deny']);
  steps.push(cli(verifier, ['--replay-chain', './receipts/receipts.jsonl', '--key', publicKey, '--json'], 0, 'verify_chain'));
  const chain = JSON.parse(steps.at(-1).stdout);
  assert.equal(chain.verified, 2);
  assert.equal(chain.failed, 0);
  assert.equal(chain.undecidable, 0);
  assert.equal(chain.chainBreaks, 0);
  assert.equal(chain.chains, 1);
  assert.equal(chain.receipts[1].checks.previous.result, 'pass');
  const tampered = structuredClone(receipts[1]);
  tampered.payload.decision = 'allow';
  writeFileSync(join(dir, 'tampered.json'), JSON.stringify(tampered));
  steps.push(cli(verifier, ['tampered.json', '--key', publicKey, '--json'], 1, 'reject_tamper'));
  assert.match(steps.at(-1).stdout, /invalid_signature/);
  writeFileSync(join(dir, 'original.json'), JSON.stringify(receipts[0]));
  steps.push(cli(verifier, ['original.json', '--json'], 2, 'reject_embedded_key'));
  assert.equal(JSON.parse(steps.at(-1).stdout).error, 'embedded_key_rejected');
  const capture = {
    schema: 'protect-mcp.readme-demo.v1',
    capturedAt: new Date().toISOString(),
    node: process.version,
    packages,
    description: 'Result summary of a real local run; proposed tools were not executed.',
    publicKeySource: 'Fresh local key file, supplied explicitly to the verifier; not taken from the receipt. Demo identity only.',
    publicKey,
    receiptLogSha256: createHash('sha256').update(receiptBytes).digest('hex'),
    receipts,
    steps,
    limits: ['Checks only the supplied records.', 'Does not prove tool execution or complete action coverage.', 'No third-party identity or authority is established.'],
  };
  // Do not publish private material or machine-specific temporary paths.
  const encoded = `${JSON.stringify(capture, null, 2).replaceAll(dir, '<temporary-directory>')}\n`;
  if (typeof privateKey === 'string') assert.ok(!encoded.includes(privateKey), 'Private key leaked into capture');
  assert.ok(!encoded.includes('"privateKey"'), 'Private key field leaked into capture');
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, encoded);
  console.log(`Captured ${steps.length} asserted CLI results: ${output}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
