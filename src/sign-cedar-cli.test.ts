import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const POLICY = `
permit (principal, action in [Action::"Read", Action::"Glob", Action::"Grep", Action::"WebSearch"], resource);
permit (principal, action == Action::"Bash", resource) when { ["git", "npm", "ls", "cat", "pwd", "echo", "node", "python"].contains(context.command_pattern) };
forbid (principal, action == Action::"Bash", resource) when { ["rm -rf", "dd", "mkfs", "shred"].contains(context.command_pattern) };
permit (principal, action in [Action::"Write", Action::"Edit"], resource) when { context.path_starts_with == "./" };
`;

let dir: string;
function sign(tool: string, input: object, context: object, receipts: string) {
  const r = spawnSync('node', [CLI, 'sign', '--cedar', join(dir, 'policy'), '--action-model', 'tool', '--tool', tool,
    '--input', JSON.stringify(input), '--context', JSON.stringify(context), '--receipts', receipts, '--key', join(dir, 'key.json')],
    { cwd: dir, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  const lines = readFileSync(join(receipts, 'receipts.jsonl'), 'utf8').trim().split('\n');
  return { stdout: JSON.parse(r.stdout.trim().split('\n').pop() as string), receipt: JSON.parse(lines[lines.length - 1]) };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pmcp-sign-cedar-'));
  mkdirSync(join(dir, 'policy'));
  writeFileSync(join(dir, 'policy', 'autoresearch-safe.cedar'), POLICY);
  // The corpus fixture seed (fixtures/keys/README.md), in the key-file shape the conformance driver uses.
  const seed = '0000000000000000000000000000000000000000000000000000000000000001';
  const priv = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + seed, 'hex'), format: 'der', type: 'pkcs8' });
  const pub = Buffer.from(createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32)).toString('hex');
  writeFileSync(join(dir, 'key.json'), JSON.stringify({ privateKey: seed, publicKey: pub, kid: 'conformance' }));
});

describe('sign --cedar signs the policy decision', () => {
  it('denies the destructive Bash call the policy forbids', () => {
    const { stdout, receipt } = sign('Bash', { command: 'rm -rf /' }, { command_pattern: 'rm -rf' }, join(dir, 'r1'));
    expect(stdout.signed).toBe(true);
    expect(stdout.decision).toBe('deny');
    expect(receipt.payload.decision).toBe('deny');
    expect(receipt.payload.policy_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(receipt.payload.spec).toBe('draft-farley-acta-signed-receipts-03');
  });
  it('allows the Read call the policy permits, with the same policy digest', () => {
    const a = sign('Read', { file_path: './README.md' }, { path_starts_with: './' }, join(dir, 'r2'));
    const b = sign('Bash', { command: 'rm -rf /' }, { command_pattern: 'rm -rf' }, join(dir, 'r3'));
    expect(a.receipt.payload.decision).toBe('allow');
    expect(a.receipt.payload.policy_digest).toBe(b.receipt.payload.policy_digest);
  });
  it('without --cedar the verb is unchanged: allow, no policy identity', () => {
    const receipts = join(dir, 'r4');
    spawnSync('node', [CLI, 'sign', '--tool', 'Bash', '--input', '{"command":"rm -rf /"}', '--receipts', receipts, '--key', join(dir, 'key.json')], { cwd: dir, encoding: 'utf8' });
    const last = JSON.parse(readFileSync(join(receipts, 'receipts.jsonl'), 'utf8').trim().split('\n').pop() as string);
    expect(last.payload.decision).toBe('allow');
    expect(last.payload.policy_digest).toBe('none');
  });

  it('records the evaluator reason: a policy deny says cedar_deny', () => {
    const { receipt } = sign('Bash', { command: 'rm -rf /' }, { command_pattern: 'rm -rf' }, join(dir, 'r-reason-deny'));
    expect(receipt.payload.decision).toBe('deny');
    expect(String(receipt.payload.reason).startsWith('cedar_deny')).toBe(true);
  });

  it('records the evaluator reason: a policy that fails to load is not a policy deny', () => {
    // Cedar's `in` is the entity-hierarchy operator; a string on its left is a type error.
    mkdirSync(join(dir, 'bad-policy'));
    writeFileSync(join(dir, 'bad-policy', 'bad.cedar'),
      'permit (principal, action == Action::"Bash", resource) when { context.command_pattern in ["git"] };\n');
    const receipts = join(dir, 'r-reason-bad');
    const r = spawnSync('node', [CLI, 'sign', '--cedar', join(dir, 'bad-policy'), '--action-model', 'tool', '--tool', 'Bash',
      '--input', '{"command":"git status"}', '--context', '{"command_pattern":"git"}', '--receipts', receipts, '--key', join(dir, 'key.json')],
      { cwd: dir, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
    expect(r.status).toBe(0);
    const lines = readFileSync(join(receipts, 'receipts.jsonl'), 'utf8').trim().split('\n');
    const receipt = JSON.parse(lines[lines.length - 1]);
    expect(receipt.payload.decision).toBe('deny');
    const reason = String(receipt.payload.reason);
    expect(reason).not.toBe('cedar_deny');
    expect(reason.startsWith('cedar_deny: {"reason":["policy0"]')).toBe(false);
    expect(/policy_error|errors":\["/.test(reason)).toBe(true);
  });
});
