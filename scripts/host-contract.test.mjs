import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { verifyReceipt } from '../dist/index.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const cli = join(root, 'dist/cli.js');
assert.ok(existsSync(cli), 'Run npm run build before host contract checks');
const vectors = JSON.parse(readFileSync(join(root, 'vectors/host-contract.v1.json'), 'utf8'));
const dir = mkdtempSync(join(tmpdir(), 'protect-host-contract-'));
const policy = join(dir, 'contract.cedar');
const keyFile = join(dir, 'fixture-key.json');
const privateKey = ed25519.utils.randomPrivateKey();
const publicKey = Buffer.from(ed25519.getPublicKey(privateKey)).toString('hex');
writeFileSync(keyFile, JSON.stringify({ privateKey: Buffer.from(privateKey).toString('hex'), publicKey }), { mode: 0o600 });
writeFileSync(policy, `permit(principal, action, resource);
forbid(principal, action, resource == Tool::"run_shell_command");
forbid(principal, action, resource) when {
  context has input && context.input has payment && context.input.payment has amount && context.input.payment.amount > 100
};
`);
test.after(() => rmSync(dir, { recursive: true, force: true }));
const hosts = ['claude', 'codex', 'cursor', 'gemini', 'hermes'];

function call(host, payload, args = []) {
  const result = spawnSync(process.execPath, [cli, 'evaluate', '--format', host, '--policy', policy, ...args], {
    cwd: dir, input: payload, encoding: 'utf8', timeout: 10000,
    env: { ...process.env, PROTECT_MCP_TELEMETRY: 'off' },
  });
  assert.ifError(result.error);
  return { code: result.status, stdout: result.stdout, stderr: result.stderr, verdict: result.stdout.trim() ? JSON.parse(result.stdout) : null };
}
function expectDecision(host, actual, decision) {
  assert.equal(actual.code, decision === 'deny' && host !== 'hermes' ? 2 : 0);
  if (host === 'cursor') {
    assert.equal(actual.verdict.permission, decision);
    assert.ok(!Object.hasOwn(actual.verdict, 'userMessage'));
    if (decision === 'deny') assert.equal(typeof actual.verdict.user_message, 'string');
  } else if (host === 'gemini') assert.equal(actual.verdict.decision, decision);
  else if (host === 'hermes') assert.deepEqual(actual.verdict, decision === 'allow' ? {} : { decision: 'block', reason: actual.verdict.reason });
  // Codex 0.145.0 checks hook output against closed schemas: an allow prints {}, and a deny is exit 2 with the reason on stderr.
  else if (host === 'codex') assert.deepEqual(actual.verdict, decision === 'allow' ? {} : null);
  else if (host === 'claude' && decision === 'deny') assert.equal(actual.verdict.hookSpecificOutput.permissionDecision, 'deny');
  if (decision === 'deny') assert.match(actual.stderr, /protect-mcp denied:/);
}

for (const host of hosts) {
  test(`${host}: policy receives full nested arguments and native tool identity`, () => {
    for (const vector of vectors.cases) {
      const payload = JSON.stringify({ tool_name: vector.tool, tool_input: host === 'cursor' ? JSON.stringify(vector.input) : vector.input });
      expectDecision(host, call(host, payload), vector.decision);
    }
  });
  test(`${host}: malformed hook data cannot fall back to allowed flags`, () => {
    for (const payload of vectors.invalid_payloads) {
      const actual = call(host, payload, ['--tool', 'lookup', '--input', '{}', '--fail-on-missing-policy', 'false']);
      expectDecision(host, actual, 'deny');
      assert.match(actual.stderr, /invalid_hook_payload/);
    }
  });
  test(`${host}: missing policy refuses a well-formed call`, () => {
    // A separate call avoids duplicate --policy option semantics.
    const actual = spawnSync(process.execPath, [cli, 'evaluate', '--format', host, '--cedar', join(dir, 'absent')], {
      cwd: dir, input: JSON.stringify({ tool_name: 'lookup', tool_input: {} }), encoding: 'utf8', timeout: 10000,
    });
    assert.ifError(actual.error);
    expectDecision(host, { code: actual.status, verdict: actual.stdout.trim() ? JSON.parse(actual.stdout) : null, stderr: actual.stderr }, 'deny');
    assert.match(actual.stderr, /policy not found/);
  });
}
test('Cursor rejects malformed or primitive JSON-encoded MCP arguments', () => {
  for (const input of ['not json', 'null', '[]', '"text"']) {
    expectDecision('cursor', call('cursor', JSON.stringify({ tool_name: 'lookup', tool_input: input })), 'deny');
  }
});
test('Cursor shell contract includes a valid allow response', () => {
  expectDecision('cursor', call('cursor', JSON.stringify({ command: 'printf synthetic', cwd: dir })), 'allow');
});
test('Cursor never interprets an MCP launch command as missing tool arguments', () => {
  for (const payload of [
    { command: 17 }, { command: null }, { command: '' },
    { tool_name: 'lookup', command: 'node server.js' },
    { tool_name: 'lookup', tool_input: null, command: 'node server.js' },
    { tool_name: 'lookup', tool_input: null, toolInput: {}, command: 'node server.js' },
  ]) expectDecision('cursor', call('cursor', JSON.stringify(payload)), 'deny');
});
test('after-tool signing never emits a new Cursor, Gemini or Codex tool decision', () => {
  for (const host of ['cursor', 'gemini', 'codex']) {
    const receipts = join(dir, `receipts-${host}`);
    const actual = spawnSync(process.execPath, [cli, 'sign', '--format', host, '--key', keyFile, '--receipts', receipts], {
      cwd: dir, input: JSON.stringify({ tool_name: 'lookup', tool_input: host === 'cursor' ? '{"nested":{"value":1}}' : { nested: { value: 1 } }, tool_response: { ok: true } }), encoding: 'utf8', timeout: 10000,
    });
    assert.ifError(actual.error);
    assert.equal(actual.status, 0);
    assert.deepEqual(JSON.parse(actual.stdout), {});
    const record = JSON.parse(readFileSync(resolve(receipts, 'receipts.jsonl'), 'utf8').trim());
    assert.equal(verifyReceipt(record, publicKey).valid, true);
    assert.equal(record.payload.payload_digest.input_hash, createHash('sha256').update('{"nested":{"value":1}}').digest('hex'));
  }
});
test('invalid formatted signing does not invent a receipt', () => {
  for (const host of hosts) {
    const receipts = join(dir, `invalid-receipts-${host}`);
    const actual = spawnSync(process.execPath, [cli, 'sign', '--format', host, '--key', keyFile, '--receipts', receipts], {
      cwd: dir, input: 'null', encoding: 'utf8', timeout: 10000,
    });
    assert.ifError(actual.error);
    // A recording failure, not a block: in a PostToolUse hook the tool has already run.
    assert.equal(actual.status, 1);
    assert.equal(actual.stdout, '');
    assert.match(actual.stderr, /no receipt recorded/);
    assert.equal(existsSync(join(receipts, 'receipts.jsonl')), false);
  }
});
