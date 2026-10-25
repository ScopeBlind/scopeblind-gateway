import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const temporary = mkdtempSync(join(tmpdir(), 'protect-assistant-smoke-'));
// Spaces exercise path handling without a shell.
const workspace = join(temporary, 'demo with spaces');
const helper = join(root, 'plugins/protect-mcp-assistant/skills/protect-mcp-demo/scripts/demo.mjs');
const run = () => spawnSync(process.execPath, [helper, '--workspace', workspace], { encoding: 'utf8', timeout: 240_000, maxBuffer: 4 * 1024 * 1024 });
try {
  const result = run();
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
  const summary = JSON.parse(readFileSync(join(workspace, 'demo-summary.json'), 'utf8'));
  assert.deepEqual(summary.decisions, ['allow', 'deny']);
  assert.equal(summary.verifiedReceipts, 2);
  assert.equal(summary.toolsExecuted, false);
  assert.equal(summary.hostConfigured, false);
  assert.equal(summary.tamperedReceiptRejected, true);
  assert.equal(summary.missingTrustedKeyRejected, true);
  assert.equal(summary.wrongTrustedKeyRejected, true);
  const receiptsBefore = readFileSync(join(workspace, 'receipts/receipts.jsonl'));
  const keyBefore = readFileSync(join(workspace, 'protect-mcp.key'));
  const filesBefore = readdirSync(workspace).sort();
  const repeated = run();
  assert.equal(repeated.status, 1, 'Repeated run must refuse an existing directory');
  assert.deepEqual(readFileSync(join(workspace, 'receipts/receipts.jsonl')), receiptsBefore);
  assert.deepEqual(readFileSync(join(workspace, 'protect-mcp.key')), keyBefore);
  assert.deepEqual(readdirSync(workspace).sort(), filesBefore);
  console.log(result.stdout.trim());
  console.log('PASS: shipped demo helper, trusted-key verification, tamper rejection, and no-overwrite retry');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
