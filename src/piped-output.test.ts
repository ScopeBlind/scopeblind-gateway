/**
 * Output larger than a pipe holds reaches the reader whole, with the exit status of the outcome. Up to 0.32.3 the CLI
 * ended these commands with process.exit(), which ends the process at once, while Node writes stdout to a pipe
 * asynchronously on macOS and on Linux: whatever the reader had not yet taken was lost, and the exit status was still
 * 0. `protect-mcp report | jq` read the first 64 KiB of the report. The stdio gateway did the same to a large last
 * reply when the server it wraps exited. Each case here sends several times 64 KiB through a shell pipe, reads all of
 * it and checks the exit status.
 *
 * The reader starts a second late, as `| less` or a busy `| jq` can. Before the fix that made the cut certain: every
 * case below arrived as 64 KiB or less. With a reader that keeps up, report and simulate were still cut on every run,
 * while receipts and the gateway relay arrived whole on some runs.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const haveCli = existsSync(CLI);
const noShell = process.platform === 'win32';

// One decision log, receipt log and policy, large enough that each output below is several times what a pipe holds.
const COUNT = 4000;
const FLOOR = 3 * 64 * 1024;
const tool = (i: number) => `records.read.segment_${String(i).padStart(5, '0')}`;
const dir = mkdtempSync(join(tmpdir(), 'pmcp-piped-output-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
{
  const now = Date.now();
  const log: string[] = [];
  const receipts: string[] = [];
  const tools: Record<string, unknown> = { '*': { require: 'any' } };
  for (let i = 0; i < COUNT; i++) {
    const decision = i % 2 ? 'deny' : 'allow';
    const reason_code = decision === 'deny' ? 'policy_block' : 'default_allow';
    const timestamp = now - (COUNT - i) * 1000;
    log.push(JSON.stringify({ tool: tool(i), decision, reason_code, tier: 'unknown', mode: 'enforce', request_id: `req-${i}`, timestamp }));
    receipts.push(JSON.stringify({ type: 'decision_receipt', issued_at: new Date(timestamp).toISOString(), payload: { tool: tool(i), decision, reason_code }, signature: 'test' }));
    tools[tool(i)] = i % 3 ? { rate_limit: '10/minute' } : { block: true };
  }
  writeFileSync(join(dir, '.protect-mcp-log.jsonl'), log.join('\n') + '\n');
  writeFileSync(join(dir, '.protect-mcp-receipts.jsonl'), receipts.join('\n') + '\n');
  writeFileSync(join(dir, 'policy.json'), JSON.stringify({ tools }, null, 2));
  // A stand-in MCP server, in a folder of its own so the gateway's logs stay apart from the ones above: it answers the
  // first request with a reply of about 1 MiB, then exits with status 3 once that reply is written.
  mkdirSync(join(dir, 'relay'));
  writeFileSync(join(dir, 'relay', 'big-reply-server.mjs'), [
    "import { createInterface } from 'node:readline';",
    'createInterface({ input: process.stdin }).once(\'line\', (line) => {',
    '  const { id } = JSON.parse(line);',
    "  const reply = JSON.stringify({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'x'.repeat(1048576) }] } });",
    "  process.stdout.write(reply + '\\n', () => process.exit(3));",
    '});',
    '',
  ].join('\n'));
}

const env = { ...process.env, NO_COLOR: '1', PROTECT_MCP_TELEMETRY: 'off', PROTECT_MCP_HTTP_PORT: '0' };
const options = { cwd: dir, env, encoding: 'utf8' as const, maxBuffer: 64 * 1024 * 1024, timeout: 120_000 };

interface Run { status: number; stdout: string; stderr: string }

/** The command in a shell pipeline whose reader starts a second late; its exit status comes back on fd 3. */
function piped(args: string[], reader = '{ sleep 1; cat; }'): Run {
  const run = spawnSync('sh', ['-c', `{ "$0" "$@"; echo "$?" >&3; } | ${reader}`, process.execPath, CLI, ...args], { ...options, stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
  if (run.error) throw run.error;
  const status = String(run.output[3] ?? '').trim();
  if (!/^\d+$/.test(status)) throw new Error(`the pipeline gave no exit status (sh exit ${run.status}): ${run.stderr}`);
  return { status: Number(status), stdout: String(run.stdout), stderr: String(run.stderr) };
}

/** The same command with stdout written to a file, which a cut never reached. */
function toFile(args: string[]): Run {
  const out = join(dir, 'to-file.out');
  const run = spawnSync('sh', ['-c', `"$0" "$@" > "${out}"`, process.execPath, CLI, ...args], options);
  if (run.error) throw run.error;
  return { status: run.status ?? -1, stdout: readFileSync(out, 'utf8'), stderr: String(run.stderr) };
}

/** The whole JSON document, parsed: it fails, naming how much arrived, when stdout ended early. */
function wholeJson(run: Run, label: string): any {
  const bytes = Buffer.byteLength(run.stdout);
  let parsed: unknown;
  try {
    parsed = JSON.parse(run.stdout);
  } catch (e) {
    expect.fail(`${label}: stdout ended after ${bytes} bytes and is not one whole JSON document (${(e as Error).message}); exit ${run.status}`);
  }
  expect(bytes, `${label}: a document of ${bytes} bytes is too small to test this`).toBeGreaterThan(FLOOR);
  return parsed;
}

describe.skipIf(!haveCli || noShell)('output through a pipe arrives whole', () => {
  it('report --format json: the whole report, with exit 0', () => {
    const run = piped(['report', '--format', 'json', '--dir', dir]);
    const report = wholeJson(run, 'report json');
    expect(run.status).toBe(0);
    expect(report.tool_breakdown.length).toBe(COUNT);
    expect(run.stderr).toBe('');
  }, 120_000);

  it('report --format md: the whole report, down to its last line, with exit 0', () => {
    const run = piped(['report', '--format', 'md', '--dir', dir]);
    expect(run.stdout.endsWith('*Generated by protect-mcp · scopeblind.com*\n'), `the report ended after ${Buffer.byteLength(run.stdout)} bytes`).toBe(true);
    expect(Buffer.byteLength(run.stdout)).toBeGreaterThan(FLOOR);
    expect(run.status).toBe(0);
  }, 120_000);

  it('simulate --json: the whole summary, the same as written to a file, with exit 0', () => {
    const args = ['simulate', '--policy', join(dir, 'policy.json'), '--log', join(dir, '.protect-mcp-log.jsonl'), '--json'];
    const run = piped(args);
    const summary = wholeJson(run, 'simulate json');
    expect(run.status).toBe(0);
    expect(summary.total_calls).toBe(COUNT);
    expect(run.stdout).toBe(toFile(args).stdout);
  }, 120_000);

  it('simulate: the whole text, the same as written to a file, with exit 0', () => {
    const args = ['simulate', '--policy', join(dir, 'policy.json'), '--log', join(dir, '.protect-mcp-log.jsonl')];
    const run = piped(args);
    const file = toFile(args);
    expect(Buffer.byteLength(file.stdout)).toBeGreaterThan(FLOOR);
    expect(Buffer.byteLength(run.stdout), 'bytes through the pipe').toBe(Buffer.byteLength(file.stdout));
    expect(run.stdout).toBe(file.stdout);
    expect(run.status).toBe(0);
  }, 120_000);

  it('receipts --last N: every line, the same as written to a file, with exit 0', () => {
    const args = ['receipts', '--last', String(COUNT), '--dir', dir];
    const run = piped(args);
    const file = toFile(args);
    expect(Buffer.byteLength(file.stdout)).toBeGreaterThan(FLOOR);
    expect(run.stdout.split('\n').filter((line) => line.includes('records.read.segment_')).length, `lines through the pipe (${Buffer.byteLength(run.stdout)} bytes)`).toBe(COUNT);
    expect(run.stdout).toBe(file.stdout);
    expect(run.status).toBe(0);
  }, 120_000);

  it('the stdio gateway relays a large last reply whole when the server exits, with the server\'s exit status', () => {
    const request = JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'resources/read', params: {} });
    const run = spawnSync('sh', ['-c', `{ printf '%s\\n' '${request}' | "$0" "$1" -- "$0" big-reply-server.mjs; echo "$?" >&3; } | { sleep 1; cat; }`, process.execPath, CLI], { ...options, cwd: join(dir, 'relay'), stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
    if (run.error) throw run.error;
    const stdout = String(run.stdout);
    const lines = stdout.split('\n').filter(Boolean);
    expect(lines.length, `the relay ended after ${Buffer.byteLength(stdout)} bytes`).toBe(1);
    const reply = JSON.parse(lines[0]);
    expect(reply.id).toBe(7);
    expect(reply.result.content[0].text.length).toBe(1048576);
    expect(String(run.output[3]).trim()).toBe('3');
  }, 120_000);

  it('a reader that stops early: the exit status and stderr are what they would have been', () => {
    // The rest of the report cannot be written, so the write fails (EPIPE). That must end the run with its own status,
    // not an unhandled 'error' event, exit 1 and a stack trace.
    const run = piped(['report', '--format', 'json', '--dir', dir], 'head -c 64');
    expect(Buffer.byteLength(run.stdout)).toBe(64);
    expect(run.status).toBe(0);
    expect(run.stderr).toBe('');
  }, 120_000);
});
