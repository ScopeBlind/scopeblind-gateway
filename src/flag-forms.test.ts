/**
 * `--flag=value` is read as `--flag value`, and a call that names no tool is denied. Up to 0.32.4 a `--flag=value`
 * argument matched no option: `evaluate --format=claude` read neither the format nor the hook payload, evaluated an
 * empty tool name and allowed `rm -rf /` with exit 0, and `--cedar=<dir>` ran the gateway without that policy. These
 * run the built CLI the way a host or a shell does.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const haveCli = existsSync(CLI);
const dir = mkdtempSync(join(tmpdir(), 'pmcp-flag-forms-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const env = { ...process.env, NO_COLOR: '1', PROTECT_MCP_TELEMETRY: 'off', PROTECT_MCP_HTTP_PORT: '0' };
function run(args: string[], stdin = '', cwd = dir): { code: number; out: string; err: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, env, input: stdin, encoding: 'utf8', timeout: 60_000 });
  if (r.error) throw r.error;
  return { code: r.status ?? -1, out: r.stdout, err: r.stderr };
}

const DELETE_ROOT = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
const LIST = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } });

describe.skipIf(!haveCli)('--flag=value reads as --flag value', () => {
  for (const format of ['claude', 'codex', 'cursor', 'gemini', 'hermes']) {
    it(`evaluate --format=${format} reads the hook payload and decides it in that host's form`, () => {
      const deny = run(['evaluate', `--format=${format}`, '--policy', 'builtin:starter'], DELETE_ROOT);
      expect(deny.code, deny.out).toBe(format === 'hermes' ? 0 : 2);
      expect(deny.err).toMatch(/starter\.delete-root-or-home/);
      if (format === 'hermes') expect(JSON.parse(deny.out)).toMatchObject({ decision: 'block' });
      if (format === 'claude') expect(JSON.parse(deny.out).hookSpecificOutput.permissionDecision).toBe('deny');
      const allow = run(['evaluate', `--format=${format}`, '--policy=builtin:starter'], LIST);
      expect(allow.code, allow.err).toBe(0);
      expect(allow.err).toBe('');
    });
  }

  it('evaluate reads --policy=, --tool= and --input= in flag mode', () => {
    const r = run(['evaluate', '--policy=builtin:starter', '--tool=Bash', '--input={"command":"rm -rf /"}']);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/starter\.delete-root-or-home/);
  });

  it('sign --format=claude writes the Claude Code output shape', () => {
    const r = run(['sign', '--format=claude', `--receipts=${join(dir, 'signed')}`], LIST);
    expect(r.code).toBe(0);
    const out = JSON.parse(r.out);
    expect(out.receipt_decision).toBe('allow');
    expect(out).not.toHaveProperty('decision');
  });

  it('a switch that takes no value is refused with one, and nothing is done', () => {
    const target = mkdtempSync(join(dir, 'hooks-'));
    const r = run(['init-hooks', '--dry-run=false', '--dir', target]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/--dry-run takes no value/);
    expect(readdirSync(target)).toEqual([]);
    const g = run(['--enforce=false', '--', process.execPath, '-e', '']);
    expect(g.code).toBe(2);
    expect(g.err).toMatch(/--enforce takes no value/);
  });
});

describe.skipIf(!haveCli)('evaluate denies a call that names no tool', () => {
  it('with no --tool, or an empty one, under a policy that allows by default', () => {
    for (const args of [['evaluate', '--policy', 'builtin:starter'], ['evaluate', '--policy', 'builtin:starter', '--tool='], ['evaluate', '--policy', 'builtin:starter', '--tool', ' ']]) {
      const r = run(args);
      expect(r.code, args.join(' ')).toBe(2);
      expect(r.err, args.join(' ')).toMatch(/no tool name/);
      expect(r.out, args.join(' ')).toBe('');
    }
  });

  it('with --fail-on-missing-policy false and no policy', () => {
    const r = run(['evaluate', '--fail-on-missing-policy', 'false']);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/no tool name/);
  });
});

describe.skipIf(!haveCli)('the stdio gateway reads --cedar=<dir>', () => {
  it('a call the policy forbids is refused and never reaches the server', async () => {
    const work = mkdtempSync(join(dir, 'gateway-'));
    // A folder the gateway would not find on its own (it looks in ./cedar, ./policies and .).
    mkdirSync(join(work, 'rules'));
    writeFileSync(join(work, 'rules', 'policy.cedar'), 'permit(principal, action, resource);\nforbid(principal, action, resource == Tool::"danger");\n');
    writeFileSync(join(work, 'child.mjs'), [
      "import { createInterface } from 'node:readline';",
      "import { appendFileSync } from 'node:fs';",
      'createInterface({ input: process.stdin }).on(\'line\', (line) => {',
      '  const m = JSON.parse(line);',
      "  if (m.method === 'tools/call') appendFileSync('executed.jsonl', JSON.stringify(m.params.name) + '\\n');",
      "  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'ran' }] } }) + '\\n');",
      '});',
      '',
    ].join('\n'));
    const proc = spawn(process.execPath, [CLI, '--enforce', '--cedar=./rules', '--', process.execPath, 'child.mjs'], { cwd: work, env, stdio: ['pipe', 'pipe', 'pipe'] });
    const reply = await new Promise<Record<string, any>>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('no reply from the gateway')), 20_000);
      createInterface({ input: proc.stdout! }).once('line', (line) => { clearTimeout(timer); resolve(JSON.parse(line)); });
      proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'danger', arguments: {} } }) + '\n');
    });
    proc.stdin!.end();
    await new Promise((resolve) => proc.on('exit', resolve));
    expect(reply.error?.message ?? JSON.stringify(reply)).toMatch(/danger/);
    expect(reply.result).toBeUndefined();
    expect(existsSync(join(work, 'executed.jsonl'))).toBe(false);
  }, 60_000);
});
