/**
 * An enforcing gate starts only with the policy it was given. Up to 0.32.4 each of the refused cases below started and
 * allowed every call: the gateway (stdio and --http) and the hook server (`serve`) warned about an option they do not
 * read and ran without it, took the next option as an option's value (`--slug --enforce` ran in shadow mode, `serve
 * --cedar --enforce` armed with no policy), and the hook server went on without a policy that did not load. These run
 * the built CLI the way a host or a shell does, against a policy that forbids everything.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const haveCli = existsSync(CLI);
const root = mkdtempSync(join(tmpdir(), 'pmcp-enforce-startup-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const env = { ...process.env, NO_COLOR: '1', PROTECT_MCP_TELEMETRY: 'off', PROTECT_MCP_HTTP_PORT: '0' };

/** A working directory with ./rules (forbids everything), ./empty (no .cedar files) and ./open.json (allows everything). */
function work(): string {
  const dir = mkdtempSync(join(root, 'w-'));
  mkdirSync(join(dir, 'rules'));
  writeFileSync(join(dir, 'rules', 'deny-all.cedar'), 'forbid(principal, action, resource);\n');
  mkdirSync(join(dir, 'empty'));
  writeFileSync(join(dir, 'open.json'), '{"tools":{}}\n');
  return dir;
}

/** The wrapped server: it records that it started, then waits. */
const CHILD = ['--', process.execPath, '-e', "require('fs').writeFileSync('child-started', ''); process.stdin.resume()"];

function run(args: string[], cwd: string, stdin = ''): { code: number | null; err: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, env, input: stdin, encoding: 'utf8', timeout: 30_000 });
  if (r.error) throw r.error;
  return { code: r.status, err: r.stderr };
}

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => { const p = (s.address() as { port: number }).port; s.close(() => resolve(p)); });
  });
}

/** Start a long-running command and wait until its stderr matches, or fail if it exits first. */
async function started(args: string[], cwd: string, ready: RegExp): Promise<{ proc: ChildProcess; err: () => string }> {
  const proc = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ['pipe', 'ignore', 'pipe'] });
  let err = '';
  proc.stderr!.on('data', (b: Buffer) => { err += b.toString(); });
  const until = Date.now() + 20_000;
  while (!ready.test(err)) {
    if (proc.exitCode !== null) throw new Error(`exited ${proc.exitCode} before it was ready:\n${err}`);
    if (Date.now() > until) { proc.kill('SIGTERM'); throw new Error(`not ready in time:\n${err}`); }
    await new Promise((r) => setTimeout(r, 50));
  }
  return { proc, err: () => err };
}

describe.skipIf(!haveCli)('an enforcing gateway starts only with the policy it was given', () => {
  const refused: Array<[string, string[], number, RegExp]> = [
    ['a misspelled policy option', ['--enforce', '--ceder', './rules'], 2, /unknown options "--ceder", "\.\/rules"/],
    ['--cedar with no value', ['--enforce', '--cedar'], 2, /--cedar needs a value and none was given/],
    ['--cedar followed by --enforce', ['--cedar', '--enforce'], 2, /--cedar needs a value, but the argument after it is the option --enforce/],
    ['--enforce taken as the value of --slug', ['--slug', '--enforce', '--cedar', './rules'], 2, /--slug needs a value, but the argument after it is the option --enforce/],
    ['--port followed by another option', ['--enforce', '--cedar', './rules', '--port', '--http'], 2, /--port needs a value/],
    ['no policy at all', ['--enforce'], 1, /no policy was loaded, so there is nothing to enforce/],
    ['no policy at all, over --http', ['--http', '--enforce'], 1, /no policy was loaded/],
    ['a Cedar directory that does not exist', ['--enforce', '--cedar', './missing'], 1, /Cedar policy directory not found/],
    ['a Cedar directory with no policies', ['--enforce', '--cedar', './empty'], 1, /No \.cedar files found/],
  ];
  for (const [name, args, code, message] of refused) {
    it(`refuses ${name}, and never starts the wrapped server`, () => {
      const dir = work();
      const r = run([...args, ...CHILD], dir);
      expect(r.code, r.err).toBe(code);
      expect(r.err).toMatch(message);
      expect(r.err).toMatch(/Nothing was started|Error loading Cedar policies/);
      expect(existsSync(join(dir, 'child-started'))).toBe(false);
    });
  }

  it('in shadow mode warns about an option it does not read and starts, as before', async () => {
    const dir = work();
    const { proc, err } = await started(['--ceder', './rules', ...CHILD], dir, /Warning: Unknown option "--ceder"/);
    try {
      for (let i = 0; i < 200 && !existsSync(join(dir, 'child-started')); i++) await new Promise((r) => setTimeout(r, 50));
      expect(existsSync(join(dir, 'child-started')), err()).toBe(true);
    } finally {
      proc.kill('SIGTERM');
    }
  }, 30_000);

  it('starts with the policy it was given', async () => {
    const dir = work();
    const { proc } = await started(['--enforce', '--cedar', './rules', ...CHILD], dir, /Cedar policy engine: loaded 1 policies from \.\/rules/);
    proc.kill('SIGTERM');
  }, 30_000);

  it('refuses a standard it cannot read as that standard, not as no policy', () => {
    // A standard alone is a policy, and gateway.test.ts starts an enforcing gateway on one.
    const dir = work();
    const r = run(['--enforce', '--standard', './missing-standard.json', ...CHILD], dir);
    expect(r.code).toBe(1);
    expect(r.err).not.toMatch(/no policy was loaded/);
    expect(existsSync(join(dir, 'child-started'))).toBe(false);
  });
});

describe.skipIf(!haveCli)('an enforcing hook server starts only with the policy it was given', () => {
  const refused: Array<[string, string[], number, RegExp]> = [
    ['a Cedar directory that does not exist, with a JSON policy', ['--enforce', '--cedar', './missing', '--policy', './open.json'], 1, /the Cedar policies in \.\/missing did not load \(Cedar policy directory not found/],
    ['a Cedar directory with no policies, with a JSON policy', ['--enforce', '--cedar', './empty', '--policy', './open.json'], 1, /the Cedar policies in \.\/empty did not load \(No \.cedar files found/],
    ['a JSON policy that does not exist, with Cedar policies', ['--enforce', '--cedar', './rules', '--policy', './missing.json'], 1, /the policy \.\/missing\.json could not be used/],
    ['a Cedar directory that does not exist', ['--enforce', '--cedar', './missing'], 1, /the Cedar policies in \.\/missing did not load/],
    ['no policy at all', ['--enforce'], 1, /no policy was loaded, so there is nothing to enforce/],
    ['--cedar followed by --enforce', ['--cedar', '--enforce'], 2, /--cedar needs a value, but the argument after it is the option --enforce/],
    ['a misspelled policy option', ['--enforce', '--ceder', './rules'], 2, /unknown options "--ceder", "\.\/rules"/],
    ['--policy followed by another option', ['--enforce', '--cedar', './rules', '--policy'], 2, /--policy needs a value, but the argument after it is the option --port/],
  ];
  for (const [name, args, code, message] of refused) {
    it(`refuses ${name}`, async () => {
      const dir = work();
      const r = run(['serve', ...args, '--port', String(await freePort())], dir);
      expect(r.code, r.err).toBe(code);
      expect(r.err).toMatch(message);
    });
  }

  it('starts with Cedar policies and a JSON policy, and the Cedar policies decide', async () => {
    const dir = work();
    const port = await freePort();
    const { proc } = await started(['serve', '--enforce', '--cedar', './rules', '--policy', './open.json', '--port', String(port)], dir, /Policy +Cedar/);
    try {
      for (let i = 0; i < 200; i++) { try { await fetch(`http://127.0.0.1:${port}/health`); break; } catch { await new Promise((r) => setTimeout(r, 50)); } }
      const res = await fetch(`http://127.0.0.1:${port}/hook`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Bash', tool_input: { command: 'ls' } }),
      });
      expect(((await res.json()) as Record<string, any>).hookSpecificOutput?.permissionDecision).toBe('deny');
    } finally {
      proc.kill('SIGTERM');
    }
  }, 30_000);

  it('in shadow mode warns about an option it does not read and starts, as before', async () => {
    const dir = work();
    const port = await freePort();
    const { proc } = await started(['serve', '--ceder', './rules', '--port', String(port)], dir, /Warning: Unknown option "--ceder"[\s\S]*Mode +shadow/);
    proc.kill('SIGTERM');
  }, 30_000);
});

describe.skipIf(!haveCli)('a one-shot hook check refuses without the policy it was given', () => {
  it('evaluate with a misspelled policy option denies', () => {
    const dir = work();
    const r = run(['evaluate', '--format', 'claude', '--ceder', './rules'], dir, JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } }));
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/no --policy or --cedar was given/);
  });
});
