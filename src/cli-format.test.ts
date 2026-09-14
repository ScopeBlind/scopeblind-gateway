import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// These exercise the built one-shot CLI as a real host hook (stdin in, exit/stdout out),
// which is the only faithful way to test process.exit-based hook contracts.
const CLI = join(__dirname, '..', 'dist', 'cli.js');
const haveCli = existsSync(CLI);

const dir = mkdtempSync(join(tmpdir(), 'pmcp-fmt-'));
writeFileSync(
  join(dir, 'policy.cedar'),
  'forbid(principal, action, resource) when { context has command_pattern && context.command_pattern like "*rm -rf*" };\npermit(principal, action, resource);\n',
);

// A policy written against the documented nested `context.input.*` shape, used to
// prove tool input reaches Cedar on both the legacy --input and hook-payload paths.
const inputDir = mkdtempSync(join(tmpdir(), 'pmcp-fmt-input-'));
writeFileSync(
  join(inputDir, 'policy.cedar'),
  'forbid(principal, action, resource) when { context has "input" && context.input has "path" && context.input.path like "*/.env*" };\npermit(principal, action, resource);\n',
);

function run(args: string[], stdin: string): { code: number; out: string } {
  try {
    const out = execFileSync('node', [CLI, ...args], {
      input: stdin,
      encoding: 'utf-8',
      env: { ...process.env, PROTECT_MCP_TELEMETRY: 'off' },
    });
    return { code: 0, out };
  } catch (e: any) {
    return { code: e.status ?? 1, out: (e.stdout as string) || '' };
  }
}

const DENY = '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}';
const ALLOW = '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}';

describe.skipIf(!haveCli)('evaluate --format hook adapter', () => {
  it('Hermes denies via stdout JSON, not exit code (it ignores exit codes)', () => {
    const r = run(['evaluate', '--format', 'hermes', '--cedar', dir], DENY);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).decision).toBe('block');
  });

  it('Hermes allows with an empty stdout object', () => {
    const r = run(['evaluate', '--format', 'hermes', '--cedar', dir], ALLOW);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out)).toEqual({});
  });

  it('Codex/Claude/Gemini/Cursor deny via exit code 2', () => {
    for (const fmt of ['codex', 'claude', 'gemini', 'cursor']) {
      expect(run(['evaluate', '--format', fmt, '--cedar', dir], DENY).code).toBe(2);
    }
  });

  it('allows safe calls via exit 0 across exit-code hosts', () => {
    for (const fmt of ['codex', 'gemini', 'cursor']) {
      expect(run(['evaluate', '--format', fmt, '--cedar', dir], ALLOW).code).toBe(0);
    }
  });

  it('maps a bare Cursor shell command to the Bash tool', () => {
    const r = run(['evaluate', '--format', 'cursor', '--cedar', dir], '{"command":"rm -rf /"}');
    expect(r.code).toBe(2);
  });

  it('legacy flag mode (no --format) is unchanged', () => {
    const r = run(['evaluate', '--cedar', dir, '--tool', 'Bash', '--input', '{"command":"rm -rf /"}'], '');
    expect(r.code).toBe(2);
  });

  it('exposes --input under context.input so nested-shape policies match', () => {
    const r = run(['evaluate', '--cedar', inputDir, '--tool', 'read_file', '--input', '{"path":"/tmp/.env"}'], '');
    expect(r.code).toBe(2);
  });

  it('Claude Code: the README hook command, payload on stdin, allows a permitted call and returns the deny reason to the model', () => {
    // Exactly as Claude Code invokes a command hook: the call arrives as JSON on stdin, no TOOL_NAME or TOOL_INPUT in the environment.
    const allowed = run(['evaluate', '--cedar', dir, '--format', 'claude'], ALLOW);
    expect(allowed.code).toBe(0);
    const denied = run(['evaluate', '--cedar', dir, '--format', 'claude'], DENY);
    expect(denied.code).toBe(2);
    const verdict = JSON.parse(denied.out.trim().split('\n')[0]);
    expect(verdict.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(verdict.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(verdict.hookSpecificOutput.permissionDecisionReason).toMatch(/rm -rf|denied/);
  });

  it('says so on stderr when no policy is found and --fail-on-missing-policy false allows the call', () => {
    const empty = mkdtempSync(join(tmpdir(), 'pmcp-nopolicy-'));
    const r = spawnSync('node', [CLI, 'evaluate', '--cedar', empty, '--format', 'claude', '--fail-on-missing-policy', 'false'], { input: ALLOW, encoding: 'utf-8', env: { ...process.env, PROTECT_MCP_TELEMETRY: 'off' } });
    expect(r.status).toBe(0);
    expect(r.stderr).toMatch(/no policy found/);
    expect(r.stderr).toMatch(/Nothing is being enforced/);
  });

  it('maps a hook payload tool_input to context.input for exit-code hosts', () => {
    const r = run(
      ['evaluate', '--format', 'claude', '--cedar', inputDir],
      '{"tool_name":"read_file","tool_input":{"path":"/tmp/.env"}}',
    );
    expect(r.code).toBe(2);
  });
});

describe.skipIf(!haveCli)('sign --format hook adapter', () => {
  it('Hermes PostToolUse emits a no-op object and never blocks', () => {
    const r = run(['sign', '--format', 'hermes', '--receipts', join(dir, 'r')], '{"tool_name":"Bash","tool_response":{"ok":true}}');
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out)).toEqual({});
  });
});
