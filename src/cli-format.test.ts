import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, existsSync, readFileSync, statSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyReceipt } from './acta-envelope.js';

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

// ============================================================
// 0.31.0: the starter policy, Cedar-safe inputs and readable denials, built CLI
// ============================================================

function runAll(args: string[], stdin = '', cwd?: string): { code: number; out: string; err: string } {
  const r = spawnSync('node', [CLI, ...args], { input: stdin, cwd, encoding: 'utf-8', env: { ...process.env, PROTECT_MCP_TELEMETRY: 'off' } });
  return { code: r.status ?? 1, out: r.stdout || '', err: r.stderr || '' };
}

interface StarterVectors {
  policy: { policy_digest: string };
  cases: Array<{ id: string; tool: string; input: Record<string, unknown>; decision: 'allow' | 'deny'; rule?: string }>;
  input_cases: Array<{ id: string; tool: string; input: Record<string, unknown>; allow_all: 'allow' | 'deny'; starter: 'allow' | 'deny'; rule?: string }>;
}
const starterVectors = JSON.parse(readFileSync(join(__dirname, '..', 'vectors', 'starter-policy.v1.json'), 'utf-8')) as StarterVectors;

describe.skipIf(!haveCli)('evaluate --policy builtin:starter (the plugin hook path)', () => {
  it('decides every vector with the exit code the hook relies on, and names the rule on stderr in one line', () => {
    const all = [
      ...starterVectors.cases.map((c) => ({ ...c, expected: c.decision })),
      ...starterVectors.input_cases.map((c) => ({ ...c, expected: c.starter })),
    ];
    for (const c of all) {
      const r = runAll(['evaluate', '--policy', 'builtin:starter', '--tool', c.tool, '--input', JSON.stringify(c.input)]);
      expect(r.code, `${c.id}: ${r.err}`).toBe(c.expected === 'allow' ? 0 : 2);
      const verdict = JSON.parse(r.out.trim());
      expect(verdict.policy_digest).toBe(starterVectors.policy.policy_digest);
      if (c.expected === 'deny') {
        expect(verdict.reason, c.id).toMatch(new RegExp(`^cedar_deny: ${c.rule!.replace('.', '\\.')}: `));
        expect(r.err, c.id).toBe(`protect-mcp denied: ${verdict.reason}\n`);
      } else {
        expect(r.err, c.id).not.toContain('denied');
      }
    }
  }, 120_000);

  it('a fraction is no longer refused under an allow-all policy, in flag and hook-payload modes', () => {
    const allowAll = mkdtempSync(join(tmpdir(), 'pmcp-allowall-'));
    writeFileSync(join(allowAll, 'protect.cedar'), 'permit(principal, action, resource);\n');
    const policy = join(allowAll, 'protect.cedar');
    for (const c of starterVectors.input_cases) {
      expect(runAll(['evaluate', '--policy', policy, '--tool', c.tool, '--input', JSON.stringify(c.input)]).code, c.id).toBe(0);
      expect(runAll(['evaluate', '--policy', policy, '--format', 'claude'], JSON.stringify({ tool_name: c.tool, tool_input: c.input })).code, c.id).toBe(0);
    }
  }, 60_000);

  it('writes the reason to stderr on a deny in every mode, Hermes included', () => {
    const input = { command: 'git push --force origin main' };
    const payload = JSON.stringify({ tool_name: 'Bash', tool_input: input });
    for (const fmt of ['claude', 'codex', 'gemini', 'cursor', 'hermes']) {
      const r = runAll(['evaluate', '--policy', 'builtin:starter', '--format', fmt], payload);
      expect(r.code).toBe(fmt === 'hermes' ? 0 : 2);
      expect(r.err).toMatch(/^protect-mcp denied: cedar_deny: starter\.force-push-main: Force-push to main/);
    }
    const hermes = runAll(['evaluate', '--policy', 'builtin:starter', '--format', 'hermes'], payload);
    expect(JSON.parse(hermes.out)).toMatchObject({ decision: 'block' });
    const claude = runAll(['evaluate', '--policy', 'builtin:starter', '--format', 'claude'], payload);
    expect(JSON.parse(claude.out).hookSpecificOutput.permissionDecisionReason).toContain('starter.force-push-main');
  });

  it('a deny from a policy file with unnamed rules still reaches stderr in flag mode', () => {
    const r = runAll(['evaluate', '--cedar', dir, '--tool', 'Bash', '--input', '{"command":"rm -rf /tmp/x"}']);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/^protect-mcp denied: cedar_deny: policy0\n$/);
  });

  it('an unknown built-in fails closed and says which built-ins exist', () => {
    const r = runAll(['evaluate', '--policy', 'builtin:strict', '--tool', 'Read', '--input', '{"file_path":"/w/a.ts"}']);
    expect(r.code).toBe(2);
    expect(r.err).toContain('there is no built-in policy builtin:strict (available: builtin:starter)');
  });

  it('sign --cedar builtin:starter signs the starter decision, its named reason and its digest with the init --starter key', () => {
    const project = mkdtempSync(join(tmpdir(), 'pmcp-sign-starter-'));
    expect(runAll(['init', '--starter'], '', project).code).toBe(0);
    const keyFile = join(project, 'protect-mcp.key');
    const r = runAll(['sign', '--cedar', 'builtin:starter', '--tool', 'Read', '--input', '{"file_path":"/w/app/.env"}', '--receipts', join(project, 'receipts'), '--key', keyFile]);
    expect(r.code, r.err).toBe(0);
    const receipt = JSON.parse(readFileSync(join(project, 'receipts', 'receipts.jsonl'), 'utf-8').trim().split('\n').pop()!);
    expect(receipt.payload).toMatchObject({ decision: 'deny', policy_digest: starterVectors.policy.policy_digest });
    expect(receipt.payload.reason).toMatch(/^cedar_deny: starter\.read-secret-file: Reads a credential file/);
    expect(verifyReceipt(receipt, JSON.parse(readFileSync(keyFile, 'utf-8')).publicKey).valid).toBe(true);
  });
});

describe.skipIf(!haveCli)('init --starter', () => {
  it('writes ./protect.cedar from the starter, creates the plugin signing key once, and keeps it out of git', () => {
    const project = mkdtempSync(join(tmpdir(), 'pmcp-init-starter-'));
    writeFileSync(join(project, '.gitignore'), 'node_modules');
    const first = runAll(['init', '--starter'], '', project);
    expect(first.code, first.err).toBe(0);
    const starterText = readFileSync(join(__dirname, '..', 'policies', 'starter.cedar'), 'utf-8');
    expect(readFileSync(join(project, 'protect.cedar'), 'utf-8')).toBe(starterText);
    for (const id of ['starter.delete-root-or-home', 'starter.force-push-main', 'starter.read-secret-file', 'starter.grep-secret-path', 'starter.shell-reads-secret', 'starter.pipe-network-to-shell', 'starter.write-sensitive-location']) {
      expect(first.out).toContain(id);
    }
    const key = JSON.parse(readFileSync(join(project, 'protect-mcp.key'), 'utf-8'));
    expect(key.privateKey).toMatch(/^[0-9a-f]{64}$/);
    expect(key.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(statSync(join(project, 'protect-mcp.key')).mode & 0o777).toBe(0o600);
    expect(first.out).not.toContain(key.privateKey);
    expect(readFileSync(join(project, '.gitignore'), 'utf-8')).toBe('node_modules\n/protect-mcp.key\n');

    // A second run changes nothing: the policy is not overwritten and the key is kept.
    writeFileSync(join(project, 'protect.cedar'), '// mine\npermit(principal, action, resource);\n');
    const second = runAll(['init', '--starter'], '', project);
    expect(second.code).toBe(0);
    expect(second.out).toContain('already exists');
    expect(readFileSync(join(project, 'protect.cedar'), 'utf-8')).toBe('// mine\npermit(principal, action, resource);\n');
    expect(JSON.parse(readFileSync(join(project, 'protect-mcp.key'), 'utf-8')).privateKey).toBe(key.privateKey);
    expect(readFileSync(join(project, '.gitignore'), 'utf-8')).toBe('node_modules\n/protect-mcp.key\n');

    // --force replaces the policy and still never replaces the key.
    const forced = runAll(['init', '--starter', '--force'], '', project);
    expect(forced.code).toBe(0);
    expect(readFileSync(join(project, 'protect.cedar'), 'utf-8')).toBe(starterText);
    expect(JSON.parse(readFileSync(join(project, 'protect-mcp.key'), 'utf-8')).privateKey).toBe(key.privateKey);

    // The written file is what the plugin evaluates: same digest as the built-in.
    const viaFile = runAll(['evaluate', '--policy', join(project, 'protect.cedar'), '--tool', 'Bash', '--input', '{"command":"cat .env"}']);
    expect(viaFile.code).toBe(2);
    expect(JSON.parse(viaFile.out).policy_digest).toBe(starterVectors.policy.policy_digest);
  });

  it('--contain adds the only-inside-this-folder rules for this folder', () => {
    const base = mkdtempSync(join(tmpdir(), 'pmcp-init-contain-'));
    const project = join(base, 'app');
    mkdirSync(project);
    const r = runAll(['init', '--starter', '--contain', '--dir', project]);
    expect(r.code, r.err).toBe(0);
    const text = readFileSync(join(project, 'protect.cedar'), 'utf-8');
    expect(text).toContain('@id("starter.write-outside-project")');
    expect(text).toContain(`context.input.file_path like "${project}/*"`);
    expect(r.out).toContain('starter.delete-outside-project');
    const policy = join(project, 'protect.cedar');
    expect(runAll(['evaluate', '--policy', policy, '--tool', 'Write', '--input', JSON.stringify({ file_path: join(project, 'a.ts'), content: 'x' })]).code).toBe(0);
    // Outside the project and outside the temporary folders the rules also allow.
    const outside = runAll(['evaluate', '--policy', policy, '--tool', 'Write', '--input', JSON.stringify({ file_path: '/opt/elsewhere/a.ts', content: 'x' })]);
    expect(outside.code).toBe(2);
    expect(outside.err).toContain('starter.write-outside-project');
  });

  it('plain init is unchanged: it still writes the wrapper config and keys/gateway.json, not protect.cedar', () => {
    const project = mkdtempSync(join(tmpdir(), 'pmcp-init-plain-'));
    const r = runAll(['init', '--dir', project]);
    expect(r.code).toBe(0);
    expect(existsSync(join(project, 'protect-mcp.json'))).toBe(true);
    expect(existsSync(join(project, 'keys', 'gateway.json'))).toBe(true);
    expect(existsSync(join(project, 'protect.cedar'))).toBe(false);
  });
});
