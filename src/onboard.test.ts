/**
 * Sprint 2 acceptance: a first run produces a governed demo and a verifiable
 * receipt locally, with no account and no real credentials; and offboard removes
 * everything cleanly.
 */
import { describe, it, expect, beforeEach, afterEach, vi, type MockInstance } from 'vitest';
import { mkdtempSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { handleOnboard, handleOffboard } from './onboard.js';
import { verifyReceipt } from './acta-envelope.js';

let silence: MockInstance;
beforeEach(() => { silence = vi.spyOn(process.stdout, 'write').mockImplementation(() => true); });
afterEach(() => { silence.mockRestore(); });

function receipts(dir: string): Array<{ payload?: { tool_name?: string; decision?: string; reason?: string; policy_engine?: string } }> {
  return readFileSync(join(dir, '.protect-mcp-receipts.jsonl'), 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

describe('onboard (guided first run)', () => {
  it('runs a governed finance demo and produces an offline-verifiable receipt, no account or credentials', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'onb-'));
    await handleOnboard(['--dir', dir, '--pack', 'finance-mandate-safe', '--yes']);

    // Nothing that looks like a cloud account or credential was created.
    expect(existsSync(join(dir, 'protect-mcp.json'))).toBe(true);
    expect(existsSync(join(dir, 'keys', 'gateway.json'))).toBe(true);
    expect(existsSync(join(dir, 'audit-bundle.json'))).toBe(true);

    const rs = receipts(dir);
    expect(rs.length).toBe(3);
    // Real Cedar decisions: the restricted-list booking and the concentration
    // breach are denied; the in-mandate booking is allowed.
    expect(rs.filter((r) => r.payload?.decision === 'deny').length).toBe(2);
    expect(rs.filter((r) => r.payload?.decision === 'allow').length).toBe(1);

    // A receipt verifies with the workspace key, offline, no ScopeBlind service.
    const key = JSON.parse(readFileSync(join(dir, 'keys', 'gateway.json'), 'utf-8'));
    expect(verifyReceipt(rs[0], key.publicKey).valid).toBe(true);

    // Proof it was REAL Cedar (not the simulated fallback): real decisions carry
    // policy_engine:'cedar' and a cedar_deny reason, not a policy_simulated_* one.
    expect(rs.every((r) => r.payload?.policy_engine === 'cedar')).toBe(true);
    expect(rs.some((r) => r.payload?.reason === 'cedar_deny')).toBe(true);
    expect(rs.some((r) => r.payload?.reason?.startsWith('policy_simulated'))).toBe(false);
  });

  it('research-safe blocks reading a secret file and sending externally', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'onb-'));
    await handleOnboard(['--dir', dir, '--pack', 'research-safe', '--yes']);
    const rs = receipts(dir);
    const send = rs.find((r) => r.payload?.tool_name === 'send_email');
    const secretRead = rs.find((r) => r.payload?.tool_name === 'read_file' && r.payload?.decision === 'deny');
    expect(send?.payload?.decision).toBe('deny');
    expect(secretRead).toBeTruthy(); // the /.env read was blocked
    // and a legitimate research read was allowed
    expect(rs.some((r) => r.payload?.tool_name === 'web_search' && r.payload?.decision === 'allow')).toBe(true);
  });

  it('defaults to research-safe and shadow mode when run non-interactively with no flags', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'onb-'));
    await handleOnboard(['--dir', dir, '--yes']);
    const cfg = JSON.parse(readFileSync(join(dir, 'protect-mcp.json'), 'utf-8'));
    expect(existsSync(join(dir, 'cedar', 'research-safe.cedar'))).toBe(true);
    expect(String(cfg._mode)).toMatch(/shadow/);
  });
});

describe('offboard (clean removal)', () => {
  it('--uninstall removes local data, keys, config, and policies', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'onb-'));
    await handleOnboard(['--dir', dir, '--pack', 'email-safe', '--yes']);
    expect(existsSync(join(dir, 'protect-mcp.json'))).toBe(true);

    await handleOffboard(['--dir', dir, '--uninstall', '--yes']);
    expect(existsSync(join(dir, 'protect-mcp.json'))).toBe(false);
    expect(existsSync(join(dir, '.protect-mcp-receipts.jsonl'))).toBe(false);
    expect(existsSync(join(dir, 'keys'))).toBe(false);
    expect(existsSync(join(dir, 'cedar'))).toBe(false);
  });

  it('--uninstall deletes NOTHING destructive on a non-onboarding folder (no marker)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'real-'));
    // A real project: a protect-mcp.json WITHOUT the onboarding marker, plus policies, keys, receipts.
    mkdirSync(join(dir, 'cedar'), { recursive: true });
    mkdirSync(join(dir, 'keys'), { recursive: true });
    writeFileSync(join(dir, 'protect-mcp.json'), JSON.stringify({ cedar_dir: './cedar' }));
    writeFileSync(join(dir, 'cedar', 'my-real-policy.cedar'), 'permit(principal, action, resource);\n');
    writeFileSync(join(dir, 'keys', 'gateway.json'), '{"privateKey":"x"}');
    writeFileSync(join(dir, '.protect-mcp-receipts.jsonl'), '{"payload":{}}\n');

    await handleOffboard(['--dir', dir, '--uninstall', '--yes']);
    // A bare --uninstall on a folder onboard did not create must not delete the
    // user's real keys, receipts, config, or policies.
    expect(existsSync(join(dir, '.protect-mcp-receipts.jsonl'))).toBe(true);
    expect(existsSync(join(dir, 'keys', 'gateway.json'))).toBe(true);
    expect(existsSync(join(dir, 'protect-mcp.json'))).toBe(true);
    expect(existsSync(join(dir, 'cedar', 'my-real-policy.cedar'))).toBe(true);
  });

  it('re-running onboard into the same dir keeps the verify step working (no mixed-key receipts)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'onb-'));
    await handleOnboard(['--dir', dir, '--pack', 'git-safe', '--yes']);
    await handleOnboard(['--dir', dir, '--pack', 'git-safe', '--yes']); // second run mints a fresh key
    const rs = receipts(dir);
    const key = JSON.parse(readFileSync(join(dir, 'keys', 'gateway.json'), 'utf-8'));
    // Every receipt on disk verifies with the CURRENT key (none left over from the old key).
    expect(rs.length).toBeGreaterThan(0);
    expect(rs.every((r) => verifyReceipt(r, key.publicKey).valid)).toBe(true);
  });

  it('--delete-data removes evidence but keeps keys and config', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'onb-'));
    await handleOnboard(['--dir', dir, '--pack', 'git-safe', '--yes']);
    await handleOffboard(['--dir', dir, '--delete-data', '--yes']);
    expect(existsSync(join(dir, '.protect-mcp-receipts.jsonl'))).toBe(false);
    expect(existsSync(join(dir, 'audit-bundle.json'))).toBe(false);
    expect(existsSync(join(dir, 'keys', 'gateway.json'))).toBe(true); // keys kept
    expect(existsSync(join(dir, 'protect-mcp.json'))).toBe(true);      // config kept
  });

  it('--disable-enforcement removes only protect-mcp hooks from .claude/settings.json', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'onb-'));
    mkdirSync(join(dir, '.claude'), { recursive: true });
    writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({
      hooks: { PreToolUse: [{ matcher: '*', hooks: [
        { type: 'command', command: 'npx protect-mcp evaluate' },      // ours -> removed
        { type: 'command', command: 'some-other-tool' },               // unrelated -> kept
        { type: 'command', command: 'my-protect-mcp-audit --log x' },  // false-positive bait -> kept
      ] }] },
    }));
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      await handleOffboard(['--dir', dir, '--disable-enforcement', '--yes']);
    } finally { process.chdir(cwd); }
    const settings = JSON.parse(readFileSync(join(dir, '.claude', 'settings.json'), 'utf-8'));
    const cmds = settings.hooks.PreToolUse[0].hooks.map((h: { command: string }) => h.command);
    expect(cmds).toEqual(['some-other-tool', 'my-protect-mcp-audit --log x']);
  });
});

describe('research-safe pack (new) enforces via real Cedar', () => {
  it('blocks secret reads and external sends, permits normal reads/search', async () => {
    const { policySetFromSource, evaluateCedar } = await import('./cedar-evaluator.js');
    const { getPolicyPack } = await import('./policy-packs.js');
    const pack = getPolicyPack('research-safe')!;
    const ps = policySetFromSource(pack.files[0].contents, 'research-safe.cedar');
    const read = await evaluateCedar(ps, { tool: 'read_file', tier: 'unknown', toolInput: { path: '/research/notes.md' } });
    const secret = await evaluateCedar(ps, { tool: 'read_file', tier: 'unknown', toolInput: { path: '/home/a/.env' } });
    const send = await evaluateCedar(ps, { tool: 'send_email', tier: 'unknown', toolInput: { to: 'x@y.com' } });
    expect(read.allowed).toBe(true);
    expect(secret.allowed).toBe(false);
    expect(send.allowed).toBe(false);
  });
});
