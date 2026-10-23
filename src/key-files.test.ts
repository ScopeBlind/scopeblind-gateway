/**
 * Every command that writes a signing key writes it for its owner only (0600)
 * in an owner-only key directory (0700), whatever the umask, through the BUILT
 * CLI. A key other local users can read lets them sign receipts that verify as
 * this gate's. initSigning warns about an existing key that is open to them.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initSigning } from './signing.js';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const d = existsSync(CLI) && process.platform !== 'win32' ? describe : describe.skip;

const fresh = () => mkdtempSync(join(tmpdir(), 'pmcp-keyfiles-'));
const mode = (path: string) => (statSync(path).mode & 0o777).toString(8);

/** Run the built CLI under umask 022, the common default that left keys world-readable. */
function cli(cwd: string, args: string[], env: Record<string, string> = {}) {
  const r = spawnSync('/bin/sh', ['-c', 'umask 022 && exec "$0" "$@"', process.execPath, CLI, ...args], {
    cwd, encoding: 'utf-8', input: '', timeout: 60_000,
    env: { ...process.env, PROTECT_MCP_HTTP_PORT: '0', PROTECT_MCP_TELEMETRY: 'off', NO_COLOR: '1', ...env },
  });
  expect(r.error).toBeUndefined();
  return r;
}

d('signing keys are written for their owner only', () => {
  it('init, killer-demo, init-hooks, onboard and sample write 0600 keys in 0700 key folders', () => {
    const cases: Array<[string, (dir: string) => string[]]> = [
      ['init', (dir) => ['init', '--dir', dir]],
      ['killer-demo', (dir) => ['killer-demo', '--dir', dir]],
      ['init-hooks', (dir) => ['init-hooks', '--dir', dir]],
      ['onboard', (dir) => ['onboard', '--dir', dir, '--yes', '--pack', 'research-safe']],
      ['sample', (dir) => ['sample', '--dir', dir]],
    ];
    for (const [name, args] of cases) {
      const dir = fresh();
      const r = cli(dir, args(dir));
      expect(r.status, `${name}: ${r.stderr.slice(-400)}`).toBe(0);
      expect(mode(join(dir, 'keys', 'gateway.json')), name).toBe('600');
      expect(mode(join(dir, 'keys')), name).toBe('700');
    }
  }, 120_000);

  it('quickstart writes its key 0600 in a 0700 key folder', () => {
    const scratch = fresh();
    const r = cli(scratch, ['quickstart'], { TMPDIR: scratch });
    expect(r.status, r.stderr.slice(-400)).toBe(0);
    const workDir = readdirSync(scratch).find((n) => n.startsWith('protect-mcp-quickstart-'));
    expect(workDir).toBeDefined();
    expect(mode(join(scratch, workDir!, 'keys', 'gateway.json'))).toBe('600');
    expect(mode(join(scratch, workDir!, 'keys'))).toBe('700');
  }, 60_000);

  it('init narrows an existing world-readable key it replaces, and leaves an existing key folder as it was', () => {
    const dir = fresh();
    mkdirSync(join(dir, 'keys'));
    chmodSync(join(dir, 'keys'), 0o755);
    writeFileSync(join(dir, 'keys', 'gateway.json'), '{"old":true}\n');
    chmodSync(join(dir, 'keys', 'gateway.json'), 0o644);
    const r = cli(dir, ['init', '--dir', dir]);
    expect(r.status, r.stderr.slice(-400)).toBe(0);
    expect(mode(join(dir, 'keys', 'gateway.json'))).toBe('600');
    expect(JSON.parse(readFileSync(join(dir, 'keys', 'gateway.json'), 'utf-8')).old).toBeUndefined();
    expect(mode(join(dir, 'keys'))).toBe('755');
  }, 30_000);

  it('a new project folder made for the keys keeps the default mode; only the key folder is narrowed', () => {
    const parent = fresh();
    const dir = join(parent, 'new-project');
    const r = cli(parent, ['sample', '--dir', dir]);
    expect(r.status, r.stderr.slice(-400)).toBe(0);
    expect(mode(dir)).toBe('755');
    expect(mode(join(dir, 'keys'))).toBe('700');
  }, 30_000);
});

describe('initSigning warns about a key file other users can open', () => {
  afterEach(async () => { await initSigning(undefined); });

  const keyFile = (fileMode: number) => {
    const dir = fresh();
    const path = join(dir, 'gateway.json');
    writeFileSync(path, JSON.stringify({ privateKey: '11'.repeat(32), publicKey: '22'.repeat(32), kid: 'test' }));
    chmodSync(path, fileMode);
    return path;
  };

  it.skipIf(process.platform === 'win32')('warns for 0644 and names the fix, without disabling signing', async () => {
    const path = keyFile(0o644);
    const warnings = await initSigning({ enabled: true, key_path: path });
    expect(warnings.some((w) => w.includes(path) && w.includes('chmod 600'))).toBe(true);
    const { isSigningEnabled } = await import('./signing.js');
    expect(isSigningEnabled()).toBe(true);
  });

  it('is quiet for 0600', async () => {
    expect(await initSigning({ enabled: true, key_path: keyFile(0o600) })).toEqual([]);
  });
});
