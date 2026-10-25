import { afterEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI = join(__dirname, '..', 'dist/cli.js');
const version = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')).version;
const roots: string[] = [];
const fresh = () => { const dir = mkdtempSync(join(tmpdir(), 'pmcp-first-cli-')); roots.push(dir); return dir; };
function cli(cwd: string, args: string[]) {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', input: '', timeout: 60_000,
    env: { ...process.env, PROTECT_MCP_TELEMETRY: 'off', NO_COLOR: '1', PROTECT_MCP_VERSION: '9.9.9' } });
  expect(result.error).toBeUndefined();
  return result;
}
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe.skipIf(!existsSync(CLI))('first-use commands through the built CLI', () => {
  it('previews, installs, repeats and removes hooks in --dir, preserving an existing hook', () => {
    const cwd = fresh();
    const project = join(fresh(), 'project with spaces');
    mkdirSync(join(project, '.claude'), { recursive: true });
    const initial = { hooks: { PreToolUse: [{ matcher: 'Read', hooks: [{ type: 'command', command: 'other-hook' }] }] }, model: 'custom' };
    const path = join(project, '.claude/settings.json');
    writeFileSync(path, JSON.stringify(initial));
    let result = cli(cwd, ['init-hooks', '--dir', project, '--dry-run']);
    expect(result.status, result.stderr).toBe(0);
    expect(readdirSync(project)).toEqual(['.claude']);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual(initial);
    result = cli(cwd, ['init-hooks', '--dir', project]);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`protect-mcp@${version} serve --enforce`);
    expect(JSON.parse(readFileSync(path, 'utf8')).hooks.PreToolUse).toHaveLength(2);
    const installed = readFileSync(path, 'utf8');
    result = cli(cwd, ['init-hooks', '--dir', project]);
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(path, 'utf8')).toBe(installed);
    result = cli(cwd, ['init-hooks', '--dir', project, '--uninstall']);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual(initial);
    expect(existsSync(join(project, 'keys/gateway.json'))).toBe(true);
    expect(readdirSync(cwd)).toEqual([]);
  }, 60_000);

  it('refuses a malformed settings file and unknown or invalid options without mutation', () => {
    const dir = fresh();
    mkdirSync(join(dir, '.claude'));
    writeFileSync(join(dir, '.claude/settings.json'), '{"secret":"must-not-appear", bad');
    for (const args of [[], ['--port', '9377oops'], ['--port', '0'], ['--dir'], ['--typo']]) {
      const result = cli(dir, ['init-hooks', ...args]);
      expect(result.status).toBe(1);
      expect(result.stdout + result.stderr).not.toContain('must-not-appear');
      expect(readdirSync(dir)).toEqual(['.claude']);
      expect(readdirSync(join(dir, '.claude'))).toEqual(['settings.json']);
    }
  }, 60_000);

  it('pins printed and written wrapper configs to the installed package, not an environment override', () => {
    const dir = fresh();
    const policy = join(dir, 'protect-mcp.json');
    writeFileSync(policy, '{"tools":{}}');
    const printed = cli(dir, ['wrap', '--config', policy, '--', 'node', 'server.js']);
    expect(printed.status, printed.stderr).toBe(0);
    expect(printed.stdout).toContain(`protect-mcp@${version}`);
    expect(printed.stdout).not.toContain('protect-mcp@latest');
    expect(printed.stdout).not.toContain('protect-mcp@9.9.9');
    const host = join(dir, 'desktop.json');
    writeFileSync(host, JSON.stringify({ mcpServers: { sample: { command: 'node', args: ['server.js'] } } }));
    const written = cli(dir, ['wrap', '--config', policy, '--claude-desktop', '--path', host, '--write']);
    expect(written.status, written.stderr).toBe(0);
    expect(JSON.parse(readFileSync(host, 'utf8')).mcpServers.sample.args).toContain(`protect-mcp@${version}`);
  }, 60_000);

  it('passes doctor flags through and returns an actionable failing exit code without creating files', () => {
    const cwd = fresh();
    const project = fresh();
    const result = cli(cwd, ['doctor', '--dir', project, '--json']);
    expect(result.status, result.stderr).toBe(1);
    const report = JSON.parse(result.stdout);
    expect(report.directory).toBe(project);
    expect(report.network).toBe('not_requested');
    expect(report.ok).toBe(false);
    expect(readdirSync(project)).toEqual([]);
    expect(readdirSync(cwd)).toEqual([]);
  }, 60_000);

  it('keeps doctor and hook preview offline even when install telemetry was previously opted in', () => {
    const dir = fresh();
    const project = fresh();
    const attempted = join(dir, 'network-attempt');
    const preload = join(dir, 'deny-network.cjs');
    writeFileSync(preload, `globalThis.fetch = async () => { require('node:fs').writeFileSync(${JSON.stringify(attempted)}, 'attempted'); throw new Error('test network disabled'); };`);
    for (const args of [['doctor', '--dir', project, '--json'], ['init-hooks', '--dir', project, '--dry-run']]) {
      const result = spawnSync(process.execPath, ['--require', preload, CLI, ...args], {
        cwd: dir, encoding: 'utf8', input: '', timeout: 30_000,
        env: { ...process.env, HOME: dir, PROTECT_MCP_TELEMETRY: 'on', NO_COLOR: '1' },
      });
      expect(result.error).toBeUndefined();
      expect(result.status, result.stderr).toBe(args[0] === 'doctor' ? 1 : 0);
      expect(existsSync(attempted)).toBe(false);
      expect(existsSync(join(dir, '.protect-mcp/.telemetry-sent'))).toBe(false);
      expect(readdirSync(project)).toEqual([]);
    }
  }, 60_000);
});
