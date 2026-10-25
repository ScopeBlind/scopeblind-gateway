import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { installHooks } from './hook-install.js';
import { generateHookSettings } from './hook-patterns.js';

const roots: string[] = [];
function fresh(): string {
  const root = fs.mkdtempSync(join(tmpdir(), 'protect-mcp-hooks-'));
  roots.push(root); return root;
}
function settings(root: string): any { return JSON.parse(fs.readFileSync(join(root, '.claude/settings.json'), 'utf8')); }
function writeSettings(root: string, contents: unknown): string {
  fs.mkdirSync(join(root, '.claude'), { recursive: true });
  const body = typeof contents === 'string' ? contents : JSON.stringify(contents, null, 2);
  fs.writeFileSync(join(root, '.claude/settings.json'), body);
  return body;
}
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

describe('reversible init-hooks installation', () => {
  it('previews a nonexistent --dir without creating directories or keys', () => {
    const parent = fresh();
    const dir = join(parent, 'new project');
    const plan = installHooks({ dir, dryRun: true });
    expect(plan.changed).toContain(join(dir, 'keys/gateway.json'));
    expect(plan.changed).toContain(join(dir, '.claude/settings.json'));
    expect(fs.readdirSync(parent)).toEqual([]);
  });

  it('appends to existing event arrays and preserves unrelated settings, with an exact backup', () => {
    const dir = fresh();
    const existing = { matcher: 'Bash', hooks: [{ type: 'command', command: 'my-audit-hook' }] };
    const before = writeSettings(dir, { permissions: { allow: ['Read'] }, env: { EXAMPLE: 'kept' },
      hooks: { PreToolUse: [existing], Notification: [{ hooks: [{ type: 'command', command: 'notify' }] }] } });
    const result = installHooks({ dir });
    expect(settings(dir).hooks.PreToolUse).toHaveLength(2);
    expect(settings(dir).hooks.PreToolUse[0]).toEqual(existing);
    expect(settings(dir).hooks.Notification).toEqual([{ hooks: [{ type: 'command', command: 'notify' }] }]);
    expect(settings(dir).permissions).toEqual({ allow: ['Read'] });
    expect(settings(dir).env).toEqual({ EXAMPLE: 'kept' });
    expect(fs.readFileSync(result.backup!, 'utf8')).toBe(before);
    if (process.platform !== 'win32') {
      expect(fs.statSync(result.backup!).mode & 0o777).toBe(0o600);
      expect(fs.statSync(join(dir, 'keys/gateway.json')).mode & 0o777).toBe(0o600);
      expect(fs.statSync(join(dir, 'keys')).mode & 0o777).toBe(0o700);
    }
  });

  it('is idempotent and preserves original bytes, key, and backup count on a repeated installation', () => {
    const dir = fresh();
    writeSettings(dir, { hooks: { PreToolUse: [] } });
    installHooks({ dir });
    const before = fs.readFileSync(join(dir, '.claude/settings.json'), 'utf8');
    const key = fs.readFileSync(join(dir, 'keys/gateway.json'), 'utf8');
    const names = fs.readdirSync(join(dir, '.claude'));
    const second = installHooks({ dir });
    expect(second.changed).toEqual([]);
    expect(fs.readFileSync(join(dir, '.claude/settings.json'), 'utf8')).toBe(before);
    expect(fs.readFileSync(join(dir, 'keys/gateway.json'), 'utf8')).toBe(key);
    expect(fs.readdirSync(join(dir, '.claude'))).toEqual(names);
  });

  it.each(['{ broken', '[]', 'null', '{"hooks":[]}', '{"hooks":{"PreToolUse":{}}}'])('fails unchanged for malformed settings: %s', contents => {
    const dir = fresh();
    writeSettings(dir, contents);
    expect(() => installHooks({ dir })).toThrow();
    expect(fs.readFileSync(join(dir, '.claude/settings.json'), 'utf8')).toBe(contents);
    expect(fs.readdirSync(dir)).toEqual(['.claude']);
    expect(fs.readdirSync(join(dir, '.claude'))).toEqual(['settings.json']);
  });

  it('preserves existing policies, keys, configuration and skill byte for byte', () => {
    const dir = fresh();
    const files = ['keys/gateway.json', 'keys/.gitignore', 'policies/agent.cedar', 'protect-mcp.json', '.claude/skills/verify-receipt/SKILL.md'];
    for (const file of files) {
      fs.mkdirSync(join(dir, file, '..'), { recursive: true });
      fs.writeFileSync(join(dir, file), `custom ${file}`);
    }
    const result = installHooks({ dir });
    for (const file of files) {
      expect(result.preserved).toContain(join(dir, file));
      expect(fs.readFileSync(join(dir, file), 'utf8')).toBe(`custom ${file}`);
    }
  });

  it('uninstalls only its entries, retaining post-install user changes and all support files', () => {
    const dir = fresh();
    const initialHook = { matcher: 'Read', hooks: [{ type: 'command', command: 'audit-before' }] };
    writeSettings(dir, { hooks: { PreToolUse: [initialHook], Stop: [] }, model: 'original' });
    installHooks({ dir });
    const next = settings(dir);
    const newHook = { matcher: '*', hooks: [{ type: 'command', command: 'audit-after' }] };
    next.hooks.PreToolUse.push(newHook);
    next.model = 'user-changed';
    writeSettings(dir, next);
    const current = fs.readFileSync(join(dir, '.claude/settings.json'), 'utf8');
    const plan = installHooks({ dir, uninstall: true, dryRun: true });
    expect(plan.changed).toContain(join(dir, '.claude/settings.json'));
    expect(fs.readFileSync(join(dir, '.claude/settings.json'), 'utf8')).toBe(current);
    const result = installHooks({ dir, uninstall: true });
    expect(settings(dir)).toEqual({ hooks: { PreToolUse: [initialHook, newHook], Stop: [] }, model: 'user-changed' });
    expect(fs.readFileSync(result.backup!, 'utf8')).toBe(current);
    expect(fs.existsSync(join(dir, '.claude/protect-mcp-hooks.json'))).toBe(false);
    for (const file of ['keys/gateway.json', 'policies/agent.cedar', 'protect-mcp.json', '.claude/skills/verify-receipt/SKILL.md']) {
      expect(fs.existsSync(join(dir, file))).toBe(true);
    }
  });

  it('does not adopt or remove an identical pre-existing legacy hook', () => {
    const dir = fresh();
    const existing = (generateHookSettings('http://127.0.0.1:9377/hook').hooks as any).PreToolUse;
    writeSettings(dir, { hooks: { PreToolUse: existing } });
    const result = installHooks({ dir });
    expect(result.warnings.some(message => message.includes('not claimed'))).toBe(true);
    expect(settings(dir).hooks.PreToolUse).toHaveLength(1);
    installHooks({ dir, uninstall: true });
    expect(settings(dir)).toEqual({ hooks: { PreToolUse: existing } });
  });

  it('retains an edited installed entry and its new sibling hook for manual review', () => {
    const dir = fresh();
    installHooks({ dir });
    const next = settings(dir);
    next.hooks.PreToolUse[0].hooks.push({ type: 'command', command: 'new-user-hook' });
    writeSettings(dir, next);
    expect(() => installHooks({ dir })).toThrow(/edited or removed/);
    const result = installHooks({ dir, uninstall: true });
    expect(settings(dir).hooks.PreToolUse[0].hooks).toHaveLength(2);
    expect(Object.keys(settings(dir).hooks)).toEqual(['PreToolUse']);
    expect(result.warnings.join(' ')).toContain('manual');
    const manifest = JSON.parse(fs.readFileSync(join(dir, '.claude/protect-mcp-hooks.json'), 'utf8'));
    expect(manifest.entries).toHaveLength(1);
  });

  it('leaves untracked hooks unchanged on uninstall', () => {
    const dir = fresh();
    const before = writeSettings(dir, generateHookSettings('http://127.0.0.1:9377/hook'));
    const result = installHooks({ dir, uninstall: true });
    expect(result.changed).toEqual([]);
    expect(result.warnings.join()).toContain('No ownership manifest');
    expect(fs.readFileSync(join(dir, '.claude/settings.json'), 'utf8')).toBe(before);
  });

  it('supports a custom port and requires removal before changing an owned hook URL', () => {
    const dir = fresh();
    installHooks({ dir, port: 12345 });
    expect(settings(dir).hooks.PreToolUse[0].hooks[0].url).toBe('http://127.0.0.1:12345/hook');
    expect(() => installHooks({ dir, port: 12346 })).toThrow(/before changing/);
    installHooks({ dir, uninstall: true });
    expect(settings(dir)).toEqual({});
    installHooks({ dir, port: 12346 });
    expect(settings(dir).hooks.PreToolUse[0].hooks[0].url).toBe('http://127.0.0.1:12346/hook');
  });

  it.each([0, -1, 65536, 9377.5, NaN])('rejects invalid port %s before creating files', port => {
    const dir = fresh();
    expect(() => installHooks({ dir, port })).toThrow(/--port/);
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')('refuses symlinked settings, keys and directories before writing anything', () => {
    for (const target of ['.claude/settings.json', 'keys/gateway.json', '.claude/skills']) {
      const dir = fresh();
      const elsewhere = fresh();
      const destination = target.endsWith('skills') ? elsewhere : join(elsewhere, 'file');
      if (!target.endsWith('skills')) fs.writeFileSync(destination, '{}');
      fs.mkdirSync(join(dir, target, '..'), { recursive: true });
      fs.symlinkSync(destination, join(dir, target));
      expect(() => installHooks({ dir })).toThrow(/symlink/);
      expect(fs.existsSync(join(dir, '.claude/protect-mcp-hooks.json'))).toBe(false);
      if (!target.endsWith('skills')) expect(fs.readFileSync(destination, 'utf8')).toBe('{}');
    }
  });

  it('rolls back new files on an activation write failure, retaining the original backup', () => {
    const dir = fresh();
    const before = writeSettings(dir, { hooks: { PreToolUse: [] }, env: { EXISTING: 'kept' } });
    let failed = false;
    const faultIO = { ...fs, renameSync: ((source: fs.PathLike, destination: fs.PathLike) => {
      if (String(destination) === join(dir, '.claude/settings.json') && !failed) {
        failed = true; throw new Error('simulated settings write failure');
      }
      fs.renameSync(source, destination);
    }) } as typeof fs;
    expect(() => installHooks({ dir }, faultIO)).toThrow(/Original files restored/);
    expect(fs.readFileSync(join(dir, '.claude/settings.json'), 'utf8')).toBe(before);
    expect(fs.existsSync(join(dir, 'keys/gateway.json'))).toBe(false);
    expect(fs.existsSync(join(dir, '.claude/protect-mcp-hooks.json'))).toBe(false);
    const names = fs.readdirSync(join(dir, '.claude'));
    const backup = names.find(name => name.includes('backup'))!;
    expect(fs.readFileSync(join(dir, '.claude', backup), 'utf8')).toBe(before);
    expect(names.some(name => name.endsWith('.tmp') || name.endsWith('.lock'))).toBe(false);
  });

  it('refuses a concurrent installer lock without replacing settings or support files', () => {
    const dir = fresh();
    const before = writeSettings(dir, {});
    fs.writeFileSync(join(dir, '.claude/.protect-mcp-hooks.lock'), 'another process');
    expect(() => installHooks({ dir })).toThrow(/Hook setup failed/);
    expect(fs.readFileSync(join(dir, '.claude/settings.json'), 'utf8')).toBe(before);
    expect(fs.readFileSync(join(dir, '.claude/.protect-mcp-hooks.lock'), 'utf8')).toBe('another process');
    expect(fs.existsSync(join(dir, 'keys/gateway.json'))).toBe(false);
  });
});
