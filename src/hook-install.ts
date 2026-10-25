/** Reversible local hook setup. Settings become active only after support files exist. */
import * as fs from 'node:fs';
import { dirname, join, parse, relative, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { generateHookSettings, generateSampleCedarPolicy, generateVerifyReceiptSkill } from './hook-patterns.js';

export interface HookInstallOptions {
  dir: string;
  port?: number;
  dryRun?: boolean;
  uninstall?: boolean;
}
export interface HookInstallResult {
  directory: string;
  hookUrl: string;
  mode: 'install' | 'uninstall';
  dryRun: boolean;
  changed: string[];
  preserved: string[];
  warnings: string[];
  backup?: string;
}
type RecordValue = Record<string, unknown>;
type OwnedEntry = { event: string; entry: unknown };
type Manifest = {
  version: 1;
  hookUrl: string;
  originalHooksPresent: boolean;
  originalEvents: string[];
  entries: OwnedEntry[];
  backup?: string;
};
type Mutation = { path: string; after: string | null; mode: number; backup?: boolean };
type Snapshot = { text: string | null; mode: number };
type InstallIO = typeof fs;

function object(value: unknown, label: string): RecordValue {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be a JSON object; no files changed.`);
  return value as RecordValue;
}
function parseObject(text: string, label: string): RecordValue {
  let value: unknown;
  try { value = JSON.parse(text); }
  // JSON parser messages can include snippets of settings containing secrets.
  catch { throw new Error(`Cannot parse JSON in ${label}; no files changed.`); }
  return object(value, label);
}
function json(value: unknown): string { return `${JSON.stringify(value, null, 2)}\n`; }

/** Reject symlink targets and descendants, without rejecting OS aliases above the chosen directory. */
function safePath(io: InstallIO, root: string, path: string, finalKind: 'file' | 'dir'): void {
  const rel = relative(root, path);
  if (rel.startsWith('..') || resolve(root, rel) !== path) throw new Error(`Path is outside selected directory: ${path}`);
  const chain: string[] = [];
  for (let cursor = path; ; cursor = dirname(cursor)) {
    chain.unshift(cursor);
    if (cursor === root) break;
  }
  for (const candidate of chain) {
    let stat;
    try { stat = io.lstatSync(candidate); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
    if (stat.isSymbolicLink()) throw new Error(`Refusing symlink: ${candidate}`);
    const kind = candidate === path ? finalKind : 'dir';
    if (kind === 'dir' ? !stat.isDirectory() : !stat.isFile()) throw new Error(`Expected ${kind}: ${candidate}`);
  }
}
function snapshot(io: InstallIO, root: string, path: string): Snapshot {
  safePath(io, root, path, 'file');
  try { return { text: io.readFileSync(path, 'utf8'), mode: io.statSync(path).mode & 0o777 }; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { text: null, mode: 0o600 }; throw error; }
}
function readManifest(text: string, expected: Record<string, unknown[]>): Manifest {
  const value = parseObject(text, 'hook ownership manifest');
  if (value.version !== 1 || typeof value.hookUrl !== 'string' || !/^http:\/\/127\.0\.0\.1:\d+\/hook$/.test(value.hookUrl)
      || typeof value.originalHooksPresent !== 'boolean' || !Array.isArray(value.originalEvents)
      || !value.originalEvents.every(event => typeof event === 'string') || !Array.isArray(value.entries)) {
    throw new Error('Invalid hook ownership manifest; no files changed.');
  }
  const seen = new Set<string>();
  for (const raw of value.entries) {
    const entry = object(raw, 'owned hook entry');
    if (typeof entry.event !== 'string' || seen.has(entry.event)
        || !expected[entry.event]?.some(candidate => isDeepStrictEqual(candidate, entry.entry))) {
      throw new Error('Invalid owned hook entry; no files changed.');
    }
    seen.add(entry.event);
  }
  return value as unknown as Manifest;
}

/** The IO argument permits deterministic write-failure testing, without changing normal CLI behavior. */
export function installHooks(options: HookInstallOptions, io: InstallIO = fs): HookInstallResult {
  const root = resolve(options.dir);
  if (root === parse(root).root) throw new Error('Choose a project directory, not the filesystem root.');
  safePath(io, root, root, 'dir');
  const port = options.port ?? 9377;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('--port must be an integer from 1 to 65535.');
  const hookUrl = `http://127.0.0.1:${port}/hook`;
  const settingsPath = join(root, '.claude/settings.json');
  const manifestPath = join(root, '.claude/protect-mcp-hooks.json');
  const settingsBefore = snapshot(io, root, settingsPath);
  const manifestBefore = snapshot(io, root, manifestPath);
  const settings = settingsBefore.text === null ? {} : parseObject(settingsBefore.text, settingsPath);
  const hooks = settings.hooks === undefined ? {} : object(settings.hooks, `${settingsPath} hooks`);
  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) throw new Error(`Hook event ${event} must be an array; no files changed.`);
  }
  const originalHooksPresent = Object.hasOwn(settings, 'hooks');
  const originalEvents = Object.keys(hooks);
  const generated = generateHookSettings(hookUrl).hooks as Record<string, unknown[]>;
  let manifest: Manifest | undefined;
  if (manifestBefore.text !== null) {
    const rawManifest = parseObject(manifestBefore.text, manifestPath);
    const sourceUrl = typeof rawManifest.hookUrl === 'string' ? rawManifest.hookUrl : '';
    manifest = readManifest(manifestBefore.text, generateHookSettings(sourceUrl).hooks as Record<string, unknown[]>);
  }
  const result: HookInstallResult = {
    directory: root, hookUrl: manifest?.hookUrl ?? hookUrl,
    mode: options.uninstall ? 'uninstall' : 'install', dryRun: !!options.dryRun,
    changed: [], preserved: [], warnings: [],
  };
  const mutations: Mutation[] = [];
  const snapshots = new Map<string, Snapshot>([[settingsPath, settingsBefore], [manifestPath, manifestBefore]]);
  const create = (path: string, content: () => string, mode = 0o600): void => {
    const before = snapshot(io, root, path);
    snapshots.set(path, before);
    if (before.text !== null) { result.preserved.push(path); return; }
    // Preview validates all paths but never generates private key material.
    mutations.push({ path, after: options.dryRun ? '' : content(), mode });
  };

  if (options.uninstall) {
    if (!manifest) {
      result.warnings.push('No ownership manifest found. Existing hooks were left untouched; remove older or manually installed hooks yourself.');
      return result;
    }
    const unmatched: OwnedEntry[] = [];
    for (const owned of manifest.entries) {
      const entries = (hooks[owned.event] ?? []) as unknown[];
      const index = entries.findIndex(entry => isDeepStrictEqual(entry, owned.entry));
      if (index < 0) { unmatched.push(owned); continue; }
      entries.splice(index, 1);
      if (entries.length === 0 && !manifest.originalEvents.includes(owned.event)) delete hooks[owned.event];
    }
    if (!manifest.originalHooksPresent && Object.keys(hooks).length === 0) delete settings.hooks;
    else settings.hooks = hooks;
    if (unmatched.length) {
      result.warnings.push(`${unmatched.length} previously installed hook entries were changed or removed. Unmatched entries were left untouched; review settings manually. The manifest is retained for review.`);
      const next = json({ ...manifest, entries: unmatched });
      if (next !== manifestBefore.text) mutations.push({ path: manifestPath, after: next, mode: 0o600 });
    } else mutations.push({ path: manifestPath, after: null, mode: 0o600 });
    // No policy, config, key, receipt, or skill is deleted during hook removal.
  } else {
    if (manifest && manifest.hookUrl !== hookUrl) throw new Error(`Hooks were installed for ${manifest.hookUrl}. Uninstall them before changing --port; no files changed.`);
    const owned = manifest?.entries ?? [];
    for (const entry of owned) {
      if (!(hooks[entry.event] as unknown[] | undefined)?.some(candidate => isDeepStrictEqual(candidate, entry.entry))) {
        throw new Error('Managed hooks were edited or removed. Review settings and run init-hooks --uninstall before reinstalling; no files changed.');
      }
    }
    for (const [event, additions] of Object.entries(generated)) {
      const entries = (hooks[event] ?? []) as unknown[];
      for (const entry of additions) {
        if (entries.some(candidate => isDeepStrictEqual(candidate, entry))) {
          if (!owned.some(item => item.event === event)) result.warnings.push(`${event}: identical existing hook preserved, not claimed as installer-owned.`);
        } else {
          entries.push(entry);
          owned.push({ event, entry });
        }
      }
      hooks[event] = entries;
    }
    settings.hooks = hooks;
    create(join(root, 'keys/gateway.json'), () => {
      const privateKey = randomBytes(32);
      return json({ privateKey: bytesToHex(privateKey), publicKey: bytesToHex(ed25519.getPublicKey(privateKey)),
        kid: `hook-${Date.now()}`, generated_at: new Date().toISOString(), warning: 'KEEP THIS FILE SECRET. Never commit to version control.' });
    });
    create(join(root, 'keys/.gitignore'), () => '# Never commit signing keys\n*.json\n');
    create(join(root, 'policies/agent.cedar'), generateSampleCedarPolicy, 0o644);
    create(join(root, 'protect-mcp.json'), () => json({ tools: { '*': { rate_limit: '100/hour' } }, default_tier: 'unknown',
      signing: { key_path: './keys/gateway.json', issuer: 'protect-mcp', enabled: true } }));
    create(join(root, '.claude/skills/verify-receipt/SKILL.md'), generateVerifyReceiptSkill, 0o644);
    const nextManifest: Manifest = manifest ?? { version: 1, hookUrl, originalHooksPresent, originalEvents, entries: owned };
    if (json(nextManifest) !== manifestBefore.text) mutations.push({ path: manifestPath, after: json(nextManifest), mode: 0o600 });
  }
  const nextSettings = json(settings);
  // Compare objects so repeated installs preserve formatting/bytes and need no backup.
  const settingsChanged = !isDeepStrictEqual(settings, settingsBefore.text === null ? {} : JSON.parse(settingsBefore.text));
  if (settingsChanged) {
    if (settingsBefore.text !== null) {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backup = join(root, `.claude/settings.json.protect-mcp-backup-${stamp}-${randomBytes(4).toString('hex')}`);
      snapshots.set(backup, snapshot(io, root, backup));
      result.backup = backup;
      mutations.unshift({ path: backup, after: settingsBefore.text, mode: 0o600, backup: true });
      const manifestWrite = mutations.find(m => m.path === manifestPath && m.after !== null);
      if (manifestWrite && !options.uninstall) {
        const data = JSON.parse(manifestWrite.after!);
        data.backup = relative(root, backup);
        manifestWrite.after = json(data);
      }
    }
    // Activation last: the key, policy, config, skill and ownership manifest are ready first.
    mutations.push({ path: settingsPath, after: nextSettings, mode: settingsBefore.mode });
  }
  result.changed = mutations.map(mutation => mutation.path);
  if (options.dryRun || !mutations.length) return result;

  const createdDirectories: string[] = [];
  function ensureDirectory(path: string): void {
    if (io.existsSync(path)) return;
    ensureDirectory(dirname(path));
    io.mkdirSync(path, { mode: 0o700 });
    createdDirectories.push(path);
  }
  function atomicWrite(path: string, contents: string, mode: number): void {
    const temporary = `${path}.protect-mcp-${randomBytes(8).toString('hex')}.tmp`;
    try {
      io.writeFileSync(temporary, contents, { flag: 'wx', mode });
      io.renameSync(temporary, path);
    } finally { if (io.existsSync(temporary)) io.unlinkSync(temporary); }
  }
  const applied: Mutation[] = [];
  let lockPath: string | undefined;
  try {
    ensureDirectory(join(root, '.claude'));
    const candidateLock = join(root, '.claude/.protect-mcp-hooks.lock');
    safePath(io, root, candidateLock, 'file');
    io.writeFileSync(candidateLock, `${process.pid}\n`, { flag: 'wx', mode: 0o600 });
    lockPath = candidateLock;
    for (const mutation of mutations) {
      const expected = snapshots.get(mutation.path) ?? snapshot(io, root, mutation.path);
      snapshots.set(mutation.path, expected);
      if (snapshot(io, root, mutation.path).text !== expected.text) throw new Error(`File changed during setup: ${mutation.path}`);
      ensureDirectory(dirname(mutation.path));
      safePath(io, root, mutation.path, 'file');
      if (mutation.after === null) io.unlinkSync(mutation.path);
      else atomicWrite(mutation.path, mutation.after, mutation.mode);
      applied.push(mutation);
    }
  } catch (error) {
    const rollbackErrors: string[] = [];
    for (const mutation of applied.reverse()) {
      if (mutation.backup) continue; // A usable recovery copy survives a failed setup.
      try {
        if (snapshot(io, root, mutation.path).text !== mutation.after) {
          rollbackErrors.push(`Preserved concurrent edit: ${mutation.path}`); continue;
        }
        const before = snapshots.get(mutation.path)!;
        if (before.text === null) io.unlinkSync(mutation.path);
        else atomicWrite(mutation.path, before.text, before.mode);
      } catch (failure) { rollbackErrors.push(`${mutation.path}: ${(failure as Error).message}`); }
    }
    throw new Error(`Hook setup failed: ${(error as Error).message}. ${rollbackErrors.length ? `Recovery needs review: ${rollbackErrors.join('; ')}` : 'Original files restored.'}${result.backup ? ` Backup: ${result.backup}` : ''}`);
  } finally {
    if (lockPath) io.unlinkSync(lockPath);
    for (const path of createdDirectories.reverse()) {
      try { io.rmdirSync(path); } catch { /* Keep nonempty directories, including successful installation files. */ }
    }
  }
  return result;
}
