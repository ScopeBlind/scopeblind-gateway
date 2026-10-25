#!/usr/bin/env node
/** Explicit, project-only installation for local preview. No user config. */
import { chmod, lstat, mkdir, readFile, writeFile, rename, stat, unlink, rmdir, realpath } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { validateConfig } from './lib/cursor-relay.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const FILES = ['hooks/relay.mjs', 'lib/cursor-relay.mjs', 'lib/gate-client.mjs'];
const ENTRIES = {
  preToolUse: { command: 'node .cursor/protect-mcp/hooks/relay.mjs preToolUse', timeout: 15, failClosed: true },
  postToolUse: { command: 'node .cursor/protect-mcp/hooks/relay.mjs postToolUse', timeout: 15 },
};
const same = isDeepStrictEqual;
async function nonlink(path) {
  try { if ((await lstat(path)).isSymbolicLink()) throw new Error(`Refusing symbolic link: ${path}`); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
async function optional(path) { try { return await readFile(path, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } }
async function atomic(path, content, mode = 0o600) {
  const temp = `${path}.protect-mcp-${randomUUID()}.tmp`;
  try { await writeFile(temp, content, { flag: 'wx', mode }); await chmod(temp, mode); await rename(temp, path); }
  finally { await unlink(temp).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
}
// An existing hooks.json is the user's file: keep a copy of its bytes beside it
// before the first rewrite, and keep its permissions on the rewritten file.
async function rewriteHooks(hookPath, original, content) {
  if (original === null) { await atomic(hookPath, content); return null; }
  const mode = (await stat(hookPath)).mode & 0o777;
  const backup = `${hookPath}.protect-mcp-backup-${new Date().toISOString().replace(/[-:.]/g, '')}-${randomUUID().slice(0, 8)}`;
  await writeFile(backup, original, { flag: 'wx', mode });
  await chmod(backup, mode);
  await atomic(hookPath, content, mode);
  return backup;
}

export async function configure({ project, mode = 'plan', port }) {
  if (!['plan', 'install', 'uninstall'].includes(mode)) throw new Error('Use plan, install or uninstall');
  const root = await realpath(resolve(project));
  const cursor = join(root, '.cursor');
  const managed = join(cursor, 'protect-mcp');
  const hookPath = join(cursor, 'hooks.json');
  const configPath = join(cursor, 'protect-mcp.json');
  for (const path of [cursor, managed, hookPath, ...(mode === 'uninstall' ? [] : [configPath]), join(managed, 'hooks'), join(managed, 'lib'), ...FILES.map(file => join(managed, file))]) await nonlink(path);
  const original = await optional(hookPath);
  const hooks = original === null ? { version: 1, hooks: {} } : JSON.parse(original);
  if (!hooks || hooks.version !== 1 || typeof hooks.hooks !== 'object' || hooks.hooks === null || Array.isArray(hooks.hooks)) throw new Error('Existing hooks.json must use version 1 and a hooks object');
  for (const event of Object.keys(ENTRIES)) if (hooks.hooks[event] !== undefined && !Array.isArray(hooks.hooks[event])) throw new Error(`Invalid existing ${event} hooks`);
  // Recovery must not depend on the configuration that is causing calls to
  // block. Uninstall never reads or rewrites project configuration bytes.
  const configRaw = mode === 'uninstall' ? null : await optional(configPath);
  const config = mode === 'uninstall' ? null : configRaw === null ? validateConfig({ version: 1, port: port ?? 9377 }) : validateConfig(JSON.parse(configRaw));
  if (mode !== 'uninstall' && port !== undefined && port !== config.port) throw new Error('Existing project port differs; review protect-mcp.json explicitly');
  if (mode === 'plan') return { project: root, config: configPath, hooks: ENTRIES, port: config.port, note: 'No files changed. Start and review the gate, then repeat with --install.' };

  if (mode === 'install') {
    // Check all collisions before writing anything. An existing unrelated
    // script must never be overwritten or silently repointed by setup.
    const contents = await Promise.all(FILES.map(file => readFile(join(ROOT, file), 'utf8')));
    for (let i = 0; i < FILES.length; i++) {
      const existing = await optional(join(managed, FILES[i]));
      if (existing !== null && existing !== contents[i]) throw new Error(`Existing managed file differs: ${FILES[i]}. Uninstall the old copy before upgrading.`);
    }
    for (const [event, entry] of Object.entries(ENTRIES)) {
      const entries = hooks.hooks[event] ?? [];
      if (entries.some(value => value?.command === entry.command && !same(value, entry))) throw new Error(`Existing ${event} entry differs; review it before setup`);
      if (!entries.some(value => same(value, entry))) hooks.hooks[event] = [...entries, entry];
    }
    await mkdir(join(managed, 'hooks'), { recursive: true });
    await mkdir(join(managed, 'lib'), { recursive: true });
    for (let i = 0; i < FILES.length; i++) await atomic(join(managed, FILES[i]), contents[i]);
    if (configRaw === null) await atomic(configPath, JSON.stringify(config, null, 2) + '\n');
    const content = JSON.stringify(hooks, null, 2) + '\n';
    const backup = content === original ? null : await rewriteHooks(hookPath, original, content);
    return { project: root, installed: true, port: config.port, ...(backup ? { backup } : {}), note: 'Project hooks enabled. Restart Cursor and complete the real-host checks. User and team settings were not changed.' };
  }

  let changed = false;
  for (const [event, entry] of Object.entries(ENTRIES)) {
    if (!hooks.hooks[event]) continue;
    const kept = hooks.hooks[event].filter(value => !same(value, entry));
    if (kept.length !== hooks.hooks[event].length) {
      changed = true;
      if (kept.length) hooks.hooks[event] = kept;
      else delete hooks.hooks[event];
    }
  }
  const backup = changed ? await rewriteHooks(hookPath, original, JSON.stringify(hooks, null, 2) + '\n') : null;
  const preserved = [];
  // Keep files if a modified hook still refers to them, or if the user edited
  // the files. Uninstall is never a recursive delete.
  const stillReferenced = JSON.stringify(hooks).includes('.cursor/protect-mcp/');
  for (const file of FILES) {
    const path = join(managed, file);
    const content = await optional(path);
    if (content === null) continue;
    if (stillReferenced || content !== await readFile(join(ROOT, file), 'utf8')) preserved.push(path);
    else await unlink(path);
  }
  for (const path of [join(managed, 'hooks'), join(managed, 'lib'), managed]) await rmdir(path).catch(error => { if (!['ENOENT', 'ENOTEMPTY'].includes(error.code)) throw error; });
  return { project: root, uninstalled: true, preserved, ...(backup ? { backup } : {}), note: 'Only unchanged protect-mcp hook entries and scripts were removed. Project settings, keys, policies and receipts remain.' };
}

async function main() {
  const args = process.argv.slice(2);
  let project, mode = 'plan', port;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--project') project = args[++i];
    else if (args[i] === '--port') port = Number(args[++i]);
    else if (['--install', '--uninstall'].includes(args[i])) {
      if (mode !== 'plan') throw new Error('Choose one action');
      mode = args[i].slice(2);
    } else throw new Error('Usage: node install-project.mjs --project /absolute/project [--port 9377] [--install|--uninstall]');
  }
  if (!project) throw new Error('An explicit --project path is required');
  console.log(JSON.stringify(await configure({ project, mode, port }), null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(await realpath(process.argv[1])).href) {
  try { await main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
