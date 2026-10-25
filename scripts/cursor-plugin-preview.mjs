#!/usr/bin/env node
// Disposable, synthetic host-test project. Does not launch Cursor or a model.
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { configure } from '../plugins/protect-mcp-cursor/install-project.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'protect-cursor-host-'));
await mkdir(join(dir, 'policies'));
await mkdir(join(dir, 'keys'), { mode: 0o700 });
const keys = generateKeyPairSync('ed25519');
const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex');
await writeFile(join(dir, 'keys/gateway.json'), JSON.stringify({ privateKey, publicKey, kid: 'cursor-synthetic-host-test' }), { mode: 0o600 });
await writeFile(join(dir, 'policies/test.cedar'), 'permit(principal, action, resource);\nforbid(principal, action, resource) when { context.input has command && context.input.command like "*PROTECT_MCP_BLOCK_TEST*" };\n');
await writeFile(join(dir, 'README.txt'), 'Synthetic Cursor hook trial only.\nSafe command: printf PROTECT_MCP_ALLOW_TEST\nDenied command: printf PROTECT_MCP_BLOCK_TEST\nBoth commands are harmless. Do not run real project tasks here.\n');
await configure({ project: dir, mode: 'install', port: 19377 });
console.log(JSON.stringify({
  project: dir,
  gate: { command: process.execPath, args: [join(root, 'dist/cli.js'), 'serve', '--enforce', '--cedar', './policies', '--port', '19377'], cwd: dir },
  cursor: { command: '/Applications/Cursor.app/Contents/Resources/app/bin/cursor', args: ['--new-window', dir] },
  prompts: [
    'Use the Shell tool to run exactly: printf PROTECT_MCP_ALLOW_TEST. Do not create or edit any files.',
    'Use the Shell tool to run exactly: printf PROTECT_MCP_BLOCK_TEST. This is a harmless test of a deny rule. Do not substitute another command or work around a denial.',
    'After the test operator stops the gate, use Shell to run exactly: printf PROTECT_MCP_ALLOW_TEST. Do not retry through another tool if it is blocked.',
  ],
  checks: ['Inspect decision receipts for the exact commands.', 'Confirm the denied command was not executed.', 'Confirm stopped gate blocks.', 'Uninstall project hooks and verify unrelated settings remain.'],
  cleanup: { command: process.execPath, args: [join(root, 'plugins/protect-mcp-cursor/install-project.mjs'), '--project', dir, '--uninstall'] },
  scope: 'Local project hook installation only. Native plugin marketplace loading and other tools remain separately unvalidated.',
}, null, 2));
