#!/usr/bin/env node
// One transport implementation, copied into the self-contained distribution.
import { copyFile, readFile } from 'node:fs/promises';
const source = new URL('../hooks/relay-core.mjs', import.meta.url);
const destination = new URL('../plugins/protect-mcp-cursor/lib/gate-client.mjs', import.meta.url);
if (process.argv.includes('--write')) await copyFile(source, destination);
else if ((await readFile(source, 'utf8')) !== (await readFile(destination, 'utf8'))) {
  console.error('Cursor gate client differs. Run node scripts/cursor-plugin-sync.mjs --write and retest both adapters.');
  process.exitCode = 1;
}
