import { describe, it, expect, beforeAll } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { chainLink } from './acta-envelope.js';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const POLICY = 'permit (principal, action == Action::"MCP::Tool::call", resource) when { resource in [Tool::"Bash"] };';
let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pmcp-sign-parallel-'));
  mkdirSync(join(dir, 'policy'));
  writeFileSync(join(dir, 'policy', 'run.cedar'), POLICY);
  const seed = '0000000000000000000000000000000000000000000000000000000000000002';
  const priv = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + seed, 'hex'), format: 'der', type: 'pkcs8' });
  const pub = Buffer.from(createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32)).toString('hex');
  writeFileSync(join(dir, 'key.json'), JSON.stringify({ privateKey: seed, publicKey: pub, kid: 'parallel' }));
});

describe('sign under parallel hooks', () => {
  it('twelve concurrent signs leave one unbroken chain, every link the hash of the whole previous receipt', async () => {
    const receipts = join(dir, 'receipts');
    const runs = Array.from({ length: 12 }, (_, i) => new Promise<number | null>((resolveExit) => {
      const child = spawn('node', [CLI, 'sign', '--cedar', join(dir, 'policy'), '--action-model', 'mcp', '--tool', 'Bash', '--input', JSON.stringify({ command: `echo ${i}` }), '--receipts', receipts, '--key', join(dir, 'key.json')], { cwd: dir, env: { ...process.env, NO_COLOR: '1' } });
      child.stdin.end(); // sign reads a hook payload from stdin when it is a pipe; there is none here
      child.on('exit', (code) => resolveExit(code));
    }));
    const exits = await Promise.all(runs);
    expect(exits.every((c) => c === 0)).toBe(true);
    const lines = readFileSync(join(receipts, 'receipts.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(lines).toHaveLength(12);
    expect(lines[0].payload.previousReceiptHash).toBeUndefined();
    for (let i = 1; i < lines.length; i++) expect(lines[i].payload.previousReceiptHash).toBe(chainLink(lines[i - 1]));
  }, 60_000);
});
