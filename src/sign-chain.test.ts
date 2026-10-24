/**
 * `sign` continues the receipt chain from its log's last line, through the
 * BUILT CLI. It has no enforce mode, and a hook host may treat a failed hook
 * as non-blocking, so a log it cannot continue is moved aside, never deleted,
 * with a warning, and the new chain starts in a fresh file.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { chainLink } from './acta-envelope.js';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const d = existsSync(CLI) ? describe : describe.skip;

// A cut-off line, and JSON that cannot be hashed (invalid Unicode).
const CORRUPT_TAILS = ['{"payload":{"type":"protectmcp:decision","tool_name":"Bash"', '{"payload":{"note":"\\ud800"},"signature":{"sig":"00"}}'];

function workspace(): { dir: string; receipts: string; key: string } {
  const dir = mkdtempSync(join(tmpdir(), 'pmcp-sign-chain-'));
  const receipts = join(dir, 'receipts');
  mkdirSync(receipts);
  const priv = ed25519.utils.randomPrivateKey();
  const key = join(dir, 'key.json');
  writeFileSync(key, JSON.stringify({ privateKey: bytesToHex(priv), publicKey: bytesToHex(ed25519.getPublicKey(priv)), kid: 'test' }), { mode: 0o600 });
  return { dir, receipts, key };
}

const sign = (w: { dir: string; receipts: string; key: string }) =>
  spawnSync(process.execPath, [CLI, 'sign', '--tool', 'Bash', '--input', '{"command":"ls"}', '--receipts', w.receipts, '--key', w.key], { cwd: w.dir, encoding: 'utf-8', input: '' });

const lines = (path: string) => readFileSync(path, 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));

d('sign: a receipt log it cannot continue', () => {
  it('is moved aside with a warning, and the new chain starts in a fresh file', () => {
    for (const tail of CORRUPT_TAILS) {
      const w = workspace();
      const log = join(w.receipts, 'receipts.jsonl');
      writeFileSync(log, `{"type":"earlier"}\n${tail}\n`);
      const before = readFileSync(log, 'utf-8');
      const r = sign(w);
      expect(r.status, r.stderr).toBe(0);
      const aside = readdirSync(w.receipts).filter((n) => /^receipts\.jsonl\.corrupt-\d{8}T\d{6}Z(-\d+)?$/.test(n));
      expect(aside.length, tail).toBe(1);
      expect(readFileSync(join(w.receipts, aside[0]), 'utf-8')).toBe(before);
      expect(r.stderr).toContain(aside[0]);
      const fresh = lines(log);
      expect(fresh.length).toBe(1);
      expect(fresh[0].signature).toBeDefined();
      expect(fresh[0].payload.previousReceiptHash).toBeUndefined();
    }
  }, 30_000);

  it('continues a readable chain, and an unsigned last line still starts a new one, as before', () => {
    const w = workspace();
    const log = join(w.receipts, 'receipts.jsonl');
    expect(sign(w).status).toBe(0);
    expect(sign(w).status).toBe(0);
    const [first, second] = lines(log);
    expect(second.payload.previousReceiptHash).toBe(chainLink(first));

    const unsigned = workspace();
    const unsignedLog = join(unsigned.receipts, 'receipts.jsonl');
    writeFileSync(unsignedLog, '{"type":"unsigned-note","signed":false}\n');
    expect(sign(unsigned).status).toBe(0);
    const after = lines(unsignedLog);
    expect(after.length).toBe(2);
    expect(after[1].payload.previousReceiptHash).toBeUndefined();
    expect(readdirSync(unsigned.receipts).filter((n) => n.includes('.corrupt-'))).toEqual([]);
  }, 30_000);
});
