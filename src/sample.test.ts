import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { hexToBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { buildSampleKit, SAMPLE_KID } from './sample.js';
import { canonicalJson } from './receipt-enrichment.js';
import { buildClaim } from './claim.js';

const freshDir = (): string => mkdtempSync(join(tmpdir(), 'pmcp-sample-'));

// Independent verification: canonical JSON of the envelope minus signature,
// Ed25519 over the raw bytes, against the key embedded in the payload. This is
// the exact check the record viewer and @veritasacta/verify perform.
const verifyEnvelope = (env: Record<string, unknown>): boolean => {
  const { signature, ...rest } = env as { signature: string } & Record<string, unknown>;
  const msg = new TextEncoder().encode(canonicalJson(rest));
  const pub = (env as { payload: { public_key: string } }).payload.public_key;
  return ed25519.verify(hexToBytes(signature), msg, hexToBytes(pub));
};

const readRows = (p: string): Record<string, any>[] =>
  readFileSync(p, 'utf-8').trim().split('\n').map((l) => JSON.parse(l));

describe('sample kit (buildSampleKit)', () => {
  it('seeds 8 real signed receipts (1 blocked, 2 payments) that all verify', () => {
    const dir = freshDir();
    const kit = buildSampleKit(dir);
    const rows = readRows(join(dir, '.protect-mcp-receipts.jsonl'));
    expect(rows).toHaveLength(8);
    for (const env of rows) expect(verifyEnvelope(env)).toBe(true);

    const denies = rows.filter((e) => e.payload.decision === 'deny');
    expect(denies).toHaveLength(1);
    expect(denies[0].type).toBe('gateway_restraint');
    expect(denies[0].payload.enrichment.capabilities).toContain('net.egress');

    const pays = rows
      .map((e) => e.payload.enrichment?.payment?.amount)
      .filter((a: unknown): a is number => typeof a === 'number')
      .sort((a, b) => a - b);
    expect(pays).toEqual([0.02, 12.5]);

    expect(kit.kid).toBe(SAMPLE_KID);
    expect(kit.publicKey).toMatch(/^[0-9a-f]{64}$/);
    // Key file has the exact shape record/claim read (publicKey/privateKey/kid).
    const kd = JSON.parse(readFileSync(join(dir, 'keys', 'gateway.json'), 'utf-8'));
    expect(kd.publicKey).toBe(kit.publicKey);
    expect(kd.kid).toBe(SAMPLE_KID);
    expect(kd.privateKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('tampered copy fails verification on exactly the flipped row', () => {
    const dir = freshDir();
    buildSampleKit(dir);
    const rows = readRows(join(dir, 'demo-tampered.jsonl'));
    const bad = rows.map((e) => !verifyEnvelope(e));
    expect(bad.filter(Boolean)).toHaveLength(1);
    expect(rows[bad.indexOf(true)].payload.tool).toBe('WebFetch');
    expect(rows[bad.indexOf(true)].payload.decision).toBe('allow'); // flipped after signing
  });

  it('refuses to overwrite an existing record or key unless forced', () => {
    const dir = freshDir();
    buildSampleKit(dir);
    let code = '';
    try { buildSampleKit(dir); } catch (e) { code = (e as { code?: string }).code || ''; }
    expect(code).toBe('SAMPLE_EXISTS');
    expect(() => buildSampleKit(dir, { force: true })).not.toThrow();
  });

  it('drives the demo predicates: payment-under 100 holds, payment-under 10 refuses', () => {
    const dir = freshDir();
    buildSampleKit(dir);
    const kd = JSON.parse(readFileSync(join(dir, 'keys', 'gateway.json'), 'utf-8'));
    const receipts = readRows(join(dir, '.protect-mcp-receipts.jsonl'));
    const signer = { privateKey: kd.privateKey, publicKey: kd.publicKey, kid: kd.kid, issuer: 'protect-mcp' };

    const under100 = buildClaim(receipts, { kind: 'payment_under', cap: 100 }, signer, new Date().toISOString());
    expect(under100.claim.holds).toBe(true);
    expect(under100.claim.matched).toBe(0);
    expect(under100.scope.total).toBe(8);

    const under10 = buildClaim(receipts, { kind: 'payment_under', cap: 10 }, signer, new Date().toISOString());
    expect(under10.claim.holds).toBe(false); // the $12.50 invoice is real
    expect(under10.claim.matched).toBe(1);
  });
});

// CLI surface, exercised on the built binary like the other CLI tests.
const CLI = join(__dirname, '..', 'dist', 'cli.js');
const haveCli = existsSync(CLI);
const pkgVersion = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8')).version as string;
const dcli = haveCli ? describe : describe.skip;

dcli('cli: version, help, sample', () => {
  it('--version, -V and the version word print the package version', () => {
    for (const argv of [['--version'], ['-V'], ['version']]) {
      const r = spawnSync('node', [CLI, ...argv], { encoding: 'utf8' });
      expect(r.status).toBe(0);
      expect(r.stdout.trim()).toBe(pkgVersion);
    }
  });

  it('the help word prints usage (wrap syntax + sample) and exits 0', () => {
    const r = spawnSync('node', [CLI, 'help'], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    const usage = r.stderr + r.stdout;
    expect(usage).toContain('-- <command>');
    expect(usage).toContain('protect-mcp sample');
    expect(usage).toContain('--version');
  });

  it('sample seeds a folder, refuses a second run, obeys --force', () => {
    const dir = freshDir();
    let r = spawnSync('node', [CLI, 'sample', '--dir', dir], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Sample record seeded');
    expect(existsSync(join(dir, '.protect-mcp-receipts.jsonl'))).toBe(true);
    expect(existsSync(join(dir, 'demo-tampered.jsonl'))).toBe(true);
    expect(existsSync(join(dir, 'keys', 'gateway.json'))).toBe(true);

    r = spawnSync('node', [CLI, 'sample', '--dir', dir], { encoding: 'utf8' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('LABELED SAMPLE');

    r = spawnSync('node', [CLI, 'sample', '--dir', dir, '--force'], { encoding: 'utf8' });
    expect(r.status).toBe(0);
  });
});
