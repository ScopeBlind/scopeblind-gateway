/**
 * Locks the acta-policy-digest-v1 construction.
 *
 * The golden-vector test recomputes the digest with an INDEPENDENT inline
 * implementation (node:crypto + hand-sorted JSON), so any drift in the
 * module's construction fails here rather than silently changing every
 * receipt's policy_digest.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  digestPolicyFiles,
  digestCedarDir,
  digestCedarSource,
  digestBuiltinPolicy,
  buildPolicyBundle,
  verifyPolicyBundle,
  shortPolicyLabel,
  POLICY_DIGEST_CONSTRUCTION,
} from './policy-digest.js';

const hex = (d: string | Buffer) => createHash('sha256').update(d).digest('hex');

// Independent reimplementation of the construction, for the golden vector.
function independentDigest(engine: string, files: Array<{ name: string; content: string }>): string {
  const entries = files
    .map((f) => ({ name: f.name, sha256: hex(Buffer.from(f.content, 'utf-8')) }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
  // JCS for this manifest: sorted keys, compact separators. Keys are chosen
  // so plain sorted JSON.stringify is JCS-identical (ASCII, no numbers).
  const manifest =
    `{"construction":"${POLICY_DIGEST_CONSTRUCTION}","engine":"${engine}","files":[` +
    entries.map((e) => `{"name":${JSON.stringify(e.name)},"sha256":"${e.sha256}"}`).join(',') +
    ']}';
  return `sha256:${hex(Buffer.from(manifest, 'utf-8'))}`;
}

const FILES = [
  { name: 'agent.cedar', content: 'permit(principal, action == Action::"MCP::Tool::call", resource);\n' },
  { name: 'deny.cedar', content: 'forbid(principal, action, resource == Tool::"Bash");\n' },
];

describe('acta-policy-digest-v1 construction', () => {
  it('matches an independent implementation (golden vector)', () => {
    const result = digestPolicyFiles('cedar', FILES);
    expect(result.policy_digest).toBe(independentDigest('cedar', FILES));
    expect(result.policy_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('is independent of input file order', () => {
    const a = digestPolicyFiles('cedar', FILES);
    const b = digestPolicyFiles('cedar', [...FILES].reverse());
    expect(a.policy_digest).toBe(b.policy_digest);
  });

  it('does not collide on shifted file boundaries (the concatenation flaw)', () => {
    // Under any concatenation scheme these two sets produce identical bytes;
    // per-file hashing keeps them distinct.
    const left = digestPolicyFiles('cedar', [{ name: 'x.cedar', content: 'ab' }, { name: 'y.cedar', content: 'c' }]);
    const right = digestPolicyFiles('cedar', [{ name: 'x.cedar', content: 'a' }, { name: 'y.cedar', content: 'bc' }]);
    expect(left.policy_digest).not.toBe(right.policy_digest);
  });

  it('observes renames and rejects duplicates', () => {
    const renamed = digestPolicyFiles('cedar', [{ ...FILES[0], name: 'renamed.cedar' }, FILES[1]]);
    expect(renamed.policy_digest).not.toBe(digestPolicyFiles('cedar', FILES).policy_digest);
    expect(() => digestPolicyFiles('cedar', [FILES[0], { ...FILES[1], name: FILES[0].name }])).toThrow(/duplicate/);
  });

  it('digestCedarDir reads .cedar files only and matches digestPolicyFiles', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-pd-'));
    for (const f of FILES) writeFileSync(join(dir, f.name), f.content);
    writeFileSync(join(dir, 'README.md'), 'not a policy');
    expect(digestCedarDir(dir).policy_digest).toBe(digestPolicyFiles('cedar', FILES).policy_digest);
  });

  it('digestCedarSource pins the single-source name', () => {
    const src = FILES[0].content;
    expect(digestCedarSource(src).policy_digest).toBe(
      digestPolicyFiles('cedar', [{ name: 'policy.cedar', content: src }]).policy_digest,
    );
  });

  it('digestBuiltinPolicy is independent of key order', () => {
    const a = digestBuiltinPolicy({ tools: { Bash: { tier: 'privileged' } }, default_tier: 'unknown' });
    const b = digestBuiltinPolicy({ default_tier: 'unknown', tools: { Bash: { tier: 'privileged' } } });
    expect(a.policy_digest).toBe(b.policy_digest);
    expect(a.engine).toBe('builtin');
  });

  it('shortPolicyLabel is engine:first-16-hex', () => {
    const r = digestPolicyFiles('cedar', FILES);
    expect(shortPolicyLabel(r)).toMatch(/^cedar:[0-9a-f]{16}$/);
  });
});

describe('policy bundle publish/verify round-trip', () => {
  it('a built bundle self-verifies and its digest matches the direct construction', () => {
    const bundle = buildPolicyBundle('cedar', FILES, '2026-07-08T00:00:00.000Z');
    expect(bundle.policy_digest).toBe(digestPolicyFiles('cedar', FILES).policy_digest);
    expect(verifyPolicyBundle(bundle)).toMatchObject({ valid: true });
  });

  it('tampered file content is caught by the per-file hash', () => {
    const bundle = buildPolicyBundle('cedar', FILES);
    const tampered = JSON.parse(JSON.stringify(bundle));
    tampered.files[0].content += '\npermit(principal, action, resource);';
    const res = verifyPolicyBundle(tampered);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('file_hash_mismatch');
  });

  it('a consistent-but-swapped digest is caught by manifest recomputation', () => {
    const bundle = buildPolicyBundle('cedar', FILES);
    const swapped = JSON.parse(JSON.stringify(bundle));
    swapped.policy_digest = 'sha256:' + '0'.repeat(64);
    const res = verifyPolicyBundle(swapped);
    expect(res.valid).toBe(false);
    expect(res.error).toBe('digest_mismatch');
  });
});
