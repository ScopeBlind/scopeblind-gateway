import { describe, it, expect } from 'vitest';
import {
  buildEnrichment,
  canonicalJson,
  deriveCapabilities,
  deriveResource,
  ENRICHMENT_VERSION,
} from './receipt-enrichment.js';

describe('receipt enrichment', () => {
  it('canonicalJson is stable regardless of key order', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
    expect(canonicalJson({ a: 2, b: 1 })).toBe('{"a":2,"b":1}');
    expect(canonicalJson([{ z: 1, a: 2 }])).toBe('[{"a":2,"z":1}]');
  });

  it('input_digest is deterministic, order-independent, and a sha-256 hex', () => {
    const a = buildEnrichment('Bash', { command: 'ls', cwd: '/x' });
    const b = buildEnrichment('Bash', { cwd: '/x', command: 'ls' });
    expect(a.input_digest).toBe(b.input_digest);
    expect(a.input_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(a.v).toBe(ENRICHMENT_VERSION);
  });

  it('different input -> different digest', () => {
    const a = buildEnrichment('Bash', { command: 'ls' });
    const b = buildEnrichment('Bash', { command: 'rm -rf /' });
    expect(a.input_digest).not.toBe(b.input_digest);
  });

  it('derives capability tags deterministically and sorted', () => {
    expect(deriveCapabilities('Bash', { command: 'rm -rf build' })).toEqual(
      expect.arrayContaining(['exec.shell', 'destructive']),
    );
    expect(deriveCapabilities('WebFetch', { url: 'https://api.example.com' })).toContain('net.egress');
    expect(deriveCapabilities('Write', { file_path: '/app/.env' })).toEqual(
      expect.arrayContaining(['fs.write', 'secret.adjacent']),
    );
    expect(deriveCapabilities('Read', { file_path: '/app/x.ts' })).toContain('fs.read');
    expect(deriveCapabilities('Bash', { command: 'git push --force' })).toEqual(
      expect.arrayContaining(['exec.shell', 'vcs', 'destructive']),
    );
    const caps = deriveCapabilities('Bash', { command: 'rm -rf x' });
    expect(caps).toEqual([...caps].sort());
  });

  it('financial + data.query + package tags', () => {
    expect(deriveCapabilities('submit_order', { side: 'buy', qty: 100 })).toContain('financial');
    expect(deriveCapabilities('Bash', { command: 'psql -c "select * from accounts"' })).toContain('data.query');
    expect(deriveCapabilities('Bash', { command: 'npm install left-pad' })).toContain('package.install');
  });

  it('derives a hashed, minimum-disclosure resource for path / host / command', () => {
    const p = deriveResource({ file_path: '/secret/path.txt' });
    expect(p).toEqual({ kind: 'path', digest: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(deriveResource({ file_path: '/secret/path.txt' })!.digest).toBe(p!.digest); // clusters
    expect(JSON.stringify(p)).not.toContain('secret'); // reveals nothing
    expect(deriveResource({ url: 'https://x.example.com/a?b=c' })).toEqual({
      kind: 'host',
      digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(deriveResource({ command: 'psql -c "..."' })!.kind).toBe('command');
    expect(deriveResource({})).toBeUndefined();
  });

  it('never throws on odd input', () => {
    expect(() => buildEnrichment('x', null)).not.toThrow();
    expect(() => buildEnrichment('x', undefined)).not.toThrow();
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => buildEnrichment('x', circular)).not.toThrow();
  });
});
