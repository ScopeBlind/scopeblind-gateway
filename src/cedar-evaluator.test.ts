import { describe, it, expect, beforeEach } from 'vitest';
import { writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadCedarPolicies } from './cedar-evaluator.js';

// ============================================================
// loadCedarPolicies
// ============================================================

describe('loadCedarPolicies', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cedar-test-'));
  });

  it('loads .cedar files from a directory', () => {
    writeFileSync(join(tmpDir, 'test.cedar'), `
      @id("test-001")
      forbid (
        principal,
        action == Action::"MCP::Tool::call",
        resource == Tool::"bash"
      );
    `);

    const result = loadCedarPolicies(tmpDir);
    expect(result.fileCount).toBe(1);
    expect(result.files).toEqual(['test.cedar']);
    expect(result.source).toContain('test-001');
    expect(result.digest).toHaveLength(16);
    expect(/^[a-f0-9]{16}$/.test(result.digest)).toBe(true);
  });

  it('loads multiple .cedar files sorted alphabetically', () => {
    writeFileSync(join(tmpDir, 'b-policy.cedar'), '@id("b-001") forbid(principal, action, resource);');
    writeFileSync(join(tmpDir, 'a-policy.cedar'), '@id("a-001") forbid(principal, action, resource);');

    const result = loadCedarPolicies(tmpDir);
    expect(result.fileCount).toBe(2);
    expect(result.files).toEqual(['a-policy.cedar', 'b-policy.cedar']);
    // Source should contain both policies
    expect(result.source).toContain('a-001');
    expect(result.source).toContain('b-001');
  });

  it('produces deterministic digest regardless of file creation order', () => {
    const dir1 = mkdtempSync(join(tmpdir(), 'cedar-det-1-'));
    const dir2 = mkdtempSync(join(tmpdir(), 'cedar-det-2-'));

    // Same files, different creation order
    writeFileSync(join(dir1, 'a.cedar'), 'forbid(principal, action, resource);');
    writeFileSync(join(dir1, 'b.cedar'), 'permit(principal, action, resource);');

    writeFileSync(join(dir2, 'b.cedar'), 'permit(principal, action, resource);');
    writeFileSync(join(dir2, 'a.cedar'), 'forbid(principal, action, resource);');

    const r1 = loadCedarPolicies(dir1);
    const r2 = loadCedarPolicies(dir2);
    expect(r1.digest).toBe(r2.digest);
  });

  it('throws on non-existent directory', () => {
    expect(() => loadCedarPolicies('/nonexistent/cedar/dir')).toThrow(/not found/);
  });

  it('throws on directory with no .cedar files', () => {
    writeFileSync(join(tmpDir, 'not-cedar.json'), '{}');
    expect(() => loadCedarPolicies(tmpDir)).toThrow(/No .cedar files/);
  });

  it('ignores non-.cedar files', () => {
    writeFileSync(join(tmpDir, 'policy.cedar'), '@id("only-this") forbid(principal, action, resource);');
    writeFileSync(join(tmpDir, 'readme.md'), '# Not a Cedar file');
    writeFileSync(join(tmpDir, 'config.json'), '{}');

    const result = loadCedarPolicies(tmpDir);
    expect(result.fileCount).toBe(1);
    expect(result.files).toEqual(['policy.cedar']);
  });
});
