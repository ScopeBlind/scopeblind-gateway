import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// CI tripwire for the 0.7.0 security advisory. Cedar silently discards a policy
// whose `context.<attr> in [stringList]` (or resource.<attr>) type-errors,
// turning a forbid rule into a no-op. This guard fails the build if that pattern
// is ever reintroduced into a shipped policy. Valid entity-set membership
// (`action in [Action::...]`, `principal in <Group>`) is intentionally NOT matched.
const IN_ON_STRING = /\b(?:context|resource)\.\w+\s+in\s+\[\s*"/;

function cedarFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...cedarFiles(p));
    else if (entry.name.endsWith('.cedar')) out.push(p);
  }
  return out;
}

describe('shipped Cedar policies are free of the in-on-String hazard', () => {
  const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
  const files = cedarFiles(join(pkgRoot, 'policies'));

  it('finds the bundled policy directory', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  for (const file of files) {
    it(`${file.replace(pkgRoot + '/', '')} does not use context/resource <attr> in [strings]`, () => {
      const src = readFileSync(file, 'utf-8');
      const offending = src
        .split('\n')
        .map((line, i) => ({ line: line.trim(), n: i + 1 }))
        .filter((l) => IN_ON_STRING.test(l.line));
      expect(offending, `use [list].contains(<attr>) instead; offending: ${JSON.stringify(offending)}`).toEqual([]);
    });
  }
});
