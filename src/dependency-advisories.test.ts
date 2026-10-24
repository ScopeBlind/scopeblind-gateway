/**
 * The lockfile resolves every package with a known production advisory to a
 * fixed version. All five arrive through @modelcontextprotocol/sdk; zod and
 * fast-uri are bundled into dist through it.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const lock = JSON.parse(readFileSync(join(__dirname, '..', 'package-lock.json'), 'utf-8')) as { packages: Record<string, { version?: string }> };

const atLeast = (version: string, minimum: string): boolean => {
  const [a, b] = [version, minimum].map((v) => v.split('.').map((n) => parseInt(n, 10)));
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return true;
};

const FIXED: Array<[string, string, string]> = [
  ['body-parser', '2.4.0', 'GHSA-27r3-jxmh-p828'],
  ['zod', '4.6.6', 'GHSA-mrhx-c7xc-m3w5'],
  ['fast-uri', '3.1.9', 'GHSA-w74x-v6f9-j3xg'],
  ['hono', '4.13.11', 'GHSA-5r4p-p66f-jhc7'],
  ['ip-address', '10.7.4', 'GHSA-rxp7-6hxx-x8q5'],
];

describe('dependency advisories', () => {
  for (const [name, minimum, advisory] of FIXED) {
    it(`${name} resolves past ${advisory} (>= ${minimum})`, () => {
      const copies = Object.entries(lock.packages).filter(([path]) => path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`));
      expect(copies.length, `${name} is in the lockfile`).toBeGreaterThan(0);
      for (const [path, entry] of copies) expect(atLeast(entry.version!, minimum), `${path}@${entry.version}`).toBe(true);
    });
  }
});
