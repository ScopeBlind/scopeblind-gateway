import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Server } from 'node:http';
import { startHookServer } from './hook-server.js';
import { initSigning } from './signing.js';

/**
 * D5: enforce mode must not arm unless the live restraint self-test passes and,
 * when a signer is configured, a denial receipt can actually be produced.
 * Shadow mode must never be blocked by the self-test.
 */
describe('enforce-mode startup self-test', () => {
  let server: Server | null = null;
  let dir: string | null = null;

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
      server = null;
    }
    if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
    dir = null;
    // Reset global signing state so one test's broken signer cannot leak.
    await initSigning(undefined);
  });

  const untilListening = (s: Server): Promise<void> =>
    s.listening ? Promise.resolve() : new Promise((r) => s.once('listening', () => r()));

  it('arms enforce mode when the self-test passes (no signer configured)', async () => {
    server = await startHookServer({ port: 19381, enforce: true });
    await untilListening(server);
    expect(server.listening).toBe(true);
  });

  it('never blocks shadow mode, even with a broken signer configured', async () => {
    dir = mkdtempSync(join(tmpdir(), 'selftest-'));
    const policyPath = join(dir, 'policy.json');
    writeFileSync(policyPath, JSON.stringify({
      tools: { '*': { require: 'any' } },
      signing: { enabled: true, key_path: join(dir, 'missing-key.json') },
    }));
    server = await startHookServer({ port: 19382, enforce: false, policyPath });
    await untilListening(server);
    expect(server.listening).toBe(true);
  });

  it('refuses to arm enforce mode when signing is configured but the signer is broken', async () => {
    dir = mkdtempSync(join(tmpdir(), 'selftest-'));
    const policyPath = join(dir, 'policy.json');
    writeFileSync(policyPath, JSON.stringify({
      tools: { '*': { require: 'any' } },
      signing: { enabled: true, key_path: join(dir, 'missing-key.json') },
    }));
    await expect(startHookServer({ port: 19383, enforce: true, policyPath }))
      .rejects.toThrow(/denial receipt could not be produced/);
  });
});
