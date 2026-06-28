// P0: a configured signer that cannot sign must be DISTINGUISHABLE from "no
// signer configured", so the gateway can fail closed instead of silently
// emitting an unsigned (or absent) receipt. This pins the discriminator.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initSigning, signDecision } from './signing.js';
import type { DecisionLog } from './types.js';

function entry(): DecisionLog {
  return {
    v: 2, tool: 'place_order', decision: 'allow', reason_code: 'policy_allow',
    policy_digest: 'sha256:x', request_id: 'req-1', timestamp: Date.now(), mode: 'enforce',
  } as DecisionLog;
}

describe('signDecision fail-closed discriminator', () => {
  it('unconfigured signer is NOT a failure: ok=false, no error, artifact_type none', async () => {
    await initSigning(undefined);
    const r = signDecision(entry());
    expect(r.ok).toBe(false);
    expect(r.signed).toBeNull();
    expect(r.artifact_type).toBe('none');
    expect(r.error).toBeUndefined(); // the free/unsigned tier must not fail closed
  });

  it('a configured-but-broken signer always reports an error (fail-closed signal)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pm-signfail-'));
    const keyPath = join(dir, 'key.json');
    // Structurally complete so initSigning accepts it, but the private key is
    // not valid signing material, so createSignedArtifact throws at sign time.
    writeFileSync(keyPath, JSON.stringify({
      privateKey: 'not-a-valid-ed25519-private-key',
      publicKey: 'ab'.repeat(32),
      kid: 'broken-kid',
    }));
    try {
      await initSigning({ enabled: true, key_path: keyPath } as never);
      const r = signDecision(entry());
      expect(r.ok).toBe(false);
      expect(r.signed).toBeNull();
      expect(typeof r.error).toBe('string');
      expect(r.warning).toMatch(/signing/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await initSigning(undefined); // reset module signer state for other tests
    }
  });

  it('a missing configured key fails closed at initialization', async () => {
    await initSigning({ enabled: true, key_path: '/definitely/not/a/key.json' } as never);
    const r = signDecision(entry());
    expect(r.ok).toBe(false);
    expect(r.signed).toBeNull();
    expect(r.error).toMatch(/key file not found/);
  });

  it('disabling signing clears a previously failed configured state', async () => {
    await initSigning({ enabled: true, key_path: '/definitely/not/a/key.json' } as never);
    expect(signDecision(entry()).error).toBeDefined();
    await initSigning(undefined);
    const r = signDecision(entry());
    expect(r.error).toBeUndefined();
    expect(r.artifact_type).toBe('none');
  });
});
