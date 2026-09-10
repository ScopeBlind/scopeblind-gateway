/** The egress guard emits only commitment-bound, pseudonymous summaries. */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { inspectEgress, assertEgressSafe, toEgressSummary, runEgressSelfCheck, EGRESS_SUMMARY_TYPE } from './egress-guard.js';

const PSEUDONYM_KEY = Buffer.alloc(32, 7);
import { initSigning, signDecision } from './signing.js';

async function receiptWithRawContent(): Promise<Record<string, any>> {
  const dir = mkdtempSync(join(tmpdir(), 'egress-'));
  const priv = randomBytes(32);
  const keyPath = join(dir, 'gw.json');
  writeFileSync(keyPath, JSON.stringify({ privateKey: bytesToHex(priv), publicKey: bytesToHex(ed25519.getPublicKey(priv)), kid: 'k' }));
  await initSigning({ enabled: true, key_path: keyPath, issuer: 'test' });
  const signed = signDecision({
    v: 2, tool: 'send_email', decision: 'allow', reason_code: 'policy_allow', policy_digest: 'strategy-mean-reversion',
    request_id: 'ceo@victim.com', timestamp: 1, mode: 'enforce',
    action_readback: { tool: 'send_email', destination: 'ceo@victim.com', payload_preview: { to: 'ceo@victim.com', subject: 'Q3 MNPI', body: 'we miss earnings by 40%, sell before the print' }, payload_hash: 'deadbeefcafe', disclosed_fields: ['to', 'subject', 'body'] },
    payload_digest: { output_hash: 'cafe00', output_size: 10, truncated: false, preview: 'raw output body positions AAPL 50000' } as any,
  } as any);
  return JSON.parse(signed.signed!);
}

const RAW_MARKERS = ['ceo@victim.com', 'MNPI', 'sell before', '40%', 'positions AAPL 50000', 'strategy-mean-reversion'];

describe('egress summary v1', () => {
  it('drops raw tool content and forwards only commitment-bound pseudonyms', async () => {
    const summary = toEgressSummary(await receiptWithRawContent(), { pseudonymKey: PSEUDONYM_KEY, tenantScope: 'test-tenant' })!;
    const blob = JSON.stringify(summary);
    for (const marker of RAW_MARKERS) expect(blob).not.toContain(marker);
    expect(summary.type).toBe(EGRESS_SUMMARY_TYPE);
    expect(summary.tool_category).toBe('communication');
    expect(summary.request_pseudonym).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(summary.policy_commitment).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(summary.source_receipt_commitment).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(inspectEgress(summary).safe).toBe(true);
  });

  it('does not pass through a private key in any local container', async () => {
    const receipt = await receiptWithRawContent();
    receipt.payload.action_readback.privateKey = 'deadbeef'.repeat(8);
    const summary = toEgressSummary(receipt, { pseudonymKey: PSEUDONYM_KEY, tenantScope: 'test-tenant' })!;
    expect(JSON.stringify(summary)).not.toContain('deadbeef'.repeat(8));
    expect(inspectEgress(summary).safe).toBe(true);
  });

  it('rejects nested data, unknown fields, raw labels, and malformed commitments', () => {
    const base = toEgressSummary({ payload: { type: 'protectmcp:decision', tool_name: 'Bash', decision: 'deny', request_id: 'x', policy_digest: 'p' }, signature: { alg: 'EdDSA', kid: 'k', sig: 'y' } }, { pseudonymKey: PSEUDONYM_KEY, tenantScope: 'test-tenant' })!;
    expect(inspectEgress({ ...base, exfil: 'x' }).safe).toBe(false);
    expect(inspectEgress({ ...base, raw_body: { secret: 'no' } }).safe).toBe(false);
    expect(inspectEgress({ ...base, tool_category: 'send_email' }).safe).toBe(false);
    expect(inspectEgress({ ...base, request_pseudonym: 'ceo@victim.com' }).safe).toBe(false);
    expect(inspectEgress('a string').safe).toBe(false);
  });

  it('throws before unsafe data can leave the process', () => {
    expect(() => assertEgressSafe({ type: EGRESS_SUMMARY_TYPE, version: 1, request_pseudonym: 'raw' })).toThrow(/egress guard blocked/);
  });

  it('requires a local pseudonym key and separates tenants', async () => {
    const receipt = await receiptWithRawContent();
    expect(toEgressSummary(receipt)).toBeNull();
    const first = toEgressSummary(receipt, { pseudonymKey: PSEUDONYM_KEY, tenantScope: 'tenant-a' })!;
    const second = toEgressSummary(receipt, { pseudonymKey: PSEUDONYM_KEY, tenantScope: 'tenant-b' })!;
    expect(first.request_pseudonym).not.toBe(second.request_pseudonym);
    expect(first.policy_commitment).not.toBe(second.policy_commitment);
    expect(inspectEgress({ ...first, request_pseudonym: `sha256:${'0'.repeat(64)}` }).safe).toBe(false);
  });

  it('proves raw content and private keys are structurally absent', async () => {
    const check = runEgressSelfCheck([await receiptWithRawContent()], new Date().toISOString());
    expect(check.all_summaries_safe).toBe(true);
    expect(check.raw_content_dropped).toBe(true);
    expect(check.private_key_dropped).toBe(true);
    expect(check.deny_receipt_forwardable).toBe(true);
  });

  it('sends only an HMAC-minimized signed summary after tenant discovery', async () => {
    const sent: unknown[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/fn/brass/issue')) {
        return new Response(JSON.stringify({ auth_proof: { tenant_id: 'test-tenant', expires_at: '2099-01-01T00:00:00.000Z' } }), { status: 200 });
      }
      sent.push(JSON.parse(String(init?.body || '{}')));
      return new Response(JSON.stringify({ accepted: 1, rejected: 0 }), { status: 200 });
    }) as typeof fetch;
    const { ScopeBlindBridge } = await import('./scopeblind-bridge.js');
    const bridge = new ScopeBlindBridge({
      SCOPEBLIND_TOKEN: 'test-token',
      SCOPEBLIND_TENANT: 'test-tenant',
      SCOPEBLIND_BASE: 'https://scopeblind.test',
      SCOPEBLIND_EGRESS_KEY_DIR: mkdtempSync(join(tmpdir(), 'egress-key-')),
    });
    try {
      bridge.forward(await receiptWithRawContent());
      expect((bridge as any).queue).toHaveLength(1);
      await bridge.flush();
      const posted = sent[0] as { summaries: Array<{ payload: Record<string, unknown> }> };
      expect(posted.summaries).toHaveLength(1);
      expect(posted.summaries[0].payload.type).toBe(EGRESS_SUMMARY_TYPE);
      expect(inspectEgress(posted.summaries[0].payload, { signed: true }).safe).toBe(true);
      expect(String(posted.summaries[0].payload.request_pseudonym)).toMatch(/^hmac-sha256:/);
      expect(JSON.stringify(posted)).not.toContain('ceo@victim.com');
    } finally {
      await bridge.shutdown();
      globalThis.fetch = originalFetch;
    }
  });
});
