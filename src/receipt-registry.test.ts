import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it, vi } from 'vitest';
import { createOrgIdentity, createReceiptRegistry, readReceiptDigestRecords } from './receipt-registry.js';

describe('receipt registry paid boundary', () => {
  function fixtureDir(): string {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-registry-'));
    mkdirSync(join(dir, 'keys'));
    writeFileSync(join(dir, 'keys', 'gateway.json'), JSON.stringify({
      publicKey: 'a'.repeat(64),
      privateKey: 'b'.repeat(64),
      kid: 'test-kid',
      issuer: 'desk-gateway',
    }));
    writeFileSync(join(dir, '.protect-mcp-receipts.jsonl'), JSON.stringify({
      type: 'scopeblind.decision_receipt.v1',
      issued_at: '2026-07-02T08:00:00.000Z',
      payload: { request_id: 'req-1', tool: 'send_email', payload_preview: { secret: 'should-not-upload' } },
      signature: 'c'.repeat(128),
    }) + '\n');
    return dir;
  }

  it('extracts digest records without raw payload data in the registry upload boundary', async () => {
    const dir = fixtureDir();
    const { registry, registryPath, verifierPath, uploaded } = await createReceiptRegistry({
      dir,
      orgName: 'Meridian',
      billingAccountId: 'acct_meridian',
      now: new Date('2026-07-02T08:10:00.000Z'),
    });

    expect(uploaded).toBe(false);
    expect(registry.records).toHaveLength(1);
    expect(registry.records[0].receipt_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(registry.anchors[0].timestamp_source).toBe('local-preview-not-independent');
    expect(registry.billing.raw_data_upload).toBe(false);
    expect(readFileSync(registryPath, 'utf-8')).not.toContain('should-not-upload');
    expect(readFileSync(verifierPath, 'utf-8')).toContain('ScopeBlind verifier');
  });

  it('hosted anchoring posts digests and org metadata only', async () => {
    const dir = fixtureDir();
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      expect(JSON.stringify(body)).not.toContain('should-not-upload');
      expect(JSON.stringify(body)).not.toContain('payload_preview');
      expect(body.billing.raw_data_upload).toBe(false);
      expect(body.receipt_digests[0].receipt_hash).toMatch(/^[a-f0-9]{64}$/);
      return new Response(JSON.stringify({
        registry_url: 'https://legate.scopeblind.com/registry/demo',
        anchors: [{
          receipt_hash: body.receipt_digests[0].receipt_hash,
          anchor_id: 'anc_123',
          timestamp_utc: '2026-07-02T08:11:00.000Z',
          verifier_url: 'https://legate.scopeblind.com/verify?digest=x',
        }],
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    const { registry, uploaded } = await createReceiptRegistry({
      dir,
      hosted: true,
      endpoint: 'https://api.scopeblind.test',
      token: 'tok_test',
    });

    expect(uploaded).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(registry.anchors[0].timestamp_source).toBe('scopeblind-hosted');
    vi.unstubAllGlobals();
  });

  it('receipt digest changes when the raw receipt is tampered', () => {
    const dir = fixtureDir();
    const [before] = readReceiptDigestRecords(dir);
    writeFileSync(join(dir, '.protect-mcp-receipts.jsonl'), JSON.stringify({
      type: 'scopeblind.decision_receipt.v1',
      issued_at: '2026-07-02T08:00:00.000Z',
      payload: { request_id: 'req-1', tool: 'send_email', tampered: true },
      signature: 'c'.repeat(128),
    }) + '\n');
    const [after] = readReceiptDigestRecords(dir);
    expect(before.receipt_hash).not.toBe(after.receipt_hash);
  });

  it('creates a hosted org identity with a public key directory and no private key', () => {
    const dir = fixtureDir();
    const identity = createOrgIdentity({ dir, orgName: 'Meridian', billingAccountId: 'acct_1' });
    expect(identity.public_key_directory[0].public_key_hex).toBe('a'.repeat(64));
    expect(JSON.stringify(identity)).not.toContain('privateKey');
    expect(identity.privacy.digest_only).toBe(true);
  });
});
