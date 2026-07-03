import { describe, it, expect } from 'vitest';
import { createAuditBundle, collectSignedReceipts } from './bundle.js';

describe('createAuditBundle', () => {
  const mockKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    kid: 'test-kid-123',
    x: 'dFqNYGKQ1234567890abcdefghijklmnopqrstuvwx',
    use: 'sig',
  };

  const mockReceipt = {
    v: 2,
    type: 'decision_receipt',
    algorithm: 'ed25519',
    kid: 'test-kid-123',
    issuer: 'sb:test',
    issued_at: '2026-03-21T10:00:00Z',
    payload: { decision: 'allow', tool: 'read_file', policy_digest: 'abc', scope: 'default' },
    signature: 'a'.repeat(128),
  };

  it('creates a valid bundle', () => {
    const bundle = createAuditBundle({
      tenant: 'test-tenant',
      receipts: [mockReceipt],
      signingKeys: [mockKey],
    });

    expect(bundle.format).toBe('scopeblind:audit-bundle');
    expect(bundle.version).toBe(1);
    expect(bundle.tenant).toBe('test-tenant');
    expect(bundle.receipts).toHaveLength(1);
    expect(bundle.verification.algorithm).toBe('ed25519');
    expect(bundle.verification.signing_keys).toHaveLength(1);
    expect(bundle.verification.instructions).toContain('Ed25519');
    expect(bundle.exported_at).toBeTruthy();
  });

  it('infers time range from receipts', () => {
    const receipt2 = { ...mockReceipt, issued_at: '2026-03-21T12:00:00Z' };
    const bundle = createAuditBundle({
      tenant: 'test',
      receipts: [mockReceipt, receipt2],
      signingKeys: [mockKey],
    });

    expect(bundle.time_range).toEqual({
      from: '2026-03-21T10:00:00Z',
      to: '2026-03-21T12:00:00Z',
    });
  });

  it('uses provided time range over inferred', () => {
    const bundle = createAuditBundle({
      tenant: 'test',
      timeRange: { from: '2026-01-01T00:00:00Z', to: '2026-12-31T23:59:59Z' },
      receipts: [mockReceipt],
      signingKeys: [mockKey],
    });

    expect(bundle.time_range?.from).toBe('2026-01-01T00:00:00Z');
  });

  it('deduplicates signing keys by kid', () => {
    const bundle = createAuditBundle({
      tenant: 'test',
      receipts: [mockReceipt],
      signingKeys: [mockKey, mockKey, { ...mockKey, kid: 'other-kid' }],
    });

    expect(bundle.verification.signing_keys).toHaveLength(2);
  });

  it('throws for empty receipts', () => {
    expect(() =>
      createAuditBundle({
        tenant: 'test',
        receipts: [],
        signingKeys: [mockKey],
      }),
    ).toThrow('at least one signed receipt');
  });

  it('filters out unsigned entries', () => {
    const unsigned = { v: 2, type: 'decision_receipt', payload: {} };
    const bundle = createAuditBundle({
      tenant: 'test',
      receipts: [mockReceipt, unsigned as any],
      signingKeys: [mockKey],
    });

    expect(bundle.receipts).toHaveLength(1);
  });

  it('includes anchors when provided', () => {
    const anchor = {
      v: 2,
      type: 'audit_anchor',
      signature: 'b'.repeat(128),
      payload: { merkle_root: 'abc', chain_heads: [] },
    };
    const bundle = createAuditBundle({
      tenant: 'test',
      receipts: [mockReceipt],
      anchors: [anchor],
      signingKeys: [mockKey],
    });

    expect(bundle.anchors).toHaveLength(1);
  });

  it('includes selective disclosure packages and committed receipts', () => {
    const committedReceipt = {
      type: 'scopeblind.receipt.committed.v1',
      timestamp: '2026-03-21T13:00:00Z',
      committed_fields_root: 'a'.repeat(64),
      committed_field_names: ['tool', 'payload_digest'],
      signature: { alg: 'EdDSA', kid: 'test-kid-123', sig: 'x', public_key: 'b'.repeat(64) },
    };
    const disclosure = {
      type: 'scopeblind.selective_disclosure.v0' as const,
      version: 0 as const,
      parent_receipt_hash: 'c'.repeat(64),
      committed_fields_root: 'a'.repeat(64),
      disclosed_fields: ['tool'],
      hidden_fields: ['payload_digest'],
      disclosures: [],
      verifier_explanation: {
        summary: 'Selected fields disclosed.',
        disclosed: 'Disclosed fields: tool.',
        hidden: 'Hidden committed fields: payload_digest.',
        limitation: 'Not full zero-knowledge.',
      },
    };
    const bundle = createAuditBundle({
      tenant: 'test',
      receipts: [committedReceipt],
      selectiveDisclosures: [disclosure],
      signingKeys: [mockKey],
    });

    expect(bundle.receipts).toHaveLength(1);
    expect(bundle.selective_disclosures).toHaveLength(1);
    expect(bundle.privacy.selective_disclosure.statement).toContain('Undisclosed committed fields remain hidden');
    expect(bundle.verification.instructions).toContain('scopeblind.selective_disclosure.v0');
  });
});

describe('collectSignedReceipts', () => {
  it('returns empty for empty logs', () => {
    expect(collectSignedReceipts([])).toEqual([]);
  });

  it('filters for v2 logs with receipts', () => {
    const logs = [
      { v: 1 as const, tool: 'test', decision: 'allow' as const, timestamp: '', policy_digest: '' },
      {
        v: 2 as const,
        tool: 'test',
        decision: 'allow' as const,
        timestamp: '',
        policy_digest: '',
        receipt: { v: 2, type: 'decision_receipt', signature: 'x'.repeat(128), payload: {} },
      },
    ];

    const receipts = collectSignedReceipts(logs as any);
    expect(receipts).toHaveLength(1);
  });
});
