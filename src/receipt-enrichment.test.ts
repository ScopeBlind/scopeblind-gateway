import { describe, it, expect } from 'vitest';
import {
  buildEnrichment,
  canonicalJson,
  deriveCapabilities,
  derivePayment,
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

  it('payment capability fires on x402 wire shapes and payment-shaped tools (broad by design)', () => {
    // x402 402-response requirements
    expect(deriveCapabilities('WebFetch', { paymentRequirements: { scheme: 'exact', maxAmountRequired: '10000', payTo: '0xAbC' } })).toContain('payment');
    // x402 retry with proof of payment (header name in input)
    expect(deriveCapabilities('http_request', { headers: { 'X-PAYMENT': 'eyJ4NDAyVmVyc2lvbiI6MX0' } })).toContain('payment');
    // EIP-3009 transferWithAuthorization
    expect(deriveCapabilities('eth_call', { method: 'transferWithAuthorization', authorization: { to: '0xdef', value: '10000' } })).toContain('payment');
    // payment-shaped tool names
    expect(deriveCapabilities('wallet_send_payment', { to: 'merchant', amount: 1.5 })).toContain('payment');
    expect(deriveCapabilities('x402_pay', {})).toContain('payment');
    // NOT on ordinary calls
    expect(deriveCapabilities('Read', { file_path: '/a.ts' })).not.toContain('payment');
    expect(deriveCapabilities('WebFetch', { url: 'https://example.com' })).not.toContain('payment');
  });

  it('derivePayment extracts amount only when clearly human units; recipient is hashed', () => {
    const p1 = derivePayment('wallet_send_payment', { to: 'merchant.eth', amount: 1.5, asset: 'USDC' });
    expect(p1).toBeTruthy();
    expect(p1!.amount).toBe(1.5);
    expect(p1!.asset).toBe('USDC');
    expect(p1!.recipient_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(p1)).not.toContain('merchant'); // position-blind

    // atomic-unit x402 value: decimals unknown -> amount stays null (counts as over-cap in claims)
    const p2 = derivePayment('WebFetch', { paymentRequirements: { scheme: 'exact', maxAmountRequired: '10000', payTo: '0xabc', asset: '0xA0b8...' } });
    expect(p2).toBeTruthy();
    expect(p2!.amount).toBe(null);
    expect(p2!.scheme).toBe('exact');

    // decimal string amounts are human units
    const p3 = derivePayment('create_payment', { amount: '12.50', pay_to: 'acct_1' });
    expect(p3!.amount).toBe(12.5);

    // non-payment input -> undefined (no payment block on ordinary receipts)
    expect(derivePayment('Read', { file_path: '/a.ts' })).toBeUndefined();
    expect(buildEnrichment('Read', { file_path: '/a.ts' }).payment).toBeUndefined();
    expect(buildEnrichment('wallet_send_payment', { to: 'm', amount: 2 }).payment).toBeTruthy();
  });
});
