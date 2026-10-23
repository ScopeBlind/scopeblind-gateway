import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { buildActionReadback } from './action-readback.js';
import { canonicalize } from './acta-envelope.js';

const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

describe('buildActionReadback', () => {
  it('creates stable exact-action readbacks independent of key order', () => {
    const a = buildActionReadback('send_email', { to: 'pm@example.com', body: 'review this', action: 'send' });
    const b = buildActionReadback('send_email', { action: 'send', body: 'review this', to: 'pm@example.com' });

    expect(a.summary).toBe('send_email -> pm@example.com');
    expect(a.destination).toBe('pm@example.com');
    expect(a.action).toBe('send');
    expect(a.payload_hash).toBe(b.payload_hash);
  });

  it('redacts secret-like fields from the human preview but keeps them in the hash', () => {
    const withSecret = buildActionReadback('deploy', {
      endpoint: 'https://api.example.com',
      bearerToken: 'super-secret',
      nested: { api_key: 'sk-live-test' },
    });
    const withoutSecret = buildActionReadback('deploy', {
      endpoint: 'https://api.example.com',
      bearerToken: 'different-secret',
      nested: { api_key: 'different-key' },
    });

    expect(JSON.stringify(withSecret.payload_preview)).toContain('[redacted]');
    expect(JSON.stringify(withSecret.payload_preview)).not.toContain('super-secret');
    expect(withSecret.redacted_fields).toEqual(expect.arrayContaining(['bearerToken', 'nested.api_key']));
    expect(withSecret.payload_hash).not.toBe(withoutSecret.payload_hash);
  });

  it('is always a form a receipt can sign, whatever keys and strings the agent sends', () => {
    const inputs: unknown[] = [
      {}, // no destination field
      { query: 'weather' },
      JSON.parse('{"montant\u00e9":5,"to":"acct-1"}'),
      JSON.parse('{"amount":5,"note":"\\ud800"}'),
      JSON.parse('{"amount":5,"__proto__":{"x":1}}'),
      JSON.parse('{"\\udc00":1,"to":"\\ud800x"}'),
      { emoji: `x${'\u{1F600}'.repeat(130)}` }, // cut at 240 code units, between the halves of a pair
      JSON.parse('{"big":1e400}'),
    ];
    for (const input of inputs) {
      const readback = buildActionReadback('pay', input);
      expect(() => canonicalize(readback)).not.toThrow();
      expect('destination' in readback ? typeof readback.destination : 'absent').not.toBe('undefined');
    }
  });

  it('escapes odd keys in the preview without hiding a member, and leaves the hash on the input as sent', () => {
    const raw = '{"\\\\u00e9":"literal","\u00e9":"accented","__proto__":{"x":1}}';
    const readback = buildActionReadback('pay', JSON.parse(raw));
    const preview = readback.payload_preview as Record<string, unknown>;
    expect(Object.getPrototypeOf(preview)).toBe(Object.prototype);
    expect(Object.keys(preview)).toEqual(['\\u00e9', '\\u00e9~', '\\u005f_proto__']);
    expect(Object.values(preview)).toEqual(['literal', 'accented', { x: 1 }]);
    expect(readback.payload_hash).toBe(sha256('{"\\\\u00e9":"literal","__proto__":{"x":1},"\u00e9":"accented"}'));
  });

  it('leaves ordinary readbacks and their hashes as they were', () => {
    const readback = buildActionReadback('send_email', { to: 'pm@example.com', body: 'review this' });
    expect(readback.payload_hash).toBe(sha256('{"body":"review this","to":"pm@example.com"}'));
    expect(readback.payload_preview).toEqual({ to: 'pm@example.com', body: 'review this' });
    expect(readback.disclosed_fields).toEqual(['to', 'body']);
  });
});
