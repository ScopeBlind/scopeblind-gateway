import { describe, expect, it } from 'vitest';
import { buildActionReadback } from './action-readback.js';

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
});
