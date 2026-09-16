import { describe, expect, it } from 'vitest';
import { coordinationConfigFromArgs, validateCoordinationConfig } from './coordination-config.js';

const base = { endpoint: 'https://example.test/api/coordination', roomId: 'room-001', authorityKey: 'ab'.repeat(32), token: 'test-token' };

describe('coordination connection configuration', () => {
  it('requires an explicit pinned key and loads the token only from the selected environment variable', () => {
    const args = ['--endpoint', base.endpoint, '--room', base.roomId, '--authority-key', base.authorityKey, '--token-env', 'ROOM_EXECUTOR', '--run', 'run-room-001'];
    expect(coordinationConfigFromArgs(args, { ROOM_EXECUTOR: 'secret' })).toMatchObject({ ...base, token: 'secret', runId: 'run-room-001' });
    expect(() => coordinationConfigFromArgs(args, {})).toThrow('executor token');
    expect(() => coordinationConfigFromArgs([...args, '--token', 'secret'], {})).toThrow('Unknown coordination option');
    expect(() => validateCoordinationConfig({ ...base, authorityKey: '' })).toThrow('explicitly pinned');
  });

  it('only permits HTTPS or loopback HTTP and never puts credentials in a URL', () => {
    expect(validateCoordinationConfig({ ...base, endpoint: 'http://127.0.0.1:8788/api/coordination' }).endpoint).toContain('127.0.0.1');
    for (const endpoint of ['http://example.test/api/coordination', 'https://user:secret@example.test/api/coordination', 'https://example.test/api/coordination?token=secret', 'https://example.test/api/coordination#token']) {
      expect(() => validateCoordinationConfig({ ...base, endpoint })).toThrow();
    }
  });

  it('rejects duplicate flags, malformed values, and header injection without reflecting the token', () => {
    expect(() => coordinationConfigFromArgs(['--room', 'a', '--room', 'b'])).toThrow('once');
    expect(() => coordinationConfigFromArgs(['--room'])).toThrow('requires a value');
    expect(() => validateCoordinationConfig({ ...base, token: 'do-not-print\r\nX-Injected: true' })).toThrow('environment variable');
    expect(() => validateCoordinationConfig({ ...base, timeoutMs: 0 })).toThrow('timeout');
    for (const roomId of ['short', 'room:0001', 'r'.repeat(101)]) {
      expect(() => validateCoordinationConfig({ ...base, roomId })).toThrow(/room/i);
    }
    for (const runId of ['room-001', 'run-short', 'run-room:0001']) {
      expect(() => validateCoordinationConfig({ ...base, runId })).toThrow(/run/i);
    }
  });
});

describe('negotiation config isolation', () => {
  it('requires both a paired session and principal only for negotiation connections', () => {
    const paired = { ...base, purpose: 'negotiation' as const, sessionId: 'neg-session-001', principalKey: 'cd'.repeat(32) };
    expect(validateCoordinationConfig(paired)).toMatchObject(paired);
    for (const change of [{ sessionId: undefined }, { sessionId: 'short' }, { principalKey: undefined }, { principalKey: 'not-a-key' }, { purpose: 'execution' as const }, { purpose: 'rehearsal' as const }, { purpose: undefined }]) {
      expect(() => validateCoordinationConfig({ ...paired, ...change })).toThrow();
    }
    expect(validateCoordinationConfig(base).purpose).toBeUndefined();
  });
});
