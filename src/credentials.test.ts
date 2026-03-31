import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolveCredential, listCredentialLabels, validateCredentials } from './credentials.js';
import type { CredentialConfig } from './types.js';

describe('resolveCredential', () => {
  const savedEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it('resolves credential from env var', () => {
    process.env.TEST_SECRET = 'sk_live_test123';
    const credentials: Record<string, CredentialConfig> = {
      stripe_api: {
        inject: 'header',
        name: 'Authorization',
        value_env: 'TEST_SECRET',
      },
    };

    const result = resolveCredential('stripe_api', credentials);
    expect(result.resolved).toBe(true);
    expect(result.label).toBe('stripe_api');
    expect(result.value).toBe('sk_live_test123');
    expect(result.inject).toBe('header');
    expect(result.name).toBe('Authorization');
  });

  it('fails for unconfigured credential', () => {
    const result = resolveCredential('unknown', {});
    expect(result.resolved).toBe(false);
    expect(result.error).toContain('not configured');
  });

  it('fails for missing env var', () => {
    delete process.env.MISSING_VAR;
    const credentials: Record<string, CredentialConfig> = {
      missing: {
        inject: 'header',
        name: 'X-Api-Key',
        value_env: 'MISSING_VAR',
      },
    };

    const result = resolveCredential('missing', credentials);
    expect(result.resolved).toBe(false);
    expect(result.error).toContain('not set');
  });

  it('returns undefined for no credentials config', () => {
    const result = resolveCredential('test', undefined);
    expect(result.resolved).toBe(false);
  });
});

describe('listCredentialLabels', () => {
  it('returns labels', () => {
    const labels = listCredentialLabels({
      stripe: { inject: 'header', name: 'Auth', value_env: 'X' },
      github: { inject: 'header', name: 'Auth', value_env: 'Y' },
    });
    expect(labels).toEqual(['stripe', 'github']);
  });

  it('returns empty for undefined', () => {
    expect(listCredentialLabels(undefined)).toEqual([]);
  });
});

describe('validateCredentials', () => {
  const savedEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it('returns no warnings for valid config', () => {
    process.env.VALID_KEY = 'test';
    const warnings = validateCredentials({
      api: { inject: 'header', name: 'Auth', value_env: 'VALID_KEY' },
    });
    expect(warnings).toEqual([]);
  });

  it('warns about missing env var', () => {
    delete process.env.MISSING_KEY;
    const warnings = validateCredentials({
      api: { inject: 'header', name: 'Auth', value_env: 'MISSING_KEY' },
    });
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain('MISSING_KEY');
  });

  it('warns about missing value_env', () => {
    const warnings = validateCredentials({
      api: { inject: 'header', name: 'Auth' } as any,
    });
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain('missing value_env');
  });

  it('returns empty for undefined', () => {
    expect(validateCredentials(undefined)).toEqual([]);
  });
});
