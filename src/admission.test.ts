import { describe, it, expect } from 'vitest';
import { evaluateTier, meetsMinTier } from './admission.js';
import type { ManifestPresentation } from './admission.js';

describe('evaluateTier', () => {
  it('returns unknown for null manifest', () => {
    const result = evaluateTier(null);
    expect(result.tier).toBe('unknown');
    expect(result.reason).toBe('no_manifest_presented');
  });

  it('returns unknown for invalid signature', () => {
    const result = evaluateTier({
      agent_id: 'sb:agent:test',
      manifest_hash: 'abc',
      signature_valid: false,
    });
    expect(result.tier).toBe('unknown');
    expect(result.reason).toBe('invalid_manifest_signature');
  });

  it('returns signed-known for valid manifest', () => {
    const result = evaluateTier({
      agent_id: 'sb:agent:test',
      manifest_hash: 'abc',
      signature_valid: true,
    });
    expect(result.tier).toBe('signed-known');
    expect(result.agent_id).toBe('sb:agent:test');
    expect(result.reason).toBe('valid_signed_manifest');
  });

  it('returns unknown for unverified manifest', () => {
    const result = evaluateTier({
      agent_id: 'sb:agent:test',
      manifest_hash: 'abc',
    });
    expect(result.tier).toBe('unknown');
    expect(result.reason).toBe('manifest_unverified');
  });

  it('respects operator overrides', () => {
    const result = evaluateTier(
      {
        agent_id: 'sb:agent:vip',
        manifest_hash: 'abc',
        signature_valid: true,
      },
      { 'sb:agent:vip': 'privileged' },
    );
    expect(result.tier).toBe('privileged');
    expect(result.reason).toBe('operator_override');
  });

  it('returns evidenced when evidence threshold met', () => {
    const result = evaluateTier({
      agent_id: 'sb:agent:proven',
      manifest_hash: 'abc',
      signature_valid: true,
      evidence_summary: {
        receipt_count: 15,
        epoch_span: 5,
        issuer_count: 3,
      },
    });
    expect(result.tier).toBe('evidenced');
    expect(result.reason).toBe('evidence_threshold_met');
  });

  it('stays signed-known when evidence is insufficient', () => {
    const result = evaluateTier({
      agent_id: 'sb:agent:new',
      manifest_hash: 'abc',
      signature_valid: true,
      evidence_summary: {
        receipt_count: 2,
        epoch_span: 1,
        issuer_count: 1,
      },
    });
    expect(result.tier).toBe('signed-known');
  });
});

describe('meetsMinTier', () => {
  it('unknown meets unknown', () => {
    expect(meetsMinTier('unknown', 'unknown')).toBe(true);
  });

  it('signed-known meets unknown', () => {
    expect(meetsMinTier('signed-known', 'unknown')).toBe(true);
  });

  it('unknown does not meet signed-known', () => {
    expect(meetsMinTier('unknown', 'signed-known')).toBe(false);
  });

  it('privileged meets everything', () => {
    expect(meetsMinTier('privileged', 'unknown')).toBe(true);
    expect(meetsMinTier('privileged', 'signed-known')).toBe(true);
    expect(meetsMinTier('privileged', 'evidenced')).toBe(true);
    expect(meetsMinTier('privileged', 'privileged')).toBe(true);
  });

  it('unknown meets only unknown', () => {
    expect(meetsMinTier('unknown', 'unknown')).toBe(true);
    expect(meetsMinTier('unknown', 'signed-known')).toBe(false);
    expect(meetsMinTier('unknown', 'evidenced')).toBe(false);
    expect(meetsMinTier('unknown', 'privileged')).toBe(false);
  });
});
