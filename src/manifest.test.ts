import { describe, it, expect } from 'vitest';
import {
  isAgentId,
  isEvidenceType,
  isManifestStatus,
  isDisclosureMode,
  validateManifest,
  validateEvidenceReceipt,
} from './manifest.js';

// ============================================================
// Type guards
// ============================================================

describe('isAgentId', () => {
  it('accepts valid agent ID', () => {
    expect(isAgentId('sb:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')).toBe(true);
  });

  it('rejects wrong prefix', () => {
    expect(isAgentId('sb:coach:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')).toBe(false);
  });

  it('rejects short hash', () => {
    expect(isAgentId('sb:agent:a1b2c3d4')).toBe(false);
  });

  it('rejects uppercase hex', () => {
    expect(isAgentId('sb:agent:A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(isAgentId('')).toBe(false);
  });
});

describe('isEvidenceType', () => {
  it.each(['arena', 'benchmark', 'work', 'restraint', 'attestation'])(
    'accepts "%s"',
    (type) => {
      expect(isEvidenceType(type)).toBe(true);
    },
  );

  it('rejects unknown types', () => {
    expect(isEvidenceType('reputation')).toBe(false);
    expect(isEvidenceType('')).toBe(false);
  });
});

describe('isManifestStatus', () => {
  it.each(['active', 'suspended', 'revoked'])('accepts "%s"', (s) => {
    expect(isManifestStatus(s)).toBe(true);
  });

  it('rejects unknown statuses', () => {
    expect(isManifestStatus('deleted')).toBe(false);
  });
});

describe('isDisclosureMode', () => {
  it.each(['private', 'scoped', 'named'])('accepts "%s"', (m) => {
    expect(isDisclosureMode(m)).toBe(true);
  });

  it('rejects unknown modes', () => {
    expect(isDisclosureMode('public')).toBe(false);
  });
});

// ============================================================
// validateManifest
// ============================================================

function makeValidManifest(): Record<string, unknown> {
  const now = new Date().toISOString();
  return {
    manifest_version: '0.1',
    id: 'sb:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
    version: 1,
    previous_version: null,
    created_at: now,
    updated_at: now,
    expires_at: null,
    status: 'active',
    status_reason: null,
    status_changed_at: null,
    identity: {
      public_key: 'ed25519:abc123base64url',
      key_algorithm: 'Ed25519',
      builder: { name: 'Test Builder' },
    },
    capabilities: {
      model_family_hash: 'sha256:abc123',
      tool_categories: ['file_read', 'web_search'],
      supported_disclosure_modes: ['private', 'scoped'],
    },
    config: {
      system_prompt_hash: 'sha256:prompt123',
      tool_definitions_hash: 'sha256:tools123',
      parameters_hash: 'sha256:params123',
    },
    evidence_summary: {
      arena: { count: 5, latest_at: now, issuer: 'blindllm.com' },
      benchmark: { count: 0, latest_at: '', issuer: '' },
      work: { count: 0, latest_at: '', issuer: '' },
      restraint: { count: 0, latest_at: '', issuer: '' },
      attestation: { count: 0, latest_at: '', issuer: '' },
    },
    lease_compatibility: {},
    signature: {
      algorithm: 'Ed25519',
      signer: 'sb:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
      value: 'base64urlsignaturevalue',
    },
  };
}

describe('validateManifest', () => {
  it('returns empty array for valid manifest', () => {
    const errors = validateManifest(makeValidManifest());
    expect(errors).toEqual([]);
  });

  it('rejects null', () => {
    expect(validateManifest(null)).toEqual(['Manifest must be a non-null object']);
  });

  it('rejects non-object', () => {
    expect(validateManifest('string')).toEqual(['Manifest must be a non-null object']);
  });

  it('catches wrong manifest_version', () => {
    const m = makeValidManifest();
    m.manifest_version = '1.0';
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('manifest_version must be "0.1"'));
  });

  it('catches invalid agent ID', () => {
    const m = makeValidManifest();
    m.id = 'bad-id';
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('valid AgentId'));
  });

  it('catches non-integer version', () => {
    const m = makeValidManifest();
    m.version = 1.5;
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('positive integer'));
  });

  it('catches zero version', () => {
    const m = makeValidManifest();
    m.version = 0;
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('positive integer'));
  });

  it('catches invalid previous_version', () => {
    const m = makeValidManifest();
    m.previous_version = 'not-a-hash';
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('sha256:'));
  });

  it('allows sha256: prefixed previous_version', () => {
    const m = makeValidManifest();
    m.previous_version = 'sha256:abc123';
    expect(validateManifest(m)).toEqual([]);
  });

  it('catches invalid status', () => {
    const m = makeValidManifest();
    m.status = 'deleted';
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('status must be'));
  });

  it('catches missing identity', () => {
    const m = makeValidManifest();
    delete m.identity;
    expect(validateManifest(m)).toContainEqual('identity is required');
  });

  it('catches invalid public_key prefix', () => {
    const m = makeValidManifest();
    (m.identity as Record<string, unknown>).public_key = 'rsa:abc123';
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('ed25519:'));
  });

  it('catches invalid disclosure mode in capabilities', () => {
    const m = makeValidManifest();
    (m.capabilities as Record<string, unknown>).supported_disclosure_modes = ['private', 'public'];
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('Invalid disclosure mode'));
  });

  it('catches missing config hashes', () => {
    const m = makeValidManifest();
    (m.config as Record<string, unknown>).system_prompt_hash = 'not-sha256';
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('config.system_prompt_hash'));
  });

  it('catches missing evidence_summary entries', () => {
    const m = makeValidManifest();
    delete (m.evidence_summary as Record<string, unknown>).arena;
    expect(validateManifest(m)).toContainEqual('evidence_summary.arena is required');
  });

  it('catches missing signature', () => {
    const m = makeValidManifest();
    delete m.signature;
    expect(validateManifest(m)).toContainEqual('signature is required');
  });

  it('catches wrong signature algorithm', () => {
    const m = makeValidManifest();
    (m.signature as Record<string, unknown>).algorithm = 'RSA';
    expect(validateManifest(m)).toContainEqual(expect.stringContaining('signature.algorithm'));
  });

  it('accumulates multiple errors', () => {
    const errors = validateManifest({
      manifest_version: '2.0',
      id: 'bad',
      version: -1,
    });
    expect(errors.length).toBeGreaterThanOrEqual(3);
  });
});

// ============================================================
// validateEvidenceReceipt
// ============================================================

function makeValidReceipt(): Record<string, unknown> {
  return {
    receipt_version: '0.1',
    receipt_id: 'ev:arena:abc123',
    evidence_type: 'arena',
    agent_id: 'sb:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
    issuer: {
      id: 'blindllm.com',
      type: 'platform',
      public_key: 'ed25519:abc123',
    },
    issued_at: new Date().toISOString(),
    expires_at: null,
    freshness_window_seconds: 86400,
    payload: {
      battle_id: 'battle_123',
      opponent_hash: 'sha256:def456',
      outcome: 'win',
      platform: 'blindllm',
    },
    signature: {
      algorithm: 'Ed25519',
      signer: 'blindllm.com',
      value: 'base64urlsig',
    },
  };
}

describe('validateEvidenceReceipt', () => {
  it('returns empty array for valid receipt', () => {
    expect(validateEvidenceReceipt(makeValidReceipt())).toEqual([]);
  });

  it('rejects null', () => {
    expect(validateEvidenceReceipt(null)).toEqual(['Receipt must be a non-null object']);
  });

  it('catches wrong receipt_version', () => {
    const r = makeValidReceipt();
    r.receipt_version = '1.0';
    expect(validateEvidenceReceipt(r)).toContainEqual(expect.stringContaining('receipt_version'));
  });

  it('catches invalid evidence_type', () => {
    const r = makeValidReceipt();
    r.evidence_type = 'reputation';
    expect(validateEvidenceReceipt(r)).toContainEqual(expect.stringContaining('evidence_type'));
  });

  it('catches invalid agent_id', () => {
    const r = makeValidReceipt();
    r.agent_id = 'not-valid';
    expect(validateEvidenceReceipt(r)).toContainEqual(expect.stringContaining('AgentId'));
  });

  it('catches missing issuer', () => {
    const r = makeValidReceipt();
    delete r.issuer;
    expect(validateEvidenceReceipt(r)).toContainEqual('issuer is required');
  });

  it('catches invalid issuer public_key', () => {
    const r = makeValidReceipt();
    (r.issuer as Record<string, unknown>).public_key = 'rsa:key';
    expect(validateEvidenceReceipt(r)).toContainEqual(expect.stringContaining('ed25519:'));
  });

  it('catches missing freshness_window_seconds', () => {
    const r = makeValidReceipt();
    delete r.freshness_window_seconds;
    expect(validateEvidenceReceipt(r)).toContainEqual(expect.stringContaining('freshness_window_seconds'));
  });

  it('catches missing payload', () => {
    const r = makeValidReceipt();
    delete r.payload;
    expect(validateEvidenceReceipt(r)).toContainEqual('payload is required');
  });

  it('catches missing signature', () => {
    const r = makeValidReceipt();
    delete r.signature;
    expect(validateEvidenceReceipt(r)).toContainEqual('signature is required');
  });
});
