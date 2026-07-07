/**
 * Locks the record viewer's in-browser verification algorithm to the real
 * signer. The viewer (RECORD_HTML + the web /record page) recomputes the
 * @veritasacta/artifacts preimage — JCS-style canonical JSON (sorted keys) of
 * the receipt minus its signature — and verifies Ed25519 over those bytes. If
 * this test passes, a receipt signed by the gate verifies in the viewer, and a
 * tampered one does not.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { initSigning, signDecision } from './signing.js';
import type { DecisionLog } from './types.js';

// The exact algorithm the viewers run (kept dependency-free there; @noble here).
function canonMirror(v: unknown): string {
  return JSON.stringify(v, (_k, x) => {
    if (x && typeof x === 'object' && !Array.isArray(x)) {
      const s: Record<string, unknown> = {};
      for (const kk of Object.keys(x as Record<string, unknown>).sort()) s[kk] = (x as Record<string, unknown>)[kk];
      return s;
    }
    return x;
  });
}
function viewerVerify(raw: Record<string, unknown>, keyOverride?: string): 'ok' | 'bad' | 'nokey' | 'unsigned' {
  if (!raw || typeof raw.signature !== 'string') return 'unsigned';
  const rest: Record<string, unknown> = {};
  for (const k of Object.keys(raw)) if (k !== 'signature') rest[k] = raw[k];
  const msg = new TextEncoder().encode(canonMirror(rest));
  const payload = rest.payload as Record<string, unknown> | undefined;
  const emb = keyOverride || String((payload && payload.public_key) || rest.public_key || '');
  if (!/^[0-9a-f]{64}$/i.test(emb)) return 'nokey';
  try {
    return ed25519.verify(hexToBytes(raw.signature as string), msg, hexToBytes(emb)) ? 'ok' : 'bad';
  } catch {
    return 'bad';
  }
}

describe('record viewer in-browser verification contract', () => {
  let publicKey = '';
  let receipt: Record<string, unknown>;

  beforeAll(async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-rv-'));
    mkdirSync(join(dir, 'keys'), { recursive: true });
    const priv = ed25519.utils.randomPrivateKey();
    publicKey = bytesToHex(ed25519.getPublicKey(priv));
    const keyPath = join(dir, 'keys', 'gateway.json');
    writeFileSync(keyPath, JSON.stringify({ privateKey: bytesToHex(priv), publicKey, kid: 'viewer-test' }));
    const warnings = await initSigning({ enabled: true, key_path: keyPath } as never);
    expect(warnings).toEqual([]);
    const entry = {
      tool: 'Write',
      decision: 'allow',
      reason_code: 'policy_ok',
      policy_digest: 'abc123',
      request_id: 'rv-1',
      mode: 'enforce',
      enrichment: { v: 1, input_digest: 'x'.repeat(64), capabilities: ['fs.write'] },
    } as unknown as DecisionLog;
    const res = signDecision(entry);
    expect(res.ok).toBe(true);
    receipt = JSON.parse(res.signed as string);
  });

  it('receipts embed the signer public key inside the signed payload', () => {
    const payload = receipt.payload as Record<string, unknown>;
    expect(payload.public_key).toBe(publicKey);
  });

  it('the viewer algorithm verifies a real receipt via its embedded key and via a pinned key', () => {
    expect(viewerVerify(receipt)).toBe('ok');
    expect(viewerVerify(receipt, publicKey)).toBe('ok');
  });

  it('tampering any field (even deep in enrichment) breaks verification', () => {
    const t1 = JSON.parse(JSON.stringify(receipt));
    (t1.payload as Record<string, unknown>).decision = 'deny';
    expect(viewerVerify(t1)).toBe('bad');
    const t2 = JSON.parse(JSON.stringify(receipt));
    ((t2.payload as Record<string, unknown>).enrichment as Record<string, unknown>).capabilities = [];
    expect(viewerVerify(t2)).toBe('bad');
  });

  it('a swapped embedded key or wrong pinned key does not verify', () => {
    const swapped = JSON.parse(JSON.stringify(receipt));
    const stranger = bytesToHex(ed25519.getPublicKey(ed25519.utils.randomPrivateKey()));
    (swapped.payload as Record<string, unknown>).public_key = stranger;
    // the key sits INSIDE the signed payload, so swapping it breaks the signature
    expect(viewerVerify(swapped)).toBe('bad');
    expect(viewerVerify(receipt, stranger)).toBe('bad');
  });

  it('receipts without a key are honestly "nokey", unsigned lines are "unsigned"', () => {
    const old = JSON.parse(JSON.stringify(receipt));
    delete (old.payload as Record<string, unknown>).public_key;
    expect(viewerVerify(old)).toBe('nokey'); // pre-0.9.3 receipt without a pinned key
    expect(viewerVerify({ v: 2, type: 'decision_log' })).toBe('unsigned');
  });
});
