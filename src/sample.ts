/**
 * `protect-mcp sample`: seed a clearly-labeled sample record so anyone can
 * replay the public demo (record / claim / verify-claim / anchor-record) in an
 * empty folder, before wiring the gate in front of a real agent.
 *
 * The receipts are REAL signed artifacts: a fresh Ed25519 keypair, the same
 * envelope shape and canonical-JSON preimage the gate's signer produces, so
 * every verifier in the product (the record viewer's in-browser check, claim,
 * verify-claim, npx @veritasacta/verify) treats them exactly like gate output.
 * They are labeled sample by kid and policy_digest ("sample-demo"), and this
 * module refuses to touch an existing record or signing key.
 *
 * The set mirrors the public demo film: 8 decisions, one BLOCKED network call
 * (prevention, not detection), and two payments (a $0.02 x402-style per-call
 * payment and a $12.50 invoice) so `claim --payment-under 100` holds and
 * `claim --payment-under 10` honestly refuses.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { canonicalJson } from './receipt-enrichment.js';

export const SAMPLE_KID = 'sample-demo';

export interface SampleEnvelope {
  v: 2;
  type: 'decision_receipt' | 'gateway_restraint';
  algorithm: 'ed25519';
  kid: string;
  issuer: string;
  issued_at: string;
  payload: Record<string, unknown>;
  signature: string;
}

export interface SampleKit {
  dir: string;
  publicKey: string;
  kid: string;
  receipts: SampleEnvelope[];
  paymentsUsd: number[];
  files: string[];
}

const sha256Hex = (s: string): string => bytesToHex(sha256(new TextEncoder().encode(s)));

function signEnvelope(unsigned: Omit<SampleEnvelope, 'signature'>, privHex: string): SampleEnvelope {
  const msg = new TextEncoder().encode(canonicalJson(unsigned));
  const signature = bytesToHex(ed25519.sign(msg, hexToBytes(privHex)));
  return { ...unsigned, signature };
}

/** Throws { code: 'SAMPLE_EXISTS' } if the folder already holds a record or key (unless force). */
export function buildSampleKit(dir: string, opts?: { force?: boolean; now?: Date }): SampleKit {
  const receiptsPath = join(dir, '.protect-mcp-receipts.jsonl');
  const keyPath = join(dir, 'keys', 'gateway.json');
  if (!opts?.force && (existsSync(receiptsPath) || existsSync(keyPath))) {
    throw Object.assign(
      new Error(`refusing to overwrite an existing record or signing key in ${dir}`),
      { code: 'SAMPLE_EXISTS' },
    );
  }

  mkdirSync(join(dir, 'keys'), { recursive: true });
  const priv = ed25519.utils.randomPrivateKey();
  const privHex = bytesToHex(priv);
  const pub = bytesToHex(ed25519.getPublicKey(priv));
  writeFileSync(keyPath, JSON.stringify({ privateKey: privHex, publicKey: pub, kid: SAMPLE_KID }, null, 2));
  writeFileSync(join(dir, 'keys', '.gitignore'), '# Never commit signing keys\n*.json\n');

  const now = opts?.now ?? new Date();
  const stamp = (i: number): string => new Date(now.getTime() - (7 - i) * 5 * 60_000).toISOString();

  const receipt = (
    i: number,
    tool: string,
    decision: 'allow' | 'deny',
    caps: string[],
    extra?: Record<string, unknown>,
  ): SampleEnvelope => {
    const ts = stamp(i);
    const payload: Record<string, unknown> = {
      tool,
      decision,
      reason_code: decision === 'deny' ? 'policy_deny' : 'policy_ok',
      policy_digest: SAMPLE_KID,
      scope: `${tool}-${ts}`,
      mode: 'enforce',
      request_id: `${tool}-${ts}`,
      spec: 'draft-farley-acta-signed-receipts-01',
      issuer_certification: 'self-signed',
      public_key: pub,
      hook_event: 'PreToolUse',
      enrichment: { v: 2, input_digest: sha256Hex(tool + ts), capabilities: caps, ...(extra || {}) },
    };
    return signEnvelope({
      v: 2,
      type: decision === 'deny' ? 'gateway_restraint' : 'decision_receipt',
      algorithm: 'ed25519',
      kid: SAMPLE_KID,
      issuer: 'protect-mcp',
      issued_at: ts,
      payload,
    }, privHex);
  };
  const pay = (amount: number): Record<string, unknown> => ({
    payment: { amount, asset: 'USDC', recipient_digest: sha256Hex('sample-merchant'), scheme: 'exact' },
  });

  const rows: SampleEnvelope[] = [
    receipt(0, 'Read', 'allow', ['fs.read']),
    receipt(1, 'Bash', 'allow', ['exec.shell']),
    receipt(2, 'Write', 'allow', ['fs.write']),
    receipt(3, 'WebFetch', 'deny', ['net.egress']),
    receipt(4, 'x402_pay', 'allow', ['financial', 'payment'], pay(0.02)),
    receipt(5, 'Read', 'allow', ['fs.read', 'secret.adjacent']),
    receipt(6, 'wallet_send_payment', 'allow', ['financial', 'payment'], pay(12.5)),
    receipt(7, 'Bash', 'allow', ['exec.shell', 'vcs']),
  ];
  writeFileSync(receiptsPath, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');

  // Tampered copy: flip the DENIED egress to "allow" AFTER signing. The record
  // viewer flags exactly this row as an invalid signature (the tamper beat).
  const tampered = rows.map((r) => JSON.parse(JSON.stringify(r)) as SampleEnvelope);
  (tampered[3].payload as { decision?: string }).decision = 'allow';
  writeFileSync(join(dir, 'demo-tampered.jsonl'), tampered.map((r) => JSON.stringify(r)).join('\n') + '\n');

  return {
    dir,
    publicKey: pub,
    kid: SAMPLE_KID,
    receipts: rows,
    paymentsUsd: [0.02, 12.5],
    files: ['.protect-mcp-receipts.jsonl', 'demo-tampered.jsonl', 'keys/gateway.json'],
  };
}
