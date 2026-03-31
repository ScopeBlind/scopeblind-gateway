/**
 * @scopeblind/protect-mcp — Audit Bundle Export
 *
 * Creates self-contained audit bundles that can be verified offline.
 * A bundle includes receipts, optional anchors, and the signing keys
 * needed to verify everything — no network calls required.
 *
 * Format:
 * {
 *   format: "scopeblind:audit-bundle",
 *   version: 1,
 *   exported_at: ISO-8601,
 *   tenant: string,
 *   time_range: { from, to },
 *   receipts: [...signed v2 artifacts...],
 *   anchors: [...optional audit anchors...],
 *   verification: {
 *     algorithm: "ed25519",
 *     signing_keys: [...JWK keys needed to verify all receipts...],
 *     instructions: "..."
 *   }
 * }
 */

import type { DecisionLog } from './types.js';

export interface AuditBundleOptions {
  /** Tenant/service identifier */
  tenant: string;
  /** Time range for exported receipts */
  timeRange?: { from: string; to: string };
  /** Signed v2 artifacts (decision_receipts and/or gateway_restraints) */
  receipts: Record<string, unknown>[];
  /** Optional audit anchors */
  anchors?: Record<string, unknown>[];
  /** JWK signing keys used by the receipts */
  signingKeys: Array<{
    kty: string;
    crv: string;
    kid: string;
    x: string;
    use?: string;
  }>;
}

export interface AuditBundle {
  format: 'scopeblind:audit-bundle';
  version: 1;
  exported_at: string;
  tenant: string;
  time_range: { from: string; to: string } | null;
  receipts: Record<string, unknown>[];
  anchors: Record<string, unknown>[];
  verification: {
    algorithm: 'ed25519';
    signing_keys: Array<{
      kty: string;
      crv: string;
      kid: string;
      x: string;
      use?: string;
    }>;
    instructions: string;
  };
}

/**
 * Create a self-contained audit bundle for offline verification.
 *
 * The bundle contains everything needed to verify all receipts:
 * - The signed receipts themselves
 * - The public keys used to sign them
 * - Verification instructions
 *
 * No network access required to verify.
 */
export function createAuditBundle(opts: AuditBundleOptions): AuditBundle {
  const receipts = opts.receipts.filter(
    (r) => r && typeof r === 'object' && typeof r.signature === 'string',
  );

  if (receipts.length === 0) {
    throw new Error('Audit bundle requires at least one signed receipt');
  }

  // Deduplicate signing keys by kid
  const keyMap = new Map<string, (typeof opts.signingKeys)[0]>();
  for (const key of opts.signingKeys) {
    if (!keyMap.has(key.kid)) {
      keyMap.set(key.kid, key);
    }
  }

  // Infer time range from receipts if not provided
  let timeRange = opts.timeRange || null;
  if (!timeRange) {
    const timestamps = receipts
      .map((r) => r.issued_at as string || r.timestamp as string)
      .filter(Boolean)
      .sort();

    if (timestamps.length > 0) {
      timeRange = {
        from: timestamps[0],
        to: timestamps[timestamps.length - 1],
      };
    }
  }

  return {
    format: 'scopeblind:audit-bundle',
    version: 1,
    exported_at: new Date().toISOString(),
    tenant: opts.tenant,
    time_range: timeRange,
    receipts,
    anchors: opts.anchors || [],
    verification: {
      algorithm: 'ed25519',
      signing_keys: Array.from(keyMap.values()),
      instructions:
        'Verify each receipt by: (1) remove the "signature" field, ' +
        '(2) canonicalize the remaining object with JCS (sorted keys at every level), ' +
        '(3) encode as UTF-8 bytes, ' +
        '(4) verify the Ed25519 signature using the signing key matching the receipt\'s "kid" field. ' +
        'CLI: npx @veritasacta/verify bundle.json --bundle',
    },
  };
}

/**
 * Collect decision log entries into signed receipts suitable for bundling.
 * Filters for entries that have attached signed artifacts.
 */
export function collectSignedReceipts(
  logs: DecisionLog[],
): Record<string, unknown>[] {
  return logs
    .filter((log) => log.v === 2)
    .map((log) => {
      // If the log has a receipt attached (from signing.ts), return it
      // Otherwise return the log itself as a record
      const logRecord = log as unknown as Record<string, unknown>;
      if (logRecord.receipt) {
        return logRecord.receipt as Record<string, unknown>;
      }
      return logRecord;
    })
    .filter((r) => typeof r.signature === 'string');
}
