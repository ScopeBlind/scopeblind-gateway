// src/bundle.ts
function createAuditBundle(opts) {
  const receipts = opts.receipts.filter(
    (r) => r && typeof r === "object" && (typeof r.signature === "string" || r.signature !== null && typeof r.signature === "object")
  );
  if (receipts.length === 0) {
    throw new Error("Audit bundle requires at least one signed receipt");
  }
  const keyMap = /* @__PURE__ */ new Map();
  for (const key of opts.signingKeys) {
    if (!keyMap.has(key.kid)) {
      keyMap.set(key.kid, key);
    }
  }
  let timeRange = opts.timeRange || null;
  if (!timeRange) {
    const timestamps = receipts.map((r) => r.issued_at || r.timestamp).filter(Boolean).sort();
    if (timestamps.length > 0) {
      timeRange = {
        from: timestamps[0],
        to: timestamps[timestamps.length - 1]
      };
    }
  }
  return {
    format: "scopeblind:audit-bundle",
    version: 1,
    exported_at: (/* @__PURE__ */ new Date()).toISOString(),
    tenant: opts.tenant,
    time_range: timeRange,
    receipts,
    anchors: opts.anchors || [],
    selective_disclosures: opts.selectiveDisclosures || [],
    privacy: {
      selective_disclosure: {
        supported: true,
        model: "salted_commitments_merkle_v0",
        statement: "Committed receipts may disclose selected fields with salted Merkle openings. Undisclosed committed fields remain hidden while staying bound to the signed commitment root."
      }
    },
    verification: {
      algorithm: "ed25519",
      signing_keys: Array.from(keyMap.values()),
      instructions: `Verify each receipt by: (1) remove the "signature" field, (2) canonicalize the remaining object with JCS (sorted keys at every level), (3) encode as UTF-8 bytes, (4) verify the Ed25519 signature using the signing key matching the receipt's "kid" field. For scopeblind.selective_disclosure.v0 packages, recompute each disclosed leaf and verify it against the receipt committed_fields_root; fields not disclosed remain hidden. CLI: npx @veritasacta/verify bundle.json --bundle`
    }
  };
}
function collectSignedReceipts(logs) {
  return logs.filter((log) => log.v === 2).map((log) => {
    const logRecord = log;
    if (logRecord.receipt) {
      return logRecord.receipt;
    }
    return logRecord;
  }).filter((r) => typeof r.signature === "string");
}

export {
  createAuditBundle,
  collectSignedReceipts
};
