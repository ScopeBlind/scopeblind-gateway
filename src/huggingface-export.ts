/**
 * Hugging Face Dataset Export
 *
 * Exports Veritas Acta receipt chains as HF-compatible datasets.
 * Produces JSONL format with structured fields for ML research.
 *
 * Usage:
 *   npx protect-mcp export-hf --output dataset.jsonl
 *   npx protect-mcp export-hf --output dataset.jsonl --format parquet
 */

export interface HFReceiptRow {
  /** Unique receipt identifier */
  receipt_id: string;
  /** Receipt type: decision, execution, outcome, policy_load, observation, approval */
  receipt_type: string;
  /** Tool that was called */
  tool_name: string | null;
  /** Decision verdict: allow, deny, null */
  decision: string | null;
  /** Agent identifier (pseudonymous) */
  agent_id: string | null;
  /** Issuer identifier */
  issuer_id: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** SHA-256 hash of the active policy at decision time */
  policy_hash: string | null;
  /** Typed causal edges to other receipts */
  edges: Array<{ receipt_id: string; relation: string }>;
  /** Number of edges (for quick filtering) */
  edge_count: number;
  /** Ed25519 signature (hex) */
  signature: string | null;
  /** Whether the receipt has a valid signature */
  signed: boolean;
  /** Context hash for selective disclosure */
  context_hash: string | null;
  /** Chain ID linking related receipts */
  chain_id: string | null;
}

export interface HFDatasetMetadata {
  /** Dataset name */
  name: string;
  /** Description */
  description: string;
  /** Number of rows */
  num_rows: number;
  /** Receipt type distribution */
  type_distribution: Record<string, number>;
  /** Decision distribution */
  decision_distribution: Record<string, number>;
  /** Time range */
  time_range: { from: string; to: string };
  /** Unique agents */
  unique_agents: number;
  /** Unique tools */
  unique_tools: number;
  /** Export timestamp */
  exported_at: string;
  /** License */
  license: "MIT";
  /** Tags for HF Hub */
  tags: string[];
}

/**
 * Convert raw receipt objects to HF-compatible rows.
 */
export function receiptsToHFRows(receipts: Record<string, unknown>[]): HFReceiptRow[] {
  return receipts.map((r) => {
    const raw = r as Record<string, unknown>;
    const payload = (raw.payload || {}) as Record<string, unknown>;
    const edges = Array.isArray(raw.parent_receipts)
      ? (raw.parent_receipts as Array<{ receipt_id: string; relation: string }>)
      : [];

    return {
      receipt_id: String(raw.receipt_id || raw.id || ""),
      receipt_type: String(raw.receipt_type || raw.type || "unknown"),
      tool_name: payload.tool_name ? String(payload.tool_name) : null,
      decision: payload.decision ? String(payload.decision) : null,
      agent_id: payload.agent_id ? String(payload.agent_id) : raw.subject_id ? String(raw.subject_id) : null,
      issuer_id: String(raw.issuer_id || "unknown"),
      timestamp: String(raw.timestamp || raw.event_time || new Date().toISOString()),
      policy_hash: payload.active_policy_hash ? String(payload.active_policy_hash) : null,
      edges,
      edge_count: edges.length,
      signature: raw.signature ? String(raw.signature) : null,
      signed: Boolean(raw.signature),
      context_hash: raw.context_hash ? String(raw.context_hash) : null,
      chain_id: raw.chain_id ? String(raw.chain_id) : null,
    };
  });
}

/**
 * Generate dataset metadata for HF Hub.
 */
export function generateHFMetadata(rows: HFReceiptRow[], name?: string): HFDatasetMetadata {
  const types: Record<string, number> = {};
  const decisions: Record<string, number> = {};
  const agents = new Set<string>();
  const tools = new Set<string>();
  let minTime = Infinity;
  let maxTime = -Infinity;

  for (const row of rows) {
    types[row.receipt_type] = (types[row.receipt_type] || 0) + 1;
    if (row.decision) decisions[row.decision] = (decisions[row.decision] || 0) + 1;
    if (row.agent_id) agents.add(row.agent_id);
    if (row.tool_name) tools.add(row.tool_name);
    const t = new Date(row.timestamp).getTime();
    if (t < minTime) minTime = t;
    if (t > maxTime) maxTime = t;
  }

  return {
    name: name || "scopeblind-acta-receipts",
    description: "Cryptographically signed decision receipts from AI agent tool calls. Each row is an Ed25519-signed receipt capturing a machine decision, its causal context, and policy evaluation result. Produced by protect-mcp and verified with @veritasacta/verify.",
    num_rows: rows.length,
    type_distribution: types,
    decision_distribution: decisions,
    time_range: {
      from: isFinite(minTime) ? new Date(minTime).toISOString() : "",
      to: isFinite(maxTime) ? new Date(maxTime).toISOString() : "",
    },
    unique_agents: agents.size,
    unique_tools: tools.size,
    exported_at: new Date().toISOString(),
    license: "MIT",
    tags: [
      "ai-safety",
      "agent-governance",
      "cryptographic-receipts",
      "veritas-acta",
      "scopeblind",
      "mcp",
      "ed25519",
      "causal-dag",
      "decision-evidence",
    ],
  };
}

/**
 * Export receipts as JSONL (one JSON object per line).
 */
export function exportJSONL(rows: HFReceiptRow[]): string {
  return rows.map((row) => JSON.stringify(row)).join("\n") + "\n";
}

/**
 * Generate a HuggingFace dataset card (README.md) for the dataset repo.
 */
export function generateDatasetCard(metadata: HFDatasetMetadata): string {
  return `---
license: mit
task_categories:
  - text-classification
tags:
${metadata.tags.map((t) => `  - ${t}`).join("\n")}
size_categories:
  - ${metadata.num_rows < 1000 ? "n<1K" : metadata.num_rows < 10000 ? "1K<n<10K" : "10K<n<100K"}
---

# ${metadata.name}

${metadata.description}

## Dataset Structure

Each row is a cryptographically signed receipt representing a single machine decision.

| Field | Type | Description |
|-------|------|-------------|
| receipt_id | string | Unique receipt identifier (content-addressed hash) |
| receipt_type | string | decision, execution, outcome, policy_load, observation, approval |
| tool_name | string | MCP tool that was called |
| decision | string | allow, deny, or null |
| agent_id | string | Pseudonymous agent identifier |
| timestamp | string | ISO 8601 timestamp |
| policy_hash | string | SHA-256 hash of the active policy |
| edges | array | Typed causal edges to parent receipts |
| signature | string | Ed25519 signature (hex) |
| signed | boolean | Whether the receipt has a valid signature |

## Statistics

- **Total receipts:** ${metadata.num_rows.toLocaleString()}
- **Unique agents:** ${metadata.unique_agents}
- **Unique tools:** ${metadata.unique_tools}
- **Time range:** ${metadata.time_range.from} → ${metadata.time_range.to}

### Type distribution
${Object.entries(metadata.type_distribution).map(([k, v]) => `- ${k}: ${v}`).join("\n")}

### Decision distribution
${Object.entries(metadata.decision_distribution).map(([k, v]) => `- ${k}: ${v}`).join("\n")}

## Verification

Every receipt in this dataset can be independently verified:

\`\`\`bash
npx @veritasacta/verify receipt.json
\`\`\`

The verification is offline, MIT-licensed, and does not contact any server.

## Source

- Protocol: [Veritas Acta](https://veritasacta.com)
- Gateway: [protect-mcp](https://npmjs.com/package/protect-mcp)
- IETF Draft: [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)

## License

MIT
`;
}
