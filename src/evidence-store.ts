/**
 * @scopeblind/protect-mcp — Evidence Store
 *
 * File-based evidence store that tracks receipt history per agent.
 * Used by the admission evaluator to promote agents to the 'evidenced' tier
 * based on accumulated verified receipts.
 *
 * Storage: .protect-mcp-evidence.json in cwd
 * Format: { agents: { [agentId]: EvidenceRecord } }
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * A single receipt observation for an agent.
 */
export interface ReceiptObservation {
  /** Issuer of the receipt (e.g., protect-mcp instance kid) */
  issuer: string;
  /** ISO timestamp */
  timestamp: string;
  /** Epoch hour (for epoch_span calculation) */
  epoch_hour: number;
}

/**
 * Accumulated evidence for a single agent.
 */
export interface EvidenceRecord {
  agent_id: string;
  receipts: ReceiptObservation[];
  first_seen: string;
  last_seen: string;
}

/**
 * Summary of evidence for tier evaluation.
 */
export interface EvidenceSummary {
  receipt_count: number;
  epoch_span: number;
  issuer_count: number;
}

/**
 * Thresholds for the 'evidenced' tier.
 */
export interface EvidenceThresholds {
  min_receipts: number;
  min_epoch_span: number;
  min_issuers: number;
}

export const DEFAULT_THRESHOLDS: EvidenceThresholds = {
  min_receipts: 10,
  min_epoch_span: 3,
  min_issuers: 2,
};

/**
 * Evidence store — tracks receipt history per agent.
 */
export class EvidenceStore {
  private agents: Map<string, EvidenceRecord> = new Map();
  private filePath: string;
  private dirty = false;

  constructor(dir?: string) {
    this.filePath = join(dir || process.cwd(), '.protect-mcp-evidence.json');
    this.load();
  }

  /**
   * Record a receipt observation for an agent.
   */
  record(agentId: string, issuer: string, timestamp?: string): void {
    const ts = timestamp || new Date().toISOString();
    const epochHour = Math.floor(new Date(ts).getTime() / (3600 * 1000));

    const existing = this.agents.get(agentId);
    const observation: ReceiptObservation = {
      issuer,
      timestamp: ts,
      epoch_hour: epochHour,
    };

    if (existing) {
      existing.receipts.push(observation);
      existing.last_seen = ts;
      // Keep at most 200 most recent observations to bound file size
      if (existing.receipts.length > 200) {
        existing.receipts = existing.receipts.slice(-200);
      }
    } else {
      this.agents.set(agentId, {
        agent_id: agentId,
        receipts: [observation],
        first_seen: ts,
        last_seen: ts,
      });
    }

    this.dirty = true;
  }

  /**
   * Get the evidence summary for an agent.
   */
  getSummary(agentId: string): EvidenceSummary {
    const record = this.agents.get(agentId);
    if (!record || record.receipts.length === 0) {
      return { receipt_count: 0, epoch_span: 0, issuer_count: 0 };
    }

    const uniqueIssuers = new Set(record.receipts.map(r => r.issuer));
    const uniqueEpochs = new Set(record.receipts.map(r => r.epoch_hour));

    return {
      receipt_count: record.receipts.length,
      epoch_span: uniqueEpochs.size,
      issuer_count: uniqueIssuers.size,
    };
  }

  /**
   * Check if an agent meets the evidenced tier thresholds.
   */
  meetsEvidencedThreshold(
    agentId: string,
    thresholds: EvidenceThresholds = DEFAULT_THRESHOLDS,
  ): boolean {
    const summary = this.getSummary(agentId);
    return (
      summary.receipt_count >= thresholds.min_receipts &&
      summary.epoch_span >= thresholds.min_epoch_span &&
      summary.issuer_count >= thresholds.min_issuers
    );
  }

  /**
   * Persist to disk (call periodically or on shutdown).
   */
  save(): void {
    if (!this.dirty) return;

    const data: Record<string, EvidenceRecord> = {};
    for (const [id, record] of this.agents) {
      data[id] = record;
    }

    try {
      writeFileSync(this.filePath, JSON.stringify({ v: 1, agents: data }, null, 2) + '\n');
      this.dirty = false;
    } catch {
      // Silently fail — evidence store is best-effort
    }
  }

  /**
   * Load from disk.
   */
  private load(): void {
    if (!existsSync(this.filePath)) return;

    try {
      const raw = readFileSync(this.filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (parsed.agents && typeof parsed.agents === 'object') {
        for (const [id, record] of Object.entries(parsed.agents)) {
          this.agents.set(id, record as EvidenceRecord);
        }
      }
    } catch {
      // Corrupted file — start fresh
    }
  }

  /**
   * Get total agent count (for status display).
   */
  agentCount(): number {
    return this.agents.size;
  }

  /**
   * Get all agent summaries (for status display).
   */
  allSummaries(): Array<{ agent_id: string; summary: EvidenceSummary }> {
    const result: Array<{ agent_id: string; summary: EvidenceSummary }> = [];
    for (const [id] of this.agents) {
      result.push({ agent_id: id, summary: this.getSummary(id) });
    }
    return result;
  }
}
