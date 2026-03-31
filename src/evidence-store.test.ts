import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EvidenceStore, DEFAULT_THRESHOLDS } from './evidence-store.js';
import { existsSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

describe('EvidenceStore', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'evidence-test-'));
  });

  afterEach(() => {
    const filePath = join(dir, '.protect-mcp-evidence.json');
    if (existsSync(filePath)) {
      unlinkSync(filePath);
    }
  });

  it('records and summarizes evidence for an agent', () => {
    const store = new EvidenceStore(dir);
    store.record('agent-1', 'issuer-a', '2026-03-20T10:00:00Z');
    store.record('agent-1', 'issuer-a', '2026-03-20T11:00:00Z');
    store.record('agent-1', 'issuer-b', '2026-03-20T12:00:00Z');

    const summary = store.getSummary('agent-1');
    expect(summary.receipt_count).toBe(3);
    expect(summary.epoch_span).toBe(3); // 10:xx, 11:xx, 12:xx = 3 distinct hours
    expect(summary.issuer_count).toBe(2); // issuer-a, issuer-b
  });

  it('returns zero summary for unknown agent', () => {
    const store = new EvidenceStore(dir);
    const summary = store.getSummary('nonexistent');
    expect(summary.receipt_count).toBe(0);
    expect(summary.epoch_span).toBe(0);
    expect(summary.issuer_count).toBe(0);
  });

  it('evaluates evidenced threshold correctly', () => {
    const store = new EvidenceStore(dir);

    // Not enough receipts
    for (let i = 0; i < 5; i++) {
      store.record('agent-1', 'issuer-a', `2026-03-20T${10 + i}:00:00Z`);
    }
    expect(store.meetsEvidencedThreshold('agent-1')).toBe(false);

    // Enough receipts but not enough issuers
    for (let i = 5; i < 10; i++) {
      store.record('agent-1', 'issuer-a', `2026-03-20T${10 + i}:00:00Z`);
    }
    expect(store.meetsEvidencedThreshold('agent-1')).toBe(false);

    // Add a second issuer — now meets all thresholds
    store.record('agent-1', 'issuer-b', '2026-03-21T10:00:00Z');
    const summary = store.getSummary('agent-1');
    expect(summary.receipt_count).toBe(11);
    expect(summary.issuer_count).toBe(2);
    expect(summary.epoch_span).toBeGreaterThanOrEqual(3);
    expect(store.meetsEvidencedThreshold('agent-1')).toBe(true);
  });

  it('supports custom thresholds', () => {
    const store = new EvidenceStore(dir);
    store.record('agent-1', 'issuer-a', '2026-03-20T10:00:00Z');
    store.record('agent-1', 'issuer-b', '2026-03-20T11:00:00Z');

    const lowThresholds = { min_receipts: 2, min_epoch_span: 2, min_issuers: 2 };
    expect(store.meetsEvidencedThreshold('agent-1', lowThresholds)).toBe(true);

    const highThresholds = { min_receipts: 100, min_epoch_span: 10, min_issuers: 5 };
    expect(store.meetsEvidencedThreshold('agent-1', highThresholds)).toBe(false);
  });

  it('persists and reloads', () => {
    const store1 = new EvidenceStore(dir);
    store1.record('agent-1', 'issuer-a', '2026-03-20T10:00:00Z');
    store1.record('agent-1', 'issuer-b', '2026-03-20T11:00:00Z');
    store1.save();

    // Load into a new store
    const store2 = new EvidenceStore(dir);
    const summary = store2.getSummary('agent-1');
    expect(summary.receipt_count).toBe(2);
    expect(summary.issuer_count).toBe(2);
  });

  it('caps receipts at 200 per agent', () => {
    const store = new EvidenceStore(dir);
    for (let i = 0; i < 250; i++) {
      store.record('agent-1', 'issuer-a', `2026-03-20T${String(i % 24).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:00Z`);
    }
    const summary = store.getSummary('agent-1');
    expect(summary.receipt_count).toBe(200);
  });

  it('reports agent count', () => {
    const store = new EvidenceStore(dir);
    store.record('agent-1', 'issuer-a');
    store.record('agent-2', 'issuer-b');
    expect(store.agentCount()).toBe(2);
  });
});
