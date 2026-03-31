/**
 * protect-mcp simulate — dry-run policy evaluation
 *
 * Reads a recorded log file (.protect-mcp-log.jsonl) and evaluates
 * each tool call against a policy file. Shows what would have been
 * blocked, rate-limited, or approved — without wrapping a live server.
 *
 * Usage:
 *   npx protect-mcp simulate --policy strict.json [--log .protect-mcp-log.jsonl] [--json]
 */

import { readFileSync } from 'node:fs';
import { getToolPolicy, parseRateLimit, checkRateLimit } from './policy.js';
import { meetsMinTier } from './admission.js';
import type { ProtectPolicy, TrustTier } from './types.js';

export interface LogEntry {
  v: number;
  tool: string;
  decision: string;
  reason_code: string;
  mode: string;
  timestamp: number;
  tier?: string;
  rate_limit_remaining?: number;
  [key: string]: unknown;
}

export interface SimulationResult {
  tool: string;
  calls: number;
  results: {
    allow: number;
    block: number;
    rate_limited: number;
    require_approval: number;
    tier_insufficient: number;
  };
  original: {
    allow: number;
    deny: number;
  };
}

export interface SimulationSummary {
  policy_file: string;
  log_file: string;
  total_calls: number;
  results: {
    allow: number;
    block: number;
    rate_limited: number;
    require_approval: number;
    tier_insufficient: number;
  };
  original: {
    allow: number;
    deny: number;
  };
  tool_breakdown: SimulationResult[];
  changes: string[];
}

/**
 * Parse a JSONL log file into log entries.
 */
export function parseLogFile(path: string): LogEntry[] {
  const raw = readFileSync(path, 'utf-8');
  const entries: LogEntry[] = [];

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Strip [PROTECT_MCP] prefix if present
    const jsonStr = trimmed.replace(/^\[PROTECT_MCP\]\s*/, '');

    try {
      const parsed = JSON.parse(jsonStr);
      if (parsed.tool && parsed.decision) {
        entries.push(parsed as LogEntry);
      }
    } catch {
      // Skip malformed lines
    }
  }

  return entries;
}

/**
 * Simulate a policy against a set of log entries.
 * Evaluates each entry against the policy's per-tool rules,
 * including block, rate_limit, min_tier, and require_approval.
 */
export function simulate(
  entries: LogEntry[],
  policy: ProtectPolicy,
  tier: TrustTier = 'unknown',
): SimulationSummary {
  const rateLimitStore = new Map<string, number[]>();
  const toolResults = new Map<string, SimulationResult>();

  const totals = {
    allow: 0,
    block: 0,
    rate_limited: 0,
    require_approval: 0,
    tier_insufficient: 0,
  };

  const originalTotals = { allow: 0, deny: 0 };
  const changes: string[] = [];

  for (const entry of entries) {
    const toolName = entry.tool;
    const toolPolicy = getToolPolicy(toolName, policy);

    // Track original decision
    if (entry.decision === 'allow') {
      originalTotals.allow++;
    } else {
      originalTotals.deny++;
    }

    // Evaluate new decision
    let newDecision: 'allow' | 'block' | 'rate_limited' | 'require_approval' | 'tier_insufficient';

    if (toolPolicy.block) {
      newDecision = 'block';
    } else if (toolPolicy.min_tier && !meetsMinTier(tier, toolPolicy.min_tier as TrustTier)) {
      newDecision = 'tier_insufficient';
    } else if ((toolPolicy as { require_approval?: boolean }).require_approval) {
      newDecision = 'require_approval';
    } else if (toolPolicy.rate_limit) {
      const limit = parseRateLimit(toolPolicy.rate_limit);
      const result = checkRateLimit(toolName, limit, rateLimitStore);
      newDecision = result.allowed ? 'allow' : 'rate_limited';
    } else {
      newDecision = 'allow';
    }

    totals[newDecision]++;

    // Track per-tool results
    if (!toolResults.has(toolName)) {
      toolResults.set(toolName, {
        tool: toolName,
        calls: 0,
        results: { allow: 0, block: 0, rate_limited: 0, require_approval: 0, tier_insufficient: 0 },
        original: { allow: 0, deny: 0 },
      });
    }
    const tr = toolResults.get(toolName)!;
    tr.calls++;
    tr.results[newDecision]++;
    if (entry.decision === 'allow') {
      tr.original.allow++;
    } else {
      tr.original.deny++;
    }
  }

  // Compute changes
  for (const [tool, result] of toolResults) {
    const wasAllBlocked = result.original.allow === 0;
    const nowAllBlocked = result.results.allow === 0;
    const wasAllAllowed = result.original.deny === 0;

    if (wasAllAllowed && result.results.block > 0) {
      changes.push(`${tool}: ${result.results.block} calls would be blocked (was: all allowed)`);
    }
    if (wasAllAllowed && result.results.rate_limited > 0) {
      changes.push(`${tool}: ${result.results.rate_limited} calls would be rate-limited (was: all allowed)`);
    }
    if (wasAllAllowed && result.results.require_approval > 0) {
      changes.push(`${tool}: ${result.results.require_approval} calls would require approval (was: all allowed)`);
    }
    if (wasAllAllowed && result.results.tier_insufficient > 0) {
      changes.push(`${tool}: ${result.results.tier_insufficient} calls would fail tier check (was: all allowed)`);
    }
    if (wasAllBlocked && result.results.allow > 0 && !nowAllBlocked) {
      changes.push(`${tool}: ${result.results.allow} calls would now be allowed (was: all blocked)`);
    }
  }

  return {
    policy_file: '',
    log_file: '',
    total_calls: entries.length,
    results: totals,
    original: originalTotals,
    tool_breakdown: Array.from(toolResults.values()).sort((a, b) => b.calls - a.calls),
    changes,
  };
}

/**
 * Format simulation results for terminal output.
 */
export function formatSimulation(summary: SimulationSummary): string {
  const lines: string[] = [];

  lines.push(`Simulating ${summary.policy_file} against ${summary.total_calls} recorded tool calls:\n`);

  // Tool breakdown table
  const maxToolLen = Math.max(...summary.tool_breakdown.map(t => t.tool.length), 4);

  for (const tr of summary.tool_breakdown) {
    const parts: string[] = [];
    if (tr.results.allow > 0) parts.push(`${tr.results.allow} allow`);
    if (tr.results.block > 0) parts.push(`\x1b[31m${tr.results.block} blocked\x1b[0m`);
    if (tr.results.rate_limited > 0) parts.push(`\x1b[33m${tr.results.rate_limited} rate_limited\x1b[0m`);
    if (tr.results.require_approval > 0) parts.push(`\x1b[36m${tr.results.require_approval} require_approval\x1b[0m`);
    if (tr.results.tier_insufficient > 0) parts.push(`\x1b[35m${tr.results.tier_insufficient} tier_insufficient\x1b[0m`);

    const originalParts: string[] = [];
    if (tr.original.allow > 0) originalParts.push(`${tr.original.allow} allow`);
    if (tr.original.deny > 0) originalParts.push(`${tr.original.deny} deny`);

    lines.push(`  ${tr.tool.padEnd(maxToolLen)}  × ${String(tr.calls).padStart(3)} → ${parts.join(', ')}  (was: ${originalParts.join(', ')})`);
  }

  lines.push('');
  lines.push(`Summary: ${summary.results.allow} allow, ${summary.results.block} blocked, ${summary.results.rate_limited} rate_limited, ${summary.results.require_approval} require_approval, ${summary.results.tier_insufficient} tier_insufficient`);
  lines.push(`  vs original: ${summary.original.allow} allow, ${summary.original.deny} deny`);

  if (summary.changes.length > 0) {
    lines.push('');
    lines.push('Changes:');
    for (const change of summary.changes) {
      lines.push(`  • ${change}`);
    }
  }

  return lines.join('\n');
}
