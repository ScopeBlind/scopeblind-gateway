/**
 * protect-mcp report — compliance report generation
 *
 * Generates structured compliance reports from local log and receipt files.
 * Output as JSON (machine-readable) or Markdown (human-readable, PDF-convertible).
 *
 * Usage:
 *   npx protect-mcp report --period 30d --output report.json
 *   npx protect-mcp report --period 30d --format md --output report.md
 */

import { readFileSync, existsSync } from 'node:fs';

export interface ComplianceReport {
  generated_at: string;
  period: { from: string; to: string };
  signing_identity: { kid: string; issuer: string } | null;
  summary: {
    total_decisions: number;
    allowed: number;
    blocked: number;
    rate_limited: number;
    approval_required: number;
    unique_tools: number;
    unique_tiers: number;
  };
  tool_breakdown: Array<{
    tool: string;
    total: number;
    allowed: number;
    blocked: number;
    rate_limited: number;
    approval_required: number;
  }>;
  policy_changes: Array<{
    at: string;
    policy_digest: string;
  }>;
  verification: {
    receipts_signed: number;
    receipts_unsigned: number;
    verify_command: string;
  };
}

interface LogEntry {
  tool: string;
  decision: string;
  reason_code?: string;
  timestamp: number;
  policy_digest?: string;
  tier?: string;
  [key: string]: unknown;
}

/**
 * Generate a compliance report from local log and receipt files.
 */
export function generateReport(
  logPath: string,
  receiptPath: string,
  periodDays: number,
): ComplianceReport {
  const now = new Date();
  const from = new Date(now.getTime() - periodDays * 86_400_000);

  // Parse log entries
  const entries: LogEntry[] = [];
  if (existsSync(logPath)) {
    const raw = readFileSync(logPath, 'utf-8');
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const jsonStr = trimmed.replace(/^\[PROTECT_MCP\]\s*/, '');
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed.tool && parsed.decision && parsed.timestamp) {
          // Filter by period
          const entryTime = typeof parsed.timestamp === 'number' && parsed.timestamp > 1e12
            ? parsed.timestamp
            : parsed.timestamp * 1000; // handle seconds vs ms
          if (entryTime >= from.getTime()) {
            entries.push(parsed as LogEntry);
          }
        }
      } catch {
        // Skip malformed
      }
    }
  }

  // Count signed receipts
  let receiptsSigned = 0;
  let signerKid = '';
  let signerIssuer = '';
  if (existsSync(receiptPath)) {
    const raw = readFileSync(receiptPath, 'utf-8');
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.signature) {
          receiptsSigned++;
          if (parsed.kid && !signerKid) signerKid = parsed.kid;
          if (parsed.issuer && !signerIssuer) signerIssuer = parsed.issuer;
        }
      } catch {
        // Skip
      }
    }
  }

  // Compute summary
  const toolMap = new Map<string, { total: number; allowed: number; blocked: number; rate_limited: number; approval_required: number }>();
  const tiers = new Set<string>();
  const policyDigests = new Map<string, string>(); // digest → earliest timestamp
  let allowed = 0;
  let blocked = 0;
  let rateLimited = 0;
  let approvalRequired = 0;

  for (const entry of entries) {
    const tool = entry.tool;
    if (!toolMap.has(tool)) {
      toolMap.set(tool, { total: 0, allowed: 0, blocked: 0, rate_limited: 0, approval_required: 0 });
    }
    const tm = toolMap.get(tool)!;
    tm.total++;

    if (entry.decision === 'allow') { allowed++; tm.allowed++; }
    else if (entry.decision === 'deny' && entry.reason_code === 'rate_limit_exceeded') { rateLimited++; tm.rate_limited++; }
    else if (entry.decision === 'deny' && entry.reason_code === 'require_approval') { approvalRequired++; tm.approval_required++; }
    else { blocked++; tm.blocked++; }

    if (entry.tier) tiers.add(entry.tier);
    if (entry.policy_digest && !policyDigests.has(entry.policy_digest)) {
      policyDigests.set(entry.policy_digest, new Date(entry.timestamp).toISOString());
    }
  }

  // Policy changes (dedup by digest, show first appearance)
  const policyChanges = Array.from(policyDigests.entries()).map(([digest, at]) => ({
    at,
    policy_digest: digest,
  })).sort((a, b) => a.at.localeCompare(b.at));

  return {
    generated_at: now.toISOString(),
    period: { from: from.toISOString(), to: now.toISOString() },
    signing_identity: signerKid ? { kid: signerKid, issuer: signerIssuer } : null,
    summary: {
      total_decisions: entries.length,
      allowed,
      blocked,
      rate_limited: rateLimited,
      approval_required: approvalRequired,
      unique_tools: toolMap.size,
      unique_tiers: tiers.size,
    },
    tool_breakdown: Array.from(toolMap.entries())
      .map(([tool, stats]) => ({ tool, ...stats }))
      .sort((a, b) => b.total - a.total),
    policy_changes: policyChanges,
    verification: {
      receipts_signed: receiptsSigned,
      receipts_unsigned: entries.length - receiptsSigned,
      verify_command: 'npx @veritasacta/verify audit-bundle.json --bundle',
    },
  };
}

/**
 * Format a compliance report as Markdown.
 */
export function formatReportMarkdown(report: ComplianceReport): string {
  const lines: string[] = [];

  lines.push('# ScopeBlind Compliance Report');
  lines.push('');
  lines.push(`**Generated:** ${report.generated_at}`);
  lines.push(`**Period:** ${report.period.from.split('T')[0]} to ${report.period.to.split('T')[0]}`);
  if (report.signing_identity) {
    lines.push(`**Signing identity:** kid \`${report.signing_identity.kid}\`, issuer \`${report.signing_identity.issuer}\``);
  }
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total decisions | ${report.summary.total_decisions} |`);
  lines.push(`| Allowed | ${report.summary.allowed} |`);
  lines.push(`| Blocked | ${report.summary.blocked} |`);
  lines.push(`| Rate-limited | ${report.summary.rate_limited} |`);
  lines.push(`| Approval required | ${report.summary.approval_required} |`);
  lines.push(`| Unique tools | ${report.summary.unique_tools} |`);
  lines.push(`| Unique tiers | ${report.summary.unique_tiers} |`);
  lines.push('');

  // Tool breakdown
  if (report.tool_breakdown.length > 0) {
    lines.push('## Tool Breakdown');
    lines.push('');
    lines.push('| Tool | Total | Allowed | Blocked | Rate-limited | Approval |');
    lines.push('|------|-------|---------|---------|--------------|----------|');
    for (const t of report.tool_breakdown) {
      lines.push(`| \`${t.tool}\` | ${t.total} | ${t.allowed} | ${t.blocked} | ${t.rate_limited} | ${t.approval_required} |`);
    }
    lines.push('');
  }

  // Policy changes
  if (report.policy_changes.length > 0) {
    lines.push('## Policy History');
    lines.push('');
    lines.push('| Timestamp | Policy Digest |');
    lines.push('|-----------|--------------|');
    for (const pc of report.policy_changes) {
      lines.push(`| ${pc.at} | \`${pc.policy_digest}\` |`);
    }
    lines.push('');
  }

  // Verification
  lines.push('## Verification');
  lines.push('');
  lines.push(`- Receipts signed: **${report.verification.receipts_signed}**`);
  lines.push(`- Receipts unsigned: **${report.verification.receipts_unsigned}**`);
  lines.push('');
  lines.push('Verify the audit bundle:');
  lines.push('');
  lines.push('```bash');
  lines.push(report.verification.verify_command);
  lines.push('```');
  lines.push('');
  lines.push('The verifier is MIT-licensed and works offline. No ScopeBlind account required.');
  lines.push('');
  lines.push('---');
  lines.push('*Generated by protect-mcp · scopeblind.com*');

  return lines.join('\n');
}
