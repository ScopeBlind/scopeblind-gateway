import {
  receiptIdentity
} from "./chunk-XOP3PEBM.mjs";

// src/report.ts
import { readFileSync, existsSync } from "fs";
function generateReport(logPath, receiptPath, periodDays) {
  const now = /* @__PURE__ */ new Date();
  const from = new Date(now.getTime() - periodDays * 864e5);
  const entries = [];
  if (existsSync(logPath)) {
    const raw = readFileSync(logPath, "utf-8");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const jsonStr = trimmed.replace(/^\[PROTECT_MCP\]\s*/, "");
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed.tool && parsed.decision && parsed.timestamp) {
          const entryTime = typeof parsed.timestamp === "number" && parsed.timestamp > 1e12 ? parsed.timestamp : parsed.timestamp * 1e3;
          if (entryTime >= from.getTime()) {
            entries.push(parsed);
          }
        }
      } catch {
      }
    }
  }
  let receiptsSigned = 0;
  let signerKid = "";
  let signerIssuer = "";
  if (existsSync(receiptPath)) {
    const raw = readFileSync(receiptPath, "utf-8");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.signature) {
          receiptsSigned++;
          const identity = receiptIdentity(parsed);
          if (identity.kid && !signerKid) signerKid = identity.kid;
          if (identity.issuer && !signerIssuer) signerIssuer = identity.issuer;
        }
      } catch {
      }
    }
  }
  const toolMap = /* @__PURE__ */ new Map();
  const tiers = /* @__PURE__ */ new Set();
  const policyDigests = /* @__PURE__ */ new Map();
  let allowed = 0;
  let blocked = 0;
  let rateLimited = 0;
  let approvalRequired = 0;
  for (const entry of entries) {
    const tool = entry.tool;
    if (!toolMap.has(tool)) {
      toolMap.set(tool, { total: 0, allowed: 0, blocked: 0, rate_limited: 0, approval_required: 0 });
    }
    const tm = toolMap.get(tool);
    tm.total++;
    if (entry.decision === "allow") {
      allowed++;
      tm.allowed++;
    } else if (entry.decision === "deny" && entry.reason_code === "rate_limit_exceeded") {
      rateLimited++;
      tm.rate_limited++;
    } else if (entry.decision === "deny" && entry.reason_code === "require_approval") {
      approvalRequired++;
      tm.approval_required++;
    } else {
      blocked++;
      tm.blocked++;
    }
    if (entry.tier) tiers.add(entry.tier);
    if (entry.policy_digest && !policyDigests.has(entry.policy_digest)) {
      policyDigests.set(entry.policy_digest, new Date(entry.timestamp).toISOString());
    }
  }
  const policyChanges = Array.from(policyDigests.entries()).map(([digest, at]) => ({
    at,
    policy_digest: digest
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
      unique_tiers: tiers.size
    },
    tool_breakdown: Array.from(toolMap.entries()).map(([tool, stats]) => ({ tool, ...stats })).sort((a, b) => b.total - a.total),
    policy_changes: policyChanges,
    verification: {
      receipts_signed: receiptsSigned,
      receipts_unsigned: entries.length - receiptsSigned,
      verify_command: "npx @veritasacta/verify audit-bundle.json --bundle"
    }
  };
}
function formatReportMarkdown(report) {
  const lines = [];
  lines.push("# ScopeBlind Compliance Report");
  lines.push("");
  lines.push(`**Generated:** ${report.generated_at}`);
  lines.push(`**Period:** ${report.period.from.split("T")[0]} to ${report.period.to.split("T")[0]}`);
  if (report.signing_identity) {
    lines.push(`**Signing identity:** kid \`${report.signing_identity.kid}\`, issuer \`${report.signing_identity.issuer}\``);
  }
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total decisions | ${report.summary.total_decisions} |`);
  lines.push(`| Allowed | ${report.summary.allowed} |`);
  lines.push(`| Blocked | ${report.summary.blocked} |`);
  lines.push(`| Rate-limited | ${report.summary.rate_limited} |`);
  lines.push(`| Approval required | ${report.summary.approval_required} |`);
  lines.push(`| Unique tools | ${report.summary.unique_tools} |`);
  lines.push(`| Unique tiers | ${report.summary.unique_tiers} |`);
  lines.push("");
  if (report.tool_breakdown.length > 0) {
    lines.push("## Tool Breakdown");
    lines.push("");
    lines.push("| Tool | Total | Allowed | Blocked | Rate-limited | Approval |");
    lines.push("|------|-------|---------|---------|--------------|----------|");
    for (const t of report.tool_breakdown) {
      lines.push(`| \`${t.tool}\` | ${t.total} | ${t.allowed} | ${t.blocked} | ${t.rate_limited} | ${t.approval_required} |`);
    }
    lines.push("");
  }
  if (report.policy_changes.length > 0) {
    lines.push("## Policy History");
    lines.push("");
    lines.push("| Timestamp | Policy Digest |");
    lines.push("|-----------|--------------|");
    for (const pc of report.policy_changes) {
      lines.push(`| ${pc.at} | \`${pc.policy_digest}\` |`);
    }
    lines.push("");
  }
  lines.push("## Verification");
  lines.push("");
  lines.push(`- Receipts signed: **${report.verification.receipts_signed}**`);
  lines.push(`- Receipts unsigned: **${report.verification.receipts_unsigned}**`);
  lines.push("");
  lines.push("Verify the audit bundle:");
  lines.push("");
  lines.push("```bash");
  lines.push(report.verification.verify_command);
  lines.push("```");
  lines.push("");
  lines.push("The verifier is MIT-licensed and works offline. No ScopeBlind account required.");
  lines.push("");
  lines.push("---");
  lines.push("*Generated by protect-mcp \xB7 scopeblind.com*");
  return lines.join("\n");
}

export {
  generateReport,
  formatReportMarkdown
};
