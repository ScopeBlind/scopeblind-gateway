import {
  meetsMinTier
} from "./chunk-UBZJ3VI2.mjs";
import {
  checkRateLimit,
  getToolPolicy,
  parseRateLimit
} from "./chunk-D2RDY2JR.mjs";

// src/simulate.ts
import { readFileSync } from "fs";
function parseLogFile(path) {
  const raw = readFileSync(path, "utf-8");
  const entries = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const jsonStr = trimmed.replace(/^\[PROTECT_MCP\]\s*/, "");
    try {
      const parsed = JSON.parse(jsonStr);
      if (parsed.tool && parsed.decision) {
        entries.push(parsed);
      }
    } catch {
    }
  }
  return entries;
}
function simulate(entries, policy, tier = "unknown") {
  const rateLimitStore = /* @__PURE__ */ new Map();
  const toolResults = /* @__PURE__ */ new Map();
  const totals = {
    allow: 0,
    block: 0,
    rate_limited: 0,
    require_approval: 0,
    tier_insufficient: 0
  };
  const originalTotals = { allow: 0, deny: 0 };
  const changes = [];
  for (const entry of entries) {
    const toolName = entry.tool;
    const toolPolicy = getToolPolicy(toolName, policy);
    if (entry.decision === "allow") {
      originalTotals.allow++;
    } else {
      originalTotals.deny++;
    }
    let newDecision;
    if (toolPolicy.block) {
      newDecision = "block";
    } else if (toolPolicy.min_tier && !meetsMinTier(tier, toolPolicy.min_tier)) {
      newDecision = "tier_insufficient";
    } else if (toolPolicy.require_approval) {
      newDecision = "require_approval";
    } else if (toolPolicy.rate_limit) {
      const limit = parseRateLimit(toolPolicy.rate_limit);
      const result = checkRateLimit(toolName, limit, rateLimitStore);
      newDecision = result.allowed ? "allow" : "rate_limited";
    } else {
      newDecision = "allow";
    }
    totals[newDecision]++;
    if (!toolResults.has(toolName)) {
      toolResults.set(toolName, {
        tool: toolName,
        calls: 0,
        results: { allow: 0, block: 0, rate_limited: 0, require_approval: 0, tier_insufficient: 0 },
        original: { allow: 0, deny: 0 }
      });
    }
    const tr = toolResults.get(toolName);
    tr.calls++;
    tr.results[newDecision]++;
    if (entry.decision === "allow") {
      tr.original.allow++;
    } else {
      tr.original.deny++;
    }
  }
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
    policy_file: "",
    log_file: "",
    total_calls: entries.length,
    results: totals,
    original: originalTotals,
    tool_breakdown: Array.from(toolResults.values()).sort((a, b) => b.calls - a.calls),
    changes
  };
}
function formatSimulation(summary) {
  const lines = [];
  lines.push(`Simulating ${summary.policy_file} against ${summary.total_calls} recorded tool calls:
`);
  const maxToolLen = Math.max(...summary.tool_breakdown.map((t) => t.tool.length), 4);
  for (const tr of summary.tool_breakdown) {
    const parts = [];
    if (tr.results.allow > 0) parts.push(`${tr.results.allow} allow`);
    if (tr.results.block > 0) parts.push(`\x1B[31m${tr.results.block} blocked\x1B[0m`);
    if (tr.results.rate_limited > 0) parts.push(`\x1B[33m${tr.results.rate_limited} rate_limited\x1B[0m`);
    if (tr.results.require_approval > 0) parts.push(`\x1B[36m${tr.results.require_approval} require_approval\x1B[0m`);
    if (tr.results.tier_insufficient > 0) parts.push(`\x1B[35m${tr.results.tier_insufficient} tier_insufficient\x1B[0m`);
    const originalParts = [];
    if (tr.original.allow > 0) originalParts.push(`${tr.original.allow} allow`);
    if (tr.original.deny > 0) originalParts.push(`${tr.original.deny} deny`);
    lines.push(`  ${tr.tool.padEnd(maxToolLen)}  \xD7 ${String(tr.calls).padStart(3)} \u2192 ${parts.join(", ")}  (was: ${originalParts.join(", ")})`);
  }
  lines.push("");
  lines.push(`Summary: ${summary.results.allow} allow, ${summary.results.block} blocked, ${summary.results.rate_limited} rate_limited, ${summary.results.require_approval} require_approval, ${summary.results.tier_insufficient} tier_insufficient`);
  lines.push(`  vs original: ${summary.original.allow} allow, ${summary.original.deny} deny`);
  if (summary.changes.length > 0) {
    lines.push("");
    lines.push("Changes:");
    for (const change of summary.changes) {
      lines.push(`  \u2022 ${change}`);
    }
  }
  return lines.join("\n");
}

// src/policy-packs.ts
var header = (id, description) => `// ScopeBlind protect-mcp policy pack: ${id}
// ${description}
// Start in shadow mode, review receipts, then run with --enforce.

`;
var defaultPermit = `
// Default posture: allow non-matching calls so teams can start in shadow mode.
// Tighten this after reviewing your local action dashboard.
permit(principal, action == Action::"MCP::Tool::call", resource);
`;
var filesystemSafe = `${header("filesystem-safe", "Block common destructive filesystem and secret-file access patterns.")}// Destructive file tools are never safe as an unattended default.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"delete_file");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"remove_file");

// Secret-like reads by path.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/id_rsa*" ||
    context.input.path like "*/.ssh/*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*credential*"
  )
};

// Dangerous shell operations that mutate or destroy local state.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*rm -rf*" ||
    context.command like "*mkfs*" ||
    context.command like "*dd if=*" ||
    context.command like "*chmod -R 777*" ||
    context.command like "*chown -R*"
  )
};
${defaultPermit}`;
var gitSafe = `${header("git-safe", "Prevent unattended history rewrites, force pushes, and destructive repo cleanup.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*git push --force*" ||
    context.command like "*git push -f*" ||
    context.command like "*git reset --hard*" ||
    context.command like "*git clean -fd*" ||
    context.command like "*git checkout --*" ||
    context.command like "*git branch -D*" ||
    context.command like "*gh repo delete*"
  )
};
${defaultPermit}`;
var emailSafe = `${header("email-safe", "Permit drafting but block unattended external sends.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"mail.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"email.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"send_email");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"gmail.send");

// Shell fallbacks that send mail are blocked too.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*sendmail*" ||
    context.command like "*mailx*" ||
    context.command like "*smtp*"
  )
};
${defaultPermit}`;
var databaseSafe = `${header("database-safe", "Allow reads, block write/admin SQL unless explicitly approved elsewhere.")}forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "query" && (
    context.input.query like "*DROP *" ||
    context.input.query like "*TRUNCATE *" ||
    context.input.query like "*DELETE *" ||
    context.input.query like "*UPDATE *" ||
    context.input.query like "*INSERT *" ||
    context.input.query like "*ALTER *" ||
    context.input.query like "*GRANT *" ||
    context.input.query like "*REVOKE *"
  )
};
${defaultPermit}`;
var cloudSpendSafe = `${header("cloud-spend-safe", "Block cloud actions that can create spend or destroy infrastructure.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*terraform destroy*" ||
    context.command like "*terraform apply*" ||
    context.command like "*pulumi up*" ||
    context.command like "*pulumi destroy*" ||
    context.command like "*aws ec2 run-instances*" ||
    context.command like "*aws rds create*" ||
    context.command like "*gcloud compute instances create*" ||
    context.command like "*az vm create*" ||
    context.command like "*kubectl delete*"
  )
};
${defaultPermit}`;
var secretsSafe = `${header("secrets-safe", "Block secret exfiltration from files, env, shell, and common credential tools.")}forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/.aws/credentials*" ||
    context.input.path like "*/.npmrc*" ||
    context.input.path like "*/.netrc*" ||
    context.input.path like "*/id_rsa*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*token*"
  )
};

forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*printenv*" ||
    context.command like "*env |*" ||
    context.command like "*security find-generic-password*" ||
    context.command like "*aws secretsmanager get-secret-value*" ||
    context.command like "*gcloud secrets versions access*" ||
    context.command like "*op read*"
  )
};
${defaultPermit}`;
var financeMandateSafe = `${header("finance-mandate-safe", "Block restricted-list and concentration-limit breaches in booking tools.")}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"pms.book") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"booking.execute") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"booking.ticket") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};

// Default example caps: single-name > 10%, gross > 200%, net > 100%.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_weight_bps" && context.input.post_trade_weight_bps > 1000
};
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_gross_exposure_bps" && context.input.post_trade_gross_exposure_bps > 20000
};
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_net_exposure_bps" && context.input.post_trade_net_exposure_bps > 10000
};
${defaultPermit}`;
var POLICY_PACKS = [
  {
    id: "filesystem-safe",
    name: "Filesystem Safe",
    description: "Blocks destructive filesystem calls and secret-like path reads.",
    recommendedMode: "shadow-first",
    files: [{ path: "filesystem-safe.cedar", contents: filesystemSafe }]
  },
  {
    id: "git-safe",
    name: "Git Safe",
    description: "Blocks force pushes, hard resets, destructive cleanup, and repo deletion.",
    recommendedMode: "shadow-first",
    files: [{ path: "git-safe.cedar", contents: gitSafe }]
  },
  {
    id: "email-safe",
    name: "Email Safe",
    description: "Allows drafting workflows while blocking unattended sends.",
    recommendedMode: "shadow-first",
    files: [{ path: "email-safe.cedar", contents: emailSafe }]
  },
  {
    id: "database-safe",
    name: "Database Safe",
    description: "Allows read-oriented DB tools while blocking mutating/admin SQL.",
    recommendedMode: "shadow-first",
    files: [{ path: "database-safe.cedar", contents: databaseSafe }]
  },
  {
    id: "cloud-spend-safe",
    name: "Cloud Spend Safe",
    description: "Blocks obvious cloud spend creation and infrastructure destruction.",
    recommendedMode: "shadow-first",
    files: [{ path: "cloud-spend-safe.cedar", contents: cloudSpendSafe }]
  },
  {
    id: "secrets-safe",
    name: "Secrets Safe",
    description: "Blocks common file, env, shell, and cloud secret exfiltration paths.",
    recommendedMode: "enforce-ready",
    files: [{ path: "secrets-safe.cedar", contents: secretsSafe }]
  },
  {
    id: "finance-mandate-safe",
    name: "Finance Mandate Safe",
    description: "Blocks restricted-list and concentration breaches in booking flows.",
    recommendedMode: "shadow-first",
    files: [{ path: "finance-mandate-safe.cedar", contents: financeMandateSafe }]
  }
];
function getPolicyPack(id) {
  return POLICY_PACKS.find((pack) => pack.id === id);
}
function policyPackIds() {
  return POLICY_PACKS.map((pack) => pack.id);
}

// src/connector-pilots.ts
import { existsSync, mkdirSync, readdirSync, readFileSync as readFileSync2, writeFileSync } from "fs";
import { join } from "path";
var defaultPermit2 = `
// Default posture: observe all non-matching tools so the connector can be piloted in shadow mode.
permit(principal, action == Action::"MCP::Tool::call", resource);
`;
var CONNECTOR_PILOTS = [
  {
    id: "github",
    category: "code",
    name: "GitHub pull-request control",
    status: "usable-pilot",
    description: "Controls GitHub REST/MCP calls for issue, PR, branch, and workflow actions.",
    value: "Useful when agents already have repo access through GitHub MCP, gh, or a GitHub-backed tool server.",
    env: [
      { name: "GITHUB_TOKEN", required: true, description: "Fine-grained token scoped to the pilot repo." },
      { name: "GITHUB_REPOSITORY", required: true, description: "owner/repo target for the pilot." }
    ],
    tools: ["github.rest.request", "github.issue.create", "github.pull_request.merge", "github.workflow.dispatch"],
    actions: [
      { name: "Read repo metadata", tool: "github.rest.request", risk: "low", mode: "observe", description: "GET-only repository and PR inspection." },
      { name: "Create issue or comment", tool: "github.issue.create", risk: "medium", mode: "require_approval", description: "External write to the system of record." },
      { name: "Merge PR / dispatch workflow", tool: "github.pull_request.merge", risk: "high", mode: "require_approval", description: "Code-changing or CI-triggering action." }
    ],
    setup: [
      "Create a fine-grained GitHub token for one repository.",
      "Set GITHUB_TOKEN and GITHUB_REPOSITORY.",
      "Run the agent through protect-mcp and review GitHub tool calls in the dashboard."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "github",
      target_env: ["GITHUB_TOKEN", "GITHUB_REPOSITORY"],
      safe_read_probe: "GET /repos/{GITHUB_REPOSITORY}",
      controlled_tools: ["github.rest.request", "github.issue.create", "github.pull_request.merge", "github.workflow.dispatch"],
      approval_required_for: ["POST", "PATCH", "PUT", "DELETE", "merge", "workflow_dispatch"],
      receipt_fields: ["method", "path", "repo", "actor", "payload_hash", "approval_reason"]
    },
    cedar: `${defaultPermit2}
// GitHub pilot: reads are observed; writes and merges need exact-action approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.pull_request.merge" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.workflow.dispatch" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.issue.create" && !context.approved };
`
  },
  {
    id: "email-gmail",
    category: "communications",
    name: "Gmail self-send / draft approval",
    status: "usable-pilot",
    description: "Uses the existing Gmail OAuth connector path and restricts send mode to email.self for the first production pilot.",
    value: "Makes external communications reviewable before an agent can send mail.",
    env: [
      { name: "GOOGLE_CLIENT_ID", required: true, description: "OAuth client for Gmail." },
      { name: "GOOGLE_CLIENT_SECRET", required: true, description: "OAuth client secret." },
      { name: "CONNECTOR_TOKEN_KEY", required: true, description: "AES-GCM key material for sealed connector tokens." }
    ],
    tools: ["gmail.draft.create", "gmail.send.email_self", "email.send"],
    actions: [
      { name: "Create draft", tool: "gmail.draft.create", risk: "medium", mode: "require_approval", description: "Draft content can leak sensitive information." },
      { name: "Self-send test", tool: "gmail.send.email_self", risk: "medium", mode: "require_approval", description: "First release allows only sending to the account owner." },
      { name: "External send", tool: "email.send", risk: "high", mode: "deny", description: "Direct external send stays blocked until a customer-specific allowlist exists." }
    ],
    setup: [
      "Configure Google OAuth redirect /fn/connectors/gmail/callback.",
      "Connect Gmail through the hosted console or local connector flow.",
      "Keep send mode to email.self until the customer approves recipient allowlists."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "gmail",
      hosted_functions: ["/fn/connectors/gmail/start", "/fn/connectors/gmail/callback", "/fn/connectors/gmail/send", "/fn/connectors/gmail/status"],
      first_release_scope: "email.self",
      denied_until_configured: ["email.send.external", "email.bulk_send"],
      receipt_fields: ["to_hash", "subject_hash", "body_hash", "approval_reason", "gmail_message_id"]
    },
    cedar: `${defaultPermit2}
// Email pilot: no direct external send. Draft/self-send require exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "email.send" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.draft.create" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.send.email_self" && !context.approved };
`
  },
  {
    id: "filesystem-git",
    category: "local-computer",
    name: "Filesystem and Git control",
    status: "usable-pilot",
    description: "Controls reads, writes, shell commands, and Git mutation in the local project.",
    value: "Immediately useful with Claude Code, Codex, Cursor, and any agent that edits files or runs shell commands.",
    env: [],
    tools: ["Read", "Write", "Edit", "MultiEdit", "Bash", "git.commit", "git.push"],
    actions: [
      { name: "Read files", tool: "Read", risk: "low", mode: "observe", description: "Observe file reads for audit context." },
      { name: "Write/edit files", tool: "Write", risk: "medium", mode: "require_approval", description: "Require approval for sensitive paths or broad rewrites." },
      { name: "Git push/reset", tool: "Bash", risk: "high", mode: "require_approval", description: "Commands that publish, reset, or delete require exact-action approval." }
    ],
    setup: [
      "Run protect-mcp init-hooks in the project.",
      "Install filesystem-safe and Git-safe policy packs.",
      "Review the dashboard before turning on enforce mode."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "filesystem-git",
      local_only: true,
      protected_paths: [".env", ".ssh", "keys/", "secrets/", "node_modules/"],
      dangerous_command_patterns: ["rm -rf", "git push", "git reset --hard", "curl | sh", "chmod 777"],
      receipt_fields: ["tool", "path_hash", "command_hash", "diff_hash", "approval_reason"]
    },
    cedar: `${defaultPermit2}
// Filesystem/Git pilot: dangerous shell and protected-path writes need approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git reset --hard") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git push") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["Write", "Edit", "MultiEdit"].contains(context.tool) && context.path.contains(".env") && !context.approved };
`
  },
  {
    id: "slack-teams",
    category: "communications",
    name: "Slack or Teams outbound approval",
    status: "usable-pilot",
    description: "Controls messages to Slack channels or Microsoft Teams webhooks.",
    value: "Makes high-impact internal broadcasts and client channels approval-gated.",
    env: [
      { name: "SLACK_BOT_TOKEN", required: false, description: "Slack bot token for chat.postMessage pilots." },
      { name: "SLACK_CHANNEL_ID", required: false, description: "Default Slack channel for the pilot." },
      { name: "TEAMS_WEBHOOK_URL", required: false, description: "Teams incoming webhook URL if Teams is preferred." }
    ],
    tools: ["slack.chat.postMessage", "slack.files.upload", "teams.webhook.post"],
    actions: [
      { name: "Post internal message", tool: "slack.chat.postMessage", risk: "medium", mode: "require_approval", description: "Message text and channel are read back before send." },
      { name: "Upload file", tool: "slack.files.upload", risk: "high", mode: "require_approval", description: "Files can leak customer data and need explicit approval." },
      { name: "Teams webhook post", tool: "teams.webhook.post", risk: "medium", mode: "require_approval", description: "Webhook destination and payload hash are receipted." }
    ],
    setup: [
      "Choose Slack or Teams for the first pilot, not both.",
      "Set the relevant token/webhook environment variables.",
      "Start with a private test channel and exact-action approval for every send."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "slack-or-teams",
      supported_modes: ["slack.chat.postMessage", "teams.webhook.post"],
      require_channel_allowlist: true,
      receipt_fields: ["channel_hash", "message_hash", "file_hash", "approval_reason", "provider_message_id"]
    },
    cedar: `${defaultPermit2}
// Slack/Teams pilot: all outbound posts and uploads require approval by default.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["slack.chat.postMessage", "slack.files.upload", "teams.webhook.post"].contains(context.tool) && !context.approved };
`
  },
  {
    id: "finance-pms",
    category: "finance",
    name: "Finance PMS mock-to-real adapter",
    status: "usable-pilot",
    description: "Stages orders into a PMS adapter contract, with mock mode locally and real mode through PMS_ADAPTER_URL.",
    value: "Gives hedge funds the controlled booking path: parse, mandate-check, approve, book, corroborate, receipt.",
    env: [
      { name: "PMS_ADAPTER_URL", required: false, description: "Customer-owned adapter endpoint. Omit for local mock mode." },
      { name: "PMS_ADAPTER_TOKEN", required: false, description: "Bearer token for the customer-owned PMS adapter." }
    ],
    tools: ["pms.order.stage", "pms.order.book", "pms.order.cancel", "pms.reconcile"],
    actions: [
      { name: "Stage order", tool: "pms.order.stage", risk: "medium", mode: "require_approval", description: "Creates a booking ticket but does not execute." },
      { name: "Book order", tool: "pms.order.book", risk: "high", mode: "require_approval", description: "Must pass mandate checks and human readback." },
      { name: "Cancel/order correction", tool: "pms.order.cancel", risk: "high", mode: "require_approval", description: "Mutates book state and requires approval." }
    ],
    setup: [
      "Run local mock mode first with the Legate finance pilot pack.",
      "Point PMS_ADAPTER_URL at a customer-owned bridge when ready.",
      "Require mandate checks and exact-action approval before pms.order.book."
    ],
    config: {
      type: "scopeblind.connector_pilot.v1",
      provider: "finance-pms",
      mode: "mock-first",
      adapter_contract: {
        stage: "POST /orders/stage",
        book: "POST /orders/book",
        cancel: "POST /orders/{client_order_id}/cancel",
        reconcile: "GET /orders/{client_order_id}"
      },
      receipt_fields: ["client_order_id", "side", "symbol_hash", "qty", "price", "mandate_digest", "approval_reason", "external_confirmation_hash"]
    },
    cedar: `${defaultPermit2}
// Finance/PMS pilot: booking actions require mandate pass and exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["pms.order.stage", "pms.order.book", "pms.order.cancel"].contains(context.tool) && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "pms.order.book" && context.mandate_passed != true };
`
  }
];
function connectorPilotIds() {
  return CONNECTOR_PILOTS.map((pilot) => pilot.id);
}
function getConnectorPilot(id) {
  return CONNECTOR_PILOTS.find((pilot) => pilot.id === id);
}
function connectorDirectory(dir) {
  return join(dir, ".protect-mcp", "connectors");
}
function writeConnectorPilots(opts) {
  const directory = connectorDirectory(opts.dir);
  mkdirSync(directory, { recursive: true });
  const selected = opts.ids && opts.ids.length > 0 && !opts.ids.includes("all") ? opts.ids.map((id) => {
    const pilot = getConnectorPilot(id);
    if (!pilot) throw new Error(`Unknown connector pilot: ${id}`);
    return pilot;
  }) : CONNECTOR_PILOTS;
  const written = [];
  for (const pilot of selected) {
    const configPath = join(directory, `${pilot.id}.json`);
    const policyPath = join(directory, `${pilot.id}.cedar`);
    if (!opts.force && (existsSync(configPath) || existsSync(policyPath))) {
      throw new Error(`Refusing to overwrite ${pilot.id}. Re-run with --force if intentional.`);
    }
    writeFileSync(configPath, JSON.stringify({ ...pilot.config, id: pilot.id, name: pilot.name, category: pilot.category, tools: pilot.tools, actions: pilot.actions, setup: pilot.setup }, null, 2) + "\n");
    writeFileSync(policyPath, pilot.cedar.endsWith("\n") ? pilot.cedar : `${pilot.cedar}
`);
    written.push(configPath, policyPath);
  }
  writeFileSync(join(directory, "README.md"), renderConnectorReadme(selected));
  written.push(join(directory, "README.md"));
  return { written, pilots: selected, directory };
}
function readInstalledConnectorPilots(dir) {
  const directory = connectorDirectory(dir);
  if (!existsSync(directory)) return [];
  return readdirSync(directory).filter((name) => name.endsWith(".json")).map((name) => {
    const configPath = join(directory, name);
    try {
      const parsed = JSON.parse(readFileSync2(configPath, "utf-8"));
      const id = String(parsed.id || name.replace(/\.json$/, ""));
      const pilot = getConnectorPilot(id);
      return {
        id,
        name: String(parsed.name || pilot?.name || id),
        category: String(parsed.category || pilot?.category || "unknown"),
        status: String(parsed.status || parsed.type || "installed"),
        config_path: configPath,
        policy_path: join(directory, `${id}.cedar`)
      };
    } catch {
      return null;
    }
  }).filter(Boolean);
}
function connectorDoctor(dir, env = process.env) {
  const installed = new Set(readInstalledConnectorPilots(dir).map((pilot) => pilot.id));
  return CONNECTOR_PILOTS.map((pilot) => {
    const envRows = pilot.env.map((item) => ({
      name: item.name,
      required: item.required,
      present: Boolean(env[item.name]),
      description: item.description
    }));
    const missingRequired = envRows.filter((item) => item.required && !item.present).map((item) => item.name);
    const optionalPresent = envRows.filter((item) => !item.required && item.present).map((item) => item.name);
    const optionalProviderReady = pilot.id === "slack-teams" ? Boolean(env.SLACK_BOT_TOKEN || env.TEAMS_WEBHOOK_URL) : pilot.id === "finance-pms" ? Boolean(env.PMS_ADAPTER_URL) : false;
    const mockModeReady = pilot.id === "finance-pms";
    return {
      id: pilot.id,
      name: pilot.name,
      category: pilot.category,
      installed: installed.has(pilot.id),
      usable: missingRequired.length === 0 && (pilot.env.some((item) => item.required) || pilot.env.length === 0 || optionalProviderReady || mockModeReady),
      mode: pilot.id === "finance-pms" && !env.PMS_ADAPTER_URL ? "mock" : pilot.id === "slack-teams" && !env.SLACK_BOT_TOKEN && !env.TEAMS_WEBHOOK_URL ? "needs_provider_choice" : "configured_or_local",
      missing_required: missingRequired,
      optional_present: optionalPresent,
      tools: pilot.tools,
      next: missingRequired.length > 0 ? `Set ${missingRequired.join(", ")}` : installed.has(pilot.id) ? "Run through protect-mcp and inspect the dashboard." : `Install with protect-mcp connectors init ${pilot.id}`
    };
  });
}
function renderConnectorReadme(pilots) {
  return `# protect-mcp connector pilots

These files make real tool classes visible and controllable without uploading raw prompts or payloads.

${pilots.map((pilot) => `## ${pilot.name}

${pilot.description}

Value: ${pilot.value}

Tools: ${pilot.tools.map((tool) => `\`${tool}\``).join(", ")}

Setup:
${pilot.setup.map((step) => `- ${step}`).join("\n")}
`).join("\n")}
Next: run \`npx protect-mcp dashboard --open\` and review tool inventory, policy coverage, approvals, and receipts.
`;
}

export {
  parseLogFile,
  simulate,
  formatSimulation,
  POLICY_PACKS,
  getPolicyPack,
  policyPackIds,
  CONNECTOR_PILOTS,
  connectorPilotIds,
  getConnectorPilot,
  connectorDirectory,
  writeConnectorPilots,
  readInstalledConnectorPilots,
  connectorDoctor
};
