#!/usr/bin/env node
import {
  CONNECTOR_PILOTS,
  POLICY_PACKS,
  connectorDoctor,
  formatSimulation,
  getConnectorPilot,
  getPolicyPack,
  parseLogFile,
  policyPackIds,
  readInstalledConnectorPilots,
  simulate,
  writeConnectorPilots
} from "./chunk-CXW2EIRM.mjs";
import {
  ProtectGateway,
  validateCredentials
} from "./chunk-GHR65WVD.mjs";
import {
  buildActionReadback,
  evaluateCedar,
  initSigning,
  isCedarAvailable,
  loadCedarPolicies,
  loadPolicy,
  policySetFromSource,
  runEvaluatorSelfTest,
  signDecision
} from "./chunk-IDUH2O4Q.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/cli.ts
import { createHash as createHashCli } from "crypto";
import { readFileSync as readFileSyncCli, existsSync as existsSyncCli, appendFileSync as appendFileSyncCli, mkdirSync as mkdirSyncCli, readdirSync as readdirSyncCli, writeFileSync as writeFileSyncCli } from "fs";
import { basename as basenameCli, dirname as dirnameCli, join as joinCli, resolve as resolveCli } from "path";
import { homedir as homedirCli } from "os";
function printHelp() {
  process.stderr.write(`
protect-mcp: Enterprise security gateway for MCP servers & Claude Code hooks

Usage:
  protect-mcp [options] -- <command> [args...]
  protect-mcp serve [--port <port>] [--enforce] [--policy <path>] [--cedar <dir>]
  protect-mcp init-hooks [--dir <path>] [--port <port>]
  protect-mcp quickstart [--connect]
  protect-mcp wrap [--write] [--claude-desktop] [-- <command>]
  protect-mcp dashboard [--port <port>] [--dir <path>] [--open]
  protect-mcp recommend [--dir <path>] [--output <path>] [--write]
  protect-mcp registry init|anchor|status [--dir <path>] [--org <name>] [--hosted]
  protect-mcp trial [--dir <path>] [--hosted]
  protect-mcp killer-demo [--dir <path>] [--hosted]
  protect-mcp connectors list|show|init|doctor [connector|all] [--dir <path>] [--force]
  protect-mcp verify-disclosure --receipt <path> --disclosure <path>
  protect-mcp policy-packs list|show|install [pack] [--dir ./cedar] [--force]
  protect-mcp connect
  protect-mcp init [--dir <path>]
  protect-mcp demo
  protect-mcp trace <receipt_id> [--endpoint <url>] [--depth <n>]
  protect-mcp status [--dir <path>]
  protect-mcp digest [--today] [--dir <path>]
  protect-mcp receipts [--last <n>] [--dir <path>]
  protect-mcp record [--dir <path>] [--live] [--no-open]
  protect-mcp bundle [--output <path>] [--dir <path>]
  protect-mcp simulate --policy <path> [--log <path>] [--tier <tier>] [--json]
  protect-mcp report [--period <days>d] [--format md|json] [--output <path>] [--dir <path>]

Options:
  --policy <path>   Policy/config JSON file (default: allow-all)
  --cedar <dir>     Cedar policy directory (alternative to --policy, evaluates locally via WASM)
  --slug <slug>     ScopeBlind tenant slug (optional)
  --enforce         Enable enforcement mode (default: shadow mode)
  --http            Start HTTP/SSE server instead of stdio proxy
  --port <port>     HTTP server port (default: 3000 for --http, 9377 for serve)
  --verbose         Enable debug logging to stderr
  --help            Show this help

Commands:
  serve             Start HTTP hook server for Claude Code integration (port 9377)
  evaluate          Evaluate one tool call against a Cedar policy (PreToolUse gate; exit 2 = deny, fail-closed)
  sign              Sign one tool call into a receipt (PostToolUse)
  init-hooks        Generate Claude Code hook config + skill + sample Cedar policy
  quickstart        Zero-config onboarding: init + demo + show receipts in one command
  wrap              Print or install a protect-mcp wrapper for MCP servers
  dashboard         Start a local-only action dashboard from logs/receipts
  recommend         Draft a policy from shadow-mode call inventory
  registry          Paid-boundary receipt digest registry and verifier page
  trial             Build the 10-minute self-serve proof path locally
  killer-demo       Build a 3-minute shadow\u2192policy\u2192approval\u2192receipt demo pack
  connectors        Install and inspect real connector pilots
  verify-disclosure Verify a v0 selective-disclosure package and explain hidden fields
  policy-packs      List, inspect, or install starter Cedar policy packs
  connect           Create a ScopeBlind sandbox dashboard and configure receipt upload
  init              Generate config template, Ed25519 keypair, and sample policy
  demo              Start a demo server wrapped with protect-mcp (see receipts instantly)
  doctor            Check your setup: keys, policies, verifier, API connectivity
  trace <id>        Visualize the receipt DAG from a given receipt_id (ASCII tree)
  status            Show tool call statistics from the local decision log
  digest            Generate a human-readable summary of agent activity
  receipts          Show recent persisted signed receipts
  record            Open a local, searchable view of your record in the browser
  bundle            Export an offline-verifiable audit bundle

Examples:
  protect-mcp serve                           # Start hook server (Claude Code)
  protect-mcp serve --enforce --cedar ./cedar  # Enforce Cedar policies
  protect-mcp init-hooks                       # One-command Claude Code setup
  protect-mcp quickstart
  protect-mcp quickstart --connect               # Quickstart + create dashboard
  protect-mcp wrap -- node my-server.js          # Print wrapped MCP command
  protect-mcp wrap --claude-desktop --write      # Patch Claude Desktop MCP config
  protect-mcp dashboard --open                   # Local risk/inventory dashboard
  protect-mcp recommend --write                  # Draft a policy from observed calls
  protect-mcp registry anchor --hosted           # Upload only receipt digests for anchoring
  protect-mcp trial --dir ./scopeblind-trial     # Generate self-serve trial artifacts
  protect-mcp killer-demo --dir ./scopeblind-demo # Generate sales-demo artifacts
  protect-mcp connectors init all --force        # Install connector pilot configs
  protect-mcp connectors doctor                  # Check connector credentials safely
  protect-mcp verify-disclosure --receipt committed.json --disclosure tool-only.json
  protect-mcp policy-packs install filesystem-safe --dir ./cedar
  protect-mcp connect                             # Connect existing setup to dashboard
  protect-mcp -- node my-server.js
  protect-mcp init
  protect-mcp demo
  protect-mcp trace sha256:abc123 --depth 5
  protect-mcp status
  protect-mcp bundle --output audit.json

Dashboard:
  npx protect-mcp dashboard      Local-only dashboard (127.0.0.1; no account)
  npx protect-mcp connect        Create a free ScopeBlind dashboard
                                  Free up to 20,000 receipts/month

  https://scopeblind.com          Docs, pricing, enterprise

`);
}
function parseArgs(argv) {
  let policyPath;
  let cedarDir;
  let slug;
  let enforce = false;
  let verbose = false;
  let childCommand = [];
  const separatorIndex = argv.indexOf("--");
  if (separatorIndex === -1) {
    process.stderr.write(
      '[PROTECT_MCP] Error: Missing "--" separator before the command to wrap.\nUsage: protect-mcp [options] -- <command> [args...]\nExample: protect-mcp --policy policy.json -- node my-server.js\n'
    );
    process.exit(1);
  }
  childCommand = argv.slice(separatorIndex + 1);
  if (childCommand.length === 0) {
    process.stderr.write('[PROTECT_MCP] Error: No command specified after "--"\n');
    process.exit(1);
  }
  const options = argv.slice(0, separatorIndex);
  for (let i = 0; i < options.length; i++) {
    const arg = options[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else if (arg === "--policy" && i + 1 < options.length) {
      policyPath = options[++i];
    } else if (arg === "--cedar" && i + 1 < options.length) {
      cedarDir = options[++i];
    } else if (arg === "--slug" && i + 1 < options.length) {
      slug = options[++i];
    } else if (arg === "--enforce") {
      enforce = true;
    } else if (arg === "--verbose" || arg === "-v") {
      verbose = true;
    } else {
      process.stderr.write(`[PROTECT_MCP] Warning: Unknown option "${arg}"
`);
    }
  }
  return { policyPath, cedarDir, slug, enforce, verbose, childCommand };
}
async function handleInit(argv) {
  const { writeFileSync, existsSync, mkdirSync } = await import("fs");
  const { join } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) {
    dir = argv[dirIdx + 1];
  }
  const configPath = join(dir, "protect-mcp.json");
  const keysDir = join(dir, "keys");
  const keyPath = join(keysDir, "gateway.json");
  if (existsSync(configPath)) {
    process.stderr.write(`[PROTECT_MCP] Config already exists at ${configPath}
`);
    process.stderr.write("[PROTECT_MCP] Delete it first if you want to regenerate.\n");
    process.exit(1);
  }
  let keypair;
  {
    const { randomBytes } = await import("crypto");
    const { ed25519 } = await import("./ed25519-SQA3S2RV.mjs");
    const { bytesToHex } = await import("./utils-6AYZFE5A.mjs");
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    keypair = {
      privateKey: bytesToHex(privateKey),
      publicKey: bytesToHex(publicKey),
      kid: "generated"
    };
  }
  if (!existsSync(keysDir)) {
    mkdirSync(keysDir, { recursive: true });
  }
  writeFileSync(keyPath, JSON.stringify({
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    kid: keypair.kid,
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    warning: "KEEP THIS FILE SECRET. Never commit to version control."
  }, null, 2) + "\n");
  const gitignorePath = join(keysDir, ".gitignore");
  if (!existsSync(gitignorePath)) {
    writeFileSync(gitignorePath, "# Never commit signing keys\n*.json\n");
  }
  const config = {
    tools: {
      "*": {
        rate_limit: "100/hour"
      },
      "delete_file": {
        block: true,
        min_tier: "privileged"
      },
      "write_file": {
        min_tier: "signed-known",
        rate_limit: "10/minute"
      },
      "read_file": {
        rate_limit: "50/minute"
      }
    },
    default_tier: "unknown",
    signing: {
      key_path: "./keys/gateway.json",
      issuer: "protect-mcp",
      enabled: true
    },
    credentials: {
      _example_api: {
        inject: "env",
        name: "EXAMPLE_API_KEY",
        value_env: "EXAMPLE_API_KEY",
        _comment: "Remove the underscore prefix and set EXAMPLE_API_KEY in your environment"
      }
    }
  };
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
  const claudeConfig = {
    "mcpServers": {
      "my-server": {
        "command": "npx",
        "args": ["protect-mcp", "--policy", configPath, "--", "node", "my-server.js"]
      }
    }
  };
  process.stderr.write(`
${bold("protect-mcp initialized!")}

Created:
  ${configPath}     Config with shadow mode + local signing
  ${keyPath}       Ed25519 signing keypair

${bold("Next steps:")}
  1. Edit protect-mcp.json to match your MCP server's tools
  2. Set any credential environment variables
  3. Run: protect-mcp --policy protect-mcp.json -- <your-mcp-server>

${bold("Your gateway public key:")}
  ${keypair.publicKey}

${bold("Key ID (kid):")}
  ${keypair.kid}

${bold("Claude Desktop config snippet")} (add to claude_desktop_config.json):
${dim(JSON.stringify(claudeConfig, null, 2))}

${bold("Quick demo:")}
  protect-mcp demo

Shadow mode is the default \u2014 all tool calls are logged and nothing is blocked.
Add --enforce when ready to block policy violations.
`);
}
async function handleDemo() {
  const { existsSync } = await import("fs");
  const { join, dirname, resolve } = await import("path");
  const { realpathSync } = await import("fs");
  const cliPath = resolve(process.argv[1] || "dist/cli.js");
  let cliDir;
  try {
    cliDir = dirname(realpathSync(cliPath));
  } catch {
    cliDir = dirname(cliPath);
  }
  const demoServerPath = join(cliDir, "demo-server.js");
  const configPath = join(process.cwd(), "protect-mcp.json");
  const hasConfig = existsSync(configPath);
  if (!hasConfig) {
    process.stderr.write(`
${bold("protect-mcp demo")}

Starting demo with default shadow mode (no signing).
For signed receipts, run ${dim("npx protect-mcp init")} first.

`);
  } else {
    process.stderr.write(`
${bold("protect-mcp demo")}

Using config from ${configPath}
Starting demo server with 5 tools...

`);
  }
  let policy = null;
  let policyDigest = "none";
  let credentials;
  let signing;
  if (hasConfig) {
    try {
      const loaded = loadPolicy(configPath);
      policy = loaded.policy;
      policyDigest = loaded.digest;
      credentials = loaded.credentials;
      signing = loaded.signing;
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Warning: Could not load config: ${err instanceof Error ? err.message : err}
`);
    }
  }
  if (signing) {
    const warnings = await initSigning(signing);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  if (credentials) {
    const warnings = validateCredentials(credentials);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  const config = {
    command: process.execPath,
    // node
    args: [demoServerPath],
    policy,
    policyDigest,
    enforce: false,
    // Demo always runs in shadow mode
    verbose: true,
    signing,
    credentials
  };
  const gateway = new ProtectGateway(config);
  process.stderr.write(`${bold("Demo ready!")} The demo server is running.
`);
  process.stderr.write(`Send JSON-RPC tool calls on stdin, or use an MCP client.

`);
  process.stderr.write(`${dim("Example (paste into stdin):")}
`);
  process.stderr.write(`${dim('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}')}

`);
  await gateway.start();
}
async function handleStatus(argv) {
  const { readFileSync, existsSync } = await import("fs");
  const { join } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) {
    dir = argv[dirIdx + 1];
  }
  const logPath = join(dir, ".protect-mcp-log.jsonl");
  if (!existsSync(logPath)) {
    process.stderr.write(`${bold("protect-mcp status")}

`);
    process.stderr.write(`No log file found at ${logPath}
`);
    process.stderr.write(`Run protect-mcp with a wrapped server first to generate logs.
`);
    process.exit(0);
  }
  const raw = readFileSync(logPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  if (lines.length === 0) {
    process.stderr.write(`${bold("protect-mcp status")}

No entries in log file.
`);
    process.exit(0);
  }
  const entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
    }
  }
  if (entries.length === 0) {
    process.stderr.write(`${bold("protect-mcp status")}

No valid entries in log file.
`);
    process.exit(0);
  }
  const toolCounts = /* @__PURE__ */ new Map();
  let allowCount = 0;
  let denyCount = 0;
  let rateLimitCount = 0;
  const tierCounts = /* @__PURE__ */ new Map();
  const reasonCounts = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    toolCounts.set(entry.tool, (toolCounts.get(entry.tool) || 0) + 1);
    if (entry.decision === "allow") allowCount++;
    else if (entry.decision === "deny") denyCount++;
    if (entry.reason_code === "rate_limit_exceeded") rateLimitCount++;
    if (entry.tier) tierCounts.set(entry.tier, (tierCounts.get(entry.tier) || 0) + 1);
    reasonCounts.set(entry.reason_code, (reasonCounts.get(entry.reason_code) || 0) + 1);
  }
  const firstTs = new Date(Math.min(...entries.map((e) => e.timestamp)));
  const lastTs = new Date(Math.max(...entries.map((e) => e.timestamp)));
  const sortedTools = [...toolCounts.entries()].sort((a, b) => b[1] - a[1]);
  process.stdout.write(`
${bold("protect-mcp status")}

`);
  process.stdout.write(`  Total decisions: ${bold(String(entries.length))}
`);
  process.stdout.write(`  ${green("\u2713 Allow")}: ${allowCount}    ${red("\u2717 Deny")}: ${denyCount}    ${yellow("\u2298 Rate-limited")}: ${rateLimitCount}

`);
  process.stdout.write(`  ${bold("Time range:")}
`);
  process.stdout.write(`    First: ${firstTs.toISOString()}
`);
  process.stdout.write(`    Last:  ${lastTs.toISOString()}

`);
  process.stdout.write(`  ${bold("Top tools:")}
`);
  for (const [tool, count] of sortedTools.slice(0, 10)) {
    const bar = "\u2588".repeat(Math.min(Math.ceil(count / entries.length * 30), 30));
    process.stdout.write(`    ${tool.padEnd(20)} ${String(count).padStart(4)}  ${dim(bar)}
`);
  }
  if (tierCounts.size > 0) {
    process.stdout.write(`
  ${bold("Trust tiers seen:")}
`);
    for (const [tier, count] of tierCounts) {
      process.stdout.write(`    ${tier.padEnd(15)} ${count}
`);
    }
  }
  process.stdout.write(`
  ${bold("Decision reasons:")}
`);
  for (const [reason, count] of [...reasonCounts.entries()].sort((a, b) => b[1] - a[1])) {
    process.stdout.write(`    ${reason.padEnd(25)} ${count}
`);
  }
  const evidencePath = join(dir, ".protect-mcp-evidence.json");
  if (existsSync(evidencePath)) {
    try {
      const evidenceRaw = readFileSync(evidencePath, "utf-8");
      const evidence = JSON.parse(evidenceRaw);
      const agentCount = Object.keys(evidence.agents || {}).length;
      process.stdout.write(`
  ${bold("Evidence store:")} ${agentCount} agent(s) tracked
`);
    } catch {
    }
  }
  const keyPath = join(dir, "keys", "gateway.json");
  if (existsSync(keyPath)) {
    try {
      const keyData = JSON.parse(readFileSync(keyPath, "utf-8"));
      if (keyData.publicKey) {
        const fingerprint = keyData.publicKey.slice(0, 16) + "...";
        process.stdout.write(`
  ${bold("\u{1F6E1}\uFE0F Passport identity:")}
`);
        process.stdout.write(`    Public key:  ${fingerprint}
`);
        if (keyData.kid) process.stdout.write(`    Key ID:      ${keyData.kid}
`);
        process.stdout.write(`    Issuer:      ${keyData.issuer || "protect-mcp"}
`);
        process.stdout.write(`    Verify:      ${dim("npx @veritasacta/verify <receipt.json>")}
`);
      }
    } catch {
    }
  }
  process.stdout.write(`
  Log file: ${dim(logPath)}

`);
}
function commandNeedsValue(argv, flag) {
  const value = flagValue(argv, flag);
  return Boolean(value && !value.startsWith("--"));
}
function absoluteOrCwd(pathValue) {
  return resolveCli(process.cwd(), pathValue);
}
function shellQuoteArg(arg) {
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}
function shellCommand(command, args) {
  return [command, ...args].map(shellQuoteArg).join(" ");
}
function wrapperArgsFor(command, opts) {
  const args = ["-y", "protect-mcp@latest"];
  if (opts.cedarDir) args.push("--cedar", opts.cedarDir);
  else args.push("--policy", opts.configPath || absoluteOrCwd("protect-mcp.json"));
  if (opts.enforce) args.push("--enforce");
  args.push("--", ...command);
  return args;
}
function claudeDesktopConfigPath() {
  if (process.platform === "darwin") {
    return joinCli(homedirCli(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
  }
  if (process.platform === "win32") {
    return joinCli(process.env.APPDATA || joinCli(homedirCli(), "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
  }
  return joinCli(homedirCli(), ".config", "Claude", "claude_desktop_config.json");
}
async function ensureLocalConfig(dir = process.cwd()) {
  const { existsSync } = await import("fs");
  const { join, resolve } = await import("path");
  const configPath = join(dir, "protect-mcp.json");
  if (!existsSync(configPath)) {
    process.stderr.write(`${bold("protect-mcp wrap")}

No protect-mcp.json found; creating local shadow-mode config first.

`);
    await handleInit(["--dir", dir]);
  }
  return resolve(configPath);
}
function parseJsonlFile(pathValue) {
  try {
    const raw = readFileSyncCli(pathValue, "utf-8");
    return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
  } catch {
    return [];
  }
}
function parseJsonlRecords(pathValue) {
  try {
    const raw = readFileSyncCli(pathValue, "utf-8");
    return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
      try {
        return [{
          value: JSON.parse(line),
          raw: line,
          hash: createHashCli("sha256").update(line).digest("hex")
        }];
      } catch {
        return [];
      }
    });
  } catch {
    return [];
  }
}
function loadPolicyJson(policyPath) {
  try {
    if (!existsSyncCli(policyPath)) return null;
    return JSON.parse(readFileSyncCli(policyPath, "utf-8"));
  } catch {
    return null;
  }
}
function policyCoverageForTool(tool, policy) {
  const tools = policy?.tools && typeof policy.tools === "object" ? policy.tools : {};
  if (tools[tool]) {
    return { status: "exact", label: "Exact rule", policy: tools[tool] };
  }
  if (tools["*"]) {
    return { status: "wildcard", label: "Wildcard fallback", policy: tools["*"] };
  }
  return { status: "none", label: "No rule" };
}
function receiptRequestId(receipt) {
  const direct = receipt.request_id || receipt.scope;
  if (typeof direct === "string") return direct;
  const payload = receipt.payload;
  if (payload && typeof payload === "object") {
    const candidate = payload.request_id || payload.scope;
    if (typeof candidate === "string") return candidate;
  }
  const claims = receipt.signed_claims;
  if (claims && typeof claims === "object") {
    const nestedClaims = claims.claims;
    if (nestedClaims && typeof nestedClaims === "object") {
      const candidate = nestedClaims.request_id || nestedClaims.scope;
      if (typeof candidate === "string") return candidate;
    }
  }
  return void 0;
}
function buildReceiptChains(entries, receipts) {
  const receiptMap = /* @__PURE__ */ new Map();
  for (const receipt of receipts) {
    const requestId = receiptRequestId(receipt.value);
    if (!requestId) continue;
    const rows = receiptMap.get(requestId) || [];
    rows.push(receipt);
    receiptMap.set(requestId, rows);
  }
  const logMap = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    if (!entry.request_id) continue;
    const rows = logMap.get(entry.request_id) || [];
    rows.push(entry);
    logMap.set(entry.request_id, rows);
  }
  return [...logMap.entries()].map(([requestId, logs]) => {
    const relatedReceipts = receiptMap.get(requestId) || [];
    const latest = logs[logs.length - 1];
    return {
      request_id: requestId,
      tool: latest?.tool || "unknown",
      decision: latest?.decision || "unknown",
      reason_code: latest?.reason_code || "",
      action_readback: latest?.action_readback,
      log_events: logs.map((log) => ({
        decision: log.decision,
        reason_code: log.reason_code,
        timestamp: log.timestamp,
        hook_event: log.hook_event
      })),
      receipts: relatedReceipts.map((receipt) => ({
        hash: receipt.hash,
        type: String(receipt.value.type || receipt.value.artifact_type || "receipt")
      })),
      complete: relatedReceipts.length > 0
    };
  }).sort((a, b) => {
    const at = a.log_events[0]?.timestamp || 0;
    const bt = b.log_events[0]?.timestamp || 0;
    return bt - at;
  }).slice(0, 80);
}
function riskForTool(toolRaw) {
  const tool = toolRaw.toLowerCase();
  const reasons = [];
  const highPatterns = [
    ["delete", "delete/destructive"],
    ["remove", "delete/destructive"],
    ["rm", "delete/destructive"],
    ["write", "writes data"],
    ["send", "external send"],
    ["email", "external comms"],
    ["slack", "external comms"],
    ["teams", "external comms"],
    ["github", "source-control mutation"],
    ["commit", "source-control mutation"],
    ["push", "source-control mutation"],
    ["deploy", "deployment"],
    ["terraform", "cloud infrastructure"],
    ["aws", "cloud infrastructure"],
    ["gcp", "cloud infrastructure"],
    ["azure", "cloud infrastructure"],
    ["sql", "database access"],
    ["database", "database access"],
    ["payment", "spend/payment"],
    ["order", "order/transaction"],
    ["trade", "trade/transaction"],
    ["pms", "portfolio-system mutation"],
    ["book", "portfolio-system mutation"],
    ["fill", "portfolio-system mutation"],
    ["secret", "secrets"],
    ["token", "secrets"]
  ];
  for (const [needle, label] of highPatterns) {
    if (tool.includes(needle) && !reasons.includes(label)) reasons.push(label);
  }
  if (reasons.length > 0) return { tier: "high", reasons };
  if (tool.includes("read") || tool.includes("search") || tool.includes("list") || tool.includes("fetch")) {
    return { tier: "medium", reasons: ["data access"] };
  }
  return { tier: "low", reasons: ["observed"] };
}
function suggestedGuardrailFor(_tool, risk, reasons) {
  const reasonSet = new Set(reasons);
  if (reasonSet.has("delete/destructive") || reasonSet.has("secrets")) {
    return {
      action: "Block by default",
      reason: "Destructive and secret-handling tools should start deny-first.",
      policy: { block: true, min_tier: "privileged" }
    };
  }
  if (reasonSet.has("order/transaction") || reasonSet.has("trade/transaction") || reasonSet.has("spend/payment") || reasonSet.has("portfolio-system mutation") || reasonSet.has("deployment") || reasonSet.has("cloud infrastructure") || reasonSet.has("database access") || reasonSet.has("external send") || reasonSet.has("source-control mutation")) {
    return {
      action: "Require approval",
      reason: "Consequential tools should require a human approval receipt before enforce mode.",
      policy: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" }
    };
  }
  if (risk === "medium") {
    return {
      action: "Rate-limit and identify",
      reason: "Read/search/fetch tools can leak data at scale; keep them visible and bounded.",
      policy: { min_tier: "signed-known", rate_limit: "60/hour" }
    };
  }
  return {
    action: "Observe",
    reason: "Low-risk observed tool. Keep receipts and a broad rate limit.",
    policy: { rate_limit: "100/hour" }
  };
}
function buildDashboardSummary(dir, policyPath = joinCli(dir, "protect-mcp.json")) {
  const logPath = joinCli(dir, ".protect-mcp-log.jsonl");
  const receiptPath = joinCli(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = joinCli(dir, "keys", "gateway.json");
  const entries = parseJsonlFile(logPath);
  const receiptRecords = parseJsonlRecords(receiptPath);
  const receipts = receiptRecords.map((record) => record.value);
  const activePolicy = loadPolicyJson(policyPath);
  const tools = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    const tool = String(entry.tool || "unknown");
    const risk = riskForTool(tool);
    const current = tools.get(tool) || {
      tool,
      calls: 0,
      allows: 0,
      denies: 0,
      reviews: 0,
      risk: risk.tier,
      reasons: risk.reasons
    };
    current.calls += 1;
    if (entry.decision === "allow") current.allows += 1;
    else if (entry.decision === "deny") current.denies += 1;
    else if (entry.decision === "require_approval") current.reviews += 1;
    if (risk.tier === "high" || risk.tier === "medium" && current.risk === "low") current.risk = risk.tier;
    current.reasons = [.../* @__PURE__ */ new Set([...current.reasons, ...risk.reasons])];
    if (typeof entry.timestamp === "number") current.last_seen = new Date(entry.timestamp).toISOString();
    tools.set(tool, current);
  }
  const toolRows = [...tools.values()].sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 };
    return order[a.risk] - order[b.risk] || b.calls - a.calls || a.tool.localeCompare(b.tool);
  }).map((tool) => ({
    ...tool,
    suggestion: suggestedGuardrailFor(tool.tool, tool.risk, tool.reasons),
    policy_coverage: policyCoverageForTool(tool.tool, activePolicy)
  }));
  const highRisk = toolRows.filter((t) => t.risk === "high");
  const uncovered = toolRows.filter((t) => t.policy_coverage.status === "none").length;
  const exactCovered = toolRows.filter((t) => t.policy_coverage.status === "exact").length;
  const wildcardCovered = toolRows.filter((t) => t.policy_coverage.status === "wildcard").length;
  const allowed = entries.filter((e) => e.decision === "allow").length;
  const denied = entries.filter((e) => e.decision === "deny").length;
  const review = entries.filter((e) => e.decision === "require_approval").length;
  const pendingApprovals = entries.filter((e) => e.decision === "require_approval").slice(-25).reverse();
  const chains = buildReceiptChains(entries, receiptRecords);
  let key = null;
  if (existsSyncCli(keyPath)) {
    try {
      const parsed = JSON.parse(readFileSyncCli(keyPath, "utf-8"));
      key = {
        kid: parsed.kid || null,
        issuer: parsed.issuer || "protect-mcp",
        publicKeyPrefix: typeof parsed.publicKey === "string" ? `${parsed.publicKey.slice(0, 16)}...` : null
      };
    } catch {
    }
  }
  return {
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    dir,
    files: {
      log: logPath,
      receipts: receiptPath,
      key: keyPath,
      policy: policyPath,
      log_exists: existsSyncCli(logPath),
      receipts_exist: existsSyncCli(receiptPath),
      key_exists: existsSyncCli(keyPath),
      policy_exists: existsSyncCli(policyPath)
    },
    totals: {
      decisions: entries.length,
      receipts: receipts.length,
      tools: toolRows.length,
      high_risk_tools: highRisk.length,
      exact_covered: exactCovered,
      wildcard_covered: wildcardCovered,
      uncovered,
      allowed,
      denied,
      review
    },
    key,
    policy: activePolicy ? {
      path: policyPath,
      digest: createHashCli("sha256").update(JSON.stringify(activePolicy)).digest("hex").slice(0, 16),
      default_tier: activePolicy.default_tier || "unknown",
      tools: activePolicy.tools || {}
    } : null,
    tools: toolRows,
    pending_approvals: pendingApprovals,
    receipt_chains: chains,
    recent: entries.slice(-50).reverse(),
    policy_packs: {
      directory: policyPackDirectory(dir),
      installed: installedPolicyPackIds(dir),
      available: POLICY_PACKS.map((pack) => ({
        id: pack.id,
        name: pack.name,
        description: pack.description,
        recommendedMode: pack.recommendedMode,
        files: pack.files.map((file) => ({ path: file.path, contents: file.contents }))
      }))
    },
    connector_pilots: {
      directory: joinCli(dir, ".protect-mcp", "connectors"),
      installed: readInstalledConnectorPilots(dir),
      doctor: connectorDoctor(dir),
      available: CONNECTOR_PILOTS.map((pilot) => ({
        id: pilot.id,
        name: pilot.name,
        category: pilot.category,
        description: pilot.description,
        value: pilot.value,
        tools: pilot.tools,
        actions: pilot.actions,
        setup: pilot.setup
      }))
    },
    registry: dashboardRegistryStatus(dir),
    recommendations: [
      entries.length === 0 ? "Run in shadow mode first: npx protect-mcp -- node your-mcp-server.js" : "",
      highRisk.length > 0 ? "Run npx protect-mcp recommend --write, review the generated policy, then restart your wrapper with --enforce." : "",
      receipts.length === 0 ? "Run npx protect-mcp init so decisions are signed into local receipts." : "",
      "Install a starter policy pack from this dashboard when you know the tool class: filesystem, Git, email, database, cloud spend, secrets, or finance.",
      "Create a registry preview locally, then use hosted digest anchoring when you need independent timestamp evidence.",
      "Export an audit bundle with: npx protect-mcp bundle --output audit.json"
    ].filter(Boolean)
  };
}
function dashboardHtml() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>protect-mcp local action dashboard</title>
<style>
:root {
  color-scheme: light;
  --ink:#12110e; --muted:#6f6b61; --soft:#9a9488; --line:#ded7c9;
  --paper:#f7f3ea; --card:#fffdf7; --black:#11110f;
  --bad:#8f241c; --warn:#8d620f; --ok:#2f6f4e;
  --shadow: 0 22px 70px rgba(36,30,18,.10);
}
* { box-sizing: border-box; }
body { margin:0; background:radial-gradient(circle at top left,#fffdf7 0,#f7f3ea 34%,#e8dfce 100%); color:var(--ink); font:14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
main { width:min(1380px, calc(100vw - 32px)); margin:24px auto 60px; }
.hero { display:grid; grid-template-columns:1.35fr .65fr; gap:16px; align-items:stretch; }
.card { background:rgba(255,253,247,.92); border:1px solid var(--line); border-radius:24px; padding:22px; box-shadow:var(--shadow); }
.kicker { text-transform:uppercase; letter-spacing:.18em; font-size:11px; color:var(--muted); font-weight:800; }
h1 { font-family: ui-serif, Georgia, serif; font-weight:520; font-size:clamp(38px,5vw,76px); line-height:.92; letter-spacing:-.045em; margin:12px 0 14px; max-width:980px; }
h2 { margin:0 0 12px; font-size:17px; letter-spacing:-.01em; }
h3 { margin:0 0 8px; font-size:14px; }
p { color:var(--muted); margin:0; }
small { color:var(--muted); }
.layout { display:grid; grid-template-columns:1.28fr .72fr; gap:16px; margin-top:16px; }
.stack { display:grid; gap:16px; }
.stats { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:16px 0; }
.stat { background:#fffaf0; border:1px solid var(--line); border-radius:18px; padding:13px; min-height:86px; }
.stat strong { display:block; font-size:26px; letter-spacing:-.04em; }
.actions { display:flex; flex-wrap:wrap; gap:9px; margin-top:16px; }
button, a.btn { appearance:none; border:1px solid var(--black); background:var(--black); color:#fff; text-decoration:none; border-radius:999px; padding:9px 12px; cursor:pointer; font-weight:800; font-size:13px; }
button.secondary, a.btn.secondary { background:transparent; color:var(--black); }
button.ghost { border-color:var(--line); background:#fffaf0; color:var(--ink); }
button.danger { background:#7f1d18; border-color:#7f1d18; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:12px 9px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-size:11px; letter-spacing:.09em; text-transform:uppercase; }
.pill { display:inline-flex; align-items:center; border-radius:999px; padding:4px 9px; font-size:11px; font-weight:900; white-space:nowrap; }
.high { background:#f7d9d3; color:var(--bad); }
.medium { background:#f4e5bd; color:var(--warn); }
.low { background:#dcebdd; color:var(--ok); }
.exact { background:#dcebdd; color:var(--ok); }
.wildcard { background:#e5decc; color:#5e5545; }
.none { background:#f7d9d3; color:var(--bad); }
.allow { color:var(--ok); } .deny { color:var(--bad); } .require_approval { color:var(--warn); }
code { background:#f2eadc; border:1px solid var(--line); border-radius:8px; padding:2px 6px; }
pre { white-space:pre-wrap; background:#181712; color:#f8f1df; border-radius:16px; padding:14px; overflow:auto; font-size:12px; }
.muted { color:var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.approval { border:1px solid var(--line); background:#fffaf0; border-radius:18px; padding:14px; margin-bottom:10px; }
.readback { background:#181712; color:#f8f1df; border-radius:16px; padding:12px; margin:10px 0; }
.readback .label { color:#bdb49f; font-size:11px; text-transform:uppercase; letter-spacing:.12em; }
.preview { max-height:180px; overflow:auto; }
.row-actions { display:flex; flex-wrap:wrap; gap:6px; }
.chain { display:grid; gap:8px; }
.chain-item { border:1px solid var(--line); border-radius:16px; padding:12px; background:#fffaf0; }
.pack-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; margin-top:12px; }
.pack { border:1px solid var(--line); border-radius:16px; padding:12px; background:#fffaf0; display:grid; gap:8px; }
.pack.installed { border-color:rgba(47,111,78,.35); background:#f3f8ef; }
.divider { border:0; border-top:1px solid var(--line); margin:14px 0; }
.field { display:grid; gap:5px; margin-top:9px; }
.field label { font-size:11px; text-transform:uppercase; letter-spacing:.09em; color:var(--muted); font-weight:900; }
input { border:1px solid var(--line); border-radius:12px; background:#fffaf0; color:var(--ink); padding:10px; font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
.toast { position:fixed; right:18px; bottom:18px; background:#111; color:#fff; padding:12px 14px; border-radius:14px; box-shadow:var(--shadow); display:none; max-width:360px; }
@media (max-width: 980px) { .hero,.layout { grid-template-columns:1fr; } .stats { grid-template-columns:repeat(2,1fr); } main { width:min(100vw - 20px, 1380px); margin-top:14px; } }
</style>
</head>
<body>
<main>
  <section class="hero">
    <div class="card">
      <div class="kicker">Local Action Dashboard</div>
      <h1>See what agents can do. Control dangerous actions. Prove what happened.</h1>
      <p>Runs on <code>127.0.0.1</code>. Start in shadow mode, switch risky tools to exact-action approval, then export signed evidence without uploading sensitive data.</p>
      <div class="actions">
        <button onclick="refresh()">Refresh</button>
        <button class="secondary" onclick="exportBundle()">Export audit bundle</button>
        <a class="btn secondary" href="/api/summary">Raw JSON</a>
      </div>
    </div>
    <div class="card">
      <div class="kicker">Next move</div>
      <h2>Shadow, review, then enforce</h2>
      <pre>npx protect-mcp wrap -- node your-server.js
npx protect-mcp dashboard --open
npx protect-mcp recommend --write
npx protect-mcp --policy protect-mcp.json --enforce -- node your-server.js</pre>
      <p class="muted" id="dir"></p>
      <p class="muted" id="policy"></p>
    </div>
  </section>

  <section class="stats" id="stats"></section>

  <section class="layout">
    <div class="stack">
      <section class="card">
        <h2>Tool Inventory</h2>
        <p>Risk, policy coverage, and one-click guardrail drafting for each observed tool.</p>
        <div style="overflow:auto; margin-top:12px"><table id="tools"></table></div>
      </section>
      <section class="card">
        <h2>Policy Packs</h2>
        <p>Install a starter Cedar pack from the dashboard. This removes the blank-policy problem while keeping final enforcement local and reviewable.</p>
        <div id="policy-packs" class="pack-grid"></div>
      </section>
      <section class="card">
        <h2>Connector Pilots</h2>
        <p>Real tool categories teams already use: GitHub, Gmail/email, filesystem/Git, Slack or Teams, and finance/PMS. Install a pilot, check credentials, then watch those tools in the dashboard.</p>
        <div id="connector-pilots" class="pack-grid"></div>
      </section>
      <section class="card">
        <h2>Call History</h2>
        <p>What agents actually tried to do, including exact-action readbacks when available.</p>
        <div id="recent" style="margin-top:12px"></div>
      </section>
    </div>
    <div class="stack">
      <section class="card">
        <h2>Approval Queue</h2>
        <p>Desktop fallback approval surface. If you start this dashboard with <code>--approval-endpoint</code> and <code>--approval-nonce</code>, Approve forwards to the live local gateway.</p>
        <div id="approvals" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Receipt Chain</h2>
        <p>Decision logs correlated with signed receipts by request id.</p>
        <div id="chains" class="chain" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Paid Boundary</h2>
        <p>Free local receipts stay local. The paid line starts when a ScopeBlind org identity independently timestamps receipt digests without raw prompt, payload, or receipt upload.</p>
        <div id="registry" style="margin-top:12px"></div>
      </section>
      <section class="card">
        <h2>Recommendations</h2>
        <div id="recommendations"></div>
      </section>
    </div>
  </section>
</main>
<div class="toast" id="toast"></div>
<script>
var state = null;
async function refresh(){
  state = await fetch('/api/summary').then(function(r){ return r.json(); });
  render(state);
}
function render(data){
  document.getElementById('dir').textContent = 'Reading: ' + data.dir;
  document.getElementById('policy').textContent = 'Policy: ' + ((data.files || {}).policy || 'protect-mcp.json');
  var t = data.totals || {};
  document.getElementById('stats').innerHTML = [
    ['Decisions', t.decisions || 0, 'All observed tool decisions'],
    ['High risk', t.high_risk_tools || 0, 'Tools that can mutate, send, trade, deploy, or expose secrets'],
    ['Exact rules', t.exact_covered || 0, 'Tools with explicit policy entries'],
    ['Uncovered', t.uncovered || 0, 'Tools falling through without exact policy'],
    ['Receipts', t.receipts || 0, 'Signed proof records available for audit']
  ].map(function(x){ return '<div class="stat"><span class="muted">'+escapeHtml(x[0])+'</span><strong>'+x[1]+'</strong><small>'+escapeHtml(x[2])+'</small></div>'; }).join('');
  renderTools(data.tools || []);
  renderApprovals(data.pending_approvals || []);
  renderRecent(data.recent || []);
  renderChains(data.receipt_chains || []);
  renderPolicyPacks(data.policy_packs || {});
  renderConnectorPilots(data.connector_pilots || {});
  renderRegistry(data.registry || {});
  document.getElementById('recommendations').innerHTML = (data.recommendations || []).map(function(r){ return '<p style="margin:0 0 10px">* '+escapeHtml(r)+'</p>'; }).join('') || '<p class="muted">No recommendations yet.</p>';
}
function renderTools(tools){
  document.getElementById('tools').innerHTML = '<thead><tr><th>Risk</th><th>Tool</th><th>Coverage</th><th>Observed</th><th>Suggested guardrail</th><th>Actions</th></tr></thead><tbody>' +
    tools.map(function(t){
      var cov = t.policy_coverage || { status:'none', label:'No rule' };
      var s = t.suggestion || { action:'Observe', reason:'' };
      return '<tr><td><span class="pill '+t.risk+'">'+escapeHtml(t.risk)+'</span></td>'+
        '<td><strong>'+escapeHtml(t.tool)+'</strong><br><span class="muted">'+escapeHtml((t.reasons || []).join(', '))+'</span></td>'+
        '<td><span class="pill '+escapeHtml(cov.status)+'">'+escapeHtml(cov.label)+'</span><br><span class="muted mono">'+escapeHtml(JSON.stringify(cov.policy || {}))+'</span></td>'+
        '<td>'+t.calls+' calls<br><span class="allow">'+t.allows+' allow</span> \xB7 <span class="deny">'+t.denies+' deny</span> \xB7 <span class="require_approval">'+t.reviews+' review</span></td>'+
        '<td><strong>'+escapeHtml(s.action)+'</strong><br><span class="muted">'+escapeHtml(s.reason)+'</span></td>'+
        '<td><div class="row-actions"><button data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="require_approval">Require approval</button><button class="danger" data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="block">Block</button><button class="ghost" data-policy-tool="'+escapeHtml(t.tool)+'" data-policy-action="observe">Observe</button></div></td></tr>';
    }).join('') + (tools.length ? '' : '<tr><td colspan="6" class="muted">No tool calls yet. Wrap an MCP server or run the demo.</td></tr>') + '</tbody>';
}
function renderApprovals(rows){
  document.getElementById('approvals').innerHTML = rows.map(function(r){
    var rb = r.action_readback || {};
    var id = r.request_id || '';
    return '<div class="approval"><div class="kicker">Pending exact-action review</div><h3>'+escapeHtml(rb.summary || r.tool || 'Unknown action')+'</h3>'+
      '<div class="readback"><div class="label">You are approving exactly this</div><div><strong>Tool</strong>: '+escapeHtml(r.tool || 'unknown')+'</div><div><strong>Action</strong>: '+escapeHtml(rb.action || r.tool || 'unknown')+'</div><div><strong>Destination</strong>: '+escapeHtml(rb.destination || 'not declared')+'</div><div><strong>Payload hash</strong>: <span class="mono">'+escapeHtml(rb.payload_hash || 'not available')+'</span></div><div><strong>Policy basis</strong>: '+escapeHtml(r.reason_code || 'requires approval')+'</div><div class="preview"><pre>'+escapeHtml(JSON.stringify(rb.payload_preview || {}, null, 2))+'</pre></div></div>'+
      '<textarea id="reason-'+escapeAttr(id)+'" placeholder="Reason or instruction" style="width:100%; min-height:64px; border:1px solid var(--line); border-radius:12px; padding:10px"></textarea>'+
      '<div class="row-actions" style="margin-top:10px"><button data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="approve">Approve</button><button class="danger" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="deny">Deny</button><button class="ghost" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="edit">Edit</button><button class="ghost" data-approval-id="'+escapeHtml(id)+'" data-approval-tool="'+escapeHtml(r.tool || '')+'" data-approval-resolution="take_over">Take over</button></div></div>';
  }).join('') || '<p class="muted">No approval-required calls in the local log yet.</p>';
}
function renderRecent(rows){
  document.getElementById('recent').innerHTML = rows.slice(0,20).map(function(r){
    var rb = r.action_readback || {};
    return '<div class="chain-item"><strong class="'+escapeHtml(r.decision || '')+'">'+escapeHtml(r.decision || 'unknown')+'</strong> \xB7 '+escapeHtml(r.tool || 'unknown')+'<br><span class="muted">'+escapeHtml(rb.summary || r.reason_code || '')+'</span><br><span class="muted mono">'+escapeHtml(r.request_id || '')+'</span></div>';
  }).join('') || '<p class="muted">No decisions yet.</p>';
}
function renderChains(rows){
  document.getElementById('chains').innerHTML = rows.slice(0,12).map(function(c){
    var hashes = (c.receipts || []).map(function(r){ return '<span class="mono">'+escapeHtml((r.hash || '').slice(0,16))+'...</span>'; }).join('<br>');
    return '<div class="chain-item"><strong>'+escapeHtml(c.tool || 'unknown')+'</strong> <span class="pill '+(c.complete ? 'exact' : 'none')+'">'+(c.complete ? 'receipt linked' : 'no receipt')+'</span><br><span class="muted">'+escapeHtml(((c.action_readback || {}).summary) || c.reason_code || '')+'</span><br><span class="muted mono">request '+escapeHtml(c.request_id || '')+'</span><div style="margin-top:8px">'+(hashes || '<span class="muted">No signed receipt hash found</span>')+'</div></div>';
  }).join('') || '<p class="muted">No receipt chains yet.</p>';
}
function renderPolicyPacks(info){
  var available = info.available || [];
  var installed = new Set(info.installed || []);
  document.getElementById('policy-packs').innerHTML = available.map(function(pack){
    var isInstalled = installed.has(pack.id);
    var files = (pack.files || []).map(function(f){ return f.path; }).join(', ');
    return '<div class="pack '+(isInstalled ? 'installed' : '')+'">'+
      '<div style="display:flex;gap:8px;align-items:center"><strong>'+escapeHtml(pack.name)+'</strong><span class="pill '+(isInstalled ? 'exact' : 'wildcard')+'">'+(isInstalled ? 'installed' : escapeHtml(pack.recommendedMode || 'shadow-first'))+'</span></div>'+
      '<p>'+escapeHtml(pack.description || '')+'</p>'+
      '<small>Writes to <code>'+escapeHtml((info.directory || './cedar') + '/' + files)+'</code></small>'+
      '<div class="row-actions"><button data-pack-install="'+escapeHtml(pack.id)+'">'+(isInstalled ? 'Reinstall' : 'Install')+'</button><button class="ghost" data-pack-preview="'+escapeHtml(pack.id)+'">Preview</button></div>'+
      '<pre id="pack-preview-'+escapeAttr(pack.id)+'" style="display:none;max-height:240px">'+escapeHtml((pack.files || []).map(function(f){ return '--- '+f.path+' ---\\n'+f.contents; }).join('\\n\\n'))+'</pre>'+
    '</div>';
  }).join('') || '<p class="muted">No policy packs bundled.</p>';
}
function renderConnectorPilots(info){
  var available = info.available || [];
  var installed = new Set((info.installed || []).map(function(row){ return row.id; }));
  var doctor = {};
  (info.doctor || []).forEach(function(row){ doctor[row.id] = row; });
  document.getElementById('connector-pilots').innerHTML = available.map(function(pilot){
    var row = doctor[pilot.id] || {};
    var isInstalled = installed.has(pilot.id);
    var status = row.installed ? (row.usable ? 'installed' : 'needs env') : 'not installed';
    var statusClass = row.installed ? (row.usable ? 'exact' : 'wildcard') : 'none';
    var missing = (row.missing_required || []).join(', ');
    var tools = (pilot.tools || []).slice(0,4).map(function(tool){ return '<code>'+escapeHtml(tool)+'</code>'; }).join(' ');
    return '<div class="pack '+(isInstalled ? 'installed' : '')+'">'+
      '<div style="display:flex;gap:8px;align-items:center"><strong>'+escapeHtml(pilot.name)+'</strong><span class="pill '+statusClass+'">'+escapeHtml(status)+'</span></div>'+
      '<p>'+escapeHtml(pilot.description || '')+'</p>'+
      '<small>'+escapeHtml(pilot.value || '')+'</small>'+
      '<div>'+tools+'</div>'+
      (missing ? '<small>Missing: <code>'+escapeHtml(missing)+'</code></small>' : '<small>'+escapeHtml(row.next || 'Ready for shadow-mode review.')+'</small>')+
      '<details><summary>Details</summary><pre>'+escapeHtml(JSON.stringify({ setup: pilot.setup, actions: pilot.actions, doctor: row }, null, 2))+'</pre></details>'+
      '<div class="row-actions"><button data-connector-install="'+escapeHtml(pilot.id)+'">'+(isInstalled ? 'Reinstall' : 'Install')+'</button><button class="ghost" data-connector-doctor="1">Run doctor</button></div>'+
    '</div>';
  }).join('') || '<p class="muted">No connector pilots bundled.</p>';
}
function renderRegistry(reg){
  var boundaryClass = reg.hosted ? 'exact' : reg.registry_exists ? 'wildcard' : 'none';
  document.getElementById('registry').innerHTML =
    '<div class="chain-item"><span class="pill '+boundaryClass+'">'+escapeHtml(reg.boundary || 'not configured')+'</span>'+
    '<p style="margin-top:8px"><strong>'+escapeHtml(reg.org_name || 'No org identity yet')+'</strong></p>'+
    '<p class="muted">Digests: '+(reg.records || 0)+' \xB7 Anchors: '+(reg.anchors || 0)+'</p>'+
    '<p class="muted mono" style="margin-top:6px">'+escapeHtml(reg.registry_path || '')+'</p></div>'+
    '<div class="field"><label>Org name</label><input id="registry-org" placeholder="Meridian Global Macro" value="'+escapeHtml(reg.org_name || '')+'"></div>'+
    '<div class="field"><label>Hosted token (optional, not stored)</label><input id="registry-token" type="password" placeholder="SCOPEBLIND_TOKEN for hosted digest anchoring"></div>'+
    '<div class="row-actions" style="margin-top:10px"><button data-registry-anchor="local">Create local registry preview</button><button class="secondary" data-registry-anchor="hosted">Hosted digest anchor</button></div>'+
    '<small style="display:block;margin-top:8px">Hosted mode uploads digest metadata only: receipt hash, byte count, receipt type, request id, local issuer/kid, org id, billing account, and public keys. It does not upload prompts, tool payloads, outputs, raw receipts, or private keys.</small>';
}
async function setPolicy(tool, action){
  var res = await fetch('/api/tool-policy', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ tool: tool, action: action }) });
  if(!res.ok){ toast('Policy update failed'); return; }
  toast('Policy updated: '+tool+' -> '+action+'. Restart the wrapper to apply.');
  await refresh();
}
async function resolveApproval(requestId, tool, resolution){
  var reasonEl = document.getElementById('reason-'+escapeAttr(requestId));
  var reason = reasonEl ? reasonEl.value : '';
  var edited = undefined;
  if(resolution === 'edit'){
    var raw = prompt('Paste edited JSON payload. This records the edit instruction; rerun the tool with the edited payload.');
    if(raw){ try { edited = JSON.parse(raw); } catch(e){ toast('Edit payload is not valid JSON'); return; } }
  }
  var res = await fetch('/api/approval/resolve', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ request_id: requestId, tool: tool, resolution: resolution, reason: reason, edited_payload: edited }) });
  var body = await res.json().catch(function(){ return {}; });
  toast(resolution+' recorded'+(body.forwarded && body.forwarded.ok ? ' and forwarded to live gateway' : ' locally'));
}
async function installPack(pack){
  var res = await fetch('/api/policy-packs/install', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ pack: pack, force: true }) });
  var body = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(body.error || 'Policy pack install failed'); return; }
  toast('Installed '+pack+' into '+body.dir);
  await refresh();
}
async function installConnector(pilot){
  var res = await fetch('/api/connectors/install', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ pilot: pilot, force: true }) });
  var body = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(body.error || 'Connector install failed'); return; }
  toast('Installed '+pilot+' into '+body.dir);
  await refresh();
}
function togglePackPreview(pack){
  var el = document.getElementById('pack-preview-'+escapeAttr(pack));
  if(el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
async function anchorRegistry(mode){
  var org = document.getElementById('registry-org') ? document.getElementById('registry-org').value : '';
  var token = document.getElementById('registry-token') ? document.getElementById('registry-token').value : '';
  var body = { org_name: org, hosted: mode === 'hosted', token: token };
  var res = await fetch('/api/registry/anchor', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body) });
  var out = await res.json().catch(function(){ return {}; });
  if(!res.ok){ toast(out.error || 'Registry anchor failed'); return; }
  toast((out.uploaded ? 'Hosted anchor complete' : 'Local registry preview written') + ': ' + out.records + ' digest(s)');
  await refresh();
}
async function exportBundle(){
  var res = await fetch('/api/audit-bundle');
  if(!res.ok){
    var err = await res.json().catch(function(){ return {}; });
    toast(err.message || 'Audit bundle export requires signed receipts');
    return;
  }
  var blob = await res.blob();
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'protect-mcp-audit-bundle.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
}
document.addEventListener('click', function(ev){
  var target = ev.target && ev.target.closest ? ev.target.closest('[data-policy-tool],[data-approval-id],[data-pack-install],[data-pack-preview],[data-registry-anchor],[data-connector-install],[data-connector-doctor]') : null;
  if(!target) return;
  var connectorInstall = target.getAttribute('data-connector-install');
  if(connectorInstall){ installConnector(connectorInstall); return; }
  if(target.getAttribute('data-connector-doctor')){ toast('Connector doctor refreshed. Missing secrets are shown as names only, never values.'); refresh(); return; }
  var packInstall = target.getAttribute('data-pack-install');
  if(packInstall){ installPack(packInstall); return; }
  var packPreview = target.getAttribute('data-pack-preview');
  if(packPreview){ togglePackPreview(packPreview); return; }
  var anchorMode = target.getAttribute('data-registry-anchor');
  if(anchorMode){ anchorRegistry(anchorMode); return; }
  var policyTool = target.getAttribute('data-policy-tool');
  if(policyTool){
    setPolicy(policyTool, target.getAttribute('data-policy-action') || 'require_approval');
    return;
  }
  var approvalId = target.getAttribute('data-approval-id');
  if(approvalId){
    resolveApproval(approvalId, target.getAttribute('data-approval-tool') || '', target.getAttribute('data-approval-resolution') || 'deny');
  }
});
function toast(msg){ var el=document.getElementById('toast'); el.textContent=msg; el.style.display='block'; setTimeout(function(){el.style.display='none';}, 4200); }
function escapeHtml(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function escapeAttr(v){ return String(v || '').replace(/[^A-Za-z0-9_-]/g,'_'); }
refresh();
</script>
</body>
</html>`;
}
async function handleDashboard(argv) {
  const { createServer } = await import("http");
  const { execFile } = await import("child_process");
  const { resolve } = await import("path");
  const port = commandNeedsValue(argv, "--port") ? parseInt(flagValue(argv, "--port") || "9877", 10) : 9877;
  const dir = resolve(commandNeedsValue(argv, "--dir") ? flagValue(argv, "--dir") || process.cwd() : process.cwd());
  const policyPath = resolve(flagValue(argv, "--policy") || joinCli(dir, "protect-mcp.json"));
  const approvalEndpoint = flagValue(argv, "--approval-endpoint");
  const approvalNonce = flagValue(argv, "--approval-nonce");
  const open = argv.includes("--open");
  const server = createServer((req, res) => {
    void (async () => {
      try {
        const url2 = new URL(req.url || "/", "http://127.0.0.1");
        if (url2.pathname === "/api/summary") {
          const body = JSON.stringify(buildDashboardSummary(dir, policyPath), null, 2);
          res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
          res.end(body);
          return;
        }
        if (url2.pathname === "/api/tool-policy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const tool = typeof body.tool === "string" ? body.tool : "";
          const action = body.action === "block" || body.action === "observe" ? body.action : "require_approval";
          if (!tool) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_tool" }));
            return;
          }
          const policy = writeToolPolicy(policyPath, tool, action);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, policy_path: policyPath, policy }));
          return;
        }
        if (url2.pathname === "/api/policy-packs/install" && req.method === "POST") {
          const body = await readJsonBody(req);
          const pack = typeof body.pack === "string" ? body.pack : "";
          if (!pack) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_policy_pack" }));
            return;
          }
          const installed = installPolicyPackToDir(dir, pack, Boolean(body.force));
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            ok: true,
            ...installed,
            installed: installedPolicyPackIds(dir)
          }));
          return;
        }
        if (url2.pathname === "/api/connectors/install" && req.method === "POST") {
          const body = await readJsonBody(req);
          const pilot = typeof body.pilot === "string" ? body.pilot : "";
          if (!pilot) {
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "missing_connector_pilot" }));
            return;
          }
          const installed = writeConnectorPilots({ dir, ids: [pilot], force: Boolean(body.force) });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            ok: true,
            dir: installed.directory,
            written: installed.written,
            installed: readInstalledConnectorPilots(dir),
            doctor: connectorDoctor(dir)
          }));
          return;
        }
        if (url2.pathname === "/api/registry/anchor" && req.method === "POST") {
          const body = await readJsonBody(req);
          const { createReceiptRegistry } = await import("./receipt-registry-6CAOY6RP.mjs");
          try {
            const hosted = Boolean(body.hosted);
            const result = await createReceiptRegistry({
              dir,
              orgName: typeof body.org_name === "string" && body.org_name.trim() ? body.org_name.trim() : void 0,
              orgId: typeof body.org_id === "string" && body.org_id.trim() ? body.org_id.trim() : void 0,
              billingAccountId: typeof body.billing_account_id === "string" && body.billing_account_id.trim() ? body.billing_account_id.trim() : void 0,
              hosted,
              token: typeof body.token === "string" && body.token.trim() ? body.token.trim() : process.env.SCOPEBLIND_TOKEN,
              endpoint: typeof body.endpoint === "string" && body.endpoint.trim() ? body.endpoint.trim() : hosted ? process.env.SCOPEBLIND_REGISTRY_ENDPOINT || "https://api.scopeblind.com" : void 0,
              verifierBaseUrl: typeof body.verifier_base === "string" && body.verifier_base.trim() ? body.verifier_base.trim() : process.env.SCOPEBLIND_VERIFIER_BASE || "https://legate.scopeblind.com"
            });
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({
              ok: true,
              uploaded: result.uploaded,
              records: result.registry.records.length,
              anchors: result.registry.anchors.length,
              registry_path: result.registryPath,
              verifier_path: result.verifierPath,
              registry: dashboardRegistryStatus(dir)
            }));
          } catch (err) {
            res.writeHead(409, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
            res.end(JSON.stringify({
              error: "registry_anchor_unavailable",
              message: err instanceof Error ? err.message : String(err),
              next_step: "Run protect-mcp with signing enabled so decisions are written as signed receipts, then try again."
            }));
          }
          return;
        }
        if (url2.pathname === "/api/approval/resolve" && req.method === "POST") {
          const body = await readJsonBody(req);
          const result = await recordApprovalResolution({ dir, approvalEndpoint, approvalNonce, body });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(result));
          return;
        }
        if (url2.pathname === "/api/audit-bundle") {
          let bundle;
          try {
            bundle = await buildAuditBundleForDir(dir);
          } catch (err) {
            res.writeHead(409, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
            res.end(JSON.stringify({
              error: "audit_bundle_unavailable",
              message: err instanceof Error ? err.message : String(err),
              next_step: "Run protect-mcp with signing enabled so decisions are written as signed receipts, then export again."
            }));
            return;
          }
          res.writeHead(200, {
            "content-type": "application/json; charset=utf-8",
            "content-disposition": 'attachment; filename="protect-mcp-audit-bundle.json"',
            "cache-control": "no-store"
          });
          res.end(JSON.stringify(bundle, null, 2) + "\n");
          return;
        }
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        });
        res.end(dashboardHtml());
      } catch (err) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
    })();
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(port, "127.0.0.1", () => resolveListen());
  });
  const url = `http://127.0.0.1:${port}`;
  process.stderr.write(`
${bold("protect-mcp dashboard")}

`);
  process.stderr.write(`  Local URL: ${url}
`);
  process.stderr.write(`  Reading:   ${dir}
`);
  process.stderr.write(`  Policy:    ${policyPath}
`);
  process.stderr.write(`  Network:   127.0.0.1 only; no uploads

`);
  if (open) {
    const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
    const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
    execFile(opener, args, () => {
    });
  }
}
function draftPolicyFromSummary(summary) {
  const files = summary.files || {};
  const rows = Array.isArray(summary.tools) ? summary.tools : [];
  const tools = {
    "*": { rate_limit: "100/hour" }
  };
  for (const row of rows) {
    if (!row.tool || row.tool === "unknown") continue;
    const suggestion = row.suggestion || suggestedGuardrailFor(row.tool, row.risk || "low", row.reasons || []);
    tools[row.tool] = suggestion.policy;
  }
  return {
    tools,
    default_tier: "unknown",
    signing: files.key_exists ? {
      key_path: "./keys/gateway.json",
      issuer: "protect-mcp"
    } : void 0,
    notes: [
      "Generated from local shadow-mode inventory.",
      "Review before running with --enforce.",
      "High-risk transaction, deployment, external-send, and database tools require approval.",
      "Destructive and secret-handling tools are blocked by default."
    ]
  };
}
function writeToolPolicy(policyPath, tool, action) {
  const existing = loadPolicyJson(policyPath) || { tools: {}, default_tier: "unknown" };
  const tools = existing.tools && typeof existing.tools === "object" ? { ...existing.tools } : {};
  if (action === "require_approval") {
    tools[tool] = { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" };
  } else if (action === "block") {
    tools[tool] = { block: true, min_tier: "privileged" };
  } else {
    tools[tool] = { rate_limit: "100/hour" };
  }
  const next = {
    ...existing,
    tools,
    default_tier: existing.default_tier || "unknown"
  };
  writeFileSyncCli(policyPath, JSON.stringify(next, null, 2) + "\n");
  return next;
}
function policyPackDirectory(dir) {
  return joinCli(dir, "cedar");
}
function installedPolicyPackIds(dir) {
  const cedarDir = policyPackDirectory(dir);
  return POLICY_PACKS.filter(
    (pack) => pack.files.every((file) => existsSyncCli(joinCli(cedarDir, file.path)))
  ).map((pack) => pack.id);
}
function installPolicyPackToDir(dir, packId, force = false) {
  const packs = packId === "all" ? POLICY_PACKS : [getPolicyPack(packId)].filter(Boolean);
  if (packs.length === 0) throw new Error(`Unknown policy pack: ${packId}`);
  const outDir = policyPackDirectory(dir);
  mkdirSyncCli(outDir, { recursive: true });
  const written = [];
  for (const pack of packs) {
    for (const file of pack.files) {
      const outPath = joinCli(outDir, file.path);
      if (existsSyncCli(outPath) && !force) {
        throw new Error(`Refusing to overwrite ${outPath}. Pass force=true if intentional.`);
      }
      mkdirSyncCli(dirnameCli(outPath), { recursive: true });
      writeFileSyncCli(outPath, file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
      written.push(outPath);
    }
  }
  return { dir: outDir, written, packs: packs.map((pack) => pack.id) };
}
function dashboardRegistryStatus(dir) {
  const identityPath = joinCli(dir, ".protect-mcp-org.json");
  const registryPath = joinCli(dir, ".protect-mcp-registry.json");
  const verifierPath = joinCli(dir, "scopeblind-verifier.html");
  const identity = existsSyncCli(identityPath) ? (() => {
    try {
      return JSON.parse(readFileSyncCli(identityPath, "utf-8"));
    } catch {
      return null;
    }
  })() : null;
  const registry = existsSyncCli(registryPath) ? (() => {
    try {
      return JSON.parse(readFileSyncCli(registryPath, "utf-8"));
    } catch {
      return null;
    }
  })() : null;
  const anchors = Array.isArray(registry?.anchors) ? registry.anchors : [];
  const hosted = anchors.some((anchor) => anchor.timestamp_source === "scopeblind-hosted");
  return {
    identity_exists: existsSyncCli(identityPath),
    registry_exists: existsSyncCli(registryPath),
    verifier_exists: existsSyncCli(verifierPath),
    identity_path: identityPath,
    registry_path: registryPath,
    verifier_path: verifierPath,
    org_name: identity?.org_name || (registry?.org && typeof registry.org === "object" ? registry.org.org_name : null),
    org_id: identity?.org_id || (registry?.org && typeof registry.org === "object" ? registry.org.org_id : null),
    billing_account_id: identity?.billing_account_id || (registry?.billing && typeof registry.billing === "object" ? registry.billing.billing_account_id : null),
    records: Array.isArray(registry?.records) ? registry.records.length : 0,
    anchors: anchors.length,
    hosted,
    boundary: hosted ? "hosted digest anchor" : registry ? "local preview only" : "not configured"
  };
}
async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  const raw = Buffer.concat(chunks).toString("utf-8").trim();
  return raw ? JSON.parse(raw) : {};
}
async function buildAuditBundleForDir(dir) {
  const { createAuditBundle } = await import("./bundle-YUUHAG7O.mjs");
  const receiptPath = joinCli(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = joinCli(dir, "keys", "gateway.json");
  if (!existsSyncCli(receiptPath)) throw new Error("No receipt file found.");
  if (!existsSyncCli(keyPath)) throw new Error("No signing key found.");
  const receipts = parseJsonlFile(receiptPath);
  if (receipts.length === 0) throw new Error("No signed receipts found.");
  const keyData = JSON.parse(readFileSyncCli(keyPath, "utf-8"));
  return createAuditBundle({
    tenant: keyData.issuer || "protect-mcp",
    receipts,
    selectiveDisclosures: collectSelectiveDisclosurePackages(dir),
    signingKeys: [{
      kty: "OKP",
      crv: "Ed25519",
      kid: keyData.kid || "unknown",
      x: Buffer.from(keyData.publicKey || "", "hex").toString("base64url"),
      use: "sig"
    }]
  });
}
function collectSelectiveDisclosurePackages(dir) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  const candidates = [];
  const receiptsDir = joinCli(dir, "receipts");
  if (existsSyncCli(receiptsDir)) {
    for (const name of readdirSyncCli(receiptsDir)) {
      if (name.includes("selective-disclosure") && name.endsWith(".json")) {
        candidates.push(joinCli(receiptsDir, name));
      }
    }
  }
  const jsonlPath = joinCli(dir, ".protect-mcp-selective-disclosures.jsonl");
  if (existsSyncCli(jsonlPath)) {
    for (const line of readFileSyncCli(jsonlPath, "utf-8").split("\n").map((s) => s.trim()).filter(Boolean)) {
      try {
        const parsed = JSON.parse(line);
        addSelectiveDisclosure(out, seen, parsed);
      } catch {
      }
    }
  }
  for (const path of candidates) {
    try {
      const parsed = JSON.parse(readFileSyncCli(path, "utf-8"));
      addSelectiveDisclosure(out, seen, parsed);
    } catch {
    }
  }
  return out;
}
function addSelectiveDisclosure(out, seen, parsed) {
  if (parsed?.type !== "scopeblind.selective_disclosure.v0") return;
  const key = [
    parsed.parent_receipt_hash || "",
    Array.isArray(parsed.disclosed_fields) ? parsed.disclosed_fields.slice().sort().join(",") : "",
    Array.isArray(parsed.hidden_fields) ? parsed.hidden_fields.slice().sort().join(",") : ""
  ].join("|");
  if (seen.has(key)) return;
  seen.add(key);
  out.push(parsed);
}
async function recordApprovalResolution(opts) {
  const resolution = String(opts.body.resolution || "deny");
  const requestId = String(opts.body.request_id || "");
  const tool = String(opts.body.tool || "unknown");
  const record = {
    type: "scopeblind.approval_resolution.v1",
    at: (/* @__PURE__ */ new Date()).toISOString(),
    request_id: requestId,
    tool,
    resolution,
    reason: typeof opts.body.reason === "string" ? opts.body.reason.slice(0, 1e3) : "",
    edited_payload: opts.body.edited_payload || void 0,
    takeover_note: opts.body.takeover_note || void 0,
    payload_hash: opts.body.payload_hash || void 0
  };
  appendFileSyncCli(joinCli(opts.dir, ".protect-mcp-approval-resolutions.jsonl"), JSON.stringify(record) + "\n");
  let forwarded = null;
  if (resolution === "approve" && opts.approvalEndpoint && opts.approvalNonce) {
    const endpoint = opts.approvalEndpoint.replace(/\/$/, "") + "/approve";
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        request_id: requestId,
        tool,
        mode: "once",
        nonce: opts.approvalNonce
      })
    });
    forwarded = {
      ok: response.ok,
      status: response.status,
      body: await response.text().catch(() => "")
    };
  }
  return { recorded: true, resolution: record, forwarded };
}
async function handleRecommend(argv) {
  const { writeFileSync } = await import("fs");
  const { resolve } = await import("path");
  const dir = resolve(commandNeedsValue(argv, "--dir") ? flagValue(argv, "--dir") || process.cwd() : process.cwd());
  const outputPath = resolve(flagValue(argv, "--output") || "protect-mcp.recommended.json");
  const write = argv.includes("--write");
  const summary = buildDashboardSummary(dir);
  const totals = summary.totals;
  const policy = draftPolicyFromSummary(summary);
  const rows = Array.isArray(summary.tools) ? summary.tools : [];
  process.stdout.write(`
${bold("protect-mcp recommend")}

`);
  process.stdout.write(`  Source:    ${dir}
`);
  process.stdout.write(`  Decisions: ${totals.decisions || 0}
`);
  process.stdout.write(`  Tools:     ${totals.tools || 0}

`);
  if (rows.length === 0) {
    process.stdout.write(`No tool calls found yet. First run:

`);
    process.stdout.write(`  ${dim("npx protect-mcp wrap -- node your-mcp-server.js")}
`);
    process.stdout.write(`  ${dim("npx protect-mcp dashboard --open")}

`);
    return;
  }
  for (const row of rows) {
    const suggestion = row.suggestion || suggestedGuardrailFor(row.tool, row.risk, row.reasons);
    process.stdout.write(`  - ${row.tool}: ${bold(suggestion.action)} (${row.risk})
`);
    process.stdout.write(`    ${dim(suggestion.reason)}
`);
  }
  const body = JSON.stringify(policy, null, 2) + "\n";
  if (!write) {
    process.stdout.write(`
Dry run only. Write the policy with:
`);
    process.stdout.write(`  ${dim("npx protect-mcp recommend --write")}

`);
    process.stdout.write(dim(body));
    return;
  }
  writeFileSync(outputPath, body);
  process.stdout.write(`
${green("\u2713 Wrote recommended policy")}
`);
  process.stdout.write(`  Output: ${outputPath}
`);
  process.stdout.write(`  Review it, then restart your wrapper with:
`);
  process.stdout.write(`  ${dim(shellCommand("npx", ["protect-mcp", "--policy", outputPath, "--enforce", "--", "node", "your-mcp-server.js"]))}

`);
}
async function handleWrap(argv) {
  const { existsSync, readFileSync, writeFileSync } = await import("fs");
  const { resolve } = await import("path");
  const configFlag = flagValue(argv, "--config");
  const cedarFlag = flagValue(argv, "--cedar");
  const enforce = argv.includes("--enforce");
  const write = argv.includes("--write");
  const claudeDesktop = argv.includes("--claude-desktop") || argv.includes("--claude");
  const serverName = flagValue(argv, "--server");
  const separator = argv.indexOf("--");
  const childCommand = separator >= 0 ? argv.slice(separator + 1).filter(Boolean) : [];
  const configPath = cedarFlag ? void 0 : resolve(configFlag || await ensureLocalConfig(process.cwd()));
  const cedarDir = cedarFlag ? resolve(cedarFlag) : void 0;
  if (childCommand.length > 0) {
    const args = wrapperArgsFor(childCommand, { configPath, cedarDir, enforce });
    process.stdout.write(`
${bold("protect-mcp wrap")}

`);
    process.stdout.write(`Use this command in your MCP client config:

`);
    process.stdout.write(`  ${shellCommand("npx", args)}

`);
    process.stdout.write(`Claude Desktop JSON snippet:

`);
    process.stdout.write(dim(JSON.stringify({
      command: "npx",
      args
    }, null, 2)) + "\n\n");
    process.stdout.write(`Then inspect calls with: ${dim("npx protect-mcp dashboard --open")}

`);
    return;
  }
  const claudePath = resolve(flagValue(argv, "--path") || claudeDesktopConfigPath());
  if (!claudeDesktop && !existsSync(claudePath)) {
    process.stdout.write(`
${bold("protect-mcp wrap")}

`);
    process.stdout.write(`No command was passed after "--" and no Claude Desktop config was found.

`);
    process.stdout.write(`Examples:
`);
    process.stdout.write(`  ${dim("npx protect-mcp wrap -- node server.js")}
`);
    process.stdout.write(`  ${dim("npx protect-mcp wrap --claude-desktop --write")}

`);
    return;
  }
  if (!existsSync(claudePath)) {
    process.stderr.write(`protect-mcp wrap: Claude Desktop config not found at ${claudePath}
`);
    process.exit(1);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(claudePath, "utf-8"));
  } catch (err) {
    process.stderr.write(`protect-mcp wrap: could not parse ${claudePath}: ${err instanceof Error ? err.message : err}
`);
    process.exit(1);
  }
  const servers = parsed.mcpServers || {};
  const names = Object.keys(servers).filter((name) => !serverName || name === serverName);
  if (names.length === 0) {
    process.stderr.write(`protect-mcp wrap: no MCP servers found${serverName ? ` matching "${serverName}"` : ""}.
`);
    process.exit(1);
  }
  const next = { ...parsed, mcpServers: { ...servers } };
  const changes = [];
  for (const name of names) {
    const before = servers[name] || {};
    const originalCommand = before.command;
    const originalArgs = Array.isArray(before.args) ? before.args : [];
    if (!originalCommand) {
      changes.push({ name, before, after: before, skipped: "missing command" });
      continue;
    }
    if (originalCommand === "npx" && originalArgs.some((arg) => String(arg).includes("protect-mcp"))) {
      changes.push({ name, before, after: before, skipped: "already wrapped" });
      continue;
    }
    const wrappedArgs = wrapperArgsFor([originalCommand, ...originalArgs], { configPath, cedarDir, enforce });
    const after = { ...before, command: "npx", args: wrappedArgs };
    next.mcpServers[name] = after;
    changes.push({ name, before, after });
  }
  process.stdout.write(`
${bold("protect-mcp wrap: Claude Desktop")}

`);
  process.stdout.write(`Config: ${claudePath}
`);
  process.stdout.write(`Mode:   ${enforce ? "enforce" : "shadow"}

`);
  for (const change of changes) {
    if (change.skipped) {
      process.stdout.write(`  - ${change.name}: ${yellow(change.skipped)}
`);
    } else {
      process.stdout.write(`  - ${change.name}: ${green("will wrap")}
`);
      process.stdout.write(`    ${dim(`${change.before.command || ""} ${(change.before.args || []).join(" ")}`)}
`);
      process.stdout.write(`    ${dim(shellCommand("npx", change.after.args || []))}
`);
    }
  }
  if (!write) {
    process.stdout.write(`
Dry run only. Apply with:
`);
    process.stdout.write(`  ${dim("npx protect-mcp wrap --claude-desktop --write")}

`);
    return;
  }
  const backupPath = `${claudePath}.bak.${Date.now()}`;
  writeFileSync(backupPath, readFileSync(claudePath, "utf-8"));
  writeFileSync(claudePath, JSON.stringify(next, null, 2) + "\n");
  process.stdout.write(`
${green("\u2713 Claude Desktop config updated")}
`);
  process.stdout.write(`  Backup: ${backupPath}
`);
  process.stdout.write(`  Restart Claude Desktop, then run: ${dim("npx protect-mcp dashboard --open")}

`);
}
function bold(s) {
  return process.env.NO_COLOR ? s : `\x1B[1m${s}\x1B[0m`;
}
function dim(s) {
  return process.env.NO_COLOR ? s : `\x1B[2m${s}\x1B[0m`;
}
function green(s) {
  return process.env.NO_COLOR ? s : `\x1B[32m${s}\x1B[0m`;
}
function red(s) {
  return process.env.NO_COLOR ? s : `\x1B[31m${s}\x1B[0m`;
}
function yellow(s) {
  return process.env.NO_COLOR ? s : `\x1B[33m${s}\x1B[0m`;
}
async function handleDigest(argv) {
  const { readFileSync, existsSync } = await import("fs");
  const { join } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const today = argv.includes("--today");
  const logPath = join(dir, ".protect-mcp-log.jsonl");
  if (!existsSync(logPath)) {
    process.stderr.write(`${bold("protect-mcp digest")}

No log file found. Run protect-mcp first.
`);
    process.exit(0);
  }
  const raw = readFileSync(logPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  let entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
    }
  }
  if (today) {
    const todayStart = /* @__PURE__ */ new Date();
    todayStart.setHours(0, 0, 0, 0);
    entries = entries.filter((e) => e.timestamp >= todayStart.getTime());
  }
  if (entries.length === 0) {
    process.stdout.write(`
${bold("\u{1F6E1}\uFE0F Agent Digest")}

  No activity${today ? " today" : ""}.

`);
    process.exit(0);
  }
  const allowed = entries.filter((e) => e.decision === "allow").length;
  const denied = entries.filter((e) => e.decision === "deny").length;
  const approvalRequired = entries.filter((e) => e.decision === "require_approval").length;
  const toolUsage = /* @__PURE__ */ new Map();
  for (const e of entries) {
    toolUsage.set(e.tool, (toolUsage.get(e.tool) || 0) + 1);
  }
  const sortedTools = [...toolUsage.entries()].sort((a, b) => b[1] - a[1]);
  const currentTier = entries[entries.length - 1]?.tier || "unknown";
  const firstTime = new Date(Math.min(...entries.map((e) => e.timestamp)));
  const lastTime = new Date(Math.max(...entries.map((e) => e.timestamp)));
  const durationMs = lastTime.getTime() - firstTime.getTime();
  const durationStr = durationMs < 6e4 ? `${Math.round(durationMs / 1e3)}s` : durationMs < 36e5 ? `${Math.round(durationMs / 6e4)}m` : `${(durationMs / 36e5).toFixed(1)}h`;
  process.stdout.write(`
${bold("\u{1F6E1}\uFE0F Agent Daily Digest")}

`);
  process.stdout.write(`  \u{1F4CA} ${bold(String(entries.length))} actions | `);
  process.stdout.write(`${green("\u2713 " + allowed)} allowed | `);
  process.stdout.write(`${red("\u2717 " + denied)} blocked`);
  if (approvalRequired > 0) process.stdout.write(` | ${yellow("\u23F3 " + approvalRequired)} awaiting approval`);
  process.stdout.write(`
`);
  process.stdout.write(`  \u{1F3C5} Trust tier: ${bold(currentTier)} | \u23F1 Active: ${durationStr}

`);
  process.stdout.write(`  ${bold("Tools used:")}
`);
  for (const [tool, count] of sortedTools.slice(0, 8)) {
    process.stdout.write(`    ${tool.padEnd(22)} ${count}x
`);
  }
  if (denied > 0) {
    const deniedTools = entries.filter((e) => e.decision === "deny");
    const deniedToolNames = [...new Set(deniedTools.map((e) => e.tool))];
    process.stdout.write(`
  ${bold(red("Blocked tools:"))}
`);
    for (const tool of deniedToolNames) {
      const reason = deniedTools.find((e) => e.tool === tool)?.reason_code || "policy";
      process.stdout.write(`    ${red("\u2717")} ${tool} (${reason})
`);
    }
  }
  process.stdout.write(`
  ${dim("Latest receipt: curl -s http://127.0.0.1:9876/receipts/latest | jq -r .receipt > receipt.json")}
`);
  process.stdout.write(`  ${dim("Verify: npx @veritasacta/verify receipt.json --key <public-key-hex>")}
`);
  process.stdout.write(`  ${dim("Export: npx protect-mcp bundle --output audit.json")}

`);
}
async function handleReceipts(argv) {
  const { readFileSync, existsSync } = await import("fs");
  const { join } = await import("path");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const lastIdx = argv.indexOf("--last");
  const count = lastIdx !== -1 && argv[lastIdx + 1] ? parseInt(argv[lastIdx + 1], 10) : 20;
  const receiptsPath = join(dir, ".protect-mcp-receipts.jsonl");
  if (!existsSync(receiptsPath)) {
    process.stderr.write(`${bold("protect-mcp receipts")}

No signed receipt file found. Run protect-mcp with signing enabled first.
`);
    process.exit(0);
  }
  const raw = readFileSync(receiptsPath, "utf-8");
  const lines = raw.trim().split("\n").filter(Boolean);
  const recent = lines.slice(-count);
  process.stdout.write(`
${bold("\u{1F6E1}\uFE0F Recent Receipts")} (last ${recent.length})

`);
  for (const line of recent) {
    try {
      const entry = JSON.parse(line);
      const payload = entry.payload || {};
      const time = typeof entry.issued_at === "string" ? new Date(entry.issued_at).toLocaleTimeString() : "unknown";
      const decision = payload.decision || "unknown";
      const icon = decision === "allow" ? green("\u2713") : decision === "require_approval" ? yellow("\u23F3") : red("\u2717");
      process.stdout.write(`  ${dim(time)} ${icon} ${String(payload.tool || "unknown").padEnd(22)} ${String(entry.type || "receipt").padEnd(18)} ${dim(String(payload.reason_code || "signed"))}
`);
    } catch {
    }
  }
  process.stdout.write(`
`);
}
var _pkgV = null;
async function pkgVersion() {
  if (_pkgV) return _pkgV;
  let v = "0.0.0";
  try {
    const { readFileSync, existsSync, realpathSync } = await import("fs");
    const { dirname, join, resolve } = await import("path");
    let base = "";
    try {
      base = dirname(realpathSync(resolve(process.argv[1] || "")));
    } catch {
    }
    const candidates = [
      base ? join(base, "..", "package.json") : "",
      base ? join(base, "package.json") : ""
    ].filter(Boolean);
    for (const p of candidates) {
      if (existsSync(p)) {
        const parsed = JSON.parse(readFileSync(p, "utf-8"));
        if (parsed && parsed.name === "protect-mcp" && parsed.version) {
          v = parsed.version;
          break;
        }
      }
    }
  } catch {
  }
  _pkgV = v;
  return v;
}
function mapRecordEntry(e) {
  const p = e && e.payload && typeof e.payload === "object" ? e.payload : e;
  const dec = String(p.decision || e.decision || "").toLowerCase();
  const verdict = /den|block|reject|refus/.test(dec) ? "blocked" : /ask|approv|hold|escal|review|pending/.test(dec) ? "held" : "allowed";
  const tsRaw = e.issued_at || e.timestamp || p.timestamp || p.issued_at;
  const ms = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "string" ? Date.parse(tsRaw) : NaN;
  const ts = isFinite(ms) ? new Date(ms).toISOString() : "";
  const tool = String(p.tool || e.tool || "action");
  const reason = String(p.reason_code || e.reason_code || p.policy_engine || "signed");
  const hook = String(p.hook_event || e.hook_event || "");
  const signed = !!(e.signature || e.sig || e.receipt_hash || typeof e.type === "string" && e.type.indexOf("receipt") >= 0);
  let digest = "";
  if (e.receipt_hash) digest = String(e.receipt_hash);
  else if (e.digest) digest = String(e.digest);
  else if (p.payload_digest && p.payload_digest.output_hash) digest = String(p.payload_digest.output_hash);
  const enr = p && typeof p.enrichment === "object" && p.enrichment || typeof e.enrichment === "object" && e.enrichment || null;
  const caps = enr && Array.isArray(enr.capabilities) ? enr.capabilities.map(String) : [];
  const sw = p && typeof p.swarm === "object" && p.swarm || null;
  const agent = sw && (sw.agent_name || sw.agent_id || sw.agent_type) ? String(sw.agent_name || sw.agent_id || sw.agent_type) : "main agent";
  const tm = p && typeof p.timing === "object" && p.timing || null;
  const dur = tm && typeof tm.tool_duration_ms === "number" ? tm.tool_duration_ms : 0;
  return { ts, tool, verdict, reason, hook, signed, caps, agent, dur, id: String(e.request_id || p.request_id || ""), digest, raw: e };
}
async function handleRecord(argv) {
  const { readFileSync, existsSync, writeFileSync } = await import("fs");
  const { join } = await import("path");
  const osMod = await import("os");
  const cp = await import("child_process");
  let dir = process.cwd();
  const di = argv.indexOf("--dir");
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  const recPath = join(dir, ".protect-mcp-receipts.jsonl");
  const logPath = join(dir, ".protect-mcp-log.jsonl");
  const pick = () => existsSync(recPath) ? recPath : existsSync(logPath) ? logPath : null;
  const chosen = pick();
  if (!chosen) {
    process.stderr.write(`
${bold("protect-mcp record")}

No record found in ${dir}.
Start the gate with ${bold("npx protect-mcp serve")}, use your agent, then run this again.
`);
    process.stderr.write(`Tip: run this in the directory where your gate is signing (where .protect-mcp-receipts.jsonl lives), or pass ${bold("--dir <path>")}.

`);
    process.exit(0);
    return;
  }
  const readRecs = (file) => readFileSync(file, "utf-8").split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter((x) => x !== null).map(mapRecordEntry);
  const openTarget = (target) => {
    if (argv.includes("--no-open")) return;
    const platform = process.platform;
    const opener = platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
    const openArgs = platform === "win32" ? ["/c", "start", "", target] : [target];
    try {
      const child = cp.spawn(opener, openArgs, { stdio: "ignore", detached: true });
      child.unref();
    } catch {
    }
  };
  if (argv.includes("--live") || argv.includes("--watch")) {
    const http = await import("http");
    const pi = argv.indexOf("--port");
    const port = pi !== -1 && argv[pi + 1] ? parseInt(argv[pi + 1], 10) : 9378;
    const server = http.createServer((req, res) => {
      if (req.url && req.url.indexOf("/data") === 0) {
        let recs2 = [];
        const f = pick();
        try {
          if (f) recs2 = readRecs(f);
        } catch {
        }
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ recs: recs2, signed: f === recPath }));
        return;
      }
      const meta2 = { file: chosen, signed: pick() === recPath, count: 0, live: true };
      const page = RECORD_HTML.replace("__DATA__", () => "[]").replace("__META__", () => JSON.stringify(meta2));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(page);
    });
    server.on("error", (e) => {
      process.stderr.write(`
protect-mcp record --live: could not start on port ${port}${e && e.code ? ` (${e.code})` : ""}. Try ${bold("--port <n>")}.

`);
      process.exit(1);
    });
    server.listen(port, "127.0.0.1", () => {
      const url = `http://127.0.0.1:${port}`;
      openTarget(url);
      process.stdout.write(`
${bold("\u{1F6E1}\uFE0F  Your record")} ${dim("\xB7")} live at ${url}
`);
      process.stdout.write(`  Updates as your agent runs. All local, nothing uploaded. ${dim("Ctrl-C to stop.")}

`);
    });
    return;
  }
  const recs = readRecs(chosen);
  const meta = { file: chosen, signed: chosen === recPath, count: recs.length, live: false };
  const html = RECORD_HTML.replace("__DATA__", () => JSON.stringify(recs)).replace("__META__", () => JSON.stringify(meta));
  const out = join(osMod.tmpdir(), "protect-mcp-record-" + Date.now() + ".html");
  writeFileSync(out, html);
  openTarget(out);
  process.stdout.write(`
${bold("\u{1F6E1}\uFE0F  Your record")} ${dim("\xB7")} ${recs.length} decision${recs.length === 1 ? "" : "s"}, all on this machine
`);
  if (!meta.signed) process.stdout.write(`  ${dim("(decision log; signed receipts appear in .protect-mcp-receipts.jsonl once signing is on)")}
`);
  const fileUrl = "file://" + encodeURI(out);
  if (process.stdout.isTTY) {
    process.stdout.write(`  Opened in your browser. If it did not open, click: \x1B]8;;${fileUrl}\x1B\\${bold("your record")}\x1B]8;;\x1B\\
`);
  } else {
    process.stdout.write(`  Opened in your browser. If it did not open, open: ${out}
`);
  }
  process.stdout.write(`  ${dim("Want it to update live as your agent runs? npx protect-mcp record --live")}

`);
  process.exit(0);
}
var RECORD_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>protect-mcp record</title>
<style>
:root{--paper:#f6f4ef;--ink:#1b1815;--soft:#524d46;--faint:#8a837a;--line:#ddd7c9;--g:#3f6146;--gb:#e7eee3;--a:#8f6216;--ab:#f2e8d3;--r:#7d3535;--rb:#f2e0dc}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto;padding:26px 22px 60px}
h1{font-size:24px;margin:0 0 4px;letter-spacing:-.012em}
.meta{color:var(--faint);font-size:12.5px;font-family:ui-monospace,Menlo,Consolas,monospace;display:flex;align-items:center}
.pulse{width:7px;height:7px;border-radius:100px;background:var(--g);display:inline-block;margin-left:8px;animation:pl 1.6s ease-in-out infinite}
@keyframes pl{0%,100%{opacity:.3}50%{opacity:1}}
@media (prefers-reduced-motion:reduce){.pulse{animation:none}}
.stats{display:flex;gap:15px;flex-wrap:wrap;align-items:center;margin:14px 0 10px;font-size:13px}
.stat{display:flex;align-items:center;gap:6px;color:var(--soft)}
.stat b{color:var(--ink);font-weight:680}
.dot{width:8px;height:8px;border-radius:100px;display:inline-block}
.dot.g{background:var(--g)}.dot.a{background:var(--a)}.dot.r{background:var(--r)}
.stat.sig{margin-left:auto;color:var(--g);font-weight:600}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 16px}
.btn{cursor:pointer;font:inherit;font-size:12.5px;padding:7px 13px;border-radius:8px;border:1px solid var(--line);background:#fff;color:var(--ink);transition:border-color .12s}
.btn:hover{border-color:var(--ink)}
.btn.p{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.btn:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.vhint{font-size:12px;color:var(--faint);margin-left:auto;font-family:ui-monospace,Menlo,monospace}
.bar{margin:6px 0 12px}
input{width:100%;padding:10px 13px;border:1px solid var(--line);border-radius:9px;background:#fff;font:inherit}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.chip{cursor:pointer;font-size:12px;padding:3px 10px;border-radius:100px;border:1px solid var(--line);background:#fff;color:var(--soft)}
.chip.on{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.count{color:var(--faint);font-size:12px;font-family:ui-monospace,Menlo,monospace;margin-bottom:8px}
.row{border:1px solid var(--line);border-radius:9px;background:#fcfbf7;padding:11px 13px;margin-bottom:8px;cursor:pointer}
.row.blocked{border-left:3px solid var(--r)}.row.held{border-left:3px solid var(--a)}
.top{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.pill{font-size:11px;font-weight:600;padding:2px 9px;border-radius:100px}
.pill.allowed{background:var(--gb);color:var(--g)}.pill.held{background:var(--ab);color:var(--a)}.pill.blocked{background:var(--rb);color:var(--r)}
.tag{font-size:11px;padding:1px 7px;border-radius:100px;background:var(--paper);border:1px solid var(--line);color:var(--faint)}
.cap{font-size:10px;padding:1px 6px;border-radius:100px;background:#eef0ea;border:1px solid var(--line);color:var(--soft)}
.badge{font-size:10.5px;font-weight:600;padding:1px 7px;border-radius:100px}
.badge.sgn{background:var(--gb);color:var(--g)}
.badge.log{background:var(--paper);color:var(--faint);border:1px solid var(--line)}
.dg{font-size:10.5px;color:var(--faint);font-family:ui-monospace,Menlo,monospace}
.when{margin-left:auto;font-size:12px;color:var(--faint);font-family:ui-monospace,Menlo,monospace}
.det{margin-top:8px;padding-top:8px;border-top:1px solid var(--line);font-size:12px;color:var(--soft);font-family:ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-all;display:none}
.row.open .det{display:block}
.foot{margin-top:22px;color:var(--faint);font-size:12px;line-height:1.6;border-top:1px solid var(--line);padding-top:14px}
.foot b{color:var(--soft)}
.viewtoggle{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.viewtoggle button{border:0;background:#fff;color:var(--soft);font:inherit;font-size:12.5px;padding:7px 12px;cursor:pointer}
.viewtoggle button.on{background:var(--ink);color:var(--paper)}
.agent{border:1px solid var(--line);border-radius:10px;background:#fcfbf7;margin-bottom:10px;overflow:hidden}
.ahead{display:flex;gap:9px;align-items:center;flex-wrap:wrap;padding:11px 13px;cursor:pointer}
.atwist{color:var(--faint);font-size:11px;transition:transform .12s;display:inline-block}
.agent.open .atwist{transform:rotate(90deg)}
.acount{font-size:12px;color:var(--faint)}
.akids{display:none;padding:2px 12px 12px 24px;border-top:1px solid var(--line)}
.agent.open .akids{display:block}
.act{display:flex;gap:9px;align-items:center;flex-wrap:wrap;padding:8px 10px;border-radius:8px;cursor:pointer;border:1px solid var(--line);border-left:3px solid var(--line);margin-top:7px;background:#fff}
.act.blocked{border-left-color:var(--r)}.act.held{border-left-color:var(--a)}.act.allowed{border-left-color:var(--g)}
.act .det{flex-basis:100%}
.act.open .det{display:block}
.ev{display:flex;gap:8px;align-items:center;font-size:12px;color:var(--faint);padding:5px 10px;margin-top:6px}
.evdot{width:6px;height:6px;border-radius:100px;background:var(--faint);display:inline-block}
.evre{color:var(--soft)}
.badge.blk{background:var(--rb);color:var(--r)}
</style></head><body><div class="wrap">
<h1>Your record</h1>
<div class="meta"><span id="meta"></span><span id="live"></span></div>
<div class="stats" id="stats"></div>
<div class="actions">
<div class="viewtoggle"><button id="vlist" class="on" onclick="setView('list')">List</button><button id="vtree" onclick="setView('tree')">Tree</button></div>
<button class="btn p" onclick="exportJsonl()">Export receipts (.jsonl)</button>
<button class="btn" onclick="exportMd()">Export report (.md)</button>
<button class="btn" id="cpv" onclick="copyVerify()">Copy verify command</button>
<span class="vhint">verify offline: npx @veritasacta/verify</span>
</div>
<div class="bar"><input id="q" placeholder="Search your record: tool, reason, verdict"></div>
<div class="chips" id="chips"></div>
<div class="count" id="count"></div>
<div id="list"></div>
<div class="foot">Signed decisions from your own gate, on this machine. Nothing was uploaded. Each row is Ed25519-signed, and the exports carry the signatures, so anyone you hand them to (an allocator, an auditor, a counterparty) verifies offline with <b>npx @veritasacta/verify</b>, our code removed. For a Merkle-rooted evidence pack: <b>npx protect-mcp bundle</b>. protect-mcp governs proposed actions before they run.</div>
</div>
<script>
var RECORDS=__DATA__;var META=__META__;var Q="",ACT={},VIEW="list";var NL=String.fromCharCode(10);
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
function vlabel(v){return v==="allowed"?"Allowed":v==="held"?"Held":"Blocked"}
function when(ts){if(!ts)return"";var d=new Date(ts);return d.toLocaleDateString(undefined,{month:"short",day:"numeric"})+" "+d.toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit"})}
function counts(rows){var c={allowed:0,held:0,blocked:0,signed:0};rows.forEach(function(r){c[r.verdict]=(c[r.verdict]||0)+1;if(r.signed)c.signed++});return c}
function fvals(key){var m={};RECORDS.forEach(function(r){var vs=key==="Decision"?[vlabel(r.verdict)]:(key==="Capability"?(r.caps||[]):[r[key.toLowerCase()]]);vs.forEach(function(v){if(v){m[v]=(m[v]||0)+1}})});return Object.keys(m).sort(function(a,b){return m[b]-m[a]}).slice(0,10).map(function(v){return[v,m[v]]})}
function match(r){if(ACT.Decision&&vlabel(r.verdict)!==ACT.Decision)return false;if(ACT.Tool&&r.tool!==ACT.Tool)return false;if(ACT.Reason&&r.reason!==ACT.Reason)return false;if(ACT.Capability&&(r.caps||[]).indexOf(ACT.Capability)<0)return false;if(Q){var h=(r.tool+" "+r.reason+" "+vlabel(r.verdict)+" "+r.hook+" "+(r.caps||[]).join(" ")).toLowerCase();if(h.indexOf(Q)<0)return false}return true}
function filtered(){return RECORDS.filter(match)}
function dl(name,text,type){var b=new Blob([text],{type:type||"text/plain"});var u=URL.createObjectURL(b);var a=document.createElement("a");a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(u)},1500)}
function stamp(){return new Date().toISOString().replace(/[:.]/g,"-").slice(0,19)}
function exportJsonl(){var rows=filtered();if(!rows.length)return;var lines=rows.map(function(r){return JSON.stringify(r.raw||r)}).join(NL);dl("protect-mcp-record-"+stamp()+".jsonl",lines,"application/x-ndjson")}
function exportMd(){var rows=filtered();if(!rows.length)return;var c=counts(rows);var head=["# Agent decision record","",rows.length+" decisions from "+META.file,c.allowed+" allowed, "+c.held+" held, "+c.blocked+" blocked, "+c.signed+" signed.","","Generated locally by protect-mcp. These are signed receipts; verify offline with npx @veritasacta/verify (our code removed).","","| When | Decision | Tool | Reason | Hook | Signed |","|---|---|---|---|---|---|"];var body=rows.slice(0,3000).map(function(r){return "| "+(r.ts||"")+" | "+vlabel(r.verdict)+" | "+String(r.tool||"").replace(/\\|/g,"/")+" | "+String(r.reason||"").replace(/\\|/g,"/")+" | "+(r.hook||"")+" | "+(r.signed?"yes":"no")+" |"});dl("protect-mcp-record-"+stamp()+".md",head.concat(body).join(NL)+NL,"text/markdown")}
function copyVerify(){var cmd="npx @veritasacta/verify";try{navigator.clipboard&&navigator.clipboard.writeText(cmd)}catch(e){}var b=document.getElementById("cpv");if(b){var t=b.textContent;b.textContent="Copied";setTimeout(function(){b.textContent=t},1200)}}
function renderStats(){var c=counts(RECORDS);var p=[];p.push('<span class="stat"><b>'+RECORDS.length+'</b> decisions</span>');p.push('<span class="stat"><span class="dot g"></span>'+c.allowed+' allowed</span>');if(c.held)p.push('<span class="stat"><span class="dot a"></span>'+c.held+' held</span>');p.push('<span class="stat"><span class="dot r"></span>'+c.blocked+' blocked</span>');p.push('<span class="stat sig">'+c.signed+' signed, verifiable offline</span>');document.getElementById("stats").innerHTML=p.join("")}
function renderList(rows){var html="";rows.slice(0,800).forEach(function(r){var sig=r.signed?'<span class="badge sgn">signed</span>':'<span class="badge log">log</span>';var dg=r.digest?'<span class="dg">'+esc(String(r.digest).slice(0,10))+'</span>':'';var ct=(r.caps||[]).map(function(c){return '<span class="cap">'+esc(c)+'</span>'}).join('');html+='<div class="row '+r.verdict+'"><div class="top"><span class="pill '+r.verdict+'">'+vlabel(r.verdict)+"</span><b>"+esc(r.tool)+'</b><span class="tag">'+esc(r.reason)+"</span>"+ct+(r.hook?'<span class="tag">'+esc(r.hook)+"</span>":"")+sig+dg+'<span class="when">'+esc(when(r.ts))+'</span></div><div class="det">'+esc(JSON.stringify(r.raw||r,null,2))+"</div></div>"});document.getElementById("list").innerHTML=html||'<p style="color:#8a837a">No records match.</p>';}
function isLifecycle(r){var h=r.hook||"";return h==="SessionStart"||h==="SessionEnd"||h==="Stop"||h==="SubagentStart"||h==="SubagentStop"||h==="TaskCreated"||h==="TaskCompleted"||h==="ConfigChange"||h==="Notification"||h==="PreCompact";}
function buildTree(rows){var ags={},order=[];rows.forEach(function(r){var a=r.agent||"main agent";if(!ags[a]){ags[a]={name:a,byId:{},items:[],caps:{},blocked:0,actions:0};order.push(a);}var g=ags[a];(r.caps||[]).forEach(function(c){g.caps[c]=(g.caps[c]||0)+1;});if(isLifecycle(r)){g.items.push({t:"e",ts:r.ts,r:r});return;}var id=r.id||("_"+r.ts);var n=g.byId[id];if(!n){n={t:"a",id:id,tool:r.tool,verdict:r.verdict,caps:(r.caps||[]).slice(),ts:r.ts,dur:0,signed:!!r.signed,raw:r.raw};g.byId[id]=n;g.items.push(n);g.actions++;}if(r.hook==="PostToolUse"){if(r.dur)n.dur=r.dur;if(!n.raw)n.raw=r.raw;}else{n.verdict=r.verdict;if((r.caps||[]).length)n.caps=r.caps.slice();n.raw=r.raw;n.ts=r.ts;}if(r.signed)n.signed=true;});order.forEach(function(a){var g=ags[a];g.blocked=g.items.filter(function(it){return it.t==="a"&&it.verdict==="blocked";}).length;g.items.sort(function(x,y){return (x.ts<y.ts)?-1:1;});});return order.map(function(a){return ags[a];});}
function renderTree(ags){if(!ags.length){document.getElementById("list").innerHTML='<p style="color:#8a837a">No records match.</p>';return;}var html="",N=0;ags.forEach(function(g,gi){var capstr=Object.keys(g.caps).sort(function(a,b){return g.caps[b]-g.caps[a];}).slice(0,5).map(function(c){return '<span class="cap">'+esc(c)+'</span>';}).join('');var op=(ags.length===1||gi===0)?" open":"";html+='<div class="agent'+op+'"><div class="ahead"><span class="atwist">\u25B8</span><b>'+esc(g.name)+'</b><span class="acount">'+g.actions+' action'+(g.actions===1?'':'s')+'</span>'+(g.blocked?'<span class="badge blk">'+g.blocked+' blocked</span>':'')+capstr+'</div><div class="akids">';g.items.forEach(function(it){if(N++>1500)return;if(it.t==="e"){var r=it.r;html+='<div class="ev"><span class="evdot"></span>'+esc(r.hook||r.tool)+' <span class="evre">'+esc(r.reason)+'</span><span class="when">'+esc(when(r.ts))+'</span></div>';}else{var ct=(it.caps||[]).map(function(c){return '<span class="cap">'+esc(c)+'</span>';}).join('');var dur=it.dur?'<span class="dg">'+it.dur+'ms</span>':'';html+='<div class="act '+it.verdict+'"><span class="pill '+it.verdict+'">'+vlabel(it.verdict)+'</span><b>'+esc(it.tool)+'</b>'+ct+(it.signed?'<span class="badge sgn">signed</span>':'')+dur+'<span class="when">'+esc(when(it.ts))+'</span><div class="det">'+esc(JSON.stringify(it.raw||{},null,2))+'</div></div>';}});html+='</div></div>';});if(N>1500)html+='<p style="color:#8a837a;font-size:12px;margin-top:10px">Showing the first 1500 items. Search or pick a facet to narrow.</p>';document.getElementById("list").innerHTML=html;}
function setView(v){VIEW=v;document.getElementById("vlist").className=v==="list"?"on":"";document.getElementById("vtree").className=v==="tree"?"on":"";render();}
function render(){
document.getElementById("meta").textContent=META.count+" decisions from "+META.file+(META.signed?" (signed)":" (decision log)")+" - all local"+(META.live?" \xB7 live, updating":"");
document.getElementById("live").innerHTML=META.live?'<span class="pulse"></span>':"";
renderStats();
var chips="";["Decision","Tool","Reason","Capability"].forEach(function(key){fvals(key).forEach(function(p){var on=ACT[key]===p[0];chips+='<span class="chip'+(on?" on":"")+'" data-k="'+key+'" data-v="'+esc(p[0])+'">'+esc(p[0])+" "+p[1]+"</span>"})});
document.getElementById("chips").innerHTML=chips;
var rows=RECORDS.filter(match);
document.getElementById("count").textContent=rows.length+" of "+RECORDS.length+" records"+(VIEW==="tree"?" \xB7 grouped by agent":"");
if(VIEW==="tree"){renderTree(buildTree(rows));}else{renderList(rows);}}
document.getElementById("q").addEventListener("input",function(e){Q=e.target.value.toLowerCase().trim();render()});
document.getElementById("chips").addEventListener("click",function(e){var c=e.target.closest(".chip");if(!c)return;var k=c.getAttribute("data-k"),v=c.getAttribute("data-v");ACT[k]=ACT[k]===v?undefined:v;render()});
document.getElementById("list").addEventListener("click",function(e){var ah=e.target.closest(".ahead");if(ah){ah.parentNode.classList.toggle("open");return;}var act=e.target.closest(".act");if(act){act.classList.toggle("open");return;}var row=e.target.closest(".row");if(row)row.classList.toggle("open")});
render();
if(META.live){var poll=function(){fetch('/data',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){RECORDS=d.recs||[];META.count=RECORDS.length;if(typeof d.signed==='boolean')META.signed=d.signed;render()}).catch(function(){})};poll();setInterval(poll,2000);}
</script></body></html>`;
async function handleBundle(argv) {
  const { readFileSync, writeFileSync, existsSync } = await import("fs");
  const { join } = await import("path");
  const { createAuditBundle } = await import("./bundle-YUUHAG7O.mjs");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const outputIdx = argv.indexOf("--output");
  const outputPath = outputIdx !== -1 && argv[outputIdx + 1] ? argv[outputIdx + 1] : join(dir, "audit-bundle.json");
  const receiptsPath = join(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = join(dir, "keys", "gateway.json");
  if (!existsSync(receiptsPath)) {
    process.stderr.write(`${bold("protect-mcp bundle")}

No signed receipt file found. Run protect-mcp with signing enabled first.
`);
    process.exit(0);
  }
  if (!existsSync(keyPath)) {
    process.stderr.write(`${bold("protect-mcp bundle")}

No key file found at ${keyPath}
`);
    process.exit(1);
  }
  const receipts = readFileSync(receiptsPath, "utf-8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const keyData = JSON.parse(readFileSync(keyPath, "utf-8"));
  const bundle = createAuditBundle({
    tenant: keyData.issuer || "protect-mcp",
    receipts,
    selectiveDisclosures: collectSelectiveDisclosurePackages(dir),
    signingKeys: [{
      kty: "OKP",
      crv: "Ed25519",
      kid: keyData.kid || "unknown",
      x: Buffer.from(keyData.publicKey, "hex").toString("base64url"),
      use: "sig"
    }]
  });
  writeFileSync(outputPath, JSON.stringify(bundle, null, 2) + "\n");
  process.stdout.write(`
${bold("protect-mcp bundle")}

`);
  process.stdout.write(`  Receipts: ${receipts.length}
`);
  process.stdout.write(`  Disclosures: ${collectSelectiveDisclosurePackages(dir).length}
`);
  process.stdout.write(`  Output:   ${outputPath}
`);
  process.stdout.write(`  Verify:   npx @veritasacta/verify ${outputPath} --bundle

`);
}
async function createSandbox() {
  const { mkdirSync, writeFileSync, existsSync, readFileSync } = await import("fs");
  const { join } = await import("path");
  const { homedir } = await import("os");
  let response;
  try {
    response = await fetch("https://api.scopeblind.com/sandbox/create", { method: "POST" });
  } catch {
    process.stderr.write(yellow("  \u26A0 Could not create dashboard (offline or server unavailable).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  if (!response.ok) {
    process.stderr.write(yellow("  \u26A0 Could not create dashboard (offline or server unavailable).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  let data;
  try {
    data = await response.json();
  } catch {
    process.stderr.write(yellow("  \u26A0 Could not create dashboard (unexpected response).\n"));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.

`);
    return null;
  }
  const dashboardUrl = `https://scopeblind.com/t/${data.slug}`;
  const configDir = join(homedir(), ".protect-mcp");
  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
  }
  const configPath = join(configDir, "config.json");
  let existing = {};
  if (existsSync(configPath)) {
    try {
      existing = JSON.parse(readFileSync(configPath, "utf-8"));
    } catch {
    }
  }
  writeFileSync(configPath, JSON.stringify({
    ...existing,
    sandbox_slug: data.slug,
    dashboard_url: dashboardUrl
  }, null, 2) + "\n");
  return dashboardUrl;
}
async function handleConnect() {
  process.stderr.write(`
${bold("protect-mcp connect")}
`);
  process.stderr.write(`${"\u2500".repeat(50)}

`);
  process.stderr.write(`  Creating ScopeBlind sandbox dashboard...

`);
  const dashboardUrl = await createSandbox();
  if (dashboardUrl) {
    process.stderr.write(green(`  \u2713 Dashboard created: ${dashboardUrl}
`));
    process.stderr.write(`    Receipts will be uploaded automatically.
`);
    process.stderr.write(dim(`    Free tier: 20,000 receipts/month, no credit card required.
`));
    process.stderr.write(`
${"\u2500".repeat(50)}

`);
  }
}
async function handleQuickstart(argv) {
  const connectFlag = argv.includes("--connect");
  const { mkdtempSync, writeFileSync, existsSync, mkdirSync, readFileSync } = await import("fs");
  const { join } = await import("path");
  const { tmpdir } = await import("os");
  const dir = mkdtempSync(join(tmpdir(), "protect-mcp-quickstart-"));
  process.stdout.write(`
${bold("protect-mcp quickstart")}
`);
  process.stdout.write(`${"\u2500".repeat(50)}

`);
  process.stdout.write(`  This will:
`);
  process.stdout.write(`  1. Generate an Ed25519 signing keypair
`);
  process.stdout.write(`  2. Create a shadow-mode policy
`);
  process.stdout.write(`  3. Start a demo MCP server with protect-mcp wrapping it
`);
  process.stdout.write(`  4. Log signed receipts for every tool call
`);
  if (connectFlag) {
    process.stdout.write(`  5. Create a ScopeBlind dashboard for receipt viewing
`);
  }
  process.stdout.write(`
  Working dir: ${dir}

`);
  const keysDir = join(dir, "keys");
  mkdirSync(keysDir, { recursive: true });
  const { randomBytes } = await import("crypto");
  let keypair;
  try {
    const { ed25519 } = await import("./ed25519-SQA3S2RV.mjs");
    const { bytesToHex } = await import("./utils-6AYZFE5A.mjs");
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    keypair = {
      privateKey: bytesToHex(privateKey),
      publicKey: bytesToHex(publicKey),
      kid: `quickstart-${Date.now()}`
    };
  } catch {
    keypair = {
      privateKey: randomBytes(32).toString("hex"),
      publicKey: randomBytes(32).toString("hex"),
      kid: `quickstart-${Date.now()}`
    };
  }
  writeFileSync(join(keysDir, "gateway.json"), JSON.stringify({
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    kid: keypair.kid,
    generated_at: (/* @__PURE__ */ new Date()).toISOString()
  }, null, 2) + "\n");
  const configPath = join(dir, "protect-mcp.json");
  const config = {
    tools: {
      "*": { rate_limit: "100/hour" },
      "delete_file": { block: true }
    },
    default_tier: "unknown",
    signing: {
      key_path: join(keysDir, "gateway.json"),
      issuer: "protect-mcp-quickstart",
      enabled: true
    }
  };
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
  process.stdout.write(`  \u2713 Keypair generated (kid: ${keypair.kid})
`);
  process.stdout.write(`  \u2713 Policy created (shadow mode, all tools logged)
`);
  process.stdout.write(`  \u2713 Signing enabled (Ed25519)

`);
  if (connectFlag) {
    process.stdout.write(`${bold("Connecting to ScopeBlind dashboard...")}

`);
    const dashboardUrl = await createSandbox();
    if (dashboardUrl) {
      const updatedConfig = { ...config, dashboard_url: dashboardUrl };
      writeFileSync(configPath, JSON.stringify(updatedConfig, null, 2) + "\n");
      process.stdout.write(green(`  \u2713 Dashboard created: ${dashboardUrl}
`));
      process.stdout.write(`    Receipts will be uploaded automatically.
`);
      process.stdout.write(dim(`    Free tier: 20,000 receipts/month, no credit card required.
`));
      process.stdout.write(`
`);
    }
  }
  process.stdout.write(`${bold("Starting demo server...")}

`);
  process.stdout.write(`  Every tool call will produce a signed receipt.
`);
  process.stdout.write(`  Try it with Claude Desktop or any MCP client.

`);
  process.stdout.write(`  ${bold("To use in production:")}
`);
  process.stdout.write(`    1. Copy ${configPath} to your project
`);
  process.stdout.write(`    2. Edit tool policies to match your server
`);
  process.stdout.write(`    3. Run: protect-mcp --policy protect-mcp.json -- node your-server.js

`);
  process.stdout.write(`${"\u2500".repeat(50)}

`);
  process.env.PROTECT_MCP_CONFIG = configPath;
  await handleDemo();
}
async function handleRegistry(argv) {
  const subcommand = argv[0] || "status";
  const dir = resolveCli(flagValue(argv, "--dir") || process.cwd());
  const orgName = flagValue(argv, "--org") || process.env.SCOPEBLIND_ORG;
  const orgId = flagValue(argv, "--org-id") || process.env.SCOPEBLIND_ORG_ID;
  const billingAccountId = flagValue(argv, "--billing-account") || process.env.SCOPEBLIND_BILLING_ACCOUNT;
  const endpoint = flagValue(argv, "--endpoint") || process.env.SCOPEBLIND_REGISTRY_ENDPOINT || (argv.includes("--hosted") ? "https://api.scopeblind.com" : void 0);
  const token = flagValue(argv, "--token") || process.env.SCOPEBLIND_TOKEN;
  const verifierBaseUrl = flagValue(argv, "--verifier-base") || process.env.SCOPEBLIND_VERIFIER_BASE || "https://legate.scopeblind.com";
  const registryMod = await import("./receipt-registry-6CAOY6RP.mjs");
  if (subcommand === "init") {
    const identity = registryMod.createOrgIdentity({
      dir,
      orgName,
      orgId,
      billingAccountId
    });
    const path = registryMod.writeOrgIdentity(dir, identity);
    process.stdout.write(`
${bold("protect-mcp registry init")}

`);
    process.stdout.write(`  Org:              ${identity.org_name}
`);
    process.stdout.write(`  Org ID:           ${identity.org_id}
`);
    process.stdout.write(`  Billing account:  ${identity.billing_account_id}
`);
    process.stdout.write(`  Public keys:      ${identity.public_key_directory.length}
`);
    process.stdout.write(`  Wrote:            ${path}

`);
    process.stdout.write(`${dim("No prompts, tool payloads, raw receipts, or private keys are included.")}

`);
    return;
  }
  if (subcommand === "anchor") {
    process.stdout.write(`
${bold("protect-mcp registry anchor")}

`);
    const result = await registryMod.createReceiptRegistry({
      dir,
      orgName,
      orgId,
      billingAccountId,
      endpoint,
      token,
      hosted: argv.includes("--hosted") || Boolean(endpoint || token),
      verifierBaseUrl,
      outPath: flagValue(argv, "--output")
    });
    process.stdout.write(`  Org:              ${result.registry.org.org_name}
`);
    process.stdout.write(`  Billing account:  ${result.registry.billing.billing_account_id}
`);
    process.stdout.write(`  Digests:          ${result.registry.records.length}
`);
    process.stdout.write(`  Anchors:          ${result.registry.anchors.length}
`);
    process.stdout.write(`  Boundary:         ${result.uploaded ? green("hosted digest anchor") : yellow("local preview only")}
`);
    process.stdout.write(`  Registry:         ${result.registryPath}
`);
    process.stdout.write(`  Verifier page:    ${result.verifierPath}

`);
    process.stdout.write(`  Uploaded fields:  ${result.registry.privacy.uploaded_fields.join(", ")}
`);
    process.stdout.write(`  Excluded fields:  ${result.registry.privacy.excluded_fields.join(", ")}

`);
    if (!result.uploaded) {
      process.stdout.write(`${yellow("  This is not an independent timestamp yet.")}
`);
      process.stdout.write(`  Run with ${dim("--hosted --token $SCOPEBLIND_TOKEN")} to make the paid boundary real.

`);
    }
    return;
  }
  if (subcommand === "status") {
    const registryPath = joinCli(dir, registryMod.REGISTRY_FILE);
    const identityPath = joinCli(dir, registryMod.ORG_IDENTITY_FILE);
    process.stdout.write(`
${bold("protect-mcp registry status")}

`);
    if (existsSyncCli(identityPath)) {
      const identity = JSON.parse(readFileSyncCli(identityPath, "utf-8"));
      process.stdout.write(`  Org:              ${identity.org_name || "unknown"}
`);
      process.stdout.write(`  Org ID:           ${identity.org_id || "unknown"}
`);
      process.stdout.write(`  Billing account:  ${identity.billing_account_id || "unknown"}
`);
    } else {
      process.stdout.write(`  Org identity:     ${yellow("missing")} (${identityPath})
`);
    }
    if (existsSyncCli(registryPath)) {
      const registry = JSON.parse(readFileSyncCli(registryPath, "utf-8"));
      const hosted = Array.isArray(registry.anchors) && registry.anchors.some((a) => a.timestamp_source === "scopeblind-hosted");
      process.stdout.write(`  Registry:         ${registryPath}
`);
      process.stdout.write(`  Digests:          ${registry.records?.length || 0}
`);
      process.stdout.write(`  Anchors:          ${registry.anchors?.length || 0}
`);
      process.stdout.write(`  Boundary:         ${hosted ? green("hosted digest anchor") : yellow("local preview only")}
`);
      process.stdout.write(`  Verifier page:    ${joinCli(dir, registryMod.VERIFIER_PAGE_FILE)}
`);
    } else {
      process.stdout.write(`  Registry:         ${yellow("missing")} (${registryPath})
`);
      process.stdout.write(`  Next:             ${dim("npx protect-mcp registry anchor --hosted")}
`);
    }
    process.stdout.write(`
`);
    return;
  }
  process.stderr.write("Usage: protect-mcp registry init|anchor|status [--dir <path>] [--org <name>] [--hosted]\\n");
  process.exit(1);
}
async function handleKillerDemo(argv) {
  const { mkdtempSync } = await import("fs");
  const { tmpdir } = await import("os");
  const { ed25519 } = await import("./ed25519-SQA3S2RV.mjs");
  const { bytesToHex } = await import("./utils-6AYZFE5A.mjs");
  const { randomBytes } = await import("crypto");
  const artifacts = await import("@veritasacta/artifacts");
  const {
    createSelectiveDisclosurePackage,
    signCommittedDecision,
    verifySelectiveDisclosurePackage
  } = await import("./signing-committed-TGWXSLAO.mjs");
  const registryMod = await import("./receipt-registry-6CAOY6RP.mjs");
  const dir = resolveCli(flagValue(argv, "--dir") || mkdtempSync(joinCli(tmpdir(), "scopeblind-killer-demo-")));
  mkdirSyncCli(dir, { recursive: true });
  mkdirSyncCli(joinCli(dir, "keys"), { recursive: true });
  mkdirSyncCli(joinCli(dir, "receipts"), { recursive: true });
  const privateKeyBytes = randomBytes(32);
  const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
  const keypair = {
    privateKey: bytesToHex(privateKeyBytes),
    publicKey: bytesToHex(publicKeyBytes),
    kid: `killer-demo-${Date.now()}`,
    issuer: "scopeblind-killer-demo"
  };
  const keyPath = joinCli(dir, "keys", "gateway.json");
  writeFileSyncCli(keyPath, JSON.stringify({
    ...keypair,
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    warning: "Demo key only. Do not use for production."
  }, null, 2) + "\n");
  const shadowConfigPath = joinCli(dir, "protect-mcp.shadow.json");
  const policyPackPath = joinCli(dir, "protect-mcp.policy-pack.json");
  const config = {
    tools: { "*": { rate_limit: "100/hour" } },
    default_tier: "signed-known",
    signing: { key_path: keyPath, issuer: keypair.issuer, enabled: true }
  };
  const policyPack = {
    tools: {
      "*": { rate_limit: "100/hour" },
      read_file: { rate_limit: "60/hour" },
      github_create_pr: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      send_email: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      pms_book_fill: { require_approval: true, min_tier: "signed-known", rate_limit: "10/hour" },
      delete_file: { block: true, min_tier: "privileged" }
    },
    default_tier: "signed-known",
    signing: { key_path: keyPath, issuer: keypair.issuer, enabled: true },
    notes: ["Demo policy pack: approvals for GitHub, email, and PMS booking; destructive tools blocked."]
  };
  writeFileSyncCli(shadowConfigPath, JSON.stringify(config, null, 2) + "\n");
  writeFileSyncCli(policyPackPath, JSON.stringify(policyPack, null, 2) + "\n");
  await initSigning({ enabled: true, key_path: keyPath, issuer: keypair.issuer });
  const logPath = joinCli(dir, ".protect-mcp-log.jsonl");
  const receiptPath = joinCli(dir, ".protect-mcp-receipts.jsonl");
  const shadowCalls = [
    { tool: "read_file", input: { path: "/research/macro-notes.md" }, reason: "observe_mode" },
    { tool: "github_create_pr", input: { repo: "scopeblind/legate", branch: "agent/pms-adapter", title: "Wire mock PMS adapter" }, reason: "observe_mode" },
    { tool: "send_email", input: { to: "ops@examplefund.com", subject: "Booking update", body: "Draft only", api_key: "demo-secret" }, reason: "observe_mode" },
    { tool: "pms_book_fill", input: { account: "Meridian Global Macro", symbol: "AAPL", side: "BUY", quantity: 50, price: 182.4, strategy: "US Large Cap Tactical", bearerToken: "demo-secret" }, reason: "observe_mode" }
  ];
  for (const [idx, call] of shadowCalls.entries()) {
    const requestId2 = `demo-shadow-${idx + 1}`;
    appendFileSyncCli(logPath, JSON.stringify({
      v: 2,
      tool: call.tool,
      decision: "allow",
      reason_code: call.reason,
      request_id: requestId2,
      timestamp: Date.now() + idx,
      mode: "shadow",
      policy_digest: "shadow-policy",
      action_readback: buildActionReadback(call.tool, call.input)
    }) + "\n");
  }
  const sensitiveInput = {
    account: "Meridian Global Macro",
    symbol: "AAPL",
    side: "BUY",
    quantity: 50,
    price: 182.4,
    strategy: "US Large Cap Tactical",
    trader_note: "Do not reveal portfolio context outside the desk.",
    api_key: "demo-pms-secret"
  };
  const readback = buildActionReadback("pms_book_fill", sensitiveInput);
  const requestId = "demo-sensitive-pms-booking";
  const requireApprovalEntry = {
    v: 2,
    tool: "pms_book_fill",
    decision: "require_approval",
    reason_code: "requires_human_approval",
    request_id: requestId,
    timestamp: Date.now() + 10,
    mode: "enforce",
    policy_digest: createHashCli("sha256").update(JSON.stringify(policyPack)).digest("hex").slice(0, 16),
    action_readback: readback
  };
  appendFileSyncCli(logPath, JSON.stringify(requireApprovalEntry) + "\n");
  appendFileSyncCli(joinCli(dir, ".protect-mcp-approval-resolutions.jsonl"), JSON.stringify({
    type: "scopeblind.approval_resolution.v1",
    at: (/* @__PURE__ */ new Date()).toISOString(),
    request_id: requestId,
    tool: "pms_book_fill",
    resolution: "approve",
    reason: "Matches the ticket and stays inside mandate.",
    payload_hash: readback.payload_hash
  }) + "\n");
  const executedEntry = {
    ...requireApprovalEntry,
    decision: "allow",
    reason_code: "approval_granted",
    timestamp: Date.now() + 20,
    payload_digest: {
      output_hash: createHashCli("sha256").update("mock-pms-booking-confirmed").digest("hex"),
      output_size: 26,
      truncated: false
    }
  };
  appendFileSyncCli(logPath, JSON.stringify(executedEntry) + "\n");
  const signed = signDecision(executedEntry);
  if (!signed.signed) throw new Error(`demo signing failed: ${signed.warning || signed.error || "unknown"}`);
  appendFileSyncCli(receiptPath, signed.signed + "\n");
  writeFileSyncCli(joinCli(dir, "receipts", "approved-pms-booking.receipt.json"), JSON.stringify(JSON.parse(signed.signed), null, 2) + "\n");
  const receiptArtifact = JSON.parse(signed.signed);
  const tamperedArtifact = JSON.parse(signed.signed);
  if (tamperedArtifact.payload && typeof tamperedArtifact.payload === "object") {
    tamperedArtifact.payload.decision = "deny";
    tamperedArtifact.payload.tool = "send_email";
  } else {
    tamperedArtifact.tool = "send_email";
  }
  const validOriginal = artifacts.verifyArtifact(receiptArtifact, keypair.publicKey);
  const validTampered = artifacts.verifyArtifact(tamperedArtifact, keypair.publicKey);
  writeFileSyncCli(joinCli(dir, "receipts", "tampered.receipt.json"), JSON.stringify(tamperedArtifact, null, 2) + "\n");
  const committed = signCommittedDecision(
    executedEntry,
    ["tool", "payload_digest", "swarm"],
    keypair.privateKey,
    keypair.publicKey,
    keypair.kid,
    keypair.issuer
  );
  const committedReceipt = JSON.parse(committed.signed);
  const disclosurePackage = createSelectiveDisclosurePackage(committedReceipt, ["tool"], committed.openings);
  const disclosureVerification = verifySelectiveDisclosurePackage(committedReceipt, disclosurePackage);
  appendFileSyncCli(receiptPath, committed.signed + "\n");
  writeFileSyncCli(joinCli(dir, "receipts", "selective-disclosure.receipt.json"), JSON.stringify(committedReceipt, null, 2) + "\n");
  writeFileSyncCli(joinCli(dir, "receipts", "selective-disclosure.package.json"), JSON.stringify(disclosurePackage, null, 2) + "\n");
  writeFileSyncCli(joinCli(dir, "receipts", "selective-disclosure.tool-only.json"), JSON.stringify(disclosurePackage, null, 2) + "\n");
  writeFileSyncCli(joinCli(dir, "verification-results.json"), JSON.stringify({
    original_receipt_valid: validOriginal,
    tampered_receipt_valid: validTampered,
    selective_disclosure_valid: disclosureVerification.valid,
    selective_disclosure_explanation: disclosureVerification.explanation
  }, null, 2) + "\n");
  const registry = await registryMod.createReceiptRegistry({
    dir,
    orgName: flagValue(argv, "--org") || "Meridian Global Macro Demo",
    billingAccountId: flagValue(argv, "--billing-account") || "demo_billing_digest_only",
    hosted: argv.includes("--hosted"),
    endpoint: flagValue(argv, "--endpoint") || process.env.SCOPEBLIND_REGISTRY_ENDPOINT || (argv.includes("--hosted") ? "https://api.scopeblind.com" : void 0),
    token: flagValue(argv, "--token") || process.env.SCOPEBLIND_TOKEN,
    verifierBaseUrl: flagValue(argv, "--verifier-base") || "https://legate.scopeblind.com"
  });
  const runbook = [
    "# ScopeBlind Killer Demo",
    "",
    "Three-minute flow, generated locally.",
    "",
    "## 1. Agent has tools",
    "",
    "Mock tools represented: filesystem `read_file`, GitHub `github_create_pr`, email `send_email`, and PMS `pms_book_fill`.",
    "",
    "## 2. Shadow mode shows risk",
    "",
    "Open the dashboard against this directory:",
    "",
    "```bash",
    `npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`,
    "```",
    "",
    "You will see GitHub, email, and PMS calls ranked as high risk.",
    "",
    "## 3. Apply policy pack",
    "",
    `Policy pack: \`${policyPackPath}\`.`,
    "",
    "It requires approval for GitHub PRs, outbound email, and PMS booking; destructive file deletion is blocked.",
    "",
    "## 4. Sensitive action requires exact approval",
    "",
    `Request id: \`${requestId}\``,
    "",
    `Exact readback summary: \`${readback.summary}\``,
    "",
    `Payload hash: \`${readback.payload_hash}\``,
    "",
    "Secret-like fields are redacted from the approval preview but still affect the hash.",
    "",
    "## 5. User approves; tool executes through gateway",
    "",
    "Approval resolution: `.protect-mcp-approval-resolutions.jsonl`",
    "",
    "Signed receipt: `receipts/approved-pms-booking.receipt.json`",
    "",
    "## 6. Offline verification and tamper failure",
    "",
    "Verification result: `verification-results.json`.",
    "",
    "Expected: original valid, tampered invalid.",
    "",
    "## 7. Selective disclosure",
    "",
    "Committed receipt: `receipts/selective-disclosure.receipt.json`",
    "",
    "Tool-only v0 disclosure package: `receipts/selective-disclosure.tool-only.json`",
    "",
    "The disclosure opens only the committed `tool` field. Other committed fields, such as `payload_digest`, remain hidden but bound to the signed `committed_fields_root`.",
    "",
    "This demonstrates hiding sensitive context while revealing the minimum needed proof. It is salted commitment disclosure, not full zero-knowledge.",
    "",
    "## 8. Paid boundary MVP",
    "",
    `Registry: \`${registry.registryPath}\``,
    "",
    `Verifier page: \`${registry.verifierPath}\``,
    "",
    `Boundary: ${registry.uploaded ? "hosted digest anchor with independent timestamp" : "local preview only; hosted anchoring not used"}.`,
    "",
    "No raw prompt, payload, output, private key, or raw receipt is uploaded by the registry flow. Hosted mode submits receipt digests, request ids, org public keys, and billing account metadata only.",
    ""
  ].join("\n");
  writeFileSyncCli(joinCli(dir, "DEMO-RUNBOOK.md"), runbook);
  writeFileSyncCli(joinCli(dir, "demo-summary.json"), JSON.stringify({
    dir,
    dashboard_command: `npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`,
    policy_pack: policyPackPath,
    receipt: joinCli(dir, "receipts", "approved-pms-booking.receipt.json"),
    tampered_receipt: joinCli(dir, "receipts", "tampered.receipt.json"),
    selective_disclosure_receipt: joinCli(dir, "receipts", "selective-disclosure.receipt.json"),
    selective_disclosure_package: joinCli(dir, "receipts", "selective-disclosure.tool-only.json"),
    verification_results: joinCli(dir, "verification-results.json"),
    registry: registry.registryPath,
    verifier_page: registry.verifierPath,
    runbook: joinCli(dir, "DEMO-RUNBOOK.md"),
    original_valid: validOriginal.valid,
    tampered_valid: validTampered.valid,
    selective_disclosure_valid: disclosureVerification.valid
  }, null, 2) + "\n");
  process.stdout.write(`
${bold("protect-mcp killer-demo")}

`);
  process.stdout.write(`  Demo dir:          ${dir}
`);
  process.stdout.write(`  Dashboard:         ${dim(`npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`)}
`);
  process.stdout.write(`  Runbook:           ${joinCli(dir, "DEMO-RUNBOOK.md")}
`);
  process.stdout.write(`  Signed receipt:    ${joinCli(dir, "receipts", "approved-pms-booking.receipt.json")}
`);
  process.stdout.write(`  Tamper check:      original=${validOriginal.valid ? green("valid") : red("invalid")} tampered=${validTampered.valid ? red("valid") : green("invalid")}
`);
  process.stdout.write(`  Registry:          ${registry.registryPath}
`);
  process.stdout.write(`  Verifier page:     ${registry.verifierPath}
`);
  process.stdout.write(`  Boundary:          ${registry.uploaded ? green("hosted digest anchor") : yellow("local preview only")}

`);
}
async function handleVerifyDisclosure(argv) {
  const receiptPath = flagValue(argv, "--receipt");
  const disclosurePath = flagValue(argv, "--disclosure");
  if (!receiptPath || !disclosurePath) {
    process.stderr.write("Usage: protect-mcp verify-disclosure --receipt <committed-receipt.json> --disclosure <selective-disclosure.json>\\n");
    process.exit(1);
  }
  const { verifySelectiveDisclosurePackage } = await import("./signing-committed-TGWXSLAO.mjs");
  const receipt = JSON.parse(readFileSyncCli(resolveCli(receiptPath), "utf-8"));
  const disclosure = JSON.parse(readFileSyncCli(resolveCli(disclosurePath), "utf-8"));
  const result = verifySelectiveDisclosurePackage(receipt, disclosure);
  process.stdout.write(`
${bold("protect-mcp verify-disclosure")}

`);
  process.stdout.write(`  Result:           ${result.valid ? green("valid") : red("invalid")}
`);
  process.stdout.write(`  Receipt hash:     ${result.receipt_hash_valid ? green("matches") : red("mismatch")}
`);
  process.stdout.write(`  Signature:        ${result.signature_valid === true ? green("valid") : result.signature_valid === null ? yellow("not checked") : red("invalid")}
`);
  process.stdout.write(`  Commitment root:  ${result.commitment_root_valid ? green("matches") : red("mismatch")}
`);
  process.stdout.write(`  Disclosed fields: ${result.disclosed_fields.length ? result.disclosed_fields.join(", ") : "none"}
`);
  process.stdout.write(`  Hidden fields:    ${result.hidden_fields.length ? result.hidden_fields.join(", ") : "none"}

`);
  for (const line of result.explanation) {
    process.stdout.write(`  - ${line}
`);
  }
  if (result.errors.length > 0) {
    process.stdout.write(`
${red("Errors:")}
`);
    for (const err of result.errors) process.stdout.write(`  - ${err}
`);
  }
  process.stdout.write("\n");
  if (!result.valid) process.exit(2);
}
async function handlePolicyPacks(argv) {
  const subcommand = argv[0] || "list";
  const packArg = argv[1];
  const dir = resolveCli(flagValue(argv, "--dir") || "./cedar");
  const force = argv.includes("--force");
  if (subcommand === "list") {
    process.stdout.write(`
${bold("protect-mcp policy-packs")}

`);
    for (const pack of POLICY_PACKS) {
      process.stdout.write(`  ${bold(pack.id.padEnd(22))} ${pack.name}
`);
      process.stdout.write(`  ${dim(" ".repeat(24) + pack.description)}
`);
      process.stdout.write(`  ${dim(" ".repeat(24) + `recommended: ${pack.recommendedMode}`)}

`);
    }
    process.stdout.write(`Install one: ${dim("protect-mcp policy-packs install filesystem-safe --dir ./cedar")}
`);
    process.stdout.write(`Install all: ${dim("protect-mcp policy-packs install all --dir ./cedar")}

`);
    return;
  }
  if (subcommand === "show") {
    const pack = getPolicyPack(packArg || "");
    if (!pack) {
      process.stderr.write(`Unknown policy pack "${packArg || ""}". Available: ${policyPackIds().join(", ")}
`);
      process.exit(1);
    }
    process.stdout.write(`
${bold(pack.name)} (${pack.id})

`);
    process.stdout.write(`${pack.description}
`);
    process.stdout.write(`Recommended rollout: ${pack.recommendedMode}

`);
    for (const file of pack.files) {
      process.stdout.write(`${dim(`--- ${file.path} ---`)}
`);
      process.stdout.write(file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
      process.stdout.write("\n");
    }
    return;
  }
  if (subcommand === "install") {
    const packs = packArg === "all" ? POLICY_PACKS : [getPolicyPack(packArg || "")].filter(Boolean);
    if (packs.length === 0) {
      process.stderr.write(`Usage: protect-mcp policy-packs install <${policyPackIds().join("|")}|all> [--dir ./cedar] [--force]
`);
      process.exit(1);
    }
    mkdirSyncCli(dir, { recursive: true });
    const written = [];
    for (const pack of packs) {
      for (const file of pack.files) {
        const outPath = joinCli(dir, file.path);
        if (existsSyncCli(outPath) && !force) {
          process.stderr.write(`Refusing to overwrite ${outPath}. Re-run with --force if intentional.
`);
          process.exit(1);
        }
        writeFileSyncCli(outPath, file.contents.endsWith("\n") ? file.contents : `${file.contents}
`);
        written.push(outPath);
      }
    }
    process.stdout.write(`
${bold("protect-mcp policy-packs install")}

`);
    process.stdout.write(`  Directory: ${dir}
`);
    for (const outPath of written) process.stdout.write(`  Wrote:     ${outPath}
`);
    process.stdout.write(`
Next: ${dim(`protect-mcp serve --cedar ${dir}`)} for shadow mode, then add ${dim("--enforce")} after reviewing receipts.

`);
    return;
  }
  process.stderr.write("Usage: protect-mcp policy-packs list|show|install [pack] [--dir ./cedar] [--force]\n");
  process.exit(1);
}
async function handleConnectors(argv) {
  const subcommand = argv[0] || "list";
  const pilotArg = argv[1];
  const dir = resolveCli(flagValue(argv, "--dir") || process.cwd());
  const force = argv.includes("--force");
  if (subcommand === "list") {
    process.stdout.write(`
${bold("protect-mcp connector pilots")}

`);
    for (const pilot of CONNECTOR_PILOTS) {
      process.stdout.write(`  ${bold(pilot.id.padEnd(18))} ${pilot.name}
`);
      process.stdout.write(`  ${dim(" ".repeat(20) + pilot.description)}
`);
      process.stdout.write(`  ${dim(" ".repeat(20) + `tools: ${pilot.tools.join(", ")}`)}

`);
    }
    process.stdout.write(`Install all: ${dim("protect-mcp connectors init all --force")}
`);
    process.stdout.write(`Check credentials: ${dim("protect-mcp connectors doctor")}

`);
    return;
  }
  if (subcommand === "show") {
    const pilot = getConnectorPilot(pilotArg || "");
    if (!pilot) {
      process.stderr.write(`Unknown connector pilot "${pilotArg || ""}". Available: ${CONNECTOR_PILOTS.map((p) => p.id).join(", ")}
`);
      process.exit(1);
    }
    process.stdout.write(`
${bold(pilot.name)} (${pilot.id})

`);
    process.stdout.write(`${pilot.description}

`);
    process.stdout.write(`${bold("Why it matters:")} ${pilot.value}

`);
    process.stdout.write(`${bold("Tools:")} ${pilot.tools.join(", ")}

`);
    process.stdout.write(`${bold("Setup:")}
`);
    for (const step of pilot.setup) process.stdout.write(`  - ${step}
`);
    process.stdout.write(`
${bold("Starter policy:")}
${pilot.cedar}
`);
    return;
  }
  if (subcommand === "init") {
    const ids = pilotArg ? [pilotArg] : ["all"];
    const installed = writeConnectorPilots({ dir, ids, force });
    process.stdout.write(`
${bold("protect-mcp connectors init")}

`);
    process.stdout.write(`  Directory: ${installed.directory}
`);
    for (const outPath of installed.written) process.stdout.write(`  Wrote:     ${outPath}
`);
    process.stdout.write(`
Next: ${dim("protect-mcp connectors doctor")} then ${dim("protect-mcp dashboard --open")}.

`);
    return;
  }
  if (subcommand === "doctor") {
    let rows = connectorDoctor(dir);
    if (pilotArg && pilotArg !== "all") {
      const pilot = getConnectorPilot(pilotArg);
      if (!pilot) {
        process.stderr.write(`Unknown connector pilot "${pilotArg}". Available: ${CONNECTOR_PILOTS.map((p) => p.id).join(", ")}
`);
        process.exit(1);
      }
      rows = rows.filter((row) => row.id === pilot.id);
    }
    process.stdout.write(`
${bold("protect-mcp connectors doctor")}

`);
    for (const row of rows) {
      const missing = Array.isArray(row.missing_required) && row.missing_required.length > 0 ? row.missing_required.join(", ") : "";
      const status = row.installed ? row.usable ? green("ready") : yellow("needs setup") : dim("not installed");
      process.stdout.write(`  ${bold(String(row.id).padEnd(18))} ${status}
`);
      process.stdout.write(`  ${dim(" ".repeat(20) + `mode: ${String(row.mode || "unknown")}`)}
`);
      if (missing) process.stdout.write(`  ${yellow(" ".repeat(20) + `missing: ${missing}`)}
`);
      process.stdout.write(`  ${dim(" ".repeat(20) + String(row.next || ""))}

`);
    }
    process.stdout.write(`${dim("Secret values are never printed; only missing variable names are shown.")}

`);
    return;
  }
  process.stderr.write("Usage: protect-mcp connectors list|show|init|doctor [connector|all] [--dir <path>] [--force]\n");
  process.exit(1);
}
async function handleTrace(argv) {
  const receiptId = argv[0];
  if (!receiptId) {
    process.stderr.write("[PROTECT_MCP] Usage: protect-mcp trace <receipt_id> [--endpoint <url>] [--depth <n>]\n");
    process.exit(1);
  }
  let endpoint = "https://api.scopeblind.com/evidence";
  let depth = 3;
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === "--endpoint" && argv[i + 1]) {
      endpoint = argv[++i];
    } else if (argv[i] === "--depth" && argv[i + 1]) {
      depth = Math.min(10, Math.max(1, parseInt(argv[++i], 10) || 3));
    }
  }
  process.stdout.write(`
${bold("protect-mcp trace")}
`);
  process.stdout.write(`${"\u2500".repeat(60)}

`);
  process.stdout.write(`  Root:     ${receiptId}
`);
  process.stdout.write(`  Endpoint: ${endpoint}
`);
  process.stdout.write(`  Depth:    ${depth}

`);
  const url = `${endpoint}/evidence/graph/${encodeURIComponent(receiptId)}?depth=${depth}&direction=both&max=50`;
  let graphData;
  try {
    const resp = await fetch(url);
    if (!resp.ok) {
      const body = await resp.text();
      process.stderr.write(`[PROTECT_MCP] Error fetching graph: ${resp.status} ${body}
`);
      process.exit(1);
    }
    graphData = await resp.json();
  } catch (err) {
    process.stderr.write(`[PROTECT_MCP] Could not reach evidence indexer at ${endpoint}
`);
    process.stderr.write(`[PROTECT_MCP] Trying local receipts...

`);
    await traceLocal(receiptId);
    return;
  }
  if (!graphData.nodes || graphData.nodes.length === 0) {
    process.stdout.write(`  No receipts found for ${receiptId}

`);
    return;
  }
  process.stdout.write(`  ${bold("Evidence DAG")} (${graphData.node_count} nodes, ${graphData.edge_count} edges)

`);
  const nodeMap = /* @__PURE__ */ new Map();
  for (const node of graphData.nodes) {
    nodeMap.set(node.receipt_id, node);
  }
  const childMap = /* @__PURE__ */ new Map();
  for (const edge of graphData.edges) {
    if (!childMap.has(edge.from)) childMap.set(edge.from, []);
    childMap.get(edge.from).push({ to: edge.to, relation: edge.relation });
  }
  const rendered = /* @__PURE__ */ new Set();
  function renderNode(id, prefix, isLast) {
    const node = nodeMap.get(id);
    const connector = isLast ? "\u2514\u2500\u2500 " : "\u251C\u2500\u2500 ";
    const childPrefix = isLast ? "    " : "\u2502   ";
    const typeEmoji = getTypeEmoji(node?.receipt_type || "unknown");
    const shortId = id.length > 16 ? id.slice(0, 12) + "\u2026" : id;
    const time = node?.event_time ? new Date(node.event_time).toLocaleTimeString() : "?";
    const type = node?.receipt_type?.replace("acta:", "") || "unknown";
    process.stdout.write(`${prefix}${connector}${typeEmoji} ${bold(type)} ${dim(shortId)} ${dim(time)}
`);
    if (rendered.has(id)) {
      process.stdout.write(`${prefix}${childPrefix}${dim("(cycle: already rendered)")}
`);
      return;
    }
    rendered.add(id);
    const children = childMap.get(id) || [];
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const edgeLabel = dim(`\u2500\u2500[${child.relation}]\u2500\u2500\u25B6`);
      process.stdout.write(`${prefix}${childPrefix}${edgeLabel}
`);
      renderNode(child.to, prefix + childPrefix, i === children.length - 1);
    }
  }
  const rootNode = nodeMap.get(receiptId);
  if (rootNode) {
    const typeEmoji = getTypeEmoji(rootNode.receipt_type);
    const type = rootNode.receipt_type?.replace("acta:", "") || "unknown";
    const time = rootNode.event_time ? new Date(rootNode.event_time).toLocaleTimeString() : "?";
    process.stdout.write(`  ${typeEmoji} ${bold(type)} ${dim(receiptId.slice(0, 16) + "\u2026")} ${dim(time)} ${bold("(root)")}
`);
    rendered.add(receiptId);
    const children = childMap.get(receiptId) || [];
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const edgeLabel = dim(`\u2500\u2500[${child.relation}]\u2500\u2500\u25B6`);
      process.stdout.write(`  ${edgeLabel}
`);
      renderNode(child.to, "  ", i === children.length - 1);
    }
    const incomingEdges = (graphData.edges || []).filter((e) => e.to === receiptId);
    if (incomingEdges.length > 0) {
      process.stdout.write(`
  ${bold("Incoming edges:")}
`);
      for (const edge of incomingEdges) {
        const fromNode = nodeMap.get(edge.from);
        const fromType = fromNode?.receipt_type?.replace("acta:", "") || "unknown";
        process.stdout.write(`  \u25C0\u2500\u2500[${edge.relation}]\u2500\u2500 ${getTypeEmoji(fromNode?.receipt_type)} ${fromType} ${dim(edge.from.slice(0, 16) + "\u2026")}
`);
      }
    }
  } else {
    for (const node of graphData.nodes) {
      const typeEmoji = getTypeEmoji(node.receipt_type);
      const type = node.receipt_type?.replace("acta:", "") || "unknown";
      process.stdout.write(`  ${typeEmoji} ${bold(type)} ${dim(node.receipt_id.slice(0, 16) + "\u2026")}
`);
    }
  }
  process.stdout.write(`
${"\u2500".repeat(60)}
`);
  process.stdout.write(`  ${dim(`Fetched from ${endpoint}`)}

`);
}
async function traceLocal(receiptId) {
  const { readFileSync, existsSync } = await import("fs");
  const { join } = await import("path");
  const dir = process.cwd();
  const receiptsDir = join(dir, ".protect-mcp", "receipts");
  if (!existsSync(receiptsDir)) {
    process.stdout.write(`  No local receipts found in ${receiptsDir}

`);
    return;
  }
  const { readdirSync } = await import("fs");
  const files = readdirSync(receiptsDir).filter((f) => f.endsWith(".json"));
  process.stdout.write(`  Scanning ${files.length} local receipts...

`);
  const receipts = [];
  for (const file of files) {
    try {
      const content = readFileSync(join(receiptsDir, file), "utf-8");
      const receipt = JSON.parse(content);
      receipts.push(receipt);
    } catch {
    }
  }
  const match = receipts.find(
    (r) => r.signed_claims?.claims?.receipt_id === receiptId || r.receipt_id === receiptId
  );
  if (match) {
    const claims = match.signed_claims?.claims || match;
    process.stdout.write(`  Found: ${getTypeEmoji(claims.receipt_type)} ${bold(claims.receipt_type?.replace("acta:", "") || "unknown")}
`);
    process.stdout.write(`  Event:  ${claims.event_id || "?"}
`);
    process.stdout.write(`  Issuer: ${claims.issuer_id || "?"}
`);
    process.stdout.write(`  Time:   ${claims.event_time || "?"}
`);
    if (claims.edges && claims.edges.length > 0) {
      process.stdout.write(`
  ${bold("Edges:")}
`);
      for (const edge of claims.edges) {
        process.stdout.write(`    \u2500\u2500[${edge.relation}]\u2500\u2500\u25B6 ${dim(edge.receipt_id?.slice(0, 16) + "\u2026")}
`);
      }
    }
  } else {
    process.stdout.write(`  Receipt ${receiptId} not found locally.
`);
  }
  process.stdout.write("\n");
}
function getTypeEmoji(type) {
  switch (type) {
    case "acta:observation":
      return "\u{1F441} ";
    case "acta:policy-load":
      return "\u{1F4CB}";
    case "acta:approval":
      return "\u2705";
    case "acta:decision":
      return "\u2696\uFE0F ";
    case "acta:execution":
      return "\u26A1";
    case "acta:outcome":
      return "\u{1F4E6}";
    case "acta:delegation":
      return "\u{1F91D}";
    case "acta:capability-attestation":
      return "\u{1F3C5}";
    default:
      return "\u{1F4C4}";
  }
}
async function handleInitHooks(argv) {
  const { writeFileSync, existsSync, mkdirSync, readFileSync } = await import("fs");
  const { join } = await import("path");
  const { generateHookSettings, generateSampleCedarPolicy, generateVerifyReceiptSkill } = await import("./hook-patterns.mjs");
  let dir = process.cwd();
  const dirIdx = argv.indexOf("--dir");
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];
  const portIdx = argv.indexOf("--port");
  const port = portIdx >= 0 && argv[portIdx + 1] ? parseInt(argv[portIdx + 1]) : 9377;
  const hookUrl = `http://127.0.0.1:${port}/hook`;
  process.stdout.write(`
${bold("protect-mcp init-hooks")}
`);
  process.stdout.write(`${"\u2500".repeat(55)}

`);
  const claudeDir = join(dir, ".claude");
  const settingsPath = join(claudeDir, "settings.json");
  let existingSettings = {};
  if (!existsSync(claudeDir)) {
    mkdirSync(claudeDir, { recursive: true });
  }
  if (existsSync(settingsPath)) {
    try {
      existingSettings = JSON.parse(readFileSync(settingsPath, "utf-8"));
    } catch {
      process.stderr.write(`[PROTECT_MCP] Warning: Could not parse existing ${settingsPath}
`);
    }
  }
  const hookSettings = generateHookSettings(hookUrl);
  const mergedSettings = {
    ...existingSettings,
    hooks: {
      ...existingSettings.hooks || {},
      ...hookSettings.hooks
    }
  };
  writeFileSync(settingsPath, JSON.stringify(mergedSettings, null, 2) + "\n");
  process.stdout.write(`  ${green("\u2713")} ${settingsPath}
`);
  process.stdout.write(`    Hook URL: ${dim(hookUrl)}
`);
  process.stdout.write(`    Events: PreToolUse, PostToolUse, SubagentStart/Stop, Task, Session, Config, Stop

`);
  const keysDir = join(dir, "keys");
  const keyPath = join(keysDir, "gateway.json");
  if (!existsSync(keyPath)) {
    if (!existsSync(keysDir)) mkdirSync(keysDir, { recursive: true });
    const { randomBytes: rb } = await import("crypto");
    try {
      const { ed25519 } = await import("./ed25519-SQA3S2RV.mjs");
      const { bytesToHex } = await import("./utils-6AYZFE5A.mjs");
      const privateKey = rb(32);
      const publicKey = ed25519.getPublicKey(privateKey);
      writeFileSync(keyPath, JSON.stringify({
        privateKey: bytesToHex(privateKey),
        publicKey: bytesToHex(publicKey),
        kid: `hook-${Date.now()}`,
        generated_at: (/* @__PURE__ */ new Date()).toISOString(),
        warning: "KEEP THIS FILE SECRET. Never commit to version control."
      }, null, 2) + "\n");
      const gitignorePath = join(keysDir, ".gitignore");
      if (!existsSync(gitignorePath)) {
        writeFileSync(gitignorePath, "# Never commit signing keys\n*.json\n");
      }
      process.stdout.write(`  ${green("\u2713")} ${keyPath} (Ed25519 keypair)

`);
    } catch {
      process.stdout.write(`  ${yellow("\u26A0")} Could not generate Ed25519 keys, signing disabled

`);
    }
  } else {
    process.stdout.write(`  ${green("\u2713")} ${keyPath} (existing keys found)

`);
  }
  const policiesDir = join(dir, "policies");
  const cedarPath = join(policiesDir, "agent.cedar");
  if (!existsSync(cedarPath)) {
    if (!existsSync(policiesDir)) mkdirSync(policiesDir, { recursive: true });
    writeFileSync(cedarPath, generateSampleCedarPolicy());
    process.stdout.write(`  ${green("\u2713")} ${cedarPath}
`);
    process.stdout.write(`    Edit to customize tool permissions. Cedar deny is AUTHORITATIVE.

`);
  } else {
    process.stdout.write(`  ${green("\u2713")} ${cedarPath} (existing policy found)

`);
  }
  const configPath = join(dir, "protect-mcp.json");
  if (!existsSync(configPath)) {
    const config = {
      tools: { "*": { rate_limit: "100/hour" } },
      default_tier: "unknown",
      signing: {
        key_path: "./keys/gateway.json",
        issuer: "protect-mcp",
        enabled: true
      }
    };
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
    process.stdout.write(`  ${green("\u2713")} ${configPath}

`);
  }
  const skillsDir = join(dir, ".claude", "skills", "verify-receipt");
  const skillPath = join(skillsDir, "SKILL.md");
  if (!existsSync(skillPath)) {
    mkdirSync(skillsDir, { recursive: true });
    writeFileSync(skillPath, generateVerifyReceiptSkill());
    process.stdout.write(`  ${green("\u2713")} ${skillPath}
`);
    process.stdout.write(`    Use ${dim("/verify-receipt")} in Claude Code to check audit trails.

`);
  } else {
    process.stdout.write(`  ${green("\u2713")} ${skillPath} (existing skill found)

`);
  }
  process.stdout.write(`${"\u2500".repeat(55)}

`);
  process.stdout.write(`${bold("Next steps:")}

`);
  process.stdout.write(`  1. Start the hook server:
`);
  process.stdout.write(`     ${dim(`npx protect-mcp serve`)}

`);
  process.stdout.write(`  2. Open a Claude Code session in this project.
`);
  process.stdout.write(`     Every tool call will be receipted automatically.

`);
  process.stdout.write(`  3. See your record: a searchable view of every decision.
`);
  process.stdout.write(`     ${dim(`npx protect-mcp record`)}
`);
  process.stdout.write(`     ${dim(`Everything stays on this machine. Nothing is uploaded.`)}

`);
  process.stdout.write(`     Prefer the terminal? ${dim(`npx protect-mcp receipts`)}, or ${dim("/verify-receipt")} in Claude Code.

`);
  process.stdout.write(`  4. View policy suggestions:
`);
  process.stdout.write(`     ${dim(`curl http://127.0.0.1:${port}/suggestions`)}

`);
  process.stdout.write(`${bold("Key facts:")}
`);
  process.stdout.write(`  \u2022 deny decisions are ${bold("AUTHORITATIVE")}: they cannot be overridden
`);
  process.stdout.write(`  \u2022 PostToolUse runs ${bold("async")}, so there is zero latency impact on tool execution
`);
  process.stdout.write(`  \u2022 Receipts are Ed25519-signed and append-only
`);
  process.stdout.write(`  \u2022 Swarm topology (coordinator/workers) is tracked automatically

`);
}
async function sendInstallTelemetry() {
  try {
    const { existsSync, mkdirSync, writeFileSync, readFileSync } = await import("fs");
    const { join, dirname } = await import("path");
    const { homedir } = await import("os");
    const { fileURLToPath } = await import("url");
    const markerDir = join(homedir(), ".protect-mcp");
    const markerFile = join(markerDir, ".telemetry-sent");
    if (existsSync(markerFile) || process.env.PROTECT_MCP_TELEMETRY === "off") {
      return;
    }
    const version = await pkgVersion();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3e3);
    fetch("https://api.scopeblind.com/telemetry/install", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: "protect-mcp",
        version,
        os: process.platform,
        arch: process.arch,
        node: process.version,
        ts: Date.now()
      }),
      signal: controller.signal
    }).catch(() => {
    }).finally(() => clearTimeout(timeout));
    if (!existsSync(markerDir)) {
      mkdirSync(markerDir, { recursive: true });
    }
    writeFileSync(markerFile, String(Date.now()), "utf-8");
    process.stderr.write(
      "[protect-mcp] Thanks for installing! Anonymous telemetry sent (disable: PROTECT_MCP_TELEMETRY=off)\n[protect-mcp] Free dashboard: npx protect-mcp connect | https://scopeblind.com\n"
    );
  } catch {
  }
}
function flagValue(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : void 0;
}
function loadPolicyArg(argv) {
  const cedarDir = flagValue(argv, "--cedar");
  const policyFile = flagValue(argv, "--policy");
  try {
    if (cedarDir) return loadCedarPolicies(cedarDir);
    if (policyFile && existsSyncCli(policyFile)) {
      return policySetFromSource(readFileSyncCli(policyFile, "utf-8"), basenameCli(policyFile));
    }
  } catch {
  }
  return null;
}
async function readHookStdin() {
  if (process.stdin.isTTY) return null;
  try {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf-8").trim();
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function mapHookPayload(j) {
  const tool = j.tool_name ?? j.toolName;
  const input = j.tool_input ?? j.toolInput;
  if (input === void 0 && j.command !== void 0) {
    return { tool: tool ?? "Bash", input: { command: j.command } };
  }
  return { tool, input };
}
function emitDecision(format, allowed, reason) {
  if (format === "hermes") {
    process.stdout.write(JSON.stringify(allowed ? {} : { decision: "block", reason }) + "\n");
    process.exit(0);
  }
  if (allowed) {
    process.stdout.write(JSON.stringify({ allowed: true, reason }) + "\n");
    process.exit(0);
  }
  if (format === "cursor") {
    process.stdout.write(JSON.stringify({ permission: "deny", userMessage: reason }) + "\n");
  } else if (format === "gemini") {
    process.stdout.write(JSON.stringify({ decision: "deny", reason }) + "\n");
  }
  process.stderr.write(`protect-mcp denied: ${reason}
`);
  process.exit(2);
}
async function handleEvaluate(argv) {
  const format = flagValue(argv, "--format");
  let tool = flagValue(argv, "--tool") || "";
  let inputRaw = flagValue(argv, "--input") || "{}";
  const contextRaw = flagValue(argv, "--context");
  const failOnMissing = flagValue(argv, "--fail-on-missing-policy") !== "false";
  if (format) {
    const j = await readHookStdin();
    if (j) {
      const m = mapHookPayload(j);
      if (m.tool) tool = m.tool;
      if (m.input !== void 0) inputRaw = JSON.stringify(m.input);
    }
  }
  const policySet = loadPolicyArg(argv);
  if (!policySet) {
    if (failOnMissing) {
      if (format) emitDecision(format, false, "policy not found (fail-closed)");
      process.stderr.write("protect-mcp evaluate: policy not found; denying (fail-closed). Pass --fail-on-missing-policy false to allow.\n");
      process.exit(2);
    }
    if (format) emitDecision(format, true, "no_policy_configured");
    process.stdout.write(JSON.stringify({ allowed: true, reason: "no_policy_configured" }) + "\n");
    process.exit(0);
  }
  let input = {};
  try {
    input = JSON.parse(inputRaw);
  } catch {
  }
  let extra = {};
  if (contextRaw) {
    try {
      extra = JSON.parse(contextRaw);
    } catch {
    }
  }
  const context = { ...input, ...extra };
  if (typeof input.command === "string" && context.command_pattern === void 0) {
    context.command_pattern = input.command;
  }
  const decision = await evaluateCedar(policySet, { tool, tier: "unknown", context, toolInput: input }, void 0, { failClosed: true });
  if (format) emitDecision(format, decision.allowed, decision.reason || (decision.allowed ? "allowed" : "denied by policy"));
  process.stdout.write(JSON.stringify({ allowed: decision.allowed, reason: decision.reason, policy_digest: policySet.digest }) + "\n");
  process.exit(decision.allowed ? 0 : 2);
}
async function handleSign(argv) {
  const format = flagValue(argv, "--format");
  let tool = flagValue(argv, "--tool") || "";
  const receiptsDir = flagValue(argv, "--receipts") || "./receipts/";
  const keyPath = flagValue(argv, "--key");
  if (format) {
    const j = await readHookStdin();
    if (j) {
      const m = mapHookPayload(j);
      if (m.tool) tool = m.tool;
    }
  }
  if (keyPath && existsSyncCli(keyPath)) {
    try {
      await initSigning({ enabled: true, key_path: keyPath });
    } catch {
    }
  }
  const requestId = `tu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const signed = signDecision({
    tool,
    decision: "allow",
    reason_code: "post_execution_receipt",
    policy_digest: "none",
    request_id: requestId,
    mode: "enforce",
    timestamp: Date.now()
  });
  try {
    mkdirSyncCli(receiptsDir, { recursive: true });
  } catch {
  }
  const line = signed.signed ?? JSON.stringify({ tool, request_id: requestId, signed: false, note: signed.warning || "no signer configured" });
  try {
    appendFileSyncCli(joinCli(receiptsDir, "receipts.jsonl"), line + "\n");
  } catch {
  }
  if (format === "hermes") {
    process.stdout.write("{}\n");
    process.exit(0);
  }
  process.stdout.write(JSON.stringify({ signed: Boolean(signed.signed), artifact_type: signed.artifact_type, request_id: requestId }) + "\n");
  process.exit(0);
}
async function main() {
  sendInstallTelemetry().catch(() => {
  });
  const args = process.argv.slice(2);
  process.env.PROTECT_MCP_VERSION = process.env.PROTECT_MCP_VERSION || await pkgVersion();
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  if (args[0] === "evaluate") {
    await handleEvaluate(args.slice(1));
    return;
  }
  if (args[0] === "sign") {
    await handleSign(args.slice(1));
    return;
  }
  if (args[0] === "serve") {
    const { startHookServer } = await import("./hook-server.mjs");
    const portIdx = args.indexOf("--port");
    const port = portIdx >= 0 && args[portIdx + 1] ? parseInt(args[portIdx + 1]) : 9377;
    const policyIdx = args.indexOf("--policy");
    const policyPath2 = policyIdx >= 0 && args[policyIdx + 1] ? args[policyIdx + 1] : void 0;
    const cedarIdx = args.indexOf("--cedar");
    const cedarDir2 = cedarIdx >= 0 && args[cedarIdx + 1] ? args[cedarIdx + 1] : void 0;
    const enforce2 = args.includes("--enforce");
    const verbose2 = args.includes("--verbose") || args.includes("-v");
    if (enforce2) {
      const selfTest = await runEvaluatorSelfTest();
      if (!selfTest.passed) {
        process.stderr.write("protect-mcp serve --enforce: the policy-engine restraint self-test FAILED. Refusing to arm the gate.\n");
        for (const c of selfTest.cases.filter((c2) => !c2.pass)) {
          process.stderr.write(`  [FAIL] ${c.name}: expected ${c.expected}, got ${c.actual}
`);
        }
        process.exit(1);
      }
      if (verbose2) process.stderr.write(`protect-mcp: restraint self-test passed (${selfTest.cases.length} vectors). Arming gate.
`);
    }
    await startHookServer({ port, policyPath: policyPath2, cedarDir: cedarDir2, enforce: enforce2, verbose: verbose2 });
    return;
  }
  if (args[0] === "record") {
    await handleRecord(args.slice(1));
    return;
  }
  if (args[0] === "init-hooks") {
    await handleInitHooks(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "quickstart") {
    await handleQuickstart(args.slice(1));
    return;
  }
  if (args[0] === "wrap") {
    await handleWrap(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "dashboard") {
    await handleDashboard(args.slice(1));
    return;
  }
  if (args[0] === "recommend") {
    await handleRecommend(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "registry") {
    await handleRegistry(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "trial") {
    await handleKillerDemo(args.slice(1));
    process.stdout.write(`${bold("Next: open the local dashboard")}
`);
    process.stdout.write(`  npx protect-mcp dashboard --dir ${dim(flagValue(args.slice(1), "--dir") || "<demo dir printed above>")} --open

`);
    process.stdout.write(`${dim("No ScopeBlind account is required for local receipts. Add --hosted with SCOPEBLIND_TOKEN when you want independent digest anchoring.")}

`);
    process.exit(0);
  }
  if (args[0] === "killer-demo") {
    await handleKillerDemo(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "verify-disclosure") {
    await handleVerifyDisclosure(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "policy-packs") {
    await handlePolicyPacks(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "connectors") {
    await handleConnectors(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "connect") {
    await handleConnect();
    process.exit(0);
  }
  if (args[0] === "init") {
    await handleInit(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "demo") {
    await handleDemo();
    return;
  }
  if (args[0] === "status") {
    await handleStatus(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "digest") {
    await handleDigest(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "receipts") {
    await handleReceipts(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "bundle") {
    await handleBundle(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "trace") {
    await handleTrace(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "simulate") {
    await handleSimulate(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "report") {
    await handleReport(args.slice(1));
    process.exit(0);
  }
  if (args[0] === "doctor") {
    await handleDoctor();
    process.exit(0);
  }
  const { policyPath, cedarDir, slug, enforce, verbose, childCommand } = parseArgs(args);
  let policy = null;
  let policyDigest = "none";
  let credentials;
  let signing;
  let cedarPolicySet = null;
  let effectiveCedarDir = cedarDir;
  if (!effectiveCedarDir && !policyPath) {
    const { existsSync, readdirSync } = await import("fs");
    for (const candidate of ["cedar", "policies", "."]) {
      try {
        if (existsSync(candidate) && readdirSync(candidate).some((f) => f.endsWith(".cedar"))) {
          effectiveCedarDir = candidate;
          process.stderr.write(`[PROTECT_MCP] Auto-detected Cedar policies in ./${candidate}/
`);
          break;
        }
      } catch {
      }
    }
  }
  if (effectiveCedarDir) {
    try {
      const cedarAvailable = await isCedarAvailable();
      if (!cedarAvailable) {
        process.stderr.write("[PROTECT_MCP] Warning: @cedar-policy/cedar-wasm not installed. Install with: npm install @cedar-policy/cedar-wasm\n");
        process.stderr.write("[PROTECT_MCP] Cedar policies will be loaded but evaluated with fallback (allow-all).\n");
      }
      cedarPolicySet = loadCedarPolicies(effectiveCedarDir);
      policyDigest = cedarPolicySet.digest;
      policy = {
        tools: { "*": { require: "any" } },
        policy_engine: "cedar",
        cedar_dir: effectiveCedarDir
      };
      process.stderr.write(`[PROTECT_MCP] Cedar policy engine: loaded ${cedarPolicySet.fileCount} policies from ${effectiveCedarDir} (digest: ${policyDigest})
`);
      if (verbose) {
        process.stderr.write(`[PROTECT_MCP] Cedar files: ${cedarPolicySet.files.join(", ")}
`);
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading Cedar policies: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
  } else if (policyPath) {
    try {
      const loaded = loadPolicy(policyPath);
      policy = loaded.policy;
      policyDigest = loaded.digest;
      credentials = loaded.credentials;
      signing = loaded.signing;
      if (verbose) {
        process.stderr.write(`[PROTECT_MCP] Loaded policy from ${policyPath} (digest: ${policyDigest})
`);
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading policy: ${err instanceof Error ? err.message : err}
`);
      process.exit(1);
    }
  }
  if (signing) {
    const warnings = await initSigning(signing);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  if (credentials) {
    const warnings = validateCredentials(credentials);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}
`);
    }
  }
  const config = {
    command: childCommand[0],
    args: childCommand.slice(1),
    policy,
    policyDigest,
    slug,
    enforce,
    verbose,
    signing,
    credentials
  };
  const useHttp = args.includes("--http");
  if (useHttp) {
    const portIdx = args.indexOf("--port");
    const httpPort = portIdx >= 0 && args[portIdx + 1] ? parseInt(args[portIdx + 1]) : 3e3;
    const { startHttpTransport } = await import("./http-transport-D7C64PIA.mjs");
    startHttpTransport({ port: httpPort, config, serverCommand: childCommand });
    return;
  }
  const gateway = new ProtectGateway(config);
  if (cedarPolicySet) {
    gateway.setCedarPolicies(cedarPolicySet);
  }
  await gateway.start();
}
async function handleSimulate(args) {
  let policyPath = "";
  let logPath = ".protect-mcp-log.jsonl";
  let tier = "unknown";
  let jsonOutput = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--policy" && args[i + 1]) {
      policyPath = args[++i];
    } else if (args[i] === "--log" && args[i + 1]) {
      logPath = args[++i];
    } else if (args[i] === "--tier" && args[i + 1]) {
      tier = args[++i];
    } else if (args[i] === "--json") {
      jsonOutput = true;
    }
  }
  if (!policyPath) {
    process.stderr.write("Usage: protect-mcp simulate --policy <path> [--log <path>] [--tier <tier>] [--json]\n");
    process.exit(1);
  }
  const { existsSync } = await import("fs");
  if (!existsSync(logPath)) {
    process.stderr.write(`Log file not found: ${logPath}
`);
    process.stderr.write("Run protect-mcp in shadow mode first to generate a log file.\n");
    process.exit(1);
  }
  const { policy } = loadPolicy(policyPath);
  const entries = parseLogFile(logPath);
  if (entries.length === 0) {
    process.stderr.write("No tool call entries found in log file.\n");
    process.exit(1);
  }
  const summary = simulate(entries, policy, tier);
  summary.policy_file = policyPath;
  summary.log_file = logPath;
  if (jsonOutput) {
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  } else {
    process.stdout.write(formatSimulation(summary) + "\n");
  }
}
async function handleDoctor() {
  const { existsSync, readFileSync, readdirSync } = await import("fs");
  const { join } = await import("path");
  const { execSync } = await import("child_process");
  const green2 = (s) => `\x1B[32m\u2713\x1B[0m ${s}`;
  const red2 = (s) => `\x1B[31m\u2717\x1B[0m ${s}`;
  const yellow2 = (s) => `\x1B[33m\u26A0\x1B[0m ${s}`;
  const dim2 = (s) => `\x1B[2m${s}\x1B[0m`;
  process.stdout.write("\n\x1B[1mprotect-mcp doctor\x1B[0m\n");
  process.stdout.write(dim2("Checking your ScopeBlind setup...\n\n"));
  let issues = 0;
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1));
  if (major >= 18) {
    process.stdout.write(green2(`Node.js ${nodeVersion}
`));
  } else {
    process.stdout.write(red2(`Node.js ${nodeVersion}, requires >= 18
`));
    issues++;
  }
  const configPath = join(process.cwd(), "scopeblind.config.json");
  if (existsSync(configPath)) {
    try {
      const config = JSON.parse(readFileSync(configPath, "utf-8"));
      if (config.signing?.private_key || config.signing?.key_file) {
        process.stdout.write(green2("Signing keys configured\n"));
      } else {
        process.stdout.write(yellow2("Config found but no signing keys. Run: protect-mcp init\n"));
        issues++;
      }
    } catch {
      process.stdout.write(red2("Invalid scopeblind.config.json\n"));
      issues++;
    }
  } else {
    process.stdout.write(yellow2("No scopeblind.config.json. Run: protect-mcp init\n"));
  }
  let policyFound = false;
  for (const dir of ["cedar", "policies", "."]) {
    try {
      if (existsSync(dir) && readdirSync(dir).some((f) => f.endsWith(".cedar"))) {
        process.stdout.write(green2(`Cedar policies found in ./${dir}/
`));
        policyFound = true;
        break;
      }
    } catch {
    }
  }
  if (!policyFound) {
    for (const name of ["policy.json", "protect-mcp.policy.json", "scopeblind-policy.json"]) {
      if (existsSync(name)) {
        process.stdout.write(green2(`JSON policy found: ${name}
`));
        policyFound = true;
        break;
      }
    }
  }
  if (!policyFound) {
    process.stdout.write(yellow2("No policy files found, running in shadow mode (allow all)\n"));
  }
  try {
    const cedarAvailable = await isCedarAvailable();
    if (cedarAvailable) {
      process.stdout.write(green2("Cedar WASM engine available\n"));
    } else {
      process.stdout.write(dim2("  Cedar WASM not installed. Install: npm install @cedar-policy/cedar-wasm\n"));
    }
  } catch {
    process.stdout.write(dim2("  Cedar WASM not installed\n"));
  }
  const logFile = join(process.cwd(), "protect-mcp-decisions.jsonl");
  const receiptFile = join(process.cwd(), "protect-mcp-receipts.jsonl");
  if (existsSync(logFile)) {
    try {
      const lines = readFileSync(logFile, "utf-8").trim().split("\n").length;
      process.stdout.write(green2(`Decision log: ${lines} entries
`));
    } catch {
      process.stdout.write(green2("Decision log exists\n"));
    }
  } else {
    process.stdout.write(dim2("  No decision log yet, will be created on first tool call\n"));
  }
  if (existsSync(receiptFile)) {
    try {
      const lines = readFileSync(receiptFile, "utf-8").trim().split("\n").length;
      process.stdout.write(green2(`Receipt file: ${lines} signed receipts
`));
    } catch {
      process.stdout.write(green2("Receipt file exists\n"));
    }
  }
  try {
    execSync("npx @veritasacta/verify --version 2>/dev/null", { stdio: "pipe", timeout: 1e4 });
    process.stdout.write(green2("Verifier available: @veritasacta/verify\n"));
  } catch {
    process.stdout.write(dim2("  Verifier not cached. Install: npm install -g @veritasacta/verify\n"));
  }
  try {
    const res = await fetch("https://api.scopeblind.com/health", { signal: AbortSignal.timeout(5e3) });
    if (res.ok) {
      process.stdout.write(green2("ScopeBlind API reachable\n"));
    } else {
      process.stdout.write(yellow2("ScopeBlind API returned non-200, receipts will be stored locally\n"));
    }
  } catch {
    process.stdout.write(dim2("  ScopeBlind API not reachable, offline mode (receipts stored locally)\n"));
  }
  process.stdout.write("\nRestraint self-test:\n");
  try {
    const st = await runEvaluatorSelfTest();
    if (!st.wasmAvailable) {
      process.stdout.write(dim2("  Cedar WASM not installed; the gate fails closed (denies) until it is.\n"));
    }
    for (const c of st.cases) {
      process.stdout.write(c.pass ? green2(`  ${c.name}
`) : `\x1B[31m  FAIL: ${c.name} (expected ${c.expected}, got ${c.actual})
\x1B[0m`);
    }
    if (!st.passed) issues++;
    else process.stdout.write(green2("  the gate denies what it should and allows what it should\n"));
  } catch (err) {
    process.stdout.write(yellow2(`  self-test could not run: ${err instanceof Error ? err.message : "unknown"}
`));
    issues++;
  }
  process.stdout.write("\n");
  if (issues === 0) {
    process.stdout.write("\x1B[32m\x1B[1mAll checks passed.\x1B[0m Ready to wrap MCP servers.\n");
    process.stdout.write(dim2("\n  npx protect-mcp -- node your-server.js\n\n"));
  } else {
    process.stdout.write(`\x1B[33m\x1B[1m${issues} issue(s) found.\x1B[0m Fix them and run doctor again.

`);
  }
}
async function handleReport(args) {
  let period = 30;
  let format = "json";
  let outputPath = "";
  let dir = process.cwd();
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--period" && args[i + 1]) {
      const match = args[++i].match(/^(\d+)d$/);
      if (match) period = parseInt(match[1], 10);
    } else if (args[i] === "--format" && args[i + 1]) {
      format = args[++i];
    } else if (args[i] === "--output" && args[i + 1]) {
      outputPath = args[++i];
    } else if (args[i] === "--dir" && args[i + 1]) {
      dir = args[++i];
    }
  }
  const { generateReport, formatReportMarkdown } = await import("./report-5XCNW6FB.mjs");
  const { join } = await import("path");
  const logPath = join(dir, ".protect-mcp-log.jsonl");
  const receiptPath = join(dir, ".protect-mcp-receipts.jsonl");
  const report = generateReport(logPath, receiptPath, period);
  let output;
  if (format === "md") {
    output = formatReportMarkdown(report);
  } else {
    output = JSON.stringify(report, null, 2);
  }
  if (outputPath) {
    const { writeFileSync } = await import("fs");
    writeFileSync(outputPath, output, "utf-8");
    process.stderr.write(`Report written to ${outputPath}
`);
  } else {
    process.stdout.write(output + "\n");
  }
}
main().catch((err) => {
  process.stderr.write(`[PROTECT_MCP] Fatal error: ${err instanceof Error ? err.message : err}
`);
  process.exit(1);
});
