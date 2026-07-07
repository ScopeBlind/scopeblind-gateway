#!/usr/bin/env node

/**
 * @scopeblind/protect-mcp CLI
 *
 * Usage:
 *   npx protect-mcp [options] -- <command> [args...]
 *   npx protect-mcp init [--dir <path>]
 *   npx protect-mcp wrap [--write] [--claude-desktop] [-- <command>]
 *   npx protect-mcp dashboard [--port <port>] [--dir <path>] [--open]
 *   npx protect-mcp recommend [--dir <path>] [--output <path>] [--write]
 *   npx protect-mcp connect
 *   npx protect-mcp trial [--dir <path>] [--hosted]
 *   npx protect-mcp connectors list|show|init|doctor [connector|all] [--dir <path>] [--force]
 *   npx protect-mcp demo
 *   npx protect-mcp status [--dir <path>]
 *   npx protect-mcp bundle [--output <path>] [--dir <path>]
 *
 * Options:
 *   --policy <path>   Policy JSON file (default: allow-all)
 *   --slug <slug>     ScopeBlind tenant slug (optional)
 *   --enforce         Enable enforcement mode (default: shadow mode)
 *   --verbose         Enable debug logging to stderr
 *   --help            Show help
 *
 * Commands:
 *   init              Generate config, keypair, and policy template
 *   demo              Run a built-in demo server with protect-mcp wrapping it
 *   status            Show tool call statistics from the local log file
 */

import { ProtectGateway } from './gateway.js';
import { loadPolicy } from './policy.js';
import { initSigning, signDecision } from './signing.js';
import { validateCredentials } from './credentials.js';
import { parseLogFile, simulate, formatSimulation } from './simulate.js';
import { buildActionReadback } from './action-readback.js';
import { loadCedarPolicies, isCedarAvailable, evaluateCedar, policySetFromSource, runEvaluatorSelfTest, type CedarPolicySet } from './cedar-evaluator.js';
import { POLICY_PACKS, getPolicyPack, policyPackIds } from './policy-packs.js';
import { CONNECTOR_PILOTS, connectorDoctor, getConnectorPilot, readInstalledConnectorPilots, writeConnectorPilots } from './connector-pilots.js';
import { createHash as createHashCli } from 'node:crypto';
import { readFileSync as readFileSyncCli, existsSync as existsSyncCli, appendFileSync as appendFileSyncCli, mkdirSync as mkdirSyncCli, readdirSync as readdirSyncCli, writeFileSync as writeFileSyncCli } from 'node:fs';
import { basename as basenameCli, dirname as dirnameCli, join as joinCli, resolve as resolveCli } from 'node:path';
import { homedir as homedirCli } from 'node:os';
import type { ProtectConfig, ToolPolicy } from './types.js';

function printHelp(): void {
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
  protect-mcp claim [--no <cap>] [--only <c,c>] [--count <verdict>] [--dir <path>] [--output <path>]
  protect-mcp verify-claim <claim.json> [--key <public-hex>]
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
  killer-demo       Build a 3-minute shadow→policy→approval→receipt demo pack
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
  claim             Attest a signed, position-blind claim over your record (e.g. no egress,
                    no payment, every payment under a cap)
  verify-claim      Verify a claim attestation offline (signature + predicate + commitment
                    + the anchor sidecar and issuer identity when present)
  anchor-record     Checkpoint the record's Merkle root + count into the public log
                    (heartbeat-friendly: skips when unchanged; only hashes leave)
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

function parseArgs(argv: string[]): {
  policyPath?: string;
  cedarDir?: string;
  slug?: string;
  enforce: boolean;
  verbose: boolean;
  childCommand: string[];
} {
  let policyPath: string | undefined;
  let cedarDir: string | undefined;
  let slug: string | undefined;
  let enforce = false;
  let verbose = false;
  let childCommand: string[] = [];

  // Find the -- separator
  const separatorIndex = argv.indexOf('--');

  if (separatorIndex === -1) {
    process.stderr.write(
      '[PROTECT_MCP] Error: Missing "--" separator before the command to wrap.\n' +
      'Usage: protect-mcp [options] -- <command> [args...]\n' +
      'Example: protect-mcp --policy policy.json -- node my-server.js\n',
    );
    process.exit(1);
  }

  // Everything after -- is the child command
  childCommand = argv.slice(separatorIndex + 1);

  if (childCommand.length === 0) {
    process.stderr.write('[PROTECT_MCP] Error: No command specified after "--"\n');
    process.exit(1);
  }

  // Parse options before --
  const options = argv.slice(0, separatorIndex);
  for (let i = 0; i < options.length; i++) {
    const arg = options[i];

    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (arg === '--policy' && i + 1 < options.length) {
      policyPath = options[++i];
    } else if (arg === '--cedar' && i + 1 < options.length) {
      cedarDir = options[++i];
    } else if (arg === '--slug' && i + 1 < options.length) {
      slug = options[++i];
    } else if (arg === '--enforce') {
      enforce = true;
    } else if (arg === '--verbose' || arg === '-v') {
      verbose = true;
    } else {
      process.stderr.write(`[PROTECT_MCP] Warning: Unknown option "${arg}"\n`);
    }
  }

  return { policyPath, cedarDir, slug, enforce, verbose, childCommand };
}

/**
 * Handle the `init` command: generate config, keypair, and policy template.
 */
async function handleInit(argv: string[]): Promise<void> {
  const { writeFileSync, existsSync, mkdirSync } = await import('node:fs');
  const { join } = await import('node:path');

  let dir = process.cwd();
  const dirIdx = argv.indexOf('--dir');
  if (dirIdx !== -1 && argv[dirIdx + 1]) {
    dir = argv[dirIdx + 1];
  }

  const configPath = join(dir, 'protect-mcp.json');
  const keysDir = join(dir, 'keys');
  const keyPath = join(keysDir, 'gateway.json');

  // Check if config already exists
  if (existsSync(configPath)) {
    process.stderr.write(`[PROTECT_MCP] Config already exists at ${configPath}\n`);
    process.stderr.write('[PROTECT_MCP] Delete it first if you want to regenerate.\n');
    process.exit(1);
  }

  // Generate Ed25519 keypair using noble-curves
  let keypair: { privateKey: string; publicKey: string; kid: string };
  {
    const { randomBytes } = await import('node:crypto');
    const { ed25519 } = await import('@noble/curves/ed25519');
    const { bytesToHex } = await import('@noble/hashes/utils');

    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);

    keypair = {
      privateKey: bytesToHex(privateKey),
      publicKey: bytesToHex(publicKey),
      kid: 'generated',
    };
  }

  // Create keys directory
  if (!existsSync(keysDir)) {
    mkdirSync(keysDir, { recursive: true });
  }

  // Write keypair
  writeFileSync(keyPath, JSON.stringify({
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    kid: keypair.kid,
    generated_at: new Date().toISOString(),
    warning: 'KEEP THIS FILE SECRET. Never commit to version control.',
  }, null, 2) + '\n');

  // Write .gitignore for keys directory
  const gitignorePath = join(keysDir, '.gitignore');
  if (!existsSync(gitignorePath)) {
    writeFileSync(gitignorePath, '# Never commit signing keys\n*.json\n');
  }

  // Write config template
  const config = {
    tools: {
      '*': {
        rate_limit: '100/hour',
      },
      'delete_file': {
        block: true,
        min_tier: 'privileged',
      },
      'write_file': {
        min_tier: 'signed-known',
        rate_limit: '10/minute',
      },
      'read_file': {
        rate_limit: '50/minute',
      },
    },
    default_tier: 'unknown',
    signing: {
      key_path: './keys/gateway.json',
      issuer: 'protect-mcp',
      enabled: true,
    },
    credentials: {
      _example_api: {
        inject: 'env',
        name: 'EXAMPLE_API_KEY',
        value_env: 'EXAMPLE_API_KEY',
        _comment: 'Remove the underscore prefix and set EXAMPLE_API_KEY in your environment',
      },
    },
  };

  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  // Generate Claude Desktop config snippet
  const claudeConfig = {
    'mcpServers': {
      'my-server': {
        'command': 'npx',
        'args': ['protect-mcp', '--policy', configPath, '--', 'node', 'my-server.js'],
      },
    },
  };

  process.stderr.write(`
${bold('protect-mcp initialized!')}

Created:
  ${configPath}     Config with shadow mode + local signing
  ${keyPath}       Ed25519 signing keypair

${bold('Next steps:')}
  1. Edit protect-mcp.json to match your MCP server's tools
  2. Set any credential environment variables
  3. Run: protect-mcp --policy protect-mcp.json -- <your-mcp-server>

${bold('Your gateway public key:')}
  ${keypair.publicKey}

${bold('Key ID (kid):')}
  ${keypair.kid}

${bold('Claude Desktop config snippet')} (add to claude_desktop_config.json):
${dim(JSON.stringify(claudeConfig, null, 2))}

${bold('Quick demo:')}
  protect-mcp demo

Shadow mode is the default — all tool calls are logged and nothing is blocked.
Add --enforce when ready to block policy violations.
`);
}

/**
 * Handle the `demo` command: run built-in demo server wrapped with protect-mcp.
 */
async function handleDemo(): Promise<void> {
  const { existsSync } = await import('node:fs');
  const { join, dirname, resolve } = await import('node:path');

  // Find the demo server script — follow symlinks for global npm installs
  const { realpathSync } = await import('node:fs');
  const cliPath = resolve(process.argv[1] || 'dist/cli.js');
  let cliDir: string;
  try {
    cliDir = dirname(realpathSync(cliPath));
  } catch {
    cliDir = dirname(cliPath);
  }
  const demoServerPath = join(cliDir, 'demo-server.js');

  // Check if init has been run (keys + policy exist)
  const configPath = join(process.cwd(), 'protect-mcp.json');
  const hasConfig = existsSync(configPath);

  if (!hasConfig) {
    process.stderr.write(`
${bold('protect-mcp demo')}

Starting demo with default shadow mode (no signing).
For signed receipts, run ${dim('npx protect-mcp init')} first.

`);
  } else {
    process.stderr.write(`
${bold('protect-mcp demo')}

Using config from ${configPath}
Starting demo server with 5 tools...

`);
  }

  // Build config — load policy if available
  let policy = null;
  let policyDigest = 'none';
  let credentials: Record<string, any> | undefined;
  let signing: any | undefined;

  if (hasConfig) {
    try {
      const loaded = loadPolicy(configPath);
      policy = loaded.policy;
      policyDigest = loaded.digest;
      credentials = loaded.credentials;
      signing = loaded.signing;
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Warning: Could not load config: ${err instanceof Error ? err.message : err}\n`);
    }
  }

  // Initialize signing if available
  if (signing) {
    const warnings = await initSigning(signing);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}\n`);
    }
  }

  // Validate credentials
  if (credentials) {
    const warnings = validateCredentials(credentials);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}\n`);
    }
  }

  const config: ProtectConfig = {
    command: process.execPath, // node
    args: [demoServerPath],
    policy,
    policyDigest,
    enforce: false, // Demo always runs in shadow mode
    verbose: true,
    signing,
    credentials,
  };

  const gateway = new ProtectGateway(config);

  process.stderr.write(`${bold('Demo ready!')} The demo server is running.\n`);
  process.stderr.write(`Send JSON-RPC tool calls on stdin, or use an MCP client.\n\n`);
  process.stderr.write(`${dim('Example (paste into stdin):')}\n`);
  process.stderr.write(`${dim('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}')}\n\n`);

  await gateway.start();
}

/**
 * Handle the `status` command: show tool call statistics from the log file.
 */
async function handleStatus(argv: string[]): Promise<void> {
  const { readFileSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');

  let dir = process.cwd();
  const dirIdx = argv.indexOf('--dir');
  if (dirIdx !== -1 && argv[dirIdx + 1]) {
    dir = argv[dirIdx + 1];
  }

  const logPath = join(dir, '.protect-mcp-log.jsonl');

  if (!existsSync(logPath)) {
    process.stderr.write(`${bold('protect-mcp status')}\n\n`);
    process.stderr.write(`No log file found at ${logPath}\n`);
    process.stderr.write(`Run protect-mcp with a wrapped server first to generate logs.\n`);
    process.exit(0);
  }

  const raw = readFileSync(logPath, 'utf-8');
  const lines = raw.trim().split('\n').filter(Boolean);

  if (lines.length === 0) {
    process.stderr.write(`${bold('protect-mcp status')}\n\nNo entries in log file.\n`);
    process.exit(0);
  }

  // Parse all log entries
  interface LogEntry {
    tool: string;
    decision: string;
    reason_code: string;
    tier?: string;
    timestamp: number;
    credential_ref?: string;
    mode?: string;
  }

  const entries: LogEntry[] = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
      // Skip malformed lines
    }
  }

  if (entries.length === 0) {
    process.stderr.write(`${bold('protect-mcp status')}\n\nNo valid entries in log file.\n`);
    process.exit(0);
  }

  // Calculate statistics
  const toolCounts = new Map<string, number>();
  let allowCount = 0;
  let denyCount = 0;
  let rateLimitCount = 0;
  const tierCounts = new Map<string, number>();
  const reasonCounts = new Map<string, number>();

  for (const entry of entries) {
    toolCounts.set(entry.tool, (toolCounts.get(entry.tool) || 0) + 1);

    if (entry.decision === 'allow') allowCount++;
    else if (entry.decision === 'deny') denyCount++;

    if (entry.reason_code === 'rate_limit_exceeded') rateLimitCount++;
    if (entry.tier) tierCounts.set(entry.tier, (tierCounts.get(entry.tier) || 0) + 1);
    reasonCounts.set(entry.reason_code, (reasonCounts.get(entry.reason_code) || 0) + 1);
  }

  const firstTs = new Date(Math.min(...entries.map(e => e.timestamp)));
  const lastTs = new Date(Math.max(...entries.map(e => e.timestamp)));

  // Sort tools by count descending
  const sortedTools = [...toolCounts.entries()].sort((a, b) => b[1] - a[1]);

  // Output
  process.stdout.write(`\n${bold('protect-mcp status')}\n\n`);
  process.stdout.write(`  Total decisions: ${bold(String(entries.length))}\n`);
  process.stdout.write(`  ${green('✓ Allow')}: ${allowCount}    ${red('✗ Deny')}: ${denyCount}    ${yellow('⊘ Rate-limited')}: ${rateLimitCount}\n\n`);

  process.stdout.write(`  ${bold('Time range:')}\n`);
  process.stdout.write(`    First: ${firstTs.toISOString()}\n`);
  process.stdout.write(`    Last:  ${lastTs.toISOString()}\n\n`);

  process.stdout.write(`  ${bold('Top tools:')}\n`);
  for (const [tool, count] of sortedTools.slice(0, 10)) {
    const bar = '█'.repeat(Math.min(Math.ceil(count / entries.length * 30), 30));
    process.stdout.write(`    ${tool.padEnd(20)} ${String(count).padStart(4)}  ${dim(bar)}\n`);
  }

  if (tierCounts.size > 0) {
    process.stdout.write(`\n  ${bold('Trust tiers seen:')}\n`);
    for (const [tier, count] of tierCounts) {
      process.stdout.write(`    ${tier.padEnd(15)} ${count}\n`);
    }
  }

  process.stdout.write(`\n  ${bold('Decision reasons:')}\n`);
  for (const [reason, count] of [...reasonCounts.entries()].sort((a, b) => b[1] - a[1])) {
    process.stdout.write(`    ${reason.padEnd(25)} ${count}\n`);
  }

  // Check for evidence store
  const evidencePath = join(dir, '.protect-mcp-evidence.json');
  if (existsSync(evidencePath)) {
    try {
      const evidenceRaw = readFileSync(evidencePath, 'utf-8');
      const evidence = JSON.parse(evidenceRaw);
      const agentCount = Object.keys(evidence.agents || {}).length;
      process.stdout.write(`\n  ${bold('Evidence store:')} ${agentCount} agent(s) tracked\n`);
    } catch {
      // Skip
    }
  }

  // Show passport identity if keys exist
  const keyPath = join(dir, 'keys', 'gateway.json');
  if (existsSync(keyPath)) {
    try {
      const keyData = JSON.parse(readFileSync(keyPath, 'utf-8'));
      if (keyData.publicKey) {
        const fingerprint = keyData.publicKey.slice(0, 16) + '...';
        process.stdout.write(`\n  ${bold('🛡️ Passport identity:')}\n`);
        process.stdout.write(`    Public key:  ${fingerprint}\n`);
        if (keyData.kid) process.stdout.write(`    Key ID:      ${keyData.kid}\n`);
        process.stdout.write(`    Issuer:      ${keyData.issuer || 'protect-mcp'}\n`);
        process.stdout.write(`    Verify:      ${dim('npx @veritasacta/verify <receipt.json>')}\n`);
      }
    } catch {
      // Skip
    }
  }

  process.stdout.write(`\n  Log file: ${dim(logPath)}\n\n`);
}

type DashboardEntry = {
  tool?: string;
  decision?: string;
  reason_code?: string;
  timestamp?: number;
  mode?: string;
  tier?: string;
  policy_digest?: string;
  request_id?: string;
  issuer_certification?: string;
  action_readback?: {
    tool?: string;
    action?: string;
    destination?: string;
    payload_preview?: unknown;
    payload_hash?: string;
    payload_bytes?: number;
    disclosed_fields?: string[];
    redacted_fields?: string[];
    summary?: string;
  };
};

type ToolRisk = 'high' | 'medium' | 'low';

type SuggestedGuardrail = {
  action: string;
  reason: string;
  policy: ToolPolicy;
};

type PolicyCoverage = {
  status: 'exact' | 'wildcard' | 'none';
  label: string;
  policy?: ToolPolicy;
};

type JsonlRecord = {
  value: Record<string, unknown>;
  raw: string;
  hash: string;
};

type ClaudeDesktopServer = {
  command?: string;
  args?: string[];
  [key: string]: unknown;
};

type ClaudeDesktopConfig = {
  mcpServers?: Record<string, ClaudeDesktopServer>;
  [key: string]: unknown;
};

function commandNeedsValue(argv: string[], flag: string): boolean {
  const value = flagValue(argv, flag);
  return Boolean(value && !value.startsWith('--'));
}

function absoluteOrCwd(pathValue: string): string {
  return resolveCli(process.cwd(), pathValue);
}

function shellQuoteArg(arg: string): string {
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

function shellCommand(command: string, args: string[]): string {
  return [command, ...args].map(shellQuoteArg).join(' ');
}

function wrapperArgsFor(command: string[], opts: { configPath?: string; cedarDir?: string; enforce?: boolean }): string[] {
  const args = ['-y', 'protect-mcp@latest'];
  if (opts.cedarDir) args.push('--cedar', opts.cedarDir);
  else args.push('--policy', opts.configPath || absoluteOrCwd('protect-mcp.json'));
  if (opts.enforce) args.push('--enforce');
  args.push('--', ...command);
  return args;
}

function claudeDesktopConfigPath(): string {
  if (process.platform === 'darwin') {
    return joinCli(homedirCli(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  }
  if (process.platform === 'win32') {
    return joinCli(process.env.APPDATA || joinCli(homedirCli(), 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json');
  }
  return joinCli(homedirCli(), '.config', 'Claude', 'claude_desktop_config.json');
}

async function ensureLocalConfig(dir = process.cwd()): Promise<string> {
  const { existsSync } = await import('node:fs');
  const { join, resolve } = await import('node:path');
  const configPath = join(dir, 'protect-mcp.json');
  if (!existsSync(configPath)) {
    process.stderr.write(`${bold('protect-mcp wrap')}\n\nNo protect-mcp.json found; creating local shadow-mode config first.\n\n`);
    await handleInit(['--dir', dir]);
  }
  return resolve(configPath);
}

function parseJsonlFile(pathValue: string): DashboardEntry[] {
  try {
    const raw = readFileSyncCli(pathValue, 'utf-8');
    return raw
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .flatMap((line) => {
        try { return [JSON.parse(line) as DashboardEntry]; } catch { return []; }
      });
  } catch {
    return [];
  }
}

function parseJsonlRecords(pathValue: string): JsonlRecord[] {
  try {
    const raw = readFileSyncCli(pathValue, 'utf-8');
    return raw
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .flatMap((line) => {
        try {
          return [{
            value: JSON.parse(line) as Record<string, unknown>,
            raw: line,
            hash: createHashCli('sha256').update(line).digest('hex'),
          }];
        } catch {
          return [];
        }
      });
  } catch {
    return [];
  }
}

function loadPolicyJson(policyPath: string): Record<string, unknown> | null {
  try {
    if (!existsSyncCli(policyPath)) return null;
    return JSON.parse(readFileSyncCli(policyPath, 'utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function policyCoverageForTool(tool: string, policy: Record<string, unknown> | null): PolicyCoverage {
  const tools = policy?.tools && typeof policy.tools === 'object'
    ? policy.tools as Record<string, ToolPolicy>
    : {};
  if (tools[tool]) {
    return { status: 'exact', label: 'Exact rule', policy: tools[tool] };
  }
  if (tools['*']) {
    return { status: 'wildcard', label: 'Wildcard fallback', policy: tools['*'] };
  }
  return { status: 'none', label: 'No rule' };
}

function receiptRequestId(receipt: Record<string, unknown>): string | undefined {
  const direct = receipt.request_id || receipt.scope;
  if (typeof direct === 'string') return direct;
  const payload = receipt.payload;
  if (payload && typeof payload === 'object') {
    const candidate = (payload as Record<string, unknown>).request_id || (payload as Record<string, unknown>).scope;
    if (typeof candidate === 'string') return candidate;
  }
  const claims = receipt.signed_claims;
  if (claims && typeof claims === 'object') {
    const nestedClaims = (claims as Record<string, unknown>).claims;
    if (nestedClaims && typeof nestedClaims === 'object') {
      const candidate = (nestedClaims as Record<string, unknown>).request_id || (nestedClaims as Record<string, unknown>).scope;
      if (typeof candidate === 'string') return candidate;
    }
  }
  return undefined;
}

function buildReceiptChains(entries: DashboardEntry[], receipts: JsonlRecord[]): Array<Record<string, unknown>> {
  const receiptMap = new Map<string, JsonlRecord[]>();
  for (const receipt of receipts) {
    const requestId = receiptRequestId(receipt.value);
    if (!requestId) continue;
    const rows = receiptMap.get(requestId) || [];
    rows.push(receipt);
    receiptMap.set(requestId, rows);
  }
  const logMap = new Map<string, DashboardEntry[]>();
  for (const entry of entries) {
    if (!entry.request_id) continue;
    const rows = logMap.get(entry.request_id) || [];
    rows.push(entry);
    logMap.set(entry.request_id, rows);
  }
  return [...logMap.entries()]
    .map(([requestId, logs]) => {
      const relatedReceipts = receiptMap.get(requestId) || [];
      const latest = logs[logs.length - 1];
      return {
        request_id: requestId,
        tool: latest?.tool || 'unknown',
        decision: latest?.decision || 'unknown',
        reason_code: latest?.reason_code || '',
        action_readback: latest?.action_readback,
        log_events: logs.map((log) => ({
          decision: log.decision,
          reason_code: log.reason_code,
          timestamp: log.timestamp,
          hook_event: (log as Record<string, unknown>).hook_event,
        })),
        receipts: relatedReceipts.map((receipt) => ({
          hash: receipt.hash,
          type: String(receipt.value.type || receipt.value.artifact_type || 'receipt'),
        })),
        complete: relatedReceipts.length > 0,
      };
    })
    .sort((a, b) => {
      const at = ((a.log_events as Array<{ timestamp?: number }>)[0]?.timestamp || 0);
      const bt = ((b.log_events as Array<{ timestamp?: number }>)[0]?.timestamp || 0);
      return bt - at;
    })
    .slice(0, 80);
}

function riskForTool(toolRaw: string): { tier: ToolRisk; reasons: string[] } {
  const tool = toolRaw.toLowerCase();
  const reasons: string[] = [];
  const highPatterns = [
    ['delete', 'delete/destructive'],
    ['remove', 'delete/destructive'],
    ['rm', 'delete/destructive'],
    ['write', 'writes data'],
    ['send', 'external send'],
    ['email', 'external comms'],
    ['slack', 'external comms'],
    ['teams', 'external comms'],
    ['github', 'source-control mutation'],
    ['commit', 'source-control mutation'],
    ['push', 'source-control mutation'],
    ['deploy', 'deployment'],
    ['terraform', 'cloud infrastructure'],
    ['aws', 'cloud infrastructure'],
    ['gcp', 'cloud infrastructure'],
    ['azure', 'cloud infrastructure'],
    ['sql', 'database access'],
    ['database', 'database access'],
    ['payment', 'spend/payment'],
    ['order', 'order/transaction'],
    ['trade', 'trade/transaction'],
    ['pms', 'portfolio-system mutation'],
    ['book', 'portfolio-system mutation'],
    ['fill', 'portfolio-system mutation'],
    ['secret', 'secrets'],
    ['token', 'secrets'],
  ] as const;
  for (const [needle, label] of highPatterns) {
    if (tool.includes(needle) && !reasons.includes(label)) reasons.push(label);
  }
  if (reasons.length > 0) return { tier: 'high', reasons };
  if (tool.includes('read') || tool.includes('search') || tool.includes('list') || tool.includes('fetch')) {
    return { tier: 'medium', reasons: ['data access'] };
  }
  return { tier: 'low', reasons: ['observed'] };
}

function suggestedGuardrailFor(_tool: string, risk: ToolRisk, reasons: string[]): SuggestedGuardrail {
  const reasonSet = new Set(reasons);
  if (reasonSet.has('delete/destructive') || reasonSet.has('secrets')) {
    return {
      action: 'Block by default',
      reason: 'Destructive and secret-handling tools should start deny-first.',
      policy: { block: true, min_tier: 'privileged' },
    };
  }
  if (
    reasonSet.has('order/transaction') ||
    reasonSet.has('trade/transaction') ||
    reasonSet.has('spend/payment') ||
    reasonSet.has('portfolio-system mutation') ||
    reasonSet.has('deployment') ||
    reasonSet.has('cloud infrastructure') ||
    reasonSet.has('database access') ||
    reasonSet.has('external send') ||
    reasonSet.has('source-control mutation')
  ) {
    return {
      action: 'Require approval',
      reason: 'Consequential tools should require a human approval receipt before enforce mode.',
      policy: { require_approval: true, min_tier: 'signed-known', rate_limit: '10/hour' },
    };
  }
  if (risk === 'medium') {
    return {
      action: 'Rate-limit and identify',
      reason: 'Read/search/fetch tools can leak data at scale; keep them visible and bounded.',
      policy: { min_tier: 'signed-known', rate_limit: '60/hour' },
    };
  }
  return {
    action: 'Observe',
    reason: 'Low-risk observed tool. Keep receipts and a broad rate limit.',
    policy: { rate_limit: '100/hour' },
  };
}

function buildDashboardSummary(dir: string, policyPath = joinCli(dir, 'protect-mcp.json')): Record<string, unknown> {
  const logPath = joinCli(dir, '.protect-mcp-log.jsonl');
  const receiptPath = joinCli(dir, '.protect-mcp-receipts.jsonl');
  const keyPath = joinCli(dir, 'keys', 'gateway.json');
  const entries = parseJsonlFile(logPath);
  const receiptRecords = parseJsonlRecords(receiptPath);
  const receipts = receiptRecords.map((record) => record.value);
  const activePolicy = loadPolicyJson(policyPath);

  const tools = new Map<string, {
    tool: string;
    calls: number;
    allows: number;
    denies: number;
    reviews: number;
    risk: ToolRisk;
    reasons: string[];
    suggestion?: SuggestedGuardrail;
    policy_coverage?: PolicyCoverage;
    last_seen?: string;
  }>();

  for (const entry of entries) {
    const tool = String(entry.tool || 'unknown');
    const risk = riskForTool(tool);
    const current = tools.get(tool) || {
      tool,
      calls: 0,
      allows: 0,
      denies: 0,
      reviews: 0,
      risk: risk.tier,
      reasons: risk.reasons,
    };
    current.calls += 1;
    if (entry.decision === 'allow') current.allows += 1;
    else if (entry.decision === 'deny') current.denies += 1;
    else if (entry.decision === 'require_approval') current.reviews += 1;
    if (risk.tier === 'high' || (risk.tier === 'medium' && current.risk === 'low')) current.risk = risk.tier;
    current.reasons = [...new Set([...current.reasons, ...risk.reasons])];
    if (typeof entry.timestamp === 'number') current.last_seen = new Date(entry.timestamp).toISOString();
    tools.set(tool, current);
  }

  const toolRows = [...tools.values()].sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 };
    return order[a.risk] - order[b.risk] || b.calls - a.calls || a.tool.localeCompare(b.tool);
  }).map((tool) => ({
    ...tool,
    suggestion: suggestedGuardrailFor(tool.tool, tool.risk, tool.reasons),
    policy_coverage: policyCoverageForTool(tool.tool, activePolicy),
  }));

  const highRisk = toolRows.filter((t) => t.risk === 'high');
  const uncovered = toolRows.filter((t) => t.policy_coverage.status === 'none').length;
  const exactCovered = toolRows.filter((t) => t.policy_coverage.status === 'exact').length;
  const wildcardCovered = toolRows.filter((t) => t.policy_coverage.status === 'wildcard').length;
  const allowed = entries.filter((e) => e.decision === 'allow').length;
  const denied = entries.filter((e) => e.decision === 'deny').length;
  const review = entries.filter((e) => e.decision === 'require_approval').length;
  const pendingApprovals = entries
    .filter((e) => e.decision === 'require_approval')
    .slice(-25)
    .reverse();
  const chains = buildReceiptChains(entries, receiptRecords);
  let key: Record<string, unknown> | null = null;
  if (existsSyncCli(keyPath)) {
    try {
      const parsed = JSON.parse(readFileSyncCli(keyPath, 'utf-8')) as Record<string, unknown>;
      key = {
        kid: parsed.kid || null,
        issuer: parsed.issuer || 'protect-mcp',
        publicKeyPrefix: typeof parsed.publicKey === 'string' ? `${parsed.publicKey.slice(0, 16)}...` : null,
      };
    } catch { /* ignore */ }
  }

  return {
    generated_at: new Date().toISOString(),
    dir,
    files: {
      log: logPath,
      receipts: receiptPath,
      key: keyPath,
      policy: policyPath,
      log_exists: existsSyncCli(logPath),
      receipts_exist: existsSyncCli(receiptPath),
      key_exists: existsSyncCli(keyPath),
      policy_exists: existsSyncCli(policyPath),
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
      review,
    },
    key,
    policy: activePolicy ? {
      path: policyPath,
      digest: createHashCli('sha256').update(JSON.stringify(activePolicy)).digest('hex').slice(0, 16),
      default_tier: activePolicy.default_tier || 'unknown',
      tools: activePolicy.tools || {},
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
        files: pack.files.map((file) => ({ path: file.path, contents: file.contents })),
      })),
    },
    connector_pilots: {
      directory: joinCli(dir, '.protect-mcp', 'connectors'),
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
        setup: pilot.setup,
      })),
    },
    registry: dashboardRegistryStatus(dir),
    recommendations: [
      entries.length === 0 ? 'Run in shadow mode first: npx protect-mcp -- node your-mcp-server.js' : '',
      highRisk.length > 0 ? 'Run npx protect-mcp recommend --write, review the generated policy, then restart your wrapper with --enforce.' : '',
      receipts.length === 0 ? 'Run npx protect-mcp init so decisions are signed into local receipts.' : '',
      'Install a starter policy pack from this dashboard when you know the tool class: filesystem, Git, email, database, cloud spend, secrets, or finance.',
      'Create a registry preview locally, then use hosted digest anchoring when you need independent timestamp evidence.',
      'Export an audit bundle with: npx protect-mcp bundle --output audit.json',
    ].filter(Boolean),
  };
}

function dashboardHtml(): string {
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
        '<td>'+t.calls+' calls<br><span class="allow">'+t.allows+' allow</span> · <span class="deny">'+t.denies+' deny</span> · <span class="require_approval">'+t.reviews+' review</span></td>'+
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
    return '<div class="chain-item"><strong class="'+escapeHtml(r.decision || '')+'">'+escapeHtml(r.decision || 'unknown')+'</strong> · '+escapeHtml(r.tool || 'unknown')+'<br><span class="muted">'+escapeHtml(rb.summary || r.reason_code || '')+'</span><br><span class="muted mono">'+escapeHtml(r.request_id || '')+'</span></div>';
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
    '<p class="muted">Digests: '+(reg.records || 0)+' · Anchors: '+(reg.anchors || 0)+'</p>'+
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

async function handleDashboard(argv: string[]): Promise<void> {
  const { createServer } = await import('node:http');
  const { execFile } = await import('node:child_process');
  const { resolve } = await import('node:path');
  const port = commandNeedsValue(argv, '--port') ? parseInt(flagValue(argv, '--port') || '9877', 10) : 9877;
  const dir = resolve(commandNeedsValue(argv, '--dir') ? flagValue(argv, '--dir') || process.cwd() : process.cwd());
  const policyPath = resolve(flagValue(argv, '--policy') || joinCli(dir, 'protect-mcp.json'));
  const approvalEndpoint = flagValue(argv, '--approval-endpoint');
  const approvalNonce = flagValue(argv, '--approval-nonce');
  const open = argv.includes('--open');

  const server = createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url || '/', 'http://127.0.0.1');
        if (url.pathname === '/api/summary') {
          const body = JSON.stringify(buildDashboardSummary(dir, policyPath), null, 2);
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
          res.end(body);
          return;
        }
        if (url.pathname === '/api/tool-policy' && req.method === 'POST') {
          const body = await readJsonBody(req);
          const tool = typeof body.tool === 'string' ? body.tool : '';
          const action = body.action === 'block' || body.action === 'observe' ? body.action : 'require_approval';
          if (!tool) {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'missing_tool' }));
            return;
          }
          const policy = writeToolPolicy(policyPath, tool, action);
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true, policy_path: policyPath, policy }));
          return;
        }
        if (url.pathname === '/api/policy-packs/install' && req.method === 'POST') {
          const body = await readJsonBody(req);
          const pack = typeof body.pack === 'string' ? body.pack : '';
          if (!pack) {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'missing_policy_pack' }));
            return;
          }
          const installed = installPolicyPackToDir(dir, pack, Boolean(body.force));
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            ok: true,
            ...installed,
            installed: installedPolicyPackIds(dir),
          }));
          return;
        }
        if (url.pathname === '/api/connectors/install' && req.method === 'POST') {
          const body = await readJsonBody(req);
          const pilot = typeof body.pilot === 'string' ? body.pilot : '';
          if (!pilot) {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'missing_connector_pilot' }));
            return;
          }
          const installed = writeConnectorPilots({ dir, ids: [pilot], force: Boolean(body.force) });
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            ok: true,
            dir: installed.directory,
            written: installed.written,
            installed: readInstalledConnectorPilots(dir),
            doctor: connectorDoctor(dir),
          }));
          return;
        }
        if (url.pathname === '/api/registry/anchor' && req.method === 'POST') {
          const body = await readJsonBody(req);
          const { createReceiptRegistry } = await import('./receipt-registry.js');
          try {
            const hosted = Boolean(body.hosted);
            const result = await createReceiptRegistry({
              dir,
              orgName: typeof body.org_name === 'string' && body.org_name.trim() ? body.org_name.trim() : undefined,
              orgId: typeof body.org_id === 'string' && body.org_id.trim() ? body.org_id.trim() : undefined,
              billingAccountId: typeof body.billing_account_id === 'string' && body.billing_account_id.trim() ? body.billing_account_id.trim() : undefined,
              hosted,
              token: typeof body.token === 'string' && body.token.trim() ? body.token.trim() : process.env.SCOPEBLIND_TOKEN,
              endpoint: typeof body.endpoint === 'string' && body.endpoint.trim()
                ? body.endpoint.trim()
                : hosted ? (process.env.SCOPEBLIND_REGISTRY_ENDPOINT || 'https://api.scopeblind.com') : undefined,
              verifierBaseUrl: typeof body.verifier_base === 'string' && body.verifier_base.trim()
                ? body.verifier_base.trim()
                : (process.env.SCOPEBLIND_VERIFIER_BASE || 'https://legate.scopeblind.com'),
            });
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({
              ok: true,
              uploaded: result.uploaded,
              records: result.registry.records.length,
              anchors: result.registry.anchors.length,
              registry_path: result.registryPath,
              verifier_path: result.verifierPath,
              registry: dashboardRegistryStatus(dir),
            }));
          } catch (err) {
            res.writeHead(409, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
            res.end(JSON.stringify({
              error: 'registry_anchor_unavailable',
              message: err instanceof Error ? err.message : String(err),
              next_step: 'Run protect-mcp with signing enabled so decisions are written as signed receipts, then try again.',
            }));
          }
          return;
        }
        if (url.pathname === '/api/approval/resolve' && req.method === 'POST') {
          const body = await readJsonBody(req);
          const result = await recordApprovalResolution({ dir, approvalEndpoint, approvalNonce, body });
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify(result));
          return;
        }
        if (url.pathname === '/api/audit-bundle') {
          let bundle: unknown;
          try {
            bundle = await buildAuditBundleForDir(dir);
          } catch (err) {
            res.writeHead(409, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
            res.end(JSON.stringify({
              error: 'audit_bundle_unavailable',
              message: err instanceof Error ? err.message : String(err),
              next_step: 'Run protect-mcp with signing enabled so decisions are written as signed receipts, then export again.',
            }));
            return;
          }
          res.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'content-disposition': 'attachment; filename="protect-mcp-audit-bundle.json"',
            'cache-control': 'no-store',
          });
          res.end(JSON.stringify(bundle, null, 2) + '\n');
          return;
        }
        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'content-security-policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        });
        res.end(dashboardHtml());
      } catch (err) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
    })();
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(port, '127.0.0.1', () => resolveListen());
  });
  const url = `http://127.0.0.1:${port}`;
  process.stderr.write(`\n${bold('protect-mcp dashboard')}\n\n`);
  process.stderr.write(`  Local URL: ${url}\n`);
  process.stderr.write(`  Reading:   ${dir}\n`);
  process.stderr.write(`  Policy:    ${policyPath}\n`);
  process.stderr.write(`  Network:   127.0.0.1 only; no uploads\n\n`);
  if (open) {
    const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
    const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
    execFile(opener, args, () => {});
  }
}

function draftPolicyFromSummary(summary: Record<string, unknown>): Record<string, unknown> {
  const files = (summary.files || {}) as Record<string, unknown>;
  const rows = Array.isArray(summary.tools) ? summary.tools as Array<{
    tool?: string;
    risk?: ToolRisk;
    reasons?: string[];
    suggestion?: SuggestedGuardrail;
  }> : [];
  const tools: Record<string, ToolPolicy> = {
    '*': { rate_limit: '100/hour' },
  };
  for (const row of rows) {
    if (!row.tool || row.tool === 'unknown') continue;
    const suggestion = row.suggestion || suggestedGuardrailFor(row.tool, row.risk || 'low', row.reasons || []);
    tools[row.tool] = suggestion.policy;
  }
  return {
    tools,
    default_tier: 'unknown',
    signing: files.key_exists ? {
      key_path: './keys/gateway.json',
      issuer: 'protect-mcp',
    } : undefined,
    notes: [
      'Generated from local shadow-mode inventory.',
      'Review before running with --enforce.',
      'High-risk transaction, deployment, external-send, and database tools require approval.',
      'Destructive and secret-handling tools are blocked by default.',
    ],
  };
}

function writeToolPolicy(policyPath: string, tool: string, action: 'require_approval' | 'block' | 'observe'): Record<string, unknown> {
  const existing = loadPolicyJson(policyPath) || { tools: {}, default_tier: 'unknown' };
  const tools = existing.tools && typeof existing.tools === 'object'
    ? { ...(existing.tools as Record<string, ToolPolicy>) }
    : {};
  if (action === 'require_approval') {
    tools[tool] = { require_approval: true, min_tier: 'signed-known', rate_limit: '10/hour' };
  } else if (action === 'block') {
    tools[tool] = { block: true, min_tier: 'privileged' };
  } else {
    tools[tool] = { rate_limit: '100/hour' };
  }
  const next = {
    ...existing,
    tools,
    default_tier: existing.default_tier || 'unknown',
  };
  writeFileSyncCli(policyPath, JSON.stringify(next, null, 2) + '\n');
  return next;
}

function policyPackDirectory(dir: string): string {
  return joinCli(dir, 'cedar');
}

function installedPolicyPackIds(dir: string): string[] {
  const cedarDir = policyPackDirectory(dir);
  return POLICY_PACKS.filter((pack) =>
    pack.files.every((file) => existsSyncCli(joinCli(cedarDir, file.path)))
  ).map((pack) => pack.id);
}

function installPolicyPackToDir(dir: string, packId: string, force = false): { dir: string; written: string[]; packs: string[] } {
  const packs = packId === 'all'
    ? POLICY_PACKS
    : [getPolicyPack(packId)].filter(Boolean) as typeof POLICY_PACKS;
  if (packs.length === 0) throw new Error(`Unknown policy pack: ${packId}`);
  const outDir = policyPackDirectory(dir);
  mkdirSyncCli(outDir, { recursive: true });
  const written: string[] = [];
  for (const pack of packs) {
    for (const file of pack.files) {
      const outPath = joinCli(outDir, file.path);
      if (existsSyncCli(outPath) && !force) {
        throw new Error(`Refusing to overwrite ${outPath}. Pass force=true if intentional.`);
      }
      mkdirSyncCli(dirnameCli(outPath), { recursive: true });
      writeFileSyncCli(outPath, file.contents.endsWith('\n') ? file.contents : `${file.contents}\n`);
      written.push(outPath);
    }
  }
  return { dir: outDir, written, packs: packs.map((pack) => pack.id) };
}

function dashboardRegistryStatus(dir: string): Record<string, unknown> {
  const identityPath = joinCli(dir, '.protect-mcp-org.json');
  const registryPath = joinCli(dir, '.protect-mcp-registry.json');
  const verifierPath = joinCli(dir, 'scopeblind-verifier.html');
  const identity = existsSyncCli(identityPath)
    ? (() => { try { return JSON.parse(readFileSyncCli(identityPath, 'utf-8')) as Record<string, unknown>; } catch { return null; } })()
    : null;
  const registry = existsSyncCli(registryPath)
    ? (() => { try { return JSON.parse(readFileSyncCli(registryPath, 'utf-8')) as Record<string, unknown>; } catch { return null; } })()
    : null;
  const anchors = Array.isArray(registry?.anchors) ? registry.anchors as Array<Record<string, unknown>> : [];
  const hosted = anchors.some((anchor) => anchor.timestamp_source === 'scopeblind-hosted');
  return {
    identity_exists: existsSyncCli(identityPath),
    registry_exists: existsSyncCli(registryPath),
    verifier_exists: existsSyncCli(verifierPath),
    identity_path: identityPath,
    registry_path: registryPath,
    verifier_path: verifierPath,
    org_name: identity?.org_name || (registry?.org && typeof registry.org === 'object' ? (registry.org as Record<string, unknown>).org_name : null),
    org_id: identity?.org_id || (registry?.org && typeof registry.org === 'object' ? (registry.org as Record<string, unknown>).org_id : null),
    billing_account_id: identity?.billing_account_id || (registry?.billing && typeof registry.billing === 'object' ? (registry.billing as Record<string, unknown>).billing_account_id : null),
    records: Array.isArray(registry?.records) ? registry.records.length : 0,
    anchors: anchors.length,
    hosted,
    boundary: hosted ? 'hosted digest anchor' : registry ? 'local preview only' : 'not configured',
  };
}

async function readJsonBody(req: import('node:http').IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  const raw = Buffer.concat(chunks).toString('utf-8').trim();
  return raw ? JSON.parse(raw) as Record<string, unknown> : {};
}

async function buildAuditBundleForDir(dir: string): Promise<unknown> {
  const { createAuditBundle } = await import('./bundle.js');
  const receiptPath = joinCli(dir, '.protect-mcp-receipts.jsonl');
  const keyPath = joinCli(dir, 'keys', 'gateway.json');
  if (!existsSyncCli(receiptPath)) throw new Error('No receipt file found.');
  if (!existsSyncCli(keyPath)) throw new Error('No signing key found.');
  const receipts = parseJsonlFile(receiptPath);
  if (receipts.length === 0) throw new Error('No signed receipts found.');
  const keyData = JSON.parse(readFileSyncCli(keyPath, 'utf-8')) as Record<string, string>;
  return createAuditBundle({
    tenant: keyData.issuer || 'protect-mcp',
    receipts,
    selectiveDisclosures: collectSelectiveDisclosurePackages(dir),
    signingKeys: [{
      kty: 'OKP',
      crv: 'Ed25519',
      kid: keyData.kid || 'unknown',
      x: Buffer.from(keyData.publicKey || '', 'hex').toString('base64url'),
      use: 'sig',
    }],
  });
}

function collectSelectiveDisclosurePackages(dir: string): any[] {
  const out: any[] = [];
  const seen = new Set<string>();
  const candidates: string[] = [];
  const receiptsDir = joinCli(dir, 'receipts');
  if (existsSyncCli(receiptsDir)) {
    for (const name of readdirSyncCli(receiptsDir)) {
      if (name.includes('selective-disclosure') && name.endsWith('.json')) {
        candidates.push(joinCli(receiptsDir, name));
      }
    }
  }
  const jsonlPath = joinCli(dir, '.protect-mcp-selective-disclosures.jsonl');
  if (existsSyncCli(jsonlPath)) {
    for (const line of readFileSyncCli(jsonlPath, 'utf-8').split('\n').map((s) => s.trim()).filter(Boolean)) {
      try {
        const parsed = JSON.parse(line);
        addSelectiveDisclosure(out, seen, parsed);
      } catch {
        // Ignore malformed optional disclosure rows.
      }
    }
  }
  for (const path of candidates) {
    try {
      const parsed = JSON.parse(readFileSyncCli(path, 'utf-8'));
      addSelectiveDisclosure(out, seen, parsed);
    } catch {
      // Ignore non-v0 or malformed optional disclosure files.
    }
  }
  return out;
}

function addSelectiveDisclosure(out: any[], seen: Set<string>, parsed: any): void {
  if (parsed?.type !== 'scopeblind.selective_disclosure.v0') return;
  const key = [
    parsed.parent_receipt_hash || '',
    Array.isArray(parsed.disclosed_fields) ? parsed.disclosed_fields.slice().sort().join(',') : '',
    Array.isArray(parsed.hidden_fields) ? parsed.hidden_fields.slice().sort().join(',') : '',
  ].join('|');
  if (seen.has(key)) return;
  seen.add(key);
  out.push(parsed);
}

async function recordApprovalResolution(opts: {
  dir: string;
  approvalEndpoint?: string;
  approvalNonce?: string;
  body: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const resolution = String(opts.body.resolution || 'deny');
  const requestId = String(opts.body.request_id || '');
  const tool = String(opts.body.tool || 'unknown');
  const record = {
    type: 'scopeblind.approval_resolution.v1',
    at: new Date().toISOString(),
    request_id: requestId,
    tool,
    resolution,
    reason: typeof opts.body.reason === 'string' ? opts.body.reason.slice(0, 1000) : '',
    edited_payload: opts.body.edited_payload || undefined,
    takeover_note: opts.body.takeover_note || undefined,
    payload_hash: opts.body.payload_hash || undefined,
  };
  appendFileSyncCli(joinCli(opts.dir, '.protect-mcp-approval-resolutions.jsonl'), JSON.stringify(record) + '\n');

  let forwarded: Record<string, unknown> | null = null;
  if (resolution === 'approve' && opts.approvalEndpoint && opts.approvalNonce) {
    const endpoint = opts.approvalEndpoint.replace(/\/$/, '') + '/approve';
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        request_id: requestId,
        tool,
        mode: 'once',
        nonce: opts.approvalNonce,
      }),
    });
    forwarded = {
      ok: response.ok,
      status: response.status,
      body: await response.text().catch(() => ''),
    };
  }

  return { recorded: true, resolution: record, forwarded };
}

async function handleRecommend(argv: string[]): Promise<void> {
  const { writeFileSync } = await import('node:fs');
  const { resolve } = await import('node:path');
  const dir = resolve(commandNeedsValue(argv, '--dir') ? flagValue(argv, '--dir') || process.cwd() : process.cwd());
  const outputPath = resolve(flagValue(argv, '--output') || 'protect-mcp.recommended.json');
  const write = argv.includes('--write');
  const summary = buildDashboardSummary(dir);
  const totals = summary.totals as Record<string, number>;
  const policy = draftPolicyFromSummary(summary);
  const rows = Array.isArray(summary.tools) ? summary.tools as Array<{
    tool: string;
    risk: ToolRisk;
    reasons: string[];
    suggestion?: SuggestedGuardrail;
  }> : [];

  process.stdout.write(`\n${bold('protect-mcp recommend')}\n\n`);
  process.stdout.write(`  Source:    ${dir}\n`);
  process.stdout.write(`  Decisions: ${totals.decisions || 0}\n`);
  process.stdout.write(`  Tools:     ${totals.tools || 0}\n\n`);

  if (rows.length === 0) {
    process.stdout.write(`No tool calls found yet. First run:\n\n`);
    process.stdout.write(`  ${dim('npx protect-mcp wrap -- node your-mcp-server.js')}\n`);
    process.stdout.write(`  ${dim('npx protect-mcp dashboard --open')}\n\n`);
    return;
  }

  for (const row of rows) {
    const suggestion = row.suggestion || suggestedGuardrailFor(row.tool, row.risk, row.reasons);
    process.stdout.write(`  - ${row.tool}: ${bold(suggestion.action)} (${row.risk})\n`);
    process.stdout.write(`    ${dim(suggestion.reason)}\n`);
  }

  const body = JSON.stringify(policy, null, 2) + '\n';
  if (!write) {
    process.stdout.write(`\nDry run only. Write the policy with:\n`);
    process.stdout.write(`  ${dim('npx protect-mcp recommend --write')}\n\n`);
    process.stdout.write(dim(body));
    return;
  }

  writeFileSync(outputPath, body);
  process.stdout.write(`\n${green('✓ Wrote recommended policy')}\n`);
  process.stdout.write(`  Output: ${outputPath}\n`);
  process.stdout.write(`  Review it, then restart your wrapper with:\n`);
  process.stdout.write(`  ${dim(shellCommand('npx', ['protect-mcp', '--policy', outputPath, '--enforce', '--', 'node', 'your-mcp-server.js']))}\n\n`);
}

async function handleWrap(argv: string[]): Promise<void> {
  const { existsSync, readFileSync, writeFileSync } = await import('node:fs');
  const { resolve } = await import('node:path');
  const configFlag = flagValue(argv, '--config');
  const cedarFlag = flagValue(argv, '--cedar');
  const enforce = argv.includes('--enforce');
  const write = argv.includes('--write');
  const claudeDesktop = argv.includes('--claude-desktop') || argv.includes('--claude');
  const serverName = flagValue(argv, '--server');
  const separator = argv.indexOf('--');
  const childCommand = separator >= 0 ? argv.slice(separator + 1).filter(Boolean) : [];

  const configPath = cedarFlag ? undefined : resolve(configFlag || await ensureLocalConfig(process.cwd()));
  const cedarDir = cedarFlag ? resolve(cedarFlag) : undefined;

  if (childCommand.length > 0) {
    const args = wrapperArgsFor(childCommand, { configPath, cedarDir, enforce });
    process.stdout.write(`\n${bold('protect-mcp wrap')}\n\n`);
    process.stdout.write(`Use this command in your MCP client config:\n\n`);
    process.stdout.write(`  ${shellCommand('npx', args)}\n\n`);
    process.stdout.write(`Claude Desktop JSON snippet:\n\n`);
    process.stdout.write(dim(JSON.stringify({
      command: 'npx',
      args,
    }, null, 2)) + '\n\n');
    process.stdout.write(`Then inspect calls with: ${dim('npx protect-mcp dashboard --open')}\n\n`);
    return;
  }

  const claudePath = resolve(flagValue(argv, '--path') || claudeDesktopConfigPath());
  if (!claudeDesktop && !existsSync(claudePath)) {
    process.stdout.write(`\n${bold('protect-mcp wrap')}\n\n`);
    process.stdout.write(`No command was passed after "--" and no Claude Desktop config was found.\n\n`);
    process.stdout.write(`Examples:\n`);
    process.stdout.write(`  ${dim('npx protect-mcp wrap -- node server.js')}\n`);
    process.stdout.write(`  ${dim('npx protect-mcp wrap --claude-desktop --write')}\n\n`);
    return;
  }

  if (!existsSync(claudePath)) {
    process.stderr.write(`protect-mcp wrap: Claude Desktop config not found at ${claudePath}\n`);
    process.exit(1);
  }

  let parsed: ClaudeDesktopConfig;
  try {
    parsed = JSON.parse(readFileSync(claudePath, 'utf-8')) as ClaudeDesktopConfig;
  } catch (err) {
    process.stderr.write(`protect-mcp wrap: could not parse ${claudePath}: ${err instanceof Error ? err.message : err}\n`);
    process.exit(1);
  }

  const servers = parsed.mcpServers || {};
  const names = Object.keys(servers).filter((name) => !serverName || name === serverName);
  if (names.length === 0) {
    process.stderr.write(`protect-mcp wrap: no MCP servers found${serverName ? ` matching "${serverName}"` : ''}.\n`);
    process.exit(1);
  }

  const next: ClaudeDesktopConfig = { ...parsed, mcpServers: { ...servers } };
  const changes: Array<{ name: string; before: ClaudeDesktopServer; after: ClaudeDesktopServer; skipped?: string }> = [];

  for (const name of names) {
    const before = servers[name] || {};
    const originalCommand = before.command;
    const originalArgs = Array.isArray(before.args) ? before.args : [];
    if (!originalCommand) {
      changes.push({ name, before, after: before, skipped: 'missing command' });
      continue;
    }
    if (originalCommand === 'npx' && originalArgs.some((arg) => String(arg).includes('protect-mcp'))) {
      changes.push({ name, before, after: before, skipped: 'already wrapped' });
      continue;
    }
    const wrappedArgs = wrapperArgsFor([originalCommand, ...originalArgs], { configPath, cedarDir, enforce });
    const after = { ...before, command: 'npx', args: wrappedArgs };
    next.mcpServers![name] = after;
    changes.push({ name, before, after });
  }

  process.stdout.write(`\n${bold('protect-mcp wrap: Claude Desktop')}\n\n`);
  process.stdout.write(`Config: ${claudePath}\n`);
  process.stdout.write(`Mode:   ${enforce ? 'enforce' : 'shadow'}\n\n`);
  for (const change of changes) {
    if (change.skipped) {
      process.stdout.write(`  - ${change.name}: ${yellow(change.skipped)}\n`);
    } else {
      process.stdout.write(`  - ${change.name}: ${green('will wrap')}\n`);
      process.stdout.write(`    ${dim(`${change.before.command || ''} ${(change.before.args || []).join(' ')}`)}\n`);
      process.stdout.write(`    ${dim(shellCommand('npx', change.after.args || []))}\n`);
    }
  }

  if (!write) {
    process.stdout.write(`\nDry run only. Apply with:\n`);
    process.stdout.write(`  ${dim('npx protect-mcp wrap --claude-desktop --write')}\n\n`);
    return;
  }

  const backupPath = `${claudePath}.bak.${Date.now()}`;
  writeFileSync(backupPath, readFileSync(claudePath, 'utf-8'));
  writeFileSync(claudePath, JSON.stringify(next, null, 2) + '\n');
  process.stdout.write(`\n${green('✓ Claude Desktop config updated')}\n`);
  process.stdout.write(`  Backup: ${backupPath}\n`);
  process.stdout.write(`  Restart Claude Desktop, then run: ${dim('npx protect-mcp dashboard --open')}\n\n`);
}

function bold(s: string): string {
  return process.env.NO_COLOR ? s : `\x1b[1m${s}\x1b[0m`;
}

function dim(s: string): string {
  return process.env.NO_COLOR ? s : `\x1b[2m${s}\x1b[0m`;
}

function green(s: string): string {
  return process.env.NO_COLOR ? s : `\x1b[32m${s}\x1b[0m`;
}

function red(s: string): string {
  return process.env.NO_COLOR ? s : `\x1b[31m${s}\x1b[0m`;
}

function yellow(s: string): string {
  return process.env.NO_COLOR ? s : `\x1b[33m${s}\x1b[0m`;
}

/**
 * Handle the `digest` command: generate a human-readable summary of today's activity.
 */
async function handleDigest(argv: string[]): Promise<void> {
  const { readFileSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');

  let dir = process.cwd();
  const dirIdx = argv.indexOf('--dir');
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];

  const today = argv.includes('--today');
  const logPath = join(dir, '.protect-mcp-log.jsonl');

  if (!existsSync(logPath)) {
    process.stderr.write(`${bold('protect-mcp digest')}\n\nNo log file found. Run protect-mcp first.\n`);
    process.exit(0);
  }

  const raw = readFileSync(logPath, 'utf-8');
  const lines = raw.trim().split('\n').filter(Boolean);

  interface LogEntry {
    tool: string;
    decision: string;
    reason_code: string;
    tier?: string;
    timestamp: number;
    mode?: string;
  }

  let entries: LogEntry[] = [];
  for (const line of lines) {
    try { entries.push(JSON.parse(line)); } catch { /* skip */ }
  }

  if (today) {
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    entries = entries.filter(e => e.timestamp >= todayStart.getTime());
  }

  if (entries.length === 0) {
    process.stdout.write(`\n${bold('🛡️ Agent Digest')}\n\n  No activity${today ? ' today' : ''}.\n\n`);
    process.exit(0);
  }

  // Compute stats
  const allowed = entries.filter(e => e.decision === 'allow').length;
  const denied = entries.filter(e => e.decision === 'deny').length;
  const approvalRequired = entries.filter(e => e.decision === 'require_approval').length;
  const toolUsage = new Map<string, number>();
  for (const e of entries) {
    toolUsage.set(e.tool, (toolUsage.get(e.tool) || 0) + 1);
  }
  const sortedTools = [...toolUsage.entries()].sort((a, b) => b[1] - a[1]);
  const currentTier = entries[entries.length - 1]?.tier || 'unknown';
  const firstTime = new Date(Math.min(...entries.map(e => e.timestamp)));
  const lastTime = new Date(Math.max(...entries.map(e => e.timestamp)));
  const durationMs = lastTime.getTime() - firstTime.getTime();
  const durationStr = durationMs < 60000 ? `${Math.round(durationMs / 1000)}s` :
    durationMs < 3600000 ? `${Math.round(durationMs / 60000)}m` :
    `${(durationMs / 3600000).toFixed(1)}h`;

  process.stdout.write(`\n${bold('🛡️ Agent Daily Digest')}\n\n`);
  process.stdout.write(`  📊 ${bold(String(entries.length))} actions | `);
  process.stdout.write(`${green('✓ ' + allowed)} allowed | `);
  process.stdout.write(`${red('✗ ' + denied)} blocked`);
  if (approvalRequired > 0) process.stdout.write(` | ${yellow('⏳ ' + approvalRequired)} awaiting approval`);
  process.stdout.write(`\n`);
  process.stdout.write(`  🏅 Trust tier: ${bold(currentTier)} | ⏱ Active: ${durationStr}\n\n`);

  process.stdout.write(`  ${bold('Tools used:')}\n`);
  for (const [tool, count] of sortedTools.slice(0, 8)) {
    process.stdout.write(`    ${tool.padEnd(22)} ${count}x\n`);
  }

  if (denied > 0) {
    const deniedTools = entries.filter(e => e.decision === 'deny');
    const deniedToolNames = [...new Set(deniedTools.map(e => e.tool))];
    process.stdout.write(`\n  ${bold(red('Blocked tools:'))}\n`);
    for (const tool of deniedToolNames) {
      const reason = deniedTools.find(e => e.tool === tool)?.reason_code || 'policy';
      process.stdout.write(`    ${red('✗')} ${tool} (${reason})\n`);
    }
  }

  process.stdout.write(`\n  ${dim('Latest receipt: curl -s http://127.0.0.1:9876/receipts/latest | jq -r .receipt > receipt.json')}\n`);
  process.stdout.write(`  ${dim('Verify: npx @veritasacta/verify receipt.json --key <public-key-hex>')}\n`);
  process.stdout.write(`  ${dim('Export: npx protect-mcp bundle --output audit.json')}\n\n`);
}

/**
 * Handle the `receipts` command: show recent persisted signed decisions.
 */
async function handleReceipts(argv: string[]): Promise<void> {
  const { readFileSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');

  let dir = process.cwd();
  const dirIdx = argv.indexOf('--dir');
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];

  const lastIdx = argv.indexOf('--last');
  const count = lastIdx !== -1 && argv[lastIdx + 1] ? parseInt(argv[lastIdx + 1], 10) : 20;

  const receiptsPath = join(dir, '.protect-mcp-receipts.jsonl');

  if (!existsSync(receiptsPath)) {
    process.stderr.write(`${bold('protect-mcp receipts')}\n\nNo signed receipt file found. Run protect-mcp with signing enabled first.\n`);
    process.exit(0);
  }

  const raw = readFileSync(receiptsPath, 'utf-8');
  const lines = raw.trim().split('\n').filter(Boolean);
  const recent = lines.slice(-count);

  process.stdout.write(`\n${bold('🛡️ Recent Receipts')} (last ${recent.length})\n\n`);

  for (const line of recent) {
    try {
      const entry = JSON.parse(line);
      const payload = entry.payload || {};
      const time = typeof entry.issued_at === 'string'
        ? new Date(entry.issued_at).toLocaleTimeString()
        : 'unknown';
      const decision = payload.decision || 'unknown';
      const icon = decision === 'allow' ? green('✓') :
                   decision === 'require_approval' ? yellow('⏳') : red('✗');
      process.stdout.write(`  ${dim(time)} ${icon} ${String(payload.tool || 'unknown').padEnd(22)} ${String(entry.type || 'receipt').padEnd(18)} ${dim(String(payload.reason_code || 'signed'))}\n`);
    } catch { /* skip */ }
  }

  process.stdout.write(`\n`);
}

// ── record: a local, searchable view of your own receipts ────────────────────
let _pkgV: string | null = null;
async function pkgVersion(): Promise<string> {
  if (_pkgV) return _pkgV;
  let v = '0.0.0';
  try {
    const { readFileSync, existsSync, realpathSync } = await import('node:fs');
    const { dirname, join, resolve } = await import('node:path');
    // Resolve the CLI's own location from process.argv[1] (the invoked script).
    // import.meta.url is empty in the bundled CJS bin, so we cannot rely on it.
    // Follow symlinks so global npm installs resolve to the real package dir.
    let base = '';
    try { base = dirname(realpathSync(resolve(process.argv[1] || ''))); } catch { /* fall through */ }
    const candidates = [
      base ? join(base, '..', 'package.json') : '',
      base ? join(base, 'package.json') : '',
    ].filter(Boolean);
    for (const p of candidates) {
      if (existsSync(p)) {
        const parsed = JSON.parse(readFileSync(p, 'utf-8'));
        if (parsed && parsed.name === 'protect-mcp' && parsed.version) { v = parsed.version; break; }
      }
    }
  } catch { /* best-effort */ }
  _pkgV = v;
  return v;
}

function mapRecordEntry(e: any): any {
  const p = e && e.payload && typeof e.payload === 'object' ? e.payload : e;
  const dec = String(p.decision || e.decision || '').toLowerCase();
  const verdict = /den|block|reject|refus/.test(dec) ? 'blocked' : (/ask|approv|hold|escal|review|pending/.test(dec) ? 'held' : 'allowed');
  const tsRaw = e.issued_at || e.timestamp || p.timestamp || p.issued_at;
  const ms = typeof tsRaw === 'number' ? tsRaw : (typeof tsRaw === 'string' ? Date.parse(tsRaw) : NaN);
  const ts = isFinite(ms) ? new Date(ms).toISOString() : '';
  const tool = String(p.tool || e.tool || 'action');
  const reason = String(p.reason_code || e.reason_code || p.policy_engine || 'signed');
  const hook = String(p.hook_event || e.hook_event || '');
  const signed = !!(e.signature || e.sig || e.receipt_hash || (typeof e.type === 'string' && e.type.indexOf('receipt') >= 0));
  let digest = '';
  if (e.receipt_hash) digest = String(e.receipt_hash);
  else if (e.digest) digest = String(e.digest);
  else if (p.payload_digest && p.payload_digest.output_hash) digest = String(p.payload_digest.output_hash);
  const enr = (p && typeof p.enrichment === 'object' && p.enrichment) || (typeof e.enrichment === 'object' && e.enrichment) || null;
  const caps = enr && Array.isArray(enr.capabilities) ? enr.capabilities.map(String) : [];
  const sw = (p && typeof p.swarm === 'object' && p.swarm) || null;
  const agent = sw && (sw.agent_name || sw.agent_id || sw.agent_type) ? String(sw.agent_name || sw.agent_id || sw.agent_type) : 'main agent';
  const tm = (p && typeof p.timing === 'object' && p.timing) || null;
  const dur = tm && typeof tm.tool_duration_ms === 'number' ? tm.tool_duration_ms : 0;
  // raw carries the original (signed) receipt so the viewer's export emits real,
  // offline-verifiable receipts, not the display projection.
  return { ts, tool, verdict, reason, hook, signed, caps, agent, dur, id: String(e.request_id || p.request_id || ''), digest, raw: e };
}

async function handleRecord(argv: string[]): Promise<void> {
  const { readFileSync, existsSync, writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const osMod = await import('node:os');
  const cp = await import('node:child_process');

  let dir = process.cwd();
  const di = argv.indexOf('--dir');
  if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  const recPath = join(dir, '.protect-mcp-receipts.jsonl');
  const logPath = join(dir, '.protect-mcp-log.jsonl');
  // Re-evaluated on every read so live mode upgrades to signed receipts the
  // moment the gate starts signing, and picks up the file appearing later.
  const pick = (): string | null => existsSync(recPath) ? recPath : (existsSync(logPath) ? logPath : null);
  const chosen = pick();
  if (!chosen) {
    process.stderr.write(`\n${bold('protect-mcp record')}\n\nNo record found in ${dir}.\nStart the gate with ${bold('npx protect-mcp serve')}, use your agent, then run this again.\n`);
    process.stderr.write(`Tip: run this in the directory where your gate is signing (where .protect-mcp-receipts.jsonl lives), or pass ${bold('--dir <path>')}.\n\n`);
    process.exit(0);
    return;
  }
  const readRecs = (file: string): any[] => readFileSync(file, 'utf-8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter((x) => x !== null).map(mapRecordEntry);

  // The operator's PUBLIC key, so the viewer verifies signatures in-browser
  // against YOUR gate's key (authenticity, not just self-consistency). Only the
  // public half ever reaches the page; the private key is never read into it.
  let pinnedKey = '';
  let pinnedKid = '';
  try {
    const kd = JSON.parse(readFileSync(join(dir, 'keys', 'gateway.json'), 'utf-8'));
    if (kd && typeof kd.publicKey === 'string' && /^[0-9a-f]{64}$/i.test(kd.publicKey)) {
      pinnedKey = kd.publicKey;
      pinnedKid = typeof kd.kid === 'string' ? kd.kid : '';
    }
  } catch { /* no key file: viewer falls back to keys embedded in receipts */ }

  const openTarget = (target: string): void => {
    if (argv.includes('--no-open')) return;
    const platform = process.platform;
    const opener = platform === 'darwin' ? 'open' : platform === 'win32' ? 'cmd' : 'xdg-open';
    const openArgs = platform === 'win32' ? ['/c', 'start', '', target] : [target];
    try { const child = cp.spawn(opener, openArgs, { stdio: 'ignore', detached: true }); child.unref(); } catch { /* ignore */ }
  };

  // ── live mode: serve a local page that re-reads the record as the gate writes it ──
  if (argv.includes('--live') || argv.includes('--watch')) {
    const http = await import('node:http');
    const pi = argv.indexOf('--port');
    const port = pi !== -1 && argv[pi + 1] ? parseInt(argv[pi + 1], 10) : 9378;
    const server = http.createServer((req, res) => {
      if (req.url && req.url.indexOf('/data') === 0) {
        let recs: any[] = [];
        const f = pick();
        try { if (f) recs = readRecs(f); } catch { /* best-effort */ }
        res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ recs, signed: f === recPath }));
        return;
      }
      const meta = { file: chosen, signed: pick() === recPath, count: 0, live: true, pinned_key: pinnedKey, pinned_kid: pinnedKid };
      const page = RECORD_HTML.replace('__DATA__', () => '[]').replace('__META__', () => JSON.stringify(meta));
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(page);
    });
    server.on('error', (e: NodeJS.ErrnoException) => {
      process.stderr.write(`\nprotect-mcp record --live: could not start on port ${port}${e && e.code ? ` (${e.code})` : ''}. Try ${bold('--port <n>')}.\n\n`);
      process.exit(1);
    });
    server.listen(port, '127.0.0.1', () => {
      const url = `http://127.0.0.1:${port}`;
      openTarget(url);
      process.stdout.write(`\n${bold('🛡️  Your record')} ${dim('·')} live at ${url}\n`);
      process.stdout.write(`  Updates as your agent runs. All local, nothing uploaded. ${dim('Ctrl-C to stop.')}\n\n`);
    });
    return; // keep serving
  }

  // ── static snapshot (default) ──
  const recs = readRecs(chosen);
  const meta = { file: chosen, signed: chosen === recPath, count: recs.length, live: false, pinned_key: pinnedKey, pinned_kid: pinnedKid };
  const html = RECORD_HTML
    .replace('__DATA__', () => JSON.stringify(recs))
    .replace('__META__', () => JSON.stringify(meta));
  const out = join(osMod.tmpdir(), 'protect-mcp-record-' + Date.now() + '.html');
  writeFileSync(out, html);
  openTarget(out);

  process.stdout.write(`\n${bold('🛡️  Your record')} ${dim('·')} ${recs.length} decision${recs.length === 1 ? '' : 's'}, all on this machine\n`);
  if (!meta.signed) process.stdout.write(`  ${dim('(decision log; signed receipts appear in .protect-mcp-receipts.jsonl once signing is on)')}\n`);
  // Print the viewer path as an OSC 8 clickable hyperlink in supporting terminals
  // (iTerm2, WezTerm, VS Code, GNOME Terminal, ...); plain text elsewhere and in
  // pipes (guarded by isTTY so redirected output never contains escape codes).
  const fileUrl = 'file://' + encodeURI(out);
  if (process.stdout.isTTY) {
    process.stdout.write(`  Opened in your browser. If it did not open, click: \x1b]8;;${fileUrl}\x1b\\${bold('your record')}\x1b]8;;\x1b\\\n`);
  } else {
    process.stdout.write(`  Opened in your browser. If it did not open, open: ${out}\n`);
  }
  process.stdout.write(`  ${dim('Want it to update live as your agent runs? npx protect-mcp record --live')}\n\n`);
  process.exit(0);
}

const RECORD_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>protect-mcp record</title>
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
.attest{margin:0 0 12px;font-size:12.5px;color:var(--soft);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cmd{font-family:ui-monospace,Menlo,monospace;font-size:12px;background:#efece4;border:1px solid var(--line);border-radius:6px;padding:3px 8px;color:var(--ink)}
.btn2{cursor:pointer;font:inherit;font-size:12px;padding:4px 9px;border-radius:7px;border:1px solid var(--line);background:#fff;color:var(--ink)}
.btn2:hover{border-color:var(--ink)}
.bar{margin:6px 0 12px}
input{width:100%;padding:10px 13px;border:1px solid var(--line);border-radius:9px;background:#fff;font:inherit}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.chip{cursor:pointer;font-size:12px;padding:3px 10px;border-radius:100px;border:1px solid var(--line);background:#fff;color:var(--soft)}
.chip.on{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.count{color:var(--faint);font-size:12px;font-family:ui-monospace,Menlo,monospace;margin-bottom:8px}
.row{border:1px solid var(--line);border-radius:9px;background:#fcfbf7;padding:11px 13px;margin-bottom:8px;cursor:pointer}
.row.blocked{background:#fbf3f0}.row.held{background:#fbf7ee}
.top{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.pill{font-size:11px;font-weight:600;padding:2px 9px;border-radius:100px}
.pill.allowed{background:var(--gb);color:var(--g)}.pill.held{background:var(--ab);color:var(--a)}.pill.blocked{background:var(--rb);color:var(--r)}
.tag{font-size:11px;padding:1px 7px;border-radius:100px;background:var(--paper);border:1px solid var(--line);color:var(--faint)}
.cap{font-size:10px;padding:1px 6px;border-radius:100px;background:#eef0ea;border:1px solid var(--line);color:var(--soft)}
.badge{font-size:10.5px;font-weight:600;padding:1px 7px;border-radius:100px}
.badge.sgn{background:var(--gb);color:var(--g)}
.badge.log{background:var(--paper);color:var(--faint);border:1px solid var(--line)}
.badge.vbad{background:#fbecec;color:#b3382f;border:1px solid #edc6c2}
.badge.vfor{background:#fbf3df;color:#8a6d1a;border:1px solid #e8d8ae}
.stat .badk{color:#b3382f;font-weight:680}.stat .warnk{color:#8a6d1a}.stat .dim2{color:var(--faint);font-weight:400}
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
.act{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:9px 4px;cursor:pointer;border-bottom:1px solid var(--line)}
.akids .act:last-child{border-bottom:0}
.act:hover{background:rgba(0,0,0,.02)}
.act.blocked{background:#fbf3f0}.act.held{background:#fbf7ee}
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
<div class="attest" id="attest"></div>
<div id="list"></div>
<div class="foot">Signed decisions from your own gate, on this machine. Nothing was uploaded. Each row is Ed25519-signed, and the exports carry the signatures, so anyone you hand them to (an allocator, an auditor, a counterparty) verifies offline with <b>npx @veritasacta/verify</b>, our code removed. For a Merkle-rooted evidence pack: <b>npx protect-mcp bundle</b>. To prove a claim over this record without revealing it (e.g. no egress): <b>npx protect-mcp claim --no net.egress</b>, checked offline with <b>npx protect-mcp verify-claim</b>. protect-mcp governs proposed actions before they run.</div>
</div>
<script>
var RECORDS=__DATA__;var META=__META__;var Q="",ACT={},VIEW="list",OPEN={};var NL=String.fromCharCode(10);
// In-browser signature verification. Mirrors @veritasacta/artifacts exactly:
// preimage = JCS-style canonical JSON (sorted keys) of the receipt minus its
// signature, verified with WebCrypto Ed25519. Pinned key (your keys/gateway.json
// public half, injected by the CLI) = authenticity; key embedded in the receipt
// payload (0.9.3+) = self-consistency. Everything runs locally.
var VSTATE={},VDONE=false,VBUSY=false,VUNSUP=false;
function vkey(r){return "row:"+(r.id||"")+"|"+(r.ts||"")}
function hexb(h){h=String(h||"");var a=new Uint8Array(h.length>>1);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a}
function canon(v){return JSON.stringify(v,function(k,x){if(x&&typeof x==="object"&&!Array.isArray(x)){var s={},ks=Object.keys(x).sort();for(var i=0;i<ks.length;i++)s[ks[i]]=x[ks[i]];return s}return x})}
async function edv(sig,msg,pub){var key=await crypto.subtle.importKey("raw",hexb(pub),{name:"Ed25519"},false,["verify"]);return crypto.subtle.verify({name:"Ed25519"},key,hexb(sig),msg)}
async function verifyRow(r){var raw=r.raw;if(!raw||typeof raw.signature!=="string")return"unsigned";
var rest={},k;for(k in raw)if(k!=="signature")rest[k]=raw[k];
var msg=new TextEncoder().encode(canon(rest));
var pin=String(META.pinned_key||"").toLowerCase();
var emb=String((raw.payload&&raw.payload.public_key)||raw.public_key||"").toLowerCase();
if(!/^[0-9a-f]{64}$/.test(emb))emb="";
if(pin){if(await edv(raw.signature,msg,pin))return"ok";if(emb&&emb!==pin&&await edv(raw.signature,msg,emb))return"foreign";return"bad"}
if(emb)return(await edv(raw.signature,msg,emb))?"ok":"bad";
return"nokey"}
function vsum(){var s={ok:0,bad:0,foreign:0,nokey:0};RECORDS.forEach(function(r){if(!r.signed)return;var v=VSTATE[vkey(r)];if(v&&s[v]!==undefined)s[v]++});return s}
async function kickVerify(){if(VBUSY||VUNSUP||!(window.crypto&&crypto.subtle))return;VBUSY=true;
try{var rows=RECORDS.slice(0,1500);for(var i=0;i<rows.length;i++){var r=rows[i],kk=vkey(r);if(VSTATE[kk])continue;
try{VSTATE[kk]=await verifyRow(r)}catch(e){if(e&&e.name==="NotSupportedError"){VUNSUP=true;break}VSTATE[kk]="bad"}}}
finally{VDONE=true;VBUSY=false;render()}}
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
function copyAttest(){var a=document.getElementById("attest");var cmd=a?a.getAttribute("data-cmd"):"";try{navigator.clipboard&&cmd&&navigator.clipboard.writeText(cmd)}catch(e){}var b=document.getElementById("cpa");if(b){var t=b.textContent;b.textContent="Copied";setTimeout(function(){b.textContent=t},1200)}}
function copyVerify(){var cmd="npx @veritasacta/verify";try{navigator.clipboard&&navigator.clipboard.writeText(cmd)}catch(e){}var b=document.getElementById("cpv");if(b){var t=b.textContent;b.textContent="Copied";setTimeout(function(){b.textContent=t},1200)}}
function renderStats(){var c=counts(RECORDS);var p=[];p.push('<span class="stat"><b>'+RECORDS.length+'</b> decisions</span>');p.push('<span class="stat"><span class="dot g"></span>'+c.allowed+' allowed</span>');if(c.held)p.push('<span class="stat"><span class="dot a"></span>'+c.held+' held</span>');p.push('<span class="stat"><span class="dot r"></span>'+c.blocked+' blocked</span>');var st;if(!c.signed){st='0 signed, verifiable offline'}else if(VUNSUP||!(window.crypto&&crypto.subtle)){st=c.signed+' signed, verifiable offline <span class="dim2">(in-browser check unavailable here; run npx protect-mcp receipts)</span>'}else if(!VDONE){st=c.signed+' signed · verifying in your browser…'}else{var s=vsum();st=s.ok+' of '+c.signed+' signatures verified in your browser';if(s.foreign)st+=' <span class="warnk">· '+s.foreign+' signed by an unpinned key</span>';if(s.bad)st+=' <span class="badk">· '+s.bad+' INVALID</span>';if(s.nokey)st+=' <span class="dim2">· '+s.nokey+' need a key to check</span>'}
p.push('<span class="stat sig">'+st+'</span>');document.getElementById("stats").innerHTML=p.join("")}
function renderList(rows){var html="";rows.slice(0,800).forEach(function(r){var vs=VSTATE[vkey(r)];var sig=!r.signed?'<span class="badge log">log</span>':vs==="ok"?'<span class="badge sgn">✓ verified</span>':vs==="bad"?'<span class="badge vbad">✗ invalid signature</span>':vs==="foreign"?'<span class="badge vfor">signed · unpinned key</span>':'<span class="badge sgn">signed</span>';var dg=r.digest?'<span class="dg">'+esc(String(r.digest).slice(0,10))+'</span>':'';var ct=(r.caps||[]).map(function(c){return '<span class="cap">'+esc(c)+'</span>'}).join('');var rk="row:"+(r.id||"")+"|"+(r.ts||"");html+='<div class="row '+r.verdict+(OPEN[rk]?" open":"")+'" data-k="'+esc(rk)+'"><div class="top"><span class="pill '+r.verdict+'">'+vlabel(r.verdict)+"</span><b>"+esc(r.tool)+'</b><span class="tag">'+esc(r.reason)+"</span>"+ct+(r.hook?'<span class="tag">'+esc(r.hook)+"</span>":"")+sig+dg+'<span class="when">'+esc(when(r.ts))+'</span></div><div class="det">'+esc(JSON.stringify(r.raw||r,null,2))+"</div></div>"});document.getElementById("list").innerHTML=html||'<p style="color:#8a837a">No records match.</p>';}
function isLifecycle(r){var h=r.hook||"";return h==="SessionStart"||h==="SessionEnd"||h==="Stop"||h==="SubagentStart"||h==="SubagentStop"||h==="TaskCreated"||h==="TaskCompleted"||h==="ConfigChange"||h==="Notification"||h==="PreCompact";}
function buildTree(rows){var ags={},order=[];rows.forEach(function(r){var a=r.agent||"main agent";if(!ags[a]){ags[a]={name:a,byId:{},items:[],caps:{},blocked:0,actions:0};order.push(a);}var g=ags[a];(r.caps||[]).forEach(function(c){g.caps[c]=(g.caps[c]||0)+1;});if(isLifecycle(r)){g.items.push({t:"e",ts:r.ts,r:r});return;}var id=r.id||("_"+r.ts);var n=g.byId[id];if(!n){n={t:"a",id:id,tool:r.tool,verdict:r.verdict,caps:(r.caps||[]).slice(),ts:r.ts,dur:0,signed:!!r.signed,raw:r.raw};g.byId[id]=n;g.items.push(n);g.actions++;}if(r.hook==="PostToolUse"){if(r.dur)n.dur=r.dur;if(!n.raw)n.raw=r.raw;}else{n.verdict=r.verdict;if((r.caps||[]).length)n.caps=r.caps.slice();n.raw=r.raw;n.ts=r.ts;}if(r.signed)n.signed=true;});order.forEach(function(a){var g=ags[a];g.blocked=g.items.filter(function(it){return it.t==="a"&&it.verdict==="blocked";}).length;g.items.sort(function(x,y){return (x.ts<y.ts)?-1:1;});});return order.map(function(a){return ags[a];});}
function renderTree(ags){if(!ags.length){document.getElementById("list").innerHTML='<p style="color:#8a837a">No records match.</p>';return;}var html="",N=0;ags.forEach(function(g,gi){var capstr=Object.keys(g.caps).sort(function(a,b){return g.caps[b]-g.caps[a];}).slice(0,5).map(function(c){return '<span class="cap">'+esc(c)+'</span>';}).join('');var ak="ag:"+g.name;var op=(OPEN.hasOwnProperty(ak)?OPEN[ak]:(ags.length===1||gi===0))?" open":"";html+='<div class="agent'+op+'" data-k="'+esc(ak)+'"><div class="ahead"><span class="atwist">▸</span><b>'+esc(g.name)+'</b><span class="acount">'+g.actions+' action'+(g.actions===1?'':'s')+'</span>'+(g.blocked?'<span class="badge blk">'+g.blocked+' blocked</span>':'')+capstr+'</div><div class="akids">';g.items.forEach(function(it){if(N++>1500)return;if(it.t==="e"){var r=it.r;html+='<div class="ev"><span class="evdot"></span>'+esc(r.hook||r.tool)+' <span class="evre">'+esc(r.reason)+'</span><span class="when">'+esc(when(r.ts))+'</span></div>';}else{var ct=(it.caps||[]).map(function(c){return '<span class="cap">'+esc(c)+'</span>';}).join('');var dur=it.dur?'<span class="dg">'+it.dur+'ms</span>':'';var ik="act:"+it.id;html+='<div class="act '+it.verdict+(OPEN[ik]?" open":"")+'" data-k="'+esc(ik)+'"><span class="pill '+it.verdict+'">'+vlabel(it.verdict)+'</span><b>'+esc(it.tool)+'</b>'+ct+(it.signed?'<span class="badge sgn">signed</span>':'')+dur+'<span class="when">'+esc(when(it.ts))+'</span><div class="det">'+esc(JSON.stringify(it.raw||{},null,2))+'</div></div>';}});html+='</div></div>';});if(N>1500)html+='<p style="color:#8a837a;font-size:12px;margin-top:10px">Showing the first 1500 items. Search or pick a facet to narrow.</p>';document.getElementById("list").innerHTML=html;}
function setView(v){VIEW=v;document.getElementById("vlist").className=v==="list"?"on":"";document.getElementById("vtree").className=v==="tree"?"on":"";render();}
function render(){
document.getElementById("meta").textContent=META.count+" decisions from "+META.file+(META.signed?" (signed)":" (decision log)")+" - all local"+(META.live?" · live, updating":"");
document.getElementById("live").innerHTML=META.live?'<span class="pulse"></span>':"";
renderStats();
var chips="";["Decision","Tool","Reason","Capability"].forEach(function(key){fvals(key).forEach(function(p){var on=ACT[key]===p[0];chips+='<span class="chip'+(on?" on":"")+'" data-k="'+key+'" data-v="'+esc(p[0])+'">'+esc(p[0])+" "+p[1]+"</span>"})});
document.getElementById("chips").innerHTML=chips;
var rows=RECORDS.filter(match);
document.getElementById("count").textContent=rows.length+" of "+RECORDS.length+" records"+(VIEW==="tree"?" · grouped by agent":"");
var _at=document.getElementById("attest");if(ACT.Capability){var _cmd="npx protect-mcp claim --no "+ACT.Capability;_at.setAttribute("data-cmd",_cmd);_at.innerHTML='Prove it over this record, revealing nothing: <span class="cmd">'+esc(_cmd)+'</span><button class="btn2" id="cpa" onclick="copyAttest()">Copy</button>';}else{_at.innerHTML="";_at.removeAttribute("data-cmd");}
if(VIEW==="tree"){renderTree(buildTree(rows));}else{renderList(rows);}}
document.getElementById("q").addEventListener("input",function(e){Q=e.target.value.toLowerCase().trim();render()});
document.getElementById("chips").addEventListener("click",function(e){var c=e.target.closest(".chip");if(!c)return;var k=c.getAttribute("data-k"),v=c.getAttribute("data-v");ACT[k]=ACT[k]===v?undefined:v;render()});
document.getElementById("list").addEventListener("click",function(e){var ah=e.target.closest(".ahead");if(ah){var ag=ah.parentNode;ag.classList.toggle("open");var ak=ag.getAttribute("data-k");if(ak)OPEN[ak]=ag.classList.contains("open");return;}var el=e.target.closest(".act")||e.target.closest(".row");if(el){el.classList.toggle("open");var k=el.getAttribute("data-k");if(k)OPEN[k]=el.classList.contains("open");}});
render();kickVerify();
if(META.live){var poll=function(){fetch('/data',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){var nr=d.recs||[];var changed=nr.length!==RECORDS.length;RECORDS=nr;META.count=RECORDS.length;if(typeof d.signed==='boolean')META.signed=d.signed;if(changed){render();kickVerify()}}).catch(function(){})};poll();setInterval(poll,2000);}
</script></body></html>`;

// ── claim: a signed, position-blind attestation of a predicate over your record ──
async function handleClaim(argv: string[]): Promise<void> {
  const { readFileSync, existsSync, writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { buildClaim } = await import('./claim.js');

  let dir = process.cwd();
  const di = argv.indexOf('--dir'); if (di !== -1 && argv[di + 1]) dir = argv[di + 1];

  let predicate: import('./claim.js').ClaimPredicate | null = null;
  const noIdx = argv.indexOf('--no'), onlyIdx = argv.indexOf('--only'), nvIdx = argv.indexOf('--no-verdict'), cvIdx = argv.indexOf('--count'), puIdx = argv.indexOf('--payment-under');
  if (noIdx !== -1 && argv[noIdx + 1]) predicate = { kind: 'no_capability', capability: argv[noIdx + 1] };
  else if (onlyIdx !== -1 && argv[onlyIdx + 1]) predicate = { kind: 'only_capabilities', capabilities: argv[onlyIdx + 1].split(',').map((s) => s.trim()).filter(Boolean) };
  else if (nvIdx !== -1 && argv[nvIdx + 1]) predicate = { kind: 'no_verdict', verdict: argv[nvIdx + 1] as 'allowed' | 'held' | 'blocked' };
  else if (cvIdx !== -1 && argv[cvIdx + 1]) predicate = { kind: 'count_verdict', verdict: argv[cvIdx + 1] as 'allowed' | 'held' | 'blocked' };
  else if (puIdx !== -1 && argv[puIdx + 1] && isFinite(parseFloat(argv[puIdx + 1]))) predicate = { kind: 'payment_under', cap: parseFloat(argv[puIdx + 1]) };
  if (!predicate) {
    process.stderr.write(`\n${bold('protect-mcp claim')}\n\nAttest a signed, position-blind claim over your record:\n  --no <capability>        no action used it, e.g. ${dim('--no net.egress')} or ${dim('--no payment')}\n  --only <c1,c2,...>       all actions confined to these capabilities\n  --no-verdict <verdict>   e.g. ${dim('--no-verdict blocked')}\n  --count <verdict>        how many, e.g. ${dim('--count blocked')}\n  --payment-under <cap>    every agent payment stayed under the cap (amounts the\n                           gate could not read count as OVER, so this cannot lie)\n  --anchor                 also record the claim digest in the public append-only\n                           log so a counterparty can trust it is complete (only the\n                           hash is sent; your record stays local)\n\nExample: ${bold('npx protect-mcp claim --no net.egress --anchor')}\n\n`);
    process.exit(0); return;
  }

  const keyPath = join(dir, 'keys', 'gateway.json');
  if (!existsSync(keyPath)) {
    process.stderr.write(`\n${bold('protect-mcp claim')}\n\nNo signing key at ${keyPath}. A claim must be signed. Run ${bold('npx protect-mcp init')} first.\n\n`);
    process.exit(1); return;
  }
  let key: { privateKey?: string; publicKey?: string; kid?: string };
  try { key = JSON.parse(readFileSync(keyPath, 'utf-8')); } catch { process.stderr.write(`\nprotect-mcp claim: ${keyPath} is not valid JSON.\n\n`); process.exit(1); return; }
  if (!key.privateKey || !key.publicKey) { process.stderr.write(`\nprotect-mcp claim: ${keyPath} is missing privateKey/publicKey.\n\n`); process.exit(1); return; }

  const recPath = join(dir, '.protect-mcp-receipts.jsonl');
  if (!existsSync(recPath)) {
    process.stderr.write(`\n${bold('protect-mcp claim')}\n\nNo signed receipts in ${dir}. Run the gate with signing on, then try again.\n\n`);
    process.exit(0); return;
  }
  const receipts = readFileSync(recPath, 'utf-8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((x): x is Record<string, unknown> => x !== null);
  if (!receipts.length) { process.stderr.write(`\nprotect-mcp claim: no readable receipts in ${recPath}.\n\n`); process.exit(0); return; }

  const pack = buildClaim(receipts, predicate, { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || 'gateway', issuer: 'protect-mcp' }, new Date().toISOString());
  const oi = argv.indexOf('--output');
  const out = oi !== -1 && argv[oi + 1] ? argv[oi + 1] : join(dir, 'claim-' + Date.now() + '.json');
  writeFileSync(out, JSON.stringify(pack, null, 2) + '\n');

  process.stdout.write(`\n${bold('🛡️  Signed claim')}\n`);
  process.stdout.write(`  ${pack.claim.statement}: ${pack.claim.holds ? green('holds') : yellow('does not hold')}  ${dim('(' + pack.claim.matched + ' matched of ' + pack.scope.total + ' decisions)')}\n`);
  process.stdout.write(`  ${dim('Position-blind: reveals decision categories, never tool inputs, outputs, or data. Ed25519-signed.')}\n`);
  process.stdout.write(`  Written to ${out}\n`);
  process.stdout.write(`  Hand it to anyone. They verify offline: ${bold('npx protect-mcp verify-claim ' + out)}\n`);

  if (argv.indexOf('--anchor') !== -1) {
    const { anchorClaim } = await import('./claim.js');
    const li = argv.indexOf('--log');
    const logBase = li !== -1 && argv[li + 1] ? argv[li + 1] : undefined;
    process.stdout.write(`\n  ${dim('Anchoring the claim digest to the public append-only log (only the hash leaves your machine)...')}\n`);
    const res = await anchorClaim(
      pack,
      { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || 'gateway', issuer: 'protect-mcp' },
      { log: logBase, issuedAt: new Date().toISOString() },
    );
    if (res.ok) {
      const sidecar = out.replace(/\.json$/, '') + '.anchor.json';
      writeFileSync(sidecar, JSON.stringify({ log: logBase || 'https://scopeblind.com', seq: res.seq, entry_url: res.entry_url, anchored_at: res.anchored_at, claim_digest: res.claim_digest, envelope: res.envelope }, null, 2) + '\n');
      process.stdout.write(`  ${green('Anchored')} as log entry ${bold('#' + res.seq)}${res.already_anchored ? dim(' (already present)') : ''}  ${dim(res.entry_url || '')}\n`);
      process.stdout.write(`  ${dim('A counterparty can now confirm this exact claim existed at ' + (res.anchored_at || 'this time') + ' and cannot be quietly re-cut.')}\n`);
      process.stdout.write(`  ${dim('Anchor record written to ' + sidecar + '. Only the digest was sent; your record stayed local.')}\n`);
      const { lookupPinnedIdentity } = await import('./claim.js');
      const who = await lookupPinnedIdentity(key.publicKey, { log: logBase });
      if (who && who.found && !who.revoked) {
        process.stdout.write(`  ${green('Identity:')} anchored as ${bold(who.name || who.slug || 'enrolled org')} ${dim('(key pinned in the ScopeBlind directory' + (who.enrolled_at ? ', enrolled ' + who.enrolled_at.slice(0, 10) : '') + ')')}\n`);
      } else if (who && who.found && who.revoked) {
        process.stdout.write(`  ${red('Identity: this key is REVOKED in the ScopeBlind directory.')}\n`);
      } else {
        process.stdout.write(`  ${dim('Identity: anonymous (key not enrolled). To anchor as a named org a counterparty can pin, see')} ${bold('scopeblind.com/enroll')}\n`);
      }
    } else {
      process.stdout.write(`  ${yellow('Anchor skipped')} ${dim('(' + (res.error || 'unavailable') + '). The claim above is complete and verifiable offline without it.')}\n`);
    }
  }
  process.stdout.write(`\n`);
  process.exit(0);
}

// anchor-record: checkpoint the record's CURRENT commitment (Merkle root +
// count + time range, nothing else) into the public log. Run on a heartbeat
// (cron, a scheduler, or by hand) and the record grows an anchored history a
// later claim can be checked against: same root => provably the complete set
// as of that checkpoint. Skips when the record has not changed since the last
// checkpoint (.protect-mcp-anchors.jsonl) so a heartbeat never spams the log.
async function handleAnchorRecord(argv: string[]): Promise<void> {
  const { readFileSync, existsSync, appendFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { anchorRecordCheckpoint, buildRecordCheckpoint, lookupPinnedIdentity } = await import('./claim.js');

  let dir = process.cwd();
  const di = argv.indexOf('--dir'); if (di !== -1 && argv[di + 1]) dir = argv[di + 1];
  const li = argv.indexOf('--log');
  const logBase = li !== -1 && argv[li + 1] ? argv[li + 1] : undefined;

  const keyPath = join(dir, 'keys', 'gateway.json');
  if (!existsSync(keyPath)) {
    process.stderr.write(`\n${bold('protect-mcp anchor-record')}\n\nNo signing key at ${keyPath}. A checkpoint must be signed. Run ${bold('npx protect-mcp init')} first.\n\n`);
    process.exit(1); return;
  }
  let key: { privateKey?: string; publicKey?: string; kid?: string };
  try { key = JSON.parse(readFileSync(keyPath, 'utf-8')); } catch { process.stderr.write(`\nprotect-mcp anchor-record: ${keyPath} is not valid JSON.\n\n`); process.exit(1); return; }
  if (!key.privateKey || !key.publicKey) { process.stderr.write(`\nprotect-mcp anchor-record: ${keyPath} is missing privateKey/publicKey.\n\n`); process.exit(1); return; }

  const recPath = join(dir, '.protect-mcp-receipts.jsonl');
  if (!existsSync(recPath)) {
    process.stderr.write(`\n${bold('protect-mcp anchor-record')}\n\nNo signed receipts in ${dir}. Run the gate with signing on, then try again.\n\n`);
    process.exit(0); return;
  }
  const receipts = readFileSync(recPath, 'utf-8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((x): x is Record<string, unknown> => x !== null);
  if (!receipts.length) { process.stderr.write(`\nprotect-mcp anchor-record: no readable receipts in ${recPath}.\n\n`); process.exit(0); return; }

  const claimKey = { privateKey: key.privateKey, publicKey: key.publicKey, kid: key.kid || 'gateway', issuer: 'protect-mcp' };
  const historyPath = join(dir, '.protect-mcp-anchors.jsonl');

  // Heartbeat dedup: if the record commitment is unchanged since the last
  // anchored checkpoint, there is nothing new to prove.
  const preview = buildRecordCheckpoint(receipts, claimKey, 'preview');
  if (!argv.includes('--force') && existsSync(historyPath)) {
    const lines = readFileSync(historyPath, 'utf-8').split(/\r?\n/).filter(Boolean);
    const last = lines.length ? (() => { try { return JSON.parse(lines[lines.length - 1]); } catch { return null; } })() : null;
    if (last && last.record_root === preview.record_root && last.total === preview.total) {
      process.stdout.write(`\n${bold('🛡️  Record checkpoint')}\n`);
      process.stdout.write(`  Unchanged since entry ${bold('#' + last.seq)} ${dim('(' + last.total + ' receipts, anchored ' + (last.anchored_at || '') + ')')}. Nothing new to anchor.\n`);
      process.stdout.write(`  ${dim('Use --force to re-anchor anyway.')}\n\n`);
      process.exit(0); return;
    }
  }

  const res = await anchorRecordCheckpoint(receipts, claimKey, { log: logBase, issuedAt: new Date().toISOString() });
  process.stdout.write(`\n${bold('🛡️  Record checkpoint')}\n`);
  process.stdout.write(`  ${res.total} receipts ${dim('·')} root ${dim(res.record_root.slice(0, 16) + '…')} ${dim('(' + res.checkpoint.from.slice(0, 10) + ' → ' + res.checkpoint.to.slice(0, 10) + ')')}\n`);
  if (!res.ok) {
    process.stdout.write(`  ${yellow('Anchor failed')} ${dim('(' + (res.error || 'unavailable') + '). Nothing was recorded; try again.')}\n\n`);
    process.exit(1); return;
  }
  appendFileSync(historyPath, JSON.stringify({ schema: res.checkpoint.schema, seq: res.seq, anchored_at: res.anchored_at, total: res.total, record_root: res.record_root, entry_url: res.entry_url, digest: res.checkpoint.digest }) + '\n');
  process.stdout.write(`  ${green('Anchored')} as log entry ${bold('#' + res.seq)}  ${dim(res.entry_url || '')}\n`);
  process.stdout.write(`  ${dim('Only the root, count, and time range were sent. History: ' + historyPath)}\n`);
  const who = await lookupPinnedIdentity(claimKey.publicKey, { log: logBase });
  if (who && who.found && !who.revoked) {
    process.stdout.write(`  ${green('Identity:')} anchored as ${bold(who.name || who.slug || 'enrolled org')} ${dim('(key pinned in the ScopeBlind directory)')}\n`);
  } else if (who && who.found && who.revoked) {
    process.stdout.write(`  ${red('Identity: this key is REVOKED in the ScopeBlind directory.')}\n`);
  } else {
    process.stdout.write(`  ${dim('Identity: anonymous (key not enrolled). Named identity: scopeblind.com/enroll')}\n`);
  }
  process.stdout.write(`  ${dim('A claim whose commitment matches this root is provably over the complete record as of')}\n`);
  process.stdout.write(`  ${dim('this checkpoint. Run this on a heartbeat (e.g. cron) to keep the anchored history growing.')}\n\n`);
  process.exit(0);
}

async function handleVerifyClaim(argv: string[]): Promise<void> {
  const { readFileSync, existsSync } = await import('node:fs');
  const { verifyClaim } = await import('./claim.js');
  const file = argv.find((a) => !a.startsWith('--'));
  if (!file || !existsSync(file)) {
    process.stderr.write(`\n${bold('protect-mcp verify-claim')} <claim.json> [--key <public-hex>]\n\nProvide a claim pack file.\n\n`);
    process.exit(2); return;
  }
  let pack: import('./claim.js').ClaimPack;
  try { pack = JSON.parse(readFileSync(file, 'utf-8')); } catch { process.stderr.write(`\nprotect-mcp verify-claim: ${file} is not valid JSON.\n\n`); process.exit(2); return; }
  if (!pack || pack.type !== 'scopeblind.claim.v1') { process.stderr.write(`\nprotect-mcp verify-claim: not a scopeblind.claim.v1 pack.\n\n`); process.exit(2); return; }

  const ki = argv.indexOf('--key');
  const v = verifyClaim(pack, ki !== -1 ? argv[ki + 1] : undefined);
  const ok = (b: boolean) => (b ? green('✓') : red('✗'));

  process.stdout.write(`\n${bold('protect-mcp verify-claim')}\n`);
  process.stdout.write(`  Claim:      ${pack.claim ? pack.claim.statement : '(none)'}\n`);
  process.stdout.write(`  Holds:      ${v.holds ? green('yes') : yellow('no')}  ${dim('(' + v.matched + ' matched of ' + v.total + ' decisions)')}\n`);
  process.stdout.write(`  Signature:  ${ok(v.authentic)} ${v.authentic ? 'valid' : 'INVALID'}  ${dim('issuer kid ' + ((pack.issuer && pack.issuer.kid) || '?'))}\n`);
  process.stdout.write(`  Commitment: ${ok(v.root_ok)} ${v.root_ok ? 'Merkle root matches the ' + v.total + ' disclosed decisions' : 'MISMATCH'}\n`);
  process.stdout.write(`  Predicate:  ${ok(v.predicate_ok)} ${v.predicate_ok ? 'recomputed independently and matches' : 'MISMATCH'}\n`);

  // ── Anchor: auto-detect the .anchor.json sidecar and verify it end-to-end ──
  // Local checks bind the anchored envelope to THIS claim; one GET confirms the
  // public log holds it. --anchor-file <p> overrides the path, --check-anchor
  // makes a missing/failed anchor fatal, --offline skips the network hop.
  const ai = argv.indexOf('--anchor-file');
  const sidecarPath = ai !== -1 && argv[ai + 1] ? argv[ai + 1] : file.replace(/\.json$/, '') + '.anchor.json';
  const requireAnchor = argv.includes('--check-anchor');
  let anchorOk = true; // only flips false on a real refutation, never on "no sidecar" (unless required)
  if (existsSync(sidecarPath)) {
    const { checkClaimAnchor } = await import('./claim.js');
    let sidecar: import('./claim.js').AnchorSidecar | null = null;
    try { sidecar = JSON.parse(readFileSync(sidecarPath, 'utf-8')); } catch { /* unreadable */ }
    if (!sidecar) {
      anchorOk = false;
      process.stdout.write(`  Anchor:     ${red('✗')} ${sidecarPath} is not valid JSON\n`);
    } else {
      const a = await checkClaimAnchor(pack, sidecar, { offline: argv.includes('--offline') });
      anchorOk = a.local_ok && a.log_ok !== false;
      if (a.local_ok) {
        process.stdout.write(`  Anchor:     ${green('✓')} anchored envelope binds this exact claim and its record root\n`);
        process.stdout.write(`              ${green('✓')} envelope signed by the claim issuer's key\n`);
      } else {
        for (const r of a.reasons.slice(0, 3)) process.stdout.write(`  Anchor:     ${red('✗')} ${r}\n`);
      }
      if (a.log_ok === true) {
        process.stdout.write(`              ${green('✓')} public log confirms it${typeof a.seq === 'number' ? ': entry ' + bold('#' + a.seq) : ''}${a.anchored_at ? dim(' · anchored ' + a.anchored_at) : ''}\n`);
      } else if (a.log_ok === false) {
        process.stdout.write(`              ${red('✗')} ${a.reasons[a.reasons.length - 1]}\n`);
      } else if (a.local_ok) {
        process.stdout.write(`              ${yellow('~')} log not checked ${dim(argv.includes('--offline') ? '(--offline)' : '(unreachable; local binding checks stand)')}\n`);
      }
      // Identity: resolve the anchoring key against the public key directory,
      // so "anchored" upgrades from a timestamp to a name the verifier can pin.
      if (!argv.includes('--offline') && sidecar.envelope) {
        const { lookupPinnedIdentity } = await import('./claim.js');
        const who = await lookupPinnedIdentity(sidecar.envelope.verification_key, {});
        if (who && who.found && !who.revoked) {
          process.stdout.write(`              ${green('✓')} issuer key pinned to ${bold(who.name || who.slug || 'an enrolled org')} ${dim('(ScopeBlind key directory)')}\n`);
        } else if (who && who.found && who.revoked) {
          anchorOk = false;
          process.stdout.write(`              ${red('✗')} issuer key is REVOKED in the ScopeBlind key directory\n`);
        } else if (who && !who.found) {
          process.stdout.write(`              ${dim('issuer key not enrolled (anonymous issuer); named identities pin via scopeblind.com/enroll')}\n`);
        }
      }
    }
  } else if (requireAnchor) {
    anchorOk = false;
    process.stdout.write(`  Anchor:     ${red('✗')} no anchor sidecar at ${sidecarPath} ${dim('(mint with: protect-mcp claim ... --anchor)')}\n`);
  } else {
    process.stdout.write(`  Anchor:     ${dim('none found (' + sidecarPath + '). Anchoring proves the claim was fixed at a time: claim ... --anchor')}\n`);
  }

  const finalValid = v.valid && anchorOk;
  process.stdout.write(`\n  ${finalValid ? green('VALID') : red('INVALID')} attestation${v.valid && !anchorOk ? red(' (anchor check failed)') : ''}.\n`);
  process.stdout.write(`  ${dim('Proves the pack came from the issuer key and the claim is true over the disclosed decision')}\n`);
  process.stdout.write(`  ${dim('categories (verdict + capabilities), which reveal no tool inputs, outputs, or data. Completeness')}\n`);
  process.stdout.write(`  ${dim('of the disclosed set is attested by the issuer; the anchor fixes it in a public append-only log.')}\n\n`);
  process.exit(finalValid ? 0 : 1);
}

async function handleBundle(argv: string[]): Promise<void> {
  const { readFileSync, writeFileSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { createAuditBundle } = await import('./bundle.js');

  let dir = process.cwd();
  const dirIdx = argv.indexOf('--dir');
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];

  const outputIdx = argv.indexOf('--output');
  const outputPath = outputIdx !== -1 && argv[outputIdx + 1]
    ? argv[outputIdx + 1]
    : join(dir, 'audit-bundle.json');

  const receiptsPath = join(dir, '.protect-mcp-receipts.jsonl');
  const keyPath = join(dir, 'keys', 'gateway.json');

  if (!existsSync(receiptsPath)) {
    process.stderr.write(`${bold('protect-mcp bundle')}\n\nNo signed receipt file found. Run protect-mcp with signing enabled first.\n`);
    process.exit(0);
  }

  if (!existsSync(keyPath)) {
    process.stderr.write(`${bold('protect-mcp bundle')}\n\nNo key file found at ${keyPath}\n`);
    process.exit(1);
  }

  const receipts = readFileSync(receiptsPath, 'utf-8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  const keyData = JSON.parse(readFileSync(keyPath, 'utf-8'));
  const bundle = createAuditBundle({
    tenant: keyData.issuer || 'protect-mcp',
    receipts,
    selectiveDisclosures: collectSelectiveDisclosurePackages(dir),
    signingKeys: [{
      kty: 'OKP',
      crv: 'Ed25519',
      kid: keyData.kid || 'unknown',
      x: Buffer.from(keyData.publicKey, 'hex').toString('base64url'),
      use: 'sig',
    }],
  });

  writeFileSync(outputPath, JSON.stringify(bundle, null, 2) + '\n');

  process.stdout.write(`\n${bold('protect-mcp bundle')}\n\n`);
  process.stdout.write(`  Receipts: ${receipts.length}\n`);
  process.stdout.write(`  Disclosures: ${collectSelectiveDisclosurePackages(dir).length}\n`);
  process.stdout.write(`  Output:   ${outputPath}\n`);
  process.stdout.write(`  Verify:   npx @veritasacta/verify ${outputPath} --bundle\n\n`);
}

/**
 * Create a ScopeBlind sandbox and save config to ~/.protect-mcp/config.json.
 * Returns the dashboard URL on success, or null on failure.
 */
async function createSandbox(): Promise<string | null> {
  const { mkdirSync, writeFileSync, existsSync, readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { homedir } = await import('node:os');

  let response: Response;
  try {
    response = await fetch('https://api.scopeblind.com/sandbox/create', { method: 'POST' });
  } catch {
    process.stderr.write(yellow('  ⚠ Could not create dashboard (offline or server unavailable).\n'));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.\n\n`);
    return null;
  }

  if (!response.ok) {
    process.stderr.write(yellow('  ⚠ Could not create dashboard (offline or server unavailable).\n'));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.\n\n`);
    return null;
  }

  let data: { slug: string; mgmt_token?: string; password?: string };
  try {
    data = await response.json() as typeof data;
  } catch {
    process.stderr.write(yellow('  ⚠ Could not create dashboard (unexpected response).\n'));
    process.stderr.write(`    Run 'npx protect-mcp connect' later to set up the dashboard.\n\n`);
    return null;
  }

  const dashboardUrl = `https://scopeblind.com/t/${data.slug}`;

  // Save to ~/.protect-mcp/config.json
  const configDir = join(homedir(), '.protect-mcp');
  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
  }
  const configPath = join(configDir, 'config.json');

  // Merge with existing config if present
  let existing: Record<string, unknown> = {};
  if (existsSync(configPath)) {
    try {
      existing = JSON.parse(readFileSync(configPath, 'utf-8'));
    } catch {
      // Overwrite corrupt config
    }
  }

  writeFileSync(configPath, JSON.stringify({
    ...existing,
    sandbox_slug: data.slug,
    dashboard_url: dashboardUrl,
  }, null, 2) + '\n');

  return dashboardUrl;
}

/**
 * Handle the `connect` command: create a ScopeBlind sandbox independently.
 */
async function handleConnect(): Promise<void> {
  process.stderr.write(`\n${bold('protect-mcp connect')}\n`);
  process.stderr.write(`${'─'.repeat(50)}\n\n`);
  process.stderr.write(`  Creating ScopeBlind sandbox dashboard...\n\n`);

  const dashboardUrl = await createSandbox();
  if (dashboardUrl) {
    process.stderr.write(green(`  ✓ Dashboard created: ${dashboardUrl}\n`));
    process.stderr.write(`    Receipts will be uploaded automatically.\n`);
    process.stderr.write(dim(`    Free tier: 20,000 receipts/month, no credit card required.\n`));
    process.stderr.write(`\n${'─'.repeat(50)}\n\n`);
  }
}

/**
 * Handle the `quickstart` command: zero-config onboarding.
 * Runs init (to tmpdir), then demo, automatically.
 */
async function handleQuickstart(argv: string[]): Promise<void> {
  const connectFlag = argv.includes('--connect');
  const { mkdtempSync, writeFileSync, existsSync, mkdirSync, readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');

  const dir = mkdtempSync(join(tmpdir(), 'protect-mcp-quickstart-'));

  process.stdout.write(`\n${bold('protect-mcp quickstart')}\n`);
  process.stdout.write(`${'─'.repeat(50)}\n\n`);
  process.stdout.write(`  This will:\n`);
  process.stdout.write(`  1. Generate an Ed25519 signing keypair\n`);
  process.stdout.write(`  2. Create a shadow-mode policy\n`);
  process.stdout.write(`  3. Start a demo MCP server with protect-mcp wrapping it\n`);
  process.stdout.write(`  4. Log signed receipts for every tool call\n`);
  if (connectFlag) {
    process.stdout.write(`  5. Create a ScopeBlind dashboard for receipt viewing\n`);
  }
  process.stdout.write(`\n  Working dir: ${dir}\n\n`);

  // Generate keypair
  const keysDir = join(dir, 'keys');
  mkdirSync(keysDir, { recursive: true });

  const { randomBytes } = await import('node:crypto');
  let keypair: { privateKey: string; publicKey: string; kid: string };
  try {
    const { ed25519 } = await import('@noble/curves/ed25519');
    const { bytesToHex } = await import('@noble/hashes/utils');
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    keypair = {
      privateKey: bytesToHex(privateKey),
      publicKey: bytesToHex(publicKey),
      kid: `quickstart-${Date.now()}`,
    };
  } catch {
    // Fallback — generate without signing
    keypair = {
      privateKey: randomBytes(32).toString('hex'),
      publicKey: randomBytes(32).toString('hex'),
      kid: `quickstart-${Date.now()}`,
    };
  }

  writeFileSync(join(keysDir, 'gateway.json'), JSON.stringify({
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    kid: keypair.kid,
    generated_at: new Date().toISOString(),
  }, null, 2) + '\n');

  // Write quick policy
  const configPath = join(dir, 'protect-mcp.json');
  const config = {
    tools: {
      '*': { rate_limit: '100/hour' },
      'delete_file': { block: true },
    },
    default_tier: 'unknown',
    signing: {
      key_path: join(keysDir, 'gateway.json'),
      issuer: 'protect-mcp-quickstart',
      enabled: true,
    },
  };
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  process.stdout.write(`  ✓ Keypair generated (kid: ${keypair.kid})\n`);
  process.stdout.write(`  ✓ Policy created (shadow mode, all tools logged)\n`);
  process.stdout.write(`  ✓ Signing enabled (Ed25519)\n\n`);

  // --connect: create sandbox dashboard and update config
  if (connectFlag) {
    process.stdout.write(`${bold('Connecting to ScopeBlind dashboard...')}\n\n`);
    const dashboardUrl = await createSandbox();
    if (dashboardUrl) {
      // Add dashboard_url to the quickstart config
      const updatedConfig = { ...config, dashboard_url: dashboardUrl };
      writeFileSync(configPath, JSON.stringify(updatedConfig, null, 2) + '\n');

      process.stdout.write(green(`  ✓ Dashboard created: ${dashboardUrl}\n`));
      process.stdout.write(`    Receipts will be uploaded automatically.\n`);
      process.stdout.write(dim(`    Free tier: 20,000 receipts/month, no credit card required.\n`));
      process.stdout.write(`\n`);
    }
  }

  process.stdout.write(`${bold('Starting demo server...')}\n\n`);
  process.stdout.write(`  Every tool call will produce a signed receipt.\n`);
  process.stdout.write(`  Try it with Claude Desktop or any MCP client.\n\n`);
  process.stdout.write(`  ${bold('To use in production:')}\n`);
  process.stdout.write(`    1. Copy ${configPath} to your project\n`);
  process.stdout.write(`    2. Edit tool policies to match your server\n`);
  process.stdout.write(`    3. Run: protect-mcp --policy protect-mcp.json -- node your-server.js\n\n`);
  process.stdout.write(`${'─'.repeat(50)}\n\n`);

  // Set env and run demo
  process.env.PROTECT_MCP_CONFIG = configPath;
  await handleDemo();
}

async function handleRegistry(argv: string[]): Promise<void> {
  const subcommand = argv[0] || 'status';
  const dir = resolveCli(flagValue(argv, '--dir') || process.cwd());
  const orgName = flagValue(argv, '--org') || process.env.SCOPEBLIND_ORG;
  const orgId = flagValue(argv, '--org-id') || process.env.SCOPEBLIND_ORG_ID;
  const billingAccountId = flagValue(argv, '--billing-account') || process.env.SCOPEBLIND_BILLING_ACCOUNT;
  const endpoint = flagValue(argv, '--endpoint') || process.env.SCOPEBLIND_REGISTRY_ENDPOINT || (argv.includes('--hosted') ? 'https://api.scopeblind.com' : undefined);
  const token = flagValue(argv, '--token') || process.env.SCOPEBLIND_TOKEN;
  const verifierBaseUrl = flagValue(argv, '--verifier-base') || process.env.SCOPEBLIND_VERIFIER_BASE || 'https://legate.scopeblind.com';

  const registryMod = await import('./receipt-registry.js');

  if (subcommand === 'init') {
    const identity = registryMod.createOrgIdentity({
      dir,
      orgName,
      orgId,
      billingAccountId,
    });
    const path = registryMod.writeOrgIdentity(dir, identity);
    process.stdout.write(`\n${bold('protect-mcp registry init')}\n\n`);
    process.stdout.write(`  Org:              ${identity.org_name}\n`);
    process.stdout.write(`  Org ID:           ${identity.org_id}\n`);
    process.stdout.write(`  Billing account:  ${identity.billing_account_id}\n`);
    process.stdout.write(`  Public keys:      ${identity.public_key_directory.length}\n`);
    process.stdout.write(`  Wrote:            ${path}\n\n`);
    process.stdout.write(`${dim('No prompts, tool payloads, raw receipts, or private keys are included.')}\n\n`);
    return;
  }

  if (subcommand === 'anchor') {
    process.stdout.write(`\n${bold('protect-mcp registry anchor')}\n\n`);
    const result = await registryMod.createReceiptRegistry({
      dir,
      orgName,
      orgId,
      billingAccountId,
      endpoint,
      token,
      hosted: argv.includes('--hosted') || Boolean(endpoint || token),
      verifierBaseUrl,
      outPath: flagValue(argv, '--output'),
    });
    process.stdout.write(`  Org:              ${result.registry.org.org_name}\n`);
    process.stdout.write(`  Billing account:  ${result.registry.billing.billing_account_id}\n`);
    process.stdout.write(`  Digests:          ${result.registry.records.length}\n`);
    process.stdout.write(`  Anchors:          ${result.registry.anchors.length}\n`);
    process.stdout.write(`  Boundary:         ${result.uploaded ? green('hosted digest anchor') : yellow('local preview only')}\n`);
    process.stdout.write(`  Registry:         ${result.registryPath}\n`);
    process.stdout.write(`  Verifier page:    ${result.verifierPath}\n\n`);
    process.stdout.write(`  Uploaded fields:  ${result.registry.privacy.uploaded_fields.join(', ')}\n`);
    process.stdout.write(`  Excluded fields:  ${result.registry.privacy.excluded_fields.join(', ')}\n\n`);
    if (!result.uploaded) {
      process.stdout.write(`${yellow('  This is not an independent timestamp yet.')}\n`);
      process.stdout.write(`  Run with ${dim('--hosted --token $SCOPEBLIND_TOKEN')} to make the paid boundary real.\n\n`);
    }
    return;
  }

  if (subcommand === 'status') {
    const registryPath = joinCli(dir, registryMod.REGISTRY_FILE);
    const identityPath = joinCli(dir, registryMod.ORG_IDENTITY_FILE);
    process.stdout.write(`\n${bold('protect-mcp registry status')}\n\n`);
    if (existsSyncCli(identityPath)) {
      const identity = JSON.parse(readFileSyncCli(identityPath, 'utf-8')) as Record<string, unknown>;
      process.stdout.write(`  Org:              ${identity.org_name || 'unknown'}\n`);
      process.stdout.write(`  Org ID:           ${identity.org_id || 'unknown'}\n`);
      process.stdout.write(`  Billing account:  ${identity.billing_account_id || 'unknown'}\n`);
    } else {
      process.stdout.write(`  Org identity:     ${yellow('missing')} (${identityPath})\n`);
    }
    if (existsSyncCli(registryPath)) {
      const registry = JSON.parse(readFileSyncCli(registryPath, 'utf-8')) as Record<string, any>;
      const hosted = Array.isArray(registry.anchors) && registry.anchors.some((a: any) => a.timestamp_source === 'scopeblind-hosted');
      process.stdout.write(`  Registry:         ${registryPath}\n`);
      process.stdout.write(`  Digests:          ${registry.records?.length || 0}\n`);
      process.stdout.write(`  Anchors:          ${registry.anchors?.length || 0}\n`);
      process.stdout.write(`  Boundary:         ${hosted ? green('hosted digest anchor') : yellow('local preview only')}\n`);
      process.stdout.write(`  Verifier page:    ${joinCli(dir, registryMod.VERIFIER_PAGE_FILE)}\n`);
    } else {
      process.stdout.write(`  Registry:         ${yellow('missing')} (${registryPath})\n`);
      process.stdout.write(`  Next:             ${dim('npx protect-mcp registry anchor --hosted')}\n`);
    }
    process.stdout.write(`\n`);
    return;
  }

  process.stderr.write('Usage: protect-mcp registry init|anchor|status [--dir <path>] [--org <name>] [--hosted]\\n');
  process.exit(1);
}

async function handleKillerDemo(argv: string[]): Promise<void> {
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { ed25519 } = await import('@noble/curves/ed25519');
  const { bytesToHex } = await import('@noble/hashes/utils');
  const { randomBytes } = await import('node:crypto');
  const artifacts = await import('@veritasacta/artifacts');
  const {
    createSelectiveDisclosurePackage,
    signCommittedDecision,
    verifySelectiveDisclosurePackage,
  } = await import('./signing-committed.js');
  const registryMod = await import('./receipt-registry.js');

  const dir = resolveCli(flagValue(argv, '--dir') || mkdtempSync(joinCli(tmpdir(), 'scopeblind-killer-demo-')));
  mkdirSyncCli(dir, { recursive: true });
  mkdirSyncCli(joinCli(dir, 'keys'), { recursive: true });
  mkdirSyncCli(joinCli(dir, 'receipts'), { recursive: true });

  const privateKeyBytes = randomBytes(32);
  const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
  const keypair = {
    privateKey: bytesToHex(privateKeyBytes),
    publicKey: bytesToHex(publicKeyBytes),
    kid: `killer-demo-${Date.now()}`,
    issuer: 'scopeblind-killer-demo',
  };
  const keyPath = joinCli(dir, 'keys', 'gateway.json');
  writeFileSyncCli(keyPath, JSON.stringify({
    ...keypair,
    generated_at: new Date().toISOString(),
    warning: 'Demo key only. Do not use for production.',
  }, null, 2) + '\n');

  const shadowConfigPath = joinCli(dir, 'protect-mcp.shadow.json');
  const policyPackPath = joinCli(dir, 'protect-mcp.policy-pack.json');
  const config = {
    tools: { '*': { rate_limit: '100/hour' } },
    default_tier: 'signed-known',
    signing: { key_path: keyPath, issuer: keypair.issuer, enabled: true },
  };
  const policyPack = {
    tools: {
      '*': { rate_limit: '100/hour' },
      read_file: { rate_limit: '60/hour' },
      github_create_pr: { require_approval: true, min_tier: 'signed-known', rate_limit: '10/hour' },
      send_email: { require_approval: true, min_tier: 'signed-known', rate_limit: '10/hour' },
      pms_book_fill: { require_approval: true, min_tier: 'signed-known', rate_limit: '10/hour' },
      delete_file: { block: true, min_tier: 'privileged' },
    },
    default_tier: 'signed-known',
    signing: { key_path: keyPath, issuer: keypair.issuer, enabled: true },
    notes: ['Demo policy pack: approvals for GitHub, email, and PMS booking; destructive tools blocked.'],
  };
  writeFileSyncCli(shadowConfigPath, JSON.stringify(config, null, 2) + '\n');
  writeFileSyncCli(policyPackPath, JSON.stringify(policyPack, null, 2) + '\n');

  await initSigning({ enabled: true, key_path: keyPath, issuer: keypair.issuer });
  const logPath = joinCli(dir, '.protect-mcp-log.jsonl');
  const receiptPath = joinCli(dir, '.protect-mcp-receipts.jsonl');

  const shadowCalls = [
    { tool: 'read_file', input: { path: '/research/macro-notes.md' }, reason: 'observe_mode' },
    { tool: 'github_create_pr', input: { repo: 'scopeblind/legate', branch: 'agent/pms-adapter', title: 'Wire mock PMS adapter' }, reason: 'observe_mode' },
    { tool: 'send_email', input: { to: 'ops@examplefund.com', subject: 'Booking update', body: 'Draft only', api_key: 'demo-secret' }, reason: 'observe_mode' },
    { tool: 'pms_book_fill', input: { account: 'Meridian Global Macro', symbol: 'AAPL', side: 'BUY', quantity: 50, price: 182.4, strategy: 'US Large Cap Tactical', bearerToken: 'demo-secret' }, reason: 'observe_mode' },
  ];

  for (const [idx, call] of shadowCalls.entries()) {
    const requestId = `demo-shadow-${idx + 1}`;
    appendFileSyncCli(logPath, JSON.stringify({
      v: 2,
      tool: call.tool,
      decision: 'allow',
      reason_code: call.reason,
      request_id: requestId,
      timestamp: Date.now() + idx,
      mode: 'shadow',
      policy_digest: 'shadow-policy',
      action_readback: buildActionReadback(call.tool, call.input),
    }) + '\n');
  }

  const sensitiveInput = {
    account: 'Meridian Global Macro',
    symbol: 'AAPL',
    side: 'BUY',
    quantity: 50,
    price: 182.4,
    strategy: 'US Large Cap Tactical',
    trader_note: 'Do not reveal portfolio context outside the desk.',
    api_key: 'demo-pms-secret',
  };
  const readback = buildActionReadback('pms_book_fill', sensitiveInput);
  const requestId = 'demo-sensitive-pms-booking';
  const requireApprovalEntry = {
    v: 2,
    tool: 'pms_book_fill',
    decision: 'require_approval',
    reason_code: 'requires_human_approval',
    request_id: requestId,
    timestamp: Date.now() + 10,
    mode: 'enforce',
    policy_digest: createHashCli('sha256').update(JSON.stringify(policyPack)).digest('hex').slice(0, 16),
    action_readback: readback,
  };
  appendFileSyncCli(logPath, JSON.stringify(requireApprovalEntry) + '\n');
  appendFileSyncCli(joinCli(dir, '.protect-mcp-approval-resolutions.jsonl'), JSON.stringify({
    type: 'scopeblind.approval_resolution.v1',
    at: new Date().toISOString(),
    request_id: requestId,
    tool: 'pms_book_fill',
    resolution: 'approve',
    reason: 'Matches the ticket and stays inside mandate.',
    payload_hash: readback.payload_hash,
  }) + '\n');

  const executedEntry = {
    ...requireApprovalEntry,
    decision: 'allow',
    reason_code: 'approval_granted',
    timestamp: Date.now() + 20,
    payload_digest: {
      output_hash: createHashCli('sha256').update('mock-pms-booking-confirmed').digest('hex'),
      output_size: 26,
      truncated: false,
    },
  };
  appendFileSyncCli(logPath, JSON.stringify(executedEntry) + '\n');
  const signed = signDecision(executedEntry as any);
  if (!signed.signed) throw new Error(`demo signing failed: ${signed.warning || signed.error || 'unknown'}`);
  appendFileSyncCli(receiptPath, signed.signed + '\n');
  writeFileSyncCli(joinCli(dir, 'receipts', 'approved-pms-booking.receipt.json'), JSON.stringify(JSON.parse(signed.signed), null, 2) + '\n');

  const receiptArtifact = JSON.parse(signed.signed);
  const tamperedArtifact = JSON.parse(signed.signed);
  if (tamperedArtifact.payload && typeof tamperedArtifact.payload === 'object') {
    tamperedArtifact.payload.decision = 'deny';
    tamperedArtifact.payload.tool = 'send_email';
  } else {
    tamperedArtifact.tool = 'send_email';
  }
  const validOriginal = artifacts.verifyArtifact(receiptArtifact, keypair.publicKey);
  const validTampered = artifacts.verifyArtifact(tamperedArtifact, keypair.publicKey);
  writeFileSyncCli(joinCli(dir, 'receipts', 'tampered.receipt.json'), JSON.stringify(tamperedArtifact, null, 2) + '\n');

  const committed = signCommittedDecision(
    executedEntry as any,
    ['tool', 'payload_digest', 'swarm'],
    keypair.privateKey,
    keypair.publicKey,
    keypair.kid,
    keypair.issuer,
  );
  const committedReceipt = JSON.parse(committed.signed);
  const disclosurePackage = createSelectiveDisclosurePackage(committedReceipt, ['tool'], committed.openings);
  const disclosureVerification = verifySelectiveDisclosurePackage(committedReceipt, disclosurePackage);
  appendFileSyncCli(receiptPath, committed.signed + '\n');
  writeFileSyncCli(joinCli(dir, 'receipts', 'selective-disclosure.receipt.json'), JSON.stringify(committedReceipt, null, 2) + '\n');
  writeFileSyncCli(joinCli(dir, 'receipts', 'selective-disclosure.package.json'), JSON.stringify(disclosurePackage, null, 2) + '\n');
  writeFileSyncCli(joinCli(dir, 'receipts', 'selective-disclosure.tool-only.json'), JSON.stringify(disclosurePackage, null, 2) + '\n');
  writeFileSyncCli(joinCli(dir, 'verification-results.json'), JSON.stringify({
    original_receipt_valid: validOriginal,
    tampered_receipt_valid: validTampered,
    selective_disclosure_valid: disclosureVerification.valid,
    selective_disclosure_explanation: disclosureVerification.explanation,
  }, null, 2) + '\n');

  const registry = await registryMod.createReceiptRegistry({
    dir,
    orgName: flagValue(argv, '--org') || 'Meridian Global Macro Demo',
    billingAccountId: flagValue(argv, '--billing-account') || 'demo_billing_digest_only',
    hosted: argv.includes('--hosted'),
    endpoint: flagValue(argv, '--endpoint') || process.env.SCOPEBLIND_REGISTRY_ENDPOINT || (argv.includes('--hosted') ? 'https://api.scopeblind.com' : undefined),
    token: flagValue(argv, '--token') || process.env.SCOPEBLIND_TOKEN,
    verifierBaseUrl: flagValue(argv, '--verifier-base') || 'https://legate.scopeblind.com',
  });

  const runbook = [
    '# ScopeBlind Killer Demo',
    '',
    'Three-minute flow, generated locally.',
    '',
    '## 1. Agent has tools',
    '',
    'Mock tools represented: filesystem `read_file`, GitHub `github_create_pr`, email `send_email`, and PMS `pms_book_fill`.',
    '',
    '## 2. Shadow mode shows risk',
    '',
    'Open the dashboard against this directory:',
    '',
    '```bash',
    `npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`,
    '```',
    '',
    'You will see GitHub, email, and PMS calls ranked as high risk.',
    '',
    '## 3. Apply policy pack',
    '',
    `Policy pack: \`${policyPackPath}\`.`,
    '',
    'It requires approval for GitHub PRs, outbound email, and PMS booking; destructive file deletion is blocked.',
    '',
    '## 4. Sensitive action requires exact approval',
    '',
    `Request id: \`${requestId}\``,
    '',
    `Exact readback summary: \`${readback.summary}\``,
    '',
    `Payload hash: \`${readback.payload_hash}\``,
    '',
    'Secret-like fields are redacted from the approval preview but still affect the hash.',
    '',
    '## 5. User approves; tool executes through gateway',
    '',
    'Approval resolution: `.protect-mcp-approval-resolutions.jsonl`',
    '',
    'Signed receipt: `receipts/approved-pms-booking.receipt.json`',
    '',
    '## 6. Offline verification and tamper failure',
    '',
    'Verification result: `verification-results.json`.',
    '',
    'Expected: original valid, tampered invalid.',
    '',
    '## 7. Selective disclosure',
    '',
    'Committed receipt: `receipts/selective-disclosure.receipt.json`',
    '',
    'Tool-only v0 disclosure package: `receipts/selective-disclosure.tool-only.json`',
    '',
    'The disclosure opens only the committed `tool` field. Other committed fields, such as `payload_digest`, remain hidden but bound to the signed `committed_fields_root`.',
    '',
    'This demonstrates hiding sensitive context while revealing the minimum needed proof. It is salted commitment disclosure, not full zero-knowledge.',
    '',
    '## 8. Paid boundary MVP',
    '',
    `Registry: \`${registry.registryPath}\``,
    '',
    `Verifier page: \`${registry.verifierPath}\``,
    '',
    `Boundary: ${registry.uploaded ? 'hosted digest anchor with independent timestamp' : 'local preview only; hosted anchoring not used'}.`,
    '',
    'No raw prompt, payload, output, private key, or raw receipt is uploaded by the registry flow. Hosted mode submits receipt digests, request ids, org public keys, and billing account metadata only.',
    '',
  ].join('\n');
  writeFileSyncCli(joinCli(dir, 'DEMO-RUNBOOK.md'), runbook);
  writeFileSyncCli(joinCli(dir, 'demo-summary.json'), JSON.stringify({
    dir,
    dashboard_command: `npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`,
    policy_pack: policyPackPath,
    receipt: joinCli(dir, 'receipts', 'approved-pms-booking.receipt.json'),
    tampered_receipt: joinCli(dir, 'receipts', 'tampered.receipt.json'),
    selective_disclosure_receipt: joinCli(dir, 'receipts', 'selective-disclosure.receipt.json'),
    selective_disclosure_package: joinCli(dir, 'receipts', 'selective-disclosure.tool-only.json'),
    verification_results: joinCli(dir, 'verification-results.json'),
    registry: registry.registryPath,
    verifier_page: registry.verifierPath,
    runbook: joinCli(dir, 'DEMO-RUNBOOK.md'),
    original_valid: validOriginal.valid,
    tampered_valid: validTampered.valid,
    selective_disclosure_valid: disclosureVerification.valid,
  }, null, 2) + '\n');

  process.stdout.write(`\n${bold('protect-mcp killer-demo')}\n\n`);
  process.stdout.write(`  Demo dir:          ${dir}\n`);
  process.stdout.write(`  Dashboard:         ${dim(`npx protect-mcp dashboard --dir ${dir} --policy ${policyPackPath} --open`)}\n`);
  process.stdout.write(`  Runbook:           ${joinCli(dir, 'DEMO-RUNBOOK.md')}\n`);
  process.stdout.write(`  Signed receipt:    ${joinCli(dir, 'receipts', 'approved-pms-booking.receipt.json')}\n`);
  process.stdout.write(`  Tamper check:      original=${validOriginal.valid ? green('valid') : red('invalid')} tampered=${validTampered.valid ? red('valid') : green('invalid')}\n`);
  process.stdout.write(`  Registry:          ${registry.registryPath}\n`);
  process.stdout.write(`  Verifier page:     ${registry.verifierPath}\n`);
  process.stdout.write(`  Boundary:          ${registry.uploaded ? green('hosted digest anchor') : yellow('local preview only')}\n\n`);
}

async function handleVerifyDisclosure(argv: string[]): Promise<void> {
  const receiptPath = flagValue(argv, '--receipt');
  const disclosurePath = flagValue(argv, '--disclosure');
  if (!receiptPath || !disclosurePath) {
    process.stderr.write('Usage: protect-mcp verify-disclosure --receipt <committed-receipt.json> --disclosure <selective-disclosure.json>\\n');
    process.exit(1);
  }
  const { verifySelectiveDisclosurePackage } = await import('./signing-committed.js');
  const receipt = JSON.parse(readFileSyncCli(resolveCli(receiptPath), 'utf-8')) as Record<string, unknown>;
  const disclosure = JSON.parse(readFileSyncCli(resolveCli(disclosurePath), 'utf-8')) as any;
  const result = verifySelectiveDisclosurePackage(receipt, disclosure);

  process.stdout.write(`\n${bold('protect-mcp verify-disclosure')}\n\n`);
  process.stdout.write(`  Result:           ${result.valid ? green('valid') : red('invalid')}\n`);
  process.stdout.write(`  Receipt hash:     ${result.receipt_hash_valid ? green('matches') : red('mismatch')}\n`);
  process.stdout.write(`  Signature:        ${result.signature_valid === true ? green('valid') : result.signature_valid === null ? yellow('not checked') : red('invalid')}\n`);
  process.stdout.write(`  Commitment root:  ${result.commitment_root_valid ? green('matches') : red('mismatch')}\n`);
  process.stdout.write(`  Disclosed fields: ${result.disclosed_fields.length ? result.disclosed_fields.join(', ') : 'none'}\n`);
  process.stdout.write(`  Hidden fields:    ${result.hidden_fields.length ? result.hidden_fields.join(', ') : 'none'}\n\n`);
  for (const line of result.explanation) {
    process.stdout.write(`  - ${line}\n`);
  }
  if (result.errors.length > 0) {
    process.stdout.write(`\n${red('Errors:')}\n`);
    for (const err of result.errors) process.stdout.write(`  - ${err}\n`);
  }
  process.stdout.write('\n');
  if (!result.valid) process.exit(2);
}

async function handlePolicyPacks(argv: string[]): Promise<void> {
  const subcommand = argv[0] || 'list';
  const packArg = argv[1];
  const dir = resolveCli(flagValue(argv, '--dir') || './cedar');
  const force = argv.includes('--force');

  if (subcommand === 'list') {
    process.stdout.write(`\n${bold('protect-mcp policy-packs')}\n\n`);
    for (const pack of POLICY_PACKS) {
      process.stdout.write(`  ${bold(pack.id.padEnd(22))} ${pack.name}\n`);
      process.stdout.write(`  ${dim(' '.repeat(24) + pack.description)}\n`);
      process.stdout.write(`  ${dim(' '.repeat(24) + `recommended: ${pack.recommendedMode}`)}\n\n`);
    }
    process.stdout.write(`Install one: ${dim('protect-mcp policy-packs install filesystem-safe --dir ./cedar')}\n`);
    process.stdout.write(`Install all: ${dim('protect-mcp policy-packs install all --dir ./cedar')}\n\n`);
    return;
  }

  if (subcommand === 'show') {
    const pack = getPolicyPack(packArg || '');
    if (!pack) {
      process.stderr.write(`Unknown policy pack "${packArg || ''}". Available: ${policyPackIds().join(', ')}\n`);
      process.exit(1);
    }
    process.stdout.write(`\n${bold(pack.name)} (${pack.id})\n\n`);
    process.stdout.write(`${pack.description}\n`);
    process.stdout.write(`Recommended rollout: ${pack.recommendedMode}\n\n`);
    for (const file of pack.files) {
      process.stdout.write(`${dim(`--- ${file.path} ---`)}\n`);
      process.stdout.write(file.contents.endsWith('\n') ? file.contents : `${file.contents}\n`);
      process.stdout.write('\n');
    }
    return;
  }

  if (subcommand === 'install') {
    const packs = packArg === 'all'
      ? POLICY_PACKS
      : [getPolicyPack(packArg || '')].filter(Boolean) as typeof POLICY_PACKS;
    if (packs.length === 0) {
      process.stderr.write(`Usage: protect-mcp policy-packs install <${policyPackIds().join('|')}|all> [--dir ./cedar] [--force]\n`);
      process.exit(1);
    }
    mkdirSyncCli(dir, { recursive: true });
    const written: string[] = [];
    for (const pack of packs) {
      for (const file of pack.files) {
        const outPath = joinCli(dir, file.path);
        if (existsSyncCli(outPath) && !force) {
          process.stderr.write(`Refusing to overwrite ${outPath}. Re-run with --force if intentional.\n`);
          process.exit(1);
        }
        writeFileSyncCli(outPath, file.contents.endsWith('\n') ? file.contents : `${file.contents}\n`);
        written.push(outPath);
      }
    }
    process.stdout.write(`\n${bold('protect-mcp policy-packs install')}\n\n`);
    process.stdout.write(`  Directory: ${dir}\n`);
    for (const outPath of written) process.stdout.write(`  Wrote:     ${outPath}\n`);
    process.stdout.write(`\nNext: ${dim(`protect-mcp serve --cedar ${dir}`)} for shadow mode, then add ${dim('--enforce')} after reviewing receipts.\n\n`);
    return;
  }

  process.stderr.write('Usage: protect-mcp policy-packs list|show|install [pack] [--dir ./cedar] [--force]\n');
  process.exit(1);
}

async function handleConnectors(argv: string[]): Promise<void> {
  const subcommand = argv[0] || 'list';
  const pilotArg = argv[1];
  const dir = resolveCli(flagValue(argv, '--dir') || process.cwd());
  const force = argv.includes('--force');

  if (subcommand === 'list') {
    process.stdout.write(`\n${bold('protect-mcp connector pilots')}\n\n`);
    for (const pilot of CONNECTOR_PILOTS) {
      process.stdout.write(`  ${bold(pilot.id.padEnd(18))} ${pilot.name}\n`);
      process.stdout.write(`  ${dim(' '.repeat(20) + pilot.description)}\n`);
      process.stdout.write(`  ${dim(' '.repeat(20) + `tools: ${pilot.tools.join(', ')}`)}\n\n`);
    }
    process.stdout.write(`Install all: ${dim('protect-mcp connectors init all --force')}\n`);
    process.stdout.write(`Check credentials: ${dim('protect-mcp connectors doctor')}\n\n`);
    return;
  }

  if (subcommand === 'show') {
    const pilot = getConnectorPilot(pilotArg || '');
    if (!pilot) {
      process.stderr.write(`Unknown connector pilot "${pilotArg || ''}". Available: ${CONNECTOR_PILOTS.map((p) => p.id).join(', ')}\n`);
      process.exit(1);
    }
    process.stdout.write(`\n${bold(pilot.name)} (${pilot.id})\n\n`);
    process.stdout.write(`${pilot.description}\n\n`);
    process.stdout.write(`${bold('Why it matters:')} ${pilot.value}\n\n`);
    process.stdout.write(`${bold('Tools:')} ${pilot.tools.join(', ')}\n\n`);
    process.stdout.write(`${bold('Setup:')}\n`);
    for (const step of pilot.setup) process.stdout.write(`  - ${step}\n`);
    process.stdout.write(`\n${bold('Starter policy:')}\n${pilot.cedar}\n`);
    return;
  }

  if (subcommand === 'init') {
    const ids = pilotArg ? [pilotArg] : ['all'];
    const installed = writeConnectorPilots({ dir, ids, force });
    process.stdout.write(`\n${bold('protect-mcp connectors init')}\n\n`);
    process.stdout.write(`  Directory: ${installed.directory}\n`);
    for (const outPath of installed.written) process.stdout.write(`  Wrote:     ${outPath}\n`);
    process.stdout.write(`\nNext: ${dim('protect-mcp connectors doctor')} then ${dim('protect-mcp dashboard --open')}.\n\n`);
    return;
  }

  if (subcommand === 'doctor') {
    let rows = connectorDoctor(dir);
    if (pilotArg && pilotArg !== 'all') {
      const pilot = getConnectorPilot(pilotArg);
      if (!pilot) {
        process.stderr.write(`Unknown connector pilot "${pilotArg}". Available: ${CONNECTOR_PILOTS.map((p) => p.id).join(', ')}\n`);
        process.exit(1);
      }
      rows = rows.filter((row) => row.id === pilot.id);
    }
    process.stdout.write(`\n${bold('protect-mcp connectors doctor')}\n\n`);
    for (const row of rows) {
      const missing = Array.isArray(row.missing_required) && row.missing_required.length > 0 ? row.missing_required.join(', ') : '';
      const status = row.installed ? (row.usable ? green('ready') : yellow('needs setup')) : dim('not installed');
      process.stdout.write(`  ${bold(String(row.id).padEnd(18))} ${status}\n`);
      process.stdout.write(`  ${dim(' '.repeat(20) + `mode: ${String(row.mode || 'unknown')}`)}\n`);
      if (missing) process.stdout.write(`  ${yellow(' '.repeat(20) + `missing: ${missing}`)}\n`);
      process.stdout.write(`  ${dim(' '.repeat(20) + String(row.next || ''))}\n\n`);
    }
    process.stdout.write(`${dim('Secret values are never printed; only missing variable names are shown.')}\n\n`);
    return;
  }

  process.stderr.write('Usage: protect-mcp connectors list|show|init|doctor [connector|all] [--dir <path>] [--force]\n');
  process.exit(1);
}

/**
 * Handle the `trace` command: ASCII DAG visualizer.
 * Queries the evidence indexer for the receipt's graph and renders it.
 */
async function handleTrace(argv: string[]): Promise<void> {
  const receiptId = argv[0];
  if (!receiptId) {
    process.stderr.write('[PROTECT_MCP] Usage: protect-mcp trace <receipt_id> [--endpoint <url>] [--depth <n>]\n');
    process.exit(1);
  }

  let endpoint = 'https://api.scopeblind.com/evidence';
  let depth = 3;

  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === '--endpoint' && argv[i + 1]) {
      endpoint = argv[++i];
    } else if (argv[i] === '--depth' && argv[i + 1]) {
      depth = Math.min(10, Math.max(1, parseInt(argv[++i], 10) || 3));
    }
  }

  process.stdout.write(`\n${bold('protect-mcp trace')}\n`);
  process.stdout.write(`${'─'.repeat(60)}\n\n`);
  process.stdout.write(`  Root:     ${receiptId}\n`);
  process.stdout.write(`  Endpoint: ${endpoint}\n`);
  process.stdout.write(`  Depth:    ${depth}\n\n`);

  // Fetch graph
  const url = `${endpoint}/evidence/graph/${encodeURIComponent(receiptId)}?depth=${depth}&direction=both&max=50`;
  let graphData: any;

  try {
    const resp = await fetch(url);
    if (!resp.ok) {
      const body = await resp.text();
      process.stderr.write(`[PROTECT_MCP] Error fetching graph: ${resp.status} ${body}\n`);
      process.exit(1);
    }
    graphData = await resp.json();
  } catch (err) {
    // If the remote indexer isn't reachable, try local receipts
    process.stderr.write(`[PROTECT_MCP] Could not reach evidence indexer at ${endpoint}\n`);
    process.stderr.write(`[PROTECT_MCP] Trying local receipts...\n\n`);
    await traceLocal(receiptId);
    return;
  }

  if (!graphData.nodes || graphData.nodes.length === 0) {
    process.stdout.write(`  No receipts found for ${receiptId}\n\n`);
    return;
  }

  // Render ASCII DAG
  process.stdout.write(`  ${bold('Evidence DAG')} (${graphData.node_count} nodes, ${graphData.edge_count} edges)\n\n`);

  // Build adjacency for rendering
  const nodeMap = new Map<string, any>();
  for (const node of graphData.nodes) {
    nodeMap.set(node.receipt_id, node);
  }

  const childMap = new Map<string, Array<{ to: string; relation: string }>>();
  for (const edge of graphData.edges) {
    if (!childMap.has(edge.from)) childMap.set(edge.from, []);
    childMap.get(edge.from)!.push({ to: edge.to, relation: edge.relation });
  }

  // DFS render from root
  const rendered = new Set<string>();

  function renderNode(id: string, prefix: string, isLast: boolean): void {
    const node = nodeMap.get(id);
    const connector = isLast ? '└── ' : '├── ';
    const childPrefix = isLast ? '    ' : '│   ';

    const typeEmoji = getTypeEmoji(node?.receipt_type || 'unknown');
    const shortId = id.length > 16 ? id.slice(0, 12) + '…' : id;
    const time = node?.event_time ? new Date(node.event_time).toLocaleTimeString() : '?';
    const type = node?.receipt_type?.replace('acta:', '') || 'unknown';

    process.stdout.write(`${prefix}${connector}${typeEmoji} ${bold(type)} ${dim(shortId)} ${dim(time)}\n`);

    if (rendered.has(id)) {
      process.stdout.write(`${prefix}${childPrefix}${dim('(cycle: already rendered)')}\n`);
      return;
    }
    rendered.add(id);

    const children = childMap.get(id) || [];
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const edgeLabel = dim(`──[${child.relation}]──▶`);
      process.stdout.write(`${prefix}${childPrefix}${edgeLabel}\n`);
      renderNode(child.to, prefix + childPrefix, i === children.length - 1);
    }
  }

  // Start from root
  const rootNode = nodeMap.get(receiptId);
  if (rootNode) {
    const typeEmoji = getTypeEmoji(rootNode.receipt_type);
    const type = rootNode.receipt_type?.replace('acta:', '') || 'unknown';
    const time = rootNode.event_time ? new Date(rootNode.event_time).toLocaleTimeString() : '?';
    process.stdout.write(`  ${typeEmoji} ${bold(type)} ${dim(receiptId.slice(0, 16) + '…')} ${dim(time)} ${bold('(root)')}\n`);
    rendered.add(receiptId);

    const children = childMap.get(receiptId) || [];
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const edgeLabel = dim(`──[${child.relation}]──▶`);
      process.stdout.write(`  ${edgeLabel}\n`);
      renderNode(child.to, '  ', i === children.length - 1);
    }

    // Also show incoming edges (nodes that point TO root)
    const incomingEdges = (graphData.edges || []).filter((e: any) => e.to === receiptId);
    if (incomingEdges.length > 0) {
      process.stdout.write(`\n  ${bold('Incoming edges:')}\n`);
      for (const edge of incomingEdges) {
        const fromNode = nodeMap.get(edge.from);
        const fromType = fromNode?.receipt_type?.replace('acta:', '') || 'unknown';
        process.stdout.write(`  ◀──[${edge.relation}]── ${getTypeEmoji(fromNode?.receipt_type)} ${fromType} ${dim(edge.from.slice(0, 16) + '…')}\n`);
      }
    }
  } else {
    // Root not found, render all nodes flat
    for (const node of graphData.nodes) {
      const typeEmoji = getTypeEmoji(node.receipt_type);
      const type = node.receipt_type?.replace('acta:', '') || 'unknown';
      process.stdout.write(`  ${typeEmoji} ${bold(type)} ${dim(node.receipt_id.slice(0, 16) + '…')}\n`);
    }
  }

  process.stdout.write(`\n${'─'.repeat(60)}\n`);
  process.stdout.write(`  ${dim(`Fetched from ${endpoint}`)}\n\n`);
}

/**
 * Trace local receipts (when remote indexer is not reachable).
 */
async function traceLocal(receiptId: string): Promise<void> {
  const { readFileSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');

  const dir = process.cwd();
  const receiptsDir = join(dir, '.protect-mcp', 'receipts');

  if (!existsSync(receiptsDir)) {
    process.stdout.write(`  No local receipts found in ${receiptsDir}\n\n`);
    return;
  }

  // Scan for the receipt
  const { readdirSync } = await import('node:fs');
  const files = readdirSync(receiptsDir).filter(f => f.endsWith('.json'));

  process.stdout.write(`  Scanning ${files.length} local receipts...\n\n`);

  const receipts: any[] = [];
  for (const file of files) {
    try {
      const content = readFileSync(join(receiptsDir, file), 'utf-8');
      const receipt = JSON.parse(content);
      receipts.push(receipt);
    } catch {
      // skip malformed
    }
  }

  const match = receipts.find(r =>
    r.signed_claims?.claims?.receipt_id === receiptId ||
    r.receipt_id === receiptId
  );

  if (match) {
    const claims = match.signed_claims?.claims || match;
    process.stdout.write(`  Found: ${getTypeEmoji(claims.receipt_type)} ${bold(claims.receipt_type?.replace('acta:', '') || 'unknown')}\n`);
    process.stdout.write(`  Event:  ${claims.event_id || '?'}\n`);
    process.stdout.write(`  Issuer: ${claims.issuer_id || '?'}\n`);
    process.stdout.write(`  Time:   ${claims.event_time || '?'}\n`);

    if (claims.edges && claims.edges.length > 0) {
      process.stdout.write(`\n  ${bold('Edges:')}\n`);
      for (const edge of claims.edges) {
        process.stdout.write(`    ──[${edge.relation}]──▶ ${dim(edge.receipt_id?.slice(0, 16) + '…')}\n`);
      }
    }
  } else {
    process.stdout.write(`  Receipt ${receiptId} not found locally.\n`);
  }
  process.stdout.write('\n');
}

function getTypeEmoji(type: string | undefined): string {
  switch (type) {
    case 'acta:observation': return '👁 ';
    case 'acta:policy-load': return '📋';
    case 'acta:approval': return '✅';
    case 'acta:decision': return '⚖️ ';
    case 'acta:execution': return '⚡';
    case 'acta:outcome': return '📦';
    case 'acta:delegation': return '🤝';
    case 'acta:capability-attestation': return '🏅';
    default: return '📄';
  }
}


/**
 * Handle the `init-hooks` command: generate Claude Code hook integration files.
 * Creates: .claude/settings.json hooks, sample Cedar policy, and /verify-receipt skill.
 */
async function handleInitHooks(argv: string[]): Promise<void> {
  const { writeFileSync, existsSync, mkdirSync, readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { generateHookSettings, generateSampleCedarPolicy, generateVerifyReceiptSkill } = await import('./hook-patterns.js');

  let dir = process.cwd();
  const dirIdx = argv.indexOf('--dir');
  if (dirIdx !== -1 && argv[dirIdx + 1]) dir = argv[dirIdx + 1];

  const portIdx = argv.indexOf('--port');
  const port = portIdx >= 0 && argv[portIdx + 1] ? parseInt(argv[portIdx + 1]) : 9377;

  const hookUrl = `http://127.0.0.1:${port}/hook`;

  process.stdout.write(`\n${bold('protect-mcp init-hooks')}\n`);
  process.stdout.write(`${'─'.repeat(55)}\n\n`);

  // 1. Generate .claude/settings.json hooks
  const claudeDir = join(dir, '.claude');
  const settingsPath = join(claudeDir, 'settings.json');
  let existingSettings: Record<string, unknown> = {};

  if (!existsSync(claudeDir)) {
    mkdirSync(claudeDir, { recursive: true });
  }

  if (existsSync(settingsPath)) {
    try {
      existingSettings = JSON.parse(readFileSync(settingsPath, 'utf-8'));
    } catch {
      process.stderr.write(`[PROTECT_MCP] Warning: Could not parse existing ${settingsPath}\n`);
    }
  }

  const hookSettings = generateHookSettings(hookUrl);
  const mergedSettings = {
    ...existingSettings,
    hooks: {
      ...(existingSettings.hooks as Record<string, unknown> || {}),
      ...(hookSettings.hooks as Record<string, unknown>),
    },
  };

  writeFileSync(settingsPath, JSON.stringify(mergedSettings, null, 2) + '\n');
  process.stdout.write(`  ${green('✓')} ${settingsPath}\n`);
  process.stdout.write(`    Hook URL: ${dim(hookUrl)}\n`);
  process.stdout.write(`    Events: PreToolUse, PostToolUse, SubagentStart/Stop, Task, Session, Config, Stop\n\n`);

  // 2. Generate signing keys if not present
  const keysDir = join(dir, 'keys');
  const keyPath = join(keysDir, 'gateway.json');
  if (!existsSync(keyPath)) {
    if (!existsSync(keysDir)) mkdirSync(keysDir, { recursive: true });

    const { randomBytes: rb } = await import('node:crypto');
    try {
      const { ed25519 } = await import('@noble/curves/ed25519');
      const { bytesToHex } = await import('@noble/hashes/utils');
      const privateKey = rb(32);
      const publicKey = ed25519.getPublicKey(privateKey);

      writeFileSync(keyPath, JSON.stringify({
        privateKey: bytesToHex(privateKey),
        publicKey: bytesToHex(publicKey),
        kid: `hook-${Date.now()}`,
        generated_at: new Date().toISOString(),
        warning: 'KEEP THIS FILE SECRET. Never commit to version control.',
      }, null, 2) + '\n');

      const gitignorePath = join(keysDir, '.gitignore');
      if (!existsSync(gitignorePath)) {
        writeFileSync(gitignorePath, '# Never commit signing keys\n*.json\n');
      }

      process.stdout.write(`  ${green('✓')} ${keyPath} (Ed25519 keypair)\n\n`);
    } catch {
      process.stdout.write(`  ${yellow('⚠')} Could not generate Ed25519 keys, signing disabled\n\n`);
    }
  } else {
    process.stdout.write(`  ${green('✓')} ${keyPath} (existing keys found)\n\n`);
  }

  // 3. Generate sample Cedar policy
  const policiesDir = join(dir, 'policies');
  const cedarPath = join(policiesDir, 'agent.cedar');
  if (!existsSync(cedarPath)) {
    if (!existsSync(policiesDir)) mkdirSync(policiesDir, { recursive: true });
    writeFileSync(cedarPath, generateSampleCedarPolicy());
    process.stdout.write(`  ${green('✓')} ${cedarPath}\n`);
    process.stdout.write(`    Edit to customize tool permissions. Cedar deny is AUTHORITATIVE.\n\n`);
  } else {
    process.stdout.write(`  ${green('✓')} ${cedarPath} (existing policy found)\n\n`);
  }

  // 4. Generate JSON policy config with signing reference
  const configPath = join(dir, 'protect-mcp.json');
  if (!existsSync(configPath)) {
    const config = {
      tools: { '*': { rate_limit: '100/hour' } },
      default_tier: 'unknown',
      signing: {
        key_path: './keys/gateway.json',
        issuer: 'protect-mcp',
        enabled: true,
      },
    };
    writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
    process.stdout.write(`  ${green('✓')} ${configPath}\n\n`);
  }

  // 5. Generate /verify-receipt skill
  const skillsDir = join(dir, '.claude', 'skills', 'verify-receipt');
  const skillPath = join(skillsDir, 'SKILL.md');
  if (!existsSync(skillPath)) {
    mkdirSync(skillsDir, { recursive: true });
    writeFileSync(skillPath, generateVerifyReceiptSkill());
    process.stdout.write(`  ${green('✓')} ${skillPath}\n`);
    process.stdout.write(`    Use ${dim('/verify-receipt')} in Claude Code to check audit trails.\n\n`);
  } else {
    process.stdout.write(`  ${green('✓')} ${skillPath} (existing skill found)\n\n`);
  }

  // Summary
  process.stdout.write(`${'─'.repeat(55)}\n\n`);
  process.stdout.write(`${bold('Next steps:')}\n\n`);
  process.stdout.write(`  1. Start the hook server:\n`);
  process.stdout.write(`     ${dim(`npx protect-mcp serve`)}\n\n`);
  process.stdout.write(`  2. Open a Claude Code session in this project.\n`);
  process.stdout.write(`     Every tool call will be receipted automatically.\n\n`);
  process.stdout.write(`  3. See your record: a searchable view of every decision.\n`);
  process.stdout.write(`     ${dim(`npx protect-mcp record`)}\n`);
  process.stdout.write(`     ${dim(`Everything stays on this machine. Nothing is uploaded.`)}\n\n`);
  process.stdout.write(`     Prefer the terminal? ${dim(`npx protect-mcp receipts`)}, or ${dim('/verify-receipt')} in Claude Code.\n\n`);
  process.stdout.write(`  4. View policy suggestions:\n`);
  process.stdout.write(`     ${dim(`curl http://127.0.0.1:${port}/suggestions`)}\n\n`);
  process.stdout.write(`${bold('Key facts:')}\n`);
  process.stdout.write(`  • deny decisions are ${bold('AUTHORITATIVE')}: they cannot be overridden\n`);
  process.stdout.write(`  • PostToolUse runs ${bold('async')}, so there is zero latency impact on tool execution\n`);
  process.stdout.write(`  • Receipts are Ed25519-signed and append-only\n`);
  process.stdout.write(`  • Swarm topology (coordinator/workers) is tracked automatically\n\n`);
}

/**
 * Fire-and-forget install telemetry. Runs once per machine, opt-out via
 * PROTECT_MCP_TELEMETRY=off. Errors are silently swallowed.
 */
async function sendInstallTelemetry(): Promise<void> {
  try {
    const { existsSync, mkdirSync, writeFileSync, readFileSync } = await import('node:fs');
    const { join, dirname } = await import('node:path');
    const { homedir } = await import('node:os');
    const { fileURLToPath } = await import('node:url');

    const markerDir = join(homedir(), '.protect-mcp');
    const markerFile = join(markerDir, '.telemetry-sent');

    if (existsSync(markerFile) || process.env.PROTECT_MCP_TELEMETRY === 'off') {
      return;
    }

    // Read version via the shared resolver (robust in the bundled CJS bin).
    const version = await pkgVersion();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    fetch('https://api.scopeblind.com/telemetry/install', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: 'protect-mcp',
        version,
        os: process.platform,
        arch: process.arch,
        node: process.version,
        ts: Date.now(),
      }),
      signal: controller.signal,
    })
      .catch(() => {})
      .finally(() => clearTimeout(timeout));

    // Create marker directory and file
    if (!existsSync(markerDir)) {
      mkdirSync(markerDir, { recursive: true });
    }
    writeFileSync(markerFile, String(Date.now()), 'utf-8');

    process.stderr.write(
      '[protect-mcp] Thanks for installing! Anonymous telemetry sent (disable: PROTECT_MCP_TELEMETRY=off)\n' +
      '[protect-mcp] Free dashboard: npx protect-mcp connect | https://scopeblind.com\n',
    );
  } catch {
    // Never crash the CLI for telemetry
  }
}

function flagValue(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : undefined;
}

/** Load a Cedar policy set from --cedar <dir> or --policy <file.cedar>. */
function loadPolicyArg(argv: string[]): CedarPolicySet | null {
  const cedarDir = flagValue(argv, '--cedar');
  const policyFile = flagValue(argv, '--policy');
  try {
    if (cedarDir) return loadCedarPolicies(cedarDir);
    if (policyFile && existsSyncCli(policyFile)) {
      return policySetFromSource(readFileSyncCli(policyFile, 'utf-8'), basenameCli(policyFile));
    }
  } catch {
    /* fall through to null */
  }
  return null;
}

/** Read a client hook payload from stdin (JSON) when one is piped. */
async function readHookStdin(): Promise<Record<string, unknown> | null> {
  if (process.stdin.isTTY) return null;
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
    const raw = Buffer.concat(chunks).toString('utf-8').trim();
    return raw ? (JSON.parse(raw) as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Map a host hook stdin payload to (tool, input). Claude Code, Codex, Gemini,
 * and Hermes all send tool_name + tool_input; Cursor's shell hook sends a bare
 * command. Field-name variants are tolerated.
 */
function mapHookPayload(j: Record<string, unknown>): { tool?: string; input?: unknown } {
  const tool = (j.tool_name ?? j.toolName) as string | undefined;
  const input = (j.tool_input ?? j.toolInput) as unknown;
  if (input === undefined && j.command !== undefined) {
    return { tool: tool ?? 'Bash', input: { command: j.command } };
  }
  return { tool, input };
}

/**
 * Emit a PreToolUse decision in the target host's hook contract and exit.
 * Every supported host blocks on a non-zero exit code EXCEPT Hermes, which
 * IGNORES exit codes and reads the verdict from stdout. A raw exit-2 would
 * therefore silently fail open in Hermes, so it gets an explicit branch.
 */
function emitDecision(format: string | undefined, allowed: boolean, reason: string): never {
  if (format === 'hermes') {
    process.stdout.write(JSON.stringify(allowed ? {} : { decision: 'block', reason }) + '\n');
    process.exit(0);
  }
  if (allowed) {
    process.stdout.write(JSON.stringify({ allowed: true, reason }) + '\n');
    process.exit(0);
  }
  // claude / codex / gemini / cursor / grok all block on exit code 2. For the
  // hosts that ALSO accept a structured stdout verdict, emit it too so the deny
  // holds even if a host stops honoring the exit code (belt and suspenders).
  if (format === 'cursor') {
    process.stdout.write(JSON.stringify({ permission: 'deny', userMessage: reason }) + '\n');
  } else if (format === 'gemini') {
    process.stdout.write(JSON.stringify({ decision: 'deny', reason }) + '\n');
  }
  process.stderr.write(`protect-mcp denied: ${reason}\n`);
  process.exit(2);
}

/**
 * One-shot Cedar evaluation for a PreToolUse hook. FAIL-CLOSED: a missing or
 * unloadable policy denies (exit 2) unless --fail-on-missing-policy false is set.
 * Exits 0 when allowed and 2 when denied (the host blocks the tool on exit 2).
 *
 * Pass --format <host> (claude|codex|gemini|cursor|hermes|grok) to read the
 * host's hook payload from stdin and emit the deny verdict in that host's
 * contract. Without --format it reads --tool/--input flags (the legacy mode).
 */
async function handleEvaluate(argv: string[]): Promise<void> {
  const format = flagValue(argv, '--format');
  let tool = flagValue(argv, '--tool') || '';
  let inputRaw = flagValue(argv, '--input') || '{}';
  const contextRaw = flagValue(argv, '--context');
  const failOnMissing = flagValue(argv, '--fail-on-missing-policy') !== 'false';

  // With --format, accept the host's hook payload from stdin (overrides flags).
  if (format) {
    const j = await readHookStdin();
    if (j) {
      const m = mapHookPayload(j);
      if (m.tool) tool = m.tool;
      if (m.input !== undefined) inputRaw = JSON.stringify(m.input);
    }
  }

  const policySet = loadPolicyArg(argv);
  if (!policySet) {
    if (failOnMissing) {
      if (format) emitDecision(format, false, 'policy not found (fail-closed)');
      process.stderr.write('protect-mcp evaluate: policy not found; denying (fail-closed). Pass --fail-on-missing-policy false to allow.\n');
      process.exit(2);
    }
    if (format) emitDecision(format, true, 'no_policy_configured');
    process.stdout.write(JSON.stringify({ allowed: true, reason: 'no_policy_configured' }) + '\n');
    process.exit(0);
  }

  let input: Record<string, unknown> = {};
  try { input = JSON.parse(inputRaw); } catch { /* tolerate non-JSON input */ }
  let extra: Record<string, unknown> = {};
  if (contextRaw) { try { extra = JSON.parse(contextRaw); } catch { /* ignore */ } }
  const context: Record<string, unknown> = { ...input, ...extra };
  // Convenience: expose the raw command as command_pattern when a policy expects it.
  if (typeof input.command === 'string' && context.command_pattern === undefined) {
    context.command_pattern = input.command;
  }

  // Pass the parsed --input through as toolInput so policies can match the
  // documented nested `context.input.*` shape (the evaluator maps toolInput ->
  // context.input). The flattened top-level fields above are kept for back-compat.
  const decision = await evaluateCedar(policySet, { tool, tier: 'unknown', context, toolInput: input }, undefined, { failClosed: true });
  if (format) emitDecision(format, decision.allowed, decision.reason || (decision.allowed ? 'allowed' : 'denied by policy'));
  process.stdout.write(JSON.stringify({ allowed: decision.allowed, reason: decision.reason, policy_digest: policySet.digest }) + '\n');
  process.exit(decision.allowed ? 0 : 2);
}

/**
 * One-shot signed receipt for a PostToolUse hook. Appends an Ed25519-signed
 * receipt to the receipts directory when a key is configured. Never blocks the
 * tool: a missing signer records an honest unsigned line rather than failing.
 *
 * Pass --format <host> to read the host's PostToolUse payload from stdin. Since
 * PostToolUse never blocks, the only host-specific behavior is emitting a no-op
 * verdict ({}) for Hermes, which reads stdout.
 */
async function handleSign(argv: string[]): Promise<void> {
  const format = flagValue(argv, '--format');
  let tool = flagValue(argv, '--tool') || '';
  const receiptsDir = flagValue(argv, '--receipts') || './receipts/';
  const keyPath = flagValue(argv, '--key');

  if (format) {
    const j = await readHookStdin();
    if (j) {
      const m = mapHookPayload(j);
      if (m.tool) tool = m.tool;
    }
  }

  if (keyPath && existsSyncCli(keyPath)) {
    try { await initSigning({ enabled: true, key_path: keyPath } as any); } catch { /* unsigned fallback below */ }
  }

  const requestId = `tu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const signed = signDecision({
    tool,
    decision: 'allow',
    reason_code: 'post_execution_receipt',
    policy_digest: 'none',
    request_id: requestId,
    mode: 'enforce',
    timestamp: Date.now(),
  } as any);

  try { mkdirSyncCli(receiptsDir, { recursive: true }); } catch { /* best-effort */ }
  const line = signed.signed ?? JSON.stringify({ tool, request_id: requestId, signed: false, note: signed.warning || 'no signer configured' });
  try { appendFileSyncCli(joinCli(receiptsDir, 'receipts.jsonl'), line + '\n'); } catch { /* best-effort */ }

  // PostToolUse never blocks; Hermes reads stdout, so emit a no-op verdict there.
  if (format === 'hermes') { process.stdout.write('{}\n'); process.exit(0); }
  process.stdout.write(JSON.stringify({ signed: Boolean(signed.signed), artifact_type: signed.artifact_type, request_id: requestId }) + '\n');
  process.exit(0);
}

async function main(): Promise<void> {
  // Fire-and-forget install telemetry (once per machine, opt-out via env)
  sendInstallTelemetry().catch(() => {});

  // Skip node + script path
  const args = process.argv.slice(2);

  // Resolve the real package version once so every banner, health endpoint,
  // and serverInfo block reports what the user actually installed.
  process.env.PROTECT_MCP_VERSION = process.env.PROTECT_MCP_VERSION || await pkgVersion();

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  // One-shot PreToolUse gate (fail-closed) and PostToolUse receipt signer. These
  // are what hook configs invoke per tool call (exit 0 allow, exit 2 deny).
  if (args[0] === 'evaluate') { await handleEvaluate(args.slice(1)); return; }
  if (args[0] === 'sign') { await handleSign(args.slice(1)); return; }

  // Handle serve command — Claude Code Hook Server
  if (args[0] === 'serve') {
    const { startHookServer } = await import('./hook-server.js');
    const portIdx = args.indexOf('--port');
    const port = portIdx >= 0 && args[portIdx + 1] ? parseInt(args[portIdx + 1]) : 9377;
    const policyIdx = args.indexOf('--policy');
    const policyPath = policyIdx >= 0 && args[policyIdx + 1] ? args[policyIdx + 1] : undefined;
    const cedarIdx = args.indexOf('--cedar');
    const cedarDir = cedarIdx >= 0 && args[cedarIdx + 1] ? args[cedarIdx + 1] : undefined;
    const enforce = args.includes('--enforce');
    const verbose = args.includes('--verbose') || args.includes('-v');

    // Proof of restraint: before arming an enforcing gate, prove it actually
    // denies a known-forbidden vector. If it cannot, refuse to serve (fail-closed)
    // rather than run a gate that might silently permit.
    if (enforce) {
      const selfTest = await runEvaluatorSelfTest();
      if (!selfTest.passed) {
        process.stderr.write('protect-mcp serve --enforce: the policy-engine restraint self-test FAILED. Refusing to arm the gate.\n');
        for (const c of selfTest.cases.filter((c) => !c.pass)) {
          process.stderr.write(`  [FAIL] ${c.name}: expected ${c.expected}, got ${c.actual}\n`);
        }
        process.exit(1);
      }
      if (verbose) process.stderr.write(`protect-mcp: restraint self-test passed (${selfTest.cases.length} vectors). Arming gate.\n`);
    }

    await startHookServer({ port, policyPath, cedarDir, enforce, verbose });
    return; // Server keeps running
  }

  // Handle record command — open a local, searchable view of your own receipts.
  // (Static mode exits inside handleRecord; --live keeps the process serving.)
  if (args[0] === 'record') {
    await handleRecord(args.slice(1));
    return;
  }

  // Handle claim / verify-claim — signed, position-blind attestations over the record
  if (args[0] === 'claim') { await handleClaim(args.slice(1)); return; }
  if (args[0] === 'verify-claim') { await handleVerifyClaim(args.slice(1)); return; }
  if (args[0] === 'anchor-record') { await handleAnchorRecord(args.slice(1)); return; }

  // Handle init-hooks command — Claude Code integration setup
  if (args[0] === 'init-hooks') {
    await handleInitHooks(args.slice(1));
    process.exit(0);
  }

  // Handle quickstart command
  if (args[0] === 'quickstart') {
    await handleQuickstart(args.slice(1));
    return; // demo keeps running
  }

  // Handle wrap command
  if (args[0] === 'wrap') {
    await handleWrap(args.slice(1));
    process.exit(0);
  }

  // Handle dashboard command
  if (args[0] === 'dashboard') {
    await handleDashboard(args.slice(1));
    return; // server keeps running
  }

  // Handle recommend command
  if (args[0] === 'recommend') {
    await handleRecommend(args.slice(1));
    process.exit(0);
  }

  // Handle registry command
  if (args[0] === 'registry') {
    await handleRegistry(args.slice(1));
    process.exit(0);
  }

  // Handle trial command — buyer-friendly alias for the complete proof pack.
  if (args[0] === 'trial') {
    await handleKillerDemo(args.slice(1));
    process.stdout.write(`${bold('Next: open the local dashboard')}\n`);
    process.stdout.write(`  npx protect-mcp dashboard --dir ${dim(flagValue(args.slice(1), '--dir') || '<demo dir printed above>')} --open\n\n`);
    process.stdout.write(`${dim('No ScopeBlind account is required for local receipts. Add --hosted with SCOPEBLIND_TOKEN when you want independent digest anchoring.')}\n\n`);
    process.exit(0);
  }

  // Handle killer-demo command
  if (args[0] === 'killer-demo') {
    await handleKillerDemo(args.slice(1));
    process.exit(0);
  }

  // Handle selective-disclosure verifier command
  if (args[0] === 'verify-disclosure') {
    await handleVerifyDisclosure(args.slice(1));
    process.exit(0);
  }

  // Handle starter Cedar policy packs
  if (args[0] === 'policy-packs') {
    await handlePolicyPacks(args.slice(1));
    process.exit(0);
  }

  // Handle real connector pilots
  if (args[0] === 'connectors') {
    await handleConnectors(args.slice(1));
    process.exit(0);
  }

  // Handle connect command
  if (args[0] === 'connect') {
    await handleConnect();
    process.exit(0);
  }

  // Handle init command
  if (args[0] === 'init') {
    await handleInit(args.slice(1));
    process.exit(0);
  }

  // Handle demo command
  if (args[0] === 'demo') {
    await handleDemo();
    return; // demo keeps running
  }

  // Handle status command
  if (args[0] === 'status') {
    await handleStatus(args.slice(1));
    process.exit(0);
  }

  // Handle digest command
  if (args[0] === 'digest') {
    await handleDigest(args.slice(1));
    process.exit(0);
  }

  // Handle receipts command
  if (args[0] === 'receipts') {
    await handleReceipts(args.slice(1));
    process.exit(0);
  }

  if (args[0] === 'bundle') {
    await handleBundle(args.slice(1));
    process.exit(0);
  }

  // Handle trace command
  if (args[0] === 'trace') {
    await handleTrace(args.slice(1));
    process.exit(0);
  }

  // Handle simulate command
  if (args[0] === 'simulate') {
    await handleSimulate(args.slice(1));
    process.exit(0);
  }

  // Handle report command
  if (args[0] === 'report') {
    await handleReport(args.slice(1));
    process.exit(0);
  }

  if (args[0] === 'doctor') {
    await handleDoctor();
    process.exit(0);
  }

  const { policyPath, cedarDir, slug, enforce, verbose, childCommand } = parseArgs(args);

  // Load policy if provided
  let policy = null;
  let policyDigest = 'none';
  let credentials: Record<string, any> | undefined;
  let signing: any | undefined;

  // Cedar policy mode: load .cedar files from directory
  // Auto-detect Cedar policies if no explicit flag given
  let cedarPolicySet: Awaited<ReturnType<typeof loadCedarPolicies>> | null = null;
  let effectiveCedarDir = cedarDir;
  if (!effectiveCedarDir && !policyPath) {
    // Auto-detect: check for cedar/ or policies/ directories with .cedar files
    const { existsSync, readdirSync } = await import('node:fs');
    for (const candidate of ['cedar', 'policies', '.']) {
      try {
        if (existsSync(candidate) && readdirSync(candidate).some((f: string) => f.endsWith('.cedar'))) {
          effectiveCedarDir = candidate;
          process.stderr.write(`[PROTECT_MCP] Auto-detected Cedar policies in ./${candidate}/\n`);
          break;
        }
      } catch { /* directory doesn't exist or not readable */ }
    }
  }
  if (effectiveCedarDir) {
    try {
      const cedarAvailable = await isCedarAvailable();
      if (!cedarAvailable) {
        process.stderr.write('[PROTECT_MCP] Warning: @cedar-policy/cedar-wasm not installed. Install with: npm install @cedar-policy/cedar-wasm\n');
        process.stderr.write('[PROTECT_MCP] Cedar policies will be loaded but evaluated with fallback (allow-all).\n');
      }
      cedarPolicySet = loadCedarPolicies(effectiveCedarDir);
      policyDigest = cedarPolicySet.digest;
      // Create a minimal policy object with cedar engine mode
      policy = {
        tools: { '*': { require: 'any' as const } },
        policy_engine: 'cedar' as const,
        cedar_dir: effectiveCedarDir,
      };
      process.stderr.write(`[PROTECT_MCP] Cedar policy engine: loaded ${cedarPolicySet.fileCount} policies from ${effectiveCedarDir} (digest: ${policyDigest})\n`);
      if (verbose) {
        process.stderr.write(`[PROTECT_MCP] Cedar files: ${cedarPolicySet.files.join(', ')}\n`);
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading Cedar policies: ${err instanceof Error ? err.message : err}\n`);
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
        process.stderr.write(`[PROTECT_MCP] Loaded policy from ${policyPath} (digest: ${policyDigest})\n`);
      }
    } catch (err) {
      process.stderr.write(`[PROTECT_MCP] Error loading policy: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  }

  // Initialize signing
  if (signing) {
    const warnings = await initSigning(signing);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}\n`);
    }
  }

  // Validate credentials
  if (credentials) {
    const warnings = validateCredentials(credentials);
    for (const w of warnings) {
      process.stderr.write(`[PROTECT_MCP] Warning: ${w}\n`);
    }
  }

  const config: ProtectConfig = {
    command: childCommand[0],
    args: childCommand.slice(1),
    policy,
    policyDigest,
    slug,
    enforce,
    verbose,
    signing,
    credentials,
  };

  // HTTP transport mode
  const useHttp = args.includes('--http');
  if (useHttp) {
    const portIdx = args.indexOf('--port');
    const httpPort = portIdx >= 0 && args[portIdx + 1] ? parseInt(args[portIdx + 1]) : 3000;
    const { startHttpTransport } = await import('./http-transport.js');
    startHttpTransport({ port: httpPort, config, serverCommand: childCommand });
    return;
  }

  const gateway = new ProtectGateway(config);

  // Set Cedar policies on gateway if loaded
  if (cedarPolicySet) {
    gateway.setCedarPolicies(cedarPolicySet);
  }

  await gateway.start();
}

// ============================================================
// Simulate command
// ============================================================

async function handleSimulate(args: string[]): Promise<void> {
  let policyPath = '';
  let logPath = '.protect-mcp-log.jsonl';
  let tier = 'unknown';
  let jsonOutput = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--policy' && args[i + 1]) { policyPath = args[++i]; }
    else if (args[i] === '--log' && args[i + 1]) { logPath = args[++i]; }
    else if (args[i] === '--tier' && args[i + 1]) { tier = args[++i]; }
    else if (args[i] === '--json') { jsonOutput = true; }
  }

  if (!policyPath) {
    process.stderr.write('Usage: protect-mcp simulate --policy <path> [--log <path>] [--tier <tier>] [--json]\n');
    process.exit(1);
  }

  const { existsSync } = await import('node:fs');
  if (!existsSync(logPath)) {
    process.stderr.write(`Log file not found: ${logPath}\n`);
    process.stderr.write('Run protect-mcp in shadow mode first to generate a log file.\n');
    process.exit(1);
  }

  const { policy } = loadPolicy(policyPath);
  const entries = parseLogFile(logPath);

  if (entries.length === 0) {
    process.stderr.write('No tool call entries found in log file.\n');
    process.exit(1);
  }

  const summary = simulate(entries, policy, tier as any);
  summary.policy_file = policyPath;
  summary.log_file = logPath;

  if (jsonOutput) {
    process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  } else {
    process.stdout.write(formatSimulation(summary) + '\n');
  }
}

// ============================================================
// Report command
// ============================================================

async function handleDoctor(): Promise<void> {
  const { existsSync, readFileSync, readdirSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { execSync } = await import('node:child_process');

  const green = (s: string) => `\x1b[32m✓\x1b[0m ${s}`;
  const red = (s: string) => `\x1b[31m✗\x1b[0m ${s}`;
  const yellow = (s: string) => `\x1b[33m⚠\x1b[0m ${s}`;
  const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;

  process.stdout.write('\n\x1b[1mprotect-mcp doctor\x1b[0m\n');
  process.stdout.write(dim('Checking your ScopeBlind setup...\n\n'));

  let issues = 0;

  // 1. Check Node.js version
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1));
  if (major >= 18) {
    process.stdout.write(green(`Node.js ${nodeVersion}\n`));
  } else {
    process.stdout.write(red(`Node.js ${nodeVersion}, requires >= 18\n`));
    issues++;
  }

  // 2. Check for signing keys
  const configPath = join(process.cwd(), 'scopeblind.config.json');
  if (existsSync(configPath)) {
    try {
      const config = JSON.parse(readFileSync(configPath, 'utf-8'));
      if (config.signing?.private_key || config.signing?.key_file) {
        process.stdout.write(green('Signing keys configured\n'));
      } else {
        process.stdout.write(yellow('Config found but no signing keys. Run: protect-mcp init\n'));
        issues++;
      }
    } catch {
      process.stdout.write(red('Invalid scopeblind.config.json\n'));
      issues++;
    }
  } else {
    process.stdout.write(yellow('No scopeblind.config.json. Run: protect-mcp init\n'));
  }

  // 3. Check for policy files
  let policyFound = false;
  // Check Cedar
  for (const dir of ['cedar', 'policies', '.']) {
    try {
      if (existsSync(dir) && readdirSync(dir).some((f: string) => f.endsWith('.cedar'))) {
        process.stdout.write(green(`Cedar policies found in ./${dir}/\n`));
        policyFound = true;
        break;
      }
    } catch {}
  }
  // Check JSON
  if (!policyFound) {
    for (const name of ['policy.json', 'protect-mcp.policy.json', 'scopeblind-policy.json']) {
      if (existsSync(name)) {
        process.stdout.write(green(`JSON policy found: ${name}\n`));
        policyFound = true;
        break;
      }
    }
  }
  if (!policyFound) {
    process.stdout.write(yellow('No policy files found, running in shadow mode (allow all)\n'));
  }

  // 4. Check for Cedar WASM
  try {
    const cedarAvailable = await isCedarAvailable();
    if (cedarAvailable) {
      process.stdout.write(green('Cedar WASM engine available\n'));
    } else {
      process.stdout.write(dim('  Cedar WASM not installed. Install: npm install @cedar-policy/cedar-wasm\n'));
    }
  } catch {
    process.stdout.write(dim('  Cedar WASM not installed\n'));
  }

  // 5. Check for receipt files
  const logFile = join(process.cwd(), 'protect-mcp-decisions.jsonl');
  const receiptFile = join(process.cwd(), 'protect-mcp-receipts.jsonl');
  if (existsSync(logFile)) {
    try {
      const lines = readFileSync(logFile, 'utf-8').trim().split('\n').length;
      process.stdout.write(green(`Decision log: ${lines} entries\n`));
    } catch {
      process.stdout.write(green('Decision log exists\n'));
    }
  } else {
    process.stdout.write(dim('  No decision log yet, will be created on first tool call\n'));
  }
  if (existsSync(receiptFile)) {
    try {
      const lines = readFileSync(receiptFile, 'utf-8').trim().split('\n').length;
      process.stdout.write(green(`Receipt file: ${lines} signed receipts\n`));
    } catch {
      process.stdout.write(green('Receipt file exists\n'));
    }
  }

  // 6. Check verifier
  try {
    execSync('npx @veritasacta/verify --version 2>/dev/null', { stdio: 'pipe', timeout: 10000 });
    process.stdout.write(green('Verifier available: @veritasacta/verify\n'));
  } catch {
    process.stdout.write(dim('  Verifier not cached. Install: npm install -g @veritasacta/verify\n'));
  }

  // 7. Check network (ScopeBlind API reachable)
  try {
    const res = await fetch('https://api.scopeblind.com/health', { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      process.stdout.write(green('ScopeBlind API reachable\n'));
    } else {
      process.stdout.write(yellow('ScopeBlind API returned non-200, receipts will be stored locally\n'));
    }
  } catch {
    process.stdout.write(dim('  ScopeBlind API not reachable, offline mode (receipts stored locally)\n'));
  }

  // Proof of restraint: run the live engine against known deny/allow vectors so a
  // gate that would silently permit is caught here rather than in production.
  process.stdout.write('\nRestraint self-test:\n');
  try {
    const st = await runEvaluatorSelfTest();
    if (!st.wasmAvailable) {
      process.stdout.write(dim('  Cedar WASM not installed; the gate fails closed (denies) until it is.\n'));
    }
    for (const c of st.cases) {
      process.stdout.write(c.pass ? green(`  ${c.name}\n`) : `\x1b[31m  FAIL: ${c.name} (expected ${c.expected}, got ${c.actual})\n\x1b[0m`);
    }
    if (!st.passed) issues++;
    else process.stdout.write(green('  the gate denies what it should and allows what it should\n'));
  } catch (err) {
    process.stdout.write(yellow(`  self-test could not run: ${err instanceof Error ? err.message : 'unknown'}\n`));
    issues++;
  }

  // Summary
  process.stdout.write('\n');
  if (issues === 0) {
    process.stdout.write('\x1b[32m\x1b[1mAll checks passed.\x1b[0m Ready to wrap MCP servers.\n');
    process.stdout.write(dim('\n  npx protect-mcp -- node your-server.js\n\n'));
  } else {
    process.stdout.write(`\x1b[33m\x1b[1m${issues} issue(s) found.\x1b[0m Fix them and run doctor again.\n\n`);
  }
}

async function handleReport(args: string[]): Promise<void> {
  let period = 30;
  let format = 'json';
  let outputPath = '';
  let dir = process.cwd();

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--period' && args[i + 1]) {
      const match = args[++i].match(/^(\d+)d$/);
      if (match) period = parseInt(match[1], 10);
    }
    else if (args[i] === '--format' && args[i + 1]) { format = args[++i]; }
    else if (args[i] === '--output' && args[i + 1]) { outputPath = args[++i]; }
    else if (args[i] === '--dir' && args[i + 1]) { dir = args[++i]; }
  }

  const { generateReport, formatReportMarkdown } = await import('./report.js');
  const { join } = await import('node:path');

  const logPath = join(dir, '.protect-mcp-log.jsonl');
  const receiptPath = join(dir, '.protect-mcp-receipts.jsonl');

  const report = generateReport(logPath, receiptPath, period);

  let output: string;
  if (format === 'md') {
    output = formatReportMarkdown(report);
  } else {
    output = JSON.stringify(report, null, 2);
  }

  if (outputPath) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(outputPath, output, 'utf-8');
    process.stderr.write(`Report written to ${outputPath}\n`);
  } else {
    process.stdout.write(output + '\n');
  }
}

main().catch((err) => {
  process.stderr.write(`[PROTECT_MCP] Fatal error: ${err instanceof Error ? err.message : err}\n`);
  process.exit(1);
});
