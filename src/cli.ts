#!/usr/bin/env node

/**
 * @scopeblind/protect-mcp CLI
 *
 * Usage:
 *   npx protect-mcp [options] -- <command> [args...]
 *   npx protect-mcp init [--dir <path>]
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
import { initSigning } from './signing.js';
import { validateCredentials } from './credentials.js';
import { parseLogFile, simulate, formatSimulation } from './simulate.js';
import { loadCedarPolicies, isCedarAvailable } from './cedar-evaluator.js';
import type { ProtectConfig } from './types.js';

function printHelp(): void {
  process.stderr.write(`
protect-mcp — Shadow-mode security gateway for MCP servers

Usage:
  protect-mcp [options] -- <command> [args...]
  protect-mcp quickstart
  protect-mcp init [--dir <path>]
  protect-mcp demo
  protect-mcp trace <receipt_id> [--endpoint <url>] [--depth <n>]
  protect-mcp status [--dir <path>]
  protect-mcp digest [--today] [--dir <path>]
  protect-mcp receipts [--last <n>] [--dir <path>]
  protect-mcp bundle [--output <path>] [--dir <path>]
  protect-mcp simulate --policy <path> [--log <path>] [--tier <tier>] [--json]
  protect-mcp report [--period <days>d] [--format md|json] [--output <path>] [--dir <path>]

Options:
  --policy <path>   Policy/config JSON file (default: allow-all)
  --cedar <dir>     Cedar policy directory (alternative to --policy, evaluates locally via WASM)
  --slug <slug>     ScopeBlind tenant slug (optional)
  --enforce         Enable enforcement mode (default: shadow mode)
  --http            Start HTTP/SSE server instead of stdio proxy
  --port <port>     HTTP server port (default: 3000, requires --http)
  --verbose         Enable debug logging to stderr
  --help            Show this help

Commands:
  quickstart        Zero-config onboarding: init + demo + show receipts in one command
  init              Generate config template, Ed25519 keypair, and sample policy
  demo              Start a demo server wrapped with protect-mcp (see receipts instantly)
  doctor            Check your setup: keys, policies, verifier, API connectivity
  trace <id>        Visualize the receipt DAG from a given receipt_id (ASCII tree)
  status            Show tool call statistics from the local decision log
  digest            Generate a human-readable summary of agent activity
  receipts          Show recent persisted signed receipts
  bundle            Export an offline-verifiable audit bundle

Examples:
  protect-mcp quickstart
  protect-mcp -- node my-server.js
  protect-mcp --policy protect-mcp.json -- node my-server.js
  protect-mcp init
  protect-mcp demo
  protect-mcp trace sha256:abc123 --depth 5
  protect-mcp status
  protect-mcp digest --today
  protect-mcp receipts --last 10
  protect-mcp bundle --output audit.json

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
  process.stdout.write(`  Output:   ${outputPath}\n`);
  process.stdout.write(`  Verify:   npx @veritasacta/verify ${outputPath} --bundle\n\n`);
}

/**
 * Handle the `quickstart` command: zero-config onboarding.
 * Runs init (to tmpdir), then demo, automatically.
 */
async function handleQuickstart(): Promise<void> {
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
  process.stdout.write(`  4. Log signed receipts for every tool call\n\n`);
  process.stdout.write(`  Working dir: ${dir}\n\n`);

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
      process.stdout.write(`${prefix}${childPrefix}${dim('(cycle — already rendered)')}\n`);
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


async function main(): Promise<void> {
  // Skip node + script path
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  // Handle quickstart command
  if (args[0] === 'quickstart') {
    await handleQuickstart();
    return; // demo keeps running
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
    process.stdout.write(red(`Node.js ${nodeVersion} — requires >= 18\n`));
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
        process.stdout.write(yellow('Config found but no signing keys — run: protect-mcp init\n'));
        issues++;
      }
    } catch {
      process.stdout.write(red('Invalid scopeblind.config.json\n'));
      issues++;
    }
  } else {
    process.stdout.write(yellow('No scopeblind.config.json — run: protect-mcp init\n'));
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
    process.stdout.write(yellow('No policy files found — running in shadow mode (allow all)\n'));
  }

  // 4. Check for Cedar WASM
  try {
    const cedarAvailable = await isCedarAvailable();
    if (cedarAvailable) {
      process.stdout.write(green('Cedar WASM engine available\n'));
    } else {
      process.stdout.write(dim('  Cedar WASM not installed — install: npm install @cedar-policy/cedar-wasm\n'));
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
    process.stdout.write(dim('  No decision log yet — will be created on first tool call\n'));
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
    process.stdout.write(dim('  Verifier not cached — install: npm install -g @veritasacta/verify\n'));
  }

  // 7. Check network (ScopeBlind API reachable)
  try {
    const res = await fetch('https://api.scopeblind.com/health', { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      process.stdout.write(green('ScopeBlind API reachable\n'));
    } else {
      process.stdout.write(yellow('ScopeBlind API returned non-200 — receipts will be stored locally\n'));
    }
  } catch {
    process.stdout.write(dim('  ScopeBlind API not reachable — offline mode (receipts stored locally)\n'));
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
