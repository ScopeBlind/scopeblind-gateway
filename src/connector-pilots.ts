import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export type ConnectorPilotId = 'github' | 'email-gmail' | 'filesystem-git' | 'slack-teams' | 'finance-pms';

export interface ConnectorEnvVar {
  name: string;
  required: boolean;
  description: string;
}

export interface ConnectorAction {
  name: string;
  tool: string;
  risk: 'low' | 'medium' | 'high';
  mode: 'observe' | 'require_approval' | 'deny';
  description: string;
}

export interface ConnectorPilot {
  id: ConnectorPilotId;
  category: string;
  name: string;
  status: 'usable-pilot';
  description: string;
  value: string;
  env: ConnectorEnvVar[];
  tools: string[];
  actions: ConnectorAction[];
  setup: string[];
  config: Record<string, unknown>;
  cedar: string;
}

export interface InstalledConnectorPilot {
  id: string;
  name: string;
  category: string;
  status: string;
  config_path: string;
  policy_path: string;
}

const defaultPermit = `
// Default posture: observe all non-matching tools so the connector can be piloted in shadow mode.
permit(principal, action == Action::"MCP::Tool::call", resource);
`;

export const CONNECTOR_PILOTS: ConnectorPilot[] = [
  {
    id: 'github',
    category: 'code',
    name: 'GitHub pull-request control',
    status: 'usable-pilot',
    description: 'Controls GitHub REST/MCP calls for issue, PR, branch, and workflow actions.',
    value: 'Useful when agents already have repo access through GitHub MCP, gh, or a GitHub-backed tool server.',
    env: [
      { name: 'GITHUB_TOKEN', required: true, description: 'Fine-grained token scoped to the pilot repo.' },
      { name: 'GITHUB_REPOSITORY', required: true, description: 'owner/repo target for the pilot.' },
    ],
    tools: ['github.rest.request', 'github.issue.create', 'github.pull_request.merge', 'github.workflow.dispatch'],
    actions: [
      { name: 'Read repo metadata', tool: 'github.rest.request', risk: 'low', mode: 'observe', description: 'GET-only repository and PR inspection.' },
      { name: 'Create issue or comment', tool: 'github.issue.create', risk: 'medium', mode: 'require_approval', description: 'External write to the system of record.' },
      { name: 'Merge PR / dispatch workflow', tool: 'github.pull_request.merge', risk: 'high', mode: 'require_approval', description: 'Code-changing or CI-triggering action.' },
    ],
    setup: [
      'Create a fine-grained GitHub token for one repository.',
      'Set GITHUB_TOKEN and GITHUB_REPOSITORY.',
      'Run the agent through protect-mcp and review GitHub tool calls in the dashboard.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'github',
      target_env: ['GITHUB_TOKEN', 'GITHUB_REPOSITORY'],
      safe_read_probe: 'GET /repos/{GITHUB_REPOSITORY}',
      controlled_tools: ['github.rest.request', 'github.issue.create', 'github.pull_request.merge', 'github.workflow.dispatch'],
      approval_required_for: ['POST', 'PATCH', 'PUT', 'DELETE', 'merge', 'workflow_dispatch'],
      receipt_fields: ['method', 'path', 'repo', 'actor', 'payload_hash', 'approval_reason'],
    },
    cedar: `${defaultPermit}
// GitHub pilot: reads are observed; writes and merges need exact-action approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.pull_request.merge" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.workflow.dispatch" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.issue.create" && !context.approved };
`,
  },
  {
    id: 'email-gmail',
    category: 'communications',
    name: 'Gmail self-send / draft approval',
    status: 'usable-pilot',
    description: 'Uses the existing Gmail OAuth connector path and restricts send mode to email.self for the first production pilot.',
    value: 'Makes external communications reviewable before an agent can send mail.',
    env: [
      { name: 'GOOGLE_CLIENT_ID', required: true, description: 'OAuth client for Gmail.' },
      { name: 'GOOGLE_CLIENT_SECRET', required: true, description: 'OAuth client secret.' },
      { name: 'CONNECTOR_TOKEN_KEY', required: true, description: 'AES-GCM key material for sealed connector tokens.' },
    ],
    tools: ['gmail.draft.create', 'gmail.send.email_self', 'email.send'],
    actions: [
      { name: 'Create draft', tool: 'gmail.draft.create', risk: 'medium', mode: 'require_approval', description: 'Draft content can leak sensitive information.' },
      { name: 'Self-send test', tool: 'gmail.send.email_self', risk: 'medium', mode: 'require_approval', description: 'First release allows only sending to the account owner.' },
      { name: 'External send', tool: 'email.send', risk: 'high', mode: 'deny', description: 'Direct external send stays blocked until a customer-specific allowlist exists.' },
    ],
    setup: [
      'Configure Google OAuth redirect /fn/connectors/gmail/callback.',
      'Connect Gmail through the hosted console or local connector flow.',
      'Keep send mode to email.self until the customer approves recipient allowlists.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'gmail',
      hosted_functions: ['/fn/connectors/gmail/start', '/fn/connectors/gmail/callback', '/fn/connectors/gmail/send', '/fn/connectors/gmail/status'],
      first_release_scope: 'email.self',
      denied_until_configured: ['email.send.external', 'email.bulk_send'],
      receipt_fields: ['to_hash', 'subject_hash', 'body_hash', 'approval_reason', 'gmail_message_id'],
    },
    cedar: `${defaultPermit}
// Email pilot: no direct external send. Draft/self-send require exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "email.send" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.draft.create" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.send.email_self" && !context.approved };
`,
  },
  {
    id: 'filesystem-git',
    category: 'local-computer',
    name: 'Filesystem and Git control',
    status: 'usable-pilot',
    description: 'Controls reads, writes, shell commands, and Git mutation in the local project.',
    value: 'Immediately useful with Claude Code, Codex, Cursor, and any agent that edits files or runs shell commands.',
    env: [],
    tools: ['Read', 'Write', 'Edit', 'MultiEdit', 'Bash', 'git.commit', 'git.push'],
    actions: [
      { name: 'Read files', tool: 'Read', risk: 'low', mode: 'observe', description: 'Observe file reads for audit context.' },
      { name: 'Write/edit files', tool: 'Write', risk: 'medium', mode: 'require_approval', description: 'Require approval for sensitive paths or broad rewrites.' },
      { name: 'Git push/reset', tool: 'Bash', risk: 'high', mode: 'require_approval', description: 'Commands that publish, reset, or delete require exact-action approval.' },
    ],
    setup: [
      'Run protect-mcp init-hooks in the project.',
      'Install filesystem-safe and Git-safe policy packs.',
      'Review the dashboard before turning on enforce mode.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'filesystem-git',
      local_only: true,
      protected_paths: ['.env', '.ssh', 'keys/', 'secrets/', 'node_modules/'],
      dangerous_command_patterns: ['rm -rf', 'git push', 'git reset --hard', 'curl | sh', 'chmod 777'],
      receipt_fields: ['tool', 'path_hash', 'command_hash', 'diff_hash', 'approval_reason'],
    },
    cedar: `${defaultPermit}
// Filesystem/Git pilot: dangerous shell and protected-path writes need approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git reset --hard") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git push") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["Write", "Edit", "MultiEdit"].contains(context.tool) && context.path.contains(".env") && !context.approved };
`,
  },
  {
    id: 'slack-teams',
    category: 'communications',
    name: 'Slack or Teams outbound approval',
    status: 'usable-pilot',
    description: 'Controls messages to Slack channels or Microsoft Teams webhooks.',
    value: 'Makes high-impact internal broadcasts and client channels approval-gated.',
    env: [
      { name: 'SLACK_BOT_TOKEN', required: false, description: 'Slack bot token for chat.postMessage pilots.' },
      { name: 'SLACK_CHANNEL_ID', required: false, description: 'Default Slack channel for the pilot.' },
      { name: 'TEAMS_WEBHOOK_URL', required: false, description: 'Teams incoming webhook URL if Teams is preferred.' },
    ],
    tools: ['slack.chat.postMessage', 'slack.files.upload', 'teams.webhook.post'],
    actions: [
      { name: 'Post internal message', tool: 'slack.chat.postMessage', risk: 'medium', mode: 'require_approval', description: 'Message text and channel are read back before send.' },
      { name: 'Upload file', tool: 'slack.files.upload', risk: 'high', mode: 'require_approval', description: 'Files can leak customer data and need explicit approval.' },
      { name: 'Teams webhook post', tool: 'teams.webhook.post', risk: 'medium', mode: 'require_approval', description: 'Webhook destination and payload hash are receipted.' },
    ],
    setup: [
      'Choose Slack or Teams for the first pilot, not both.',
      'Set the relevant token/webhook environment variables.',
      'Start with a private test channel and exact-action approval for every send.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'slack-or-teams',
      supported_modes: ['slack.chat.postMessage', 'teams.webhook.post'],
      require_channel_allowlist: true,
      receipt_fields: ['channel_hash', 'message_hash', 'file_hash', 'approval_reason', 'provider_message_id'],
    },
    cedar: `${defaultPermit}
// Slack/Teams pilot: all outbound posts and uploads require approval by default.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["slack.chat.postMessage", "slack.files.upload", "teams.webhook.post"].contains(context.tool) && !context.approved };
`,
  },
  {
    id: 'finance-pms',
    category: 'finance',
    name: 'Finance PMS mock-to-real adapter',
    status: 'usable-pilot',
    description: 'Stages orders into a PMS adapter contract, with mock mode locally and real mode through PMS_ADAPTER_URL.',
    value: 'Gives hedge funds the controlled booking path: parse, mandate-check, approve, book, corroborate, receipt.',
    env: [
      { name: 'PMS_ADAPTER_URL', required: false, description: 'Customer-owned adapter endpoint. Omit for local mock mode.' },
      { name: 'PMS_ADAPTER_TOKEN', required: false, description: 'Bearer token for the customer-owned PMS adapter.' },
    ],
    tools: ['pms.order.stage', 'pms.order.book', 'pms.order.cancel', 'pms.reconcile'],
    actions: [
      { name: 'Stage order', tool: 'pms.order.stage', risk: 'medium', mode: 'require_approval', description: 'Creates a booking ticket but does not execute.' },
      { name: 'Book order', tool: 'pms.order.book', risk: 'high', mode: 'require_approval', description: 'Must pass mandate checks and human readback.' },
      { name: 'Cancel/order correction', tool: 'pms.order.cancel', risk: 'high', mode: 'require_approval', description: 'Mutates book state and requires approval.' },
    ],
    setup: [
      'Run local mock mode first with the Legate finance pilot pack.',
      'Point PMS_ADAPTER_URL at a customer-owned bridge when ready.',
      'Require mandate checks and exact-action approval before pms.order.book.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'finance-pms',
      mode: 'mock-first',
      adapter_contract: {
        stage: 'POST /orders/stage',
        book: 'POST /orders/book',
        cancel: 'POST /orders/{client_order_id}/cancel',
        reconcile: 'GET /orders/{client_order_id}',
      },
      receipt_fields: ['client_order_id', 'side', 'symbol_hash', 'qty', 'price', 'mandate_digest', 'approval_reason', 'external_confirmation_hash'],
    },
    cedar: `${defaultPermit}
// Finance/PMS pilot: booking actions require mandate pass and exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["pms.order.stage", "pms.order.book", "pms.order.cancel"].contains(context.tool) && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "pms.order.book" && context.mandate_passed != true };
`,
  },
];

export function connectorPilotIds(): ConnectorPilotId[] {
  return CONNECTOR_PILOTS.map((pilot) => pilot.id);
}

export function getConnectorPilot(id: string): ConnectorPilot | undefined {
  return CONNECTOR_PILOTS.find((pilot) => pilot.id === id);
}

export function connectorDirectory(dir: string): string {
  return join(dir, '.protect-mcp', 'connectors');
}

export function writeConnectorPilots(opts: { dir: string; ids?: string[]; force?: boolean }): { written: string[]; pilots: ConnectorPilot[]; directory: string } {
  const directory = connectorDirectory(opts.dir);
  mkdirSync(directory, { recursive: true });
  const selected = (opts.ids && opts.ids.length > 0 && !opts.ids.includes('all'))
    ? opts.ids.map((id) => {
        const pilot = getConnectorPilot(id);
        if (!pilot) throw new Error(`Unknown connector pilot: ${id}`);
        return pilot;
      })
    : CONNECTOR_PILOTS;
  const written: string[] = [];
  for (const pilot of selected) {
    const configPath = join(directory, `${pilot.id}.json`);
    const policyPath = join(directory, `${pilot.id}.cedar`);
    if (!opts.force && (existsSync(configPath) || existsSync(policyPath))) {
      throw new Error(`Refusing to overwrite ${pilot.id}. Re-run with --force if intentional.`);
    }
    writeFileSync(configPath, JSON.stringify({ ...pilot.config, id: pilot.id, name: pilot.name, category: pilot.category, tools: pilot.tools, actions: pilot.actions, setup: pilot.setup }, null, 2) + '\n');
    writeFileSync(policyPath, pilot.cedar.endsWith('\n') ? pilot.cedar : `${pilot.cedar}\n`);
    written.push(configPath, policyPath);
  }
  writeFileSync(join(directory, 'README.md'), renderConnectorReadme(selected));
  written.push(join(directory, 'README.md'));
  return { written, pilots: selected, directory };
}

export function readInstalledConnectorPilots(dir: string): InstalledConnectorPilot[] {
  const directory = connectorDirectory(dir);
  if (!existsSync(directory)) return [];
  return readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .map((name) => {
      const configPath = join(directory, name);
      try {
        const parsed = JSON.parse(readFileSync(configPath, 'utf-8')) as Record<string, any>;
        const id = String(parsed.id || name.replace(/\.json$/, ''));
        const pilot = getConnectorPilot(id);
        return {
          id,
          name: String(parsed.name || pilot?.name || id),
          category: String(parsed.category || pilot?.category || 'unknown'),
          status: String(parsed.status || parsed.type || 'installed'),
          config_path: configPath,
          policy_path: join(directory, `${id}.cedar`),
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean) as InstalledConnectorPilot[];
}

export function connectorDoctor(dir: string, env: NodeJS.ProcessEnv = process.env): Array<Record<string, unknown>> {
  const installed = new Set(readInstalledConnectorPilots(dir).map((pilot) => pilot.id));
  return CONNECTOR_PILOTS.map((pilot) => {
    const envRows = pilot.env.map((item) => ({
      name: item.name,
      required: item.required,
      present: Boolean(env[item.name]),
      description: item.description,
    }));
    const missingRequired = envRows.filter((item) => item.required && !item.present).map((item) => item.name);
    const optionalPresent = envRows.filter((item) => !item.required && item.present).map((item) => item.name);
    const optionalProviderReady = pilot.id === 'slack-teams'
      ? Boolean(env.SLACK_BOT_TOKEN || env.TEAMS_WEBHOOK_URL)
      : pilot.id === 'finance-pms'
        ? Boolean(env.PMS_ADAPTER_URL)
        : false;
    const mockModeReady = pilot.id === 'finance-pms';
    return {
      id: pilot.id,
      name: pilot.name,
      category: pilot.category,
      installed: installed.has(pilot.id),
      usable: missingRequired.length === 0 && (pilot.env.some((item) => item.required) || pilot.env.length === 0 || optionalProviderReady || mockModeReady),
      mode: pilot.id === 'finance-pms' && !env.PMS_ADAPTER_URL ? 'mock' : pilot.id === 'slack-teams' && !env.SLACK_BOT_TOKEN && !env.TEAMS_WEBHOOK_URL ? 'needs_provider_choice' : 'configured_or_local',
      missing_required: missingRequired,
      optional_present: optionalPresent,
      tools: pilot.tools,
      next: missingRequired.length > 0 ? `Set ${missingRequired.join(', ')}` : installed.has(pilot.id) ? 'Run through protect-mcp and inspect the dashboard.' : `Install with protect-mcp connectors init ${pilot.id}`,
    };
  });
}

function renderConnectorReadme(pilots: ConnectorPilot[]): string {
  return `# protect-mcp connector pilots\n\nThese files make real tool classes visible and controllable without uploading raw prompts or payloads.\n\n${pilots.map((pilot) => `## ${pilot.name}\n\n${pilot.description}\n\nValue: ${pilot.value}\n\nTools: ${pilot.tools.map((tool) => `\`${tool}\``).join(', ')}\n\nSetup:\n${pilot.setup.map((step) => `- ${step}`).join('\n')}\n`).join('\n')}\nNext: run \`npx protect-mcp dashboard --open\` and review tool inventory, policy coverage, approvals, and receipts.\n`;
}
