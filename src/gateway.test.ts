/**
 * The stdio gateway, driven through the BUILT CLI (dist/cli.js) the way an MCP
 * client drives it: JSON-RPC lines on stdin, responses on stdout, the operator's
 * lines on stderr. A small child MCP server records every call it executed, so
 * each test can tell what reached the tool from what the gate stopped.
 */
import { describe, it, expect } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { request } from 'node:http';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { buildActionReadback } from './action-readback.js';
import { verifyReceipt, chainLink } from './acta-envelope.js';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const d = existsSync(CLI) ? describe : describe.skip;

// A minimal MCP server: answers every request and appends each executed tool call to executed.jsonl.
const CHILD = `
import { createInterface } from 'node:readline';
import { appendFileSync } from 'node:fs';
appendFileSync('argv.jsonl', JSON.stringify(process.argv.slice(2)) + '\\n');
createInterface({ input: process.stdin }).on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'tools/call') appendFileSync('executed.jsonl', JSON.stringify({ tool: m.params && m.params.name }) + '\\n');
  const text = m.method === 'tools/call' ? 'CHILD EXECUTED ' + (m.params && m.params.name) : 'child ok ' + m.method;
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text }] } }) + '\\n');
});
`;

function workspace(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'pmcp-gateway-'));
  writeFileSync(join(dir, 'child.mjs'), CHILD);
  for (const [name, contents] of Object.entries(files)) writeFileSync(join(dir, name), contents);
  return dir;
}

/** The tools the child actually ran, in order. */
function executed(dir: string): string[] {
  const path = join(dir, 'executed.jsonl');
  return existsSync(path) ? readFileSync(path, 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l).tool) : [];
}

type Message = Record<string, any>;

class Gateway {
  readonly proc: ChildProcess;
  /** Every line the gateway wrote to stdout: everything the MCP client, and so the model, receives. */
  readonly lines: string[] = [];
  stderr = '';
  readonly exited: Promise<number | null>;
  private waiters = new Map<string, (m: Message) => void>();

  constructor(readonly cwd: string, args: string[], env: Record<string, string> = {}, nodeArgs: string[] = [], childArgs: string[] = []) {
    this.proc = spawn(process.execPath, [...nodeArgs, CLI, ...args, '--', process.execPath, 'child.mjs', ...childArgs], {
      cwd, env: { ...process.env, PROTECT_MCP_HTTP_PORT: '0', ...env }, stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.proc.stderr!.on('data', (b: Buffer) => { this.stderr += b.toString(); });
    createInterface({ input: this.proc.stdout! }).on('line', (line) => {
      this.lines.push(line);
      let m: Message;
      try { m = JSON.parse(line); } catch { return; }
      const key = JSON.stringify(m.id);
      const waiter = this.waiters.get(key);
      if (waiter) { this.waiters.delete(key); waiter(m); }
    });
    this.exited = new Promise((resolve) => this.proc.on('exit', (code) => {
      for (const waiter of this.waiters.values()) waiter({ gateway_exited: code });
      this.waiters.clear();
      resolve(code);
    }));
  }

  send(id: number, line: string): Promise<Message> {
    return new Promise((resolve) => {
      const key = JSON.stringify(id);
      const timer = setTimeout(() => { this.waiters.delete(key); resolve({ timeout: true }); }, 8000);
      this.waiters.set(key, (m) => { clearTimeout(timer); resolve(m); });
      this.proc.stdin!.write(line + '\n');
    });
  }

  call(id: number, name: unknown, args: unknown = {}): Promise<Message> {
    return this.send(id, JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }));
  }

  async stderrMatch(re: RegExp, ms = 8000): Promise<RegExpExecArray> {
    const until = Date.now() + ms;
    for (;;) {
      const m = re.exec(this.stderr);
      if (m) return m;
      if (Date.now() > until) throw new Error(`stderr never matched ${re}:\n${this.stderr.slice(-2000)}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  async stop(): Promise<void> {
    if (this.proc.exitCode === null && this.proc.signalCode === null) {
      this.proc.stdin!.end();
      const timer = setTimeout(() => this.proc.kill('SIGKILL'), 3000);
      await this.exited;
      clearTimeout(timer);
    }
  }
}

const text = (m: Message): string => m.result?.content?.[0]?.text ?? m.error?.message ?? JSON.stringify(m);

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
  });
}

async function waitForHttp(url: string, ms = 8000): Promise<void> {
  const until = Date.now() + ms;
  for (;;) {
    try { await fetch(url); return; } catch { /* not listening yet */ }
    if (Date.now() > until) throw new Error(`${url} never answered`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

// A signed standard (shape only; the gate does not check the author's signature at load): a person approves above USD 500.
const STANDARD = JSON.stringify({
  type: 'scopeblind.proof_request.v1', version: 1, request_id: 'pr-gateway-test', digest: 'd'.repeat(64),
  recipient: { name: 'Test Approver', organization: 'Test', key_id: 'recipient:0000', verification_key: 'a'.repeat(64) },
  requirements: {
    human_approval: { required_above: { amount: 500, currency: 'USD' }, distinct_approvers: 1 },
    action_limits: { amount_max: { amount: 2000, currency: 'USD' }, per_instruction: true },
    run: { allowed_tools: ['pay_invoice'] },
  },
  enforcement: { policy_digest: 'p'.repeat(64) },
  signature: { algorithm: 'Ed25519', value: 'f'.repeat(128) },
});

d('gateway: the approval nonce never reaches the model', () => {
  it('no tool result or MCP response carries it, and the operator still gets it on stderr', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: { send_email: { require_approval: true }, blocked: { block: true } } }) });
    const g = new Gateway(dir, ['--enforce', '--policy', './rules.json']);
    try {
      const nonce = (await g.stderrMatch(/Approval nonce: ([0-9a-f]{32})/))[1];
      const held = await g.call(1, 'send_email', { to: 'cfo@example.com', subject: 'wire' });
      expect(held.result?.isError).toBe(true);
      expect(text(held)).toContain('REQUIRES_APPROVAL');
      expect(text(await g.call(2, 'blocked'))).toContain('blocked by policy');
      expect(text(await g.call(3, 'read_file', { path: '/tmp/x' }))).toBe('CHILD EXECUTED read_file');
      expect(g.lines.length).toBe(3);
      for (const line of g.lines) expect(line).not.toContain(nonce);
      // The person who approves still has what they need, on stderr.
      const hint = await g.stderrMatch(/Approval required for "send_email"[^\n]*/);
      expect(hint[0]).toContain(nonce);
    } finally {
      await g.stop();
    }
  }, 20_000);

  it('an action held by the standard with no page tells the model nothing it could approve with', async () => {
    const dir = workspace({ 'standard.json': STANDARD });
    const g = new Gateway(dir, ['--enforce', '--standard', './standard.json']);
    try {
      const nonce = (await g.stderrMatch(/Approval nonce: ([0-9a-f]{32})/))[1];
      const held = await g.call(1, 'pay_invoice', { amount_minor: 100000, currency: 'USD', to: 'acct-1' });
      expect(text(held)).toContain('REQUIRES_APPROVAL');
      expect(text(held)).toContain('granted at the gate');
      for (const line of g.lines) expect(line).not.toContain(nonce);
      expect((await g.stderrMatch(/Approval required for "pay_invoice"[^\n]*/))[0]).toContain(nonce);
      expect(executed(dir)).toEqual([]);
    } finally {
      await g.stop();
    }
  }, 20_000);
});

d('gateway: a once grant approves one exact action', () => {
  const postApprove = (port: number, body: Record<string, unknown>) =>
    fetch(`http://127.0.0.1:${port}/approve`, { method: 'POST', body: JSON.stringify(body) });

  it('is keyed by tool and payload hash, matches the identical retry once, and never a call with other arguments', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: { send_email: { require_approval: true } } }) });
    const port = await freePort();
    const g = new Gateway(dir, ['--enforce', '--policy', './rules.json'], { PROTECT_MCP_HTTP_PORT: String(port) });
    try {
      const nonce = (await g.stderrMatch(/Approval nonce: ([0-9a-f]{32})/))[1];
      const args = { to: 'cfo@example.com', subject: 'wire' };
      const first = await g.call(1, 'send_email', args);
      const requestId = /Request ID: (\S+)\. /.exec(text(first))?.[1];
      expect(requestId).toBe(`send_email:${buildActionReadback('send_email', args).payload_hash}`);
      await waitForHttp(`http://127.0.0.1:${port}/health`);

      expect((await postApprove(port, { request_id: requestId, tool: 'send_email', mode: 'once', nonce })).status).toBe(200);
      expect(text(await g.call(2, 'send_email', args))).toBe('CHILD EXECUTED send_email');
      // Used: the same call needs a person again.
      expect(text(await g.call(3, 'send_email', args))).toContain('REQUIRES_APPROVAL');
      // A grant for this action does not cover the same tool with other arguments.
      expect((await postApprove(port, { request_id: requestId, tool: 'send_email', mode: 'once', nonce })).status).toBe(200);
      expect(text(await g.call(4, 'send_email', { to: 'attacker@evil.example', subject: 'wire' }))).toContain('REQUIRES_APPROVAL');
      expect(executed(dir)).toEqual(['send_email']);

      // A once grant must name the action it approves; one that could never match is refused.
      expect((await postApprove(port, { tool: 'send_email', mode: 'once', nonce })).status).toBe(400);
      expect((await postApprove(port, { request_id: 'c59994ad-ca1', tool: 'send_email', mode: 'once', nonce })).status).toBe(400);
      expect((await postApprove(port, { request_id: requestId, tool: 'other_tool', mode: 'once', nonce })).status).toBe(400);
      expect((await postApprove(port, { request_id: requestId, tool: 'send_email', mode: 'once', nonce: 'f'.repeat(32) })).status).toBe(403);

      // 'always' is unchanged: one grant for the tool, whatever the arguments.
      expect((await postApprove(port, { tool: 'send_email', mode: 'always', nonce })).status).toBe(200);
      expect(text(await g.call(5, 'send_email', { to: 'ops@example.com' }))).toBe('CHILD EXECUTED send_email');
    } finally {
      await g.stop();
    }
  }, 30_000);

  it('grants an action the standard holds, when no page is configured, the same way', async () => {
    const dir = workspace({ 'standard.json': STANDARD });
    const port = await freePort();
    const g = new Gateway(dir, ['--enforce', '--standard', './standard.json'], { PROTECT_MCP_HTTP_PORT: String(port) });
    try {
      const nonce = (await g.stderrMatch(/Approval nonce: ([0-9a-f]{32})/))[1];
      const args = { amount_minor: 100000, currency: 'USD', to: 'acct-1' };
      const held = await g.call(1, 'pay_invoice', args);
      const requestId = /request ID (\S+)\)/.exec(text(held))?.[1];
      expect(requestId).toBe(`pay_invoice:${buildActionReadback('pay_invoice', args).payload_hash}`);
      await waitForHttp(`http://127.0.0.1:${port}/health`);
      expect((await postApprove(port, { request_id: requestId, tool: 'pay_invoice', mode: 'once', nonce })).status).toBe(200);
      expect(text(await g.call(2, 'pay_invoice', args))).toBe('CHILD EXECUTED pay_invoice');
      expect(text(await g.call(3, 'pay_invoice', args))).toContain('REQUIRES_APPROVAL');
      expect(executed(dir)).toEqual(['pay_invoice']);
    } finally {
      await g.stop();
    }
  }, 30_000);

  it('the dashboard Approve button forwards a grant the retry matches', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: { send_email: { require_approval: true } } }) });
    const port = await freePort();
    const g = new Gateway(dir, ['--enforce', '--policy', './rules.json'], { PROTECT_MCP_HTTP_PORT: String(port) });
    let dashboard: ChildProcess | undefined;
    try {
      const nonce = (await g.stderrMatch(/Approval nonce: ([0-9a-f]{32})/))[1];
      const args = { to: 'cfo@example.com', subject: 'wire' };
      expect(text(await g.call(1, 'send_email', args))).toContain('REQUIRES_APPROVAL');
      await waitForHttp(`http://127.0.0.1:${port}/health`);

      const dashPort = await freePort();
      dashboard = spawn(process.execPath, [CLI, 'dashboard', '--port', String(dashPort), '--dir', dir,
        '--approval-endpoint', `http://127.0.0.1:${port}`, '--approval-nonce', nonce], { cwd: dir, stdio: 'ignore' });
      await waitForHttp(`http://127.0.0.1:${dashPort}/api/summary`);
      const summary = await (await fetch(`http://127.0.0.1:${dashPort}/api/summary`)).json() as { pending_approvals: Array<{ request_id: string; tool: string }> };
      const card = summary.pending_approvals[0];
      // Exactly what the page posts when the person presses Approve: its origin, JSON and the token it carries.
      const page = await (await fetch(`http://127.0.0.1:${dashPort}/`)).text();
      const token = /var DASHBOARD_TOKEN = '([0-9a-f]{64})';/.exec(page)![1];
      const resolved = await (await fetch(`http://127.0.0.1:${dashPort}/api/approval/resolve`, {
        method: 'POST', headers: { 'content-type': 'application/json', origin: `http://127.0.0.1:${dashPort}`, 'x-dashboard-token': token },
        body: JSON.stringify({ request_id: card.request_id, tool: card.tool, resolution: 'approve', reason: '' }),
      })).json() as { forwarded: { ok: boolean } };
      expect(resolved.forwarded.ok).toBe(true);
      expect(text(await g.call(2, 'send_email', args))).toBe('CHILD EXECUTED send_email');
    } finally {
      dashboard?.kill('SIGTERM');
      await g.stop();
    }
  }, 30_000);
});

function writeKey(dir: string, name = 'gateway.json'): string {
  const priv = ed25519.utils.randomPrivateKey();
  writeFileSync(join(dir, name), JSON.stringify({ privateKey: bytesToHex(priv), publicKey: bytesToHex(ed25519.getPublicKey(priv)), kid: 'test' }), { mode: 0o600 });
  return bytesToHex(ed25519.getPublicKey(priv));
}

function receiptLines(dir: string): Array<Record<string, any>> {
  const path = join(dir, '.protect-mcp-receipts.jsonl');
  return existsSync(path) ? readFileSync(path, 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
}

const CEDAR_PERMIT_ALL_BUT_DANGER = '@id("allow-all")\npermit(principal, action, resource);\n@id("no-danger")\n@reason("danger is forbidden")\nforbid(principal, action, resource == Tool::"danger");\n';
const JSON_RULES = { safe: { require_approval: true }, rl: { rate_limit: '1/hour' }, blocked: { block: true }, tiered: { min_tier: 'privileged' } };

d('gateway: --cedar with --policy applies both', () => {
  it('a Cedar allow still meets the JSON rules: block, require_approval, rate limit and min_tier', async () => {
    const dir = workspace();
    mkdirSync(join(dir, 'cedar'));
    writeFileSync(join(dir, 'cedar', 'policy.cedar'), CEDAR_PERMIT_ALL_BUT_DANGER);
    const publicKey = writeKey(dir);
    writeFileSync(join(dir, 'rules.json'), JSON.stringify({ tools: JSON_RULES, signing: { key_path: './gateway.json', enabled: true } }));
    const g = new Gateway(dir, ['--enforce', '--cedar', './cedar', '--policy', './rules.json']);
    try {
      expect(text(await g.call(1, 'safe', { path: '/tmp/x' }))).toContain('REQUIRES_APPROVAL');
      expect(text(await g.call(2, 'danger', { path: '/tmp/x' }))).toContain('denied by Cedar policy: no-danger');
      expect(text(await g.call(3, 'rl', { path: '/tmp/x' }))).toBe('CHILD EXECUTED rl');
      expect(text(await g.call(4, 'rl', { path: '/tmp/x' }))).toContain('rate limit exceeded');
      expect(text(await g.call(5, 'blocked', { path: '/tmp/x' }))).toContain('blocked by policy');
      expect(text(await g.call(6, 'tiered', { path: '/tmp/x' }))).toContain('requires tier "privileged"');
      expect(text(await g.call(7, 'other', { path: '/tmp/x' }))).toBe('CHILD EXECUTED other');
      expect(executed(dir)).toEqual(['rl', 'other']);
    } finally {
      await g.stop();
    }
    // The --policy file's signing config is the gateway's: every decision is a receipt signed with its key.
    const receipts = receiptLines(dir);
    expect(receipts.length).toBe(7);
    for (const r of receipts) expect(verifyReceipt(r, publicKey).valid).toBe(true);
    expect(receipts.map((r) => r.payload.decision)).toEqual(['require_approval', 'deny', 'allow', 'deny', 'deny', 'deny', 'allow']);
    expect(receipts[6].payload.reason).toBe('cedar_allow');
  }, 30_000);

  it('--cedar alone still reads signing from ./protect-mcp.json and allows what Cedar permits', async () => {
    const dir = workspace();
    mkdirSync(join(dir, 'cedar'));
    writeFileSync(join(dir, 'cedar', 'policy.cedar'), CEDAR_PERMIT_ALL_BUT_DANGER);
    const publicKey = writeKey(dir);
    writeFileSync(join(dir, 'protect-mcp.json'), JSON.stringify({ tools: { '*': {} }, signing: { key_path: './gateway.json', enabled: true } }));
    const g = new Gateway(dir, ['--enforce', '--cedar', './cedar']);
    try {
      expect(text(await g.call(1, 'safe', { path: '/tmp/x' }))).toBe('CHILD EXECUTED safe');
      expect(text(await g.call(2, 'danger', { path: '/tmp/x' }))).toContain('denied by Cedar policy');
    } finally {
      await g.stop();
    }
    const receipts = receiptLines(dir);
    expect(receipts.map((r) => [r.payload.decision, verifyReceipt(r, publicKey).valid])).toEqual([['allow', true], ['deny', true]]);
    expect(receipts[0].payload.reason).toBe('cedar_allow');
  }, 30_000);
});

const SIGNING_CONFIG = JSON.stringify({ tools: { '*': {} }, signing: { key_path: './gateway.json', enabled: true } });
const isTombstone = (line: Record<string, any>) => line.type === 'scopeblind.signing_failure.v1';
const raw = (id: number, name: string, args: string) => `{"jsonrpc":"2.0","id":${id},"method":"tools/call","params":{"name":${name},"arguments":${args}}}`;

d('gateway: every allowed call is signed, or it does not run', () => {
  it('signs a receipt for any arguments an agent can send', async () => {
    const dir = workspace({ 'protect-mcp.json': SIGNING_CONFIG });
    const publicKey = writeKey(dir);
    const inputs = [
      '{"amount":5,"to":"acct-1"}',
      '{"montanté":5,"to":"acct-1"}', // a non-ASCII key
      '{"amount":5,"note":"\\ud800"}', // a lone surrogate
      '{"amount":5,"__proto__":{"x":1}}',
      '{"query":"weather"}', // no destination field
      '{}',
    ];
    const g = new Gateway(dir, ['--enforce', '--policy', './protect-mcp.json']);
    try {
      for (const [i, args] of inputs.entries()) expect(text(await g.send(i + 1, raw(i + 1, '"pay"', args)))).toBe('CHILD EXECUTED pay');
    } finally {
      await g.stop();
    }
    const receipts = receiptLines(dir);
    expect(receipts.filter(isTombstone)).toEqual([]);
    expect(receipts.length).toBe(inputs.length);
    for (const r of receipts) expect(verifyReceipt(r, publicKey).valid).toBe(true);
  }, 30_000);

  it('in --enforce, refuses an allow whose receipt could not be signed, and records the gap', async () => {
    const dir = workspace({ 'protect-mcp.json': SIGNING_CONFIG });
    writeKey(dir);
    const g = new Gateway(dir, ['--enforce', '--policy', './protect-mcp.json']);
    try {
      // A tool name that is not valid Unicode cannot be signed, whatever the arguments.
      const r = await g.send(1, raw(1, '"pay\\ud800"', '{"to":"acct-1"}'));
      expect(text(r)).toContain('receipt could not be signed');
      expect(text(await g.send(2, raw(2, '"pay"', '{"to":"acct-1"}')))).toBe('CHILD EXECUTED pay');
    } finally {
      await g.stop();
    }
    expect(executed(dir)).toEqual(['pay']);
    expect(receiptLines(dir).map((l) => (isTombstone(l) ? 'tombstone' : l.payload.decision))).toEqual(['tombstone', 'allow']);
  }, 30_000);

  it('--enforce refuses to start when signing is configured but the key is missing or unreadable', async () => {
    for (const [key, extra] of [[null, []], ['not json', []], [null, ['--http', '--port', '0']]] as Array<[string | null, string[]]>) {
      const dir = workspace({ 'protect-mcp.json': SIGNING_CONFIG });
      if (key !== null) writeFileSync(join(dir, 'gateway.json'), key);
      const g = new Gateway(dir, [...extra, '--enforce', '--policy', './protect-mcp.json']);
      try {
        const outcome = await Promise.race([g.exited, new Promise((r) => setTimeout(() => r('still running'), 6000))]);
        expect(outcome, `${extra.join(' ')} key=${key}`).toBe(1);
        expect(g.stderr).toContain('enforce mode refused to start');
        expect(executed(dir)).toEqual([]);
      } finally {
        await g.stop();
      }
    }
  }, 40_000);

  it('shadow mode still starts without a key and lets calls through, as before', async () => {
    const dir = workspace({ 'protect-mcp.json': SIGNING_CONFIG });
    const g = new Gateway(dir, ['--policy', './protect-mcp.json']);
    try {
      expect(text(await g.send(1, raw(1, '"pay"', '{"to":"acct-1"}')))).toBe('CHILD EXECUTED pay');
      expect(g.stderr).toContain('key file not found');
    } finally {
      await g.stop();
    }
  }, 20_000);
});

d('quickstart', () => {
  it('signs a receipt for a call with the key it generated, and says signing is on', async () => {
    const scratch = mkdtempSync(join(tmpdir(), 'pmcp-quickstart-'));
    const proc = spawn(process.execPath, [CLI, 'quickstart'], {
      cwd: scratch, env: { ...process.env, TMPDIR: scratch, PROTECT_MCP_HTTP_PORT: '0', NO_COLOR: '1' }, stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    proc.stdout!.on('data', (b: Buffer) => { out += b.toString(); });
    proc.stderr!.on('data', (b: Buffer) => { err += b.toString(); });
    const exited = new Promise((resolve) => proc.on('exit', resolve));
    const until = async (ok: () => boolean, what: string) => {
      const deadline = Date.now() + 15_000;
      while (!ok()) {
        if (Date.now() > deadline) throw new Error(`quickstart never showed ${what}:\n${err.slice(-1500)}`);
        await new Promise((r) => setTimeout(r, 50));
      }
    };
    try {
      await until(() => err.includes('Demo ready'), 'the demo');
      proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/etc/hosts' } } }) + '\n');
      await until(() => /"tool":"read_file"/.test(err), 'the decision');
    } finally {
      proc.stdin!.end();
      await exited;
    }
    expect(out).toContain('Signing enabled');
    const workDir = readdirSync(scratch).find((name) => name.startsWith('protect-mcp-quickstart-'));
    const { publicKey } = JSON.parse(readFileSync(join(scratch, workDir!, 'keys', 'gateway.json'), 'utf-8'));
    const receipts = receiptLines(scratch);
    expect(receipts.length).toBe(1);
    expect(receipts[0].payload.tool_name).toBe('read_file');
    expect(verifyReceipt(receipts[0], publicKey).valid).toBe(true);
  }, 40_000);
});

// Loads the built CLI as if @cedar-policy/cedar-wasm were not installed: a resolve hook refuses the package.
const NO_CEDAR_HOOKS = 'data:text/javascript,export async function resolve(s,c,n){if(s.startsWith("@cedar-policy/cedar-wasm"))throw Object.assign(new Error("Cannot find package @cedar-policy/cedar-wasm"),{code:"ERR_MODULE_NOT_FOUND"});return n(s,c)}';
const WITHOUT_CEDAR = ['--import', `data:text/javascript,import{register}from'node:module';register('${NO_CEDAR_HOOKS}');`];
const canHookModules = typeof (createRequire(__filename)('node:module') as { register?: unknown }).register === 'function';

d('without @cedar-policy/cedar-wasm, the warning says what happens', () => {
  it.skipIf(!canHookModules)('the gateway warns that every call is denied, and denies it', async () => {
    for (const enforce of [true, false]) {
      const dir = workspace();
      mkdirSync(join(dir, 'cedar'));
      writeFileSync(join(dir, 'cedar', 'policy.cedar'), CEDAR_PERMIT_ALL_BUT_DANGER);
      const g = new Gateway(dir, [...(enforce ? ['--enforce'] : []), '--cedar', './cedar'], {}, WITHOUT_CEDAR);
      try {
        const r = await g.call(1, 'safe', { path: '/tmp/x' });
        if (enforce) expect(text(r)).toContain('denied by Cedar policy');
        expect(g.stderr).toContain('every call will be denied until @cedar-policy/cedar-wasm is installed');
        expect(g.stderr).not.toContain('allow-all');
      } finally {
        await g.stop();
      }
    }
  }, 30_000);

  it.skipIf(!canHookModules)('the hook server warns the same way', async () => {
    const dir = workspace();
    mkdirSync(join(dir, 'cedar'));
    writeFileSync(join(dir, 'cedar', 'policy.cedar'), CEDAR_PERMIT_ALL_BUT_DANGER);
    const port = await freePort();
    const proc = spawn(process.execPath, [...WITHOUT_CEDAR, CLI, 'serve', '--cedar', './cedar', '--port', String(port)], {
      cwd: dir, env: { ...process.env, PROTECT_MCP_HTTP_PORT: '0' }, stdio: ['ignore', 'ignore', 'pipe'],
    });
    let err = '';
    proc.stderr!.on('data', (b: Buffer) => { err += b.toString(); });
    try {
      const deadline = Date.now() + 10_000;
      while (!/Cedar policies loaded/.test(err) || !/cedar-wasm/.test(err)) {
        if (Date.now() > deadline) throw new Error(`no warning:\n${err.slice(-1500)}`);
        await new Promise((r) => setTimeout(r, 50));
      }
      expect(err).toContain('every call will be denied until @cedar-policy/cedar-wasm is installed');
      expect(err).not.toContain('allow-all');
    } finally {
      proc.kill('SIGTERM');
    }
  }, 30_000);
});


d('gateway: a call it cannot evaluate is refused, not a crash', () => {
  it('denies arguments nested 20,000 deep and keeps serving, in enforce and shadow mode', async () => {
    const deep = '{"a":'.repeat(20_000) + '1' + '}'.repeat(20_000);
    for (const enforce of [true, false]) {
      const dir = workspace();
      mkdirSync(join(dir, 'cedar'));
      writeFileSync(join(dir, 'cedar', 'policy.cedar'), CEDAR_PERMIT_ALL_BUT_DANGER);
      const g = new Gateway(dir, [...(enforce ? ['--enforce'] : []), '--cedar', './cedar']);
      try {
        const refused = await g.send(1, raw(1, '"danger"', deep));
        expect(refused.gateway_exited, `exited: ${g.stderr.slice(-300)}`).toBeUndefined();
        expect(text(refused)).toContain('could not evaluate');
        expect(text(await g.call(2, 'safe', { path: '/tmp/x' }))).toBe('CHILD EXECUTED safe');
        expect(executed(dir)).toEqual(['safe']);
      } finally {
        await g.stop();
      }
    }
  }, 40_000);
});

/** The hook server (`serve`) from the built CLI, on a free port, with one PreToolUse call at a time. */
async function hookServer(dir: string, args: string[]) {
  const port = await freePort();
  const proc = spawn(process.execPath, [CLI, 'serve', '--port', String(port), ...args], {
    cwd: dir, env: { ...process.env, PROTECT_MCP_HTTP_PORT: '0' }, stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  proc.stderr!.on('data', (b: Buffer) => { stderr += b.toString(); });
  await waitForHttp(`http://127.0.0.1:${port}/health`);
  return {
    port,
    get stderr() { return stderr; },
    async pre(tool: string, input: Record<string, unknown> = {}): Promise<{ decision: string; reason: string }> {
      const res = await fetch(`http://127.0.0.1:${port}/hook`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's1', tool_name: tool, tool_input: input }),
      });
      const out = (await res.json()) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
      return { decision: out.hookSpecificOutput?.permissionDecision ?? 'allow', reason: out.hookSpecificOutput?.permissionDecisionReason ?? '' };
    },
    stop: () => proc.kill('SIGTERM'),
  };
}

const BAD_RATE_LIMITS = {
  typo: { rate_limit: '10/minutes' },
  not_text: { rate_limit: 10 },
  tier_typo: { rate_limits: { unknown: { max: 5, window: 'fortnight' } } },
};

d('a rate limit the gate cannot read fails closed', () => {
  it('the gateway denies the call and names the bad spec; shadow mode records the deny', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: BAD_RATE_LIMITS }) });
    const g = new Gateway(dir, ['--enforce', '--policy', './rules.json']);
    try {
      expect(text(await g.call(1, 'typo', { path: '/tmp/x' }))).toMatch(/rate limit "10\/minutes" is not a valid spec/);
      expect(text(await g.call(2, 'not_text', { path: '/tmp/x' }))).toMatch(/rate limit 10 is not a valid spec/);
      expect(text(await g.call(3, 'tier_typo', { path: '/tmp/x' }))).toMatch(/rate limit "5\/fortnight" is not a valid spec/);
      expect(executed(dir)).toEqual([]);
    } finally {
      await g.stop();
    }

    const shadow = workspace({ 'rules.json': JSON.stringify({ tools: BAD_RATE_LIMITS }) });
    const s = new Gateway(shadow, ['--policy', './rules.json']);
    try {
      expect(text(await s.call(1, 'typo', { path: '/tmp/x' }))).toBe('CHILD EXECUTED typo');
    } finally {
      await s.stop();
    }
    const logged = readFileSync(join(shadow, '.protect-mcp-log.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
    expect(logged.map((l) => [l.decision, l.reason_code])).toEqual([['deny', 'rate_limit_invalid']]);
  }, 30_000);

  it('the hook server denies the call and names the bad spec', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: BAD_RATE_LIMITS }) });
    const hs = await hookServer(dir, ['--policy', './rules.json']);
    try {
      const typo = await hs.pre('typo', { path: '/tmp/x' });
      expect(typo.decision).toBe('deny');
      expect(typo.reason).toMatch(/rate limit "10\/minutes" is not a valid spec/);
      expect((await hs.pre('not_text')).decision).toBe('deny');
    } finally {
      hs.stop();
    }
  }, 30_000);
});

const PROTOTYPE_NAMES = ['constructor', 'toString', 'hasOwnProperty', '__proto__', 'valueOf'];

d('a tool named like an Object.prototype member gets the rules the policy gives it', () => {
  it('the gateway applies the "*" rule to it, and a rule a policy names that way', async () => {
    const dir = workspace({ 'rules.json': '{"tools":{"*":{"block":true},"valueOf":{"rate_limit":"1/hour"}}}' });
    const g = new Gateway(dir, ['--enforce', '--policy', './rules.json']);
    try {
      let id = 1;
      for (const name of PROTOTYPE_NAMES.filter((n) => n !== 'valueOf')) {
        expect(text(await g.call(id++, name, { path: '/tmp/x' })), name).toContain('blocked by policy');
      }
      expect(text(await g.call(id++, 'valueOf', { path: '/tmp/x' }))).toBe('CHILD EXECUTED valueOf');
      expect(text(await g.call(id++, 'valueOf', { path: '/tmp/x' }))).toContain('rate limit exceeded');
    } finally {
      await g.stop();
    }
    expect(executed(dir)).toEqual(['valueOf']);
  }, 30_000);

  it('the hook server applies the "*" rule to it', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: { '*': { block: true } } }) });
    const hs = await hookServer(dir, ['--policy', './rules.json']);
    try {
      for (const name of PROTOTYPE_NAMES) expect((await hs.pre(name, { path: '/tmp/x' })).decision, name).toBe('deny');
    } finally {
      hs.stop();
    }
  }, 30_000);
});

d('the wrapped command keeps its own flags', () => {
  it('--http and --port after "--" go to the child, and the gateway stays on stdio', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: { '*': {} } }) });
    const childPort = String(await freePort());
    const g = new Gateway(dir, ['--enforce', '--policy', './rules.json'], {}, [], ['--http', '--port', childPort]);
    try {
      expect(text(await g.call(1, 'safe', { path: '/tmp/x' }))).toBe('CHILD EXECUTED safe');
      expect(g.stderr).not.toContain('HTTP transport listening');
    } finally {
      await g.stop();
    }
    expect(JSON.parse(readFileSync(join(dir, 'argv.jsonl'), 'utf-8').trim())).toEqual(['--http', '--port', childPort]);
  }, 30_000);
});

/** A request to 127.0.0.1:port carrying exactly the given Host header. */
function withHost(port: number, path: string, host: string, method = 'GET', body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, setHost: false, headers: { host, 'content-type': 'application/json' } }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: text }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

d('the hook server answers only requests addressed to its loopback port', () => {
  it('refuses a rebinding Host on reads and on /hook, and serves 127.0.0.1, localhost and [::1]', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: { '*': {} } }) });
    const hs = await hookServer(dir, ['--policy', './rules.json']);
    try {
      const evil = `rebind.evil.example:${hs.port}`;
      for (const path of ['/health', '/receipts', '/suggestions']) {
        expect((await withHost(hs.port, path, evil)).status, path).toBe(403);
      }
      const event = JSON.stringify({ hook_event_name: 'PostToolUse', session_id: 's1', tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, tool_use_id: 'forged-1' });
      expect((await withHost(hs.port, '/hook', evil, 'POST', event)).status).toBe(403);
      const logPath = join(dir, '.protect-mcp-log.jsonl');
      expect(existsSync(logPath) ? readFileSync(logPath, 'utf-8') : '').not.toContain('forged-1');
      for (const host of [`127.0.0.1:${hs.port}`, `localhost:${hs.port}`, `[::1]:${hs.port}`]) {
        expect((await withHost(hs.port, '/health', host)).status, host).toBe(200);
      }
    } finally {
      hs.stop();
    }
  }, 30_000);
});

d('gateway: a tool named like an Object.prototype member has no credential of its own', () => {
  it('runs under the same rules as any tool, rather than failing on a credential nobody configured', async () => {
    const dir = workspace({ 'rules.json': JSON.stringify({ tools: { '*': {} }, credentials: { github: { inject: 'env', name: 'GITHUB_TOKEN', value_env: 'PMCP_TEST_UNSET_GITHUB' } } }) });
    const g = new Gateway(dir, ['--enforce', '--policy', './rules.json']);
    try {
      expect(text(await g.call(1, 'constructor', { path: '/tmp/x' }))).toBe('CHILD EXECUTED constructor');
      expect(text(await g.call(2, 'read_file', { path: '/tmp/x' }))).toBe('CHILD EXECUTED read_file');
      // The configured credential, with its variable unset, still fails closed as before.
      expect(text(await g.call(3, 'github', { path: '/tmp/x' }))).toContain('Credential error');
    } finally {
      await g.stop();
    }
  }, 30_000);
});


d('the hook server refuses web pages', () => {
  it('a cross-site text/plain POST cannot get a forged event signed, and a cross-origin page cannot read receipts', async () => {
    const dir = workspace();
    mkdirSync(join(dir, 'keys'));
    writeKey(dir, join('keys', 'gateway.json'));
    const hs = await hookServer(dir, []);
    const base = `http://127.0.0.1:${hs.port}`;
    const forged = JSON.stringify({ hook_event_name: 'PostToolUse', session_id: 's', tool_name: 'Bash', tool_input: { command: 'echo forged-by-page' }, tool_use_id: 'forged-xyz' });
    try {
      // What any page can send without a CORS preflight: refused, with or without an Origin.
      const fromPage = await fetch(`${base}/hook`, { method: 'POST', headers: { 'content-type': 'text/plain', origin: 'https://evil.example' }, body: forged });
      expect(fromPage.status).toBe(403);
      expect((await fetch(`${base}/hook`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: forged })).status).toBe(415);
      expect((await fetch(`${base}/hook`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: forged })).status).toBe(415);
      // A JSON POST from a page on another site is refused too.
      expect((await fetch(`${base}/hook`, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: forged })).status).toBe(403);
      const receiptsFile = join(dir, '.protect-mcp-receipts.jsonl');
      expect(existsSync(receiptsFile) ? readFileSync(receiptsFile, 'utf-8') : '').not.toContain('forged-xyz');

      // A cross-origin read is refused, and no route grants one.
      const read = await fetch(`${base}/receipts`, { headers: { origin: 'https://evil.example' } });
      expect(read.status).toBe(403);
      expect(read.headers.get('access-control-allow-origin')).toBeNull();
      for (const path of ['/health', '/receipts', '/receipts/latest', '/suggestions', '/alerts']) {
        expect((await fetch(`${base}${path}`)).headers.get('access-control-allow-origin'), path).toBeNull();
      }
      const preflight = await fetch(`${base}/hook`, { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' } });
      expect(preflight.headers.get('access-control-allow-origin')).toBeNull();

      // Hook hosts still work: Claude Code's http hooks and the shipped curl hooks send JSON and no Origin.
      expect((await hs.pre('Read', { file_path: '/tmp/x' })).decision).toBe('allow');
      const json = await fetch(`${base}/hook`, { method: 'POST', headers: { 'content-type': 'application/json; charset=utf-8' }, body: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Read', tool_input: {} }) });
      expect(json.status).toBe(200);
      // The approval page's own POST (same origin, JSON) gets past these checks to the route.
      const approve = await fetch(`${base}/mandate/proposals/p1/webauthn/approve`, { method: 'POST', headers: { 'content-type': 'application/json', origin: base }, body: '{}' });
      expect([403, 415]).not.toContain(approve.status);
    } finally {
      hs.stop();
    }
    // Signing was on throughout: the hook calls were signed, the forged event never was.
    const signed = receiptLines(dir).filter((r) => r.signature);
    expect(signed.map((r) => r.payload.tool_name)).toEqual(['Read', 'Read']);
  }, 30_000);
});

// Two tails a receipt log can end in that cannot be continued: a cut-off line, and JSON that cannot be hashed (invalid Unicode).
const CORRUPT_TAILS = ['{"payload":{"type":"protectmcp:decision","tool_name":"pay"', '{"payload":{"note":"\\ud800"}}'];
const RECEIPTS = '.protect-mcp-receipts.jsonl';
const asideFiles = (dir: string) => readdirSync(dir).filter((n) => /^\.protect-mcp-receipts\.jsonl\.corrupt-\d{8}T\d{6}Z(-\d+)?$/.test(n));
const exitOrRunning = (proc: { exited: Promise<number | null> }) =>
  Promise.race([proc.exited, new Promise<string>((resolve) => setTimeout(() => resolve('still running'), 6000))]);

d('a receipt log whose chain cannot be continued', () => {
  it('the gateway under --enforce refuses to start, names the file and leaves it as it was', async () => {
    for (const tail of CORRUPT_TAILS) {
      const dir = workspace({ 'protect-mcp.json': SIGNING_CONFIG });
      writeKey(dir);
      writeFileSync(join(dir, RECEIPTS), `{"type":"earlier"}\n${tail}\n`);
      const before = readFileSync(join(dir, RECEIPTS), 'utf-8');
      const g = new Gateway(dir, ['--enforce', '--policy', './protect-mcp.json']);
      try {
        expect(await exitOrRunning(g), tail).toBe(1);
        expect(g.stderr).toContain('refused to start');
        expect(g.stderr).toContain(join(dir, RECEIPTS));
        expect(readFileSync(join(dir, RECEIPTS), 'utf-8')).toBe(before);
        expect(asideFiles(dir)).toEqual([]);
        expect(executed(dir)).toEqual([]);
      } finally {
        await g.stop();
      }
    }
  }, 30_000);

  it('the gateway in shadow mode moves the file aside, warns, and starts a new chain in a fresh file', async () => {
    for (const tail of CORRUPT_TAILS) {
      const dir = workspace({ 'protect-mcp.json': SIGNING_CONFIG });
      writeKey(dir);
      writeFileSync(join(dir, RECEIPTS), `{"type":"earlier"}\n${tail}\n`);
      const before = readFileSync(join(dir, RECEIPTS), 'utf-8');
      const g = new Gateway(dir, ['--policy', './protect-mcp.json']);
      try {
        expect(text(await g.call(1, 'pay', { to: 'acct-1' }))).toBe('CHILD EXECUTED pay');
      } finally {
        await g.stop();
      }
      const aside = asideFiles(dir);
      expect(aside.length, tail).toBe(1);
      expect(readFileSync(join(dir, aside[0]), 'utf-8')).toBe(before);
      expect(g.stderr).toContain(aside[0]);
      const fresh = receiptLines(dir);
      expect(fresh.length).toBe(1);
      expect(fresh[0].payload.previousReceiptHash).toBeUndefined();
    }
  }, 30_000);

  it('the gateway starts a new chain for a missing or empty log, and continues a readable one', async () => {
    const dir = workspace({ 'protect-mcp.json': SIGNING_CONFIG });
    writeKey(dir);
    writeFileSync(join(dir, RECEIPTS), '');
    for (const id of [1, 2]) {
      const g = new Gateway(dir, ['--enforce', '--policy', './protect-mcp.json']);
      try {
        expect(text(await g.call(id, 'pay', { to: 'acct-1' }))).toBe('CHILD EXECUTED pay');
      } finally {
        await g.stop();
      }
    }
    const [first, second] = receiptLines(dir);
    expect(first.payload.previousReceiptHash).toBeUndefined();
    expect(second.payload.previousReceiptHash).toBe(chainLink(first));
  }, 30_000);

  it('the hook server under --enforce refuses to start, and in shadow mode moves the file aside', async () => {
    const enforced = workspace();
    writeFileSync(join(enforced, RECEIPTS), `${CORRUPT_TAILS[0]}\n`);
    const port = await freePort();
    const proc = spawn(process.execPath, [CLI, 'serve', '--enforce', '--port', String(port)], {
      cwd: enforced, env: { ...process.env, PROTECT_MCP_HTTP_PORT: '0' }, stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    proc.stderr!.on('data', (b: Buffer) => { stderr += b.toString(); });
    const exited = new Promise<number | null>((resolve) => proc.on('exit', (code) => resolve(code)));
    try {
      expect(await exitOrRunning({ exited })).not.toBe('still running');
      expect(stderr).toContain(join(enforced, RECEIPTS));
      expect(asideFiles(enforced)).toEqual([]);
    } finally {
      proc.kill('SIGTERM');
    }

    const shadow = workspace();
    mkdirSync(join(shadow, 'keys'));
    writeKey(shadow, join('keys', 'gateway.json'));
    writeFileSync(join(shadow, RECEIPTS), `${CORRUPT_TAILS[1]}\n`);
    const hs = await hookServer(shadow, []);
    try {
      expect((await hs.pre('Read', { file_path: '/tmp/x' })).decision).toBe('allow');
    } finally {
      hs.stop();
    }
    expect(asideFiles(shadow).length).toBe(1);
    const fresh = receiptLines(shadow);
    expect(fresh.length).toBe(1);
    expect(fresh[0].payload.previousReceiptHash).toBeUndefined();
  }, 30_000);
});

// A receipt log the gate can read but not append to. Root ignores file modes, so these cases skip there.
const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
function readOnlyReceiptLog(dir: string): void {
  writeFileSync(join(dir, RECEIPTS), '');
  chmodSync(join(dir, RECEIPTS), 0o444);
}

d('an allowed call whose receipt cannot be recorded', () => {
  it.skipIf(asRoot)('the gateway under --enforce refuses it, and shadow mode runs it as before', async () => {
    for (const enforce of [true, false]) {
      const dir = workspace({ 'protect-mcp.json': SIGNING_CONFIG });
      writeKey(dir);
      readOnlyReceiptLog(dir);
      const g = new Gateway(dir, [...(enforce ? ['--enforce'] : []), '--policy', './protect-mcp.json']);
      try {
        const r = await g.call(1, 'pay', { to: 'acct-1' });
        if (enforce) {
          expect(text(r)).toContain('receipt could not be recorded');
          expect(executed(dir)).toEqual([]);
        } else {
          expect(text(r)).toBe('CHILD EXECUTED pay');
        }
      } finally {
        await g.stop();
      }
      // The decision log still has the line, as before.
      expect(readFileSync(join(dir, '.protect-mcp-log.jsonl'), 'utf-8')).toContain('"tool":"pay"');
    }
  }, 30_000);

  it.skipIf(asRoot)('the hook server under --enforce refuses it, and shadow mode allows it as before', async () => {
    for (const enforce of [true, false]) {
      const dir = workspace();
      mkdirSync(join(dir, 'keys'));
      writeKey(dir, join('keys', 'gateway.json'));
      readOnlyReceiptLog(dir);
      const hs = await hookServer(dir, enforce ? ['--enforce'] : []);
      try {
        const r = await hs.pre('Read', { file_path: '/tmp/x' });
        if (enforce) {
          expect(r.decision).toBe('deny');
          expect(r.reason).toContain('receipt could not be recorded');
        } else {
          expect(r.decision).toBe('allow');
        }
      } finally {
        hs.stop();
      }
    }
  }, 30_000);
});

