/**
 * The local dashboard (`protect-mcp dashboard`), through the BUILT CLI: a web
 * page the operator happens to have open must not be able to change policy,
 * install packs or connectors, anchor or resolve approvals through it, and a
 * page that rebinds its own name to 127.0.0.1 must not be able to read it.
 * Its own page must keep working.
 */
import { describe, it, expect } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const d = existsSync(CLI) ? describe : describe.skip;

const POLICY = JSON.stringify({ tools: { delete_file: { block: true } } });
const STATE_ROUTES: Array<[string, Record<string, unknown>]> = [
  ['/api/tool-policy', { tool: 'delete_file', action: 'observe' }],
  ['/api/policy-packs/install', { pack: 'filesystem-safe', force: true }],
  ['/api/connectors/install', { pilot: 'github', force: true }],
  ['/api/registry/anchor', { hosted: true, endpoint: 'https://collector.evil.example' }],
  ['/api/approval/resolve', { request_id: 'r1', tool: 'delete_file', resolution: 'approve' }],
];

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

async function dashboard(dir: string): Promise<{ port: number; proc: ChildProcess }> {
  const port = await freePort();
  const proc = spawn(process.execPath, [CLI, 'dashboard', '--port', String(port), '--dir', dir], { cwd: dir, stdio: 'ignore' });
  const until = Date.now() + 10_000;
  for (;;) {
    try { await fetch(`http://127.0.0.1:${port}/api/summary`); return { port, proc }; } catch { /* not up yet */ }
    if (Date.now() > until) throw new Error('dashboard did not start');
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** A request with full control of Host, Origin and Content-Type. */
function send(port: number, path: string, opts: { method?: string; host?: string; headers?: Record<string, string>; body?: string } = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: '127.0.0.1', port, path, method: opts.method || 'GET', setHost: false,
      headers: { host: opts.host ?? `127.0.0.1:${port}`, ...(opts.headers || {}) },
    }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: text }));
    });
    req.on('error', reject);
    req.end(opts.body);
  });
}

const pageToken = (html: string): string | undefined => /var DASHBOARD_TOKEN = '([0-9a-f]{64})';/.exec(html)?.[1];

/** Every file under the folder and its contents, to check that a refused request wrote nothing. */
function snapshot(dir: string, prefix = ''): string {
  return readdirSync(join(dir, prefix), { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((entry) => {
      const rel = join(prefix, entry.name);
      return entry.isDirectory() ? `${rel}/\n${snapshot(dir, rel)}` : `${rel}: ${readFileSync(join(dir, rel), 'utf-8')}`;
    })
    .join('\n');
}

function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), 'pmcp-dashboard-'));
  writeFileSync(join(dir, 'protect-mcp.json'), POLICY);
  return dir;
}

d('dashboard: only its own page can change anything', () => {
  it('refuses the text/plain cross-site POST that rewrote the policy', async () => {
    const dir = workspace();
    const { port, proc } = await dashboard(dir);
    try {
      // What any web page can send without a CORS preflight.
      const res = await fetch(`http://127.0.0.1:${port}/api/tool-policy`, {
        method: 'POST', headers: { 'content-type': 'text/plain', origin: 'https://evil.example' },
        body: JSON.stringify({ tool: 'delete_file', action: 'observe' }),
      });
      expect(res.status).toBe(403);
      expect(readFileSync(join(dir, 'protect-mcp.json'), 'utf-8')).toBe(POLICY);
    } finally {
      proc.kill('SIGTERM');
    }
  }, 20_000);

  it('every state-changing route needs the page origin, a JSON body and the launch token', async () => {
    const dir = workspace();
    const { port, proc } = await dashboard(dir);
    try {
      const token = pageToken((await send(port, '/')).body);
      expect(token).toBeDefined();
      const before = snapshot(dir);
      const own = `http://127.0.0.1:${port}`;
      for (const [path, payload] of STATE_ROUTES) {
        const body = JSON.stringify(payload);
        const json = { 'content-type': 'application/json' };
        const cases: Array<[Record<string, string>, number, string]> = [
          [{ ...json, origin: 'https://evil.example', 'x-dashboard-token': token! }, 403, 'cross_site_request'],
          [{ ...json, origin: 'null', 'x-dashboard-token': token! }, 403, 'cross_site_request'],
          [{ 'content-type': 'text/plain', origin: own, 'x-dashboard-token': token! }, 415, 'json_required'],
          [{ ...json, origin: own }, 403, 'dashboard_token_required'],
          [{ ...json, origin: own, 'x-dashboard-token': 'f'.repeat(64) }, 403, 'dashboard_token_required'],
          [json, 403, 'dashboard_token_required'],
        ];
        for (const [headers, status, error] of cases) {
          const res = await send(port, path, { method: 'POST', headers, body });
          expect(res.status, `${path} ${JSON.stringify(headers)}`).toBe(status);
          expect(JSON.parse(res.body).error, path).toBe(error);
        }
      }
      expect(snapshot(dir)).toBe(before);
    } finally {
      proc.kill('SIGTERM');
    }
  }, 30_000);

  it('answers only requests addressed to its loopback port, so a rebinding page cannot read it or its token', async () => {
    const dir = workspace();
    const { port, proc } = await dashboard(dir);
    try {
      for (const path of ['/', '/api/summary', '/api/audit-bundle']) {
        const res = await send(port, path, { host: `rebind.evil.example:${port}` });
        expect(res.status, path).toBe(403);
        expect(pageToken(res.body), path).toBeUndefined();
      }
      for (const host of [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]) {
        expect((await send(port, '/api/summary', { host })).status, host).toBe(200);
      }
    } finally {
      proc.kill('SIGTERM');
    }
  }, 20_000);

  it('its own page keeps working: every POST it makes carries the token, and that request is accepted', async () => {
    const dir = workspace();
    const { port, proc } = await dashboard(dir);
    try {
      const html = await (await fetch(`http://127.0.0.1:${port}/`)).text();
      const token = pageToken(html);
      expect(token).toBeDefined();
      const posts = [...html.matchAll(/fetch\('([^']+)', \{ method:'POST', headers:\{([^}]*)\}/g)];
      expect(posts.map((m) => m[1]).sort()).toEqual(STATE_ROUTES.map(([path]) => path).sort());
      for (const m of posts) expect(m[2], m[1]).toContain("'x-dashboard-token':DASHBOARD_TOKEN");

      // The request the page sends when the person presses Observe on delete_file.
      const res = await fetch(`http://127.0.0.1:${port}/api/tool-policy`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: `http://127.0.0.1:${port}`, 'x-dashboard-token': token! },
        body: JSON.stringify({ tool: 'delete_file', action: 'observe' }),
      });
      expect(res.status).toBe(200);
      expect(JSON.parse(readFileSync(join(dir, 'protect-mcp.json'), 'utf-8')).tools.delete_file).toEqual({ rate_limit: '100/hour' });
    } finally {
      proc.kill('SIGTERM');
    }
  }, 20_000);
});

const logLine = (tool: string, i: number) => JSON.stringify({ v: 2, tool, decision: 'allow', reason_code: 'observe_mode', request_id: `r${i}`, timestamp: Date.now(), mode: 'shadow' });

d('dashboard: tool names are read and written as own entries of the policy', () => {
  it('the coverage view shows the "*" rule for a tool named like an Object.prototype member, and ordinary tools as before', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-dashboard-'));
    writeFileSync(join(dir, 'protect-mcp.json'), JSON.stringify({ tools: { '*': { block: true }, read_file: { rate_limit: '5/minute' } } }));
    writeFileSync(join(dir, '.protect-mcp-log.jsonl'), ['constructor', 'toString', 'read_file', 'other'].map(logLine).join('\n') + '\n');
    const { port, proc } = await dashboard(dir);
    try {
      const summary = await (await fetch(`http://127.0.0.1:${port}/api/summary`)).json() as { tools: Array<{ tool: string; policy_coverage: { status: string; policy?: unknown } }> };
      const coverage = Object.fromEntries(summary.tools.map((t) => [t.tool, t.policy_coverage]));
      expect(coverage.constructor).toEqual({ status: 'wildcard', label: 'Wildcard fallback', policy: { block: true } });
      expect(coverage.toString).toEqual({ status: 'wildcard', label: 'Wildcard fallback', policy: { block: true } });
      expect(coverage.read_file).toEqual({ status: 'exact', label: 'Exact rule', policy: { rate_limit: '5/minute' } });
      expect(coverage.other).toEqual({ status: 'wildcard', label: 'Wildcard fallback', policy: { block: true } });
    } finally {
      proc.kill('SIGTERM');
    }
  }, 20_000);

  it('Block on a tool named __proto__ writes a rule for it, and an ordinary tool as before', async () => {
    const dir = workspace();
    const { port, proc } = await dashboard(dir);
    try {
      const token = pageToken(await (await fetch(`http://127.0.0.1:${port}/`)).text())!;
      const post = (tool: string, action: string) => fetch(`http://127.0.0.1:${port}/api/tool-policy`, {
        method: 'POST', headers: { 'content-type': 'application/json', origin: `http://127.0.0.1:${port}`, 'x-dashboard-token': token },
        body: JSON.stringify({ tool, action }),
      });
      expect((await post('__proto__', 'block')).status).toBe(200);
      expect((await post('read_file', 'require_approval')).status).toBe(200);
    } finally {
      proc.kill('SIGTERM');
    }
    const tools = JSON.parse(readFileSync(join(dir, 'protect-mcp.json'), 'utf-8')).tools;
    expect(Object.prototype.hasOwnProperty.call(tools, '__proto__')).toBe(true);
    expect(tools['__proto__']).toEqual({ block: true, min_tier: 'privileged' });
    expect(tools.read_file).toEqual({ require_approval: true, min_tier: 'signed-known', rate_limit: '10/hour' });
    expect(tools.delete_file).toEqual({ block: true });
  }, 20_000);

  it('recommend --write drafts a rule for a tool named __proto__, and for ordinary tools as before', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-recommend-'));
    writeFileSync(join(dir, '.protect-mcp-log.jsonl'), ['__proto__', 'plain_tool', 'read_file'].map(logLine).join('\n') + '\n');
    const out = join(dir, 'recommended.json');
    const r = spawnSync(process.execPath, [CLI, 'recommend', '--dir', dir, '--output', out, '--write'], { cwd: dir, encoding: 'utf-8', input: '' });
    expect(r.status, r.stderr).toBe(0);
    const tools = JSON.parse(readFileSync(out, 'utf-8')).tools;
    expect(Object.keys(tools).sort()).toEqual(['*', '__proto__', 'plain_tool', 'read_file']);
    // The same draft rule an equally plain name gets.
    expect(tools['__proto__']).toEqual(tools.plain_tool);
  }, 20_000);
});

