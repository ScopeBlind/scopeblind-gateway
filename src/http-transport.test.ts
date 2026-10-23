/**
 * The --http transport, driven through the BUILT CLI: where it listens, who
 * may call it, and what it tells a caller who has not authenticated.
 */
import { describe, it, expect } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const d = existsSync(CLI) ? describe : describe.skip;

const CHILD = `
import { createInterface } from 'node:readline';
import { appendFileSync } from 'node:fs';
createInterface({ input: process.stdin }).on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'tools/call') appendFileSync('executed.jsonl', JSON.stringify({ tool: m.params && m.params.name }) + '\\n');
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'CHILD EXECUTED ' + (m.params && m.params.name) }] } }) + '\\n');
});
`;

function freePort(host = '127.0.0.1'): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, host, () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
  });
}

const canListen = (host: string) => freePort(host).then(() => true, () => false);
const lanAddress = Object.values(networkInterfaces()).flat().find((a) => a && a.family === 'IPv4' && !a.internal)?.address;

class HttpGateway {
  readonly proc: ChildProcess;
  stderr = '';
  readonly dir = mkdtempSync(join(tmpdir(), 'pmcp-http-'));
  constructor(args: string[], env: Record<string, string> = {}, childArgs: string[] = []) {
    writeFileSync(join(this.dir, 'child.mjs'), CHILD);
    this.proc = spawn(process.execPath, [CLI, '--http', ...args, '--', process.execPath, 'child.mjs', ...childArgs], {
      cwd: this.dir, env: { ...process.env, PROTECT_MCP_HTTP_PORT: '0', ...env }, stdio: ['ignore', 'ignore', 'pipe'],
    });
    this.proc.stderr!.on('data', (b: Buffer) => { this.stderr += b.toString(); });
  }
  async stderrMatch(re: RegExp, ms = 8000): Promise<RegExpExecArray> {
    const until = Date.now() + ms;
    for (;;) {
      const m = re.exec(this.stderr);
      if (m) return m;
      if (Date.now() > until) throw new Error(`stderr never matched ${re}:\n${this.stderr.slice(-1500)}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }
  executed(): string[] {
    const path = join(this.dir, 'executed.jsonl');
    return existsSync(path) ? readFileSync(path, 'utf-8').trim().split('\n').map((l) => JSON.parse(l).tool) : [];
  }
  stop(): void { this.proc.kill('SIGTERM'); }
}

const toolCall = (id: number) => JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'safe', arguments: {} } });
const post = (url: string, headers: Record<string, string> = {}) =>
  fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: toolCall(1) });

d('--http transport: loopback, bearer token, no CORS', () => {
  it('listens on 127.0.0.1 by default, and only a caller with the printed token reaches the tools', async () => {
    const port = await freePort();
    const g = new HttpGateway(['--port', String(port)]);
    try {
      expect((await g.stderrMatch(/HTTP transport listening on (\S+)/))[1]).toBe(`http://127.0.0.1:${port}`);
      const token = (await g.stderrMatch(/Bearer token: ([0-9a-f]{64})/))[1];
      const base = `http://127.0.0.1:${port}`;

      expect((await post(`${base}/mcp`)).status).toBe(401);
      expect((await post(`${base}/mcp`, { authorization: `Bearer ${'0'.repeat(64)}` })).status).toBe(401);
      expect((await post(`${base}/mcp`, { authorization: token })).status).toBe(401);
      expect((await fetch(`${base}/mcp/sse`)).status).toBe(401);
      expect((await fetch(`${base}/mcp`, { method: 'DELETE' })).status).toBe(401);
      expect(g.executed()).toEqual([]);

      const ok = await post(`${base}/mcp`, { authorization: `Bearer ${token}` });
      expect(ok.status).toBe(200);
      expect(JSON.stringify(await ok.json())).toContain('CHILD EXECUTED safe');
      expect(g.executed()).toEqual(['safe']);

      // Not reachable through any other interface.
      if (lanAddress) await expect(fetch(`http://${lanAddress}:${port}/health`)).rejects.toThrow();
    } finally {
      g.stop();
    }
  }, 20_000);

  it('sends no CORS headers, and /health does not show the wrapped command', async () => {
    const port = await freePort();
    const g = new HttpGateway(['--port', String(port)]);
    try {
      const token = (await g.stderrMatch(/Bearer token: ([0-9a-f]{64})/))[1];
      const base = `http://127.0.0.1:${port}`;
      const evil = { origin: 'https://evil.example' };
      const preflight = await fetch(`${base}/mcp`, { method: 'OPTIONS', headers: { ...evil, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type,authorization' } });
      expect(preflight.headers.get('access-control-allow-origin')).toBeNull();
      expect(preflight.headers.get('access-control-allow-credentials')).toBeNull();
      const withOrigin = await post(`${base}/mcp`, { ...evil, authorization: `Bearer ${token}` });
      expect(withOrigin.headers.get('access-control-allow-origin')).toBeNull();

      const health = await fetch(`${base}/health`);
      expect(health.status).toBe(200);
      const body = await health.text();
      expect(JSON.parse(body).status).toBe('ok');
      expect(body).not.toContain('child.mjs');
      expect(body).not.toContain('wrapping');
    } finally {
      g.stop();
    }
  }, 20_000);

  it('takes the token from PROTECT_MCP_HTTP_TOKEN without printing it', async () => {
    const port = await freePort();
    const secret = 'operator-chosen-token-for-this-test-0123456789';
    const g = new HttpGateway(['--port', String(port)], { PROTECT_MCP_HTTP_TOKEN: secret });
    try {
      await g.stderrMatch(/Bearer token: from PROTECT_MCP_HTTP_TOKEN/);
      expect(g.stderr).not.toContain(secret);
      const base = `http://127.0.0.1:${port}`;
      expect((await post(`${base}/mcp`, { authorization: `Bearer ${secret}x` })).status).toBe(401);
      expect((await post(`${base}/mcp`, { authorization: `Bearer ${secret}` })).status).toBe(200);
    } finally {
      g.stop();
    }
  }, 20_000);

  it('listens on another address only when asked, with --host or PROTECT_MCP_HTTP_HOST', async () => {
    if (!(await canListen('::1'))) return; // no IPv6 loopback on this machine
    for (const [args, env] of [[['--host', '::1'], {}], [[], { PROTECT_MCP_HTTP_HOST: '::1' }]] as Array<[string[], Record<string, string>]>) {
      const port = await freePort('::1');
      const g = new HttpGateway(['--port', String(port), ...args], env);
      try {
        expect((await g.stderrMatch(/HTTP transport listening on (\S+)/))[1]).toBe(`http://[::1]:${port}`);
        expect((await fetch(`http://[::1]:${port}/health`)).status).toBe(200);
        await expect(fetch(`http://127.0.0.1:${port}/health`)).rejects.toThrow();
      } finally {
        g.stop();
      }
    }
  }, 30_000);

  it('refuses a call it cannot evaluate (arguments nested 20,000 deep) as a JSON-RPC error, and keeps serving', async () => {
    const port = await freePort();
    const g = new HttpGateway(['--port', String(port), '--enforce']);
    try {
      const token = (await g.stderrMatch(/Bearer token: ([0-9a-f]{64})/))[1];
      const deep = '{"a":'.repeat(20_000) + '1' + '}'.repeat(20_000);
      const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":${deep}}}`,
      });
      expect(res.status).toBe(200);
      expect((await res.json()).error.message).toContain('could not evaluate');
      expect((await post(`http://127.0.0.1:${port}/mcp`, { authorization: `Bearer ${token}` })).status).toBe(200);
      expect(g.executed()).toEqual(['safe']);
    } finally {
      g.stop();
    }
  }, 20_000);

  it("listens on its own --port, never one in the wrapped command's arguments", async () => {
    const childPort = await freePort();
    const g = new HttpGateway([], {}, ['--port', String(childPort)]);
    try {
      // With no --port of its own the gateway takes 3000 (or reports that 3000 is busy).
      const m = await g.stderrMatch(/HTTP transport listening on http:\/\/127\.0\.0\.1:(\d+)|address already in use \S*?:(\d+)/);
      expect(m[1] ?? m[2]).toBe('3000');
      await expect(fetch(`http://127.0.0.1:${childPort}/health`)).rejects.toThrow();
    } finally {
      g.stop();
    }
  }, 20_000);

  it('refuses to start when PROTECT_MCP_HTTP_TOKEN is set but shorter than 32 characters, and never prints it', async () => {
    for (const short of ['', 'x'.repeat(31), `  ${'y'.repeat(30)}  `]) {
      const g = new HttpGateway(['--port', String(await freePort())], { PROTECT_MCP_HTTP_TOKEN: short });
      try {
        const code = await Promise.race([
          new Promise<number | null>((resolve) => g.proc.on('exit', (c) => resolve(c))),
          new Promise<string>((resolve) => setTimeout(() => resolve('still running'), 6000)),
        ]);
        expect(code, JSON.stringify(short)).toBe(1);
        expect(g.stderr).toMatch(/PROTECT_MCP_HTTP_TOKEN must be at least 32 characters/);
        if (short.trim()) expect(g.stderr).not.toContain(short.trim());
        expect(g.executed()).toEqual([]);
      } finally {
        g.stop();
      }
    }
  }, 30_000);

  it('a generated token meets the minimum, and a 32-character token is accepted', async () => {
    const generated = new HttpGateway(['--port', String(await freePort())]);
    try {
      expect((await generated.stderrMatch(/Bearer token: (\S+)/))[1].length).toBeGreaterThanOrEqual(32);
    } finally {
      generated.stop();
    }
    const port = await freePort();
    const exact = 'z'.repeat(32);
    const g = new HttpGateway(['--port', String(port)], { PROTECT_MCP_HTTP_TOKEN: exact });
    try {
      await g.stderrMatch(/Bearer token: from PROTECT_MCP_HTTP_TOKEN/);
      expect((await post(`http://127.0.0.1:${port}/mcp`, { authorization: `Bearer ${exact}` })).status).toBe(200);
    } finally {
      g.stop();
    }
  }, 20_000);
});

