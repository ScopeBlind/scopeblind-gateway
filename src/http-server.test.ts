import { describe, it, expect } from 'vitest';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { ReceiptBuffer, startStatusServer } from './http-server.js';

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

/** A request to 127.0.0.1:port carrying the given Host header (none when host is null). */
function send(port: number, path: string, host: string | null, method = 'GET', body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, setHost: false, headers: host === null ? {} : { host } }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: text }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

describe('the local status server', () => {
  it('sends no CORS headers, so a web page cannot read recent decisions or receipts', async () => {
    const port = await freePort();
    const receipts = new ReceiptBuffer();
    receipts.add('req-1', '{"payload":{"tool_name":"send_email"}}');
    const server = startStatusServer({ port, mode: 'enforce' }, receipts, new Map(), 'n'.repeat(32));
    await new Promise((resolve) => server.once('listening', resolve));
    try {
      const evil = { origin: 'https://evil.example' };
      for (const path of ['/receipts', '/receipts/latest', '/receipts/req-1', '/status', '/health', '/approvals']) {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, { headers: evil });
        expect(res.status, path).toBe(200);
        expect(res.headers.get('access-control-allow-origin'), path).toBeNull();
      }
      const preflight = await fetch(`http://127.0.0.1:${port}/approve`, {
        method: 'OPTIONS',
        headers: { ...evil, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' },
      });
      expect(preflight.headers.get('access-control-allow-origin')).toBeNull();
    } finally {
      server.close();
    }
  });

  it('answers only requests addressed to its loopback port, so DNS rebinding cannot read or approve', async () => {
    const port = await freePort();
    const receipts = new ReceiptBuffer();
    receipts.add('req-1', '{"payload":{"tool_name":"send_email"}}');
    const grants = new Map<string, { tool: string; mode: 'once' | 'always'; expires_at: number }>();
    const nonce = 'n'.repeat(32);
    const server = startStatusServer({ port, mode: 'enforce' }, receipts, grants, nonce);
    await new Promise((resolve) => server.once('listening', resolve));
    try {
      for (const host of [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`, `LOCALHOST:${port}`]) {
        expect((await send(port, '/receipts', host)).status, host).toBe(200);
      }
      for (const host of [`rebind.evil.example:${port}`, `127.0.0.1:${port + 1}`, '127.0.0.1', `localhost.evil.example:${port}`]) {
        const res = await send(port, '/receipts', host);
        expect(res.status, host).toBe(403);
        expect(res.body, host).not.toContain('send_email');
      }
      // No Host at all: refused too (newer Node versions answer 400 before the handler runs).
      const bare = await send(port, '/receipts', null);
      expect(bare.status).toBeGreaterThanOrEqual(400);
      expect(bare.body).not.toContain('send_email');
      // Not even with the right nonce: a rebinding page cannot grant itself an approval.
      const approve = await send(port, '/approve', `rebind.evil.example:${port}`, 'POST', JSON.stringify({ tool: 'send_email', mode: 'always', nonce }));
      expect(approve.status).toBe(403);
      expect(grants.size).toBe(0);
    } finally {
      server.close();
    }
  });
});

