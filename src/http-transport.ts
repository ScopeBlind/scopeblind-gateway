/**
 * @scopeblind/protect-mcp — HTTP/SSE Transport Layer
 *
 * Exposes protect-mcp as an HTTP server supporting:
 * - Streamable HTTP (POST /mcp with JSON-RPC, response as JSON or SSE)
 * - Server-Sent Events (GET /mcp/sse for event stream)
 * - Health check (GET /health)
 *
 * This enables deployment on Smithery, ChatGPT Apps, Glama, and any
 * MCP client that supports remote HTTP servers.
 *
 * Usage:
 *   npx protect-mcp --http --port 3000 -- node your-server.js
 *
 * It listens on 127.0.0.1 unless another address is asked for (--host or
 * PROTECT_MCP_HTTP_HOST), and every request except GET /health must carry
 * Authorization: Bearer <token>, the token from PROTECT_MCP_HTTP_TOKEN or one
 * generated at startup and printed on stderr. It sends no CORS headers.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { ProtectGateway } from './gateway.js';
import type { ProtectConfig, JsonRpcRequest } from './types.js';

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
const MIN_TOKEN_LENGTH = 32;

interface HttpTransportOptions {
  port: number;
  /** Listen address; default 127.0.0.1 (or PROTECT_MCP_HTTP_HOST) */
  host?: string;
  config: ProtectConfig;
  serverCommand: string[];
  /** Loaded Cedar policy set; attached to the gateway before the child starts */
  cedarPolicySet?: import('./cedar-evaluator.js').CedarPolicySet;
}

export async function startHttpTransport(options: HttpTransportOptions): Promise<void> {
  const { port, config, serverCommand } = options;
  const host = options.host || process.env.PROTECT_MCP_HTTP_HOST || '127.0.0.1';

  // Every request except GET /health must present this bearer token. The
  // comparison runs over fixed-length digests, so it is constant-time. A token
  // the operator sets must be at least 32 characters; a generated one is 64.
  const configuredToken = process.env.PROTECT_MCP_HTTP_TOKEN;
  const tokenFromEnv = configuredToken?.trim() ?? '';
  if (configuredToken !== undefined && tokenFromEnv.length < MIN_TOKEN_LENGTH) {
    throw new Error(`PROTECT_MCP_HTTP_TOKEN must be at least ${MIN_TOKEN_LENGTH} characters (it has ${tokenFromEnv.length}); set a random value, for example the output of: openssl rand -hex 32`);
  }
  const token = tokenFromEnv || randomBytes(32).toString('hex');
  const tokenDigest = createHash('sha256').update(token).digest();
  const authorized = (req: IncomingMessage): boolean => {
    const match = /^Bearer +(.+)$/i.exec(req.headers.authorization || '');
    return match !== null && timingSafeEqual(createHash('sha256').update(match[1].trim()).digest(), tokenDigest);
  };

  // Track SSE connections
  const sseClients = new Set<ServerResponse>();

  // Create the gateway with HTTP mode enabled
  // Override config command/args from serverCommand
  const httpConfig: ProtectConfig = {
    ...config,
    command: serverCommand[0],
    args: serverCommand.slice(1),
  };
  const gateway = new ProtectGateway(httpConfig);

  // Cedar policies MUST be attached before the child starts. Before 0.10.1
  // the stdio path attached them after the HTTP branch returned, so in HTTP
  // mode loaded Cedar policies were silently never enforced (fail-open).
  if (options.cedarPolicySet) {
    gateway.setCedarPolicies(options.cedarPolicySet);
  }

  // Start the child process (without stdin reading)
  await gateway.startForHttp();

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // No CORS headers: this serves MCP clients, not web pages. Reflecting the
    // caller's Origin with credentials let any page a browser opened drive the
    // wrapped tools.

    // Preflight (answered without CORS headers, so a browser refuses it)
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://localhost:${port}`);

    // Health check
    if (url.pathname === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        server: 'protect-mcp',
        version: process.env.PROTECT_MCP_VERSION || 'unknown',
        transport: 'streamable-http',
        mode: config.policy ? (config.enforce ? 'enforce' : 'shadow') : 'shadow',
      }));
      return;
    }

    if (!authorized(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json', 'WWW-Authenticate': 'Bearer' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32001, message: 'Unauthorized: send Authorization: Bearer <token>, the token the gateway printed at startup or PROTECT_MCP_HTTP_TOKEN' },
        id: null,
      }));
      return;
    }

    // SSE endpoint — persistent connection for server-initiated events
    if (url.pathname === '/mcp/sse' && req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });
      res.write(`data: ${JSON.stringify({ type: 'connected', server: 'protect-mcp' })}\n\n`);
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    // Streamable HTTP — JSON-RPC over POST
    if (url.pathname === '/mcp' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', async () => {
        try {
          const jsonRpc = JSON.parse(body) as JsonRpcRequest;

          // Check Accept header for SSE vs JSON response
          const acceptSSE = (req.headers.accept || '').includes('text/event-stream');

          // Process through gateway (policy evaluation + forwarding to child)
          const responseStr = await gateway.processRequest(jsonRpc);
          const response = JSON.parse(responseStr);

          if (acceptSSE) {
            // SSE response mode (Streamable HTTP)
            res.writeHead(200, {
              'Content-Type': 'text/event-stream',
              'Cache-Control': 'no-cache',
            });
            res.write(`data: ${JSON.stringify(response)}\n\n`);
            res.end();
          } else {
            // Standard JSON response
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(response));
          }

          // Broadcast decision events to SSE clients
          if (jsonRpc.method === 'tools/call') {
            const event = {
              type: 'decision',
              tool: jsonRpc.params?.name,
              timestamp: new Date().toISOString(),
            };
            for (const client of sseClients) {
              try {
                client.write(`data: ${JSON.stringify(event)}\n\n`);
              } catch {
                sseClients.delete(client);
              }
            }
          }
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            error: { code: -32700, message: 'Parse error' },
            id: null,
          }));
        }
      });
      return;
    }

    // Session termination (DELETE /mcp)
    if (url.pathname === '/mcp' && req.method === 'DELETE') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'session_closed' }));
      return;
    }

    // 404 for everything else
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: 'not_found',
      endpoints: [
        'POST /mcp          — JSON-RPC endpoint (Streamable HTTP)',
        'GET  /mcp/sse      — Server-Sent Events stream',
        'GET  /health       — Health check',
        'DELETE /mcp        — Close session',
      ],
    }));
  });

  server.listen(port, host, () => {
    const address = server.address();
    const boundPort = address && typeof address === 'object' ? address.port : port;
    process.stderr.write(`\n[PROTECT_MCP] HTTP transport listening on http://${host.includes(':') ? `[${host}]` : host}:${boundPort}\n`);
    process.stderr.write(`  POST   /mcp        — JSON-RPC (Streamable HTTP)\n`);
    process.stderr.write(`  GET    /mcp/sse    — Server-Sent Events\n`);
    process.stderr.write(`  GET    /health     — Health check\n`);
    process.stderr.write(`  DELETE /mcp        — Close session\n`);
    process.stderr.write(`\n  Wrapping: ${serverCommand.join(' ')}\n`);
    process.stderr.write(`  Mode: ${config.enforce ? 'enforce' : 'shadow'}\n`);
    process.stderr.write(`  Bearer token: ${tokenFromEnv ? 'from PROTECT_MCP_HTTP_TOKEN' : token}\n`);
    process.stderr.write(`  Every request except GET /health needs the header Authorization: Bearer <token>\n`);
    if (!LOOPBACK.has(host) && !host.startsWith('127.')) {
      process.stderr.write(`  Warning: ${host} is not a loopback address, so anything that can reach this port can try the token. Put TLS and authentication in front of it.\n`);
    }
    process.stderr.write('\n');
  });

  // Graceful shutdown
  const shutdown = () => {
    process.stderr.write('\n[PROTECT_MCP] Shutting down HTTP transport...\n');
    for (const client of sseClients) {
      try { client.end(); } catch { /* ignore */ }
    }
    server.close();
    gateway.stop();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
