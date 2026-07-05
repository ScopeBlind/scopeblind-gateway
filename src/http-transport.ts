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
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { ProtectGateway } from './gateway.js';
import type { ProtectConfig, JsonRpcRequest } from './types.js';

interface HttpTransportOptions {
  port: number;
  config: ProtectConfig;
  serverCommand: string[];
}

export async function startHttpTransport(options: HttpTransportOptions): Promise<void> {
  const { port, config, serverCommand } = options;

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

  // Start the child process (without stdin reading)
  await gateway.startForHttp();

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // CORS headers
    const origin = req.headers.origin || '*';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id');
    res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    // Preflight
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
        wrapping: serverCommand.join(' '),
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

  server.listen(port, () => {
    process.stderr.write(`\n[PROTECT_MCP] HTTP transport listening on http://0.0.0.0:${port}\n`);
    process.stderr.write(`  POST   /mcp        — JSON-RPC (Streamable HTTP)\n`);
    process.stderr.write(`  GET    /mcp/sse    — Server-Sent Events\n`);
    process.stderr.write(`  GET    /health     — Health check\n`);
    process.stderr.write(`  DELETE /mcp        — Close session\n`);
    process.stderr.write(`\n  Wrapping: ${serverCommand.join(' ')}\n`);
    process.stderr.write(`  Mode: ${config.enforce ? 'enforce' : 'shadow'}\n\n`);
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
