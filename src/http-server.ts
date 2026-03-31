/**
 * @scopeblind/protect-mcp — HTTP Status Server
 *
 * Lightweight HTTP server that runs alongside the stdio gateway.
 * Exposes receipts, status, approvals, and health for observability integration.
 *
 * Endpoints:
 *   GET  /health          → { status: "ok", uptime, mode }
 *   GET  /status          → decision stats (same data as `protect-mcp status`)
 *   GET  /receipts        → recent receipts as JSON array
 *   GET  /receipts/latest → most recent receipt
 *   GET  /receipts/:id    → single receipt by request_id
 *   POST /approve         → grant approval for a tool { tool, mode: "once"|"always" }
 *   GET  /approvals       → list current approval grants
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const LOG_FILE = '.protect-mcp-log.jsonl';
const MAX_RECEIPTS = 100;

interface StatusServerConfig {
  port: number;
  mode: 'shadow' | 'enforce';
  verbose?: boolean;
}

interface DecisionEntry {
  tool: string;
  decision: string;
  reason_code: string;
  tier?: string;
  timestamp: number;
  request_id: string;
  credential_ref?: string;
  mode?: string;
}

/**
 * In-memory receipt buffer for the /receipts endpoint.
 */
export class ReceiptBuffer {
  private receipts: Array<{ request_id: string; receipt: string; timestamp: number }> = [];

  add(requestId: string, receipt: string): void {
    this.receipts.push({
      request_id: requestId,
      receipt,
      timestamp: Date.now(),
    });
    // Keep only the most recent MAX_RECEIPTS
    if (this.receipts.length > MAX_RECEIPTS) {
      this.receipts = this.receipts.slice(-MAX_RECEIPTS);
    }
  }

  getAll(): typeof this.receipts {
    return [...this.receipts].reverse(); // newest first
  }

  getById(requestId: string): typeof this.receipts[0] | undefined {
    return this.receipts.find(r => r.request_id === requestId);
  }

  count(): number {
    return this.receipts.length;
  }

  getLatest(): typeof this.receipts[0] | undefined {
    return this.receipts.length > 0 ? this.receipts[this.receipts.length - 1] : undefined;
  }
}

/**
 * Start the HTTP status server.
 */
export function startStatusServer(
  config: StatusServerConfig,
  receiptBuffer: ReceiptBuffer,
  approvalStore?: Map<string, { tool: string; mode: 'once' | 'always'; expires_at: number }>,
  approvalNonce?: string,
): Server {
  const startTime = Date.now();
  const logDir = process.cwd();

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // CORS headers for dashboard/observability tools
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://localhost:${config.port}`);
    const path = url.pathname;

    try {
      if (path === '/health') {
        handleHealth(res, startTime, config);
      } else if (path === '/status') {
        handleStatus(res, logDir);
      } else if (path === '/receipts') {
        handleReceipts(res, receiptBuffer, url);
      } else if (path === '/receipts/latest') {
        handleReceiptLatest(res, receiptBuffer);
      } else if (path.startsWith('/receipts/')) {
        const id = path.slice('/receipts/'.length);
        handleReceiptById(res, receiptBuffer, id);
      } else if (path === '/approve' && req.method === 'POST') {
        handleApprove(req, res, approvalStore, approvalNonce);
      } else if (path === '/approvals' && req.method === 'GET') {
        handleListApprovals(res, approvalStore);
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'not_found', endpoints: ['/health', '/status', '/receipts', '/receipts/latest', '/receipts/:id', '/approve', '/approvals'] }));
      }
    } catch (err) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: 'internal_error' }));
    }
  });

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (config.verbose) {
      process.stderr.write(`[PROTECT_MCP] HTTP status server error: ${err.message}\n`);
    }
  });

  server.listen(config.port, '127.0.0.1', () => {
    if (config.verbose) {
      process.stderr.write(`[PROTECT_MCP] HTTP status server listening on http://127.0.0.1:${config.port}\n`);
    }
  });

  // Don't let the HTTP server prevent process exit
  server.unref();

  return server;
}

function handleHealth(res: ServerResponse, startTime: number, config: StatusServerConfig): void {
  res.writeHead(200);
  res.end(JSON.stringify({
    status: 'ok',
    uptime_ms: Date.now() - startTime,
    mode: config.mode,
    version: '0.3.1',
  }));
}

function handleStatus(res: ServerResponse, logDir: string): void {
  const logPath = join(logDir, LOG_FILE);

  if (!existsSync(logPath)) {
    res.writeHead(200);
    res.end(JSON.stringify({ entries: 0, message: 'no log file yet' }));
    return;
  }

  const raw = readFileSync(logPath, 'utf-8');
  const lines = raw.trim().split('\n').filter(Boolean);
  const entries: DecisionEntry[] = [];

  for (const line of lines) {
    try { entries.push(JSON.parse(line)); } catch { /* skip */ }
  }

  const toolCounts: Record<string, number> = {};
  let allowCount = 0, denyCount = 0;
  const tierCounts: Record<string, number> = {};

  for (const e of entries) {
    toolCounts[e.tool] = (toolCounts[e.tool] || 0) + 1;
    if (e.decision === 'allow') allowCount++;
    else denyCount++;
    if (e.tier) tierCounts[e.tier] = (tierCounts[e.tier] || 0) + 1;
  }

  res.writeHead(200);
  res.end(JSON.stringify({
    entries: entries.length,
    allow: allowCount,
    deny: denyCount,
    tools: toolCounts,
    tiers: tierCounts,
    first_timestamp: entries.length > 0 ? entries[0].timestamp : null,
    last_timestamp: entries.length > 0 ? entries[entries.length - 1].timestamp : null,
  }));
}

function handleReceipts(res: ServerResponse, buffer: ReceiptBuffer, url: URL): void {
  const limit = parseInt(url.searchParams.get('limit') || '20', 10);
  const receipts = buffer.getAll().slice(0, Math.min(limit, MAX_RECEIPTS));

  res.writeHead(200);
  res.end(JSON.stringify({
    count: receipts.length,
    total: buffer.count(),
    receipts,
  }));
}

function handleReceiptLatest(res: ServerResponse, buffer: ReceiptBuffer): void {
  const latest = buffer.getLatest();
  if (!latest) {
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'no_receipts', message: 'No receipts yet. Make a tool call through protect-mcp first.' }));
    return;
  }

  res.writeHead(200);
  res.end(JSON.stringify(latest));
}

function handleReceiptById(res: ServerResponse, buffer: ReceiptBuffer, id: string): void {
  const receipt = buffer.getById(id);
  if (!receipt) {
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'receipt_not_found', request_id: id }));
    return;
  }

  res.writeHead(200);
  res.end(JSON.stringify(receipt));
}

function handleApprove(
  req: IncomingMessage,
  res: ServerResponse,
  approvalStore?: Map<string, { tool: string; mode: 'once' | 'always'; expires_at: number }>,
  expectedNonce?: string,
): void {
  if (!approvalStore) {
    res.writeHead(503);
    res.end(JSON.stringify({ error: 'approval_store_not_available' }));
    return;
  }

  let body = '';
  req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
  req.on('end', () => {
    try {
      const { request_id, tool, mode, nonce } = JSON.parse(body);

      // Verify nonce (prevents unauthorized local processes from granting approvals)
      if (expectedNonce && nonce !== expectedNonce) {
        res.writeHead(403);
        res.end(JSON.stringify({ error: 'invalid_nonce', message: 'Approval nonce does not match. Check stderr output for the correct nonce.' }));
        return;
      }

      if (!tool || typeof tool !== 'string') {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'missing_tool', usage: '{"request_id":"abc123","tool":"send_email","mode":"once|always","nonce":"..."}' }));
        return;
      }

      const grantMode: 'once' | 'always' = mode === 'always' ? 'always' : 'once';
      // TTL: 'once' = 5 minutes (enough for retry), 'always' = 24 hours (session-scoped)
      const ttlMs = grantMode === 'once' ? 5 * 60 * 1000 : 24 * 60 * 60 * 1000;
      const grantEntry = { tool, mode: grantMode, expires_at: Date.now() + ttlMs };

      if (grantMode === 'always') {
        // 'always' grants keyed by tool name for session-wide approval
        approvalStore.set(`always:${tool}`, grantEntry);
      } else if (request_id) {
        // 'once' grants keyed by specific request_id
        approvalStore.set(request_id, grantEntry);
      } else {
        // Fallback: if no request_id, key by tool name (less secure but functional)
        approvalStore.set(tool, grantEntry);
      }

      res.writeHead(200);
      res.end(JSON.stringify({
        approved: true,
        request_id: request_id || null,
        tool,
        mode: grantMode,
        expires_in_seconds: ttlMs / 1000,
      }));
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'invalid_json', usage: '{"request_id":"abc123","tool":"send_email","mode":"once","nonce":"..."}' }));
    }
  });
}

function handleListApprovals(
  res: ServerResponse,
  approvalStore?: Map<string, { tool: string; mode: 'once' | 'always'; expires_at: number }>,
): void {
  if (!approvalStore) {
    res.writeHead(200);
    res.end(JSON.stringify({ grants: [] }));
    return;
  }

  const now = Date.now();
  const grants: Array<{ key: string; tool: string; mode: string; expires_in_seconds: number }> = [];
  for (const [key, grant] of approvalStore) {
    if (now < grant.expires_at) {
      grants.push({ key, tool: grant.tool, mode: grant.mode, expires_in_seconds: Math.round((grant.expires_at - now) / 1000) });
    }
  }

  res.writeHead(200);
  res.end(JSON.stringify({ grants }));
}
