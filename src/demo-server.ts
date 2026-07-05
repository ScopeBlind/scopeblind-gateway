#!/usr/bin/env node

/**
 * @scopeblind/protect-mcp — Built-in Demo MCP Server
 *
 * A minimal MCP server (JSON-RPC over stdio) that registers 5 demo tools.
 * Used by `protect-mcp demo` to let users see receipts flowing
 * without having their own MCP server.
 *
 * Tools:
 *  - read_file    (safe, high-frequency)
 *  - write_file   (medium risk)
 *  - delete_file  (destructive, blocked by default policy)
 *  - web_search   (rate-limited)
 *  - deploy       (high-privilege)
 *  - github_create_pr (source-control mutation)
 *  - send_email   (external communication)
 *  - pms_book_fill (mock portfolio-management booking)
 */

import { createInterface } from 'node:readline';

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
}

const TOOLS = [
  {
    name: 'read_file',
    description: 'Read the contents of a file',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'File path to read' } },
      required: ['path'],
    },
  },
  {
    name: 'write_file',
    description: 'Write content to a file',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'File path to write' },
        content: { type: 'string', description: 'Content to write' },
      },
      required: ['path', 'content'],
    },
  },
  {
    name: 'delete_file',
    description: 'Delete a file from the filesystem',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'File path to delete' } },
      required: ['path'],
    },
  },
  {
    name: 'web_search',
    description: 'Search the web for information',
    inputSchema: {
      type: 'object',
      properties: { query: { type: 'string', description: 'Search query' } },
      required: ['query'],
    },
  },
  {
    name: 'deploy',
    description: 'Deploy the application to production',
    inputSchema: {
      type: 'object',
      properties: {
        environment: { type: 'string', description: 'Target environment', enum: ['staging', 'production'] },
        reason: { type: 'string', description: 'Deployment reason' },
      },
      required: ['environment'],
    },
  },
  {
    name: 'github_create_pr',
    description: 'Create a GitHub pull request',
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string', description: 'Repository name' },
        branch: { type: 'string', description: 'Source branch' },
        title: { type: 'string', description: 'Pull request title' },
      },
      required: ['repo', 'branch', 'title'],
    },
  },
  {
    name: 'send_email',
    description: 'Send an email',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient email address' },
        subject: { type: 'string', description: 'Subject line' },
        body: { type: 'string', description: 'Message body' },
      },
      required: ['to', 'subject'],
    },
  },
  {
    name: 'pms_book_fill',
    description: 'Book a fill into the mock portfolio management system',
    inputSchema: {
      type: 'object',
      properties: {
        account: { type: 'string', description: 'Portfolio or fund account' },
        symbol: { type: 'string', description: 'Instrument symbol' },
        side: { type: 'string', enum: ['BUY', 'SELL'] },
        quantity: { type: 'number' },
        price: { type: 'number' },
        strategy: { type: 'string' },
      },
      required: ['account', 'symbol', 'side', 'quantity', 'price'],
    },
  },
];

function handleRequest(request: JsonRpcRequest): string {
  // Handle MCP protocol methods
  if (request.method === 'initialize') {
    return JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: {
        protocolVersion: '2024-11-05',
        serverInfo: { name: 'protect-mcp-demo', version: process.env.PROTECT_MCP_VERSION || '0.5.3' },
        capabilities: { tools: {} },
      },
    });
  }

  if (request.method === 'notifications/initialized') {
    // No response needed for notifications
    return '';
  }

  if (request.method === 'tools/list') {
    return JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: { tools: TOOLS },
    });
  }

  if (request.method === 'tools/call') {
    const toolName = (request.params?.name as string) || 'unknown';
    const args = (request.params?.arguments as Record<string, unknown>) || {};

    let resultText: string;
    switch (toolName) {
      case 'read_file':
        resultText = `[demo] Read file: ${args.path || '/example.txt'}\nContents: Hello from protect-mcp demo server!`;
        break;
      case 'write_file':
        resultText = `[demo] Wrote ${String(args.content || '').length} bytes to ${args.path || '/example.txt'}`;
        break;
      case 'delete_file':
        resultText = `[demo] Deleted file: ${args.path || '/example.txt'}`;
        break;
      case 'web_search':
        resultText = `[demo] Search results for "${args.query || 'test'}":\n1. Example result — scopeblind.com\n2. MCP security — modelcontextprotocol.io`;
        break;
      case 'deploy':
        resultText = `[demo] Deployed to ${args.environment || 'staging'}${args.reason ? ` (reason: ${args.reason})` : ''}`;
        break;
      case 'github_create_pr':
        resultText = `[demo] Created PR in ${args.repo || 'scopeblind/demo'} from ${args.branch || 'agent/demo'}: ${args.title || 'Agent change'}`;
        break;
      case 'send_email':
        resultText = `[demo] Drafted email to ${args.to || 'pm@example.com'}: ${args.subject || 'Agent update'}`;
        break;
      case 'pms_book_fill':
        resultText = `[demo] Booked ${args.side || 'BUY'} ${args.quantity || 0} ${args.symbol || 'AAPL'} @ ${args.price || 0} into ${args.account || 'Demo Fund'} (${args.strategy || 'Unassigned'})`;
        break;
      default:
        resultText = `[demo] Unknown tool: ${toolName}`;
    }

    return JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: {
        content: [{ type: 'text', text: resultText }],
      },
    });
  }

  // Unknown method
  if (request.id !== undefined) {
    return JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      error: { code: -32601, message: `Method not found: ${request.method}` },
    });
  }

  return '';
}

// Main: read JSON-RPC lines from stdin, write responses to stdout
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line: string) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const request = JSON.parse(trimmed) as JsonRpcRequest;
    const response = handleRequest(request);
    if (response) {
      process.stdout.write(response + '\n');
    }
  } catch {
    // Ignore malformed input
  }
});

process.stderr.write('[DEMO_SERVER] protect-mcp demo server started — 5 tools registered\n');

/**
 * Smithery sandbox server — returns a McpServer instance
 * that Smithery can scan for tool/resource capabilities.
 */
export function createSandboxServer() {
  const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
  const { z } = require('zod');

  const server = new McpServer({
    name: 'protect-mcp',
    version: process.env.PROTECT_MCP_VERSION || '0.4.5',
    description: 'Security gateway for MCP servers. Per-tool policies, Ed25519-signed receipts, human approval gates, trust tiers.',
  });

  server.tool('read_file', 'Read the contents of a file', { path: z.string().describe('File path to read') },
    async (args: { path: string }) => ({ content: [{ type: 'text' as const, text: `[demo] Read file: ${args.path}` }] }));

  server.tool('write_file', 'Write content to a file', { path: z.string().describe('File path'), content: z.string().describe('Content to write') },
    async (args: { path: string; content: string }) => ({ content: [{ type: 'text' as const, text: `[demo] Wrote to ${args.path}` }] }));

  server.tool('delete_file', 'Delete a file from the filesystem', { path: z.string().describe('File path to delete') },
    async (args: { path: string }) => ({ content: [{ type: 'text' as const, text: `[demo] Deleted: ${args.path}` }] }));

  server.tool('web_search', 'Search the web for information', { query: z.string().describe('Search query') },
    async (args: { query: string }) => ({ content: [{ type: 'text' as const, text: `[demo] Search: ${args.query}` }] }));

  server.tool('deploy', 'Deploy the application to production', { environment: z.enum(['staging', 'production']).describe('Target environment'), reason: z.string().optional().describe('Deployment reason') },
    async (args: { environment: string; reason?: string }) => ({ content: [{ type: 'text' as const, text: `[demo] Deployed to ${args.environment}` }] }));

  server.tool('github_create_pr', 'Create a GitHub pull request', {
    repo: z.string(),
    branch: z.string(),
    title: z.string(),
  }, async (args: { repo: string; branch: string; title: string }) => ({
    content: [{ type: 'text' as const, text: `[demo] PR created in ${args.repo} from ${args.branch}: ${args.title}` }],
  }));

  server.tool('send_email', 'Send an email', {
    to: z.string(),
    subject: z.string(),
    body: z.string().optional(),
  }, async (args: { to: string; subject: string; body?: string }) => ({
    content: [{ type: 'text' as const, text: `[demo] Email prepared for ${args.to}: ${args.subject}` }],
  }));

  server.tool('pms_book_fill', 'Book a fill into a mock PMS', {
    account: z.string(),
    symbol: z.string(),
    side: z.enum(['BUY', 'SELL']),
    quantity: z.number(),
    price: z.number(),
    strategy: z.string().optional(),
  }, async (args: { account: string; symbol: string; side: 'BUY' | 'SELL'; quantity: number; price: number; strategy?: string }) => ({
    content: [{ type: 'text' as const, text: `[demo] Booked ${args.side} ${args.quantity} ${args.symbol} @ ${args.price} into ${args.account}` }],
  }));

  return server;
}
