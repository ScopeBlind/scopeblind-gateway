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
];

function handleRequest(request: JsonRpcRequest): string {
  // Handle MCP protocol methods
  if (request.method === 'initialize') {
    return JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: {
        protocolVersion: '2024-11-05',
        serverInfo: { name: 'protect-mcp-demo', version: '0.2.0' },
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
