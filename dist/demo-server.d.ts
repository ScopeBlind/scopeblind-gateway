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
/**
 * Smithery sandbox server — returns a McpServer instance
 * that Smithery can scan for tool/resource capabilities.
 */
declare function createSandboxServer(): any;

export { createSandboxServer };
