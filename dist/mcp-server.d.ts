#!/usr/bin/env node
/**
 * protect-mcp — the gate as an MCP server (JSON-RPC over stdio).
 *
 * `protect-mcp mcp` exposes the gate's product surface as MCP tools, so an
 * agent or orchestrator can ask "may I do this?" and "prove I was restrained"
 * as ordinary tool calls, without wiring the PreToolUse/PostToolUse hooks. The
 * four tools are the whole loop:
 *
 *   evaluate_action  decide a proposed tool call against a Cedar policy (fail-closed)
 *   sign_decision    turn a decision into an Ed25519 signed receipt
 *   verify_receipt   check a signed receipt offline against a public key
 *   self_test        prove the gate denies a known-forbidden action and the
 *                    sign -> verify round-trip holds
 *
 * Hand-rolled JSON-RPC (no MCP SDK dependency) to match src/demo-server.ts and
 * keep the bundle lean. Every tool is read-only with respect to the world: it
 * makes decisions and produces artifacts, but writes nothing and contacts no
 * network. Receipts are byte-compatible with the ones the gate signs (same
 * payload shape as src/signing.ts).
 */
declare function runMcpServer(): Promise<void>;

export { runMcpServer };
