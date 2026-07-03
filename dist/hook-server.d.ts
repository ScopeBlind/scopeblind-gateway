import { Server } from 'node:http';

/**
 * @scopeblind/protect-mcp — Claude Code Hook Server
 *
 * HTTP server that integrates protect-mcp with Claude Code's hook system.
 * Receives hook events via HTTP POST, evaluates Cedar policies, signs
 * receipts, and returns hook responses matching Claude Code's syncHookResponseSchema.
 *
 * Architecture:
 *   - Persistent local server on 127.0.0.1:9377 (configurable)
 *   - Zero cold start (Cedar policies loaded once, cached in memory)
 *   - PreToolUse: synchronous policy check (deny is authoritative)
 *   - PostToolUse: async receipt signing (never blocks tool execution)
 *   - Full swarm lifecycle tracking (7 agent events)
 *   - ConfigChange tamper detection
 *
 * Claude Code hook config (.claude/settings.json):
 *   {
 *     "hooks": {
 *       "PreToolUse": [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:9377/hook" }] }],
 *       "PostToolUse": [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:9377/hook" }] }]
 *     }
 *   }
 *
 * @standard RFC 8032 (Ed25519), RFC 8785 (JCS)
 */

interface HookServerOptions {
    port?: number;
    policyPath?: string;
    cedarDir?: string;
    enforce?: boolean;
    verbose?: boolean;
}
declare function startHookServer(options?: HookServerOptions): Promise<Server>;

export { type HookServerOptions, startHookServer };
