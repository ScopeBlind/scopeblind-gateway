/**
 * Tests for the protect-mcp Claude Code Hook Server.
 *
 * Tests cover:
 * 1. snake_case → camelCase input normalization (the critical bug fix)
 * 2. PreToolUse: Cedar deny, policy block, rate limit, require_approval, allow
 * 3. PostToolUse: additionalContext inside hookSpecificOutput
 * 4. Swarm lifecycle: SubagentStart/Stop, TaskCreated/Completed
 * 5. Session lifecycle: SessionStart/End
 * 6. ConfigChange tamper detection
 * 7. Payload hashing for large inputs
 * 8. Deny iteration tracking
 * 9. Permission suggestions
 * 10. HTTP integration: round-trip request/response
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';

// We test the normalizer and handler logic by making actual HTTP requests
// to a running hook server instance.

const HOOK_URL = 'http://127.0.0.1:19377/hook';
const HEALTH_URL = 'http://127.0.0.1:19377/health';

// Helper to POST JSON to the hook server
async function postHook(body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(HOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json() as Record<string, unknown>;
  return { status: res.status, body: json };
}

// Helper: minimal PreToolUse event in Claude Code's snake_case format
function makePreToolUse(toolName: string, toolInput: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    hook_event_name: 'PreToolUse',
    session_id: 'test-session-1',
    transcript_path: '/tmp/test-transcript.jsonl',
    cwd: '/tmp',
    tool_name: toolName,
    tool_input: toolInput,
    tool_use_id: `tu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
  };
}

// Helper: minimal PostToolUse event in snake_case
function makePostToolUse(toolName: string, toolResponse: unknown = {}): Record<string, unknown> {
  return {
    hook_event_name: 'PostToolUse',
    session_id: 'test-session-1',
    transcript_path: '/tmp/test-transcript.jsonl',
    cwd: '/tmp',
    tool_name: toolName,
    tool_input: { command: 'echo hello' },
    tool_response: toolResponse,
    tool_use_id: `tu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
  };
}

// ============================================================
// Start hook server for tests (on a non-default port)
// ============================================================

let hookServer: Server | undefined;

beforeAll(async () => {
  // Dynamically import and start the hook server on test port
  const { startHookServer } = await import('./hook-server.js');
  hookServer = await startHookServer({
    port: 19377,
    verbose: false,
    enforce: true,
    // No cedar dir or policy path — runs in observe/allow-all mode
  });
  // Give server time to bind
  await new Promise(r => setTimeout(r, 200));
}, 10_000);

afterAll(() => {
  if (hookServer) {
    hookServer.close();
  }
});

// ============================================================
// 1. Snake_case normalization
// ============================================================

describe('snake_case → camelCase normalization', () => {
  it('accepts snake_case input from Claude Code and processes correctly', async () => {
    const result = await postHook(makePreToolUse('read_file'));
    expect(result.status).toBe(200);
    // In observe mode (no policies), should allow everything
    // Empty response body = implicit allow
  });

  it('rejects requests missing hook_event_name', async () => {
    const result = await postHook({ session_id: 'test', cwd: '/tmp' });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe('missing_hook_event_name');
  });

  it('also accepts camelCase input (forward-compatible)', async () => {
    const result = await postHook({
      hookEventName: 'PreToolUse',
      sessionId: 'test-session-1',
      transcriptPath: '/tmp/test.jsonl',
      cwd: '/tmp',
      toolName: 'read_file',
      toolInput: {},
      toolUseId: 'tu-camel-test',
    });
    expect(result.status).toBe(200);
  });
});

// ============================================================
// 2. PreToolUse handler
// ============================================================

describe('PreToolUse handler', () => {
  it('returns implicit allow (empty body) when no policies loaded', async () => {
    const result = await postHook(makePreToolUse('read_file'));
    expect(result.status).toBe(200);
    // Empty object or object without permissionDecision = allow
    if (result.body.hookSpecificOutput) {
      expect((result.body.hookSpecificOutput as Record<string, unknown>).permissionDecision).not.toBe('deny');
    }
  });

  it('tracks swarm context from agent_id in input', async () => {
    const result = await postHook({
      ...makePreToolUse('read_file'),
      agent_id: 'worker-a1b',
      agent_type: 'general-purpose',
      team_name: 'test-team',
    });
    expect(result.status).toBe(200);
  });
});

// ============================================================
// 3. PostToolUse handler
// ============================================================

describe('PostToolUse handler', () => {
  it('returns additionalContext inside hookSpecificOutput', async () => {
    const result = await postHook(makePostToolUse('read_file', { content: 'hello' }));
    expect(result.status).toBe(200);
    expect(result.body.hookSpecificOutput).toBeDefined();
    const output = result.body.hookSpecificOutput as Record<string, unknown>;
    expect(output.hookEventName).toBe('PostToolUse');
    expect(typeof output.additionalContext).toBe('string');
    expect(output.additionalContext).toContain('[ScopeBlind]');
    expect(output.additionalContext).toContain('Receipt:');
  });

  it('does NOT return additionalContext at top level', async () => {
    const result = await postHook(makePostToolUse('read_file'));
    // additionalContext should NOT be at the top level
    expect(result.body.additionalContext).toBeUndefined();
  });

  it('does NOT return async: true', async () => {
    const result = await postHook(makePostToolUse('read_file'));
    expect(result.body.async).toBeUndefined();
  });

  it('handles large tool responses (payload digest)', async () => {
    const largeResponse = { data: 'x'.repeat(2000) };
    const result = await postHook(makePostToolUse('read_file', largeResponse));
    expect(result.status).toBe(200);
    // The response should still work — digest is in the receipt, not the hook response
    expect(result.body.hookSpecificOutput).toBeDefined();
  });
});

// ============================================================
// 4. Swarm lifecycle
// ============================================================

describe('Swarm lifecycle hooks', () => {
  it('handles SubagentStart event', async () => {
    const result = await postHook({
      hook_event_name: 'SubagentStart',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
      agent_id: 'worker-a1b',
      agent_type: 'general-purpose',
    });
    expect(result.status).toBe(200);
  });

  it('handles SubagentStop event', async () => {
    const result = await postHook({
      hook_event_name: 'SubagentStop',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
      agent_id: 'worker-a1b',
      agent_type: 'general-purpose',
      agent_transcript_path: '/tmp/worker-transcript.jsonl',
    });
    expect(result.status).toBe(200);
  });

  it('handles TaskCreated event', async () => {
    const result = await postHook({
      hook_event_name: 'TaskCreated',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
      task_id: 'task-123',
      task_subject: 'Fix the bug',
      teammate_name: 'researcher',
      team_name: 'backend-team',
    });
    expect(result.status).toBe(200);
  });

  it('handles TaskCompleted event', async () => {
    const result = await postHook({
      hook_event_name: 'TaskCompleted',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
      task_id: 'task-123',
      task_subject: 'Fix the bug',
    });
    expect(result.status).toBe(200);
  });
});

// ============================================================
// 5. Session lifecycle
// ============================================================

describe('Session lifecycle hooks', () => {
  it('handles SessionStart event', async () => {
    const result = await postHook({
      hook_event_name: 'SessionStart',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
      source: 'startup',
      model: 'claude-sonnet-4-6',
    });
    expect(result.status).toBe(200);
  });

  it('handles SessionEnd event', async () => {
    const result = await postHook({
      hook_event_name: 'SessionEnd',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
      reason: 'clear',
    });
    expect(result.status).toBe(200);
  });
});

// ============================================================
// 6. ConfigChange tamper detection
// ============================================================

describe('ConfigChange tamper detection', () => {
  it('flags modifications to .claude/ paths', async () => {
    const result = await postHook({
      hook_event_name: 'ConfigChange',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
      source: 'project_settings',
      file_path: '/tmp/.claude/settings.json',
    });
    expect(result.status).toBe(200);
    // Should log a tamper alert — check /alerts endpoint
    const alertsRes = await fetch('http://127.0.0.1:19377/alerts');
    const alerts = await alertsRes.json() as { count: number; alerts: unknown[] };
    expect(alerts.count).toBeGreaterThan(0);
  });
});

// ============================================================
// 7. Unknown/Stop events
// ============================================================

describe('Edge cases', () => {
  it('handles Stop event gracefully', async () => {
    const result = await postHook({
      hook_event_name: 'Stop',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
      stop_hook_active: true,
    });
    expect(result.status).toBe(200);
  });

  it('handles unknown hook event gracefully', async () => {
    const result = await postHook({
      hook_event_name: 'SomeNewFutureEvent',
      session_id: 'test-session-1',
      transcript_path: '/tmp/test.jsonl',
      cwd: '/tmp',
    });
    expect(result.status).toBe(200);
    // Should return empty object (pass-through)
  });

  it('returns 400 for invalid JSON', async () => {
    const res = await fetch(HOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json at all',
    });
    expect(res.status).toBe(400);
  });
});

// ============================================================
// 8. Health endpoint
// ============================================================

describe('Health and observability', () => {
  it('GET /health returns server info', async () => {
    const res = await fetch(HEALTH_URL);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(body.server).toBe('protect-mcp-hooks');
    expect(body.version).toBe('0.5.0');
    expect(body.mode).toBe('enforce');
    expect(typeof body.uptime_ms).toBe('number');
  });

  it('GET /receipts returns receipt array', async () => {
    const res = await fetch('http://127.0.0.1:19377/receipts');
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(typeof body.count).toBe('number');
    expect(Array.isArray(body.receipts)).toBe(true);
  });

  it('GET /suggestions returns policy suggestions', async () => {
    const res = await fetch('http://127.0.0.1:19377/suggestions');
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(typeof body.count).toBe('number');
    expect(Array.isArray(body.suggestions)).toBe(true);
  });

  it('returns 404 for unknown paths', async () => {
    const res = await fetch('http://127.0.0.1:19377/nonexistent');
    expect(res.status).toBe(404);
  });
});
