#!/usr/bin/env node
import { readFile, realpath } from 'node:fs/promises';
import { isAbsolute, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { relay as gateRelay, parsePort } from '../lib/gate-client.mjs';

const EVENTS = new Set(['preToolUse', 'postToolUse']);
const NATIVE_TOOLS = Object.freeze({ Shell: 'Bash', Read: 'Read', Write: 'Write', Grep: 'Grep', Glob: 'Glob', Delete: 'delete_file', Task: 'Task' });
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = value => typeof value === 'string' && value.trim().length > 0;
const fail = message => { throw new Error(message); };
const own = (value, key) => Object.hasOwn(value, key);
const GATE_ERRORS = new Set([
  'invalid_port', 'wrong_server', 'gate_not_enforcing', 'cedar_not_configured',
  'signing_not_configured', 'connection_failed', 'request_timeout', 'http_status',
  'response_too_large', 'response_incomplete', 'invalid_response_json',
  'invalid_response', 'unexpected_response',
]);

// Interpret only the canonical relay's fixed messages. No reason returned by
// the HTTP server, tool payload, or arbitrary exception reaches the UI.
function gateFailureCode(result) {
  if (result.stderr === '[protect-mcp] The local policy gate denied this tool call. Review the local gate log for details.\n') return 'policy_denied';
  const match = /^\[protect-mcp\] (?:Tool call blocked|After-action recording failed) \(([a-z_]+)\)\./.exec(result.stderr);
  return match && GATE_ERRORS.has(match[1]) ? match[1] : 'gate_rejected';
}

export function validateConfig(value) {
  if (!object(value) || value.version !== 1 || Object.keys(value).some(key => !['version', 'port', 'mcpTools'].includes(key))) fail('invalid_project_config');
  if (!Number.isInteger(value.port)) fail('invalid_project_config');
  parsePort(String(value.port));
  if (value.mcpTools !== undefined) {
    if (!object(value.mcpTools)) fail('invalid_project_config');
    for (const [host, policy] of Object.entries(value.mcpTools)) {
      if (!/^MCP:.+/.test(host) || !text(policy) || policy.length > 200 || /[\r\n\u0000]/.test(policy)) fail('invalid_project_config');
    }
  }
  return { version: 1, port: value.port, mcpTools: value.mcpTools ?? {} };
}

export function normalizeInput(event, input, config) {
  if (!EVENTS.has(event) || !object(input) || input.hook_event_name !== event) fail('invalid_event');
  for (const field of ['conversation_id', 'tool_use_id', 'tool_name']) if (!text(input[field])) fail('invalid_input');
  // Cursor 3.17.8 sends an empty cwd for Shell in a single-root project.
  // Resolve only that explicit empty value to the independently checked root;
  // never fill in a missing field or rewrite the actual tool arguments.
  const cwd = input.cwd === '' ? config.workspaceRoot : input.cwd;
  if (!object(input.tool_input) || typeof cwd !== 'string' || !isAbsolute(cwd)) fail('invalid_input');
  // Unknown native tools and unconfigured MCP names never inherit an allow.
  const tool = own(NATIVE_TOOLS, input.tool_name) ? NATIVE_TOOLS[input.tool_name] :
    own(config.mcpTools, input.tool_name) ? config.mcpTools[input.tool_name] : undefined;
  if (!tool) fail('unmapped_tool');
  const normalized = {
    hook_event_name: event === 'preToolUse' ? 'PreToolUse' : 'PostToolUse',
    tool_name: tool,
    tool_input: input.tool_input,
    tool_use_id: JSON.stringify(['cursor', input.conversation_id, input.tool_use_id]),
    session_id: input.conversation_id,
    cwd,
  };
  if (event === 'postToolUse') {
    if (typeof input.tool_output !== 'string') fail('missing_tool_output');
    try { normalized.tool_response = JSON.parse(input.tool_output); }
    catch { fail('invalid_tool_output'); }
  }
  return normalized;
}

export async function loadConfig(input) {
  if (!object(input) || !Array.isArray(input.workspace_roots) || input.workspace_roots.length !== 1 || !text(input.workspace_roots[0]) || !isAbsolute(input.workspace_roots[0]) || typeof input.cwd !== 'string' || (input.cwd !== '' && !isAbsolute(input.cwd))) fail('invalid_workspace');
  let root, cwd;
  try { root = await realpath(input.workspace_roots[0]); cwd = input.cwd === '' ? root : await realpath(input.cwd); }
  catch { fail('invalid_workspace'); }
  const path = relative(root, cwd);
  if (path === '..' || path.startsWith('../') || path.startsWith('..\\') || isAbsolute(path)) fail('wrong_workspace');
  let raw;
  try { raw = await readFile(join(root, '.cursor', 'protect-mcp.json'), 'utf8'); }
  catch { fail('missing_project_config'); }
  if (Buffer.byteLength(raw) > 32 * 1024) fail('invalid_project_config');
  try { return { ...validateConfig(JSON.parse(raw)), workspaceRoot: root }; }
  catch { fail('invalid_project_config'); }
}

export function failureResult(event, reason) {
  const after = event === 'postToolUse';
  const guidance = {
    policy_denied: 'The project policy denied this action. Review the local gate log and choose an action the policy permits.',
    connection_failed: 'The local gate is unavailable. Start the gate for this project with --enforce, a Cedar policy and signing on its configured port, then retry.',
    request_timeout: 'The local gate did not answer in time. Check its terminal and health before retrying.',
    relay_timeout: 'The hook timed out. Check the local gate and hook setup before retrying.',
    gate_not_enforcing: 'The local gate is not enforcing. Restart it with --enforce after reviewing the project policy.',
    cedar_not_configured: 'The gate has no ready Cedar policy. Check the project policy directory and gate startup command.',
    signing_not_configured: 'The gate has no ready signer. Check its configured key locally; never paste the private key into chat.',
    wrong_server: 'The configured port does not identify a protect-mcp gate. Check this project\'s port and gate process.',
    approval_required: 'The gate requires approval. Complete its approval process and retry the exact action; a chat approval alone is insufficient.',
  };
  const message = after
    ? `[protect-mcp] After-action recording failed (${reason}). The tool already ran. Check the gate and local receipt log.`
    : `[protect-mcp] Tool blocked (${reason}). ${own(guidance, reason) ? guidance[reason] : 'Review this project\'s configuration, policy and local gate before retrying.'}`;
  return { code: 2, stdout: after ? '{}\n' : JSON.stringify({ permission: 'deny', user_message: message, agent_message: message }) + '\n', stderr: message + '\n' };
}

export async function relay({ event, input, timeoutMs = 3000 }) {
  try {
    const config = await loadConfig(input);
    const normalized = normalizeInput(event, input, config);
    const result = await gateRelay({ event: normalized.hook_event_name, input: normalized, port: String(config.port), timeoutMs });
    if (result.code !== 0) return failureResult(event, gateFailureCode(result));
    if (event === 'postToolUse') return { code: 0, stdout: '{}\n', stderr: '' };
    // Cursor documents that preToolUse does not enforce "ask". Keep an
    // approval requirement held instead of silently downgrading it to allow.
    if (result.stdout) return failureResult(event, 'approval_required');
    return { code: 0, stdout: '{"permission":"allow"}\n', stderr: '' };
  } catch (error) {
    const allowed = ['invalid_event', 'invalid_input', 'unmapped_tool', 'missing_tool_output', 'invalid_tool_output', 'invalid_workspace', 'wrong_workspace', 'missing_project_config', 'invalid_project_config'];
    return failureResult(event, allowed.includes(error.message) ? error.message : 'relay_failed');
  }
}

async function main() {
  const event = process.argv[2];
  let finished = false;
  const finish = result => {
    if (finished) return;
    finished = true;
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    process.exit(result.code);
  };
  const deadline = setTimeout(() => finish(failureResult(event, 'relay_timeout')), 8000);
  try {
    if (process.argv.length !== 3 || !EVENTS.has(event)) fail('invalid_event');
    const chunks = [];
    let bytes = 0;
    for await (const chunk of process.stdin) {
      bytes += chunk.length;
      if (bytes > 2 * 1024 * 1024) fail('input_too_large');
      chunks.push(chunk);
    }
    let input;
    try { input = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { fail('invalid_input_json'); }
    const result = await relay({ event, input });
    clearTimeout(deadline);
    finish(result);
  } catch (error) {
    clearTimeout(deadline);
    finish(failureResult(event, ['invalid_event', 'input_too_large', 'invalid_input_json'].includes(error.message) ? error.message : 'input_failed'));
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(await realpath(process.argv[1])).href) await main();
