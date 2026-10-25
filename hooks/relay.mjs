#!/usr/bin/env node
/**
 * Claude Code command-hook adapter for the released local HTTP gate.
 * Never returns permissionDecision=allow: successful policy evaluation still
 * goes through Claude Code's native permissions. This is not a sandbox and
 * does not authenticate a process that can impersonate the loopback server.
 */
import http from 'node:http';
import { pathToFileURL } from 'node:url';

const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 3000;
const TOTAL_TIMEOUT_MS = 8000;
const EVENTS = new Set(['PreToolUse', 'PostToolUse']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const fail = code => { throw new Error(code); };

export function parsePort(value = '9377') {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,4}$/.test(value)) fail('invalid_port');
  const port = Number(value);
  if (port > 65535) fail('invalid_port');
  return port;
}

export function validateInput(event, value) {
  if (!EVENTS.has(event) || !object(value) || value.hook_event_name !== event) fail('invalid_event');
  for (const key of ['tool_name', 'tool_use_id', 'session_id', 'cwd']) {
    if (!nonempty(value[key])) fail('invalid_input');
  }
  if (!object(value.tool_input)) fail('invalid_input');
  if (event === 'PostToolUse' && !Object.hasOwn(value, 'tool_response')) fail('missing_tool_response');
  // Forward a single spelling of each supported field. The server's camelCase
  // aliases must never override the snake_case fields that we just validated.
  const normalized = {};
  for (const key of ['hook_event_name', 'tool_name', 'tool_use_id', 'session_id', 'cwd', 'tool_input']) normalized[key] = value[key];
  for (const key of ['agent_id', 'agent_type', 'team_name', 'permission_mode']) {
    if (Object.hasOwn(value, key)) {
      if (typeof value[key] !== 'string') fail('invalid_input');
      normalized[key] = value[key];
    }
  }
  if (event === 'PostToolUse') normalized.tool_response = value.tool_response;
  return normalized;
}

export function validateHealth(value) {
  if (!object(value) || value.status !== 'ok' || value.server !== 'protect-mcp-hooks') fail('wrong_server');
  if (value.mode !== 'enforce') fail('gate_not_enforcing');
  if (value.policy_engine !== 'cedar' || !Number.isInteger(value.cedar_files) || value.cedar_files < 1 || !nonempty(value.policy_digest) || value.policy_digest === 'none') fail('cedar_not_configured');
  if (value.signing !== true || !object(value.signer) || !nonempty(value.signer.kid)) fail('signing_not_configured');
}

function keysOnly(value, allowed) {
  return Object.keys(value).every(key => allowed.includes(key));
}

export function normalizeResponse(event, value) {
  if (!object(value)) fail('invalid_response');
  if (event === 'PreToolUse' && Object.keys(value).length === 0) return { code: 0, stdout: '', stderr: '' };
  if (!keysOnly(value, ['hookSpecificOutput']) || !object(value.hookSpecificOutput)) fail('unexpected_response');
  const output = value.hookSpecificOutput;
  if (output.hookEventName !== event) fail('unexpected_response');
  if (event === 'PostToolUse') {
    if (!keysOnly(output, ['hookEventName', 'additionalContext']) || typeof output.additionalContext !== 'string') fail('unexpected_response');
    // 0.32.3's post handler does not return a signed receipt or propagate a
    // receipt-write failure. Do not repeat its optimistic "receipted" message.
    return { code: 0, stdout: '', stderr: '' };
  }
  if (!keysOnly(output, ['hookEventName', 'permissionDecision', 'permissionDecisionReason']) || !['deny', 'ask'].includes(output.permissionDecision) || !nonempty(output.permissionDecisionReason)) fail('unexpected_response');
  const reason = output.permissionDecision === 'deny'
    ? '[protect-mcp] The local policy gate denied this tool call. Review the local gate log for details.'
    : '[protect-mcp] The local policy gate requires your approval for this tool call.';
  return {
    code: output.permissionDecision === 'deny' ? 2 : 0,
    stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: output.permissionDecision, permissionDecisionReason: reason } }) + '\n',
    stderr: output.permissionDecision === 'deny' ? reason + '\n' : '',
  };
}

function requestJson(port, path, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const request = http.request({
      hostname: '127.0.0.1', port, path, method: body === undefined ? 'GET' : 'POST',
      agent: false,
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }) },
    });
    const timer = setTimeout(() => request.destroy(new Error('request_timeout')), timeoutMs);
    const finish = (error, value) => { clearTimeout(timer); error ? reject(error) : resolve(value); };
    request.on('error', error => finish(new Error(error.message === 'request_timeout' ? 'request_timeout' : 'connection_failed')));
    request.on('response', response => {
      // node:http does not follow redirects. Reject before reading any body.
      if (response.statusCode !== 200) { response.resume(); request.destroy(); finish(new Error('http_status')); return; }
      let bytes = 0;
      const chunks = [];
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_RESPONSE_BYTES) { request.destroy(); finish(new Error('response_too_large')); return; }
        chunks.push(chunk);
      });
      response.on('error', () => finish(new Error('response_incomplete')));
      response.on('end', () => {
        try { finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { finish(new Error('invalid_response_json')); }
      });
    });
    request.end(body);
  });
}

export function failureResult(event, code) {
  const after = event === 'PostToolUse';
  const reason = after
    ? `[protect-mcp] After-action recording failed (${code}). The tool already ran; this hook did not undo it. Check the local gate and receipt log.`
    : `[protect-mcp] Tool call blocked (${code}). Start the local gate with --enforce, a Cedar policy and signing before retrying.`;
  return {
    code: 2,
    stdout: after ? '' : JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }) + '\n',
    stderr: reason + '\n',
  };
}

export async function relay({ event, input, port = '9377', timeoutMs = REQUEST_TIMEOUT_MS }) {
  try {
    const gatePort = parsePort(port);
    const payload = validateInput(event, input);
    validateHealth(await requestJson(gatePort, '/health', undefined, timeoutMs));
    return normalizeResponse(event, await requestJson(gatePort, '/hook', payload, timeoutMs));
  } catch (error) {
    return failureResult(event, error.message);
  }
}

async function main() {
  const event = process.argv[2];
  let finished = false;
  function finish(result) {
    if (finished) return;
    finished = true;
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    process.exit(result.code);
  }
  const deadline = setTimeout(() => finish(failureResult(event, 'relay_timeout')), TOTAL_TIMEOUT_MS);
  try {
    if (process.argv.length !== 3 || !EVENTS.has(event)) fail('invalid_event');
    const chunks = [];
    let bytes = 0;
    for await (const chunk of process.stdin) {
      bytes += chunk.length;
      if (bytes > MAX_INPUT_BYTES) fail('input_too_large');
      chunks.push(chunk);
    }
    let input;
    try { input = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { fail('invalid_input_json'); }
    const result = await relay({ event, input, port: process.env.PROTECT_MCP_HOOK_PORT ?? '9377' });
    clearTimeout(deadline);
    finish(result);
  } catch (error) {
    clearTimeout(deadline);
    // Only our fixed errors are exposed. Parser, request and payload contents
    // are never copied into the hook's stdout or stderr.
    finish(failureResult(event, ['invalid_event', 'input_too_large', 'invalid_input_json'].includes(error.message) ? error.message : 'input_failed'));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
