import { describe, it, expect, beforeAll } from 'vitest';
import { spawn } from 'node:child_process';
import { join } from 'node:path';

// Drive the built MCP server over real stdio JSON-RPC, exactly as an MCP host
// (or Glama) would: initialize, tools/list, then tools/call for each tool.
const SERVER = join(__dirname, '..', 'dist', 'mcp-server.js');

function rpc(requests: object[]): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const p = spawn('node', [SERVER], { stdio: ['pipe', 'pipe', 'ignore'] });
    let out = '';
    p.stdout.on('data', (d) => { out += d.toString(); });
    p.on('error', reject);
    p.on('close', () => {
      const msgs = out.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      resolve(msgs);
    });
    for (const r of requests) p.stdin.write(JSON.stringify(r) + '\n');
    p.stdin.end();
  });
}

const call = (id: number, name: string, args: object = {}) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
const parse = (msgs: any[], id: number) => JSON.parse(msgs.find((m) => m.id === id).result.content[0].text);

const DENY_POLICY = `
permit(principal, action == Action::"MCP::Tool::call", resource);
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")
  when { context has input && context.input has command && context.input.command like "*rm -rf*" };
`;

describe('protect-mcp MCP server', () => {
  let list: any[];
  beforeAll(async () => {
    list = await rpc([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    ]);
  });

  it('lists four annotated tools', () => {
    const tools = list.find((m) => m.id === 2).result.tools;
    const names = tools.map((t: any) => t.name).sort();
    expect(names).toEqual(['evaluate_action', 'self_test', 'sign_decision', 'verify_receipt']);
    for (const t of tools) {
      expect(t.annotations?.readOnlyHint).toBe(true);
      expect(t.description.length).toBeGreaterThan(120);
      expect(t.description).toContain('Returns JSON');
    }
  });

  it('evaluate_action denies a forbidden command and allows a safe one, fail-closed', async () => {
    const msgs = await rpc([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      call(2, 'evaluate_action', { tool: 'Bash', input: { command: 'rm -rf /' }, policy: DENY_POLICY }),
      call(3, 'evaluate_action', { tool: 'Read', input: { path: './x' }, policy: DENY_POLICY }),
      call(4, 'evaluate_action', { tool: 'Bash', input: { command: 'x' }, policy: '' }),
    ]);
    expect(parse(msgs, 2).allowed).toBe(false);
    expect(parse(msgs, 3).allowed).toBe(true);
    expect(parse(msgs, 4).allowed).toBe(false); // no policy -> fail closed
  });

  it('sign_decision produces a verifiable receipt; verify_receipt catches tampering', async () => {
    const msgs = await rpc([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      call(2, 'sign_decision', { tool: 'Bash', decision: 'deny', reason_code: 'restricted_list' }),
    ]);
    const signed = parse(msgs, 2);
    expect(signed.artifact_type).toBe('gateway_restraint');
    expect(signed.ephemeral).toBe(true);
    expect(typeof signed.public_key).toBe('string');

    const tampered = JSON.parse(JSON.stringify(signed.receipt));
    tampered.payload.tool = 'tampered';
    const v = await rpc([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      call(2, 'verify_receipt', { receipt: signed.receipt, public_key_hex: signed.public_key }),
      call(3, 'verify_receipt', { receipt: tampered, public_key_hex: signed.public_key }),
      call(4, 'verify_receipt', { receipt: signed.receipt }), // key embedded in payload
    ]);
    expect(parse(v, 2).valid).toBe(true);
    expect(parse(v, 3).valid).toBe(false);
    expect(parse(v, 3).error).toBe('invalid_signature');
    expect(parse(v, 4).valid).toBe(true);
  });

  it('self_test proves the gate denies and receipts round-trip', async () => {
    const msgs = await rpc([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      call(2, 'self_test'),
    ]);
    const r = parse(msgs, 2);
    expect(r.gate_denies_forbidden).toBe(true);
    expect(r.sign_verify_roundtrip).toBe(true);
    expect(r.ok).toBe(true);
  });
});
