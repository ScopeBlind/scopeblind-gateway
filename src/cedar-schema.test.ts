/**
 * Tests for Cedar schema generation from MCP tool descriptions.
 */

import { describe, it, expect } from 'vitest';
import { generateCedarSchema, generateSchemaStub, type McpToolDescription } from './cedar-schema.js';

const SAMPLE_TOOLS: McpToolDescription[] = [
  {
    name: 'read_file',
    description: 'Read the contents of a file',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'File path to read' },
      },
      required: ['path'],
    },
  },
  {
    name: 'write_file',
    description: 'Write content to a file',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        content: { type: 'string' },
      },
      required: ['path', 'content'],
    },
  },
  {
    name: 'execute_command',
    description: 'Execute a shell command',
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string' },
        args: { type: 'array', items: { type: 'string' } },
        timeout: { type: 'integer' },
      },
      required: ['command'],
    },
  },
];

describe('generateCedarSchema', () => {
  it('generates schema text with correct namespace', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('namespace ScopeBlind {');
    expect(result.toolCount).toBe(3);
    expect(result.tools).toEqual(['read_file', 'write_file', 'execute_command']);
  });

  it('generates per-tool actions', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('action "read_file"');
    expect(result.schemaText).toContain('action "write_file"');
    expect(result.schemaText).toContain('action "execute_command"');
  });

  it('generates blanket MCP::Tool::call action', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('action "MCP::Tool::call"');
  });

  it('maps string properties to String type', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('"path": String');
  });

  it('maps integer properties to Long type', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('"timeout": Long?');
  });

  it('maps array properties to Set type', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('"args": Set<String>?');
  });

  it('marks required fields without ?', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    // 'path' is required in read_file
    expect(result.schemaText).toMatch(/"path": String[^?]/);
  });

  it('marks optional fields with ?', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    // 'timeout' is optional in execute_command
    expect(result.schemaText).toContain('"timeout": Long?');
  });

  it('includes Agent entity with tier attribute', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('entity Agent');
    expect(result.schemaText).toContain('"tier": String');
  });

  it('includes Tool entity', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('entity Tool;');
  });

  it('generates input type declarations', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('type read_file_Input');
    expect(result.schemaText).toContain('type write_file_Input');
    expect(result.schemaText).toContain('type execute_command_Input');
  });

  it('uses custom namespace', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS, { namespace: 'MyOrg' });
    expect(result.schemaText).toContain('namespace MyOrg {');
  });

  it('generates schema JSON for WASM', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaJson).toBeDefined();
    expect(result.schemaJson['ScopeBlind']).toBeDefined();
    const ns = result.schemaJson['ScopeBlind'] as Record<string, unknown>;
    expect(ns.entityTypes).toBeDefined();
    expect(ns.actions).toBeDefined();
  });

  it('schema JSON contains per-tool actions', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    const ns = result.schemaJson['ScopeBlind'] as Record<string, Record<string, unknown>>;
    expect(ns.actions['read_file']).toBeDefined();
    expect(ns.actions['write_file']).toBeDefined();
    expect(ns.actions['execute_command']).toBeDefined();
    expect(ns.actions['MCP::Tool::call']).toBeDefined();
  });

  it('schema JSON actions reference Agent and Tool', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    const ns = result.schemaJson['ScopeBlind'] as Record<string, Record<string, unknown>>;
    const readFile = ns.actions['read_file'] as Record<string, Record<string, unknown>>;
    expect(readFile.appliesTo.principalTypes).toEqual(['Agent']);
    expect(readFile.appliesTo.resourceTypes).toEqual(['Tool']);
  });

  it('handles tools with no input schema', () => {
    const tools: McpToolDescription[] = [
      { name: 'get_status', description: 'Get server status' },
    ];
    const result = generateCedarSchema(tools);
    expect(result.toolCount).toBe(1);
    expect(result.schemaText).toContain('action "get_status"');
    // Should not crash, should produce valid schema
  });

  it('handles tools with empty properties', () => {
    const tools: McpToolDescription[] = [
      {
        name: 'ping',
        inputSchema: { type: 'object', properties: {} },
      },
    ];
    const result = generateCedarSchema(tools);
    expect(result.toolCount).toBe(1);
    expect(result.schemaText).toContain('action "ping"');
  });

  it('handles boolean properties', () => {
    const tools: McpToolDescription[] = [
      {
        name: 'set_flag',
        inputSchema: {
          type: 'object',
          properties: { enabled: { type: 'boolean' } },
        },
      },
    ];
    const result = generateCedarSchema(tools);
    expect(result.schemaText).toContain('"enabled": Bool?');
  });

  it('generates cedar-for-agents compatible annotations in comments', () => {
    const result = generateCedarSchema(SAMPLE_TOOLS);
    expect(result.schemaText).toContain('Compatible with cedar-policy/cedar-for-agents');
  });
});

describe('generateSchemaStub', () => {
  it('generates a valid stub with default namespace', () => {
    const stub = generateSchemaStub();
    expect(stub).toContain('namespace ScopeBlind {');
    expect(stub).toContain('entity Agent');
    expect(stub).toContain('entity Tool;');
    expect(stub).toContain('action "MCP::Tool::call"');
  });

  it('generates a stub with custom namespace', () => {
    const stub = generateSchemaStub('MyCompany');
    expect(stub).toContain('namespace MyCompany {');
  });

  it('includes cedar-for-agents compatibility note', () => {
    const stub = generateSchemaStub();
    expect(stub).toContain('cedar-for-agents');
  });
});
