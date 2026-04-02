/**
 * @scopeblind/protect-mcp — Cedar Schema Generator for MCP Tools
 *
 * Auto-generates a Cedar authorization schema from MCP tool descriptions.
 * This enables typed Cedar policies that reference tool input attributes:
 *
 *   permit(principal, action == Action::"read_file", resource)
 *   when { context.input.path like "./workspace/*" };
 *
 * Compatible with cedar-policy/cedar-for-agents schema format.
 * Designed to replace `schema: null` in Cedar WASM evaluations.
 *
 * @see https://github.com/cedar-policy/cedar-for-agents
 * @standard RFC 8785 (JCS), Cedar Policy Language v4
 */

// ============================================================
// Types
// ============================================================

/** MCP tool description from tools/list response */
export interface McpToolDescription {
  name: string;
  description?: string;
  inputSchema?: JsonSchema;
}

/** Subset of JSON Schema that MCP tools use */
export interface JsonSchema {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: (string | number | boolean)[];
  format?: string;
  description?: string;
  additionalProperties?: boolean | JsonSchema;
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
}

/** Generated Cedar schema components */
export interface CedarSchemaResult {
  /** The .cedarschema text (human-readable Cedar schema format) */
  schemaText: string;
  /** The schema as a JSON object (for passing to Cedar WASM) */
  schemaJson: Record<string, unknown>;
  /** Number of tools mapped */
  toolCount: number;
  /** Tool names included */
  tools: string[];
}

export interface SchemaGeneratorConfig {
  /** Namespace for generated types (default: "ScopeBlind") */
  namespace?: string;
  /** Include agent tier as principal attribute (default: true) */
  includeTier?: boolean;
  /** Include timestamp context (default: true) */
  includeTimestamp?: boolean;
  /** Include agent_id as principal attribute (default: true) */
  includeAgentId?: boolean;
}

// ============================================================
// JSON Schema → Cedar Type Mapping
// ============================================================

/**
 * Map a JSON Schema type to a Cedar type string.
 * Follows the cedar-for-agents mapping convention.
 */
function jsonSchemaToCedarType(schema: JsonSchema, namespace: string, path: string): string {
  if (schema.enum) {
    return 'String'; // Enums become strings in Cedar
  }

  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;

  switch (type) {
    case 'string':
      if (schema.format === 'date-time') return 'String'; // Cedar doesn't have native datetime in all contexts
      if (schema.format === 'uri') return 'String';
      return 'String';

    case 'integer':
    case 'number':
      return 'Long';

    case 'boolean':
      return 'Bool';

    case 'array':
      if (schema.items) {
        const itemType = jsonSchemaToCedarType(schema.items, namespace, path + '_item');
        return `Set<${itemType}>`;
      }
      return 'Set<String>'; // Default to Set<String> for untyped arrays

    case 'object':
      // Complex objects become inline records
      if (schema.properties && Object.keys(schema.properties).length > 0) {
        const fields = Object.entries(schema.properties).map(([key, prop]) => {
          const cedarType = jsonSchemaToCedarType(prop, namespace, path + '_' + sanitizeIdentifier(key));
          const isRequired = schema.required?.includes(key) ?? false;
          return `    "${sanitizeIdentifier(key)}": ${cedarType}${isRequired ? '' : '?'}`;
        });
        return `{\n${fields.join(',\n')}\n  }`;
      }
      return 'Record'; // Empty objects

    default:
      return 'String'; // Safe fallback
  }
}

/**
 * Sanitize a string into a valid Cedar identifier.
 * Cedar identifiers must match [a-zA-Z_][a-zA-Z0-9_]*
 */
function sanitizeIdentifier(name: string): string {
  return name
    .replace(/[^a-zA-Z0-9_]/g, '_')
    .replace(/^(\d)/, '_$1');
}

/**
 * Sanitize a tool name for use as a Cedar action identifier.
 * Tool names with special characters get quoted in Cedar.
 */
function cedarActionId(toolName: string): string {
  // If the name is a valid Cedar identifier, use it directly
  if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(toolName)) {
    return toolName;
  }
  // Otherwise it must be quoted in the schema
  return toolName;
}

// ============================================================
// Schema Generation
// ============================================================

/**
 * Generate a Cedar schema from MCP tool descriptions.
 *
 * Produces both human-readable .cedarschema text and the JSON
 * representation that Cedar WASM accepts.
 *
 * The generated schema defines:
 * - Agent entity type (principal) with tier and agent_id attributes
 * - Tool entity type (resource)
 * - One action per MCP tool, with typed input context
 * - A parent action "MCP::Tool::call" for blanket policies
 *
 * This enables policies like:
 *   forbid(principal, action == Action::"execute_command", resource)
 *   when { context.input has "command" && context.input.command like "rm *" };
 */
export function generateCedarSchema(
  tools: McpToolDescription[],
  config: SchemaGeneratorConfig = {},
): CedarSchemaResult {
  const ns = config.namespace || 'ScopeBlind';
  const includeTier = config.includeTier !== false;
  const includeTimestamp = config.includeTimestamp !== false;
  const includeAgentId = config.includeAgentId !== false;

  // ── Build agent attributes ──
  const agentAttrs: string[] = [];
  if (includeTier) agentAttrs.push('    "tier": String');
  if (includeAgentId) agentAttrs.push('    "agent_id": String?');

  // ── Build context type ──
  const sessionFields: string[] = [];
  if (includeTimestamp) sessionFields.push('    "timestamp": String?');
  sessionFields.push('    "hook_event": String?');

  // ── Build per-tool action declarations ──
  const actionDeclarations: string[] = [];
  const inputTypeDeclarations: string[] = [];

  for (const tool of tools) {
    const actionName = cedarActionId(tool.name);
    const inputTypeName = `${sanitizeIdentifier(tool.name)}_Input`;

    // Generate input type from tool's JSON schema
    if (tool.inputSchema?.properties && Object.keys(tool.inputSchema.properties).length > 0) {
      const fields = Object.entries(tool.inputSchema.properties).map(([key, prop]) => {
        const cedarType = jsonSchemaToCedarType(prop, ns, sanitizeIdentifier(tool.name) + '_' + sanitizeIdentifier(key));
        const isRequired = tool.inputSchema?.required?.includes(key) ?? false;
        return `    "${sanitizeIdentifier(key)}": ${cedarType}${isRequired ? '' : '?'}`;
      });

      inputTypeDeclarations.push(
        `  // Input type for tool: ${tool.name}` +
        (tool.description ? `\n  // ${tool.description}` : '') +
        `\n  type ${inputTypeName} = {\n${fields.join(',\n')}\n  };`
      );

      actionDeclarations.push(
        `  action "${actionName}" in [Action::"MCP::Tool::call"] appliesTo {\n` +
        `    principal: [Agent],\n` +
        `    resource: [Tool],\n` +
        `    context: {\n` +
        `      "input": ${inputTypeName},\n` +
        `      "tier": String${includeTimestamp ? ',\n      "timestamp": String?' : ''}${includeAgentId ? ',\n      "agent_id": String?' : ''}\n` +
        `    }\n` +
        `  };`
      );
    } else {
      // Tool with no input schema — use empty context
      actionDeclarations.push(
        `  action "${actionName}" in [Action::"MCP::Tool::call"] appliesTo {\n` +
        `    principal: [Agent],\n` +
        `    resource: [Tool],\n` +
        `    context: {\n` +
        `      "tier": String${includeTimestamp ? ',\n      "timestamp": String?' : ''}${includeAgentId ? ',\n      "agent_id": String?' : ''}\n` +
        `    }\n` +
        `  };`
      );
    }
  }

  // ── Blanket action for policies that match all tools ──
  actionDeclarations.push(
    `  // Blanket action for policies matching any tool call\n` +
    `  action "MCP::Tool::call" appliesTo {\n` +
    `    principal: [Agent],\n` +
    `    resource: [Tool],\n` +
    `    context: {\n` +
    `      "tier": String${includeTimestamp ? ',\n      "timestamp": String?' : ''}${includeAgentId ? ',\n      "agent_id": String?' : ''}\n` +
    `    }\n` +
    `  };`
  );

  // ── Assemble the schema text ──
  const schemaText = [
    `// Cedar schema for MCP tool governance`,
    `// Generated by protect-mcp from ${tools.length} tool description(s)`,
    `// Compatible with cedar-policy/cedar-for-agents`,
    ``,
    `namespace ${ns} {`,
    ``,
    `  // ── Entity types ──`,
    ``,
    `  entity Agent${agentAttrs.length > 0 ? ` = {\n${agentAttrs.join(',\n')}\n  }` : ''};`,
    ``,
    `  entity Tool;`,
    ``,
    ...(inputTypeDeclarations.length > 0
      ? [`  // ── Tool input types ──`, ``, ...inputTypeDeclarations, ``]
      : []),
    `  // ── Actions ──`,
    ``,
    ...actionDeclarations,
    ``,
    `}`,
    ``,
  ].join('\n');

  // ── Build JSON schema for Cedar WASM ──
  const schemaJson = buildSchemaJson(tools, ns, config);

  return {
    schemaText,
    schemaJson,
    toolCount: tools.length,
    tools: tools.map(t => t.name),
  };
}

/**
 * Build the Cedar schema JSON structure for WASM isAuthorized().
 * This is the format Cedar WASM expects in the `schema` parameter.
 */
function buildSchemaJson(
  tools: McpToolDescription[],
  namespace: string,
  config: SchemaGeneratorConfig,
): Record<string, unknown> {
  const entityTypes: Record<string, unknown> = {
    Agent: {
      shape: {
        type: 'Record',
        attributes: {
          ...(config.includeTier !== false ? { tier: { type: 'String', required: false } } : {}),
          ...(config.includeAgentId !== false ? { agent_id: { type: 'String', required: false } } : {}),
        },
      },
      memberOfTypes: [],
    },
    Tool: {
      shape: { type: 'Record', attributes: {} },
      memberOfTypes: [],
    },
  };

  const actions: Record<string, unknown> = {};

  // Per-tool actions
  for (const tool of tools) {
    const contextAttrs: Record<string, unknown> = {
      tier: { type: 'String', required: false },
    };

    if (config.includeTimestamp !== false) {
      contextAttrs['timestamp'] = { type: 'String', required: false };
    }
    if (config.includeAgentId !== false) {
      contextAttrs['agent_id'] = { type: 'String', required: false };
    }

    // Map tool input schema to Cedar context attributes
    if (tool.inputSchema?.properties) {
      const inputAttrs: Record<string, unknown> = {};
      for (const [key, prop] of Object.entries(tool.inputSchema.properties)) {
        inputAttrs[sanitizeIdentifier(key)] = {
          type: jsonSchemaToSchemaJsonType(prop),
          required: tool.inputSchema.required?.includes(key) ?? false,
        };
      }
      contextAttrs['input'] = {
        type: 'Record',
        attributes: inputAttrs,
        required: false,
      };
    }

    actions[tool.name] = {
      appliesTo: {
        principalTypes: ['Agent'],
        resourceTypes: ['Tool'],
        context: { type: 'Record', attributes: contextAttrs },
      },
      memberOf: [{ id: 'MCP::Tool::call' }],
    };
  }

  // Blanket action
  const blanketContext: Record<string, unknown> = {
    tier: { type: 'String', required: false },
  };
  if (config.includeTimestamp !== false) {
    blanketContext['timestamp'] = { type: 'String', required: false };
  }
  if (config.includeAgentId !== false) {
    blanketContext['agent_id'] = { type: 'String', required: false };
  }

  actions['MCP::Tool::call'] = {
    appliesTo: {
      principalTypes: ['Agent'],
      resourceTypes: ['Tool'],
      context: { type: 'Record', attributes: blanketContext },
    },
  };

  return {
    [namespace]: {
      entityTypes,
      actions,
    },
  };
}

/**
 * Map a JSON Schema property to a Cedar schema JSON type object.
 */
function jsonSchemaToSchemaJsonType(schema: JsonSchema): string {
  if (schema.enum) return 'String';

  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;

  switch (type) {
    case 'string': return 'String';
    case 'integer':
    case 'number': return 'Long';
    case 'boolean': return 'EntityOrCommon'; // Cedar JSON schema uses this for Bool
    case 'array': return 'Set';
    default: return 'String';
  }
}

// ============================================================
// Schema file management
// ============================================================

/**
 * Generate a Cedar schema stub file for customization.
 * This is the starting point for users who want to extend the auto-generated schema.
 */
export function generateSchemaStub(namespace: string = 'ScopeBlind'): string {
  return [
    `// Cedar schema stub for protect-mcp`,
    `// This defines the principal and resource entity types.`,
    `// Tool-specific actions are auto-generated from MCP tools/list.`,
    `//`,
    `// Compatible with cedar-policy/cedar-for-agents @mcp_principal/@mcp_resource annotations.`,
    `// See: https://github.com/cedar-policy/cedar-for-agents`,
    ``,
    `namespace ${namespace} {`,
    ``,
    `  // @mcp_principal`,
    `  entity Agent = {`,
    `    "tier": String,`,
    `    "agent_id": String?`,
    `  };`,
    ``,
    `  // @mcp_resource`,
    `  entity Tool;`,
    ``,
    `  // @mcp_action`,
    `  action "MCP::Tool::call" appliesTo {`,
    `    principal: [Agent],`,
    `    resource: [Tool],`,
    `    context: {`,
    `      "tier": String`,
    `    }`,
    `  };`,
    ``,
    `}`,
    ``,
  ].join('\n');
}
