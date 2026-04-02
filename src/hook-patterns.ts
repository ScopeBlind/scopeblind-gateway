/**
 * @scopeblind/protect-mcp — Hook Patterns Library
 *
 * Pre-built dangerous pattern filters for Claude Code's `if` condition field.
 * These layer ON TOP of Cedar policies as a first-pass regex filter,
 * reducing the number of hook invocations that reach protect-mcp.
 *
 * Shipped with `npx protect-mcp init-hooks` and customizable by the user.
 */

// ============================================================
// Pattern definitions
// ============================================================

export interface HookPattern {
  /** Matcher: which tool this pattern applies to */
  matcher: string;
  /** Condition: Claude Code's `if` field (regex-like tool input matching) */
  condition: string;
  /** Default decision for this pattern */
  decision: 'deny' | 'ask';
  /** Human-readable description */
  description: string;
  /** Risk category */
  category: 'destructive' | 'exfiltration' | 'privilege_escalation' | 'sensitive_file' | 'network';
}

/**
 * Built-in dangerous patterns that ship with protect-mcp.
 * These are conservative — they catch the most common dangerous commands
 * without generating excessive false positives.
 */
export const BUILTIN_PATTERNS: HookPattern[] = [
  // ── Destructive filesystem operations ──
  {
    matcher: 'Bash',
    condition: 'Bash(rm -rf *)',
    decision: 'deny',
    description: 'Recursive force-delete',
    category: 'destructive',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(rm -r *)',
    decision: 'ask',
    description: 'Recursive delete',
    category: 'destructive',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(chmod 777 *)',
    decision: 'deny',
    description: 'World-writable permissions',
    category: 'privilege_escalation',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(chmod -R *)',
    decision: 'ask',
    description: 'Recursive permission change',
    category: 'privilege_escalation',
  },

  // ── SQL destruction ──
  {
    matcher: 'Bash',
    condition: 'Bash(DROP TABLE *)',
    decision: 'deny',
    description: 'SQL DROP TABLE',
    category: 'destructive',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(DROP DATABASE *)',
    decision: 'deny',
    description: 'SQL DROP DATABASE',
    category: 'destructive',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(TRUNCATE *)',
    decision: 'deny',
    description: 'SQL TRUNCATE',
    category: 'destructive',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(DELETE FROM *)',
    decision: 'ask',
    description: 'SQL DELETE (mass deletion)',
    category: 'destructive',
  },

  // ── Network exfiltration ──
  {
    matcher: 'Bash',
    condition: 'Bash(curl * --upload-file *)',
    decision: 'deny',
    description: 'Upload file via curl',
    category: 'exfiltration',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(wget --post-file *)',
    decision: 'deny',
    description: 'Upload file via wget',
    category: 'exfiltration',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(scp * *:*)',
    decision: 'ask',
    description: 'Remote file copy',
    category: 'exfiltration',
  },

  // ── Sensitive file access ──
  {
    matcher: 'Write',
    condition: 'Write(*.env)',
    decision: 'ask',
    description: 'Write to .env file',
    category: 'sensitive_file',
  },
  {
    matcher: 'Write',
    condition: 'Write(*.key)',
    decision: 'deny',
    description: 'Write to key file',
    category: 'sensitive_file',
  },
  {
    matcher: 'Write',
    condition: 'Write(*.pem)',
    decision: 'deny',
    description: 'Write to certificate file',
    category: 'sensitive_file',
  },
  {
    matcher: 'Edit',
    condition: 'Edit(*.env)',
    decision: 'ask',
    description: 'Edit .env file',
    category: 'sensitive_file',
  },
  {
    matcher: 'Write',
    condition: 'Write(*id_rsa*)',
    decision: 'deny',
    description: 'Write to SSH key',
    category: 'sensitive_file',
  },
  {
    matcher: 'Read',
    condition: 'Read(*id_rsa*)',
    decision: 'ask',
    description: 'Read SSH private key',
    category: 'sensitive_file',
  },

  // ── Privilege escalation ──
  {
    matcher: 'Bash',
    condition: 'Bash(sudo *)',
    decision: 'ask',
    description: 'Sudo execution',
    category: 'privilege_escalation',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(su *)',
    decision: 'deny',
    description: 'Switch user',
    category: 'privilege_escalation',
  },

  // ── Package/system modification ──
  {
    matcher: 'Bash',
    condition: 'Bash(npm publish *)',
    decision: 'ask',
    description: 'Publish npm package',
    category: 'destructive',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(pip install *)',
    decision: 'ask',
    description: 'Install Python package',
    category: 'network',
  },
  {
    matcher: 'Bash',
    condition: 'Bash(git push --force*)',
    decision: 'ask',
    description: 'Force push to git',
    category: 'destructive',
  },
];

/**
 * Generate Claude Code settings.json hook entries with pattern-based filtering.
 */
export function generateHookSettings(
  hookUrl: string,
  patterns: HookPattern[] = BUILTIN_PATTERNS,
): Record<string, unknown> {
  // Group patterns by matcher for PreToolUse
  const preToolUseEntries: Array<Record<string, unknown>> = [];

  // Add catch-all hook (fires for every tool call)
  preToolUseEntries.push({
    matcher: '',
    hooks: [{
      type: 'http',
      url: hookUrl,
    }],
  });

  // PostToolUse: one catch-all for receipt signing (async)
  const postToolUseEntries = [{
    matcher: '',
    hooks: [{
      type: 'http',
      url: hookUrl,
    }],
  }];

  // Swarm lifecycle hooks
  const lifecycleEvents: Record<string, Array<Record<string, unknown>>> = {};
  for (const event of [
    'SubagentStart', 'SubagentStop', 'TaskCreated', 'TaskCompleted',
    'SessionStart', 'SessionEnd', 'TeammateIdle', 'ConfigChange', 'Stop',
  ]) {
    lifecycleEvents[event] = [{
      matcher: '',
      hooks: [{
        type: 'http',
        url: hookUrl,
      }],
    }];
  }

  return {
    hooks: {
      PreToolUse: preToolUseEntries,
      PostToolUse: postToolUseEntries,
      ...lifecycleEvents,
    },
  };
}

/**
 * Generate a sample Cedar policy from the built-in patterns.
 */
export function generateSampleCedarPolicy(): string {
  const lines: string[] = [
    '// Generated by protect-mcp init-hooks',
    '// Customize these policies to match your security requirements.',
    '// Cedar deny decisions are AUTHORITATIVE — they cannot be overridden.',
    '',
    '// Allow all read-only tools by default',
    'permit(',
    '  principal,',
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Read"',
    ');',
    '',
    'permit(',
    '  principal,',
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Glob"',
    ');',
    '',
    'permit(',
    '  principal,',
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Grep"',
    ');',
    '',
    '// Allow write/edit tools (remove these to require explicit approval)',
    'permit(',
    '  principal,',
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Write"',
    ');',
    '',
    'permit(',
    '  principal,',
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Edit"',
    ');',
    '',
    '// Allow Bash with caution (Cedar evaluates before hook patterns)',
    'permit(',
    '  principal,',
    '  action == Action::"MCP::Tool::call",',
    '  resource == Tool::"Bash"',
    ');',
    '',
    '// Block dangerous tools entirely',
    '// Uncomment any of these to block specific tools:',
    '// forbid(',
    '//   principal,',
    '//   action == Action::"MCP::Tool::call",',
    '//   resource == Tool::"delete_file"',
    '// );',
    '',
  ];

  return lines.join('\n');
}

/**
 * Generate the /verify-receipt skill file for Claude Code.
 */
export function generateVerifyReceiptSkill(): string {
  return `---
name: verify-receipt
description: Verify ScopeBlind receipt chain integrity and display audit trail
allowed-tools: [Read, Bash(npx:@veritasacta/verify*), Bash(cat:*protect-mcp*), Bash(jq:*)]
when_to_use: "Use when the user asks to verify receipts, check audit trails, validate decision logs, or see what tools were called"
context: inline
---

# ScopeBlind Receipt Verification

When the user asks to verify receipts or check the audit trail:

1. **Check for receipt files:**
   - Look for \`.protect-mcp-receipts.jsonl\` in the project root
   - Look for \`.protect-mcp-log.jsonl\` for decision history

2. **Display recent activity:**
   \`\`\`bash
   tail -n 20 .protect-mcp-log.jsonl | jq -r '[.tool, .decision, .reason_code, .hook_event // "stdio"] | @tsv'
   \`\`\`

3. **Verify receipt signatures:**
   \`\`\`bash
   npx @veritasacta/verify .protect-mcp-receipts.jsonl --format jsonl
   \`\`\`

4. **Show swarm topology (if multi-agent):**
   \`\`\`bash
   cat .protect-mcp-log.jsonl | jq -r 'select(.swarm != null) | [.swarm.agent_id, .swarm.agent_type, .tool, .decision] | @tsv'
   \`\`\`

5. **Show policy suggestions:**
   \`\`\`bash
   curl -s http://127.0.0.1:9377/suggestions | jq '.suggestions[]'
   \`\`\`

6. **Show config tamper alerts:**
   \`\`\`bash
   curl -s http://127.0.0.1:9377/alerts | jq '.alerts[]'
   \`\`\`

7. **Export audit bundle:**
   \`\`\`bash
   npx protect-mcp bundle --output audit-bundle.json
   \`\`\`

Present results in a clear, formatted table showing: timestamp, tool, decision, reason, and receipt ID.
If swarm data exists, show the agent topology (coordinator → workers).
`;
}
