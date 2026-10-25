import {
  STARTER_POLICY
} from "./chunk-53HXPRKS.mjs";

// src/hook-patterns.ts
var BUILTIN_PATTERNS = [
  // ── Destructive filesystem operations ──
  {
    matcher: "Bash",
    condition: "Bash(rm -rf *)",
    decision: "deny",
    description: "Recursive force-delete",
    category: "destructive"
  },
  {
    matcher: "Bash",
    condition: "Bash(rm -r *)",
    decision: "ask",
    description: "Recursive delete",
    category: "destructive"
  },
  {
    matcher: "Bash",
    condition: "Bash(chmod 777 *)",
    decision: "deny",
    description: "World-writable permissions",
    category: "privilege_escalation"
  },
  {
    matcher: "Bash",
    condition: "Bash(chmod -R *)",
    decision: "ask",
    description: "Recursive permission change",
    category: "privilege_escalation"
  },
  // ── SQL destruction ──
  {
    matcher: "Bash",
    condition: "Bash(DROP TABLE *)",
    decision: "deny",
    description: "SQL DROP TABLE",
    category: "destructive"
  },
  {
    matcher: "Bash",
    condition: "Bash(DROP DATABASE *)",
    decision: "deny",
    description: "SQL DROP DATABASE",
    category: "destructive"
  },
  {
    matcher: "Bash",
    condition: "Bash(TRUNCATE *)",
    decision: "deny",
    description: "SQL TRUNCATE",
    category: "destructive"
  },
  {
    matcher: "Bash",
    condition: "Bash(DELETE FROM *)",
    decision: "ask",
    description: "SQL DELETE (mass deletion)",
    category: "destructive"
  },
  // ── Network exfiltration ──
  {
    matcher: "Bash",
    condition: "Bash(curl * --upload-file *)",
    decision: "deny",
    description: "Upload file via curl",
    category: "exfiltration"
  },
  {
    matcher: "Bash",
    condition: "Bash(wget --post-file *)",
    decision: "deny",
    description: "Upload file via wget",
    category: "exfiltration"
  },
  {
    matcher: "Bash",
    condition: "Bash(scp * *:*)",
    decision: "ask",
    description: "Remote file copy",
    category: "exfiltration"
  },
  // ── Sensitive file access ──
  {
    matcher: "Write",
    condition: "Write(*.env)",
    decision: "ask",
    description: "Write to .env file",
    category: "sensitive_file"
  },
  {
    matcher: "Write",
    condition: "Write(*.key)",
    decision: "deny",
    description: "Write to key file",
    category: "sensitive_file"
  },
  {
    matcher: "Write",
    condition: "Write(*.pem)",
    decision: "deny",
    description: "Write to certificate file",
    category: "sensitive_file"
  },
  {
    matcher: "Edit",
    condition: "Edit(*.env)",
    decision: "ask",
    description: "Edit .env file",
    category: "sensitive_file"
  },
  {
    matcher: "Write",
    condition: "Write(*id_rsa*)",
    decision: "deny",
    description: "Write to SSH key",
    category: "sensitive_file"
  },
  {
    matcher: "Read",
    condition: "Read(*id_rsa*)",
    decision: "ask",
    description: "Read SSH private key",
    category: "sensitive_file"
  },
  // ── Privilege escalation ──
  {
    matcher: "Bash",
    condition: "Bash(sudo *)",
    decision: "ask",
    description: "Sudo execution",
    category: "privilege_escalation"
  },
  {
    matcher: "Bash",
    condition: "Bash(su *)",
    decision: "deny",
    description: "Switch user",
    category: "privilege_escalation"
  },
  // ── Package/system modification ──
  {
    matcher: "Bash",
    condition: "Bash(npm publish *)",
    decision: "ask",
    description: "Publish npm package",
    category: "destructive"
  },
  {
    matcher: "Bash",
    condition: "Bash(pip install *)",
    decision: "ask",
    description: "Install Python package",
    category: "network"
  },
  {
    matcher: "Bash",
    condition: "Bash(git push --force*)",
    decision: "ask",
    description: "Force push to git",
    category: "destructive"
  }
];
function generateHookSettings(hookUrl, patterns = BUILTIN_PATTERNS) {
  const preToolUseEntries = [];
  preToolUseEntries.push({
    matcher: "",
    hooks: [{
      type: "http",
      url: hookUrl
    }]
  });
  const postToolUseEntries = [{
    matcher: "",
    hooks: [{
      type: "http",
      url: hookUrl
    }]
  }];
  const lifecycleEvents = {};
  for (const event of [
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "SessionStart",
    "SessionEnd",
    "TeammateIdle",
    "ConfigChange",
    "Stop"
  ]) {
    lifecycleEvents[event] = [{
      matcher: "",
      hooks: [{
        type: "http",
        url: hookUrl
      }]
    }];
  }
  return {
    hooks: {
      PreToolUse: preToolUseEntries,
      PostToolUse: postToolUseEntries,
      ...lifecycleEvents
    }
  };
}
function generateSampleCedarPolicy() {
  return STARTER_POLICY;
}
function generateVerifyReceiptSkill() {
  return `---
name: verify-receipt
description: Verify ScopeBlind receipt chain integrity and display audit trail
allowed-tools: [Read, Bash(npx:@veritasacta/verify*), Bash(cat:*protect-mcp*), Bash(jq:*)]
when_to_use: "Use when the user asks to verify receipts, check audit trails, validate decision logs, or see what tools were called"
context: inline
---

# ScopeBlind Receipt Verification

Check supplied signed receipts against a public key obtained separately. The
record covers calls received by the configured gateway; signatures do not prove
that every action was recorded or executed. A local decision log is not itself
a signed receipt.

When the user asks to verify receipts or check the audit trail:

1. **Check for receipt files:**
   - Look for \`.protect-mcp-receipts.jsonl\` in the project root
   - Look for \`.protect-mcp-log.jsonl\` for decision history

2. **Display recent activity:**
   \`\`\`bash
   tail -n 20 .protect-mcp-log.jsonl | jq -r '[.tool, .decision, .reason_code, .hook_event // "stdio"] | @tsv'
   \`\`\`

3. **Verify receipt signatures and links:** For your own local demo, take the
   public key from your separate signing-key file. Do not copy the private key.
   For another party's record, obtain their expected public key through a trusted
   channel outside the receipt and set PROTECT_MCP_PUBLIC_KEY to that value.
   \`\`\`bash
   PROTECT_MCP_PUBLIC_KEY=$(node -p 'JSON.parse(require("fs").readFileSync("keys/gateway.json", "utf8")).publicKey')
   npx --yes @veritasacta/verify@0.11.0 --replay-chain .protect-mcp-receipts.jsonl --key "$PROTECT_MCP_PUBLIC_KEY" --json
   \`\`\`
   The pinned verifier is fetched during its first installation; verification
   itself is local. Exit 0 is valid, 1 invalid, and 2 not checked/error. Do not
   describe an embedded-key result as independently authenticated. Chain replay
   checks supplied links, not whether an entire history was supplied.

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
If swarm data exists, show the agent topology (coordinator \u2192 workers).
`;
}

export {
  BUILTIN_PATTERNS,
  generateHookSettings,
  generateSampleCedarPolicy,
  generateVerifyReceiptSkill
};
