"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/hook-patterns.ts
var hook_patterns_exports = {};
__export(hook_patterns_exports, {
  BUILTIN_PATTERNS: () => BUILTIN_PATTERNS,
  generateHookSettings: () => generateHookSettings,
  generateSampleCedarPolicy: () => generateSampleCedarPolicy,
  generateVerifyReceiptSkill: () => generateVerifyReceiptSkill
});
module.exports = __toCommonJS(hook_patterns_exports);

// src/starter-policy.ts
var STARTER_POLICY = [
  "// protect-mcp starter policy for coding agents, v1.",
  "// Everything is allowed except the forbids below, and a forbid always wins.",
  "// Shell rules match the raw command text, so they are best effort: a reworded",
  "// command can get past them. Every rule checks `has` first, because the gate",
  "// denies on any policy error. This file is yours to edit.",
  "",
  '@id("starter.allow-by-default")',
  "permit (principal, action, resource);",
  "",
  '@id("starter.delete-root-or-home")',
  '@reason("Recursive delete of /, the home folder or the parent folder. Delete a specific path inside the project instead.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command && (",
  '    context.input.command like "*rm -rf /" || context.input.command like "*rm -rf / *" ||',
  '    context.input.command like "*rm -rf ~" || context.input.command like "*rm -rf ~ *" ||',
  '    context.input.command like "*rm -rf ~/" || context.input.command like "*rm -rf ~/ *" ||',
  '    context.input.command like "*rm -rf $HOME" || context.input.command like "*rm -rf $HOME *" ||',
  '    context.input.command like "*rm -rf $HOME/" || context.input.command like "*rm -rf $HOME/ *" ||',
  '    context.input.command like "*rm -rf \\"$HOME\\"" || context.input.command like "*rm -rf \\"$HOME\\" *" ||',
  '    context.input.command like "*rm -rf .." || context.input.command like "*rm -rf .. *" ||',
  '    context.input.command like "*rm -rf ../" || context.input.command like "*rm -rf ../ *" ||',
  '    context.input.command like "*rm -rf /\\**" || context.input.command like "*rm -rf ~/\\**" ||',
  '    context.input.command like "*rm -rf $HOME/\\**" || context.input.command like "*rm -rf \\"$HOME/\\"\\**" ||',
  '    context.input.command like "*rm -fr /" || context.input.command like "*rm -fr ~" ||',
  '    context.input.command like "*rm -fr ~/" || context.input.command like "*rm -fr $HOME")',
  "};",
  "",
  '@id("starter.force-push-main")',
  '@reason("Force-push to main or master, or a force-push that names no branch. Push a named feature branch instead.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command && (",
  '    context.input.command like "*git push*--force* origin main*" || context.input.command like "*git push*-f origin main*" ||',
  '    context.input.command like "*git push*origin main --force*" || context.input.command like "*git push*origin main -f*" ||',
  '    context.input.command like "*git push*--force*:main*" || context.input.command like "*git push*origin +main*" ||',
  '    context.input.command like "*git push*--force* origin master*" || context.input.command like "*git push*-f origin master*" ||',
  '    context.input.command like "*git push*origin master --force*" || context.input.command like "*git push*origin master -f*" ||',
  '    context.input.command like "*git push*--force*:master*" || context.input.command like "*git push*origin +master*" ||',
  '    context.input.command like "*git push*--force" || context.input.command like "*git push*--force 2>&1*" ||',
  '    context.input.command like "*git push*--force &&*" || context.input.command like "*git push*--force-with-lease" ||',
  '    context.input.command like "*git push*--force-with-lease 2>&1*" || context.input.command like "*git push*--force-with-lease &&*" ||',
  '    context.input.command like "*git push*-f" || context.input.command like "*git push*-f 2>&1*" ||',
  '    context.input.command like "*git push*-f &&*")',
  "};",
  "",
  '@id("starter.read-secret-file")',
  '@reason("Reads a credential file such as .env, ~/.ssh or ~/.aws. Ask the person for the value you need.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource)',
  "when {",
  '  resource == Tool::"Read" && context has input && context.input has file_path && (',
  '    context.input.file_path like "*/.env" || context.input.file_path like "*/.env.*" ||',
  '    context.input.file_path like "*/.ssh/*" || context.input.file_path like "*/.aws/*" ||',
  '    context.input.file_path like "*/.netrc" || context.input.file_path like "*/.git-credentials" ||',
  '    context.input.file_path like "*/.npmrc" || context.input.file_path like "*/.pypirc" ||',
  '    context.input.file_path like "*/.docker/config.json" || context.input.file_path like "*/.kube/config" ||',
  '    context.input.file_path like "*/.config/gh/hosts.yml" || context.input.file_path like "*/.gnupg/*" ||',
  '    context.input.file_path like "*/protect-mcp.key" || context.input.file_path like "*/keys/gateway.json")',
  "}",
  "unless {",
  '  context.input.file_path like "*.pub" || context.input.file_path like "*.example" ||',
  '  context.input.file_path like "*.sample" || context.input.file_path like "*.template"',
  "};",
  "",
  '@id("starter.grep-secret-path")',
  '@reason("Searches inside a credential file or folder. Ask the person for the value you need.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource)',
  "when {",
  '  resource == Tool::"Grep" && context has input && context.input has path && (',
  '    context.input.path like "*/.env" || context.input.path like "*/.env.*" ||',
  '    context.input.path like "*/.ssh*" || context.input.path like "*/.aws*")',
  "};",
  "",
  '@id("starter.shell-reads-secret")',
  '@reason("Prints a credential file in the shell. Ask the person for the value you need.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command && (",
  '    context.input.command like "*cat *" || context.input.command like "*grep *" ||',
  '    context.input.command like "*rg *" || context.input.command like "*head *" ||',
  '    context.input.command like "*tail *" || context.input.command like "*less *" ||',
  '    context.input.command like "*more *" || context.input.command like "*strings *" ||',
  '    context.input.command like "*base64 *" || context.input.command like "*xxd *") && (',
  '    context.input.command like "* .env" || context.input.command like "* .env *" ||',
  '    context.input.command like "*/.env" || context.input.command like "*/.env *" ||',
  '    context.input.command like "* .env.*" || context.input.command like "*/.env.*" ||',
  '    context.input.command like "*.ssh/id_*" || context.input.command like "*.aws/credentials*" ||',
  '    context.input.command like "*.netrc*" || context.input.command like "*.git-credentials*" ||',
  '    context.input.command like "*.docker/config.json*" || context.input.command like "*gh/hosts.yml*")',
  "}",
  "unless {",
  '  context.input.command like "*.env.example*" || context.input.command like "*.env.sample*" ||',
  '  context.input.command like "*.env.template*" || context.input.command like "*.pub*"',
  "};",
  "",
  '@id("starter.pipe-network-to-shell")',
  '@reason("Runs a downloaded script without review. Save it to a file and read it first.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command &&",
  '  (context.input.command like "*curl *" || context.input.command like "*wget *") && (',
  '    context.input.command like "*| sh" || context.input.command like "*| sh *" ||',
  '    context.input.command like "*|sh" || context.input.command like "*|sh *" ||',
  '    context.input.command like "*| bash" || context.input.command like "*| bash *" ||',
  '    context.input.command like "*|bash" || context.input.command like "*|bash *" ||',
  '    context.input.command like "*| zsh" || context.input.command like "*| zsh *" ||',
  '    context.input.command like "*| sudo sh*" || context.input.command like "*| sudo bash*" ||',
  '    context.input.command like "*| sudo -E bash*" || context.input.command like "*sh <(curl*" ||',
  '    context.input.command like "*sh <(wget*" || context.input.command like "*source <(curl*" ||',
  '    context.input.command like "*sh -c \\"$(curl*" || context.input.command like "*sh -c \\"$(wget*" ||',
  '    context.input.command like "*eval \\"$(curl*" || context.input.command like "*eval $(curl*")',
  "};",
  "",
  '@id("starter.write-sensitive-location")',
  '@reason("Writes a system, shell-profile, SSH, credential or agent-control file. A person makes this change.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource)',
  "when {",
  '  (resource == Tool::"Write" || resource == Tool::"Edit" || resource == Tool::"MultiEdit") &&',
  "  context has input && context.input has file_path && (",
  '    context.input.file_path like "/etc/*" || context.input.file_path like "/private/etc/*" ||',
  '    context.input.file_path like "/usr/*" || context.input.file_path like "/bin/*" ||',
  '    context.input.file_path like "/sbin/*" || context.input.file_path like "/System/*" ||',
  '    context.input.file_path like "/Library/*" || context.input.file_path like "*/Library/LaunchAgents/*" ||',
  '    context.input.file_path like "*/.bashrc" || context.input.file_path like "*/.bash_profile" ||',
  '    context.input.file_path like "*/.zshrc" || context.input.file_path like "*/.zprofile" ||',
  '    context.input.file_path like "*/.zshenv" || context.input.file_path like "*/.profile" ||',
  '    context.input.file_path like "*/.config/autostart/*" || context.input.file_path like "*/.gitconfig" ||',
  '    context.input.file_path like "*/.ssh/*" || context.input.file_path like "*/.aws/*" ||',
  '    context.input.file_path like "*/.netrc" || context.input.file_path like "*/.git-credentials" ||',
  '    context.input.file_path like "*/.claude/settings.json" || context.input.file_path like "*/.claude/settings.local.json" ||',
  '    context.input.file_path like "*/.codex/config.toml" || context.input.file_path like "*/.codex/hooks.json" ||',
  '    context.input.file_path like "*/protect.cedar" || context.input.file_path like "*/protect-mcp.key" ||',
  '    context.input.file_path like "*/keys/gateway.json" || context.input.file_path like "*/../*")',
  "};",
  ""
].join("\n");
var STARTER_CONTAIN_TEMPLATE = [
  '@id("starter.write-outside-project")',
  '@reason("Writes outside this project. Work inside the project or a temporary folder, or ask the person.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource)',
  "when {",
  '  (resource == Tool::"Write" || resource == Tool::"Edit" || resource == Tool::"MultiEdit") &&',
  "  context has input && context.input has file_path",
  "}",
  "unless {",
  '  context.input.file_path like "__PROJECT__/*" ||',
  '  context.input.file_path like "/tmp/*" || context.input.file_path like "/private/tmp/*" ||',
  '  context.input.file_path like "/var/folders/*" || context.input.file_path like "/private/var/folders/*" ||',
  '  context.input.file_path like "__HOME__/.claude/projects/*/memory/*" ||',
  '  context.input.file_path like "__HOME__/.claude/plans/*"',
  "};",
  "",
  '@id("starter.delete-outside-project")',
  '@reason("Recursive delete of an absolute path outside this project. Delete inside the project, or ask the person.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command && (",
  '    context.input.command like "*rm -rf /*" || context.input.command like "*rm -rf \\"/*" ||',
  '    context.input.command like "*rm -rf ~/*" || context.input.command like "*rm -rf $HOME/*" ||',
  '    context.input.command like "*rm -rf \\"$HOME/*")',
  "}",
  "unless {",
  '  context.input.command like "*rm -rf __PROJECT__/*" || context.input.command like "*rm -rf \\"__PROJECT__/*" ||',
  '  context.input.command like "*rm -rf __TILDE__/*" ||',
  '  context.input.command like "*rm -rf /tmp/*" || context.input.command like "*rm -rf \\"/tmp/*" ||',
  '  context.input.command like "*rm -rf /private/tmp/*" || context.input.command like "*rm -rf \\"/private/tmp/*" ||',
  '  context.input.command like "*rm -rf /var/folders/*" || context.input.command like "*rm -rf \\"/var/folders/*" ||',
  '  context.input.command like "*rm -rf /private/var/folders/*" || context.input.command like "*rm -rf \\"/private/var/folders/*" ||',
  '  context.input.command like "*rm -rf $TMPDIR*" || context.input.command like "*rm -rf \\"$TMPDIR*"',
  "};",
  ""
].join("\n");

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

Every AI agent tool call gets a cryptographic receipt. Verify offline. No vendor trust required.

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
If swarm data exists, show the agent topology (coordinator \u2192 workers).
`;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  BUILTIN_PATTERNS,
  generateHookSettings,
  generateSampleCedarPolicy,
  generateVerifyReceiptSkill
});
