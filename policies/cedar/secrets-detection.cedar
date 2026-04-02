// ============================================================
// Secrets & Credential Protection — Cedar Edition
//
// Prevents AI agents from reading, writing, or exfiltrating
// sensitive files (SSH keys, env files, credentials, tokens).
//
// Controls: SOC2-CC6.1, SOC2-CC6.7, OWASP-A01, OWASP-A07
//           MCP-01, MCP-04, NIST-GOVERN-1.1
// ============================================================

// Block reading SSH private keys
@id("sb-secrets-001")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"read_file"
)
when {
  context has "input" &&
  context.input has "path" &&
  context.input.path like "*/.ssh/*"
};

// Block reading .env files
@id("sb-secrets-002")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"read_file"
)
when {
  context has "input" &&
  context.input has "path" &&
  context.input.path like "*/.env*"
};

// Block reading credential files
@id("sb-secrets-003")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"read_file"
)
when {
  context has "input" &&
  context.input has "path" &&
  context.input.path like "*/credentials*"
};

// Block reading token files
@id("sb-secrets-004")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"read_file"
)
when {
  context has "input" &&
  context.input has "path" &&
  context.input.path like "*/.token*"
};

// Block reading AWS credentials
@id("sb-secrets-005")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"read_file"
)
when {
  context has "input" &&
  context.input has "path" &&
  context.input.path like "*/.aws/*"
};

// Block writing to sensitive directories
@id("sb-secrets-006")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"write_file"
)
when {
  context has "input" &&
  context.input has "path" &&
  context.input.path like "*/.ssh/*"
};

// Block exfiltrating files via curl upload
@id("sb-secrets-007")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"bash"
)
when {
  context has "input" &&
  context.input has "command" &&
  context.input.command like "*--upload-file*"
};

// Block piping secrets to network
@id("sb-secrets-008")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"bash"
)
when {
  context has "input" &&
  context.input has "command" &&
  context.input.command like "*| curl*"
};
