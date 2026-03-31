// ============================================================
// Clinejection Protection — Cedar Edition
//
// CVE-2025-6514: Clinejection MCP OAuth Proxy Hijack
// A prompt injection in a GitHub issue title caused an AI agent
// to publish backdoored npm packages. 437,000+ developer
// environments compromised in 8 hours.
//
// Controls: SOC2-CC6.1, SOC2-CC6.8, SOC2-CC7.2, SOC2-CC8.1
//           EU-AI-Art.9, EU-AI-Art.12, EU-AI-Art.14
//           OWASP-A01, OWASP-A03
//           MCP-01, MCP-03, MCP-04
//           NIST-GOVERN-1.1, NIST-MAP-3.1, NIST-MEASURE-2.1
// ============================================================

// Block all shell execution tools
@id("sb-clinejection-001")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"execute_command"
);

@id("sb-clinejection-002")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"run_command"
);

@id("sb-clinejection-003")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"shell"
);

@id("sb-clinejection-004")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"bash"
);

@id("sb-clinejection-005")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"terminal"
);
