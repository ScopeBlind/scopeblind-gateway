// ============================================================
// Terraform Destroy Protection — Cedar Edition
//
// CVE-2026-XXXX: AI Agent Terraform Destroy Incident
// An AI agent unpacked old Terraform configs and ran
// terraform destroy, wiping a production VPC, RDS database
// and ECS cluster.
//
// Controls: SOC2-CC6.1, SOC2-CC6.6, SOC2-CC8.1
//           EU-AI-Art.9, EU-AI-Art.14
//           OWASP-A06, OWASP-A09
//           MCP-02, MCP-06
//           NIST-GOVERN-1.2, NIST-MAP-3.1
// ============================================================

// Block bash/shell (primary vector for terraform commands)
@id("sb-terraform-001")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"bash"
);

@id("sb-terraform-002")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"execute_command"
);

@id("sb-terraform-003")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"run_command"
);

// Block destructive file operations
@id("sb-terraform-004")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"delete_file"
);
