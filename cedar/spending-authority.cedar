// ============================================================
// Spending Authority — Cedar Edition
//
// AI agents spending money on behalf of humans is the highest-
// stakes MCP action class. Without cryptographic proof of
// authorization, merchants cannot distinguish legitimate agent
// purchases from unauthorized ones, and organizations cannot
// enforce budget controls across autonomous agent fleets.
//
// The receipt proves authorization; it never touches money.
// The merchant settles through their existing payment rail.
//
// Controls: SOC2-CC6.1, SOC2-CC6.3, SOC2-CC6.6, SOC2-CC8.1
//           EU-AI-Art.9, EU-AI-Art.14, EU-AI-Art.52
//           OWASP-A01, OWASP-A04
//           MCP-01, MCP-05, MCP-06
//           NIST-GOVERN-1.1, NIST-GOVERN-1.2, NIST-MAP-3.1
//           NIST-MEASURE-2.1, NIST-MANAGE-2.3
// ============================================================

// ─── Auto-approve: low-value transactions under threshold ────
// Threshold is configurable per scope (default: $25.00 / 2500 cents)
@id("sb-spending-001")
permit (
  principal,
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  resource.amount_cents < context.auto_approve_threshold_cents &&
  context.budget_utilization != "exceeded" &&
  context.category_allowed == true
};

// ─── Require human approval: high-value transactions ─────────
// Amounts at or above the auto-approve threshold require explicit
// human confirmation before a receipt is issued.
@id("sb-spending-002")
forbid (
  principal,
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  resource.amount_cents >= context.auto_approve_threshold_cents &&
  context.approval_method != "human_confirmed"
};

// ─── Block: budget exhausted ─────────────────────────────────
// When cumulative spend reaches or exceeds the ceiling, all
// spending is blocked regardless of amount or approval method.
@id("sb-spending-003")
forbid (
  principal,
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  context.budget_utilization == "exceeded"
};

// ─── Block: disallowed merchant category ─────────────────────
// Organizations configure allowed merchant category codes.
// Any transaction to a disallowed category is rejected.
@id("sb-spending-004")
forbid (
  principal,
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  context.category_allowed == false
};

// ─── Per-agent-tier spending limits ──────────────────────────
// Unknown agents: $5 max per transaction (500 cents)
@id("sb-spending-005")
forbid (
  principal == Agent::"unknown",
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  resource.amount_cents > 500
};

// Signed-known agents: $50 max per transaction (5000 cents)
@id("sb-spending-006")
forbid (
  principal == Agent::"signed-known",
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  resource.amount_cents > 5000
};

// Evidenced agents: $500 max per transaction (50000 cents)
@id("sb-spending-007")
forbid (
  principal == Agent::"evidenced",
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  resource.amount_cents > 50000
};

// Privileged agents: $5000 max per transaction (500000 cents)
// Even the highest trust tier has a ceiling — no unlimited spend.
@id("sb-spending-008")
forbid (
  principal == Agent::"privileged",
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  resource.amount_cents > 500000
};

// ─── Block: high utilization + large transaction ─────────────
// When budget is 75%+ consumed, block any single transaction
// that exceeds 10% of the original ceiling. Prevents a single
// large purchase from blowing through the remaining budget.
@id("sb-spending-009")
forbid (
  principal,
  action == Action::"MCP::Spend::authorize",
  resource
)
when {
  context.budget_utilization == "high" &&
  resource.amount_cents > context.ceiling_tenth_cents
};
