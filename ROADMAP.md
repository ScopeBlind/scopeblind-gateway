# Roadmap

Directions that are planned but not started. Each was an issue opened in April 2026 with no
activity since; they live here now so the issue list shows only work in progress. Open an
issue when one of these starts, or when you want to take one.

- **Receipt-signing middleware for MCP server frameworks.** A drop-in for the common MCP server
  libraries that signs a decision receipt for every tool call the server handles, so a server
  author gets Acta receipts without wiring protect-mcp as a gateway.
- **Cedar policy pack library for common agent governance patterns.** Named, versioned policy
  sets (read-only agents, no egress, no destructive shell, spend caps) shipped under
  `policies/` with digests, so a deployment can cite the pack it enforces.
- **Vulnerability disclosure receipt type.** A receipt profile for coordinated disclosure
  events (finding, notification, fix, publication) so each step is signed and chained,
  proposed for Project Glasswing style programs.

Shipped items move to [CHANGELOG.md](CHANGELOG.md).
