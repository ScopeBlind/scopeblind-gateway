# Changelog

## v0.5.2 (2026-04-04)

### Added
- Claude Code hook server: 11 event types, Cedar WASM policy eval, Ed25519 receipt signing
- `init-hooks` command for one-command Claude Code integration
- `issuer_certification` and `spec` fields on every receipt
- Swarm tracking: agent_id, agent_type, team_name per receipt
- Config tamper detection via ConfigChange event
- `iteration_id` field for behavioral windowing (community contribution)
- Open Plugins standard: skills/SKILL.md, mcp.json, hooks/hooks.json
- Verified Knowledge Base: acta.today/wiki — 8 frontier models, 3 adversarial rounds

### Changed
- License: FSL-1.1-MIT to MIT
- Repository: scopeblind/scopeblind-gateway
- PostToolUse response updated to match Claude Code schema

### Integrations
- Merged into Microsoft Agent Governance Toolkit (PR #667)
- Mission Control: Ed25519 audit signing (PR #556)
- Assay: signed receipts as evidence source (#1029)
- IETF Internet-Draft: draft-farley-acta-signed-receipts-01
- Claude Code + Cursor plugin marketplaces

## v0.3.1 (2026-03-24)

### Added
- Per-tool policies: `block`, `rate_limit`, `min_tier`, `require_approval`
- Non-blocking approval flow with request_id scoping and nonce authentication
- Passport identity in `protect-mcp status` output
- Signed decision receipts persisted to `.protect-mcp-receipts.jsonl`
- Audit bundle export via `protect-mcp bundle`
- `protect-mcp simulate` — dry-run policy evaluation against recorded tool calls
- `protect-mcp report` — compliance report generation (JSON + Markdown)
- Policy packs: shadow, web-browsing-safe, email-safe, strict
- Local HTTP status server with receipt API and approval endpoints

### Changed
- Shadow mode is the default (renamed from "observe mode")
- Decision logs use v2 format with tier and reason codes

## v0.3.0 (2026-03-22)

### Added
- Trust-tier gating from agent manifests
- Credential vault configuration
- BYOPE hooks (OPA, Cerbos, generic HTTP)
- `protect-mcp init` — generates Ed25519 signing keys and config template

## v0.2.0 (2026-03-21)

### Added
- Artifact v2 envelope format with JCS canonicalization
- JWK thumbprint-based key identifiers (kid)
- Holder binding commitments

## v0.1.0 (2026-03-08)

### Added
- Initial release: stdio proxy, shadow/enforce modes, per-tool policies, structured decision logs
