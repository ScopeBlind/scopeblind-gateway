# Integrations and contributions

These links document upstream contributions, downstream integrations and
interoperability work around protect-mcp and Acta receipts. Each entry names
the relationship; inclusion does not imply customer use or endorsement.

Source snapshot checked on 24 October 2026. Upstream projects may change their
implementations and package versions independently of this repository.

## Microsoft AI Agents for Beginners

protect-mcp's maintainer, [Tom Farley](https://github.com/tomjwxf), authored
**Lesson 18: Securing AI Agents with Cryptographic Receipts**. It teaches signing,
verification and chaining of agent receipts.

- [Current lesson](https://github.com/microsoft/ai-agents-for-beginners/tree/main/18-securing-ai-agents).
- [Authorship PR #533](https://github.com/microsoft/ai-agents-for-beginners/pull/533),
  merged 30 April 2026
  ([merged source](https://github.com/microsoft/ai-agents-for-beginners/tree/0afb2c76889dc1e6d3b3fb9c96f98789d69c2fe5/18-securing-ai-agents)).
- [Reference update #646](https://github.com/microsoft/ai-agents-for-beginners/pull/646),
  merged 13 July 2026, updates draft and conformance references.

This is an educational contribution to Microsoft's public curriculum.

## Cedar for Agents

Tom contributed the WASM bindings for Cedar's Rust MCP schema generator, making
the generator available to JavaScript and TypeScript consumers.

- [Current module](https://github.com/cedar-policy/cedar-for-agents/tree/main/rust/cedar-policy-mcp-schema-generator-wasm).
- [PR #64](https://github.com/cedar-policy/cedar-for-agents/pull/64), merged
  15 April 2026
  ([merged source](https://github.com/cedar-policy/cedar-for-agents/tree/af35ea58cb0d44beb21560cceab2eed4f9ea9ce0/rust/cedar-policy-mcp-schema-generator-wasm)).

The contribution is to the MCP schema-generation tooling. Cedar itself is the
policy engine used by protect-mcp; this contribution is not authorship of Cedar.

## wshobson/agents

The repository ships a protect-mcp plugin with Claude Code policy and receipt
hooks. Its maintainer-facing setup and version pins live upstream.

- [Current plugin](https://github.com/wshobson/agents/tree/main/plugins/protect-mcp).
- [Compatibility contribution #756](https://github.com/wshobson/agents/pull/756),
  merged 15 October 2026, fixes evaluation on Node.js 18 and 20 and decimal
  inputs by moving evaluation to protect-mcp 0.31.0
  ([merged source](https://github.com/wshobson/agents/tree/cdf0eab94fda955499fc37b1e6ceeec40468959e/plugins/protect-mcp)).

The integration's pinned evaluation and signing versions may differ from this
repository's current release. Follow its documented versions; for current
gateway setup, use the [local gateway guide](local-gateway.md).

## TRACE receipt fixtures

TRACE publishes Acta decision-receipt examples. Veritas Acta's verifier publishes
the results of checking those fixtures against a pinned upstream snapshot.

- [Current TRACE fixtures](https://github.com/agentrust-io/trace-spec/tree/main/examples/action-receipts/acta).
- [Pinned fixture source](https://github.com/agentrust-io/trace-spec/tree/b8d2ce6161e57d41dd0b49be78efc05e86baeca5/examples/action-receipts/acta).
- [Verifier report and reproduction commands](https://github.com/VeritasActa/verify/blob/9d0fb12303212ac8bf6d94dcb101183f57477b14/docs/trace-fixtures.md).

The report covers **11 fixtures and 35 compared checks**, with no differences in
the checked signing input, signatures, key-validity windows and supplied
predecessor links. Policy freshness and session binding are not checked by that
run. This is a published compatibility result from our verifier, not a security
certification or an external audit of protect-mcp.

## Add an integration or compatibility result

For an integration, link the actual adapter or plugin and state the supported
versions. For a compatibility result, pin the fixture revision, include commands
and expected outcomes, and list the properties the run does and does not check.

The [shared conformance corpus](https://github.com/ScopeBlind/agent-governance-testvectors)
is another place to contribute receipt fixtures. See [CONTRIBUTING.md](../CONTRIBUTING.md)
for local setup and review expectations.
