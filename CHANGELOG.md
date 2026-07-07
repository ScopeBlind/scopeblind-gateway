# Changelog

## 0.9.2: anchor a claim to the public log

Closes the one honest gap in a bare claim: that the disclosed set is complete.

- Added `protect-mcp claim --anchor`: records the claim's digest in the public,
  append-only ScopeBlind transparency log, so a counterparty who does not trust
  you can confirm the exact claim existed at a time and was not quietly re-cut.
  Only the hash is sent; the claim, its leaves, and every receipt stay on your
  machine. Writes a `<claim>.anchor.json` sidecar with the log entry and a
  verify URL. Anonymous and free; enrolling an org identity a counterparty can
  pin is the paid upgrade (scopeblind.com/enroll).

## 0.9.1: prove a claim without revealing the record

The record viewer closes the loop from a decision to a portable proof.

- The `record` viewer surfaces the exact `claim` command when you filter by a
  capability, so a decision becomes a signed, position-blind attestation in one
  step, with copy-to-clipboard and an offline `verify-claim` hint.
- The browser drop-viewer (legate.scopeblind.com/record) reached parity with
  the CLI: signed capability tags, a capability facet, and a provenance tree.

## 0.9.0: signed, position-blind claim attestations

Prove a predicate over the record without revealing it.

- Added `protect-mcp claim`: mints a signed attestation of a predicate over the
  record (`--no <cap>` for "no action carried this capability", `--only`,
  `--count`/`--no-verdict <verdict>`), disclosing only per-decision categories
  (receipt digest, verdict, capability tags), never inputs, outputs, or data.
- Added `protect-mcp verify-claim`: checks it offline via Ed25519 over the pack,
  a recomputed Merkle root over the disclosed set, and the predicate recomputed
  independently. Honest trust model: an accountable position-blind attestation,
  not zero-knowledge; set-completeness is issuer-attested.

## 0.8.0: deterministic receipt enrichment

Each signed decision now carries minimum-disclosure, rule-derived metadata.

- `input_digest`: SHA-256 of the canonicalized tool input, so you can prove what
  was requested without storing it.
- Signed `capabilities`: deterministic, rule-derived tags (fs.read, fs.write,
  net.egress, secret.adjacent, destructive, financial, exec.shell, ...) so the
  record is queryable by what an action touched.
- `resource`: the hashed target (path, host, or command). The gate sees tool
  calls, not the model's prompt or reasoning, and does not claim to.

## 0.7.6: the live record viewer

- Added `protect-mcp record --live`: a local, streaming view of the receipt
  file that turns decisions into a searchable, auto-labelled record as the agent
  runs (stat strip, per-row signed badge and digest, a List/Tree provenance
  view), all local, nothing uploaded.
- One-click export: `.jsonl` carrying the real signatures (so a recipient
  verifies offline with `npx @veritasacta/verify`) plus a Markdown report.

## 0.7.5: honest version strings and the record viewer

- Added `protect-mcp record`, a local browser viewer over the receipts file
  (the answer to "the receipts are a hidden dotfile I cannot find").
- Fixed hard-coded version strings in the banner and health/serverInfo: they
  read the resolved package version now.
- WebAuthn co-sign hardening: verify the rpIdHash and enforce challenge expiry.

## 0.7.4: the self-serve trial path

Everything the scopeblind.com trial and docs pages describe now ships in the
published package: wrap, dashboard, trial, policy packs, connectors, the
registry client, and selective disclosure v0.

- Added `protect-mcp trial`, a guided ten-minute local trial: run the demo
  tool server, watch risky calls, install a policy pack, require an approval,
  and export a signed receipt you can verify offline.
- Added `protect-mcp connectors`, dry-run connector pilots for GitHub, email,
  filesystem/Git, Slack or Teams, and a mock-to-real PMS adapter
  (`connectors list|show|init|doctor`). These are scaffolds with policies and
  config, not a managed marketplace; GitHub, Slack/Teams, and real PMS mode
  still need customer tokens or adapters.
- Added `protect-mcp wrap` for install-to-aha onboarding. It prints a protected
  MCP command, can patch Claude Desktop MCP server config in dry-run mode, and
  writes only when `--write` is passed.
- Added `protect-mcp dashboard`, a local-only `127.0.0.1` dashboard for
  shadow-mode inventory, risk review, receipts, and next policy moves.
- Added exact-action readbacks to decision logs and signed receipts: tool,
  action, destination, redacted payload preview, payload hash, disclosed fields,
  and redacted fields.
- Upgraded the local dashboard into an action-control surface: policy coverage,
  one-click `Require approval`/`Block`/`Observe` drafting, pending approval
  queue, reason capture, desktop approval forwarding, receipt-chain view, and
  audit-bundle export with explicit signed-receipt preflight.
- Added `protect-mcp recommend`, which drafts a reviewable JSON policy from
  observed local tool calls before users flip wrappers into `--enforce`.
- Added `protect-mcp registry`, a paid-boundary MVP for hosted org identity,
  receipt digest anchoring, org public-key directory, billing-account metadata,
  and a static verifier page. Hosted mode uploads digests only, not raw prompts,
  payloads, outputs, private keys, or raw receipts.
- Added `protect-mcp killer-demo`, which generates a three-minute
  shadow-mode → policy → exact approval → gateway execution → signed receipt →
  tamper failure → selective-disclosure demo pack.
- Added Selective Disclosure v0 on committed receipts: `committed_fields_root`,
  multi-field disclosure packages, verifier explanations for disclosed versus
  hidden fields, CLI verification via `protect-mcp verify-disclosure`, and audit
  bundle inclusion. This is salted commitments + Merkle proofs, not full ZK.
- Added `protect-mcp policy-packs`, a starter Cedar template library for
  filesystem-safe, Git-safe, email-safe, database-safe, cloud-spend-safe,
  secrets-safe, and finance-mandate-safe rollouts.
- Expanded the built-in demo MCP server with GitHub PR, email, and mock PMS
  booking tools so the demo maps to agent actions a hedge fund actually cares
  about.
- Reworked the README quickstart around the practical path: initialize, wrap,
  inspect, draft policy, then enforce.

## 0.7.3: tool input reaches `context.input`, and the hook path fails closed

Two correctness fixes for policy authors who rely on the documented Cedar shape.

The evaluator maps tool input to Cedar `context.input`, and the bundled policy
examples are written against `context.input.*`, but the `evaluate` CLI path and
the HTTP hook server only flattened tool input into top-level context fields. So
a policy keyed on `context.input.path` silently saw nothing on those paths: a
`forbid` that should have denied never fired, and the call was allowed. Both
paths now pass the tool input through, so nested-shape policies match. The
existing flattened fields are kept for back-compat. (Thanks to @koriyoshi2041,
scopeblind-gateway#8, for the report and repro.)

Separately, the hook server's Cedar evaluation fell through to **allow** on an
unexpected evaluator throw, which contradicted the "denies on any error"
guarantee from 0.7.0 (the CLI path already failed closed). The hook path now
denies on an unexpected eval error while a policy is configured.

Regression coverage added on all three paths; `npm ci` from a clean clone also
works again (the lockfile was out of sync).

## 0.7.2: run the gate in other agents (Codex, Cursor, Gemini, Hermes)

The `evaluate` and `sign` verbs now accept `--format <host>`
(claude | codex | gemini | cursor | hermes | grok). With it, the verb reads the
host's hook payload from stdin (tool name and input) and emits the deny verdict
in that host's hook contract, so the same fail-closed Cedar gate works as a
PreToolUse/PostToolUse hook outside Claude Code.

The load-bearing detail: **Hermes ignores hook exit codes** and reads the verdict
from stdout, so `--format hermes` denies via `{"decision":"block"}` on stdout. A
raw exit-2 (which every other host honors) would have silently failed open there.
Cursor and Gemini receive their structured stdout deny verdict in addition to
exit 2. Without `--format`, the verbs behave exactly as before (the
`--tool`/`--input` flag mode is unchanged).

## 0.7.1: documentation and security policy

No code change from 0.7.0. Rewrote the README to lead with the fail-closed and
self-test guarantees, and added a `SECURITY.md` disclosure policy (supported
versions, the affected 0.5.x/0.6.x range, the published advisory, and the
coordinated-disclosure process). The package now ships `SECURITY.md`.

## 0.7.0 (security release): the gate now fails closed and actually evaluates

This release fixes the way the Cedar policy gate behaves when anything goes
wrong, and a separate defect that meant Cedar policies were not being evaluated
at all against the pinned engine. If you rely on protect-mcp to enforce a Cedar
policy, upgrade.

### Security

- **Fail closed, not open.** Before 0.7.0, if the Cedar engine was unavailable,
  the result was malformed, evaluation threw, or a policy errored, the evaluator
  returned ALLOW. A security gate must do the opposite. Every error and
  uncertainty path now DENIES. The allow-on-error behavior is reachable only by
  explicitly passing `{ failClosed: false }` (observe mode), and even then the
  decision is flagged `would_deny: true` so a failure is never silent.
- **An errored policy can no longer permit-all.** Cedar silently discards a
  policy that errors at evaluation (for example the `context.<string> in [list]`
  type error in the 0.5.x and 0.6.x advisory), which could leave a residual
  permit standing. The evaluator now treats any per-policy error as an
  evaluation error and denies under enforcement.
- **Cedar policies are actually evaluated now.** The `isAuthorized` call passed
  the policy text as a bare string, but `@cedar-policy/cedar-wasm@4.x` requires a
  structured `PolicySet`. As a result every Cedar evaluation errored against the
  pinned engine and (with the old fail-open default) allowed everything. The call
  shape and the response parser are corrected, so a `forbid` rule actually denies
  and a `permit` actually allows.

### Added

- **`protect-mcp evaluate`** and **`protect-mcp sign`**: one-shot per-call verbs
  for PreToolUse and PostToolUse hooks. `evaluate` loads a Cedar policy, evaluates
  one tool call fail-closed, and exits 2 on deny (so the tool is blocked) and 0 on
  allow; a missing or unloadable policy denies unless `--fail-on-missing-policy
  false` is set. This makes hook configs that invoke these verbs work as written.
- **`runEvaluatorSelfTest()`** plus a startup gate: `serve --enforce` runs the
  self-test before arming and refuses to start if the engine cannot prove it
  denies a known-forbidden vector. `protect-mcp doctor` reports the same, so the
  gate verifies its own restraint before it is trusted.
- A CI tripwire test that fails the build if the discarded `in`-on-String pattern
  is ever reintroduced into a shipped policy.

### Affected versions

The fail-open behavior and the unevaluated-Cedar defect are present in the
0.5.x and 0.6.x lines. Upgrade to 0.7.0.
