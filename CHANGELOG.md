# Changelog

## 0.10.1: HTTP gateway mode enforces Cedar and emits chained receipts

Three fixes found by running the cloud-gateway path end to end before
documenting it:

- Fail-open fixed: in `--http` mode, loaded Cedar policies were never
  attached to the gateway (the stdio path attached them after the HTTP
  branch returned), so a remote gate started with `--enforce` and a Cedar
  policy silently allowed everything. Cedar policies are now attached
  before the child starts, and a forbidden tool call over HTTP is denied.
- Silent-unsigned fixed: a Cedar-mode gateway never read `signing` from
  protect-mcp.json (only the JSON-policy branch did), so it emitted no
  receipts while looking fully configured. Cedar mode now picks up signing
  and credentials from protect-mcp.json when present and says so on stderr.
- Gateway receipts now chain: the wrapped-server path (stdio and HTTP)
  threads previousReceiptHash per draft s5.7 and resumes the chain across
  restarts from the log tail, matching the hook server. Verified end to
  end: a cloud-style client over Streamable HTTP, one allow and one deny,
  chained draft-02 receipts, replayed offline with the published
  @veritasacta/verify with zero chain breaks.


## 0.10.0: receipts migrate to the draft-02 Acta envelope

Also in this release, the policy digest becomes a recomputable commitment
(prompted by public review of opaque policy identifiers):

- One normative construction for every engine, `acta-policy-digest-v1`:
  per-file SHA-256s into a sorted `{construction, engine, files}` manifest,
  JCS, SHA-256, emitted as `"sha256:<64 hex>"`. Replaces two divergent
  code-defined preimages that concatenated sources (ambiguous file
  boundaries) and truncated to 16 hex characters with no prefix. Receipts
  now carry the full-strength digest; pre-0.10 digests should be treated
  as opaque labels.
- `protect-mcp policy digest` prints the digest, the per-file hashes, and
  the recompute rule (`--expect` for CI, `--json` for tooling).
- `protect-mcp policy publish` writes the `acta.policy-bundle.v1` bundle
  (policy bytes plus preimage spec, addressed by the digest) ready to host
  at `.well-known/acta-policies/<hex>.json`; a verifier confirms which
  policy governed a receipt from the bundle bytes alone, with no
  communication with the issuer.
- The construction is specified normatively in
  draft-farley-acta-signed-receipts-03 (section 5.8), alongside
  `require_approval` as a decision value.

Receipts are now emitted in the envelope the IETF draft actually specifies
(draft-farley-acta-signed-receipts-02): a two-field
`{ payload, signature: { alg: "EdDSA", kid, sig } }` envelope, with the
access-decision fields from section 3.1 (`type: "protectmcp:decision"`,
`tool_name`, `decision`, `reason`, `policy_digest`), `issuer_id` equal to
`signature.kid` (section 2.2), the signature computed as PureEdDSA directly
over the JCS bytes of the payload with no pre-hash (section 5.6), and new
keys defaulting to the section 2.1.1 recommended
`sb:issuer:<base58-fingerprint>` kid format (existing key files keep their
explicit kid). Previously the package emitted an internal envelope shape
that predated the published draft.

Receipt logs are now hash-chained per section 5.7: each receipt's
`previousReceiptHash` is the bare-hex SHA-256 of the JCS bytes of the
previous log line exactly as written, signature included. The hook server
resumes the chain across restarts from the tail of the existing log, and
signing-failure tombstones participate in the chain so an unsigned gap
cannot be silently dropped.

Verification is dual-shape everywhere (the `verify_receipt` MCP tool, the
`serve --enforce` self-test, the embedded record viewer, and the exported
`verifyReceipt` API): receipts written by protect-mcp 0.9.x and earlier
(flat v1 artifacts and structured v2 envelopes with a top-level signature
string) continue to verify, and a mixed pre/post-migration log replays
cleanly, including the chain link that spans the boundary. Verified against
3,352 real receipts from a production gate log: all verify. The published
`@veritasacta/verify` CLI (0.9.2) verifies the new envelopes as-is via its
passport path; no verifier upgrade is required.

New module `acta-envelope` (exported from the package root):
`createReceiptEnvelope`, `verifyReceipt`, `receiptHash`, `receiptIdentity`,
`computeSbIssuerKid`. `signDecision` accepts an optional previous-chain-hash
argument and returns the emitted receipt's chain hash. `@noble/curves` and
`@noble/hashes` moved from optional to regular dependencies.

Fixed: importing the package as a library no longer attaches the demo
server's stdin JSON-RPC listener (it now only starts when demo-server is
the process entry point). Previously any `require("protect-mcp")` kept the
host process's event loop alive and answered JSON-RPC on stdout.

Note for strict draft conformance: `decision` may be "require_approval" for
held-for-co-sign flows, an extension value beyond the section 3.1 set
(allow, deny, rate_limit), pending a revision of the draft.


## 0.9.7: the gate as an MCP server

`protect-mcp mcp` boots a stdio MCP server exposing the gate itself as four
tools, so an agent can call the gate directly instead of only through the
PreToolUse/PostToolUse hooks: `evaluate_action` (Cedar decision, fail-closed),
`sign_decision` (Ed25519 receipt, byte-compatible with the runtime gate's),
`verify_receipt` (offline check), and `self_test` (proves a known-forbidden
action is denied and a signed receipt round-trips). All four are read-only
and annotated with what they return. A bare-spawnable bin,
`protect-mcp-mcp`, is included alongside the `mcp` subcommand so any MCP
host or registry can point at either.

## 0.9.6: policy you can see and change

The gate is default-deny and fail-closed, but a deny used to be a dead end: an
empty reason and no pointer to the file that decides. This release makes the
policy legible and editable from the terminal, and lets a running gate pick up
a policy change without a restart.

- **`policy` command.** `policy list` shows every tool named in the policy
  (permit / forbid / default-deny) cross-referenced with how often the gate
  actually allowed or denied it; `policy show` prints the active policy and its
  digest; `policy allow <tool>` / `policy deny <tool>` append a Cedar rule and
  print the digest change; `policy path` prints the file. Idempotent and
  tool-name validated.
- **Denies that teach.** A blocked call now says whether it was default-deny
  (no permit matched) or an explicit forbid, names the policy directory, and
  gives the exact fix: `npx protect-mcp policy allow <tool>`.
- **Hot reload.** `protect-mcp serve` watches the .cedar files and reloads the
  policy on an on-disk change, so `policy allow/deny` (or a hand edit) takes
  effect without restarting the gate. Fail-closed: an unparseable edit keeps the
  previous policy rather than opening the gate, and the reload is logged.

## 0.9.5: replayable from scratch

The public demo film (legate.scopeblind.com/record) is now reproducible by
anyone in 60 seconds, and the CLI answers the first two commands every new
user types.

- **`sample`.** Seeds a clearly-labeled sample record (fresh Ed25519 keypair,
  kid `sample-demo`): 8 decisions including one BLOCKED network call and two
  payments ($0.02 x402-style per-call, $12.50 invoice), plus
  `demo-tampered.jsonl` with one decision flipped after signing. The receipts
  are real signed artifacts (same envelope and canonical-JSON preimage as the
  gate's signer), so `record`, `claim --payment-under`, `verify-claim`, and
  `anchor-record` work on the folder immediately. Refuses to touch an existing
  record or signing key; `--force` overrides.
- **`--version` / `version` / `-V`.** Prints the installed version. Previously
  these fell through to wrap-mode parsing and errored demanding a `--`
  separator, which was the first thing many new users saw.
- **`help` word.** `npx protect-mcp help` prints usage (previously errored).
  Help and version flags are now only recognized BEFORE the `--` separator, so
  `protect-mcp -- node server.js --version` wraps that command as intended
  instead of printing our help.

## 0.9.4: agent payments get receipts, records get heartbeats, anchors get names

The provenance layer reaches the agentic economy's payment rails (x402), the
record gains continuous completeness, and anchoring can carry an identity.

- **Payment receipts (x402 interop).** The gate now tags agent payments with a
  signed `payment` capability, detected broadly across x402 wire shapes
  (`paymentRequirements`, `X-PAYMENT`, EIP-3009 `transferWithAuthorization`)
  and payment-shaped tools. Receipts carry minimum-disclosure payment facts:
  amount (only when clearly readable in human units), asset, a HASHED recipient,
  and the x402 scheme. `claim --no payment` proves no agent paid anything;
  `claim --payment-under <cap>` proves every payment stayed under a cap, and an
  amount the gate could not read counts as OVER (you cannot prove an amount you
  could not read, so the claim cannot lie).
- **Record checkpoints (`anchor-record`).** Anchors the record's CURRENT
  commitment (the same Merkle root a claim commits to, plus count and time
  range) into the public log. Run it on a heartbeat and the record grows an
  anchored history: a later claim whose root matches a checkpoint is provably
  over the complete set as of that checkpoint. Skips when the record is
  unchanged; writes a local `.protect-mcp-anchors.jsonl` history; only the
  root, count, and time range leave the machine.
- **Pinned identity in the anchor loop.** `claim --anchor`, `anchor-record`,
  and `verify-claim` now resolve the anchoring key against the public ScopeBlind
  key directory: an enrolled key shows "anchored as <Org> (key pinned)", a
  revoked key fails verification, an anonymous key points at enrollment. The
  free anchor stays anonymous; the named identity is the paid upgrade.

## 0.9.3: the skeptic's tools sharpen

Two verification upgrades: the anchor check moves into the verifier, and the
record viewer proves signatures instead of just labelling them.

- `verify-claim` now verifies the anchor automatically: it finds the
  `<claim>.anchor.json` sidecar, checks offline that the anchored envelope binds
  this exact claim (digest, record root, and the same issuer key), and confirms
  against the public log that the digest sits at the recorded entry. A failed
  binding makes the attestation INVALID; an unreachable log does not (the local
  checks stand alone). `--check-anchor` makes a missing anchor fatal,
  `--anchor-file <p>` overrides the path, `--offline` skips the network hop.
- The `record` viewer now verifies Ed25519 signatures in the browser, locally:
  each row shows `✓ verified`, `✗ invalid signature`, or `signed · unpinned
  key`, and the stat strip counts how many verified. The CLI injects your
  gateway's PUBLIC key so rows verify against your own key (the private key
  never reaches the page).
- Receipts now embed the signer's public key inside the signed payload
  (`payload.public_key`), so a receipt is self-contained: any verifier can check
  it without a side channel, and the key cannot be swapped without breaking the
  signature. Older receipts still verify against a pinned or pasted key.

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
