# protect-mcp

Fail-closed Cedar policy gate plus signed receipts for AI agent tool calls.

[![npm version](https://img.shields.io/npm/v/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![downloads](https://img.shields.io/npm/dm/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![license](https://img.shields.io/npm/l/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![node](https://img.shields.io/node/v/protect-mcp)](https://www.npmjs.com/package/protect-mcp)

`protect-mcp` is a gate that sits in front of an AI agent's tool calls. It evaluates
each call against a [Cedar](https://www.cedarpolicy.com/) policy,
blocks what breaks the rules before it runs, and signs an
offline-verifiable Ed25519 receipt of every decision. The configured gateway runs locally and sends no decision telemetry. The
separate coordination adapter connects to ScopeBlind’s hosted collaboration service;
its requests and returned records have the data path described below. Both are
MIT licensed.

For shared repository work, use [client projects](https://scopeblind.com/standard?trial=new&view=workspace):
people agree on the brief and limits, agents prepare reviews, and both people
approve an exact version before the owner's receiver can change the repository.
The [repository workflow below](#recurring-client-reviews-and-agent-preparation)
includes setup and the five bounded agent tools.

## Why it is different

- **Fail-closed by default.** On any policy error, a missing engine, or an
  evaluation failure, the decision is DENY. The gate never silently allows. An
  observe mode exists for shadow rollout, but even there a call that would be
  blocked is flagged `would_deny: true`, so a failure is never silent.
- **It proves its own restraint.** `serve --enforce` and `doctor` run a startup
  self-test and refuse to arm the gate unless they can show that a known-forbidden
  action is actually denied. A gate that cannot prove it denies does not start.
- **Every decision is a receipt anyone can verify.** Decisions are Ed25519-signed
  and verifiable offline with [`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify).
  Signature verification needs no network lookup. Claims about execution still
  depend on the identified gate operator.

## Quickstart: install to first useful proof

```bash
# 1. Generate an Ed25519 keypair, config template, and sample policy.
npx protect-mcp init

# 2. Print a shadow-mode client configuration, then apply it in your MCP host.
#    This command prints configuration and exits; it does not launch the server.
npx protect-mcp wrap -- node your-mcp-server.js

# 3. Reopen the host and use its tools, then inspect the local-only dashboard.
npx protect-mcp dashboard --open

# 4. Draft a reviewable policy from observed calls.
npx protect-mcp recommend --write

# 5. When reviewed, restart the wrapper in enforce mode with that policy.
npx protect-mcp --policy protect-mcp.recommended.json --enforce -- node your-mcp-server.js
```

For Claude Desktop, run a dry-run config patch first, then apply it:

```bash
npx protect-mcp wrap --claude-desktop
npx protect-mcp wrap --claude-desktop --write
npx protect-mcp dashboard --open
```

The dashboard binds to `127.0.0.1`, reads only local log/receipt files, and does
not upload anything. Use `npx protect-mcp connect` only if you explicitly want a
hosted ScopeBlind dashboard.

## The gate as an MCP server

If you would rather call the gate as tools than wire the Claude Code hooks, run
it as an MCP server:

```bash
npx protect-mcp mcp
```

It speaks MCP over stdio and exposes four read-only tools, the whole loop:

- **`evaluate_action`**: decide a proposed tool call against an inline Cedar policy, fail-closed (any policy error is DENY). Returns `{ allowed, decision, reason, policy_digest }`.
- **`sign_decision`**: turn a decision into an Ed25519 signed receipt (a denial signs a `gateway_restraint`, an allow a `decision_receipt`). Returns the receipt and its public key; generates an ephemeral key if you do not supply one.
- **`verify_receipt`**: verify a signed receipt offline against a public key. Returns `{ valid, error, type, kid, issuer }`.
- **`self_test`**: prove it, no inputs. A known-forbidden action is denied, then a signed receipt round-trips and a tampered copy fails.

Point any MCP host at it, for example Claude Desktop:

```json
{
  "mcpServers": {
    "protect-mcp": { "command": "npx", "args": ["-y", "protect-mcp", "mcp"] }
  }
}
```

Receipts are byte-compatible with the ones the gate signs at runtime, so a
receipt minted here uses the same Acta envelope. Verification capabilities and
canonicalization compatibility depend on the verifier version; use the gateway's
`verifyReceipt` API for the conformance behavior described below.

### Receipt canonicalization compatibility

This source tree fixes the integer-key ordering defect present through 0.14.0: signatures and
chain hashes now use direct JCS member emission, retaining the gateway's ASCII
object-key profile. Numeric-looking keys such as `"10"` precede `"2"`, including
inside nested objects. Non-JSON values and invalid Unicode are rejected.

Ordinary JSON receipts whose encodings are unchanged continue to verify.
Historical receipts signed with the old numeric-key order are reported as
`legacy_non_jcs_signature`; strict verification does not call them valid JCS.
For an explicit historical compatibility check, use
`verifyReceipt(receipt, publicKey, { allowLegacyNumericKeys: true })` and inspect
the `canonicalization` and `warning` fields. Its `hash` is then the original
historical hash. Preserve original receipts and chain links: recomputing an old
numeric-key receipt with `receiptHash` now produces its JCS hash and can break
the historical chain. These changes are included in `0.15.0`.

### Start with your agent, then authorize each task

Version `0.25.0` includes a reusable agent profile. Open
[Start through your agent](https://scopeblind.com/standard?trial=new&view=agent)
for the setup command with the service’s displayed authority key. Check that key
against a trusted source before connecting. For example:

```bash
npx --yes protect-mcp@0.25.0 coordination agent setup \
  --client claude-code \
  --profile ~/.scopeblind/agent.json \
  --endpoint https://scopeblind.com/api/coordination \
  --authority-key PINNED_64_HEX_AUTHORITY_KEY
```

Use `--client codex` or `--client json` for those registration instructions.
Setup prints configuration; apply it in your client, then reopen that client.
The private profile holds an agent key and separately scoped connections, with
file permissions `600`. Setup grants no task permissions and copies no human
browser key. The registered server runs `coordination agent --profile FILE`.

Ask your agent to prepare a shared invoice task for your review. The tool flow is:

1. `coordination.prepare_task({request_id, draft})` saves an unsigned draft and
   returns a private review link for you. Keep the same `request_id`
   when retrying. The draft contains a title, goal, and optional proposed limits,
   assumptions, and private preferences. It creates no room or human authority.
2. Review the draft in the browser, edit it, and sign your own limits. Invite
   the other person, who signs their own limits independently. Separately
   authorize your agent’s negotiation connection. Review links expire after
   30 minutes; possession does not give the agent payment or approval powers.
3. `coordination.inspect_task_request({request_id})` checks that review.
   `coordination.claim_task_connection({request_id})` claims the exact authorized
   grant and returns a `connection_id`. Then call
   `coordination.inspect_negotiation({connection_id})` before proposing or testing.
4. Both humans approve one exact tested plan. The original organizer creates
   the separate task and may explicitly authorize the same agent to execute it.
   `coordination.check_handoffs({connection_id})` discovers that authorization;
   `coordination.claim_execution_connection({connection_id, handoff_id})` saves
   a **new execution connection**. Inspect its returned `connection_id` before
   submitting payments. The negotiation token never becomes a payment token.

Every scoped tool in the profile requires an explicit `connection_id`; use
`coordination.connections` to list saved connections without credentials. The
profile preserves tokens before claiming so an uncertain reply can be recovered
with the same IDs. Initial pairing windows last at most ten minutes. If that
window or a grant expires, the original person must explicitly reconnect the
same profile under current limits. Missing profiles require fresh authorization.
A profile holds at most 50 requests and 50 connections; keep it private.

Existing one-room connections below still work. Import one with
`coordination agent import --profile FILE --config OLD_PRIVATE_CONFIG` after
setting up the profile. Import preserves its scope and cannot reconstruct a
private agent key discarded by older pairing; that connection cannot claim a
same-key execution handoff.

Draft text and private instructions are sent to ScopeBlind. Your agent’s model
provider may receive tool results, including your own authorized private brief.
A hosted assistant receives its own principal’s brief plus shared records.
Neither profile setup nor a stopped client runs a background agent or model.

### Make exact decisions on another device

From a task on the original authorized browser, choose **Continue on another
device**. Open or scan its link on your phone, request access, and compare the
shown code on both devices. The original browser signs the exact phone key,
room, permissions, and expiry. A link or QR code alone grants no authority;
each device retains its own private signing key.

Access lasts no longer than seven days or the task’s expiry. Depending on the
chosen scope and the person’s existing role, the phone can inspect the task,
approve or deny an exact payment, accept or request changes to its exact result,
and sign its own negotiation mandate or exact tested-plan decision. It cannot
create tasks, invite people or agents, start a hosted model, adopt rules, execute
payments, or delegate to another device. Future agreement and reviewer-role
signatures are allowed only within that exact jointly reviewed proposal. They
do not carry phone access into the new task.

The original browser or the linked device can revoke that device’s access.
Revocation blocks new actions; it does not erase valid earlier decisions.
Evidence preserves the actual device signer, the original principal’s signed
authorization, and the service’s signed authorization-use receipt. Portable
negotiation, result, and rehearsal verification checks the required lineage.
These signatures identify keys, not verified real-world identities.

[Your decisions](https://scopeblind.com/standard?trial=new&view=inbox) reads
current work authenticated by this device. Opening an item checks the current
request again; expired or superseded decisions cannot authorize a changed
payment or result. Optional browser reminders contain no task details or
credentials, open this inbox, and never approve work or wake an external agent.
Delivery depends on the browser, operating system, and host configuration. On
iPhone or iPad, add ScopeBlind to the Home Screen, link that app’s device key,
and enable reminders there. Reminders can be turned off without changing task
permissions.

### Connect your agent to a shared invoice room

`protect-mcp` version `0.25.0` connects your installed agent to the same admission and
sample-ledger service as the shared room. Start a room at
[ScopeBlind](https://scopeblind.com/standard?trial=new), then choose **Use your
own agent → Create pairing code**. It is a fictional invoice sandbox; no real
money moves.

The release is distributed as a versioned package from scopeblind.com. Its
[SHA-256 checksum](https://scopeblind.com/releases/protect-mcp-0.20.0.tgz.sha256)
is published alongside it. Run the room's command in your terminal. For a single connection:

```bash
npx --yes protect-mcp@0.25.0 coordination pair
```

Paste the private code when prompted. It is never a command-line argument or
URL parameter. The command generates an independent agent key and credential,
saves pending state before claiming, verifies the owner authorization and pinned
service acknowledgment, then stores the completed connection in
`~/.scopeblind/coordination.json` with permissions `600`. The pairing code lasts
at most ten minutes; the resulting connection lasts at most 24 hours. The owner
can revoke it in the room. If a response is lost, rerun the same command with
the same config file to recover the same enrollment.

For multiple rooms, use the room-specific `--config` path shown in the browser.
An existing config is never replaced with a different room's credential.

Successful pairing prints the Claude Code registration command directly. To
print it again:

```bash
npx --yes protect-mcp@0.25.0 coordination setup --client claude-code
```

Run the command it prints in the project where you use Claude Code. It registers
an MCP server in local scope, with the private config's path and no credential
in the command or client settings. Restart Claude Code and check `/mcp`, then ask:

> Inspect the ScopeBlind invoice room and its purchase orders. Complete the
> permitted work under the agreed limits. Request exact approval where needed;
> keep working on other invoices, then use coordination.wait for decisions. Deliver the completed result
> for the recipient to review.

`setup --client json` prints standard `mcpServers` configuration for manual use
with other clients. Use `setup --client codex` for Codex CLI registration. These commands print
configuration and do not edit your client settings. For Claude Code, see its
[official MCP documentation](https://code.claude.com/docs/en/mcp).

The MCP tools are:

- `coordination.inspect`: inspect the owner-signed agreement, invoices, purchase
  orders, budget, current and historical operations, and revision instructions.
- `ledger.pay`: submit exact `operation_id`, `invoice_id`, `amount_minor`, `currency`
  (`USD`), and `destination`. Live rooms also require the `fixture_revision` from
  inspect. The adapter verifies the signed admission before execution and the
  signed outcome afterward.
- `coordination.wait`: pass the event `cursor` from inspect as `after_cursor`.
  The tool waits up to 30 seconds and checks for changes every two seconds,
  without calling the model between checks. It returns `changed` or `waiting`,
  the current run/cursor, and what needs attention. On a timeout an active
  session can wait again; resumption depends on the MCP client. This tool sends no push notifications; optional browser inbox reminders
  are separate. Cancellation and disconnect stop an active wait.
- `coordination.deliver`: provide the inspected `run_id` and freeze the result once all work has a recorded
  disposition. The service refuses unresolved work. The recipient separately
  accepts the exact result or requests a revision.

Retain the same operation ID across retries and restarts. A changed payload
under that ID is refused. After a reviewer approves held work, retry the same
operation unchanged. The agent cannot approve its own request, change rules,
create a revision, invite people, or accept its own result. Owner-authorized
revisions retain the cumulative budget and duplicate-invoice protection.

An unknown execution outcome keeps its reservation. A repeated confirmed
operation returns the original signed result; it does not pay twice. Revoking
an agent stops future admissions and uncommitted effects, including a request
that raced with revocation. It does not undo confirmed payments.

For custom service operators, the original explicit connection remains:

```bash
npx --yes protect-mcp@0.25.0 coordination \
  --endpoint https://YOUR-HOST/api/coordination \
  --room ROOM_ID \
  --authority-key PINNED_64_HEX_AUTHORITY_KEY \
  --token-env PROTECT_MCP_COORDINATION_TOKEN
```

The named environment variable contains the executor credential. HTTPS is
required except for loopback local testing. Redirects are refused. Credentials
are never printed. The configured service receives the sample requests; your
agent's model provider may receive records returned by the tools. The adapter
covers this sample-ledger path and does not govern other tools in your client.

### Let an agent test the rules

In **Test these rules**, choose **Let your agent test the rules** to create a
separate, explicitly scoped test connection. Use its room-specific command and
private code, then run the printed Claude Code registration command. Version
`0.20.0` recognizes these version-2 pairing codes; old execution grants remain
unchanged and do not gain test permissions. Use separate config files for an
execution connection and a test connection. Setup registers a test connection as
`scopeblind-test`, so it does not overwrite the `scopeblind` execution connection.

Ask your agent:

> Inspect this rehearsal. I want a person to review invoices above $400.
> Add that expectation for Fieldwork, propose the threshold change, and compare
> the actual gate before and after. Explain which useful work still succeeds and
> whether all required safety cases pass. Leave adoption to me.

A test connection exposes only these four tools:

- `coordination.inspect_rehearsal`: read the signed source agreement, records,
  cases, proposals, and reports. Supply `report_digest` to retrieve an exact
  historical evidence snapshot and verify it.
- `coordination.propose_case`: add a case with a stable `id`, invoice, expectation,
  and requirement. Fixed safety cases cannot be replaced or marked optional.
- `coordination.propose_repair`: propose a review threshold and rationale bound
  to the source agreement, fixture snapshot, and cases. Other terms cannot change.
- `coordination.run_rehearsal`: supply a stable test `id` and optional `proposal_id`
  to run the real gate in separate sample ledgers. The tool continues up to six
  durable chunks within three minutes; unfinished work returns `pending` with
  instructions to resume the same ID. Cancellation stops further client requests
  and completed chunks remain available. If the response is lost or
  times out, inspect the reports and retry the same test ID to recover its result.

The test agent cannot pay in the source room, approve exceptions, invite another
agent, or activate a repair. The owner separately decides whether a passing
comparison should become a **new sample task**. That new task has its own ledger;
source agreements, budgets, payments, and results remain unchanged. Revocation
blocks future requests and the final publication of a test still in flight.

Reports describe the observed gate behavior for concrete cases. A valid signature
identifies the named gate operator and protects the exact record from alteration;
it does not prove all possible inputs or independently observe the operator.
The installed adapter verifies the report and snapshot bindings before returning
comparison evidence. Offline applications can check an exported bundle with:

```js
import { verifyRehearsalEvidence } from 'protect-mcp';
const result = await verifyRehearsalEvidence(bundle, expectedAuthorityPublicKey);
if (!result.valid) throw new Error(result.errors.join('; '));
console.log(result.checks, result.limitations);
```

Pin the authority key independently; omitting it checks against the key named in
the owner-signed source agreement. A verified report is evidence for a human
adoption decision, not permission to execute a payment.

### Local Action Dashboard

`protect-mcp dashboard` is the operator view for moving from visibility to
enforcement:

- **Tool inventory:** every observed tool, call count, high/medium/low risk, and
  whether the active policy has an exact rule, a wildcard fallback, or no rule.
- **Policy coverage:** one-click local policy edits for `Require approval`,
  `Block`, or `Observe`. Restart the wrapper after reviewing changes.
- **Exact-action approval queue:** the exact tool, action, destination, redacted
  payload preview, payload hash, policy basis, and reason capture before a human
  approves, denies, edits, or takes over.
- **Receipt chain:** request ids correlated with signed receipt hashes, so an
  audit reviewer can see which decisions have cryptographic proof.
- **Audit export:** downloads the offline-verifiable audit bundle when signed
  receipts exist. If only unsigned local logs exist, the dashboard explains that
  signing must be enabled first.

For live desktop fallback approvals, start the dashboard with the local gateway
approval endpoint and nonce printed by the wrapper:

```bash
npx protect-mcp dashboard --open \
  --approval-endpoint http://127.0.0.1:9876 \
  --approval-nonce "$PROTECT_MCP_APPROVAL_NONCE"
```

`Approve` forwards to the live local gateway when those flags are present.
`Deny`, `Edit`, and `Take over` are recorded locally as approval-resolution
records; use them as the operator instruction and rerun the tool when needed.

### Paid Boundary MVP: digest anchoring, not data upload

Local self-signed receipts stay free and offline-verifiable. The paid boundary is
independent evidence that ScopeBlind saw a receipt digest at a time, under an org
identity, without receiving the raw prompt, tool payload, output, private key, or
raw receipt.

```bash
# Create or refresh a local org identity and public-key directory.
npx protect-mcp registry init --org "Meridian Global Macro" --billing-account acct_meridian

# Local preview: writes a digest registry and shareable static verifier page.
npx protect-mcp registry anchor

# Hosted mode: uploads receipt digests only for independent anchoring.
SCOPEBLIND_TOKEN=... npx protect-mcp registry anchor \
  --hosted \
  --endpoint https://api.scopeblind.com \
  --verifier-base https://scopeblind.com
```

The local preview is deliberately labeled `local-preview-not-independent`.
Hosted mode anchors only receipt hashes, request ids, org public keys, and
billing metadata. It does not upload raw receipts or sensitive context.

### Killer Demo: shadow to policy to proof

`protect-mcp killer-demo` generates a complete three-minute sales/demo pack:

```bash
npx protect-mcp killer-demo --dir ./scopeblind-demo
```

It creates mock filesystem, GitHub, email, and PMS activity; shows risky calls in
shadow mode; applies a policy pack; requires approval for a sensitive PMS booking;
executes through the gateway; writes a signed receipt; proves the original
receipt verifies; proves a tampered receipt fails; and creates a selective
disclosure package that hides sensitive context while showing the minimum proof.

Open the generated `DEMO-RUNBOOK.md` first. Then run the printed dashboard
command to walk a customer through the exact sequence.

### Selective Disclosure v0

Commitment-mode receipts can carry a `committed_fields_root` instead of exposing
every field in cleartext. Later, the holder can disclose selected fields only:

```bash
npx protect-mcp verify-disclosure \
  --receipt ./receipts/selective-disclosure.receipt.json \
  --disclosure ./receipts/selective-disclosure.tool-only.json
```

The verifier checks the parent receipt hash, Ed25519 signature, commitment root,
and each disclosed field's Merkle proof. It then explains which fields were
disclosed and which committed fields remain hidden. This is salted commitment
disclosure, not full zero-knowledge, but it makes the privacy claim concrete:
auditors can verify selected facts without receiving the full tool payload or
sensitive desk context.

### Prove a claim over the record (position-blind attestations)

You can prove a CLAIM over your record without revealing it. Mint a signed,
position-blind attestation over the whole record that discloses only per-decision
categories (a receipt digest, the verdict, capability tags), never your tool
inputs, outputs, or data:

```bash
# "No action reached the network across the record":
npx protect-mcp claim --no net.egress

# other predicates:
#   --only fs.read,fs.write     all actions were confined to these capabilities
#   --no-verdict blocked        no action was blocked
#   --count blocked             how many were blocked
```

Anyone verifies it offline, seeing only the categories, never the content:

```bash
npx protect-mcp verify-claim claim-<id>.json
```

The verifier recomputes a Merkle root over the disclosed set and recomputes the
predicate independently, so the issuer cannot lie about the claim given the
disclosure. Add `--anchor` to record the claim's digest in the public,
append-only ScopeBlind transparency log, so a counterparty who does not trust you
can confirm the disclosed set is complete and was not quietly re-cut (only the
hash is sent; the record stays local):

```bash
npx protect-mcp claim --no net.egress --anchor
```

This is an accountable, position-blind attestation, not full zero-knowledge: it
reveals the shape, not the content.

## Try it in 60 seconds (no agent required)

[![Watch the two-minute demo film](https://scopeblind.com/media/scopeblind-demo-poster.jpg)](https://scopeblind.com/film)

Watch the two-minute film at [scopeblind.com/film](https://scopeblind.com/film), then replay it against your own copy:

```bash
npx protect-mcp sample     # seed a labeled sample record (8 decisions: 1 blocked, 2 payments)
npx protect-mcp record     # open it: signatures verified in your browser

npx protect-mcp claim --payment-under 100 --anchor --output payments-under-100.json
npx protect-mcp verify-claim payments-under-100.json
npx protect-mcp anchor-record
```

Drop the generated `demo-tampered.jsonl` into the record page to watch a
post-signing edit get caught. `sample` refuses to touch an existing record, so
run it in an empty folder. When you are ready for the real thing, wire the gate
below and the same commands run against your agent's own record.

## Claude Code hook quickstart

```bash
# Generate hook config and a sample Cedar policy.
npx protect-mcp init-hooks

# Serve the Claude Code hook gate in enforce mode. It runs a restraint self-test
# first and refuses to start if it cannot prove it denies a forbidden vector.
npx protect-mcp serve --enforce --cedar ./cedar
```

One-shot evaluation, the way a PreToolUse hook calls it. Exit code 2 means deny
(the tool is blocked); exit 0 means allow:

```bash
npx protect-mcp evaluate --cedar ./cedar --tool Bash --input '{"command":"rm"}'
echo $?   # 2  -> denied, fail-closed

npx protect-mcp evaluate --cedar ./cedar --tool Read --input '{"path":"README.md"}'
echo $?   # 0  -> allowed
```

A missing or unloadable policy denies (exit 2) unless you explicitly pass
`--fail-on-missing-policy false`.

## Claude Code hooks

`protect-mcp init-hooks` writes a `.claude/settings.json` for you. To wire the
gate by hand, the two verbs you need are `evaluate` (PreToolUse, blocks on exit 2)
and `sign` (PostToolUse, records a receipt). Claude Code hands a hook the call
as JSON on stdin and sets no `TOOL_NAME` or `TOOL_INPUT` variables, so pass
`--format claude` and nothing else about the call: the gate reads `tool_name`
and `tool_input` from the payload, and on a deny it returns the reason to the
model as `hookSpecificOutput.permissionDecisionReason` as well as exit 2. Pin
the version so a Claude Code session always runs the gate you tested:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "npx protect-mcp@0.25.0 evaluate --cedar ./cedar --format claude"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "npx protect-mcp@0.25.0 sign --format claude --receipts ./receipts --key ./keys/gateway.json"
          }
        ]
      }
    ]
  }
}
```

### Put a signed standard in force, and let the record land on its page

From 0.14.0 the gateway can hold the signed standard itself (the `standard.json`
written and signed on [scopeblind.com/write](https://scopeblind.com/write)) next
to the Cedar policy compiled from it, and report to the standard's own page:

```bash
# Initialize the signing key once, unless this directory already has one.
npx protect-mcp@0.25.0 init
npx protect-mcp@0.25.0 --enforce --cedar ./policy --standard ./standard.json \
  --report 'https://scopeblind.com/api/standard?s=<standard id>' \
  -- <your MCP server command>
```

With `--standard`, three of the standard's terms are enforced from the standard
rather than inferred: a call to a tool the standard does not name is refused
(`standard_tool_not_allowed`); a call whose amount is over the per-instruction
limit, or in another currency, is refused before it runs
(`standard_amount_over_limit`, `standard_currency_not_permitted`); and a call
whose amount is above the approval threshold is **held** for the named person
(`standard_requires_person`). Amounts are read from the call's `amount_minor`
(integer minor units) or `amount` (major units) and `currency` fields; a call
that carries no amount is not a payment and is not held.

A held call is answered to the model as a tool result, never an error, so the
conversation continues: `REQUIRES_APPROVAL: ... waiting for the named person at
https://scopeblind.com/standard?s=<id>#held-<hid>`. The person opens that page
and approves or denies the exact action, signed in the browser with the key the
standard accepts. When the model retries the same call (the same payload hash),
the gate finds the decision: an approval lets the call through with the decision
in the receipt (`approval: { hid, approver_key_id, digest, page }`); a denial
refuses it (`person_denied`). A changed call is a new action.

With `--report`, every receipt is appended to the local chain first and posted
to the page after, in order, best-effort: the page never blocks a call, and a
page that cannot be reached is logged, not fatal. The token comes from the Sign
tab on the Write page, shown once; set it in the process environment as
`PROTECT_MCP_REPORT_TOKEN`. `--run <id>` names the run on the page (default: a
timestamp). Receipts carry `standard: { request_id, digest }` so a reader can
tell which standard was in force.

The hook server takes the same four flags, so a coding agent's calls through
Claude Code hooks land on the page and are held under the standard the same way:

```bash
npx protect-mcp@0.25.0 serve --enforce --cedar ./policy --standard ./standard.json \
  --report 'https://scopeblind.com/api/standard?s=<standard id>'
```

A hold on the hook path is returned as a deny whose reason names the page; the
agent retries the same call after the person has decided there.

The gateway now also passes the call's input to Cedar as `context.input`, so a
policy compiled from a standard's amount limit is evaluated at the gate exactly
as `sign --cedar` and the hook server evaluate it.

### Sign the policy decision itself

From 0.13.0, `sign` can evaluate the policy and record the real decision in the
receipt instead of an unconditional allow. Pass the policy directory and the
same input and context the hook would pass to `evaluate`:

```bash
npx protect-mcp@0.25.0 sign --cedar ./cedar --tool Bash \
  --input '{"command":"rm -rf /"}' --context '{"command_pattern":"rm -rf"}' \
  --receipts ./receipts --key ./keys/gateway.json
```

Without `--receipts`, the receipt joins the gateway's own log (`.protect-mcp-receipts.jsonl` in `--dir`), so a deployment has one chain and `record` shows every decision; `--receipts <dir>` keeps a separate `receipts.jsonl`.

The receipt payload then carries `decision` (allow or deny), `reason`
(`cedar_allow` or `cedar_deny`), and `policy_digest` (the acta-policy-digest-v1
digest of the policy set), and cites draft-farley-acta-signed-receipts-03. The
command prints the decision and digest on stdout. A deny is still signed: the
receipt is the record of the decision, not permission to proceed.

Two Cedar action models are supported. The runtime gate evaluates
`Action::"MCP::Tool::call"` with the tool as the resource, which is what the
policies in `cedar/` expect and what `sign --cedar` uses by default. Policies
that name the tool as the action (`action == Action::"Bash"`), such as the
published conformance policy in agent-governance-testvectors, need
`--action-model tool`. `evaluate` accepts the same flag.

`evaluate` exits 2 on deny so Claude Code blocks the tool call, and 0 on allow.
`sign` is best-effort: it appends an Ed25519-signed receipt when a key is
configured, and if no signer is available it records an honest unsigned line
(`"signed": false`) rather than failing the tool.

## Use it in other agents (Codex, Cursor, Gemini, Hermes)

The same fail-closed gate runs as a tool hook in any agent that supports them. Add
`--format <host>` so the verb reads that host's hook payload from stdin and denies
in its contract:

```bash
# the PreToolUse / before-tool command for each host
npx -y protect-mcp@0.25.0 evaluate --format codex  --cedar ./cedar   # OpenAI Codex
npx -y protect-mcp@0.25.0 evaluate --format gemini --cedar ./cedar   # Gemini CLI BeforeTool
npx -y protect-mcp@0.25.0 evaluate --format cursor --cedar ./cedar   # Cursor beforeShellExecution
npx -y protect-mcp@0.25.0 evaluate --format hermes --cedar ./cedar   # Hermes pre_tool_call
```

Pair each with `sign --format <host>` on the post-tool event for receipts. The
important case is **Hermes**, which ignores hook exit codes and reads the verdict
from stdout, so `--format hermes` denies via `{"decision":"block"}` rather than
exit 2 (a raw exit-2 would silently fail open there). Without `--format`, the
verbs read `--tool`/`--input` flags exactly as in the Claude Code section above.

## Write a policy

Cedar policies live in a directory you point at with `--cedar`. A `forbid` rule
denies, a `permit` rule allows. To match against a value in the tool input, use
the `.contains()` idiom:

```cedar
// Allow read-only tools.
permit(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"Read"
);

// Deny dangerous shell commands by matching the command against a list.
forbid(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"Bash"
) when {
  ["rm", "dd", "mkfs"].contains(context.command)
};

// Block destructive tools outright.
forbid(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"delete_file"
);
```

> **Hazard:** do NOT write `context.command in ["rm", "dd"]` to match a string
> against a list. `in` is for entity hierarchies, not string membership. Cedar
> treats the expression as a type error and silently discards the whole `forbid`
> rule, which (under a fail-open gate) leaves a residual `permit` standing. This
> is the exact defect behind the advisory below. Use `[...].contains(context.command)`
> instead. From 0.7.0 the gate denies on that error rather than permitting, and a
> CI tripwire test fails the build if the pattern is reintroduced into a shipped
> policy. See [GHSA-hm46-7j72-rpv9](https://github.com/ScopeBlind/scopeblind-gateway/security/advisories/GHSA-hm46-7j72-rpv9).

### Starter policy packs

Most teams should not write Cedar from scratch on day one. Install a starter
pack, run in shadow mode, inspect receipts, then tighten or enforce:

```bash
npx protect-mcp policy-packs list
npx protect-mcp policy-packs show secrets-safe
npx protect-mcp policy-packs install filesystem-safe --dir ./cedar
npx protect-mcp policy-packs install all --dir ./cedar
npx protect-mcp serve --cedar ./cedar
```

Built-in packs:

- `filesystem-safe`: destructive file actions and secret-like path reads.
- `git-safe`: force pushes, hard resets, destructive cleanup, repo deletion.
- `email-safe`: allow drafting, block unattended sends.
- `database-safe`: read-oriented DB posture, block write/admin SQL.
- `cloud-spend-safe`: obvious cloud spend creation and infrastructure destruction.
- `secrets-safe`: common file, env, shell, and cloud secret exfiltration.
- `finance-mandate-safe`: restricted-list and concentration breaches in booking flows.

## Credentials the agent never holds

The gateway can hold a secret and inject it at dispatch, so the agent works with a label and never sees the value. Configure the vault in `protect-mcp.json`; the value is read from the named environment variable of the gateway process, not the agent's:

```json
{
  "credentials": {
    "github_token": { "inject": "header", "name": "Authorization", "value_env": "GITHUB_TOKEN" },
    "warehouse":    { "inject": "env",    "name": "PGPASSWORD",    "value_env": "WAREHOUSE_PASSWORD" }
  }
}
```

`inject: "env"` puts the value in the wrapped server's environment; `inject: "header"` and `"query"` attach it to the outbound call. A tool whose name matches a label is resolved on every call; if the secret is missing the call is refused with `credential_error` rather than sent without it. Each receipt for such a call carries `credential_ref` with the label, never the value, so a reader can see that the credential the standard names was used through the gateway. What the receipts cannot show is that the agent had no other copy of the secret; that is a property of the deployment.

A ScopeBlind standard states this as `requirements.credentials_held_by_gate`, and the gateway receipt report on scopeblind.com/verify checks the label on every receipt for the tool.

## Verify a receipt

Receipts are signed and verifiable offline by anyone with the public key. No
network, no vendor, no trust in ScopeBlind:

```bash
npx @veritasacta/verify ./receipts/receipts.jsonl --format jsonl
# Exit 0 = valid, non-zero = tampered or malformed
```

`npx protect-mcp bundle --output audit.json` exports a self-contained,
offline-verifiable audit bundle of your receipts plus the public signing key.

## Security

`protect-mcp` 0.7.0 fails closed by design. On any policy-evaluation error, a
missing engine, or a policy that errored at evaluation, the decision is DENY,
not allow. `serve --enforce` and `doctor` run a boot self-test that proves the
gate denies a known-forbidden vector before it is trusted, and refuse to arm if
it cannot.

**Affected versions: 0.5.x and 0.6.x.** Those lines fail open (they return ALLOW
on evaluation error) and do not evaluate Cedar correctly against the pinned
engine, so a `forbid` rule could fail to block. **Upgrade to >= 0.7.0.**

Details and remediation: [GHSA-hm46-7j72-rpv9](https://github.com/ScopeBlind/scopeblind-gateway/security/advisories/GHSA-hm46-7j72-rpv9).
To report a vulnerability, see [SECURITY.md](./SECURITY.md).

## Commands

| Command | Description |
|---------|-------------|
| `serve` | Start the HTTP hook server for Claude Code (port 9377). `--enforce` runs the restraint self-test first; `--cedar <dir>` and `--policy <path>` select the policy. |
| `init` | Generate an Ed25519 keypair (`keys/gateway.json`), a config template, and a sample policy. |
| `sample` | Seed a clearly-labeled sample record (8 decisions: one blocked call, two payments; kid `sample-demo`) plus a tampered copy, so `record`, `claim`, `verify-claim`, and `anchor-record` are replayable from scratch before wiring an agent. Refuses to touch an existing record; `--force` overrides. |
| `policy` | See and change the Cedar policy from the terminal: `policy list` (permit / forbid / default-deny per tool, with how often the gate allowed or denied it), `policy show`, `policy allow <tool>`, `policy deny <tool>`, `policy path`. A running `serve` hot-reloads on the change. |
| `wrap` | Print a protected MCP command or patch Claude Desktop MCP servers. Dry-run by default; use `--write` to update Claude Desktop config. |
| `dashboard` | Start a local-only dashboard on `127.0.0.1` showing tool inventory, risk, policy coverage, exact-action approvals, receipt chains, and audit export. |
| `recommend` | Draft a reviewable JSON policy from observed local calls. Dry-run by default; use `--write` to create `protect-mcp.recommended.json`. |
| `registry` | Create an org identity, anchor receipt digests, and write a static verifier page. Hosted mode uploads digests only. |
| `record` | Open a local, searchable viewer over your receipts (`--live` streams as the agent runs): Ed25519 signatures verified in your browser against your gateway key, capability tags, a provenance tree, and one-click signed export. All local, nothing uploaded. |
| `claim` | Mint a signed, position-blind attestation of a predicate over the record (`--no <cap>` incl. `--no payment`, `--only <c1,c2>`, `--no-verdict <verdict>`, `--count <verdict>`, `--payment-under <cap>`), disclosing only decision categories. Add `--anchor` to record the claim digest in the public transparency log; enrolled keys anchor as a named org. |
| `anchor-record` | Checkpoint the record's Merkle root + count + time range into the public log (heartbeat-friendly: skips when unchanged). A later claim whose commitment matches an anchored checkpoint is provably over the complete record as of that checkpoint. |
| `verify-claim` | Verify a claim pack offline: signature, recomputed Merkle root, independently recomputed predicate, and the anchor sidecar when present (binds the anchored envelope to this exact claim, then confirms the public log holds it). `--check-anchor` requires the anchor; `--offline` skips the log hop. |
| `killer-demo` | Generate a complete shadow-mode to policy to approval to signed-receipt demo pack. |
| `verify-disclosure` | Verify a `scopeblind.selective_disclosure.v0` package and explain disclosed versus hidden fields. |
| `policy-packs` | List, inspect, and install starter Cedar policy packs. |
| `evaluate` | Evaluate one tool call against a Cedar policy (PreToolUse gate). Exit 2 = deny (fail-closed), exit 0 = allow. |
| `sign` | Sign one tool call into a receipt (PostToolUse). Best-effort: records an honest unsigned line if no key. |
| `simulate` | Dry-run a policy against a recorded decision log to see what it would have blocked. |
| `demo` | Start a built-in demo server wrapped with the gate, to see receipts instantly. |
| `doctor` | Check your setup (keys, policies, Cedar engine, verifier) and run the restraint self-test. |
| `bundle` | Export an offline-verifiable audit bundle of receipts plus the public key. |
| `report` | Generate a compliance report (Markdown or JSON) from the decision log and receipts. |

Run `npx protect-mcp --help` for the full flag reference.

## Links

- Protocol (IETF): [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
- [CHANGELOG](./CHANGELOG.md)
- [npm](https://www.npmjs.com/package/protect-mcp)
- [scopeblind.com](https://scopeblind.com)

MIT licensed. Built by [ScopeBlind](https://scopeblind.com).


### Let your agent negotiate for you

Version `0.25.0` supports the two-person agreement at
[ScopeBlind](https://scopeblind.com/standard?trial=new&view=negotiate). Each person
signs their own mandate and creates their own version-3 pairing code. The private
configuration binds one principal and discussion; it does not inherit payment
or reviewer powers. Existing version-1 and version-2 connections retain their scopes.

Ask your agent:

> Inspect my negotiation mandate and private brief. Seek a review threshold that
> satisfies both shared mandates and their invoice requirements. Propose, compare,
> and respond using only the negotiation tools. Leave approval of the exact plan
> to both people.

Tools: `coordination.inspect_negotiation`, `coordination.propose_candidate`,
`coordination.respond_candidate`, `coordination.compare_candidate`, and
`coordination.wait_negotiation`. Waiting polls only the scoped discussion and is
cancelable, bounded to 30 seconds. Each agent can read its own principal's private
brief, never the other person's brief. ScopeBlind stores the briefs; your model
provider may receive your own agent's tool results. Shared exports omit the briefs.

The discussion can change the invoice review threshold, with at most three
candidates. Both people sign the exact proposal, gate report, future agreement,
and reviewer enrollment before the organizer creates a separate trial. Agent
recommendations cannot substitute for those approvals. The browser verifier
checks the shared history offline, including the principal's independently signed
pairing authorization for contributions made by an installed agent.


### Review a visible repository change together

Open [the contact-button demo](https://scopeblind.com/standard?trial=new&view=repository)
to create an isolated ScopeBlind-owned repository task and invite a second person.
The preview renders checked `demo/contact.json` data with a fixed template; it does
not execute repository code or claim that a public website was deployed. Both
people approve the exact reviewed commits before the trusted receiver applies them.
The recipient can accept the observed result or request a linked fresh revision.

For your own repository, choose **Use your repository** and run the generated
`protect-mcp@0.25.0 repository setup` command locally. It discovers actual check
names/providers, saves a receiver key with owner-only permissions, and prepares a
hash-pinned workflow for your review. The returned `connection.json` contains public
keys and signed discovery evidence. Keep `receiver-key.json` private. Discovery,
an installed matching workflow, and a signed successful Actions readiness run are
shown separately. None grants human approval of a task.

The browser-generated command supplies your public owner key and service authority
pin. Its complete form is below; replace each uppercase placeholder with those
reviewed values and choose a new output directory. Sign in locally with `gh auth login`,
or supply `GITHUB_TOKEN` through your local credential manager. Setup does not save
or print that token.

```sh
npx --yes protect-mcp@0.25.0 repository setup \
  --repository OWNER/REPOSITORY \
  --owner-key YOUR_PUBLIC_OWNER_KEY \
  --authority-key REVIEWED_SERVICE_AUTHORITY_KEY \
  --endpoint https://scopeblind.com/api/coordination \
  --output ./repository-connection
```

To inspect the existing CI checks for a particular open, same-repository pull
request, add `--pull NUMBER`. Review the generated `INSTALL.md` before installing
the workflow or configuring Actions. Import only the public `connection.json`.
To refresh local read-only readiness for this same connection, use a new output file:

```sh
npx --yes protect-mcp@0.25.0 repository ready \
  --connection ./repository-connection/connection-config.json \
  --key-file ./repository-connection/receiver-key.json \
  --output ./repository-readiness.json
```

This local refresh does not establish that the Actions receiver is responding.
For that observation, run the reviewed workflow's `ready` operation and import its
public evidence as described in `INSTALL.md`.

Your reusable agent profile exposes its public key through `coordination.connections`.
Authorize that exact key in the repository task, then ask the agent to call
`coordination.inspect_repository` with the task and grant IDs. The returned repository
connection supports `coordination.request_repository_revision` with an explicit
current basis digest and stable request ID. It can suggest bounded contact-page
data and a reason; it cannot enroll a reviewer, approve a change, or execute the
receiver. Reusing a request ID retries the exact original signed suggestion.

### Recurring client reviews and agent preparation

Create a client project from the repository review page to reuse its repository,
receiver connection and reviewer membership. Each review contains its own brief,
stable success criteria and exact pull-request snapshot. Both people approve that
reviewed version; the recipient can separately accept the observed result.

For recurring preparation, both people can sign a mandate naming one public agent
key, repository, branch, permitted paths, required check providers, expiry and
request limits. Obtain the profile's public key with `coordination.connections`,
then authorize it in the project's **Agent permissions** panel. A connected agent
uses these tools:

| Tool | Purpose |
| --- | --- |
| `coordination.inspect_workspace` | Verify the project and joint mandate; inspect remaining allowance and existing drafts. |
| `coordination.prepare_repository_review` | Submit a signed PR review draft to the project inbox for a person to adopt. |
| `coordination.inspect_repository_review` | Read the assigned task's exact brief, criteria, receiver packet and attributed feedback. |
| `coordination.report_repository_criteria` | Report `met`, `not_met` or `unknown` against each criterion, citing evidence present in the packet. |
| `coordination.request_repository_changes` | Record general revision feedback tied to the exact reviewed version. |

Use the exact `workspace_id` and `mandate_id` shown in the project. After inspection,
the mandate ID becomes this purpose's `connection_id`. Reuse a stable `request_id`
after an interrupted submission; the private profile retains the original signed
intent. New findings against a changed packet require fresh inspection and a new ID.
To prepare a revision from recorded feedback, include the exact `draft.source`
reference returned by the review: task ID and digest, basis digest, packet digest
and feedback digest. The project preserves that reference in the new review's
portable evidence. The new version requires fresh human approvals.

These permissions prepare and review work. They cannot impersonate a person, adopt
the mandate, approve a change, merge a PR or accept a result. ScopeBlind does not
start a hosted model or keep an external agent running. The implementer handles
requested code changes through their existing development tools and permissions.

A receiver's preview record describes GitHub deployment and check metadata for the
observed commit. An external preview URL remains mutable; it is not an immutable
artifact or proof of the bytes subsequently served. Criterion findings are attributed
agent recommendations, including explicit unknowns, for the human decision.

Project recovery uses a separately enrolled recovery credential. It rotates that
project member's future authority; it never recreates an old browser private key
or rewrites historical approvals. Start a new review with the current membership
before making further decisions on work assigned to a former key.


### Guided connection and bounded code work

Open [your projects](https://scopeblind.com/standard?trial=new&view=workspace) and connect a repository. The guided route identifies the selected repository and pull request, then supplies a version-pinned installer command. Paste its short-lived setup link into the prompt rather than a shell argument:

```sh
npx --yes protect-mcp@0.25.0 repository connect --link-stdin --install
```

Review the exact workflow, permissions and receiver key before authorizing installation. Keys are generated locally. A GitHub Actions identity proof and receiver signature establish which installed workflow answered the readiness challenge. Existing manual receiver setup remains available.

Coding work is an optional, separate installation and permission. Both project members sign the allowed paths, fixed tests/build, immutable runtime image, public-preview permission, time, file, token and model-call limits. The worker starts from exact recorded feedback. Its untrusted repository programs run in a Docker container without network access or credentials; the trusted controller checks the resulting files and publishes the admitted new branch, PR and preview. The initial runtime supports small Node 22 static sites with self-contained relative assets and fixed Node test/build scripts.

Automatic job startup requires the GitHub App connection. With an owner-local connection, the queued job shows the exact repository’s `scopeblind-coding.yml` Actions page, branch and job ID. Select **Run workflow** and supply that existing ID as `job_id`; this does not create another job or bypass either person’s permission.

GitHub Actions must be allowed to create pull requests under **Settings → Actions → General → Workflow permissions**. Existing required CI may need **Approve workflows to run** or a configured manual run for the exact new PR head. `GITHUB_TOKEN`-created PRs do not guarantee automatic execution of existing CI; [GitHub documents the current trigger and approval rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow). Every agreed check/provider remains mandatory before review approval or an effect.

The result requires a fresh review. No coding grant authorizes a merge. After a publication was admitted, cancellation cannot undo effects already sent; an uncertain result is reconciled by reading its deterministic branch and PR. Signed evidence distinguishes these observations from proof that the code meets every criterion.

Project members can also authorize a second browser for selected review actions. Both devices confirm the link. This preserves the original membership key and never grants project setup, recovery, agent delegation or execution permissions. Revocation stops new device access and decisions while preserving already recorded signatures.


### Shared managed coding trial

The hosted [real AI revision trial](https://scopeblind.com/standard?trial=new&view=repository&coding_trial=new) uses a disposable ScopeBlind-owned repository. Two browser identities agree the work, authorize one bounded coding job, inspect the published preview, approve the exact resulting change and accept the recorded result. It does not require visitor GitHub access. The initial styled starter is deterministic; only the separately authorized revision is model-produced.

The managed controller is shipped as `dist/repository-trial-cli.js`. It is not a general-purpose hosted repository credential or a way to bypass a project's own receiver. Its reviewed workflow pins the repository, template, service authority and worker identities. Recovery observations describe current provider state; they are not approvals, merge receipts, or code-correctness guarantees.
