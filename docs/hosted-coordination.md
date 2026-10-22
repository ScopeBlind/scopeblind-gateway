# Hosted coordination and repository workflows

[Back to the local gateway](../README.md)

These optional adapters connect to ScopeBlind’s hosted service. They are separate
from local policy evaluation and receipt verification. The service receives the
requests described in each workflow; your agent’s provider may receive tool
results. A hosted feature’s availability is separate from the open-source package.

### Start with your agent, then authorize each task

Version `0.25.0` includes a reusable agent profile. Open
[Start through your agent](https://scopeblind.com/standard?trial=new&view=agent)
for the setup command with the service’s displayed authority key. Check that key
against a trusted source before connecting. For example:

```bash
npx --yes protect-mcp@0.31.1 coordination agent setup \
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

Install a pinned package from npm. See the [release process](releases.md) for
validation and provenance details. Run the room’s command in your terminal.
For a single connection:

```bash
npx --yes protect-mcp@0.31.1 coordination pair
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
npx --yes protect-mcp@0.31.1 coordination setup --client claude-code
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
npx --yes protect-mcp@0.31.1 coordination \
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
### Put a signed standard in force, and let the record land on its page

From 0.14.0 the gateway can hold the signed standard itself (the `standard.json`
written and signed on [scopeblind.com/write](https://scopeblind.com/write)) next
to the Cedar policy compiled from it, and report to the standard's own page:

```bash
# Initialize the signing key once, unless this directory already has one.
npx protect-mcp@0.31.1 init
npx protect-mcp@0.31.1 --enforce --cedar ./policy --standard ./standard.json \
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
npx protect-mcp@0.31.1 serve --enforce --cedar ./policy --standard ./standard.json \
  --report 'https://scopeblind.com/api/standard?s=<standard id>'
```

A hold on the hook path is returned as a deny whose reason names the page; the
agent retries the same call after the person has decided there.

The gateway now also passes the call's input to Cedar as `context.input`, so a
policy compiled from a standard's amount limit is evaluated at the gate exactly
as `sign --cedar` and the hook server evaluate it.
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
`protect-mcp@0.31.1 repository setup` command locally. It discovers actual check
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
npx --yes protect-mcp@0.31.1 repository setup \
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
npx --yes protect-mcp@0.31.1 repository ready \
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
npx --yes protect-mcp@0.31.1 repository connect --link-stdin --install
```

Review the exact workflow, permissions and receiver key before authorizing installation. Keys are generated locally. A GitHub Actions identity proof and receiver signature establish which installed workflow answered the readiness challenge. Existing manual receiver setup remains available.

Coding work is an optional, separate installation and permission. Both project members sign the allowed paths, fixed tests/build, immutable runtime image, public-preview permission, time, file, token and model-call limits. The worker starts from exact recorded feedback. Its untrusted repository programs run in a Docker container without network access or credentials; the trusted controller checks the resulting files and publishes the admitted new branch, PR and preview. The initial runtime supports small Node 22 static sites with self-contained relative assets and fixed Node test/build scripts.

Automatic job startup requires the GitHub App connection. With an owner-local connection, the queued job shows the exact repository’s `scopeblind-coding.yml` Actions page, branch and job ID. Select **Run workflow** and supply that existing ID as `job_id`; this does not create another job or bypass either person’s permission.

GitHub Actions must be allowed to create pull requests under **Settings → Actions → General → Workflow permissions**. Existing required CI may need **Approve workflows to run** or a configured manual run for the exact new PR head. `GITHUB_TOKEN`-created PRs do not guarantee automatic execution of existing CI; [GitHub documents the current trigger and approval rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow). Every agreed check/provider remains mandatory before review approval or an effect.

The result requires a fresh review. No coding grant authorizes a merge. After a publication was admitted, cancellation cannot undo effects already sent; an uncertain result is reconciled by reading its deterministic branch and PR. Signed evidence distinguishes these observations from proof that the code meets every criterion.

Project members can also authorize a second browser for selected review actions. Both devices confirm the link. This preserves the original membership key and never grants project setup, recovery, agent delegation or execution permissions. Revocation stops new device access and decisions while preserving already recorded signatures.


### Shared managed coding trial

The hosted [real AI revision trial](https://scopeblind.com/standard?trial=new&view=repository&coding_trial=new) uses a disposable ScopeBlind-owned repository. Two browser identities agree the work, authorize one bounded coding job, inspect the published preview, approve the exact resulting change and accept the recorded result. It does not require visitor GitHub access. The initial styled starter is deterministic; only the separately authorized revision is model-produced.

The managed controller is shipped as `dist/repository-trial-cli.js`. It is not a general-purpose hosted repository credential or a way to bypass a project's own receiver. Its reviewed workflow pins the repository, template, service authority and worker identities. If publication succeeds but GitHub readiness confirmation is interrupted, users can check the existing publication without changing it, then explicitly finish that same PR’s readiness while both people’s permission remains current. Neither step reruns the model or replaces the PR. Recovery observations describe current provider state; they are not approvals, merge receipts, or code-correctness guarantees.
