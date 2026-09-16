# Runtime-Enforced Mandate Lifecycle

`protect-mcp mandate` makes a Cedar policy directory a locally governed
runtime boundary. It is intended for a pilot where a policy change must be
reviewable, time-bounded, and provable without sending prompts, positions, or
strategy data to ScopeBlind.

## What changes operationally

Before a directory is managed, `protect-mcp policy allow|deny` can edit Cedar
files for local experimentation. After `protect-mcp mandate init`, that direct
write path is refused. The hook server checks the signed registry before every
tool decision. If the Cedar bytes do not match its signed active head, the gate
denies before evaluating the tool.

The only activation path is:

1. A gate-signed denial receipt under the current policy head.
2. A proposal that binds that denial, the current head, the complete candidate
   Cedar snapshot, an exact executable diff, and an expiry.
3. A distinct registered controller approves that exact proposal.
4. The gate atomically swaps the compiled Cedar directory, signs the new head,
   and records the transition in an append-only local history.
5. Before every later decision, expiry reverts the temporary policy to its
   signed baseline. A failed rollback or any inconsistent state denies.

Every signed `protectmcp:decision` receipt records the registry id, active
policy head, latest transition hash, and any active expiry.

## Bootstrap a pilot

Create a separate controller key for an offline recovery/test ceremony. Do not
reuse the gate key: the command rejects it.

```sh
protect-mcp mandate init \
  --cedar ./cedar \
  --controller-id cro-1 \
  --controller-label "Chief Risk Officer" \
  --controller-public-key "<32-byte-ed25519-public-key-hex>"

protect-mcp serve --enforce --cedar ./cedar
```

The registry and immutable policy snapshots are stored beside the Cedar
directory, not inside it, so a safe policy-directory swap cannot destroy its
audit state.

## Propose, review, approve

Create a candidate Cedar directory rather than editing the managed one, then
propose it against a gate-signed denial receipt:

```sh
protect-mcp mandate propose \
  --cedar ./cedar \
  --candidate ./candidate-cedar \
  --denial-receipt ./blocked-decision.json \
  --reason "Allow this reviewed operational task during the migration window." \
  --expires-at "2026-08-01T17:00:00Z"
```

The command prints the complete added and removed executable statements. It
does not activate anything.

For a registered WebAuthn controller, open the local URL printed by the command
after the hook server is running. The browser page shows the exact policy diff,
originating blocked action, current head, proposed head, and expiry. The passkey
assertion is cryptographically bound to that proposal id; the registry retains
the assertion and verification result for offline checking.

`http://localhost` is a secure context for modern desktop browsers. A phone
approval transport may surface the same assertion protocol after pairing, but a
pilot must not describe remote iPhone approval as live until its paired-device
route has been tested on the customer network.

If the hook server runs on a non-default port, pass the same value as
`--approval-port` to `mandate propose` so it prints the correct controller URL.

For recovery testing only, a direct controller key can create the same signed
approval object:

```sh
protect-mcp mandate approve <proposal-id> \
  --cedar ./cedar \
  --controller-id cro-1 \
  --controller-key ./keys/cro-controller.json
```

## Verify and export

```sh
# Verifies signatures, denial origin, controller separation, policy-head chain,
# current Cedar bytes, and the active expiry state.
protect-mcp mandate verify --cedar ./cedar

# Position-blind policy-change summary plus a full local registry attachment.
protect-mcp mandate export \
  --cedar ./cedar \
  --output ./discipline-policy-changes.json
```

The summary can be bound into a Discipline Record using
`SCOPEBLIND_MANDATE_DISCIPLINE_ATTACHMENT`. It carries policy digests,
transition hashes, controller method, and expiry only. The adjacent registry
attachment is the audit artifact that allows an offline verifier to re-check
the full policy bytes and approval transition chain.

## What this stops, and what it does not (read this before you rely on it)

Be precise about the adversary. This control is strong against **the agent** and
against a **non-gate-key** party who can write the registry file. It is not, and
a purely local control cannot be, tamper-proof against a party who holds the gate
signing key or who can roll the machine's state back across a restart.

**Enforced (verified by the offline verifier and covered by tests):**

- The agent's tool calls run through the gate and cannot edit the registry, mint
  gate signatures, or forge a controller approval.
- The controller SET (ids, keys, and registered passkey credentials) is bound
  into the gate-signed `initialized` transition. Injecting a controller or
  swapping a registered passkey key in the plain registry file is rejected
  (`controller_set_unanchored`) unless the gate key itself signs the change.
- A widening's expiry is bound to the gate-signed activation; stripping or
  extending `active.expires_at` is rejected (`active_expiry_mismatch`).
- A WebAuthn approval's challenge is derived from the exact proposal digest, so
  the biometric consent is a cryptographic statement about *which* policy change
  was approved, not a signature over a bare nonce.
- One signed denial justifies at most one widening (`denial_receipt_reused`).
- A widening may only be proposed from a stable head, not stacked on an already-
  active temporary grant, so no grant's expiry can be lost when a stacked one
  reverts. Let the active grant expire or revert, then widen from baseline.
- A proposal is bound to its registry (`proposal_registry_mismatch`), and the
  gate key may not also be a controller across *either* key type.
- A running gate rejects a registry rolled back or forked to an earlier
  signed-consistent state (`mandate_rollback_detected` / `mandate_history_forked`),
  and a system clock set backward cannot un-expire a live grant.
- An unreadable/corrupt registry fails **closed** (denies), it does not fail open.

**Residual limits that need an external anchor, stated plainly (do not market
these away):**

- A holder of the **gate signing key** can re-sign the whole transition chain,
  including a rewritten controller set. Local files cannot defeat this. The
  answer is an external append-only anchor (a transparency log the manager
  cannot rewrite) and remote controller *enrollment* co-signing, so the party the
  gate governs cannot unilaterally add themselves as a controller.
- **Across a process restart**, both the anti-rollback high-water mark AND the
  monotonic clock floor reset to the current registry / real clock, so durable
  rollback detection and durable backward-clock resistance also need the external
  anchor. Within a running session both hold.
- The **WebAuthn `sign_count`** (authenticator clone-detection) is mutable
  registry data by design (it advances every approval), so a registry writer can
  roll it back and weaken clone-detection. This is a secondary control: the
  primary defence is that each approval's challenge is bound to its proposal
  digest, so a replayed assertion does not authorise a different policy change.
- Because the manager typically runs the gate on their own machine, "the governed
  agent cannot widen its own leash" is true **for the agent**; it is not a claim
  that a malicious *operator* cannot. Market it as the former, and as
  "dual-control widening is verifiable in the evidence layer," not as
  non-bypassable end-to-end.

## Operational notes

- This protects actions routed through the configured gate. It does not prove
  that an unmanaged process never acted outside that deployment surface.
- A local registry is an operational control alongside a customer change-
  management process, source-control review, and OS isolation, not a replacement.
- The full registry may contain policy source and WebAuthn assertion material.
  Treat it as internal audit evidence. The position-blind Discipline Record
  summary intentionally excludes prompts, tool payloads, portfolio data, and
  strategy inputs, and its headline numbers are re-derived from the registry, not
  trusted from the summary.
