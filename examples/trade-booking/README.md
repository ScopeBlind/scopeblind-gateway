# Trade-booking gate: a small synthetic learning example

Starting point for [issue #26](https://github.com/ScopeBlind/scopeblind-gateway/issues/26),
following [Siddhartha's booking flow](https://github.com/finos/ai-governance-framework/pull/412#issuecomment-6407685801)
and [the accepted walkthrough](https://github.com/finos/ai-governance-framework/pull/412#issuecomment-6486006604).
It uses a real Cedar engine and synthetic data. It makes no model calls, books no
trades, and contacts no booking service. The proposals in the demo are handwritten
examples of the structured output a model could produce.

## First run

Use Node **22.22.3** (or newer Node 22 with type stripping) and Python **3.11+**.
From the repository root:

```sh
npm ci
node --experimental-strip-types examples/trade-booking/run.ts --demo
npx vitest run src/trade-booking-example.test.ts
```

The eight demo decisions are allow, deny, allow, deny, allow, deny, deny, allow.
Read each proposal next to the rule that admitted or refused it. No tool is
executed after an allow; `cancel` only reserves an in-memory attempt.

Your first contribution: write a test using **one** `SyntheticGate` instance and
a mutable clock. At 999 ms, `listen` should be allowed. Move to 1000 ms and try
`listen` twice: both should be denied; `lookup` for the original reference should
be allowed. Explain why retrying the proposal must not reset the deadline. Share
the test and explanation on issue #26 for review before extending the policy.
The configured window is illustrative; this example does not prescribe a banking
service's timeout value.

## Run the promised 21 cases

Install the exact upstream wheel; it has no required third-party dependencies.
These are installation-time network operations. Evaluation itself is local.

```sh
python3 -m venv examples/trade-booking/.venv
examples/trade-booking/.venv/bin/python -m pip install --require-hashes --only-binary=:all: --no-deps -r examples/trade-booking/requirements.txt
examples/trade-booking/.venv/bin/python -m unittest discover -s examples/trade-booking -p 'test_*.py'
node --experimental-strip-types examples/trade-booking/run.ts --output examples/trade-booking/report.json
```

Expected: **21 upstream cases / 147 axis checks; 42 Cedar evidence checks;
0 failures**. Pick a new output path on subsequent runs; existing reports are
never overwritten. `TRADE_BOOKING_PYTHON` can name another Python interpreter
containing that exact pinned package. CI runs these checks in
[trade-booking.yml](../../.github/workflows/trade-booking.yml).

The corpus is **saved signed evidence**, not 21 ordered model/tool-call traces.
Each case has seven independent `ESTABLISHED`, `CONTRADICTED`, or
`NOT_ESTABLISHED` answers. Treating each case as a single action allow/deny would
misrepresent it. This harness therefore reports two layers separately:

| Layer | What is evaluated | What the result means |
| --- | --- | --- |
| Upstream reference reader | All 21 cases × seven claims, including signatures, signer roles and booking binding | The original evidence predicates match the pinned expected results |
| Cedar evidence rules | `cancel_confirmed` and `single_compensation`, for every case | Allow means this particular evidence claim is established; it does **not** authorize another cancel |
| Synthetic state tests | Fixed deadline, reference match, cancel reservation, late observation, operations handoff, missing evidence and invalid proposals | The local adapter and Cedar rules behave as specified for those test inputs |

`bridge.py` passes only signed statements to the upstream evaluator and derives
Cedar facts only from statements the evaluator counted. It never uses case names
or expected answers to construct policy input. Expected answers are read only
for comparison after evaluation. The bridge pins the corpus files independently
of its manifest, so changing the corpus and manifest together still fails.

Cedar's boolean evidence decision deliberately merges `CONTRADICTED` and
`NOT_ESTABLISHED` into deny. The report retains the original tri-state answers.
`booking_committed`, `release_backed`, `one_live_booking_per_quote`,
`limit_copy_matches`, and `resolved` remain **upstream-only checks**. A confirmed
cancel can coexist with two compensation events: the first evidence claim is
established while the second is contradicted. Neither proves the cancellation
was authorized or correct.

The corpus has no listening deadline, pre-action sequence, durable attempt count,
or operations-ownership state. Those controls are tested with additional
synthetic state; the 21 cases cannot establish their enforcement. A search miss
alone is also **not** proof of never booked: the upstream reader distinguishes it
from an authoritative reconciliation close. This starter has no release-capacity,
retry-booking, reset, or live-execution permission.

## Where the boundary sits

```text
Model or handwritten proposal: { action, bookingRef }
    -> trusted adapter adds clock, original deadline, observed state and attempt count
    -> Cedar assesses the proposal
    -> adapter reserves a permitted cancel attempt (this demo stops here)

Pinned signed statements -> upstream verifier -> counted facts -> Cedar evidence assessment
```

`policy.cedar` is the policy skeleton. `gate.ts` invokes the installed Cedar WASM
engine and fails closed on evaluation errors. The model cannot submit policy
context through `SyntheticGate.assess`: extra proposal fields are refused. The
`observe` method and `evaluatePolicy` function are trusted internal teaching seams,
not model tools. The synthetic adapter models a session already in timeout recovery;
the lower-level policy also tests a normal booking that needs no cancellation.

Cedar does not keep time, verify booking-system signatures, or remember prior
attempts. A production state adapter would need authenticated, fresh observations
bound to the same booking, a trusted monotonic clock and fixed deadline, durable atomic
reservation across workers/restarts, downstream idempotency and a persisted
operations handoff. The in-memory reservation demonstrates only one process's
behavior. An unknown/error cancel reply leaves the attempt reserved and needs
reconciliation or operations; it does not grant an automatic retry. A late booked
observation inside the window can already justify the one cancellation attempt.

There is no new receipt format or signing scheme here. Upstream's signed synthetic
statements are verified by its own pinned reader. The generated report is an
**unsigned assessment**, not proof of execution. A later gateway integration could
reuse protect-mcp's existing signed decision receipts, with their policy and input
bindings, while keeping evidence of the booking's actual outcome separate.

After the first test, compare `v2_lp_reject_cancel_retried_two_events` with
`v3_ops_reversed_first_agent_skips_cancel` in the report. Explain the difference
between confirmation, a single compensation event, and permission to send a
cancel. Then propose one small policy/test change on the starting issue. Choosing
business intent, matching an ambiguous trade, and resolving contradictory evidence
remain decisions for the model's proposer or an authorized person; the gate does
not infer them from prose.

## Reproducibility and attribution

The fixture and reader are Sankalp Gilda / Probity's
[agent-evidence-vectors 0.28.0](https://pypi.org/project/agent-evidence-vectors/0.28.0/),
from [commit 3a3c5b0007bbd870d775aee1c41098112b001df6](https://github.com/probityai/agent-evidence-vectors/tree/3a3c5b0007bbd870d775aee1c41098112b001df6).
See its [trade-booking documentation](https://github.com/probityai/agent-evidence-vectors/blob/3a3c5b0007bbd870d775aee1c41098112b001df6/packaging/agent_evidence_vectors/trade_booking/README.md).
This is a ScopeBlind teaching adapter, not an independent certification of Probity
or a production banking control.

The wheel SHA-256 is
`e87a2d64e3ba0953c23f6556f8665be4149c37f61e6f7095a9949580cbab0b4f`.
`requirements.txt` enforces it; `bridge.py` records and checks the manifest,
occurrence, trust and cases SHA-256 values. The repository lockfile pins the
Cedar engine; every report also records the policy SHA-256.

Upstream is **Apache-2.0, Copyright 2026 Sankalp Gilda**. Its original wheel and
license are installed intact; no fixture or reader source is vendored here.
The bridge's projection follows upstream's documented counting semantics.
The surrounding starter is under this repository's MIT license. Preserve the
upstream attribution and license if redistributing its files. All fixture signing
keys are published **test keys**, unsuitable for real evidence.
