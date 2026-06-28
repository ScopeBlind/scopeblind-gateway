# Changelog

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
