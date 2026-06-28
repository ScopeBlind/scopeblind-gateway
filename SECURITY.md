# Security Policy

This policy covers the `protect-mcp` npm package.

## Supported versions

| Version | Supported |
|---------|-----------|
| >= 0.7.0 | Yes |
| 0.6.x | No, upgrade |
| 0.5.x | No, upgrade |

## Affected versions

The 0.5.x and 0.6.x lines have a fail-open gate: the Cedar policy was not
evaluated correctly against the pinned engine, and the evaluator returned ALLOW
on evaluation error. A `forbid` rule could therefore fail to block. This is fixed
in 0.7.0, which fails closed (denies) on any evaluation error, missing engine, or
errored policy. If you are on 0.5.x or 0.6.x, upgrade to >= 0.7.0.

Advisory: [GHSA-hm46-7j72-rpv9](https://github.com/ScopeBlind/scopeblind-gateway/security/advisories/GHSA-hm46-7j72-rpv9).

## Design posture

The gate fails closed by default. On any policy error, a missing engine, or an
evaluation failure, the decision is DENY, never a silent ALLOW. Before arming an
enforcing gate, `serve --enforce` and `doctor` run a boot self-test that proves
the gate denies a known-forbidden vector, and refuse to start if it cannot. The
observe mode that allows on error is opt-in, and even then flags any call that
would be blocked as `would_deny: true`.

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue for an
unpatched vulnerability.

- Email: security@scopeblind.com
- Or open a private advisory via [GitHub Security Advisories](https://github.com/ScopeBlind/scopeblind-gateway/security/advisories/new).

Include the affected version, a description, and (if possible) a minimal
reproduction. We aim to acknowledge reports within 3 business days and to ship a
fix or a clear remediation plan as quickly as the severity warrants.

## Disclosure and credit

We follow coordinated disclosure: we work with you on a fix and a timeline before
any public detail is released. Reporters who disclose responsibly are credited in
the advisory and the CHANGELOG unless they ask to remain anonymous.
