# Security Policy

This policy covers the `protect-mcp` npm package.

## Supported versions

Security fixes target the latest published npm version.
Older versions are not maintained as separate support branches; upgrade to the
latest release before checking whether an issue remains. Historical fixes below
are version boundaries, not a promise to support every later version forever.

## Affected versions

The 0.5.x and 0.6.x lines have a fail-open gate: the Cedar policy was not
evaluated correctly against the pinned engine, and the evaluator returned ALLOW
on evaluation error. A `forbid` rule could therefore fail to block. This is fixed
in 0.7.0, which fails closed (denies) on any evaluation error, missing engine, or
errored policy. If you are on 0.5.x or 0.6.x, upgrade to the latest release
(the original correction shipped in 0.7.0).

Advisory: [GHSA-hm46-7j72-rpv9](https://github.com/ScopeBlind/scopeblind-gateway/security/advisories/GHSA-hm46-7j72-rpv9).

## Design posture

Cedar enforcement fails closed by default. The MCP wrapper starts in shadow
mode unless `--enforce` is selected; shadow mode deliberately does not block.
In enforcing mode, a policy error, missing engine or evaluation failure denies
the call. Before arming an
enforcing gate, `serve --enforce` and `doctor` run a boot self-test that proves
the gate denies a known-forbidden vector, and refuse to start if it cannot.
Shadow/observe mode flags calls that would be blocked as `would_deny: true`.
In enforcing mode the MCP wrapper also refuses to start when signing is
configured but its key is missing or unreadable, and refuses an allowed call
whose receipt cannot be signed. With both `--cedar` and `--policy`, a call needs
a Cedar permit and must also pass the JSON policy's rules.

## Coverage and deployment

The gateway covers calls routed through it. Agents with independent credentials,
network access or shell execution may bypass that path. Starter shell policies
match command text and are not a sandbox. Signatures establish integrity against
a trusted key, not the truth of a result or completeness of a supplied record.
Protect signing keys and pin expected issuer keys independently of receipts.
Keys are written 0600, and the gateway warns about a key file other users can
read.

The HTTP gateway (`--http`) listens on 127.0.0.1 and requires a bearer token of
at least 32 characters (`PROTECT_MCP_HTTP_TOKEN`, or one it generates and prints
on stderr); `--host` exposes it beyond the machine. The local status server,
hook server and dashboard answer only requests addressed to their loopback port
and refuse requests from other sites. The dashboard also requires its page's
per-launch token for any change.

See [release validation and provenance](docs/releases.md) for what the release
checks cover and which publication claims can be verified.

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
