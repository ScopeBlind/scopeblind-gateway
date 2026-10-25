# Contributing to protect-mcp

Small, focused changes are welcome: a reproducible bug, an interoperability
fixture, a documentation correction or an integration improvement. Start a
GitHub issue before a substantial feature so its scope can be discussed.

Report suspected vulnerabilities privately through [SECURITY.md](SECURITY.md).
Never include production credentials, private signing keys or customer receipts
in an issue or pull request. Use synthetic examples and throwaway keys.

## Set up a checkout

CI uses Node.js 22 and npm 11. Use the committed lockfile:

```sh
git clone https://github.com/ScopeBlind/scopeblind-gateway.git
cd scopeblind-gateway
npm ci
npm test
```

`npm test` builds the package before running Vitest. To work on a focused test
without rebuilding each time, run `npx vitest run src/<name>.test.ts`; CLI tests
that exercise `dist/` still need `npm run build` after source changes.

## Before opening a pull request

- Explain the problem, expected behavior and how you checked the change.
- Add a regression case for behavior changes, especially allow/deny decisions,
  signature inputs, replay handling and independent trust anchors. Documentation
  changes do not need a mirrored unit test.
- Preserve receipt compatibility or document an explicit migration and version
  boundary. Do not silently reinterpret historical signed bytes.
- Run `npm test`. For README command or packaging changes, also run:

```sh
npm pack --json > packed.json
node scripts/release-install-check.mjs
node scripts/readme-smoke.mjs --packed
```

The README smoke installs the packed candidate and a pinned published verifier
in a temporary directory, then executes the documented first example. It needs
npm registry access for dependencies; policy evaluation and verification are
local. `node scripts/readme-smoke.mjs --released` checks the pinned published
versions instead.

Changes affecting the isolated coding runtime also require Docker:

```sh
npm run test:docker
```

GitHub Actions runs the full suite, Docker check, package installation and README
example on pull requests and `main`. Do not put real service secrets in tests.

## Good starting points

Choose one bounded task from the
[help-wanted issues](https://github.com/ScopeBlind/scopeblind-gateway/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22),
or report a reproducible onboarding problem. Say which host and version you use
before starting a compatibility task so another contributor can pick a different
one. Useful contributions include:

| Contribution | Useful evidence | Where to start |
|---|---|---|
| Follow the setup in a clean project | Exact command, expected result, actual result, OS, Node and package version | [Local setup guide](docs/local-gateway.md#claude-code-hook-quickstart) |
| Capture one supported host's hook contract | Sanitized allow/deny payloads, host version, output and evidence the host actually blocked the harmless test action | `src/cli-format.test.ts` |
| Exercise another supported runtime | Packed-package installation, allow/deny/sign/verify/tamper result and exact runtime versions | `scripts/release-install-check.mjs`, `scripts/readme-smoke.mjs` |
| Add one useful policy recipe | Permitted action, denied action, harmless look-alike and missing-field behavior, evaluated by the real Cedar engine | `src/policy-packs.test.ts`, `docs/local-gateway.md` |

Host fixtures should use a disposable project with synthetic data. Remove private
paths, identifiers, prompts and credentials, and document replacements that
preserve the event shape. A CLI fixture test is not evidence that a real host
loaded or obeyed its hooks; label the two checks separately. No private customer
records or hosted account are needed for the committed fixture tests.

Prefer a small pull request with one purpose over a broad cleanup. Generated
`dist/` files are tracked: run `npm run build` when changing source and include
corresponding build outputs. Do not update generated files by hand.

## Review and licensing

The maintainer reviews public pull requests and coordinates releases. A review
may ask for a narrower scope, clearer compatibility evidence or a design issue
first. There is no guaranteed review SLA. See [GOVERNANCE.md](GOVERNANCE.md).

Contributions are made under this repository's MIT licence. Preserve third-party
notices and discuss new dependencies or licensing changes before adding them.
See [LICENSE](LICENSE) and the existing [PATENTS.md](PATENTS.md).
