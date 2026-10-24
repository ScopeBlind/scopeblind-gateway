# Validation and releases

[Back to the quickstart](../README.md)

## What CI checks

[Validate package](https://github.com/ScopeBlind/scopeblind-gateway/actions/workflows/validate-release.yml)
runs on pull requests, `main`, release-candidate branches and manual dispatch:

1. Install dependencies from the lockfile, then build and run the Vitest suite.
2. Run the existing Docker isolation smoke test on a Linux runner.
3. Pack the built package and check the installed entry points in an empty directory.
4. Run the literal README first-example block against that tarball and
   `@veritasacta/verify@0.11.0` from npm. Assert allow/deny decisions, a valid
   signature chain, tamper rejection and refusal to treat an embedded key as trust.
5. Preserve logs, the tarball and its SHA-256 digest as workflow artifacts.

These checks exercise defined cases. They are not a comprehensive security audit
or proof that every deployment routes all actions through the gateway.

## Reproduce locally

Use Node.js 22, npm and Docker for the isolation check:

```sh
npm ci
npm test
npm run test:docker
npm pack --json > packed.json
node scripts/release-install-check.mjs
node scripts/readme-smoke.mjs --packed
```

To check the README against the two published versions rather than your checkout:

```sh
node scripts/readme-smoke.mjs --released
```

The smoke script extracts the example from README rather than maintaining a
second copy. It cleans up its temporary directory, which contains only fresh
demo keys and generated records. Registry access is needed to install packages.

## Publishing

The [publish workflow](../.github/workflows/publish.yml) is manually dispatched
from `main` with the exact version committed in `package.json`. It repeats the
checks before publishing the packed tarball using npm trusted publishing and
`--provenance`. Repository environment protections and npm publisher settings
are configured separately from this file.

Do not publish from a developer laptop as a substitute for a failed workflow.
Inspect failures, update the reviewed source and rerun validation. Published npm
versions cannot be overwritten; a corrected release requires a new version.

## Provenance and its limits

npm provenance ties a package publication to its source and build workflow. It
does not attest to code correctness, a security audit or the identity of a
receipt's issuer. A locally generated checksum checks bytes, not publisher trust.

The workflow is configured for provenance, but that does not retroactively add
attestations to earlier releases. At this maintenance review (22 October 2026),
`protect-mcp@0.31.1` had no npm provenance attestation. Check the npm package's
provenance information for the particular version you install. This repository
does not claim that every release or Git tag is cryptographically signed.

The README pins known package versions for reproducibility. When updating those
pins, run both the packed and released examples and record any compatibility
change in the changelog.
