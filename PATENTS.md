# Patent Notice

This software is open source. You are free to use, modify, and distribute it
under its stated license (MIT or Apache-2.0 — see each package's LICENSE file).

## Patent Holdings

ScopeBlind Pty Ltd (ABN 41 693 027 440) holds provisional patent applications
covering specific methods used in conjunction with this software:

1. **VOPRF Metering** (AU Provisional, ~October 2025) — Deterministic
   credential derivation using Verifiable Oblivious Pseudorandom Functions
   for privacy-preserving rate limiting and metering.

2. **Verifier Nullifiers** (AU Provisional, ~October 2025) — Issuer-blind
   verification scheme where the verifier confirms credential validity
   without learning which organization issued it.

3. **Offline Enforcement** (AU Provisional, ~October 2025) — Self-contained
   policy enforcement with cryptographic receipts that are independently
   verifiable without contacting the issuer.

4. **Decision Receipts with Configurable Disclosure** (AU Provisional,
   March 2026) — Signed decision artifacts with holder-bound zero-knowledge
   compliance proofs, tool-calling gateway integration, agent manifests,
   portable identity, and cross-algorithm key binding. 20 claims, 8 figures.

## Scope

These patents cover specific server-side issuance methods and the novel
composition of VOPRF credentials with policy enforcement and receipt signing.
They do NOT restrict your use of:

- The open-source verification code (`@veritasacta/verify`)
- The policy enforcement gateway (`protect-mcp`)
- The Ed25519 signing primitives (`@veritasacta/artifacts`)
- The receipt format specified in the IETF Internet-Draft
- Standard cryptographic operations (Ed25519, JCS, SHA-256)

## Apache-2.0 Patent Grant

Packages licensed under Apache-2.0 include an explicit patent grant per
Section 3 of the Apache License, Version 2.0. This grant covers the use
of the software as distributed. The grant terminates only if you initiate
patent litigation alleging that the software constitutes patent infringement
(retaliation clause, Section 3).

## Contact

Patent inquiries: patents@scopeblind.com
General: tommy@scopeblind.com
Website: https://scopeblind.com
IETF Draft: https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/
