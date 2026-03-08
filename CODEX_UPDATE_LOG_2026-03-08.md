# Codex Update Log — 2026-03-08

Updated `/Users/tomfarley/scopeblind-gateway` to match the current official ScopeBlind secure-mode gateway story.

## Files changed

- `package.json`
  - changed description to secure-mode JWT enforcement wording
  - added `jose` dependency for JWKS / EdDSA JWT verification
  - added `check` script
  - changed license field to `SEE LICENSE IN LICENSE`

- `wrangler.toml`
  - replaced legacy verifier-url config with current audience + JWKS config
  - renamed public-mode config to `OBSERVE_MODE`
  - documented `SHADOW_MODE` as legacy alias only

- `src/index.ts`
  - replaced old proof-header verifier flow with pass-token / JWKS verification flow
  - verifies `sb_pass` cookie or `X-ScopeBlind-Token`
  - emits `observe` / `enforce` terminology
  - strips ScopeBlind credentials before forwarding to origin
  - forwards verification metadata headers to origin

- `README.md`
  - rewrote positioning around secure-mode gateway enforcement
  - aligned terminology to observe mode / trusted agents / pass tokens
  - documented current config and behavior

## Not changed

- `.gitignore`
- `tsconfig.json`
- `LICENSE`

## Follow-up still needed

- Update the GitHub repository “About” description in GitHub UI to match the new README.
- Install dependencies and run `npm run check` locally before pushing.
