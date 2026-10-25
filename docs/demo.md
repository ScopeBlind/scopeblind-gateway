# A small, reproducible policy demo

[Watch the animated summary](assets/readme-demo.gif) ·
[View the static image](assets/readme-demo.png) ·
[Read the captured JSON results](assets/readme-demo-run.json)

The illustration summarizes a real local run of published `protect-mcp@0.32.2`
and `@veritasacta/verify@0.11.0`. It is a result summary, not a terminal recording.
The five stages use actual captured decisions and verifier results:

| Stage | Result |
|---|---|
| Evaluate `Read` for `README.md` | Allowed; exit 0 |
| Evaluate a proposed `git push --force origin main` | Denied by `starter.force-push-main`; exit 2 |
| Re-evaluate and sign both decisions | Two signed receipts: `allow`, then `deny` |
| Replay the log using the public key from the generated local key file | Two receipts verified; their link passes; zero chain breaks |
| Change the signed denial to `allow` | `invalid_signature`; exit 1 |

Neither proposed tool is executed. In particular, this demo never runs
`git push`. It also checks that verifying the original receipt without an
externally supplied key returns `embedded_key_rejected` (exit 2).

## Reproduce the capture

Use Node.js 22 and npm. From this repository's root:

```sh
node scripts/readme-demo.mjs /tmp/protect-mcp-demo-run.json
```

The script installs the two pinned published packages into a temporary directory,
creates a fresh demo key, runs and asserts all seven CLI results, and removes the
temporary directory and private key in a `finally` block. The capture contains
only the public key, receipts, CLI output, package versions and package integrity
digests. It redacts the temporary directory's path.

The public key is supplied to the verifier from the separate key file, rather
than trusted because it appears inside a receipt. This establishes a local demo
check, not an independently authenticated third-party identity. Real recipients
must obtain the expected issuer key through their own trusted channel.

To refresh the checked-in capture and render the illustration, use Python 3 and
[Pillow](https://pillow.readthedocs.io/):

```sh
node scripts/readme-demo.mjs
python3 scripts/render-readme-demo.py
```

The renderer reads the captured JSON; it does not invent CLI output. It produces
one static PNG and a six-frame, 14-second GIF. It supports macOS system fonts and
Linux DejaVu fonts; set `DEMO_SANS_FONT` and `DEMO_MONO_FONT` to installed font
paths when needed. A rerun uses a fresh key, timestamps and request IDs, so its
bytes will differ while the asserted results remain the same.

## What this demonstrates

The starter policy evaluates these two proposed calls; the verifier checks the
signed bytes and the supplied receipt link against the provided public key.
Changing a signed decision causes signature verification to fail.

It does not establish tool execution, a complete action history, a third party's
identity, or their authority. The verifier also reports that the supplied key has
no independently established validity window. Starter command-text rules have
coverage limits; see the [local gateway guide](local-gateway.md#start-with-the-starter-policy).
