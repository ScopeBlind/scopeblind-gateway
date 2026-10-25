#!/usr/bin/env node
// The Cursor hook entry. It always runs the relay. Up to protect-mcp 0.32.4 the relay
// ran only when its module URL matched the realpath of process.argv[1], which a
// case-variant path on a case-insensitive file system did not, so the hook exited 0
// with no output and the gate was never asked. The code lives in
// ../lib/cursor-relay.mjs, which tests and the installer import without running it.
import { main } from '../lib/cursor-relay.mjs';

await main();
