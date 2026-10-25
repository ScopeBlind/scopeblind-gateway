#!/usr/bin/env node
// The Claude Code hook entry. It always runs the relay. Up to 0.32.4 the relay ran
// only when its own module URL matched process.argv[1]; Node resolves symbolic
// links for the module and not for argv, so through a symlinked plugin directory
// (a linked ~/.claude, CLAUDE_CONFIG_DIR or --plugin-dir) the hook exited 0 with no
// output, and the gate was never asked. The code lives in relay-core.mjs, which
// tests and other modules import without running it.
import { main } from './relay-core.mjs';

await main();
