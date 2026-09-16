#!/usr/bin/env node
import {
  runRepositoryCommand
} from "./chunk-NPJHA265.mjs";
import {
  RepositoryReceiverError
} from "./chunk-4HNR7Y44.mjs";
import "./chunk-62IJNG3V.mjs";
import "./chunk-VS4TVKA7.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-receiver-cli.ts
runRepositoryCommand(process.argv.slice(2)).catch((error) => {
  const message = error instanceof RepositoryReceiverError ? error.message : "The receiver could not complete this request. Inspect the existing task before continuing.";
  process.stderr.write(`${message}
`);
  process.exitCode = 1;
});
