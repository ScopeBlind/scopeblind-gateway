#!/usr/bin/env node
import {
  runRepositoryCommand
} from "./chunk-Q6MPYSGG.mjs";
import {
  RepositoryReceiverError
} from "./chunk-RJYX2HEV.mjs";
import "./chunk-W4EKTNR3.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-receiver-cli.ts
runRepositoryCommand(process.argv.slice(2)).catch((error) => {
  const message = error instanceof RepositoryReceiverError ? error.message : "The receiver could not complete this request. Inspect the existing task before continuing.";
  process.stderr.write(`${message}
`);
  process.exitCode = 1;
});
