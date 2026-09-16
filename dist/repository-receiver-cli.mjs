#!/usr/bin/env node
import {
  RepositoryReceiverError,
  runRepositoryReceiver
} from "./chunk-MGBXP7YK.mjs";
import "./chunk-BPZXU6OQ.mjs";
import "./chunk-VS4TVKA7.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-receiver-cli.ts
runRepositoryReceiver(process.argv.slice(2)).catch((error) => {
  const message = error instanceof RepositoryReceiverError ? error.message : "The receiver could not complete this request. Inspect the existing task before continuing.";
  process.stderr.write(`${message}
`);
  process.exitCode = 1;
});
