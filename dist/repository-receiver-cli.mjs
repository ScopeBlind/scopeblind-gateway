#!/usr/bin/env node
import {
  runRepositoryCommand
} from "./chunk-66FWA2ZU.mjs";
import {
  RepositoryReceiverError
} from "./chunk-E3D47JUV.mjs";
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
