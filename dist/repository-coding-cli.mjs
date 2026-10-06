import {
  runRepositoryCoding
} from "./chunk-EZJRRWCW.mjs";
import "./chunk-3ZDDS2TV.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-coding-cli.ts
runRepositoryCoding().catch(() => {
  process.stderr.write("The coding worker stopped. Inspect the signed job before retrying; publication may require read-only reconciliation.\n");
  process.exitCode = 1;
});
