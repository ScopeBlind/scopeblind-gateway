import {
  runRepositoryCoding
} from "./chunk-AY2523BQ.mjs";
import "./chunk-W4EKTNR3.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-coding-cli.ts
runRepositoryCoding().catch(() => {
  process.stderr.write("The coding worker stopped. Inspect the signed job before retrying; publication may require read-only reconciliation.\n");
  process.exitCode = 1;
});
