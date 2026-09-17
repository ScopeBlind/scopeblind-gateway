import {
  runRepositoryCoding
} from "./chunk-N5HNIKFM.mjs";
import "./chunk-S2VKIQZF.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-coding-cli.ts
runRepositoryCoding().catch(() => {
  process.stderr.write("The coding worker stopped. Inspect the signed job before retrying; publication may require read-only reconciliation.\n");
  process.exitCode = 1;
});
