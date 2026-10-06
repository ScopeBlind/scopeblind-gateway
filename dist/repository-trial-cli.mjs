import {
  runRepositoryTrial
} from "./chunk-Y77UXWY3.mjs";
import "./chunk-EZJRRWCW.mjs";
import "./chunk-KS5QKUVX.mjs";
import "./chunk-3ZDDS2TV.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-trial-cli.ts
runRepositoryTrial().catch((error) => {
  process.stderr.write("Managed trial stopped: " + (error instanceof Error && /^[a-z0-9_]{3,100}$/.test(error.message) ? error.message : "trial_runner_interrupted") + "\n");
  process.exitCode = 1;
});
