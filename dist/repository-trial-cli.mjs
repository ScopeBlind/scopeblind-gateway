import {
  runRepositoryTrial
} from "./chunk-M7UV5PUZ.mjs";
import "./chunk-N5HNIKFM.mjs";
import "./chunk-JRJSKQFR.mjs";
import "./chunk-S2VKIQZF.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/repository-trial-cli.ts
runRepositoryTrial().catch((error) => {
  process.stderr.write("Managed trial stopped: " + (error instanceof Error && /^[a-z0-9_]{3,100}$/.test(error.message) ? error.message : "trial_runner_interrupted") + "\n");
  process.exitCode = 1;
});
