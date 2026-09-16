#!/usr/bin/env node
/** Standalone, dependency-free privileged receiver entry. Never imports PR code. */
import {RepositoryReceiverError} from './repository-receiver.js';
import {runRepositoryCommand} from './repository-setup.js';
runRepositoryCommand(process.argv.slice(2)).catch(error=>{
 const message=error instanceof RepositoryReceiverError?error.message:'The receiver could not complete this request. Inspect the existing task before continuing.';
 process.stderr.write(`${message}\n`);process.exitCode=1;
});
