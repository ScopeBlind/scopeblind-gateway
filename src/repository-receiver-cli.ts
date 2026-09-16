#!/usr/bin/env node
/** Standalone, dependency-free privileged receiver entry. Never imports PR code. */
import {runRepositoryReceiver,RepositoryReceiverError} from './repository-receiver.js';
runRepositoryReceiver(process.argv.slice(2)).catch(error=>{
 const message=error instanceof RepositoryReceiverError?error.message:'The receiver could not complete this request. Inspect the existing task before continuing.';
 process.stderr.write(`${message}\n`);process.exitCode=1;
});
