import {runRepositoryCoding} from './repository-coding-runner.js';
runRepositoryCoding().catch(()=>{process.stderr.write('The coding worker stopped. Inspect the signed job before retrying; publication may require read-only reconciliation.\n');process.exitCode=1;});
