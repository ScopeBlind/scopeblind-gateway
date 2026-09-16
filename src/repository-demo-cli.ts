import {runRepositoryDemo} from './repository-demo-runner.js';
runRepositoryDemo().catch(()=>{process.stderr.write('The demo runner did not complete. Check its durable job state before retrying.\n');process.exitCode=1;});
