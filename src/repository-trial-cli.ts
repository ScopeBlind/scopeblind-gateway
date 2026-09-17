import {runRepositoryTrial} from './repository-trial-runner.js';
runRepositoryTrial().catch(error=>{process.stderr.write('Managed trial stopped: '+(error instanceof Error&&/^[a-z0-9_]{3,100}$/.test(error.message)?error.message:'trial_runner_interrupted')+'\n');process.exitCode=1;});
