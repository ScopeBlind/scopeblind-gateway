/** Audited workflow templates shared by the installer and service validation. */
import {repositorySetupArtifactUrl} from './coordination-repository-connection.js';
const hash=(v:string)=>/^[a-f0-9]{64}$/.test(v);
export function renderGuidedReceiverWorkflow(artifact:{url:string;sha256:string}):string{
 if(!repositorySetupArtifactUrl(artifact.url)||!hash(artifact.sha256))throw new Error('setup_invalid_artifact');
 return `# Owner-reviewed installation; no PR checkout, imported code, or implicit approval.
name: ScopeBlind connected receiver
on:
  workflow_dispatch:
    inputs:
      job_id:
        description: Exact signed ScopeBlind connection job
        type: string
        required: true
permissions:
  contents: write
  pull-requests: read
  checks: read
  deployments: read
  id-token: write
concurrency:
  group: scopeblind-connection-\${{ inputs.job_id }}
  cancel-in-progress: false
jobs:
  receiver:
    if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - name: Use the reviewed Node runtime
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          node-version: '22.22.3'
      - name: Verify the reviewed receiver artifact
        env:
          RECEIVER_URL: ${artifact.url}
          RECEIVER_SHA256: ${artifact.sha256}
        shell: bash
        run: |
          set -euo pipefail
          curl --fail --silent --show-error --proto '=https' --max-time 30 "$RECEIVER_URL" --output receiver.cjs
          printf '%s  receiver.cjs\\n' "$RECEIVER_SHA256" | sha256sum --check --strict
      - name: Run only the signed connection job
        env:
          GITHUB_TOKEN: \${{ github.token }}
          SCOPEBLIND_RECEIVER_PRIVATE_KEY: \${{ secrets.SCOPEBLIND_GUIDED_RECEIVER_KEY }}
          CONNECTION_CONFIG: \${{ vars.SCOPEBLIND_GUIDED_CONNECTION }}
          JOB_ID: \${{ inputs.job_id }}
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          node -e 'require("node:fs").writeFileSync("connection.json",process.env.CONNECTION_CONFIG,{mode:0o600,flag:"wx"})'
          node receiver.cjs connection-job --connection connection.json --job "$JOB_ID"
`;
}
export function renderGuidedCodingWorkflow(artifact:{url:string;sha256:string},receiver:{url:string;sha256:string}):string{
 if(!/^https:\/\/scopeblind\.com\/releases\/repository-coding-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(artifact.url)||!hash(artifact.sha256)||!repositorySetupArtifactUrl(receiver.url)||!hash(receiver.sha256))throw new Error('setup_invalid_coding_artifact');
 return `# Trusted controller only; proposed code runs in a separate credential-free networkless container.
name: ScopeBlind bounded coding worker
on:
  workflow_dispatch:
    inputs:
      job_id:
        description: Connection setup ID for readiness, or an authorized coding job ID
        type: string
        required: true
permissions:
  contents: write
  pull-requests: write
  checks: write
  deployments: write
  id-token: write
concurrency:
  group: scopeblind-coding-controller
  cancel-in-progress: false
jobs:
  coding:
    if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - name: Use the reviewed Node runtime
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          node-version: '22.22.3'
      - name: Verify the reviewed controller artifacts
        env:
          RECEIVER_URL: ${receiver.url}
          RECEIVER_SHA256: ${receiver.sha256}
          CODING_URL: ${artifact.url}
          CODING_SHA256: ${artifact.sha256}
        shell: bash
        run: |
          set -euo pipefail
          curl --fail --silent --show-error --proto '=https' --max-time 30 "$RECEIVER_URL" --output receiver.cjs
          curl --fail --silent --show-error --proto '=https' --max-time 30 "$CODING_URL" --output coding.cjs
          printf '%s  receiver.cjs\\n%s  coding.cjs\\n' "$RECEIVER_SHA256" "$CODING_SHA256" | sha256sum --check --strict
      - name: Confirm the exact worker then run bounded work
        env:
          GITHUB_TOKEN: \${{ github.token }}
          SCOPEBLIND_CODING_WORKER_KEY: \${{ secrets.SCOPEBLIND_CODING_WORKER_KEY }}
          CODING_CONFIG: \${{ vars.SCOPEBLIND_CODING_CONNECTION }}
          CONNECTION_CONFIG: \${{ vars.SCOPEBLIND_GUIDED_CONNECTION }}
          JOB_ID: \${{ inputs.job_id }}
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          node -e 'require("node:fs").writeFileSync("coding.json",process.env.CODING_CONFIG,{mode:0o600,flag:"wx"});require("node:fs").writeFileSync("connection.json",process.env.CONNECTION_CONFIG,{mode:0o600,flag:"wx"})'
          node receiver.cjs coding-ready --connection connection.json --coding coding.json
          SETUP_ID="$(node -e 'process.stdout.write(JSON.parse(require("node:fs").readFileSync("connection.json","utf8")).authorization.payload.setup_id)')"
          if [ "$JOB_ID" = "$SETUP_ID" ]; then
            printf '%s\\n' 'Connection readiness refreshed. No coding job was run.'
          else
            node coding.cjs --config coding.json
          fi
`;
}
