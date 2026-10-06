import { describe, it, expect } from 'vitest';
import { validRepositoryCodingWorkflowRun, workflowRunFromEnvironment, validRepositoryCodingResult } from './coordination-repository-coding.js';

const repo = 'ScopeBlind/scopeblind-repository-demo';
const env = { GITHUB_RUN_ID: '1234567', GITHUB_RUN_ATTEMPT: '2', GITHUB_WORKFLOW_REF: `${repo}/.github/workflows/scopeblind-coding.yml@refs/heads/main`, GITHUB_WORKFLOW_SHA: 'a'.repeat(40), GITHUB_REPOSITORY: repo };
const result = (over: Record<string, unknown> = {}) => ({ type: 'scopeblind.repository.coding-result.v1', job_id: 'job_0123456789', plan_digest: 'b'.repeat(64), publication_digest: 'c'.repeat(64), repository: repo, branch: 'scopeblind/coding/x', head_sha: 'd'.repeat(40), pull_number: 7, pull_url: `https://github.com/${repo}/pull/7`, preview_url: 'https://preview.scopeblind.com/v1/job_0123456789/' + 'd'.repeat(40) + '/' + 'e'.repeat(64) + '/index.html', preview_digest: 'e'.repeat(64), deployment_id: 1, deployment_status_id: 1, deployment_environment: 'ScopeBlind coding preview', check: { id: 1, name: 'ScopeBlind isolated coding checks', app_id: 15368, head_sha: 'd'.repeat(40), conclusion: 'success' }, observed_at: '2026-09-19T00:00:00.000Z', ...over });

describe('the workflow run bound into a coding result', () => {
  it('is read from the Actions environment and named exactly as GitHub names it', () => {
    expect(workflowRunFromEnvironment(env, repo)).toEqual({ id: 1234567, attempt: 2, workflow_ref: env.GITHUB_WORKFLOW_REF, workflow_sha: 'a'.repeat(40), repository: repo });
    expect(workflowRunFromEnvironment({}, repo)).toBeUndefined();
    expect(workflowRunFromEnvironment({ ...env, GITHUB_RUN_ATTEMPT: '0' }, repo)).toBeUndefined();
    expect(workflowRunFromEnvironment({ ...env, GITHUB_REPOSITORY: 'someone/else' }, repo)).toBeUndefined();
    expect(workflowRunFromEnvironment({ ...env, GITHUB_WORKFLOW_REF: 'someone/else/.github/workflows/x.yml@refs/heads/main' }, repo)).toBeUndefined();
    expect(workflowRunFromEnvironment({ ...env, GITHUB_WORKFLOW_REF: `${repo}/.github/workflows/x.yml@main` }, repo)).toBeUndefined();
    expect(workflowRunFromEnvironment({ ...env, GITHUB_WORKFLOW_SHA: 'short' }, repo)).toBeUndefined();
  });
  it('is optional on a result and, when present, must belong to the same repository', () => {
    expect(validRepositoryCodingResult(result())).toBe(true);
    expect(validRepositoryCodingResult(result({ workflow_run: workflowRunFromEnvironment(env, repo) }))).toBe(true);
    expect(validRepositoryCodingResult(result({ workflow_run: { ...workflowRunFromEnvironment(env, repo), repository: 'someone/else' } }))).toBe(false);
    expect(validRepositoryCodingResult(result({ workflow_run: { id: 1, attempt: 1 } }))).toBe(false);
    expect(validRepositoryCodingWorkflowRun({ id: 1, attempt: 1, workflow_ref: `${repo}/.github/workflows/a.yaml@refs/tags/v1`, workflow_sha: 'f'.repeat(40), repository: repo }, repo)).toBe(true);
  });
});
