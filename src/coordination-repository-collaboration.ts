/** Companion records for repository v1 tasks. None widens a v1 human/receiver role. */
import { canonical, type Signed } from './coordination-protocol.js';
import { REPOSITORY_HEX, REPOSITORY_ID, REPOSITORY_SHA, repositoryBranch, type RepositoryState, type RepositoryTask } from './coordination-repository.js';
export const REPOSITORY_COLLABORATION_ACTIONS = [
    'repository_connection_save', 'repository_connection_get', 'repository_readiness_record',
    'repository_participants_bind', 'repository_collaboration_get', 'repository_collaboration_export', 'repository_preview_record',
    'repository_agent_grant', 'repository_agent_revoke', 'repository_agent_get', 'repository_revision_request', 'repository_revision_create',
    'repository_demo_info', 'repository_demo_create', 'repository_demo_get', 'repository_demo_activate', 'repository_demo_enqueue', 'repository_demo_poll', 'repository_demo_complete',
] as const;
export type RepositoryCollaborationAction = typeof REPOSITORY_COLLABORATION_ACTIONS[number];
export interface RepositoryConnection {
    type: 'scopeblind.repository.connection.v1';
    id: string;
    endpoint: string;
    repository: string;
    base_branch: string;
    owner_key: string;
    receiver_key: string;
    authority_key: string;
    issued_at: string;
    expires_at: string;
}
export interface RepositoryReadiness {
    type: 'scopeblind.repository.readiness.v1';
    connection_digest: string;
    repository: string;
    base_branch: string;
    owner_key: string;
    receiver_key: string;
    authority_key: string;
    checks: Array<{
        name: string;
        app_id: number;
        app_name?: string;
    }>;
    base_sha: string;
    check_head_sha: string;
    required_checks?: Array<{
        name: string;
        app_id: number | null;
    }>;
    protection: 'observed' | 'unavailable';
    runtime: 'local' | 'github_actions';
    workflow: 'not_checked' | 'missing' | 'matching' | 'different' | 'unavailable';
    workflow_sha?: string;
    observed_at: string;
    expires_at: string;
}
export interface RepositoryConnectionState {
    type: 'scopeblind.repository.connection-state.v1';
    connection: Signed<RepositoryConnection>;
    readiness: Signed<RepositoryReadiness>;
    observed_at: string;
}
export interface RepositoryConnectionImport {
    type: 'scopeblind.repository.connection-import.v1';
    connection: RepositoryConnection;
    readiness: Signed<RepositoryReadiness>;
}
export interface RepositoryParticipants {
    type: 'scopeblind.repository.participants.v1';
    task_id: string;
    task_digest: string;
    owner_key: string;
    receiver_key: string;
    reviewer_key: string;
    reviewer_claim_digest: string;
    issued_at: string;
    expires_at: string;
}
export interface ContactPage {
    type: 'scopeblind.contact-page.v1';
    button_label: string;
    target: 'broken' | 'contact';
    accent: 'indigo' | 'emerald' | 'rose';
}
export interface RepositoryPreview {
    type: 'scopeblind.repository.preview.v1';
    task_id: string;
    task_digest: string;
    proposal_digest: string;
    base_sha: string;
    head_sha: string;
    merge_sha: string;
    tree_sha: string;
    path: 'demo/contact.json';
    before: {
        model: ContactPage;
        blob_sha: string;
        content_sha256: string;
    };
    after: {
        model: ContactPage;
        blob_sha: string;
        content_sha256: string;
    };
    renderer: 'scopeblind.contact-page.v1';
    observed_at: string;
}
export interface RepositoryAgentGrant {
    type: 'scopeblind.repository.agent-grant.v1';
    id: string;
    task_id: string;
    task_digest: string;
    issuer_key: string;
    agent_key: string;
    permissions: Array<'read_task' | 'request_revision'>;
    issued_at: string;
    expires_at: string;
}
export interface RepositoryRevisionRequest {
    type: 'scopeblind.repository.revision-request.v1';
    id: string;
    task_id: string;
    task_digest: string;
    basis_digest: string;
    requester_key: string;
    grant_digest?: string;
    message: string;
    proposed: ContactPage;
    issued_at: string;
}
export interface RepositoryRevisionLink {
    type: 'scopeblind.repository.revision-link.v1';
    id: string;
    parent_task_id: string;
    parent_task_digest: string;
    parent_basis_digest: string;
    request_digest: string;
    child_task_id: string;
    child_task_digest: string;
    owner_key: string;
    issued_at: string;
}
export interface RepositoryCollaboration {
    type: 'scopeblind.repository.collaboration.v1';
    task_id: string;
    task_digest: string;
    participants: Signed<RepositoryParticipants> | null;
    preview: Signed<RepositoryPreview> | null;
    requests: Array<Signed<RepositoryRevisionRequest>>;
    revisions: Array<Signed<RepositoryRevisionLink>>;
    agent_grants: Array<{
        grant: Signed<RepositoryAgentGrant>;
        revoked: boolean;
    }>;
    observed_at: string;
}
export interface RepositoryDemoRequest {
    type: 'scopeblind.repository.demo-request.v1';
    id: string;
    owner_key: string;
    receiver_key: string;
    authority_key: string;
    title: string;
    goal: string;
    proposed: ContactPage;
    reviewer_secret_hash: string;
    issued_at: string;
    expires_at: string;
    parent_task_id?: string;
    parent_task_digest?: string;
    parent_basis_digest?: string;
    revision_request_digest?: string;
}
export interface RepositoryDemoProvision {
    type: 'scopeblind.repository.demo-provision.v1';
    request_id: string;
    request_digest: string;
    repository: string;
    base_branch: string;
    head_branch: string;
    pull_number: number;
    initial_base_sha: string;
    initial_head_sha: string;
    receiver_key: string;
    required_checks: Array<{
        name: string;
        app_id: number;
    }>;
    observed_at: string;
}
export interface RepositoryDemoInfo {
    type: 'scopeblind.repository.demo-info.v1';
    repository: typeof DEMO_REPOSITORY;
    receiver_key: string | null;
    authority_key: string;
    template: 'contact-button-v1';
    template_commit: string | null;
    availability: 'ready' | 'starting' | 'setup_required';
    dispatch_available: boolean;
    last_receiver_seen_at: string | null;
    required_checks: Array<{
        name: string;
        app_id: number;
    }>;
    default_model: ContactPage;
    observed_at: string;
}
export interface RepositoryDemoState {
    type: 'scopeblind.repository.demo-state.v1';
    request: Signed<RepositoryDemoRequest>;
    provision: Signed<RepositoryDemoProvision> | null;
    task: Signed<RepositoryTask> | null;
    status: 'queued' | 'provisioning' | 'ready_to_review' | 'active' | 'failed' | 'expired';
    dispatch: 'requested' | 'unconfigured' | 'unavailable';
    error: string | null;
    observed_at: string;
}
export interface RepositoryDemoJob {
    type: 'scopeblind.repository.demo-job.v1';
    id: string;
    request_id: string;
    kind: 'provision' | 'inspect' | 'execute' | 'reconcile';
    request: Signed<RepositoryDemoRequest>;
    provision: Signed<RepositoryDemoProvision> | null;
    task: Signed<RepositoryTask> | null;
    participants: Signed<RepositoryParticipants> | null;
    task_state: Signed<RepositoryState> | null;
    parent_state: Signed<RepositoryState> | null;
    revision_request: Signed<RepositoryRevisionRequest> | null;
    lease_id: string;
    lease_expires_at: string;
    issued_at: string;
}
export interface RepositoryDemoCompletion {
    type: 'scopeblind.repository.demo-completion.v1';
    job_id: string;
    lease_id: string;
    request_id: string;
    kind: RepositoryDemoJob['kind'];
    status: 'complete' | 'failed';
    provision?: Signed<RepositoryDemoProvision>;
    task_state?: Signed<RepositoryState>;
    error?: string;
    observed_at: string;
}
export const DEMO_REPOSITORY = 'ScopeBlind/scopeblind-repository-demo';
export const DEMO_CHECK = { name: 'ScopeBlind contact validation', app_id: 4962726 } as const;
export const CONTACT_PATH = 'demo/contact.json' as const;
export const DEFAULT_CONTACT_PAGE: ContactPage = { type: 'scopeblind.contact-page.v1', button_label: 'Get in touch', target: 'broken', accent: 'indigo' };
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const shape = (value: unknown, required: string[], optional: string[] = []): value is Record<string, unknown> => object(value) && required.every(key => key in value) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const text = (value: unknown, max: number, empty = false) => typeof value === 'string' && (empty || value.trim().length > 0) && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const hex = (value: unknown) => typeof value === 'string' && REPOSITORY_HEX.test(value);
const id = (value: unknown) => typeof value === 'string' && REPOSITORY_ID.test(value);
const sha = (value: unknown) => typeof value === 'string' && REPOSITORY_SHA.test(value);
const at = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const span = (issued: unknown, expires: unknown, max: number) => at(issued) && at(expires) && Date.parse(String(expires)) > Date.parse(String(issued)) && Date.parse(String(expires)) - Date.parse(String(issued)) <= max;
const repository = (value: unknown) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value);
export function validContactPage(value: unknown): value is ContactPage {
    return shape(value, ['type', 'button_label', 'target', 'accent']) && value.type === 'scopeblind.contact-page.v1' && text(value.button_label, 40) && ['broken', 'contact'].includes(String(value.target)) && ['indigo', 'emerald', 'rose'].includes(String(value.accent));
}
export function contactPageBytes(value: ContactPage): string {
    if (!validContactPage(value))
        throw new Error('invalid_contact_page');
    return canonical(value) + '\n';
}
/** Only the canonical JSON model is interpreted; no repository HTML or JS runs. */
export function parseContactPageJson(source: string): ContactPage {
    if (typeof source !== 'string' || new TextEncoder().encode(source).length > 1024)
        throw new Error('invalid_contact_page');
    let value: unknown;
    try {
        value = JSON.parse(source);
    }
    catch {
        throw new Error('invalid_contact_page');
    }
    if (!validContactPage(value) || contactPageBytes(value) !== source)
        throw new Error('noncanonical_contact_page');
    return value;
}
export function validRepositoryConnection(v: unknown): v is RepositoryConnection {
    if (!shape(v, ['type', 'id', 'endpoint', 'repository', 'base_branch', 'owner_key', 'receiver_key', 'authority_key', 'issued_at', 'expires_at']))
        return false;
    let endpoint: URL;
    try {
        endpoint = new URL(String(v.endpoint));
    }
    catch {
        return false;
    }
    return v.type === 'scopeblind.repository.connection.v1' && id(v.id) && endpoint.protocol === 'https:' && endpoint.pathname === '/api/coordination' && !endpoint.search && !endpoint.hash && !endpoint.username && !endpoint.password && endpoint.href === v.endpoint && repository(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(hex) && new Set([v.owner_key, v.receiver_key, v.authority_key]).size === 3 && span(v.issued_at, v.expires_at, 30 * 86400000);
}
export function validRepositoryReadiness(v: unknown): v is RepositoryReadiness {
    if (!shape(v, ['type', 'connection_digest', 'repository', 'base_branch', 'owner_key', 'receiver_key', 'authority_key', 'checks', 'base_sha', 'check_head_sha', 'protection', 'runtime', 'workflow', 'observed_at', 'expires_at'], ['required_checks', 'workflow_sha']))
        return false;
    return v.type === 'scopeblind.repository.readiness.v1' && hex(v.connection_digest) && repository(v.repository) && repositoryBranch(v.base_branch) && [v.owner_key, v.receiver_key, v.authority_key].every(hex) && sha(v.base_sha) && sha(v.check_head_sha) && ['observed', 'unavailable'].includes(String(v.protection)) && ['local', 'github_actions'].includes(String(v.runtime)) && ['not_checked', 'missing', 'matching', 'different', 'unavailable'].includes(String(v.workflow)) && (v.workflow_sha === undefined || sha(v.workflow_sha)) && span(v.observed_at, v.expires_at, 86400000) && Array.isArray(v.checks) && v.checks.length <= 100 && v.checks.every(c => shape(c, ['name', 'app_id'], ['app_name']) && text(c.name, 100) && Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0 && (c.app_name === undefined || text(c.app_name, 100))) && (v.required_checks === undefined || Array.isArray(v.required_checks) && v.required_checks.length <= 100 && v.required_checks.every(c => shape(c, ['name', 'app_id']) && text(c.name, 100) && (c.app_id === null || Number.isSafeInteger(c.app_id) && Number(c.app_id) > 0)));
}
export function validRepositoryParticipants(v: unknown): v is RepositoryParticipants {
    return shape(v, ['type', 'task_id', 'task_digest', 'owner_key', 'receiver_key', 'reviewer_key', 'reviewer_claim_digest', 'issued_at', 'expires_at']) && v.type === 'scopeblind.repository.participants.v1' && id(v.task_id) && [v.task_digest, v.owner_key, v.receiver_key, v.reviewer_key, v.reviewer_claim_digest].every(hex) && new Set([v.owner_key, v.receiver_key, v.reviewer_key]).size === 3 && span(v.issued_at, v.expires_at, 7 * 86400000);
}
export function validRepositoryPreview(v: unknown): v is RepositoryPreview {
    return shape(v, ['type', 'task_id', 'task_digest', 'proposal_digest', 'base_sha', 'head_sha', 'merge_sha', 'tree_sha', 'path', 'before', 'after', 'renderer', 'observed_at']) && v.type === 'scopeblind.repository.preview.v1' && id(v.task_id) && hex(v.task_digest) && hex(v.proposal_digest) && [v.base_sha, v.head_sha, v.merge_sha, v.tree_sha].every(sha) && v.path === CONTACT_PATH && v.renderer === 'scopeblind.contact-page.v1' && at(v.observed_at) && [v.before, v.after].every(side => shape(side, ['model', 'blob_sha', 'content_sha256']) && validContactPage(side.model) && sha(side.blob_sha) && hex(side.content_sha256));
}
export function validRepositoryAgentGrant(v: unknown): v is RepositoryAgentGrant {
    return shape(v, ['type', 'id', 'task_id', 'task_digest', 'issuer_key', 'agent_key', 'permissions', 'issued_at', 'expires_at']) && v.type === 'scopeblind.repository.agent-grant.v1' && id(v.id) && id(v.task_id) && [v.task_digest, v.issuer_key, v.agent_key].every(hex) && v.issuer_key !== v.agent_key && Array.isArray(v.permissions) && v.permissions.length > 0 && v.permissions.length <= 2 && new Set(v.permissions).size === v.permissions.length && v.permissions.every(p => p === 'read_task' || p === 'request_revision') && v.permissions.includes('read_task') && span(v.issued_at, v.expires_at, 3600000);
}
export function validRepositoryRevisionRequest(v: unknown): v is RepositoryRevisionRequest {
    return shape(v, ['type', 'id', 'task_id', 'task_digest', 'basis_digest', 'requester_key', 'message', 'proposed', 'issued_at'], ['grant_digest']) && v.type === 'scopeblind.repository.revision-request.v1' && id(v.id) && id(v.task_id) && [v.task_digest, v.basis_digest, v.requester_key].every(hex) && (v.grant_digest === undefined || hex(v.grant_digest)) && text(v.message, 600) && validContactPage(v.proposed) && at(v.issued_at);
}
export function validRepositoryRevisionLink(v: unknown): v is RepositoryRevisionLink {
    return shape(v, ['type', 'id', 'parent_task_id', 'parent_task_digest', 'parent_basis_digest', 'request_digest', 'child_task_id', 'child_task_digest', 'owner_key', 'issued_at']) && v.type === 'scopeblind.repository.revision-link.v1' && [v.id, v.parent_task_id, v.child_task_id].every(id) && v.parent_task_id !== v.child_task_id && [v.parent_task_digest, v.parent_basis_digest, v.request_digest, v.child_task_digest, v.owner_key].every(hex) && at(v.issued_at);
}
export function validRepositoryDemoRequest(v: unknown): v is RepositoryDemoRequest {
    if (!shape(v, ['type', 'id', 'owner_key', 'receiver_key', 'authority_key', 'title', 'goal', 'proposed', 'reviewer_secret_hash', 'issued_at', 'expires_at'], ['parent_task_id', 'parent_task_digest', 'parent_basis_digest', 'revision_request_digest']))
        return false;
    const parent = ['parent_task_id', 'parent_task_digest', 'parent_basis_digest', 'revision_request_digest'];
    return v.type === 'scopeblind.repository.demo-request.v1' && id(v.id) && [v.owner_key, v.receiver_key, v.authority_key, v.reviewer_secret_hash].every(hex) && new Set([v.owner_key, v.receiver_key, v.authority_key]).size === 3 && text(v.title, 140) && text(v.goal, 600) && validContactPage(v.proposed) && span(v.issued_at, v.expires_at, 86400000) && (parent.every(k => v[k] === undefined) || id(v.parent_task_id) && [v.parent_task_digest, v.parent_basis_digest, v.revision_request_digest].every(hex));
}
export function validRepositoryDemoProvision(v: unknown): v is RepositoryDemoProvision {
    return shape(v, ['type', 'request_id', 'request_digest', 'repository', 'base_branch', 'head_branch', 'pull_number', 'initial_base_sha', 'initial_head_sha', 'receiver_key', 'required_checks', 'observed_at']) && v.type === 'scopeblind.repository.demo-provision.v1' && id(v.request_id) && [v.request_digest, v.receiver_key].every(hex) && v.repository === DEMO_REPOSITORY && v.base_branch === `scopeblind/demo/${v.request_id}/base` && v.head_branch === `scopeblind/demo/${v.request_id}/change` && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && sha(v.initial_base_sha) && sha(v.initial_head_sha) && Array.isArray(v.required_checks) && canonical(v.required_checks) === canonical([DEMO_CHECK]) && at(v.observed_at);
}
export function validRepositoryDemoCompletion(v: unknown): v is RepositoryDemoCompletion {
    return shape(v, ['type', 'job_id', 'lease_id', 'request_id', 'kind', 'status', 'observed_at'], ['provision', 'task_state', 'error']) && v.type === 'scopeblind.repository.demo-completion.v1' && [v.job_id, v.lease_id, v.request_id].every(id) && ['provision', 'inspect', 'execute', 'reconcile'].includes(String(v.kind)) && ['complete', 'failed'].includes(String(v.status)) && at(v.observed_at) && (v.error === undefined || text(v.error, 100));
}
export function repositoryRevisionBasis(state: RepositoryState): string | null { return state.acceptance?.digest ?? state.outcome?.digest ?? state.proposal?.digest ?? null; }
