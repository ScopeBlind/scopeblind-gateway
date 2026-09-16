import {
  CONTACT_PATH,
  contactPageBytes,
  repositoryRevisionBasis,
  validRepositoryAgentGrant,
  validRepositoryDemoProvision,
  validRepositoryDemoRequest,
  validRepositoryParticipants,
  validRepositoryPreview,
  validRepositoryRevisionLink,
  validRepositoryRevisionRequest,
  verifyRepositoryEvidence
} from "./chunk-62IJNG3V.mjs";
import {
  canonical,
  sha256,
  verify
} from "./chunk-VS4TVKA7.mjs";

// src/coordination-repository-collaboration-evidence.ts
var shape = (v, required, optional = []) => !!v && typeof v === "object" && !Array.isArray(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
var envelope = (v) => shape(v, ["payload", "signer", "digest", "signature"]);
var time = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
var within = (at, start, end) => Date.parse(at) >= Date.parse(start) && Date.parse(at) <= Date.parse(end);
function requireValid(condition, message) {
  if (!condition) throw new Error(message);
}
var baseLimitations = [
  "A preview is the receiver\u2019s signed observation of canonical contact-page data, rendered by ScopeBlind\u2019s fixed template. It does not execute repository code or prove a deployed website.",
  "Agent grants allow only the recorded reading and revision suggestions. They do not convey human approval or receiver execution authority.",
  "Revocation flags and the completeness of the collaboration history are statements by the service. The included record does not prove a currently live grant."
];
async function verifyRepositoryCollaborationEvidence(input, pins) {
  const result = { valid: false, accepted: false, authorityPinned: false, previewVerified: false, revisionLinked: false, errors: [], limitations: [...baseLimitations] };
  try {
    requireValid(shape(input, ["type", "repository", "collaboration"], ["demo", "parent", "parent_request", "parent_agent_grant"]) && input.type === "scopeblind.repository.collaboration-evidence.v1", "Unsupported collaboration evidence shape.");
    const bundle = input;
    const core = await verifyRepositoryEvidence(bundle.repository, pins);
    result.limitations.push(...core.limitations);
    requireValid(core.valid, core.errors.join("; "));
    result.authorityPinned = core.authorityPinned;
    const state = bundle.repository.state.payload, task = state.task.payload, collaboration = bundle.collaboration, c = collaboration?.payload;
    requireValid(envelope(collaboration) && await verify(collaboration, task.authority_key) && shape(c, ["type", "task_id", "task_digest", "participants", "preview", "requests", "revisions", "agent_grants", "observed_at"]) && c.type === "scopeblind.repository.collaboration.v1" && c.task_id === task.id && c.task_digest === state.task.digest && time(c.observed_at), "Collaboration must be signed by this task\u2019s authority and name the exact task.");
    const principals = [task.owner_key, ...state.reviewer ? [state.reviewer.payload.reviewer_key] : []];
    if (c.participants !== null) {
      const signed = c.participants, p = signed?.payload;
      requireValid(envelope(signed) && validRepositoryParticipants(p) && await verify(signed, task.owner_key) && p.task_id === task.id && p.task_digest === state.task.digest && p.owner_key === task.owner_key && p.receiver_key === task.receiver_key && p.reviewer_key === state.reviewer?.payload.reviewer_key && p.reviewer_claim_digest === state.reviewer?.digest && within(p.issued_at, task.issued_at, task.expires_at) && Date.parse(p.expires_at) <= Date.parse(task.expires_at), "The owner\u2019s participant binding does not match this task and enrolled reviewer.");
    }
    if (c.preview !== null) {
      const signed = c.preview, p = signed?.payload, proposal = state.proposal;
      requireValid(envelope(signed) && validRepositoryPreview(p) && await verify(signed, task.receiver_key) && proposal && p.task_id === task.id && p.task_digest === state.task.digest && p.proposal_digest === proposal.digest && ["base_sha", "head_sha", "merge_sha", "tree_sha"].every((k) => p[k] === proposal.payload[k]) && proposal.payload.files.some((f) => f.path === CONTACT_PATH), "The preview is not bound to this exact receiver-reviewed proposal.");
      for (const side of [p.before, p.after]) {
        const bytes = new TextEncoder().encode(contactPageBytes(side.model)), header = new TextEncoder().encode(`blob ${bytes.length}\0`), blob = new Uint8Array(header.length + bytes.length);
        blob.set(header);
        blob.set(bytes, header.length);
        const gitSha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", blob)), (n) => n.toString(16).padStart(2, "0")).join("");
        requireValid(await sha256(contactPageBytes(side.model)) === side.content_sha256 && gitSha === side.blob_sha, "Preview content does not match its canonical bytes and Git blob digest.");
      }
      requireValid(Date.parse(p.observed_at) >= Date.parse(proposal.payload.observed_at) && Date.parse(p.observed_at) <= Date.parse(c.observed_at), "Preview timing does not follow the reviewed proposal.");
      result.previewVerified = true;
    }
    requireValid(Array.isArray(c.agent_grants) && c.agent_grants.length <= 100 && Array.isArray(c.requests) && c.requests.length <= 100 && Array.isArray(c.revisions) && c.revisions.length <= 100, "Collaboration collections exceed their supported bounds.");
    const incomingLinks = c.revisions.filter((link) => link?.payload?.child_task_id === task.id);
    requireValid(incomingLinks.length <= 1 && (incomingLinks.length === 1 || !["parent", "parent_request", "parent_agent_grant"].some((key) => Object.hasOwn(bundle, key))), "Predecessor records must be consumed by exactly one incoming revision link.");
    const grants = /* @__PURE__ */ new Map(), requestIds = /* @__PURE__ */ new Set(), requests = /* @__PURE__ */ new Map();
    for (const entry of c.agent_grants) {
      const signed = entry.grant, g = signed?.payload;
      requireValid(shape(entry, ["grant", "revoked"]) && typeof entry.revoked === "boolean" && envelope(signed) && validRepositoryAgentGrant(g) && await verify(signed, g.issuer_key) && principals.includes(g.issuer_key) && ![...principals, task.receiver_key, task.authority_key].includes(g.agent_key) && g.task_id === task.id && g.task_digest === state.task.digest && within(g.issued_at, task.issued_at, task.expires_at) && Date.parse(g.issued_at) <= Date.parse(c.observed_at) && Date.parse(g.expires_at) <= Date.parse(task.expires_at) && !grants.has(signed.digest), "An agent grant is invalid, duplicated, or crosses a human/receiver boundary.");
      grants.set(signed.digest, entry);
    }
    for (const signed of c.requests) {
      const r = signed?.payload;
      requireValid(envelope(signed) && validRepositoryRevisionRequest(r) && await verify(signed, r.requester_key) && r.task_id === task.id && r.task_digest === state.task.digest && within(r.issued_at, task.issued_at, task.expires_at) && Date.parse(r.issued_at) <= Date.parse(c.observed_at) && !requestIds.has(r.id) && !requests.has(signed.digest), "A revision request is invalid or duplicated.");
      requestIds.add(r.id);
      requests.set(signed.digest, signed);
      if (principals.includes(r.requester_key)) requireValid(r.grant_digest === void 0, "A human revision must not borrow an agent grant.");
      else {
        const g = r.grant_digest ? grants.get(r.grant_digest)?.grant.payload : void 0;
        requireValid(g && g.agent_key === r.requester_key && g.permissions.includes("request_revision") && within(r.issued_at, g.issued_at, g.expires_at), "The suggesting agent did not hold the exact recorded revision scope.");
      }
    }
    let parent;
    if (bundle.parent) {
      const checked = await verifyRepositoryEvidence(bundle.parent, pins);
      requireValid(checked.valid, "The predecessor repository evidence does not verify.");
      parent = bundle.parent.state.payload;
      requireValid(parent.task.payload.owner_key === task.owner_key && parent.task.payload.receiver_key === task.receiver_key && parent.task.payload.authority_key === task.authority_key && parent.task.payload.repository === task.repository, "The predecessor crosses this repository or participant authority.");
    }
    const linkIds = /* @__PURE__ */ new Set();
    for (const signed of c.revisions) {
      const l = signed?.payload;
      requireValid(envelope(signed) && validRepositoryRevisionLink(l) && await verify(signed, task.owner_key) && l.owner_key === task.owner_key && time(l.issued_at) && Date.parse(l.issued_at) <= Date.parse(c.observed_at) && !linkIds.has(l.id), "A revision link is invalid or duplicated.");
      linkIds.add(l.id);
      if (l.child_task_id === task.id) {
        requireValid(l.child_task_digest === state.task.digest && parent && l.parent_task_id === parent.task.payload.id && l.parent_task_digest === parent.task.digest && l.parent_basis_digest === repositoryRevisionBasis(parent), "The child revision does not bind the included predecessor and exact feedback.");
        const signedRequest = bundle.parent_request, r = signedRequest?.payload, pt = parent.task.payload;
        requireValid(envelope(signedRequest) && validRepositoryRevisionRequest(r) && await verify(signedRequest, r.requester_key) && signedRequest.digest === l.request_digest && r.task_id === pt.id && r.task_digest === parent.task.digest && r.basis_digest === l.parent_basis_digest && within(r.issued_at, pt.issued_at, pt.expires_at) && Date.parse(r.issued_at) <= Date.parse(l.issued_at), "The original signed feedback is missing or does not match this revision.");
        const parentPrincipals = [pt.owner_key, ...parent.reviewer ? [parent.reviewer.payload.reviewer_key] : []];
        if (parentPrincipals.includes(r.requester_key)) requireValid(r.grant_digest === void 0 && bundle.parent_agent_grant === void 0, "Human feedback must not borrow an agent grant.");
        else {
          const signedGrant = bundle.parent_agent_grant, g = signedGrant?.payload;
          requireValid(envelope(signedGrant) && validRepositoryAgentGrant(g) && await verify(signedGrant, g.issuer_key) && signedGrant.digest === r.grant_digest && parentPrincipals.includes(g.issuer_key) && ![...parentPrincipals, pt.receiver_key, pt.authority_key].includes(g.agent_key) && g.agent_key === r.requester_key && g.task_id === pt.id && g.task_digest === parent.task.digest && g.permissions.includes("request_revision") && within(g.issued_at, pt.issued_at, pt.expires_at) && Date.parse(g.expires_at) <= Date.parse(pt.expires_at) && within(r.issued_at, g.issued_at, g.expires_at), "The original feedback agent\u2019s exact human-signed scope is missing or invalid.");
        }
        result.revisionLinked = true;
      } else {
        requireValid(l.parent_task_id === task.id && l.parent_task_digest === state.task.digest && requests.has(l.request_digest) && requests.get(l.request_digest).payload.basis_digest === l.parent_basis_digest, "The outgoing revision link does not name this task and an included suggestion.");
      }
    }
    if (bundle.demo) {
      const signed = bundle.demo, d = signed?.payload, r = d?.request?.payload, p = d?.provision?.payload;
      requireValid(envelope(signed) && await verify(signed, task.authority_key) && shape(d, ["type", "request", "provision", "task", "status", "dispatch", "error", "observed_at"]) && d.type === "scopeblind.repository.demo-state.v1" && ["queued", "provisioning", "ready_to_review", "active", "failed", "expired"].includes(d.status) && ["requested", "unconfigured", "unavailable"].includes(d.dispatch) && (d.error === null || typeof d.error === "string" && d.error.length <= 100) && time(d.observed_at), "The demo\u2019s service record is invalid.");
      requireValid(envelope(d.request) && validRepositoryDemoRequest(r) && await verify(d.request, task.owner_key) && r.id === task.id && r.owner_key === task.owner_key && r.authority_key === task.authority_key && r.receiver_key === task.receiver_key && r.reviewer_secret_hash === task.reviewer_secret_hash && r.title === task.title && Date.parse(task.expires_at) <= Date.parse(r.expires_at), "The demo request is not the task owner\u2019s exact provisioning authority.");
      requireValid(d.task && canonical(d.task) === canonical(state.task) && envelope(d.provision) && validRepositoryDemoProvision(p) && await verify(d.provision, task.receiver_key) && p.request_id === task.id && p.request_digest === d.request.digest && p.repository === task.repository && p.base_branch === task.base_branch && p.pull_number === task.pull_number && p.receiver_key === task.receiver_key && canonical(p.required_checks) === canonical(task.required_checks) && canonical(task.allowed_paths) === canonical([CONTACT_PATH]), "The provisioned workspace does not match the signed task.");
      if (c.preview) requireValid(c.preview.payload.base_sha === p.initial_base_sha && c.preview.payload.head_sha === p.initial_head_sha && canonical(c.preview.payload.after.model) === canonical(r.proposed), "The demo preview differs from the exact requested and provisioned change.");
      if (r.parent_task_id) requireValid(result.revisionLinked && parent && r.parent_task_id === parent.task.payload.id && r.parent_task_digest === parent.task.digest && r.parent_basis_digest === repositoryRevisionBasis(parent) && canonical(bundle.parent_request?.payload.proposed) === canonical(r.proposed) && c.revisions.some((l) => l.payload.child_task_id === task.id && l.payload.request_digest === r.revision_request_digest), "The demo revision lacks its exact predecessor link.");
    }
    result.valid = true;
    result.accepted = core.accepted;
  } catch (error) {
    result.errors.push(error instanceof Error ? error.message : "The collaboration evidence could not be verified.");
    result.previewVerified = false;
    result.revisionLinked = false;
    result.accepted = false;
  }
  return result;
}

export {
  verifyRepositoryCollaborationEvidence
};
