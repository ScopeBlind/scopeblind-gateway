import {
  COORDINATION_DOMAIN,
  canonical,
  hexToBytes,
  invoiceMatchesPurchaseOrder,
  payloadHash,
  sha256,
  verify
} from "./chunk-O3K3FPBT.mjs";

// src/coordination-devices.ts
var DEVICE_AUTHORIZATION_DOMAIN = "scopeblind.coordination.device-authorization.v1\n";
var DEVICE_ACTIONS = ["inspect", "decision_inbox", "negotiation_get", "decide", "accept", "negotiation_mandate", "negotiation_approve"];
var DEVICE_LINK_TTL_MS = 10 * 60 * 1e3;
var DEVICE_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1e3;
var hex = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
var id = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(value);
var object = (value) => !!value && typeof value === "object" && !Array.isArray(value);
var time = (value) => typeof value === "string" ? Date.parse(value) : NaN;
var exact = (value, fields) => Object.keys(value).sort().join(" ") === fields.split(" ").sort().join(" ");
function deviceAuthorizationPreimage(payloadDigest, authorizationDigest) {
  return DEVICE_AUTHORIZATION_DOMAIN + payloadDigest + "\n" + authorizationDigest;
}
function humanPrincipal(value) {
  return value.authorization?.payload.principal_key ?? value.signer;
}
async function verifyDeviceAuthorization(value) {
  try {
    const g = value.payload;
    return exact(value, "payload signer digest signature") && await verify(value, g.principal_key) && exact(g, "type id link_id room_id agreement_digest principal_key device_key device_name actions issued_at expires_at authority_key") && g.type === "scopeblind.coordination.device-authorization.v1" && id(g.id) && id(g.link_id) && id(g.room_id) && hex(g.agreement_digest) && hex(g.principal_key) && hex(g.device_key) && g.device_key !== g.principal_key && hex(g.authority_key) && typeof g.device_name === "string" && g.device_name.trim() === g.device_name && g.device_name.length > 0 && g.device_name.length <= 60 && Array.isArray(g.actions) && g.actions.length > 0 && g.actions.length <= DEVICE_ACTIONS.length && new Set(g.actions).size === g.actions.length && g.actions.every((action) => DEVICE_ACTIONS.includes(action)) && Number.isFinite(time(g.issued_at)) && time(g.expires_at) > time(g.issued_at) && time(g.expires_at) - time(g.issued_at) <= DEVICE_MAX_TTL_MS;
  } catch {
    return false;
  }
}
async function contextProposal(context, g) {
  const proposal = context.proposal, p = proposal?.payload;
  return proposal && p && await verify(proposal, g.authority_key) && p.type === "scopeblind.coordination.negotiation-proposal.v1" && p.room_id === g.room_id && p.agreement_digest === g.agreement_digest ? proposal : null;
}
async function humanPermission(value, context = {}) {
  const p = value.payload, g = value.authorization?.payload;
  if (!g || !object(p)) return null;
  const direct = (action) => typeof p.issued_at === "string" && p.room_id === g.room_id && (p.agreement_digest === void 0 || p.agreement_digest === g.agreement_digest) ? { action, at: p.issued_at } : null;
  switch (p.type) {
    case "scopeblind.coordination.request.v1":
      return typeof p.action === "string" && DEVICE_ACTIONS.includes(p.action) ? direct(p.action) : null;
    case "scopeblind.coordination.approval.v1":
      return direct("decide");
    case "scopeblind.coordination.acceptance.v1":
      return direct("accept");
    case "scopeblind.coordination.negotiation-mandate.v1":
      return p.principal_key === g.principal_key ? direct("negotiation_mandate") : null;
    case "scopeblind.coordination.negotiation-approval.v1": {
      const proposal = await contextProposal(context, g), q = proposal?.payload;
      return q && p.principal_key === g.principal_key && p.session_id === q.session_id && p.proposal_digest === proposal.digest && p.next_agreement_digest === q.next_agreement_digest && canonical(p.mandate_digests) === canonical(q.mandate_digests) && typeof p.issued_at === "string" ? { action: "negotiation_approve", at: p.issued_at } : null;
    }
    case "scopeblind.coordination.agreement.v1":
    case "scopeblind.coordination.grant.v1":
    case "scopeblind.coordination.claim.v1": {
      const proposal = await contextProposal(context, g), q = proposal?.payload, approval = context.approval;
      if (!q || !approval || approval.payload.decision !== "approve" || approval.authorization?.digest !== value.authorization?.digest || !await verifyHuman(approval, g.principal_key, { proposal, requireRecordedUse: context.requireRecordedUse, authorityKey: context.authorityKey })) return null;
      const exactPayload = p.type === "scopeblind.coordination.agreement.v1" ? q.next_agreement.owner_key === g.principal_key && canonical(p) === canonical(q.next_agreement) : p.type === "scopeblind.coordination.grant.v1" ? q.reviewer_grant.issuer === g.principal_key && canonical(p) === canonical(q.reviewer_grant) : p.guest_key === g.principal_key && p.room_id === q.next_agreement.id && p.grant_id === q.reviewer_grant.grant_id && typeof p.issued_at === "string" && time(p.issued_at) >= time(approval.payload.issued_at) - 3e5 && time(p.issued_at) <= time(approval.payload.expires_at);
      return exactPayload ? { action: "negotiation_approve", at: approval.payload.issued_at } : null;
    }
    default:
      return null;
  }
}
async function verifyHuman(value, expectedPrincipal, context = {}) {
  try {
    if (!value || !object(value) || Object.keys(value).some((key2) => !["payload", "signer", "digest", "signature", "authorization", "authorization_signature", "authorization_use"].includes(key2))) return false;
    if (!value.authorization) return !value.authorization_signature && !value.authorization_use && await verify(value, expectedPrincipal);
    const authorization = value.authorization, g = authorization.payload;
    if (context.authorityKey !== void 0 && g.authority_key !== context.authorityKey) return false;
    if (!await verify(value) || !await verifyDeviceAuthorization(authorization) || g.principal_key !== expectedPrincipal || g.device_key !== value.signer || typeof value.authorization_signature !== "string" || !/^[0-9a-f]{128}$/.test(value.authorization_signature)) return false;
    const key = await crypto.subtle.importKey("raw", hexToBytes(value.signer), { name: "Ed25519" }, false, ["verify"]);
    if (!await crypto.subtle.verify("Ed25519", key, hexToBytes(value.authorization_signature), new TextEncoder().encode(deviceAuthorizationPreimage(value.digest, authorization.digest)))) return false;
    const permission = await humanPermission(value, context);
    if (!permission || !g.actions.includes(permission.action) || time(permission.at) < time(g.issued_at) - 3e5 || time(permission.at) >= time(g.expires_at)) return false;
    const p = value.payload;
    if (p.expires_at !== void 0 && !["scopeblind.coordination.grant.v1", "scopeblind.coordination.agreement.v1"].includes(String(p.type)) && (!Number.isFinite(time(p.expires_at)) || time(p.expires_at) > time(g.expires_at))) return false;
    const use = value.authorization_use;
    if (!use) return !context.requireRecordedUse;
    const u = use.payload;
    return exact(use, "payload signer digest signature") && await verify(use, g.authority_key) && exact(u, "type authorization_digest principal_key device_key room_id payload_digest action recorded_at") && u.type === "scopeblind.coordination.device-use.v1" && u.authorization_digest === authorization.digest && u.principal_key === g.principal_key && u.device_key === g.device_key && u.room_id === g.room_id && u.payload_digest === value.digest && u.action === permission.action && time(u.recorded_at) >= time(g.issued_at) && time(u.recorded_at) < time(g.expires_at) && time(u.recorded_at) >= time(permission.at) - 3e5;
  } catch {
    return false;
  }
}

// src/coordination-rehearsal.ts
var REHEARSAL_ACTIONS = ["rehearsal_get", "rehearsal_case", "rehearsal_run", "rehearsal_propose"];
var kinds = /* @__PURE__ */ new Set(["invoice", "approved_invoice", "duplicate_invoice", "changed_approval", "changed_destination", "expired_approval", "budget_cap"]);
var outcomes = /* @__PURE__ */ new Set(["allow", "ask", "refuse", "invariant"]);
function parseRehearsalCase(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_rehearsal_case");
  const v = value;
  if (Object.keys(v).some((k) => !["id", "title", "kind", "invoice_id", "amount_minor", "expected", "requirement", "required"].includes(k)) || typeof v.id !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(v.id) || typeof v.title !== "string" || !v.title.trim() || v.title.length > 120 || typeof v.kind !== "string" || !kinds.has(v.kind) || typeof v.invoice_id !== "string" || !/^[A-Za-z0-9_-]{1,60}$/.test(v.invoice_id) || typeof v.expected !== "string" || !outcomes.has(v.expected) || typeof v.requirement !== "string" || !v.requirement.trim() || v.requirement.length > 400 || v.amount_minor !== void 0 && (!Number.isSafeInteger(v.amount_minor) || Number(v.amount_minor) < 1 || Number(v.amount_minor) > 1e7) || v.required !== void 0 && typeof v.required !== "boolean") throw new Error("invalid_rehearsal_case");
  if (v.kind === "invoice" === (v.expected === "invariant")) throw new Error("invalid_rehearsal_expectation");
  if (v.amount_minor !== void 0 && ["changed_approval", "expired_approval", "budget_cap"].includes(v.kind)) throw new Error("rehearsal_amount_not_supported");
  return {
    id: v.id,
    title: v.title.trim(),
    kind: v.kind,
    invoice_id: v.invoice_id,
    ...v.amount_minor !== void 0 ? { amount_minor: Number(v.amount_minor) } : {},
    expected: v.expected,
    requirement: v.requirement.trim(),
    ...v.required !== void 0 ? { required: v.required } : {}
  };
}
function parseRepairProposal(value, budget) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_repair_proposal");
  const v = value;
  if (Object.keys(v).some((k) => !["id", "approval_above_minor", "rationale"].includes(k)) || typeof v.id !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(v.id) || !Number.isSafeInteger(v.approval_above_minor) || Number(v.approval_above_minor) < 0 || Number(v.approval_above_minor) > budget || typeof v.rationale !== "string" || !v.rationale.trim() || v.rationale.length > 600) throw new Error("invalid_repair_proposal");
  return { id: v.id, approval_above_minor: Number(v.approval_above_minor), rationale: v.rationale.trim() };
}
function defaultRehearsalCases(fixtures) {
  const invoice = fixtures.invoices.find((i) => !i.duplicate_of);
  const make = (id3, title, kind, requirement) => ({ id: `required-${id3}`, title, kind, invoice_id: invoice.invoice_id, expected: "invariant", requirement, required: true });
  return [
    make("valid", "A legitimate payment can complete", "approved_invoice", "An exact, authorized invoice can be paid once. Required review must not prevent approved work from completing."),
    make("duplicate", "Submit the same invoice twice", "duplicate_invoice", "A second operation for an already-paid invoice must not create another payment."),
    make("changed", "Change the amount after approval", "changed_approval", "Approval for one exact request must not authorize a changed amount."),
    make("destination", "Change the payment destination", "changed_destination", "A payment to a destination outside the approved vendor record must be refused."),
    make("expired", "Use an expired approval", "expired_approval", "An expired exact approval cannot authorize a payment that needs review."),
    make("budget", "Go over the total budget", "budget_cap", "The aggregate budget cannot be exceeded, even with separate operations and exact approvals.")
  ];
}
async function rehearsalDigest(value) {
  return sha256(canonical(value));
}
async function verifyRehearsalEvidence(bundle, pin) {
  const checks = [];
  const add = (label, ok) => checks.push({ label, ok: !!ok });
  try {
    add("Recognized rehearsal evidence", bundle.type === "scopeblind.coordination.rehearsal-evidence.v1");
    const a = bundle.agreement.payload, r = bundle.report.payload;
    add("Bounded invoice agreement and case set", a.type === "scopeblind.coordination.agreement.v1" && a.currency === "USD" && Number.isSafeInteger(a.budget_minor) && a.budget_minor > 0 && a.budget_minor <= 1e7 && Number.isSafeInteger(a.approval_above_minor) && a.approval_above_minor >= 0 && a.approval_above_minor <= a.budget_minor && Array.isArray(bundle.cases) && bundle.cases.length >= 6 && bundle.cases.length <= 30 && new Set(bundle.cases.map((c) => c.id)).size === bundle.cases.length && bundle.cases.every((c) => canonical(parseRehearsalCase(c)) === canonical(c)));
    add("Owner signed the source agreement", await verifyOwnerAgreement(bundle.agreement, bundle.source_negotiation) && (bundle.agreement.authorization ? !!bundle.source_negotiation : bundle.source_negotiation === void 0));
    add("Named authority signed the report", await verify(bundle.report, pin || a.registrar_key));
    add("Report authority matches the agreement", bundle.report.signer === a.registrar_key);
    add("Report binds this agreement and room", r.type === "scopeblind.coordination.rehearsal-report.v1" && r.agreement_digest === bundle.agreement.digest && r.room_id === a.id);
    add("Exact source fixtures and included cases are present", r.fixture_digest === await rehearsalDigest(bundle.fixtures) && r.cases_digest === await rehearsalDigest(bundle.cases));
    add("Report includes each case exactly once", r.results.length === bundle.cases.length && canonical(r.results.map((x) => x.case)) === canonical(bundle.cases));
    add("Declared isolation and adapter are explicit", r.isolation === "separate-fixture-ledgers" && r.adapter === "coordination-d1-sandbox" && r.runtime_revision.length > 0);
    add("Source threshold matches the tested version", r.before_approval_above_minor === a.approval_above_minor);
    if (bundle.proposal) {
      const p = bundle.proposal.payload;
      add("Authority recorded the exact proposed change", await verify(bundle.proposal, a.registrar_key) && p.type === "scopeblind.coordination.repair-proposal.v1");
      add("Proposal and report share the same source and cases", r.proposal_digest === bundle.proposal.digest && p.room_id === a.id && p.agreement_digest === bundle.agreement.digest && p.fixture_digest === r.fixture_digest && p.cases_digest === r.cases_digest);
      add("Proposed threshold matches the comparison", p.previous_approval_above_minor === a.approval_above_minor && p.approval_above_minor === r.after_approval_above_minor && Number.isSafeInteger(p.approval_above_minor) && p.approval_above_minor >= 0 && p.approval_above_minor <= a.budget_minor);
    } else add("Baseline report claims no proposed version", r.proposal_digest === void 0 && r.after_approval_above_minor === void 0);
    const selected = r.results.map((x) => bundle.proposal ? x.after : x.before);
    add("Every compared case has an observation", selected.every(Boolean) && r.results.every((x) => !!x.before && (!bundle.proposal ? x.after === void 0 : true)));
    const sound = (c, o) => o && typeof o.reason === "string" && o.reason.length <= 2e3 && Array.isArray(o.steps) && o.steps.length > 0 && o.steps.length <= 50 && o.steps.every((s) => typeof s.action === "string" && s.action.length <= 200 && typeof s.reason === "string" && s.reason.length <= 2e3 && ["allow", "ask", "refuse", "confirmed", "rejected"].includes(s.decision)) && Number.isSafeInteger(o.payments) && o.payments >= 0 && Number.isSafeInteger(o.spent_minor) && o.spent_minor >= 0 && ["allow", "ask", "refuse", "error"].includes(o.actual) && !(o.actual === "error" && o.matched) && o.matched === (c.expected === "invariant" ? o.invariant_passed === true : o.actual === c.expected);
    add("Observation summaries agree with stated expectations", r.results.every((x) => sound(x.case, x.before) && (!x.after || sound(x.case, x.after))));
    add("Required safety cases remain included", defaultRehearsalCases(bundle.fixtures).every((c) => bundle.cases.some((x) => canonical(x) === canonical(c))));
    add("Required-case and expectation totals match the observations", r.required_passed === r.results.every((x, i) => !x.case.required || selected[i]?.matched === true) && r.expectations_met === selected.every((x) => x?.matched === true));
    if (bundle.adoption) {
      const d = bundle.adoption.payload, authorization = bundle.adoption_authorization, next = bundle.adopted_agreement;
      add("Authority recorded adoption of this exact report", await verify(bundle.adoption, a.registrar_key) && d.type === "scopeblind.coordination.rehearsal-adoption.v1" && d.source_room_id === a.id && d.source_agreement_digest === bundle.agreement.digest && d.report_digest === bundle.report.digest && d.proposal_digest === bundle.proposal?.digest && d.fixture_digest === r.fixture_digest && d.cases_digest === r.cases_digest && d.owner_key === a.owner_key && d.scope === "new-separate-sample-task");
      add("Owner signed adoption of the exact report and new agreement", authorization && next && await verify(authorization, a.owner_key) && await verify(next, a.owner_key) && authorization.digest === d.authorization_digest && authorization.payload.type === "scopeblind.coordination.request.v1" && authorization.payload.action === "rehearsal_adopt" && authorization.payload.room_id === a.id && authorization.payload.body.report_digest === bundle.report.digest && authorization.payload.body.proposal_id === bundle.proposal?.payload.id && canonical(authorization.payload.body.agreement) === canonical(next) && next.digest === d.agreement_digest && next.payload.id === d.room_id && next.payload.id !== a.id);
      add("Only the tested threshold changed in the new task", next && bundle.proposal && canonical(next.payload) === canonical({ ...a, id: next.payload.id, issued_at: next.payload.issued_at, approval_above_minor: bundle.proposal.payload.approval_above_minor }) && r.required_passed && r.expectations_met);
    } else add("No unbound adoption claims are present", !bundle.adoption_authorization && !bundle.adopted_agreement);
  } catch {
    add("Complete, well-formed rehearsal evidence", false);
  }
  return { valid: checks.every((x) => x.ok), checks, errors: checks.filter((x) => !x.ok).map((x) => x.label), limitations: [
    "These are concrete checks against isolated sample ledgers, not proof for every possible input or another deployment.",
    "The named ScopeBlind authority attests to observed gate behavior. Signatures establish integrity and key control, not independent observation or legal identity.",
    "Proposed changes grant no authority by themselves. A new sample task has its own ledger; earlier work and payments remain unchanged."
  ] };
}

// src/coordination-negotiation.ts
var NEGOTIATION_MAX_PROPOSALS = 3;
var NEGOTIATION_MAX_MODEL_STEPS = 6;
var NEGOTIATION_AGENT_ACTIONS = ["negotiation_get", "negotiation_propose", "negotiation_respond", "negotiation_compare"];
var NEGOTIATION_ACTIONS = [
  ...NEGOTIATION_AGENT_ACTIONS,
  "negotiation_create",
  "negotiation_claim",
  "negotiation_mandate",
  "negotiation_approve",
  "negotiation_adopt",
  "negotiation_pair_create",
  "negotiation_pair_claim",
  "negotiation_pair_revoke",
  "negotiation_step",
  "negotiation_cancel"
];
var negotiationDigest = (value) => sha256(canonical(value));
var negotiationPayloadDigest = (value) => sha256(COORDINATION_DOMAIN + canonical(value));
async function privateBriefCommitment(brief) {
  return sha256("scopeblind.negotiation.private-brief.v1\n" + canonical(brief));
}
function parseNegotiationBrief(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_private_brief");
  const v = value;
  if (!["preference,salt,text", "budget_preference,preference,salt,text"].includes(Object.keys(v).sort().join(",")) || v.budget_preference !== void 0 && !["preserve_budget", "lower_budget", "more_capacity"].includes(String(v.budget_preference)) || typeof v.text !== "string" || v.text.length > 2e3 || !["fewer_reviews", "more_review", "balanced"].includes(String(v.preference)) || typeof v.salt !== "string" || !/^[0-9a-f]{64}$/.test(v.salt)) throw new Error("invalid_private_brief");
  canonical(v);
  return v;
}
function mandateCases(mandates, fixtures) {
  return [...defaultRehearsalCases(fixtures), ...mandates.some((m) => m.payload.min_budget_minor !== void 0) ? fixtures.invoices.filter((i) => !i.duplicate_of).map((i, index) => ({ id: `sample-invoice-${index}`, title: `${i.invoice_id} \xB7 sample outcome`, kind: "invoice", invoice_id: i.invoice_id, expected: "allow", required: false, requirement: "Observe this sample invoice in isolation; its outcome is not a hard requirement." })) : [], ...mandates.flatMap((m, side) => m.payload.required_invoices.map((r, index) => ({
    id: `principal-${side}-${index}`,
    title: `${r.invoice_id} \xB7 ${r.expected === "allow" ? "keep moving" : "needs review"}`,
    kind: "invoice",
    invoice_id: r.invoice_id,
    expected: r.expected,
    requirement: `Required by ${side === 0 ? "the organizer" : "the partner"}.`,
    required: true
  })))];
}
function mandateBudget(m, sourceBudget) {
  return { min: m.min_budget_minor ?? sourceBudget, max: m.max_budget_minor ?? sourceBudget };
}
function negotiationPlanWithinMandate(m, threshold, budget, sourceBudget) {
  const range = mandateBudget(m, sourceBudget);
  return Number.isSafeInteger(threshold) && Number.isSafeInteger(budget) && budget >= range.min && budget <= range.max && threshold >= m.min_threshold_minor && threshold <= m.max_threshold_minor && threshold <= budget;
}
var HEX = /^[0-9a-f]{64}$/;
var id2 = (v, max = 100) => typeof v === "string" && /^[A-Za-z0-9_-]+$/.test(v) && v.length >= 8 && v.length <= max;
var integer = (v, min, max) => Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max;
var time2 = (v) => typeof v === "string" ? Date.parse(v) : NaN;
var exact2 = (v, required, optional = []) => !!v && typeof v === "object" && !Array.isArray(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
var same = (a, b) => canonical(a) === canonical(b);
var keys = (s) => s.split(" ");
var text = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max;
async function signed(v, key) {
  return exact2(v, keys("payload signer digest signature")) && HEX.test(key) && await verify(v, key);
}
function boundedAgreement(a) {
  return exact2(a, keys("type id version title owner_key registrar_key currency budget_minor approval_above_minor approval_ttl_seconds allowed_destinations issued_at"), keys("mode brief preferences assumptions require_po_match")) && a.type === "scopeblind.coordination.agreement.v1" && id2(a.id) && a.version === 1 && text(a.title, 200) && HEX.test(a.owner_key) && HEX.test(a.registrar_key) && a.currency === "USD" && integer(a.budget_minor, 1, 1e7) && integer(a.approval_above_minor, 0, a.budget_minor) && integer(a.approval_ttl_seconds, 30, 900) && Number.isFinite(time2(a.issued_at)) && Array.isArray(a.allowed_destinations) && a.allowed_destinations.length > 0 && a.allowed_destinations.length <= 100 && new Set(a.allowed_destinations).size === a.allowed_destinations.length && a.allowed_destinations.every((d) => text(d, 500)) && (a.mode === void 0 || ["guided", "live"].includes(a.mode)) && (a.require_po_match === void 0 || typeof a.require_po_match === "boolean") && (a.brief === void 0 || typeof a.brief === "string" && a.brief.length <= 1e4) && [a.preferences, a.assumptions].every((v) => v === void 0 || Array.isArray(v) && v.length <= 100 && v.every((t) => typeof t === "string" && t.length <= 2e3));
}
function boundedFixtures(f) {
  return exact2(f, keys("revision invoices purchase_orders")) && integer(f.revision, 1, 1e7) && Array.isArray(f.invoices) && f.invoices.length > 0 && f.invoices.length <= 100 && f.invoices.some((i) => !i.duplicate_of) && new Set(f.invoices.filter((i) => !i.duplicate_of).map((i) => i.invoice_id)).size === f.invoices.filter((i) => !i.duplicate_of).length && f.invoices.every((i) => !i.duplicate_of || f.invoices.some((base) => !base.duplicate_of && base.id === i.duplicate_of && base.invoice_id === i.invoice_id && base.amount_minor === i.amount_minor && base.destination === i.destination && base.vendor === i.vendor)) && new Set(f.invoices.map((i) => i.id)).size === f.invoices.length && f.invoices.every((i) => exact2(i, keys("id invoice_id vendor description amount_minor destination"), keys("duplicate_of purchase_order_id")) && text(i.id, 100) && text(i.invoice_id, 60) && text(i.vendor, 300) && typeof i.description === "string" && i.description.length <= 2e3 && integer(i.amount_minor, 1, 1e7) && text(i.destination, 500) && (i.duplicate_of === void 0 || text(i.duplicate_of, 60)) && (i.purchase_order_id === void 0 || text(i.purchase_order_id, 100))) && Array.isArray(f.purchase_orders) && f.purchase_orders.length <= 100 && new Set(f.purchase_orders.map((p) => p.id)).size === f.purchase_orders.length && f.purchase_orders.every((p) => exact2(p, keys("id vendor destination amount_minor currency")) && text(p.id, 100) && text(p.vendor, 300) && text(p.destination, 500) && integer(p.amount_minor, 1, 1e7) && p.currency === "USD");
}
function observationConsistent(c, o, a, f) {
  if (!exact2(o, keys("actual matched reason steps payments spent_minor"), ["invariant_passed"]) || !["allow", "ask", "refuse", "error"].includes(o.actual) || typeof o.matched !== "boolean" || typeof o.reason !== "string" || o.reason.length > 2e3 || !integer(o.payments, 0, 2) || !integer(o.spent_minor, 0, 2e7) || !Array.isArray(o.steps) || o.steps.length < 1 || o.steps.length > 50 || !o.steps.every((s) => exact2(s, keys("action decision reason"), keys("operation_id payload_hash")) && ["setup", "admit", "submit_changed_request", "approve_exact", "submit_expired_approval", "execute"].includes(s.action) && ["allow", "ask", "refuse", "confirmed", "rejected"].includes(s.decision) && typeof s.reason === "string" && s.reason.length <= 2e3 && (s.operation_id === void 0 || id2(s.operation_id)) && (s.payload_hash === void 0 || HEX.test(s.payload_hash)))) return false;
  if (c.expected === "invariant" ? typeof o.invariant_passed !== "boolean" : o.invariant_passed !== void 0) return false;
  if (o.matched !== (c.expected === "invariant" ? o.invariant_passed === true : o.actual === c.expected)) return false;
  if (o.actual === "error") return !o.matched && o.invariant_passed !== true;
  const original = f.invoices.find((i) => i.invoice_id === c.invoice_id);
  if (!original) return false;
  let amount = c.amount_minor ?? original.amount_minor;
  if (c.kind !== "invoice" && c.amount_minor === void 0) amount = Math.min(amount, a.budget_minor);
  if (c.kind === "budget_cap") amount = Math.floor(a.budget_minor / 2) + 1;
  if (["changed_approval", "expired_approval"].includes(c.kind) && a.mode !== "live" && !a.require_po_match && a.approval_above_minor < a.budget_minor) amount = a.approval_above_minor + 1;
  const admissions = o.steps.filter((s) => s.action === "admit" || s.action === "submit_changed_request"), first = admissions[0], last = admissions.at(-1);
  const executed = o.steps.filter((s) => s.action === "execute" && s.decision === "confirmed");
  if (!first || !last || o.payments !== executed.length || o.spent_minor !== amount * o.payments) return false;
  if (executed.some((s) => !s.operation_id || !s.payload_hash || !o.steps.slice(0, o.steps.indexOf(s)).some((p) => (p.action === "admit" || p.action === "submit_changed_request") && p.decision === "allow" && p.operation_id === s.operation_id && p.payload_hash === s.payload_hash))) return false;
  let invariant = false;
  if (c.kind === "invoice") {
    const order = f.purchase_orders.find((p) => p.id === original.purchase_order_id);
    const poMatches = c.amount_minor !== void 0 || !!order && order.amount_minor === amount && order.vendor === original.vendor && order.destination === original.destination && order.currency === "USD";
    const expectedGate = !a.allowed_destinations.includes(original.destination) || amount > a.budget_minor ? "refuse" : amount > a.approval_above_minor || a.require_po_match === true && !poMatches ? "ask" : "allow";
    return o.actual === expectedGate && o.actual === first.decision && admissions.length === 1 && o.payments <= 1;
  }
  if (c.kind === "approved_invoice") {
    invariant = o.payments === 1 && o.spent_minor === amount;
    if (o.actual !== (executed.length ? "allow" : "refuse")) return false;
  } else if (c.kind === "duplicate_invoice" || c.kind === "budget_cap") {
    if (o.actual !== last.decision || admissions.length < 2) return false;
    invariant = executed.length > 0 && last.decision !== "allow" && o.payments === 1 && o.spent_minor <= a.budget_minor;
  } else if (c.kind === "changed_destination") {
    if (o.actual !== last.decision) return false;
    invariant = last.decision === "refuse" && o.payments === 0;
  } else if (c.kind === "changed_approval") {
    if (first.decision === "ask") {
      if (o.actual !== last.decision) return false;
      invariant = o.steps.some((s) => s.action === "approve_exact" && s.decision === "allow") && last.action === "submit_changed_request" && last.decision !== "allow" && o.payments === 0;
    } else if (first.decision === "allow") {
      invariant = last.decision === "rejected" && last.reason === "operation_id_payload_mismatch" && o.payments === 0;
      if (o.actual !== (invariant ? "refuse" : "allow")) return false;
    } else if (o.actual !== "refuse") return false;
  } else if (c.kind === "expired_approval") {
    if (o.actual !== last.decision) return false;
    const expired = o.steps.find((s) => s.action === "submit_expired_approval");
    invariant = expired?.decision === "rejected" && expired.reason === "invalid_approval_expiry" && (!(a.require_po_match === true || amount > a.approval_above_minor) || last.decision !== "allow") && o.payments === 0;
  }
  return o.invariant_passed === invariant;
}
async function verifyNegotiationEvidence(value, authorityKey, depth = 0) {
  const checks = [];
  const add = (name, passed) => checks.push({ name, passed: !!passed });
  try {
    if (depth > 4) throw new Error("Device agreement lineage exceeds supported depth");
    const e = value;
    add("Recognized public negotiation export with no private context", exact2(e, keys("type session invitation binding agreement fixtures mandates proposals responses report approvals"), keys("adoption adopted_agreement reviewer_grant reviewer_binding agent_bindings source_negotiation")) && e.type === "scopeblind.coordination.negotiation-evidence.v1");
    add("Device-signed source has only its required bounded lineage", e.agreement.authorization ? !!e.source_negotiation : e.source_negotiation === void 0);
    const a = e.agreement.payload, s = e.session.payload, i = e.invitation.payload, b = e.binding.payload;
    const authority = authorityKey ?? a.registrar_key;
    add("Owner signed the bounded source agreement and exact fixture snapshot", boundedAgreement(a) && boundedFixtures(e.fixtures) && await verifyOwnerAgreement(e.agreement, e.source_negotiation, depth + 1) && a.registrar_key === authority);
    add("Named authority signed a bounded session tied to this source", await signed(e.session, authority) && exact2(s, keys("type id room_id agreement_digest fixture_digest owner_key registrar_key invitation_digest created_at expires_at max_proposals"), ["parent_session_id", "source_operation_id", "source_invoice_id", "source_operation_digest"]) && s.type === "scopeblind.coordination.negotiation-session.v1" && id2(s.id) && s.room_id === a.id && s.agreement_digest === e.agreement.digest && s.fixture_digest === await negotiationDigest(e.fixtures) && (s.parent_session_id === void 0 || id2(s.parent_session_id) && s.parent_session_id !== s.id) && s.parent_session_id === i.parent_session_id && s.source_operation_id === i.source_operation_id && (s.source_operation_id === void 0 ? s.source_invoice_id === void 0 && s.source_operation_digest === void 0 : id2(s.source_operation_id) && text(s.source_invoice_id, 60) && HEX.test(s.source_operation_digest ?? "") && e.fixtures.invoices.some((v) => !v.duplicate_of && v.invoice_id === s.source_invoice_id)) && s.owner_key === a.owner_key && s.registrar_key === authority && s.invitation_digest === e.invitation.digest && s.max_proposals === 3 && time2(s.created_at) >= time2(a.issued_at) - 3e5 && time2(s.expires_at) > time2(s.created_at) && time2(s.expires_at) <= time2(s.created_at) + 864e5);
    const during = (at) => time2(at) >= time2(s.created_at) - 3e5 && time2(at) < time2(s.expires_at);
    add("Owner invited one counterparty for this exact session", await signed(e.invitation, a.owner_key) && exact2(i, keys("type session_id room_id agreement_digest fixture_digest issuer registrar_key role token_hash max_claims expires_at"), ["parent_session_id", "source_operation_id"]) && i.type === "scopeblind.coordination.negotiation-invitation.v1" && i.session_id === s.id && i.room_id === a.id && i.agreement_digest === e.agreement.digest && i.fixture_digest === s.fixture_digest && i.issuer === a.owner_key && i.registrar_key === authority && i.role === "counterparty" && i.max_claims === 1 && HEX.test(i.token_hash) && i.expires_at === s.expires_at);
    const claim = b.claim.payload, partner = b.guest_key, principals = [a.owner_key, partner];
    add("Distinct counterparty signed its claim and the authority bound that claim", await signed(e.binding, authority) && await signed(b.claim, partner) && exact2(b, keys("type session_id room_id invitation_digest guest_key name issued_at expires_at claim")) && b.type === "scopeblind.coordination.negotiation-binding.v1" && b.session_id === s.id && b.room_id === a.id && b.invitation_digest === e.invitation.digest && HEX.test(partner) && partner !== a.owner_key && during(b.issued_at) && b.expires_at === s.expires_at && exact2(claim, keys("type session_id room_id guest_key name issued_at nonce")) && claim.type === "scopeblind.coordination.negotiation-claim.v1" && claim.session_id === s.id && claim.room_id === a.id && claim.guest_key === partner && text(claim.name, 60) && claim.name === b.name && id2(claim.nonce) && Math.abs(time2(claim.issued_at) - time2(b.issued_at)) <= 3e5);
    add("Exactly two distinct principal mandates are included in organizer/partner order", Array.isArray(e.mandates) && e.mandates.length === 2 && e.mandates.every((m, n) => m.payload.principal_key === principals[n]) && new Set(e.mandates.map((m) => m.digest)).size === 2);
    const mandateDigests = e.mandates.map((m) => m.digest);
    for (let n = 0; n < e.mandates.length; n++) {
      const m = e.mandates[n].payload;
      add(`Principal ${n + 1} signed bounded negotiation-only authority`, await verifyHuman(e.mandates[n], principals[n], { requireRecordedUse: true, authorityKey: authority }) && exact2(m, keys("type session_id room_id principal_key version agreement_digest fixture_digest min_threshold_minor max_threshold_minor required_invoices private_brief_commitment agent_mode actions issued_at expires_at"), ["min_budget_minor", "max_budget_minor"]) && m.type === "scopeblind.coordination.negotiation-mandate.v1" && m.session_id === s.id && m.room_id === a.id && m.principal_key === principals[n] && m.agreement_digest === e.agreement.digest && m.fixture_digest === s.fixture_digest && integer(m.version, 1, 1e6) && (m.min_budget_minor === void 0 && m.max_budget_minor === void 0 || integer(m.min_budget_minor, 1, 1e7) && integer(m.max_budget_minor, m.min_budget_minor, 1e7)) && integer(m.min_threshold_minor, 0, mandateBudget(m, a.budget_minor).max) && integer(m.max_threshold_minor, m.min_threshold_minor, mandateBudget(m, a.budget_minor).max) && Array.isArray(m.required_invoices) && m.required_invoices.length <= 2 && new Set(m.required_invoices.map((r2) => r2.invoice_id)).size === m.required_invoices.length && m.required_invoices.every((r2) => exact2(r2, keys("invoice_id expected")) && ["allow", "ask"].includes(r2.expected) && e.fixtures.invoices.some((v) => v.invoice_id === r2.invoice_id && !v.duplicate_of)) && (s.source_invoice_id === void 0 || m.required_invoices.some((r2) => r2.invoice_id === s.source_invoice_id)) && HEX.test(m.private_brief_commitment) && ["hosted", "own", "manual"].includes(m.agent_mode) && same(m.actions, NEGOTIATION_AGENT_ACTIONS) && during(m.issued_at) && time2(m.expires_at) > time2(m.issued_at) && time2(m.expires_at) <= time2(s.expires_at));
    }
    const validAt = (principal, at) => {
      const m = e.mandates.find((m2) => m2.payload.principal_key === principal)?.payload;
      return !!m && during(at) && time2(at) >= time2(m.issued_at) - 3e5 && time2(at) < time2(m.expires_at);
    };
    const agentBindings = e.agent_bindings ?? [];
    add("Installed agent bindings are bounded and independently scoped per principal", Array.isArray(agentBindings) && agentBindings.length <= 12 && new Set(agentBindings.map((v) => v.payload.pair_id)).size === agentBindings.length);
    for (const binding of agentBindings) {
      const g = binding.payload, auth = g.owner_authorization, q = auth.payload, body = q.body, principal = g.principal_key;
      add("Principal signed the installed agent pairing authorization", await signed(binding, authority) && await signed(auth, principal) && exact2(g, keys("type pair_id room_id session_id principal_key agreement_digest owner_key agent_key name scope audience issued_at expires_at owner_authorization")) && g.type === "scopeblind.coordination.agent-binding.v1" && g.audience === "scopeblind.coordination.negotiation" && id2(g.pair_id) && g.room_id === a.id && g.session_id === s.id && principals.includes(principal) && g.owner_key === principal && HEX.test(g.agent_key) && !principals.includes(g.agent_key) && g.agreement_digest === e.agreement.digest && same(g.scope, NEGOTIATION_AGENT_ACTIONS) && validAt(principal, g.issued_at) && time2(g.expires_at) > time2(g.issued_at) && time2(g.expires_at) <= time2(e.mandates.find((m) => m.payload.principal_key === principal).payload.expires_at) && exact2(q, keys("type action room_id body issued_at nonce")) && q.type === "scopeblind.coordination.request.v1" && q.action === "negotiation_pair_create" && q.room_id === a.id && id2(q.nonce) && exact2(body, keys("session_id pair_id secret_hash name expires_at token_expires_at scope"), ["expected_agent_key"]) && (body.expected_agent_key === void 0 || body.expected_agent_key === g.agent_key) && body.session_id === s.id && body.pair_id === g.pair_id && HEX.test(String(body.secret_hash)) && text(body.name, 60) && text(g.name, 60) && same(body.scope, NEGOTIATION_AGENT_ACTIONS) && body.token_expires_at === g.expires_at && validAt(principal, q.issued_at) && time2(body.expires_at) > time2(q.issued_at) && time2(body.expires_at) <= time2(q.issued_at) + 9e5 && time2(g.issued_at) < time2(body.expires_at) && time2(g.issued_at) >= time2(q.issued_at) - 3e5 && time2(body.expires_at) <= time2(g.expires_at) && !agentBindings.some((other) => other.payload.agent_key === g.agent_key && other.payload.principal_key !== principal));
    }
    const actorBound = (p2) => {
      const mandate = e.mandates.find((m) => m.payload.principal_key === p2.principal_key)?.payload;
      if (!mandate || !validAt(p2.principal_key, p2.issued_at)) return false;
      if (p2.agent_mode === "manual") return p2.agent_key === void 0;
      if (p2.agent_mode === "hosted") return mandate.agent_mode === "hosted" && p2.agent_key === void 0;
      return p2.agent_mode === "own" && mandate.agent_mode === "own" && agentBindings.some((v) => v.payload.agent_key === p2.agent_key && v.payload.principal_key === p2.principal_key && time2(p2.issued_at) >= time2(v.payload.issued_at) && time2(p2.issued_at) < time2(v.payload.expires_at));
    };
    add("At most three uniquely identified proposals are included", Array.isArray(e.proposals) && e.proposals.length >= 1 && e.proposals.length <= 3 && new Set(e.proposals.map((p2) => p2.payload.id)).size === e.proposals.length);
    for (let n = 0; n < e.proposals.length; n++) {
      const envelope = e.proposals[n], p2 = envelope.payload, mine = e.mandates.find((m) => m.payload.principal_key === p2.principal_key)?.payload, g = p2.reviewer_grant;
      add(`Candidate ${n + 1} has a signed source, parent and principal authority`, await signed(envelope, authority) && exact2(p2, keys("type id approval_above_minor session_id room_id round principal_key agent_mode agreement_digest fixture_digest mandate_digests next_agreement next_agreement_digest reviewer_grant reviewer_grant_digest issued_at"), keys("parent_digest agent_key budget_minor exploration")) && p2.type === "scopeblind.coordination.negotiation-proposal.v1" && typeof p2.id === "string" && /^[A-Za-z0-9_-]{1,80}$/.test(p2.id) && p2.session_id === s.id && p2.room_id === a.id && p2.round === n + 1 && p2.parent_digest === e.proposals[n - 1]?.digest && p2.agreement_digest === e.agreement.digest && p2.fixture_digest === s.fixture_digest && same(p2.mandate_digests, mandateDigests) && (p2.exploration === void 0 || p2.exploration === true && p2.agent_mode === "manual" && !p2.agent_key) && !!mine && negotiationPlanWithinMandate(mine, p2.approval_above_minor, p2.budget_minor ?? a.budget_minor, a.budget_minor) && actorBound(p2) && (n === 0 || time2(p2.issued_at) >= time2(e.proposals[n - 1].payload.issued_at)));
      add(`Candidate ${n + 1} changes only the tested threshold and authorized budget in a separate task`, boundedAgreement(p2.next_agreement) && p2.next_agreement.id !== a.id && same(p2.next_agreement, { ...a, id: p2.next_agreement.id, issued_at: p2.issued_at, approval_above_minor: p2.approval_above_minor, budget_minor: p2.budget_minor ?? a.budget_minor }) && p2.next_agreement_digest === await negotiationPayloadDigest(p2.next_agreement));
      add(`Candidate ${n + 1} fixes the partner's future reviewer role before approval`, exact2(g, keys("type grant_id room_id agreement_digest issuer registrar_key role actions expires_at token_hash max_claims")) && g.type === "scopeblind.coordination.grant.v1" && id2(g.grant_id) && g.room_id === p2.next_agreement.id && g.agreement_digest === p2.next_agreement_digest && g.issuer === a.owner_key && g.registrar_key === authority && g.role === "reviewer" && same(g.actions, ["decide", "accept"]) && HEX.test(g.token_hash) && g.max_claims === 1 && g.expires_at === s.expires_at && p2.reviewer_grant_digest === await negotiationPayloadDigest(g));
    }
    add("Recommendations are distinct from human approvals and uniquely bound", Array.isArray(e.responses) && e.responses.length <= 6 && new Set(e.responses.map((r2) => `${r2.payload.proposal_digest}:${r2.payload.principal_key}`)).size === e.responses.length);
    for (const response of e.responses) {
      const r2 = response.payload, p2 = e.proposals.find((p3) => p3.digest === r2.proposal_digest), mine = e.mandates.find((m) => m.payload.principal_key === r2.principal_key);
      add("Authority recorded an exactly scoped principal recommendation", await signed(response, authority) && exact2(r2, keys("type session_id principal_key proposal_digest mandate_digest decision agent_mode issued_at"), ["agent_key"]) && r2.type === "scopeblind.coordination.negotiation-response.v1" && r2.session_id === s.id && !!p2 && !!mine && r2.mandate_digest === mine.digest && ["support", "no_agreement"].includes(r2.decision) && actorBound(r2) && time2(r2.issued_at) >= time2(p2.payload.issued_at) && (r2.decision !== "support" || negotiationPlanWithinMandate(mine.payload, p2.payload.approval_above_minor, p2.payload.budget_minor ?? a.budget_minor, a.budget_minor)));
    }
    const r = e.report.payload, selected = e.proposals.find((p2) => p2.digest === r.proposal_digest), p = selected.payload;
    add("Named authority signed the exact comparison and full union of required cases", await signed(e.report, authority) && exact2(r, keys("type session_id room_id proposal_digest agreement_digest fixture_digest mandate_digests cases_digest runtime_revision adapter isolation issued_at before_approval_above_minor after_approval_above_minor results required_passed expectations_met mandates_met"), ["before_budget_minor", "after_budget_minor"]) && r.type === "scopeblind.coordination.negotiation-report.v1" && r.session_id === s.id && r.room_id === a.id && !!selected && r.agreement_digest === e.agreement.digest && r.fixture_digest === s.fixture_digest && same(r.mandate_digests, mandateDigests) && r.adapter === "coordination-d1-sandbox" && r.isolation === "separate-fixture-ledgers" && typeof r.runtime_revision === "string" && (r.runtime_revision === "development-unbound" || /^scopeblind\.invoice-rehearsal\.v1:[0-9a-f]{64}$/.test(r.runtime_revision)) && time2(r.issued_at) >= time2(p.issued_at) && principals.every((key) => validAt(key, r.issued_at)) && (p.budget_minor === void 0 ? r.before_budget_minor === void 0 && r.after_budget_minor === void 0 : r.before_budget_minor === a.budget_minor && r.after_budget_minor === p.budget_minor) && r.before_approval_above_minor === a.approval_above_minor && r.after_approval_above_minor === p.approval_above_minor && Array.isArray(r.results) && r.results.length <= 110 && r.results.every((x) => exact2(x, keys("case before after"))) && same(r.results.map((x) => x.case), mandateCases(e.mandates, e.fixtures)) && r.cases_digest === await negotiationDigest(mandateCases(e.mandates, e.fixtures)));
    add("Both gate traces and payment totals support every observation summary", r.results.every((x) => observationConsistent(x.case, x.before, a, e.fixtures) && observationConsistent(x.case, x.after, p.next_agreement, e.fixtures)));
    const rangeMet = e.mandates.every((m) => negotiationPlanWithinMandate(m.payload, p.approval_above_minor, p.budget_minor ?? a.budget_minor, a.budget_minor));
    add("Required cases, expectations and both mandates match the reported calculations", r.required_passed === r.results.every((x) => !x.case.required || x.after.matched) && r.expectations_met === r.results.every((x) => x.case.id.startsWith("sample-invoice-") || x.after.matched) && r.mandates_met === (rangeMet && r.results.filter((x) => x.case.id.startsWith("principal-")).every((x) => x.after.matched)));
    add("Human decisions are at most one per principal", Array.isArray(e.approvals) && e.approvals.length <= 2 && new Set(e.approvals.map((v) => v.payload.principal_key)).size === e.approvals.length);
    for (const approval of e.approvals) {
      const v = approval.payload;
      add("Human signed a decision over these exact rules, report and mandates", await verifyHuman(approval, v.principal_key, { proposal: selected, requireRecordedUse: true, authorityKey: authority }) && exact2(v, keys("type session_id principal_key proposal_digest report_digest next_agreement_digest mandate_digests decision issued_at expires_at"), ["selection_basis"]) && v.type === "scopeblind.coordination.negotiation-approval.v1" && principals.includes(v.principal_key) && v.session_id === s.id && v.proposal_digest === selected.digest && v.report_digest === e.report.digest && (v.selection_basis === void 0 || v.selection_basis === "human-selected-tested-plan") && v.next_agreement_digest === p.next_agreement_digest && same(v.mandate_digests, mandateDigests) && ["approve", "reject"].includes(v.decision) && validAt(v.principal_key, v.issued_at) && time2(v.issued_at) >= time2(r.issued_at) - 3e5 && time2(v.expires_at) > time2(v.issued_at) && time2(v.expires_at) <= time2(s.expires_at));
    }
    if (e.reviewer_grant) add("Organizer signed the exact proposed reviewer grant", await verifyHuman(e.reviewer_grant, a.owner_key, { proposal: selected, approval: e.approvals.find((v) => v.payload.principal_key === a.owner_key), requireRecordedUse: true, authorityKey: authority }) && same(e.reviewer_grant.payload, p.reviewer_grant) && e.reviewer_grant.digest === p.reviewer_grant_digest);
    if (e.adoption) {
      const d = e.adoption.payload, next = e.adopted_agreement, g = e.reviewer_grant, binding = e.reviewer_binding, rb = binding.payload, claim2 = rb.claim.payload;
      add("Both unexpired human approvals authorize adoption of this exact tested candidate", e.approvals.length === 2 && e.approvals.every((v) => v.payload.decision === "approve" && time2(d.issued_at) >= time2(v.payload.issued_at) - 3e5 && time2(d.issued_at) < time2(v.payload.expires_at)) && selected.digest === e.proposals.at(-1).digest && principals.every((key) => validAt(key, d.issued_at)) && r.required_passed && r.expectations_met && r.mandates_met && (e.approvals.every((v) => v.payload.selection_basis === "human-selected-tested-plan") || principals.every((key) => e.responses.some((v) => v.payload.principal_key === key && v.payload.proposal_digest === selected.digest && v.payload.decision === "support"))));
      add("Authority recorded exact lineage into a new separately authorized sample task", await signed(e.adoption, authority) && exact2(d, keys("type session_id source_room_id room_id source_agreement_digest agreement_digest proposal_digest report_digest approval_digests issued_at scope")) && d.type === "scopeblind.coordination.negotiation-adoption.v1" && d.session_id === s.id && d.source_room_id === a.id && d.room_id === p.next_agreement.id && d.room_id !== a.id && d.source_agreement_digest === e.agreement.digest && d.agreement_digest === p.next_agreement_digest && d.proposal_digest === selected.digest && d.report_digest === e.report.digest && same(d.approval_digests, principals.map((key) => e.approvals.find((v) => v.payload.principal_key === key).digest)) && d.scope === "new-separate-sample-task" && await verifyHuman(next, a.owner_key, { proposal: selected, approval: e.approvals.find((v) => v.payload.principal_key === a.owner_key), requireRecordedUse: true, authorityKey: authority }) && same(next.payload, p.next_agreement) && next.digest === d.agreement_digest);
      add("Partner independently claimed the fixed reviewer role in the new task", await signed(binding, authority) && await verifyHuman(rb.claim, partner, { proposal: selected, approval: e.approvals.find((v) => v.payload.principal_key === partner), requireRecordedUse: true, authorityKey: authority }) && exact2(rb, keys("type grant_id grant_digest room_id guest_key name issued_at expires_at claim")) && rb.type === "scopeblind.coordination.binding.v1" && rb.grant_id === g.payload.grant_id && rb.grant_digest === g.digest && rb.room_id === d.room_id && rb.guest_key === partner && rb.expires_at === g.payload.expires_at && time2(rb.issued_at) >= time2(d.issued_at) && time2(rb.issued_at) < time2(rb.expires_at) && exact2(claim2, keys("type grant_id room_id guest_key name issued_at nonce")) && claim2.type === "scopeblind.coordination.claim.v1" && claim2.grant_id === rb.grant_id && claim2.room_id === d.room_id && claim2.guest_key === partner && text(claim2.name, 60) && claim2.name === rb.name && id2(claim2.nonce) && time2(claim2.issued_at) >= time2(r.issued_at) - 3e5 && time2(claim2.issued_at) <= time2(rb.issued_at) + 3e5);
    } else add("No unbound adopted agreement or reviewer binding is present", !e.adopted_agreement && !e.reviewer_binding);
  } catch {
    add("Complete, well-formed negotiation evidence", false);
  }
  return { valid: checks.length > 0 && checks.every((c) => c.passed), checks, limitations: [
    "Signatures establish record integrity and control of keys. Display names are not authenticated legal identities.",
    "The named service attests to gate traces and sample-ledger effects. These records do not independently prove execution or safety for every input or deployment.",
    "Private briefs are omitted; signed commitments do not reveal or validate their contents. Recommendations are separate from human approval and adoption.",
    "Comparisons test each case in a separate ledger; observing several payable invoices does not establish that all fit one shared run budget.",
    "Expiry is checked at recorded actions. An export does not establish present authorization, revocation status, or permission to make a payment."
  ] };
}

// src/coordination-evidence.ts
async function verifyOwnerAgreement(agreement, negotiation, depth = 0) {
  try {
    if (!agreement.authorization) return await verifyHuman(agreement, agreement.payload.owner_key);
    if (depth > 4 || !negotiation?.adoption || !negotiation.adopted_agreement || canonical(negotiation.adopted_agreement) !== canonical(agreement) || negotiation.adoption.payload.room_id !== agreement.payload.id) return false;
    return (await verifyNegotiationEvidence(negotiation, agreement.payload.registrar_key, depth)).valid;
  } catch {
    return false;
  }
}
var integer2 = (n) => Number.isSafeInteger(n) && Number(n) >= 0;
var timestamp = (s) => typeof s === "string" ? Date.parse(s) : NaN;
async function verifyEvidence(value, expectedAuthority) {
  const checks = [];
  const check = (label, ok) => {
    checks.push({ label, ok: ok === true });
  };
  let accepted = false;
  try {
    const b = value;
    if (!b || b.type !== "scopeblind.coordination.evidence.v1" || !Array.isArray(b.grants) || !Array.isArray(b.acceptances)) throw new Error("Unrecognized coordination evidence.");
    const a = b.agreement.payload, m = b.manifest.payload, authority = a.registrar_key;
    check("Agreement signed by its author", a.type === "scopeblind.coordination.agreement.v1" && await verifyOwnerAgreement(b.agreement, b.negotiation));
    check("Agreement parameters are supported", a.version === 1 && (a.mode === void 0 || a.mode === "guided" || a.mode === "live") && a.currency === "USD" && integer2(a.budget_minor) && integer2(a.approval_above_minor) && integer2(a.approval_ttl_seconds) && a.approval_ttl_seconds > 0 && Array.isArray(a.allowed_destinations) && a.allowed_destinations.every((x) => typeof x === "string") && Number.isFinite(timestamp(a.issued_at)));
    if (expectedAuthority) check("Authority matches the independently supplied key", authority === expectedAuthority);
    if (b.negotiation) {
      const negotiated = await verifyNegotiationEvidence(b.negotiation, expectedAuthority);
      check("Two-person agreement history is intact", negotiated.valid && !!b.negotiation.adoption && b.negotiation.adopted_agreement?.digest === b.agreement.digest && b.negotiation.adoption.payload.room_id === a.id);
    }
    check("Finalized manifest signed by the agreed authority", m.type === "scopeblind.coordination.manifest.v1" && await verify(b.manifest, authority));
    check("Manifest binds this agreement and run", m.room_id === a.id && m.agreement_digest === b.agreement.digest && typeof m.run_id === "string" && m.run_id.length > 0 && Number.isFinite(timestamp(m.finalized_at)) && timestamp(m.finalized_at) >= timestamp(a.issued_at));
    if (!Array.isArray(m.operations) || m.operations.length > 500 || b.grants.length > 100 || b.acceptances.length > 100) throw new Error("Evidence exceeds supported bounds.");
    check("Result explanation is bounded text", m.summary === void 0 || typeof m.summary === "string" && m.summary.length <= 600);
    const prior = b.prior_attempts ?? [];
    if (!Array.isArray(prior) || prior.length > 9) throw new Error("Too many prior attempts.");
    const history = m.historical_operations ?? [];
    check("Revision lineage is complete", prior.length > 0 ? m.previous_manifest_digest === prior.at(-1).manifest.digest : !m.previous_manifest_digest && history.length === 0);
    const priorRuns = /* @__PURE__ */ new Set();
    for (let index = 0; index < prior.length; index++) {
      const attempt = prior[index], link = attempt.revision.payload;
      check(`Prior attempt ${index + 1} \xB7 no unresolved authority released by revision`, attempt.manifest.payload.budget.reserved_minor === 0 && attempt.manifest.payload.operations.every((op) => !["held", "request_changes", "admitted", "unknown"].includes(op.status)));
      if (index === prior.length - 1) {
        const checked = await verifyEvidence({ ...b, manifest: attempt.manifest, acceptances: attempt.acceptances, acceptance_records: attempt.acceptance_records, prior_attempts: prior.slice(0, index) }, expectedAuthority);
        check(`Prior attempt ${index + 1} \xB7 signatures and accounting`, checked.valid);
      }
      check(`Prior attempt ${index + 1} \xB7 authorized continuation`, await verify(attempt.revision, authority) && link.type === "scopeblind.coordination.revision.v1" && link.room_id === a.id && link.previous_run_id === attempt.manifest.payload.run_id && link.run_id === (prior[index + 1]?.manifest.payload.run_id ?? m.run_id) && link.previous_manifest_digest === attempt.manifest.digest && link.agreement_digest === b.agreement.digest && link.requested_by === a.owner_key && !priorRuns.has(link.previous_run_id) && link.previous_run_id !== m.run_id && timestamp(link.issued_at) >= timestamp(attempt.manifest.payload.finalized_at));
      priorRuns.add(link.previous_run_id);
    }
    const expectedHistory = prior.flatMap((attempt) => attempt.manifest.payload.operations.filter((op) => op.status === "confirmed"));
    check("Earlier payments are preserved exactly once", canonical([...history].sort((x, y) => x.operation_id.localeCompare(y.operation_id))) === canonical(expectedHistory.sort((x, y) => x.operation_id.localeCompare(y.operation_id))));
    if (prior.length && m.fixtures) check("Invoice records remain unchanged across attempts", prior.every((attempt) => attempt.manifest.payload.fixtures ? canonical(attempt.manifest.payload.fixtures) === canonical(m.fixtures) : a.mode !== "live"));
    if (a.mode === "live") check("Live agreement requires matching frozen purchase-order records", a.require_po_match === true && !!m.fixtures && integer2(m.fixtures.revision) && m.fixtures.revision > 0 && Array.isArray(m.fixtures.invoices) && Array.isArray(m.fixtures.purchase_orders));
    const proposal = b.negotiation?.proposals.find((p) => p.digest === b.negotiation?.adoption?.payload.proposal_digest);
    const deviceContext = (principal) => ({ proposal, approval: b.negotiation?.approvals.find((v) => v.payload.principal_key === principal), requireRecordedUse: true, authorityKey: authority });
    const grants = /* @__PURE__ */ new Map();
    for (const v of b.grants) {
      const g = v.grant.payload;
      let ok = !grants.has(g.grant_id) && g.type === "scopeblind.coordination.grant.v1" && await verifyHuman(v.grant, a.owner_key, deviceContext(a.owner_key)) && g.issuer === a.owner_key && g.registrar_key === authority && g.room_id === a.id && g.agreement_digest === b.agreement.digest && g.role === "reviewer" && g.max_claims === 1 && Array.isArray(g.actions) && g.actions.every((x) => ["decide", "accept"].includes(x)) && Number.isFinite(timestamp(g.expires_at));
      if (v.binding) {
        const p = v.binding.payload, c = p.claim.payload;
        ok = ok && p.type === "scopeblind.coordination.binding.v1" && await verify(v.binding, authority) && p.grant_id === g.grant_id && p.grant_digest === v.grant.digest && p.room_id === a.id && p.expires_at === g.expires_at && timestamp(p.issued_at) < timestamp(g.expires_at) && c.type === "scopeblind.coordination.claim.v1" && await verifyHuman(p.claim, p.guest_key, deviceContext(p.guest_key)) && c.guest_key === p.guest_key && c.grant_id === g.grant_id && c.room_id === a.id && c.name === p.name;
      }
      check(`Invitation and guest key binding \xB7 ${g.grant_id}`, ok);
      grants.set(g.grant_id, v);
    }
    async function reviewer(s, action) {
      const p = s.payload, v = grants.get(p.grant_id), binding = v?.binding?.payload;
      return !!v && !!binding && v.grant.payload.actions.includes(action) && await verifyHuman(s, binding.guest_key, { requireRecordedUse: true, authorityKey: authority }) && p.room_id === a.id && p.run_id === m.run_id && p.agreement_digest === b.agreement.digest && timestamp(p.issued_at) >= timestamp(binding.issued_at) - 3e5 && timestamp(p.issued_at) < timestamp(binding.expires_at);
    }
    const ids = /* @__PURE__ */ new Set(), paidInvoices = /* @__PURE__ */ new Set();
    let spent = 0, reserved = 0;
    for (const op of history) {
      const businessKey = op.input.invoice_id;
      check(`Earlier payment ${op.operation_id} \xB7 unique invoice`, !paidInvoices.has(businessKey) && !ids.has(op.operation_id));
      paidInvoices.add(businessKey);
      ids.add(op.operation_id);
      spent += op.input.amount_minor;
    }
    for (const op of m.operations) {
      const label = `Operation ${op.operation_id}`;
      const hash = await payloadHash(op.input);
      check(`${label} \xB7 exact input and unique identity`, op.tool === "ledger.pay" && op.run_id === m.run_id && typeof op.operation_id === "string" && !ids.has(op.operation_id) && hash === op.payload_hash && integer2(op.input.amount_minor) && op.input.amount_minor > 0 && op.input.currency === a.currency && typeof op.input.invoice_id === "string");
      ids.add(op.operation_id);
      if (op.admission) {
        const p = op.admission.payload;
        check(`${label} \xB7 signed gate decision`, p.type === "scopeblind.coordination.admission.v1" && await verify(op.admission, authority) && p.room_id === a.id && p.run_id === m.run_id && p.operation_id === op.operation_id && p.agreement_digest === b.agreement.digest && p.payload_hash === hash && await payloadHash(p.input) === hash && p.destination === op.input.destination && ["admitted", "held", "refused"].includes(p.decision));
      }
      if (op.decision) {
        const p = op.decision.payload;
        check(`${label} \xB7 recipient decision binds exact input`, p.type === "scopeblind.coordination.approval.v1" && await reviewer(op.decision, "decide") && p.operation_id === op.operation_id && p.payload_hash === hash && ["approve", "deny", "request_changes"].includes(p.decision) && timestamp(p.expires_at) > timestamp(p.issued_at) && timestamp(p.expires_at) - timestamp(p.issued_at) <= a.approval_ttl_seconds * 1e3);
      }
      const invoice = m.fixtures?.invoices.find((i) => i.invoice_id === op.input.invoice_id);
      const needsApproval = op.input.amount_minor > a.approval_above_minor || a.require_po_match === true && (!invoice || !m.fixtures || !invoiceMatchesPurchaseOrder(invoice, m.fixtures));
      if (["admitted", "confirmed", "unknown"].includes(op.status)) {
        if (a.mode === "live") check(`${label} \xB7 frozen invoice input`, !!invoice && op.input.fixture_revision === m.fixtures?.revision && op.input.amount_minor === invoice.amount_minor && op.input.destination === invoice.destination);
        const p = op.admission?.payload;
        check(`${label} \xB7 authorized destination and admission`, p?.decision === "admitted" && a.allowed_destinations.includes(op.input.destination));
        if (needsApproval) {
          const d = op.decision?.payload;
          check(`${label} \xB7 fresh approval at admission`, !!d && d.decision === "approve" && !!p && timestamp(d.issued_at) <= timestamp(p.issued_at) + 6e4 && timestamp(d.expires_at) > timestamp(p.issued_at));
        }
        const businessKey = op.input.invoice_id;
        check(`${label} \xB7 invoice paid or reserved once`, !paidInvoices.has(businessKey));
        paidInvoices.add(businessKey);
      }
      if (op.receipt) {
        const p = op.receipt.payload;
        check(`${label} \xB7 signed outcome binds exact input`, p.type === "scopeblind.coordination.outcome.v1" && await verify(op.receipt, authority) && p.room_id === a.id && p.run_id === m.run_id && p.operation_id === op.operation_id && p.payload_hash === hash && p.amount_minor === op.input.amount_minor && p.destination === op.input.destination && p.status === op.status);
      }
      if (op.status === "confirmed") {
        check(`${label} \xB7 sandbox destination confirmation`, op.receipt?.payload.status === "confirmed" && op.receipt.payload.observed_by === "sandbox-ledger" && !!op.receipt.payload.transaction_id);
        const gate = op.admission?.payload, effectAt = timestamp(op.receipt.payload.issued_at);
        check(`${label} \xB7 effect within admission validity`, !!gate && effectAt >= timestamp(gate.issued_at) && effectAt < timestamp(gate.expires_at));
        if (needsApproval) check(`${label} \xB7 approval still fresh at effect`, !!op.decision && effectAt < timestamp(op.decision.payload.expires_at));
        spent += op.input.amount_minor;
      } else if (op.status === "admitted" || op.status === "unknown") reserved += op.input.amount_minor;
      else check(`${label} \xB7 recognized final state`, ["held", "refused", "declined", "request_changes", "superseded", "failed"].includes(op.status));
    }
    const budget = m.budget;
    check("Budget reconciles with signed outcomes and reservations", integer2(budget.limit_minor) && integer2(budget.spent_minor) && integer2(budget.reserved_minor) && integer2(budget.remaining_minor) && budget.limit_minor === a.budget_minor && budget.spent_minor === spent && budget.reserved_minor === reserved && budget.limit_minor === spent + reserved + budget.remaining_minor);
    const records = b.acceptance_records ?? [];
    const acceptanceIds = /* @__PURE__ */ new Set();
    for (const s of b.acceptances) {
      const p = s.payload;
      const ok = !acceptanceIds.has(s.digest) && p.type === "scopeblind.coordination.acceptance.v1" && await reviewer(s, "accept") && p.manifest_digest === b.manifest.digest && ["accept", "request_changes"].includes(p.decision) && timestamp(p.issued_at) >= timestamp(m.finalized_at) - 3e5;
      acceptanceIds.add(s.digest);
      check("Recipient decision signs this finalized manifest", ok);
      const record = records.find((r) => r.payload.acceptance_digest === s.digest);
      check("Authority recorded recipient authority at acceptance", !!record && record.payload.type === "scopeblind.coordination.acceptance-record.v1" && await verify(record, authority) && record.payload.room_id === a.id && record.payload.run_id === m.run_id && record.payload.manifest_digest === b.manifest.digest && record.payload.reviewer_key === humanPrincipal(s) && timestamp(record.payload.recorded_at) >= timestamp(m.finalized_at));
    }
    check("Acceptance records refer only to supplied decisions", records.length === b.acceptances.length && records.every((r) => acceptanceIds.has(r.payload.acceptance_digest)));
    const recordedAt = new Map(records.map((r) => [r.payload.acceptance_digest, timestamp(r.payload.recorded_at)]));
    accepted = b.acceptances.length > 0 && [...b.acceptances].sort((x, y) => (recordedAt.get(x.digest) ?? 0) - (recordedAt.get(y.digest) ?? 0)).at(-1)?.payload.decision === "accept";
  } catch (e) {
    check(e instanceof Error ? e.message : "Malformed evidence", false);
  }
  const errors = checks.filter((x) => !x.ok).map((x) => x.label);
  return {
    valid: errors.length === 0,
    checks,
    errors,
    accepted: accepted && errors.length === 0,
    authorityPinned: !!expectedAuthority && errors.length === 0,
    limitations: [
      "Signatures bind these records to keys; they do not establish a person\u2019s legal identity.",
      "The authority attests to gate state, enrollment, and the sandbox ledger. These records do not prove real payments, agent reasoning, or activity outside this gate.",
      "The manifest binds the included operations. An offline file cannot establish that an operator disclosed every run or that access is still active.",
      ...!expectedAuthority ? ["No independent authority key was supplied. Integrity was checked against the authority named in the signed agreement."] : []
    ]
  };
}

// src/coordination-config.ts
function validateCoordinationConfig(config) {
  if (config.purpose !== void 0 && !["execution", "rehearsal", "negotiation"].includes(config.purpose)) throw new Error("Unknown coordination connection purpose.");
  if (config.purpose === "negotiation") {
    if (!config.sessionId || !/^[A-Za-z0-9_-]{8,100}$/.test(config.sessionId)) throw new Error("A negotiation connection requires its exact paired session ID.");
    if (!config.principalKey || !/^[0-9a-f]{64}$/.test(config.principalKey)) throw new Error("A negotiation connection requires its paired principal public key.");
  } else if (config.sessionId !== void 0 || config.principalKey !== void 0) throw new Error("Negotiation session and principal fields require a negotiation connection.");
  let endpoint;
  try {
    endpoint = new URL(config.endpoint);
  } catch {
    throw new Error("Coordination endpoint must be an absolute URL.");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname);
  if (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && local)) {
    throw new Error("Coordination endpoint requires HTTPS (HTTP is permitted only on loopback for local trials).");
  }
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error("Coordination endpoint must not contain credentials, query parameters, or a fragment.");
  }
  if (!/^[a-fA-F0-9]{64}$/.test(config.authorityKey)) {
    throw new Error("An explicitly pinned 32-byte Ed25519 authority public key is required (64 hexadecimal characters).");
  }
  if (!/^[A-Za-z0-9_-]{8,100}$/.test(config.roomId)) throw new Error("Room ID must use 8\u2013100 letters, numbers, underscores, or hyphens.");
  if (!config.token || /[\r\n]/.test(config.token)) throw new Error("An executor token is required in the configured environment variable.");
  if (config.runId !== void 0 && !/^run-[A-Za-z0-9_-]{8,100}$/.test(config.runId)) throw new Error("Run ID must be run- followed by the room ID.");
  if (config.timeoutMs !== void 0 && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 12e4)) {
    throw new Error("Coordination timeout must be an integer from 1 to 120000 milliseconds.");
  }
  return { ...config, endpoint: endpoint.href, authorityKey: config.authorityKey.toLowerCase() };
}
function coordinationConfigFromArgs(args, env = process.env) {
  const values = /* @__PURE__ */ new Map();
  const flags = /* @__PURE__ */ new Set(["--endpoint", "--room", "--authority-key", "--token-env", "--run"]);
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i];
    if (!flags.has(flag)) throw new Error("Unknown coordination option. Use --endpoint, --room, --authority-key, --token-env, and optionally --run.");
    if (values.has(flag)) throw new Error("Coordination options may only be supplied once.");
    const value = args[i + 1];
    if (!value || value.startsWith("--")) throw new Error("Every coordination option requires a value.");
    values.set(flag, value);
  }
  const variable = values.get("--token-env") || "PROTECT_MCP_COORDINATION_TOKEN";
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) throw new Error("--token-env must name an environment variable.");
  return validateCoordinationConfig({
    endpoint: values.get("--endpoint") || "",
    roomId: values.get("--room") || "",
    authorityKey: values.get("--authority-key") || "",
    token: env[variable] || "",
    runId: values.get("--run")
  });
}

export {
  humanPrincipal,
  verifyDeviceAuthorization,
  verifyHuman,
  verifyOwnerAgreement,
  verifyEvidence,
  REHEARSAL_ACTIONS,
  parseRehearsalCase,
  parseRepairProposal,
  rehearsalDigest,
  verifyRehearsalEvidence,
  NEGOTIATION_MAX_PROPOSALS,
  NEGOTIATION_MAX_MODEL_STEPS,
  NEGOTIATION_AGENT_ACTIONS,
  negotiationDigest,
  negotiationPayloadDigest,
  privateBriefCommitment,
  parseNegotiationBrief,
  mandateCases,
  mandateBudget,
  negotiationPlanWithinMandate,
  verifyNegotiationEvidence,
  validateCoordinationConfig,
  coordinationConfigFromArgs
};
