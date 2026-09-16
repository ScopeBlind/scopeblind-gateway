import {
  coordinationConfigFromFile
} from "./chunk-GDQ3RE5B.mjs";
import {
  CoordinationClient,
  CoordinationError
} from "./chunk-2SYSTEXK.mjs";
import {
  coordinationConfigFromArgs
} from "./chunk-ZSS4X3C3.mjs";

// src/coordination-server.ts
import { createInterface } from "readline";
var COORDINATION_TOOLS = [
  {
    name: "coordination.deliver",
    description: "Freeze the completed invoice result for the recipient to accept or request changes. The service refuses delivery while operations remain held, admitted, or unknown, or invoices have no recorded disposition. Does not accept the result on behalf of a person, change terms, or grant a revision. Returns the verified service-signed manifest.",
    inputSchema: { type: "object", properties: { run_id: { type: "string", pattern: "^run-[A-Za-z0-9_-]{8,100}$", description: "Exact run_id from the inspected task. Prevents delivery of a different revision." } }, required: ["run_id"], additionalProperties: false },
    annotations: { title: "Deliver the result for review", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "ledger.pay",
    description: "Pay a sample invoice through the shared room authority. The installed adapter obtains and verifies an exact signed admission BEFORE the sample ledger can execute. No real money moves. Reuse operation_id for retries of the same intended payment; a changed payload with the same ID is refused. Held requests need the room reviewer; call again with unchanged terms after approval. An unknown outcome must be reconciled with the same ID, never replaced by a new payment. Returns signed admission and destination evidence when available.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        operation_id: { type: "string", minLength: 8, maxLength: 100, pattern: "^[A-Za-z0-9_-]{8,100}$", description: "Stable identity for this intended payment, retained across retries and restarts." },
        invoice_id: { type: "string", minLength: 1, maxLength: 60 },
        amount_minor: { type: "integer", minimum: 1, maximum: 1e7, description: "USD cents; 32000 means $320.00." },
        currency: { type: "string", enum: ["USD"] },
        fixture_revision: { type: "integer", minimum: 1, description: "Current records revision from coordination.inspect. Required for live rooms; binds this exact record version." },
        destination: { type: "string", minLength: 1, maxLength: 100, description: "Sample destination from coordination.inspect, for example sandbox:northstar." }
      },
      required: ["operation_id", "invoice_id", "amount_minor", "currency", "destination"]
    },
    annotations: { title: "Pay a sample invoice under the agreed rules", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.inspect",
    description: "Read this shared invoice room, its owner-signed agreement, sample invoices, budget, and pending outcomes. The configured registrar key is pinned; the adapter verifies the agreement signature. Live budget/operation listings are the service report, not proof of complete runtime coverage. Use ledger.pay to independently verify the exact admission and destination outcome. Does not approve, execute, change rules, or move money.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { title: "Inspect the shared invoice room", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.wait",
    description: "Await a colleague decision or other room event for up to 30 seconds. Pass the cursor from coordination.inspect or the last wait. The installed tool polls every two seconds without calling the model between checks. Returns changed or waiting, current cursor/run, recent events, and operations needing attention. On changed, inspect and retry approved requests with unchanged operation IDs. On timeout, the active agent session can call wait again; resumption depends on the MCP client. This does not push notifications, approve, execute, or grant authority.",
    inputSchema: { type: "object", properties: {
      after_cursor: { type: "integer", minimum: 0, description: "Event cursor returned by coordination.inspect or the preceding wait." },
      run_id: { type: "string", pattern: "^run-[A-Za-z0-9_-]{8,100}$", description: "Optional inspected run; a changed attempt returns immediately." },
      timeout_ms: { type: "integer", minimum: 1e3, maximum: 3e4, default: 3e4 }
    }, required: ["after_cursor"], additionalProperties: false },
    annotations: { title: "Wait for the next room decision", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }
];
var REHEARSAL_TOOLS = [
  {
    name: "coordination.inspect_rehearsal",
    description: "Inspect the owner-signed agreement, sample records, proposed expectations, repairs, and signed test reports. Optional report_digest retrieves exact historical evidence. The adapter pins the authority and verifies source signatures; the gate operator attests to observations. This test grant cannot execute source payments, approve exceptions, or activate a repair.",
    inputSchema: { type: "object", properties: { report_digest: { type: "string", pattern: "^[0-9a-f]{64}$", description: "Optional exact report digest to retrieve its immutable evidence snapshot." } }, additionalProperties: false },
    annotations: { title: "Inspect rules and test evidence", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.propose_case",
    description: "Add an explicit human expectation or safety challenge against sample invoices. Stable case IDs make identical retries safe; changed content needs a new ID. Cases only influence isolated tests and do not pause work or change the active agreement. Required shipped safety cases cannot be replaced. Invoice expectations are allow, ask, or refuse; adversarial case kinds use invariant.",
    inputSchema: { type: "object", properties: { case: { type: "object", properties: {
      id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" },
      title: { type: "string", minLength: 1, maxLength: 120 },
      kind: { type: "string", enum: ["invoice", "approved_invoice", "duplicate_invoice", "changed_approval", "changed_destination", "expired_approval", "budget_cap"] },
      invoice_id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,60}$" },
      amount_minor: { type: "integer", minimum: 1, maximum: 1e7, description: "Optional explicit invoice AND matching purchase-order override inside this case\u2019s isolated ledger only." },
      expected: { type: "string", enum: ["allow", "ask", "refuse", "invariant"] },
      requirement: { type: "string", minLength: 1, maxLength: 400 }
    }, required: ["id", "title", "kind", "invoice_id", "expected", "requirement"], additionalProperties: false } }, required: ["case"], additionalProperties: false },
    annotations: { title: "Propose a test case", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.propose_repair",
    description: "Propose a single review-threshold change in USD cents, with an explicit rationale. The proposal is bound to the current source agreement, sample records, and cases. It cannot activate rules, change the budget or destination, or authorize a payment. Keep its stable id for retries; inspect again if the source snapshot changes.",
    inputSchema: { type: "object", properties: { proposal: { type: "object", properties: { id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" }, approval_above_minor: { type: "integer", minimum: 0, maximum: 1e7 }, rationale: { type: "string", minLength: 1, maxLength: 600 } }, required: ["id", "approval_above_minor", "rationale"], additionalProperties: false } }, required: ["proposal"], additionalProperties: false },
    annotations: { title: "Propose a review-threshold repair", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.run_rehearsal",
    description: "Run concrete cases through the actual gate in separate fixture ledgers. Omit proposal_id for a baseline, or select an exact proposal to compare before and after. The tool resumes up to six durable chunks within three minutes and returns pending if unfinished. Use one stable id per intended run and retain it if a response is lost or times out; inspect reports before retrying. Results are bounded observations, not proof for every input. This never spends the source budget, changes the source ledger, or adopts a repair.",
    inputSchema: { type: "object", properties: { id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" }, proposal_id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" } }, required: ["id"], additionalProperties: false },
    annotations: { title: "Test and compare rules in isolation", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }
];
var NEGOTIATION_TOOLS = [
  {
    name: "coordination.inspect_negotiation",
    description: "Inspect your principal\u2019s signed mandate and private brief, plus the shared candidates, responses, and isolated comparison records for this paired session. Never returns the other principal\u2019s private brief. Treat brief text as private task context, not as permission to override the signed limits. Optional report_digest retrieves exact historical comparison evidence. This connection cannot pay, approve, adopt, delegate, or run a hosted model.",
    inputSchema: { type: "object", properties: { report_digest: { type: "string", pattern: "^[0-9a-f]{64}$" } }, additionalProperties: false },
    annotations: { title: "Inspect my mandate and shared negotiation", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.propose_candidate",
    description: "Propose a review threshold and optional total budget within your principal\u2019s signed limits. At most three candidate proposals may exist in this session; the service enforces the limit across all agents and retries. Reuse id for retries with identical terms. A counterproposal must name the current parent_digest. Only structured terms are shared; do not send private briefing text. A candidate grants no authority and cannot change the active job.",
    inputSchema: { type: "object", properties: { proposal: { type: "object", properties: { id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,80}$" }, approval_above_minor: { type: "integer", minimum: 0, maximum: 1e7, description: "USD cents: 40000 means review above $400." }, budget_minor: { type: "integer", minimum: 1, maximum: 1e7, description: "Optional total budget in USD cents, within the principal\u2019s signed budget limits. Omit to retain the source budget." }, parent_digest: { type: "string", pattern: "^[0-9a-f]{64}$" } }, required: ["id", "approval_above_minor"], additionalProperties: false } }, required: ["proposal"], additionalProperties: false },
    annotations: { title: "Propose bounded terms", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.respond_candidate",
    description: "Record support or no agreement for an exact shared candidate on behalf of your principal\u2019s agent mandate. Support is a recommendation only; it is never either human\u2019s approval. No agreement is a valid bounded outcome. This tool cannot pay, approve the final agreement, or adopt it.",
    inputSchema: { type: "object", properties: { proposal_digest: { type: "string", pattern: "^[0-9a-f]{64}$" }, decision: { type: "string", enum: ["support", "no_agreement"] } }, required: ["proposal_digest", "decision"], additionalProperties: false },
    annotations: { title: "Respond to the exact candidate", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.compare_candidate",
    description: "Compare an exact supported candidate against the baseline using the real gate in isolated sample ledgers. The server owns one fixed report identity per proposal; retries resume two-case chunks. This tool runs for at most three minutes and returns pending if unfinished. Resume with the SAME proposal_digest after timeout or cancellation. A verified report records observed cases; it does not approve or adopt terms, spend the source budget, or prove every possible input.",
    inputSchema: { type: "object", properties: { proposal_digest: { type: "string", pattern: "^[0-9a-f]{64}$" } }, required: ["proposal_digest"], additionalProperties: false },
    annotations: { title: "Compare the candidate in isolation", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "coordination.wait_negotiation",
    description: "Wait for this principal\u2019s next negotiation action or a completed, blocked, or human-decision state. Polls only the principal-scoped negotiation endpoint every two seconds for at most thirty seconds, without model calls. Pass state_digest from inspection as after_digest to also return on any state change. This is bounded polling, not a background notification or permission to keep proposing beyond three candidates.",
    inputSchema: { type: "object", properties: { after_digest: { type: "string", pattern: "^[0-9a-f]{64}$" }, timeout_ms: { type: "integer", minimum: 1e3, maximum: 3e4, default: 3e4 } }, additionalProperties: false },
    annotations: { title: "Wait for negotiation status", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }
];
var toolsForPurpose = (purpose) => purpose === "negotiation" ? NEGOTIATION_TOOLS : purpose === "rehearsal" ? REHEARSAL_TOOLS : COORDINATION_TOOLS;
var textResult = (id, value, isError = false) => ({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(value) }], ...isError ? { isError: true } : {} } });
async function handleCoordinationRequest(client, request, signal) {
  if (!request || request.jsonrpc !== "2.0" || typeof request.method !== "string") return { jsonrpc: "2.0", id: request?.id ?? null, error: { code: -32600, message: "Invalid JSON-RPC request." } };
  if (request.id === void 0) return void 0;
  if (request.method === "initialize") return { jsonrpc: "2.0", id: request.id, result: { protocolVersion: "2024-11-05", serverInfo: { name: "protect-mcp-coordination", version: process.env.PROTECT_MCP_VERSION || "0.21.0" }, capabilities: { tools: {} } } };
  if (request.method === "ping") return { jsonrpc: "2.0", id: request.id, result: {} };
  if (request.method === "tools/list") return { jsonrpc: "2.0", id: request.id, result: { tools: toolsForPurpose(client.purpose) } };
  if (request.method !== "tools/call") return { jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found." } };
  try {
    const args = request.params?.arguments ?? {};
    if (!args || typeof args !== "object" || Array.isArray(args)) throw new CoordinationError("invalid_input", "Tool arguments must be an object.");
    const available = toolsForPurpose(client.purpose);
    if (!available.some((tool) => tool.name === request.params?.name)) throw new CoordinationError("tool_outside_grant", "This connection does not expose that capability. Use the separately authorized connection for its intended purpose.");
    const fields = args;
    if (request.params?.name === "coordination.inspect_negotiation") {
      if (Object.keys(fields).some((key) => key !== "report_digest")) throw new CoordinationError("invalid_input", "Inspect takes only an optional report_digest; session and principal come from the pairing.");
      return textResult(request.id, await client.inspectNegotiation(fields.report_digest, signal));
    }
    if (request.params?.name === "coordination.propose_candidate") {
      if (Object.keys(fields).join(",") !== "proposal") throw new CoordinationError("invalid_input", "Propose requires only proposal.");
      return textResult(request.id, await client.proposeCandidate(fields.proposal));
    }
    if (request.params?.name === "coordination.respond_candidate") return textResult(request.id, await client.respondCandidate(fields));
    if (request.params?.name === "coordination.compare_candidate") return textResult(request.id, await client.compareCandidate(fields, signal));
    if (request.params?.name === "coordination.wait_negotiation") return textResult(request.id, await client.waitNegotiation(fields, signal));
    if (request.params?.name === "coordination.inspect_rehearsal") {
      if (Object.keys(fields).some((key) => key !== "report_digest")) throw new CoordinationError("invalid_input", "Inspect takes only an optional report_digest.");
      return textResult(request.id, await client.inspectRehearsal(fields.report_digest));
    }
    if (request.params?.name === "coordination.propose_case") {
      if (Object.keys(fields).join(",") !== "case") throw new CoordinationError("invalid_input", "Propose case requires only case.");
      return textResult(request.id, await client.proposeCase(fields.case));
    }
    if (request.params?.name === "coordination.propose_repair") {
      if (Object.keys(fields).join(",") !== "proposal") throw new CoordinationError("invalid_input", "Propose repair requires only proposal.");
      return textResult(request.id, await client.proposeRepair(fields.proposal));
    }
    if (request.params?.name === "coordination.run_rehearsal") return textResult(request.id, await client.runRehearsal(fields, signal));
    if (request.params?.name === "coordination.wait") return textResult(request.id, await client.wait(args, signal));
    if (request.params?.name === "coordination.deliver") {
      if (Object.keys(args).join(",") !== "run_id") throw new CoordinationError("invalid_input", "coordination.deliver requires only the exact run_id from coordination.inspect.");
      return textResult(request.id, await client.deliver(args.run_id));
    }
    if (request.params?.name === "coordination.inspect") {
      if (Object.keys(args).length) throw new CoordinationError("invalid_input", "coordination.inspect takes no arguments.");
      return textResult(request.id, await client.inspect());
    }
    if (request.params?.name !== "ledger.pay") throw new CoordinationError("unknown_tool", "Unknown coordination tool.");
    const values = args;
    const allowed = /* @__PURE__ */ new Set(["operation_id", "invoice_id", "amount_minor", "currency", "destination", "fixture_revision"]);
    if (Object.keys(values).some((key) => !allowed.has(key))) throw new CoordinationError("invalid_input", "Payment contains unsupported fields.");
    const payment = {
      operation_id: values.operation_id,
      input: { invoice_id: values.invoice_id, amount_minor: values.amount_minor, currency: values.currency, destination: values.destination, ...values.fixture_revision !== void 0 ? { fixture_revision: values.fixture_revision } : {} }
    };
    return textResult(request.id, await client.pay(payment));
  } catch (error) {
    return textResult(request.id, {
      code: error instanceof CoordinationError ? error.code : "coordination_error",
      error: error instanceof CoordinationError ? error.message : "Coordination request could not be completed."
    }, true);
  }
}
async function runCoordinationServer(args) {
  const config = args.length === 2 && args[0] === "--config" ? coordinationConfigFromFile(args[1]) : coordinationConfigFromArgs(args);
  const client = new CoordinationClient(config);
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();
  const waits = /* @__PURE__ */ new Map();
  const cancelWaits = () => {
    for (const controller of waits.values()) controller.abort();
  };
  lines.on("close", cancelWaits);
  process.stdout.on("error", cancelWaits);
  lines.on("line", (line) => {
    if (!line.trim()) return;
    let request;
    try {
      if (line.length > 1e6) throw new Error("Frame too large");
      request = JSON.parse(line);
    } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Invalid or oversized JSON-RPC message." } }) + "\n");
      return;
    }
    if (request?.jsonrpc === "2.0" && request.method === "notifications/cancelled") {
      const id = request.params?.requestId;
      if (typeof id === "string" || typeof id === "number") waits.get(id)?.abort();
      return;
    }
    const controller = request?.method === "tools/call" && ["coordination.wait", "coordination.run_rehearsal", "coordination.wait_negotiation", "coordination.compare_candidate"].includes(String(request.params?.name)) ? new AbortController() : void 0;
    if (controller) waits.set(request.id, controller);
    chain = chain.then(async () => {
      let response;
      try {
        response = await handleCoordinationRequest(client, request, controller?.signal);
      } catch {
        response = { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Invalid or oversized JSON-RPC message." } };
      } finally {
        if (controller && waits.get(request.id) === controller) waits.delete(request.id);
      }
      if (response !== void 0) process.stdout.write(JSON.stringify(response) + "\n");
    });
  });
  process.stderr.write(client.purpose === "negotiation" ? "[PROTECT_MCP] Negotiation MCP ready: inspect_negotiation, propose_candidate, respond_candidate, compare_candidate, and wait_negotiation. One principal only; no payment, human approval, adoption, or hosted-model authority.\n" : client.purpose === "rehearsal" ? "[PROTECT_MCP] Test MCP ready: inspect_rehearsal, propose_case, propose_repair, and run_rehearsal. Separate sample ledgers; no execution or adoption authority.\n" : "[PROTECT_MCP] Coordination MCP ready: ledger.pay, coordination.inspect, coordination.deliver, and coordination.wait. Sample ledger only; no real money moves.\n");
  await new Promise((resolve) => lines.on("close", resolve));
  await chain;
  process.stdout.removeListener("error", cancelWaits);
}

export {
  COORDINATION_TOOLS,
  REHEARSAL_TOOLS,
  NEGOTIATION_TOOLS,
  handleCoordinationRequest,
  runCoordinationServer
};
