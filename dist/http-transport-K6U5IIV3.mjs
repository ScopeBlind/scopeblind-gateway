import {
  ProtectGateway
} from "./chunk-YRFAFP5H.mjs";
import "./chunk-6U5IHP7S.mjs";
import "./chunk-VJ743MCX.mjs";
import "./chunk-RYIZBSTW.mjs";
import "./chunk-P2YFFXF2.mjs";
import "./chunk-SRLE63GU.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/http-transport.ts
import { createServer } from "http";
import { createHash, randomBytes, timingSafeEqual } from "crypto";
var LOOPBACK = /* @__PURE__ */ new Set(["127.0.0.1", "::1", "localhost"]);
var MIN_TOKEN_LENGTH = 32;
async function startHttpTransport(options) {
  const { port, config, serverCommand } = options;
  const host = options.host || process.env.PROTECT_MCP_HTTP_HOST || "127.0.0.1";
  const configuredToken = process.env.PROTECT_MCP_HTTP_TOKEN;
  const tokenFromEnv = configuredToken?.trim() ?? "";
  if (configuredToken !== void 0 && tokenFromEnv.length < MIN_TOKEN_LENGTH) {
    throw new Error(`PROTECT_MCP_HTTP_TOKEN must be at least ${MIN_TOKEN_LENGTH} characters (it has ${tokenFromEnv.length}); set a random value, for example the output of: openssl rand -hex 32`);
  }
  const token = tokenFromEnv || randomBytes(32).toString("hex");
  const tokenDigest = createHash("sha256").update(token).digest();
  const authorized = (req) => {
    const match = /^Bearer +(.+)$/i.exec(req.headers.authorization || "");
    return match !== null && timingSafeEqual(createHash("sha256").update(match[1].trim()).digest(), tokenDigest);
  };
  const sseClients = /* @__PURE__ */ new Set();
  const httpConfig = {
    ...config,
    command: serverCommand[0],
    args: serverCommand.slice(1)
  };
  const gateway = new ProtectGateway(httpConfig);
  if (options.cedarPolicySet) {
    gateway.setCedarPolicies(options.cedarPolicySet);
  }
  await gateway.startForHttp();
  const server = createServer(async (req, res) => {
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url || "/", `http://localhost:${port}`);
    if (url.pathname === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        server: "protect-mcp",
        version: process.env.PROTECT_MCP_VERSION || "unknown",
        transport: "streamable-http",
        mode: config.policy ? config.enforce ? "enforce" : "shadow" : "shadow"
      }));
      return;
    }
    if (!authorized(req)) {
      res.writeHead(401, { "Content-Type": "application/json", "WWW-Authenticate": "Bearer" });
      res.end(JSON.stringify({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized: send Authorization: Bearer <token>, the token the gateway printed at startup or PROTECT_MCP_HTTP_TOKEN" },
        id: null
      }));
      return;
    }
    if (url.pathname === "/mcp/sse" && req.method === "GET") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      });
      res.write(`data: ${JSON.stringify({ type: "connected", server: "protect-mcp" })}

`);
      sseClients.add(res);
      req.on("close", () => sseClients.delete(res));
      return;
    }
    if (url.pathname === "/mcp" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", async () => {
        try {
          const jsonRpc = JSON.parse(body);
          const acceptSSE = (req.headers.accept || "").includes("text/event-stream");
          const responseStr = await gateway.processRequest(jsonRpc);
          const response = JSON.parse(responseStr);
          if (acceptSSE) {
            res.writeHead(200, {
              "Content-Type": "text/event-stream",
              "Cache-Control": "no-cache"
            });
            res.write(`data: ${JSON.stringify(response)}

`);
            res.end();
          } else {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(response));
          }
          if (jsonRpc.method === "tools/call") {
            const event = {
              type: "decision",
              tool: jsonRpc.params?.name,
              timestamp: (/* @__PURE__ */ new Date()).toISOString()
            };
            for (const client of sseClients) {
              try {
                client.write(`data: ${JSON.stringify(event)}

`);
              } catch {
                sseClients.delete(client);
              }
            }
          }
        } catch (err) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32700, message: "Parse error" },
            id: null
          }));
        }
      });
      return;
    }
    if (url.pathname === "/mcp" && req.method === "DELETE") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "session_closed" }));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: "not_found",
      endpoints: [
        "POST /mcp          \u2014 JSON-RPC endpoint (Streamable HTTP)",
        "GET  /mcp/sse      \u2014 Server-Sent Events stream",
        "GET  /health       \u2014 Health check",
        "DELETE /mcp        \u2014 Close session"
      ]
    }));
  });
  server.listen(port, host, () => {
    const address = server.address();
    const boundPort = address && typeof address === "object" ? address.port : port;
    process.stderr.write(`
[PROTECT_MCP] HTTP transport listening on http://${host.includes(":") ? `[${host}]` : host}:${boundPort}
`);
    process.stderr.write(`  POST   /mcp        \u2014 JSON-RPC (Streamable HTTP)
`);
    process.stderr.write(`  GET    /mcp/sse    \u2014 Server-Sent Events
`);
    process.stderr.write(`  GET    /health     \u2014 Health check
`);
    process.stderr.write(`  DELETE /mcp        \u2014 Close session
`);
    process.stderr.write(`
  Wrapping: ${serverCommand.join(" ")}
`);
    process.stderr.write(`  Mode: ${config.enforce ? "enforce" : "shadow"}
`);
    process.stderr.write(`  Bearer token: ${tokenFromEnv ? "from PROTECT_MCP_HTTP_TOKEN" : token}
`);
    process.stderr.write(`  Every request except GET /health needs the header Authorization: Bearer <token>
`);
    if (!LOOPBACK.has(host) && !host.startsWith("127.")) {
      process.stderr.write(`  Warning: ${host} is not a loopback address, so anything that can reach this port can try the token. Put TLS and authentication in front of it.
`);
    }
    process.stderr.write("\n");
  });
  const shutdown = () => {
    process.stderr.write("\n[PROTECT_MCP] Shutting down HTTP transport...\n");
    for (const client of sseClients) {
      try {
        client.end();
      } catch {
      }
    }
    server.close();
    gateway.stop();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
export {
  startHttpTransport
};
