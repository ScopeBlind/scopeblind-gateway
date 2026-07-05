import {
  ProtectGateway
} from "./chunk-VTPZ4G5I.mjs";
import "./chunk-WIPWNWMJ.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/http-transport.ts
import { createServer } from "http";
async function startHttpTransport(options) {
  const { port, config, serverCommand } = options;
  const sseClients = /* @__PURE__ */ new Set();
  const httpConfig = {
    ...config,
    command: serverCommand[0],
    args: serverCommand.slice(1)
  };
  const gateway = new ProtectGateway(httpConfig);
  await gateway.startForHttp();
  const server = createServer(async (req, res) => {
    const origin = req.headers.origin || "*";
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
    res.setHeader("Access-Control-Allow-Credentials", "true");
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
        mode: config.policy ? config.enforce ? "enforce" : "shadow" : "shadow",
        wrapping: serverCommand.join(" ")
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
  server.listen(port, () => {
    process.stderr.write(`
[PROTECT_MCP] HTTP transport listening on http://0.0.0.0:${port}
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
