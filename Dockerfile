FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
COPY --from=builder /app/policies ./policies
LABEL org.opencontainers.image.title="protect-mcp"
LABEL org.opencontainers.image.description="MCP security gateway with Ed25519-signed decision receipts"
LABEL org.opencontainers.image.source="https://github.com/scopeblind/scopeblind-gateway"
LABEL org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["mcp"]
