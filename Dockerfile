FROM node:22-alpine
LABEL org.opencontainers.image.title="protect-mcp"
LABEL org.opencontainers.image.description="MCP security gateway with Ed25519-signed decision receipts"
LABEL org.opencontainers.image.source="https://github.com/scopeblind/scopeblind-gateway"
LABEL org.opencontainers.image.licenses="MIT"

RUN npm install -g protect-mcp@0.7.1

ENTRYPOINT ["protect-mcp"]
CMD ["--help"]
