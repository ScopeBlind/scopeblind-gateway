# Integrating protect-mcp with Popular MCP Servers

## Overview

`protect-mcp` wraps **any** stdio-based MCP server as a transparent proxy. This guide shows copy-paste configurations for popular community MCP servers.

The pattern is always the same:

```
protect-mcp [options] -- <original-mcp-server-command>
```

## Quick Start

```bash
# 1. Initialize (generates keys + policy template)
npx protect-mcp init

# 2. Run with your server
npx protect-mcp --policy protect-mcp.json -- <your-server-command>
```

---

## Filesystem Server (@modelcontextprotocol/server-filesystem)

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "protect-mcp", "--policy", "protect-mcp.json", "--",
        "npx", "@modelcontextprotocol/server-filesystem", "/Users/you/allowed-dir"
      ]
    }
  }
}
```

**Recommended policy** (`protect-mcp.json`):
```json
{
  "tools": {
    "*": { "rate_limit": "100/hour" },
    "write_file": { "min_tier": "signed-known", "rate_limit": "20/hour" },
    "delete_file": { "block": true },
    "move_file": { "min_tier": "signed-known" }
  }
}
```

---

## PostgreSQL Server (@modelcontextprotocol/server-postgres)

```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": [
        "protect-mcp", "--policy", "protect-mcp.json", "--",
        "npx", "@modelcontextprotocol/server-postgres"
      ],
      "env": {
        "DATABASE_URL": "postgresql://user:pass@localhost:5432/mydb"
      }
    }
  }
}
```

**Recommended policy** — credential isolation + destructive query blocking:
```json
{
  "tools": {
    "*": { "rate_limit": "50/hour" },
    "query": { "rate_limit": "30/hour" },
    "execute": { "min_tier": "privileged", "rate_limit": "5/hour" }
  },
  "credentials": {
    "database_url": {
      "inject": "env",
      "name": "DATABASE_URL",
      "value_env": "DATABASE_URL"
    }
  }
}
```

---

## Brave Search Server (@modelcontextprotocol/server-brave-search)

```json
{
  "mcpServers": {
    "brave-search": {
      "command": "npx",
      "args": [
        "protect-mcp", "--policy", "protect-mcp.json", "--",
        "npx", "@modelcontextprotocol/server-brave-search"
      ],
      "env": {
        "BRAVE_API_KEY": "your-brave-api-key"
      }
    }
  }
}
```

**Recommended policy** — rate limiting to control API costs:
```json
{
  "tools": {
    "brave_web_search": { "rate_limit": "20/hour" },
    "brave_local_search": { "rate_limit": "10/hour" }
  },
  "credentials": {
    "brave_api": {
      "inject": "env",
      "name": "BRAVE_API_KEY",
      "value_env": "BRAVE_API_KEY"
    }
  }
}
```

---

## GitHub Server (@modelcontextprotocol/server-github)

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "protect-mcp", "--policy", "protect-mcp.json", "--",
        "npx", "@modelcontextprotocol/server-github"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..."
      }
    }
  }
}
```

**Recommended policy** — protect write operations:
```json
{
  "tools": {
    "*": { "rate_limit": "100/hour" },
    "create_issue": { "min_tier": "signed-known", "rate_limit": "10/hour" },
    "create_pull_request": { "min_tier": "signed-known", "rate_limit": "5/hour" },
    "push_files": { "min_tier": "privileged", "rate_limit": "5/hour" },
    "delete_file": { "block": true }
  },
  "credentials": {
    "github_token": {
      "inject": "env",
      "name": "GITHUB_PERSONAL_ACCESS_TOKEN",
      "value_env": "GITHUB_PERSONAL_ACCESS_TOKEN"
    }
  }
}
```

---

## Custom / Any MCP Server

Any stdio-based MCP server works. The pattern:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": [
        "protect-mcp", "--policy", "protect-mcp.json", "--",
        "node", "my-custom-server.js"
      ]
    }
  }
}
```

## Using with External Policy Engines (BYOPE)

protect-mcp can delegate decisions to OPA, Cerbos, or any HTTP policy endpoint:

```json
{
  "tools": {
    "*": { "rate_limit": "100/hour" }
  },
  "policy_engine": "hybrid",
  "external": {
    "endpoint": "http://localhost:8181/v1/data/mcp/allow",
    "format": "opa",
    "timeout_ms": 300,
    "fallback": "deny"
  }
}
```

Supported formats: `opa`, `cerbos`, `generic`.

In `hybrid` mode, both the external PDP and built-in policy are consulted.
In `external` mode, only the external PDP decision is used (built-in policy is skipped).

## Verifying Receipts

After running with signing enabled (`npx protect-mcp init`), verify receipts:

```bash
# From the receipt JSON printed to stderr
npx @veritasacta/verify receipt.json

# Or paste at
# https://scopeblind.com/verify
```

## Monitoring with `status`

```bash
npx protect-mcp status
```

Shows tool call counts, allow/deny breakdown, tier distribution, and decision reasons from the local `.protect-mcp-log.jsonl` file.
