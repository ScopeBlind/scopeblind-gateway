import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, normalize } from 'node:path';

export type ConnectorPilotId = 'github' | 'email-gmail' | 'filesystem-git' | 'slack-teams' | 'finance-pms' | 'nautilus-trader';

export interface ConnectorEnvVar {
  name: string;
  required: boolean;
  description: string;
}

export interface ConnectorAction {
  name: string;
  tool: string;
  risk: 'low' | 'medium' | 'high';
  mode: 'observe' | 'require_approval' | 'deny';
  description: string;
}

export interface ConnectorArtifact {
  path: string;
  contents: string;
  executable?: boolean;
}

export interface ConnectorPilot {
  id: ConnectorPilotId;
  category: string;
  name: string;
  status: 'usable-pilot';
  description: string;
  value: string;
  env: ConnectorEnvVar[];
  tools: string[];
  actions: ConnectorAction[];
  setup: string[];
  config: Record<string, unknown>;
  cedar: string;
  artifacts?: ConnectorArtifact[];
}

export interface InstalledConnectorPilot {
  id: string;
  name: string;
  category: string;
  status: string;
  config_path: string;
  policy_path: string;
}

const defaultPermit = `
// Default posture: observe all non-matching tools so the connector can be piloted in shadow mode.
permit(principal, action == Action::"MCP::Tool::call", resource);
`;

const nautilusBridgePy = String.raw`#!/usr/bin/env python3
"""
ScopeBlind external bridge for NautilusTrader-compatible pilots.

This file is intentionally outside NautilusTrader. It gives protect-mcp a stable
JSONL command boundary for staging, approval-gated submission, cancellation, and
event export while keeping the trading engine customer-owned.

Mock mode runs without NautilusTrader installed. Real mode is enabled by setting
NAUTILUS_BRIDGE_MODULE to "module.path:ClassName"; the class may implement:
  submit_order(order), modify_order(order), cancel_order(order), reconcile(order),
  export_events(since=None)
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class BridgeState:
    root: Path = field(default_factory=lambda: Path(os.environ.get("SCOPEBLIND_NAUTILUS_STATE_DIR", ".protect-mcp/nautilus")))

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.orders_path.touch(exist_ok=True)
        self.events_path.touch(exist_ok=True)

    @property
    def orders_path(self) -> Path:
        return self.root / "orders.jsonl"

    @property
    def events_path(self) -> Path:
        return self.root / "events.jsonl"

    def append_order(self, order: dict[str, Any]) -> None:
        with self.orders_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(order) + "\n")

    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        enriched = {
            "event_id": event.get("event_id") or f"nt-{now_ms()}-{len(event)}",
            "observed_at_ms": now_ms(),
            **event,
        }
        enriched["event_digest"] = sha256_json(enriched)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(enriched) + "\n")
        return enriched

    def events(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        with self.events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    rows.append(json.loads(line))
        return rows


class ScopeBlindNautilusBridge:
    def __init__(self) -> None:
        self.state = BridgeState()
        self.real = self._load_real_bridge()

    def _load_real_bridge(self) -> Any | None:
        target = os.environ.get("NAUTILUS_BRIDGE_MODULE")
        if not target:
            return None
        module_name, _, class_name = target.partition(":")
        if not module_name or not class_name:
            raise ValueError("NAUTILUS_BRIDGE_MODULE must be module.path:ClassName")
        module = importlib.import_module(module_name)
        return getattr(module, class_name)()

    def handle(self, command: dict[str, Any]) -> dict[str, Any]:
        action = command.get("action")
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "stage_order": self.stage_order,
            "submit_order": self.submit_order,
            "modify_order": self.modify_order,
            "cancel_order": self.cancel_order,
            "reconcile": self.reconcile,
            "export_events": self.export_events,
        }
        if action not in handlers:
            return self.error(command, "unknown_action", f"Unsupported action: {action}")
        try:
            return handlers[action](command)
        except Exception as exc:
            return self.error(command, "bridge_error", str(exc))

    def require(self, command: dict[str, Any], *fields: str) -> None:
        missing = [field for field in fields if command.get(field) in (None, "")]
        if missing:
            raise ValueError(f"missing required field(s): {', '.join(missing)}")

    def require_approved(self, command: dict[str, Any]) -> None:
        self.require(command, "approval_receipt")
        if command.get("mandate_passed") is not True:
            raise ValueError("mandate_passed must be true before live order mutation")

    def stage_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require(command, "client_order_id", "instrument_id", "side", "quantity")
        order = self.order_projection(command, status="staged")
        self.state.append_order(order)
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_staged.v1",
            "client_order_id": order["client_order_id"],
            "order_digest": sha256_json(order),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "staged", "order": order, "event": event})

    def submit_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        order = self.order_projection(command, status="submitted")
        if self.real and hasattr(self.real, "submit_order"):
            external = self.real.submit_order(order)
        else:
            external = {"mode": "mock", "external_order_id": f"MOCK-{order['client_order_id']}"}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_submitted.v1",
            "client_order_id": order["client_order_id"],
            "order_digest": sha256_json(order),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "submitted", "order": order, "external": external, "event": event})

    def modify_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "modify_order"):
            external = self.real.modify_order(command)
        else:
            external = {"mode": "mock", "modified": command["client_order_id"]}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_modified.v1",
            "client_order_id": command["client_order_id"],
            "command_digest": sha256_json(command),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "modified", "external": external, "event": event})

    def cancel_order(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require_approved(command)
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "cancel_order"):
            external = self.real.cancel_order(command)
        else:
            external = {"mode": "mock", "cancelled": command["client_order_id"]}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.order_cancelled.v1",
            "client_order_id": command["client_order_id"],
            "command_digest": sha256_json(command),
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "cancelled", "external": external, "event": event})

    def reconcile(self, command: dict[str, Any]) -> dict[str, Any]:
        self.require(command, "client_order_id")
        if self.real and hasattr(self.real, "reconcile"):
            external = self.real.reconcile(command)
        else:
            external = {"mode": "mock", "client_order_id": command["client_order_id"], "state": "accepted"}
        event = self.state.append_event({
            "type": "scopeblind.nautilus.reconciled.v1",
            "client_order_id": command["client_order_id"],
            "external_digest": sha256_json(external),
            "disclosure": "position_blind",
        })
        return self.ok(command, {"status": "reconciled", "external": external, "event": event})

    def export_events(self, command: dict[str, Any]) -> dict[str, Any]:
        if self.real and hasattr(self.real, "export_events"):
            external_events = self.real.export_events(command.get("since"))
        else:
            external_events = self.state.events()
        return self.ok(command, {
            "status": "exported",
            "event_count": len(external_events),
            "commitment_root": sha256_json(external_events),
            "events": external_events,
        })

    def order_projection(self, command: dict[str, Any], status: str) -> dict[str, Any]:
        return {
            "client_order_id": command["client_order_id"],
            "instrument_id": command["instrument_id"],
            "side": command["side"],
            "quantity": command["quantity"],
            "price": command.get("price"),
            "time_in_force": command.get("time_in_force", "GTC"),
            "strategy_id": command.get("strategy_id"),
            "mandate_digest": command.get("mandate_digest"),
            "approval_receipt": command.get("approval_receipt"),
            "status": status,
            "created_at_ms": now_ms(),
        }

    def ok(self, command: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "bridge": "scopeblind.nautilus.external.v1",
            "mode": "real" if self.real else "mock",
            "request_digest": sha256_json(command),
            **result,
        }

    def error(self, command: dict[str, Any], code: str, message: str) -> dict[str, Any]:
        return {
            "ok": False,
            "bridge": "scopeblind.nautilus.external.v1",
            "mode": "real" if self.real else "mock",
            "error": {"code": code, "message": message},
            "request_digest": sha256_json(command),
        }


def main() -> int:
    bridge = ScopeBlindNautilusBridge()
    for line in sys.stdin:
        if not line.strip():
            continue
        command = json.loads(line)
        print(canonical_json(bridge.handle(command)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
`;

const nautilusAdapterReadme = `# NautilusTrader-compatible external bridge

This connector is intentionally external to NautilusTrader. It lets protect-mcp
control and receipt high-risk order actions while a customer-owned Nautilus
process remains the trading engine.

## Local mock run

\`\`\`bash
python3 .protect-mcp/connectors/nautilus-trader/bridge.py <<'JSONL'
{"action":"stage_order","client_order_id":"SB-1","instrument_id":"AAPL.NASDAQ","side":"BUY","quantity":"50","price":"182.40","mandate_digest":"demo"}
{"action":"submit_order","client_order_id":"SB-1","instrument_id":"AAPL.NASDAQ","side":"BUY","quantity":"50","price":"182.40","mandate_digest":"demo","mandate_passed":true,"approval_receipt":"receipt-demo"}
{"action":"export_events"}
JSONL
\`\`\`

## Real mode

Set \`NAUTILUS_BRIDGE_MODULE=customer_module:BridgeClass\`. The class can
implement \`submit_order\`, \`modify_order\`, \`cancel_order\`, \`reconcile\`,
and \`export_events\`. Keep that glue in the customer's repository so Nautilus
licensing, credentials, and trading logic stay outside ScopeBlind.

## Upstream contribution posture

The best NautilusTrader contribution is not this bridge or a UI. It is a small,
vendor-neutral audit/event sink RFC: a documented way to export normalized order
commands, execution reports, fills, cancels, and reconciliation events so
external compliance wrappers can prove what happened without mutating the
engine.
`;

export const CONNECTOR_PILOTS: ConnectorPilot[] = [
  {
    id: 'github',
    category: 'code',
    name: 'GitHub pull-request control',
    status: 'usable-pilot',
    description: 'Controls GitHub REST/MCP calls for issue, PR, branch, and workflow actions.',
    value: 'Useful when agents already have repo access through GitHub MCP, gh, or a GitHub-backed tool server.',
    env: [
      { name: 'GITHUB_TOKEN', required: true, description: 'Fine-grained token scoped to the pilot repo.' },
      { name: 'GITHUB_REPOSITORY', required: true, description: 'owner/repo target for the pilot.' },
    ],
    tools: ['github.rest.request', 'github.issue.create', 'github.pull_request.merge', 'github.workflow.dispatch'],
    actions: [
      { name: 'Read repo metadata', tool: 'github.rest.request', risk: 'low', mode: 'observe', description: 'GET-only repository and PR inspection.' },
      { name: 'Create issue or comment', tool: 'github.issue.create', risk: 'medium', mode: 'require_approval', description: 'External write to the system of record.' },
      { name: 'Merge PR / dispatch workflow', tool: 'github.pull_request.merge', risk: 'high', mode: 'require_approval', description: 'Code-changing or CI-triggering action.' },
    ],
    setup: [
      'Create a fine-grained GitHub token for one repository.',
      'Set GITHUB_TOKEN and GITHUB_REPOSITORY.',
      'Run the agent through protect-mcp and review GitHub tool calls in the dashboard.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'github',
      target_env: ['GITHUB_TOKEN', 'GITHUB_REPOSITORY'],
      safe_read_probe: 'GET /repos/{GITHUB_REPOSITORY}',
      controlled_tools: ['github.rest.request', 'github.issue.create', 'github.pull_request.merge', 'github.workflow.dispatch'],
      approval_required_for: ['POST', 'PATCH', 'PUT', 'DELETE', 'merge', 'workflow_dispatch'],
      receipt_fields: ['method', 'path', 'repo', 'actor', 'payload_hash', 'approval_reason'],
    },
    cedar: `${defaultPermit}
// GitHub pilot: reads are observed; writes and merges need exact-action approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.pull_request.merge" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.workflow.dispatch" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "github.issue.create" && !context.approved };
`,
  },
  {
    id: 'email-gmail',
    category: 'communications',
    name: 'Gmail self-send / draft approval',
    status: 'usable-pilot',
    description: 'Uses the existing Gmail OAuth connector path and restricts send mode to email.self for the first production pilot.',
    value: 'Makes external communications reviewable before an agent can send mail.',
    env: [
      { name: 'GOOGLE_CLIENT_ID', required: true, description: 'OAuth client for Gmail.' },
      { name: 'GOOGLE_CLIENT_SECRET', required: true, description: 'OAuth client secret.' },
      { name: 'CONNECTOR_TOKEN_KEY', required: true, description: 'AES-GCM key material for sealed connector tokens.' },
    ],
    tools: ['gmail.draft.create', 'gmail.send.email_self', 'email.send'],
    actions: [
      { name: 'Create draft', tool: 'gmail.draft.create', risk: 'medium', mode: 'require_approval', description: 'Draft content can leak sensitive information.' },
      { name: 'Self-send test', tool: 'gmail.send.email_self', risk: 'medium', mode: 'require_approval', description: 'First release allows only sending to the account owner.' },
      { name: 'External send', tool: 'email.send', risk: 'high', mode: 'deny', description: 'Direct external send stays blocked until a customer-specific allowlist exists.' },
    ],
    setup: [
      'Configure Google OAuth redirect /fn/connectors/gmail/callback.',
      'Connect Gmail through the hosted console or local connector flow.',
      'Keep send mode to email.self until the customer approves recipient allowlists.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'gmail',
      hosted_functions: ['/fn/connectors/gmail/start', '/fn/connectors/gmail/callback', '/fn/connectors/gmail/send', '/fn/connectors/gmail/status'],
      first_release_scope: 'email.self',
      denied_until_configured: ['email.send.external', 'email.bulk_send'],
      receipt_fields: ['to_hash', 'subject_hash', 'body_hash', 'approval_reason', 'gmail_message_id'],
    },
    cedar: `${defaultPermit}
// Email pilot: no direct external send. Draft/self-send require exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "email.send" };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.draft.create" && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "gmail.send.email_self" && !context.approved };
`,
  },
  {
    id: 'filesystem-git',
    category: 'local-computer',
    name: 'Filesystem and Git control',
    status: 'usable-pilot',
    description: 'Controls reads, writes, shell commands, and Git mutation in the local project.',
    value: 'Immediately useful with Claude Code, Codex, Cursor, and any agent that edits files or runs shell commands.',
    env: [],
    tools: ['Read', 'Write', 'Edit', 'MultiEdit', 'Bash', 'git.commit', 'git.push'],
    actions: [
      { name: 'Read files', tool: 'Read', risk: 'low', mode: 'observe', description: 'Observe file reads for audit context.' },
      { name: 'Write/edit files', tool: 'Write', risk: 'medium', mode: 'require_approval', description: 'Require approval for sensitive paths or broad rewrites.' },
      { name: 'Git push/reset', tool: 'Bash', risk: 'high', mode: 'require_approval', description: 'Commands that publish, reset, or delete require exact-action approval.' },
    ],
    setup: [
      'Run protect-mcp init-hooks in the project.',
      'Install filesystem-safe and Git-safe policy packs.',
      'Review the dashboard before turning on enforce mode.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'filesystem-git',
      local_only: true,
      protected_paths: ['.env', '.ssh', 'keys/', 'secrets/', 'node_modules/'],
      dangerous_command_patterns: ['rm -rf', 'git push', 'git reset --hard', 'curl | sh', 'chmod 777'],
      receipt_fields: ['tool', 'path_hash', 'command_hash', 'diff_hash', 'approval_reason'],
    },
    cedar: `${defaultPermit}
// Filesystem/Git pilot: dangerous shell and protected-path writes need approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git reset --hard") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "Bash" && context.command_pattern.contains("git push") && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["Write", "Edit", "MultiEdit"].contains(context.tool) && context.path.contains(".env") && !context.approved };
`,
  },
  {
    id: 'slack-teams',
    category: 'communications',
    name: 'Slack or Teams outbound approval',
    status: 'usable-pilot',
    description: 'Controls messages to Slack channels or Microsoft Teams webhooks.',
    value: 'Makes high-impact internal broadcasts and client channels approval-gated.',
    env: [
      { name: 'SLACK_BOT_TOKEN', required: false, description: 'Slack bot token for chat.postMessage pilots.' },
      { name: 'SLACK_CHANNEL_ID', required: false, description: 'Default Slack channel for the pilot.' },
      { name: 'TEAMS_WEBHOOK_URL', required: false, description: 'Teams incoming webhook URL if Teams is preferred.' },
    ],
    tools: ['slack.chat.postMessage', 'slack.files.upload', 'teams.webhook.post'],
    actions: [
      { name: 'Post internal message', tool: 'slack.chat.postMessage', risk: 'medium', mode: 'require_approval', description: 'Message text and channel are read back before send.' },
      { name: 'Upload file', tool: 'slack.files.upload', risk: 'high', mode: 'require_approval', description: 'Files can leak customer data and need explicit approval.' },
      { name: 'Teams webhook post', tool: 'teams.webhook.post', risk: 'medium', mode: 'require_approval', description: 'Webhook destination and payload hash are receipted.' },
    ],
    setup: [
      'Choose Slack or Teams for the first pilot, not both.',
      'Set the relevant token/webhook environment variables.',
      'Start with a private test channel and exact-action approval for every send.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'slack-or-teams',
      supported_modes: ['slack.chat.postMessage', 'teams.webhook.post'],
      require_channel_allowlist: true,
      receipt_fields: ['channel_hash', 'message_hash', 'file_hash', 'approval_reason', 'provider_message_id'],
    },
    cedar: `${defaultPermit}
// Slack/Teams pilot: all outbound posts and uploads require approval by default.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["slack.chat.postMessage", "slack.files.upload", "teams.webhook.post"].contains(context.tool) && !context.approved };
`,
  },
  {
    id: 'finance-pms',
    category: 'finance',
    name: 'Finance PMS mock-to-real adapter',
    status: 'usable-pilot',
    description: 'Stages orders into a PMS adapter contract, with mock mode locally and real mode through PMS_ADAPTER_URL.',
    value: 'Gives hedge funds the controlled booking path: parse, mandate-check, approve, book, corroborate, receipt.',
    env: [
      { name: 'PMS_ADAPTER_URL', required: false, description: 'Customer-owned adapter endpoint. Omit for local mock mode.' },
      { name: 'PMS_ADAPTER_TOKEN', required: false, description: 'Bearer token for the customer-owned PMS adapter.' },
    ],
    tools: ['pms.order.stage', 'pms.order.book', 'pms.order.cancel', 'pms.reconcile'],
    actions: [
      { name: 'Stage order', tool: 'pms.order.stage', risk: 'medium', mode: 'require_approval', description: 'Creates a booking ticket but does not execute.' },
      { name: 'Book order', tool: 'pms.order.book', risk: 'high', mode: 'require_approval', description: 'Must pass mandate checks and human readback.' },
      { name: 'Cancel/order correction', tool: 'pms.order.cancel', risk: 'high', mode: 'require_approval', description: 'Mutates book state and requires approval.' },
    ],
    setup: [
      'Run local mock mode first with the Legate finance pilot pack.',
      'Point PMS_ADAPTER_URL at a customer-owned bridge when ready.',
      'Require mandate checks and exact-action approval before pms.order.book.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'finance-pms',
      mode: 'mock-first',
      adapter_contract: {
        stage: 'POST /orders/stage',
        book: 'POST /orders/book',
        cancel: 'POST /orders/{client_order_id}/cancel',
        reconcile: 'GET /orders/{client_order_id}',
      },
      receipt_fields: ['client_order_id', 'side', 'symbol_hash', 'qty', 'price', 'mandate_digest', 'approval_reason', 'external_confirmation_hash'],
    },
    cedar: `${defaultPermit}
// Finance/PMS pilot: booking actions require mandate pass and exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["pms.order.stage", "pms.order.book", "pms.order.cancel"].contains(context.tool) && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "pms.order.book" && context.mandate_passed != true };
`,
  },
  {
    id: 'nautilus-trader',
    category: 'finance',
    name: 'NautilusTrader-compatible external bridge',
    status: 'usable-pilot',
    description: 'Controls NautilusTrader-compatible staged orders through an external JSONL bridge, with local mock mode and customer-owned real mode.',
    value: 'Turns Nautilus into a strong Legate demo target: mandate-check, exact approval, external order event, position-blind audit bundle, and later reconciliation.',
    env: [
      { name: 'NAUTILUS_BRIDGE_MODULE', required: false, description: 'Optional customer glue in module.path:ClassName form for real Nautilus submission.' },
      { name: 'SCOPEBLIND_NAUTILUS_STATE_DIR', required: false, description: 'Optional state directory for local mock events. Defaults to .protect-mcp/nautilus.' },
      { name: 'NAUTILUS_TRADER_PROJECT', required: false, description: 'Optional path to the customer Nautilus project when running real mode.' },
    ],
    tools: [
      'nautilus.order.stage',
      'nautilus.order.submit',
      'nautilus.order.modify',
      'nautilus.order.cancel',
      'nautilus.strategy.deploy',
      'nautilus.event.export',
      'nautilus.reconcile',
    ],
    actions: [
      { name: 'Stage order', tool: 'nautilus.order.stage', risk: 'medium', mode: 'require_approval', description: 'Creates a position-blind booking intent and event commitment.' },
      { name: 'Submit order', tool: 'nautilus.order.submit', risk: 'high', mode: 'require_approval', description: 'Requires mandate pass plus exact approval before live order mutation.' },
      { name: 'Modify or cancel order', tool: 'nautilus.order.modify', risk: 'high', mode: 'require_approval', description: 'Mutates live order state and must carry a fresh approval receipt.' },
      { name: 'Deploy strategy', tool: 'nautilus.strategy.deploy', risk: 'high', mode: 'require_approval', description: 'Requires signed strategy pack, mandate scope, and operator approval.' },
      { name: 'Export event log', tool: 'nautilus.event.export', risk: 'low', mode: 'observe', description: 'Exports normalized event commitments for receipt corroboration.' },
    ],
    setup: [
      'Run mock mode first: protect-mcp connectors init nautilus-trader --force.',
      'Pipe stage/submit/reconcile JSONL through .protect-mcp/connectors/nautilus-trader/bridge.py.',
      'For real mode, set NAUTILUS_BRIDGE_MODULE to customer-owned glue that calls NautilusTrader APIs.',
      'Open an upstream NautilusTrader RFC for a neutral audit/event sink before proposing any PR.',
    ],
    config: {
      type: 'scopeblind.connector_pilot.v1',
      provider: 'nautilus-trader-compatible',
      mode: 'external-bridge-mock-first',
      license_boundary: 'No NautilusTrader code is bundled. Real mode calls a customer-owned process/module.',
      adapter_contract: {
        protocol: 'stdin/stdout JSONL',
        bridge: '.protect-mcp/connectors/nautilus-trader/bridge.py',
        real_mode_env: 'NAUTILUS_BRIDGE_MODULE=module.path:ClassName',
        actions: ['stage_order', 'submit_order', 'modify_order', 'cancel_order', 'reconcile', 'export_events'],
      },
      controlled_tools: [
        'nautilus.order.stage',
        'nautilus.order.submit',
        'nautilus.order.modify',
        'nautilus.order.cancel',
        'nautilus.strategy.deploy',
        'nautilus.event.export',
        'nautilus.reconcile',
      ],
      approval_required_for: ['submit_order', 'modify_order', 'cancel_order', 'strategy_deploy'],
      receipt_fields: [
        'client_order_id',
        'instrument_id_hash',
        'side',
        'quantity',
        'price',
        'mandate_digest',
        'approval_receipt',
        'external_event_digest',
        'commitment_root',
      ],
      upstream_rfc: {
        title: '[RFC] Add a vendor-neutral order/execution audit event sink',
        non_goals: ['ScopeBlind dependency', 'UI dashboard', 'AI tooling', 'new venue adapter'],
      },
    },
    artifacts: [
      { path: 'nautilus-trader/bridge.py', contents: nautilusBridgePy, executable: true },
      { path: 'nautilus-trader/README.md', contents: nautilusAdapterReadme },
    ],
    cedar: `${defaultPermit}
// NautilusTrader-compatible pilot: stage can be observed, but any live mutation requires exact approval.
forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["nautilus.order.submit", "nautilus.order.modify", "nautilus.order.cancel", "nautilus.strategy.deploy"].contains(context.tool) && !context.approved };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { ["nautilus.order.submit", "nautilus.order.modify", "nautilus.order.cancel"].contains(context.tool) && context.mandate_passed != true };

forbid(principal, action == Action::"MCP::Tool::call", resource)
when { context.tool == "nautilus.strategy.deploy" && context.strategy_pack_signed != true };
`,
  },
];

export function connectorPilotIds(): ConnectorPilotId[] {
  return CONNECTOR_PILOTS.map((pilot) => pilot.id);
}

export function getConnectorPilot(id: string): ConnectorPilot | undefined {
  return CONNECTOR_PILOTS.find((pilot) => pilot.id === id);
}

export function connectorDirectory(dir: string): string {
  return join(dir, '.protect-mcp', 'connectors');
}

export function writeConnectorPilots(opts: { dir: string; ids?: string[]; force?: boolean }): { written: string[]; pilots: ConnectorPilot[]; directory: string } {
  const directory = connectorDirectory(opts.dir);
  mkdirSync(directory, { recursive: true });
  const selected = (opts.ids && opts.ids.length > 0 && !opts.ids.includes('all'))
    ? opts.ids.map((id) => {
        const pilot = getConnectorPilot(id);
        if (!pilot) throw new Error(`Unknown connector pilot: ${id}`);
        return pilot;
      })
    : CONNECTOR_PILOTS;
  const written: string[] = [];
  for (const pilot of selected) {
    const configPath = join(directory, `${pilot.id}.json`);
    const policyPath = join(directory, `${pilot.id}.cedar`);
    if (!opts.force && (existsSync(configPath) || existsSync(policyPath))) {
      throw new Error(`Refusing to overwrite ${pilot.id}. Re-run with --force if intentional.`);
    }
    writeFileSync(configPath, JSON.stringify({ ...pilot.config, id: pilot.id, name: pilot.name, category: pilot.category, tools: pilot.tools, actions: pilot.actions, setup: pilot.setup }, null, 2) + '\n');
    writeFileSync(policyPath, pilot.cedar.endsWith('\n') ? pilot.cedar : `${pilot.cedar}\n`);
    written.push(configPath, policyPath);
    for (const artifact of pilot.artifacts || []) {
      const artifactPath = connectorArtifactPath(directory, artifact.path);
      mkdirSync(dirname(artifactPath), { recursive: true });
      writeFileSync(artifactPath, artifact.contents.endsWith('\n') ? artifact.contents : `${artifact.contents}\n`);
      if (artifact.executable) chmodSync(artifactPath, 0o755);
      written.push(artifactPath);
    }
  }
  writeFileSync(join(directory, 'README.md'), renderConnectorReadme(selected));
  written.push(join(directory, 'README.md'));
  return { written, pilots: selected, directory };
}

function connectorArtifactPath(directory: string, relativePath: string): string {
  const clean = normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, '');
  if (clean.startsWith('/') || clean.includes('..')) {
    throw new Error(`Unsafe connector artifact path: ${relativePath}`);
  }
  return join(directory, clean);
}

export function readInstalledConnectorPilots(dir: string): InstalledConnectorPilot[] {
  const directory = connectorDirectory(dir);
  if (!existsSync(directory)) return [];
  return readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .map((name) => {
      const configPath = join(directory, name);
      try {
        const parsed = JSON.parse(readFileSync(configPath, 'utf-8')) as Record<string, any>;
        const id = String(parsed.id || name.replace(/\.json$/, ''));
        const pilot = getConnectorPilot(id);
        return {
          id,
          name: String(parsed.name || pilot?.name || id),
          category: String(parsed.category || pilot?.category || 'unknown'),
          status: String(parsed.status || parsed.type || 'installed'),
          config_path: configPath,
          policy_path: join(directory, `${id}.cedar`),
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean) as InstalledConnectorPilot[];
}

export function connectorDoctor(dir: string, env: NodeJS.ProcessEnv = process.env): Array<Record<string, unknown>> {
  const installed = new Set(readInstalledConnectorPilots(dir).map((pilot) => pilot.id));
  return CONNECTOR_PILOTS.map((pilot) => {
    const envRows = pilot.env.map((item) => ({
      name: item.name,
      required: item.required,
      present: Boolean(env[item.name]),
      description: item.description,
    }));
    const missingRequired = envRows.filter((item) => item.required && !item.present).map((item) => item.name);
    const optionalPresent = envRows.filter((item) => !item.required && item.present).map((item) => item.name);
    const optionalProviderReady = pilot.id === 'slack-teams'
      ? Boolean(env.SLACK_BOT_TOKEN || env.TEAMS_WEBHOOK_URL)
      : pilot.id === 'finance-pms'
        ? Boolean(env.PMS_ADAPTER_URL)
        : pilot.id === 'nautilus-trader'
          ? Boolean(env.NAUTILUS_BRIDGE_MODULE || env.NAUTILUS_TRADER_PROJECT)
        : false;
    const mockModeReady = pilot.id === 'finance-pms' || pilot.id === 'nautilus-trader';
    return {
      id: pilot.id,
      name: pilot.name,
      category: pilot.category,
      installed: installed.has(pilot.id),
      usable: missingRequired.length === 0 && (pilot.env.some((item) => item.required) || pilot.env.length === 0 || optionalProviderReady || mockModeReady),
      mode: pilot.id === 'finance-pms' && !env.PMS_ADAPTER_URL ? 'mock' : pilot.id === 'nautilus-trader' && !env.NAUTILUS_BRIDGE_MODULE ? 'mock_bridge' : pilot.id === 'slack-teams' && !env.SLACK_BOT_TOKEN && !env.TEAMS_WEBHOOK_URL ? 'needs_provider_choice' : 'configured_or_local',
      missing_required: missingRequired,
      optional_present: optionalPresent,
      tools: pilot.tools,
      next: missingRequired.length > 0 ? `Set ${missingRequired.join(', ')}` : installed.has(pilot.id) ? 'Run through protect-mcp and inspect the dashboard.' : `Install with protect-mcp connectors init ${pilot.id}`,
    };
  });
}

function renderConnectorReadme(pilots: ConnectorPilot[]): string {
  return `# protect-mcp connector pilots\n\nThese files make real tool classes visible and controllable without uploading raw prompts or payloads.\n\n${pilots.map((pilot) => `## ${pilot.name}\n\n${pilot.description}\n\nValue: ${pilot.value}\n\nTools: ${pilot.tools.map((tool) => `\`${tool}\``).join(', ')}\n\nSetup:\n${pilot.setup.map((step) => `- ${step}`).join('\n')}\n${pilot.artifacts?.length ? `\nGenerated files:\n${pilot.artifacts.map((artifact) => `- \`${artifact.path}\``).join('\n')}\n` : ''}`).join('\n')}\nNext: run \`npx protect-mcp dashboard --open\` and review tool inventory, policy coverage, approvals, and receipts.\n`;
}
