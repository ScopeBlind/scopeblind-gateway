/**
 * @scopeblind/protect-mcp — External PDP Adapter
 *
 * BYOPE (Bring Your Own Policy Engine) — sends decision context
 * to an external Policy Decision Point via HTTP webhook.
 *
 * Supports OPA, Cerbos, Cedar (AWS), and generic JSON formats.
 * ScopeBlind always signs the receipt regardless of who made the decision.
 *
 * Sprint 2: One HTTP webhook adapter. More adapters later.
 */

import type {
  DecisionContext,
  ExternalDecision,
  ExternalPDPConfig,
  TrustTier,
} from './types.js';

/**
 * Query an external PDP for a policy decision.
 *
 * @param context - The decision context (transport-agnostic)
 * @param config - External PDP configuration
 * @returns ExternalDecision with allow/deny and optional metadata
 */
export async function queryExternalPDP(
  context: DecisionContext,
  config: ExternalPDPConfig,
): Promise<ExternalDecision> {
  const timeout = config.timeout_ms || 500;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const body = formatRequest(context, config.format || 'generic');

    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      return fallbackDecision(config, `PDP returned HTTP ${response.status}`);
    }

    const result = await response.json();
    return parseResponse(result, config.format || 'generic');
  } catch (err) {
    clearTimeout(timer);

    if (err instanceof Error && err.name === 'AbortError') {
      return fallbackDecision(config, `PDP timeout after ${timeout}ms`);
    }

    return fallbackDecision(config, `PDP error: ${err instanceof Error ? err.message : 'unknown'}`);
  }
}

/**
 * Format the request body for the external PDP.
 */
function formatRequest(
  context: DecisionContext,
  format: string,
): Record<string, unknown> {
  switch (format) {
    case 'opa':
      // OPA Data API format
      return {
        input: {
          actor: context.actor,
          action: context.action,
          target: context.target,
          credential_ref: context.credential_ref,
          mode: context.mode,
          metadata: context.request_metadata,
        },
      };

    case 'cerbos':
      // Cerbos-style request
      return {
        principal: {
          id: context.actor.id || 'unknown',
          roles: [context.actor.tier],
          attr: {
            manifest_hash: context.actor.manifest_hash,
          },
        },
        resource: {
          kind: 'tool',
          id: context.action.tool,
          attr: context.target,
        },
        actions: [context.action.operation || 'call'],
      };

    case 'cedar':
      // AWS Cedar / Cedar Agent format
      // Compatible with AWS AgentCore Policy (GA March 2026)
      // Cedar expects: principal, action, resource, context
      return {
        principal: {
          type: 'Agent',
          id: context.actor.id || 'unknown',
        },
        action: {
          type: 'Action',
          id: `MCP::Tool::${context.action.operation || 'call'}`,
        },
        resource: {
          type: 'Tool',
          id: context.action.tool,
        },
        context: {
          tier: context.actor.tier,
          manifest_hash: context.actor.manifest_hash || null,
          service: context.target.service || 'default',
          mode: context.mode,
          credential_ref: context.credential_ref || null,
        },
      };

    case 'generic':
    default:
      // Pass the full context as-is
      return context as unknown as Record<string, unknown>;
  }
}

/**
 * Parse the response from the external PDP.
 */
function parseResponse(
  result: Record<string, unknown>,
  format: string,
): ExternalDecision {
  switch (format) {
    case 'opa':
      // OPA returns { result: boolean } or { result: { allow: boolean } }
      if (typeof result.result === 'boolean') {
        return { allowed: result.result };
      }
      if (result.result && typeof result.result === 'object') {
        const r = result.result as Record<string, unknown>;
        return {
          allowed: Boolean(r.allow),
          reason: r.reason as string | undefined,
          metadata: r,
        };
      }
      return { allowed: false, reason: 'unrecognized OPA response' };

    case 'cerbos':
      // Cerbos returns { results: [{ actions: { call: "EFFECT_ALLOW" } }] }
      if (Array.isArray(result.results) && result.results.length > 0) {
        const actions = (result.results[0] as Record<string, unknown>).actions as Record<string, string>;
        if (actions) {
          const effect = Object.values(actions)[0];
          return { allowed: effect === 'EFFECT_ALLOW' };
        }
      }
      return { allowed: false, reason: 'unrecognized Cerbos response' };

    case 'cedar':
      // Cedar returns { decision: "Allow" | "Deny", diagnostics?: {...} }
      // Also supports Cedar Agent batch format: { results: [{ decision: "Allow" }] }
      if (typeof result.decision === 'string') {
        return {
          allowed: result.decision === 'Allow',
          reason: result.decision === 'Deny'
            ? `cedar_deny${result.diagnostics ? ': ' + JSON.stringify(result.diagnostics) : ''}`
            : undefined,
          metadata: result.diagnostics as Record<string, unknown> | undefined,
        };
      }
      if (Array.isArray(result.results) && result.results.length > 0) {
        const first = result.results[0] as Record<string, unknown>;
        return {
          allowed: first.decision === 'Allow',
          reason: first.decision === 'Deny' ? 'cedar_deny' : undefined,
        };
      }
      return { allowed: false, reason: 'unrecognized Cedar response' };

    case 'generic':
    default:
      // Expect { allowed: boolean, reason?: string }
      return {
        allowed: Boolean(result.allowed),
        reason: result.reason as string | undefined,
        metadata: result.metadata as Record<string, unknown> | undefined,
      };
  }
}

/**
 * Return the fallback decision when the PDP is unreachable.
 */
function fallbackDecision(config: ExternalPDPConfig, reason: string): ExternalDecision {
  const fallback = config.fallback || 'deny';
  return {
    allowed: fallback === 'allow',
    reason: `fallback_${fallback}: ${reason}`,
  };
}

/**
 * Build a DecisionContext from a tool call.
 */
export function buildDecisionContext(
  toolName: string,
  tier: TrustTier,
  opts: {
    agentId?: string;
    manifestHash?: string;
    credentialRef?: string;
    mode: 'shadow' | 'enforce';
    slug?: string;
    requestMetadata?: Record<string, unknown>;
  },
): DecisionContext {
  return {
    v: 1,
    actor: {
      id: opts.agentId,
      tier,
      manifest_hash: opts.manifestHash,
    },
    action: {
      tool: toolName,
      operation: 'call',
    },
    target: {
      service: opts.slug || 'default',
    },
    credential_ref: opts.credentialRef,
    mode: opts.mode,
    request_metadata: opts.requestMetadata || {},
  };
}
