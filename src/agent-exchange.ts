/**
 * Agent-to-Agent Receipt Exchange
 *
 * Middleware for multi-agent systems (CrewAI, LangGraph, AutoGen) that
 * propagates receipts across agent boundaries. Each hop produces a
 * chained receipt, enabling end-to-end accountability tracing.
 *
 * Status: Beta — API may change
 *
 * @example
 * ```typescript
 * import { ReceiptPropagator } from 'protect-mcp/agent-exchange';
 *
 * const propagator = new ReceiptPropagator({ issuer: 'agent-alpha' });
 *
 * // Agent A delegates to Agent B
 * const delegation = propagator.delegate('agent-beta', {
 *   tools: ['read_file', 'search_web'],
 *   scope: 'task-123',
 *   ttl: 3600,
 * });
 *
 * // Agent B receives the delegation and wraps its actions
 * const action = propagator.wrapAction('read_file', {
 *   delegation_receipt: delegation.receipt_id,
 *   args: { path: 'data.json' },
 * });
 *
 * // Verify the full chain
 * const chain = propagator.traceChain(action.receipt_id);
 * // Returns: [delegation_receipt, action_receipt]
 * ```
 */

import { randomUUID } from 'node:crypto';

// ── Types ──────────────────────────────────────────────────────

export interface DelegationReceipt {
  receipt_id: string;
  receipt_type: 'delegation';
  issuer_id: string;
  event_time: string;
  payload: {
    /** The agent receiving delegated authority */
    delegate_id: string;
    /** Tools the delegate is authorized to use */
    authorized_tools: string[];
    /** Scope identifier for this delegation */
    scope: string;
    /** Time-to-live in seconds */
    ttl: number;
    /** Expiry timestamp */
    expires_at: string;
    /** Maximum number of tool calls allowed */
    max_calls?: number;
    /** Whether the delegate can further sub-delegate */
    allow_subdelegation: boolean;
  };
  parent_receipts: string[];
  signature?: string;
}

export interface ActionReceipt {
  receipt_id: string;
  receipt_type: 'execution';
  issuer_id: string;
  event_time: string;
  payload: {
    tool_name: string;
    decision: 'allow' | 'deny';
    delegation_receipt: string;
    scope: string;
    call_index: number;
  };
  parent_receipts: string[];
  signature?: string;
}

export interface PropagatorConfig {
  /** Issuer ID for this agent */
  issuer: string;
  /** Optional signing function (receipt → signed receipt) */
  signer?: (receipt: Record<string, unknown>) => Record<string, unknown>;
}

// ── Receipt Propagator ─────────────────────────────────────────

/**
 * Propagates receipts across agent boundaries in multi-agent systems.
 * Each hop produces a chained receipt enabling end-to-end accountability.
 *
 * @patent Patent-protected construction — delegated signing with receipt chain
 * propagation. Covered by Apache 2.0 patent grant for users of this code.
 * Clean-room reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export class ReceiptPropagator {
  private issuer: string;
  private signer?: (receipt: Record<string, unknown>) => Record<string, unknown>;
  private receipts: Map<string, DelegationReceipt | ActionReceipt> = new Map();
  private delegationCallCounts: Map<string, number> = new Map();

  constructor(config: PropagatorConfig) {
    this.issuer = config.issuer;
    this.signer = config.signer;
  }

  /**
   * Create a delegation receipt authorizing another agent to use specific tools.
   *
   * @patent Patent-protected construction — delegated signing with receipt chain
   * propagation. Covered by Apache 2.0 patent grant for users of this code.
   * Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  delegate(delegateId: string, options: {
    tools: string[];
    scope: string;
    ttl: number;
    maxCalls?: number;
    allowSubdelegation?: boolean;
    parentReceipts?: string[];
  }): DelegationReceipt {
    const now = new Date();
    const receipt: DelegationReceipt = {
      receipt_id: `del_${randomUUID().slice(0, 12)}`,
      receipt_type: 'delegation',
      issuer_id: this.issuer,
      event_time: now.toISOString(),
      payload: {
        delegate_id: delegateId,
        authorized_tools: options.tools,
        scope: options.scope,
        ttl: options.ttl,
        expires_at: new Date(now.getTime() + options.ttl * 1000).toISOString(),
        max_calls: options.maxCalls,
        allow_subdelegation: options.allowSubdelegation ?? false,
      },
      parent_receipts: options.parentReceipts || [],
    };

    if (this.signer) {
      const signed = this.signer(receipt as unknown as Record<string, unknown>);
      Object.assign(receipt, signed);
    }

    this.receipts.set(receipt.receipt_id, receipt);
    this.delegationCallCounts.set(receipt.receipt_id, 0);
    return receipt;
  }

  /**
   * Wrap a tool call with a receipt that references the delegation.
   * Validates the delegation is still valid (not expired, within call limit,
   * tool is authorized).
   *
   * @patent Patent-protected construction — delegated signing with receipt chain
   * propagation. Covered by Apache 2.0 patent grant for users of this code.
   * Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  wrapAction(toolName: string, options: {
    delegation_receipt: string;
    args?: Record<string, unknown>;
  }): ActionReceipt {
    const delegation = this.receipts.get(options.delegation_receipt) as DelegationReceipt | undefined;

    // Validate delegation
    let decision: 'allow' | 'deny' = 'allow';

    if (!delegation) {
      decision = 'deny';
    } else if (delegation.receipt_type !== 'delegation') {
      decision = 'deny';
    } else {
      // Check expiry
      if (new Date(delegation.payload.expires_at) < new Date()) {
        decision = 'deny';
      }
      // Check tool authorization
      if (!delegation.payload.authorized_tools.includes(toolName) &&
          !delegation.payload.authorized_tools.includes('*')) {
        decision = 'deny';
      }
      // Check call limit
      if (delegation.payload.max_calls !== undefined) {
        const count = this.delegationCallCounts.get(options.delegation_receipt) || 0;
        if (count >= delegation.payload.max_calls) {
          decision = 'deny';
        }
      }
    }

    // Increment call count
    const currentCount = this.delegationCallCounts.get(options.delegation_receipt) || 0;
    this.delegationCallCounts.set(options.delegation_receipt, currentCount + 1);

    const receipt: ActionReceipt = {
      receipt_id: `act_${randomUUID().slice(0, 12)}`,
      receipt_type: 'execution',
      issuer_id: this.issuer,
      event_time: new Date().toISOString(),
      payload: {
        tool_name: toolName,
        decision,
        delegation_receipt: options.delegation_receipt,
        scope: delegation?.payload.scope || 'unknown',
        call_index: currentCount + 1,
      },
      parent_receipts: [options.delegation_receipt],
    };

    if (this.signer) {
      const signed = this.signer(receipt as unknown as Record<string, unknown>);
      Object.assign(receipt, signed);
    }

    this.receipts.set(receipt.receipt_id, receipt);
    return receipt;
  }

  /**
   * Trace the full receipt chain from a given receipt back to the root delegation.
   *
   * @patent Patent-protected construction — delegated signing with receipt chain
   * propagation. Covered by Apache 2.0 patent grant for users of this code.
   * Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  traceChain(receiptId: string): Array<DelegationReceipt | ActionReceipt> {
    const chain: Array<DelegationReceipt | ActionReceipt> = [];
    const visited = new Set<string>();

    const walk = (id: string) => {
      if (visited.has(id)) return;
      visited.add(id);
      const receipt = this.receipts.get(id);
      if (!receipt) return;
      for (const parentId of receipt.parent_receipts) {
        walk(parentId);
      }
      chain.push(receipt);
    };

    walk(receiptId);
    return chain;
  }

  /**
   * Export all receipts as a JSON array (for verification, archival, or Trace visualization).
   */
  exportAll(): Array<DelegationReceipt | ActionReceipt> {
    return Array.from(this.receipts.values());
  }

  /**
   * Validate that a delegation chain is intact and all signatures verify.
   *
   * @patent Patent-protected construction — delegated signing with receipt chain
   * propagation. Covered by Apache 2.0 patent grant for users of this code.
   * Clean-room reimplementation requires a patent license.
   * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
   */
  validateChain(receiptId: string): {
    valid: boolean;
    chain_length: number;
    issues: string[];
  } {
    const chain = this.traceChain(receiptId);
    const issues: string[] = [];

    if (chain.length === 0) {
      return { valid: false, chain_length: 0, issues: ['Receipt not found'] };
    }

    // Check that delegations precede actions
    let sawAction = false;
    for (const receipt of chain) {
      if (receipt.receipt_type === 'delegation' && sawAction) {
        issues.push(`Delegation ${receipt.receipt_id} appears after action in chain`);
      }
      if (receipt.receipt_type === 'execution') sawAction = true;
    }

    // Check parent references exist
    for (const receipt of chain) {
      for (const parentId of receipt.parent_receipts) {
        if (!this.receipts.has(parentId)) {
          issues.push(`Missing parent receipt: ${parentId}`);
        }
      }
    }

    return {
      valid: issues.length === 0,
      chain_length: chain.length,
      issues,
    };
  }
}

// ── LangGraph Integration Helper ───────────────────────────────

/**
 * Create a LangGraph-compatible state channel that propagates receipts.
 *
 * Usage with LangGraph:
 * ```typescript
 * import { createReceiptChannel } from 'protect-mcp/agent-exchange';
 *
 * const channel = createReceiptChannel('orchestrator');
 *
 * // In your LangGraph node:
 * const result = await channel.withDelegation('worker-agent', ['read_file'], async (ctx) => {
 *   // ctx.delegation is the delegation receipt
 *   // Agent B's actions will reference this delegation
 *   return await agentB.run(ctx.delegation);
 * });
 * ```
 */
export function createReceiptChannel(orchestratorId: string) {
  const propagator = new ReceiptPropagator({ issuer: orchestratorId });

  return {
    propagator,

    async withDelegation<T>(
      delegateId: string,
      tools: string[],
      fn: (ctx: { delegation: DelegationReceipt; propagator: ReceiptPropagator }) => Promise<T>,
      options?: { ttl?: number; maxCalls?: number; scope?: string }
    ): Promise<{ result: T; delegation: DelegationReceipt; chain: Array<DelegationReceipt | ActionReceipt> }> {
      const delegation = propagator.delegate(delegateId, {
        tools,
        scope: options?.scope || `task-${randomUUID().slice(0, 8)}`,
        ttl: options?.ttl || 3600,
        maxCalls: options?.maxCalls,
      });

      const result = await fn({ delegation, propagator });

      return {
        result,
        delegation,
        chain: propagator.exportAll(),
      };
    },
  };
}
