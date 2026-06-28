/**
 * scopeblind-bridge.ts
 *
 * Optional bridge between protect-mcp (local, MIT) and a paid ScopeBlind
 * tenant. When SCOPEBLIND_TOKEN is set in the environment, every signed
 * receipt that protect-mcp emits also gets forwarded to the tenant's
 * dashboard at https://scopeblind.com/console/<slug>.
 *
 * Lifecycle:
 *   1. On first use, exchange SCOPEBLIND_TOKEN for a short-lived BRASS-v2
 *      auth proof from /fn/brass/issue. Cache the proof in memory until
 *      ~5 minutes before expiry, then refresh.
 *   2. As receipts are emitted by hook-server.ts, push them into an
 *      in-memory batch queue.
 *   3. Flush the queue every 5s (or when it reaches 128 receipts) by POSTing
 *      to /fn/console/<slug>/receipts with Bearer SCOPEBLIND_TOKEN.
 *
 * Failure mode: forward errors NEVER throw upstream. protect-mcp continues
 * to mint and persist receipts locally regardless of dashboard availability.
 * The bridge logs failures to stderr (best-effort) and retries on the next
 * flush.
 *
 * Configuration:
 *   SCOPEBLIND_TOKEN        Tenant bearer token (from welcome email).
 *   SCOPEBLIND_TENANT       Optional slug override. By default we discover
 *                           the slug from the BRASS proof's tenant_id.
 *   SCOPEBLIND_BASE         Defaults to https://scopeblind.com.
 *
 * @license MIT
 */

const DEFAULT_BASE = "https://scopeblind.com";
const FLUSH_INTERVAL_MS = 5_000;
const BATCH_MAX = 128;
const BRASS_REFRESH_MARGIN_MS = 5 * 60 * 1000; // refresh 5 min before expiry

interface BrassAuthProof {
  type: "brass-v2";
  scope: string;
  tier: string;
  tenant_id: string;
  expires_at: string;
  issued_at: string;
  nullifier: string;
  signature: string;
  kid: string;
  alg: string;
}

interface BridgeStats {
  enabled: boolean;
  tenant_slug: string | null;
  forwarded_total: number;
  rejected_total: number;
  last_flush_at: string | null;
  last_error: string | null;
}

export class ScopeBlindBridge {
  private readonly token: string | null;
  private readonly base: string;
  private readonly tenantOverride: string | null;
  private cachedProof: BrassAuthProof | null = null;
  private queue: any[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private stats: BridgeStats;
  private shuttingDown = false;

  constructor(env: Record<string, string | undefined> = process.env) {
    this.token = env.SCOPEBLIND_TOKEN || null;
    this.base = (env.SCOPEBLIND_BASE || DEFAULT_BASE).replace(/\/$/, "");
    this.tenantOverride = env.SCOPEBLIND_TENANT || null;
    this.stats = {
      enabled: Boolean(this.token),
      tenant_slug: this.tenantOverride,
      forwarded_total: 0,
      rejected_total: 0,
      last_flush_at: null,
      last_error: null,
    };

    if (this.enabled()) {
      this.flushTimer = setInterval(() => { void this.flush(); }, FLUSH_INTERVAL_MS);
      // Don't keep the Node event loop alive just for flushing.
      if (typeof this.flushTimer === "object" && this.flushTimer && "unref" in this.flushTimer) {
        (this.flushTimer as any).unref?.();
      }
      // Best-effort flush on process exit.
      process.on("beforeExit", () => { void this.shutdown(); });
    }
  }

  enabled(): boolean { return Boolean(this.token); }

  /** Push a signed receipt into the queue. Non-blocking. */
  forward(signedReceipt: any): void {
    if (!this.enabled() || this.shuttingDown) return;
    this.queue.push(signedReceipt);
    if (this.queue.length >= BATCH_MAX) void this.flush();
  }

  /** Flush the queue. Safe to call concurrently. */
  async flush(): Promise<void> {
    if (!this.enabled() || this.queue.length === 0) return;
    const batch = this.queue.splice(0, BATCH_MAX);
    try {
      const proof = await this.ensureBrassProof();
      const slug = this.tenantOverride || proof?.tenant_id;
      if (!slug) {
        // Without a tenant, we can't address the ingestion endpoint. Re-queue
        // and try again next flush; common during the first call.
        this.queue.unshift(...batch);
        return;
      }
      this.stats.tenant_slug = slug;

      const res = await fetch(`${this.base}/fn/console/${slug}/receipts`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.token}`,
          "user-agent": "protect-mcp/scopeblind-bridge",
        },
        body: JSON.stringify({ receipts: batch }),
      });

      if (!res.ok) {
        const errBody = await res.text().catch(() => "");
        this.stats.last_error = `HTTP ${res.status} ${errBody.slice(0, 160)}`;
        this.stats.rejected_total += batch.length;
        // 429 = daily quota or rate limit; drop the batch (don't loop), the
        // local .receipts/ chain remains authoritative.
        if (res.status >= 500 && res.status !== 503) {
          // Transient server error: re-queue at the front so retry preserves order.
          this.queue.unshift(...batch);
        }
        return;
      }

      const body = await res.json().catch(() => ({}));
      this.stats.forwarded_total += body?.accepted ?? batch.length;
      this.stats.rejected_total += body?.rejected ?? 0;
      this.stats.last_flush_at = new Date().toISOString();
      this.stats.last_error = null;
    } catch (err: any) {
      this.stats.last_error = String(err?.message || err);
      // Network-level failure: re-queue the batch so a future flush retries it.
      this.queue.unshift(...batch);
    }
  }

  /** Exchange SCOPEBLIND_TOKEN for a BRASS-v2 proof; refresh near expiry. */
  private async ensureBrassProof(): Promise<BrassAuthProof | null> {
    if (!this.token) return null;
    const now = Date.now();
    if (this.cachedProof && (Date.parse(this.cachedProof.expires_at) - now) > BRASS_REFRESH_MARGIN_MS) {
      return this.cachedProof;
    }
    try {
      const res = await fetch(`${this.base}/fn/brass/issue`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "user-agent": "protect-mcp/scopeblind-bridge",
        },
        body: JSON.stringify({
          token: this.token,
          scope: "protect-mcp-receipt-emit",
          ttl_seconds: 3600,
        }),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        this.stats.last_error = `brass-issue: HTTP ${res.status} ${text.slice(0, 160)}`;
        return null;
      }
      const body = await res.json();
      if (!body?.auth_proof) {
        this.stats.last_error = "brass-issue: missing auth_proof in response";
        return null;
      }
      this.cachedProof = body.auth_proof;
      return this.cachedProof;
    } catch (err: any) {
      this.stats.last_error = `brass-issue: ${err?.message || err}`;
      return null;
    }
  }

  /**
   * Return a snapshot of bridge stats. Useful for `protect-mcp scopeblind status`.
   */
  getStats(): BridgeStats & { queued: number; brass_proof_expires_at: string | null } {
    return {
      ...this.stats,
      queued: this.queue.length,
      brass_proof_expires_at: this.cachedProof?.expires_at || null,
    };
  }

  /** Flush remaining receipts and stop the interval. Called on process exit. */
  async shutdown(): Promise<void> {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    if (this.flushTimer) clearInterval(this.flushTimer);
    if (this.queue.length > 0) await this.flush();
  }
}

// ───── Module-level singleton ─────
// Mosts callers want a single bridge instance per protect-mcp process.

let singleton: ScopeBlindBridge | null = null;

export function getScopeBlindBridge(): ScopeBlindBridge {
  if (!singleton) singleton = new ScopeBlindBridge();
  return singleton;
}

/** Convenience: forward a signed receipt without instantiating yourself. */
export function forwardReceipt(signedReceipt: any): void {
  getScopeBlindBridge().forward(signedReceipt);
}
