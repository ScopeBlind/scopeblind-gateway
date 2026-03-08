/**
 * ScopeBlind Gateway — Cloudflare Worker Reverse Proxy
 *
 * Enforces ScopeBlind pass tokens at the edge for strict protection on public APIs.
 * Start in observe mode (measure only), then flip to enforcement when ready.
 *
 * Observe mode: logs what WOULD be blocked, forwards everything to origin.
 * Enforce mode: blocks protected requests that do not present a valid pass token.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export interface Env {
  ORIGIN_URL: string;
  SCOPEBLIND_AUDIENCE: string;   // Your tenant slug (JWT aud)
  SCOPEBLIND_JWKS_URL?: string;  // Defaults to production JWKS
  OBSERVE_MODE?: string;         // "true" | "false"
  SHADOW_MODE?: string;          // Legacy alias
  PROTECTED_METHODS?: string;    // comma-separated: "POST,PUT,DELETE,PATCH"
  FALLBACK_MODE?: string;        // "open" | "closed"
}

interface ScopeBlindPayload extends JWTPayload {
  agent?: boolean;
  sub?: string;
  jti?: string;
}

const DEFAULT_JWKS_URL = 'https://api.scopeblind.com/.well-known/jwks.json';
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJWKS(url: string) {
  if (!jwksCache.has(url)) {
    jwksCache.set(url, createRemoteJWKSet(new URL(url)));
  }
  return jwksCache.get(url)!;
}

function isObserveMode(env: Env) {
  const raw = env.OBSERVE_MODE ?? env.SHADOW_MODE ?? 'true';
  return raw === 'true';
}

function logObserve(action: string, data: Record<string, unknown>) {
  console.log(JSON.stringify({
    _scopeblind: true,
    action,
    ts: new Date().toISOString(),
    ...data,
  }));
}

function corsHeaders(request: Request): HeadersInit {
  return {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
  };
}

function getCookie(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;

  for (const part of cookieHeader.split(/;\s*/)) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1);
    if (key === name) return value;
  }
  return null;
}

function getPassToken(request: Request): { token: string | null; source: 'cookie' | 'header' | 'none' } {
  const cookieToken = getCookie(request, 'sb_pass');
  if (cookieToken) return { token: cookieToken, source: 'cookie' };

  const headerToken = request.headers.get('X-ScopeBlind-Token');
  if (headerToken) return { token: headerToken, source: 'header' };

  return { token: null, source: 'none' };
}

function stripCookie(headers: Headers, name: string) {
  const cookieHeader = headers.get('Cookie');
  if (!cookieHeader) return;

  const filtered = cookieHeader
    .split(/;\s*/)
    .filter((part) => !part.startsWith(`${name}=`) && part.length > 0);

  if (filtered.length === 0) {
    headers.delete('Cookie');
  } else {
    headers.set('Cookie', filtered.join('; '));
  }
}

function classifyVerifyError(error: unknown): string {
  if (!(error instanceof Error)) return 'invalid_token';
  const msg = error.message.toLowerCase();
  if (msg.includes('exp')) return 'expired_token';
  if (msg.includes('aud')) return 'invalid_audience';
  if (msg.includes('iss')) return 'invalid_issuer';
  if (msg.includes('signature')) return 'invalid_signature';
  if (msg.includes('jwt')) return 'invalid_token';
  return 'verification_failed';
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const observe = isObserveMode(env);
    const protectedMethods = (env.PROTECTED_METHODS || 'POST,PUT,DELETE,PATCH')
      .split(',')
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);
    const jwksUrl = env.SCOPEBLIND_JWKS_URL || DEFAULT_JWKS_URL;

    // 1. CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-ScopeBlind-Token, DPoP',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // 2. Health check
    if (url.pathname === '/_scopeblind/health') {
      return Response.json({
        ok: true,
        mode: observe ? 'observe' : 'enforce',
        origin: env.ORIGIN_URL,
        audience: env.SCOPEBLIND_AUDIENCE,
        jwks: jwksUrl,
      });
    }

    // 3. Unprotected methods pass through
    const needsToken = protectedMethods.includes(request.method.toUpperCase());
    if (!needsToken) {
      return forwardToOrigin(request, env, url, {
        'X-ScopeBlind-Mode': observe ? 'observe' : 'enforce',
        'X-ScopeBlind-Verified': 'skipped',
      });
    }

    // 4. Extract pass token
    const { token, source } = getPassToken(request);
    if (!token) {
      logObserve('missing_token', {
        method: request.method,
        path: url.pathname,
        ip: request.headers.get('CF-Connecting-IP') || 'unknown',
      });

      if (observe) {
        return forwardToOrigin(request, env, url, {
          'X-ScopeBlind-Mode': 'observe',
          'X-ScopeBlind-Verified': 'missing',
          'X-ScopeBlind-Action': 'would-block',
        });
      }

      return Response.json(
        {
          error: 'pass_token_required',
          message: 'This endpoint requires a valid ScopeBlind pass token.',
        },
        { status: 403, headers: corsHeaders(request) },
      );
    }

    // 5. Verify JWT via JWKS
    try {
      const JWKS = getJWKS(jwksUrl);
      const { payload } = await jwtVerify(token, JWKS, {
        algorithms: ['EdDSA'],
        issuer: 'scopeblind.com',
        audience: env.SCOPEBLIND_AUDIENCE,
      });

      const claims = payload as ScopeBlindPayload;
      logObserve('verified', {
        method: request.method,
        path: url.pathname,
        sub: claims.sub || null,
        agent: !!claims.agent,
        source,
      });

      return forwardToOrigin(request, env, url, {
        'X-ScopeBlind-Mode': observe ? 'observe' : 'enforce',
        'X-ScopeBlind-Verified': 'true',
        'X-ScopeBlind-Subject': claims.sub || '',
        'X-ScopeBlind-Agent': claims.agent ? 'true' : 'false',
        'X-ScopeBlind-Token-Source': source,
        'X-ScopeBlind-Expires': claims.exp ? String(claims.exp) : '',
        'X-ScopeBlind-JTI': claims.jti || '',
      });
    } catch (error) {
      const reason = classifyVerifyError(error);

      logObserve('invalid_token', {
        method: request.method,
        path: url.pathname,
        reason,
        source,
        ip: request.headers.get('CF-Connecting-IP') || 'unknown',
      });

      const verifierUnavailable = reason === 'verification_failed';
      if (verifierUnavailable && env.FALLBACK_MODE === 'closed' && !observe) {
        return Response.json(
          {
            error: 'verification_unavailable',
            message: 'Unable to verify ScopeBlind pass token. Try again later.',
          },
          { status: 503, headers: corsHeaders(request) },
        );
      }

      if (observe || (verifierUnavailable && env.FALLBACK_MODE !== 'closed')) {
        return forwardToOrigin(request, env, url, {
          'X-ScopeBlind-Mode': observe ? 'observe' : 'enforce',
          'X-ScopeBlind-Verified': verifierUnavailable ? 'error' : 'invalid',
          'X-ScopeBlind-Action': verifierUnavailable ? 'fallback-allow' : 'would-block',
          'X-ScopeBlind-Error': reason,
        });
      }

      return Response.json(
        {
          error: 'invalid_pass_token',
          message: 'ScopeBlind pass token missing, invalid, expired, or not issued for this API.',
          details: reason,
        },
        { status: 403, headers: corsHeaders(request) },
      );
    }
  },
};

async function forwardToOrigin(
  request: Request,
  env: Env,
  url: URL,
  extraHeaders: Record<string, string>,
): Promise<Response> {
  const origin = new URL(env.ORIGIN_URL);
  url.hostname = origin.hostname;
  url.protocol = origin.protocol;
  url.port = origin.port;

  const headers = new Headers(request.headers);
  for (const [k, v] of Object.entries(extraHeaders)) {
    if (v) headers.set(k, v);
  }

  // ScopeBlind is the security boundary here — do not leak token inputs to origin.
  headers.delete('X-ScopeBlind-Token');
  headers.delete('X-Proof');
  headers.delete('X-ScopeBlind-Proof');
  stripCookie(headers, 'sb_pass');

  try {
    const response = await fetch(
      new Request(url.toString(), {
        method: request.method,
        headers,
        body: request.body,
        redirect: 'follow',
      }),
    );

    const res = new Response(response.body, response);
    res.headers.set('Access-Control-Allow-Origin', request.headers.get('Origin') || '*');
    return res;
  } catch {
    return Response.json(
      { error: 'upstream_error', message: 'Failed to reach backend.' },
      { status: 502, headers: corsHeaders(request) },
    );
  }
}
