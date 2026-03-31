/**
 * @scopeblind/protect-mcp — Credential Vault
 *
 * Config-driven credential injection for MCP tool calls.
 * The agent NEVER sees the raw credential. protect-mcp holds
 * the secret and injects it into the appropriate context.
 *
 * Credentials are referenced by label in the policy and receipts.
 * The actual secret value is read from environment variables.
 *
 * Example config:
 * {
 *   "credentials": {
 *     "stripe_api": {
 *       "inject": "header",
 *       "name": "Authorization",
 *       "value_env": "STRIPE_KEY"
 *     },
 *     "github_token": {
 *       "inject": "header",
 *       "name": "Authorization",
 *       "value_env": "GITHUB_TOKEN"
 *     }
 *   }
 * }
 */

import type { CredentialConfig } from './types.js';

/**
 * Result of credential resolution.
 */
export interface CredentialResolution {
  /** Whether the credential was found and resolved */
  resolved: boolean;
  /** The credential label (safe to log, never the actual value) */
  label: string;
  /** Error message if resolution failed */
  error?: string;
  /** The resolved value (NEVER log this) */
  value?: string;
  /** How the credential should be injected */
  inject?: 'header' | 'query' | 'env';
  /** Injection target name (header name, query param, env var) */
  name?: string;
}

/**
 * Resolve a credential from the vault.
 * Reads the actual secret from the environment variable specified in config.
 *
 * @param label - Credential label (e.g., "stripe_api")
 * @param credentials - Credential configuration map
 * @returns CredentialResolution (value is only populated on success)
 *
 * @patent Patent-protected construction — privacy-preserving credential presentation.
 * Covered by Apache 2.0 patent grant for users of this code. Clean-room
 * reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export function resolveCredential(
  label: string,
  credentials: Record<string, CredentialConfig> | undefined,
): CredentialResolution {
  if (!credentials || !credentials[label]) {
    return {
      resolved: false,
      label,
      error: `credential "${label}" not configured`,
    };
  }

  const config = credentials[label];
  const value = process.env[config.value_env];

  if (!value) {
    return {
      resolved: false,
      label,
      error: `environment variable "${config.value_env}" for credential "${label}" is not set`,
    };
  }

  return {
    resolved: true,
    label,
    value,
    inject: config.inject,
    name: config.name,
  };
}

/**
 * Get the list of configured credential labels (safe to log).
 *
 * @param credentials - Credential configuration map
 * @returns Array of credential labels
 *
 * @patent Patent-protected construction — privacy-preserving credential presentation.
 * Covered by Apache 2.0 patent grant for users of this code. Clean-room
 * reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export function listCredentialLabels(
  credentials: Record<string, CredentialConfig> | undefined,
): string[] {
  if (!credentials) return [];
  return Object.keys(credentials);
}

/**
 * Validate credential configuration at startup.
 * Checks that all referenced environment variables exist.
 *
 * @param credentials - Credential configuration map
 * @returns Array of warnings for missing env vars
 *
 * @patent Patent-protected construction — privacy-preserving credential presentation.
 * Covered by Apache 2.0 patent grant for users of this code. Clean-room
 * reimplementation requires a patent license.
 * @see {@link https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/}
 */
export function validateCredentials(
  credentials: Record<string, CredentialConfig> | undefined,
): string[] {
  const warnings: string[] = [];

  if (!credentials) return warnings;

  for (const [label, config] of Object.entries(credentials)) {
    if (!config.value_env) {
      warnings.push(`credential "${label}": missing value_env`);
      continue;
    }

    if (!config.inject) {
      warnings.push(`credential "${label}": missing inject type`);
      continue;
    }

    if (!process.env[config.value_env]) {
      warnings.push(`credential "${label}": env var "${config.value_env}" not set`);
    }
  }

  return warnings;
}
