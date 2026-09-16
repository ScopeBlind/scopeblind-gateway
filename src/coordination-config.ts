/** Explicit trust and room configuration for the installed coordination adapter. */
export interface CoordinationConfig {
  endpoint: string;
  roomId: string;
  authorityKey: string;
  token: string;
  runId?: string;
  timeoutMs?: number;
  /** Presentation only; server-side grant checks remain authoritative. */
  purpose?: 'execution' | 'rehearsal' | 'negotiation';
  /** Negotiation identity is pinned by the separate principal-authorized pairing. */
  sessionId?: string;
  principalKey?: string;
}

export function validateCoordinationConfig(config: CoordinationConfig): CoordinationConfig {
  if (config.purpose !== undefined && !['execution','rehearsal','negotiation'].includes(config.purpose)) throw new Error('Unknown coordination connection purpose.');
  if (config.purpose === 'negotiation') {
    if (!config.sessionId || !/^[A-Za-z0-9_-]{8,100}$/.test(config.sessionId)) throw new Error('A negotiation connection requires its exact paired session ID.');
    if (!config.principalKey || !/^[0-9a-f]{64}$/.test(config.principalKey)) throw new Error('A negotiation connection requires its paired principal public key.');
  } else if (config.sessionId !== undefined || config.principalKey !== undefined) throw new Error('Negotiation session and principal fields require a negotiation connection.');
  let endpoint: URL;
  try { endpoint = new URL(config.endpoint); } catch { throw new Error('Coordination endpoint must be an absolute URL.'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname);
  if (endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && local)) {
    throw new Error('Coordination endpoint requires HTTPS (HTTP is permitted only on loopback for local trials).');
  }
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error('Coordination endpoint must not contain credentials, query parameters, or a fragment.');
  }
  if (!/^[a-fA-F0-9]{64}$/.test(config.authorityKey)) {
    throw new Error('An explicitly pinned 32-byte Ed25519 authority public key is required (64 hexadecimal characters).');
  }
  if (!/^[A-Za-z0-9_-]{8,100}$/.test(config.roomId)) throw new Error('Room ID must use 8–100 letters, numbers, underscores, or hyphens.');
  if (!config.token || /[\r\n]/.test(config.token)) throw new Error('An executor token is required in the configured environment variable.');
  if (config.runId !== undefined && !/^run-[A-Za-z0-9_-]{8,100}$/.test(config.runId)) throw new Error('Run ID must be run- followed by the room ID.');
  if (config.timeoutMs !== undefined && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 120_000)) {
    throw new Error('Coordination timeout must be an integer from 1 to 120000 milliseconds.');
  }
  return { ...config, endpoint: endpoint.href, authorityKey: config.authorityKey.toLowerCase() };
}

/** Credentials deliberately have no command-line-value flag and are never printed. */
export function coordinationConfigFromArgs(args: string[], env: NodeJS.ProcessEnv = process.env): CoordinationConfig {
  const values = new Map<string, string>();
  const flags = new Set(['--endpoint', '--room', '--authority-key', '--token-env', '--run']);
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i];
    if (!flags.has(flag)) throw new Error('Unknown coordination option. Use --endpoint, --room, --authority-key, --token-env, and optionally --run.');
    if (values.has(flag)) throw new Error('Coordination options may only be supplied once.');
    const value = args[i + 1];
    if (!value || value.startsWith('--')) throw new Error('Every coordination option requires a value.');
    values.set(flag, value);
  }
  const variable = values.get('--token-env') || 'PROTECT_MCP_COORDINATION_TOKEN';
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) throw new Error('--token-env must name an environment variable.');
  return validateCoordinationConfig({
    endpoint: values.get('--endpoint') || '',
    roomId: values.get('--room') || '',
    authorityKey: values.get('--authority-key') || '',
    token: env[variable] || '',
    runId: values.get('--run'),
  });
}
