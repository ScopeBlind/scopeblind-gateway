/** Shared, credential-free setup instructions for the browser and installed CLI. */
export type AgentClient = 'claude-code' | 'codex' | 'json';
export type AgentPurpose = 'execution' | 'rehearsal' | 'negotiation';
export const AGENT_PACKAGE_URL = 'protect-mcp@0.25.0';
export const AGENT_CLIENTS = [
  { id: 'claude-code', label: 'Claude Code' },
  { id: 'codex', label: 'Codex CLI' },
  { id: 'json', label: 'Other MCP client' },
] as const;
export const shellQuote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";
export function agentClient(value: string): AgentClient {
  if (!AGENT_CLIENTS.some(client => client.id === value)) throw new Error('Supported setup clients: claude-code, codex, or json.');
  return value as AgentClient;
}
export function agentConfigFilename(purpose: AgentPurpose, roomId: string, pairId: string): string {
  if (![roomId, pairId].every(value => /^[A-Za-z0-9_-]{8,100}$/.test(value))) throw new Error('Invalid setup destination.');
  return `${roomId}-${purpose}-${pairId}.json`;
}
export function agentServerName(purpose: AgentPurpose, roomId: string, pairId?: string, principalKey?: string): string {
  const suffix = (pairId || roomId).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 12);
  return purpose === 'negotiation' ? `scopeblind-negotiate-${principalKey?.slice(0, 8) || 'agent'}-${suffix}` : `scopeblind-${purpose === 'rehearsal' ? 'test' : 'work'}-${suffix}`;
}
export function agentRegistration(client: AgentClient, serverName: string, configPath: string): string {
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(serverName)) throw new Error('Invalid MCP server name.');
  const launch = `npx --yes ${AGENT_PACKAGE_URL} coordination --config ${shellQuote(configPath)}`;
  if (client === 'claude-code') return `claude mcp add --transport stdio --scope local ${serverName} -- ${launch}`;
  if (client === 'codex') return `codex mcp add ${serverName} -- ${launch}`;
  return JSON.stringify({ mcpServers: { [serverName]: { command: 'npx', args: ['--yes', AGENT_PACKAGE_URL, 'coordination', '--config', configPath] } } }, null, 2);
}
export function agentProfileRegistration(client: AgentClient, serverName: string, profilePath: string): string {
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(serverName)) throw new Error('Invalid MCP server name.');
  const args = ['--yes',AGENT_PACKAGE_URL,'coordination','agent','--profile',profilePath];
  const launch = `npx --yes ${AGENT_PACKAGE_URL} coordination agent --profile ${shellQuote(profilePath)}`;
  if (client === 'claude-code') return `claude mcp add --transport stdio --scope local ${serverName} -- ${launch}`;
  if (client === 'codex') return `codex mcp add ${serverName} -- ${launch}`;
  return JSON.stringify({mcpServers:{[serverName]:{command:'npx',args}}},null,2);
}
export function agentPrompt(purpose: AgentPurpose, roomId: string, sessionId?: string): string {
  const subject = purpose === 'negotiation' ? `ScopeBlind negotiation ${sessionId || '(the paired session)'} in room ${roomId}` : `ScopeBlind ${purpose === 'rehearsal' ? 'rehearsal' : 'room'} ${roomId}`;
  if (purpose === 'negotiation') return `Resume ${subject}. First call coordination.inspect_negotiation to read my current signed mandate, my private instructions, and the shared state. Summarize my hard limits without disclosing my private brief. Take only my next permitted action: propose within my limits, respond to the exact candidate, or compare it in isolation. Keep stable IDs when retrying. Use coordination.wait_negotiation when waiting for the other participant. Stop at a human decision, an unmet hard limit, or the round limit. Recommendations are not human approval; do not pay, adopt terms, or claim to run after this agent session ends.`;
  if (purpose === 'rehearsal') return `Resume ${subject}. First call coordination.inspect_rehearsal to read the current signed rules, sample records, and test history. Help test my expectations and compare a proposed repair using isolated ledgers. Explain observed tradeoffs. Keep stable case, proposal, and run IDs across retries. Leave adoption and approvals to me; this connection cannot pay or change the active rules.`;
  return `Resume ${subject}. First call coordination.inspect to read the current signed agreement, sample records, and recorded operations. Reconcile the invoices within those rules. Reuse existing operation IDs; check uncertain outcomes before retrying. Use coordination.wait for reviewer decisions while this agent session is active. Stop when human action is required, the room is paused, or the result is delivered. Do not approve your own exceptions or change the rules.`;
}
