import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { connectorDoctor, connectorPilotIds, readInstalledConnectorPilots, writeConnectorPilots } from './connector-pilots.js';

describe('connector pilots', () => {
  it('installs all connector pilot configs and policy snippets', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-connectors-'));
    try {
      const result = writeConnectorPilots({ dir, ids: ['all'], force: true });
      expect(result.pilots.map((p) => p.id)).toEqual(connectorPilotIds());
      expect(result.written.some((p) => p.endsWith('github.json'))).toBe(true);
      expect(result.written.some((p) => p.endsWith('finance-pms.cedar'))).toBe(true);
      const installed = readInstalledConnectorPilots(dir);
      expect(installed.map((p) => p.id).sort()).toEqual(connectorPilotIds().sort());
      expect(existsSync(join(dir, '.protect-mcp/connectors/nautilus-trader/bridge.py'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reports credential gaps without exposing values', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-connectors-'));
    try {
      writeConnectorPilots({ dir, ids: ['github'], force: true });
      const rows = connectorDoctor(dir, { GITHUB_TOKEN: 'secret' } as any);
      const github = rows.find((row) => row.id === 'github') as any;
      expect(github.installed).toBe(true);
      expect(github.missing_required).toEqual(['GITHUB_REPOSITORY']);
      expect(JSON.stringify(rows)).not.toContain('secret');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps the finance PMS pilot usable in local mock mode', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-connectors-'));
    try {
      writeConnectorPilots({ dir, ids: ['finance-pms'], force: true });
      const rows = connectorDoctor(dir, {});
      const finance = rows.find((row) => row.id === 'finance-pms') as any;
      expect(finance.installed).toBe(true);
      expect(finance.mode).toBe('mock');
      expect(finance.usable).toBe(true);
      expect(finance.missing_required).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('installs a NautilusTrader-compatible bridge without requiring Nautilus locally', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-connectors-'));
    try {
      const result = writeConnectorPilots({ dir, ids: ['nautilus-trader'], force: true });
      expect(result.pilots.map((pilot) => pilot.id)).toEqual(['nautilus-trader']);
      const bridgePath = join(dir, '.protect-mcp/connectors/nautilus-trader/bridge.py');
      const bridge = readFileSync(bridgePath, 'utf-8');
      expect(bridge).toContain('ScopeBlind external bridge');
      expect(bridge).toContain('NAUTILUS_BRIDGE_MODULE');
      const rows = connectorDoctor(dir, {});
      const nautilus = rows.find((row) => row.id === 'nautilus-trader') as any;
      expect(nautilus.installed).toBe(true);
      expect(nautilus.mode).toBe('mock_bridge');
      expect(nautilus.usable).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
