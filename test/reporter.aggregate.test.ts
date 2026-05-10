import { describe, expect, it } from 'vitest';
import { renderAggregateJson } from '../src/reporters/aggregateJsonReporter.js';
import { renderAggregateText } from '../src/reporters/aggregateTextReporter.js';
import type { AggregateScanResult } from '../src/types.js';

const result = (): AggregateScanResult => ({
  schemaVersion: '2',
  targets: [
    {
      path: '/Users/alice/project/.cursor/mcp.json',
      client: 'cursor',
      scope: 'project',
      labels: ['cursor project'],
      scanned: true,
      serversScanned: 1,
      findings: 1,
    },
  ],
  summary: {
    risk: 'high',
    targetsDiscovered: 1,
    targetsScanned: 1,
    serversScanned: 1,
    findings: 1,
  },
  findings: [
    {
      ruleId: 'MCPG001',
      severity: 'high',
      server: 'remote',
      title: 'Secret-like value in headers',
      message: 'Header Authorization appears to contain a secret. Value not shown.',
      recommendation: 'Move secrets to a secure secret manager or prompt-based auth flow. Avoid committing real values.',
      path: 'mcpServers.remote.headers.Authorization',
      target: {
        path: '/Users/alice/project/.cursor/mcp.json',
        client: 'cursor',
        scope: 'project',
        labels: ['cursor project'],
      },
    },
  ],
});

describe('aggregate reporters', () => {
  it('renders aggregate JSON with redacted target paths', () => {
    const parsed = JSON.parse(renderAggregateJson(result(), { home: '/Users/alice' }));

    expect(parsed.schemaVersion).toBe('2');
    expect(parsed.targets[0].path).toBe('~/project/.cursor/mcp.json');
    expect(parsed.findings[0].target.path).toBe('~/project/.cursor/mcp.json');
    expect(JSON.stringify(parsed)).not.toContain('/Users/alice');
  });

  it('renders aggregate text grouped by target and server', () => {
    const out = renderAggregateText(result(), { color: false, home: '/Users/alice' });

    expect(out).toContain('mcp-guard scan --all');
    expect(out).toContain('Risk: HIGH');
    expect(out).toContain('Targets scanned: 1/1');
    expect(out).toContain('Target: ~/project/.cursor/mcp.json (cursor, project)');
    expect(out).toContain('Server: remote');
    expect(out).toContain('MCPG001 Secret-like value in headers');
    expect(out).not.toContain('/Users/alice');
  });

  it('quiet aggregate text omits finding details', () => {
    const out = renderAggregateText(result(), { color: false, quiet: true, home: '/Users/alice' });

    expect(out).toContain('Risk: HIGH');
    expect(out).not.toContain('MCPG001');
    expect(out).not.toContain('Server: remote');
  });
});
