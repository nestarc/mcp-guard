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

const groupingResult = (): AggregateScanResult => ({
  schemaVersion: '2',
  targets: [
    {
      path: '/Users/alice/project/.cursor/mcp.json',
      client: 'cursor',
      scope: 'project',
      labels: ['cursor project'],
      scanned: true,
      serversScanned: 2,
      findings: 3,
    },
    {
      path: '/Users/alice/.claude.json',
      client: 'claude-code',
      scope: 'user',
      labels: ['claude-code user'],
      scanned: true,
      serversScanned: 1,
      findings: 1,
    },
  ],
  summary: {
    risk: 'high',
    targetsDiscovered: 2,
    targetsScanned: 2,
    serversScanned: 3,
    findings: 4,
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
    {
      ruleId: 'MCPG002',
      severity: 'medium',
      server: 'remote',
      title: 'Remote URL uses a broad origin',
      message: 'Remote URL origin is broader than the expected project endpoint.',
      recommendation: 'Restrict the remote server URL to the expected endpoint.',
      path: 'mcpServers.remote.url',
      target: {
        path: '/Users/alice/project/.cursor/mcp.json',
        client: 'cursor',
        scope: 'project',
        labels: ['cursor project'],
      },
    },
    {
      ruleId: 'MCPG003',
      severity: 'medium',
      server: 'local',
      title: 'Local command has broad filesystem access',
      message: 'Command arguments allow reading from a broad directory.',
      recommendation: 'Limit filesystem access to the project directory.',
      path: 'mcpServers.local.args',
      target: {
        path: '/Users/alice/project/.cursor/mcp.json',
        client: 'cursor',
        scope: 'project',
        labels: ['cursor project'],
      },
    },
    {
      ruleId: 'MCPG004',
      severity: 'low',
      server: 'claude',
      title: 'Environment variable fallback is unset',
      message: 'Environment variable fallback may fail when the value is not configured.',
      recommendation: 'Document the required environment variable.',
      path: 'mcpServers.claude.env.API_TOKEN',
      target: {
        path: '/Users/alice/.claude.json',
        client: 'claude-code',
        scope: 'user',
        labels: ['claude-code user'],
      },
    },
  ],
});

function indexOfRequired(output: string, expected: string): number {
  const index = output.indexOf(expected);
  expect(index).toBeGreaterThanOrEqual(0);
  return index;
}

function countOccurrences(output: string, expected: string): number {
  return output.split(expected).length - 1;
}

describe('aggregate reporters', () => {
  it('renders aggregate JSON with redacted target paths', () => {
    const parsed = JSON.parse(renderAggregateJson(result(), { home: '/Users/alice' }));

    expect(parsed.schemaVersion).toBe('2');
    expect(parsed.targets[0].path).toBe('~/project/.cursor/mcp.json');
    expect(parsed.findings[0].target.path).toBe('~/project/.cursor/mcp.json');
    expect(JSON.stringify(parsed)).not.toContain('/Users/alice');
  });

  it('renders aggregate text grouped by target then server in finding order', () => {
    const out = renderAggregateText(groupingResult(), { color: false, home: '/Users/alice' });

    expect(out).toContain('mcp-guard scan --all');
    expect(out).toContain('Risk: HIGH');
    expect(out).toContain('Targets scanned: 2/2');

    const firstTarget = indexOfRequired(out, 'Target: ~/project/.cursor/mcp.json (cursor, project)');
    const remoteServer = indexOfRequired(out, 'Server: remote');
    const remoteFinding = indexOfRequired(out, 'MCPG001 Secret-like value in headers');
    const secondRemoteFinding = indexOfRequired(out, 'MCPG002 Remote URL uses a broad origin');
    const localServer = indexOfRequired(out, 'Server: local');
    const localFinding = indexOfRequired(out, 'MCPG003 Local command has broad filesystem access');
    const secondTarget = indexOfRequired(out, 'Target: ~/.claude.json (claude-code, user)');
    const claudeServer = indexOfRequired(out, 'Server: claude');
    const claudeFinding = indexOfRequired(out, 'MCPG004 Environment variable fallback is unset');

    expect(countOccurrences(out, 'Target: ~/project/.cursor/mcp.json (cursor, project)')).toBe(1);
    expect(countOccurrences(out, 'Target: ~/.claude.json (claude-code, user)')).toBe(1);
    expect(countOccurrences(out, 'Server: remote')).toBe(1);

    expect(firstTarget).toBeLessThan(remoteServer);
    expect(remoteServer).toBeLessThan(remoteFinding);
    expect(remoteFinding).toBeLessThan(secondRemoteFinding);
    expect(secondRemoteFinding).toBeLessThan(localServer);
    expect(localServer).toBeLessThan(localFinding);
    expect(localFinding).toBeLessThan(secondTarget);
    expect(secondTarget).toBeLessThan(claudeServer);
    expect(claudeServer).toBeLessThan(claudeFinding);
    expect(out).not.toContain('/Users/alice');
  });

  it('quiet aggregate text omits finding details', () => {
    const out = renderAggregateText(result(), { color: false, quiet: true, home: '/Users/alice' });

    expect(out).toContain('Risk: HIGH');
    expect(out).not.toContain('MCPG001');
    expect(out).not.toContain('Server: remote');
  });
});
