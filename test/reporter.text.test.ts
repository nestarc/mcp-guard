import { describe, it, expect } from 'vitest';
import { renderText } from '../src/reporters/textReporter.js';
import type { ScanResult } from '../src/types.js';

const result = (): ScanResult => ({
  schemaVersion: '1',
  target: '/Users/alice/mcp.json',
  summary: { risk: 'high', serversScanned: 2, findings: 2 },
  findings: [
    {
      ruleId: 'MCPG005',
      severity: 'high',
      server: 'fs',
      title: 'Broad filesystem access',
      message: 'Argument grants broad access: /Users/alice/project.',
      recommendation: 'Restrict /Users/alice/project to a subdirectory.',
    },
    {
      ruleId: 'MCPG004',
      severity: 'medium',
      server: 'remote',
      title: 'Plain HTTP transport',
      message: 'Server URL uses plain HTTP: http://localhost:3000/sse',
    },
  ],
});

describe('renderText', () => {
  it('includes header lines', () => {
    const out = renderText(result(), { color: false, home: '/Users/alice' });

    expect(out).toContain('Risk: HIGH');
    expect(out).toContain('Servers scanned: 2');
    expect(out).toContain('Findings: 2');
  });

  it('groups findings by server', () => {
    const out = renderText(result(), { color: false, home: '/Users/alice' });

    expect(out).toContain('Server: fs');
    expect(out).toContain('Server: remote');
  });

  it('redacts home path in messages and target output', () => {
    const out = renderText(result(), { color: false, home: '/Users/alice' });

    expect(out).toContain('mcp-guard scan ~/mcp.json');
    expect(out).toContain('Argument grants broad access: ~/project.');
    expect(out).toContain('Restrict ~/project to a subdirectory.');
    expect(out).not.toContain('/Users/alice');
  });

  it('omits ANSI escape codes when color disabled', () => {
    const out = renderText(result(), { color: false, home: '/Users/alice' });

    expect(out).not.toMatch(/\x1b\[/);
  });

  it('emits ANSI escape codes when color enabled', () => {
    const out = renderText(result(), { color: true, home: '/Users/alice' });

    expect(out).toMatch(/\x1b\[/);
  });

  it('quiet mode omits finding lines', () => {
    const out = renderText(result(), { color: false, quiet: true, home: '/Users/alice' });

    expect(out).toContain('Risk: HIGH');
    expect(out).not.toContain('MCPG005');
    expect(out).not.toContain('Server: fs');
  });

  it('renders empty findings cleanly', () => {
    const out = renderText(
      {
        schemaVersion: '1',
        target: '/Users/alice/mcp.json',
        summary: { risk: 'info', serversScanned: 1, findings: 0 },
        findings: [],
      },
      { color: false, home: '/Users/alice' }
    );

    expect(out).toBe('mcp-guard scan ~/mcp.json\n\nRisk: INFO\nServers scanned: 1\nFindings: 0\n');
  });

  it('does not render Recommendation or undefined for findings without recommendation', () => {
    const out = renderText(
      {
        schemaVersion: '1',
        target: '/Users/alice/mcp.json',
        summary: { risk: 'medium', serversScanned: 1, findings: 1 },
        findings: [
          {
            ruleId: 'MCPG004',
            severity: 'medium',
            server: 'remote',
            title: 'Plain HTTP transport',
            message: 'Server URL uses plain HTTP.',
          },
        ],
      },
      { color: false, home: '/Users/alice' }
    );

    expect(out).not.toContain('Recommendation:');
    expect(out).not.toContain('undefined');
  });
});
