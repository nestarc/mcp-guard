import { describe, it, expect } from 'vitest';
import { renderJson } from '../src/reporters/jsonReporter.js';
import type { ScanResult } from '../src/types.js';

const sampleResult = (): ScanResult => ({
  schemaVersion: '1',
  target: '/Users/alice/mcp.json',
  summary: { risk: 'high', serversScanned: 1, findings: 1 },
  findings: [
    {
      ruleId: 'MCPG005',
      severity: 'high',
      server: 'fs',
      title: 'Broad filesystem access',
      message: 'Argument appears to grant broad file access: /Users/alice.',
      recommendation: 'Restrict access to a project-specific directory.',
      path: 'mcpServers.fs.args',
    },
  ],
});

describe('renderJson', () => {
  it('produces valid JSON', () => {
    const out = renderJson(sampleResult(), { home: '/Users/alice' });

    expect(() => JSON.parse(out)).not.toThrow();
  });

  it('includes schemaVersion=1', () => {
    const parsed = JSON.parse(renderJson(sampleResult(), { home: '/Users/alice' }));

    expect(parsed.schemaVersion).toBe('1');
  });

  it('redacts home path in target', () => {
    const parsed = JSON.parse(renderJson(sampleResult(), { home: '/Users/alice' }));

    expect(parsed.target).toBe('~/mcp.json');
  });

  it('redacts home path in finding messages', () => {
    const parsed = JSON.parse(renderJson(sampleResult(), { home: '/Users/alice' }));

    expect(parsed.findings[0].message).toContain('~');
    expect(parsed.findings[0].message).not.toContain('/Users/alice');
  });

  it('does not add absent optional finding fields', () => {
    const result = sampleResult();
    result.findings = [
      {
        ruleId: 'MCPG005',
        severity: 'high',
        server: 'fs',
        title: 'Broad filesystem access',
        message: 'Argument appears to grant broad file access: /Users/alice.',
      },
    ];

    const parsed = JSON.parse(renderJson(result, { home: '/Users/alice' }));

    expect(parsed.findings[0].message).toContain('~');
    expect(Object.hasOwn(parsed.findings[0], 'recommendation')).toBe(false);
    expect(Object.hasOwn(parsed.findings[0], 'path')).toBe(false);
  });
});
