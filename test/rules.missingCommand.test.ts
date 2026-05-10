import { describe, it, expect } from 'vitest';
import { missingCommandRule } from '../src/scanner/rules/missingCommand.js';
import type { McpServerConfig } from '../src/types.js';

const server = (overrides: Partial<McpServerConfig> = {}): McpServerConfig => ({
  name: 's',
  raw: {},
  ...overrides,
});

describe('missingCommandRule (MCPG009)', () => {
  it('has MCPG009 rule id', () => {
    expect(missingCommandRule.id).toBe('MCPG009');
  });

  it('flags when neither command nor url present as info', () => {
    const f = missingCommandRule.run(server());
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('info');
    expect(f[0]!.ruleId).toBe('MCPG009');
  });

  it('does not flag when command present', () => {
    expect(missingCommandRule.run(server({ command: 'node' }))).toEqual([]);
  });

  it('does not flag when command is an empty string', () => {
    expect(missingCommandRule.run(server({ command: '' }))).toEqual([]);
  });

  it('does not flag when url present', () => {
    expect(missingCommandRule.run(server({ url: 'https://x' }))).toEqual([]);
  });

  it('does not flag when url is an empty string', () => {
    expect(missingCommandRule.run(server({ url: '' }))).toEqual([]);
  });

  it('reports MCPG009 finding shape', () => {
    expect(missingCommandRule.run(server())[0]).toEqual({
      ruleId: 'MCPG009',
      severity: 'info',
      server: 's',
      title: 'Missing command or url',
      message: 'Server entry has neither a string `command` nor a string `url`.',
      recommendation:
        'Verify the entry is intentional. The server cannot be launched without one of these.',
      path: 'mcpServers.s',
    });
  });
});
