import { describe, it, expect } from 'vitest';
import { dynamicRunnerRule } from '../src/scanner/rules/dynamicRunner.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  ...(command === undefined ? {} : { command }),
  ...(args === undefined ? {} : { args }),
  raw: { command, args },
});

describe('dynamicRunnerRule (MCPG003)', () => {
  it.each(['npx', 'pnpx', 'bunx', 'uvx'])('flags %s', (c) => {
    const f = dynamicRunnerRule.run(server(c, ['-y', 'pkg']));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.ruleId).toBe('MCPG003');
  });

  it('flags yarn dlx', () => {
    expect(dynamicRunnerRule.run(server('yarn', ['dlx', 'pkg']))).toHaveLength(1);
  });

  it('flags pnpm dlx', () => {
    expect(dynamicRunnerRule.run(server('pnpm', ['dlx', 'pkg']))).toHaveLength(1);
  });

  it('flags pnpm dlx even when other args precede', () => {
    expect(dynamicRunnerRule.run(server('pnpm', ['--silent', 'dlx', 'pkg']))).toHaveLength(1);
  });

  it('flags yarn dlx even when other args precede', () => {
    expect(dynamicRunnerRule.run(server('yarn', ['--silent', 'dlx', 'pkg']))).toHaveLength(1);
  });

  it.each(['C:\\Users\\s\\AppData\\Roaming\\npm\\npx.cmd', '/usr/bin/uvx'])(
    'normalizes command basename for %s',
    (command) => {
      expect(dynamicRunnerRule.run(server(command, ['pkg']))).toHaveLength(1);
    }
  );

  it('returns MCPG003 finding details', () => {
    const f = dynamicRunnerRule.run(server('npx', ['pkg']));

    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: 'MCPG003',
      severity: 'medium',
      server: 's',
      title: 'Dynamic package runner',
      message:
        'Server uses a dynamic package runner (npx). Packages may be fetched and executed at runtime.',
      recommendation:
        'Pin the exact package version or pre-install the dependency. Verify package provenance.',
      path: 'mcpServers.s.command',
    });
  });

  it('does not flag yarn install', () => {
    expect(dynamicRunnerRule.run(server('yarn', ['install']))).toEqual([]);
  });

  it('does not flag node', () => {
    expect(dynamicRunnerRule.run(server('node', ['./server.js']))).toEqual([]);
  });

  it('does not flag when command absent', () => {
    expect(dynamicRunnerRule.run(server(undefined))).toEqual([]);
  });
});
