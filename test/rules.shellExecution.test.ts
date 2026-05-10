import { describe, it, expect } from 'vitest';
import { shellExecutionRule } from '../src/scanner/rules/shellExecution.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  ...(command === undefined ? {} : { command }),
  ...(args === undefined ? {} : { args }),
  raw: { command, args },
});

describe('shellExecutionRule (MCPG002)', () => {
  it.each(['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'cmd', 'powershell', 'pwsh'])(
    'flags %s as high',
    (c) => {
      const f = shellExecutionRule.run(server(c));
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe('high');
      expect(f[0]!.ruleId).toBe('MCPG002');
    }
  );

  it('flags Windows path with .exe', () => {
    const f = shellExecutionRule.run(server('C:\\Windows\\System32\\cmd.exe'));
    expect(f).toHaveLength(1);
  });

  it('flags POSIX absolute path /usr/bin/bash', () => {
    const f = shellExecutionRule.run(server('/usr/bin/bash'));
    expect(f).toHaveLength(1);
  });

  it('mentions -c flag in message when present', () => {
    const f = shellExecutionRule.run(server('bash', ['-c', 'echo hi']));
    expect(f[0]!.message).toContain('-c');
  });

  it('mentions /c flag for cmd', () => {
    const f = shellExecutionRule.run(server('cmd', ['/c', 'dir']));
    expect(f[0]!.message).toContain('/c');
  });

  it('does not flag node', () => {
    expect(shellExecutionRule.run(server('node'))).toEqual([]);
  });

  it('does not flag when command absent', () => {
    expect(shellExecutionRule.run(server(undefined))).toEqual([]);
  });
});
