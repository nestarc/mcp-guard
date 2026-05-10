import { describe, it, expect } from 'vitest';
import { filesystemAccessRule } from '../src/scanner/rules/filesystemAccess.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  ...(command === undefined ? {} : { command }),
  ...(args === undefined ? {} : { args }),
  raw: { command, args },
});

describe('filesystemAccessRule (MCPG005)', () => {
  it('has MCPG005 rule id', () => {
    expect(filesystemAccessRule.id).toBe('MCPG005');
  });

  it('flags / root', () => {
    const f = filesystemAccessRule.run(server('node', ['./srv.js', '/']));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.ruleId).toBe('MCPG005');
  });

  it('flags ~ home', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', '~']))).toHaveLength(1);
  });

  it('flags /Users/alice (home)', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', '/Users/alice']))).toHaveLength(1);
  });

  it('flags C:\\Users\\alice', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', 'C:\\Users\\alice']))).toHaveLength(
      1
    );
  });

  it('flags parent traversal ..', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', '../..']))).toHaveLength(1);
  });

  it('does not flag narrow subpath /Users/alice/project/docs', () => {
    expect(
      filesystemAccessRule.run(server('node', ['./srv.js', '/Users/alice/project/docs']))
    ).toEqual([]);
  });

  it('mentions filesystem server in message when @modelcontextprotocol/server-filesystem present', () => {
    const f = filesystemAccessRule.run(
      server('npx', ['-y', '@modelcontextprotocol/server-filesystem', '/Users/alice'])
    );
    expect(f[0]!.message.toLowerCase()).toContain('filesystem');
  });

  it('mentions filesystem server in message when command is @modelcontextprotocol/server-filesystem', () => {
    const f = filesystemAccessRule.run(
      server('@modelcontextprotocol/server-filesystem', ['/Users/alice'])
    );
    expect(f[0]!.message.toLowerCase()).toContain('filesystem');
  });

  it('returns exactly one finding when multiple args are broad or traversing', () => {
    const f = filesystemAccessRule.run(server('node', ['./srv.js', '/', '../..']));
    expect(f).toHaveLength(1);
    expect(f[0]!.message).toContain('/');
  });

  it('returns expected finding shape for broad access', () => {
    const f = filesystemAccessRule.run(server('node', ['./srv.js', '/Users/alice']));
    expect(f).toEqual([
      expect.objectContaining({
        ruleId: 'MCPG005',
        severity: 'high',
        server: 's',
        title: 'Broad filesystem access',
        recommendation: 'Restrict access to a project-specific directory.',
        path: 'mcpServers.s.args',
      }),
    ]);
    expect(f[0]!.message).toContain('Argument appears to grant broad file access');
    expect(f[0]!.message).toContain('/Users/alice');
  });

  it('does not flag when no args', () => {
    expect(filesystemAccessRule.run(server('node'))).toEqual([]);
  });
});
