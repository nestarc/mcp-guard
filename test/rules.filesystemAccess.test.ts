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
  it('flags / root', () => {
    const f = filesystemAccessRule.run(server('node', ['./srv.js', '/']));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
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

  it('does not flag when no args', () => {
    expect(filesystemAccessRule.run(server('node'))).toEqual([]);
  });
});
