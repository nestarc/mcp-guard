import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { buildCandidatePaths } from '../src/discovery/candidatePaths.js';

describe('buildCandidatePaths', () => {
  it('builds project candidates for all supported clients', () => {
    const cwd = path.resolve('workspace');
    const home = path.resolve('home');
    const candidates = buildCandidatePaths({ cwd, home, scope: 'project' });

    expect(candidates.map((candidate) => candidate.label)).toEqual([
      'cursor project',
      'vscode project',
      'claude-code project',
    ]);
    expect(candidates.map((candidate) => candidate.path)).toEqual([
      path.join(cwd, '.cursor', 'mcp.json'),
      path.join(cwd, '.vscode', 'mcp.json'),
      path.join(cwd, '.mcp.json'),
    ]);
  });

  it('builds user candidates for Windows app config locations', () => {
    const home = 'C:\\Users\\alice';
    const appData = 'C:\\Users\\alice\\AppData\\Roaming';
    const candidates = buildCandidatePaths({
      cwd: 'C:\\repo',
      home,
      platform: 'win32',
      env: { APPDATA: appData },
      scope: 'user',
    });

    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(home, '.cursor', 'mcp.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(appData, 'Code', 'User', 'mcp.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(home, '.claude.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(appData, 'Claude', 'claude_desktop_config.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(appData, 'Claude', 'config.json'));
  });

  it('builds user candidates for macOS app config locations', () => {
    const home = '/Users/alice';
    const candidates = buildCandidatePaths({
      cwd: '/repo',
      home,
      platform: 'darwin',
      env: {},
      scope: 'user',
    });

    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(home, 'Library', 'Application Support', 'Claude', 'config.json'));
  });

  it('builds user candidates for Linux app config locations', () => {
    const home = '/home/alice';
    const configHome = '/home/alice/.config';
    const candidates = buildCandidatePaths({
      cwd: '/repo',
      home,
      platform: 'linux',
      env: { XDG_CONFIG_HOME: configHome },
      scope: 'user',
    });

    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(configHome, 'Code', 'User', 'mcp.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(configHome, 'Claude', 'claude_desktop_config.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.join(configHome, 'Claude', 'config.json'));
  });

  it('filters by client and scope', () => {
    const candidates = buildCandidatePaths({
      cwd: '/repo',
      home: '/home/alice',
      platform: 'linux',
      client: 'cursor',
      scope: 'user',
    });

    expect(candidates).toEqual([
      {
        client: 'cursor',
        scope: 'user',
        label: 'cursor user',
        path: path.join('/home/alice', '.cursor', 'mcp.json'),
      },
    ]);
  });
});
