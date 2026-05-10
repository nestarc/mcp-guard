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

    expect(candidates.map((candidate) => candidate.path)).toContain(path.win32.join(home, '.cursor', 'mcp.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.win32.join(appData, 'Code', 'User', 'mcp.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.win32.join(home, '.claude.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.win32.join(appData, 'Claude', 'claude_desktop_config.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.win32.join(appData, 'Claude', 'config.json'));
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

    expect(candidates.map((candidate) => candidate.path)).toContain(path.posix.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.posix.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.posix.join(home, 'Library', 'Application Support', 'Claude', 'config.json'));
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

    expect(candidates.map((candidate) => candidate.path)).toContain(path.posix.join(configHome, 'Code', 'User', 'mcp.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.posix.join(configHome, 'Claude', 'claude_desktop_config.json'));
    expect(candidates.map((candidate) => candidate.path)).toContain(path.posix.join(configHome, 'Claude', 'config.json'));
  });

  it('uses injected platform path separators for project candidates', () => {
    const windowsCandidates = buildCandidatePaths({
      cwd: 'C:\\repo',
      home: 'C:\\Users\\alice',
      platform: 'win32',
      scope: 'project',
    });
    const linuxCandidates = buildCandidatePaths({
      cwd: '/repo',
      home: '/home/alice',
      platform: 'linux',
      scope: 'project',
    });

    expect(windowsCandidates.map((candidate) => candidate.path)).toEqual([
      path.win32.join('C:\\repo', '.cursor', 'mcp.json'),
      path.win32.join('C:\\repo', '.vscode', 'mcp.json'),
      path.win32.join('C:\\repo', '.mcp.json'),
    ]);
    expect(linuxCandidates.map((candidate) => candidate.path)).toEqual([
      path.posix.join('/repo', '.cursor', 'mcp.json'),
      path.posix.join('/repo', '.vscode', 'mcp.json'),
      path.posix.join('/repo', '.mcp.json'),
    ]);
  });

  it('falls back to default Windows AppData when APPDATA is missing or empty', () => {
    const home = 'C:\\Users\\alice';
    const fallback = path.win32.join(home, 'AppData', 'Roaming');

    for (const env of [{}, { APPDATA: '' }]) {
      const paths = buildCandidatePaths({
        cwd: 'C:\\repo',
        home,
        platform: 'win32',
        env,
        scope: 'user',
      }).map((candidate) => candidate.path);

      expect(paths).toContain(path.win32.join(fallback, 'Code', 'User', 'mcp.json'));
      expect(paths).toContain(path.win32.join(fallback, 'Claude', 'claude_desktop_config.json'));
      expect(paths).toContain(path.win32.join(fallback, 'Claude', 'config.json'));
    }
  });

  it('falls back to default XDG config home when XDG_CONFIG_HOME is missing or empty', () => {
    const home = '/home/alice';
    const fallback = path.posix.join(home, '.config');

    for (const env of [{}, { XDG_CONFIG_HOME: '' }]) {
      const paths = buildCandidatePaths({
        cwd: '/repo',
        home,
        platform: 'linux',
        env,
        scope: 'user',
      }).map((candidate) => candidate.path);

      expect(paths).toContain(path.posix.join(fallback, 'Code', 'User', 'mcp.json'));
      expect(paths).toContain(path.posix.join(fallback, 'Claude', 'claude_desktop_config.json'));
      expect(paths).toContain(path.posix.join(fallback, 'Claude', 'config.json'));
    }
  });

  it('defaults scope to all candidates', () => {
    const candidates = buildCandidatePaths({
      cwd: '/repo',
      home: '/home/alice',
      platform: 'linux',
      env: { XDG_CONFIG_HOME: '/home/alice/.config' },
    });

    expect(candidates.map((candidate) => candidate.label)).toEqual([
      'cursor project',
      'vscode project',
      'claude-code project',
      'cursor user',
      'vscode user',
      'claude-code user',
      'claude-desktop user claude_desktop_config',
      'claude-desktop user config',
    ]);
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
        path: path.posix.join('/home/alice', '.cursor', 'mcp.json'),
      },
    ]);
  });
});
