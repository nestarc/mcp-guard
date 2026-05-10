import os from 'node:os';
import path from 'node:path';
import type {
  CandidatePath,
  CandidatePathOptions,
  DiscoveryScope,
  McpClient,
} from './types.js';

function addCandidate(
  out: CandidatePath[],
  client: McpClient,
  scope: DiscoveryScope,
  label: string,
  filePath: string
): void {
  out.push({ client, scope, label, path: filePath });
}

function defaultWindowsAppData(home: string): string {
  return path.join(home, 'AppData', 'Roaming');
}

function appConfigDir(
  appName: 'Code' | 'Claude',
  home: string,
  platform: NodeJS.Platform,
  env: Record<string, string | undefined>
): string {
  if (platform === 'win32') {
    return path.join(env['APPDATA'] ?? defaultWindowsAppData(home), appName);
  }

  if (platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', appName);
  }

  return path.join(env['XDG_CONFIG_HOME'] ?? path.join(home, '.config'), appName);
}

function includeCandidate(candidate: CandidatePath, opts: CandidatePathOptions): boolean {
  if (opts.client !== undefined && candidate.client !== opts.client) return false;

  const scope = opts.scope ?? 'all';
  if (scope !== 'all' && candidate.scope !== scope) return false;

  return true;
}

export function buildCandidatePaths(opts: CandidatePathOptions = {}): CandidatePath[] {
  const cwd = opts.cwd ?? process.cwd();
  const home = opts.home ?? os.homedir();
  const platform = opts.platform ?? process.platform;
  const env = opts.env ?? process.env;

  const candidates: CandidatePath[] = [];

  addCandidate(candidates, 'cursor', 'project', 'cursor project', path.join(cwd, '.cursor', 'mcp.json'));
  addCandidate(candidates, 'vscode', 'project', 'vscode project', path.join(cwd, '.vscode', 'mcp.json'));
  addCandidate(candidates, 'claude-code', 'project', 'claude-code project', path.join(cwd, '.mcp.json'));

  addCandidate(candidates, 'cursor', 'user', 'cursor user', path.join(home, '.cursor', 'mcp.json'));
  addCandidate(
    candidates,
    'vscode',
    'user',
    'vscode user',
    path.join(appConfigDir('Code', home, platform, env), 'User', 'mcp.json')
  );
  addCandidate(candidates, 'claude-code', 'user', 'claude-code user', path.join(home, '.claude.json'));

  const claudeDir = appConfigDir('Claude', home, platform, env);
  addCandidate(
    candidates,
    'claude-desktop',
    'user',
    'claude-desktop user claude_desktop_config',
    path.join(claudeDir, 'claude_desktop_config.json')
  );
  addCandidate(
    candidates,
    'claude-desktop',
    'user',
    'claude-desktop user config',
    path.join(claudeDir, 'config.json')
  );

  return candidates.filter((candidate) => includeCandidate(candidate, opts));
}
