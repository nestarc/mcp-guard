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

type PlatformPath = typeof path.posix;

function pathForPlatform(platform: NodeJS.Platform): PlatformPath {
  return platform === 'win32' ? path.win32 : path.posix;
}

function nonEmpty(value: string | undefined): string | undefined {
  return value && value.length > 0 ? value : undefined;
}

function defaultWindowsAppData(pathApi: PlatformPath, home: string): string {
  return pathApi.join(home, 'AppData', 'Roaming');
}

function appConfigDir(
  pathApi: PlatformPath,
  appName: 'Code' | 'Claude',
  home: string,
  platform: NodeJS.Platform,
  env: Record<string, string | undefined>
): string {
  if (platform === 'win32') {
    return pathApi.join(nonEmpty(env['APPDATA']) ?? defaultWindowsAppData(pathApi, home), appName);
  }

  if (platform === 'darwin') {
    return pathApi.join(home, 'Library', 'Application Support', appName);
  }

  return pathApi.join(nonEmpty(env['XDG_CONFIG_HOME']) ?? pathApi.join(home, '.config'), appName);
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
  const pathApi = pathForPlatform(platform);

  const candidates: CandidatePath[] = [];

  addCandidate(candidates, 'cursor', 'project', 'cursor project', pathApi.join(cwd, '.cursor', 'mcp.json'));
  addCandidate(candidates, 'vscode', 'project', 'vscode project', pathApi.join(cwd, '.vscode', 'mcp.json'));
  addCandidate(candidates, 'claude-code', 'project', 'claude-code project', pathApi.join(cwd, '.mcp.json'));

  addCandidate(candidates, 'cursor', 'user', 'cursor user', pathApi.join(home, '.cursor', 'mcp.json'));
  addCandidate(
    candidates,
    'vscode',
    'user',
    'vscode user',
    pathApi.join(appConfigDir(pathApi, 'Code', home, platform, env), 'User', 'mcp.json')
  );
  addCandidate(candidates, 'claude-code', 'user', 'claude-code user', pathApi.join(home, '.claude.json'));

  const claudeDir = appConfigDir(pathApi, 'Claude', home, platform, env);
  addCandidate(
    candidates,
    'claude-desktop',
    'user',
    'claude-desktop user claude_desktop_config',
    pathApi.join(claudeDir, 'claude_desktop_config.json')
  );
  addCandidate(
    candidates,
    'claude-desktop',
    'user',
    'claude-desktop user config',
    pathApi.join(claudeDir, 'config.json')
  );

  return candidates.filter((candidate) => includeCandidate(candidate, opts));
}
