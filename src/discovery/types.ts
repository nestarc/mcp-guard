export type McpClient = 'cursor' | 'vscode' | 'claude-code' | 'claude-desktop';

export type DiscoveryScope = 'project' | 'user';

export type DiscoveryScopeFilter = DiscoveryScope | 'all';

export interface CandidatePath {
  client: McpClient;
  scope: DiscoveryScope;
  label: string;
  path: string;
}

export interface CandidatePathOptions {
  cwd?: string;
  home?: string;
  platform?: NodeJS.Platform;
  env?: Record<string, string | undefined>;
  client?: McpClient;
  scope?: DiscoveryScopeFilter;
}

export interface DiscoveredTarget {
  client: McpClient;
  scope: DiscoveryScope;
  label: string;
  path: string;
  realPath: string;
  labels: string[];
}

export interface DiscoverConfigOptions extends CandidatePathOptions {
  candidates?: CandidatePath[];
}
