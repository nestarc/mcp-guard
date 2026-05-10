import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { commandBasename } from '../../utils/command.js';

const DIRECT = new Set(['npx', 'pnpx', 'bunx', 'uvx']);
const DLX_HOSTS = new Set(['yarn', 'pnpm']);

export const dynamicRunnerRule: Rule = {
  id: 'MCPG003',
  run(server: McpServerConfig): Finding[] {
    if (!server.command) return [];
    const basename = commandBasename(server.command);
    const triggered =
      DIRECT.has(basename) || (DLX_HOSTS.has(basename) && (server.args ?? []).includes('dlx'));
    if (!triggered) return [];
    return [
      {
        ruleId: 'MCPG003',
        severity: 'medium',
        server: server.name,
        title: 'Dynamic package runner',
        message: `Server uses a dynamic package runner (${basename}). Packages may be fetched and executed at runtime.`,
        recommendation:
          'Pin the exact package version or pre-install the dependency. Verify package provenance.',
        path: `mcpServers.${server.name}.command`,
      },
    ];
  },
};
