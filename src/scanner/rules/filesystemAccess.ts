import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { isBroadPath, isParentTraversal } from '../../utils/paths.js';

const FS_SERVER_HINT = '@modelcontextprotocol/server-filesystem';

export const filesystemAccessRule: Rule = {
  id: 'MCPG005',
  run(server: McpServerConfig): Finding[] {
    const args = server.args ?? [];
    const flagged = args.find((a) => isBroadPath(a) || isParentTraversal(a));
    if (!flagged) return [];

    const usesFsServer =
      args.some((a) => a.includes(FS_SERVER_HINT)) ||
      (server.command?.includes(FS_SERVER_HINT) ?? false);
    const fsHint = usesFsServer
      ? ' This server appears to be the MCP filesystem server, which exposes the path directly.'
      : '';

    return [
      {
        ruleId: 'MCPG005',
        severity: 'high',
        server: server.name,
        title: 'Broad filesystem access',
        message: `Argument appears to grant broad file access: ${flagged}.${fsHint}`,
        recommendation: 'Restrict access to a project-specific directory.',
        path: `mcpServers.${server.name}.args`,
      },
    ];
  },
};
