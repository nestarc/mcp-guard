import type { Finding, McpServerConfig, Rule } from '../../types.js';

export const missingCommandRule: Rule = {
  id: 'MCPG009',
  run(server: McpServerConfig): Finding[] {
    if (server.command || server.url) return [];
    return [
      {
        ruleId: 'MCPG009',
        severity: 'info',
        server: server.name,
        title: 'Server entry missing command or url',
        message: 'Server entry does not define a command or url.',
        recommendation: 'Define a command for stdio servers or url for remote servers.',
        path: `mcpServers.${server.name}`,
      },
    ];
  },
};
