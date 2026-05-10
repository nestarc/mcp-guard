import type { Finding, McpServerConfig, Rule } from '../../types.js';

export const missingCommandRule: Rule = {
  id: 'MCPG009',
  run(server: McpServerConfig): Finding[] {
    if (typeof server.command === 'string' || typeof server.url === 'string') return [];
    return [
      {
        ruleId: 'MCPG009',
        severity: 'info',
        server: server.name,
        title: 'Missing command or url',
        message: 'Server entry has neither a string `command` nor a string `url`.',
        recommendation:
          'Verify the entry is intentional. The server cannot be launched without one of these.',
        path: `mcpServers.${server.name}`,
      },
    ];
  },
};
