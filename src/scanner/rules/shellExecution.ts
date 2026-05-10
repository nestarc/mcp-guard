import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { commandBasename } from '../../utils/command.js';

const SHELLS = new Set(['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'cmd', 'powershell', 'pwsh']);
const EVAL_FLAGS = new Set(['-c', '/c', '-e', '--eval', '--command']);

export const shellExecutionRule: Rule = {
  id: 'MCPG002',
  run(server: McpServerConfig): Finding[] {
    if (!server.command) return [];
    const basename = commandBasename(server.command);
    if (!SHELLS.has(basename)) return [];
    const flags = (server.args ?? []).filter((a) => EVAL_FLAGS.has(a));
    const flagSuffix = flags.length > 0 ? ` (with eval flag: ${flags.join(', ')})` : '';
    return [
      {
        ruleId: 'MCPG002',
        severity: 'high',
        server: server.name,
        title: 'Shell execution command',
        message: `Server uses a shell interpreter (${basename}) as its command${flagSuffix}.`,
        recommendation:
          'Prefer invoking a specific binary directly. Shell commands can execute arbitrary code provided in args.',
        path: `mcpServers.${server.name}.command`,
      },
    ];
  },
};
