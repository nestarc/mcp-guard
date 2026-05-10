import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { commandBasename } from '../../utils/command.js';

const RUNTIMES = new Set(['docker', 'podman']);

function findIssues(args: string[]): string[] {
  const issues: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--privileged') {
      issues.push('--privileged flag');
      continue;
    }
    if (a === '-v' || a === '--volume') {
      const next = args[i + 1] ?? '';
      if (next.includes('docker.sock')) issues.push('Docker socket mount via -v');
      else if (next.startsWith('/:') || next.startsWith('/:/')) issues.push('Host root mount via -v');
    }
    if (a === '--mount') {
      const next = args[i + 1] ?? '';
      if (next.includes('source=/var/run/docker.sock')) issues.push('Docker socket mount via --mount');
      else if (/(^|,)source=\//.test(next) && !/(^|,)source=\.\//.test(next)) {
        // crude: source=/ but not source=./
        if (/(^|,)source=\/(,|$)/.test(next)) issues.push('Host root mount via --mount');
      }
    }
  }
  return issues;
}

export const dockerRiskRule: Rule = {
  id: 'MCPG006',
  run(server: McpServerConfig): Finding[] {
    if (!server.command) return [];
    const basename = commandBasename(server.command);
    if (!RUNTIMES.has(basename)) return [];
    const issues = findIssues(server.args ?? []);
    if (issues.length === 0) return [];
    return [
      {
        ruleId: 'MCPG006',
        severity: 'high',
        server: server.name,
        title: 'Docker privileged or socket access',
        message: `Container runtime arguments grant elevated host access: ${issues.join('; ')}.`,
        recommendation:
          'Avoid --privileged and host root or docker.sock mounts. Mount only specific paths needed by the server.',
        path: `mcpServers.${server.name}.args`,
      },
    ];
  },
};
