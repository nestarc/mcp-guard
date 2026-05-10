import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { commandBasename } from '../../utils/command.js';

const RUNTIMES = new Set(['docker', 'podman']);

function optionValue(arg: string, option: string, args: string[], index: number): string | undefined {
  if (arg === option) return args[index + 1];
  const prefix = `${option}=`;
  if (arg.startsWith(prefix)) return arg.slice(prefix.length);
  return undefined;
}

function mountSource(spec: string): string | undefined {
  return spec
    .split(',')
    .find((part) => part.startsWith('source='))
    ?.slice('source='.length);
}

function findIssues(args: string[]): string[] {
  const issues: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--privileged') {
      issues.push('--privileged flag');
      continue;
    }
    const volume = optionValue(a, '-v', args, i) ?? optionValue(a, '--volume', args, i);
    if (volume !== undefined) {
      if (volume.includes('docker.sock')) issues.push('Docker socket mount via -v');
      else if (volume.startsWith('/:') || volume.startsWith('/:/')) issues.push('Host root mount via -v');
    }

    const mount = optionValue(a, '--mount', args, i);
    const source = mount === undefined ? undefined : mountSource(mount);
    if (source?.includes('docker.sock')) {
      issues.push('Docker socket mount via --mount');
    } else if (source === '/') {
      issues.push('Host root mount via --mount');
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
