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
  const part = spec.split(',').find((candidate) => candidate.startsWith('source=') || candidate.startsWith('src='));
  if (part?.startsWith('source=')) return part.slice('source='.length);
  if (part?.startsWith('src=')) return part.slice('src='.length);
  return undefined;
}

function volumeHostPath(spec: string): string | undefined {
  const colon = spec.indexOf(':');
  return colon === -1 ? undefined : spec.slice(0, colon);
}

function findIssues(args: string[]): string[] {
  const issues: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--privileged' || a === '--privileged=true') {
      issues.push('--privileged flag');
      continue;
    }
    const volume = optionValue(a, '-v', args, i) ?? optionValue(a, '--volume', args, i);
    if (volume !== undefined) {
      const hostPath = volumeHostPath(volume);
      if (hostPath?.includes('docker.sock')) issues.push('Docker socket mount via -v');
      else if (hostPath === '/') issues.push('Host root mount via -v');
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
