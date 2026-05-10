import type { Finding, McpServerConfig, Rule } from '../../types.js';

const PATTERNS: Array<{ id: string; re: RegExp; label: string }> = [
  {
    id: 'pipe',
    re: /\b(curl|wget)\b\s+[^|]+\|\s*(sh|bash|zsh|fish)\b/i,
    label: 'pipe-to-shell download',
  },
  { id: 'rmrf', re: /\brm\s+-(rf|fr)\b/i, label: 'recursive forced removal' },
  { id: 'chmodx', re: /\bchmod\s+\+x\b/i, label: 'chmod +x' },
];

export const suspiciousArgsRule: Rule = {
  id: 'MCPG007',
  run(server: McpServerConfig): Finding[] {
    if (!server.command && (!server.args || server.args.length === 0)) return [];
    const haystack = [server.command ?? '', ...(server.args ?? [])].join(' ');
    const out: Finding[] = [];
    for (const p of PATTERNS) {
      if (p.re.test(haystack)) {
        out.push({
          ruleId: 'MCPG007',
          severity: 'critical',
          server: server.name,
          title: 'Suspicious shell pipeline or download',
          message: `Detected pattern: ${p.label}.`,
          recommendation:
            'Inspect the command carefully. Piping a remote download into a shell or recursive deletion can have severe consequences.',
          path: `mcpServers.${server.name}.args`,
          metadata: { pattern: p.id },
        });
      }
    }
    return out;
  },
};
