import type { Finding, McpServerConfig, Rule } from '../../types.js';

function parseUrl(input: string | undefined): URL | null {
  if (!input) return null;
  try {
    return new URL(input);
  } catch {
    return null;
  }
}

function isLoopback(host: string): boolean {
  const h = host.toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1';
}

function isPrivateIPv4(host: string): boolean {
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

export const plainHttpRule: Rule = {
  id: 'MCPG004',
  run(server: McpServerConfig): Finding[] {
    if (!server.url || !server.url.startsWith('http://')) return [];
    return [
      {
        ruleId: 'MCPG004',
        severity: 'medium',
        server: server.name,
        title: 'Plain HTTP transport',
        message: `Server URL uses plain HTTP: ${server.url}`,
        recommendation: 'Prefer authenticated HTTPS or a trusted local-only transport.',
        path: `mcpServers.${server.name}.url`,
      },
    ];
  },
};

export const publicRemoteEndpointRule: Rule = {
  id: 'MCPG008',
  run(server: McpServerConfig): Finding[] {
    if (!server.url || !server.url.startsWith('https://')) return [];
    const url = parseUrl(server.url);
    if (!url) return [];
    if (isLoopback(url.hostname) || isPrivateIPv4(url.hostname)) return [];
    return [
      {
        ruleId: 'MCPG008',
        severity: 'low',
        server: server.name,
        title: 'Public remote endpoint',
        message: `Server connects to a public remote endpoint: ${url.origin}`,
        recommendation:
          'Confirm the endpoint is trusted and uses authenticated TLS. Be aware that data may leave your environment.',
        path: `mcpServers.${server.name}.url`,
      },
    ];
  },
};
