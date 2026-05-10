import type { Finding, McpServerConfig, Rule } from '../../types.js';

function parseUrl(input: string | undefined): URL | null {
  if (!input) return null;
  try {
    return new URL(input);
  } catch {
    return null;
  }
}

function safeUrlForMessage(url: URL): string {
  return url.origin;
}

function isLoopback(host: string): boolean {
  const h = host.toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1';
}

function normalizeIPv6Host(host: string): string {
  return host.toLowerCase().replace(/^\[(.*)\]$/, '$1');
}

function isLocalIPv6(host: string): boolean {
  const h = normalizeIPv6Host(host);
  if (!h.includes(':')) return false;
  if (h === '::1') return true;
  const firstSegment = h.split(':', 1)[0];
  if (!firstSegment) return false;
  const first = Number.parseInt(firstSegment, 16);
  if (Number.isNaN(first)) return false;
  if (first >= 0xfe80 && first <= 0xfebf) return true;
  if (first >= 0xfc00 && first <= 0xfdff) return true;
  return false;
}

function isPrivateIPv4(host: string): boolean {
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 127) return true;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

export const plainHttpRule: Rule = {
  id: 'MCPG004',
  run(server: McpServerConfig): Finding[] {
    const url = parseUrl(server.url);
    if (!url || url.protocol !== 'http:') return [];
    return [
      {
        ruleId: 'MCPG004',
        severity: 'medium',
        server: server.name,
        title: 'Plain HTTP transport',
        message: `Server URL uses plain HTTP: ${safeUrlForMessage(url)}`,
        recommendation: 'Prefer authenticated HTTPS or a trusted local-only transport.',
        path: `mcpServers.${server.name}.url`,
      },
    ];
  },
};

export const publicRemoteEndpointRule: Rule = {
  id: 'MCPG008',
  run(server: McpServerConfig): Finding[] {
    const url = parseUrl(server.url);
    if (!url || url.protocol !== 'https:') return [];
    if (isLoopback(url.hostname) || isPrivateIPv4(url.hostname) || isLocalIPv6(url.hostname)) return [];
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
