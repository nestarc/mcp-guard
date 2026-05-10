import type { Finding, McpServerConfig, Rule, Severity } from '../../types.js';

const SUBSTRINGS = [
  'TOKEN',
  'SECRET',
  'PASSWORD',
  'PASSWD',
  'API_KEY',
  'APIKEY',
  'PRIVATE_KEY',
  'CREDENTIAL',
  'ACCESS_KEY',
  'AUTHORIZATION',
  'COOKIE',
  'X-API-KEY',
];

const PREFIXES = ['AWS_', 'GCP_', 'GOOGLE_', 'AZURE_', 'OPENAI_', 'ANTHROPIC_', 'GITHUB_TOKEN', 'GITLAB_TOKEN'];

const PLACEHOLDER_RE = /^(\$\{[^}]+\}|<[^>]+>|your[-_].*[-_]here)$/i;

function looksSecret(key: string): boolean {
  const upper = key.toUpperCase();
  if (SUBSTRINGS.some((s) => upper.includes(s))) return true;
  if (PREFIXES.some((p) => upper.startsWith(p))) return true;
  return false;
}

function decideSeverity(value: unknown): Severity {
  if (typeof value !== 'string') return 'high';
  if (value === '') return 'medium';
  if (PLACEHOLDER_RE.test(value)) return 'medium';
  if (value.length < 8) return 'medium';
  return 'high';
}

function scanRecord(
  server: McpServerConfig,
  source: 'env' | 'headers',
  values: Record<string, unknown> | undefined
): Finding[] {
  if (!values) return [];
  const out: Finding[] = [];
  for (const [key, value] of Object.entries(values)) {
    if (!looksSecret(key)) continue;
    const severity = decideSeverity(value);
    const label = source === 'env' ? 'environment variables' : 'headers';
    out.push({
      ruleId: 'MCPG001',
      severity,
      server: server.name,
      title: `Secret-like value in ${label}`,
      message: `${source === 'env' ? 'Environment variable' : 'Header'} ${key} appears to contain a secret. Value not shown.`,
      recommendation:
        'Move secrets to a secure secret manager or prompt-based auth flow. Avoid committing real values.',
      path: `mcpServers.${server.name}.${source}.${key}`,
    });
  }
  return out;
}

export const secretsRule: Rule = {
  id: 'MCPG001',
  run(server: McpServerConfig): Finding[] {
    return [
      ...scanRecord(server, 'env', server.env),
      ...scanRecord(server, 'headers', server.headers),
    ];
  },
};
