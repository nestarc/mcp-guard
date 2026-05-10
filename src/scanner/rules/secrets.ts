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

export const secretsRule: Rule = {
  id: 'MCPG001',
  run(server: McpServerConfig): Finding[] {
    if (!server.env) return [];
    const out: Finding[] = [];
    for (const [key, value] of Object.entries(server.env)) {
      if (!looksSecret(key)) continue;
      const severity = decideSeverity(value);
      out.push({
        ruleId: 'MCPG001',
        severity,
        server: server.name,
        title: 'Secret-like value in environment variables',
        message: `Environment variable ${key} appears to contain a secret. Value not shown.`,
        recommendation:
          'Move secrets to a secure secret manager or prompt-based auth flow. Avoid committing real values.',
        path: `mcpServers.${server.name}.env.${key}`,
      });
    }
    return out;
  },
};
