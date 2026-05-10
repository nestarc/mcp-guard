import { describe, it, expect } from 'vitest';
import { secretsRule } from '../src/scanner/rules/secrets.js';
import type { McpServerConfig } from '../src/types.js';

const server = (env: Record<string, unknown>): McpServerConfig => ({
  name: 's',
  env,
  raw: { env },
});

const serverWithFields = (fields: Partial<McpServerConfig>): McpServerConfig => ({
  name: 's',
  raw: fields,
  ...fields,
});

describe('secretsRule (MCPG001)', () => {
  it('flags GITHUB_TOKEN with non-empty long value as high', () => {
    const f = secretsRule.run(server({ GITHUB_TOKEN: 'ghp_aaaaaaaaaaaaaaaaaa' }));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.ruleId).toBe('MCPG001');
  });

  it('does not include the secret value in message', () => {
    const f = secretsRule.run(server({ GITHUB_TOKEN: 'ghp_super_secret_value_12345' }));
    expect(f[0]!.message).not.toContain('ghp_super_secret_value_12345');
  });

  it('flags placeholder value with severity medium', () => {
    const f = secretsRule.run(server({ AWS_ACCESS_KEY_ID: '${AWS_ACCESS_KEY_ID}' }));
    expect(f[0]!.severity).toBe('medium');
  });

  it('flags empty string value with severity medium', () => {
    const f = secretsRule.run(server({ API_KEY: '' }));
    expect(f[0]!.severity).toBe('medium');
  });

  it('flags <placeholder> with severity medium', () => {
    const f = secretsRule.run(server({ PASSWORD: '<your-password>' }));
    expect(f[0]!.severity).toBe('medium');
  });

  it('flags short value (<8 chars) with severity medium', () => {
    const f = secretsRule.run(server({ SECRET_TOKEN: 'short' }));
    expect(f[0]!.severity).toBe('medium');
  });

  it('flags AWS_ prefix as secret', () => {
    const f = secretsRule.run(server({ AWS_SESSION_TOKEN: 'AKIAaaaaaaaaaaaa' }));
    expect(f).toHaveLength(1);
  });

  it.each([
    ['MY_PASSWD'],
    ['MY_APIKEY'],
    ['MY_PRIVATE_KEY'],
    ['MY_CREDENTIAL'],
    ['MY_ACCESS_KEY'],
    ['GCP_SERVICE_ACCOUNT'],
    ['GOOGLE_CLIENT_SECRET'],
    ['AZURE_CLIENT_SECRET'],
    ['OPENAI_API_KEY'],
    ['ANTHROPIC_API_KEY'],
    ['GITLAB_TOKEN'],
  ])('flags %s as secret-like', (key) => {
    const f = secretsRule.run(server({ [key]: 'secret-value-12345' }));
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe('MCPG001');
  });

  it('flags case-insensitive matches', () => {
    const f = secretsRule.run(server({ github_token: 'ghp_aaaaaaaaaaaaaaaa' }));
    expect(f).toHaveLength(1);
  });

  it('returns expected finding shape', () => {
    const f = secretsRule.run(server({ API_KEY: 'secret-value-12345' }));
    expect(f[0]).toMatchObject({
      title: 'Secret-like value in environment variables',
      recommendation:
        'Move secrets to a secure secret manager or prompt-based auth flow. Avoid committing real values.',
      path: 'mcpServers.s.env.API_KEY',
    });
  });

  it('does not include the secret value anywhere in serialized finding output', () => {
    const secret = 'super_secret_value_12345';
    const f = secretsRule.run(server({ API_KEY: secret }));
    expect(JSON.stringify(f[0])).not.toContain(secret);
  });

  it('does not flag non-secret keys', () => {
    const f = secretsRule.run(server({ NODE_ENV: 'production', PORT: '3000' }));
    expect(f).toEqual([]);
  });

  it('does not flag when env is undefined', () => {
    expect(secretsRule.run({ name: 's', raw: {} })).toEqual([]);
  });

  it('flags non-string value (e.g. number) as high (cannot judge content)', () => {
    const f = secretsRule.run(server({ API_KEY: 123456789 }));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
  });

  it('flags secret-like header keys without printing values', () => {
    const secret = 'Bearer ghp_super_secret_value_12345';
    const findings = secretsRule.run(
      serverWithFields({
        headers: { Authorization: secret, 'X-API-Key': 'secret-value-12345' },
      })
    );

    expect(findings).toHaveLength(2);
    expect(findings.map((finding) => finding.path)).toEqual([
      'mcpServers.s.headers.Authorization',
      'mcpServers.s.headers.X-API-Key',
    ]);
    expect(JSON.stringify(findings)).not.toContain(secret);
  });

  it('does not flag non-secret header keys', () => {
    const findings = secretsRule.run(
      serverWithFields({
        headers: { Accept: 'application/json' },
      })
    );

    expect(findings).toEqual([]);
  });
});
