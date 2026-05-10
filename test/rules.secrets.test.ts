import { describe, it, expect } from 'vitest';
import { secretsRule } from '../src/scanner/rules/secrets.js';
import type { McpServerConfig } from '../src/types.js';

const server = (env: Record<string, unknown>): McpServerConfig => ({
  name: 's',
  env,
  raw: { env },
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

  it('flags case-insensitive matches', () => {
    const f = secretsRule.run(server({ github_token: 'ghp_aaaaaaaaaaaaaaaa' }));
    expect(f).toHaveLength(1);
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
});
