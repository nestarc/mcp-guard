import { describe, it, expect } from 'vitest';
import {
  plainHttpRule,
  publicRemoteEndpointRule,
} from '../src/scanner/rules/httpTransport.js';
import type { McpServerConfig } from '../src/types.js';

const server = (url?: string): McpServerConfig => ({
  name: 's',
  ...(url === undefined ? {} : { url }),
  raw: url === undefined ? {} : { url },
});

describe('plainHttpRule (MCPG004)', () => {
  it('flags http://localhost as medium', () => {
    const f = plainHttpRule.run(server('http://localhost:3000/sse'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.ruleId).toBe('MCPG004');
  });

  it('flags http://example.com as medium', () => {
    expect(plainHttpRule.run(server('http://example.com'))[0]!.severity).toBe('medium');
  });

  it('does not flag https://', () => {
    expect(plainHttpRule.run(server('https://example.com'))).toEqual([]);
  });

  it('does not flag when url absent', () => {
    expect(plainHttpRule.run(server(undefined))).toEqual([]);
  });
});

describe('publicRemoteEndpointRule (MCPG008)', () => {
  it('flags https://example.com as low', () => {
    const f = publicRemoteEndpointRule.run(server('https://api.example.com'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('low');
    expect(f[0]!.ruleId).toBe('MCPG008');
  });

  it('does not flag https://localhost', () => {
    expect(publicRemoteEndpointRule.run(server('https://localhost:3000'))).toEqual([]);
  });

  it('does not flag https://127.0.0.1', () => {
    expect(publicRemoteEndpointRule.run(server('https://127.0.0.1:3000'))).toEqual([]);
  });

  it('does not flag https://10.0.0.5 (RFC1918)', () => {
    expect(publicRemoteEndpointRule.run(server('https://10.0.0.5:3000'))).toEqual([]);
  });

  it('does not flag https://192.168.1.5', () => {
    expect(publicRemoteEndpointRule.run(server('https://192.168.1.5'))).toEqual([]);
  });

  it('does not flag http URL (covered by MCPG004)', () => {
    expect(publicRemoteEndpointRule.run(server('http://example.com'))).toEqual([]);
  });

  it('does not flag invalid URL', () => {
    expect(publicRemoteEndpointRule.run(server('not-a-url'))).toEqual([]);
  });
});
