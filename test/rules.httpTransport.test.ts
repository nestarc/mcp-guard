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
  it('has MCPG004 rule id', () => {
    expect(plainHttpRule.id).toBe('MCPG004');
  });

  it('flags http://localhost as medium', () => {
    const f = plainHttpRule.run(server('http://localhost:3000/sse'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.ruleId).toBe('MCPG004');
  });

  it('reports MCPG004 finding shape', () => {
    expect(plainHttpRule.run(server('http://example.com'))[0]).toEqual({
      ruleId: 'MCPG004',
      severity: 'medium',
      server: 's',
      title: 'Plain HTTP transport',
      message: 'Server URL uses plain HTTP: http://example.com',
      recommendation: 'Prefer authenticated HTTPS or a trusted local-only transport.',
      path: 'mcpServers.s.url',
    });
  });

  it('does not leak credentials or query parameters in MCPG004 message', () => {
    const message = plainHttpRule.run(server('http://user:secret@example.com/mcp?api_key=abc123'))[0]!
      .message;

    expect(message).toContain('http://example.com');
    expect(message).not.toContain('secret');
    expect(message).not.toContain('api_key=abc123');
  });

  it('flags http://example.com as medium', () => {
    expect(plainHttpRule.run(server('http://example.com'))[0]!.severity).toBe('medium');
  });

  it('flags uppercase HTTP scheme as medium', () => {
    const f = plainHttpRule.run(server('HTTP://example.com'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.ruleId).toBe('MCPG004');
  });

  it('does not flag https://', () => {
    expect(plainHttpRule.run(server('https://example.com'))).toEqual([]);
  });

  it('does not flag invalid plain HTTP URL', () => {
    expect(plainHttpRule.run(server('http://'))).toEqual([]);
  });

  it('does not flag when url absent', () => {
    expect(plainHttpRule.run(server(undefined))).toEqual([]);
  });
});

describe('publicRemoteEndpointRule (MCPG008)', () => {
  it('has MCPG008 rule id', () => {
    expect(publicRemoteEndpointRule.id).toBe('MCPG008');
  });

  it('flags https://example.com as low', () => {
    const f = publicRemoteEndpointRule.run(server('https://api.example.com'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('low');
    expect(f[0]!.ruleId).toBe('MCPG008');
  });

  it('flags uppercase HTTPS scheme as low', () => {
    const f = publicRemoteEndpointRule.run(server('HTTPS://api.example.com'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('low');
    expect(f[0]!.ruleId).toBe('MCPG008');
  });

  it('reports MCPG008 finding shape', () => {
    expect(publicRemoteEndpointRule.run(server('https://api.example.com/path'))[0]).toEqual({
      ruleId: 'MCPG008',
      severity: 'low',
      server: 's',
      title: 'Public remote endpoint',
      message: 'Server connects to a public remote endpoint: https://api.example.com',
      recommendation:
        'Confirm the endpoint is trusted and uses authenticated TLS. Be aware that data may leave your environment.',
      path: 'mcpServers.s.url',
    });
  });

  it('does not flag https://localhost', () => {
    expect(publicRemoteEndpointRule.run(server('https://localhost:3000'))).toEqual([]);
  });

  it('does not flag https://127.0.0.1', () => {
    expect(publicRemoteEndpointRule.run(server('https://127.0.0.1:3000'))).toEqual([]);
  });

  it('does not flag https://127.0.0.2 (IPv4 loopback)', () => {
    expect(publicRemoteEndpointRule.run(server('https://127.0.0.2'))).toEqual([]);
  });

  it('does not flag https://127.1.2.3 (IPv4 loopback)', () => {
    expect(publicRemoteEndpointRule.run(server('https://127.1.2.3'))).toEqual([]);
  });

  it('does not flag https://10.0.0.5 (RFC1918)', () => {
    expect(publicRemoteEndpointRule.run(server('https://10.0.0.5:3000'))).toEqual([]);
  });

  it('does not flag https://172.16.0.1 (RFC1918)', () => {
    expect(publicRemoteEndpointRule.run(server('https://172.16.0.1'))).toEqual([]);
  });

  it('does not flag https://172.31.255.255 (RFC1918)', () => {
    expect(publicRemoteEndpointRule.run(server('https://172.31.255.255'))).toEqual([]);
  });

  it('does not flag https://192.168.1.5', () => {
    expect(publicRemoteEndpointRule.run(server('https://192.168.1.5'))).toEqual([]);
  });

  it('does not flag https://169.254.1.1 (link-local)', () => {
    expect(publicRemoteEndpointRule.run(server('https://169.254.1.1'))).toEqual([]);
  });

  it('does not flag https://[fe80::1] (IPv6 link-local)', () => {
    expect(publicRemoteEndpointRule.run(server('https://[fe80::1]'))).toEqual([]);
  });

  it('does not flag https://[fc00::1] (IPv6 ULA)', () => {
    expect(publicRemoteEndpointRule.run(server('https://[fc00::1]'))).toEqual([]);
  });

  it('flags https://172.15.255.255 as public', () => {
    const f = publicRemoteEndpointRule.run(server('https://172.15.255.255'));
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe('MCPG008');
  });

  it('flags https://172.32.0.0 as public', () => {
    const f = publicRemoteEndpointRule.run(server('https://172.32.0.0'));
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe('MCPG008');
  });

  it('does not flag http URL (covered by MCPG004)', () => {
    expect(publicRemoteEndpointRule.run(server('http://example.com'))).toEqual([]);
  });

  it('does not flag invalid URL', () => {
    expect(publicRemoteEndpointRule.run(server('not-a-url'))).toEqual([]);
  });
});
