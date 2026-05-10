import { describe, it, expect } from 'vitest';
import { dockerRiskRule } from '../src/scanner/rules/dockerRisk.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  ...(command === undefined ? {} : { command }),
  ...(args === undefined ? {} : { args }),
  raw: { command, args },
});

describe('dockerRiskRule (MCPG006)', () => {
  it('has MCPG006 rule id', () => {
    expect(dockerRiskRule.id).toBe('MCPG006');
  });

  it('flags --privileged', () => {
    const f = dockerRiskRule.run(server('docker', ['run', '--privileged', 'image']));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.ruleId).toBe('MCPG006');
  });

  it('reports MCPG006 finding shape', () => {
    expect(dockerRiskRule.run(server('docker', ['run', '--privileged', 'image']))[0]).toEqual({
      ruleId: 'MCPG006',
      severity: 'high',
      server: 's',
      title: 'Docker privileged or socket access',
      message: 'Container runtime arguments grant elevated host access: --privileged flag.',
      recommendation:
        'Avoid --privileged and host root or docker.sock mounts. Mount only specific paths needed by the server.',
      path: 'mcpServers.s.args',
    });
  });

  it('flags -v with docker.sock mount', () => {
    expect(
      dockerRiskRule.run(server('docker', ['run', '-v', '/var/run/docker.sock:/var/run/docker.sock', 'img']))
    ).toHaveLength(1);
  });

  it('flags -v with root mount', () => {
    expect(dockerRiskRule.run(server('docker', ['run', '-v', '/:/host', 'img']))).toHaveLength(1);
  });

  it('flags --mount with docker.sock source', () => {
    expect(
      dockerRiskRule.run(
        server('docker', ['run', '--mount', 'type=bind,source=/var/run/docker.sock,target=/sock', 'img'])
      )
    ).toHaveLength(1);
  });

  it('flags --mount with root source', () => {
    expect(
      dockerRiskRule.run(server('docker', ['run', '--mount', 'type=bind,source=/,target=/host', 'img']))
    ).toHaveLength(1);
  });

  it('flags podman --privileged', () => {
    expect(dockerRiskRule.run(server('podman', ['run', '--privileged', 'img']))).toHaveLength(1);
  });

  it('does not flag normal docker run', () => {
    expect(dockerRiskRule.run(server('docker', ['run', '-v', './data:/data', 'img']))).toEqual([]);
  });

  it('does not flag non-docker command', () => {
    expect(dockerRiskRule.run(server('node', ['./srv.js']))).toEqual([]);
  });
});
