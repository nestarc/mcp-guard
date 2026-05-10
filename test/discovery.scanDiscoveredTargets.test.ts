import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { scanDiscoveredTargets } from '../src/discovery/scanDiscoveredTargets.js';
import type { DiscoveredTarget } from '../src/discovery/types.js';

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'mcp-guard-scan-all-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function target(file: string, label = 'cursor project'): DiscoveredTarget {
  return {
    client: 'cursor',
    scope: 'project',
    label,
    path: file,
    realPath: file,
    labels: [label],
  };
}

describe('scanDiscoveredTargets', () => {
  it('aggregates findings, server counts, and target metadata', async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, '.cursor', 'mcp.json');
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(
        file,
        JSON.stringify({
          mcpServers: {
            remote: {
              url: 'https://api.example.com/mcp',
              headers: { Authorization: 'Bearer secret-value-12345' },
            },
          },
        })
      );

      const result = await scanDiscoveredTargets([target(file)]);

      expect(result.schemaVersion).toBe('2');
      expect(result.summary).toMatchObject({
        targetsDiscovered: 1,
        targetsScanned: 1,
        serversScanned: 1,
        findings: 2,
        risk: 'high',
      });
      expect(result.findings[0]!.target).toMatchObject({
        client: 'cursor',
        scope: 'project',
        path: file,
      });
      expect(JSON.stringify(result)).not.toContain('secret-value-12345');
    });
  });

  it('continues after malformed config and records a target warning', async () => {
    await withTempDir(async (dir) => {
      const bad = path.join(dir, 'bad.json');
      const good = path.join(dir, 'good.json');
      await writeFile(bad, '{');
      await writeFile(good, JSON.stringify({ mcpServers: { local: { command: 'node' } } }));

      const warnings: string[] = [];
      const result = await scanDiscoveredTargets([target(bad, 'bad'), target(good, 'good')], {
        onWarn: (message) => warnings.push(message),
      });

      expect(result.summary.targetsDiscovered).toBe(2);
      expect(result.summary.targetsScanned).toBe(1);
      expect(result.targets).toHaveLength(2);
      expect(result.targets.find((entry) => entry.path === bad)).toMatchObject({
        scanned: false,
      });
      expect(warnings.join('\n')).toMatch(/bad\.json/);
    });
  });

  it('marks unsupported discovered config shapes as not scanned', async () => {
    await withTempDir(async (dir) => {
      const unsupported = path.join(dir, 'empty-shape.json');
      await writeFile(unsupported, '{}');
      const warnings: string[] = [];

      const result = await scanDiscoveredTargets([target(unsupported, 'unsupported')], {
        onWarn: (message) => warnings.push(message),
      });

      expect(result.summary.targetsDiscovered).toBe(1);
      expect(result.summary.targetsScanned).toBe(0);
      expect(result.targets[0]).toMatchObject({
        scanned: false,
        serversScanned: 0,
        findings: 0,
      });
      expect(result.targets[0]!.warning).toMatch(/mcpServers|servers/);
      expect(warnings.join('\n')).toMatch(/mcpServers|servers/);
    });
  });

  it('counts valid empty server maps as scanned', async () => {
    await withTempDir(async (dir) => {
      const emptyMap = path.join(dir, 'empty-map.json');
      await writeFile(emptyMap, JSON.stringify({ mcpServers: {} }));

      const result = await scanDiscoveredTargets([target(emptyMap, 'empty')]);

      expect(result.summary.targetsScanned).toBe(1);
      expect(result.targets[0]).toMatchObject({
        scanned: true,
        serversScanned: 0,
        findings: 0,
      });
    });
  });

  it('returns an empty aggregate result for no targets', async () => {
    const result = await scanDiscoveredTargets([]);

    expect(result).toMatchObject({
      schemaVersion: '2',
      targets: [],
      summary: {
        risk: 'info',
        targetsDiscovered: 0,
        targetsScanned: 0,
        serversScanned: 0,
        findings: 0,
      },
      findings: [],
    });
  });
});
