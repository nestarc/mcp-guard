import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { discoverConfigs } from '../src/discovery/discoverConfigs.js';
import type { CandidatePath } from '../src/discovery/types.js';

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'mcp-guard-discovery-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('discoverConfigs', () => {
  it('ignores missing candidate files', async () => {
    await withTempDir(async (dir) => {
      const targets = await discoverConfigs({
        candidates: [
          {
            client: 'cursor',
            scope: 'project',
            label: 'cursor project',
            path: path.join(dir, '.cursor', 'mcp.json'),
          },
        ],
      });

      expect(targets).toEqual([]);
    });
  });

  it('returns existing readable candidate files', async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, '.cursor', 'mcp.json');
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, '{"mcpServers":{}}');

      const targets = await discoverConfigs({
        candidates: [
          {
            client: 'cursor',
            scope: 'project',
            label: 'cursor project',
            path: file,
          },
        ],
      });

      expect(targets).toHaveLength(1);
      expect(targets[0]).toMatchObject({
        client: 'cursor',
        scope: 'project',
        label: 'cursor project',
        path: file,
        labels: ['cursor project'],
      });
      expect(targets[0]!.realPath).toBeTruthy();
    });
  });

  it('ignores directory candidates at config file paths', async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, '.cursor', 'mcp.json');
      await mkdir(file, { recursive: true });

      const targets = await discoverConfigs({
        candidates: [
          {
            client: 'cursor',
            scope: 'project',
            label: 'cursor project',
            path: file,
          },
        ],
      });

      expect(targets).toEqual([]);
    });
  });

  it('deduplicates candidates that resolve to the same real path and preserves labels', async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, 'mcp.json');
      const nestedDir = path.join(dir, 'nested');
      const fileWithParentSegment = `${nestedDir}${path.sep}..${path.sep}mcp.json`;
      await mkdir(nestedDir);
      await writeFile(file, '{"mcpServers":{}}');
      const candidates: CandidatePath[] = [
        { client: 'cursor', scope: 'project', label: 'cursor project', path: file },
        { client: 'vscode', scope: 'project', label: 'vscode project', path: fileWithParentSegment },
      ];

      const targets = await discoverConfigs({ candidates });

      expect(targets).toHaveLength(1);
      expect(targets[0]!.labels).toEqual(['cursor project', 'vscode project']);
    });
  });

  it('uses generated candidates when candidates are not supplied', async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, '.mcp.json');
      await writeFile(file, '{"mcpServers":{}}');

      const targets = await discoverConfigs({
        cwd: dir,
        home: path.join(dir, 'home'),
        scope: 'project',
        client: 'claude-code',
      });

      expect(targets).toHaveLength(1);
      expect(targets[0]!.label).toBe('claude-code project');
    });
  });
});
