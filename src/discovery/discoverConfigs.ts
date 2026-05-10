import { open, realpath, stat } from 'node:fs/promises';
import { buildCandidatePaths } from './candidatePaths.js';
import type { DiscoverConfigOptions, DiscoveredTarget } from './types.js';

async function isReadableFile(filePath: string): Promise<boolean> {
  try {
    const info = await stat(filePath);
    if (!info.isFile()) return false;

    const handle = await open(filePath, 'r');
    try {
      return true;
    } finally {
      await handle.close();
    }
  } catch {
    return false;
  }
}

export async function discoverConfigs(opts: DiscoverConfigOptions = {}): Promise<DiscoveredTarget[]> {
  const candidates = opts.candidates ?? buildCandidatePaths(opts);
  const byRealPath = new Map<string, DiscoveredTarget>();

  for (const candidate of candidates) {
    if (!(await isReadableFile(candidate.path))) continue;

    let resolved = candidate.path;
    try {
      resolved = await realpath(candidate.path);
    } catch {
      resolved = candidate.path;
    }

    const existing = byRealPath.get(resolved);
    if (existing) {
      existing.labels.push(candidate.label);
      continue;
    }

    byRealPath.set(resolved, {
      ...candidate,
      realPath: resolved,
      labels: [candidate.label],
    });
  }

  return [...byRealPath.values()];
}
