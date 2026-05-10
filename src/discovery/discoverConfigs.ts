import { constants } from 'node:fs';
import { access, realpath } from 'node:fs/promises';
import { buildCandidatePaths } from './candidatePaths.js';
import type { DiscoverConfigOptions, DiscoveredTarget } from './types.js';

async function isReadable(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

export async function discoverConfigs(opts: DiscoverConfigOptions = {}): Promise<DiscoveredTarget[]> {
  const candidates = opts.candidates ?? buildCandidatePaths(opts);
  const byRealPath = new Map<string, DiscoveredTarget>();

  for (const candidate of candidates) {
    if (!(await isReadable(candidate.path))) continue;

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
