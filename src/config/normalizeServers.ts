import { z } from 'zod';
import { LoadError, type McpServerConfig } from '../types.js';

const EntrySchema = z
  .object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string(), z.unknown()).optional(),
    headers: z.record(z.string(), z.unknown()).optional(),
    envFile: z.string().optional(),
    url: z.string().optional(),
    transport: z.string().optional(),
    type: z.string().optional(),
  })
  .passthrough();

export interface NormalizeOptions {
  onWarn?: (message: string) => void;
}

interface ServerConfigFields {
  command?: string | undefined;
  args?: string[] | undefined;
  env?: Record<string, unknown> | undefined;
  headers?: Record<string, unknown> | undefined;
  envFile?: string | undefined;
  url?: string | undefined;
  transport?: string | undefined;
  type?: string | undefined;
}

function buildServerConfig(
  name: string,
  values: ServerConfigFields,
  raw: unknown
): McpServerConfig {
  const server: McpServerConfig = { name, raw };
  if (values.command !== undefined) server.command = values.command;
  if (values.args !== undefined) server.args = values.args;
  if (values.env !== undefined) server.env = values.env;
  if (values.headers !== undefined) server.headers = values.headers;
  if (values.envFile !== undefined) server.envFile = values.envFile;
  if (values.url !== undefined) server.url = values.url;
  if (values.transport !== undefined) server.transport = values.transport;
  if (values.type !== undefined) server.type = values.type;
  return server;
}

function isServerMap(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function serverMapFor(obj: Record<string, unknown>): Record<string, unknown> | undefined {
  return isServerMap(obj['mcpServers'])
    ? obj['mcpServers']
    : isServerMap(obj['servers'])
      ? obj['servers']
      : undefined;
}

function collectServerMaps(obj: Record<string, unknown>): Record<string, unknown>[] {
  const maps: Record<string, unknown>[] = [];
  const topLevelMap = serverMapFor(obj);
  if (topLevelMap) maps.push(topLevelMap);

  if (isServerMap(obj['projects'])) {
    for (const project of Object.values(obj['projects'])) {
      if (!isServerMap(project)) continue;
      const projectMap = serverMapFor(project);
      if (projectMap) maps.push(projectMap);
    }
  }

  return maps;
}

export function normalizeServers(raw: unknown, opts: NormalizeOptions = {}): McpServerConfig[] {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new LoadError('Top-level value must be an object');
  }

  const obj = raw as Record<string, unknown>;
  const maps = collectServerMaps(obj);
  if (maps.length === 0) {
    opts.onWarn?.('No `mcpServers` or `servers` key found at top level.');
    return [];
  }

  const out: McpServerConfig[] = [];
  for (const map of maps) {
    for (const [name, entry] of Object.entries(map)) {
      const parsed = EntrySchema.safeParse(entry);
      if (parsed.success) {
        out.push(
          buildServerConfig(
            name,
            {
              command: parsed.data.command,
              args: parsed.data.args,
              env: parsed.data.env,
              headers: parsed.data.headers,
              envFile: parsed.data.envFile,
              url: parsed.data.url,
              transport: parsed.data.transport,
              type: parsed.data.type,
            },
            entry
          )
        );
      } else {
        const e = (entry ?? {}) as Record<string, unknown>;
        out.push(
          buildServerConfig(
            name,
            {
              command: typeof e['command'] === 'string' ? e['command'] : undefined,
              args:
                Array.isArray(e['args']) && e['args'].every((x) => typeof x === 'string')
                  ? e['args']
                  : undefined,
              env:
                e['env'] && typeof e['env'] === 'object' && !Array.isArray(e['env'])
                  ? (e['env'] as Record<string, unknown>)
                  : undefined,
              headers:
                e['headers'] && typeof e['headers'] === 'object' && !Array.isArray(e['headers'])
                  ? (e['headers'] as Record<string, unknown>)
                  : undefined,
              envFile: typeof e['envFile'] === 'string' ? e['envFile'] : undefined,
              url: typeof e['url'] === 'string' ? e['url'] : undefined,
              transport: typeof e['transport'] === 'string' ? e['transport'] : undefined,
              type: typeof e['type'] === 'string' ? e['type'] : undefined,
            },
            entry
          )
        );
      }
    }
  }
  return out;
}
