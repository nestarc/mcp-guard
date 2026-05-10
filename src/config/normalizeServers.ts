import { z } from 'zod';
import { LoadError, type McpServerConfig } from '../types.js';

const EntrySchema = z
  .object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string(), z.unknown()).optional(),
    url: z.string().optional(),
    transport: z.string().optional(),
  })
  .passthrough();

export interface NormalizeOptions {
  onWarn?: (message: string) => void;
}

interface ServerConfigFields {
  command?: string | undefined;
  args?: string[] | undefined;
  env?: Record<string, unknown> | undefined;
  url?: string | undefined;
  transport?: string | undefined;
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
  if (values.url !== undefined) server.url = values.url;
  if (values.transport !== undefined) server.transport = values.transport;
  return server;
}

function isServerMap(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function normalizeServers(raw: unknown, opts: NormalizeOptions = {}): McpServerConfig[] {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new LoadError('Top-level value must be an object');
  }

  const obj = raw as Record<string, unknown>;
  const map = isServerMap(obj['mcpServers'])
    ? obj['mcpServers']
    : isServerMap(obj['servers'])
      ? obj['servers']
      : undefined;
  if (!map) {
    opts.onWarn?.('No `mcpServers` or `servers` key found at top level.');
    return [];
  }

  const out: McpServerConfig[] = [];
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
            url: parsed.data.url,
            transport: parsed.data.transport,
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
            url: typeof e['url'] === 'string' ? e['url'] : undefined,
            transport: typeof e['transport'] === 'string' ? e['transport'] : undefined,
          },
          entry
        )
      );
    }
  }
  return out;
}
