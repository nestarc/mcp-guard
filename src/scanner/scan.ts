import path from 'node:path';
import { loadConfig } from '../config/loadConfig.js';
import { normalizeServers } from '../config/normalizeServers.js';
import { defaultRules } from './rules/index.js';
import { maxSeverity } from './severity.js';
import type { Finding, McpServerConfig, Rule, ScanResult } from '../types.js';

export function scanServer(server: McpServerConfig, rules: Rule[] = defaultRules): Finding[] {
  const out: Finding[] = [];
  for (const r of rules) {
    out.push(...r.run(server));
  }
  return out;
}

export interface ScanOptions {
  rules?: Rule[];
  onWarn?: (message: string) => void;
}

export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const rules = options.rules ?? defaultRules;
  const raw = await loadConfig(target);
  const servers = normalizeServers(
    raw,
    options.onWarn === undefined ? {} : { onWarn: options.onWarn }
  );
  const findings: Finding[] = [];
  for (const s of servers) {
    findings.push(...scanServer(s, rules));
  }
  return {
    schemaVersion: '1',
    target: path.resolve(target),
    summary: {
      risk: maxSeverity(findings.map((f) => f.severity)),
      serversScanned: servers.length,
      findings: findings.length,
    },
    findings,
  };
}
