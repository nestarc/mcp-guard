import { loadConfig } from '../config/loadConfig.js';
import { normalizeServers } from '../config/normalizeServers.js';
import { defaultRules } from '../scanner/rules/index.js';
import { scanServer } from '../scanner/scan.js';
import { maxSeverity } from '../scanner/severity.js';
import { LoadError } from '../types.js';
import type {
  AggregateFinding,
  AggregateScanResult,
  Finding,
  Rule,
  ScanTargetMetadata,
  ScanTargetResult,
} from '../types.js';
import { redactHomeInText } from '../utils/redact.js';
import type { DiscoveredTarget } from './types.js';

export interface ScanDiscoveredTargetsOptions {
  rules?: Rule[];
  onWarn?: (message: string) => void;
}

function metadataFor(target: DiscoveredTarget): ScanTargetMetadata {
  return {
    path: target.path,
    client: target.client,
    scope: target.scope,
    labels: target.labels,
  };
}

function attachTarget(findings: Finding[], target: DiscoveredTarget): AggregateFinding[] {
  const targetMetadata = metadataFor(target);
  return findings.map((finding) => ({
    ...finding,
    target: targetMetadata,
  }));
}

export async function scanDiscoveredTargets(
  targets: DiscoveredTarget[],
  opts: ScanDiscoveredTargetsOptions = {}
): Promise<AggregateScanResult> {
  const rules = opts.rules ?? defaultRules;
  const targetResults: ScanTargetResult[] = [];
  const findings: AggregateFinding[] = [];
  let serversScanned = 0;
  let targetsScanned = 0;

  for (const target of targets) {
    const metadata = metadataFor(target);
    try {
      const raw = await loadConfig(target.path);
      const localWarnings: string[] = [];
      const servers = normalizeServers(raw, {
        onWarn: (message) => localWarnings.push(redactHomeInText(message)),
      });
      const targetFindings = servers.flatMap((server) => scanServer(server, rules));
      const aggregateFindings = attachTarget(targetFindings, target);
      findings.push(...aggregateFindings);
      serversScanned += servers.length;
      targetsScanned += 1;

      const warning =
        localWarnings.length === 0 ? undefined : redactHomeInText(localWarnings.join(' '));
      if (warning !== undefined) {
        opts.onWarn?.(`${redactHomeInText(target.path)}: ${warning}`);
      }

      targetResults.push({
        ...metadata,
        scanned: true,
        serversScanned: servers.length,
        findings: targetFindings.length,
        ...(warning === undefined ? {} : { warning }),
      });
    } catch (err) {
      if (!(err instanceof LoadError)) throw err;
      const warning = redactHomeInText(`${target.path}: ${err.message}`);
      opts.onWarn?.(warning);
      targetResults.push({
        ...metadata,
        scanned: false,
        serversScanned: 0,
        findings: 0,
        warning,
      });
    }
  }

  return {
    schemaVersion: '2',
    targets: targetResults,
    summary: {
      risk: maxSeverity(findings.map((finding) => finding.severity)),
      targetsDiscovered: targets.length,
      targetsScanned,
      serversScanned,
      findings: findings.length,
    },
    findings,
  };
}
