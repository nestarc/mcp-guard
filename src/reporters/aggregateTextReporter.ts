import os from 'node:os';
import pc from 'picocolors';
import { redactFinding, redactHomeInText } from '../utils/redact.js';
import type { AggregateFinding, AggregateScanResult, ScanTargetMetadata, Severity } from '../types.js';

export interface AggregateTextReporterOptions {
  color?: boolean;
  quiet?: boolean;
  home?: string;
}

interface TargetGroup {
  target: ScanTargetMetadata;
  servers: Map<string, AggregateFinding[]>;
}

function colorize(input: string, severity: Severity, color: boolean): string {
  if (!color) return input;

  const colors = pc.createColors(true);
  switch (severity) {
    case 'critical':
      return colors.bold(colors.red(input));
    case 'high':
      return colors.red(input);
    case 'medium':
      return colors.yellow(input);
    case 'low':
      return colors.blue(input);
    case 'info':
    default:
      return colors.dim(input);
  }
}

function targetKey(target: ScanTargetMetadata): string {
  return `${target.client}\0${target.scope}\0${target.path}`;
}

export function renderAggregateText(
  result: AggregateScanResult,
  opts: AggregateTextReporterOptions = {}
): string {
  const color = opts.color ?? false;
  const quiet = opts.quiet ?? false;
  const home = opts.home ?? os.homedir();

  const lines: string[] = [];
  lines.push('mcp-guard scan --all');
  lines.push('');
  lines.push(`Risk: ${colorize(result.summary.risk.toUpperCase(), result.summary.risk, color)}`);
  lines.push(`Targets scanned: ${result.summary.targetsScanned}/${result.summary.targetsDiscovered}`);
  lines.push(`Servers scanned: ${result.summary.serversScanned}`);
  lines.push(`Findings: ${result.summary.findings}`);

  if (quiet || result.findings.length === 0) {
    lines.push('');
    return lines.join('\n');
  }

  const targets = new Map<string, TargetGroup>();
  for (const finding of result.findings) {
    const key = targetKey(finding.target);
    let target = targets.get(key);
    if (!target) {
      target = {
        target: finding.target,
        servers: new Map<string, AggregateFinding[]>(),
      };
      targets.set(key, target);
    }

    const redacted = redactFinding(finding, home);
    const serverFindings = target.servers.get(finding.server) ?? [];
    serverFindings.push(redacted);
    target.servers.set(finding.server, serverFindings);
  }

  for (const { target, servers } of targets.values()) {
    const path = redactHomeInText(target.path, home);
    lines.push('');
    lines.push(`Target: ${path} (${target.client}, ${target.scope})`);

    for (const [serverName, findings] of servers) {
      lines.push(`Server: ${serverName}`);
      for (const finding of findings) {
        const severityTag = `[${finding.severity.toUpperCase()}]`;
        lines.push(`  ${colorize(severityTag, finding.severity, color)} ${finding.ruleId} ${finding.title}`);
        lines.push(`    ${finding.message}`);
        if (finding.recommendation) {
          lines.push(`    Recommendation: ${finding.recommendation}`);
        }
      }
    }
  }

  lines.push('');
  return lines.join('\n');
}
