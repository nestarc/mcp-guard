import os from 'node:os';
import pc from 'picocolors';
import { redactFinding, redactHomeInText } from '../utils/redact.js';
import type { Finding, ScanResult, Severity } from '../types.js';

export interface TextReporterOptions {
  color?: boolean;
  quiet?: boolean;
  home?: string;
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

export function renderText(result: ScanResult, opts: TextReporterOptions = {}): string {
  const color = opts.color ?? false;
  const quiet = opts.quiet ?? false;
  const home = opts.home ?? os.homedir();

  const target = redactHomeInText(result.target, home);
  const lines: string[] = [];
  lines.push(`mcp-guard scan ${target}`);
  lines.push('');
  lines.push(`Risk: ${colorize(result.summary.risk.toUpperCase(), result.summary.risk, color)}`);
  lines.push(`Servers scanned: ${result.summary.serversScanned}`);
  lines.push(`Findings: ${result.summary.findings}`);

  if (quiet || result.findings.length === 0) {
    lines.push('');
    return lines.join('\n');
  }

  const findingsByServer = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const serverFindings = findingsByServer.get(finding.server) ?? [];
    serverFindings.push(redactFinding(finding, home));
    findingsByServer.set(finding.server, serverFindings);
  }

  for (const [serverName, findings] of findingsByServer) {
    lines.push('');
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

  lines.push('');
  return lines.join('\n');
}
