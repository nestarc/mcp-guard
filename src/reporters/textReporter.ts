import os from 'node:os';
import pc from 'picocolors';
import { redactFinding as redactFindingFields, redactHome } from '../utils/redact.js';
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

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function redactHomeInText(input: string, home: string): string {
  if (!home) return input;

  let output = redactHome(input, home);
  const candidates = new Set<string>([home]);
  if (home.includes('\\')) {
    candidates.add(home.replace(/\\/g, '/'));
  }

  for (const candidate of candidates) {
    const pattern = new RegExp(
      `(^|[^A-Za-z0-9_])${escapeRegExp(candidate)}(?=$|[\\\\/\\s.,;:!?\\)\\]\\}"'])`,
      'g'
    );
    output = output.replace(pattern, '$1~');
  }

  return output;
}

function redactReporterFinding(finding: Finding, home: string): Finding {
  const redacted = redactFindingFields(finding, home);
  const result: Finding = {
    ...redacted,
    message: redactHomeInText(redacted.message, home),
  };
  const resultFields = result as unknown as Record<string, unknown>;

  if (Object.hasOwn(redacted, 'recommendation') || redacted.recommendation !== undefined) {
    resultFields.recommendation = redacted.recommendation
      ? redactHomeInText(redacted.recommendation, home)
      : redacted.recommendation;
  }
  if (Object.hasOwn(redacted, 'path') || redacted.path !== undefined) {
    resultFields.path = redacted.path ? redactHomeInText(redacted.path, home) : redacted.path;
  }

  return result;
}

export function renderText(result: ScanResult, opts: TextReporterOptions = {}): string {
  const color = opts.color ?? false;
  const quiet = opts.quiet ?? false;
  const home = opts.home ?? os.homedir();

  const target = redactHome(result.target, home);
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
    serverFindings.push(redactReporterFinding(finding, home));
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
