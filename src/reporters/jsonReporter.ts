import os from 'node:os';
import { redactFinding, redactHome } from '../utils/redact.js';
import type { Finding, ScanResult } from '../types.js';

export interface JsonReporterOptions {
  home?: string;
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
  const redacted = redactFinding(finding, home);
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

export function renderJson(result: ScanResult, opts: JsonReporterOptions = {}): string {
  const home = opts.home ?? os.homedir();
  const redacted: ScanResult = {
    ...result,
    target: redactHome(result.target, home),
    findings: result.findings.map((finding) => redactReporterFinding(finding, home)),
  };

  return JSON.stringify(redacted, null, 2);
}
