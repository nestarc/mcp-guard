import os from 'node:os';
import { redactFinding, redactHomeInText } from '../utils/redact.js';
import type { ScanResult } from '../types.js';

export interface JsonReporterOptions {
  home?: string;
}

export function renderJson(result: ScanResult, opts: JsonReporterOptions = {}): string {
  const home = opts.home ?? os.homedir();
  const redacted: ScanResult = {
    ...result,
    target: redactHomeInText(result.target, home),
    findings: result.findings.map((finding) => redactFinding(finding, home)),
  };

  return JSON.stringify(redacted, null, 2);
}
