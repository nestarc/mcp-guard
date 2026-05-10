import os from 'node:os';
import { redactFinding, redactHomeInText } from '../utils/redact.js';
import type { AggregateFinding, AggregateScanResult } from '../types.js';

export interface AggregateJsonReporterOptions {
  home?: string;
}

function redactAggregateFinding(finding: AggregateFinding, home: string): AggregateFinding {
  const redacted = redactFinding(finding, home);
  return {
    ...redacted,
    target: {
      ...redacted.target,
      path: redactHomeInText(redacted.target.path, home),
    },
  };
}

export function renderAggregateJson(
  result: AggregateScanResult,
  opts: AggregateJsonReporterOptions = {}
): string {
  const home = opts.home ?? os.homedir();
  const redacted: AggregateScanResult = {
    ...result,
    targets: result.targets.map((target) => ({
      ...target,
      path: redactHomeInText(target.path, home),
    })),
    findings: result.findings.map((finding) => redactAggregateFinding(finding, home)),
  };

  return JSON.stringify(redacted, null, 2);
}
