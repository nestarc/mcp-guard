import type { Severity } from '../types.js';

const ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return ORDER[a] - ORDER[b];
}

export function maxSeverity(severities: Severity[]): Severity {
  if (severities.length === 0) return 'info';
  let max: Severity = 'info';
  for (const s of severities) {
    if (compareSeverity(s, max) > 0) max = s;
  }
  return max;
}

export function meetsThreshold(value: Severity, threshold: Severity): boolean {
  return ORDER[value] >= ORDER[threshold];
}
