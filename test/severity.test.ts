import { describe, it, expect } from 'vitest';
import { compareSeverity, maxSeverity, meetsThreshold } from '../src/scanner/severity.js';

describe('severity', () => {
  it('compareSeverity returns negative when a < b', () => {
    expect(compareSeverity('low', 'high')).toBeLessThan(0);
  });

  it('compareSeverity returns positive when a > b', () => {
    expect(compareSeverity('critical', 'medium')).toBeGreaterThan(0);
  });

  it('compareSeverity returns 0 when equal', () => {
    expect(compareSeverity('high', 'high')).toBe(0);
  });

  it('maxSeverity picks the highest severity', () => {
    expect(maxSeverity(['info', 'medium', 'high', 'low'])).toBe('high');
  });

  it('maxSeverity returns info for empty list', () => {
    expect(maxSeverity([])).toBe('info');
  });

  it('meetsThreshold: high meets high', () => {
    expect(meetsThreshold('high', 'high')).toBe(true);
  });

  it('meetsThreshold: medium does not meet high', () => {
    expect(meetsThreshold('medium', 'high')).toBe(false);
  });

  it('meetsThreshold: critical meets high', () => {
    expect(meetsThreshold('critical', 'high')).toBe(true);
  });
});
