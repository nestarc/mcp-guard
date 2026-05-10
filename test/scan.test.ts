import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { scan } from '../src/scanner/scan.js';

const fixture = (n: string) => path.resolve('test/fixtures', n);

describe('scan', () => {
  it('safe.json: low/no high+ findings', async () => {
    const result = await scan(fixture('safe.json'));
    expect(result.summary.serversScanned).toBe(1);
    const high = result.findings.filter(
      (f) => f.severity === 'high' || f.severity === 'critical'
    );
    expect(high).toHaveLength(0);
  });

  it('risky.json: triggers MCPG001/002/003/004/005/007', async () => {
    const result = await scan(fixture('risky.json'));
    const ids = new Set(result.findings.map((f) => f.ruleId));
    for (const id of ['MCPG001', 'MCPG002', 'MCPG003', 'MCPG004', 'MCPG005', 'MCPG007']) {
      expect(ids.has(id), `expected ${id} in findings`).toBe(true);
    }
  });

  it('risky.json: summary risk is critical', async () => {
    const result = await scan(fixture('risky.json'));
    expect(result.summary.risk).toBe('critical');
  });

  it('risky.json: secret value never appears in any finding', async () => {
    const result = await scan(fixture('risky.json'));
    const blob = JSON.stringify(result);
    expect(blob).not.toContain('ghp_should_not_be_printed');
  });

  it('schemaVersion is "1"', async () => {
    const result = await scan(fixture('safe.json'));
    expect(result.schemaVersion).toBe('1');
  });
});
