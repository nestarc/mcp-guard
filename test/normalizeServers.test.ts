import { describe, it, expect } from 'vitest';
import { normalizeServers } from '../src/config/normalizeServers.js';
import { LoadError } from '../src/types.js';

describe('normalizeServers', () => {
  it('extracts mcpServers map', () => {
    const result = normalizeServers({
      mcpServers: {
        fs: { command: 'node', args: ['./server.js'] },
      },
    });
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ name: 'fs', command: 'node', args: ['./server.js'] });
  });

  it('falls back to servers when mcpServers absent', () => {
    const result = normalizeServers({
      servers: {
        api: { url: 'https://example.com' },
      },
    });
    expect(result[0]).toMatchObject({ name: 'api', url: 'https://example.com' });
  });

  it('returns empty array and warns when neither key present', () => {
    const warn: string[] = [];
    const result = normalizeServers({}, { onWarn: (m) => warn.push(m) });
    expect(result).toEqual([]);
    expect(warn).toHaveLength(1);
    expect(warn[0]).toContain('mcpServers');
  });

  it('throws LoadError when raw is not an object', () => {
    expect(() => normalizeServers(null)).toThrow(LoadError);
    expect(() => normalizeServers([])).toThrow(LoadError);
    expect(() => normalizeServers('x')).toThrow(LoadError);
  });

  it('preserves raw entry', () => {
    const entry = { command: 'node', args: ['./s.js'], extra: 'preserved' };
    const result = normalizeServers({ mcpServers: { fs: entry } });
    expect(result[0]!.raw).toEqual(entry);
  });

  it('best-effort maps a malformed entry (missing command) without throwing', () => {
    const result = normalizeServers({ mcpServers: { broken: { foo: 'bar' } } });
    expect(result[0]!.name).toBe('broken');
    expect(result[0]!.command).toBeUndefined();
    expect(result[0]!.url).toBeUndefined();
  });

  it('coerces non-string command to undefined (best-effort)', () => {
    const result = normalizeServers({ mcpServers: { x: { command: 123 } } });
    expect(result[0]!.command).toBeUndefined();
  });
});
