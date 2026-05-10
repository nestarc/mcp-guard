import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { loadConfig } from '../src/config/loadConfig.js';
import { LoadError } from '../src/types.js';

const fixture = (name: string) => path.resolve('test/fixtures', name);

describe('loadConfig', () => {
  it('parses an empty JSON object', async () => {
    const data = await loadConfig(fixture('empty.json'));
    expect(data).toEqual({});
  });

  it('parses JSONC with comments and trailing commas', async () => {
    const data = await loadConfig(fixture('jsonc.jsonc'));
    expect(data).toMatchObject({ mcpServers: { fs: { command: 'node' } } });
  });

  it('throws LoadError when file does not exist', async () => {
    await expect(loadConfig(fixture('does-not-exist.json'))).rejects.toBeInstanceOf(LoadError);
  });

  it('throws LoadError on malformed JSON', async () => {
    const filePath = fixture('malformed.json');
    await expect(loadConfig(filePath)).rejects.toBeInstanceOf(LoadError);
    await expect(loadConfig(filePath)).rejects.toThrow(
      /^Failed to parse .*malformed\.json: .+ at offset \d+$/
    );
  });
});
