import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { copyFile, mkdir, rm } from 'node:fs/promises';
import os from 'node:os';
import { promisify } from 'node:util';
import path from 'node:path';

const exec = promisify(execFile);

const fixture = (name: string) => path.resolve('test/fixtures', name);
const cli = path.resolve('src/cli.ts');
const tsxCli = path.resolve('node_modules', 'tsx', 'dist', 'cli.mjs');

interface CliResult {
  stdout: string;
  stderr: string;
  code: number;
}

async function runCli(args: string[], expectFail = false): Promise<CliResult> {
  try {
    const { stdout, stderr } = await exec(process.execPath, [tsxCli, cli, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { stdout, stderr, code: 0 };
  } catch (err: unknown) {
    if (!expectFail) throw err;
    const failed = err as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: failed.stdout ?? '',
      stderr: failed.stderr ?? '',
      code: failed.code ?? 1,
    };
  }
}

async function withSpacedFixture(): Promise<{ file: string; cleanup: () => Promise<void> }> {
  const dir = path.resolve('test/fixtures', 'cli path with spaces');
  const file = path.join(dir, 'safe file.json');
  await mkdir(dir, { recursive: true });
  await copyFile(fixture('safe.json'), file);
  return {
    file,
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

describe('cli scan', () => {
  it('safe.json exits 0 with text containing Risk:', async () => {
    const result = await runCli(['scan', fixture('safe.json')]);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain('Risk:');
  });

  it('scans fixture paths containing spaces', async () => {
    const spaced = await withSpacedFixture();
    try {
      const result = await runCli(['scan', spaced.file]);

      expect(result.code).toBe(0);
      expect(result.stdout).toContain('Risk:');
    } finally {
      await spaced.cleanup();
    }
  });

  it('risky.json --fail-on high exits 1', async () => {
    const result = await runCli(['scan', fixture('risky.json'), '--fail-on', 'high'], true);

    expect(result.code).toBe(1);
  });

  it('safe.json --fail-on high exits 0', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--fail-on', 'high']);

    expect(result.code).toBe(0);
  });

  it('--json outputs parseable JSON with schemaVersion and findings array', async () => {
    const result = await runCli(['scan', fixture('risky.json'), '--json']);
    const parsed = JSON.parse(result.stdout);

    expect(parsed.schemaVersion).toBe('1');
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it('secret literal never appears in text output', async () => {
    const result = await runCli(['scan', fixture('risky.json')]);

    expect(result.stdout).not.toContain('ghp_should_not_be_printed');
    expect(result.stderr).not.toContain('ghp_should_not_be_printed');
  });

  it('secret literal never appears in JSON output', async () => {
    const result = await runCli(['scan', fixture('risky.json'), '--json']);

    expect(result.stdout).not.toContain('ghp_should_not_be_printed');
    expect(result.stderr).not.toContain('ghp_should_not_be_printed');
  });

  it('malformed.json exits 2 and stderr mentions parse or failed', async () => {
    const result = await runCli(['scan', fixture('malformed.json')], true);

    expect(result.code).toBe(2);
    expect(result.stderr).toMatch(/parse|failed/i);
    expect(result.stderr).not.toContain(os.homedir());
  });

  it('non-existent file exits 2', async () => {
    const result = await runCli(['scan', fixture('does-not-exist.json')], true);

    expect(result.code).toBe(2);
    expect(result.stderr).not.toContain(os.homedir());
  });

  it('invalid --fail-on exits 2', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--fail-on', 'bogus'], true);

    expect(result.code).toBe(2);
  });

  it('missing scan path exits 2', async () => {
    const result = await runCli(['scan'], true);

    expect(result.code).toBe(2);
  });

  it('unknown scan option exits 2', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--bogus'], true);

    expect(result.code).toBe(2);
  });

  it('unknown command exits 2', async () => {
    const result = await runCli(['bogus'], true);

    expect(result.code).toBe(2);
  });

  it('docker-socket reports MCPG006', async () => {
    const result = await runCli(['scan', fixture('docker-socket.json'), '--json']);
    const parsed = JSON.parse(result.stdout);

    expect(parsed.findings.map((finding: { ruleId: string }) => finding.ruleId)).toContain('MCPG006');
  });

  it('pipeline-curl reports MCPG007', async () => {
    const result = await runCli(['scan', fixture('pipeline-curl.json'), '--json']);
    const parsed = JSON.parse(result.stdout);

    expect(parsed.findings.map((finding: { ruleId: string }) => finding.ruleId)).toContain('MCPG007');
  });

  it('public-https reports MCPG008', async () => {
    const result = await runCli(['scan', fixture('public-https.json'), '--json']);
    const parsed = JSON.parse(result.stdout);

    expect(parsed.findings.map((finding: { ruleId: string }) => finding.ruleId)).toContain('MCPG008');
  });

  it('placeholder-secret reports MCPG001 medium', async () => {
    const result = await runCli(['scan', fixture('placeholder-secret.json'), '--json']);
    const parsed = JSON.parse(result.stdout);
    const finding = parsed.findings.find(
      (candidate: { ruleId: string }) => candidate.ruleId === 'MCPG001'
    );

    expect(finding.severity).toBe('medium');
  });

  it('missing-cmd reports MCPG009', async () => {
    const result = await runCli(['scan', fixture('missing-cmd.json'), '--json']);
    const parsed = JSON.parse(result.stdout);

    expect(parsed.findings.map((finding: { ruleId: string }) => finding.ruleId)).toContain('MCPG009');
  });

  it('empty.json scans without crash and warns on stderr', async () => {
    const result = await runCli(['scan', fixture('empty.json')]);

    expect(result.code).toBe(0);
    expect(result.stderr).toMatch(/mcpServers/);
  });
});
