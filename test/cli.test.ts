import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
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

interface RunCliOptions {
  expectFail?: boolean;
  cwd?: string;
  env?: Record<string, string | undefined>;
}

async function runCli(args: string[], options: RunCliOptions = {}): Promise<CliResult> {
  try {
    const { stdout, stderr } = await exec(process.execPath, [tsxCli, cli, ...args], {
      cwd: options.cwd,
      env: { ...process.env, ...options.env, NO_COLOR: '1' },
    });
    return { stdout, stderr, code: 0 };
  } catch (err: unknown) {
    if (!options.expectFail) throw err;
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

async function withScanAllFixture(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'mcp-guard-cli-'));
  const cursorDir = path.join(dir, '.cursor');
  await mkdir(cursorDir, { recursive: true });
  await copyFile(fixture('public-https.json'), path.join(cursorDir, 'mcp.json'));
  return {
    dir,
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
    const result = await runCli(['scan', fixture('risky.json'), '--fail-on', 'high'], {
      expectFail: true,
    });

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
    const result = await runCli(['scan', fixture('malformed.json')], { expectFail: true });

    expect(result.code).toBe(2);
    expect(result.stderr).toMatch(/parse|failed/i);
    expect(result.stderr).not.toContain(os.homedir());
  });

  it('non-existent file exits 2', async () => {
    const result = await runCli(['scan', fixture('does-not-exist.json')], {
      expectFail: true,
    });

    expect(result.code).toBe(2);
    expect(result.stderr).not.toContain(os.homedir());
  });

  it('invalid --fail-on exits 2', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--fail-on', 'bogus'], {
      expectFail: true,
    });

    expect(result.code).toBe(2);
  });

  it('scan <path> --client cursor exits 2', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--client', 'cursor'], {
      expectFail: true,
    });

    expect(result.code).toBe(2);
    expect(result.stderr).toContain('require --all');
  });

  it('scan <path> --scope project exits 2', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--scope', 'project'], {
      expectFail: true,
    });

    expect(result.code).toBe(2);
    expect(result.stderr).toContain('require --all');
  });

  it('scan <path> --list-targets exits 2', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--list-targets'], {
      expectFail: true,
    });

    expect(result.code).toBe(2);
    expect(result.stderr).toContain('require --all');
  });

  it('missing scan path exits 2', async () => {
    const result = await runCli(['scan'], { expectFail: true });

    expect(result.code).toBe(2);
  });

  it('unknown scan option exits 2', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--bogus'], {
      expectFail: true,
    });

    expect(result.code).toBe(2);
  });

  it('unknown command exits 2', async () => {
    const result = await runCli(['bogus'], { expectFail: true });

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

  it('scan --all outputs aggregate text for discovered targets', async () => {
    const fixtureDir = await withScanAllFixture();
    try {
      const result = await runCli(['scan', '--all', '--scope', 'project'], { cwd: fixtureDir.dir });

      expect(result.code).toBe(0);
      expect(result.stdout).toContain('mcp-guard scan --all');
      expect(result.stdout).toContain('Targets scanned: 1/1');
      expect(result.stdout).toContain('MCPG008');
    } finally {
      await fixtureDir.cleanup();
    }
  });

  it('scan --all --json outputs aggregate schema version 2', async () => {
    const fixtureDir = await withScanAllFixture();
    try {
      const result = await runCli(['scan', '--all', '--scope', 'project', '--json'], {
        cwd: fixtureDir.dir,
      });
      const parsed = JSON.parse(result.stdout);

      expect(parsed.schemaVersion).toBe('2');
      expect(parsed.summary.targetsScanned).toBe(1);
      expect(parsed.findings[0].target.client).toBe('cursor');
    } finally {
      await fixtureDir.cleanup();
    }
  });

  it('scan --all --client bogus exits 2', async () => {
    const result = await runCli(['scan', '--all', '--client', 'bogus'], { expectFail: true });

    expect(result.code).toBe(2);
  });

  it('scan --all --scope bogus exits 2', async () => {
    const result = await runCli(['scan', '--all', '--scope', 'bogus'], { expectFail: true });

    expect(result.code).toBe(2);
  });

  it('scan --all --scope project with no targets exits 0 and renders empty aggregate', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'mcp-guard-cli-empty-'));
    try {
      const result = await runCli(['scan', '--all', '--scope', 'project'], { cwd: dir });

      expect(result.code).toBe(0);
      expect(result.stderr).toContain('warning: no MCP configuration files found');
      expect(result.stdout).toContain('mcp-guard scan --all');
      expect(result.stdout).toContain('Targets scanned: 0/0');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('scan --all --scope project with malformed target exits 2 after rendering aggregate', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'mcp-guard-cli-malformed-'));
    try {
      const cursorDir = path.join(dir, '.cursor');
      await mkdir(cursorDir, { recursive: true });
      await copyFile(fixture('malformed.json'), path.join(cursorDir, 'mcp.json'));

      const result = await runCli(['scan', '--all', '--scope', 'project'], {
        cwd: dir,
        expectFail: true,
      });

      expect(result.code).toBe(2);
      expect(result.stdout).toContain('Targets scanned: 0/1');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('scan --all --fail-on high exits 1 for high findings', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'mcp-guard-cli-high-'));
    try {
      const cursorDir = path.join(dir, '.cursor');
      await mkdir(cursorDir, { recursive: true });
      await copyFile(fixture('risky.json'), path.join(cursorDir, 'mcp.json'));

      const result = await runCli(['scan', '--all', '--scope', 'project', '--fail-on', 'high'], {
        cwd: dir,
        expectFail: true,
      });

      expect(result.code).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('scan --all --list-targets lists discovered targets without scanning', async () => {
    const fixtureDir = await withScanAllFixture();
    try {
      const result = await runCli(['scan', '--all', '--scope', 'project', '--list-targets'], {
        cwd: fixtureDir.dir,
      });

      expect(result.code).toBe(0);
      expect(result.stdout).toContain('cursor project');
      expect(result.stdout).toContain('.cursor');
      expect(result.stdout).not.toContain('Risk:');
    } finally {
      await fixtureDir.cleanup();
    }
  });

  it('scan <path> --all exits 2 because modes are mutually exclusive', async () => {
    const result = await runCli(['scan', fixture('safe.json'), '--all'], { expectFail: true });

    expect(result.code).toBe(2);
  });
});
