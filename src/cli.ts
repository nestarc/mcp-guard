import { Command, CommanderError } from 'commander';
import { renderJson } from './reporters/jsonReporter.js';
import { renderText } from './reporters/textReporter.js';
import { scan } from './scanner/scan.js';
import { meetsThreshold } from './scanner/severity.js';
import { LoadError, type ScanResult, type Severity } from './types.js';
import { redactHomeInText } from './utils/redact.js';

const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

interface ScanOptions {
  json?: boolean;
  failOn?: string;
  color?: boolean;
  quiet?: boolean;
}

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as string[]).includes(value);
}

function colorEnabled(opts: ScanOptions): boolean {
  if (opts.color === false) return false;
  if (process.env['NO_COLOR']) return false;
  return Boolean(process.stdout.isTTY);
}

async function loadScanResult(target: string): Promise<ScanResult> {
  return scan(target, {
    onWarn: (message) => process.stderr.write(`warning: ${message}\n`),
  });
}

async function runScan(target: string, opts: ScanOptions): Promise<number> {
  if (opts.failOn !== undefined && !isSeverity(opts.failOn)) {
    process.stderr.write(
      `Invalid --fail-on value: ${opts.failOn}. Allowed: ${SEVERITIES.join(', ')}\n`
    );
    return 2;
  }

  let result: ScanResult;
  try {
    result = await loadScanResult(target);
  } catch (err) {
    if (err instanceof LoadError) {
      process.stderr.write(`error: ${redactHomeInText(err.message)}\n`);
      return 2;
    }
    throw err;
  }

  if (opts.json) {
    process.stdout.write(`${renderJson(result)}\n`);
  } else {
    process.stdout.write(
      `${renderText(result, {
        color: colorEnabled(opts),
        quiet: Boolean(opts.quiet),
      })}\n`
    );
  }

  if (opts.failOn !== undefined) {
    const threshold = opts.failOn;
    if (result.findings.some((finding) => meetsThreshold(finding.severity, threshold))) {
      return 1;
    }
  }

  return 0;
}

async function main(): Promise<void> {
  const program = new Command();
  program
    .name('mcp-guard')
    .description('Security scanner for MCP servers and configurations.')
    .version('0.1.0');
  program.exitOverride();

  program
    .command('scan')
    .description('Scan an MCP configuration file for risky patterns')
    .argument('<path>', 'path to MCP configuration file')
    .option('--json', 'output JSON')
    .option(
      '--fail-on <level>',
      `exit 1 when findings reach this severity (one of: ${SEVERITIES.join(', ')})`
    )
    .option('--no-color', 'disable colored output')
    .option('--quiet', 'print only the summary')
    .action(async (target: string, options: ScanOptions) => {
      const code = await runScan(target, options);
      process.exitCode = code;
    });

  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    if (err instanceof CommanderError) {
      process.exitCode = err.exitCode === 0 ? 0 : 2;
      return;
    }
    throw err;
  }
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`unexpected error: ${message}\n`);
  process.exitCode = 2;
});
