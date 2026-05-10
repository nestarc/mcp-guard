import { Command, CommanderError } from 'commander';
import { discoverConfigs } from './discovery/discoverConfigs.js';
import { scanDiscoveredTargets } from './discovery/scanDiscoveredTargets.js';
import type { DiscoveryScopeFilter, McpClient } from './discovery/types.js';
import { renderAggregateJson } from './reporters/aggregateJsonReporter.js';
import { renderAggregateText } from './reporters/aggregateTextReporter.js';
import { renderJson } from './reporters/jsonReporter.js';
import { renderText } from './reporters/textReporter.js';
import { scan } from './scanner/scan.js';
import { meetsThreshold } from './scanner/severity.js';
import { LoadError, type ScanResult, type Severity } from './types.js';
import { redactHomeInText } from './utils/redact.js';

const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const CLIENTS: McpClient[] = ['cursor', 'vscode', 'claude-code', 'claude-desktop'];
const SCOPES: DiscoveryScopeFilter[] = ['project', 'user', 'all'];

interface ScanOptions {
  json?: boolean;
  failOn?: string;
  color?: boolean;
  quiet?: boolean;
  all?: boolean;
  client?: string;
  scope?: string;
  listTargets?: boolean;
}

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as string[]).includes(value);
}

function isMcpClient(value: string): value is McpClient {
  return (CLIENTS as string[]).includes(value);
}

function isDiscoveryScope(value: string): value is DiscoveryScopeFilter {
  return (SCOPES as string[]).includes(value);
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

function validateSharedOptions(opts: ScanOptions): Severity | 2 | undefined {
  if (opts.failOn !== undefined && !isSeverity(opts.failOn)) {
    process.stderr.write(
      `Invalid --fail-on value: ${opts.failOn}. Allowed: ${SEVERITIES.join(', ')}\n`
    );
    return 2;
  }

  return opts.failOn;
}

function validateDiscoveryOptions(
  opts: ScanOptions
): { client?: McpClient; scope: DiscoveryScopeFilter } | 2 {
  const scope = opts.scope ?? 'all';
  if (!isDiscoveryScope(scope)) {
    process.stderr.write(`Invalid --scope value: ${scope}. Allowed: ${SCOPES.join(', ')}\n`);
    return 2;
  }

  if (opts.client !== undefined && !isMcpClient(opts.client)) {
    process.stderr.write(`Invalid --client value: ${opts.client}. Allowed: ${CLIENTS.join(', ')}\n`);
    return 2;
  }

  return opts.client === undefined ? { scope } : { client: opts.client, scope };
}

function hasDiscoveryOnlyOptions(opts: ScanOptions, scopeWasExplicit: boolean): boolean {
  return opts.client !== undefined || opts.listTargets === true || scopeWasExplicit;
}

async function runScan(target: string, opts: ScanOptions): Promise<number> {
  const threshold = validateSharedOptions(opts);
  if (threshold === 2) return 2;

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

  if (threshold !== undefined) {
    if (result.findings.some((finding) => meetsThreshold(finding.severity, threshold))) {
      return 1;
    }
  }

  return 0;
}

async function runScanAll(opts: ScanOptions): Promise<number> {
  const threshold = validateSharedOptions(opts);
  if (threshold === 2) return 2;

  const discovery = validateDiscoveryOptions(opts);
  if (discovery === 2) return 2;

  const targets = await discoverConfigs(discovery);

  if (opts.listTargets) {
    for (const target of targets) {
      process.stdout.write(`${target.label}\t${redactHomeInText(target.path)}\n`);
    }
    if (targets.length === 0) {
      process.stderr.write('warning: no MCP configuration files found\n');
    }
    return 0;
  }

  if (targets.length === 0) {
    process.stderr.write('warning: no MCP configuration files found\n');
  }

  const result = await scanDiscoveredTargets(targets, {
    onWarn: (message) => process.stderr.write(`warning: ${message}\n`),
  });

  if (opts.json) {
    process.stdout.write(`${renderAggregateJson(result)}\n`);
  } else {
    process.stdout.write(
      `${renderAggregateText(result, {
        color: colorEnabled(opts),
        quiet: Boolean(opts.quiet),
      })}\n`
    );
  }

  if (targets.length > 0 && result.summary.targetsScanned === 0) {
    return 2;
  }

  if (threshold !== undefined) {
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
    .description('Scan MCP configuration files for risky patterns')
    .argument('[path]', 'path to MCP configuration file')
    .option('--all', 'discover and scan known MCP configuration files')
    .option('--client <name>', `limit discovery to one client (${CLIENTS.join(', ')})`)
    .option('--scope <scope>', `limit discovery scope (${SCOPES.join(', ')})`, 'all')
    .option('--list-targets', 'list discovered targets without scanning')
    .option('--json', 'output JSON')
    .option(
      '--fail-on <level>',
      `exit 1 when findings reach this severity (one of: ${SEVERITIES.join(', ')})`
    )
    .option('--no-color', 'disable colored output')
    .option('--quiet', 'print only the summary')
    .action(async function (this: Command, target: string | undefined, options: ScanOptions) {
      if (options.all && target !== undefined) {
        process.stderr.write('error: scan <path> and --all are mutually exclusive\n');
        process.exitCode = 2;
        return;
      }

      const scopeSource = this.getOptionValueSource('scope');
      const scopeWasExplicit = scopeSource === 'cli' || scopeSource === 'env';
      if (!options.all && hasDiscoveryOnlyOptions(options, scopeWasExplicit)) {
        process.stderr.write('error: --client, --scope, and --list-targets require --all\n');
        process.exitCode = 2;
        return;
      }

      if (!options.all && target === undefined) {
        process.stderr.write('error: missing required argument: path\n');
        process.exitCode = 2;
        return;
      }

      const code = options.all ? await runScanAll(options) : await runScan(target!, options);
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
