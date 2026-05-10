export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface McpServerConfig {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, unknown>;
  headers?: Record<string, unknown>;
  envFile?: string;
  url?: string;
  transport?: string;
  type?: string;
  raw: unknown;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  server: string;
  title: string;
  message: string;
  recommendation?: string;
  path?: string;
  metadata?: Record<string, unknown>;
}

export interface ScanResult {
  schemaVersion: '1';
  target: string;
  summary: {
    risk: Severity;
    serversScanned: number;
    findings: number;
  };
  findings: Finding[];
}

export interface ScanTargetMetadata {
  path: string;
  client: string;
  scope: 'project' | 'user';
  labels: string[];
}

export interface ScanTargetResult extends ScanTargetMetadata {
  scanned: boolean;
  serversScanned: number;
  findings: number;
  warning?: string;
}

export interface AggregateFinding extends Finding {
  target: ScanTargetMetadata;
}

export interface AggregateScanResult {
  schemaVersion: '2';
  targets: ScanTargetResult[];
  summary: {
    risk: Severity;
    targetsDiscovered: number;
    targetsScanned: number;
    serversScanned: number;
    findings: number;
  };
  findings: AggregateFinding[];
}

export interface Rule {
  id: string;
  run(server: McpServerConfig): Finding[];
}

export class LoadError extends Error {
  constructor(message: string, public override readonly cause?: unknown) {
    super(message);
    this.name = 'LoadError';
  }
}
