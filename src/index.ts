export type {
  Severity,
  McpServerConfig,
  Finding,
  ScanResult,
  ScanTargetMetadata,
  ScanTargetResult,
  AggregateFinding,
  AggregateScanResult,
  Rule,
} from './types.js';
export { LoadError } from './types.js';
export { scan, scanServer, type ScanOptions } from './scanner/scan.js';
export { defaultRules } from './scanner/rules/index.js';
export { buildCandidatePaths } from './discovery/candidatePaths.js';
export { discoverConfigs } from './discovery/discoverConfigs.js';
export {
  scanDiscoveredTargets,
  type ScanDiscoveredTargetsOptions,
} from './discovery/scanDiscoveredTargets.js';
export type {
  McpClient,
  DiscoveryScope,
  DiscoveryScopeFilter,
  CandidatePath,
  CandidatePathOptions,
  DiscoveredTarget,
  DiscoverConfigOptions,
} from './discovery/types.js';
