import type { Rule } from '../../types.js';
import { secretsRule } from './secrets.js';
import { shellExecutionRule } from './shellExecution.js';
import { dynamicRunnerRule } from './dynamicRunner.js';
import { plainHttpRule, publicRemoteEndpointRule } from './httpTransport.js';
import { filesystemAccessRule } from './filesystemAccess.js';
import { dockerRiskRule } from './dockerRisk.js';
import { suspiciousArgsRule } from './suspiciousArgs.js';
import { missingCommandRule } from './missingCommand.js';

export const defaultRules: Rule[] = [
  secretsRule,
  shellExecutionRule,
  dynamicRunnerRule,
  plainHttpRule,
  publicRemoteEndpointRule,
  filesystemAccessRule,
  dockerRiskRule,
  suspiciousArgsRule,
  missingCommandRule,
];
