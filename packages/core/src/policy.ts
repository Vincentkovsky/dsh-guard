import type { Policy } from './types.js'
import { sha256, stableJson } from './util.js'

export const DEFAULT_POLICY: Policy = {
  schemaVersion: 1,
  id: 'dsh-guard-default-v1',
  denyCapabilities: ['profile-override', 'external-code'],
  reviewCapabilities: [
    'filesystem-read',
    'filesystem-write',
    'environment',
    'credentials',
    'network-client',
    'network-listen',
    'subprocess',
    'dynamic-code',
    'native-code',
    'tool-register',
  ],
  protectedEntryIds: [
    'webserver',
    'web-runtime',
    'agent',
    'tools',
    'credentials',
    'api-gateway',
    'client-connection',
  ],
  protectedModulePrefixes: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'],
  maxArchiveBytes: 100 * 1024 * 1024,
  maxFiles: 10_000,
  maxSourceFileBytes: 2 * 1024 * 1024,
}

export function policyHash(policy: Policy): string {
  return sha256(stableJson(policy))
}
