import type {
  ActionCapability,
  ActionDecisionV1,
  ActionEffect,
  ActionEventV1,
  ActionGrantScope,
  ActionGrantStoreV1,
  ActionGrantV1,
  ActionOutcome,
  ActionPolicyV1,
  ActionProtectionSettingsV1,
  ActionResource,
  ActionResourceConstraint,
  ActionRisk,
  ActionSchemaErrorCode,
  ActionRequestV1,
} from './types.js'
import { ActionSchemaError } from './types.js'

type UnknownRecord = Record<string, unknown>

const CAPABILITIES: ActionCapability[] = [
  'filesystem.read',
  'filesystem.write',
  'filesystem.delete',
  'process.execute',
  'network.fetch',
  'network.send',
  'credential.read',
  'external.irreversible',
]
const EFFECTS: ActionEffect[] = ['allow', 'ask', 'deny']
const RISKS: ActionRisk[] = ['low', 'medium', 'high', 'critical']
const GRANT_SCOPES: ActionGrantScope[] = ['once', 'task']
const OUTCOMES: ActionOutcome[] = ['allowed', 'approved', 'denied', 'failed', 'succeeded', 'unknown']

function fail(code: ActionSchemaErrorCode, path: string, message: string): never {
  throw new ActionSchemaError(code, `${path}: ${message}`)
}

function record(value: unknown, code: ActionSchemaErrorCode, path: string): UnknownRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code, path, 'expected object')
  return value as UnknownRecord
}

function exactKeys(
  value: UnknownRecord,
  required: string[],
  optional: string[],
  code: ActionSchemaErrorCode,
  path: string,
): void {
  for (const key of required) {
    if (!Object.hasOwn(value, key)) fail(code, `${path}.${key}`, 'missing required field')
  }
  const allowed = new Set([...required, ...optional])
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(code, `${path}.${key}`, 'unknown field')
  }
}

function string(value: unknown, code: ActionSchemaErrorCode, path: string, max = 4096): string {
  if (typeof value !== 'string' || !value || value.length > max) fail(code, path, `expected non-empty string up to ${max} characters`)
  return value
}

function isoDate(value: unknown, code: ActionSchemaErrorCode, path: string): string {
  const parsed = string(value, code, path, 64)
  if (!Number.isFinite(Date.parse(parsed))) fail(code, path, 'expected ISO date')
  return parsed
}

function number(value: unknown, code: ActionSchemaErrorCode, path: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) {
    fail(code, path, `expected number between ${min} and ${max}`)
  }
  return value
}

function integer(value: unknown, code: ActionSchemaErrorCode, path: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  const parsed = number(value, code, path, min, max)
  if (!Number.isInteger(parsed)) fail(code, path, 'expected integer')
  return parsed
}

function boolean(value: unknown, code: ActionSchemaErrorCode, path: string): boolean {
  if (typeof value !== 'boolean') fail(code, path, 'expected boolean')
  return value
}

function literalOne(value: unknown, code: ActionSchemaErrorCode, path: string): 1 {
  if (value !== 1) fail(code, path, 'unsupported schemaVersion')
  return 1
}

function enumeration<T extends string>(
  value: unknown,
  options: readonly T[],
  code: ActionSchemaErrorCode,
  path: string,
): T {
  if (typeof value !== 'string' || !options.includes(value as T)) fail(code, path, `expected one of ${options.join(', ')}`)
  return value as T
}

function stringArray(value: unknown, code: ActionSchemaErrorCode, path: string, maxItems = 256): string[] {
  if (!Array.isArray(value) || value.length > maxItems) fail(code, path, `expected array with at most ${maxItems} items`)
  return value.map((item, index) => string(item, code, `${path}[${index}]`))
}

function jsonValue(value: unknown, code: ActionSchemaErrorCode, path: string, depth = 0, seen = new Set<object>()): void {
  if (depth > 20) fail(code, path, 'JSON value is too deeply nested')
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail(code, path, 'number must be finite')
    return
  }
  if (typeof value !== 'object') fail(code, path, 'expected JSON-serializable value')
  if (seen.has(value)) fail(code, path, 'cyclic value is not allowed')
  seen.add(value)
  if (Array.isArray(value)) {
    if (value.length > 10_000) fail(code, path, 'array is too large')
    value.forEach((item, index) => jsonValue(item, code, `${path}[${index}]`, depth + 1, seen))
  } else {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) fail(code, path, 'expected plain JSON object')
    const entries = Object.entries(value as UnknownRecord)
    if (entries.length > 10_000) fail(code, path, 'object is too large')
    for (const [key, item] of entries) jsonValue(item, code, `${path}.${key}`, depth + 1, seen)
  }
  seen.delete(value)
}

function parseResource(value: unknown, path: string): ActionResource {
  const code = 'ACTION_SCHEMA_INVALID'
  const input = record(value, code, path)
  const kind = enumeration(input.kind, ['path', 'command', 'network', 'external'] as const, code, `${path}.kind`)

  if (kind === 'path') {
    exactKeys(input, ['kind', 'path', 'access', 'scope', 'sensitivity'], ['targetCount'], code, path)
    return {
      kind,
      path: string(input.path, code, `${path}.path`),
      access: enumeration(input.access, ['read', 'write', 'delete'] as const, code, `${path}.access`),
      scope: enumeration(input.scope, ['workspace', 'outside', 'unknown'] as const, code, `${path}.scope`),
      sensitivity: enumeration(input.sensitivity, ['normal', 'sensitive', 'credential'] as const, code, `${path}.sensitivity`),
      ...(input.targetCount === undefined ? {} : { targetCount: integer(input.targetCount, code, `${path}.targetCount`, 0) }),
    }
  }

  if (kind === 'command') {
    exactKeys(input, ['kind', 'command', 'executable', 'readOnly'], [], code, path)
    return {
      kind,
      command: string(input.command, code, `${path}.command`, 65_536),
      executable: string(input.executable, code, `${path}.executable`, 1024),
      readOnly: boolean(input.readOnly, code, `${path}.readOnly`),
    }
  }

  if (kind === 'network') {
    exactKeys(input, ['kind', 'direction', 'host'], ['scheme', 'port'], code, path)
    return {
      kind,
      direction: enumeration(input.direction, ['fetch', 'send'] as const, code, `${path}.direction`),
      host: string(input.host, code, `${path}.host`, 1024),
      ...(input.scheme === undefined ? {} : { scheme: string(input.scheme, code, `${path}.scheme`, 32) }),
      ...(input.port === undefined ? {} : { port: integer(input.port, code, `${path}.port`, 1, 65_535) }),
    }
  }

  exactKeys(input, ['kind', 'targetType', 'target', 'irreversible'], [], code, path)
  return {
    kind,
    targetType: string(input.targetType, code, `${path}.targetType`, 256),
    target: string(input.target, code, `${path}.target`),
    irreversible: boolean(input.irreversible, code, `${path}.irreversible`),
  }
}

export function parseActionRequest(value: unknown): ActionRequestV1 {
  const code = 'ACTION_SCHEMA_INVALID'
  const input = record(value, code, 'actionRequest')
  exactKeys(
    input,
    ['schemaVersion', 'id', 'createdAt', 'profile', 'sessionId', 'toolName', 'operation', 'arguments', 'resources', 'capabilities', 'riskHints'],
    ['taskId'],
    code,
    'actionRequest',
  )
  const argumentsValue = record(input.arguments, code, 'actionRequest.arguments')
  jsonValue(argumentsValue, code, 'actionRequest.arguments')
  if (!Array.isArray(input.resources) || input.resources.length > 256) fail(code, 'actionRequest.resources', 'expected array with at most 256 items')
  if (!Array.isArray(input.capabilities) || input.capabilities.length > CAPABILITIES.length) fail(code, 'actionRequest.capabilities', 'invalid capability array')
  return {
    schemaVersion: literalOne(input.schemaVersion, code, 'actionRequest.schemaVersion'),
    id: string(input.id, code, 'actionRequest.id', 256),
    createdAt: isoDate(input.createdAt, code, 'actionRequest.createdAt'),
    profile: string(input.profile, code, 'actionRequest.profile', 256),
    sessionId: string(input.sessionId, code, 'actionRequest.sessionId', 512),
    ...(input.taskId === undefined ? {} : { taskId: string(input.taskId, code, 'actionRequest.taskId', 512) }),
    toolName: string(input.toolName, code, 'actionRequest.toolName', 512),
    operation: string(input.operation, code, 'actionRequest.operation', 512),
    arguments: argumentsValue,
    resources: input.resources.map((resource, index) => parseResource(resource, `actionRequest.resources[${index}]`)),
    capabilities: input.capabilities.map((capability, index) => enumeration(capability, CAPABILITIES, code, `actionRequest.capabilities[${index}]`)),
    riskHints: stringArray(input.riskHints, code, 'actionRequest.riskHints'),
  }
}

export function parseActionDecision(value: unknown): ActionDecisionV1 {
  const code = 'ACTION_SCHEMA_INVALID'
  const input = record(value, code, 'actionDecision')
  exactKeys(
    input,
    ['schemaVersion', 'requestId', 'effect', 'ruleId', 'risk', 'reason', 'matchedResources', 'grantOptions'],
    ['matchedGrantId'],
    code,
    'actionDecision',
  )
  if (!Array.isArray(input.grantOptions)) fail(code, 'actionDecision.grantOptions', 'expected array')
  return {
    schemaVersion: literalOne(input.schemaVersion, code, 'actionDecision.schemaVersion'),
    requestId: string(input.requestId, code, 'actionDecision.requestId', 256),
    effect: enumeration(input.effect, EFFECTS, code, 'actionDecision.effect'),
    ruleId: string(input.ruleId, code, 'actionDecision.ruleId', 256),
    risk: enumeration(input.risk, RISKS, code, 'actionDecision.risk'),
    reason: string(input.reason, code, 'actionDecision.reason'),
    matchedResources: stringArray(input.matchedResources, code, 'actionDecision.matchedResources'),
    grantOptions: input.grantOptions.map((scope, index) => enumeration(scope, GRANT_SCOPES, code, `actionDecision.grantOptions[${index}]`)),
    ...(input.matchedGrantId === undefined ? {} : { matchedGrantId: string(input.matchedGrantId, code, 'actionDecision.matchedGrantId', 256) }),
  }
}

function parseConstraint(value: unknown, path: string): ActionResourceConstraint {
  const code = 'ACTION_GRANT_INVALID'
  const input = record(value, code, path)
  exactKeys(input, ['kind', 'fingerprint'], [], code, path)
  return {
    kind: enumeration(input.kind, ['path', 'command', 'network', 'external'] as const, code, `${path}.kind`),
    fingerprint: string(input.fingerprint, code, `${path}.fingerprint`, 128),
  }
}

export function parseActionGrant(value: unknown): ActionGrantV1 {
  const code = 'ACTION_GRANT_INVALID'
  const input = record(value, code, 'actionGrant')
  exactKeys(
    input,
    ['schemaVersion', 'id', 'createdAt', 'expiresAt', 'scope', 'profile', 'sessionId', 'toolName', 'operation', 'resourceConstraints', 'requestDigest', 'policyHash'],
    ['taskId'],
    code,
    'actionGrant',
  )
  if (!Array.isArray(input.resourceConstraints) || input.resourceConstraints.length > 256) {
    fail(code, 'actionGrant.resourceConstraints', 'expected array with at most 256 items')
  }
  const scope = enumeration(input.scope, GRANT_SCOPES, code, 'actionGrant.scope')
  const taskId = input.taskId === undefined ? undefined : string(input.taskId, code, 'actionGrant.taskId', 512)
  if (scope === 'task' && taskId === undefined) fail(code, 'actionGrant.taskId', 'task grant requires taskId')
  const createdAt = isoDate(input.createdAt, code, 'actionGrant.createdAt')
  const expiresAt = isoDate(input.expiresAt, code, 'actionGrant.expiresAt')
  if (Date.parse(expiresAt) <= Date.parse(createdAt)) fail(code, 'actionGrant.expiresAt', 'must be after createdAt')
  return {
    schemaVersion: literalOne(input.schemaVersion, code, 'actionGrant.schemaVersion'),
    id: string(input.id, code, 'actionGrant.id', 256),
    createdAt,
    expiresAt,
    scope,
    profile: string(input.profile, code, 'actionGrant.profile', 256),
    sessionId: string(input.sessionId, code, 'actionGrant.sessionId', 512),
    ...(taskId === undefined ? {} : { taskId }),
    toolName: string(input.toolName, code, 'actionGrant.toolName', 512),
    operation: string(input.operation, code, 'actionGrant.operation', 512),
    resourceConstraints: input.resourceConstraints.map((constraint, index) => parseConstraint(constraint, `actionGrant.resourceConstraints[${index}]`)),
    requestDigest: string(input.requestDigest, code, 'actionGrant.requestDigest', 128),
    policyHash: string(input.policyHash, code, 'actionGrant.policyHash', 128),
  }
}

export function parseActionGrantStore(value: unknown): ActionGrantStoreV1 {
  const code = 'ACTION_STORE_INVALID'
  const input = record(value, code, 'actionGrantStore')
  exactKeys(input, ['schemaVersion', 'updatedAt', 'grants'], [], code, 'actionGrantStore')
  if (!Array.isArray(input.grants) || input.grants.length > 10_000) {
    fail(code, 'actionGrantStore.grants', 'expected array with at most 10000 items')
  }
  const grants = input.grants.map((grant, index) => {
    try {
      return parseActionGrant(grant)
    } catch (error) {
      if (error instanceof ActionSchemaError) fail(code, `actionGrantStore.grants[${index}]`, error.message)
      throw error
    }
  })
  const ids = new Set<string>()
  for (const [index, grant] of grants.entries()) {
    if (ids.has(grant.id)) fail(code, `actionGrantStore.grants[${index}].id`, 'duplicate grant id')
    ids.add(grant.id)
  }
  return {
    schemaVersion: literalOne(input.schemaVersion, code, 'actionGrantStore.schemaVersion'),
    updatedAt: isoDate(input.updatedAt, code, 'actionGrantStore.updatedAt'),
    grants,
  }
}

export function parseActionEvent(value: unknown): ActionEventV1 {
  const code = 'ACTION_EVENT_INVALID'
  const input = record(value, code, 'actionEvent')
  exactKeys(
    input,
    ['schemaVersion', 'id', 'createdAt', 'requestId', 'decision', 'outcome', 'ruleId', 'toolName', 'operation', 'resourceSummary', 'argumentDigest'],
    ['profile', 'sessionId', 'taskId', 'durationMs', 'errorCode'],
    code,
    'actionEvent',
  )
  return {
    schemaVersion: literalOne(input.schemaVersion, code, 'actionEvent.schemaVersion'),
    id: string(input.id, code, 'actionEvent.id', 256),
    createdAt: isoDate(input.createdAt, code, 'actionEvent.createdAt'),
    requestId: string(input.requestId, code, 'actionEvent.requestId', 256),
    ...(input.profile === undefined ? {} : { profile: string(input.profile, code, 'actionEvent.profile', 256) }),
    ...(input.sessionId === undefined ? {} : { sessionId: string(input.sessionId, code, 'actionEvent.sessionId', 512) }),
    ...(input.taskId === undefined ? {} : { taskId: string(input.taskId, code, 'actionEvent.taskId', 512) }),
    decision: enumeration(input.decision, EFFECTS, code, 'actionEvent.decision'),
    outcome: enumeration(input.outcome, OUTCOMES, code, 'actionEvent.outcome'),
    ruleId: string(input.ruleId, code, 'actionEvent.ruleId', 256),
    toolName: string(input.toolName, code, 'actionEvent.toolName', 512),
    operation: string(input.operation, code, 'actionEvent.operation', 512),
    resourceSummary: stringArray(input.resourceSummary, code, 'actionEvent.resourceSummary'),
    argumentDigest: string(input.argumentDigest, code, 'actionEvent.argumentDigest', 128),
    ...(input.durationMs === undefined ? {} : { durationMs: number(input.durationMs, code, 'actionEvent.durationMs') }),
    ...(input.errorCode === undefined ? {} : { errorCode: string(input.errorCode, code, 'actionEvent.errorCode', 256) }),
  }
}

export function parseActionPolicy(value: unknown): ActionPolicyV1 {
  const code = 'ACTION_POLICY_INVALID'
  const input = record(value, code, 'actionPolicy')
  exactKeys(
    input,
    ['schemaVersion', 'id', 'workspaceRoots', 'sensitivePathPatterns', 'credentialPathPatterns', 'allowedNetworkDomains', 'deniedCommandPatterns', 'readOnlyCommandPatterns', 'maxBulkTargets', 'onceGrantTtlMs', 'taskGrantTtlMs'],
    [],
    code,
    'actionPolicy',
  )
  const deniedCommandPatterns = stringArray(input.deniedCommandPatterns, code, 'actionPolicy.deniedCommandPatterns')
  const readOnlyCommandPatterns = stringArray(input.readOnlyCommandPatterns, code, 'actionPolicy.readOnlyCommandPatterns')
  for (const [path, patterns] of [
    ['actionPolicy.deniedCommandPatterns', deniedCommandPatterns],
    ['actionPolicy.readOnlyCommandPatterns', readOnlyCommandPatterns],
  ] as const) {
    for (const [index, pattern] of patterns.entries()) {
      try {
        new RegExp(pattern, 'u')
      } catch {
        fail(code, `${path}[${index}]`, 'invalid regular expression')
      }
    }
  }
  return {
    schemaVersion: literalOne(input.schemaVersion, code, 'actionPolicy.schemaVersion'),
    id: string(input.id, code, 'actionPolicy.id', 256),
    workspaceRoots: stringArray(input.workspaceRoots, code, 'actionPolicy.workspaceRoots'),
    sensitivePathPatterns: stringArray(input.sensitivePathPatterns, code, 'actionPolicy.sensitivePathPatterns'),
    credentialPathPatterns: stringArray(input.credentialPathPatterns, code, 'actionPolicy.credentialPathPatterns'),
    allowedNetworkDomains: stringArray(input.allowedNetworkDomains, code, 'actionPolicy.allowedNetworkDomains').map((domain) => domain.toLowerCase()),
    deniedCommandPatterns,
    readOnlyCommandPatterns,
    maxBulkTargets: integer(input.maxBulkTargets, code, 'actionPolicy.maxBulkTargets', 1, 1_000_000),
    onceGrantTtlMs: integer(input.onceGrantTtlMs, code, 'actionPolicy.onceGrantTtlMs', 1_000, 86_400_000),
    taskGrantTtlMs: integer(input.taskGrantTtlMs, code, 'actionPolicy.taskGrantTtlMs', 1_000, 86_400_000),
  }
}

export function parseActionProtectionSettings(value: unknown): ActionProtectionSettingsV1 {
  const code = 'ACTION_STORE_INVALID'
  const input = record(value, code, 'actionProtection')
  exactKeys(input, ['schemaVersion', 'updatedAt', 'profiles'], [], code, 'actionProtection')
  if (!Array.isArray(input.profiles) || input.profiles.length > 256) {
    fail(code, 'actionProtection.profiles', 'expected array with at most 256 items')
  }
  const seen = new Set<string>()
  const profiles = input.profiles.map((value, index) => {
    const path = `actionProtection.profiles[${index}]`
    const profile = record(value, code, path)
    exactKeys(profile, ['profile', 'enabled', 'updatedAt'], [], code, path)
    const name = string(profile.profile, code, `${path}.profile`, 256)
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) fail(code, `${path}.profile`, 'invalid profile name')
    if (seen.has(name)) fail(code, `${path}.profile`, 'duplicate profile')
    seen.add(name)
    return {
      profile: name,
      enabled: boolean(profile.enabled, code, `${path}.enabled`),
      updatedAt: isoDate(profile.updatedAt, code, `${path}.updatedAt`),
    }
  })
  return {
    schemaVersion: literalOne(input.schemaVersion, code, 'actionProtection.schemaVersion'),
    updatedAt: isoDate(input.updatedAt, code, 'actionProtection.updatedAt'),
    profiles,
  }
}
