export const ACTION_SCHEMA_VERSION = 1 as const

export type ActionEffect = 'allow' | 'ask' | 'deny'
export type ActionRisk = 'low' | 'medium' | 'high' | 'critical'
export type ActionGrantScope = 'once' | 'task'
export type ActionOutcome = 'allowed' | 'approved' | 'denied' | 'failed' | 'succeeded' | 'unknown'

export type ActionCapability =
  | 'filesystem.read'
  | 'filesystem.write'
  | 'filesystem.delete'
  | 'process.execute'
  | 'network.fetch'
  | 'network.send'
  | 'credential.read'
  | 'external.irreversible'

export interface PathActionResource {
  kind: 'path'
  path: string
  access: 'read' | 'write' | 'delete'
  scope: 'workspace' | 'outside' | 'unknown'
  sensitivity: 'normal' | 'sensitive' | 'credential'
  targetCount?: number
}

export interface CommandActionResource {
  kind: 'command'
  command: string
  executable: string
  readOnly: boolean
}

export interface NetworkActionResource {
  kind: 'network'
  direction: 'fetch' | 'send'
  host: string
  scheme?: string
  port?: number
}

export interface ExternalActionResource {
  kind: 'external'
  targetType: string
  target: string
  irreversible: boolean
}

export type ActionResource =
  | PathActionResource
  | CommandActionResource
  | NetworkActionResource
  | ExternalActionResource

export interface ActionRequestV1 {
  schemaVersion: 1
  id: string
  createdAt: string
  profile: string
  sessionId: string
  taskId?: string
  toolName: string
  operation: string
  arguments: Record<string, unknown>
  resources: ActionResource[]
  capabilities: ActionCapability[]
  riskHints: string[]
}

export interface ActionDecisionV1 {
  schemaVersion: 1
  requestId: string
  effect: ActionEffect
  ruleId: string
  risk: ActionRisk
  reason: string
  matchedResources: string[]
  grantOptions: ActionGrantScope[]
  matchedGrantId?: string
}

export interface ActionResourceConstraint {
  kind: ActionResource['kind']
  fingerprint: string
}

export interface ActionGrantV1 {
  schemaVersion: 1
  id: string
  createdAt: string
  expiresAt: string
  scope: ActionGrantScope
  profile: string
  sessionId: string
  taskId?: string
  toolName: string
  operation: string
  resourceConstraints: ActionResourceConstraint[]
  requestDigest: string
  policyHash: string
}

export interface ActionGrantStoreV1 {
  schemaVersion: 1
  updatedAt: string
  grants: ActionGrantV1[]
}

export interface ActionEventV1 {
  schemaVersion: 1
  id: string
  createdAt: string
  requestId: string
  profile?: string
  sessionId?: string
  taskId?: string
  decision: ActionEffect
  outcome: ActionOutcome
  ruleId: string
  toolName: string
  operation: string
  resourceSummary: string[]
  argumentDigest: string
  durationMs?: number
  errorCode?: string
}

export interface ActionPolicyV1 {
  schemaVersion: 1
  id: string
  workspaceRoots: string[]
  sensitivePathPatterns: string[]
  credentialPathPatterns: string[]
  allowedNetworkDomains: string[]
  deniedCommandPatterns: string[]
  readOnlyCommandPatterns: string[]
  maxBulkTargets: number
  onceGrantTtlMs: number
  taskGrantTtlMs: number
}

export interface ActionProtectionProfileV1 {
  profile: string
  enabled: boolean
  updatedAt: string
}

export interface ActionProtectionSettingsV1 {
  schemaVersion: 1
  updatedAt: string
  profiles: ActionProtectionProfileV1[]
}

export interface CreateActionRequestInput {
  id?: string
  now?: Date
  profile: string
  sessionId: string
  taskId?: string
  toolName: string
  operation: string
  arguments?: Record<string, unknown>
  resources?: ActionResource[]
  capabilities?: ActionCapability[]
  riskHints?: string[]
}

export interface EvaluateActionOptions {
  grants?: ActionGrantV1[]
  now?: Date
}

export interface CreateActionGrantOptions {
  id?: string
  now?: Date
  ttlMs?: number
}

export interface CreateActionEventOptions {
  id?: string
  now?: Date
  durationMs?: number
  errorCode?: string
}

export interface ActionStorePaths {
  root: string
  policy: string
  protection: string
  protectionLock: string
  grants: string
  grantLock: string
  events: string
  eventLock: string
}

export interface ActionEventStoreOptions {
  maxBytes?: number
  maxFiles?: number
  limit?: number
}

export interface ActionEventReadResult {
  events: ActionEventV1[]
  invalidLines: number
  filesRead: number
}

export interface ActionStoreInspection {
  ok: boolean
  issues: string[]
  grants: number
  events: number
}

export type ActionSchemaErrorCode =
  | 'ACTION_SCHEMA_INVALID'
  | 'ACTION_POLICY_INVALID'
  | 'ACTION_GRANT_INVALID'
  | 'ACTION_EVENT_INVALID'
  | 'ACTION_STORE_INVALID'

export class ActionSchemaError extends Error {
  constructor(
    public readonly code: ActionSchemaErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'ActionSchemaError'
  }
}
