import type {
  ActionGrantScope,
  ActionGrantV1,
  ActionPolicyV1,
  ActionRequestV1,
  ActionResource,
  ActionResourceConstraint,
  CreateActionGrantOptions,
} from './types.js'
import { ActionSchemaError } from './types.js'
import { parseActionGrant, parseActionPolicy, parseActionRequest } from './schema.js'
import { sha256, sortableId, stableJson } from '../util.js'

export function actionPolicyHash(policy: ActionPolicyV1): string {
  return sha256(stableJson(parseActionPolicy(policy)))
}

export function actionRequestDigest(request: ActionRequestV1): string {
  const validated = parseActionRequest(request)
  return sha256(stableJson({
    profile: validated.profile,
    sessionId: validated.sessionId,
    taskId: validated.taskId ?? null,
    toolName: validated.toolName,
    operation: validated.operation,
    arguments: validated.arguments,
    resources: validated.resources,
    capabilities: validated.capabilities,
    riskHints: validated.riskHints,
  }))
}

export function actionResourceFingerprint(resource: ActionResource): string {
  return sha256(stableJson(resource))
}

function resourceConstraints(resources: ActionResource[]): ActionResourceConstraint[] {
  return resources
    .map((resource) => ({ kind: resource.kind, fingerprint: actionResourceFingerprint(resource) }))
    .sort((left, right) => `${left.kind}:${left.fingerprint}`.localeCompare(`${right.kind}:${right.fingerprint}`))
}

export function createActionGrant(
  request: ActionRequestV1,
  scope: ActionGrantScope,
  policy: ActionPolicyV1,
  options: CreateActionGrantOptions = {},
): ActionGrantV1 {
  const validatedRequest = parseActionRequest(request)
  const validatedPolicy = parseActionPolicy(policy)
  if (scope === 'task' && !validatedRequest.taskId) {
    throw new ActionSchemaError('ACTION_GRANT_INVALID', 'actionGrant.taskId: task grant requires request.taskId')
  }
  const now = options.now ?? new Date()
  const ttlMs = options.ttlMs ?? (scope === 'once' ? validatedPolicy.onceGrantTtlMs : validatedPolicy.taskGrantTtlMs)
  if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
    throw new ActionSchemaError('ACTION_GRANT_INVALID', 'actionGrant.ttlMs: expected a positive integer')
  }
  return parseActionGrant({
    schemaVersion: 1,
    id: options.id ?? sortableId('agrant', now),
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    scope,
    profile: validatedRequest.profile,
    sessionId: validatedRequest.sessionId,
    ...(validatedRequest.taskId === undefined ? {} : { taskId: validatedRequest.taskId }),
    toolName: validatedRequest.toolName,
    operation: validatedRequest.operation,
    resourceConstraints: resourceConstraints(validatedRequest.resources),
    requestDigest: actionRequestDigest(validatedRequest),
    policyHash: actionPolicyHash(validatedPolicy),
  })
}

function constraintsMatch(grant: ActionGrantV1, request: ActionRequestV1): boolean {
  const actual = resourceConstraints(request.resources)
  if (actual.length !== grant.resourceConstraints.length) return false
  return actual.every((constraint, index) => {
    const expected = grant.resourceConstraints[index]
    return expected?.kind === constraint.kind && expected.fingerprint === constraint.fingerprint
  })
}

export function matchesActionGrant(
  grant: ActionGrantV1,
  request: ActionRequestV1,
  policy: ActionPolicyV1,
  now = new Date(),
): boolean {
  try {
    const validatedGrant = parseActionGrant(grant)
    const validatedRequest = parseActionRequest(request)
    const validatedPolicy = parseActionPolicy(policy)
    if (validatedGrant.policyHash !== actionPolicyHash(validatedPolicy)) return false
    if (Date.parse(validatedGrant.expiresAt) <= now.getTime()) return false
    if (validatedGrant.profile !== validatedRequest.profile || validatedGrant.sessionId !== validatedRequest.sessionId) return false
    if (validatedGrant.toolName !== validatedRequest.toolName || validatedGrant.operation !== validatedRequest.operation) return false
    if (validatedGrant.scope === 'once') return validatedGrant.requestDigest === actionRequestDigest(validatedRequest)
    if (!validatedGrant.taskId || validatedGrant.taskId !== validatedRequest.taskId) return false
    return constraintsMatch(validatedGrant, validatedRequest)
  } catch {
    return false
  }
}

export function findMatchingActionGrant(
  grants: ActionGrantV1[],
  request: ActionRequestV1,
  policy: ActionPolicyV1,
  now = new Date(),
): ActionGrantV1 | undefined {
  const valid = grants.flatMap((grant) => {
    try {
      return [parseActionGrant(grant)]
    } catch {
      return []
    }
  })
  return valid
    .sort((left, right) => Number(left.scope === 'task') - Number(right.scope === 'task'))
    .find((grant) => matchesActionGrant(grant, request, policy, now))
}

export function consumeActionGrant(grants: ActionGrantV1[], grantId: string): ActionGrantV1[] {
  return grants.filter((grant) => grant.id !== grantId || grant.scope !== 'once')
}

export function revokeActionGrant(grants: ActionGrantV1[], grantId: string): ActionGrantV1[] {
  return grants.filter((grant) => grant.id !== grantId)
}
