import type {
  ActionDecisionV1,
  ActionEventV1,
  ActionOutcome,
  ActionRequestV1,
  ActionResource,
  CreateActionEventOptions,
} from './types.js'
import { parseActionEvent } from './schema.js'
import { sha256, sortableId, stableJson } from '../util.js'

const SECRET_ASSIGNMENT = /\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|private[_-]?key|secret|token)\b(\s*[:=]\s*)([^\s,;&]+)/giu
const AUTHORIZATION = /\bAuthorization\s*[:=]\s*(?:(?:Basic|Bearer|Digest)\s+)?[^\s,;&]+/giu
const COOKIE = /\b(?:Cookie|Set-Cookie)\s*[:=]\s*[^\r\n;&]+/giu
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/giu
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu
const JWT = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gu
const COMMON_TOKEN = /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b/gu

export function redactActionText(input: unknown, max = 400): string {
  return String(input ?? '')
    .replace(PRIVATE_KEY, '[redacted-private-key]')
    .replace(AUTHORIZATION, 'Authorization: [redacted]')
    .replace(COOKIE, 'Cookie: [redacted]')
    .replace(BEARER, 'Bearer [redacted]')
    .replace(SECRET_ASSIGNMENT, '$1$2[redacted]')
    .replace(JWT, '[redacted-jwt]')
    .replace(COMMON_TOKEN, '[redacted-token]')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .slice(0, max)
}

export function actionArgumentDigest(argumentsValue: Record<string, unknown>): string {
  return sha256(stableJson(argumentsValue))
}

export function summarizeActionResource(resource: ActionResource): string {
  if (resource.kind === 'path') {
    const count = resource.targetCount === undefined ? '' : ` count=${resource.targetCount}`
    return redactActionText(`path:${resource.access}:${resource.scope}:${resource.sensitivity}:${resource.path}${count}`)
  }
  if (resource.kind === 'command') {
    return redactActionText(`command:${resource.executable || '[unknown]'}:${resource.command}`)
  }
  if (resource.kind === 'network') {
    const port = resource.port === undefined ? '' : `:${resource.port}`
    return redactActionText(`network:${resource.direction}:${resource.scheme ?? 'unknown'}://${resource.host}${port}`)
  }
  return redactActionText(`external:${resource.targetType}:${resource.target}:irreversible=${resource.irreversible}`)
}

export function createActionEvent(
  request: ActionRequestV1,
  decision: ActionDecisionV1,
  outcome: ActionOutcome,
  options: CreateActionEventOptions = {},
): ActionEventV1 {
  const now = options.now ?? new Date()
  return parseActionEvent({
    schemaVersion: 1,
    id: options.id ?? sortableId('aevt', now),
    createdAt: now.toISOString(),
    requestId: request.id,
    profile: redactActionText(request.profile, 256),
    sessionId: redactActionText(request.sessionId, 512),
    ...(request.taskId === undefined ? {} : { taskId: redactActionText(request.taskId, 512) }),
    decision: decision.effect,
    outcome,
    ruleId: decision.ruleId,
    toolName: redactActionText(request.toolName, 160),
    operation: redactActionText(request.operation, 160),
    resourceSummary: request.resources.map(summarizeActionResource),
    argumentDigest: actionArgumentDigest(request.arguments),
    ...(options.durationMs === undefined ? {} : { durationMs: options.durationMs }),
    ...(options.errorCode === undefined ? {} : { errorCode: redactActionText(options.errorCode, 120) }),
  })
}
