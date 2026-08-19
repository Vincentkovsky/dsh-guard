import { resolve } from 'node:path'
import type {
  ActionDecisionV1,
  ActionPolicyV1,
  ActionRequestV1,
  ActionResource,
  EvaluateActionOptions,
  PathActionResource,
} from './types.js'
import { findMatchingActionGrant } from './grants.js'
import { resourceDisplayName } from './normalize.js'
import { parseActionPolicy, parseActionRequest } from './schema.js'

export function createDefaultActionPolicy(workspaceRoots: string[] = [process.cwd()]): ActionPolicyV1 {
  return {
    schemaVersion: 1,
    id: 'dsh-guard-action-default-v1',
    workspaceRoots: workspaceRoots.map((root) => resolve(root)),
    sensitivePathPatterns: [
      '**/.env',
      '**/.env.*',
      '**/.npmrc',
      '**/.pypirc',
      '**/.netrc',
      '**/credentials',
    ],
    credentialPathPatterns: [
      '~/.ssh/**',
      '~/.aws/**',
      '~/.config/gcloud/**',
      '~/.kube/**',
      '**/id_rsa',
      '**/id_ed25519',
    ],
    allowedNetworkDomains: [],
    deniedCommandPatterns: [
      '(?:^|[;&|]\\s*)rm\\s+(?=[^\\r\\n]*(?:-[A-Za-z]*r|--recursive))(?=[^\\r\\n]*(?:-[A-Za-z]*f|--force))[^\\r\\n]*\\s+/(?:\\s|$)',
      '(?:^|[;&|]\\s*)git\\s+reset\\s+--hard(?:\\s|$)',
      '(?:^|[;&|]\\s*)dd\\s+[^\\r\\n]*\\bof=/dev/',
      '(?:curl|wget)[^\\n]*(?:\\||&&|;)\\s*(?:sh|bash|zsh|node|python)(?:\\s|$)',
      ':\\(\\)\\s*\\{',
    ],
    readOnlyCommandPatterns: [
      '^\\s*(?:pwd|whoami|id|uname)(?:\\s|$)',
      '^\\s*(?:rg|grep|ls|stat|wc|head|tail)(?:\\s|$)',
      '^\\s*git\\s+(?:status|diff|log|show)(?:\\s|$)',
    ],
    maxBulkTargets: 20,
    onceGrantTtlMs: 5 * 60 * 1000,
    taskGrantTtlMs: 30 * 60 * 1000,
  }
}

export const DEFAULT_ACTION_POLICY = createDefaultActionPolicy()

function matchesRegex(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => new RegExp(pattern, 'u').test(value))
}

function domainAllowed(host: string, domains: string[]): boolean {
  const normalized = host.toLowerCase().replace(/\.$/, '')
  return domains.some((domain) => {
    const candidate = domain.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '')
    return normalized === candidate || normalized.endsWith(`.${candidate}`)
  })
}

export function actionContainsLikelySecret(value: unknown, key = '', depth = 0, seen = new Set<object>()): boolean {
  if (depth > 8) return false
  const keyLooksSecret = /(?:api[_-]?key|auth(?:orization)?|cookie|password|private[_-]?key|secret|token)/i.test(key)
  if (typeof value === 'string') {
    if (value === '[redacted]' || !value) return false
    if (keyLooksSecret && value.length >= 8) return true
    try {
      const url = new URL(value)
      if (url.username || url.password) return true
      for (const [queryKey, queryValue] of url.searchParams) {
        if (/(?:api[_-]?key|auth(?:orization)?|cookie|password|private[_-]?key|secret|token)/i.test(queryKey) && queryValue.length >= 8) return true
      }
    } catch { /* ordinary strings are not URLs */ }
    return /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{20,}\b|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b)/u.test(value)
  }
  if (!value || typeof value !== 'object' || seen.has(value)) return false
  seen.add(value)
  const found = Array.isArray(value)
    ? value.some((item) => actionContainsLikelySecret(item, '', depth + 1, seen))
    : Object.entries(value as Record<string, unknown>).some(([childKey, item]) => actionContainsLikelySecret(item, childKey, depth + 1, seen))
  seen.delete(value)
  return found
}

function decision(
  request: ActionRequestV1,
  effect: ActionDecisionV1['effect'],
  ruleId: string,
  risk: ActionDecisionV1['risk'],
  reason: string,
  resources: ActionResource[] = [],
  matchedGrantId?: string,
): ActionDecisionV1 {
  return {
    schemaVersion: 1,
    requestId: request.id,
    effect,
    ruleId,
    risk,
    reason,
    matchedResources: resources.map(resourceDisplayName),
    grantOptions: effect === 'ask' ? ['once', 'task'] : [],
    ...(matchedGrantId === undefined ? {} : { matchedGrantId }),
  }
}

function hardDeny(request: ActionRequestV1, policy: ActionPolicyV1): ActionDecisionV1 | undefined {
  if (request.riskHints.includes('suspected-secret-exfiltration')) {
    return decision(request, 'deny', 'network.secret-exfiltration', 'critical', 'The action appears to send secret material to an external target.', request.resources)
  }
  if (request.riskHints.includes('download-then-execute')) {
    return decision(request, 'deny', 'process.download-then-execute', 'critical', 'Downloading and immediately executing code is denied by the default policy.', request.resources)
  }
  if (request.riskHints.includes('credential-shell-read')) {
    return decision(request, 'deny', 'credential.shell-read', 'critical', 'A shell command appears to access a known credential path.', request.resources)
  }
  const privateRead = request.resources.find((resource) => resource.kind === 'path' && resource.access === 'read' && resource.sensitivity === 'credential')
  if (privateRead) {
    return decision(request, 'deny', 'credential.private-read', 'critical', 'Reading a known credential path is denied by the default policy.', [privateRead])
  }
  if (request.capabilities.includes('credential.read') && !request.resources.some((resource) => resource.kind === 'path')) {
    return decision(request, 'deny', 'credential.unscoped-read', 'critical', 'An unscoped credential read cannot be safely authorized.', request.resources)
  }
  const outsideDelete = request.resources.find((resource) => resource.kind === 'path' && resource.access === 'delete' && resource.scope !== 'workspace')
  if (outsideDelete) {
    return decision(request, 'deny', 'path.delete-outside-workspace', 'critical', 'Deleting outside an approved workspace is denied.', [outsideDelete])
  }
  const deniedCommand = request.resources.find((resource) => resource.kind === 'command' && matchesRegex(resource.command, policy.deniedCommandPatterns))
  if (deniedCommand) {
    return decision(request, 'deny', 'process.denied-command', 'critical', 'The command matches a destructive or download-and-execute rule.', [deniedCommand])
  }
  return undefined
}

function requiresApproval(request: ActionRequestV1, policy: ActionPolicyV1): ActionDecisionV1 | undefined {
  if (request.riskHints.includes('identity-missing')) {
    return decision(request, 'ask', 'identity.missing', 'high', 'The action has no DSH agent identity and requires confirmation.', request.resources)
  }
  if (request.riskHints.includes('unknown-tool')) {
    return decision(request, 'ask', 'tool.unknown', 'high', 'This tool has no registered DSH Guard action adapter.', request.resources)
  }
  if (request.riskHints.includes('sensitive-shell-read')) {
    return decision(request, 'ask', 'path.sensitive-shell-read', 'high', 'A shell command appears to access a sensitive file.', request.resources)
  }

  const unknownPath = request.resources.find((resource) => resource.kind === 'path' && resource.scope === 'unknown')
  if (unknownPath) return decision(request, 'ask', 'path.unknown', 'high', 'The target path could not be normalized safely.', [unknownPath])

  const sensitivePath = request.resources.find((resource) => resource.kind === 'path' && resource.sensitivity === 'sensitive')
  if (sensitivePath) return decision(request, 'ask', 'path.sensitive', 'high', 'The action accesses a sensitive file.', [sensitivePath])

  const outsideAccess = request.resources.find(
    (resource): resource is PathActionResource => resource.kind === 'path' && resource.scope === 'outside',
  )
  if (outsideAccess) {
    return decision(
      request,
      'ask',
      `path.${outsideAccess.access}-outside-workspace`,
      'high',
      `${outsideAccess.access === 'read' ? 'Reading' : 'Writing'} outside an approved workspace requires confirmation.`,
      [outsideAccess],
    )
  }

  const workspaceDelete = request.resources.find((resource) => resource.kind === 'path' && resource.access === 'delete')
  if (workspaceDelete) return decision(request, 'ask', 'path.delete', 'high', 'Deleting workspace files requires confirmation.', [workspaceDelete])

  const bulk = request.resources.find((resource) => resource.kind === 'path' && (resource.targetCount ?? 0) > policy.maxBulkTargets)
  if (bulk) return decision(request, 'ask', 'path.bulk-change', 'high', `The action affects more than ${policy.maxBulkTargets} targets.`, [bulk])

  const network = request.resources.find((resource) => resource.kind === 'network')
  const outbound = request.capabilities.includes('network.send') || (network?.kind === 'network' && network.direction === 'send')
  if (outbound && actionContainsLikelySecret(request.arguments)) {
    return decision(request, 'ask', 'network.possible-secret', 'critical', 'The outgoing action contains a value that resembles a secret.', network ? [network] : request.resources)
  }
  if (network && (network.host === '[invalid-host]' || !domainAllowed(network.host, policy.allowedNetworkDomains))) {
    return decision(request, 'ask', 'network.unapproved-domain', 'high', 'The network target is not in the approved domain list.', [network])
  }

  const command = request.resources.find((resource) => resource.kind === 'command')
  if (command && !command.readOnly) return decision(request, 'ask', 'process.execute', 'high', 'Executing a command that is not known to be read-only requires confirmation.', [command])

  const irreversible = request.resources.find((resource) => resource.kind === 'external' && resource.irreversible)
  if (irreversible) return decision(request, 'ask', 'external.irreversible', 'high', 'This external action is marked as irreversible.', [irreversible])

  const unscopedSideEffect = request.capabilities.some((capability) => [
    'filesystem.delete',
    'process.execute',
    'network.send',
    'external.irreversible',
  ].includes(capability)) && request.resources.length === 0
  if (unscopedSideEffect) return decision(request, 'ask', 'action.unscoped-side-effect', 'high', 'A side-effecting action without a normalized resource requires confirmation.')

  return undefined
}

export function evaluateAction(
  request: ActionRequestV1,
  policy: ActionPolicyV1,
  options: EvaluateActionOptions = {},
): ActionDecisionV1 {
  const validatedRequest = parseActionRequest(request)
  const validatedPolicy = parseActionPolicy(policy)
  const denied = hardDeny(validatedRequest, validatedPolicy)
  if (denied) return denied

  const grant = findMatchingActionGrant(options.grants ?? [], validatedRequest, validatedPolicy, options.now)
  if (grant) {
    return decision(validatedRequest, 'allow', 'grant.active', 'low', `Allowed by active ${grant.scope} grant.`, validatedRequest.resources, grant.id)
  }

  const approval = requiresApproval(validatedRequest, validatedPolicy)
  if (approval) return approval

  if (validatedRequest.resources.length === 0 && validatedRequest.capabilities.length === 0) {
    return decision(validatedRequest, 'allow', 'action.no-side-effect', 'low', 'No side-effecting capability or resource was declared.')
  }

  return decision(validatedRequest, 'allow', 'action.safe-default', 'low', 'The normalized action stays within the default local policy.', validatedRequest.resources)
}
