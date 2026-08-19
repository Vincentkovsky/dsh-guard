import { createHash } from 'node:crypto'
import type {
  ActionDecisionV1,
  ActionEventV1,
  ActionGrantV1,
  ActionPolicyV1,
  ActionRequestV1,
  ActionResource,
} from '@dsh-guard/core/action'
import {
  createActionEvent,
  createActionRequest,
  createDefaultActionPolicy,
  evaluateAction,
  actionContainsLikelySecret,
  normalizeCommandResource,
  normalizeNetworkResource,
  normalizePathResource,
  summarizeActionResource,
} from '@dsh-guard/core/action'
import type { PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'

export interface DshActionAdapterOptions {
  profile: string
  workspaceRoots: string[]
  allowedNetworkDomains: string[]
  askUnknownTools: boolean
  now?: Date
}

export interface AdaptedDshAction {
  request: ActionRequestV1
  policy: ActionPolicyV1
}

export interface DshActionGateOptions extends Omit<DshActionAdapterOptions, 'now'> {
  denyTools?: Iterable<string>
  askTools?: Iterable<string>
  now?: () => Date
  onDecision?: (request: ActionRequestV1, decision: ActionDecisionV1) => void
  onEvent?: (event: ActionEventV1) => void
  takeGrant?: (request: ActionRequestV1, policy: ActionPolicyV1, now: Date) => Promise<ActionGrantV1 | undefined>
  onStateError?: (error: unknown) => void
  pendingTimeoutMs?: number
}

export interface DshActionGate {
  pre(execution: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision>
  result(execution: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>): ActionEventV1 | undefined
  dispose(): void
}

type JsonRecord = Record<string, unknown>

type PendingAction = {
  request: ActionRequestV1
  decision: ActionDecisionV1
  startedAt: number
  timer: ReturnType<typeof setTimeout>
}

const PATH_TOOLS = new Map<string, { field: string, access: 'read' | 'write' | 'delete', operation: string }>([
  ['read', { field: 'file_path', access: 'read', operation: 'read' }],
  ['read_image', { field: 'file_path', access: 'read', operation: 'read-image' }],
  ['write', { field: 'file_path', access: 'write', operation: 'write' }],
  ['edit', { field: 'file_path', access: 'write', operation: 'edit' }],
])

function identifier(value: unknown, fallback: string, max: number): string {
  const normalized = String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim()
  return normalized ? normalized.slice(0, max) : fallback
}

function jsonRecord(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return undefined
  return value as JsonRecord
}

function stringArgument(argumentsValue: JsonRecord, field: string): string {
  const value = argumentsValue[field]
  if (typeof value !== 'string' || !value) throw new TypeError(`invalid ${field} argument`)
  return value
}

function requestId(execution: ToolExecution, profile: string, sessionId: string): string {
  const digest = createHash('sha256')
    .update([profile, sessionId, String(execution.rootCallId), String(execution.callId), execution.name].join('\u0000'))
    .digest('hex')
  return `act_${digest.slice(0, 40)}`
}

function commandRiskHints(command: string): string[] {
  const hints: string[] = []
  if (/(?:curl|wget)[^\r\n]*(?:\||&&|;)\s*(?:sh|bash|zsh|node|python)(?:\s|$)/iu.test(command)) {
    hints.push('download-then-execute')
  }
  if (/(?:\bbase64\s+(?:--decode|-d)\b|\beval\b|\batob\s*\(|fromCharCode|\\x[0-9a-f]{2})/iu.test(command)) {
    hints.push('obfuscated-command')
  }
  if (/(?:^|[\s"'])(?:(?:~|\$HOME|\$\{HOME\}|\/Users\/[^/\s]+|\/home\/[^/\s]+|\/root)\/\.(?:ssh|aws|kube)(?:\/|\s|["']|$)|[^\s/]*(?:id_rsa|id_ed25519)(?:\s|["']|$))/u.test(command)) {
    hints.push('credential-shell-read')
  } else if (/(?:^|[\s/"'])(?:\.env(?:\.[^\s/"']+)?|\.npmrc|\.pypirc|\.netrc|credentials)(?:\s|["']|$)/u.test(command)) {
    hints.push('sensitive-shell-read')
  }
  return hints
}

function urlHasSensitiveQuery(input: string): boolean {
  try {
    const url = new URL(input)
    if (url.username || url.password) return true
    for (const [key, value] of url.searchParams) {
      if (/(?:api[_-]?key|auth(?:orization)?|password|private[_-]?key|secret|token)/iu.test(key) && value.length >= 8) return true
      if (actionContainsLikelySecret(value)) return true
    }
    return false
  } catch {
    return false
  }
}

function commandNetworkResources(command: string): ActionResource[] {
  const values = command.match(/https?:\/\/[^\s"'<>|)]+/giu) ?? []
  const sendsData = /(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode)?|-F|--form|--upload-file|-T)(?:\s|=)/u.test(command)
  return [...new Set(values)].slice(0, 8).map((url) => normalizeNetworkResource(url, sendsData || urlHasSensitiveQuery(url) ? 'send' : 'fetch'))
}

function simpleShellWords(command: string): string[] | undefined {
  const words: string[] = []
  let current = ''
  let quote: "'" | '"' | undefined
  const push = () => { if (current) { words.push(current); current = '' } }
  for (let index = 0; index < command.length; index += 1) {
    const character = command[index] ?? ''
    if (quote === "'") {
      if (character === "'") quote = undefined
      else current += character
      continue
    }
    if (quote === '"') {
      if (character === '"') { quote = undefined; continue }
      if (character === '$' || character === '`') return undefined
      if (character === '\\') {
        const next = command[index + 1]
        if (next === undefined) return undefined
        current += next
        index += 1
      } else current += character
      continue
    }
    if (/[;&|<>`$()#!\r\n]/u.test(character)) return undefined
    if (/\s/u.test(character)) { push(); continue }
    if (character === "'" || character === '"') { quote = character; continue }
    if (character === '\\') {
      const next = command[index + 1]
      if (next === undefined) return undefined
      current += next
      index += 1
      continue
    }
    current += character
  }
  if (quote) return undefined
  push()
  return words
}

function simpleRmTargets(command: string): string[] {
  const words = simpleShellWords(command)
  if (!words || !/(?:^|\/)rm$/u.test(words[0] ?? '')) return []
  const targets: string[] = []
  let afterOptions = false
  for (const word of words.slice(1)) {
    if (!afterOptions && word === '--') { afterOptions = true; continue }
    if (!afterOptions && word.startsWith('-')) continue
    if (/[*?[\]{}~]/u.test(word)) return []
    targets.push(word)
    if (targets.length > 64) return []
  }
  return targets
}

function looksLikeSecretExfiltration(command: string, resources: ActionResource[]): boolean {
  const sends = resources.some((resource) => resource.kind === 'network' && resource.direction === 'send')
  const invokesNetworkClient = /(?:^|\s|[;&|])(?:curl|wget)(?:\s|$)/u.test(command)
  const secretSource = /(?:process\.env|\$(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\b|\.env\b|\.ssh\/|id_(?:rsa|ed25519)\b)/u.test(command)
  return (sends || invokesNetworkClient) && secretSource
}

function decision(
  request: ActionRequestV1,
  effect: ActionDecisionV1['effect'],
  ruleId: string,
  risk: ActionDecisionV1['risk'],
  reason: string,
): ActionDecisionV1 {
  return {
    schemaVersion: 1,
    requestId: request.id,
    effect,
    ruleId,
    risk,
    reason,
    matchedResources: [],
    grantOptions: effect === 'ask' ? ['once'] : [],
  }
}

function adapterFailureRequest(execution: ToolExecution, options: DshActionAdapterOptions): AdaptedDshAction {
  const profile = identifier(options.profile, 'default', 256)
  const sessionId = execution.agent ? identifier(execution.agent.id, '[invalid-session]', 512) : '[agentless]'
  const cwd = execution.agent?.session.header.cwd ?? process.cwd()
  const roots = options.workspaceRoots.length > 0 ? options.workspaceRoots : [cwd]
  const policy = createDefaultActionPolicy(roots)
  policy.allowedNetworkDomains = options.allowedNetworkDomains
  return {
    policy,
    request: createActionRequest({
      id: requestId(execution, profile, sessionId),
      ...(options.now === undefined ? {} : { now: options.now }),
      profile,
      sessionId,
      toolName: identifier(execution.name, '[invalid-tool]', 512),
      operation: 'adapter-failed',
      arguments: {},
      riskHints: ['adapter-failed', ...(execution.agent ? [] : ['identity-missing'])],
    }),
  }
}

export function adaptDshToolExecution(execution: ToolExecution, options: DshActionAdapterOptions): AdaptedDshAction {
  const profile = identifier(options.profile, 'default', 256)
  const sessionId = execution.agent ? identifier(execution.agent.id, '[invalid-session]', 512) : '[agentless]'
  const cwd = execution.agent?.session.header.cwd ?? process.cwd()
  const roots = options.workspaceRoots.length > 0 ? options.workspaceRoots : [cwd]
  const policy = createDefaultActionPolicy(roots)
  policy.allowedNetworkDomains = options.allowedNetworkDomains

  const parsedArguments = jsonRecord(execution.arguments)
  if (!parsedArguments) throw new TypeError('tool arguments must be an object')

  const toolName = identifier(execution.name, '[invalid-tool]', 512)
  const resources: ActionResource[] = []
  const riskHints = execution.agent ? [] : ['identity-missing']
  let operation = 'invoke'
  let capabilities: ActionRequestV1['capabilities'] | undefined

  const pathTool = PATH_TOOLS.get(toolName)
  if (pathTool) {
    operation = pathTool.operation
    resources.push(normalizePathResource(stringArgument(parsedArguments, pathTool.field), pathTool.access, policy, cwd))
  } else if (toolName === 'bash') {
    operation = 'execute'
    const command = stringArgument(parsedArguments, 'command')
    const rmTargets = simpleRmTargets(command)
    resources.push(
      normalizeCommandResource(command, policy),
      ...rmTargets.map((target) => normalizePathResource(target, 'delete', policy, cwd, rmTargets.length)),
      ...commandNetworkResources(command),
    )
    riskHints.push(...commandRiskHints(command))
    if (looksLikeSecretExfiltration(command, resources)) riskHints.push('suspected-secret-exfiltration')
  } else if (toolName === 'web_fetch') {
    operation = 'fetch'
    const url = stringArgument(parsedArguments, 'url')
    const sendsSensitiveQuery = urlHasSensitiveQuery(url) || actionContainsLikelySecret(parsedArguments)
    resources.push(normalizeNetworkResource(url, sendsSensitiveQuery ? 'send' : 'fetch'))
    if (sendsSensitiveQuery) capabilities = ['network.fetch', 'network.send']
  } else if (toolName === 'web_search') {
    operation = 'search'
    resources.push({ kind: 'external', targetType: 'search-provider', target: 'configured-provider', irreversible: false })
    capabilities = ['network.send']
  } else if (toolName === 'run_code' || toolName === 'batch') {
    operation = 'dispatch'
    capabilities = []
  } else if (options.askUnknownTools) {
    riskHints.push('unknown-tool')
  }

  return {
    policy,
    request: createActionRequest({
      id: requestId(execution, profile, sessionId),
      ...(options.now === undefined ? {} : { now: options.now }),
      profile,
      sessionId,
      toolName,
      operation,
      arguments: parsedArguments,
      resources,
      ...(capabilities === undefined ? {} : { capabilities }),
      riskHints,
    }),
  }
}

function isApprovalDenial(result: Readonly<ToolExecutionResult>): boolean {
  if (!result.isError) return false
  if (result.error.info?.code === 'ABORTED_BEFORE_DISPATCH') return true
  return /(?:the user rejected tool|approval for tool .* was cancelled|requires approval(?:,| \()|no approval channel is available|no agent to route it through)/iu.test(result.error.message)
}

function approvalReason(request: ActionRequestV1, actionDecision: ActionDecisionV1): string {
  const resources = request.resources
    .map(summarizeActionResource)
    .slice(0, 4)
    .join(', ') || '[unscoped]'
  const irreversible = request.resources.some((resource) =>
    (resource.kind === 'path' && resource.access === 'delete') ||
    (resource.kind === 'external' && resource.irreversible),
  )
  return [
    actionDecision.reason,
    `Agent/session: ${request.sessionId}`,
    `Tool/action: ${request.toolName}/${request.operation}`,
    `Resource: ${resources}`,
    `Rule: ${actionDecision.ruleId} (${actionDecision.risk})`,
    `Reversibility: ${irreversible ? 'potentially irreversible' : 'not marked irreversible'}`,
    'Approval applies to this invocation only.',
  ].join('\n')
}

export function createDshActionGate(options: DshActionGateOptions): DshActionGate {
  const denyTools = new Set(options.denyTools ?? [])
  const askTools = new Set(options.askTools ?? [])
  const pending = new Map<object, PendingAction>()
  const now = options.now ?? (() => new Date())
  const pendingTimeoutMs = Math.max(1, options.pendingTimeoutMs ?? 30 * 60_000)
  let disposed = false

  function unknown(entry: PendingAction, errorCode: string): void {
    options.onEvent?.(createActionEvent(entry.request, entry.decision, 'unknown', {
      now: now(),
      durationMs: Math.max(0, Date.now() - entry.startedAt),
      errorCode,
    }))
  }

  function remember(execution: ToolExecution, request: ActionRequestV1, actionDecision: ActionDecisionV1, startedAt: number, notify = true): void {
    const previous = pending.get(execution)
    if (previous) clearTimeout(previous.timer)
    const timer = setTimeout(() => {
      const current = pending.get(execution)
      if (!current) return
      pending.delete(execution)
      unknown(current, 'RESULT_TIMEOUT')
    }, pendingTimeoutMs)
    timer.unref?.()
    pending.set(execution, { request, decision: actionDecision, startedAt, timer })
    if (notify) options.onDecision?.(request, actionDecision)
  }

  return {
    async pre(execution, next) {
      if (disposed) return { kind: 'deny', reason: 'DSH Guard Action Gate is no longer active.' }
      const startedAt = Date.now()
      let adapted: AdaptedDshAction
      try {
        adapted = adaptDshToolExecution(execution, { ...options, now: now() })
      } catch {
        adapted = adapterFailureRequest(execution, { ...options, now: now() })
        const failed = decision(adapted.request, 'deny', 'guard.adapter-failed', 'critical', 'DSH Guard could not safely normalize this action.')
        remember(execution, adapted.request, failed, startedAt)
        return { kind: 'deny', reason: failed.reason }
      }

      let actionDecision: ActionDecisionV1
      if (execution.signal.aborted) {
        actionDecision = decision(adapted.request, 'deny', 'guard.cancelled', 'medium', 'The action was cancelled before policy evaluation.')
      } else if (denyTools.has(execution.name)) {
        actionDecision = decision(adapted.request, 'deny', 'tool.exact-deny', 'critical', `DSH Guard denies the exact tool name ${adapted.request.toolName}.`)
      } else {
        try {
          actionDecision = evaluateAction(adapted.request, adapted.policy)
        } catch {
          actionDecision = decision(adapted.request, 'deny', 'guard.policy-failed', 'critical', 'DSH Guard policy evaluation failed closed.')
        }
        if (actionDecision.effect === 'allow' && askTools.has(execution.name)) {
          actionDecision = decision(adapted.request, 'ask', 'tool.exact-ask', 'high', `DSH Guard requires approval for the exact tool name ${adapted.request.toolName}.`)
        }
      }

      if (actionDecision.effect === 'ask' && actionDecision.ruleId !== 'tool.exact-ask' && options.takeGrant) {
        try {
          const grantNow = now()
          const grant = await options.takeGrant(adapted.request, adapted.policy, grantNow)
          if (grant) actionDecision = evaluateAction(adapted.request, adapted.policy, { grants: [grant], now: grantNow })
        } catch (error) {
          options.onStateError?.(error)
        }
      }

      remember(execution, adapted.request, actionDecision, startedAt, actionDecision.effect !== 'allow')
      if (actionDecision.effect === 'deny') return { kind: 'deny', reason: actionDecision.reason }
      if (actionDecision.effect === 'ask') return { kind: 'ask', reason: approvalReason(adapted.request, actionDecision) }

      const downstream = await next()
      if (downstream.kind !== 'allow') {
        const downstreamDecision = decision(
          adapted.request,
          downstream.kind,
          `dsh.downstream-${downstream.kind}`,
          downstream.kind === 'deny' ? 'high' : 'medium',
          downstream.kind === 'deny' ? 'Another DSH policy denied this action.' : 'Another DSH policy requires approval for this action.',
        )
        remember(execution, adapted.request, downstreamDecision, startedAt)
      } else {
        options.onDecision?.(adapted.request, actionDecision)
      }
      return downstream
    },

    result(execution, result) {
      const entry = pending.get(execution)
      if (!entry) return undefined
      pending.delete(execution)
      clearTimeout(entry.timer)
      const outcome = entry.decision.effect === 'deny'
        ? 'denied'
        : !result.isError
          ? entry.decision.effect === 'ask' ? 'approved' : 'succeeded'
          : entry.decision.effect === 'ask' && isApprovalDenial(result) ? 'denied' : 'failed'
      const event = createActionEvent(entry.request, entry.decision, outcome, {
        now: now(),
        durationMs: Math.max(0, Date.now() - entry.startedAt),
        ...(result.isError ? { errorCode: result.error.info?.code ?? (outcome === 'denied' ? 'POLICY_DENIED' : 'TOOL_FAILED') } : {}),
      })
      options.onEvent?.(event)
      return event
    },

    dispose() {
      if (disposed) return
      disposed = true
      for (const entry of pending.values()) {
        clearTimeout(entry.timer)
        unknown(entry, 'GATE_DISPOSED')
      }
      pending.clear()
    },
  }
}
