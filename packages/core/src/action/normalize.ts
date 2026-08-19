import { homedir } from 'node:os'
import { realpathSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path'
import type {
  ActionCapability,
  ActionPolicyV1,
  ActionRequestV1,
  ActionResource,
  CommandActionResource,
  CreateActionRequestInput,
  NetworkActionResource,
  PathActionResource,
} from './types.js'
import { parseActionRequest } from './schema.js'
import { sortableId } from '../util.js'

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function slash(path: string): string {
  return path.split(sep).join('/')
}

function expandHome(pattern: string): string {
  return pattern === '~' ? homedir() : pattern.startsWith('~/') ? resolve(homedir(), pattern.slice(2)) : pattern
}

function globExpression(pattern: string): RegExp {
  const normalized = slash(expandHome(pattern))
  let source = '^'
  for (let index = 0; index < normalized.length; index += 1) {
    const character = normalized[index]
    if (character === '*') {
      if (normalized[index + 1] === '*') {
        index += 1
        if (normalized[index + 1] === '/') {
          index += 1
          source += '(?:.*/)?'
        } else {
          source += '.*'
        }
      } else {
        source += '[^/]*'
      }
      continue
    }
    if (character === '?') {
      source += '[^/]'
      continue
    }
    source += character?.replace(/[|\\{}()[\]^$+?.-]/g, '\\$&') ?? ''
  }
  return new RegExp(`${source}$`)
}

export function matchesPathPattern(path: string, pattern: string): boolean {
  try {
    return globExpression(pattern).test(slash(path))
  } catch {
    return false
  }
}

export function isPathWithin(root: string, candidate: string): boolean {
  const relationship = relative(resolve(root), resolve(candidate))
  return relationship === '' || (!relationship.startsWith(`..${sep}`) && relationship !== '..' && !isAbsolute(relationship))
}

function canonicalPath(input: string): string | undefined {
  const absolute = resolve(input)
  let cursor = absolute
  const suffix: string[] = []
  while (true) {
    try {
      return join(realpathSync.native(cursor), ...suffix.reverse())
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code !== 'ENOENT') return undefined
      const parent = dirname(cursor)
      if (parent === cursor || cursor === parse(cursor).root) return undefined
      suffix.push(basename(cursor))
      cursor = parent
    }
  }
}

function pathSensitivity(path: string, policy: ActionPolicyV1): PathActionResource['sensitivity'] {
  if (policy.credentialPathPatterns.some((pattern) => matchesPathPattern(path, pattern))) return 'credential'
  if (policy.sensitivePathPatterns.some((pattern) => matchesPathPattern(path, pattern))) return 'sensitive'
  return 'normal'
}

export function normalizePathResource(
  input: string,
  access: PathActionResource['access'],
  policy: ActionPolicyV1,
  cwd = process.cwd(),
  targetCount?: number,
): PathActionResource {
  if (!input || input.includes('\u0000')) {
    return {
      kind: 'path',
      path: '[invalid-path]',
      access,
      scope: 'unknown',
      sensitivity: 'sensitive',
      ...(targetCount === undefined ? {} : { targetCount }),
    }
  }

  try {
    const lexicalPath = resolve(cwd, input)
    const path = canonicalPath(lexicalPath)
    if (!path) throw new Error('Path could not be canonicalized')
    const scope = policy.workspaceRoots.some((root) => {
      const canonicalRoot = canonicalPath(root)
      return canonicalRoot ? isPathWithin(canonicalRoot, path) : false
    }) ? 'workspace' : 'outside'
    return {
      kind: 'path',
      path,
      access,
      scope,
      sensitivity: pathSensitivity(path, policy),
      ...(targetCount === undefined ? {} : { targetCount }),
    }
  } catch {
    return {
      kind: 'path',
      path: '[invalid-path]',
      access,
      scope: 'unknown',
      sensitivity: 'sensitive',
      ...(targetCount === undefined ? {} : { targetCount }),
    }
  }
}

function firstCommandToken(command: string): string {
  const match = command.trim().match(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*([^\s]+)/)
  return match?.[1]?.replace(/^['"]|['"]$/g, '') ?? ''
}

function matchesRegexList(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    try {
      return new RegExp(pattern, 'u').test(value)
    } catch {
      return false
    }
  })
}

export function normalizeCommandResource(command: string, policy: ActionPolicyV1): CommandActionResource {
  const normalized = command.trim()
  const containsShellControl = /(?:[;&|`<>]|\$\(|[\r\n])/u.test(normalized)
  const containsKnownWriteOrExecFlag = /^\s*(?:git\s+(?:diff|log|show)\b[^\r\n]*--(?:output|ext-diff|textconv)\b|rg\b[^\r\n]*--pre(?:=|\s))/u.test(normalized)
  return {
    kind: 'command',
    command: normalized,
    executable: firstCommandToken(normalized),
    readOnly: !containsShellControl && !containsKnownWriteOrExecFlag && matchesRegexList(normalized, policy.readOnlyCommandPatterns),
  }
}

export function normalizeNetworkResource(input: string, direction: NetworkActionResource['direction']): NetworkActionResource {
  try {
    const url = new URL(input)
    const port = url.port ? Number(url.port) : undefined
    return {
      kind: 'network',
      direction,
      host: url.hostname.toLowerCase(),
      scheme: url.protocol.replace(/:$/, '').toLowerCase(),
      ...(port === undefined || !Number.isInteger(port) ? {} : { port }),
    }
  } catch {
    return { kind: 'network', direction, host: '[invalid-host]' }
  }
}

export function deriveCapabilities(resources: ActionResource[]): ActionCapability[] {
  const capabilities: ActionCapability[] = []
  for (const resource of resources) {
    if (resource.kind === 'path') {
      capabilities.push(`filesystem.${resource.access}`)
      if (resource.access === 'read' && resource.sensitivity === 'credential') capabilities.push('credential.read')
    } else if (resource.kind === 'command') {
      capabilities.push('process.execute')
    } else if (resource.kind === 'network') {
      capabilities.push(`network.${resource.direction}`)
    } else if (resource.irreversible) {
      capabilities.push('external.irreversible')
    }
  }
  return unique(capabilities)
}

export function createActionRequest(input: CreateActionRequestInput): ActionRequestV1 {
  const now = input.now ?? new Date()
  const resources = input.resources ?? []
  return parseActionRequest({
    schemaVersion: 1,
    id: input.id ?? sortableId('act', now),
    createdAt: now.toISOString(),
    profile: input.profile,
    sessionId: input.sessionId,
    ...(input.taskId === undefined ? {} : { taskId: input.taskId }),
    toolName: input.toolName,
    operation: input.operation,
    arguments: input.arguments ?? {},
    resources,
    capabilities: unique(input.capabilities ?? deriveCapabilities(resources)),
    riskHints: unique(input.riskHints ?? []),
  })
}

export function resourceDisplayName(resource: ActionResource): string {
  if (resource.kind === 'path') return resource.path
  if (resource.kind === 'command') return resource.executable || '[command]'
  if (resource.kind === 'network') return resource.host
  return `${resource.targetType}:${basename(resource.target) || resource.target}`
}
