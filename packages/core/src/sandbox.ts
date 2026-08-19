import { constants as fsConstants } from 'node:fs'
import { access, chmod, copyFile, cp, lstat, mkdir, mkdtemp, realpath, rm, stat } from 'node:fs/promises'
import { homedir } from 'node:os'
import { basename, dirname, isAbsolute, join, parse, resolve, sep } from 'node:path'
import { spawn } from 'node:child_process'
import { sha256, sortableId, stableJson, isWithin } from './util.js'

export type SandboxNetworkMode = 'deny' | 'loopback' | 'unrestricted'

export interface SandboxPlanV1 {
  schemaVersion: 1
  id: string
  createdAt: string
  platform: 'darwin'
  profile: string
  network: SandboxNetworkMode
  nodePath: string
  dshBin: string
  dshRuntimeRoot: string
  sourceDshHome: string
  sourceProfile: string
  dshHome: string
  guardHome: string
  tempRoot: string
  workspaceRoots: string[]
  readOnlyPaths: string[]
  readWritePaths: string[]
  allowedEnvironmentNames: string[]
  policy: string
  policyHash: string
  warnings: string[]
}

export interface CreateSandboxPlanOptions {
  profile: string
  workspaceRoots: string[]
  dshBin: string
  sourceDshHome: string
  dshHome: string
  guardHome: string
  tempRoot: string
  network?: SandboxNetworkMode
  allowEnvironment?: string[]
  environment?: NodeJS.ProcessEnv
  nodePath?: string
  userHome?: string
  platform?: NodeJS.Platform
  now?: Date
}

export interface SandboxRuntimeV1 {
  root: string
  dshHome: string
  tempRoot: string
  sourceProfile: string
  runtimeProfile: string
}

const PROFILE_NAME = /^[a-zA-Z0-9_-]+$/
const ENVIRONMENT_NAME = /^[A-Z_][A-Z0-9_]*$/
const SHA256 = /^[a-f0-9]{64}$/
const NETWORK_MODES = new Set<SandboxNetworkMode>(['deny', 'loopback', 'unrestricted'])
const BASE_ENVIRONMENT_NAMES = [
  'DSH_GUARD_HOME', 'DSH_HOME', 'HOME', 'LANG', 'LC_ALL', 'NO_COLOR', 'PATH', 'TERM', 'TMPDIR',
] as const
const RESERVED_ENVIRONMENT_NAMES = new Set<string>(BASE_ENVIRONMENT_NAMES)
const SECRET_ENVIRONMENT_NAME = /(AUTH|COOKIE|CREDENTIAL|KEY|PASS(?:WORD)?|SECRET|TOKEN)/i
const INJECTION_ENVIRONMENT_NAME = /^(?:NODE_OPTIONS|NODE_PATH|DYLD_.*|LD_.*)$/
const MAX_PATHS = 128
const MAX_POLICY_BYTES = 1024 * 1024

async function copyOptionalRegularFile(source: string, destination: string, label: string): Promise<void> {
  try {
    const metadata = await lstat(source)
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`${label} must be a regular file`)
    await copyFile(source, destination)
    await chmod(destination, 0o600)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
}

export async function prepareSandboxRuntime(
  profile: string,
  sourceDshHomeInput: string,
  guardHomeInput: string,
): Promise<SandboxRuntimeV1> {
  if (!PROFILE_NAME.test(profile)) throw new Error(`Invalid profile name: ${profile}`)
  const [sourceDshHome, guardHome] = await Promise.all([
    canonicalDirectory(sourceDshHomeInput, 'Source DSH home'),
    canonicalDirectory(guardHomeInput, 'DSH Guard home'),
  ])
  if (overlaps(sourceDshHome, guardHome)) throw new Error('Source DSH home and DSH Guard home must not overlap')
  const sourceProfile = await canonicalDirectory(join(sourceDshHome, 'profiles', profile), 'Source DSH profile')
  if (!isWithin(sourceDshHome, sourceProfile)) throw new Error('Source DSH profile resolves outside DSH home')
  const runsRoot = join(guardHome, 'sandbox-runs')
  try {
    const metadata = await lstat(runsRoot)
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error('Sandbox runs root must be a real directory')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    await mkdir(runsRoot, { mode: 0o700 })
  }
  if (await realpath(runsRoot) !== runsRoot) throw new Error('Sandbox runs root must not resolve outside DSH Guard home')
  await chmod(runsRoot, 0o700)
  const root = await mkdtemp(join(runsRoot, 'run-'))
  await chmod(root, 0o700)
  const dshHome = join(root, 'dsh-home')
  const runtimeProfile = join(dshHome, 'profiles', profile)
  const tempRoot = join(root, 'tmp')
  try {
    await Promise.all([
      mkdir(join(dshHome, 'profiles'), { recursive: true, mode: 0o700 }),
      mkdir(join(dshHome, 'sessions'), { recursive: true, mode: 0o700 }),
      mkdir(join(dshHome, 'storages'), { recursive: true, mode: 0o700 }),
      mkdir(tempRoot, { recursive: true, mode: 0o700 }),
    ])
    await cp(sourceProfile, runtimeProfile, {
      recursive: true,
      dereference: false,
      verbatimSymlinks: true,
      preserveTimestamps: false,
    })
    await Promise.all([
      copyOptionalRegularFile(join(sourceDshHome, 'settings.yaml'), join(dshHome, 'settings.yaml'), 'DSH settings'),
      copyOptionalRegularFile(join(sourceDshHome, '.anonymous-user-id'), join(dshHome, '.anonymous-user-id'), 'DSH anonymous user id'),
    ])
    return {
      root: await realpath(root),
      dshHome: await realpath(dshHome),
      tempRoot: await realpath(tempRoot),
      sourceProfile,
      runtimeProfile: await realpath(runtimeProfile),
    }
  } catch (error) {
    await rm(root, { recursive: true, force: true })
    throw error
  }
}

export async function cleanupSandboxRuntime(runtimeRootInput: string, guardHomeInput: string): Promise<void> {
  const guardHome = await canonicalDirectory(guardHomeInput, 'DSH Guard home')
  const runsRoot = join(guardHome, 'sandbox-runs')
  const runtimeRoot = resolve(runtimeRootInput)
  if (!isWithin(runsRoot, runtimeRoot) || runtimeRoot === runsRoot || !basename(runtimeRoot).startsWith('run-')) {
    throw new Error(`Refusing to remove invalid sandbox runtime path: ${runtimeRoot}`)
  }
  const runsMetadata = await lstat(runsRoot)
  if (runsMetadata.isSymbolicLink() || !runsMetadata.isDirectory() || await realpath(runsRoot) !== runsRoot) {
    throw new Error('Refusing cleanup because sandbox runs root is no longer trusted')
  }
  let runtimeMetadata: Awaited<ReturnType<typeof lstat>>
  try {
    runtimeMetadata = await lstat(runtimeRoot)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  if (runtimeMetadata.isSymbolicLink()) {
    await rm(runtimeRoot, { force: true })
    return
  }
  if (!runtimeMetadata.isDirectory() || !isWithin(runsRoot, await realpath(runtimeRoot))) {
    throw new Error('Refusing cleanup because sandbox runtime path is no longer trusted')
  }
  await rm(runtimeRoot, { recursive: true, force: true })
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right))
}

function assertSafeText(value: string, label: string): void {
  if (!value || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} contains unsupported control characters`)
}

async function canonicalFile(input: string, label: string, executable = false): Promise<string> {
  assertSafeText(input, label)
  const path = await realpath(resolve(input))
  const metadata = await stat(path)
  if (!metadata.isFile()) throw new Error(`${label} must be a regular file: ${path}`)
  if (executable) await access(path, fsConstants.X_OK)
  return path
}

async function canonicalDirectory(input: string, label: string): Promise<string> {
  assertSafeText(input, label)
  const path = await realpath(resolve(input))
  const metadata = await stat(path)
  if (!metadata.isDirectory()) throw new Error(`${label} must be a directory: ${path}`)
  return path
}

function overlaps(left: string, right: string): boolean {
  return isWithin(left, right) || isWithin(right, left)
}

function assertWorkspaceRoot(
  workspace: string,
  protectedRoots: Array<{ path: string; label: string; allowDescendant?: boolean }>,
): void {
  if (workspace === parse(workspace).root) throw new Error('Workspace root cannot be the filesystem root')
  for (const protectedRoot of protectedRoots) {
    const collision = protectedRoot.allowDescendant
      ? workspace === protectedRoot.path || isWithin(workspace, protectedRoot.path)
      : overlaps(workspace, protectedRoot.path)
    if (collision) {
      throw new Error(`Workspace root overlaps ${protectedRoot.label}: ${workspace}`)
    }
  }
}

function dshRuntimeRoot(dshBin: string): string {
  const marker = `${sep}node_modules${sep}`
  const markerIndex = dshBin.indexOf(marker)
  if (markerIndex > 0) return dshBin.slice(0, markerIndex)
  return dirname(dirname(dshBin))
}

function sbplString(value: string): string {
  assertSafeText(value, 'SBPL string')
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`
}

function pathFilters(paths: string[], kind: 'literal' | 'subpath'): string[] {
  return paths.map((path) => `  (${kind} ${sbplString(path)})`)
}

function pathAncestors(paths: string[]): string[] {
  const ancestors = new Set<string>()
  for (const path of paths) {
    let cursor = dirname(path)
    for (;;) {
      ancestors.add(cursor)
      const parent = dirname(cursor)
      if (parent === cursor) break
      cursor = parent
    }
  }
  return uniqueSorted([...ancestors])
}

export interface CompileSandboxPolicyOptions {
  nodePath: string
  readOnlyDirectories: string[]
  readOnlyFiles: string[]
  readWriteDirectories: string[]
  network: SandboxNetworkMode
}

export function compileSandboxPolicy(options: CompileSandboxPolicyOptions): string {
  if (!NETWORK_MODES.has(options.network)) throw new Error(`Unsupported sandbox network mode: ${String(options.network)}`)
  const readOnlyDirectories = uniqueSorted(options.readOnlyDirectories)
  const readOnlyFiles = uniqueSorted(options.readOnlyFiles)
  const readWriteDirectories = uniqueSorted(options.readWriteDirectories)
  const allPaths = uniqueSorted([options.nodePath, ...readOnlyDirectories, ...readOnlyFiles, ...readWriteDirectories])
  const ancestors = pathAncestors(allPaths)
  const lines = [
    '(version 1)',
    '(deny default)',
    '(import "system.sb")',
    `(allow process-exec (literal ${sbplString(options.nodePath)}))`,
    '(allow process-fork)',
    '(allow file-read-metadata file-test-existence',
    ...pathFilters(ancestors, 'literal'),
    ')',
    '(allow file-read* file-test-existence',
    ...pathFilters(uniqueSorted([...readOnlyDirectories, ...readWriteDirectories]), 'subpath'),
    ...pathFilters(readOnlyFiles, 'literal'),
    ')',
    '(allow file-write*',
    ...pathFilters(readWriteDirectories, 'subpath'),
    ')',
    '(allow network-bind network-inbound (local tcp "localhost:*"))',
  ]
  if (options.network === 'loopback') lines.push('(allow network-outbound (remote tcp "localhost:*"))')
  if (options.network === 'unrestricted') lines.push('(allow network-outbound)')
  const policy = `${lines.join('\n')}\n`
  if (Buffer.byteLength(policy) > MAX_POLICY_BYTES) throw new Error('Compiled sandbox policy exceeds 1 MiB')
  return policy
}

function validateAllowEnvironment(names: string[], environment: NodeJS.ProcessEnv): { names: string[]; warnings: string[] } {
  const allowed: string[] = []
  const warnings: string[] = []
  for (const name of uniqueSorted(names)) {
    if (!ENVIRONMENT_NAME.test(name)) throw new Error(`Invalid environment variable name: ${name}`)
    if (RESERVED_ENVIRONMENT_NAMES.has(name) || INJECTION_ENVIRONMENT_NAME.test(name)) {
      throw new Error(`Environment variable cannot be passed through: ${name}`)
    }
    if (environment[name] === undefined) throw new Error(`Requested environment variable is not set: ${name}`)
    allowed.push(name)
    if (SECRET_ENVIRONMENT_NAME.test(name)) {
      warnings.push(`High risk: ${name} is visible to every plugin in the sandboxed DSH process.`)
    }
  }
  return { names: allowed, warnings }
}

export async function createSandboxPlan(options: CreateSandboxPlanOptions): Promise<SandboxPlanV1> {
  if ((options.platform ?? process.platform) !== 'darwin') throw new Error('The experimental OS sandbox launcher currently supports macOS only')
  if (!PROFILE_NAME.test(options.profile)) throw new Error(`Invalid profile name: ${options.profile}`)
  if (!Array.isArray(options.workspaceRoots) || options.workspaceRoots.length === 0 || options.workspaceRoots.length > MAX_PATHS) {
    throw new Error(`At least one and at most ${MAX_PATHS} workspace roots are required`)
  }
  const network = options.network ?? 'loopback'
  if (!NETWORK_MODES.has(network)) throw new Error(`Unsupported sandbox network mode: ${String(network)}`)

  const [nodePath, dshBin, sourceDshHome, dshHome, guardHome, tempRoot] = await Promise.all([
    canonicalFile(options.nodePath ?? process.execPath, 'Node executable', true),
    canonicalFile(options.dshBin, 'DSH launcher'),
    canonicalDirectory(options.sourceDshHome, 'Source DSH home'),
    canonicalDirectory(options.dshHome, 'DSH home'),
    canonicalDirectory(options.guardHome, 'DSH Guard home'),
    canonicalDirectory(options.tempRoot, 'Sandbox temporary directory'),
  ])
  const nodeRuntimeRoot = await canonicalDirectory(dirname(dirname(nodePath)), 'Node runtime root')
  const dshRoot = await canonicalDirectory(dshRuntimeRoot(dshBin), 'DSH runtime root')
  if (!isWithin(dshRoot, dshBin)) throw new Error('DSH launcher is outside the resolved DSH runtime root')
  if (!isWithin(guardHome, dshHome) || dshHome === guardHome) {
    throw new Error('Sandbox DSH home must be a disposable runtime inside DSH Guard home')
  }
  if (!isWithin(guardHome, tempRoot)) throw new Error('Sandbox temporary directory must be inside DSH Guard home')
  if (overlaps(sourceDshHome, guardHome)) throw new Error('Source DSH home and DSH Guard home must not overlap')
  if (overlaps(dshRoot, guardHome) || overlaps(nodeRuntimeRoot, guardHome)) {
    throw new Error('Executable runtime roots must not overlap writable DSH Guard state')
  }

  const workspaceRoots = uniqueSorted(await Promise.all(options.workspaceRoots.map((path, index) => (
    canonicalDirectory(path, `Workspace root ${index + 1}`)
  ))))
  const userHome = await canonicalDirectory(options.userHome ?? homedir(), 'User home')
  const protectedRoots = [
    { path: userHome, label: 'the user home', allowDescendant: true },
    { path: sourceDshHome, label: 'the source DSH home' },
    { path: dshHome, label: 'DSH home' },
    { path: guardHome, label: 'DSH Guard home' },
    { path: nodeRuntimeRoot, label: 'Node runtime' },
    { path: dshRoot, label: 'DSH runtime' },
    { path: join(userHome, '.ssh'), label: 'SSH credentials' },
    { path: join(userHome, '.gnupg'), label: 'GnuPG credentials' },
    { path: join(userHome, '.aws'), label: 'AWS credentials' },
    { path: join(userHome, '.config', 'gcloud'), label: 'Google Cloud credentials' },
    { path: join(userHome, 'Library', 'Keychains'), label: 'macOS Keychains' },
    { path: join(userHome, 'Library', 'Application Support', 'Google', 'Chrome'), label: 'Chrome profile data' },
  ]
  workspaceRoots.forEach((workspace) => assertWorkspaceRoot(workspace, protectedRoots))
  for (let left = 0; left < workspaceRoots.length; left += 1) {
    for (let right = left + 1; right < workspaceRoots.length; right += 1) {
      if (overlaps(workspaceRoots[left]!, workspaceRoots[right]!)) {
        throw new Error(`Workspace roots overlap: ${workspaceRoots[left]} and ${workspaceRoots[right]}`)
      }
    }
  }

  const profileRoot = await canonicalDirectory(join(dshHome, 'profiles', options.profile), 'DSH profile')
  if (!isWithin(dshHome, profileRoot)) throw new Error('DSH profile resolves outside DSH home')
  const sourceProfile = await canonicalDirectory(join(sourceDshHome, 'profiles', options.profile), 'Source DSH profile')
  if (!isWithin(sourceDshHome, sourceProfile)) throw new Error('Source DSH profile resolves outside source DSH home')
  const { names: extraEnvironmentNames, warnings: environmentWarnings } = validateAllowEnvironment(
    options.allowEnvironment ?? [],
    options.environment ?? process.env,
  )
  const readOnlyDirectories = uniqueSorted([
    nodeRuntimeRoot,
    dshRoot,
  ])
  const readOnlyFiles: string[] = []
  const readWriteDirectories = uniqueSorted([
    guardHome,
    dshHome,
    tempRoot,
    profileRoot,
    ...workspaceRoots,
  ])
  const policy = compileSandboxPolicy({ nodePath, readOnlyDirectories, readOnlyFiles, readWriteDirectories, network })
  const warnings = [
    'Experimental: sandbox-exec and SBPL are deprecated private macOS interfaces.',
    'This is a whole-process sandbox; every loaded plugin shares all allowed paths and environment variables.',
    'DSH runs from a writable disposable profile copy; the verified source profile is not visible in the sandbox.',
    'DSH Guard state remains writable for Action Gate operation and is not tamper-proof against an in-process plugin.',
    'Arbitrary executable launch is blocked, so DSH Bash/process tools will not work.',
    ...(network === 'unrestricted' ? ['High risk: unrestricted outbound network can exfiltrate any data visible to DSH.'] : []),
    ...environmentWarnings,
  ]
  const now = options.now ?? new Date()
  return parseSandboxPlan({
    schemaVersion: 1,
    id: sortableId('sbx', now),
    createdAt: now.toISOString(),
    platform: 'darwin',
    profile: options.profile,
    network,
    nodePath,
    dshBin,
    dshRuntimeRoot: dshRoot,
    sourceDshHome,
    sourceProfile,
    dshHome,
    guardHome,
    tempRoot,
    workspaceRoots,
    readOnlyPaths: uniqueSorted([...readOnlyDirectories, ...readOnlyFiles]),
    readWritePaths: readWriteDirectories,
    allowedEnvironmentNames: uniqueSorted([...BASE_ENVIRONMENT_NAMES, ...extraEnvironmentNames]),
    policy,
    policyHash: sha256(policy),
    warnings,
  })
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  return value as Record<string, unknown>
}

function textValue(value: unknown, label: string, max = 65_536): string {
  if (typeof value !== 'string' || !value || value.length > max || /\u0000/.test(value)) throw new Error(`${label} is invalid`)
  return value
}

function stringArray(value: unknown, label: string, max = MAX_PATHS): string[] {
  if (!Array.isArray(value) || value.length > max) throw new Error(`${label} must contain at most ${max} entries`)
  return value.map((item, index) => textValue(item, `${label}[${index}]`, 4096))
}

function exactKeys(value: Record<string, unknown>, keys: string[], label: string): void {
  const expected = new Set(keys)
  for (const key of keys) if (!Object.hasOwn(value, key)) throw new Error(`${label}.${key} is required`)
  for (const key of Object.keys(value)) if (!expected.has(key)) throw new Error(`${label}.${key} is not supported`)
}

function parsedPath(value: unknown, label: string): string {
  const path = textValue(value, label, 4096)
  if (!isAbsolute(path)) throw new Error(`${label} must be absolute`)
  assertSafeText(path, label)
  return path
}

function sortedUniqueArray(value: unknown, label: string, validatePath = false): string[] {
  const entries = stringArray(value, label)
  const parsed = entries.map((entry, index) => validatePath ? parsedPath(entry, `${label}[${index}]`) : entry)
  if (new Set(parsed).size !== parsed.length) throw new Error(`${label} contains duplicates`)
  if (parsed.some((entry, index) => index > 0 && parsed[index - 1]!.localeCompare(entry) >= 0)) {
    throw new Error(`${label} must be sorted`)
  }
  return parsed
}

export function parseSandboxPlan(value: unknown): SandboxPlanV1 {
  const item = record(value, 'SandboxPlanV1')
  exactKeys(item, [
    'schemaVersion', 'id', 'createdAt', 'platform', 'profile', 'network', 'nodePath', 'dshBin',
    'dshRuntimeRoot', 'sourceDshHome', 'sourceProfile', 'dshHome', 'guardHome', 'tempRoot', 'workspaceRoots', 'readOnlyPaths',
    'readWritePaths', 'allowedEnvironmentNames', 'policy', 'policyHash', 'warnings',
  ], 'SandboxPlanV1')
  if (item.schemaVersion !== 1) throw new Error('SandboxPlanV1.schemaVersion is unsupported')
  if (item.platform !== 'darwin') throw new Error('SandboxPlanV1.platform is unsupported')
  const id = textValue(item.id, 'SandboxPlanV1.id', 256)
  if (!/^sbx_[a-zA-Z0-9_]+$/.test(id)) throw new Error('SandboxPlanV1.id is invalid')
  const createdAt = textValue(item.createdAt, 'SandboxPlanV1.createdAt', 64)
  if (!Number.isFinite(Date.parse(createdAt))) throw new Error('SandboxPlanV1.createdAt is not an ISO timestamp')
  const profile = textValue(item.profile, 'SandboxPlanV1.profile', 256)
  if (!PROFILE_NAME.test(profile)) throw new Error('SandboxPlanV1.profile is invalid')
  if (typeof item.network !== 'string' || !NETWORK_MODES.has(item.network as SandboxNetworkMode)) {
    throw new Error('SandboxPlanV1.network is invalid')
  }
  const policy = textValue(item.policy, 'SandboxPlanV1.policy', MAX_POLICY_BYTES)
  const policyHash = textValue(item.policyHash, 'SandboxPlanV1.policyHash', 64)
  if (!SHA256.test(policyHash) || sha256(policy) !== policyHash) throw new Error('SandboxPlanV1 policy hash mismatch')
  const allowedEnvironmentNames = sortedUniqueArray(item.allowedEnvironmentNames, 'SandboxPlanV1.allowedEnvironmentNames')
  if (allowedEnvironmentNames.some((name) => !ENVIRONMENT_NAME.test(name))) {
    throw new Error('SandboxPlanV1.allowedEnvironmentNames contains an invalid name')
  }
  return {
    schemaVersion: 1,
    id,
    createdAt,
    platform: 'darwin',
    profile,
    network: item.network as SandboxNetworkMode,
    nodePath: parsedPath(item.nodePath, 'SandboxPlanV1.nodePath'),
    dshBin: parsedPath(item.dshBin, 'SandboxPlanV1.dshBin'),
    dshRuntimeRoot: parsedPath(item.dshRuntimeRoot, 'SandboxPlanV1.dshRuntimeRoot'),
    sourceDshHome: parsedPath(item.sourceDshHome, 'SandboxPlanV1.sourceDshHome'),
    sourceProfile: parsedPath(item.sourceProfile, 'SandboxPlanV1.sourceProfile'),
    dshHome: parsedPath(item.dshHome, 'SandboxPlanV1.dshHome'),
    guardHome: parsedPath(item.guardHome, 'SandboxPlanV1.guardHome'),
    tempRoot: parsedPath(item.tempRoot, 'SandboxPlanV1.tempRoot'),
    workspaceRoots: sortedUniqueArray(item.workspaceRoots, 'SandboxPlanV1.workspaceRoots', true),
    readOnlyPaths: sortedUniqueArray(item.readOnlyPaths, 'SandboxPlanV1.readOnlyPaths', true),
    readWritePaths: sortedUniqueArray(item.readWritePaths, 'SandboxPlanV1.readWritePaths', true),
    allowedEnvironmentNames,
    policy,
    policyHash,
    warnings: stringArray(item.warnings, 'SandboxPlanV1.warnings', 128),
  }
}

export function sandboxPlanDigest(plan: SandboxPlanV1): string {
  return sha256(stableJson(parseSandboxPlan(plan)))
}

export function buildSandboxEnvironment(
  planValue: SandboxPlanV1,
  source: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const plan = parseSandboxPlan(planValue)
  const environment: NodeJS.ProcessEnv = {
    PATH: `${dirname(plan.nodePath)}:/usr/bin:/bin`,
    HOME: homedir(),
    DSH_HOME: plan.dshHome,
    DSH_GUARD_HOME: plan.guardHome,
    TMPDIR: plan.tempRoot,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NO_COLOR: '1',
  }
  if (source.TERM && /^[a-zA-Z0-9._+-]{1,128}$/.test(source.TERM)) environment.TERM = source.TERM
  for (const name of plan.allowedEnvironmentNames) {
    if (RESERVED_ENVIRONMENT_NAMES.has(name)) continue
    if (INJECTION_ENVIRONMENT_NAME.test(name)) throw new Error(`Unsafe environment name in sandbox plan: ${name}`)
    const value = source[name]
    if (value === undefined) throw new Error(`Environment variable is no longer set: ${name}`)
    environment[name] = value
  }
  return environment
}

export function validateSandboxEnvironment(planValue: SandboxPlanV1, environment: NodeJS.ProcessEnv): void {
  const plan = parseSandboxPlan(planValue)
  const allowed = new Set(plan.allowedEnvironmentNames)
  for (const name of Object.keys(environment)) {
    if (!allowed.has(name)) throw new Error(`Environment contains a variable outside the sandbox plan: ${name}`)
    if (INJECTION_ENVIRONMENT_NAME.test(name)) throw new Error(`Environment contains an unsafe injection variable: ${name}`)
  }
  const expected = {
    PATH: `${dirname(plan.nodePath)}:/usr/bin:/bin`,
    HOME: homedir(),
    DSH_HOME: plan.dshHome,
    DSH_GUARD_HOME: plan.guardHome,
    TMPDIR: plan.tempRoot,
    NO_COLOR: '1',
  }
  for (const [name, value] of Object.entries(expected)) {
    if (environment[name] !== value) throw new Error(`Sandbox environment has an invalid ${name} value`)
  }
  for (const name of ['LANG', 'LC_ALL']) {
    if (!environment[name]) throw new Error(`Sandbox environment is missing ${name}`)
  }
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]'])

export function validateSandboxAppArgs(args: string[]): void {
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]
    if (argument === undefined) continue
    if (argument === '--profile' || argument.startsWith('--profile=')) {
      throw new Error('DSH app arguments cannot override the verified --profile')
    }
    if (argument === '--host') {
      const host = args[index + 1]
      if (!host || host.startsWith('-')) throw new Error('--host requires a loopback address')
      if (!LOOPBACK_HOSTS.has(host.toLowerCase())) throw new Error(`Sandboxed DSH can only bind loopback, not ${host}`)
      index += 1
    } else if (argument.startsWith('--host=')) {
      const host = argument.slice('--host='.length).toLowerCase()
      if (!LOOPBACK_HOSTS.has(host)) throw new Error(`Sandboxed DSH can only bind loopback, not ${host || '(empty)'}`)
    }
  }
}

export interface RunSandboxOptions {
  sandboxExecPath?: string
  platform?: NodeJS.Platform
  signalTarget?: NodeJS.Process
}

export async function runSandboxedDsh(
  planValue: SandboxPlanV1,
  appArgs: string[],
  environment: NodeJS.ProcessEnv,
  options: RunSandboxOptions = {},
): Promise<number> {
  if ((options.platform ?? process.platform) !== 'darwin') throw new Error('The experimental OS sandbox launcher currently supports macOS only')
  const plan = parseSandboxPlan(planValue)
  validateSandboxAppArgs(appArgs)
  validateSandboxEnvironment(plan, environment)
  const sandboxExec = await canonicalFile(options.sandboxExecPath ?? '/usr/bin/sandbox-exec', 'sandbox-exec', true)
  const signalTarget = options.signalTarget ?? process
  return new Promise<number>((resolvePromise, reject) => {
    const child = spawn(sandboxExec, [
      '-p', plan.policy, plan.nodePath, plan.dshBin, '--profile', plan.profile, ...appArgs,
    ], {
      cwd: plan.workspaceRoots[0],
      env: environment,
      shell: false,
      stdio: 'inherit',
    })
    const forward = (signal: NodeJS.Signals): void => { if (!child.killed) child.kill(signal) }
    const onSigint = (): void => forward('SIGINT')
    const onSigterm = (): void => forward('SIGTERM')
    const cleanup = (): void => {
      signalTarget.off('SIGINT', onSigint)
      signalTarget.off('SIGTERM', onSigterm)
    }
    signalTarget.on('SIGINT', onSigint)
    signalTarget.on('SIGTERM', onSigterm)
    child.once('error', (error) => { cleanup(); reject(error) })
    child.once('close', (code, signal) => {
      cleanup()
      if (code !== null) resolvePromise(code)
      else resolvePromise(signal === 'SIGINT' ? 130 : signal === 'SIGTERM' ? 143 : 1)
    })
  })
}
