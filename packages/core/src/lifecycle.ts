import { randomUUID } from 'node:crypto'
import { lstat, mkdir, open, readFile, readdir, rename, rm } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import type {
  GenerationSnapshotFileV1,
  GenerationSnapshotManifestV1,
  InstallRecord,
  LifecycleAction,
  ManagedPluginV1,
  ManagedProfileV1,
  ProfileGenerationV1,
  ProfileSnapshot,
} from './types.js'
import type { StatePaths } from './state.js'
import { initState, loadInstall, loadReport } from './state.js'
import { PROFILE_FILES, snapshotProfile } from './profile.js'
import { atomicWrite, ensurePrivateDir, sha256, sortableId, stableJson } from './util.js'

export { statePaths } from './state.js'
export type { ManagedProfileV1 } from './types.js'

const PROFILE_NAME = /^[a-zA-Z0-9_-]+$/
const GENERATION_ID = /^gen_[a-zA-Z0-9_]+$/
const REPORT_ID = /^[a-zA-Z0-9_-]+$/
const SHA256 = /^[a-f0-9]{64}$/
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/
const MAX_GENERATIONS = 10_000
const MAX_PLUGINS = 10_000
const MAX_TEXT = 2_048
const MAX_MANAGED_STATE_BYTES = 16 * 1024 * 1024
const MAX_SNAPSHOT_FILE_BYTES = 32 * 1024 * 1024
const MAX_SNAPSHOT_MANIFEST_BYTES = 1024 * 1024

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  return value as Record<string, unknown>
}

function exactKeys(value: Record<string, unknown>, required: string[], optional: string[], label: string): void {
  const allowed = new Set([...required, ...optional])
  for (const key of required) if (!(key in value)) throw new Error(`${label}.${key} is required`)
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new Error(`${label}.${key} is not supported`)
}

function textValue(value: unknown, label: string, pattern?: RegExp): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_TEXT || (pattern && !pattern.test(value))) {
    throw new Error(`${label} is invalid`)
  }
  return value
}

function dateValue(value: unknown, label: string): string {
  const result = textValue(value, label)
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} is not an ISO timestamp`)
  return result
}

function stringArray(value: unknown, label: string, max = MAX_PLUGINS): string[] {
  if (!Array.isArray(value) || value.length > max) throw new Error(`${label} must be an array with at most ${max} entries`)
  return value.map((item, index) => textValue(item, `${label}[${index}]`))
}

function parsePlugin(value: unknown, label: string): ManagedPluginV1 {
  const item = record(value, label)
  exactKeys(item, ['schemaVersion', 'packageName', 'version', 'reportId', 'artifactSha256', 'installedAt', 'updatedAt', 'bundles'], [], label)
  if (item.schemaVersion !== 1) throw new Error(`${label}.schemaVersion is unsupported`)
  return {
    schemaVersion: 1,
    packageName: textValue(item.packageName, `${label}.packageName`, PACKAGE_NAME),
    version: textValue(item.version, `${label}.version`),
    reportId: textValue(item.reportId, `${label}.reportId`, REPORT_ID),
    artifactSha256: textValue(item.artifactSha256, `${label}.artifactSha256`, SHA256),
    installedAt: dateValue(item.installedAt, `${label}.installedAt`),
    updatedAt: dateValue(item.updatedAt, `${label}.updatedAt`),
    bundles: stringArray(item.bundles, `${label}.bundles`).map((bundle, index) => textValue(bundle, `${label}.bundles[${index}]`, PACKAGE_NAME)),
  }
}

function parseGeneration(value: unknown, label: string): ProfileGenerationV1 {
  const item = record(value, label)
  exactKeys(item, [
    'schemaVersion', 'id', 'profile', 'createdAt', 'action', 'profileFingerprint', 'bundles', 'plugins',
  ], ['parentGenerationId', 'restoredGenerationId', 'reportId', 'packageName', 'configHash'], label)
  if (item.schemaVersion !== 1) throw new Error(`${label}.schemaVersion is unsupported`)
  const actions = new Set<LifecycleAction>(['install', 'update', 'uninstall', 'repair', 'rollback', 'legacy-import'])
  if (typeof item.action !== 'string' || !actions.has(item.action as LifecycleAction)) throw new Error(`${label}.action is invalid`)
  if (!Array.isArray(item.plugins) || item.plugins.length > MAX_PLUGINS) throw new Error(`${label}.plugins is invalid`)
  const plugins = item.plugins.map((plugin, index) => parsePlugin(plugin, `${label}.plugins[${index}]`))
  if (new Set(plugins.map((plugin) => plugin.packageName)).size !== plugins.length) throw new Error(`${label}.plugins contains duplicate packages`)
  const parentGenerationId = item.parentGenerationId === undefined
    ? undefined
    : textValue(item.parentGenerationId, `${label}.parentGenerationId`, GENERATION_ID)
  const restoredGenerationId = item.restoredGenerationId === undefined
    ? undefined
    : textValue(item.restoredGenerationId, `${label}.restoredGenerationId`, GENERATION_ID)
  return {
    schemaVersion: 1,
    id: textValue(item.id, `${label}.id`, GENERATION_ID),
    profile: textValue(item.profile, `${label}.profile`, PROFILE_NAME),
    createdAt: dateValue(item.createdAt, `${label}.createdAt`),
    action: item.action as LifecycleAction,
    ...(parentGenerationId ? { parentGenerationId } : {}),
    ...(restoredGenerationId ? { restoredGenerationId } : {}),
    ...(item.reportId === undefined ? {} : { reportId: textValue(item.reportId, `${label}.reportId`, REPORT_ID) }),
    ...(item.packageName === undefined ? {} : { packageName: textValue(item.packageName, `${label}.packageName`, PACKAGE_NAME) }),
    profileFingerprint: textValue(item.profileFingerprint, `${label}.profileFingerprint`, SHA256),
    ...(item.configHash === undefined ? {} : { configHash: textValue(item.configHash, `${label}.configHash`, SHA256) }),
    bundles: stringArray(item.bundles, `${label}.bundles`).map((bundle, index) => textValue(bundle, `${label}.bundles[${index}]`, PACKAGE_NAME)),
    plugins,
  }
}

export function parseManagedProfile(value: unknown): ManagedProfileV1 {
  const item = record(value, 'ManagedProfileV1')
  exactKeys(item, ['schemaVersion', 'profile', 'createdAt', 'updatedAt', 'currentGenerationId', 'generations'], ['lastVerifiedAt'], 'ManagedProfileV1')
  if (item.schemaVersion !== 1) throw new Error('ManagedProfileV1.schemaVersion is unsupported')
  if (!Array.isArray(item.generations) || item.generations.length === 0 || item.generations.length > MAX_GENERATIONS) {
    throw new Error(`ManagedProfileV1.generations must contain 1-${MAX_GENERATIONS} entries`)
  }
  const profile = textValue(item.profile, 'ManagedProfileV1.profile', PROFILE_NAME)
  const generations = item.generations.map((generation, index) => parseGeneration(generation, `ManagedProfileV1.generations[${index}]`))
  if (generations.some((generation) => generation.profile !== profile)) throw new Error('ManagedProfileV1 generation profile mismatch')
  if (new Set(generations.map((generation) => generation.id)).size !== generations.length) throw new Error('ManagedProfileV1 contains duplicate generation ids')
  const currentGenerationId = textValue(item.currentGenerationId, 'ManagedProfileV1.currentGenerationId', GENERATION_ID)
  if (!generations.some((generation) => generation.id === currentGenerationId)) throw new Error('ManagedProfileV1 current generation is missing')
  return {
    schemaVersion: 1,
    profile,
    createdAt: dateValue(item.createdAt, 'ManagedProfileV1.createdAt'),
    updatedAt: dateValue(item.updatedAt, 'ManagedProfileV1.updatedAt'),
    ...(item.lastVerifiedAt === undefined ? {} : { lastVerifiedAt: dateValue(item.lastVerifiedAt, 'ManagedProfileV1.lastVerifiedAt') }),
    currentGenerationId,
    generations,
  }
}

function managedProfileFile(profile: string, paths: StatePaths): string {
  if (!PROFILE_NAME.test(profile)) throw new Error(`Invalid profile name: ${profile}`)
  return join(paths.managedProfiles, `${profile}.json`)
}

async function rejectSymlink(path: string, label: string): Promise<void> {
  const value = await lstat(path)
  if (value.isSymbolicLink()) throw new Error(`${label} must not be a symlink`)
}

async function readBoundedRegularFile(path: string, label: string, maxBytes: number): Promise<string> {
  const value = await lstat(path)
  if (value.isSymbolicLink() || !value.isFile()) throw new Error(`${label} must be a regular file`)
  if (value.size > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`)
  return readFile(path, 'utf8')
}

export async function loadManagedProfile(profile: string, paths: StatePaths): Promise<ManagedProfileV1 | undefined> {
  const file = managedProfileFile(profile, paths)
  try {
    return parseManagedProfile(JSON.parse(await readBoundedRegularFile(file, 'Managed profile state', MAX_MANAGED_STATE_BYTES)) as unknown)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
}

export async function saveManagedProfile(value: ManagedProfileV1, paths: StatePaths): Promise<void> {
  const parsed = parseManagedProfile(value)
  await initState(paths)
  await atomicWrite(managedProfileFile(parsed.profile, paths), stableJson(parsed))
}

export async function listManagedProfileNames(paths: StatePaths): Promise<string[]> {
  await initState(paths)
  const names = await readdir(paths.managedProfiles)
  return names
    .filter((name) => name.endsWith('.json') && PROFILE_NAME.test(basename(name, '.json')))
    .map((name) => basename(name, '.json'))
    .sort()
}

function snapshotDirectory(paths: StatePaths, profile: string, generationId: string): string {
  if (!PROFILE_NAME.test(profile) || !GENERATION_ID.test(generationId)) throw new Error('Invalid generation snapshot identity')
  return join(paths.generations, profile, generationId)
}

function parseSnapshotManifest(value: unknown): GenerationSnapshotManifestV1 {
  const item = record(value, 'GenerationSnapshotManifestV1')
  exactKeys(item, ['schemaVersion', 'profile', 'generationId', 'createdAt', 'profileFingerprint', 'files'], [], 'GenerationSnapshotManifestV1')
  if (item.schemaVersion !== 1) throw new Error('GenerationSnapshotManifestV1.schemaVersion is unsupported')
  if (!Array.isArray(item.files) || item.files.length !== PROFILE_FILES.length) throw new Error('Generation snapshot file set is incomplete')
  const files = item.files.map((value, index): GenerationSnapshotFileV1 => {
    const file = record(value, `GenerationSnapshotManifestV1.files[${index}]`)
    exactKeys(file, ['name', 'present'], ['sha256'], `GenerationSnapshotManifestV1.files[${index}]`)
    if (!PROFILE_FILES.includes(file.name as typeof PROFILE_FILES[number])) throw new Error('Generation snapshot contains an unsupported filename')
    if (typeof file.present !== 'boolean') throw new Error('Generation snapshot present flag is invalid')
    if (file.present && (typeof file.sha256 !== 'string' || !SHA256.test(file.sha256))) throw new Error('Generation snapshot digest is invalid')
    if (!file.present && file.sha256 !== undefined) throw new Error('Missing generation snapshot file cannot have a digest')
    const digest = typeof file.sha256 === 'string' ? file.sha256 : undefined
    return { name: file.name as GenerationSnapshotFileV1['name'], present: file.present, ...(digest ? { sha256: digest } : {}) }
  })
  if (new Set(files.map((file) => file.name)).size !== PROFILE_FILES.length) throw new Error('Generation snapshot contains duplicate filenames')
  return {
    schemaVersion: 1,
    profile: textValue(item.profile, 'GenerationSnapshotManifestV1.profile', PROFILE_NAME),
    generationId: textValue(item.generationId, 'GenerationSnapshotManifestV1.generationId', GENERATION_ID),
    createdAt: dateValue(item.createdAt, 'GenerationSnapshotManifestV1.createdAt'),
    profileFingerprint: textValue(item.profileFingerprint, 'GenerationSnapshotManifestV1.profileFingerprint', SHA256),
    files,
  }
}

export async function createGenerationSnapshot(
  paths: StatePaths,
  snapshot: ProfileSnapshot,
  generationId: string,
  createdAt = new Date(),
): Promise<GenerationSnapshotManifestV1> {
  if (!PROFILE_NAME.test(snapshot.name) || !GENERATION_ID.test(generationId)) throw new Error('Invalid generation snapshot identity')
  await initState(paths)
  const profileDirectory = join(paths.generations, snapshot.name)
  await ensurePrivateDir(profileDirectory)
  const temporary = join(profileDirectory, `.tmp-${generationId}-${process.pid}-${randomUUID()}`)
  const target = snapshotDirectory(paths, snapshot.name, generationId)
  await mkdir(temporary, { mode: 0o700 })
  let renamed = false
  try {
    const files: GenerationSnapshotFileV1[] = []
    for (const name of PROFILE_FILES) {
      const contents = snapshot.files[name]
      if (contents === null || contents === undefined) {
        files.push({ name, present: false })
      } else {
        if (Buffer.byteLength(contents) > MAX_SNAPSHOT_FILE_BYTES) throw new Error(`Generation snapshot file exceeds 32 MiB: ${name}`)
        await atomicWrite(join(temporary, name), contents)
        files.push({ name, present: true, sha256: sha256(contents) })
      }
    }
    const manifest: GenerationSnapshotManifestV1 = {
      schemaVersion: 1,
      profile: snapshot.name,
      generationId,
      createdAt: createdAt.toISOString(),
      profileFingerprint: snapshot.fingerprint,
      files,
    }
    await atomicWrite(join(temporary, 'manifest.json'), stableJson(manifest))
    await rename(temporary, target)
    renamed = true
    const directory = await open(profileDirectory, 'r')
    try { await directory.sync() } finally { await directory.close() }
    return manifest
  } finally {
    if (!renamed) await rm(temporary, { recursive: true, force: true })
  }
}

export async function readGenerationSnapshot(
  paths: StatePaths,
  profile: string,
  generationId: string,
): Promise<ProfileSnapshot> {
  const directory = snapshotDirectory(paths, profile, generationId)
  await rejectSymlink(directory, 'Generation snapshot directory')
  const manifestPath = join(directory, 'manifest.json')
  const manifest = parseSnapshotManifest(JSON.parse(await readBoundedRegularFile(manifestPath, 'Generation snapshot manifest', MAX_SNAPSHOT_MANIFEST_BYTES)) as unknown)
  if (manifest.profile !== profile || manifest.generationId !== generationId) throw new Error('Generation snapshot identity mismatch')
  const files: Record<string, string | null> = {}
  for (const entry of manifest.files) {
    const file = join(directory, entry.name)
    if (!entry.present) {
      try { await lstat(file); throw new Error(`Unexpected file in generation snapshot: ${entry.name}`) }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
      files[entry.name] = null
      continue
    }
    const contents = await readBoundedRegularFile(file, `Generation snapshot file ${entry.name}`, MAX_SNAPSHOT_FILE_BYTES)
    if (sha256(contents) !== entry.sha256) throw new Error(`Generation snapshot digest mismatch: ${entry.name}`)
    files[entry.name] = contents
  }
  const packageJson = files['package.json'] ? JSON.parse(files['package.json']) as { dsh?: { profile?: { bundles?: unknown } } } : {}
  const rawBundles = packageJson.dsh?.profile?.bundles
  const bundles = Array.isArray(rawBundles) ? rawBundles.filter((item): item is string => typeof item === 'string') : []
  const result: ProfileSnapshot = {
    name: profile,
    path: directory,
    files,
    bundles,
    fingerprint: sha256(stableJson(files)),
  }
  if (result.fingerprint !== manifest.profileFingerprint) throw new Error('Generation snapshot profile fingerprint mismatch')
  return result
}

export function currentGeneration(profile: ManagedProfileV1): ProfileGenerationV1 {
  const generation = profile.generations.find((candidate) => candidate.id === profile.currentGenerationId)
  if (!generation) throw new Error('Managed profile current generation is missing')
  return generation
}

export interface RecordGenerationOptions {
  action: LifecycleAction
  snapshot: ProfileSnapshot
  plugins: ManagedPluginV1[]
  configHash?: string
  reportId?: string
  packageName?: string
  restoredGenerationId?: string
  now?: Date
  generationId?: string
}

export async function recordProfileGeneration(
  paths: StatePaths,
  previous: ManagedProfileV1 | undefined,
  options: RecordGenerationOptions,
): Promise<ManagedProfileV1> {
  const now = options.now ?? new Date()
  const generationId = options.generationId ?? sortableId('gen', now)
  const generation: ProfileGenerationV1 = {
    schemaVersion: 1,
    id: generationId,
    profile: options.snapshot.name,
    createdAt: now.toISOString(),
    action: options.action,
    ...(previous ? { parentGenerationId: previous.currentGenerationId } : {}),
    ...(options.restoredGenerationId ? { restoredGenerationId: options.restoredGenerationId } : {}),
    ...(options.reportId ? { reportId: options.reportId } : {}),
    ...(options.packageName ? { packageName: options.packageName } : {}),
    profileFingerprint: options.snapshot.fingerprint,
    ...(options.configHash ? { configHash: options.configHash } : {}),
    bundles: [...options.snapshot.bundles],
    plugins: options.plugins.map((plugin) => ({ ...plugin, bundles: [...plugin.bundles] })),
  }
  await createGenerationSnapshot(paths, options.snapshot, generationId, now)
  const value: ManagedProfileV1 = {
    schemaVersion: 1,
    profile: options.snapshot.name,
    createdAt: previous?.createdAt ?? now.toISOString(),
    updatedAt: now.toISOString(),
    lastVerifiedAt: now.toISOString(),
    currentGenerationId: generationId,
    generations: [...(previous?.generations ?? []), generation],
  }
  try {
    await saveManagedProfile(value, paths)
    return value
  } catch (error) {
    await rm(snapshotDirectory(paths, options.snapshot.name, generationId), { recursive: true, force: true }).catch(() => undefined)
    throw error
  }
}

function legacyPlugin(record: InstallRecord, bundles: string[]): ManagedPluginV1 {
  return {
    schemaVersion: 1,
    packageName: record.packageName,
    version: record.version,
    reportId: record.reportId,
    artifactSha256: record.artifactSha256,
    installedAt: record.installedAt,
    updatedAt: record.installedAt,
    bundles,
  }
}

export async function importLegacyManagedProfile(
  profile: string,
  paths: StatePaths,
  home?: string,
): Promise<ManagedProfileV1 | undefined> {
  const existing = await loadManagedProfile(profile, paths)
  if (existing) return existing
  const legacy = await loadInstall(profile, paths)
  if (!legacy) return undefined
  const snapshot = await snapshotProfile(profile, home)
  if (snapshot.fingerprint !== legacy.resultingProfileFingerprint) return undefined
  let ownedBundles: string[] = []
  let configHash: string | undefined
  try {
    const report = await loadReport(legacy.reportId, paths)
    ownedBundles = snapshot.bundles.filter((bundle) => !report.profile.bundles.includes(bundle))
    configHash = report.stage.afterConfigHash
  } catch {
    ownedBundles = snapshot.bundles.includes(legacy.packageName) ? [legacy.packageName] : []
  }
  return recordProfileGeneration(paths, undefined, {
    action: 'legacy-import',
    snapshot,
    plugins: [legacyPlugin(legacy, ownedBundles)],
    ...(configHash ? { configHash } : {}),
    reportId: legacy.reportId,
    packageName: legacy.packageName,
    now: new Date(legacy.installedAt),
  })
}

export async function loadOrImportManagedProfile(
  profile: string,
  paths: StatePaths,
  home?: string,
): Promise<ManagedProfileV1 | undefined> {
  return await loadManagedProfile(profile, paths) ?? importLegacyManagedProfile(profile, paths, home)
}

export async function listManagedProfiles(paths: StatePaths, home?: string): Promise<ManagedProfileV1[]> {
  const known = new Set(await listManagedProfileNames(paths))
  try {
    for (const name of await readdir(paths.installs)) {
      if (name.endsWith('.json') && PROFILE_NAME.test(basename(name, '.json'))) known.add(basename(name, '.json'))
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  const profiles: ManagedProfileV1[] = []
  for (const profile of [...known].sort()) {
    const value = await loadOrImportManagedProfile(profile, paths, home)
    if (value) profiles.push(value)
  }
  return profiles
}

export interface LifecycleStateInspection {
  ok: boolean
  profiles: number
  generations: number
  locks: string[]
  issues: string[]
}

export async function inspectLifecycleState(paths: StatePaths): Promise<LifecycleStateInspection> {
  await initState(paths)
  const issues: string[] = []
  let generations = 0
  const rawNames = await readdir(paths.managedProfiles)
  const invalidNames = rawNames.filter((name) => name.endsWith('.json') && !PROFILE_NAME.test(basename(name, '.json')))
  invalidNames.forEach((name) => issues.push(`unsupported managed profile state filename: ${name}`))
  const names = await listManagedProfileNames(paths)
  for (const profile of names) {
    try {
      const state = await loadManagedProfile(profile, paths)
      if (!state) continue
      generations += state.generations.length
      for (const generation of state.generations) {
        try {
          const snapshot = await readGenerationSnapshot(paths, profile, generation.id)
          if (snapshot.fingerprint !== generation.profileFingerprint) issues.push(`${profile}/${generation.id}: state and snapshot fingerprints differ`)
        } catch (error) {
          issues.push(`${profile}/${generation.id}: ${(error as Error).message}`)
        }
      }
    } catch (error) {
      issues.push(`${profile}: ${(error as Error).message}`)
    }
  }
  const locks = (await readdir(paths.locks)).filter((name) => /^profile-[a-zA-Z0-9_-]+\.lock$/.test(name)).sort()
  locks.forEach((name) => issues.push(`active or stale lifecycle lock: ${name}`))
  return { ok: issues.length === 0, profiles: names.length, generations, locks, issues }
}
