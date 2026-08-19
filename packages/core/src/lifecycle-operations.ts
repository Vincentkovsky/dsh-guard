import { spawn } from 'node:child_process'
import { mkdir, open, rm } from 'node:fs/promises'
import { join } from 'node:path'
import type {
  InstallRecord,
  LifecycleOperationResultV1,
  ManagedPluginV1,
  ManagedProfileV1,
  ManagedProfileViewV1,
  ProfileGenerationV1,
  ProfileSnapshot,
  StageResult,
} from './types.js'
import type { StatePaths } from './state.js'
import { appendAudit, appendEvent, deleteInstall, loadInstall, saveInstall } from './state.js'
import {
  currentGeneration,
  listManagedProfiles,
  loadOrImportManagedProfile,
  readGenerationSnapshot,
  recordProfileGeneration,
} from './lifecycle.js'
import {
  PROFILE_FILES,
  dshHomePath,
  locateDshBin,
  snapshotProfile,
  stagePackageRemoval,
} from './profile.js'
import { atomicWrite, ensurePrivateDir, sanitizeText, sha256, sortableId, stableJson } from './util.js'

const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/

interface DshCommand {
  command: string
  prefix: string[]
}

interface CommandResult {
  code: number
  stdout: string
  stderr: string
}

function run(command: string, args: string[], env: NodeJS.ProcessEnv): Promise<CommandResult> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk))
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => resolvePromise({
      code: code ?? 1,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8'),
    }))
  })
}

function environment(): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    HOME: process.env.HOME,
    DSH_HOME: dshHomePath(),
    LANG: process.env.LANG ?? 'C.UTF-8',
    LC_ALL: process.env.LC_ALL ?? 'C.UTF-8',
    CI: '1',
    NO_COLOR: '1',
  }
}

async function profileIsActive(profile: string): Promise<boolean> {
  const result = await run('/bin/ps', ['-axo', 'command='], { PATH: '/usr/bin:/bin' }).catch(() => ({ code: 1, stdout: '', stderr: '' }))
  if (result.code !== 0) return true
  return result.stdout.split(/\r?\n/).some((line) => /(?:@deepseek-ai\/dsh|\/dsh\/lib\/bin\.js|(?:^|\s)dsh(?:\s|$))/.test(line) && new RegExp(`(?:--profile\\s+${profile}\\b|\\bdsh\\s+${profile}\\b)`).test(line))
}

async function withProfileLock<T>(profile: string, paths: StatePaths, operation: () => Promise<T>): Promise<T> {
  await ensurePrivateDir(paths.locks)
  const lockPath = join(paths.locks, `profile-${profile}.lock`)
  let handle
  try { handle = await open(lockPath, 'wx', 0o600) }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error(`Profile ${profile} is locked by another DSH Guard operation`)
    throw error
  }
  try { return await operation() }
  finally {
    await handle.close()
    await rm(lockPath, { force: true })
  }
}

async function backupSnapshot(snapshot: ProfileSnapshot, paths: StatePaths): Promise<string> {
  const directory = join(paths.root, 'backups', `${snapshot.name}-${sortableId('lifecycle')}`)
  await ensurePrivateDir(directory)
  const digests: Record<string, string | null> = {}
  for (const name of PROFILE_FILES) {
    const contents = snapshot.files[name]
    if (contents === null || contents === undefined) digests[name] = null
    else {
      await atomicWrite(join(directory, name), contents)
      digests[name] = sha256(contents)
    }
  }
  await atomicWrite(join(directory, 'manifest.json'), stableJson({
    schemaVersion: 1,
    profile: snapshot.name,
    profileFingerprint: snapshot.fingerprint,
    createdAt: new Date().toISOString(),
    files: digests,
  }))
  return directory
}

async function restoreProfileFiles(snapshot: ProfileSnapshot): Promise<void> {
  const target = join(dshHomePath(), 'profiles', snapshot.name)
  await mkdir(target, { recursive: true })
  for (const name of PROFILE_FILES) {
    const contents = snapshot.files[name]
    const destination = join(target, name)
    if (contents === null || contents === undefined) await rm(destination, { force: true })
    else await atomicWrite(destination, contents)
  }
}

async function hydrate(profile: string, dsh: DshCommand, paths: StatePaths): Promise<void> {
  const result = await run(dsh.command, [
    ...dsh.prefix,
    'plugin', '--profile', profile,
    'install', '--ignore-scripts', '--frozen-lockfile', '--offline',
    '--store-dir', join(paths.cache, 'pnpm-store'),
  ], environment())
  if (result.code !== 0) throw new Error(`Offline profile hydration failed: ${sanitizeText(`${result.stderr}\n${result.stdout}`, 900)}`)
}

async function configHash(profile: string, dsh: DshCommand): Promise<string> {
  const result = await run(dsh.command, [...dsh.prefix, '--profile', profile, '--dump-config'], environment())
  if (result.code !== 0) throw new Error(`Profile config composition failed: ${sanitizeText(`${result.stderr}\n${result.stdout}`, 900)}`)
  return sha256(result.stdout)
}

function assertExpectedSnapshot(actual: ProfileSnapshot, expected: { profileFingerprint: string; bundles: string[] }): void {
  if (actual.fingerprint !== expected.profileFingerprint) throw new Error('Actual profile differs from the proposed lifecycle result')
  if (JSON.stringify(actual.bundles) !== JSON.stringify(expected.bundles)) throw new Error('Actual bundle order differs from the proposed lifecycle result')
}

async function assertStage(actual: ProfileSnapshot, stage: StageResult, dsh: DshCommand): Promise<string | undefined> {
  if (!stage.compatible || !stage.proposedProfileFingerprint || !stage.proposedLockHash) throw new Error(`Lifecycle staging failed: ${stage.reason ?? 'proposal is incomplete'}`)
  const lock = actual.files['pnpm-lock.yaml']
  if (lock === null || lock === undefined || sha256(lock) !== stage.proposedLockHash) throw new Error('Actual lockfile differs from the staged lifecycle proposal')
  assertExpectedSnapshot(actual, { profileFingerprint: stage.proposedProfileFingerprint, bundles: stage.proposedBundles ?? actual.bundles })
  if (stage.afterConfigHash) {
    const actualConfigHash = await configHash(actual.name, dsh)
    if (actualConfigHash !== stage.afterConfigHash) throw new Error('Actual composed config differs from the staged lifecycle proposal')
  }
  return stage.afterConfigHash
}

async function restoreAndVerify(
  snapshot: ProfileSnapshot,
  expectedConfigHash: string | undefined,
  dsh: DshCommand,
  paths: StatePaths,
): Promise<boolean> {
  try {
    await restoreProfileFiles(snapshot)
    await hydrate(snapshot.name, dsh, paths)
    const restored = await snapshotProfile(snapshot.name)
    if (restored.fingerprint !== snapshot.fingerprint) return false
    if (expectedConfigHash && await configHash(snapshot.name, dsh) !== expectedConfigHash) return false
    return true
  } catch {
    return false
  }
}

async function needsRepair(
  paths: StatePaths,
  profile: string,
  action: string,
  backupPath: string,
  error: unknown,
): Promise<never> {
  const reason = sanitizeText((error as Error).message)
  await appendAudit(paths, `${action}-failed-needs-repair`, { profile, backupPath, error: reason }).catch(() => undefined)
  await appendEvent(paths, {
    schemaVersion: 1,
    id: sortableId('evt'),
    createdAt: new Date().toISOString(),
    severity: 'high',
    type: 'needs-repair',
    fingerprint: sha256(`needs-repair:${profile}:${action}:${backupPath}`),
    title: 'DSH profile 需要修复',
    detail: `${action} 失败且自动恢复未能还原 profile。备份：${backupPath}`,
    profile,
  }).catch(() => undefined)
  throw new Error(`${action} failed and automatic recovery could not restore the profile. Backup: ${backupPath}. Cause: ${reason}`)
}

function requireManaged(profile: string, value: ManagedProfileV1 | undefined): ManagedProfileV1 {
  if (!value) throw new Error(`No managed lifecycle state exists for profile ${profile}`)
  return value
}

function legacyRecord(plugin: ManagedPluginV1, profile: string, fingerprint: string, bundles: string[], now: Date): InstallRecord {
  return {
    schemaVersion: 1,
    reportId: plugin.reportId,
    installedAt: plugin.installedAt,
    lastVerifiedAt: now.toISOString(),
    profile,
    packageName: plugin.packageName,
    version: plugin.version,
    artifactSha256: plugin.artifactSha256,
    expectedProfileFingerprint: fingerprint,
    resultingProfileFingerprint: fingerprint,
    expectedBundles: bundles,
  }
}

async function persistLegacyCompatibility(
  paths: StatePaths,
  profile: string,
  plugins: ManagedPluginV1[],
  fingerprint: string,
  bundles: string[],
  now: Date,
): Promise<void> {
  if (plugins.length === 0) await deleteInstall(profile, paths)
  else await saveInstall(legacyRecord(plugins[plugins.length - 1]!, profile, fingerprint, bundles, now), paths)
}

async function restoreLegacy(paths: StatePaths, profile: string, previous: InstallRecord | undefined): Promise<void> {
  if (previous) await saveInstall(previous, paths)
  else await deleteInstall(profile, paths)
}

export async function inspectManagedProfiles(paths: StatePaths, onlyProfile?: string): Promise<ManagedProfileViewV1[]> {
  const profiles = onlyProfile
    ? [requireManaged(onlyProfile, await loadOrImportManagedProfile(onlyProfile, paths))]
    : await listManagedProfiles(paths)
  const views: ManagedProfileViewV1[] = []
  for (const profile of profiles) {
    const generation = currentGeneration(profile)
    try {
      const actual = await snapshotProfile(profile.profile)
      const state = actual.fingerprint === generation.profileFingerprint ? 'verified' : 'drifted'
      views.push({
        schemaVersion: 1,
        profile: profile.profile,
        generationId: generation.id,
        state,
        detail: state === 'verified' ? 'Profile matches the current managed generation.' : 'Profile differs from the current managed generation.',
        plugins: generation.plugins,
        generationCount: profile.generations.length,
      })
    } catch (error) {
      views.push({
        schemaVersion: 1,
        profile: profile.profile,
        generationId: generation.id,
        state: 'unknown',
        detail: sanitizeText((error as Error).message),
        plugins: generation.plugins,
        generationCount: profile.generations.length,
      })
    }
  }
  return views
}

export async function uninstallManagedPlugin(
  packageName: string,
  profile: string,
  confirmation: string,
  paths: StatePaths,
): Promise<LifecycleOperationResultV1> {
  if (!PACKAGE_NAME.test(packageName)) throw new Error('Invalid package name')
  if (confirmation !== packageName) throw new Error(`Confirmation must exactly match package name: ${packageName}`)
  const managed = requireManaged(profile, await loadOrImportManagedProfile(profile, paths))
  const generation = currentGeneration(managed)
  if (!generation.plugins.some((plugin) => plugin.packageName === packageName)) throw new Error(`${packageName} is not managed in profile ${profile}`)
  if (await profileIsActive(profile)) throw new Error(`DSH profile ${profile} appears active; stop it before uninstalling`)
  const dsh = await locateDshBin()
  if (!dsh) throw new Error('DSH executable not found; set DSH_BIN')
  return withProfileLock(profile, paths, async () => {
    const before = await snapshotProfile(profile)
    if (before.fingerprint !== generation.profileFingerprint) throw new Error(`Managed profile ${profile} has drifted; repair or explicitly resolve drift before uninstalling`)
    const stage = await stagePackageRemoval(before, packageName, join(paths.cache, 'pnpm-store'))
    if (!stage.compatible) throw new Error(`Lifecycle staging failed: ${stage.reason ?? 'remove proposal is incompatible'}`)
    const backupPath = await backupSnapshot(before, paths)
    const previousLegacy = await loadInstall(profile, paths)
    try {
      const result = await run(dsh.command, [
        ...dsh.prefix,
        'plugin', '--profile', profile,
        '--config.ignore-scripts=true',
        '--config.offline=true',
        `--config.store-dir=${join(paths.cache, 'pnpm-store')}`,
        'remove', packageName,
      ], environment())
      if (result.code !== 0) throw new Error(`Offline uninstall failed: ${sanitizeText(`${result.stderr}\n${result.stdout}`, 900)}`)
      const after = await snapshotProfile(profile)
      const resultingConfigHash = await assertStage(after, stage, dsh)
      const plugins = generation.plugins.filter((plugin) => plugin.packageName !== packageName)
      const now = new Date()
      await persistLegacyCompatibility(paths, profile, plugins, after.fingerprint, after.bundles, now)
      let next
      try {
        next = await recordProfileGeneration(paths, managed, {
          action: 'uninstall',
          snapshot: after,
          plugins,
          ...(resultingConfigHash ? { configHash: resultingConfigHash } : {}),
          packageName,
          now,
        })
      } catch (error) {
        await restoreLegacy(paths, profile, previousLegacy).catch(() => undefined)
        throw error
      }
      await appendAudit(paths, 'uninstall', { profile, packageName, generationId: next.currentGenerationId, backupPath }).catch(() => undefined)
      return {
        schemaVersion: 1,
        action: 'uninstall',
        profile,
        generationId: next.currentGenerationId,
        previousGenerationId: generation.id,
        packageName,
        backupPath,
        noOp: false,
      }
    } catch (error) {
      await restoreLegacy(paths, profile, previousLegacy).catch(() => undefined)
      const recovered = await restoreAndVerify(before, generation.configHash, dsh, paths)
      if (!recovered) return needsRepair(paths, profile, 'uninstall', backupPath, error)
      await appendAudit(paths, 'uninstall-failed-recovered', { profile, packageName, backupPath, error: sanitizeText((error as Error).message) }).catch(() => undefined)
      throw error
    }
  })
}

interface RestoreOptions {
  profile: string
  targetGeneration: ProfileGenerationV1
  managed: ManagedProfileV1
  action: 'repair' | 'rollback'
  allowDrift: boolean
}

async function restoreManagedGeneration(options: RestoreOptions, paths: StatePaths): Promise<LifecycleOperationResultV1> {
  const { profile, targetGeneration, managed, action } = options
  const current = currentGeneration(managed)
  const target = await readGenerationSnapshot(paths, profile, targetGeneration.id)
  const actualBeforeLock = await snapshotProfile(profile)
  if (action === 'repair' && actualBeforeLock.fingerprint === target.fingerprint) {
    return {
      schemaVersion: 1,
      action,
      profile,
      generationId: current.id,
      previousGenerationId: current.id,
      restoredGenerationId: targetGeneration.id,
      noOp: true,
    }
  }
  if (action === 'rollback' && actualBeforeLock.fingerprint !== current.profileFingerprint && !options.allowDrift) {
    throw new Error(`Managed profile ${profile} has drifted; pass --allow-drift only after reviewing and preserving the drifted files`)
  }
  if (await profileIsActive(profile)) throw new Error(`DSH profile ${profile} appears active; stop it before ${action}`)
  const dsh = await locateDshBin()
  if (!dsh) throw new Error('DSH executable not found; set DSH_BIN')
  return withProfileLock(profile, paths, async () => {
    const before = await snapshotProfile(profile)
    if (before.fingerprint !== actualBeforeLock.fingerprint) throw new Error(`Profile ${profile} changed while waiting for the lifecycle lock`)
    const backupPath = await backupSnapshot(before, paths)
    const previousLegacy = await loadInstall(profile, paths)
    try {
      await restoreProfileFiles(target)
      await hydrate(profile, dsh, paths)
      const after = await snapshotProfile(profile)
      assertExpectedSnapshot(after, targetGeneration)
      if (targetGeneration.configHash && await configHash(profile, dsh) !== targetGeneration.configHash) {
        throw new Error('Restored composed config differs from the target generation')
      }
      const now = new Date()
      await persistLegacyCompatibility(paths, profile, targetGeneration.plugins, after.fingerprint, after.bundles, now)
      let next
      try {
        next = await recordProfileGeneration(paths, managed, {
          action,
          snapshot: after,
          plugins: targetGeneration.plugins,
          ...(targetGeneration.configHash ? { configHash: targetGeneration.configHash } : {}),
          restoredGenerationId: targetGeneration.id,
          now,
        })
      } catch (error) {
        await restoreLegacy(paths, profile, previousLegacy).catch(() => undefined)
        throw error
      }
      await appendAudit(paths, action, {
        profile,
        generationId: next.currentGenerationId,
        restoredGenerationId: targetGeneration.id,
        backupPath,
      }).catch(() => undefined)
      return {
        schemaVersion: 1,
        action,
        profile,
        generationId: next.currentGenerationId,
        previousGenerationId: current.id,
        restoredGenerationId: targetGeneration.id,
        backupPath,
        noOp: false,
      }
    } catch (error) {
      await restoreLegacy(paths, profile, previousLegacy).catch(() => undefined)
      const expectedBeforeConfig = before.fingerprint === current.profileFingerprint ? current.configHash : undefined
      const recovered = await restoreAndVerify(before, expectedBeforeConfig, dsh, paths)
      if (!recovered) return needsRepair(paths, profile, action, backupPath, error)
      await appendAudit(paths, `${action}-failed-recovered`, { profile, backupPath, error: sanitizeText((error as Error).message) }).catch(() => undefined)
      throw error
    }
  })
}

export async function repairManagedProfile(
  profile: string,
  confirmation: string,
  paths: StatePaths,
): Promise<LifecycleOperationResultV1> {
  if (confirmation !== profile) throw new Error(`Confirmation must exactly match profile name: ${profile}`)
  const managed = requireManaged(profile, await loadOrImportManagedProfile(profile, paths))
  const targetGeneration = currentGeneration(managed)
  return restoreManagedGeneration({ profile, targetGeneration, managed, action: 'repair', allowDrift: true }, paths)
}

export async function rollbackManagedProfile(
  profile: string,
  generationId: string,
  confirmation: string,
  paths: StatePaths,
  options: { allowDrift?: boolean } = {},
): Promise<LifecycleOperationResultV1> {
  if (confirmation !== generationId) throw new Error(`Confirmation must exactly match generation id: ${generationId}`)
  const managed = requireManaged(profile, await loadOrImportManagedProfile(profile, paths))
  const targetGeneration = managed.generations.find((generation) => generation.id === generationId)
  if (!targetGeneration) throw new Error(`Generation ${generationId} is not recorded for profile ${profile}`)
  if (generationId === managed.currentGenerationId) throw new Error('Target generation is already current; use plugins repair to restore it')
  return restoreManagedGeneration({
    profile,
    targetGeneration,
    managed,
    action: 'rollback',
    allowDrift: options.allowDrift ?? false,
  }, paths)
}
