import { spawn } from 'node:child_process'
import { copyFile, open, readFile, rename, rm } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import type { Approval, InstallRecord, ManagedPluginV1, ScanReport } from './types.js'
import type { StatePaths } from './state.js'
import { appendAudit, appendEvent, deleteInstall, loadApproval, loadInstall, loadReport, reportDigest, saveApproval, saveInstall } from './state.js'
import { dshHomePath, locateDshBin, snapshotProfile } from './profile.js'
import { policyHash, DEFAULT_POLICY } from './policy.js'
import { currentGeneration, loadOrImportManagedProfile, recordProfileGeneration } from './lifecycle.js'
import { ensurePrivateDir, sanitizeText, sha256, sha256File, sortableId } from './util.js'

function run(command: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number; output: string; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk))
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => {
      const out = Buffer.concat(stdout).toString('utf8')
      const err = Buffer.concat(stderr).toString('utf8')
      resolvePromise({ code: code ?? 1, output: `${out}${err}`, stdout: out, stderr: err })
    })
  })
}

export async function approveReport(reportId: string, paths: StatePaths): Promise<Approval> {
  const report = await loadReport(reportId, paths)
  if (report.verdict === 'blocked') throw new Error('Blocked reports cannot be approved; there is no force override in v1')
  const current = await snapshotProfile(report.profile.name)
  if (current.fingerprint !== report.profile.fingerprint) throw new Error('Profile changed after scanning; rescan before approval')
  if (await sha256File(report.source.artifactPath) !== report.source.sha256) throw new Error('Artifact changed after scanning; rescan required')
  const approval: Approval = {
    schemaVersion: 1,
    reportId,
    approvedAt: new Date().toISOString(),
    reportSha256: reportDigest(report),
    artifactSha256: report.source.sha256,
    profileFingerprint: report.profile.fingerprint,
    policyHash: report.policyHash,
  }
  await saveApproval(approval, paths)
  await appendAudit(paths, 'approve', { reportId, verdict: report.verdict, artifactSha256: approval.artifactSha256, profileFingerprint: approval.profileFingerprint })
  return approval
}

async function profileIsActive(profile: string): Promise<boolean> {
  const result = await run('/bin/ps', ['-axo', 'command='], { PATH: '/usr/bin:/bin' }).catch(() => ({ code: 1, output: '', stdout: '', stderr: '' }))
  if (result.code !== 0) return true
  return result.output.split(/\r?\n/).some((line) => /(?:@deepseek-ai\/dsh|\/dsh\/lib\/bin\.js|(?:^|\s)dsh(?:\s|$))/.test(line) && new RegExp(`(?:--profile\\s+${profile}\\b|\\bdsh\\s+${profile}\\b)`).test(line))
}

async function backupProfile(report: ScanReport, paths: StatePaths): Promise<string> {
  const directory = join(paths.root, 'backups', `${report.profile.name}-${sortableId('bak')}`)
  await ensurePrivateDir(directory)
  for (const name of Object.keys(report.profile.files)) {
    const source = join(report.profile.path, name)
    try { await copyFile(source, join(directory, name)) }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
  }
  return directory
}

async function restoreBackup(report: ScanReport, backup: string): Promise<boolean> {
  try {
    for (const [name, content] of Object.entries(report.profile.files)) {
      const destination = join(report.profile.path, name)
      if (content === null) await rm(destination, { force: true })
      else await copyFile(join(backup, name), destination)
    }
    return (await snapshotProfile(report.profile.name)).fingerprint === report.profile.fingerprint
  } catch {
    return false
  }
}

async function quarantineNodeModules(profilePath: string): Promise<string | undefined> {
  const source = join(profilePath, 'node_modules')
  const backup = join(dirname(profilePath), `.${basename(profilePath)}-node_modules-${sortableId('bak')}`)
  try {
    await rename(source, backup)
    return backup
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
}

async function restoreNodeModules(profilePath: string, backup: string | undefined): Promise<boolean> {
  try {
    await rm(join(profilePath, 'node_modules'), { recursive: true, force: true })
    if (backup) await rename(backup, join(profilePath, 'node_modules'))
    return true
  } catch {
    return false
  }
}

async function applyApprovedReport(reportId: string, paths: StatePaths, mode: 'install' | 'update'): Promise<InstallRecord> {
  const report = await loadReport(reportId, paths)
  const approval = await loadApproval(reportId, paths)
  if (report.verdict === 'blocked') throw new Error('Blocked reports cannot be installed')
  if (!report.stage.compatible || !report.stage.proposedLockHash || !report.stage.proposedProfileFingerprint) throw new Error('A successful isolated stage is required before installation')
  if (approval.reportSha256 !== reportDigest(report)) throw new Error('Report changed after approval')
  if (approval.policyHash !== report.policyHash || report.policyHash !== policyHash(DEFAULT_POLICY)) throw new Error('Policy changed after approval; rescan required')
  if (await sha256File(report.source.artifactPath) !== approval.artifactSha256) throw new Error('Artifact changed after approval')
  const before = await snapshotProfile(report.profile.name)
  if (before.fingerprint !== approval.profileFingerprint) throw new Error('Target profile changed after approval; rescan required')
  const managed = await loadOrImportManagedProfile(report.profile.name, paths)
  const previousGeneration = managed ? currentGeneration(managed) : undefined
  if (previousGeneration && previousGeneration.profileFingerprint !== before.fingerprint) {
    throw new Error(`Managed profile ${report.profile.name} has drifted; repair or explicitly resolve drift before changing plugins`)
  }
  const previousPlugin = previousGeneration?.plugins.find((plugin) => plugin.packageName === report.source.name)
  if (mode === 'install' && previousPlugin) throw new Error(`${report.source.name} is already managed; use plugins update with an approved report`)
  if (mode === 'update' && !previousPlugin) throw new Error(`${report.source.name} is not managed; use install for the first guarded installation`)
  if (mode === 'update' && previousPlugin?.version === report.source.version && previousPlugin.artifactSha256 === report.source.sha256) {
    throw new Error(`${report.source.name}@${report.source.version} is already the current managed artifact`)
  }
  if (await profileIsActive(report.profile.name)) throw new Error(`DSH profile ${report.profile.name} appears active; stop it before installing`)
  const dsh = await locateDshBin()
  if (!dsh) throw new Error('DSH executable not found; set DSH_BIN')
  await ensurePrivateDir(paths.locks)
  const lockPath = join(paths.locks, `profile-${report.profile.name}.lock`)
  let handle
  try { handle = await open(lockPath, 'wx', 0o600) }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error(`Profile ${report.profile.name} is locked by another DSH Guard operation`); throw error }
  const backup = await backupProfile(report, paths)
  const priorLegacy = await loadInstall(report.profile.name, paths)
  let nodeModulesBackup: string | undefined
  try {
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: process.env.HOME,
      DSH_HOME: dshHomePath(),
      LANG: process.env.LANG ?? 'C.UTF-8',
      LC_ALL: process.env.LC_ALL ?? 'C.UTF-8',
      CI: '1',
      NO_COLOR: '1',
    }
    const store = join(paths.cache, 'pnpm-store')
    nodeModulesBackup = await quarantineNodeModules(report.profile.path)
    const hydration = await run(dsh.command, [
      ...dsh.prefix, 'plugin', '--profile', report.profile.name, 'install', '--ignore-scripts', '--frozen-lockfile', '--offline',
      '--store-dir', store,
    ], env)
    if (hydration.code !== 0) throw new Error(`Offline baseline hydration failed: ${sanitizeText(hydration.output, 900)}`)
    const command = await run(dsh.command, [
      ...dsh.prefix, 'plugin', '--profile', report.profile.name, 'add', '--save-exact', '--ignore-scripts', '--offline',
      '--store-dir', store, report.source.artifactPath,
    ], env)
    if (command.code !== 0) throw new Error(`Offline install failed: ${sanitizeText(command.output, 900)}`)
    const after = await snapshotProfile(report.profile.name)
    const lock = await readFile(join(after.path, 'pnpm-lock.yaml'), 'utf8')
    if (sha256(lock) !== report.stage.proposedLockHash || after.fingerprint !== report.stage.proposedProfileFingerprint) {
      throw new Error('Actual profile differs from the approved staged proposal')
    }
    if (report.stage.proposedBundles && JSON.stringify(after.bundles) !== JSON.stringify(report.stage.proposedBundles)) {
      throw new Error('Actual profile bundle order differs from the approved staged proposal')
    }
    if (report.stage.afterConfigHash) {
      const composed = await run(dsh.command, [...dsh.prefix, '--profile', report.profile.name, '--dump-config'], env)
      if (composed.code !== 0 || sha256(composed.stdout) !== report.stage.afterConfigHash) {
        throw new Error('Actual composed config differs from the approved staged proposal')
      }
    }
    const now = new Date()
    const record: InstallRecord = {
      schemaVersion: 1,
      reportId,
      installedAt: now.toISOString(),
      lastVerifiedAt: now.toISOString(),
      profile: report.profile.name,
      packageName: report.source.name,
      version: report.source.version,
      artifactSha256: report.source.sha256,
      expectedProfileFingerprint: report.stage.proposedProfileFingerprint,
      resultingProfileFingerprint: after.fingerprint,
      expectedBundles: after.bundles,
    }
    await saveInstall(record, paths)
    const ownedBundles = after.bundles.filter((bundle) => previousPlugin?.bundles.includes(bundle) || !before.bundles.includes(bundle))
    const plugin: ManagedPluginV1 = {
      schemaVersion: 1,
      packageName: report.source.name,
      version: report.source.version,
      reportId,
      artifactSha256: report.source.sha256,
      installedAt: previousPlugin?.installedAt ?? now.toISOString(),
      updatedAt: now.toISOString(),
      bundles: ownedBundles,
    }
    const plugins = [
      ...(previousGeneration?.plugins.filter((candidate) => candidate.packageName !== plugin.packageName) ?? []),
      plugin,
    ].sort((a, b) => a.packageName.localeCompare(b.packageName))
    await recordProfileGeneration(paths, managed, {
      action: mode,
      snapshot: after,
      plugins,
      ...(report.stage.afterConfigHash ? { configHash: report.stage.afterConfigHash } : {}),
      reportId,
      packageName: record.packageName,
      now,
    })
    await appendAudit(paths, mode, { reportId, profile: record.profile, packageName: record.packageName, version: record.version, resultingProfileFingerprint: record.resultingProfileFingerprint }).catch(() => undefined)
    if (nodeModulesBackup) await rm(nodeModulesBackup, { recursive: true, force: true }).catch(() => undefined)
    return record
  } catch (error) {
    try {
      if (priorLegacy) await saveInstall(priorLegacy, paths)
      else await deleteInstall(report.profile.name, paths)
    } catch { /* recovery result below remains authoritative */ }
    const recoveredProfile = await restoreBackup(report, backup)
    const recoveredModules = await restoreNodeModules(report.profile.path, nodeModulesBackup)
    const recovered = recoveredProfile && recoveredModules
    await appendAudit(paths, recovered ? `${mode}-failed-recovered` : `${mode}-failed-needs-repair`, { reportId, error: sanitizeText((error as Error).message) })
    if (!recovered) {
      await appendEvent(paths, {
        schemaVersion: 1,
        id: sortableId('evt'),
        createdAt: new Date().toISOString(),
        severity: 'high',
        type: 'needs-repair',
        fingerprint: (await import('./util.js')).sha256(`needs-repair:${report.profile.name}:${reportId}`),
        title: 'DSH profile 需要修复',
        detail: `安装失败且自动恢复未能还原 profile。备份：${backup}`,
        profile: report.profile.name,
      })
      throw new Error(`Installation failed and automatic recovery could not restore the profile. Backup: ${backup}. Cause: ${(error as Error).message}`)
    }
    throw error
  } finally {
    await handle?.close()
    await rm(lockPath, { force: true })
  }
}

export async function installApproved(reportId: string, paths: StatePaths): Promise<InstallRecord> {
  return applyApprovedReport(reportId, paths, 'install')
}

export async function updateApproved(reportId: string, paths: StatePaths): Promise<InstallRecord> {
  return applyApprovedReport(reportId, paths, 'update')
}
