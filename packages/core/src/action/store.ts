import { randomUUID } from 'node:crypto'
import { appendFile, chmod, lstat, open, readFile, rename, stat, unlink } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import type {
  ActionEventReadResult,
  ActionEventStoreOptions,
  ActionEventV1,
  ActionGrantStoreV1,
  ActionGrantV1,
  ActionPolicyV1,
  ActionProtectionSettingsV1,
  ActionRequestV1,
  ActionStoreInspection,
  ActionStorePaths,
} from './types.js'
import { ActionSchemaError } from './types.js'
import { findMatchingActionGrant } from './grants.js'
import { parseActionEvent, parseActionGrant, parseActionGrantStore, parseActionPolicy, parseActionProtectionSettings } from './schema.js'
import { atomicWrite, ensurePrivateDir, stableJson } from '../util.js'

export const DEFAULT_ACTION_EVENT_MAX_BYTES = 5 * 1024 * 1024
export const DEFAULT_ACTION_EVENT_MAX_FILES = 4
const LOCK_STALE_MS = 30_000
const LOCK_ATTEMPTS = 25

export function actionStorePaths(root = process.env.DSH_GUARD_HOME ?? join(homedir(), '.dsh-guard')): ActionStorePaths {
  return {
    root,
    policy: join(root, 'action-policy.json'),
    protection: join(root, 'action-protection.json'),
    protectionLock: join(root, 'action-protection.lock'),
    grants: join(root, 'action-grants.json'),
    grantLock: join(root, 'action-grants.lock'),
    events: join(root, 'action-events.jsonl'),
    eventLock: join(root, 'action-events.lock'),
  }
}

function emptyGrantStore(now = new Date()): ActionGrantStoreV1 {
  return { schemaVersion: 1, updatedAt: now.toISOString(), grants: [] }
}

async function optionalText(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
}

async function privateOptionalText(path: string): Promise<string | undefined> {
  await privateFile(path)
  return optionalText(path)
}

async function privateFile(path: string): Promise<void> {
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink()) throw new ActionSchemaError('ACTION_STORE_INVALID', `${path}: symbolic links are not accepted for action state`)
    if ((info.mode & 0o077) !== 0) throw new ActionSchemaError('ACTION_STORE_INVALID', `${path}: expected private file mode 0600`)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

function lockOwnerAlive(token: string): boolean {
  const owner = Number(token.split(':', 1)[0])
  if (!Number.isSafeInteger(owner) || owner <= 0) return false
  try {
    process.kill(owner, 0)
    return true
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH'
  }
}

async function withFileLock<T>(path: string, operation: () => Promise<T>): Promise<T> {
  await ensurePrivateDir(dirname(path))
  const token = `${process.pid}:${randomUUID()}`
  let acquired = false
  for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
    try {
      const handle = await open(path, 'wx', 0o600)
      try {
        await handle.writeFile(token)
        await handle.sync()
      } finally {
        await handle.close()
      }
      acquired = true
      break
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      try {
        const info = await lstat(path)
        if (info.isSymbolicLink()) throw new ActionSchemaError('ACTION_STORE_INVALID', `${path}: symbolic lock is not accepted`)
        if (Date.now() - info.mtimeMs > LOCK_STALE_MS) {
          const ownerToken = await optionalText(path)
          if (ownerToken === undefined || !lockOwnerAlive(ownerToken)) await unlink(path)
        }
      } catch (lockError) {
        if ((lockError as NodeJS.ErrnoException).code !== 'ENOENT') throw lockError
      }
      await delay(Math.min(10 + attempt * 5, 100))
    }
  }
  if (!acquired) throw new ActionSchemaError('ACTION_STORE_INVALID', `${path}: action state lock is unavailable`)

  try {
    return await operation()
  } finally {
    try {
      if (await readFile(path, 'utf8') === token) await unlink(path)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
  }
}

export async function saveActionPolicy(paths: ActionStorePaths, policy: ActionPolicyV1): Promise<void> {
  await ensurePrivateDir(paths.root)
  await atomicWrite(paths.policy, stableJson(parseActionPolicy(policy)))
}

export async function loadActionPolicy(paths: ActionStorePaths): Promise<ActionPolicyV1 | undefined> {
  const text = await privateOptionalText(paths.policy)
  if (text === undefined) return undefined
  try {
    return parseActionPolicy(JSON.parse(text) as unknown)
  } catch (error) {
    if (error instanceof ActionSchemaError) throw error
    throw new ActionSchemaError('ACTION_STORE_INVALID', 'action-policy.json: invalid JSON')
  }
}

function emptyActionProtectionSettings(now = new Date()): ActionProtectionSettingsV1 {
  return { schemaVersion: 1, updatedAt: now.toISOString(), profiles: [] }
}

async function loadActionProtectionSettingsUnlocked(
  paths: ActionStorePaths,
  now = new Date(),
): Promise<ActionProtectionSettingsV1> {
  const text = await privateOptionalText(paths.protection)
  if (text === undefined) return emptyActionProtectionSettings(now)
  try {
    return parseActionProtectionSettings(JSON.parse(text) as unknown)
  } catch (error) {
    if (error instanceof ActionSchemaError) throw error
    throw new ActionSchemaError('ACTION_STORE_INVALID', 'action-protection.json: invalid JSON')
  }
}

export async function loadActionProtectionSettings(
  paths: ActionStorePaths,
  now = new Date(),
): Promise<ActionProtectionSettingsV1> {
  return loadActionProtectionSettingsUnlocked(paths, now)
}

export async function setActionProtectionEnabled(
  paths: ActionStorePaths,
  profile: string,
  enabled: boolean,
  now = new Date(),
): Promise<ActionProtectionSettingsV1> {
  if (!/^[a-zA-Z0-9_-]{1,256}$/.test(profile)) {
    throw new ActionSchemaError('ACTION_STORE_INVALID', 'action-protection profile name is invalid')
  }
  return withFileLock(paths.protectionLock, async () => {
    const current = await loadActionProtectionSettingsUnlocked(paths, now)
    const updatedAt = now.toISOString()
    const next = parseActionProtectionSettings({
      schemaVersion: 1,
      updatedAt,
      profiles: [
        ...current.profiles.filter((entry) => entry.profile !== profile),
        { profile, enabled, updatedAt },
      ].sort((left, right) => left.profile.localeCompare(right.profile)),
    })
    await ensurePrivateDir(paths.root)
    await atomicWrite(paths.protection, stableJson(next))
    return next
  })
}

export async function actionProtectionEnabled(
  paths: ActionStorePaths,
  profile: string,
  fallback = false,
): Promise<boolean> {
  const settings = await loadActionProtectionSettingsUnlocked(paths)
  return settings.profiles.find((entry) => entry.profile === profile)?.enabled ?? fallback
}

async function loadGrantStoreUnlocked(paths: ActionStorePaths, now = new Date()): Promise<ActionGrantStoreV1> {
  const text = await privateOptionalText(paths.grants)
  if (text === undefined) return emptyGrantStore(now)
  try {
    return parseActionGrantStore(JSON.parse(text) as unknown)
  } catch (error) {
    if (error instanceof ActionSchemaError) throw error
    throw new ActionSchemaError('ACTION_STORE_INVALID', 'action-grants.json: invalid JSON')
  }
}

async function saveGrantStoreUnlocked(paths: ActionStorePaths, grants: ActionGrantV1[], now = new Date()): Promise<ActionGrantStoreV1> {
  const store = parseActionGrantStore({ schemaVersion: 1, updatedAt: now.toISOString(), grants })
  await ensurePrivateDir(paths.root)
  await atomicWrite(paths.grants, stableJson(store))
  return store
}

export async function loadActionGrantStore(paths: ActionStorePaths, now = new Date()): Promise<ActionGrantStoreV1> {
  return loadGrantStoreUnlocked(paths, now)
}

export async function addActionGrant(paths: ActionStorePaths, grant: ActionGrantV1, now = new Date()): Promise<ActionGrantStoreV1> {
  const validated = parseActionGrant(grant)
  if (Date.parse(validated.expiresAt) <= now.getTime()) {
    throw new ActionSchemaError('ACTION_STORE_INVALID', `action grant ${validated.id} is already expired`)
  }
  return withFileLock(paths.grantLock, async () => {
    const current = await loadGrantStoreUnlocked(paths, now)
    if (current.grants.some((candidate) => candidate.id === validated.id)) {
      throw new ActionSchemaError('ACTION_STORE_INVALID', `action grant ${validated.id} already exists`)
    }
    const active = current.grants.filter((candidate) => Date.parse(candidate.expiresAt) > now.getTime())
    return saveGrantStoreUnlocked(paths, [...active, validated], now)
  })
}

export async function revokeActionGrantFromStore(paths: ActionStorePaths, grantId: string, now = new Date()): Promise<ActionGrantStoreV1> {
  return withFileLock(paths.grantLock, async () => {
    const current = await loadGrantStoreUnlocked(paths, now)
    return saveGrantStoreUnlocked(paths, current.grants.filter((grant) => grant.id !== grantId && Date.parse(grant.expiresAt) > now.getTime()), now)
  })
}

export async function revokeActionGrantsForSession(paths: ActionStorePaths, sessionId: string, now = new Date()): Promise<ActionGrantStoreV1> {
  return withFileLock(paths.grantLock, async () => {
    const current = await loadGrantStoreUnlocked(paths, now)
    return saveGrantStoreUnlocked(paths, current.grants.filter((grant) => grant.sessionId !== sessionId && Date.parse(grant.expiresAt) > now.getTime()), now)
  })
}

export async function revokeActionGrantsForProfile(paths: ActionStorePaths, profile: string, now = new Date()): Promise<ActionGrantStoreV1> {
  return withFileLock(paths.grantLock, async () => {
    const current = await loadGrantStoreUnlocked(paths, now)
    return saveGrantStoreUnlocked(paths, current.grants.filter((grant) => grant.profile !== profile && Date.parse(grant.expiresAt) > now.getTime()), now)
  })
}

export async function revokeAllActionGrants(paths: ActionStorePaths, now = new Date()): Promise<ActionGrantStoreV1> {
  return withFileLock(paths.grantLock, () => saveGrantStoreUnlocked(paths, [], now))
}

export async function takeMatchingActionGrant(
  paths: ActionStorePaths,
  request: ActionRequestV1,
  policy: ActionPolicyV1,
  now = new Date(),
): Promise<ActionGrantV1 | undefined> {
  return withFileLock(paths.grantLock, async () => {
    const current = await loadGrantStoreUnlocked(paths, now)
    const active = current.grants.filter((grant) => Date.parse(grant.expiresAt) > now.getTime())
    const match = findMatchingActionGrant(active, request, policy, now)
    const retained = match?.scope === 'once' ? active.filter((grant) => grant.id !== match.id) : active
    if (retained.length !== current.grants.length) await saveGrantStoreUnlocked(paths, retained, now)
    return match
  })
}

function rotatedEventPath(path: string, index: number): string {
  return path.endsWith('.jsonl') ? `${path.slice(0, -6)}.${index}.jsonl` : `${path}.${index}`
}

function eventOptions(options: ActionEventStoreOptions): Required<Pick<ActionEventStoreOptions, 'maxBytes' | 'maxFiles'>> {
  const maxBytes = options.maxBytes ?? DEFAULT_ACTION_EVENT_MAX_BYTES
  const maxFiles = options.maxFiles ?? DEFAULT_ACTION_EVENT_MAX_FILES
  if (!Number.isInteger(maxBytes) || maxBytes < 4096) throw new ActionSchemaError('ACTION_STORE_INVALID', 'action event maxBytes must be an integer of at least 4096')
  if (!Number.isInteger(maxFiles) || maxFiles < 2 || maxFiles > 20) throw new ActionSchemaError('ACTION_STORE_INVALID', 'action event maxFiles must be between 2 and 20')
  return { maxBytes, maxFiles }
}

async function removeIfPresent(path: string): Promise<void> {
  try { await unlink(path) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
}

async function renameIfPresent(source: string, target: string): Promise<void> {
  try { await rename(source, target) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
}

async function rotateActionEvents(paths: ActionStorePaths, maxFiles: number): Promise<void> {
  await removeIfPresent(rotatedEventPath(paths.events, maxFiles - 1))
  for (let index = maxFiles - 2; index >= 1; index -= 1) {
    await renameIfPresent(rotatedEventPath(paths.events, index), rotatedEventPath(paths.events, index + 1))
  }
  await renameIfPresent(paths.events, rotatedEventPath(paths.events, 1))
}

export async function appendActionEvent(
  paths: ActionStorePaths,
  event: ActionEventV1,
  options: ActionEventStoreOptions = {},
): Promise<void> {
  const { maxBytes, maxFiles } = eventOptions(options)
  const line = `${JSON.stringify(parseActionEvent(event))}\n`
  const bytes = Buffer.byteLength(line)
  if (bytes > maxBytes) throw new ActionSchemaError('ACTION_STORE_INVALID', 'action event exceeds the configured file size')
  await withFileLock(paths.eventLock, async () => {
    await ensurePrivateDir(paths.root)
    await privateFile(paths.events)
    let size = 0
    try { size = (await stat(paths.events)).size } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    if (size > 0 && size + bytes > maxBytes) await rotateActionEvents(paths, maxFiles)
    await appendFile(paths.events, line, { encoding: 'utf8', mode: 0o600 })
    await chmod(paths.events, 0o600)
  })
}

export async function readActionEvents(
  paths: ActionStorePaths,
  options: ActionEventStoreOptions = {},
): Promise<ActionEventReadResult> {
  const { maxFiles } = eventOptions(options)
  const limit = options.limit ?? 1_000
  if (!Number.isInteger(limit) || limit < 1 || limit > 100_000) throw new ActionSchemaError('ACTION_STORE_INVALID', 'action event limit must be between 1 and 100000')
  const events: ActionEventV1[] = []
  let invalidLines = 0
  let filesRead = 0
  for (let index = 0; index < maxFiles && events.length < limit; index += 1) {
    const path = index === 0 ? paths.events : rotatedEventPath(paths.events, index)
    const text = await privateOptionalText(path)
    if (text === undefined) continue
    filesRead += 1
    const lines = text.split(/\r?\n/).filter((line) => line.trim()).reverse()
    for (const line of lines) {
      try {
        events.push(parseActionEvent(JSON.parse(line) as unknown))
      } catch {
        invalidLines += 1
      }
      if (events.length >= limit) break
    }
  }
  return { events, invalidLines, filesRead }
}

async function checkMode(path: string, expected: number, issues: string[]): Promise<void> {
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink()) issues.push(`${path}: symbolic link is not allowed`)
    else if ((info.mode & 0o777) !== expected) issues.push(`${path}: expected mode ${expected.toString(8)}`)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') issues.push(`${path}: cannot inspect`)
  }
}

export async function inspectActionStore(paths: ActionStorePaths, options: ActionEventStoreOptions = {}): Promise<ActionStoreInspection> {
  const issues: string[] = []
  const { maxBytes, maxFiles } = eventOptions(options)
  await checkMode(paths.root, 0o700, issues)
  await checkMode(paths.policy, 0o600, issues)
  await checkMode(paths.protection, 0o600, issues)
  await checkMode(paths.grants, 0o600, issues)
  await checkMode(paths.events, 0o600, issues)
  for (let index = 1; index < maxFiles; index += 1) {
    await checkMode(rotatedEventPath(paths.events, index), 0o600, issues)
  }
  try {
    await lstat(rotatedEventPath(paths.events, maxFiles))
    issues.push('action events: retention contains more files than configured')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') issues.push('action events: cannot inspect retention')
  }
  for (let index = 0; index < maxFiles; index += 1) {
    const path = index === 0 ? paths.events : rotatedEventPath(paths.events, index)
    try {
      if ((await stat(path)).size > maxBytes) issues.push(`${path}: exceeds configured maxBytes`)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') issues.push(`${path}: cannot inspect size`)
    }
  }
  let grants = 0
  let events = 0
  try { grants = (await loadGrantStoreUnlocked(paths)).grants.length } catch { issues.push('action-grants.json: invalid or unreadable') }
  try {
    if (await privateOptionalText(paths.policy) !== undefined) await loadActionPolicy(paths)
  } catch { issues.push('action-policy.json: invalid or unreadable') }
  try {
    if (await privateOptionalText(paths.protection) !== undefined) await loadActionProtectionSettings(paths)
  } catch { issues.push('action-protection.json: invalid or unreadable') }
  try {
    const result = await readActionEvents(paths, options)
    events = result.events.length
    if (result.invalidLines > 0) issues.push(`action events: ${result.invalidLines} invalid line(s)`)
  } catch { issues.push('action events: invalid or unreadable') }
  return { ok: issues.length === 0, issues, grants, events }
}
