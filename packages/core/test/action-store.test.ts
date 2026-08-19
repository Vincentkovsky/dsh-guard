import { appendFile, chmod, lstat, mkdtemp, readFile, stat, symlink, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  ActionSchemaError,
  actionStorePaths,
  actionProtectionEnabled,
  addActionGrant,
  appendActionEvent,
  createActionEvent,
  createActionGrant,
  createActionRequest,
  createDefaultActionPolicy,
  evaluateAction,
  inspectActionStore,
  loadActionProtectionSettings,
  loadActionGrantStore,
  loadActionPolicy,
  normalizePathResource,
  readActionEvents,
  revokeActionGrantsForSession,
  revokeActionGrantsForProfile,
  saveActionPolicy,
  setActionProtectionEnabled,
  takeMatchingActionGrant,
} from '../src/index.js'
import type { ActionPolicyV1, ActionRequestV1 } from '../src/index.js'

async function fixture(): Promise<{
  root: string
  paths: ReturnType<typeof actionStorePaths>
  policy: ActionPolicyV1
  request: ActionRequestV1
}> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-guard-action-store-'))
  const workspace = join(root, 'workspace')
  const policy = createDefaultActionPolicy([workspace])
  const request = createActionRequest({
    id: 'act_store_test',
    now: new Date('2026-08-19T00:00:00.000Z'),
    profile: 'web',
    sessionId: 'session-store',
    taskId: 'task-store',
    toolName: 'read',
    operation: 'read',
    arguments: { file_path: '.env' },
    resources: [normalizePathResource('.env', 'read', policy, workspace)],
  })
  return { root, paths: actionStorePaths(root), policy, request }
}

describe('action policy and grant store', () => {
  it('persists profile-scoped action protection without changing another profile', async () => {
    const { paths } = await fixture()
    const now = new Date('2026-08-19T00:00:00.000Z')
    expect(await actionProtectionEnabled(paths, 'web')).toBe(false)
    await setActionProtectionEnabled(paths, 'web', true, now)
    expect(await actionProtectionEnabled(paths, 'web')).toBe(true)
    expect(await actionProtectionEnabled(paths, 'headless')).toBe(false)
    expect(await loadActionProtectionSettings(paths)).toEqual({
      schemaVersion: 1,
      updatedAt: now.toISOString(),
      profiles: [{ profile: 'web', enabled: true, updatedAt: now.toISOString() }],
    })
    expect((await stat(paths.protection)).mode & 0o777).toBe(0o600)
  })

  it('rejects malformed action protection state instead of silently disabling', async () => {
    const { paths } = await fixture()
    await writeFile(paths.protection, '{"schemaVersion":1,"profiles":[]}', { mode: 0o600 })
    await expect(actionProtectionEnabled(paths, 'web')).rejects.toBeInstanceOf(ActionSchemaError)
    expect((await inspectActionStore(paths)).issues).toContain('action-protection.json: invalid or unreadable')
  })

  it('round-trips a strict private policy file', async () => {
    const { paths, policy } = await fixture()
    await saveActionPolicy(paths, policy)
    expect(await loadActionPolicy(paths)).toEqual(policy)
    expect((await stat(paths.policy)).mode & 0o777).toBe(0o600)
  })

  it('atomically consumes an exact once grant at most once', async () => {
    const { paths, policy, request } = await fixture()
    const now = new Date('2026-08-19T00:00:00.000Z')
    const grant = createActionGrant(request, 'once', policy, { id: 'agrant_once_store', now, ttlMs: 60_000 })
    await addActionGrant(paths, grant, now)
    const claims = await Promise.all([
      takeMatchingActionGrant(paths, request, policy, new Date('2026-08-19T00:00:01.000Z')),
      takeMatchingActionGrant(paths, request, policy, new Date('2026-08-19T00:00:01.000Z')),
    ])
    expect(claims.filter(Boolean)).toHaveLength(1)
    expect((await loadActionGrantStore(paths)).grants).toEqual([])
    expect((await stat(paths.grants)).mode & 0o777).toBe(0o600)
  })

  it('retains a scoped task grant until session revocation', async () => {
    const { paths, policy, request } = await fixture()
    const now = new Date('2026-08-19T00:00:00.000Z')
    const grant = createActionGrant(request, 'task', policy, { id: 'agrant_task_store', now, ttlMs: 60_000 })
    await addActionGrant(paths, grant, now)
    await expect(takeMatchingActionGrant(paths, request, policy, new Date('2026-08-19T00:00:01.000Z'))).resolves.toMatchObject({ id: grant.id })
    expect((await loadActionGrantStore(paths)).grants).toHaveLength(1)
    await revokeActionGrantsForSession(paths, request.sessionId, new Date('2026-08-19T00:00:02.000Z'))
    expect((await loadActionGrantStore(paths)).grants).toEqual([])
  })

  it('revokes grants only for the disabled profile', async () => {
    const { paths, policy, request } = await fixture()
    const now = new Date('2026-08-19T00:00:00.000Z')
    const otherRequest = { ...request, id: 'act_store_other_profile', profile: 'headless', sessionId: 'session-headless' }
    await addActionGrant(paths, createActionGrant(request, 'task', policy, { id: 'agrant_web', now, ttlMs: 60_000 }), now)
    await addActionGrant(paths, createActionGrant(otherRequest, 'task', policy, { id: 'agrant_headless', now, ttlMs: 60_000 }), now)
    await revokeActionGrantsForProfile(paths, 'web', new Date('2026-08-19T00:00:01.000Z'))
    expect((await loadActionGrantStore(paths)).grants).toEqual([expect.objectContaining({ id: 'agrant_headless', profile: 'headless' })])
  })

  it('rejects malformed or overly permissive grant state instead of authorizing', async () => {
    const { paths, policy, request } = await fixture()
    await writeFile(paths.grants, '{"schemaVersion":1,"grants":[{"scope":"task"}]}', { mode: 0o600 })
    await chmod(paths.grants, 0o600)
    await expect(takeMatchingActionGrant(paths, request, policy)).rejects.toBeInstanceOf(ActionSchemaError)
    expect(evaluateAction(request, policy)).toMatchObject({ effect: 'ask', ruleId: 'path.sensitive' })
  })

  it('rejects duplicate grant identities', async () => {
    const { paths, policy, request } = await fixture()
    const now = new Date('2026-08-19T00:00:00.000Z')
    const grant = createActionGrant(request, 'once', policy, { id: 'agrant_duplicate', now, ttlMs: 60_000 })
    await addActionGrant(paths, grant, now)
    await expect(addActionGrant(paths, grant, now)).rejects.toThrow(/already exists/)
  })

  it('recovers a stale lock only when its owner is gone', async () => {
    const { paths, policy, request } = await fixture()
    await writeFile(paths.grantLock, '99999999:dead-owner', { mode: 0o600 })
    const old = new Date(Date.now() - 60_000)
    await utimes(paths.grantLock, old, old)
    const grant = createActionGrant(request, 'once', policy, { id: 'agrant_after_stale_lock', ttlMs: 60_000 })
    await expect(addActionGrant(paths, grant)).resolves.toMatchObject({ grants: [{ id: grant.id }] })
  })
})

describe('action event store', () => {
  it('rotates bounded JSONL files and reads newest events first', async () => {
    const { paths, policy, request } = await fixture()
    const decision = evaluateAction(request, policy)
    for (let index = 0; index < 45; index += 1) {
      const now = new Date(Date.UTC(2026, 7, 19, 0, 0, index))
      const event = createActionEvent(request, decision, 'denied', { id: `aevt_${String(index).padStart(3, '0')}`, now })
      await appendActionEvent(paths, event, { maxBytes: 4096, maxFiles: 3 })
    }
    const result = await readActionEvents(paths, { maxBytes: 4096, maxFiles: 3, limit: 100 })
    expect(result.invalidLines).toBe(0)
    expect(result.filesRead).toBe(3)
    expect(result.events[0]?.id).toBe('aevt_044')
    expect(result.events.at(-1)?.id).not.toBe('aevt_000')
    for (const file of [paths.events, paths.events.replace('.jsonl', '.1.jsonl'), paths.events.replace('.jsonl', '.2.jsonl')]) {
      expect((await stat(file)).size).toBeLessThanOrEqual(4096)
      expect((await stat(file)).mode & 0o777).toBe(0o600)
    }
  })

  it('reports invalid lines without turning them into events', async () => {
    const { paths, policy, request } = await fixture()
    const event = createActionEvent(request, evaluateAction(request, policy), 'denied')
    await appendActionEvent(paths, event)
    await appendFile(paths.events, '{broken-json}\n')
    const result = await readActionEvents(paths)
    expect(result.events).toHaveLength(1)
    expect(result.invalidLines).toBe(1)
    expect((await inspectActionStore(paths)).ok).toBe(false)
  })

  it('rejects symlink event targets', async () => {
    const { root, paths, policy, request } = await fixture()
    const outside = join(root, 'outside.jsonl')
    await writeFile(outside, '')
    await symlink(outside, paths.events)
    const event = createActionEvent(request, evaluateAction(request, policy), 'denied')
    await expect(appendActionEvent(paths, event)).rejects.toThrow(/symbolic links/)
    expect((await lstat(paths.events)).isSymbolicLink()).toBe(true)
    expect(await readFile(outside, 'utf8')).toBe('')
  })
})
