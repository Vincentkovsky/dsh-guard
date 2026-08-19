import { mkdir, mkdtemp, readdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import {
  actionProtectionEnabled,
  actionStorePaths,
  addActionGrant,
  createActionGrant,
  createActionRequest,
  createDefaultActionPolicy,
  loadActionGrantStore,
  normalizePathResource,
} from '@dsh-guard/core/action'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Config, apply } from '../src/index.js'

type RouteHandler = (req: unknown, res: unknown) => Promise<void> | void

function request(enabled: boolean): unknown {
  const body = Buffer.from(JSON.stringify({ enabled }))
  return {
    method: 'POST',
    headers: { host: '127.0.0.1:8080', origin: 'http://127.0.0.1:8080' },
    async *[Symbol.asyncIterator]() { yield body },
  }
}

async function call(handler: RouteHandler, enabled: boolean): Promise<{ status: number; body: Record<string, unknown> }> {
  let status = 0
  let text = ''
  const response = {
    writeHead(code: number) { status = code },
    end(value: string) { text = value },
  }
  await handler(request(enabled), response)
  return { status, body: JSON.parse(text) as Record<string, unknown> }
}

function execution(callId: string, cwd: string, filePath = '~/.ssh/id_rsa'): unknown {
  return {
    callId,
    rootCallId: callId,
    name: 'read',
    arguments: { file_path: filePath },
    agent: { id: 'session-toggle', session: { header: { cwd } } },
    signal: new AbortController().signal,
    token: Symbol('toggle-test'),
  }
}

afterEach(() => vi.unstubAllEnvs())

describe('Agent action protection runtime toggle', () => {
  it('fails closed when persisted toggle state is malformed', async () => {
    const guardHome = await mkdtemp(join(tmpdir(), 'dsh-guard-runtime-toggle-invalid-'))
    const workspace = await mkdtemp(join(tmpdir(), 'dsh-workspace-runtime-toggle-invalid-'))
    vi.stubEnv('DSH_GUARD_HOME', guardHome)
    await writeFile(actionStorePaths(guardHome).protection, '{"schemaVersion":1,"profiles":[]}', { mode: 0o600 })
    const listeners = new Map<string, (...args: never[]) => unknown>()
    const ctx = {
      on: vi.fn((event: string, handler: (...args: never[]) => unknown) => { listeners.set(event, handler) }),
      effect: vi.fn(),
      webServer: { host: '0.0.0.0' },
      logger: { warn: vi.fn() },
    } as unknown as Context
    apply(ctx, new Config({ actionPolicyEnabled: false }))
    const pre = listeners.get('tools/pre-execute') as unknown as
      (execution: unknown, next: () => Promise<{ kind: 'allow' }>) => Promise<{ kind: string }>
    const next = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(pre(execution('call-invalid-settings', workspace, '.env'), next)).resolves.toMatchObject({ kind: 'ask' })
    expect(next).not.toHaveBeenCalled()
  })

  it('enables immediately, persists by profile, then disables and revokes grants', async () => {
    const guardHome = await mkdtemp(join(tmpdir(), 'dsh-guard-runtime-toggle-'))
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-home-runtime-toggle-'))
    const workspace = await mkdtemp(join(tmpdir(), 'dsh-workspace-runtime-toggle-'))
    await mkdir(join(dshHome, 'profiles', 'web'), { recursive: true })
    vi.stubEnv('DSH_GUARD_HOME', guardHome)
    vi.stubEnv('DSH_HOME', dshHome)

    const listeners = new Map<string, (...args: never[]) => unknown>()
    const routes = new Map<string, RouteHandler>()
    const disposers: Array<() => unknown> = []
    const ctx = {
      on: vi.fn((event: string, handler: (...args: never[]) => unknown) => { listeners.set(event, handler) }),
      effect: vi.fn((factory: () => unknown) => {
        const dispose = factory()
        if (typeof dispose === 'function') disposers.push(dispose as () => unknown)
      }),
      webServer: {
        host: '127.0.0.1',
        register: vi.fn((route: { path: string; handler: RouteHandler }) => {
          routes.set(route.path, route.handler)
          return () => routes.delete(route.path)
        }),
      },
      logger: { warn: vi.fn() },
    } as unknown as Context

    apply(ctx, new Config({ actionPolicyEnabled: false }))
    const pre = listeners.get('tools/pre-execute') as unknown as
      (execution: unknown, next: () => Promise<{ kind: 'allow' }>) => Promise<{ kind: string }>
    const toggle = routes.get('/dsh-guard/api/action-protection')
    expect(toggle).toBeTypeOf('function')

    const initialNext = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(pre(execution('call-off', workspace), initialNext)).resolves.toEqual({ kind: 'allow' })
    expect(initialNext).toHaveBeenCalledOnce()

    await expect(call(toggle!, true)).resolves.toMatchObject({ status: 200, body: { enabled: true, previousEnabled: false } })
    expect(await actionProtectionEnabled(actionStorePaths(guardHome), 'web')).toBe(true)
    const blockedNext = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(pre(execution('call-on', workspace), blockedNext)).resolves.toMatchObject({ kind: 'deny' })
    expect(blockedNext).not.toHaveBeenCalled()

    const policy = createDefaultActionPolicy([workspace])
    const grantRequest = createActionRequest({
      id: 'act_toggle_grant',
      profile: 'web',
      sessionId: 'session-toggle',
      toolName: 'read',
      operation: 'read',
      arguments: { file_path: '.env' },
      resources: [normalizePathResource('.env', 'read', policy, workspace)],
    })
    await addActionGrant(actionStorePaths(guardHome), createActionGrant(grantRequest, 'once', policy))
    await expect(call(toggle!, false)).resolves.toMatchObject({
      status: 200,
      body: { enabled: false, previousEnabled: true, revokedGrants: 1 },
    })
    expect(await actionProtectionEnabled(actionStorePaths(guardHome), 'web')).toBe(false)
    expect((await loadActionGrantStore(actionStorePaths(guardHome))).grants).toEqual([])
    expect(await readdir(join(dshHome, 'profiles', 'web'))).toEqual([])

    const finalNext = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(pre(execution('call-off-again', workspace), finalNext)).resolves.toEqual({ kind: 'allow' })
    expect(finalNext).toHaveBeenCalledOnce()
    await Promise.all(disposers.reverse().map(async (dispose) => { await dispose() }))
  })
})
