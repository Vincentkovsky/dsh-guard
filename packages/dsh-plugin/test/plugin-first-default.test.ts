import type { Context } from '@deepseek-ai/cordis'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { Config, apply } from '../src/index.js'

describe('plugin-first defaults', () => {
  it('keeps Agent action protection disabled by default', () => {
    const config = new Config()
    expect(config.actionPolicyEnabled).toBe(false)
  })

  it('keeps the runtime hook pass-through while protection is disabled', async () => {
    vi.stubEnv('DSH_GUARD_HOME', await mkdtemp(join(tmpdir(), 'dsh-guard-toggle-default-')))
    const on = vi.fn()
    const guard = vi.fn()
    const config = new Config({
      denyTools: ['read'],
      askTools: ['bash'],
      actionPolicyEnabled: false,
    })
    const ctx = {
      on,
      effect: vi.fn(),
      tools: { guard },
      webServer: { host: '0.0.0.0' },
      logger: { warn: vi.fn() },
    } as unknown as Context

    apply(ctx, config)

    const pre = on.mock.calls.find(([event]) => event === 'tools/pre-execute')?.[1] as
      | ((execution: unknown, next: () => Promise<{ kind: 'allow' }>) => Promise<{ kind: string }>)
      | undefined
    expect(pre).toBeTypeOf('function')
    const next = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(pre?.({} as never, next)).resolves.toEqual({ kind: 'allow' })
    expect(next).toHaveBeenCalledOnce()
    expect(guard).not.toHaveBeenCalled()
    vi.unstubAllEnvs()
  })
})
