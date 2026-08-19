import { mkdtemp, readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { CallId } from '@deepseek-ai/dsh-llm'
import ToolRuntime, { type ToolDefinition } from '@deepseek-ai/dsh-tools'
import { describe, expect, it, vi } from 'vitest'
import { createDshActionGate } from '../src/action-gate.js'

function definition(name: string, execute: ToolDefinition['execute']): ToolDefinition {
  return {
    name,
    description: `${name} integration fixture`,
    parameters: {
      type: 'object',
      properties: {
        file_path: { type: 'string' },
        content: { type: 'string' },
      },
      required: ['file_path'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: { ok: { type: 'boolean' } },
        required: ['ok'],
        additionalProperties: false,
      },
      render: (_arguments, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    execute,
  }
}

describe('DSH rc.7 ToolRuntime integration', () => {
  it('enforces allow, native approval, deny, and authoritative result auditing', async () => {
    const runtimeEntry = createRequire(import.meta.url).resolve('@deepseek-ai/dsh-tools')
    const runtimeManifest = JSON.parse(await readFile(join(dirname(runtimeEntry), '..', 'package.json'), 'utf8')) as { version: string }
    expect(runtimeManifest.version).toBe('0.1.0-rc.7')

    const workspace = await mkdtemp(join(tmpdir(), 'dsh-guard-runtime-'))
    const ctx = new Context()
    ctx.provide('systemPrompt', {
      tools: () => () => undefined,
      section: () => () => undefined,
    })
    const approval = vi.fn(async (_request: { toolName: string; reason?: string }) => 'allowed-once' as const)
    ctx.provide('approval', { request: approval })

    const runtime = new ToolRuntime(ctx)
    const writeBody = vi.fn(async () => ({ ok: true }))
    const readBody = vi.fn(async () => ({ ok: true }))
    runtime.register(definition('write', writeBody))
    runtime.register(definition('read', readBody))

    const events: Array<NonNullable<ReturnType<ReturnType<typeof createDshActionGate>['result']>>> = []
    const gate = createDshActionGate({
      profile: 'guard-e2e',
      workspaceRoots: [workspace],
      allowedNetworkDomains: [],
      askUnknownTools: true,
      onEvent: (event) => events.push(event),
    })
    ctx.on('tools/pre-execute', (execution, next) => gate.pre(execution, next))
    ctx.on('tools/result', (execution, result) => {
      gate.result(execution, result)
      return undefined
    })

    const agent = {
      id: 'session-runtime-e2e',
      ctx,
      session: { header: { cwd: workspace } },
    } as unknown as Agent
    const execute = (callId: string, name: string, filePath: string) => runtime.execute({
      callId: callId as CallId,
      name,
      arguments: { file_path: filePath, ...(name === 'write' ? { content: 'fixture' } : {}) },
      agent,
      signal: new AbortController().signal,
    })

    const allowed = await execute('call-allow', 'write', join(workspace, 'safe.txt'))
    const approved = await execute('call-ask', 'read', join(workspace, '.env'))
    const denied = await execute('call-deny', 'read', '~/.ssh/id_ed25519')

    expect(allowed.isError).toBe(false)
    expect(approved.isError).toBe(false)
    expect(denied).toMatchObject({ isError: true, error: { message: expect.stringContaining('credential') } })
    expect(writeBody).toHaveBeenCalledOnce()
    expect(readBody).toHaveBeenCalledOnce()
    expect(approval).toHaveBeenCalledOnce()
    expect(approval.mock.calls[0]?.[0]).toMatchObject({
      toolName: 'read',
      reason: expect.stringContaining('Approval applies to this invocation only.'),
    })
    expect(events).toEqual([
      expect.objectContaining({ decision: 'allow', outcome: 'succeeded', profile: 'guard-e2e', sessionId: 'session-runtime-e2e' }),
      expect.objectContaining({ decision: 'ask', outcome: 'approved', profile: 'guard-e2e', sessionId: 'session-runtime-e2e' }),
      expect.objectContaining({ decision: 'deny', outcome: 'denied', profile: 'guard-e2e', sessionId: 'session-runtime-e2e' }),
    ])
    expect(Object.isFrozen(denied)).toBe(true)
  })
})
