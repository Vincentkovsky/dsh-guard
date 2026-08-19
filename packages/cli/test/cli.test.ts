import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  actionPolicyHash,
  actionStorePaths,
  addActionGrant,
  appendActionEvent,
  createActionEvent,
  createActionGrant,
  createActionRequest,
  createDefaultActionPolicy,
  evaluateAction,
  normalizeCommandResource,
  normalizePathResource,
  loadActionGrantStore,
  sha256,
  statePaths,
  type ScanReport,
  type GuardStatusSnapshot,
  type ManagedProfileV1,
  type SandboxPlanV1,
} from '@dsh-guard/core'
import { createProgram, EXIT, runCli, supportsDshNode, type CliServices } from '../src/index.js'

const tokenShapedFixture = ['ghp', 'abcdefghijklmnopqrstuvwxyz123456'].join('_')

afterEach(() => {
  process.exitCode = undefined
  vi.restoreAllMocks()
})

const report: ScanReport = {
  schemaVersion: 1,
  id: 'rpt_test',
  createdAt: '2026-08-19T00:00:00.000Z',
  policyHash: 'policy',
  verdict: 'review',
  summary: 'Human review is required before installation.',
  source: {
    kind: 'tarball', requested: 'fixture.tgz', name: 'fixture-plugin', version: '1.0.0',
    artifactPath: '/tmp/fixture.tgz', sha256: 'a'.repeat(64),
  },
  profile: {
    name: 'web', path: '/tmp/dsh/profiles/web', fingerprint: 'b'.repeat(64), files: {}, bundles: [],
  },
  files: [],
  entrypoints: [],
  dependencyGraph: {},
  findings: [],
  stage: { attempted: false, compatible: false, reason: 'disabled for test' },
}

const fixtureRoot = fileURLToPath(new URL('./fixtures/action', import.meta.url))

function sandboxPlan(): SandboxPlanV1 {
  const policy = '(version 1)\n(deny default)\n'
  return {
    schemaVersion: 1,
    id: 'sbx_20260819000000000_fixture',
    createdAt: '2026-08-19T00:00:00.000Z',
    platform: 'darwin',
    profile: 'web',
    network: 'loopback',
    nodePath: '/opt/node/bin/node',
    dshBin: '/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js',
    dshRuntimeRoot: '/opt/dsh',
    sourceDshHome: '/tmp/source-dsh-home',
    sourceProfile: '/tmp/source-dsh-home/profiles/web',
    dshHome: '/tmp/guard-home/sandbox-runs/run-fixture/dsh-home',
    guardHome: '/tmp/guard-home',
    tempRoot: '/tmp/guard-home/sandbox-runs/run-fixture/tmp',
    workspaceRoots: ['/tmp/workspace'],
    readOnlyPaths: ['/opt/dsh', '/opt/node'],
    readWritePaths: [
      '/tmp/guard-home',
      '/tmp/guard-home/sandbox-runs/run-fixture/dsh-home',
      '/tmp/guard-home/sandbox-runs/run-fixture/dsh-home/profiles/web',
      '/tmp/guard-home/sandbox-runs/run-fixture/tmp',
      '/tmp/workspace',
    ],
    allowedEnvironmentNames: [
      'DSH_GUARD_HOME', 'DSH_HOME', 'HOME', 'LANG', 'LC_ALL', 'NO_COLOR', 'PATH', 'SAFE_FLAG', 'TERM', 'TMPDIR',
    ].sort((left, right) => left.localeCompare(right)),
    policy,
    policyHash: sha256(policy),
    warnings: ['Experimental sandbox warning.'],
  }
}

function sandboxRuntime(plan = sandboxPlan()) {
  return {
    root: '/tmp/guard-home/sandbox-runs/run-fixture',
    dshHome: plan.dshHome,
    tempRoot: plan.tempRoot,
    sourceProfile: '/tmp/source-dsh-home/profiles/web',
    runtimeProfile: `${plan.dshHome}/profiles/web`,
  }
}

function guardStatus(status: GuardStatusSnapshot['status'] = 'verified'): GuardStatusSnapshot {
  return {
    schemaVersion: 1,
    generatedAt: '2026-08-19T00:00:00.000Z',
    status,
    label: status,
    detail: 'fixture status',
    profile: 'web',
    counts: { reports: 0, review: 0, blocked: 0, activeAlerts: 0 },
    events: [],
    managedPackages: [],
  }
}

describe('runtime requirements', () => {
  it.each([
    ['22.21.9', false],
    ['22.22.0', true],
    ['v22.23.1', true],
    ['23.0.0', true],
    ['22.22.0-rc.1', false],
    ['invalid', false],
  ])('evaluates Node %s', (version, expected) => {
    expect(supportsDshNode(version)).toBe(expected)
  })
})

describe('doctor', () => {
  it('reports a supported runtime, DSH executable, and private state directory', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-guard-cli-test-'))
    const paths = statePaths(root)
    const output: string[] = []
    const program = createProgram({
      statePaths: () => paths,
      nodeVersion: '22.22.0',
      locateDshBin: async () => ({ command: process.execPath, prefix: ['/opt/dsh/lib/bin.js'] }),
      log: (line) => output.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'doctor'])

    expect(output).toHaveLength(5)
    expect(output.every((line) => line.startsWith('✓'))).toBe(true)
    expect(process.exitCode).toBeUndefined()
  })

  it('fails closed when runtime, DSH, and state permissions are invalid', async () => {
    const output: string[] = []
    const program = createProgram({
      nodeVersion: '22.21.0',
      initState: async () => undefined,
      locateDshBin: async () => undefined,
      statMode: async () => 0o755,
      inspectActionStore: async () => ({ ok: false, issues: ['grant state invalid'], grants: 0, events: 0 }),
      inspectLifecycleState: async () => ({ ok: false, profiles: 1, generations: 2, locks: ['profile-web.lock'], issues: ['active or stale lifecycle lock: profile-web.lock'] }),
      log: (line) => output.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'doctor'])

    expect(output).toEqual([
      '× Node.js >=22.22.0 (DSH rc.7 runtime): v22.21.0',
      '× DSH executable: set DSH_BIN',
      '× State directory mode: 755',
      '× Action state: grant state invalid',
      '× Plugin lifecycle state: active or stale lifecycle lock: profile-web.lock',
    ])
    expect(process.exitCode).toBe(EXIT.runtime)
  })
})

describe('CLI contracts', () => {
  it.each([
    ['pass', EXIT.ok],
    ['review', EXIT.review],
    ['blocked', EXIT.blocked],
  ] as const)('maps scan verdict %s to exit code %s', async (verdict, exitCode) => {
    const output: string[] = []
    const scanMock = vi.fn(async () => ({ ...report, verdict }))
    const program = createProgram({
      scan: scanMock as CliServices['scan'],
      log: (line) => output.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'scan', 'fixture.tgz', '--profile', 'web', '--no-stage', '--json'])

    expect(scanMock).toHaveBeenCalledWith('fixture.tgz', { profile: 'web', stage: false })
    expect(JSON.parse(output.join('\n'))).toMatchObject({ id: 'rpt_test', verdict })
    expect(process.exitCode).toBe(exitCode)
    process.exitCode = undefined
  })

  it('requires a target profile for scan', async () => {
    const program = createProgram()
    const scanCommand = program.commands.find((command) => command.name() === 'scan')
    expect(scanCommand).toBeDefined()
    scanCommand?.exitOverride()
    scanCommand?.configureOutput({ writeErr: () => undefined })
    await expect(program.parseAsync(['node', 'dsh-guard', 'scan', 'fixture.tgz']))
      .rejects.toMatchObject({ code: 'commander.missingMandatoryOptionValue' })
  })

  it('maps runtime failures to stderr and exit code 4', async () => {
    const errors: string[] = []
    await runCli(['node', 'dsh-guard', 'report'], {
      listReportIds: async () => { throw new Error('fixture runtime failure') },
      error: (line) => errors.push(line),
    })
    expect(errors).toEqual(['dsh-guard: fixture runtime failure'])
    expect(process.exitCode).toBe(EXIT.runtime)
  })
})

describe('guarded start CLI', () => {
  it('verifies, rechecks the fingerprint, writes status, audits, and launches the exact profile', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-guard-cli-start-'))
    const paths = statePaths(root)
    const audit = vi.fn(async () => undefined)
    const writeStatus = vi.fn(async () => undefined)
    const runner = vi.fn(async () => 0)
    const buildEnvironment = vi.fn(() => ({ DSH_HOME: '/tmp/dsh-home', DSH_GUARD_LAUNCH_MODE: 'verified' }))
    const verification = {
      status: 'verified' as const,
      profile: report.profile,
      detail: 'matches managed generation',
      unmanagedBundles: [],
      generationId: 'gen_verified',
    }
    const program = createProgram({
      statePaths: () => paths,
      initState: async () => undefined,
      locateDshBin: async () => ({ command: process.execPath, prefix: ['/opt/dsh/lib/bin.js'] }),
      dshHomePath: () => '/tmp/dsh-home',
      verifyProfile: async () => verification,
      buildStatusSnapshot: async () => guardStatus(),
      writeStatusFile: writeStatus,
      snapshotProfile: async () => report.profile,
      buildGuardedDshEnvironment: buildEnvironment,
      appendAudit: audit,
      runGuardedDsh: runner,
      stableJson: (value) => JSON.stringify(value),
      sha256: () => 'argument-digest',
      cwd: '/tmp/workspace',
      environment: { NODE_OPTIONS: '--require attacker.js' },
      log: () => undefined,
    })

    await program.parseAsync([
      'node', 'dsh-guard', 'start', '--profile', 'web', '--', '--host=127.0.0.1', '--port=8080',
    ])

    expect(writeStatus).toHaveBeenCalledWith(paths, expect.objectContaining({ status: 'verified' }))
    expect(buildEnvironment).toHaveBeenCalledWith(
      { NODE_OPTIONS: '--require attacker.js' },
      { dshHome: '/tmp/dsh-home', guardHome: paths.root },
    )
    expect(audit).toHaveBeenCalledWith(paths, 'guarded-start-allow', expect.objectContaining({
      profile: 'web',
      generationId: 'gen_verified',
      argumentDigest: 'argument-digest',
    }))
    expect(runner).toHaveBeenCalledWith(
      { command: process.execPath, prefix: ['/opt/dsh/lib/bin.js'] },
      'web',
      ['--host=127.0.0.1', '--port=8080'],
      { DSH_HOME: '/tmp/dsh-home', DSH_GUARD_LAUNCH_MODE: 'verified' },
      { cwd: '/tmp/workspace' },
    )
    expect(audit).toHaveBeenCalledWith(paths, 'guarded-start-exit', { profile: 'web', code: 0 })
    expect(process.exitCode).toBeUndefined()
  })

  it.each([
    ['drifted', ['evil-plugin'], EXIT.review],
    ['unknown', [], EXIT.review],
    ['needs-repair', [], EXIT.repair],
  ] as const)('quarantines a %s profile before creating a DSH process', async (status, unmanagedBundles, exitCode) => {
    const errors: string[] = []
    const audit = vi.fn(async () => undefined)
    const runner = vi.fn(async () => 0)
    const program = createProgram({
      initState: async () => undefined,
      locateDshBin: async () => ({ command: process.execPath, prefix: ['/opt/dsh/lib/bin.js'] }),
      dshHomePath: () => '/tmp/dsh-home',
      verifyProfile: async () => ({
        status,
        profile: report.profile,
        detail: 'unmanaged plugin detected',
        unmanagedBundles: [...unmanagedBundles],
      }),
      buildStatusSnapshot: async () => guardStatus(status),
      writeStatusFile: async () => undefined,
      appendAudit: audit,
      runGuardedDsh: runner,
      error: (line) => errors.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'start', '--profile', 'web'])

    expect(runner).not.toHaveBeenCalled()
    expect(audit).toHaveBeenCalledWith(expect.any(Object), 'guarded-start-deny', expect.objectContaining({
      status,
      unmanagedBundles: [...unmanagedBundles],
    }))
    expect(errors.join('\n')).toContain('启动已隔离')
    if (unmanagedBundles.length) expect(errors.join('\n')).toContain('evil-plugin')
    expect(process.exitCode).toBe(exitCode)
  })

  it('fails closed when the profile changes after verification', async () => {
    const runner = vi.fn(async () => 0)
    const audit = vi.fn(async () => undefined)
    const verify = vi.fn()
      .mockResolvedValueOnce({
        status: 'verified',
        profile: report.profile,
        detail: 'verified',
        unmanagedBundles: [],
        generationId: 'gen_verified',
      })
      .mockResolvedValueOnce({
        status: 'drifted',
        profile: { ...report.profile, fingerprint: 'c'.repeat(64) },
        detail: 'changed after verification',
        unmanagedBundles: [],
      })
    const program = createProgram({
      initState: async () => undefined,
      locateDshBin: async () => ({ command: process.execPath, prefix: ['/opt/dsh/lib/bin.js'] }),
      dshHomePath: () => '/tmp/dsh-home',
      verifyProfile: verify,
      snapshotProfile: async () => ({ ...report.profile, fingerprint: 'c'.repeat(64) }),
      buildStatusSnapshot: async (_paths, verification) => guardStatus(verification.status),
      writeStatusFile: async () => undefined,
      appendAudit: audit,
      runGuardedDsh: runner,
      error: () => undefined,
    })

    await program.parseAsync(['node', 'dsh-guard', 'start', '--profile', 'web'])

    expect(verify).toHaveBeenCalledTimes(2)
    expect(runner).not.toHaveBeenCalled()
    expect(audit).toHaveBeenCalledWith(expect.any(Object), 'guarded-start-deny', expect.objectContaining({
      status: 'changed-after-verification',
    }))
    expect(process.exitCode).toBe(EXIT.review)
  })
})

describe('sandbox CLI', () => {
  it('prints a machine-readable plan without environment values', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-guard-cli-sandbox-'))
    const output: string[] = []
    const createPlan = vi.fn(async () => sandboxPlan())
    const program = createProgram({
      statePaths: () => statePaths(root),
      initState: async () => undefined,
      locateDshBin: async () => ({ command: '/opt/node/bin/node', prefix: ['/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js'] }),
      dshHomePath: () => '/tmp/source-dsh-home',
      prepareSandboxRuntime: async () => sandboxRuntime(),
      cleanupSandboxRuntime: async () => undefined,
      createSandboxPlan: createPlan,
      environment: { SAFE_FLAG: 'super-secret-value' },
      platform: 'darwin',
      nodePath: '/opt/node/bin/node',
      log: (line) => output.push(line),
    })

    await program.parseAsync([
      'node', 'dsh-guard', 'sandbox', 'plan', '--profile', 'web',
      '--workspace', '/tmp/workspace', '--allow-env', 'SAFE_FLAG', '--json',
    ])

    expect(createPlan).toHaveBeenCalledWith(expect.objectContaining({
      profile: 'web',
      workspaceRoots: ['/tmp/workspace'],
      network: 'loopback',
      allowEnvironment: ['SAFE_FLAG'],
    }))
    expect(JSON.parse(output.join('\n'))).toMatchObject({ schemaVersion: 1, profile: 'web', network: 'loopback' })
    expect(output.join('\n')).not.toContain('super-secret-value')
  })

  it('requires an explicit workspace', async () => {
    const program = createProgram({
      initState: async () => undefined,
      locateDshBin: async () => ({ command: process.execPath, prefix: ['/opt/dsh/lib/bin.js'] }),
    })
    await expect(program.parseAsync(['node', 'dsh-guard', 'sandbox', 'plan', '--profile', 'web']))
      .rejects.toThrow(/At least one --workspace/)
  })

  it('verifies, audits, and launches with exact pass-through arguments', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-guard-cli-sandbox-'))
    const plan = sandboxPlan()
    const audit = vi.fn(async () => undefined)
    const runner = vi.fn(async () => 7)
    const buildEnvironment = vi.fn(() => ({ SAFE_FLAG: 'super-secret-value' }))
    const cleanup = vi.fn(async () => undefined)
    const verify = vi.fn(async () => ({
      status: 'verified' as const,
      profile: report.profile,
      detail: 'matches managed generation',
      unmanagedBundles: [],
    }))
    const program = createProgram({
      statePaths: () => statePaths(root),
      initState: async () => undefined,
      locateDshBin: async () => ({ command: plan.nodePath, prefix: [plan.dshBin] }),
      dshHomePath: () => '/tmp/source-dsh-home',
      prepareSandboxRuntime: async () => sandboxRuntime(plan),
      cleanupSandboxRuntime: cleanup,
      createSandboxPlan: async () => plan,
      verifyProfile: verify,
      snapshotProfile: async () => report.profile,
      buildSandboxEnvironment: buildEnvironment,
      appendAudit: audit,
      sandboxPlanDigest: () => 'plan-digest',
      sha256: () => 'workspace-digest',
      stableJson: () => '["/tmp/workspace"]\n',
      validateSandboxAppArgs: vi.fn(),
      runSandboxedDsh: runner,
      environment: { SAFE_FLAG: 'super-secret-value' },
      platform: 'darwin',
      nodePath: plan.nodePath,
      log: () => undefined,
    })

    await program.parseAsync([
      'node', 'dsh-guard', 'sandbox', 'run', '--profile', 'web', '--workspace', '/tmp/workspace',
      '--allow-env', 'SAFE_FLAG', '--', '--dump-config', '--host=127.0.0.1',
    ])

    expect(verify).toHaveBeenCalledWith('web', expect.any(Object), '/tmp/source-dsh-home')
    expect(audit).toHaveBeenCalledWith(expect.any(Object), 'sandbox-run', expect.objectContaining({
      planDigest: 'plan-digest',
      workspaceDigest: 'workspace-digest',
      allowedEnvironmentNames: plan.allowedEnvironmentNames,
    }))
    expect(JSON.stringify(audit.mock.calls)).not.toContain('super-secret-value')
    expect(runner).toHaveBeenCalledWith(
      plan,
      ['--dump-config', '--host=127.0.0.1'],
      { SAFE_FLAG: 'super-secret-value' },
      { platform: 'darwin' },
    )
    expect(process.exitCode).toBe(7)
    expect(cleanup).toHaveBeenCalledWith('/tmp/guard-home/sandbox-runs/run-fixture', expect.any(String))
  })

  it('fails closed before audit and launch when the profile has drifted', async () => {
    const plan = sandboxPlan()
    const audit = vi.fn(async () => undefined)
    const runner = vi.fn(async () => 0)
    const program = createProgram({
      initState: async () => undefined,
      locateDshBin: async () => ({ command: plan.nodePath, prefix: [plan.dshBin] }),
      dshHomePath: () => '/tmp/source-dsh-home',
      createSandboxPlan: async () => plan,
      verifyProfile: async () => ({
        status: 'drifted',
        profile: report.profile,
        detail: 'fixture drift',
        unmanagedBundles: ['evil-plugin'],
      }),
      appendAudit: audit,
      runSandboxedDsh: runner,
      platform: 'darwin',
      nodePath: plan.nodePath,
    })

    await expect(program.parseAsync([
      'node', 'dsh-guard', 'sandbox', 'run', '--profile', 'web', '--workspace', '/tmp/workspace', '--', '--dump-config',
    ])).rejects.toThrow(/profile web is drifted/)
    expect(audit).not.toHaveBeenCalled()
    expect(runner).not.toHaveBeenCalled()
  })
})

describe('Action policy CLI', () => {
  it('shows the default policy with a stable hash', async () => {
    const output: string[] = []
    const program = createProgram({ cwd: '/workspace/project', log: (line) => output.push(line) })

    await program.parseAsync(['node', 'dsh-guard', 'policy', 'show', '--json'])

    const result = JSON.parse(output.join('\n')) as { schemaVersion: number; policyHash: string; policy: unknown }
    expect(result).toMatchObject({ schemaVersion: 1, policyHash: expect.stringMatching(/^[a-f0-9]{64}$/) })
    expect(result.policyHash).toBe(actionPolicyHash(createDefaultActionPolicy(['/workspace/project'])))
    expect(process.exitCode).toBeUndefined()
  })

  it('loads a custom policy file without echoing file contents', async () => {
    const policy = { ...createDefaultActionPolicy(['/workspace/project']), id: 'custom', allowedNetworkDomains: ['example.com'] }
    const output: string[] = []
    const program = createProgram({
      readText: async (path) => {
        expect(path).toBe('/tmp/policy.json')
        return JSON.stringify(policy)
      },
      log: (line) => output.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'policy', 'show', '--policy', '/tmp/policy.json'])

    expect(output).toContain('Action policy: custom')
    expect(output).toContain('  Allowed network domains: example.com')
  })

  it('uses a supplied policy when checking an action', async () => {
    const policy = { ...createDefaultActionPolicy(['/workspace/project']), allowedNetworkDomains: ['unknown.example'] }
    const requestPath = join(fixtureRoot, 'unknown-network-send.json')
    const output: string[] = []
    const program = createProgram({
      cwd: '/workspace/project',
      readText: async (path) => path === '/tmp/policy.json'
        ? JSON.stringify(policy)
        : readFile(path, 'utf8'),
      log: (line) => output.push(line),
    })

    await program.parseAsync([
      'node', 'dsh-guard', 'policy', 'check', requestPath, '--policy', '/tmp/policy.json', '--json',
    ])

    expect(JSON.parse(output.join('\n'))).toMatchObject({ effect: 'allow', ruleId: 'action.safe-default' })
    expect(process.exitCode).toBe(EXIT.ok)
  })

  it.each([
    ['safe-source-read.json', 'allow', 'action.safe-default', EXIT.ok],
    ['safe-workspace-write.json', 'allow', 'action.safe-default', EXIT.ok],
    ['safe-git-status.json', 'allow', 'action.safe-default', EXIT.ok],
    ['sensitive-env-read.json', 'ask', 'path.sensitive', EXIT.review],
    ['outside-delete.json', 'deny', 'path.delete-outside-workspace', EXIT.blocked],
    ['unknown-network-send.json', 'ask', 'network.unapproved-domain', EXIT.review],
    ['download-execute.json', 'deny', 'process.download-then-execute', EXIT.blocked],
    ['chained-root-delete.json', 'deny', 'process.denied-command', EXIT.blocked],
    ['encoded-shell.json', 'ask', 'process.execute', EXIT.review],
  ] as const)('evaluates corpus fixture %s as %s', async (name, effect, ruleId, exitCode) => {
    const output: string[] = []
    const program = createProgram({ cwd: '/workspace/project', log: (line) => output.push(line) })

    await program.parseAsync(['node', 'dsh-guard', 'policy', 'check', join(fixtureRoot, name), '--json'])

    expect(JSON.parse(output.join('\n'))).toMatchObject({ schemaVersion: 1, effect, ruleId })
    expect(process.exitCode).toBe(exitCode)
    process.exitCode = undefined
  })

  it('accepts an ActionRequestV1 from stdin without executing anything', async () => {
    const policy = createDefaultActionPolicy(['/workspace/project'])
    const action = createActionRequest({
      id: 'act_stdin',
      now: new Date('2026-08-19T00:00:00.000Z'),
      profile: 'web',
      sessionId: 'session-stdin',
      toolName: 'bash',
      operation: 'execute',
      resources: [normalizeCommandResource('git status', policy)],
    })
    const output: string[] = []
    const readText = vi.fn(async () => { throw new Error('readText should not be called') })
    const program = createProgram({
      cwd: '/workspace/project',
      readText,
      readStdin: async () => JSON.stringify(action),
      log: (line) => output.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'policy', 'check', '-'])

    expect(readText).not.toHaveBeenCalled()
    expect(output[0]).toContain('ALLOW LOW')
  })

  it('redacts secrets in human-readable resource output', async () => {
    const policy = createDefaultActionPolicy(['/workspace/project'])
    const secret = tokenShapedFixture
    const authorizationHeader = ['Authorization:', 'Bearer', secret].join(' ')
    const action = createActionRequest({
      id: 'act_secret',
      now: new Date('2026-08-19T00:00:00.000Z'),
      profile: 'web',
      sessionId: 'session-secret',
      toolName: 'bash',
      operation: 'execute',
      resources: [normalizeCommandResource(`curl -H "${authorizationHeader}" https://example.com`, policy)],
    })
    const output: string[] = []
    const program = createProgram({
      cwd: '/workspace/project',
      readText: async () => JSON.stringify(action),
      log: (line) => output.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'policy', 'check', '/tmp/action.json'])

    expect(output.join('\n')).not.toContain(secret)
    expect(output.join('\n')).toContain('[redacted]')
  })

  it('rejects invalid JSON, unknown schemas, and oversized inputs without echoing secrets', async () => {
    const secret = 'do-not-echo-this-secret'
    const cases = [
      `{ "schemaVersion": 1, "secret": "${secret}"`,
      JSON.stringify({ schemaVersion: 99, secret }),
      'x'.repeat(1024 * 1024 + 1),
    ]
    for (const contents of cases) {
      const errors: string[] = []
      await runCli(['node', 'dsh-guard', 'policy', 'check', '/tmp/action.json'], {
        cwd: '/workspace/project',
        readText: async () => contents,
        error: (line) => errors.push(line),
      })
      expect(errors).toHaveLength(1)
      expect(errors[0]).not.toContain(secret)
      expect(process.exitCode).toBe(EXIT.runtime)
      process.exitCode = undefined
    }
  })

  it('keeps fixture files valid JSON documents', async () => {
    const names = [
      'safe-source-read.json', 'safe-workspace-write.json', 'safe-git-status.json',
      'sensitive-env-read.json', 'outside-delete.json', 'unknown-network-send.json',
      'download-execute.json', 'chained-root-delete.json', 'encoded-shell.json',
    ]
    for (const name of names) {
      const contents = await readFile(join(fixtureRoot, name), 'utf8')
      expect(() => JSON.parse(contents)).not.toThrow()
    }
  })
})

describe('Action state CLI', () => {
  it('lists redacted action events as JSON', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-guard-cli-events-'))
    const policy = createDefaultActionPolicy([root])
    const request = createActionRequest({
      id: 'act_cli_event',
      profile: 'web',
      sessionId: 'session-cli',
      toolName: 'read',
      operation: 'read',
      arguments: { file_path: '.env' },
      resources: [normalizePathResource('.env', 'read', policy, root)],
    })
    await appendActionEvent(actionStorePaths(root), createActionEvent(request, { ...evaluateAction(request, policy) }, 'denied'))
    const output: string[] = []
    const program = createProgram({ statePaths: () => statePaths(root), log: (line) => output.push(line) })

    await program.parseAsync(['node', 'dsh-guard', 'events', 'list', '--limit', '10', '--json'])

    const value = JSON.parse(output.join('\n')) as { events: Array<{ requestId: string }>, invalidLines: number }
    expect(value.events).toMatchObject([{ requestId: 'act_cli_event' }])
    expect(value.invalidLines).toBe(0)
  })

  it('lists and revokes an exact grant', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-guard-cli-grants-'))
    const policy = createDefaultActionPolicy([root])
    const request = createActionRequest({
      id: 'act_cli_grant',
      profile: 'web',
      sessionId: 'session-cli',
      toolName: 'read',
      operation: 'read',
      arguments: { file_path: '.env' },
      resources: [normalizePathResource('.env', 'read', policy, root)],
    })
    const grant = createActionGrant(request, 'once', policy, { id: 'agrant_cli', ttlMs: 60_000 })
    await addActionGrant(actionStorePaths(root), grant)
    const output: string[] = []
    const program = createProgram({ statePaths: () => statePaths(root), log: (line) => output.push(line) })

    await program.parseAsync(['node', 'dsh-guard', 'grants', 'list', '--json'])
    expect(JSON.parse(output.join('\n'))).toMatchObject({ grants: [{ id: 'agrant_cli' }] })
    output.length = 0
    await program.parseAsync(['node', 'dsh-guard', 'grants', 'revoke', 'agrant_cli'])
    expect(output).toEqual(['Revoked Action Gate grant agrant_cli.'])
    expect((await loadActionGrantStore(actionStorePaths(root))).grants).toEqual([])
  })
})

describe('Plugin lifecycle CLI', () => {
  const managed: ManagedProfileV1 = {
    schemaVersion: 1,
    profile: 'web',
    createdAt: '2026-08-19T00:00:00.000Z',
    updatedAt: '2026-08-19T01:00:00.000Z',
    currentGenerationId: 'gen_current',
    generations: [{
      schemaVersion: 1,
      id: 'gen_current',
      profile: 'web',
      createdAt: '2026-08-19T01:00:00.000Z',
      action: 'install',
      profileFingerprint: 'b'.repeat(64),
      bundles: ['fixture-plugin'],
      plugins: [{
        schemaVersion: 1,
        packageName: 'fixture-plugin',
        version: '1.0.0',
        reportId: 'rpt_fixture',
        artifactSha256: 'a'.repeat(64),
        installedAt: '2026-08-19T00:00:00.000Z',
        updatedAt: '2026-08-19T01:00:00.000Z',
        bundles: ['fixture-plugin'],
      }],
    }],
  }

  it('lists all managed packages and maps drift to review', async () => {
    const output: string[] = []
    const inspect = vi.fn(async () => [{
      schemaVersion: 1 as const,
      profile: 'web',
      generationId: 'gen_current',
      state: 'drifted' as const,
      detail: 'Profile differs from the current managed generation.',
      plugins: managed.generations[0]!.plugins,
      generationCount: 1,
    }])
    const program = createProgram({ inspectManagedProfiles: inspect, log: (line) => output.push(line) })

    await program.parseAsync(['node', 'dsh-guard', 'plugins', 'list', '--profile', 'web', '--json'])

    expect(inspect).toHaveBeenCalledWith(expect.any(Object), 'web')
    expect(JSON.parse(output.join('\n'))).toMatchObject({ profiles: [{ profile: 'web', state: 'drifted', plugins: [{ packageName: 'fixture-plugin' }] }] })
    expect(process.exitCode).toBe(EXIT.review)
  })

  it('prints generation history with the current marker', async () => {
    const output: string[] = []
    const program = createProgram({
      loadOrImportManagedProfile: async () => managed,
      log: (line) => output.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'plugins', 'history', '--profile', 'web'])

    expect(output[0]).toContain('current gen_current')
    expect(output).toContain('* gen_current INSTALL 2026-08-19T01:00:00.000Z')
  })

  it('routes an approved update report through the guarded updater', async () => {
    const update = vi.fn(async () => ({
      schemaVersion: 1 as const,
      reportId: 'rpt_update',
      installedAt: '2026-08-19T02:00:00.000Z',
      lastVerifiedAt: '2026-08-19T02:00:00.000Z',
      profile: 'web',
      packageName: 'fixture-plugin',
      version: '2.0.0',
      artifactSha256: 'c'.repeat(64),
      expectedProfileFingerprint: 'd'.repeat(64),
      resultingProfileFingerprint: 'd'.repeat(64),
      expectedBundles: ['fixture-plugin'],
    }))
    const output: string[] = []
    const program = createProgram({ updateApproved: update, log: (line) => output.push(line) })

    await program.parseAsync(['node', 'dsh-guard', 'plugins', 'update', 'rpt_update'])

    expect(update).toHaveBeenCalledWith('rpt_update', expect.any(Object))
    expect(output[0]).toContain('fixture-plugin@2.0.0')
  })

  it('passes exact destructive confirmations to lifecycle operations', async () => {
    const uninstall = vi.fn(async () => ({
      schemaVersion: 1 as const, action: 'uninstall' as const, profile: 'web', generationId: 'gen_uninstall',
      previousGenerationId: 'gen_current', packageName: 'fixture-plugin', backupPath: '/private/backup', noOp: false,
    }))
    const repair = vi.fn(async () => ({
      schemaVersion: 1 as const, action: 'repair' as const, profile: 'web', generationId: 'gen_repair',
      previousGenerationId: 'gen_uninstall', restoredGenerationId: 'gen_uninstall', backupPath: '/private/repair', noOp: false,
    }))
    const rollback = vi.fn(async () => ({
      schemaVersion: 1 as const, action: 'rollback' as const, profile: 'web', generationId: 'gen_rollback',
      previousGenerationId: 'gen_repair', restoredGenerationId: 'gen_current', backupPath: '/private/rollback', noOp: false,
    }))
    const output: string[] = []
    const program = createProgram({
      uninstallManagedPlugin: uninstall,
      repairManagedProfile: repair,
      rollbackManagedProfile: rollback,
      log: (line) => output.push(line),
    })

    await program.parseAsync(['node', 'dsh-guard', 'plugins', 'uninstall', 'fixture-plugin', '--profile', 'web', '--confirm', 'fixture-plugin'])
    expect(uninstall).toHaveBeenCalledWith('fixture-plugin', 'web', 'fixture-plugin', expect.any(Object))
    await program.parseAsync(['node', 'dsh-guard', 'plugins', 'repair', '--profile', 'web', '--confirm', 'web'])
    expect(repair).toHaveBeenCalledWith('web', 'web', expect.any(Object))
    await program.parseAsync(['node', 'dsh-guard', 'plugins', 'rollback', '--profile', 'web', '--to', 'gen_current', '--confirm', 'gen_current', '--allow-drift'])
    expect(rollback).toHaveBeenCalledWith('web', 'gen_current', 'gen_current', expect.any(Object), { allowDrift: true })
  })
})
