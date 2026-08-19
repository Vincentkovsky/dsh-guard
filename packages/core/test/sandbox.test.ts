import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  buildSandboxEnvironment,
  compileSandboxPolicy,
  cleanupSandboxRuntime,
  createSandboxPlan,
  parseSandboxPlan,
  sandboxPlanDigest,
  prepareSandboxRuntime,
  validateSandboxEnvironment,
  validateSandboxAppArgs,
  type CreateSandboxPlanOptions,
  type SandboxNetworkMode,
} from '../src/index.js'

async function sandboxFixture(network: SandboxNetworkMode = 'loopback'): Promise<CreateSandboxPlanOptions> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-guard-sandbox-test-'))
  const sourceDshHome = join(root, 'source-dsh-home')
  const userHome = join(root, 'user-home')
  const guardHome = join(root, 'guard-home')
  const dshHome = join(guardHome, 'sandbox-runs', 'run-fixture', 'dsh-home')
  const tempRoot = join(dshHome, 'tmp')
  const workspace = join(root, 'workspace')
  const dshBin = join(root, 'runtime', 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
  await Promise.all([
    mkdir(join(dshHome, 'profiles', 'web'), { recursive: true }),
    mkdir(join(sourceDshHome, 'profiles', 'web'), { recursive: true }),
    mkdir(join(userHome, '.ssh'), { recursive: true }),
    mkdir(join(dshHome, 'profiles', 'node_modules'), { recursive: true }),
    mkdir(join(dshHome, 'sessions'), { recursive: true }),
    mkdir(join(dshHome, 'storages'), { recursive: true }),
    mkdir(tempRoot, { recursive: true }),
    mkdir(workspace, { recursive: true }),
    mkdir(dirname(dshBin), { recursive: true }),
  ])
  await Promise.all([
    writeFile(dshBin, '#!/usr/bin/env node\n'),
    writeFile(join(dshHome, 'settings.yaml'), 'telemetry: false\n'),
    writeFile(join(workspace, 'README.md'), 'fixture\n'),
  ])
  return {
    platform: 'darwin',
    profile: 'web',
    workspaceRoots: [workspace],
    dshBin,
    userHome,
    sourceDshHome,
    dshHome,
    guardHome,
    tempRoot,
    network,
    environment: { SAFE_FLAG: 'yes', API_TOKEN: 'do-not-record' },
    now: new Date('2026-08-19T00:00:00.000Z'),
  }
}

describe('macOS sandbox plans', () => {
  it('canonicalizes paths and compiles a deny-default loopback plan', async () => {
    const options = await sandboxFixture()
    const plan = await createSandboxPlan({ ...options, allowEnvironment: ['SAFE_FLAG'] })

    expect(plan).toMatchObject({
      schemaVersion: 1,
      platform: 'darwin',
      profile: 'web',
      network: 'loopback',
      policyHash: expect.stringMatching(/^[a-f0-9]{64}$/),
    })
    expect(plan.readOnlyPaths).not.toContain(plan.dshHome + '/profiles/web')
    expect(plan.readWritePaths).toEqual(expect.arrayContaining([
      plan.workspaceRoots[0], plan.guardHome, plan.dshHome, plan.tempRoot,
    ]))
    expect(plan.allowedEnvironmentNames).toContain('SAFE_FLAG')
    expect(plan.policy).toContain('(deny default)')
    expect(plan.policy).toContain('(allow process-exec (literal ')
    expect(plan.policy).toContain('(allow network-outbound (remote tcp "localhost:*"))')
    expect(plan.policy).not.toContain('do-not-record')
    expect(sandboxPlanDigest(plan)).toMatch(/^[a-f0-9]{64}$/)
  })

  it('compiles distinct deny and unrestricted network capabilities', () => {
    const common = {
      nodePath: '/opt/node/bin/node',
      readOnlyDirectories: ['/opt/node'],
      readOnlyFiles: [],
      readWriteDirectories: ['/private/tmp/guard'],
    }
    const denied = compileSandboxPolicy({ ...common, network: 'deny' })
    const unrestricted = compileSandboxPolicy({ ...common, network: 'unrestricted' })
    expect(denied).not.toContain('(allow network-outbound')
    expect(unrestricted).toContain('(allow network-outbound)')
    expect(unrestricted).toContain('(allow network-bind network-inbound (local tcp "localhost:*"))')
  })

  it('escapes SBPL strings and rejects control-character injection', () => {
    const escaped = compileSandboxPolicy({
      nodePath: '/opt/a "quoted"/node',
      readOnlyDirectories: ['/opt/a "quoted"'],
      readOnlyFiles: [],
      readWriteDirectories: ['/tmp/work'],
      network: 'deny',
    })
    expect(escaped).toContain('/opt/a \\"quoted\\"/node')
    expect(() => compileSandboxPolicy({
      nodePath: '/opt/node\n(allow default)',
      readOnlyDirectories: ['/opt'],
      readOnlyFiles: [],
      readWriteDirectories: ['/tmp/work'],
      network: 'deny',
    })).toThrow(/control characters/)
  })

  it('rejects broad and protected workspaces after resolving symlinks', async () => {
    const options = await sandboxFixture()
    await expect(createSandboxPlan({ ...options, workspaceRoots: ['/'] })).rejects.toThrow(/filesystem root/)
    const linked = join(dirname(options.workspaceRoots[0]!), 'linked-dsh-home')
    await symlink(options.dshHome, linked)
    await expect(createSandboxPlan({ ...options, workspaceRoots: [linked] })).rejects.toThrow(/overlaps DSH home/)
    await expect(createSandboxPlan({ ...options, workspaceRoots: [options.sourceDshHome] })).rejects.toThrow(/source DSH home/)
    await expect(createSandboxPlan({ ...options, workspaceRoots: [join(options.userHome!, '.ssh')] })).rejects.toThrow(/SSH credentials/)
  })

  it('fails closed on non-macOS platforms before compiling a policy', async () => {
    await expect(createSandboxPlan({ ...await sandboxFixture(), platform: 'linux' })).rejects.toThrow(/supports macOS only/)
  })

  it('rejects environment injection and warns without storing credential values', async () => {
    const options = await sandboxFixture()
    await expect(createSandboxPlan({ ...options, allowEnvironment: ['NODE_OPTIONS'] })).rejects.toThrow(/cannot be passed through/)
    await expect(createSandboxPlan({ ...options, allowEnvironment: ['NOT_SET'] })).rejects.toThrow(/is not set/)
    const plan = await createSandboxPlan({ ...options, allowEnvironment: ['API_TOKEN'] })
    expect(plan.warnings.join('\n')).toContain('API_TOKEN')
    expect(JSON.stringify(plan)).not.toContain('do-not-record')
  })

  it('strictly parses plans and verifies the policy hash', async () => {
    const plan = await createSandboxPlan(await sandboxFixture())
    expect(() => parseSandboxPlan({ ...plan, surprise: true })).toThrow(/not supported/)
    expect(() => parseSandboxPlan({ ...plan, policy: `${plan.policy}\n(allow default)` })).toThrow(/hash mismatch/)
    expect(() => parseSandboxPlan({ ...plan, workspaceRoots: [...plan.workspaceRoots, plan.workspaceRoots[0]] })).toThrow(/duplicates/)
  })

  it('builds a minimal environment and never inherits unrelated secrets', async () => {
    const options = await sandboxFixture()
    const plan = await createSandboxPlan({ ...options, allowEnvironment: ['SAFE_FLAG'] })
    const environment = buildSandboxEnvironment(plan, {
      SAFE_FLAG: 'yes',
      AWS_SECRET_ACCESS_KEY: 'must-not-leak',
      NODE_OPTIONS: '--require attacker.js',
      TERM: 'xterm-256color',
    })
    expect(environment).toMatchObject({
      SAFE_FLAG: 'yes',
      DSH_HOME: plan.dshHome,
      DSH_GUARD_HOME: plan.guardHome,
      TMPDIR: plan.tempRoot,
      NO_COLOR: '1',
    })
    expect(environment.AWS_SECRET_ACCESS_KEY).toBeUndefined()
    expect(environment.NODE_OPTIONS).toBeUndefined()
    expect(() => validateSandboxEnvironment(plan, environment)).not.toThrow()
    expect(() => validateSandboxEnvironment(plan, { ...environment, AWS_SECRET_ACCESS_KEY: 'leak' })).toThrow(/outside the sandbox plan/)
    expect(() => validateSandboxEnvironment(plan, { ...environment, DSH_HOME: '/tmp/other' })).toThrow(/invalid DSH_HOME/)
  })

  it('copies a disposable runtime profile without copying DSH credentials', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-guard-sandbox-runtime-test-'))
    const source = join(root, 'source-dsh')
    const guard = join(root, 'guard')
    await Promise.all([
      mkdir(join(source, 'profiles', 'web'), { recursive: true }),
      mkdir(guard, { recursive: true }),
    ])
    await Promise.all([
      writeFile(join(source, 'profiles', 'web', 'package.json'), '{"name":"fixture"}\n'),
      writeFile(join(source, 'profiles', 'web', 'cordis.yml'), '[]\n'),
      writeFile(join(source, 'settings.yaml'), 'telemetry: false\n'),
      writeFile(join(source, '.credentials.yaml'), 'apiKey: must-not-copy\n'),
    ])

    const runtime = await prepareSandboxRuntime('web', source, guard)
    expect(await readFile(join(runtime.runtimeProfile, 'package.json'), 'utf8')).toContain('fixture')
    expect(await readFile(join(runtime.dshHome, 'settings.yaml'), 'utf8')).toContain('telemetry')
    await expect(readFile(join(runtime.dshHome, '.credentials.yaml'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })

    await cleanupSandboxRuntime(runtime.root, guard)
    await expect(readFile(join(runtime.runtimeProfile, 'package.json'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })

    const replaced = await prepareSandboxRuntime('web', source, guard)
    const outside = join(root, 'outside-do-not-delete')
    await mkdir(outside)
    await writeFile(join(outside, 'sentinel.txt'), 'safe\n')
    await rm(replaced.root, { recursive: true })
    await symlink(outside, replaced.root)
    await cleanupSandboxRuntime(replaced.root, guard)
    expect(await readFile(join(outside, 'sentinel.txt'), 'utf8')).toBe('safe\n')
  })
})

describe('sandboxed DSH arguments', () => {
  it.each(['127.0.0.1', 'localhost', '::1'])('allows loopback host %s', (host) => {
    expect(() => validateSandboxAppArgs(['--host', host, '--port', '8080'])).not.toThrow()
  })

  it.each(['0.0.0.0', '192.168.1.10', 'example.com'])('rejects non-loopback host %s', (host) => {
    expect(() => validateSandboxAppArgs([`--host=${host}`])).toThrow(/only bind loopback/)
  })

  it('rejects attempts to override the verified profile', () => {
    expect(() => validateSandboxAppArgs(['--profile', 'evil'])).toThrow(/cannot override/)
  })
})
