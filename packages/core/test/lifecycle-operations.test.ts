import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  currentGeneration,
  inspectManagedProfiles,
  loadManagedProfile,
  recordProfileGeneration,
  repairManagedProfile,
  rollbackManagedProfile,
  sha256,
  snapshotProfile,
  statePaths,
  uninstallManagedPlugin,
  type ManagedPluginV1,
} from '../src/index.js'

const previousDshHome = process.env.DSH_HOME
const previousDshBin = process.env.DSH_BIN
const previousFakeRealHome = process.env.FAKE_DSH_REAL_HOME
const previousFakeFailReal = process.env.FAKE_DSH_FAIL_REAL
const PROFILE = 'guard-lifecycle-test'

afterEach(() => {
  if (previousDshHome === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = previousDshHome
  if (previousDshBin === undefined) delete process.env.DSH_BIN
  else process.env.DSH_BIN = previousDshBin
  if (previousFakeRealHome === undefined) delete process.env.FAKE_DSH_REAL_HOME
  else process.env.FAKE_DSH_REAL_HOME = previousFakeRealHome
  if (previousFakeFailReal === undefined) delete process.env.FAKE_DSH_FAIL_REAL
  else process.env.FAKE_DSH_FAIL_REAL = previousFakeFailReal
})

async function fakeDsh(root: string, realHome: string): Promise<string> {
  const file = join(root, 'fake-dsh.mjs')
  await writeFile(file, `
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
const args = process.argv.slice(2)
const realHome = ${JSON.stringify(realHome)}
const failMarker = ${JSON.stringify(join(root, 'fail-real-uninstall'))}
const failHydrateMarker = ${JSON.stringify(join(root, 'fail-hydrate'))}
const profileIndex = args.indexOf('--profile')
const profile = profileIndex >= 0 ? args[profileIndex + 1] : undefined
if (!profile) process.exit(2)
const profileDir = join(process.env.DSH_HOME, 'profiles', profile)
if (args.includes('--dump-config')) {
  process.stdout.write(readFileSync(join(profileDir, 'package.json'), 'utf8'))
  process.exit(0)
}
if (args[0] !== 'plugin') process.exit(2)
const removeIndex = args.indexOf('remove')
if (removeIndex >= 0) {
  const packageName = args.at(-1)
  const manifestPath = join(profileDir, 'package.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  delete manifest.dependencies?.[packageName]
  manifest.dsh.profile.bundles = manifest.dsh.profile.bundles.filter((value) => value !== packageName)
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\\n')
  const dependencies = Object.entries(manifest.dependencies ?? {}).sort(([a], [b]) => a.localeCompare(b))
  writeFileSync(join(profileDir, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\\n" + dependencies.map(([name, version]) => name + ': ' + version).join('\\n') + '\\n')
  if (existsSync(failMarker) && process.env.DSH_HOME === realHome) process.exit(9)
  process.exit(0)
}
if (args.includes('install')) {
  if (existsSync(failHydrateMarker) && process.env.DSH_HOME === realHome) {
    process.stderr.write('token=super-secret-e2e\\n')
    process.exit(8)
  }
  process.exit(0)
}
process.exit(2)
`)
  return file
}

async function createProfile(home: string, packages: Record<string, string>): Promise<void> {
  const root = join(home, 'profiles', PROFILE)
  await mkdir(root, { recursive: true })
  await writeFile(join(root, 'package.json'), JSON.stringify({
    name: `dsh-profile-${PROFILE}`,
    private: true,
    dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', ...Object.keys(packages)] } },
    dependencies: packages,
  }, null, 2) + '\n')
  await writeFile(join(root, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n" + Object.entries(packages).map(([name, version]) => `${name}: ${version}`).join('\n') + '\n')
  await writeFile(join(root, 'pnpm-workspace.yaml'), 'packages:\n  - .\n')
  await writeFile(join(root, 'cordis.yml'), '[]\n')
  await writeFile(join(root, 'cordis.patch.yml'), '[]\n')
}

function plugin(name: string, version: string): ManagedPluginV1 {
  return {
    schemaVersion: 1,
    packageName: name,
    version,
    reportId: `rpt_${name.replaceAll(/[^a-z0-9]/g, '_')}`,
    artifactSha256: sha256(`${name}@${version}`),
    installedAt: '2026-08-19T00:00:00.000Z',
    updatedAt: '2026-08-19T00:00:00.000Z',
    bundles: [name],
  }
}

async function setup(packages: Record<string, string>): Promise<{ home: string; root: string }> {
  const home = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-op-home-'))
  const root = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-op-state-'))
  await createProfile(home, packages)
  process.env.DSH_HOME = home
  process.env.DSH_BIN = await fakeDsh(root, home)
  process.env.FAKE_DSH_REAL_HOME = home
  return { home, root }
}

describe('managed profile lifecycle operations', () => {
  it('inspects all managed plugins and repairs profile drift', async () => {
    const { home, root } = await setup({ 'fixture-one': '1.0.0', 'fixture-two': '2.0.0' })
    const paths = statePaths(root)
    const before = await snapshotProfile(PROFILE, home)
    const managed = await recordProfileGeneration(paths, undefined, {
      action: 'install',
      snapshot: before,
      plugins: [plugin('fixture-one', '1.0.0'), plugin('fixture-two', '2.0.0')],
      generationId: 'gen_before_repair',
    })
    await writeFile(join(home, 'profiles', PROFILE, 'cordis.patch.yml'), '- id: drifted\n')

    await expect(inspectManagedProfiles(paths, PROFILE)).resolves.toMatchObject([{
      state: 'drifted',
      plugins: [{ packageName: 'fixture-one' }, { packageName: 'fixture-two' }],
    }])
    await expect(repairManagedProfile(PROFILE, 'wrong', paths)).rejects.toThrow(/Confirmation/)
    const result = await repairManagedProfile(PROFILE, PROFILE, paths)
    expect(result).toMatchObject({ action: 'repair', previousGenerationId: managed.currentGenerationId, noOp: false })
    expect((await snapshotProfile(PROFILE, home)).fingerprint).toBe(before.fingerprint)
    expect(currentGeneration((await loadManagedProfile(PROFILE, paths))!)).toMatchObject({
      id: result.generationId,
      action: 'repair',
      restoredGenerationId: 'gen_before_repair',
    })
    await expect(repairManagedProfile(PROFILE, PROFILE, paths)).resolves.toMatchObject({ noOp: true })
  })

  it('uninstalls one managed plugin without forgetting the others', async () => {
    const { home, root } = await setup({ 'fixture-one': '1.0.0', 'fixture-two': '2.0.0' })
    const paths = statePaths(root)
    const before = await snapshotProfile(PROFILE, home)
    await recordProfileGeneration(paths, undefined, {
      action: 'install',
      snapshot: before,
      plugins: [plugin('fixture-one', '1.0.0'), plugin('fixture-two', '2.0.0')],
      generationId: 'gen_before_uninstall',
    })

    await expect(uninstallManagedPlugin('fixture-one', PROFILE, 'fixture-two', paths)).rejects.toThrow(/Confirmation/)
    const result = await uninstallManagedPlugin('fixture-one', PROFILE, 'fixture-one', paths)
    const after = await snapshotProfile(PROFILE, home)
    const state = (await loadManagedProfile(PROFILE, paths))!
    expect(result).toMatchObject({ action: 'uninstall', packageName: 'fixture-one', noOp: false })
    expect(after.bundles).toEqual(['@deepseek-ai/dsh-base', 'fixture-two'])
    expect(currentGeneration(state).plugins).toMatchObject([{ packageName: 'fixture-two', version: '2.0.0' }])
  })

  it('rolls back to an old generation and records a new immutable generation', async () => {
    const { home, root } = await setup({ 'fixture-one': '1.0.0' })
    const paths = statePaths(root)
    const firstSnapshot = await snapshotProfile(PROFILE, home)
    const first = await recordProfileGeneration(paths, undefined, {
      action: 'install', snapshot: firstSnapshot, plugins: [plugin('fixture-one', '1.0.0')], generationId: 'gen_v1',
    })
    await createProfile(home, { 'fixture-one': '2.0.0' })
    const secondSnapshot = await snapshotProfile(PROFILE, home)
    const second = await recordProfileGeneration(paths, first, {
      action: 'update', snapshot: secondSnapshot, plugins: [plugin('fixture-one', '2.0.0')], generationId: 'gen_v2',
    })

    await expect(rollbackManagedProfile(PROFILE, 'gen_v1', 'gen_v2', paths)).rejects.toThrow(/Confirmation/)
    await writeFile(join(home, 'profiles', PROFILE, 'cordis.patch.yml'), '- id: reviewed-drift\n')
    await expect(rollbackManagedProfile(PROFILE, 'gen_v1', 'gen_v1', paths)).rejects.toThrow(/has drifted/)
    const result = await rollbackManagedProfile(PROFILE, 'gen_v1', 'gen_v1', paths, { allowDrift: true })
    const state = (await loadManagedProfile(PROFILE, paths))!
    expect(result).toMatchObject({ action: 'rollback', previousGenerationId: second.currentGenerationId, restoredGenerationId: 'gen_v1' })
    expect((await snapshotProfile(PROFILE, home)).fingerprint).toBe(firstSnapshot.fingerprint)
    expect(state.generations).toHaveLength(3)
    expect(currentGeneration(state)).toMatchObject({ action: 'rollback', plugins: [{ version: '1.0.0' }] })
  })

  it('restores the exact pre-operation profile when real uninstall fails', async () => {
    const { home, root } = await setup({ 'fixture-one': '1.0.0' })
    const paths = statePaths(root)
    const before = await snapshotProfile(PROFILE, home)
    await recordProfileGeneration(paths, undefined, {
      action: 'install', snapshot: before, plugins: [plugin('fixture-one', '1.0.0')], generationId: 'gen_failure',
    })
    await writeFile(join(root, 'fail-real-uninstall'), '1')

    await expect(uninstallManagedPlugin('fixture-one', PROFILE, 'fixture-one', paths)).rejects.toThrow(/Offline uninstall failed/)
    expect((await snapshotProfile(PROFILE, home)).fingerprint).toBe(before.fingerprint)
    expect((await loadManagedProfile(PROFILE, paths))?.currentGenerationId).toBe('gen_failure')
    expect((await readFile(join(home, 'profiles', PROFILE, 'package.json'), 'utf8'))).toContain('fixture-one')
  })

  it('fails closed with needs-repair when offline hydration and recovery are unavailable', async () => {
    const { home, root } = await setup({ 'fixture-one': '1.0.0' })
    const paths = statePaths(root)
    const before = await snapshotProfile(PROFILE, home)
    await recordProfileGeneration(paths, undefined, {
      action: 'install', snapshot: before, plugins: [plugin('fixture-one', '1.0.0')], generationId: 'gen_missing_cache',
    })
    await writeFile(join(home, 'profiles', PROFILE, 'cordis.patch.yml'), '- id: drift-before-repair\n')
    await writeFile(join(root, 'fail-hydrate'), '1')

    let message = ''
    try { await repairManagedProfile(PROFILE, PROFILE, paths) }
    catch (error) { message = (error as Error).message }
    expect(message).toMatch(/automatic recovery could not restore/)
    expect(message).not.toContain('super-secret-e2e')
    expect(message).toContain('token=[redacted]')
    const events = (await readFile(join(root, 'events.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line))
    expect(events).toContainEqual(expect.objectContaining({ type: 'needs-repair', profile: PROFILE }))
    expect((await loadManagedProfile(PROFILE, paths))?.currentGenerationId).toBe('gen_missing_cache')
  })

  it('marks a failed uninstall as needs-repair when its recovery cannot hydrate', async () => {
    const { home, root } = await setup({ 'fixture-one': '1.0.0' })
    const paths = statePaths(root)
    const before = await snapshotProfile(PROFILE, home)
    await recordProfileGeneration(paths, undefined, {
      action: 'install', snapshot: before, plugins: [plugin('fixture-one', '1.0.0')], generationId: 'gen_uninstall_needs_repair',
    })
    await writeFile(join(root, 'fail-real-uninstall'), '1')
    await writeFile(join(root, 'fail-hydrate'), '1')

    await expect(uninstallManagedPlugin('fixture-one', PROFILE, 'fixture-one', paths)).rejects.toThrow(/automatic recovery could not restore/)
    const events = (await readFile(join(root, 'events.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line))
    expect(events).toContainEqual(expect.objectContaining({ type: 'needs-repair', profile: PROFILE }))
    expect((await loadManagedProfile(PROFILE, paths))?.currentGenerationId).toBe('gen_uninstall_needs_repair')
  })
})
