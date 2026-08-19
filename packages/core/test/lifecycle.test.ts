import { mkdtemp, mkdir, readFile, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  createGenerationSnapshot,
  currentGeneration,
  listManagedProfileNames,
  importLegacyManagedProfile,
  inspectLifecycleState,
  loadManagedProfile,
  parseManagedProfile,
  readGenerationSnapshot,
  recordProfileGeneration,
  saveManagedProfile,
  saveInstall,
  sha256,
  snapshotProfile,
  statePaths,
  type ManagedPluginV1,
} from '../src/index.js'

async function createProfile(home: string, name = 'web'): Promise<void> {
  const root = join(home, 'profiles', name)
  await mkdir(root, { recursive: true })
  await writeFile(join(root, 'package.json'), JSON.stringify({
    name: `dsh-profile-${name}`,
    private: true,
    dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', 'fixture-plugin'] } },
    dependencies: { 'fixture-plugin': '1.0.0' },
  }, null, 2))
  await writeFile(join(root, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n")
  await writeFile(join(root, 'pnpm-workspace.yaml'), 'packages:\n  - .\n')
  await writeFile(join(root, 'cordis.yml'), '[]\n')
  await writeFile(join(root, 'cordis.patch.yml'), '[]\n')
}

function plugin(overrides: Partial<ManagedPluginV1> = {}): ManagedPluginV1 {
  return {
    schemaVersion: 1,
    packageName: 'fixture-plugin',
    version: '1.0.0',
    reportId: 'rpt_fixture',
    artifactSha256: sha256('fixture artifact'),
    installedAt: '2026-08-19T00:00:00.000Z',
    updatedAt: '2026-08-19T00:00:00.000Z',
    bundles: ['fixture-plugin'],
    ...overrides,
  }
}

describe('managed profile lifecycle state', () => {
  it('records immutable generations and lists managed profiles', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-home-'))
    const root = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-state-'))
    await createProfile(home)
    const paths = statePaths(root)
    const snapshot = await snapshotProfile('web', home)

    const first = await recordProfileGeneration(paths, undefined, {
      action: 'install',
      snapshot,
      plugins: [plugin()],
      reportId: 'rpt_fixture',
      packageName: 'fixture-plugin',
      configHash: sha256('config'),
      generationId: 'gen_first',
      now: new Date('2026-08-19T00:00:00.000Z'),
    })

    expect(first.currentGenerationId).toBe('gen_first')
    expect(currentGeneration(first)).toMatchObject({ action: 'install', plugins: [{ packageName: 'fixture-plugin' }] })
    expect(await listManagedProfileNames(paths)).toEqual(['web'])
    expect(await loadManagedProfile('web', paths)).toEqual(first)
    expect(await readGenerationSnapshot(paths, 'web', 'gen_first')).toMatchObject({
      name: 'web',
      fingerprint: snapshot.fingerprint,
      bundles: snapshot.bundles,
    })

    const second = await recordProfileGeneration(paths, first, {
      action: 'update',
      snapshot,
      plugins: [plugin({ version: '2.0.0', updatedAt: '2026-08-19T01:00:00.000Z' })],
      reportId: 'rpt_update',
      packageName: 'fixture-plugin',
      generationId: 'gen_second',
      now: new Date('2026-08-19T01:00:00.000Z'),
    })
    expect(second.generations).toHaveLength(2)
    expect(currentGeneration(second)).toMatchObject({ id: 'gen_second', parentGenerationId: 'gen_first' })
  })

  it('rejects unknown fields, duplicate packages, and a missing current generation', () => {
    const base = {
      schemaVersion: 1,
      profile: 'web',
      createdAt: '2026-08-19T00:00:00.000Z',
      updatedAt: '2026-08-19T00:00:00.000Z',
      currentGenerationId: 'gen_missing',
      generations: [{
        schemaVersion: 1,
        id: 'gen_first',
        profile: 'web',
        createdAt: '2026-08-19T00:00:00.000Z',
        action: 'install',
        profileFingerprint: sha256('profile'),
        bundles: [],
        plugins: [plugin(), plugin()],
      }],
    }
    expect(() => parseManagedProfile({ ...base, surprise: true })).toThrow(/not supported/)
    expect(() => parseManagedProfile(base)).toThrow(/duplicate packages/)
    expect(() => parseManagedProfile({
      ...base,
      generations: [{ ...base.generations[0], plugins: [plugin()] }],
    })).toThrow(/current generation is missing/)
  })

  it('fails closed for symlinked state and snapshot files', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-home-'))
    const root = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-state-'))
    await createProfile(home)
    const paths = statePaths(root)
    const snapshot = await snapshotProfile('web', home)
    await recordProfileGeneration(paths, undefined, {
      action: 'install', snapshot, plugins: [plugin()], generationId: 'gen_secure',
    })

    const stateFile = join(paths.managedProfiles, 'web.json')
    const stateContents = await readFile(stateFile, 'utf8')
    await writeFile(join(root, 'outside-state.json'), stateContents)
    await import('node:fs/promises').then(({ rm }) => rm(stateFile))
    await symlink(join(root, 'outside-state.json'), stateFile)
    await expect(loadManagedProfile('web', paths)).rejects.toThrow(/regular file/)

    const manifestFile = join(paths.generations, 'web', 'gen_secure', 'manifest.json')
    await writeFile(join(root, 'outside-manifest.json'), await readFile(manifestFile))
    await import('node:fs/promises').then(({ rm }) => rm(manifestFile))
    await symlink(join(root, 'outside-manifest.json'), manifestFile)
    await expect(readGenerationSnapshot(paths, 'web', 'gen_secure')).rejects.toThrow(/regular file/)
  })

  it('detects snapshot content tampering', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-home-'))
    const root = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-state-'))
    await createProfile(home)
    const paths = statePaths(root)
    const snapshot = await snapshotProfile('web', home)
    await createGenerationSnapshot(paths, snapshot, 'gen_tamper')
    await writeFile(join(paths.generations, 'web', 'gen_tamper', 'cordis.yml'), '- id: attacker\n')
    await expect(readGenerationSnapshot(paths, 'web', 'gen_tamper')).rejects.toThrow(/digest mismatch/)
  })

  it('validates values again before writing state', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-state-'))
    const paths = statePaths(root)
    await expect(saveManagedProfile({
      schemaVersion: 1,
      profile: '../escape',
      createdAt: '2026-08-19T00:00:00.000Z',
      updatedAt: '2026-08-19T00:00:00.000Z',
      currentGenerationId: 'gen_first',
      generations: [],
    }, paths)).rejects.toThrow()
  })

  it('imports an exact legacy install but does not bless a drifted profile', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-home-'))
    const root = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-state-'))
    await createProfile(home)
    const paths = statePaths(root)
    const snapshot = await snapshotProfile('web', home)
    await saveInstall({
      schemaVersion: 1,
      reportId: 'rpt_legacy',
      installedAt: '2026-08-19T00:00:00.000Z',
      lastVerifiedAt: '2026-08-19T00:00:00.000Z',
      profile: 'web',
      packageName: 'fixture-plugin',
      version: '1.0.0',
      artifactSha256: sha256('legacy artifact'),
      expectedProfileFingerprint: snapshot.fingerprint,
      resultingProfileFingerprint: snapshot.fingerprint,
      expectedBundles: snapshot.bundles,
    }, paths)

    const imported = await importLegacyManagedProfile('web', paths, home)
    expect(imported && currentGeneration(imported)).toMatchObject({
      action: 'legacy-import',
      profileFingerprint: snapshot.fingerprint,
      plugins: [{ packageName: 'fixture-plugin' }],
    })

    const driftedRoot = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-state-'))
    const driftedPaths = statePaths(driftedRoot)
    await saveInstall({
      schemaVersion: 1,
      reportId: 'rpt_legacy',
      installedAt: '2026-08-19T00:00:00.000Z',
      lastVerifiedAt: '2026-08-19T00:00:00.000Z',
      profile: 'web',
      packageName: 'fixture-plugin',
      version: '1.0.0',
      artifactSha256: sha256('legacy artifact'),
      expectedProfileFingerprint: snapshot.fingerprint,
      resultingProfileFingerprint: sha256('different profile'),
      expectedBundles: snapshot.bundles,
    }, driftedPaths)
    await expect(importLegacyManagedProfile('web', driftedPaths, home)).resolves.toBeUndefined()
  })

  it('reports damaged snapshots and lifecycle locks through doctor inspection', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-home-'))
    const root = await mkdtemp(join(tmpdir(), 'dsh-lifecycle-state-'))
    await createProfile(home)
    const paths = statePaths(root)
    const snapshot = await snapshotProfile('web', home)
    await recordProfileGeneration(paths, undefined, {
      action: 'install', snapshot, plugins: [plugin()], generationId: 'gen_doctor',
    })
    await expect(inspectLifecycleState(paths)).resolves.toMatchObject({ ok: true, profiles: 1, generations: 1, locks: [] })

    await writeFile(join(paths.generations, 'web', 'gen_doctor', 'cordis.yml'), 'tampered\n')
    await writeFile(join(paths.locks, 'profile-web.lock'), 'busy\n')
    const inspection = await inspectLifecycleState(paths)
    expect(inspection.ok).toBe(false)
    expect(inspection.locks).toEqual(['profile-web.lock'])
    expect(inspection.issues.join('\n')).toMatch(/digest mismatch/)
    expect(inspection.issues.join('\n')).toMatch(/active or stale lifecycle lock/)
  })
})
