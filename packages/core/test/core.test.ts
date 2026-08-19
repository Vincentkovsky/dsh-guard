import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as tar from 'tar'
import { afterEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_POLICY,
  approveReport,
  extractArtifact,
  packDirectory,
  scan,
  scanPackage,
  sha256File,
  snapshotProfile,
  appendEvent,
  readEvents,
  statePaths,
  sanitizeText,
} from '../src/index.js'

const previousDshHome = process.env.DSH_HOME

afterEach(() => {
  if (previousDshHome === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = previousDshHome
})

async function fixture(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-guard-test-'))
  for (const [name, content] of Object.entries(files)) {
    await mkdir(join(root, name, '..'), { recursive: true })
    await writeFile(join(root, name), content)
  }
  return root
}

async function profile(home: string, bundles: string[] = ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app']): Promise<string> {
  const root = join(home, 'profiles', 'web')
  await mkdir(root, { recursive: true })
  await writeFile(join(root, 'package.json'), JSON.stringify({ name: 'dsh-profile-web', private: true, dsh: { profile: { bundles } }, dependencies: {} }, null, 2))
  await writeFile(join(root, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n")
  await writeFile(join(root, 'pnpm-workspace.yaml'), 'packages:\n  - .\nnodeLinker: hoisted\nautoInstallPeers: false\n')
  await writeFile(join(root, 'cordis.yml'), '[]\n')
  await writeFile(join(root, 'cordis.patch.yml'), '[]\n')
  return root
}

describe('immutable artifacts', () => {
  it('redacts named secrets with a stable label', () => {
    expect(sanitizeText('token=super-secret password:another-secret')).toBe('token=[redacted] password=[redacted]')
  })

  it('packs a local directory deterministically with npm packlist', async () => {
    const root = await fixture({
      'package.json': JSON.stringify({ name: 'fixture-safe', version: '1.0.0', files: ['index.js'] }),
      'index.js': 'export const answer = 42\n',
      'ignored.txt': 'not shipped\n',
    })
    const one = join(root, 'one.tgz')
    const two = join(root, 'two.tgz')
    const first = await packDirectory(root, one)
    const second = await packDirectory(root, two)
    expect(first).toEqual(second)
    expect(first).toContain('index.js')
    expect(first).not.toContain('ignored.txt')
    expect(await sha256File(one)).toBe(await sha256File(two))
  })

  it('does not execute lifecycle scripts while packaging', async () => {
    const root = await fixture({
      'package.json': JSON.stringify({ name: 'fixture-script', version: '1.0.0', scripts: { prepare: 'node -e "require(\\\'fs\\\').writeFileSync(\\\'SENTINEL\\\',\\\'owned\\\')"' } }),
      'index.js': 'export default 1\n',
    })
    await packDirectory(root, join(root, 'artifact.tgz'))
    await expect(readFile(join(root, 'SENTINEL'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('rejects a local symlink that leaves the package root', async () => {
    const outside = await fixture({ 'secret.txt': 'secret' })
    const root = await fixture({ 'package.json': JSON.stringify({ name: 'fixture-link', version: '1.0.0', files: ['escape'] }) })
    await symlink(join(outside, 'secret.txt'), join(root, 'escape'))
    await expect(packDirectory(root, join(root, 'artifact.tgz'))).rejects.toThrow(/Symlink escapes/)
  })

  it('rejects archive entries outside package/', async () => {
    const source = await fixture({ 'evil.js': 'bad' })
    const artifact = join(source, 'evil.tgz')
    await tar.c({ cwd: source, file: artifact, gzip: true, prefix: '../' }, ['evil.js'])
    await expect(extractArtifact(artifact, DEFAULT_POLICY)).rejects.toThrow(/escapes package root/)
  })
})

describe('static analysis', () => {
  it('finds sensitive capabilities and lifecycle scripts without evaluating code', async () => {
    const root = await fixture({
      'package.json': JSON.stringify({ name: 'fixture-risky', version: '1.0.0', main: 'index.js', scripts: { postinstall: 'node install.js' }, dsh: { bundle: { patch: './cordis.patch.yml' } } }),
      'index.js': "import { exec } from 'node:child_process'; fetch('https://evil.example'); console.log(process.env.API_KEY); exec('id')\n",
      'cordis.patch.yml': "- id: fixture-risky\n  name: fixture-risky\n  config:\n    value: !!js require('node:fs').writeFileSync('/tmp/SHOULD_NOT_EXIST','x')\n",
    })
    const result = await scanPackage(root, ['package.json', 'index.js', 'cordis.patch.yml'], DEFAULT_POLICY)
    expect(result.findings.map((finding) => finding.id)).toEqual(expect.arrayContaining([
      'manifest.script.postinstall', 'capability.subprocess', 'capability.network-client', 'capability.credentials', 'patch.javascript-tag',
    ]))
    await expect(readFile('/tmp/SHOULD_NOT_EXIST', 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('blocks protected entry overrides', async () => {
    const root = await fixture({
      'package.json': JSON.stringify({ name: 'fixture-override', version: '1.0.0', main: 'index.js', dsh: { bundle: { patch: './cordis.patch.yml' } } }),
      'index.js': 'export function apply() {}\n',
      'cordis.patch.yml': "- id: credentials\n  config:\n    source: attacker\n",
    })
    const result = await scanPackage(root, ['package.json', 'index.js', 'cordis.patch.yml'], DEFAULT_POLICY)
    expect(result.findings).toContainEqual(expect.objectContaining({ id: 'patch.protected-entry', severity: 'blocked' }))
  })
})

describe('approval binding', () => {
  it('invalidates approval when the target profile changes', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-home-'))
    const state = await mkdtemp(join(tmpdir(), 'dsh-guard-state-'))
    const packageRoot = await fixture({
      'package.json': JSON.stringify({ name: 'fixture-review', version: '1.0.0', main: 'index.js', dsh: { bundle: { patch: './cordis.patch.yml' } } }),
      'index.js': "import fs from 'node:fs'; export function apply(){ return fs.existsSync('.') }\n",
      'cordis.patch.yml': "- id: fixture-review\n  name: fixture-review\n",
    })
    const profileRoot = await profile(home)
    process.env.DSH_HOME = home
    const report = await scan(packageRoot, { profile: 'web', stateHome: state, stage: false })
    await writeFile(join(profileRoot, 'cordis.patch.yml'), '- id: changed\n  name: changed\n')
    await expect(approveReport(report.id, statePaths(state))).rejects.toThrow(/Profile changed/)
  })

  it('does not modify a blocked target profile', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-home-'))
    const state = await mkdtemp(join(tmpdir(), 'dsh-guard-state-'))
    const packageRoot = await fixture({
      'package.json': JSON.stringify({ name: 'fixture-blocked', version: '1.0.0', main: 'index.js', dsh: { bundle: { patch: './cordis.patch.yml' } } }),
      'index.js': 'export function apply() {}\n',
      'cordis.patch.yml': '- id: credentials\n  config:\n    steal: true\n',
    })
    await profile(home)
    process.env.DSH_HOME = home
    const before = await snapshotProfile('web', home)
    const report = await scan(packageRoot, { profile: 'web', stateHome: state, stage: false })
    const after = await snapshotProfile('web', home)
    expect(report.verdict).toBe('blocked')
    expect(after.fingerprint).toBe(before.fingerprint)
  })

  it('rejects symlinked profile control files', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-home-'))
    const profileRoot = await profile(home)
    const outside = await fixture({ 'outside-package.json': '{"name":"outside"}\n' })
    await rm(join(profileRoot, 'package.json'))
    await symlink(join(outside, 'outside-package.json'), join(profileRoot, 'package.json'))
    await expect(snapshotProfile('web', home)).rejects.toThrow(/regular file/)
  })

  it('deduplicates unresolved events by stable fingerprint', async () => {
    const state = await mkdtemp(join(tmpdir(), 'dsh-guard-state-'))
    const paths = statePaths(state)
    const event = {
      schemaVersion: 1 as const, id: 'evt_1', createdAt: new Date().toISOString(), severity: 'high' as const,
      type: 'verified-to-drifted' as const, fingerprint: 'same', title: 'Drift', detail: 'Changed', profile: 'web',
    }
    await appendEvent(paths, event)
    await appendEvent(paths, { ...event, id: 'evt_2' })
    expect((await readEvents(paths)).filter((item) => item.fingerprint === 'same')).toHaveLength(1)
  })
})
