import { spawn } from 'node:child_process'
import { cp, mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { createRequire } from 'node:module'
import type { InstallRecord, ProfileSnapshot, StageResult, VerifyResult } from './types.js'
import type { StatePaths } from './state.js'
import { appendEvent, loadInstall, saveInstall } from './state.js'
import { sanitizeText, sha256, sortableId, stableJson } from './util.js'

const PROFILE_FILES = ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'cordis.yml', 'cordis.patch.yml'] as const

export function dshHomePath(override?: string): string {
  return override ?? process.env.DSH_HOME ?? join(homedir(), '.dsh')
}

export async function snapshotProfile(name: string, home = dshHomePath()): Promise<ProfileSnapshot> {
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) throw new Error(`Invalid profile name: ${name}`)
  const path = join(home, 'profiles', name)
  await stat(path)
  const files: Record<string, string | null> = {}
  for (const file of PROFILE_FILES) {
    try {
      files[file] = await readFile(join(path, file), 'utf8')
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') files[file] = null
      else throw error
    }
  }
  const manifest = files['package.json'] ? JSON.parse(files['package.json']) as { dsh?: { profile?: { bundles?: unknown } } } : {}
  const rawBundles = manifest.dsh?.profile?.bundles
  const bundles = Array.isArray(rawBundles) ? rawBundles.filter((item): item is string => typeof item === 'string') : []
  return { name, path, files, bundles, fingerprint: sha256(stableJson(files)) }
}

function run(command: string, args: string[], env: NodeJS.ProcessEnv, cwd?: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] })
    const out: Buffer[] = []
    const err: Buffer[] = []
    child.stdout.on('data', (chunk: Buffer) => out.push(chunk))
    child.stderr.on('data', (chunk: Buffer) => err.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => resolvePromise({ code: code ?? 1, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }))
  })
}

export async function locateDshBin(): Promise<{ command: string; prefix: string[] } | undefined> {
  if (process.env.DSH_BIN) return { command: process.execPath, prefix: [resolve(process.env.DSH_BIN)] }
  const found = await run('/usr/bin/env', ['sh', '-c', 'command -v dsh'], { PATH: process.env.PATH ?? '' }).catch(() => undefined)
  if (found?.code === 0 && found.stdout.trim()) return { command: found.stdout.trim(), prefix: [] }
  try {
    const require = createRequire(import.meta.url)
    const packageJson = require.resolve('@deepseek-ai/dsh/package.json')
    return { command: process.execPath, prefix: [join(dirname(packageJson), 'lib', 'bin.js')] }
  } catch {
    return undefined
  }
}

function configLines(value: string): string[] {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
}

export async function stageArtifact(profile: ProfileSnapshot, artifactPath: string, persistentStore?: string): Promise<StageResult> {
  const dsh = await locateDshBin()
  if (!dsh) return { attempted: false, compatible: false, reason: 'DSH executable not found; set DSH_BIN to the rc.6 lib/bin.js path' }
  const actualDshHome = dirname(dirname(profile.path))
  const stagedHome = await mkdtemp(join(dirname(actualDshHome), '.dsh-guard-stage-'))
  const stagedProfile = join(stagedHome, 'profiles', profile.name)
  await mkdir(join(stagedHome, 'profiles'), { recursive: true })
  await mkdir(join(stagedHome, 'tmp'), { recursive: true })
  await cp(profile.path, stagedProfile, { recursive: true, filter(source) { return basename(source) !== 'node_modules' } })
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    HOME: stagedHome,
    DSH_HOME: stagedHome,
    TMPDIR: join(stagedHome, 'tmp'),
    LANG: process.env.LANG ?? 'C.UTF-8',
    LC_ALL: process.env.LC_ALL ?? 'C.UTF-8',
    CI: '1',
    NO_COLOR: '1',
  }
  const store = persistentStore ?? join(stagedHome, 'pnpm-store')
  const finish = async (result: StageResult): Promise<StageResult> => {
    await rm(stagedHome, { recursive: true, force: true })
    return result
  }
  await mkdir(store, { recursive: true })
  const hydrate = await run(dsh.command, [
    ...dsh.prefix, 'plugin', '--profile', profile.name, 'install', '--ignore-scripts', '--frozen-lockfile', '--offline', '--store-dir', store,
  ], env)
  if (hydrate.code !== 0) return finish({ attempted: true, compatible: false, reason: `Baseline dependency hydration failed: ${sanitizeText(`${hydrate.stderr}\n${hydrate.stdout}`, 600)}` })
  const before = await run(dsh.command, [...dsh.prefix, '--profile', profile.name, '--dump-config'], env)
  if (before.code !== 0) return finish({ attempted: true, compatible: false, reason: `Baseline config composition failed: ${sanitizeText(`${before.stderr}\n${before.stdout}`, 600)}` })
  const install = await run(dsh.command, [
    ...dsh.prefix, 'plugin', '--profile', profile.name, 'add', '--save-exact', '--ignore-scripts', '--store-dir', store, artifactPath,
  ], env)
  if (install.code !== 0) return finish({ attempted: true, compatible: false, beforeConfigHash: sha256(before.stdout), reason: `Staged dependency install failed: ${sanitizeText(`${install.stderr}\n${install.stdout}`, 600)}` })
  const after = await run(dsh.command, [...dsh.prefix, '--profile', profile.name, '--dump-config'], env)
  if (after.code !== 0) return finish({ attempted: true, compatible: false, beforeConfigHash: sha256(before.stdout), reason: `Candidate config composition failed: ${sanitizeText(`${after.stderr}\n${after.stdout}`, 600)}` })
  const beforeSet = new Set(configLines(before.stdout))
  const afterSet = new Set(configLines(after.stdout))
  const diff = [
    ...[...beforeSet].filter((line) => !afterSet.has(line)).map((line) => `- ${line}`),
    ...[...afterSet].filter((line) => !beforeSet.has(line)).map((line) => `+ ${line}`),
  ].slice(0, 200)
  const lock = await readFile(join(stagedProfile, 'pnpm-lock.yaml'), 'utf8')
  const proposed = await snapshotProfile(profile.name, stagedHome)
  return finish({
    attempted: true,
    compatible: true,
    beforeConfigHash: sha256(before.stdout),
    afterConfigHash: sha256(after.stdout),
    proposedLockHash: sha256(lock),
    proposedProfileFingerprint: proposed.fingerprint,
    proposedBundles: proposed.bundles,
    configDiff: diff,
  })
}

export async function verifyProfile(name: string, paths: StatePaths, home?: string): Promise<VerifyResult> {
  const current = await snapshotProfile(name, dshHomePath(home))
  const expected = await loadInstall(name, paths)
  if (!expected) return { status: 'unknown', profile: current, detail: 'No DSH Guard installation record exists for this profile.', unmanagedBundles: current.bundles }
  const unmanagedBundles = current.bundles.filter((bundle) => !expected.expectedBundles.includes(bundle))
  if (current.fingerprint === expected.resultingProfileFingerprint && unmanagedBundles.length === 0) {
    const verified = { ...expected, lastVerifiedAt: new Date().toISOString() }
    await saveInstall(verified, paths)
    return { status: 'verified', profile: current, expected: verified, detail: 'Profile files match the last guarded installation.', unmanagedBundles }
  }
  const type: 'unmanaged-plugin' | 'verified-to-drifted' = unmanagedBundles.length > 0 ? 'unmanaged-plugin' : 'verified-to-drifted'
  const event = {
    schemaVersion: 1 as const,
    id: sortableId('evt'),
    createdAt: new Date().toISOString(),
    severity: 'high' as const,
    type,
    fingerprint: sha256(`${type}:${name}:${current.fingerprint}:${unmanagedBundles.join(',')}`),
    title: unmanagedBundles.length > 0 ? '发现未纳管插件' : 'DSH profile 已漂移',
    detail: unmanagedBundles.length > 0 ? `未纳管 bundle: ${unmanagedBundles.join(', ')}` : '当前 profile 文件与最后一次受控安装后的指纹不同。',
    profile: name,
  }
  await appendEvent(paths, event)
  return { status: 'drifted', profile: current, expected, detail: event.detail, unmanagedBundles }
}
