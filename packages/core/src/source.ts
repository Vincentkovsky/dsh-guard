import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { copyFile, lstat, mkdtemp, readFile, readdir, realpath, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, extname, join, resolve } from 'node:path'
import Arborist from '@npmcli/arborist'
import packlist from 'npm-packlist'
import semver from 'semver'
import * as tar from 'tar'
import type { ResolvedSource } from './types.js'
import type { StatePaths } from './state.js'
import { atomicWrite, ensurePrivateDir, isWithin, sha256File } from './util.js'

type PackageJson = {
  name?: string
  version?: string
}

interface RegistryVersion {
  name: string
  version: string
  dist: { tarball: string; integrity?: string; shasum?: string }
}

interface RegistryDocument {
  'dist-tags'?: Record<string, string>
  versions?: Record<string, RegistryVersion>
  time?: Record<string, string>
}

function parseNpmSpec(spec: string): { name: string; selector: string } {
  if (/^(?:git(?:\+[^:]+)?:|https?:|github:|gitlab:|bitbucket:|file:|link:|workspace:|npm:)/i.test(spec)) {
    throw new Error(`Unsupported source spec: ${spec}. v1 accepts public npm names, local directories, and local .tgz files only.`)
  }
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/')
    const at = spec.lastIndexOf('@')
    if (slash < 2) throw new Error(`Invalid scoped npm package: ${spec}`)
    return at > slash ? { name: spec.slice(0, at), selector: spec.slice(at + 1) || 'latest' } : { name: spec, selector: 'latest' }
  }
  const at = spec.lastIndexOf('@')
  return at > 0 ? { name: spec.slice(0, at), selector: spec.slice(at + 1) || 'latest' } : { name: spec, selector: 'latest' }
}

async function digestFile(path: string, algorithm: 'sha1' | 'sha512'): Promise<string> {
  const hash = createHash(algorithm)
  await new Promise<void>((resolvePromise, reject) => {
    const stream = createReadStream(path)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('error', reject)
    stream.on('end', resolvePromise)
  })
  return algorithm === 'sha512' ? hash.digest('base64') : hash.digest('hex')
}

async function verifyRegistryIntegrity(path: string, version: RegistryVersion): Promise<void> {
  if (version.dist.integrity) {
    const [algorithm, expected] = version.dist.integrity.split('-', 2)
    if (algorithm !== 'sha512' || !expected) throw new Error(`Unsupported registry integrity algorithm: ${algorithm ?? 'missing'}`)
    const actual = await digestFile(path, 'sha512')
    if (actual !== expected) throw new Error('Registry integrity mismatch; artifact discarded')
    return
  }
  if (!version.dist.shasum) throw new Error('Registry response has neither integrity nor shasum')
  if (await digestFile(path, 'sha1') !== version.dist.shasum) throw new Error('Registry shasum mismatch; artifact discarded')
}

async function cacheArtifact(source: string, paths: StatePaths): Promise<{ path: string; sha256: string }> {
  const hash = await sha256File(source)
  const dir = join(paths.cache, 'artifacts', hash.slice(0, 2))
  await ensurePrivateDir(dir)
  const destination = join(dir, `${hash}.tgz`)
  try {
    await stat(destination)
  } catch {
    await copyFile(source, destination)
  }
  return { path: destination, sha256: hash }
}

export async function packDirectory(directory: string, output: string): Promise<string[]> {
  const root = await realpath(directory)
  const packageJson = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as PackageJson
  if (!packageJson.name || !packageJson.version) throw new Error('Local package.json must contain name and version')
  async function rejectEscapingSymlinks(current: string): Promise<void> {
    for (const name of await readdir(current)) {
      if (name === 'node_modules' || name === '.git') continue
      const absolute = join(current, name)
      const entry = await lstat(absolute)
      if (entry.isDirectory()) await rejectEscapingSymlinks(absolute)
      else if (entry.isSymbolicLink()) {
        const target = await realpath(absolute)
        if (!isWithin(root, target)) throw new Error(`Symlink escapes package root: ${absolute.slice(root.length + 1)}`)
      }
    }
  }
  await rejectEscapingSymlinks(root)
  const tree = await new Arborist({ path: root }).loadActual()
  const files = (await packlist(tree)).sort((a, b) => a.localeCompare(b))
  for (const relative of files) {
    const absolute = resolve(root, relative)
    if (!isWithin(root, absolute)) throw new Error(`Packlist path escapes package root: ${relative}`)
    const entry = await lstat(absolute)
    if (entry.isSymbolicLink()) {
      const target = await realpath(absolute)
      if (!isWithin(root, target)) throw new Error(`Symlink escapes package root: ${relative}`)
    }
  }
  await tar.c(
    {
      cwd: root,
      file: output,
      gzip: true,
      portable: true,
      noMtime: true,
      mtime: new Date(0),
      prefix: 'package/',
      follow: false,
    },
    files,
  )
  return files
}

async function resolveDirectory(path: string, paths: StatePaths): Promise<ResolvedSource> {
  const root = await realpath(path)
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as PackageJson
  if (!pkg.name || !pkg.version) throw new Error('Local package.json must contain name and version')
  const scratch = await mkdtemp(join(tmpdir(), 'dsh-guard-pack-'))
  const tarball = join(scratch, `${pkg.name.replaceAll('/', '-')}-${pkg.version}.tgz`)
  await packDirectory(root, tarball)
  const cached = await cacheArtifact(tarball, paths)
  return { kind: 'directory', requested: path, name: pkg.name, version: pkg.version, artifactPath: cached.path, sha256: cached.sha256 }
}

async function readTarballIdentity(path: string): Promise<PackageJson> {
  let text: string | undefined
  await tar.t({
    file: path,
    onentry(entry) {
      if (entry.path === 'package/package.json') {
        const chunks: Buffer[] = []
        entry.on('data', (chunk: Buffer) => chunks.push(chunk))
        entry.on('end', () => { text = Buffer.concat(chunks).toString('utf8') })
      }
    },
  })
  if (!text) throw new Error('Tarball is missing package/package.json')
  return JSON.parse(text) as PackageJson
}

async function resolveTarball(path: string, paths: StatePaths): Promise<ResolvedSource> {
  const absolute = await realpath(path)
  const pkg = await readTarballIdentity(absolute)
  if (!pkg.name || !pkg.version) throw new Error('Tarball package.json must contain name and version')
  const cached = await cacheArtifact(absolute, paths)
  return { kind: 'tarball', requested: path, name: pkg.name, version: pkg.version, artifactPath: cached.path, sha256: cached.sha256 }
}

async function resolveNpm(spec: string, paths: StatePaths): Promise<ResolvedSource> {
  const { name, selector } = parseNpmSpec(spec)
  const registry = 'https://registry.npmjs.org'
  const response = await fetch(`${registry}/${encodeURIComponent(name).replace('%40', '@')}`, {
    headers: { accept: 'application/vnd.npm.install-v1+json', 'user-agent': 'dsh-guard/0.1.0' },
    redirect: 'error',
  })
  if (!response.ok) throw new Error(`npm registry returned ${response.status} for ${name}`)
  const document = await response.json() as RegistryDocument
  const versions = document.versions ?? {}
  const exact = document['dist-tags']?.[selector]
    ?? (semver.valid(selector) ? selector : semver.maxSatisfying(Object.keys(versions), selector, { includePrerelease: true }))
  if (!exact || !versions[exact]) throw new Error(`No public npm version satisfies ${spec}`)
  const selected = versions[exact]
  if (selected.name !== name || selected.version !== exact) throw new Error('Registry identity mismatch')
  const tarballUrl = new URL(selected.dist.tarball)
  if (tarballUrl.protocol !== 'https:') throw new Error('Registry tarball URL is not HTTPS')
  const download = await fetch(tarballUrl, { redirect: 'error', headers: { 'user-agent': 'dsh-guard/0.1.0' } })
  if (!download.ok || !download.body) throw new Error(`Tarball download failed: ${download.status}`)
  const bytes = new Uint8Array(await download.arrayBuffer())
  const scratch = await mkdtemp(join(tmpdir(), 'dsh-guard-npm-'))
  const tempTarball = join(scratch, `${basename(name)}-${exact}.tgz`)
  await atomicWrite(tempTarball, bytes)
  await verifyRegistryIntegrity(tempTarball, selected)
  const identity = await readTarballIdentity(tempTarball)
  if (identity.name !== name || identity.version !== exact) throw new Error('Downloaded artifact identity differs from registry metadata')
  const cached = await cacheArtifact(tempTarball, paths)
  return {
    kind: 'npm', requested: spec, name, version: exact, artifactPath: cached.path, sha256: cached.sha256,
    ...(selected.dist.integrity ? { integrity: selected.dist.integrity } : {}),
    registry,
    ...(document.time?.[exact] ? { publishedAt: document.time[exact] } : {}),
  }
}

export async function resolveSource(spec: string, paths: StatePaths): Promise<ResolvedSource> {
  try {
    const info = await stat(spec)
    if (info.isDirectory()) return resolveDirectory(spec, paths)
    if (info.isFile() && (extname(spec) === '.tgz' || spec.endsWith('.tar.gz'))) return resolveTarball(spec, paths)
    throw new Error(`Unsupported local source: ${spec}`)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  return resolveNpm(spec, paths)
}
