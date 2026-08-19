import { lstat, mkdtemp, readFile, realpath, readdir, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, normalize, posix, resolve, relative } from 'node:path'
import * as tar from 'tar'
import type { FileRecord, Finding, Policy } from './types.js'
import { isWithin, sha256File } from './util.js'

export interface ExtractedArtifact {
  root: string
  files: FileRecord[]
  findings: Finding[]
}

function safeArchivePath(path: string): boolean {
  if (!path.startsWith('package/')) return false
  const normalized = posix.normalize(path)
  return normalized === 'package' || (normalized.startsWith('package/') && !normalized.includes('/../') && !posix.isAbsolute(normalized))
}

export async function extractArtifact(artifact: string, policy: Policy): Promise<ExtractedArtifact> {
  const artifactInfo = await stat(artifact)
  if (artifactInfo.size > policy.maxArchiveBytes) throw new Error(`Archive exceeds ${policy.maxArchiveBytes} bytes`)
  const findings: Finding[] = []
  let entries = 0
  let expandedBytes = 0
  let unsafe: string | undefined
  await tar.t({
    file: artifact,
    strict: true,
    onentry(entry) {
      entries += 1
      expandedBytes += entry.size
      if (entries > policy.maxFiles) unsafe = `Archive exceeds ${policy.maxFiles} entries`
      if (expandedBytes > policy.maxArchiveBytes * 5) unsafe = 'Expanded archive exceeds safety budget'
      if (!safeArchivePath(entry.path)) unsafe = `Archive path escapes package root: ${entry.path}`
      if (entry.type === 'Link' || entry.type === 'SymbolicLink') {
        const linkpath = entry.linkpath ?? ''
        const target = posix.normalize(posix.join(posix.dirname(entry.path), linkpath))
        if (!target.startsWith('package/')) unsafe = `Archive link escapes package root: ${entry.path} -> ${linkpath}`
        findings.push({
          id: 'artifact.link', severity: 'review', category: 'artifact', title: 'Archive contains a link',
          detail: `${entry.path} -> ${linkpath}`, evidence: { file: entry.path },
        })
      }
    },
  })
  if (unsafe) throw new Error(unsafe)
  const destination = await mkdtemp(join(tmpdir(), 'dsh-guard-extract-'))
  await tar.x({
    cwd: destination,
    file: artifact,
    strict: true,
    preservePaths: false,
    filter(path, entry) {
      const tarEntry = entry as { type?: string; size: number }
      return safeArchivePath(path) && tarEntry.type !== 'Link' && tarEntry.type !== 'SymbolicLink' && tarEntry.size <= policy.maxSourceFileBytes * 4
    },
  })
  const root = await realpath(join(destination, 'package'))
  const files: FileRecord[] = []
  async function walk(directory: string): Promise<void> {
    for (const name of (await readdir(directory)).sort()) {
      const absolute = join(directory, name)
      const info = await lstat(absolute)
      const rel = relative(root, absolute).split('\\').join('/')
      if (info.isDirectory()) await walk(absolute)
      else if (info.isFile()) files.push({ path: rel, size: info.size, sha256: await sha256File(absolute), kind: 'file' })
      else if (info.isSymbolicLink()) {
        const target = await realpath(absolute)
        if (!isWithin(root, target)) throw new Error(`Extracted symlink escapes package root: ${rel}`)
        files.push({ path: rel, size: info.size, sha256: await sha256File(target), kind: 'symlink', linkTarget: target })
      }
    }
  }
  await walk(root)
  return { root, files, findings }
}
