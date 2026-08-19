import { createHash, randomUUID } from 'node:crypto'
import { chmod, mkdir, open, readFile, rename, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'

export function sha256(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex')
}

export async function sha256File(path: string): Promise<string> {
  return sha256(await readFile(path))
}

export function stableJson(value: unknown): string {
  return JSON.stringify(sortValue(value), null, 2) + '\n'
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, child]) => [key, sortValue(child)]),
    )
  }
  return value
}

export async function ensurePrivateDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 })
  await chmod(path, 0o700)
}

export async function atomicWrite(path: string, data: string | Uint8Array, mode = 0o600): Promise<void> {
  await ensurePrivateDir(dirname(path))
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`
  let renamed = false
  try {
    const handle = await open(temp, 'wx', mode)
    try {
      await handle.writeFile(data)
      await handle.chmod(mode)
      await handle.sync()
    } finally {
      await handle.close()
    }
    await rename(temp, path)
    renamed = true
    const directory = await open(dirname(path), 'r')
    try {
      await directory.sync()
    } finally {
      await directory.close()
    }
  } finally {
    if (!renamed) {
      try { await unlink(temp) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    }
  }
}

export function sortableId(prefix: string, now = new Date()): string {
  return `${prefix}_${now.toISOString().replace(/[-:.TZ]/g, '')}_${randomUUID().replaceAll('-', '').slice(0, 12)}`
}

export function isWithin(root: string, candidate: string): boolean {
  const normalizedRoot = root.endsWith('/') ? root : `${root}/`
  return candidate === root || candidate.startsWith(normalizedRoot)
}

export function sanitizeText(input: unknown, max = 1200): string {
  return String(input ?? '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .replace(/(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]')
    .slice(0, max)
}

export async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T
}

export async function writeJson(path: string, value: unknown): Promise<void> {
  await atomicWrite(path, stableJson(value))
}
