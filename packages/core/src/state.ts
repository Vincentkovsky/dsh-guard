import { homedir } from 'node:os'
import { join } from 'node:path'
import { appendFile, chmod, readFile, readdir } from 'node:fs/promises'
import type { Approval, GuardEvent, InstallRecord, ScanReport } from './types.js'
import { atomicWrite, ensurePrivateDir, readJson, sha256, stableJson, writeJson } from './util.js'

export interface StatePaths {
  root: string
  reports: string
  approvals: string
  installs: string
  cache: string
  locks: string
  audit: string
  events: string
  status: string
}

export function statePaths(root = process.env.DSH_GUARD_HOME ?? join(homedir(), '.dsh-guard')): StatePaths {
  return {
    root,
    reports: join(root, 'reports'),
    approvals: join(root, 'approvals'),
    installs: join(root, 'installs'),
    cache: join(root, 'cache'),
    locks: join(root, 'locks'),
    audit: join(root, 'audit.jsonl'),
    events: join(root, 'events.jsonl'),
    status: join(root, 'status.json'),
  }
}

export async function initState(paths: StatePaths): Promise<void> {
  await Promise.all([paths.root, paths.reports, paths.approvals, paths.installs, paths.cache, paths.locks].map(ensurePrivateDir))
}

export async function saveReport(report: ScanReport, paths: StatePaths): Promise<string> {
  await initState(paths)
  const file = join(paths.reports, `${report.id}.json`)
  await writeJson(file, report)
  return file
}

export async function loadReport(id: string, paths: StatePaths): Promise<ScanReport> {
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) throw new Error('Invalid report id')
  return readJson<ScanReport>(join(paths.reports, `${id}.json`))
}

export async function saveApproval(approval: Approval, paths: StatePaths): Promise<void> {
  await initState(paths)
  await writeJson(join(paths.approvals, `${approval.reportId}.json`), approval)
}

export async function loadApproval(reportId: string, paths: StatePaths): Promise<Approval> {
  return readJson<Approval>(join(paths.approvals, `${reportId}.json`))
}

export async function saveInstall(record: InstallRecord, paths: StatePaths): Promise<void> {
  await initState(paths)
  await writeJson(join(paths.installs, `${record.profile}.json`), record)
}

export async function loadInstall(profile: string, paths: StatePaths): Promise<InstallRecord | undefined> {
  try {
    return await readJson<InstallRecord>(join(paths.installs, `${profile}.json`))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
}

export async function appendAudit(paths: StatePaths, action: string, fields: Record<string, unknown>): Promise<void> {
  await initState(paths)
  const line = JSON.stringify({ at: new Date().toISOString(), action, ...fields }) + '\n'
  await appendFile(paths.audit, line, { encoding: 'utf8', mode: 0o600 })
  await chmod(paths.audit, 0o600)
}

export async function appendEvent(paths: StatePaths, event: GuardEvent): Promise<void> {
  await initState(paths)
  try {
    const latest = new Map<string, GuardEvent>()
    for (const line of (await readFile(paths.events, 'utf8')).split(/\r?\n/)) {
      if (!line.trim()) continue
      try {
        const prior = JSON.parse(line) as GuardEvent
        if (prior.fingerprint) latest.set(prior.fingerprint, prior)
      } catch { /* ignore a torn tail */ }
    }
    if (!latest.get(event.fingerprint)?.acknowledgedAt) {
      if (latest.has(event.fingerprint)) return
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  const line = JSON.stringify(event) + '\n'
  await appendFile(paths.events, line, { encoding: 'utf8', mode: 0o600 })
  await chmod(paths.events, 0o600)
}

export async function listReportIds(paths: StatePaths): Promise<string[]> {
  await initState(paths)
  return (await readdir(paths.reports)).filter((name) => name.endsWith('.json')).map((name) => name.slice(0, -5)).sort().reverse()
}

export function reportDigest(report: ScanReport): string {
  return sha256(stableJson(report))
}

export async function writeStatusFile(paths: StatePaths, status: unknown): Promise<void> {
  await atomicWrite(paths.status, stableJson(status))
}
