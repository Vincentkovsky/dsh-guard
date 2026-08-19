import { readFile } from 'node:fs/promises'
import type { GuardEvent, GuardStatusSnapshot, VerifyResult } from './types.js'
import type { StatePaths } from './state.js'
import { listReportIds, loadReport } from './state.js'

export async function readEvents(paths: StatePaths): Promise<GuardEvent[]> {
  let text: string
  try { text = await readFile(paths.events, 'utf8') }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error }
  const latest = new Map<string, GuardEvent>()
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue
    try {
      const event = JSON.parse(line) as GuardEvent
      if (event.schemaVersion === 1 && event.fingerprint) latest.set(event.fingerprint, event)
    } catch { /* a torn final event line is ignored */ }
  }
  return [...latest.values()].sort((a, b) => b.id.localeCompare(a.id))
}

export async function buildStatusSnapshot(paths: StatePaths, verification: VerifyResult): Promise<GuardStatusSnapshot> {
  const ids = await listReportIds(paths)
  const reports = await Promise.all(ids.slice(0, 200).map((id) => loadReport(id, paths)))
  const events = (await readEvents(paths)).filter((event) => !event.acknowledgedAt)
  const expected = verification.expected
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    status: verification.status,
    label: verification.status === 'verified' ? '已验证' : verification.status === 'drifted' ? '检测到漂移' : verification.status === 'needs-repair' ? '需要修复' : verification.status === 'review' ? '需要审查' : '状态未知',
    detail: verification.detail,
    profile: verification.profile.name,
    ...(verification.lastVerifiedAt ? { lastVerifiedAt: verification.lastVerifiedAt } : expected ? { lastVerifiedAt: expected.lastVerifiedAt } : {}),
    ...(verification.reportId ? { reportId: verification.reportId } : expected ? { reportId: expected.reportId } : {}),
    counts: {
      reports: reports.length,
      review: reports.filter((report) => report.verdict === 'review').length,
      blocked: reports.filter((report) => report.verdict === 'blocked').length,
      activeAlerts: events.length,
    },
    events,
    managedPackages: verification.managedPlugins?.map((plugin) => ({ name: plugin.packageName, version: plugin.version, state: verification.status }))
      ?? (expected ? [{ name: expected.packageName, version: expected.version, state: verification.status }] : []),
  }
}
