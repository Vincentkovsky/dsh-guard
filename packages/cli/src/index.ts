import { access, chmod, stat } from 'node:fs/promises'
import { constants } from 'node:fs'
import { Command } from 'commander'
import {
  approveReport,
  buildStatusSnapshot,
  initState,
  installApproved,
  listReportIds,
  loadReport,
  locateDshBin,
  scan,
  statePaths,
  verifyProfile,
  writeStatusFile,
  type ScanReport,
} from '@dsh-guard/core'

export const EXIT = { ok: 0, review: 2, blocked: 3, runtime: 4, repair: 5 } as const

function printReport(report: ScanReport): void {
  const icon = report.verdict === 'pass' ? '✓' : report.verdict === 'review' ? '!' : '×'
  console.log(`${icon} ${report.source.name}@${report.source.version} — ${report.verdict.toUpperCase()}`)
  console.log(`  报告: ${report.id}`)
  console.log(`  Profile: ${report.profile.name} (${report.profile.fingerprint.slice(0, 12)})`)
  console.log(`  Artifact: sha256:${report.source.sha256.slice(0, 16)}…`)
  console.log(`  文件: ${report.files.length}，入口: ${report.entrypoints.length}，发现: ${report.findings.length}`)
  for (const finding of report.findings) {
    const marker = finding.severity === 'blocked' ? 'BLOCK' : finding.severity === 'review' ? 'REVIEW' : 'INFO'
    const at = finding.evidence ? ` (${finding.evidence.file}${finding.evidence.line ? `:${finding.evidence.line}` : ''})` : ''
    console.log(`  [${marker}] ${finding.title}${at}`)
    console.log(`          ${finding.detail}`)
  }
  console.log(`  ${report.summary}`)
}

function reportExit(report: ScanReport): number {
  return report.verdict === 'pass' ? EXIT.ok : report.verdict === 'review' ? EXIT.review : EXIT.blocked
}

export function createProgram(): Command {
  const program = new Command()
    .name('dsh-guard')
    .description('Supply-chain scanner and policy gate for DeepSeek Harness plugins')
    .version('0.1.0')
    .showHelpAfterError()

  program.command('scan')
    .argument('<spec>', 'public npm package, local directory, or local .tgz')
    .requiredOption('--profile <name>', 'target DSH profile')
    .option('--json', 'print machine-readable JSON')
    .option('--no-stage', 'skip isolated DSH composition (forces review)')
    .action(async (spec: string, options: { profile: string; json?: boolean; stage: boolean }) => {
      const report = await scan(spec, { profile: options.profile, stage: options.stage })
      if (options.json) console.log(JSON.stringify(report, null, 2))
      else printReport(report)
      process.exitCode = reportExit(report)
    })

  program.command('report')
    .argument('[report-id]', 'report id; defaults to latest')
    .option('--json', 'print machine-readable JSON')
    .action(async (id: string | undefined, options: { json?: boolean }) => {
      const paths = statePaths()
      const reportId = id ?? (await listReportIds(paths))[0]
      if (!reportId) throw new Error('No scan reports found')
      const report = await loadReport(reportId, paths)
      if (options.json) console.log(JSON.stringify(report, null, 2))
      else printReport(report)
      process.exitCode = reportExit(report)
    })

  program.command('approve')
    .argument('<report-id>')
    .action(async (reportId: string) => {
      const approval = await approveReport(reportId, statePaths())
      console.log(`已批准 ${approval.reportId}`)
      console.log('审批已绑定 artifact、profile、policy 和完整报告哈希；任何漂移都需要重新扫描。')
    })

  program.command('install')
    .argument('<report-id>')
    .action(async (reportId: string) => {
      const record = await installApproved(reportId, statePaths())
      console.log(`已安装 ${record.packageName}@${record.version} 到 profile ${record.profile}`)
      console.log('请手动重启 DSH GUI 使插件生效。')
    })

  program.command('verify')
    .requiredOption('--profile <name>', 'target DSH profile')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { profile: string; json?: boolean }) => {
      const paths = statePaths()
      const result = await verifyProfile(options.profile, paths)
      const snapshot = await buildStatusSnapshot(paths, result)
      await writeStatusFile(paths, snapshot)
      if (options.json) console.log(JSON.stringify(snapshot, null, 2))
      else {
        console.log(`${snapshot.label}: ${snapshot.detail}`)
        if (result.unmanagedBundles.length) console.log(`未纳管 bundles: ${result.unmanagedBundles.join(', ')}`)
      }
      process.exitCode = result.status === 'verified' ? EXIT.ok : result.status === 'needs-repair' ? EXIT.repair : EXIT.review
    })

  program.command('doctor')
    .description('check local runtime and state prerequisites')
    .action(async () => {
      const paths = statePaths()
      await initState(paths)
      const dsh = await locateDshBin()
      const root = await stat(paths.root)
      const mode = root.mode & 0o777
      const checks = [
        { name: 'Node.js >=22.22 (DSH rc.6 runtime)', ok: (() => { const [major = 0, minor = 0] = process.versions.node.split('.').map(Number); return major > 22 || (major === 22 && minor >= 22) })(), detail: process.version },
        { name: 'DSH executable', ok: Boolean(dsh), detail: dsh ? `${dsh.command} ${dsh.prefix.join(' ')}` : 'set DSH_BIN' },
        { name: 'State directory mode', ok: mode === 0o700, detail: mode.toString(8) },
      ]
      checks.forEach((check) => console.log(`${check.ok ? '✓' : '×'} ${check.name}: ${check.detail}`))
      if (checks.some((check) => !check.ok)) process.exitCode = EXIT.runtime
    })

  return program
}

export async function runCli(argv = process.argv): Promise<void> {
  try {
    await createProgram().parseAsync(argv)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.error(`dsh-guard: ${message}`)
    process.exitCode = /needs-repair|could not restore/i.test(message) ? EXIT.repair : EXIT.runtime
  }
}
