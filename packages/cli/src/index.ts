import { open, stat } from 'node:fs/promises'
import { Command } from 'commander'
import {
  actionPolicyHash,
  actionStorePaths,
  appendAudit,
  approveReport,
  buildSandboxEnvironment,
  buildGuardedDshEnvironment,
  buildStatusSnapshot,
  cleanupSandboxRuntime,
  createSandboxPlan,
  createDefaultActionPolicy,
  dshHomePath,
  evaluateAction,
  initState,
  inspectActionStore,
  inspectLifecycleState,
  inspectManagedProfiles,
  installApproved,
  listReportIds,
  loadActionGrantStore,
  loadOrImportManagedProfile,
  loadReport,
  locateDshBin,
  scan,
  parseActionPolicy,
  parseActionRequest,
  prepareSandboxRuntime,
  readActionEvents,
  revokeActionGrantFromStore,
  revokeAllActionGrants,
  repairManagedProfile,
  rollbackManagedProfile,
  runGuardedDsh,
  runSandboxedDsh,
  sandboxPlanDigest,
  sanitizeText,
  sha256,
  stableJson,
  statePaths,
  snapshotProfile,
  summarizeActionResource,
  uninstallManagedPlugin,
  updateApproved,
  validateSandboxAppArgs,
  validateGuardedDshArgs,
  verifyProfile,
  writeStatusFile,
  type ActionDecisionV1,
  type ActionEventV1,
  type ActionGrantV1,
  type ActionPolicyV1,
  type ActionRequestV1,
  type ManagedProfileViewV1,
  type ProfileGenerationV1,
  type ScanReport,
  type SandboxNetworkMode,
  type SandboxPlanV1,
  type SandboxRuntimeV1,
} from '@dsh-guard/core'

export const EXIT = { ok: 0, review: 2, blocked: 3, runtime: 4, repair: 5 } as const
const MAX_ACTION_INPUT_BYTES = 1024 * 1024

export interface CliServices {
  approveReport: typeof approveReport
  appendAudit: typeof appendAudit
  actionStorePaths: typeof actionStorePaths
  buildStatusSnapshot: typeof buildStatusSnapshot
  buildSandboxEnvironment: typeof buildSandboxEnvironment
  buildGuardedDshEnvironment: typeof buildGuardedDshEnvironment
  cleanupSandboxRuntime: typeof cleanupSandboxRuntime
  createSandboxPlan: typeof createSandboxPlan
  dshHomePath: typeof dshHomePath
  initState: typeof initState
  inspectActionStore: typeof inspectActionStore
  inspectLifecycleState: typeof inspectLifecycleState
  inspectManagedProfiles: typeof inspectManagedProfiles
  installApproved: typeof installApproved
  listReportIds: typeof listReportIds
  loadActionGrantStore: typeof loadActionGrantStore
  loadOrImportManagedProfile: typeof loadOrImportManagedProfile
  loadReport: typeof loadReport
  locateDshBin: typeof locateDshBin
  prepareSandboxRuntime: typeof prepareSandboxRuntime
  scan: typeof scan
  readActionEvents: typeof readActionEvents
  revokeActionGrantFromStore: typeof revokeActionGrantFromStore
  revokeAllActionGrants: typeof revokeAllActionGrants
  repairManagedProfile: typeof repairManagedProfile
  rollbackManagedProfile: typeof rollbackManagedProfile
  runGuardedDsh: typeof runGuardedDsh
  runSandboxedDsh: typeof runSandboxedDsh
  sandboxPlanDigest: typeof sandboxPlanDigest
  sha256: typeof sha256
  stableJson: typeof stableJson
  statePaths: typeof statePaths
  snapshotProfile: typeof snapshotProfile
  uninstallManagedPlugin: typeof uninstallManagedPlugin
  updateApproved: typeof updateApproved
  validateSandboxAppArgs: typeof validateSandboxAppArgs
  validateGuardedDshArgs: typeof validateGuardedDshArgs
  verifyProfile: typeof verifyProfile
  writeStatusFile: typeof writeStatusFile
  cwd: string
  statMode(path: string): Promise<number>
  readText(path: string): Promise<string>
  readStdin(): Promise<string>
  nodeVersion: string
  nodePath: string
  platform: NodeJS.Platform
  environment: NodeJS.ProcessEnv
  log(message: string): void
  error(message: string): void
}

async function readStdin(): Promise<string> {
  let result = ''
  process.stdin.setEncoding('utf8')
  for await (const chunk of process.stdin) {
    result += String(chunk)
    if (Buffer.byteLength(result) > MAX_ACTION_INPUT_BYTES) throw new Error('Action input exceeds 1 MiB')
  }
  return result
}

const defaultServices: CliServices = {
  approveReport,
  appendAudit,
  actionStorePaths,
  buildStatusSnapshot,
  buildSandboxEnvironment,
  buildGuardedDshEnvironment,
  cleanupSandboxRuntime,
  createSandboxPlan,
  dshHomePath,
  initState,
  inspectActionStore,
  inspectLifecycleState,
  inspectManagedProfiles,
  installApproved,
  listReportIds,
  loadActionGrantStore,
  loadOrImportManagedProfile,
  loadReport,
  locateDshBin,
  prepareSandboxRuntime,
  scan,
  readActionEvents,
  revokeActionGrantFromStore,
  revokeAllActionGrants,
  repairManagedProfile,
  rollbackManagedProfile,
  runGuardedDsh,
  runSandboxedDsh,
  sandboxPlanDigest,
  sha256,
  stableJson,
  statePaths,
  snapshotProfile,
  uninstallManagedPlugin,
  updateApproved,
  validateSandboxAppArgs,
  validateGuardedDshArgs,
  verifyProfile,
  writeStatusFile,
  cwd: process.cwd(),
  async statMode(path) { return (await stat(path)).mode },
  async readText(path) {
    const handle = await open(path, 'r')
    try {
      if ((await handle.stat()).size > MAX_ACTION_INPUT_BYTES) throw new Error('Action input exceeds 1 MiB')
      return await handle.readFile('utf8')
    } finally {
      await handle.close()
    }
  },
  readStdin,
  nodeVersion: process.versions.node,
  nodePath: process.execPath,
  platform: process.platform,
  environment: process.env,
  log(message) { console.log(message) },
  error(message) { console.error(message) },
}

function parseJsonDocument(text: string, label: string): unknown {
  if (Buffer.byteLength(text) > MAX_ACTION_INPUT_BYTES) throw new Error(`${label} exceeds 1 MiB`)
  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new Error(`${label} is not valid JSON`)
  }
}

async function loadActionPolicy(
  services: CliServices,
  policyFile?: string,
): Promise<ActionPolicyV1> {
  if (!policyFile) return createDefaultActionPolicy([services.cwd])
  return parseActionPolicy(parseJsonDocument(await services.readText(policyFile), 'Action policy'))
}

async function loadActionRequest(
  services: CliServices,
  requestFile: string,
): Promise<ActionRequestV1> {
  const text = requestFile === '-' ? await services.readStdin() : await services.readText(requestFile)
  return parseActionRequest(parseJsonDocument(text, 'Action request'))
}

function printActionPolicy(policy: ActionPolicyV1, log: CliServices['log']): void {
  log(`Action policy: ${policy.id}`)
  log(`  Hash: sha256:${actionPolicyHash(policy)}`)
  log(`  Workspaces: ${policy.workspaceRoots.length ? policy.workspaceRoots.join(', ') : '(none)'}`)
  log(`  Sensitive path patterns: ${policy.sensitivePathPatterns.length}`)
  log(`  Credential path patterns: ${policy.credentialPathPatterns.length}`)
  log(`  Allowed network domains: ${policy.allowedNetworkDomains.length ? policy.allowedNetworkDomains.join(', ') : '(none)'}`)
  log(`  Grant TTL: once=${policy.onceGrantTtlMs}ms, task=${policy.taskGrantTtlMs}ms`)
}

function printActionDecision(
  request: ActionRequestV1,
  decision: ActionDecisionV1,
  log: CliServices['log'],
): void {
  const icon = decision.effect === 'allow' ? '✓' : decision.effect === 'ask' ? '!' : '×'
  log(`${icon} ${decision.effect.toUpperCase()} ${decision.risk.toUpperCase()} — ${decision.ruleId}`)
  log(`  Tool: ${request.toolName} / ${request.operation}`)
  log(`  Reason: ${decision.reason}`)
  if (request.resources.length) {
    log('  Resources:')
    request.resources.forEach((resource) => log(`    - ${summarizeActionResource(resource)}`))
  }
  if (decision.grantOptions.length) log(`  Grant options: ${decision.grantOptions.join(', ')}`)
}

function actionDecisionExit(decision: ActionDecisionV1): number {
  return decision.effect === 'allow' ? EXIT.ok : decision.effect === 'ask' ? EXIT.review : EXIT.blocked
}

function printActionEvent(event: ActionEventV1, log: CliServices['log']): void {
  log(`${event.createdAt} ${event.decision.toUpperCase()}→${event.outcome.toUpperCase()} ${event.toolName}/${event.operation}`)
  log(`  Rule: ${event.ruleId}  Request: ${event.requestId}`)
  event.resourceSummary.forEach((resource) => log(`  - ${resource}`))
}

function printActionGrant(grant: ActionGrantV1, log: CliServices['log']): void {
  log(`${grant.id} ${grant.scope.toUpperCase()} ${grant.toolName}/${grant.operation}`)
  log(`  Session: ${grant.sessionId}${grant.taskId ? `  Task: ${grant.taskId}` : ''}`)
  log(`  Expires: ${grant.expiresAt}  Resources: ${grant.resourceConstraints.length}`)
}

function printManagedProfile(view: ManagedProfileViewV1, log: CliServices['log']): void {
  log(`${view.profile} ${view.state.toUpperCase()} — ${view.generationId} (${view.generationCount} generation${view.generationCount === 1 ? '' : 's'})`)
  if (view.plugins.length === 0) log('  No managed plugins in the current generation.')
  for (const plugin of view.plugins) log(`  - ${plugin.packageName}@${plugin.version}  report=${plugin.reportId}`)
  log(`  ${view.detail}`)
}

function collectOption(value: string, previous: string[]): string[] {
  return [...previous, value]
}

interface SandboxCliOptions {
  profile: string
  workspace: string[]
  network: string
  allowEnv: string[]
  json?: boolean
}

interface StartCliOptions {
  profile: string
  cwd?: string
}

function sandboxNetwork(value: string): SandboxNetworkMode {
  if (value !== 'deny' && value !== 'loopback' && value !== 'unrestricted') {
    throw new Error('Sandbox network must be one of: deny, loopback, unrestricted')
  }
  return value
}

function sandboxDshBin(dsh: Awaited<ReturnType<typeof locateDshBin>>): string {
  if (!dsh) throw new Error('DSH executable not found; set DSH_BIN to the exact rc.7 lib/bin.js path')
  if (dsh.prefix.length > 1) throw new Error('DSH launcher shape is unsupported; set DSH_BIN to the exact rc.7 lib/bin.js path')
  return dsh.prefix[0] ?? dsh.command
}

function printSandboxPlan(plan: SandboxPlanV1, log: CliServices['log']): void {
  log(`Sandbox plan: ${plan.id}`)
  log(`  Profile: ${plan.profile}`)
  log(`  Source profile: ${plan.sourceProfile} (not exposed to sandbox)`)
  log(`  Runtime profile: ${plan.dshHome} (disposable copy)`)
  log(`  Network: ${plan.network}`)
  log(`  Policy: sha256:${plan.policyHash}`)
  log(`  Plan: sha256:${sandboxPlanDigest(plan)}`)
  log('  Workspaces:')
  plan.workspaceRoots.forEach((path) => log(`    - ${path} (read/write)`))
  log(`  Read-only paths: ${plan.readOnlyPaths.length}`)
  log(`  Read/write paths: ${plan.readWritePaths.length}`)
  log(`  Environment names: ${plan.allowedEnvironmentNames.join(', ')}`)
  log('  Process execution: exact Node runtime only; arbitrary executables blocked')
  log('  Warnings:')
  plan.warnings.forEach((warning) => log(`    - ${warning}`))
}

function printGeneration(generation: ProfileGenerationV1, current: boolean, log: CliServices['log']): void {
  log(`${current ? '*' : ' '} ${generation.id} ${generation.action.toUpperCase()} ${generation.createdAt}`)
  const subject = generation.packageName ? `  Package: ${generation.packageName}` : undefined
  if (subject) log(subject)
  if (generation.restoredGenerationId) log(`  Restored: ${generation.restoredGenerationId}`)
  log(`  Plugins: ${generation.plugins.length}  Fingerprint: ${generation.profileFingerprint.slice(0, 16)}…`)
}

export function supportsDshNode(version: string): boolean {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:\+[^\s]+)?$/.exec(version)
  if (!match) return false
  const major = Number(match[1])
  const minor = Number(match[2])
  return major > 22 || (major === 22 && minor >= 22)
}

function printReport(report: ScanReport, log: CliServices['log']): void {
  const icon = report.verdict === 'pass' ? '✓' : report.verdict === 'review' ? '!' : '×'
  log(`${icon} ${report.source.name}@${report.source.version} — ${report.verdict.toUpperCase()}`)
  log(`  报告: ${report.id}`)
  log(`  Profile: ${report.profile.name} (${report.profile.fingerprint.slice(0, 12)})`)
  log(`  Artifact: sha256:${report.source.sha256.slice(0, 16)}…`)
  log(`  文件: ${report.files.length}，入口: ${report.entrypoints.length}，发现: ${report.findings.length}`)
  for (const finding of report.findings) {
    const marker = finding.severity === 'blocked' ? 'BLOCK' : finding.severity === 'review' ? 'REVIEW' : 'INFO'
    const at = finding.evidence ? ` (${finding.evidence.file}${finding.evidence.line ? `:${finding.evidence.line}` : ''})` : ''
    log(`  [${marker}] ${finding.title}${at}`)
    log(`          ${finding.detail}`)
  }
  log(`  ${report.summary}`)
}

function reportExit(report: ScanReport): number {
  return report.verdict === 'pass' ? EXIT.ok : report.verdict === 'review' ? EXIT.review : EXIT.blocked
}

export function createProgram(overrides: Partial<CliServices> = {}): Command {
  const services: CliServices = { ...defaultServices, ...overrides }
  const program = new Command()
    .name('dsh-guard')
    .description('Supply-chain and action policy gate for DeepSeek Harness')
    .version('0.5.0-alpha.1')
    .showHelpAfterError()

  program.command('scan')
    .argument('<spec>', 'public npm package, local directory, or local .tgz')
    .requiredOption('--profile <name>', 'target DSH profile')
    .option('--json', 'print machine-readable JSON')
    .option('--no-stage', 'skip isolated DSH composition (forces review)')
    .action(async (spec: string, options: { profile: string; json?: boolean; stage: boolean }) => {
      const report = await services.scan(spec, { profile: options.profile, stage: options.stage })
      if (options.json) services.log(JSON.stringify(report, null, 2))
      else printReport(report, services.log)
      process.exitCode = reportExit(report)
    })

  program.command('report')
    .argument('[report-id]', 'report id; defaults to latest')
    .option('--json', 'print machine-readable JSON')
    .action(async (id: string | undefined, options: { json?: boolean }) => {
      const paths = services.statePaths()
      const reportId = id ?? (await services.listReportIds(paths))[0]
      if (!reportId) throw new Error('No scan reports found')
      const report = await services.loadReport(reportId, paths)
      if (options.json) services.log(JSON.stringify(report, null, 2))
      else printReport(report, services.log)
      process.exitCode = reportExit(report)
    })

  program.command('approve')
    .argument('<report-id>')
    .action(async (reportId: string) => {
      const approval = await services.approveReport(reportId, services.statePaths())
      services.log(`已批准 ${approval.reportId}`)
      services.log('审批已绑定 artifact、profile、policy 和完整报告哈希；任何漂移都需要重新扫描。')
    })

  program.command('install')
    .argument('<report-id>')
    .action(async (reportId: string) => {
      const record = await services.installApproved(reportId, services.statePaths())
      services.log(`已安装 ${record.packageName}@${record.version} 到 profile ${record.profile}`)
      services.log('请手动重启 DSH GUI 使插件生效。')
    })

  const pluginsCommand = program.command('plugins')
    .description('inspect and manage guarded plugin lifecycle generations')

  pluginsCommand.command('list')
    .option('--profile <name>', 'limit output to one DSH profile')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { profile?: string; json?: boolean }) => {
      const profiles = await services.inspectManagedProfiles(services.statePaths(), options.profile)
      if (options.json) services.log(JSON.stringify({ schemaVersion: 1, profiles }, null, 2))
      else {
        profiles.forEach((profile) => printManagedProfile(profile, services.log))
        if (profiles.length === 0) services.log('No managed plugin profiles found.')
      }
      if (profiles.some((profile) => profile.state !== 'verified')) process.exitCode = EXIT.review
    })

  pluginsCommand.command('history')
    .requiredOption('--profile <name>', 'target DSH profile')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { profile: string; json?: boolean }) => {
      const managed = await services.loadOrImportManagedProfile(options.profile, services.statePaths())
      if (!managed) throw new Error(`No managed lifecycle state exists for profile ${options.profile}`)
      if (options.json) services.log(JSON.stringify(managed, null, 2))
      else {
        services.log(`Profile ${managed.profile} — current ${managed.currentGenerationId}`)
        ;[...managed.generations].reverse().forEach((generation) => {
          printGeneration(generation, generation.id === managed.currentGenerationId, services.log)
        })
      }
    })

  pluginsCommand.command('update')
    .argument('<report-id>', 'approved scan report for an already managed package')
    .action(async (reportId: string) => {
      const record = await services.updateApproved(reportId, services.statePaths())
      services.log(`已更新 ${record.packageName}@${record.version}，profile ${record.profile} 已生成新的受管 generation。`)
      services.log('请手动重启 DSH GUI 使新版本生效。')
    })

  pluginsCommand.command('uninstall')
    .argument('<package>', 'exact managed package name')
    .requiredOption('--profile <name>', 'target DSH profile')
    .requiredOption('--confirm <package>', 'must exactly repeat the package name')
    .option('--json', 'print machine-readable JSON')
    .action(async (packageName: string, options: { profile: string; confirm: string; json?: boolean }) => {
      const result = await services.uninstallManagedPlugin(packageName, options.profile, options.confirm, services.statePaths())
      if (options.json) services.log(JSON.stringify(result, null, 2))
      else {
        services.log(`已从 profile ${result.profile} 卸载 ${result.packageName}。`)
        services.log(`新 generation: ${result.generationId}`)
        if (result.backupPath) services.log(`操作前备份: ${result.backupPath}`)
      }
    })

  pluginsCommand.command('repair')
    .requiredOption('--profile <name>', 'target DSH profile')
    .requiredOption('--confirm <profile>', 'must exactly repeat the profile name')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { profile: string; confirm: string; json?: boolean }) => {
      const result = await services.repairManagedProfile(options.profile, options.confirm, services.statePaths())
      if (options.json) services.log(JSON.stringify(result, null, 2))
      else if (result.noOp) services.log(`Profile ${result.profile} 已经与 current generation 一致，无需修复。`)
      else {
        services.log(`已修复 profile ${result.profile}，新 generation: ${result.generationId}`)
        if (result.backupPath) services.log(`修复前备份: ${result.backupPath}`)
      }
    })

  pluginsCommand.command('rollback')
    .requiredOption('--profile <name>', 'target DSH profile')
    .requiredOption('--to <generation-id>', 'exact historical generation id')
    .requiredOption('--confirm <generation-id>', 'must exactly repeat the generation id')
    .option('--allow-drift', 'preserve and replace a reviewed drifted profile')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { profile: string; to: string; confirm: string; allowDrift?: boolean; json?: boolean }) => {
      const result = await services.rollbackManagedProfile(
        options.profile,
        options.to,
        options.confirm,
        services.statePaths(),
        options.allowDrift ? { allowDrift: true } : {},
      )
      if (options.json) services.log(JSON.stringify(result, null, 2))
      else {
        services.log(`已将 profile ${result.profile} 回滚到 ${result.restoredGenerationId}。`)
        services.log(`新 generation: ${result.generationId}`)
        if (result.backupPath) services.log(`回滚前备份: ${result.backupPath}`)
      }
    })

  program.command('start')
    .description('verify a managed profile and launch DSH only when it is trusted')
    .requiredOption('--profile <name>', 'target DSH profile')
    .option('--cwd <path>', 'working directory for the DSH process')
    .argument('[dsh-args...]', 'DSH application arguments; put them after --')
    .action(async (appArgs: string[], options: StartCliOptions) => {
      services.validateGuardedDshArgs(appArgs)
      const paths = services.statePaths()
      await services.initState(paths)
      const dsh = await services.locateDshBin()
      if (!dsh) throw new Error('DSH executable not found; set DSH_BIN to the exact rc.7 lib/bin.js path')
      const dshHome = services.dshHomePath(services.environment.DSH_HOME)
      const verification = await services.verifyProfile(options.profile, paths, dshHome)
      const status = await services.buildStatusSnapshot(paths, verification)
      await services.writeStatusFile(paths, status)
      if (verification.status !== 'verified') {
        await services.appendAudit(paths, 'guarded-start-deny', {
          profile: options.profile,
          status: verification.status,
          profileFingerprint: verification.profile.fingerprint,
          unmanagedBundles: verification.unmanagedBundles,
        })
        services.error(`DSH 启动已隔离：profile ${options.profile} 为 ${verification.status}。${verification.detail}`)
        if (verification.unmanagedBundles.length) {
          services.error(`未纳管 bundles: ${verification.unmanagedBundles.join(', ')}`)
        }
        services.error(`先运行 dsh-guard verify --profile ${options.profile}；确认后使用 plugins repair，或重新执行 scan/approve/install。`)
        process.exitCode = verification.status === 'needs-repair' ? EXIT.repair : EXIT.review
        return
      }

      const finalSnapshot = await services.snapshotProfile(options.profile, dshHome)
      if (finalSnapshot.fingerprint !== verification.profile.fingerprint) {
        const changed = await services.verifyProfile(options.profile, paths, dshHome)
        await services.writeStatusFile(paths, await services.buildStatusSnapshot(paths, changed))
        await services.appendAudit(paths, 'guarded-start-deny', {
          profile: options.profile,
          status: 'changed-after-verification',
          verifiedFingerprint: verification.profile.fingerprint,
          currentFingerprint: finalSnapshot.fingerprint,
        })
        services.error(`DSH 启动已隔离：profile ${options.profile} 在验证后又发生变化，请重新验证。`)
        process.exitCode = EXIT.review
        return
      }

      const environment = services.buildGuardedDshEnvironment(services.environment, {
        dshHome,
        guardHome: paths.root,
      })
      await services.appendAudit(paths, 'guarded-start-allow', {
        profile: options.profile,
        generationId: verification.generationId,
        profileFingerprint: verification.profile.fingerprint,
        argumentCount: appArgs.length,
        argumentDigest: services.sha256(services.stableJson(appArgs)),
      })
      services.log(`Guarded Launch：profile ${options.profile} 已验证，正在启动 DSH。`)
      try {
        const code = await services.runGuardedDsh(dsh, options.profile, appArgs, environment, {
          cwd: options.cwd ?? services.cwd,
        })
        await services.appendAudit(paths, 'guarded-start-exit', { profile: options.profile, code })
        if (code !== 0) process.exitCode = code
      } catch (error) {
        await services.appendAudit(paths, 'guarded-start-failed', {
          profile: options.profile,
          error: sanitizeText((error as Error).message),
        }).catch(() => undefined)
        throw error
      }
    })

  const sandboxCommand = program.command('sandbox')
    .description('plan or run the experimental whole-process macOS sandbox')

  const addSandboxOptions = (command: Command, includeJson: boolean): Command => {
    command
      .requiredOption('--profile <name>', 'target DSH profile (run requires verified state)')
      .option('--workspace <path>', 'read/write workspace root; repeat for more roots', collectOption, [])
      .option('--network <mode>', 'deny, loopback, or unrestricted', 'loopback')
      .option('--allow-env <name>', 'pass one named environment variable; repeat as needed', collectOption, [])
    if (includeJson) command.option('--json', 'print machine-readable SandboxPlanV1 JSON')
    return command
  }

  const preparePlan = async (
    options: SandboxCliOptions,
    paths: ReturnType<typeof statePaths>,
    sourceDshHome: string,
    dshBin: string,
  ): Promise<{ plan: SandboxPlanV1; runtime: SandboxRuntimeV1 }> => {
    if (options.workspace.length === 0) throw new Error('At least one --workspace is required')
    const runtime = await services.prepareSandboxRuntime(options.profile, sourceDshHome, paths.root)
    try {
      const plan = await services.createSandboxPlan({
        profile: options.profile,
        workspaceRoots: options.workspace,
        network: sandboxNetwork(options.network),
        allowEnvironment: options.allowEnv,
        environment: services.environment,
        nodePath: services.nodePath,
        platform: services.platform,
        dshBin,
        sourceDshHome,
        dshHome: runtime.dshHome,
        guardHome: paths.root,
        tempRoot: runtime.tempRoot,
      })
      return { plan, runtime }
    } catch (error) {
      await services.cleanupSandboxRuntime(runtime.root, paths.root)
      throw error
    }
  }

  addSandboxOptions(sandboxCommand.command('plan')
    .description('compile and inspect a sandbox plan without launching DSH'), true)
    .action(async (options: SandboxCliOptions) => {
      const paths = services.statePaths()
      await services.initState(paths)
      const dshBin = sandboxDshBin(await services.locateDshBin())
      const sourceDshHome = services.dshHomePath(services.environment.DSH_HOME)
      const { plan, runtime } = await preparePlan(options, paths, sourceDshHome, dshBin)
      try {
        if (options.json) services.log(JSON.stringify(plan, null, 2))
        else printSandboxPlan(plan, services.log)
      } finally {
        await services.cleanupSandboxRuntime(runtime.root, paths.root)
      }
    })

  addSandboxOptions(sandboxCommand.command('run')
    .description('verify the profile and launch DSH inside the compiled sandbox')
    .argument('[dsh-args...]', 'DSH application arguments; put them after --'), false)
    .action(async (appArgs: string[], options: SandboxCliOptions) => {
      services.validateSandboxAppArgs(appArgs)
      if (options.workspace.length === 0) throw new Error('At least one --workspace is required')
      const paths = services.statePaths()
      await services.initState(paths)
      const dshBin = sandboxDshBin(await services.locateDshBin())
      const sourceDshHome = services.dshHomePath(services.environment.DSH_HOME)
      const verification = await services.verifyProfile(options.profile, paths, sourceDshHome)
      if (verification.status !== 'verified') {
        throw new Error(`Refusing sandbox run: profile ${options.profile} is ${verification.status}. ${verification.detail}`)
      }
      const { plan, runtime } = await preparePlan(options, paths, sourceDshHome, dshBin)
      try {
        const runtimeSnapshot = await services.snapshotProfile(plan.profile, runtime.dshHome)
        if (runtimeSnapshot.fingerprint !== verification.profile.fingerprint) {
          throw new Error('Disposable sandbox profile does not match the verified source profile')
        }
        const environment = services.buildSandboxEnvironment(plan, services.environment)
        const planDigest = services.sandboxPlanDigest(plan)
        await services.appendAudit(paths, 'sandbox-run', {
          planId: plan.id,
          planDigest,
          policyHash: plan.policyHash,
          profile: plan.profile,
          sourceProfileFingerprint: verification.profile.fingerprint,
          network: plan.network,
          workspaceDigest: services.sha256(services.stableJson(plan.workspaceRoots)),
          allowedEnvironmentNames: plan.allowedEnvironmentNames,
        })
        services.log(`Launching verified profile ${plan.profile} from a disposable copy with sandbox policy sha256:${plan.policyHash}`)
        plan.warnings.forEach((warning) => services.log(`Warning: ${warning}`))
        const code = await services.runSandboxedDsh(plan, appArgs, environment, { platform: services.platform })
        if (code !== 0) process.exitCode = code
      } finally {
        await services.cleanupSandboxRuntime(runtime.root, paths.root)
      }
    })

  program.command('verify')
    .requiredOption('--profile <name>', 'target DSH profile')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { profile: string; json?: boolean }) => {
      const paths = services.statePaths()
      const result = await services.verifyProfile(options.profile, paths)
      const snapshot = await services.buildStatusSnapshot(paths, result)
      await services.writeStatusFile(paths, snapshot)
      if (options.json) services.log(JSON.stringify(snapshot, null, 2))
      else {
        services.log(`${snapshot.label}: ${snapshot.detail}`)
        if (result.unmanagedBundles.length) services.log(`未纳管 bundles: ${result.unmanagedBundles.join(', ')}`)
      }
      process.exitCode = result.status === 'verified' ? EXIT.ok : result.status === 'needs-repair' ? EXIT.repair : EXIT.review
    })

  program.command('doctor')
    .description('check local runtime and state prerequisites')
    .action(async () => {
      const paths = services.statePaths()
      await services.initState(paths)
      const dsh = await services.locateDshBin()
      const mode = (await services.statMode(paths.root)) & 0o777
      const actionState = await services.inspectActionStore(services.actionStorePaths(paths.root))
      const lifecycleState = await services.inspectLifecycleState(paths)
      const checks = [
        { name: 'Node.js >=22.22.0 (DSH rc.7 runtime)', ok: supportsDshNode(services.nodeVersion), detail: `v${services.nodeVersion.replace(/^v/, '')}` },
        { name: 'DSH executable', ok: Boolean(dsh), detail: dsh ? `${dsh.command} ${dsh.prefix.join(' ')}` : 'set DSH_BIN' },
        { name: 'State directory mode', ok: mode === 0o700, detail: mode.toString(8) },
        { name: 'Action state', ok: actionState.ok, detail: actionState.ok ? `${actionState.grants} grant(s), ${actionState.events} event(s)` : actionState.issues.join('; ') },
        { name: 'Plugin lifecycle state', ok: lifecycleState.ok, detail: lifecycleState.ok ? `${lifecycleState.profiles} profile(s), ${lifecycleState.generations} generation(s)` : lifecycleState.issues.join('; ') },
      ]
      checks.forEach((check) => services.log(`${check.ok ? '✓' : '×'} ${check.name}: ${check.detail}`))
      if (checks.some((check) => !check.ok)) process.exitCode = EXIT.runtime
    })

  const policyCommand = program.command('policy')
    .description('inspect and simulate the local Action Gate policy')

  policyCommand.command('show')
    .description('show the default or supplied Action Gate policy')
    .option('--policy <file>', 'JSON ActionPolicyV1 file')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { policy?: string; json?: boolean }) => {
      const policy = await loadActionPolicy(services, options.policy)
      if (options.json) {
        services.log(JSON.stringify({ schemaVersion: 1, policyHash: actionPolicyHash(policy), policy }, null, 2))
      } else {
        printActionPolicy(policy, services.log)
      }
    })

  policyCommand.command('check')
    .description('evaluate an ActionRequestV1 fixture without executing a tool')
    .argument('<request-file>', 'JSON ActionRequestV1 file, or - for stdin')
    .option('--policy <file>', 'JSON ActionPolicyV1 file')
    .option('--json', 'print machine-readable ActionDecisionV1 JSON')
    .action(async (requestFile: string, options: { policy?: string; json?: boolean }) => {
      const [policy, request] = await Promise.all([
        loadActionPolicy(services, options.policy),
        loadActionRequest(services, requestFile),
      ])
      const decision = evaluateAction(request, policy)
      if (options.json) services.log(JSON.stringify(decision, null, 2))
      else printActionDecision(request, decision, services.log)
      process.exitCode = actionDecisionExit(decision)
    })

  const eventsCommand = program.command('events')
    .description('inspect redacted Action Gate events')

  eventsCommand.command('list')
    .option('--limit <count>', 'maximum recent events', '50')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { limit: string; json?: boolean }) => {
      const limit = Number(options.limit)
      if (!Number.isInteger(limit) || limit < 1 || limit > 10_000) throw new Error('Event limit must be an integer between 1 and 10000')
      const result = await services.readActionEvents(services.actionStorePaths(services.statePaths().root), { limit })
      if (options.json) services.log(JSON.stringify({ schemaVersion: 1, ...result }, null, 2))
      else {
        result.events.forEach((event) => printActionEvent(event, services.log))
        if (result.events.length === 0) services.log('No Action Gate events found.')
        if (result.invalidLines > 0) services.log(`Warning: ${result.invalidLines} invalid event line(s) were ignored.`)
      }
      if (result.invalidLines > 0) process.exitCode = EXIT.review
    })

  const grantsCommand = program.command('grants')
    .description('inspect and revoke scoped Action Gate grants')

  grantsCommand.command('list')
    .option('--json', 'print machine-readable JSON')
    .action(async (options: { json?: boolean }) => {
      const store = await services.loadActionGrantStore(services.actionStorePaths(services.statePaths().root))
      const now = Date.now()
      const grants = store.grants.filter((grant) => Date.parse(grant.expiresAt) > now)
      if (options.json) services.log(JSON.stringify({ schemaVersion: 1, updatedAt: store.updatedAt, grants }, null, 2))
      else {
        grants.forEach((grant) => printActionGrant(grant, services.log))
        if (grants.length === 0) services.log('No active Action Gate grants found.')
      }
    })

  grantsCommand.command('revoke')
    .argument('<grant-id>', 'exact grant id')
    .action(async (grantId: string) => {
      const paths = services.actionStorePaths(services.statePaths().root)
      const before = await services.loadActionGrantStore(paths)
      if (!before.grants.some((grant) => grant.id === grantId)) throw new Error(`Action grant not found: ${grantId}`)
      await services.revokeActionGrantFromStore(paths, grantId)
      services.log(`Revoked Action Gate grant ${grantId}.`)
    })

  grantsCommand.command('revoke-all')
    .action(async () => {
      const store = await services.revokeAllActionGrants(services.actionStorePaths(services.statePaths().root))
      services.log(`Revoked all Action Gate grants (${store.grants.length} remain).`)
    })

  return program
}

export async function runCli(argv = process.argv, overrides: Partial<CliServices> = {}): Promise<void> {
  const services: CliServices = { ...defaultServices, ...overrides }
  try {
    await createProgram(services).parseAsync(argv)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    services.error(`dsh-guard: ${message}`)
    process.exitCode = /needs-repair|could not restore/i.test(message) ? EXIT.repair : EXIT.runtime
  }
}
