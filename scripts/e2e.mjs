import { spawn } from 'node:child_process'
import { appendFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  actionStorePaths,
  addActionGrant,
  appendActionEvent,
  createActionEvent,
  createActionGrant,
  createActionRequest,
  createDefaultActionPolicy,
  evaluateAction,
  loadActionGrantStore,
  normalizePathResource,
} from '../packages/core/lib/action/index.js'

const runtime = process.env.DSH_BIN
if (!runtime) throw new Error('Set DSH_BIN to the target DSH lib/bin.js before running the E2E test')
const dshNode = process.env.DSH_NODE ?? process.execPath

const workspace = resolve(import.meta.dirname, '..')
const sourceProfile = process.env.DSH_E2E_SOURCE_PROFILE ?? join(homedir(), '.dsh', 'profiles', 'web')
const dshHome = await mkdtemp(join(homedir(), '.dsh-guard-e2e-home-'))
const stateHome = await mkdtemp(join(tmpdir(), 'dsh-guard-e2e-state-'))
const updateSource = await mkdtemp(join(tmpdir(), 'dsh-guard-e2e-update-'))
const secondSource = await mkdtemp(join(tmpdir(), 'dsh-guard-e2e-second-'))
const profileName = 'guard-e2e'
const targetProfile = join(dshHome, 'profiles', profileName)
const cli = join(workspace, 'packages', 'cli', 'lib', 'bin.js')
const environment = { ...process.env, DSH_BIN: runtime, DSH_HOME: dshHome, DSH_GUARD_HOME: stateHome, DSH_GUARD_PROFILE: profileName }
const tokenShapedFixture = ['ghp', 'abcdefghijklmnopqrstuvwxyz123456'].join('_')

function invoke(args, accepted = [0]) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { cwd: workspace, env: environment, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdout = []
    const stderr = []
    child.stdout.on('data', (chunk) => stdout.push(chunk))
    child.stderr.on('data', (chunk) => stderr.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => {
      const result = { code: code ?? 1, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }
      if (!accepted.includes(result.code)) reject(new Error(`dsh-guard ${args[0]} exited ${result.code}: ${result.stderr || result.stdout}`))
      else resolvePromise(result)
    })
  })
}

function invokeDsh(args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(dshNode, [runtime, ...args], { cwd: workspace, env: environment, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdout = []
    const stderr = []
    child.stdout.on('data', (chunk) => stdout.push(chunk))
    child.stderr.on('data', (chunk) => stderr.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => {
      const output = `${Buffer.concat(stdout).toString('utf8')}${Buffer.concat(stderr).toString('utf8')}`
      if ((code ?? 1) !== 0) reject(new Error(`dsh exited ${code}: ${output}`))
      else resolvePromise(output)
    })
  })
}

async function probeCompanionHost() {
  const child = spawn(dshNode, [runtime, '--profile', profileName, '--host', '127.0.0.1', '--port', '0'], {
    cwd: workspace,
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = ''
  let settled = false
  try {
    const url = await new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => reject(new Error(`Timed out waiting for DSH web boot: ${output}`)), 15_000)
      const consume = (chunk) => {
        output += chunk.toString('utf8')
        const match = output.match(/https?:\/\/(?:127\.0\.0\.1|localhost):\d+/)
        if (match && !settled) { settled = true; clearTimeout(timer); resolvePromise(match[0]) }
      }
      child.stdout.on('data', consume)
      child.stderr.on('data', consume)
      child.on('error', (error) => { clearTimeout(timer); reject(error) })
      child.on('close', (code) => { if (!settled) { clearTimeout(timer); reject(new Error(`DSH web exited ${code}: ${output}`)) } })
    })
    const response = await fetch(`${url}/dsh-guard/api/status`, { headers: { host: new URL(url).host } })
    if (!response.ok) throw new Error(`Companion Host API returned ${response.status}: ${await response.text()}`)
    const status = await response.json()
    if (status.schemaVersion !== 1 || status.profile !== profileName) throw new Error('Companion Host API returned an invalid status document')
    const managedNames = status.managedPackages?.map((plugin) => plugin.name).sort()
    if (JSON.stringify(managedNames) !== JSON.stringify(['@dsh-guard/companion', 'dsh-guard-e2e-second'])) throw new Error('Companion Host API did not expose every managed plugin')
    if (status.action?.enabled !== false || status.action?.coverage !== 'dsh-tool-registry-only') throw new Error('Companion Host API did not report Agent action protection as disabled by default')
    if (status.action.events.length !== 1 || status.action.events[0]?.sessionId !== 'session-e2e') throw new Error('Companion Host API did not expose the scoped action event')
    if (status.action.grants.length !== 1 || status.action.grants[0]?.id !== 'agrant_e2e') throw new Error('Companion Host API did not filter grants to the active profile')
    if (JSON.stringify(status).includes(tokenShapedFixture)) throw new Error('Companion Host API leaked action arguments')

    const wrongOrigin = new URL(url)
    wrongOrigin.port = wrongOrigin.port === '1' ? '2' : '1'
    const rejectedRevoke = await fetch(`${url}/dsh-guard/api/grants/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: wrongOrigin.origin },
      body: JSON.stringify({ grantId: 'agrant_e2e' }),
    })
    if (rejectedRevoke.status !== 403) throw new Error(`Cross-origin grant revoke returned ${rejectedRevoke.status}, expected 403`)
    const revoke = await fetch(`${url}/dsh-guard/api/grants/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: new URL(url).origin },
      body: JSON.stringify({ grantId: 'agrant_e2e' }),
    })
    if (!revoke.ok) throw new Error(`Same-origin grant revoke returned ${revoke.status}: ${await revoke.text()}`)
    const afterRevoke = await fetch(`${url}/dsh-guard/api/status`)
    const updated = await afterRevoke.json()
    if (updated.action?.grants.length !== 0) throw new Error('Revoked grant remained visible in Companion Host status')
    if (process.env.DSH_E2E_HOLD === '1') {
      process.stdout.write(`DSH_E2E_URL=${url}\n`)
      await new Promise((resolvePromise) => {
        process.once('SIGINT', resolvePromise)
        process.once('SIGTERM', resolvePromise)
      })
    }
    return { status: true, managedPlugins: true, agentProtectionDefaultOff: true, actionHistory: true, scopedGrants: true, sameOriginRevoke: true }
  } finally {
    if (child.exitCode === null) {
      child.kill('SIGTERM')
      await new Promise((resolvePromise) => child.once('close', resolvePromise))
    }
  }
}

async function seedActionState() {
  const paths = actionStorePaths(stateHome)
  const policy = createDefaultActionPolicy([targetProfile])
  const now = new Date()
  const request = createActionRequest({
    id: 'act_e2e',
    now,
    profile: profileName,
    sessionId: 'session-e2e',
    toolName: 'read',
    operation: 'read',
    arguments: { file_path: '.env', token: tokenShapedFixture },
    resources: [normalizePathResource('.env', 'read', policy, targetProfile)],
  })
  const decision = evaluateAction(request, policy)
  await appendActionEvent(paths, createActionEvent(request, decision, 'denied', { id: 'aevt_e2e', now }))
  await addActionGrant(paths, createActionGrant(request, 'once', policy, { id: 'agrant_e2e', now, ttlMs: 10 * 60_000 }), now)

  const other = createActionRequest({ ...request, id: 'act_other_profile', profile: 'other-profile', sessionId: 'session-other' })
  await addActionGrant(paths, createActionGrant(other, 'once', policy, { id: 'agrant_other_profile', now, ttlMs: 10 * 60_000 }), now)
}

try {
  await mkdir(targetProfile, { recursive: true })
  for (const name of ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'cordis.yml', 'cordis.patch.yml']) {
    await cp(join(sourceProfile, name), join(targetProfile, name))
  }
  await invokeDsh(['plugin', '--profile', profileName, 'install', '--ignore-scripts', '--frozen-lockfile'])
  const modulesBefore = await readFile(join(targetProfile, 'node_modules', '.modules.yaml'), 'utf8')
  if (modulesBefore.includes(join(stateHome, 'cache', 'pnpm-store'))) throw new Error('E2E baseline did not use a foreign pnpm store')
  const scan = await invoke(['scan', 'packages/dsh-plugin', '--profile', profileName, '--json'], [2])
  const report = JSON.parse(scan.stdout)
  if (report.verdict !== 'review' || report.stage?.compatible !== true) throw new Error(`Unexpected scan outcome: ${scan.stdout}`)
  await invoke(['approve', report.id])
  await invoke(['install', report.id])
  const modulesAfter = await readFile(join(targetProfile, 'node_modules', '.modules.yaml'), 'utf8')
  if (!modulesAfter.includes(join(stateHome, 'cache', 'pnpm-store'))) throw new Error('Guard install did not migrate node_modules to the private store')
  const initialList = JSON.parse((await invoke(['plugins', 'list', '--profile', profileName, '--json'])).stdout)
  const initialPlugins = initialList.profiles?.[0]?.plugins
  const initialPlugin = initialPlugins?.find((plugin) => plugin.packageName === '@dsh-guard/companion')
  if (initialPlugins?.length !== 1 || !initialPlugin) {
    throw new Error('Lifecycle inventory did not record the initial managed plugin')
  }
  const initialHistory = JSON.parse((await invoke(['plugins', 'history', '--profile', profileName, '--json'])).stdout)
  const initialGeneration = initialHistory.currentGenerationId

  await mkdir(join(secondSource, 'lib'), { recursive: true })
  await writeFile(join(secondSource, 'package.json'), `${JSON.stringify({
    name: 'dsh-guard-e2e-second',
    version: '1.0.0',
    type: 'module',
    main: './lib/index.js',
    files: ['lib/index.js', 'cordis.patch.yml'],
    dsh: { bundle: { patch: './cordis.patch.yml' } },
  }, null, 2)}\n`)
  await writeFile(join(secondSource, 'lib', 'index.js'), "export const name = 'dsh-guard-e2e-second'\nexport function apply() {}\n")
  await writeFile(join(secondSource, 'cordis.patch.yml'), "- id: dsh-guard-e2e-second\n  name: dsh-guard-e2e-second\n")
  const secondScan = JSON.parse((await invoke(['scan', secondSource, '--profile', profileName, '--json'], [0, 2])).stdout)
  if (secondScan.stage?.compatible !== true) throw new Error('Second managed plugin did not produce a compatible proposal')
  await invoke(['approve', secondScan.id])
  await invoke(['install', secondScan.id])
  const multipleList = JSON.parse((await invoke(['plugins', 'list', '--profile', profileName, '--json'])).stdout)
  const multipleNames = multipleList.profiles?.[0]?.plugins?.map((plugin) => plugin.packageName).sort()
  if (JSON.stringify(multipleNames) !== JSON.stringify(['@dsh-guard/companion', 'dsh-guard-e2e-second'])) {
    throw new Error('Lifecycle inventory did not preserve two managed plugins')
  }
  await seedActionState()
  if (process.env.DSH_E2E_ALERT === '1') {
    const event = {
      schemaVersion: 1,
      id: 'evt_e2e_alert',
      createdAt: new Date().toISOString(),
      severity: 'high',
      type: 'protected-config-changed',
      fingerprint: 'e2e-protected-config-changed',
      title: '受保护配置发生变化',
      detail: '测试事件：credentials 行的配置指纹与受控基线不一致。',
      profile: profileName,
    }
    await appendFile(join(stateHome, 'events.jsonl'), `${JSON.stringify(event)}\n`, { mode: 0o600 })
  }
  const hostApi = await probeCompanionHost()
  const remainingGrants = (await loadActionGrantStore(actionStorePaths(stateHome))).grants
  if (remainingGrants.length !== 1 || remainingGrants[0]?.profile !== 'other-profile') throw new Error('Profile-scoped revoke changed an unrelated grant')
  const verify = await invoke(['verify', '--profile', profileName, '--json'])
  const status = JSON.parse(verify.stdout)
  const manifest = JSON.parse(await readFile(join(targetProfile, 'package.json'), 'utf8'))
  if (status.status !== 'verified' || !manifest.dsh.profile.bundles.includes('@dsh-guard/companion')) throw new Error('Install/verify invariant failed')

  await appendFile(join(targetProfile, 'cordis.patch.yml'), '\n# dsh-guard lifecycle e2e drift\n')
  const drifted = JSON.parse((await invoke(['verify', '--profile', profileName, '--json'], [2])).stdout)
  if (drifted.status !== 'drifted') throw new Error('Lifecycle E2E did not detect profile drift')
  const repaired = JSON.parse((await invoke(['plugins', 'repair', '--profile', profileName, '--confirm', profileName, '--json'])).stdout)
  if (repaired.action !== 'repair' || repaired.noOp !== false) throw new Error('Lifecycle repair did not create a recovery generation')
  const repairedVerify = JSON.parse((await invoke(['verify', '--profile', profileName, '--json'])).stdout)
  if (repairedVerify.status !== 'verified') throw new Error('Repaired profile did not verify')

  await cp(join(workspace, 'packages', 'dsh-plugin'), updateSource, { recursive: true })
  const updateManifestPath = join(updateSource, 'package.json')
  const updateManifest = JSON.parse(await readFile(updateManifestPath, 'utf8'))
  updateManifest.version = '0.4.1-e2e'
  await writeFile(updateManifestPath, `${JSON.stringify(updateManifest, null, 2)}\n`)
  const updateScan = JSON.parse((await invoke(['scan', updateSource, '--profile', profileName, '--json'], [2])).stdout)
  if (updateScan.stage?.compatible !== true || updateScan.source?.version !== '0.4.1-e2e') throw new Error('Lifecycle update scan did not produce a compatible proposal')
  await invoke(['approve', updateScan.id])
  const rejectedInstall = await invoke(['install', updateScan.id], [4])
  if (!rejectedInstall.stderr.includes('use plugins update')) throw new Error('Managed package reinstall did not require the explicit update command')
  await invoke(['plugins', 'update', updateScan.id])
  const updatedList = JSON.parse((await invoke(['plugins', 'list', '--profile', profileName, '--json'])).stdout)
  if (updatedList.profiles?.[0]?.plugins?.find((plugin) => plugin.packageName === '@dsh-guard/companion')?.version !== '0.4.1-e2e') throw new Error('Lifecycle update did not replace the managed plugin version')

  const uninstalled = JSON.parse((await invoke([
    'plugins', 'uninstall', '@dsh-guard/companion', '--profile', profileName, '--confirm', '@dsh-guard/companion', '--json',
  ])).stdout)
  if (uninstalled.action !== 'uninstall') throw new Error('Lifecycle uninstall did not complete')
  const emptyList = JSON.parse((await invoke(['plugins', 'list', '--profile', profileName, '--json'])).stdout)
  if (emptyList.profiles?.[0]?.plugins?.length !== 1 || emptyList.profiles[0].plugins[0]?.packageName !== 'dsh-guard-e2e-second') {
    throw new Error('Lifecycle uninstall did not preserve the unrelated managed plugin')
  }

  const rolledBack = JSON.parse((await invoke([
    'plugins', 'rollback', '--profile', profileName, '--to', initialGeneration, '--confirm', initialGeneration, '--json',
  ])).stdout)
  if (rolledBack.action !== 'rollback' || rolledBack.restoredGenerationId !== initialGeneration) throw new Error('Lifecycle rollback did not restore the requested generation')
  const rollbackList = JSON.parse((await invoke(['plugins', 'list', '--profile', profileName, '--json'])).stdout)
  const rolledBackPlugin = rollbackList.profiles?.[0]?.plugins?.find((plugin) => plugin.packageName === '@dsh-guard/companion')
  if (rolledBackPlugin?.version !== initialPlugin.version) {
    throw new Error(`Lifecycle rollback restored ${rolledBackPlugin?.version ?? 'no managed version'}, expected ${initialPlugin.version}`)
  }
  const rollbackVerify = JSON.parse((await invoke(['verify', '--profile', profileName, '--json'])).stdout)
  if (rollbackVerify.status !== 'verified') throw new Error('Rolled back profile did not verify')

  let sandbox = { skipped: true, reason: 'macOS only' }
  if (process.platform === 'darwin') {
    const planned = JSON.parse((await invoke([
      'sandbox', 'plan', '--profile', profileName, '--workspace', workspace, '--network', 'deny', '--json',
    ])).stdout)
    if (planned.schemaVersion !== 1 || planned.profile !== profileName || planned.network !== 'deny') {
      throw new Error('Sandbox plan did not preserve the requested profile and network mode')
    }
    if (JSON.stringify(planned).includes(tokenShapedFixture)) {
      throw new Error('Sandbox plan leaked an action argument or environment value')
    }
    const sandboxedDump = await invoke([
      'sandbox', 'run', '--profile', profileName, '--workspace', workspace, '--network', 'deny', '--', '--dump-config',
    ])
    const launchedPolicyHash = sandboxedDump.stdout.match(/sandbox policy sha256:([a-f0-9]{64})/)?.[1]
    if (!launchedPolicyHash) {
      throw new Error('Sandbox run did not launch the compiled policy')
    }
    const auditLines = (await readFile(join(stateHome, 'audit.jsonl'), 'utf8')).trim().split(/\r?\n/)
    const sandboxAudit = JSON.parse(auditLines.at(-1))
    if (sandboxAudit.action !== 'sandbox-run' || sandboxAudit.profile !== profileName || sandboxAudit.policyHash !== launchedPolicyHash) {
      throw new Error('Sandbox run did not append the expected redacted audit record')
    }
    if (JSON.stringify(sandboxAudit).includes(tokenShapedFixture)) {
      throw new Error('Sandbox audit leaked an action argument or environment value')
    }
    sandbox = { planned: true, dumpConfig: true, audited: true, network: planned.network }
  }

  process.stdout.write(`${JSON.stringify({
    report: report.id,
    verdict: report.verdict,
    staged: true,
    installed: true,
    foreignStoreMigration: true,
    hostApi,
    verified: status.status,
    profile: profileName,
    lifecycle: {
      listed: true,
      multiplePlugins: multipleNames.length === 2,
      driftDetected: drifted.status === 'drifted',
      repaired: repaired.action === 'repair',
      updatedTo: updatedList.profiles[0].plugins[0].version,
      uninstalled: uninstalled.action === 'uninstall',
      rolledBackTo: rollbackList.profiles[0].plugins[0].version,
    },
    sandbox,
  }, null, 2)}\n`)
} finally {
  if (dshHome.startsWith(`${homedir()}/.dsh-guard-e2e-home-`)) await rm(dshHome, { recursive: true, force: true })
  if (stateHome.startsWith(join(tmpdir(), 'dsh-guard-e2e-state-'))) await rm(stateHome, { recursive: true, force: true })
  if (updateSource.startsWith(join(tmpdir(), 'dsh-guard-e2e-update-'))) await rm(updateSource, { recursive: true, force: true })
  if (secondSource.startsWith(join(tmpdir(), 'dsh-guard-e2e-second-'))) await rm(secondSource, { recursive: true, force: true })
}
