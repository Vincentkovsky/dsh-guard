import { spawn } from 'node:child_process'
import { appendFile, cp, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const runtime = process.env.DSH_BIN
if (!runtime) throw new Error('Set DSH_BIN to the target DSH lib/bin.js before running the E2E test')
const dshNode = process.env.DSH_NODE ?? process.execPath

const workspace = resolve(import.meta.dirname, '..')
const sourceProfile = process.env.DSH_E2E_SOURCE_PROFILE ?? join(homedir(), '.dsh', 'profiles', 'web')
const dshHome = await mkdtemp(join(homedir(), '.dsh-guard-e2e-home-'))
const stateHome = await mkdtemp(join(tmpdir(), 'dsh-guard-e2e-state-'))
const profileName = 'guard-e2e'
const targetProfile = join(dshHome, 'profiles', profileName)
const cli = join(workspace, 'packages', 'cli', 'lib', 'bin.js')
const environment = { ...process.env, DSH_BIN: runtime, DSH_HOME: dshHome, DSH_GUARD_HOME: stateHome, DSH_GUARD_PROFILE: profileName }

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
    if (process.env.DSH_E2E_HOLD === '1') {
      process.stdout.write(`DSH_E2E_URL=${url}\n`)
      await new Promise((resolvePromise) => {
        process.once('SIGINT', resolvePromise)
        process.once('SIGTERM', resolvePromise)
      })
    }
    return true
  } finally {
    if (child.exitCode === null) {
      child.kill('SIGTERM')
      await new Promise((resolvePromise) => child.once('close', resolvePromise))
    }
  }
}

try {
  await mkdir(targetProfile, { recursive: true })
  for (const name of ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'cordis.yml', 'cordis.patch.yml']) {
    await cp(join(sourceProfile, name), join(targetProfile, name))
  }
  const scan = await invoke(['scan', 'packages/dsh-plugin', '--profile', profileName, '--json'], [2])
  const report = JSON.parse(scan.stdout)
  if (report.verdict !== 'review' || report.stage?.compatible !== true) throw new Error(`Unexpected scan outcome: ${scan.stdout}`)
  await invoke(['approve', report.id])
  await invoke(['install', report.id])
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
  const verify = await invoke(['verify', '--profile', profileName, '--json'])
  const status = JSON.parse(verify.stdout)
  const manifest = JSON.parse(await readFile(join(targetProfile, 'package.json'), 'utf8'))
  if (status.status !== 'verified' || !manifest.dsh.profile.bundles.includes('@dsh-guard/companion')) throw new Error('Install/verify invariant failed')
  process.stdout.write(`${JSON.stringify({ report: report.id, verdict: report.verdict, staged: true, installed: true, hostApi, verified: status.status, profile: profileName }, null, 2)}\n`)
} finally {
  if (dshHome.startsWith(`${homedir()}/.dsh-guard-e2e-home-`)) await rm(dshHome, { recursive: true, force: true })
  if (stateHome.startsWith(join(tmpdir(), 'dsh-guard-e2e-state-'))) await rm(stateHome, { recursive: true, force: true })
}
