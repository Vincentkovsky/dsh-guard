import { spawn } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import net from 'node:net'
import { dirname, join } from 'node:path'
import { buildSandboxEnvironment, createSandboxPlan } from '../packages/core/lib/index.js'

if (process.platform !== 'darwin') {
  process.stdout.write(`${JSON.stringify({ skipped: true, reason: 'macOS sandbox-exec is unavailable' })}\n`)
  process.exit(0)
}

const root = await mkdtemp(join(tmpdir(), 'dsh-guard-sandbox-probe-'))
const sourceDshHome = join(root, 'source-dsh-home')
const guardHome = join(root, 'guard-home')
const dshHome = join(guardHome, 'sandbox-runs', 'run-probe', 'dsh-home')
const tempRoot = join(dshHome, 'tmp')
const workspace = join(root, 'workspace')
const outside = join(root, 'outside-secret.txt')
const dshBin = join(root, 'runtime', 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const workspaceRead = join(workspace, 'readable.txt')
const workspaceWrite = join(workspace, 'writable.txt')
const loopbackServer = net.createServer((socket) => {
  socket.on('error', () => undefined)
  socket.end('ok')
})
await new Promise((resolvePromise, reject) => {
  loopbackServer.once('error', reject)
  loopbackServer.listen(0, '127.0.0.1', resolvePromise)
})
const loopbackPort = loopbackServer.address().port

function execute(plan, environment) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn('/usr/bin/sandbox-exec', [
      '-p', plan.policy, plan.nodePath, plan.dshBin, '--profile', plan.profile,
    ], { cwd: workspace, env: environment, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdout = []
    const stderr = []
    child.stdout.on('data', (chunk) => stdout.push(chunk))
    child.stderr.on('data', (chunk) => stderr.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => resolvePromise({
      code: code ?? 1,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8'),
    }))
  })
}

try {
  await Promise.all([
    mkdir(join(dshHome, 'profiles', 'web'), { recursive: true }),
    mkdir(join(sourceDshHome, 'profiles', 'web'), { recursive: true }),
    mkdir(tempRoot, { recursive: true }),
    mkdir(workspace, { recursive: true }),
    mkdir(dirname(dshBin), { recursive: true }),
  ])
  await Promise.all([
    writeFile(workspaceRead, 'workspace-readable\n'),
    writeFile(outside, 'must-stay-private\n'),
  ])
  const probeSource = `
import { readFile, writeFile } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import net from 'node:net'

const result = {}
try { result.workspaceRead = (await readFile(${JSON.stringify(workspaceRead)}, 'utf8')).trim() === 'workspace-readable' ? 'allowed' : 'wrong-content' }
catch (error) { result.workspaceRead = error.code ?? error.message }
try { await writeFile(${JSON.stringify(workspaceWrite)}, 'sandbox-write\\n'); result.workspaceWrite = 'allowed' }
catch (error) { result.workspaceWrite = error.code ?? error.message }
try { await readFile(${JSON.stringify(outside)}, 'utf8'); result.outsideRead = 'ALLOWED' }
catch (error) { result.outsideRead = error.code ?? error.message }

result.childProcess = await new Promise((resolve) => {
  let settled = false
  const finish = (value) => { if (!settled) { settled = true; resolve(value) } }
  try {
    const child = spawn('/usr/bin/true')
    child.on('error', (error) => finish(error.code ?? error.message))
    child.on('close', () => finish('ALLOWED'))
  } catch (error) { finish(error.code ?? error.message) }
})

result.publicNetwork = await new Promise((resolve) => {
  let settled = false
  const finish = (value) => { if (!settled) { settled = true; socket.destroy(); resolve(value) } }
  const socket = net.connect({ host: '1.1.1.1', port: 443 })
  socket.on('connect', () => finish('ALLOWED'))
  socket.on('error', (error) => finish(error.code ?? error.message))
  setTimeout(() => finish('TIMEOUT'), 2000)
})
result.loopbackNetwork = await new Promise((resolve) => {
  let settled = false
  const finish = (value) => { if (!settled) { settled = true; socket.destroy(); resolve(value) } }
  const socket = net.connect({ host: '127.0.0.1', port: ${loopbackPort} })
  socket.on('connect', () => finish('allowed'))
  socket.on('error', (error) => finish(error.code ?? error.message))
  setTimeout(() => finish('TIMEOUT'), 2000)
})
process.stdout.write(JSON.stringify(result))
`
  await writeFile(dshBin, probeSource)

  const plan = await createSandboxPlan({
    profile: 'web',
    workspaceRoots: [workspace],
    network: 'loopback',
    dshBin,
    sourceDshHome,
    dshHome,
    guardHome,
    tempRoot,
  })
  const execution = await execute(plan, buildSandboxEnvironment(plan, {}))
  if (execution.code !== 0) throw new Error(`sandbox probe exited ${execution.code}: ${execution.stderr || execution.stdout}`)
  const result = JSON.parse(execution.stdout)
  const expected = {
    workspaceRead: 'allowed',
    workspaceWrite: 'allowed',
    outsideRead: 'EPERM',
    childProcess: 'EPERM',
    publicNetwork: 'EPERM',
    loopbackNetwork: 'allowed',
  }
  if (JSON.stringify(result) !== JSON.stringify(expected)) {
    throw new Error(`sandbox boundary mismatch: ${JSON.stringify({ expected, result })}`)
  }
  if ((await readFile(workspaceWrite, 'utf8')).trim() !== 'sandbox-write') throw new Error('sandbox workspace write did not persist')
  process.stdout.write(`${JSON.stringify({ sandbox: 'verified', policyHash: plan.policyHash, ...result }, null, 2)}\n`)
} finally {
  await new Promise((resolvePromise) => loopbackServer.close(resolvePromise))
  if (root.startsWith(join(tmpdir(), 'dsh-guard-sandbox-probe-'))) await rm(root, { recursive: true, force: true })
}
