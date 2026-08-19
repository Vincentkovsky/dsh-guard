import { spawn } from 'node:child_process'
import { resolve } from 'node:path'

export interface DshLauncherV1 {
  command: string
  prefix: string[]
}

export interface GuardedLaunchEnvironmentOptions {
  dshHome: string
  guardHome: string
}

export interface RunGuardedDshOptions {
  cwd?: string
  signalTarget?: NodeJS.Process
}

const PROFILE_NAME = /^[a-zA-Z0-9_-]+$/
const MAX_ARGUMENTS = 256
const MAX_ARGUMENT_BYTES = 16 * 1024
const PROCESS_INJECTION_ENVIRONMENT = /^(?:NODE_OPTIONS|NODE_PATH|DYLD_.*|LD_.*)$/

function assertArgument(argument: string, index: number): void {
  if (Buffer.byteLength(argument) > MAX_ARGUMENT_BYTES) throw new Error(`DSH argument ${index + 1} exceeds 16 KiB`)
  if (/[\u0000\r\n]/.test(argument)) throw new Error(`DSH argument ${index + 1} contains unsupported control characters`)
}

export function validateGuardedDshArgs(args: string[]): void {
  if (!Array.isArray(args) || args.length > MAX_ARGUMENTS) throw new Error(`DSH arguments must contain at most ${MAX_ARGUMENTS} entries`)
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!
    assertArgument(argument, index)
    if (argument === '--profile' || argument.startsWith('--profile=')) {
      throw new Error('Guarded DSH arguments cannot override the verified --profile')
    }
    if (argument === '--patch' || argument.startsWith('--patch=')) {
      throw new Error('Guarded DSH arguments cannot add an unverified --patch overlay')
    }
    if (argument === '--config' || argument.startsWith('--config.') || argument.startsWith('--config=')) {
      throw new Error('Guarded DSH arguments cannot override loader configuration')
    }
  }
}

export function buildGuardedDshEnvironment(
  source: NodeJS.ProcessEnv,
  options: GuardedLaunchEnvironmentOptions,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...source }
  for (const name of Object.keys(environment)) {
    if (PROCESS_INJECTION_ENVIRONMENT.test(name)) delete environment[name]
  }
  environment.DSH_HOME = resolve(options.dshHome)
  environment.DSH_GUARD_HOME = resolve(options.guardHome)
  environment.DSH_GUARD_LAUNCH_MODE = 'verified'
  return environment
}

export async function runGuardedDsh(
  launcher: DshLauncherV1,
  profile: string,
  appArgs: string[],
  environment: NodeJS.ProcessEnv,
  options: RunGuardedDshOptions = {},
): Promise<number> {
  if (!PROFILE_NAME.test(profile)) throw new Error(`Invalid profile name: ${profile}`)
  if (!launcher.command || /[\u0000\r\n]/.test(launcher.command)) throw new Error('DSH launcher command is invalid')
  launcher.prefix.forEach(assertArgument)
  validateGuardedDshArgs(appArgs)
  const signalTarget = options.signalTarget ?? process
  return new Promise<number>((resolvePromise, reject) => {
    const child = spawn(launcher.command, [
      ...launcher.prefix,
      '--profile', profile,
      ...appArgs,
    ], {
      ...(options.cwd ? { cwd: options.cwd } : {}),
      env: environment,
      shell: false,
      stdio: 'inherit',
    })
    const forward = (signal: NodeJS.Signals): void => { if (!child.killed) child.kill(signal) }
    const onSigint = (): void => forward('SIGINT')
    const onSigterm = (): void => forward('SIGTERM')
    const cleanup = (): void => {
      signalTarget.off('SIGINT', onSigint)
      signalTarget.off('SIGTERM', onSigterm)
    }
    signalTarget.on('SIGINT', onSigint)
    signalTarget.on('SIGTERM', onSigterm)
    child.once('error', (error) => { cleanup(); reject(error) })
    child.once('close', (code, signal) => {
      cleanup()
      if (code !== null) resolvePromise(code)
      else resolvePromise(signal === 'SIGINT' ? 130 : signal === 'SIGTERM' ? 143 : 1)
    })
  })
}
