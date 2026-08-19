import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  buildGuardedDshEnvironment,
  runGuardedDsh,
  validateGuardedDshArgs,
} from '../src/index.js'

describe('Guarded DSH launch', () => {
  it('rejects profile, patch, and loader configuration overrides', () => {
    expect(() => validateGuardedDshArgs(['--profile', 'evil'])).toThrow(/cannot override/)
    expect(() => validateGuardedDshArgs(['--profile=evil'])).toThrow(/cannot override/)
    expect(() => validateGuardedDshArgs(['--patch=evil.yml'])).toThrow(/unverified --patch/)
    expect(() => validateGuardedDshArgs(['--config.offline=false'])).toThrow(/loader configuration/)
    expect(() => validateGuardedDshArgs(['--host', '127.0.0.1', '--port=8080'])).not.toThrow()
  })

  it('removes process injection variables while preserving normal DSH credentials', () => {
    const environment = buildGuardedDshEnvironment({
      PATH: '/usr/bin:/bin',
      DEEPSEEK_API_KEY: 'fixture-secret',
      NODE_OPTIONS: '--require attacker.js',
      NODE_PATH: '/tmp/attacker',
      DYLD_INSERT_LIBRARIES: '/tmp/attacker.dylib',
      LD_PRELOAD: '/tmp/attacker.so',
    }, {
      dshHome: '/tmp/dsh-home',
      guardHome: '/tmp/guard-home',
    })

    expect(environment).toMatchObject({
      PATH: '/usr/bin:/bin',
      DEEPSEEK_API_KEY: 'fixture-secret',
      DSH_HOME: '/tmp/dsh-home',
      DSH_GUARD_HOME: '/tmp/guard-home',
      DSH_GUARD_LAUNCH_MODE: 'verified',
    })
    expect(environment.NODE_OPTIONS).toBeUndefined()
    expect(environment.NODE_PATH).toBeUndefined()
    expect(environment.DYLD_INSERT_LIBRARIES).toBeUndefined()
    expect(environment.LD_PRELOAD).toBeUndefined()
  })

  it('launches the exact verified profile and preserves the child exit code', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-guard-launcher-test-'))
    const script = join(root, 'fixture-launcher.mjs')
    const output = join(root, 'result.json')
    await writeFile(script, [
      "import { writeFile } from 'node:fs/promises'",
      "await writeFile(process.env.FIXTURE_OUTPUT, JSON.stringify({ args: process.argv.slice(2), dshHome: process.env.DSH_HOME, mode: process.env.DSH_GUARD_LAUNCH_MODE }))",
      'process.exitCode = 7',
    ].join('\n'))
    await chmod(script, 0o700)
    const environment = buildGuardedDshEnvironment({ ...process.env, FIXTURE_OUTPUT: output }, {
      dshHome: join(root, 'dsh-home'),
      guardHome: join(root, 'guard-home'),
    })

    const code = await runGuardedDsh(
      { command: process.execPath, prefix: [script] },
      'web',
      ['--host=127.0.0.1', '--port=8080'],
      environment,
      { cwd: root },
    )

    expect(code).toBe(7)
    expect(JSON.parse(await readFile(output, 'utf8'))).toEqual({
      args: ['--profile', 'web', '--host=127.0.0.1', '--port=8080'],
      dshHome: join(root, 'dsh-home'),
      mode: 'verified',
    })
  })
})
