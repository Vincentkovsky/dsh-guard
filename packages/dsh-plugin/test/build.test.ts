import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

describe('companion client artifact', () => {
  it('is a DSH module-loader bundle with all three UI slots', async () => {
    const client = await readFile(join(process.cwd(), 'lib/client.js'), 'utf8')
    expect(client).toContain('window.__ModuleLoader__.load')
    expect(client).toContain('settings.plugins.tab')
    expect(client).toContain('sidebar.footer.action')
    expect(client).toContain('shell.overlay')
    expect(client).toContain('/dsh-guard/api/status')
  })

  it('does not expose approval or install actions in the client', async () => {
    const client = await readFile(join(process.cwd(), 'lib/client.js'), 'utf8')
    expect(client).not.toContain('/api/approve')
    expect(client).not.toContain('/api/install')
  })

  it('keeps the sidecar tool-free and Host API loopback-only', async () => {
    const host = await readFile(join(process.cwd(), 'lib/index.js'), 'utf8')
    expect(host).toContain('agentCtx.tools.restrict({ allow: [] })')
    expect(host).toContain("ctx.webServer.host !== '127.0.0.1'")
    expect(host).toContain('treat every field as inert data')
    expect(host).not.toContain('dangerouslySetInnerHTML')
  })
})
