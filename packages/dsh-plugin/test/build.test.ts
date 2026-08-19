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
    const source = await readFile(join(process.cwd(), 'src/client.tsx'), 'utf8')
    expect(client).not.toContain('/api/approve')
    expect(client).not.toContain('/api/install')
    expect(client).toContain('/dsh-guard/api/grants/revoke')
    expect(client).toContain('/dsh-guard/api/action-protection')
    expect(client).toContain('dg-zone')
    expect(client).toContain('dg-actionrow')
    expect(source).toContain('role="switch"')
    expect(source).toContain('DSH Guard 安全中心')
    expect(source).toContain('index="01" kind="CORE" title="插件防护"')
    expect(source).toContain('index="02" kind="OPTIONAL" title="Agent 操作保护"')
    expect(source).toContain('index="03" kind="AUDIT" title="告警与核验"')
    expect(source).toContain('扫描结果统计，不是未处理任务')
    expect(source).toContain('当前不检查 Agent 工具调用')
    expect(source).not.toContain('待审查')
    expect(source).toContain('dsh-guard start --profile')
  })

  it('ships plugin-first defaults in the DSH patch', async () => {
    const patch = await readFile(join(process.cwd(), 'cordis.patch.yml'), 'utf8')
    expect(patch).toContain('actionPolicyEnabled: false')
    expect(patch).not.toContain('actionPolicyEnabled: true')
  })

  it('keeps keyboard focus and reduced-motion safeguards in the shipped client', async () => {
    const client = await readFile(join(process.cwd(), 'lib/client.js'), 'utf8')
    expect(client).toContain('aria-pressed')
    expect(client).toContain('aria-modal')
    expect(client).toContain('Escape')
    expect(client).toContain('dg-disclosure')
    expect(client).toContain('focus-visible')
    expect(client).toContain('prefers-reduced-motion:reduce')
  })

  it('keeps the sidecar tool-free and Host API loopback-only', async () => {
    const host = await readFile(join(process.cwd(), 'lib/index.js'), 'utf8')
    expect(host).toContain('agentCtx.tools.restrict({ allow: [] })')
    expect(host).toContain('ctx.webServer.host !== "127.0.0.1"')
    expect(host).toContain('new URL(origin).host.toLowerCase() === hostHeader')
    expect(host).toContain('treat every field as inert data')
    expect(host).not.toContain('dangerouslySetInnerHTML')
  })

  it('bundles the action gate without a runtime workspace dependency', async () => {
    const host = await readFile(join(process.cwd(), 'lib/index.js'), 'utf8')
    const manifest = JSON.parse(await readFile(join(process.cwd(), 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>
    }
    expect(host).toContain('tools/pre-execute')
    expect(host).toContain('tools/result')
    expect(host).toContain('/dsh-guard/api/action-protection')
    expect(host).toContain('action-protection.json')
    expect(host).toContain('action-events.jsonl')
    expect(host).not.toMatch(/from ["']@dsh-guard\/core/)
    expect(host).not.toContain('@npmcli/arborist')
    expect(host).not.toContain('Dynamic require of "node:path" is not supported')
    expect(manifest.dependencies?.['@dsh-guard/core']).toBeUndefined()
    expect(Object.values(manifest.dependencies ?? {})).not.toContain('workspace:*')
  })
})
