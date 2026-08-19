import React, { useCallback, useEffect, useMemo, useSyncExternalStore, useState } from 'react'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-ui-layout/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import type {} from '@deepseek-ai/dsh-client-ui-sidebar/client'

export const name = 'dsh-guard-client'
export const inject = ['slots']

type GuardStatus = 'verified' | 'review' | 'drifted' | 'needs-repair' | 'unknown'
type GuardEvent = {
  id: string
  createdAt: string
  type: string
  fingerprint: string
  title: string
  detail: string
  profile?: string
}
type StatusSnapshot = {
  schemaVersion: 1
  generatedAt: string
  status: GuardStatus
  label: string
  detail: string
  profile: string
  lastVerifiedAt?: string
  reportId?: string
  counts: { reports: number; review: number; blocked: number; activeAlerts: number }
  events: GuardEvent[]
  managedPackages: Array<{ name: string; version: string; state: GuardStatus }>
}
type SidecarAnalysis = { schemaVersion: 1; summary: string; risks: string[]; checks: string[]; limitations: string[] }

const css = `
.dg-root{font-family:var(--ds-font-family,ui-sans-serif,system-ui);color:var(--dsw-alias-label-primary);box-sizing:border-box}.dg-root *{box-sizing:border-box}
.dg-center{width:100%;max-width:840px;display:flex;flex-direction:column;gap:18px;padding:2px 0 28px}.dg-hero{position:relative;overflow:hidden;border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:14px;background:linear-gradient(145deg,var(--dsw-alias-bg-layer-3,#181b20),var(--dsw-alias-bg-layer-1,#101216));padding:22px}.dg-hero:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--dg-status,#8a9099)}
.dg-eyebrow{margin:0 0 8px;color:var(--dsw-alias-label-tertiary,#8a9099);font-family:var(--ds-font-family-code,ui-monospace);font-size:11px;letter-spacing:.12em;text-transform:uppercase}.dg-titleline{display:flex;align-items:center;gap:10px}.dg-titleline svg{width:24px;height:24px;flex:none;color:var(--dg-status)}.dg-titleline h2{font-size:22px;line-height:30px;margin:0}.dg-status-pill{border:1px solid color-mix(in srgb,var(--dg-status) 42%,transparent);background:color-mix(in srgb,var(--dg-status) 11%,transparent);color:var(--dg-status);border-radius:999px;padding:4px 9px;font-size:12px;font-weight:650}.dg-detail{max-width:650px;color:var(--dsw-alias-label-secondary,#b8bdc7);font-size:13px;line-height:21px;margin:10px 0 0}
.dg-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.dg-metric{border:1px solid var(--dsw-alias-border-l2,#30343b);background:var(--dsw-alias-bg-layer-3,#181b20);border-radius:11px;padding:13px 14px}.dg-metric strong{display:block;font-family:var(--ds-font-family-code,ui-monospace);font-size:22px;line-height:28px;font-weight:630}.dg-metric span{color:var(--dsw-alias-label-tertiary,#8a9099);font-size:11px}
.dg-section{display:flex;flex-direction:column;gap:10px}.dg-sectionhead{display:flex;justify-content:space-between;align-items:baseline}.dg-section h3{font-size:13px;margin:0}.dg-sectionhead span{font-size:11px;color:var(--dsw-alias-label-tertiary,#8a9099)}.dg-card{border:1px solid var(--dsw-alias-border-l2,#30343b);background:var(--dsw-alias-bg-layer-3,#181b20);border-radius:11px;padding:14px}.dg-empty{font-size:13px;color:var(--dsw-alias-label-tertiary,#8a9099);margin:0}.dg-package{display:flex;justify-content:space-between;gap:14px;align-items:center}.dg-package code{font-family:var(--ds-font-family-code,ui-monospace);font-size:12px}.dg-event{display:grid;grid-template-columns:9px minmax(0,1fr) auto;gap:12px;align-items:start}.dg-event+.dg-event{border-top:1px solid var(--dsw-alias-border-l2,#30343b);margin-top:12px;padding-top:12px}.dg-dot{width:8px;height:8px;margin-top:6px;border-radius:50%;background:#e25454;box-shadow:0 0 0 4px color-mix(in srgb,#e25454 13%,transparent)}.dg-event h4{font-size:13px;margin:0 0 3px}.dg-event p{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary,#b8bdc7);margin:0;overflow-wrap:anywhere}.dg-event time{font-family:var(--ds-font-family-code,ui-monospace);font-size:10px;color:var(--dsw-alias-label-tertiary,#8a9099)}
.dg-command{display:flex;gap:10px;align-items:center}.dg-command code{flex:1;overflow:auto;background:var(--dsw-alias-bg-module-platform,#0d0f12);border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:8px;padding:9px 11px;font-size:11px;white-space:nowrap}.dg-note{font-size:11px;line-height:18px;color:var(--dsw-alias-label-tertiary,#8a9099);margin:0}
.dg-shield{height:34px;min-width:34px;border:0;background:transparent;color:var(--dg-status,#8a9099);border-radius:8px;display:flex;align-items:center;justify-content:center;gap:8px;padding:0 8px;cursor:pointer}.dg-shield:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.07))}.dg-shield span{font-size:12px;font-weight:600;white-space:nowrap}.dg-shield svg{width:18px;height:18px}.dg-shield[data-wide=false] span{position:absolute;width:1px;height:1px;clip:rect(0 0 0 0);overflow:hidden}
.dg-overlay{position:fixed;inset:0;z-index:1000;pointer-events:none}.dg-alerts{position:absolute;right:22px;bottom:22px;width:min(380px,calc(100vw - 32px));display:flex;flex-direction:column;gap:10px;pointer-events:none}.dg-alert{pointer-events:auto;border:1px solid color-mix(in srgb,#e25454 45%,var(--dsw-alias-border-l2,#30343b));background:color-mix(in srgb,var(--dsw-alias-bg-layer-3,#181b20) 96%,#e25454);box-shadow:0 18px 46px rgba(0,0,0,.3);border-radius:12px;padding:14px 14px 12px;animation:dg-in .18s ease-out}.dg-alerttop{display:flex;gap:10px;align-items:flex-start}.dg-alertmark{width:8px;height:8px;background:#e25454;border-radius:50%;margin-top:6px;flex:none}.dg-alert h4{font-size:13px;margin:0}.dg-alert p{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary,#b8bdc7);margin:5px 0 0;overflow-wrap:anywhere}.dg-actions{display:flex;justify-content:flex-end;gap:7px;margin-top:11px}.dg-btn{font:inherit;font-size:11px;border:1px solid var(--dsw-alias-border-l2,#30343b);background:var(--dsw-alias-bg-layer-1,#101216);color:var(--dsw-alias-label-primary,#fff);border-radius:7px;padding:5px 9px;cursor:pointer}.dg-btn:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.07))}.dg-btn-primary{border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary,#4f8cff) 60%,transparent);color:var(--dsw-alias-state-business-primary,#75a7ff)}.dg-btn:disabled{opacity:.5;cursor:wait}
.dg-backdrop{position:absolute;inset:0;background:rgba(2,5,9,.56);backdrop-filter:blur(3px);display:grid;place-items:center;pointer-events:auto;padding:20px}.dg-modal{width:min(620px,100%);max-height:min(720px,calc(100vh - 40px));overflow:auto;border:1px solid var(--dsw-alias-border-l1,#414750);background:var(--dsw-alias-bg-layer-2,#14171c);box-shadow:0 24px 80px rgba(0,0,0,.45);border-radius:15px;padding:20px}.dg-modalhead{display:flex;justify-content:space-between;gap:14px;align-items:start;margin-bottom:16px}.dg-modalhead h2{font-size:17px;margin:0}.dg-modalhead p{font-size:12px;color:var(--dsw-alias-label-tertiary,#8a9099);margin:4px 0 0}.dg-close{border:0;background:transparent;color:var(--dsw-alias-label-secondary,#b8bdc7);font-size:20px;line-height:24px;cursor:pointer;border-radius:6px}.dg-analysis{margin-top:10px;border-left:2px solid var(--dsw-alias-state-business-primary,#4f8cff);padding:8px 10px;background:var(--dsw-alias-bg-module-platform,#0d0f12);border-radius:0 7px 7px 0}.dg-analysis strong{font-size:11px}.dg-analysis p,.dg-analysis li{font-size:11px;line-height:17px;color:var(--dsw-alias-label-secondary,#b8bdc7)}.dg-analysis ul{margin:5px 0;padding-left:16px}
@keyframes dg-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}@media(max-width:680px){.dg-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.dg-alerts{right:16px;bottom:16px}}@media(prefers-reduced-motion:reduce){.dg-alert{animation:none}}
`

function installCss(): () => void {
  const id = '@dsh-guard/companion/styles'
  if (document.querySelector(`style[data-plugin-css="${id}"]`)) return () => undefined
  const tag = document.createElement('style')
  tag.dataset.pluginCss = id
  tag.textContent = css
  document.head.appendChild(tag)
  return () => tag.remove()
}

const statusColors: Record<GuardStatus, string> = { verified: '#36a66a', review: '#d79a33', drifted: '#e25454', 'needs-repair': '#e25454', unknown: '#8a9099' }
let cached: StatusSnapshot | undefined
let failure: string | undefined
const statusListeners = new Set<() => void>()
let quickOpen = false
const quickListeners = new Set<() => void>()

function notifyStatus(): void { statusListeners.forEach((listener) => listener()) }
function notifyQuick(): void { quickListeners.forEach((listener) => listener()) }
function setQuick(value: boolean): void { quickOpen = value; notifyQuick() }

async function refreshStatus(): Promise<void> {
  try {
    const response = await fetch('/dsh-guard/api/status', { credentials: 'same-origin', cache: 'no-store' })
    if (!response.ok) throw new Error(`Host API ${response.status}`)
    cached = await response.json() as StatusSnapshot
    failure = undefined
  } catch (error) { failure = error instanceof Error ? error.message : String(error) }
  notifyStatus()
}

function useStatus(): { value: StatusSnapshot | undefined; error: string | undefined; refresh: () => Promise<void> } {
  const value = useSyncExternalStore(
    (listener) => { statusListeners.add(listener); return () => statusListeners.delete(listener) },
    () => cached,
  )
  const error = useSyncExternalStore(
    (listener) => { statusListeners.add(listener); return () => statusListeners.delete(listener) },
    () => failure,
  )
  useEffect(() => { void refreshStatus(); const timer = window.setInterval(() => void refreshStatus(), 15_000); return () => window.clearInterval(timer) }, [])
  return { value, error, refresh: refreshStatus }
}

function ShieldIcon(): React.ReactElement {
  return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2.7 20 6v5.8c0 4.7-3.1 8.2-8 9.8-4.9-1.6-8-5.1-8-9.8V6l8-3.3Z" stroke="currentColor" strokeWidth="1.7"/><path d="m8.7 12.1 2.1 2.1 4.7-5" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"/></svg>
}

function StatusHero({ status }: { status: StatusSnapshot | undefined }): React.ReactElement {
  const kind = status?.status ?? 'unknown'
  return <div className="dg-hero" style={{ '--dg-status': statusColors[kind] } as React.CSSProperties}>
    <p className="dg-eyebrow">DSH Guard / local trust state</p>
    <div className="dg-titleline"><ShieldIcon/><h2>安全中心</h2><span className="dg-status-pill">{status?.label ?? '连接中'}</span></div>
    <p className="dg-detail">{status?.detail ?? '正在读取 Host 侧的受控安装与 profile 指纹。'}</p>
  </div>
}

function Metrics({ status }: { status: StatusSnapshot | undefined }): React.ReactElement {
  const values = [
    ['报告', status?.counts.reports ?? '—'], ['待审查', status?.counts.review ?? '—'], ['已阻止', status?.counts.blocked ?? '—'], ['活动告警', status?.counts.activeAlerts ?? '—'],
  ]
  return <div className="dg-metrics">{values.map(([label, value]) => <div className="dg-metric" key={label}><strong>{value}</strong><span>{label}</span></div>)}</div>
}

function EventRows({ events, compact = false }: { events: GuardEvent[]; compact?: boolean }): React.ReactElement {
  if (!events.length) return <p className="dg-empty">没有未确认的高危事件。</p>
  return <>{events.slice(0, compact ? 4 : 20).map((event) => <div className="dg-event" key={event.fingerprint}><span className="dg-dot"/><div><h4>{event.title}</h4><p>{event.detail}</p></div><time>{new Date(event.createdAt).toLocaleString()}</time></div>)}</>
}

function SecurityCenter(): React.ReactElement {
  const { value, error, refresh } = useStatus()
  return <div className="dg-root dg-center">
    <StatusHero status={value}/>
    {error ? <div className="dg-card"><p className="dg-empty">Companion Host 不可用：{error}</p><div className="dg-actions"><button className="dg-btn" onClick={() => void refresh()}>重试</button></div></div> : null}
    <Metrics status={value}/>
    <section className="dg-section"><div className="dg-sectionhead"><h3>受控插件</h3><span>{value?.profile ?? 'web'} profile</span></div><div className="dg-card">
      {value?.managedPackages.length ? value.managedPackages.map((pkg) => <div className="dg-package" key={pkg.name}><code>{pkg.name}@{pkg.version}</code><span className="dg-status-pill" style={{ '--dg-status': statusColors[pkg.state] } as React.CSSProperties}>{pkg.state}</span></div>) : <p className="dg-empty">尚无受控安装。先在终端扫描并批准一个插件。</p>}
    </div></section>
    <section className="dg-section"><div className="dg-sectionhead"><h3>高危事件</h3><span>确认不等于解决</span></div><div className="dg-card"><EventRows events={value?.events ?? []}/></div></section>
    <section className="dg-section"><div className="dg-sectionhead"><h3>完整验证</h3><span>CLI 是权威边界</span></div><div className="dg-card"><div className="dg-command"><code>dsh-guard verify --profile {value?.profile ?? 'web'}</code><button className="dg-btn" onClick={() => navigator.clipboard?.writeText(`dsh-guard verify --profile ${value?.profile ?? 'web'}`)}>复制</button></div><p className="dg-note">Companion 只做快速漂移检查与提示；扫描、审批、安装和修复必须在独立 CLI 中完成。</p></div></section>
  </div>
}

function ShieldAction({ wide }: { wide: boolean }): React.ReactElement {
  const { value } = useStatus()
  const kind = value?.status ?? 'unknown'
  return <button className="dg-root dg-shield" data-wide={wide} style={{ '--dg-status': statusColors[kind] } as React.CSSProperties} onClick={() => setQuick(true)} title={`DSH Guard：${value?.label ?? '状态未知'}`} aria-label={`打开 DSH Guard 快速详情，${value?.label ?? '状态未知'}`}><ShieldIcon/><span>{value?.label ?? 'Guard'}</span></button>
}

async function acknowledge(event: GuardEvent): Promise<void> {
  await fetch('/dsh-guard/api/acknowledge', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ fingerprint: event.fingerprint }) })
  await refreshStatus()
}

function Analysis({ value }: { value: SidecarAnalysis }): React.ReactElement {
  return <div className="dg-analysis"><strong>隔离分析</strong><p>{value.summary}</p>{value.risks.length ? <><strong>风险</strong><ul>{value.risks.map((item) => <li key={item}>{item}</li>)}</ul></> : null}{value.checks.length ? <><strong>建议核查</strong><ul>{value.checks.map((item) => <li key={item}>{item}</li>)}</ul></> : null}<p>限制：{value.limitations.join('；') || '仅基于所示证据，不能改变 verdict。'}</p></div>
}

function EventActions({ event }: { event: GuardEvent }): React.ReactElement {
  const [busy, setBusy] = useState(false)
  const [analysis, setAnalysis] = useState<SidecarAnalysis>()
  const [error, setError] = useState<string>()
  const analyze = async () => {
    setBusy(true); setError(undefined)
    try {
      const response = await fetch('/dsh-guard/api/analyze', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: event.type, title: event.title, detail: event.detail, profile: event.profile }) })
      const body = await response.json() as SidecarAnalysis & { error?: string }
      if (!response.ok) throw new Error(body.error ?? `Host API ${response.status}`)
      setAnalysis(body)
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setBusy(false) }
  }
  return <><div className="dg-actions"><button className="dg-btn dg-btn-primary" disabled={busy} onClick={() => void analyze()}>{busy ? '分析中…' : '查看详情'}</button><button className="dg-btn" onClick={() => void acknowledge(event)}>知道了</button></div>{analysis ? <Analysis value={analysis}/> : null}{error ? <p className="dg-note">分析失败：{error}</p> : null}</>
}

function Overlay(): React.ReactElement {
  const { value } = useStatus()
  const open = useSyncExternalStore((listener) => { quickListeners.add(listener); return () => quickListeners.delete(listener) }, () => quickOpen)
  return <div className="dg-root dg-overlay">
    {open ? <div className="dg-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setQuick(false) }}><div className="dg-modal" role="dialog" aria-modal="true" aria-labelledby="dg-quick-title"><div className="dg-modalhead"><div><h2 id="dg-quick-title">DSH Guard 快速详情</h2><p>{value?.profile ?? 'web'} profile · {value?.generatedAt ? new Date(value.generatedAt).toLocaleString() : '等待 Host'}</p></div><button className="dg-close" onClick={() => setQuick(false)} aria-label="关闭">×</button></div><StatusHero status={value}/><div style={{ height: 12 }}/><Metrics status={value}/><div style={{ height: 16 }}/><section className="dg-section"><div className="dg-sectionhead"><h3>活动告警</h3><span>最多显示最近 4 条</span></div><div className="dg-card"><EventRows events={value?.events ?? []} compact/></div></section><p className="dg-note">完整历史与受控安装信息位于 Settings → Plugins → 安全中心。</p></div></div> : null}
    <div className="dg-alerts" aria-live="assertive">{(value?.events ?? []).slice(0, 3).map((event) => <article className="dg-alert" key={event.fingerprint}><div className="dg-alerttop"><span className="dg-alertmark"/><div><h4>{event.title}</h4><p>{event.detail}</p></div></div><EventActions event={event}/></article>)}</div>
  </div>
}

export function apply(ctx: Context): void {
  ctx.effect(installCss, 'dsh-guard: styles')
  ctx.slots.inject('settings.plugins.tab', () => ctx.slots.register({ name: 'settings.plugins.tab', id: 'dsh-guard', order: 30, label: '安全中心' }, SecurityCenter))
  ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({ name: 'sidebar.footer.action', id: 'dsh-guard', order: 30, label: 'DSH Guard' }, ShieldAction))
  ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'dsh-guard', order: 30, label: 'DSH Guard alerts' }, Overlay))
}
