import React, { useEffect, useRef, useSyncExternalStore, useState } from 'react'
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
type ActionEvent = {
  id: string
  createdAt: string
  decision: 'allow' | 'ask' | 'deny'
  outcome: 'allowed' | 'approved' | 'denied' | 'failed' | 'succeeded' | 'unknown'
  ruleId: string
  toolName: string
  operation: string
  sessionId?: string
  resourceSummary: string[]
  durationMs?: number
  errorCode?: string
}
type ActionGrant = {
  id: string
  createdAt: string
  expiresAt: string
  scope: 'once' | 'task'
  sessionId: string
  taskId?: string
  toolName: string
  operation: string
  resourceCount: number
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
  launch?: {
    protected: boolean
    mode: 'guarded' | 'direct'
    detail: string
  }
  action?: {
    enabled: boolean
    coverage: 'dsh-tool-registry-only'
    events: ActionEvent[]
    grants: ActionGrant[]
    state: { ok: boolean; issues: string[] }
  }
}
type SidecarAnalysis = { schemaVersion: 1; summary: string; risks: string[]; checks: string[]; limitations: string[] }

const css = `
.dg-root{font-family:var(--ds-font-family,ui-sans-serif,system-ui);color:var(--dsw-alias-label-primary);box-sizing:border-box}.dg-root *{box-sizing:border-box}
.dg-center{width:100%;max-width:840px;display:flex;flex-direction:column;gap:18px;padding:2px 0 28px}.dg-hero{position:relative;overflow:hidden;border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:14px;background:linear-gradient(145deg,var(--dsw-alias-bg-layer-3,#181b20),var(--dsw-alias-bg-layer-1,#101216));padding:22px}.dg-hero:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--dg-status,#8a9099)}
.dg-eyebrow{margin:0 0 8px;color:var(--dsw-alias-label-tertiary,#8a9099);font-family:var(--ds-font-family-code,ui-monospace);font-size:11px;letter-spacing:.12em;text-transform:uppercase}.dg-titleline{display:flex;align-items:center;gap:10px}.dg-titleline svg{width:24px;height:24px;flex:none;color:var(--dg-status)}.dg-titleline h2{font-size:22px;line-height:30px;margin:0}.dg-status-pill{border:1px solid color-mix(in srgb,var(--dg-status) 42%,transparent);background:color-mix(in srgb,var(--dg-status) 11%,transparent);color:var(--dg-status);border-radius:999px;padding:4px 9px;font-size:12px;font-weight:650}.dg-detail{max-width:650px;color:var(--dsw-alias-label-secondary,#b8bdc7);font-size:13px;line-height:21px;margin:10px 0 0}
.dg-section{display:flex;flex-direction:column;gap:10px}.dg-sectionhead{display:flex;justify-content:space-between;align-items:center;gap:12px}.dg-section h3{font-size:13px;margin:0}.dg-sectionhead span{font-size:11px;color:var(--dsw-alias-label-tertiary,#8a9099)}.dg-card{border:1px solid var(--dsw-alias-border-l2,#30343b);background:var(--dsw-alias-bg-layer-3,#181b20);border-radius:11px;padding:14px}.dg-empty{font-size:13px;color:var(--dsw-alias-label-tertiary,#8a9099);margin:0}.dg-package{display:flex;justify-content:space-between;gap:14px;align-items:center}.dg-package code{font-family:var(--ds-font-family-code,ui-monospace);font-size:12px}.dg-event{display:grid;grid-template-columns:9px minmax(0,1fr) auto;gap:12px;align-items:start}.dg-event+.dg-event{border-top:1px solid var(--dsw-alias-border-l2,#30343b);margin-top:12px;padding-top:12px}.dg-dot{width:8px;height:8px;margin-top:6px;border-radius:50%;background:#e25454;box-shadow:0 0 0 4px color-mix(in srgb,#e25454 13%,transparent)}.dg-event h4{font-size:13px;margin:0 0 3px}.dg-event p{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary,#b8bdc7);margin:0;overflow-wrap:anywhere}.dg-event time{font-family:var(--ds-font-family-code,ui-monospace);font-size:10px;color:var(--dsw-alias-label-tertiary,#8a9099)}
.dg-command{display:flex;gap:10px;align-items:center}.dg-command code{flex:1;overflow:auto;background:var(--dsw-alias-bg-module-platform,#0d0f12);border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:8px;padding:9px 11px;font-size:11px;white-space:nowrap}.dg-note{font-size:11px;line-height:18px;color:var(--dsw-alias-label-tertiary,#8a9099);margin:0}
.dg-actionmetrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.dg-actionmetric{border-left:2px solid var(--dsw-alias-border-l1,#414750);padding:8px 11px;background:var(--dsw-alias-bg-layer-3,#181b20);border-radius:0 8px 8px 0}.dg-actionmetric strong{display:block;font-family:var(--ds-font-family-code,ui-monospace);font-size:16px}.dg-actionmetric span{font-size:10px;color:var(--dsw-alias-label-tertiary,#8a9099)}
.dg-filter{display:flex;gap:5px}.dg-filter button{font:inherit;font-size:10px;color:var(--dsw-alias-label-tertiary,#8a9099);border:1px solid transparent;background:transparent;border-radius:6px;padding:3px 7px;cursor:pointer}.dg-filter button[aria-pressed=true]{color:var(--dsw-alias-label-primary,#fff);border-color:var(--dsw-alias-border-l1,#414750);background:var(--dsw-alias-bg-layer-3,#181b20)}
.dg-actionrow{display:grid;grid-template-columns:74px minmax(0,1fr) auto;gap:12px;align-items:start;padding:12px 0}.dg-actionrow:first-child{padding-top:0}.dg-actionrow:last-child{padding-bottom:0}.dg-actionrow+.dg-actionrow{border-top:1px solid var(--dsw-alias-border-l2,#30343b)}.dg-actionstamp{font-family:var(--ds-font-family-code,ui-monospace);font-size:10px;color:var(--dsw-alias-label-tertiary,#8a9099);line-height:16px}.dg-actionmain{min-width:0}.dg-actiontitle{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.dg-actiontitle code{font-size:11px;color:var(--dsw-alias-label-primary,#fff)}.dg-rule{font-family:var(--ds-font-family-code,ui-monospace);font-size:10px;color:var(--dsw-alias-label-tertiary,#8a9099);margin:5px 0 0;overflow-wrap:anywhere}.dg-tag{font-family:var(--ds-font-family-code,ui-monospace);font-size:9px;line-height:16px;text-transform:uppercase;letter-spacing:.04em;border:1px solid var(--dsw-alias-border-l1,#414750);border-radius:4px;padding:0 5px;color:var(--dsw-alias-label-secondary,#b8bdc7)}.dg-tag[data-tone=good]{color:#56bd82;border-color:color-mix(in srgb,#56bd82 45%,transparent)}.dg-tag[data-tone=warn]{color:#e4a947;border-color:color-mix(in srgb,#e4a947 45%,transparent)}.dg-tag[data-tone=bad]{color:#ef6a6a;border-color:color-mix(in srgb,#ef6a6a 50%,transparent)}.dg-resources{display:flex;flex-wrap:wrap;gap:4px;margin-top:7px}.dg-resource{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--ds-font-family-code,ui-monospace);font-size:9px;color:var(--dsw-alias-label-secondary,#b8bdc7);background:var(--dsw-alias-bg-module-platform,#0d0f12);border-radius:4px;padding:3px 5px}.dg-duration{font-family:var(--ds-font-family-code,ui-monospace);font-size:9px;color:var(--dsw-alias-label-tertiary,#8a9099);white-space:nowrap}
.dg-statebad{border-color:color-mix(in srgb,#e25454 45%,var(--dsw-alias-border-l2,#30343b));background:color-mix(in srgb,#e25454 6%,var(--dsw-alias-bg-layer-3,#181b20))}.dg-statebad h4{font-size:12px;color:#ef6a6a;margin:0 0 5px}.dg-statebad ul{margin:0;padding-left:17px;color:var(--dsw-alias-label-secondary,#b8bdc7);font-size:11px;line-height:17px}
.dg-grant{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center}.dg-grant+.dg-grant{border-top:1px solid var(--dsw-alias-border-l2,#30343b);margin-top:11px;padding-top:11px}.dg-grant code{font-size:11px}.dg-grantmeta{font-size:10px;line-height:16px;color:var(--dsw-alias-label-tertiary,#8a9099);margin-top:3px;overflow-wrap:anywhere}.dg-btn-danger{color:#ef8d62;border-color:color-mix(in srgb,#ef8d62 45%,transparent)}
.dg-switch{font:inherit;display:inline-flex;align-items:center;gap:7px;border:0;background:transparent;color:var(--dsw-alias-label-secondary,#b8bdc7);padding:2px;cursor:pointer}.dg-switchtrack{position:relative;width:34px;height:19px;border-radius:999px;background:var(--dsw-alias-border-l1,#414750);transition:background .15s ease}.dg-switchthumb{position:absolute;width:15px;height:15px;left:2px;top:2px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.35);transition:transform .15s ease}.dg-switch[aria-checked=true] .dg-switchtrack{background:var(--dsw-alias-state-business-primary,#4f8cff)}.dg-switch[aria-checked=true] .dg-switchthumb{transform:translateX(15px)}.dg-switchlabel{min-width:34px;text-align:left;font-size:11px;font-weight:600}.dg-switch:disabled{opacity:.55;cursor:wait}
.dg-shield{height:34px;min-width:34px;border:0;background:transparent;color:var(--dg-status,#8a9099);border-radius:8px;display:flex;align-items:center;justify-content:center;gap:8px;padding:0 8px;cursor:pointer}.dg-shield:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.07))}.dg-shield span{font-size:12px;font-weight:600;white-space:nowrap}.dg-shield svg{width:18px;height:18px}.dg-shield[data-wide=false] span{position:absolute;width:1px;height:1px;clip:rect(0 0 0 0);overflow:hidden}
.dg-overlay{position:fixed;inset:0;z-index:1000;pointer-events:none}.dg-alerts{position:absolute;right:22px;bottom:22px;width:min(380px,calc(100vw - 32px));display:flex;flex-direction:column;gap:10px;pointer-events:none}.dg-alert{pointer-events:auto;border:1px solid color-mix(in srgb,#e25454 45%,var(--dsw-alias-border-l2,#30343b));background:color-mix(in srgb,var(--dsw-alias-bg-layer-3,#181b20) 96%,#e25454);box-shadow:0 18px 46px rgba(0,0,0,.3);border-radius:12px;padding:14px 14px 12px;animation:dg-in .18s ease-out}.dg-alerttop{display:flex;gap:10px;align-items:flex-start}.dg-alertmark{width:8px;height:8px;background:#e25454;border-radius:50%;margin-top:6px;flex:none}.dg-alert h4{font-size:13px;margin:0}.dg-alert p{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary,#b8bdc7);margin:5px 0 0;overflow-wrap:anywhere}.dg-actions{display:flex;justify-content:flex-end;gap:7px;margin-top:11px}.dg-btn{font:inherit;font-size:11px;border:1px solid var(--dsw-alias-border-l2,#30343b);background:var(--dsw-alias-bg-layer-1,#101216);color:var(--dsw-alias-label-primary,#fff);border-radius:7px;padding:5px 9px;cursor:pointer}.dg-btn:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.07))}.dg-btn-primary{border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary,#4f8cff) 60%,transparent);color:var(--dsw-alias-state-business-primary,#75a7ff)}.dg-btn:disabled{opacity:.5;cursor:wait}
.dg-backdrop{position:absolute;inset:0;background:rgba(2,5,9,.56);backdrop-filter:blur(3px);display:grid;place-items:center;pointer-events:auto;padding:20px}.dg-modal{width:min(620px,100%);max-height:min(720px,calc(100vh - 40px));overflow:auto;border:1px solid var(--dsw-alias-border-l1,#414750);background:var(--dsw-alias-bg-layer-2,#14171c);box-shadow:0 24px 80px rgba(0,0,0,.45);border-radius:15px;padding:20px}.dg-modalhead{display:flex;justify-content:space-between;gap:14px;align-items:start;margin-bottom:16px}.dg-modalhead h2{font-size:17px;margin:0}.dg-modalhead p{font-size:12px;color:var(--dsw-alias-label-tertiary,#8a9099);margin:4px 0 0}.dg-close{border:0;background:transparent;color:var(--dsw-alias-label-secondary,#b8bdc7);font-size:20px;line-height:24px;cursor:pointer;border-radius:6px}.dg-analysis{margin-top:10px;border-left:2px solid var(--dsw-alias-state-business-primary,#4f8cff);padding:8px 10px;background:var(--dsw-alias-bg-module-platform,#0d0f12);border-radius:0 7px 7px 0}.dg-analysis strong{font-size:11px}.dg-analysis p,.dg-analysis li{font-size:11px;line-height:17px;color:var(--dsw-alias-label-secondary,#b8bdc7)}.dg-analysis ul{margin:5px 0;padding-left:16px}.dg-btn:focus-visible,.dg-filter button:focus-visible,.dg-shield:focus-visible,.dg-close:focus-visible,.dg-switch:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary,#75a7ff);outline-offset:2px}
.dg-root{--dg-core:#2f9b64;--dg-agent:#4777d7;--dg-audit:#b47b2a;--dg-danger:#d95757}.dg-center{max-width:880px;gap:14px;padding-bottom:34px}.dg-hero{border-radius:16px;padding:20px 22px;background:linear-gradient(135deg,color-mix(in srgb,var(--dg-status,#8a9099) 5%,var(--dsw-alias-bg-layer-3,#181b20)),var(--dsw-alias-bg-layer-1,#101216))}.dg-hero:before{width:3px}.dg-herohead{display:flex;align-items:flex-start;justify-content:space-between;gap:18px}.dg-titleline h2{font-size:20px;line-height:28px}.dg-titleline svg{width:22px;height:22px}.dg-detail{margin-top:8px;max-width:720px}.dg-hero-meta{display:flex;flex-wrap:wrap;gap:7px;margin-top:15px}.dg-meta{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--dsw-alias-border-l2,#30343b);background:color-mix(in srgb,var(--dsw-alias-bg-layer-3,#181b20) 84%,transparent);border-radius:999px;padding:5px 9px;color:var(--dsw-alias-label-secondary,#b8bdc7);font-size:10px}.dg-meta:before{content:"";width:6px;height:6px;border-radius:50%;background:var(--dg-meta,#8a9099)}.dg-meta[data-tone=good]{--dg-meta:var(--dg-core)}.dg-meta[data-tone=warn]{--dg-meta:var(--dg-audit)}.dg-meta[data-tone=info]{--dg-meta:var(--dg-agent)}.dg-meta strong{font-weight:650;color:var(--dsw-alias-label-primary,#fff)}
.dg-zone{--dg-zone:var(--dg-audit);position:relative;overflow:hidden;border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:15px;background:color-mix(in srgb,var(--dsw-alias-bg-layer-3,#181b20) 82%,transparent)}.dg-zone:before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:var(--dg-zone)}.dg-zone[data-tone=core]{--dg-zone:var(--dg-core)}.dg-zone[data-tone=agent]{--dg-zone:var(--dg-agent)}.dg-zone[data-tone=audit]{--dg-zone:var(--dg-audit)}.dg-zonehead{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:13px;align-items:center;padding:17px 18px 15px;border-bottom:1px solid var(--dsw-alias-border-l2,#30343b);background:linear-gradient(90deg,color-mix(in srgb,var(--dg-zone) 5%,transparent),transparent 58%)}.dg-zonenumber{display:grid;place-items:center;width:32px;height:32px;border:1px solid color-mix(in srgb,var(--dg-zone) 45%,transparent);border-radius:8px;color:var(--dg-zone);font-family:var(--ds-font-family-code,ui-monospace);font-size:10px;font-weight:700;letter-spacing:.06em}.dg-zonecopy{min-width:0}.dg-zonetitle{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.dg-zonetitle h3{margin:0;font-size:14px;line-height:20px}.dg-zonekind{color:var(--dg-zone);font-family:var(--ds-font-family-code,ui-monospace);font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}.dg-zonedesc{margin:3px 0 0;color:var(--dsw-alias-label-tertiary,#8a9099);font-size:11px;line-height:17px}.dg-zonebody{display:flex;flex-direction:column;gap:13px;padding:16px 18px 18px}.dg-zoneaction{justify-self:end}.dg-badge{display:inline-flex;align-items:center;gap:6px;border:1px solid color-mix(in srgb,var(--dg-zone) 42%,transparent);border-radius:999px;padding:5px 9px;color:var(--dg-zone);font-size:10px;font-weight:650;white-space:nowrap}.dg-badge:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.dg-facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.dg-fact{min-width:0;border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:10px;background:var(--dsw-alias-bg-layer-2,#14171c);padding:12px}.dg-factlabel{display:block;color:var(--dsw-alias-label-tertiary,#8a9099);font-size:10px}.dg-fact strong{display:block;margin-top:5px;font-size:14px;line-height:20px}.dg-fact p{margin:2px 0 0;color:var(--dsw-alias-label-tertiary,#8a9099);font-size:10px;line-height:15px}.dg-fact[data-tone=bad] strong{color:var(--dg-danger)}.dg-fact[data-tone=good] strong{color:var(--dg-core)}.dg-packageblock{border-top:1px solid var(--dsw-alias-border-l2,#30343b);padding-top:13px}.dg-minorhead{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin-bottom:9px}.dg-minorhead h4{margin:0;font-size:11px}.dg-minorhead span{color:var(--dsw-alias-label-tertiary,#8a9099);font-size:10px}.dg-package+.dg-package{border-top:1px solid var(--dsw-alias-border-l2,#30343b);margin-top:9px;padding-top:9px}.dg-reportstats{display:flex;align-items:center;gap:0;border-top:1px solid var(--dsw-alias-border-l2,#30343b);padding-top:12px}.dg-reportstat{display:flex;align-items:baseline;gap:5px;padding:0 13px;border-right:1px solid var(--dsw-alias-border-l2,#30343b)}.dg-reportstat:first-child{padding-left:0}.dg-reportstat:last-child{border-right:0}.dg-reportstat strong{font-family:var(--ds-font-family-code,ui-monospace);font-size:13px}.dg-reportstat span{color:var(--dsw-alias-label-tertiary,#8a9099);font-size:9px}.dg-reportnote{margin-left:auto;color:var(--dsw-alias-label-tertiary,#8a9099);font-size:9px;text-align:right}
.dg-statebar{display:grid;grid-template-columns:9px minmax(0,1fr);gap:10px;border:1px solid color-mix(in srgb,var(--dg-agent) 30%,var(--dsw-alias-border-l2,#30343b));border-radius:10px;padding:13px;background:color-mix(in srgb,var(--dg-agent) 5%,var(--dsw-alias-bg-layer-2,#14171c))}.dg-statebar:before{content:"";width:8px;height:8px;margin-top:5px;border-radius:50%;background:var(--dsw-alias-label-tertiary,#8a9099)}.dg-statebar[data-active=true]:before{background:var(--dg-agent);box-shadow:0 0 0 4px color-mix(in srgb,var(--dg-agent) 14%,transparent)}.dg-statebar strong{display:block;font-size:12px}.dg-statebar p{margin:3px 0 0;color:var(--dsw-alias-label-secondary,#b8bdc7);font-size:10px;line-height:16px}.dg-disclosure{border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:10px;background:var(--dsw-alias-bg-layer-2,#14171c);overflow:hidden}.dg-disclosure summary{display:flex;align-items:center;justify-content:space-between;gap:10px;list-style:none;padding:11px 12px;cursor:pointer;font-size:11px;font-weight:620}.dg-disclosure summary::-webkit-details-marker{display:none}.dg-disclosure summary:after{content:"+";color:var(--dsw-alias-label-tertiary,#8a9099);font-family:var(--ds-font-family-code,ui-monospace);font-size:14px}.dg-disclosure[open] summary:after{content:"−"}.dg-disclosure summary span{margin-left:auto;color:var(--dsw-alias-label-tertiary,#8a9099);font-size:9px;font-weight:400}.dg-disclosurebody{border-top:1px solid var(--dsw-alias-border-l2,#30343b);padding:12px}.dg-disclosure .dg-card{border:0;background:transparent;padding:0}.dg-disclosure .dg-filter{justify-content:flex-end;margin-bottom:8px}.dg-alertgrid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(260px,.85fr);gap:10px}.dg-auditcard{border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:10px;background:var(--dsw-alias-bg-layer-2,#14171c);padding:13px}.dg-auditcard .dg-minorhead{margin-bottom:10px}.dg-techline{display:grid;grid-template-columns:auto minmax(0,1fr);gap:10px;align-items:start;border-top:1px solid var(--dsw-alias-border-l2,#30343b);padding-top:11px;color:var(--dsw-alias-label-tertiary,#8a9099);font-size:9px}.dg-techline code{overflow-wrap:anywhere;color:var(--dsw-alias-label-secondary,#b8bdc7)}.dg-inlinecommand{margin-top:9px}.dg-inlinecommand code{display:block;overflow:auto;border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:7px;background:var(--dsw-alias-bg-module-platform,#0d0f12);padding:8px 9px;font-size:9px;white-space:nowrap}.dg-hosterror{border-color:color-mix(in srgb,var(--dg-danger) 45%,var(--dsw-alias-border-l2,#30343b));background:color-mix(in srgb,var(--dg-danger) 6%,var(--dsw-alias-bg-layer-3,#181b20))}.dg-quickfacts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:12px}.dg-quickfact{border-left:2px solid var(--dg-zone,var(--dsw-alias-border-l1,#414750));padding:7px 9px;background:var(--dsw-alias-bg-layer-3,#181b20);border-radius:0 7px 7px 0}.dg-quickfact span{display:block;color:var(--dsw-alias-label-tertiary,#8a9099);font-size:9px}.dg-quickfact strong{display:block;margin-top:2px;font-size:11px}
.dg-switch{border:1px solid var(--dsw-alias-border-l2,#30343b);border-radius:999px;background:var(--dsw-alias-bg-layer-2,#14171c);padding:5px 7px 5px 6px}.dg-switchtrack{width:32px;height:18px}.dg-switchthumb{width:14px;height:14px}.dg-switch[aria-checked=true] .dg-switchthumb{transform:translateX(14px)}.dg-switchlabel{font-size:10px}.dg-sectionhead h3{font-size:11px}.dg-actionmetrics{gap:7px}.dg-actionmetric{background:var(--dsw-alias-bg-layer-2,#14171c)}.dg-event h4{font-size:11px}.dg-event p{font-size:10px;line-height:16px}.dg-command{align-items:stretch}.dg-command code{font-size:9px;line-height:16px}.dg-btn{font-size:10px}.dg-empty{font-size:11px;line-height:17px}
.dg-center{gap:11px}.dg-hero{padding:15px 18px}.dg-eyebrow{margin-bottom:5px}.dg-detail{margin-top:5px;line-height:18px}.dg-hero-meta{margin-top:10px}.dg-zonehead{padding:12px 15px 11px}.dg-zonenumber{width:29px;height:29px}.dg-zonedesc{margin-top:1px;line-height:15px}.dg-zonebody{gap:9px;padding:11px 15px 13px}.dg-facts{gap:7px}.dg-fact{padding:8px 10px}.dg-fact strong{margin-top:2px;font-size:13px;line-height:18px}.dg-fact p{margin-top:1px;line-height:13px}.dg-disclosure summary{padding:8px 10px}.dg-reportstats{padding-top:8px}.dg-reportstat{padding:0 10px}.dg-reportstat strong{font-size:12px}
@keyframes dg-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}@media(max-width:680px){.dg-herohead{flex-direction:column}.dg-zonehead{grid-template-columns:auto minmax(0,1fr)}.dg-zoneaction{grid-column:1/-1;justify-self:stretch}.dg-zoneaction .dg-switch{width:100%;justify-content:center}.dg-facts,.dg-alertgrid,.dg-quickfacts{grid-template-columns:1fr}.dg-reportstats{flex-wrap:wrap;row-gap:8px}.dg-reportnote{width:100%;margin-left:0;text-align:left}.dg-actionmetrics{grid-template-columns:1fr}.dg-actionrow{grid-template-columns:1fr}.dg-alerts{right:16px;bottom:16px}}@media(prefers-reduced-motion:reduce){.dg-alert{animation:none}.dg-switchtrack,.dg-switchthumb{transition:none}}
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
const agentProtectionEventTypes = new Set(['repeated-tool-denial', 'action-state-degraded', 'critical-action-denied'])
let cached: StatusSnapshot | undefined
let failure: string | undefined
const statusListeners = new Set<() => void>()
let quickOpen = false
const quickListeners = new Set<() => void>()

function notifyStatus(): void { statusListeners.forEach((listener) => listener()) }
function notifyQuick(): void { quickListeners.forEach((listener) => listener()) }
function setQuick(value: boolean): void { quickOpen = value; notifyQuick() }
function isAgentProtectionEvent(event: GuardEvent): boolean { return agentProtectionEventTypes.has(event.type) }
function visibleAlerts(status: StatusSnapshot | undefined): GuardEvent[] {
  const events = status?.events ?? []
  return status?.action?.enabled ? events : events.filter((event) => !isAgentProtectionEvent(event))
}

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

function statusMessage(status: StatusSnapshot | undefined): string {
  switch (status?.status) {
    case 'verified': return '受控插件与 profile 配置一致，当前信任链正常。'
    case 'review': return '当前状态需要人工确认，请查看告警与权威验证结果。'
    case 'drifted': return '检测到未批准的插件或配置变化，请先停止并核验。'
    case 'needs-repair': return '上次变更未完整恢复，修复前不要继续安装或更新。'
    default: return '正在连接 Companion Host 并读取本地信任状态。'
  }
}

function formatDateTime(value: string, short = false): string {
  return new Intl.DateTimeFormat('zh-CN', short
    ? { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }
    : { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date(value))
}

function StatusHero({ status }: { status: StatusSnapshot | undefined }): React.ReactElement {
  const kind = status?.status ?? 'unknown'
  const guarded = status?.launch?.protected === true
  const actionEnabled = status?.action?.enabled === true
  return <header className="dg-hero" style={{ '--dg-status': statusColors[kind] } as React.CSSProperties}>
    <div className="dg-herohead"><div>
      <p className="dg-eyebrow">DSH Guard / Security Control</p>
      <div className="dg-titleline"><ShieldIcon/><h2>DSH Guard 安全中心</h2><span className="dg-status-pill">{status?.label ?? '连接中'}</span></div>
      <p className="dg-detail">{statusMessage(status)}</p>
    </div></div>
    <div className="dg-hero-meta" aria-label="防护状态摘要">
      <span className="dg-meta" data-tone="good"><strong>{status?.profile ?? 'web'}</strong> profile</span>
      <span className="dg-meta" data-tone={guarded ? 'good' : 'warn'}><strong>{guarded ? '受保护启动' : '直接启动'}</strong></span>
      <span className="dg-meta" data-tone={actionEnabled ? 'info' : 'warn'}><strong>Agent 保护{actionEnabled ? '开启' : '关闭'}</strong></span>
      {status?.lastVerifiedAt ? <span className="dg-meta"><strong>验证 {formatDateTime(status.lastVerifiedAt, true)}</strong></span> : null}
    </div>
  </header>
}

function SectionFrame({ index, kind, title, description, tone, action, children }: {
  index: string
  kind: string
  title: string
  description: string
  tone: 'core' | 'agent' | 'audit'
  action?: React.ReactNode
  children: React.ReactNode
}): React.ReactElement {
  return <section className="dg-zone" data-tone={tone}>
    <div className="dg-zonehead"><span className="dg-zonenumber">{index}</span><div className="dg-zonecopy"><div className="dg-zonetitle"><h3>{title}</h3><span className="dg-zonekind">{kind}</span></div><p className="dg-zonedesc">{description}</p></div>{action ? <div className="dg-zoneaction">{action}</div> : null}</div>
    <div className="dg-zonebody">{children}</div>
  </section>
}

const packageStateLabels: Record<GuardStatus, string> = { verified: '已验证', review: '需复核', drifted: '已漂移', 'needs-repair': '需修复', unknown: '未知' }

function PluginProtection({ status, pluginEvents }: { status: StatusSnapshot | undefined; pluginEvents: GuardEvent[] }): React.ReactElement {
  const guarded = status?.launch?.protected === true
  const packages = status?.managedPackages ?? []
  return <SectionFrame index="01" kind="CORE" title="插件防护" description="安装前审查、受控版本和启动前复核；不受 Agent 开关影响。" tone="core" action={<span className="dg-badge">始终开启</span>}>
    <div className="dg-facts">
      <div className="dg-fact"><span className="dg-factlabel">安装前检查</span><strong>{status ? `${status.counts.reports} 份报告` : '读取中'}</strong><p>固定制品、能力扫描与配置预演</p></div>
      <div className="dg-fact"><span className="dg-factlabel">受控版本</span><strong>{status ? `${packages.length} 个插件` : '读取中'}</strong><p>精确版本、哈希与历史 generation</p></div>
      <div className="dg-fact" data-tone={guarded ? 'good' : 'bad'}><span className="dg-factlabel">启动前验证</span><strong>{guarded ? '已生效' : '未生效'}</strong><p>{guarded ? '本进程由 Guard 验证后启动' : '请改用 dsh-guard start'}</p></div>
    </div>
    {!guarded ? <div className="dg-inlinecommand"><code>dsh-guard start --profile {status?.profile ?? 'web'} -- --host 127.0.0.1 --port 8080</code></div> : null}
    <details className="dg-disclosure"><summary>受控插件清单<span>{packages.length} 个 · {status?.profile ?? 'web'} profile</span></summary><div className="dg-disclosurebody">
      {packages.length ? packages.map((pkg) => <div className="dg-package" key={pkg.name}><code>{pkg.name}@{pkg.version}</code><span className="dg-status-pill" style={{ '--dg-status': statusColors[pkg.state] } as React.CSSProperties}>{packageStateLabels[pkg.state]}</span></div>) : <p className="dg-empty">尚无受控插件。先在终端扫描、批准并安装精确制品。</p>}
    </div></details>
    <div className="dg-reportstats" aria-label="历史扫描结果">
      <div className="dg-reportstat"><strong>{status?.counts.reports ?? '—'}</strong><span>累计扫描</span></div>
      <div className="dg-reportstat"><strong>{status?.counts.review ?? '—'}</strong><span>需人工判断</span></div>
      <div className="dg-reportstat"><strong>{status?.counts.blocked ?? '—'}</strong><span>已阻止</span></div>
      <div className="dg-reportstat"><strong>{status ? pluginEvents.length : '—'}</strong><span>当前告警</span></div>
      <span className="dg-reportnote">扫描结果统计，不是未处理任务</span>
    </div>
  </SectionFrame>
}

function EventRows({ events, compact = false }: { events: GuardEvent[]; compact?: boolean }): React.ReactElement {
  if (!events.length) return <p className="dg-empty">没有未确认的高危事件。</p>
  return <>{events.slice(0, compact ? 4 : 20).map((event) => <div className="dg-event" key={event.fingerprint}><span className="dg-dot"/><div><h4>{event.title}</h4><p>{event.detail}</p></div><time>{formatDateTime(event.createdAt)}</time></div>)}</>
}

function actionTone(event: ActionEvent): 'good' | 'warn' | 'bad' {
  if (event.outcome === 'denied' || event.outcome === 'failed' || event.outcome === 'unknown') return 'bad'
  if (event.decision === 'ask' || event.outcome === 'approved') return 'warn'
  return 'good'
}

function ActionTimeline({ events }: { events: ActionEvent[] }): React.ReactElement {
  const [filter, setFilter] = useState<'attention' | 'all'>('attention')
  const visible = filter === 'all' ? events : events.filter((event) => actionTone(event) !== 'good')
  return <div>
    <div className="dg-filter" aria-label="动作事件筛选"><button aria-pressed={filter === 'attention'} onClick={() => setFilter('attention')}>需关注</button><button aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>全部</button></div>
    <div className="dg-card">
      {visible.length ? visible.slice(0, 20).map((event) => <div className="dg-actionrow" key={event.id}>
        <time className="dg-actionstamp" dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleDateString('zh-CN')}<br/>{new Date(event.createdAt).toLocaleTimeString('zh-CN', { hour12: false })}</time>
        <div className="dg-actionmain"><div className="dg-actiontitle"><code>{event.toolName}/{event.operation}</code><span className="dg-tag" data-tone={actionTone(event)}>{event.decision}</span><span className="dg-tag" data-tone={actionTone(event)}>{event.outcome}</span></div><p className="dg-rule">{event.ruleId}{event.errorCode ? ` · ${event.errorCode}` : ''}{event.sessionId ? ` · session ${event.sessionId}` : ' · legacy event (session unavailable)'}</p>{event.resourceSummary.length ? <div className="dg-resources">{event.resourceSummary.slice(0, 4).map((resource, index) => <span className="dg-resource" title={resource} key={`${event.id}-${index}`}>{resource}</span>)}</div> : null}</div>
        <span className="dg-duration">{event.durationMs === undefined ? '—' : `${event.durationMs} ms`}</span>
      </div>) : <p className="dg-empty">{events.length ? '最近没有需要关注的动作；切换到“全部”可查看正常调用。' : '尚无 Agent 操作保护事件。显式启用后，正规工具调用会在这里显示脱敏记录。'}</p>}
    </div>
  </div>
}

async function revokeGrant(grantId: string): Promise<void> {
  const response = await fetch('/dsh-guard/api/grants/revoke', {
    method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grantId }),
  })
  const body = await response.json() as { error?: string }
  if (!response.ok) throw new Error(body.error ?? `Host API ${response.status}`)
  await refreshStatus()
}

function GrantRows({ grants }: { grants: ActionGrant[] }): React.ReactElement {
  const [busy, setBusy] = useState<string>()
  const [error, setError] = useState<string>()
  const revoke = async (grant: ActionGrant) => {
    setBusy(grant.id); setError(undefined)
    try { await revokeGrant(grant.id) }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setBusy(undefined) }
  }
  return <div className="dg-card">{grants.length ? grants.map((grant) => <div className="dg-grant" key={grant.id}><div><div className="dg-actiontitle"><code>{grant.toolName}/{grant.operation}</code><span className="dg-tag" data-tone="warn">{grant.scope}</span></div><div className="dg-grantmeta">session {grant.sessionId} · 到期 {formatDateTime(grant.expiresAt)} · {grant.resourceCount} 个资源约束</div></div><button className="dg-btn dg-btn-danger" disabled={busy === grant.id} onClick={() => void revoke(grant)} aria-label={`撤销 ${grant.toolName}/${grant.operation} 授权`}>{busy === grant.id ? '撤销中…' : '撤销'}</button></div>) : <p className="dg-empty">没有有效授权。DSH 的“仅本次允许”不会保存成下一次可复用的 grant。</p>}{error ? <p className="dg-note">撤销失败：{error}</p> : null}</div>
}

async function setActionProtection(enabled: boolean): Promise<void> {
  const response = await fetch('/dsh-guard/api/action-protection', {
    method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enabled }),
  })
  const body = await response.json() as { error?: string }
  if (!response.ok) throw new Error(body.error ?? `Host API ${response.status}`)
  await refreshStatus()
}

function ActionCenter({ action, alerts }: { action: StatusSnapshot['action']; alerts: GuardEvent[] }): React.ReactElement {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [eventsOpen, setEventsOpen] = useState(false)
  const events = action?.events ?? []
  const grants = action?.grants ?? []
  const attention = events.filter((event) => actionTone(event) !== 'good').length
  const enabled = action?.enabled === true
  useEffect(() => { if (enabled && (attention > 0 || alerts.length > 0 || action?.state.ok === false)) setEventsOpen(true) }, [enabled, attention, alerts.length, action?.state.ok])
  const toggle = async () => {
    const next = !enabled
    if (!next && !window.confirm('关闭 Agent 操作保护后，主 Agent 的工具调用将不再经过策略检查，现有临时授权会被撤销。插件安全保护仍保持开启。确定关闭吗？')) return
    setBusy(true); setError(undefined)
    try { await setActionProtection(next) }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setBusy(false) }
  }
  const switchControl = <button className="dg-switch" type="button" role="switch" aria-checked={enabled} aria-label={`Agent 操作保护${enabled ? '已开启' : '已关闭'}`} disabled={action === undefined || busy} onClick={() => void toggle()}><span className="dg-switchtrack" aria-hidden="true"><span className="dg-switchthumb"/></span><span className="dg-switchlabel">{busy ? '处理中…' : enabled ? '开启' : action ? '关闭' : '读取中'}</span></button>
  return <SectionFrame index="02" kind="OPTIONAL" title="Agent 操作保护" description="检查所有 Agent 的正规工具调用；它不是插件身份识别。" tone="agent" action={switchControl}>
    <div className="dg-statebar" data-active={enabled}><div><strong>{enabled ? '所有 Agent 工具调用都会检查' : '当前不检查 Agent 工具调用'}</strong><p>{enabled ? '文件、Bash、Web 等调用会进入策略；Host 插件直接调用 Node.js API 仍可绕过。' : '插件扫描、受控版本、漂移检测和启动前验证仍然保持运行。'}</p></div></div>
    {error ? <p className="dg-note" role="status">切换失败：{error}</p> : null}
    {action?.enabled && !action.state.ok ? <div className="dg-card dg-statebad" role="status"><h4>Agent 操作保护状态降级</h4><ul>{action.state.issues.map((issue) => <li key={issue}>{issue}</li>)}</ul></div> : null}
    <div className="dg-actionmetrics"><div className="dg-actionmetric"><strong>{events.length}</strong><span>{enabled ? '最近脱敏事件' : '历史事件'}</span></div><div className="dg-actionmetric"><strong>{attention}</strong><span>需关注</span></div><div className="dg-actionmetric"><strong>{grants.length}</strong><span>有效授权</span></div></div>
    {enabled && alerts.length ? <div className="dg-card dg-statebad"><div className="dg-minorhead"><h4>Agent 高危告警</h4><span>与插件告警分开</span></div><EventRows events={alerts}/></div> : null}
    <details className="dg-disclosure" open={eventsOpen} onToggle={(event) => setEventsOpen(event.currentTarget.open)}><summary>动作记录<span>{attention} 条需关注 · 共 {events.length} 条</span></summary><div className="dg-disclosurebody"><ActionTimeline events={events}/></div></details>
    <details className="dg-disclosure"><summary>临时授权<span>{grants.length} 个有效授权</span></summary><div className="dg-disclosurebody"><GrantRows grants={grants}/></div></details>
  </SectionFrame>
}

function AuditCenter({ status, pluginEvents }: { status: StatusSnapshot | undefined; pluginEvents: GuardEvent[] }): React.ReactElement {
  const profile = status?.profile ?? 'web'
  const command = `dsh-guard verify --profile ${profile}`
  return <SectionFrame index="03" kind="AUDIT" title="告警与核验" description="事件用于提醒；扫描、审批、安装和修复仍由独立 CLI 完成。" tone="audit">
    <div className="dg-alertgrid">
      <div className="dg-auditcard"><div className="dg-minorhead"><h4>插件安全事件</h4><span>{pluginEvents.length ? `${pluginEvents.length} 条活动告警` : '当前无告警'}</span></div><EventRows events={pluginEvents}/></div>
      <div className="dg-auditcard"><div className="dg-minorhead"><h4>权威验证</h4><span>CLI trust boundary</span></div><p className="dg-note">需要完整核验时运行此命令；页面不会代替安装门禁。</p><div className="dg-command"><code>{command}</code><button className="dg-btn" onClick={() => navigator.clipboard?.writeText(command)}>复制</button></div></div>
    </div>
    <div className="dg-techline"><span>技术状态</span><code>{status?.detail ?? '等待 Companion Host 返回 profile 指纹与 generation 状态。'}</code></div>
  </SectionFrame>
}

function SecurityCenter(): React.ReactElement {
  const { value, error, refresh } = useStatus()
  const pluginEvents = (value?.events ?? []).filter((event) => !isAgentProtectionEvent(event))
  const agentEvents = (value?.events ?? []).filter(isAgentProtectionEvent)
  return <div className="dg-root dg-center">
    <StatusHero status={value}/>
    {error ? <div className="dg-card dg-hosterror" role="status"><p className="dg-empty">Companion Host 连接失败：{error}</p><div className="dg-actions"><button className="dg-btn" onClick={() => void refresh()}>重新连接</button></div></div> : null}
    <PluginProtection status={value} pluginEvents={pluginEvents}/>
    <ActionCenter action={value?.action} alerts={agentEvents}/>
    <AuditCenter status={value} pluginEvents={pluginEvents}/>
  </div>
}

function QuickFacts({ status }: { status: StatusSnapshot | undefined }): React.ReactElement {
  const guarded = status?.launch?.protected === true
  const actionEnabled = status?.action?.enabled === true
  return <div className="dg-quickfacts" aria-label="快速防护摘要">
    <div className="dg-quickfact" style={{ '--dg-zone': 'var(--dg-core)' } as React.CSSProperties}><span>插件防护</span><strong>始终开启</strong></div>
    <div className="dg-quickfact" style={{ '--dg-zone': guarded ? 'var(--dg-core)' : 'var(--dg-danger)' } as React.CSSProperties}><span>启动方式</span><strong>{guarded ? '受保护启动' : '直接启动'}</strong></div>
    <div className="dg-quickfact" style={{ '--dg-zone': 'var(--dg-agent)' } as React.CSSProperties}><span>Agent 操作保护</span><strong>{actionEnabled ? '已开启' : '已关闭'}</strong></div>
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
  const alerts = visibleAlerts(value)
  const open = useSyncExternalStore((listener) => { quickListeners.add(listener); return () => quickListeners.delete(listener) }, () => quickOpen)
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    if (!open) return
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : undefined
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape') setQuick(false) }
    document.addEventListener('keydown', onKeyDown)
    closeRef.current?.focus()
    return () => { document.removeEventListener('keydown', onKeyDown); previous?.focus() }
  }, [open])
  return <div className="dg-root dg-overlay">
    {open ? <div className="dg-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setQuick(false) }}><div className="dg-modal" role="dialog" aria-modal="true" aria-labelledby="dg-quick-title"><div className="dg-modalhead"><div><h2 id="dg-quick-title">DSH Guard 快速详情</h2><p>{value?.profile ?? 'web'} profile · {value?.generatedAt ? formatDateTime(value.generatedAt) : '等待 Host'}</p></div><button ref={closeRef} className="dg-close" onClick={() => setQuick(false)} aria-label="关闭">×</button></div><StatusHero status={value}/><QuickFacts status={value}/><div style={{ height: 16 }}/><section className="dg-section"><div className="dg-sectionhead"><h3>活动告警</h3><span>最多显示最近 4 条</span></div><div className="dg-card"><EventRows events={alerts} compact/></div></section><p className="dg-note">完整状态位于“设置 → 插件 → 插件安全”。</p></div></div> : null}
    <div className="dg-alerts" aria-live="assertive">{alerts.slice(0, 3).map((event) => <article className="dg-alert" key={event.fingerprint}><div className="dg-alerttop"><span className="dg-alertmark"/><div><h4>{event.title}</h4><p>{event.detail}</p></div></div><EventActions event={event}/></article>)}</div>
  </div>
}

export function apply(ctx: Context): void {
  ctx.effect(installCss, 'dsh-guard: styles')
  ctx.slots.inject('settings.plugins.tab', () => ctx.slots.register({ name: 'settings.plugins.tab', id: 'dsh-guard', order: 30, label: '插件安全' }, SecurityCenter))
  ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({ name: 'sidebar.footer.action', id: 'dsh-guard', order: 30, label: 'DSH Guard' }, ShieldAction))
  ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'dsh-guard', order: 30, label: 'DSH Guard alerts' }, Overlay))
}
