import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { extractArtifact } from './archive.js'
import { DEFAULT_POLICY, policyHash } from './policy.js'
import { dshHomePath, snapshotProfile, stageArtifact } from './profile.js'
import { resolveSource } from './source.js'
import { saveReport, statePaths } from './state.js'
import { scanPackage } from './scanner.js'
import type { Finding, ScanOptions, ScanReport, Verdict } from './types.js'
import { sanitizeText, sortableId } from './util.js'

function verdictFor(findings: Finding[]): Verdict {
  if (findings.some((finding) => finding.severity === 'blocked')) return 'blocked'
  if (findings.some((finding) => finding.severity === 'review')) return 'review'
  return 'pass'
}

export async function scan(spec: string, options: ScanOptions): Promise<ScanReport> {
  const paths = statePaths(options.stateHome)
  const policy = options.policy ?? DEFAULT_POLICY
  const profile = await snapshotProfile(options.profile, dshHomePath(options.dshHome))
  const source = await resolveSource(spec, paths)
  const artifactInfo = await stat(source.artifactPath)
  const extracted = await extractArtifact(source.artifactPath, policy)
  const analysis = await scanPackage(extracted.root, extracted.files.map((file) => file.path), policy)
  const findings: Finding[] = [...extracted.findings, ...analysis.findings]
  if (analysis.manifest.name !== source.name || analysis.manifest.version !== source.version) {
    findings.push({
      id: 'artifact.identity-mismatch', severity: 'blocked', category: 'artifact', title: 'Artifact identity mismatch',
      detail: `Resolved ${source.name}@${source.version}, archive contains ${analysis.manifest.name}@${analysis.manifest.version}`,
      evidence: { file: 'package.json' },
    })
  }
  if (source.publishedAt && Date.now() - Date.parse(source.publishedAt) < 24 * 60 * 60 * 1000) {
    findings.push({ id: 'supply-chain.new-version', severity: 'review', category: 'supply-chain', title: 'Version was published less than 24 hours ago', detail: source.publishedAt, evidence: { file: 'package.json' } })
  }
  if (artifactInfo.size > policy.maxArchiveBytes) {
    findings.push({ id: 'artifact.too-large', severity: 'blocked', category: 'artifact', title: 'Artifact exceeds policy size limit', detail: `${artifactInfo.size} bytes` })
  }
  const stage = options.stage === false
    ? { attempted: false, compatible: false, reason: 'Staging explicitly disabled' }
    : await stageArtifact(profile, source.artifactPath, join(paths.cache, 'pnpm-store'))
  if (!stage.compatible) {
    findings.push({
      id: stage.attempted ? 'profile.incompatible' : 'profile.stage-unavailable',
      severity: stage.attempted ? 'blocked' : 'review',
      category: 'profile',
      title: stage.attempted ? 'Candidate failed isolated profile staging' : 'Isolated DSH compatibility was not tested',
      detail: sanitizeText(stage.reason),
    })
  }
  if (stage.compatible && analysis.manifest.dsh?.bundle?.patch && !stage.proposedBundles?.includes(source.name)) {
    findings.push({
      id: 'profile.bundle-not-activated', severity: 'blocked', category: 'profile',
      title: 'Staged install did not activate the DSH bundle',
      detail: `${source.name} was installed as a dependency but was not added to dsh.profile.bundles.`,
      evidence: { file: 'package.json' },
    })
  }
  const verdict = verdictFor(findings)
  const report: ScanReport = {
    schemaVersion: 1,
    id: sortableId('rpt'),
    createdAt: new Date().toISOString(),
    policyHash: policyHash(policy),
    verdict,
    summary: verdict === 'pass'
      ? 'No policy violations were detected. This is not proof that the plugin is safe.'
      : verdict === 'review'
        ? 'Human review is required before installation.'
        : 'Installation is blocked by one or more non-overridable findings.',
    source,
    profile,
    files: extracted.files,
    entrypoints: analysis.entrypoints,
    dependencyGraph: analysis.dependencyGraph,
    findings,
    stage,
  }
  await saveReport(report, paths)
  return report
}
