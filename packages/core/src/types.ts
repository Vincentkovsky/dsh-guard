export type Verdict = 'pass' | 'review' | 'blocked'
export type FindingSeverity = 'info' | 'review' | 'blocked'
export type GuardStatus = 'verified' | 'review' | 'drifted' | 'needs-repair' | 'unknown'

export type Capability =
  | 'filesystem-read'
  | 'filesystem-write'
  | 'environment'
  | 'credentials'
  | 'network-client'
  | 'network-listen'
  | 'subprocess'
  | 'dynamic-code'
  | 'native-code'
  | 'external-code'
  | 'tool-register'
  | 'profile-override'

export interface Evidence {
  file: string
  line?: number
  excerpt?: string
  sha256?: string
}

export interface Finding {
  id: string
  severity: FindingSeverity
  category: 'artifact' | 'code' | 'manifest' | 'supply-chain' | 'profile' | 'policy'
  title: string
  detail: string
  capability?: Capability
  evidence?: Evidence
}

export interface ResolvedSource {
  kind: 'npm' | 'directory' | 'tarball'
  requested: string
  name: string
  version: string
  artifactPath: string
  sha256: string
  integrity?: string
  registry?: string
  publishedAt?: string
}

export interface FileRecord {
  path: string
  size: number
  sha256: string
  kind: 'file' | 'symlink'
  linkTarget?: string
}

export interface ProfileSnapshot {
  name: string
  path: string
  fingerprint: string
  files: Record<string, string | null>
  bundles: string[]
}

export interface StageResult {
  attempted: boolean
  compatible: boolean
  reason?: string
  beforeConfigHash?: string
  afterConfigHash?: string
  proposedLockHash?: string
  proposedProfileFingerprint?: string
  proposedBundles?: string[]
  configDiff?: string[]
}

export interface ScanReport {
  schemaVersion: 1
  id: string
  createdAt: string
  policyHash: string
  verdict: Verdict
  summary: string
  source: ResolvedSource
  profile: ProfileSnapshot
  files: FileRecord[]
  entrypoints: string[]
  dependencyGraph: Record<string, string>
  findings: Finding[]
  stage: StageResult
}

export interface Approval {
  schemaVersion: 1
  reportId: string
  approvedAt: string
  reportSha256: string
  artifactSha256: string
  profileFingerprint: string
  policyHash: string
}

export interface InstallRecord {
  schemaVersion: 1
  reportId: string
  installedAt: string
  lastVerifiedAt: string
  profile: string
  packageName: string
  version: string
  artifactSha256: string
  expectedProfileFingerprint: string
  resultingProfileFingerprint: string
  expectedBundles: string[]
}

export type LifecycleAction = 'install' | 'update' | 'uninstall' | 'repair' | 'rollback' | 'legacy-import'

export interface ManagedPluginV1 {
  schemaVersion: 1
  packageName: string
  version: string
  reportId: string
  artifactSha256: string
  installedAt: string
  updatedAt: string
  bundles: string[]
}

export interface ProfileGenerationV1 {
  schemaVersion: 1
  id: string
  profile: string
  createdAt: string
  action: LifecycleAction
  parentGenerationId?: string
  restoredGenerationId?: string
  reportId?: string
  packageName?: string
  profileFingerprint: string
  configHash?: string
  bundles: string[]
  plugins: ManagedPluginV1[]
}

export interface ManagedProfileV1 {
  schemaVersion: 1
  profile: string
  createdAt: string
  updatedAt: string
  lastVerifiedAt?: string
  currentGenerationId: string
  generations: ProfileGenerationV1[]
}

export interface ManagedProfileViewV1 {
  schemaVersion: 1
  profile: string
  generationId: string
  state: GuardStatus
  detail: string
  plugins: ManagedPluginV1[]
  generationCount: number
}

export interface LifecycleOperationResultV1 {
  schemaVersion: 1
  action: 'uninstall' | 'repair' | 'rollback'
  profile: string
  generationId: string
  previousGenerationId: string
  packageName?: string
  restoredGenerationId?: string
  backupPath?: string
  noOp: boolean
}

export interface GenerationSnapshotFileV1 {
  name: 'package.json' | 'pnpm-lock.yaml' | 'pnpm-workspace.yaml' | 'cordis.yml' | 'cordis.patch.yml'
  present: boolean
  sha256?: string
}

export interface GenerationSnapshotManifestV1 {
  schemaVersion: 1
  profile: string
  generationId: string
  createdAt: string
  profileFingerprint: string
  files: GenerationSnapshotFileV1[]
}

export interface GuardEvent {
  schemaVersion: 1
  id: string
  createdAt: string
  severity: 'high'
  type:
    | 'verified-to-drifted'
    | 'unmanaged-plugin'
    | 'protected-config-changed'
    | 'needs-repair'
    | 'repeated-tool-denial'
  fingerprint: string
  title: string
  detail: string
  profile?: string
  acknowledgedAt?: string
}

export interface GuardStatusSnapshot {
  schemaVersion: 1
  generatedAt: string
  status: GuardStatus
  label: string
  detail: string
  profile: string
  lastVerifiedAt?: string
  reportId?: string
  counts: {
    reports: number
    review: number
    blocked: number
    activeAlerts: number
  }
  events: GuardEvent[]
  managedPackages: Array<{name: string; version: string; state: GuardStatus}>
}

export interface Policy {
  schemaVersion: 1
  id: string
  denyCapabilities: Capability[]
  reviewCapabilities: Capability[]
  protectedEntryIds: string[]
  protectedModulePrefixes: string[]
  maxArchiveBytes: number
  maxFiles: number
  maxSourceFileBytes: number
}

export interface ScanOptions {
  profile: string
  dshHome?: string
  stateHome?: string
  policy?: Policy
  stage?: boolean
}

export interface VerifyResult {
  status: GuardStatus
  profile: ProfileSnapshot
  expected?: InstallRecord
  detail: string
  unmanagedBundles: string[]
  managedPlugins?: ManagedPluginV1[]
  generationId?: string
  lastVerifiedAt?: string
  reportId?: string
}
