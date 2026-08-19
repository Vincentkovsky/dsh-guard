import { parse } from '@babel/parser'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { parseDocument } from 'yaml'
import type { Capability, Finding, Policy } from './types.js'
import { sanitizeText, sha256 } from './util.js'

type PackageJson = {
  name?: string
  version?: string
  main?: string
  module?: string
  exports?: unknown
  bin?: string | Record<string, string>
  scripts?: Record<string, string>
  dependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
  bundledDependencies?: string[]
  bundleDependencies?: string[]
  dsh?: { bundle?: { patch?: string }; client?: unknown; profile?: unknown }
}

const SOURCE_EXTENSIONS = /\.(?:[cm]?[jt]sx?)$/i
const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack']

function flattenExports(value: unknown, output: string[] = []): string[] {
  if (typeof value === 'string') output.push(value)
  else if (Array.isArray(value)) value.forEach((child) => flattenExports(child, output))
  else if (value && typeof value === 'object') Object.values(value as Record<string, unknown>).forEach((child) => flattenExports(child, output))
  return output
}

function walk(node: unknown, visit: (node: Record<string, unknown>) => void): void {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) { node.forEach((child) => walk(child, visit)); return }
  const record = node as Record<string, unknown>
  if (typeof record.type === 'string') visit(record)
  for (const [key, value] of Object.entries(record)) {
    if (key !== 'loc' && key !== 'tokens' && key !== 'comments') walk(value, visit)
  }
}

function memberName(node: Record<string, unknown>): string | undefined {
  if (node.type === 'Identifier') return String(node.name)
  if (node.type === 'StringLiteral') return String(node.value)
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    const object = memberName(node.object as Record<string, unknown>)
    const property = memberName(node.property as Record<string, unknown>)
    return object && property ? `${object}.${property}` : undefined
  }
  return undefined
}

function stringValue(node: unknown): string | undefined {
  const record = node as Record<string, unknown> | undefined
  return record?.type === 'StringLiteral' || record?.type === 'Literal' ? String(record.value) : undefined
}

function location(node: Record<string, unknown>): number | undefined {
  const loc = node.loc as { start?: { line?: number } } | undefined
  return loc?.start?.line
}

function capabilityFinding(file: string, line: number | undefined, capability: Capability, detail: string, policy: Policy): Finding {
  const severity = policy.denyCapabilities.includes(capability) ? 'blocked' : policy.reviewCapabilities.includes(capability) ? 'review' : 'info'
  return {
    id: `capability.${capability}`,
    severity,
    category: 'code',
    capability,
    title: `Capability: ${capability}`,
    detail,
    evidence: { file, ...(line ? { line } : {}) },
  }
}

function classifyModule(source: string): Array<{ capability: Capability; detail: string }> {
  if (/^(?:node:)?(?:fs|fs\/promises)$/.test(source)) return [{ capability: 'filesystem-read', detail: `Imports ${source}` }]
  if (/^(?:node:)?child_process$/.test(source)) return [{ capability: 'subprocess', detail: `Imports ${source}` }]
  if (/^(?:node:)?(?:net|tls)$/.test(source)) return [{ capability: 'network-client', detail: `Imports ${source}` }, { capability: 'network-listen', detail: `Imports ${source}` }]
  if (/^(?:node:)?(?:http|https|http2|dns|dgram)$/.test(source) || /^(?:undici|axios|got|node-fetch)(?:\/|$)/.test(source)) return [{ capability: 'network-client', detail: `Imports ${source}` }]
  if (/^(?:node:)?(?:vm|module)$/.test(source)) return [{ capability: 'dynamic-code', detail: `Imports ${source}` }]
  if (/^(?:node:)?(?:worker_threads|cluster)$/.test(source)) return [{ capability: 'external-code', detail: `Imports ${source}` }]
  return []
}

async function scanSource(root: string, file: string, policy: Policy, rootEntrypoint: boolean): Promise<Finding[]> {
  const findings: Finding[] = []
  const source = await readFile(join(root, file), 'utf8')
  if (Buffer.byteLength(source) > policy.maxSourceFileBytes) {
    return [{ id: 'code.too-large', severity: 'review', category: 'code', title: 'Source file exceeds analysis budget', detail: `${file} is too large for AST analysis`, evidence: { file, sha256: sha256(source) } }]
  }
  let ast: ReturnType<typeof parse>
  try {
    ast = parse(source, { sourceType: 'unambiguous', errorRecovery: false, plugins: ['typescript', 'jsx', 'decorators-legacy', 'importAttributes', 'topLevelAwait'] })
  } catch (error) {
    return [{
      id: 'code.parse-error', severity: rootEntrypoint ? 'blocked' : 'review', category: 'code',
      title: rootEntrypoint ? 'Root entrypoint cannot be parsed' : 'Source file cannot be parsed',
      detail: sanitizeText((error as Error).message), evidence: { file, sha256: sha256(source) },
    }]
  }
  const seen = new Set<string>()
  const add = (finding: Finding) => {
    const key = `${finding.id}:${finding.evidence?.line ?? 0}`
    if (!seen.has(key)) { seen.add(key); findings.push(finding) }
  }
  walk(ast, (node) => {
    const line = location(node)
    if (node.type === 'ImportDeclaration' || node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') {
      const sourceName = stringValue(node.source)
      if (sourceName) classifyModule(sourceName).forEach((item) => add(capabilityFinding(file, line, item.capability, item.detail, policy)))
    }
    if (node.type === 'CallExpression' || node.type === 'NewExpression' || node.type === 'OptionalCallExpression') {
      const callee = memberName(node.callee as Record<string, unknown>)
      const args = node.arguments as unknown[] | undefined
      if (callee === 'require') {
        const moduleName = stringValue(args?.[0])
        if (moduleName) classifyModule(moduleName).forEach((item) => add(capabilityFinding(file, line, item.capability, item.detail, policy)))
      }
      if (callee === 'eval' || callee === 'Function' || callee === 'globalThis.eval' || callee?.startsWith('vm.')) add(capabilityFinding(file, line, 'dynamic-code', `Calls ${callee}`, policy))
      if (callee === 'fetch' || callee?.startsWith('axios.') || callee?.startsWith('https.') || callee?.startsWith('http.')) add(capabilityFinding(file, line, 'network-client', `Calls ${callee}`, policy))
      if (/\.(?:createServer|listen)$/.test(callee ?? '')) add(capabilityFinding(file, line, 'network-listen', `Calls ${callee}`, policy))
      if (/^(?:child_process\.)?(?:exec|execFile|spawn|fork|execSync|spawnSync)$/.test(callee ?? '')) add(capabilityFinding(file, line, 'subprocess', `Calls ${callee}`, policy))
      if (/\.(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rename|renameSync|chmod|chmodSync)$/.test(callee ?? '')) add(capabilityFinding(file, line, 'filesystem-write', `Calls ${callee}`, policy))
      if (/\.(?:readFile|readFileSync|readdir|readdirSync|stat|statSync|lstat|lstatSync)$/.test(callee ?? '')) add(capabilityFinding(file, line, 'filesystem-read', `Calls ${callee}`, policy))
      if (/\.(?:register|provide)$/.test(callee ?? '') && /(?:tools|toolRuntime)/i.test(callee ?? '')) add(capabilityFinding(file, line, 'tool-register', `Calls ${callee}`, policy))
      if (callee === 'registerTool' || callee === 'harness.registerTool') add(capabilityFinding(file, line, 'tool-register', `Calls ${callee}`, policy))
    }
    if (node.type === 'ImportExpression') add(capabilityFinding(file, line, 'dynamic-code', 'Uses dynamic import()', policy))
    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      const name = memberName(node)
      if (name === 'process.env' || name?.startsWith('process.env.')) {
        add(capabilityFinding(file, line, /(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/i.test(name) ? 'credentials' : 'environment', `Reads ${name}`, policy))
      }
    }
  })
  const veryLongLines = source.split(/\r?\n/).filter((line) => line.length > 10_000).length
  if (veryLongLines > 0) findings.push({ id: 'code.obfuscation', severity: 'review', category: 'code', title: 'Possible generated or obfuscated code', detail: `${veryLongLines} line(s) exceed 10,000 characters`, evidence: { file, sha256: sha256(source) } })
  return findings
}

function scanManifest(pkg: PackageJson, files: Set<string>): Finding[] {
  const findings: Finding[] = []
  for (const name of LIFECYCLE) {
    const command = pkg.scripts?.[name]
    if (command) findings.push({ id: `manifest.script.${name}`, severity: 'review', category: 'manifest', title: `Lifecycle script: ${name}`, detail: sanitizeText(command), evidence: { file: 'package.json' } })
  }
  const nativeDeps = Object.keys({ ...pkg.dependencies, ...pkg.optionalDependencies }).filter((name) => /(?:node-gyp|prebuild|bindings|ffi|native|sqlite3|sharp|canvas|keytar)/i.test(name))
  for (const dependency of nativeDeps) findings.push({ id: 'manifest.native-dependency', severity: 'review', category: 'manifest', title: 'Native-code dependency', detail: dependency, capability: 'native-code', evidence: { file: 'package.json' } })
  if (pkg.dsh?.profile) findings.push({ id: 'manifest.profile-override', severity: 'blocked', category: 'manifest', title: 'Candidate declares a DSH profile', detail: 'Installable plugins must not replace the target profile.', capability: 'profile-override', evidence: { file: 'package.json' } })
  const primary = pkg.main ?? pkg.module
  if (primary && !files.has(primary.replace(/^\.\//, '')) && LIFECYCLE.some((name) => pkg.scripts?.[name])) {
    findings.push({ id: 'manifest.missing-build-output', severity: 'blocked', category: 'manifest', title: 'Published entrypoint is missing', detail: `${primary} is absent and would require running lifecycle scripts`, evidence: { file: 'package.json' } })
  }
  if (pkg.bundledDependencies?.length || pkg.bundleDependencies?.length) findings.push({ id: 'manifest.bundled-dependencies', severity: 'review', category: 'manifest', title: 'Bundled dependencies included', detail: [...(pkg.bundledDependencies ?? []), ...(pkg.bundleDependencies ?? [])].join(', '), evidence: { file: 'package.json' } })
  return findings
}

async function scanPatch(root: string, patchPath: string, policy: Policy): Promise<Finding[]> {
  const file = patchPath.replace(/^\.\//, '')
  let source: string
  try { source = await readFile(join(root, file), 'utf8') }
  catch { return [{ id: 'patch.missing', severity: 'blocked', category: 'manifest', title: 'DSH bundle patch is missing', detail: file, evidence: { file: 'package.json' } }] }
  const findings: Finding[] = []
  const document = parseDocument(source, { prettyErrors: false })
  if (document.errors.length > 0) return [{ id: 'patch.parse-error', severity: 'blocked', category: 'manifest', title: 'DSH patch cannot be parsed lexically', detail: sanitizeText(document.errors[0]?.message), evidence: { file, sha256: sha256(source) } }]
  if (/!!js\b/.test(source)) findings.push({ id: 'patch.javascript-tag', severity: 'review', category: 'manifest', title: 'Patch contains !!js expressions', detail: 'Expressions were treated as text and were not evaluated by the scanner.', capability: 'dynamic-code', evidence: { file } })
  for (const id of policy.protectedEntryIds) {
    const expression = new RegExp(`(?:^|\\n)\\s*-?\\s*id:\\s*["']?${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?\\s*(?:#.*)?$`, 'm')
    if (expression.test(source)) findings.push({ id: 'patch.protected-entry', severity: 'blocked', category: 'profile', title: 'Patch targets a protected DSH entry', detail: id, capability: 'profile-override', evidence: { file } })
  }
  for (const prefix of policy.protectedModulePrefixes) {
    if (source.includes(prefix)) findings.push({ id: 'patch.protected-module', severity: 'blocked', category: 'profile', title: 'Patch references a protected DSH module', detail: prefix, capability: 'profile-override', evidence: { file } })
  }
  return findings
}

export interface PackageScan {
  manifest: PackageJson
  entrypoints: string[]
  dependencyGraph: Record<string, string>
  findings: Finding[]
}

export async function scanPackage(root: string, filePaths: string[], policy: Policy): Promise<PackageScan> {
  const manifestText = await readFile(join(root, 'package.json'), 'utf8')
  let manifest: PackageJson
  try { manifest = JSON.parse(manifestText) as PackageJson }
  catch (error) { throw new Error(`Invalid package.json: ${sanitizeText((error as Error).message)}`) }
  if (!manifest.name || !manifest.version) throw new Error('package.json must contain name and version')
  const files = new Set(filePaths)
  const entrypoints = [...new Set([
    manifest.main,
    manifest.module,
    ...flattenExports(manifest.exports),
    ...(typeof manifest.bin === 'string' ? [manifest.bin] : Object.values(manifest.bin ?? {})),
    manifest.dsh?.bundle?.patch,
  ].filter((value): value is string => typeof value === 'string').map((value) => value.replace(/^\.\//, '')))]
  const rootEntries = new Set(entrypoints.filter((file) => SOURCE_EXTENSIONS.test(file)))
  const sourceFiles = filePaths.filter((file) => SOURCE_EXTENSIONS.test(file)).sort()
  const findings = scanManifest(manifest, files)
  if (!manifest.dsh?.bundle?.patch && !manifest.dsh?.client) findings.push({ id: 'manifest.not-dsh-plugin', severity: 'review', category: 'manifest', title: 'No DSH bundle or client declaration', detail: 'The package may be a dependency rather than a directly installable DSH plugin.', evidence: { file: 'package.json' } })
  if (manifest.dsh?.client) {
    const exported = manifest.exports && typeof manifest.exports === 'object' ? manifest.exports as Record<string, unknown> : {}
    if (!exported['./client']) findings.push({ id: 'manifest.client-export-missing', severity: 'blocked', category: 'manifest', title: 'dsh.client has no ./client export', detail: 'DSH cannot serve the browser bundle without exports["./client"].', evidence: { file: 'package.json' } })
    if (!exported['./package.json']) findings.push({ id: 'manifest.package-export-missing', severity: 'blocked', category: 'manifest', title: 'package.json is not exported', detail: 'DSH client module discovery resolves <package>/package.json; the export is required when package exports are restricted.', evidence: { file: 'package.json' } })
  }
  if (manifest.dsh?.bundle?.patch) findings.push(...await scanPatch(root, manifest.dsh.bundle.patch, policy))
  for (const file of sourceFiles) findings.push(...await scanSource(root, file, policy, rootEntries.has(file)))
  for (const entry of rootEntries) {
    if (!files.has(entry)) findings.push({ id: 'manifest.missing-entrypoint', severity: 'blocked', category: 'manifest', title: 'Declared entrypoint is missing', detail: entry, evidence: { file: 'package.json' } })
  }
  const dependencyGraph = { ...(manifest.dependencies ?? {}), ...(manifest.optionalDependencies ?? {}) }
  return { manifest, entrypoints, dependencyGraph, findings }
}
