/**
 * dsh-poison-guard - pre-install supply-chain scanner for DeepSeek Harness
 * plugins.
 *
 * THREAT MODEL (be honest): this is a static analyzer, not a sandbox. It runs
 * three layers - AST analysis (NodeSecure JS-X-Ray), a deobfuscation decoder,
 * and a regex heuristic fallback - to flag poisoning signatures a novice would
 * never notice. A determined attacker can still obfuscate past any static
 * tool (this is undecidable by Rice's theorem), so it reduces risk rather than
 * eliminating it. The real boundary is the harness sandbox: keep untrusted
 * plugins in workspace-write, never danger-full-access.
 *
 * @module dsh-poison-guard
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { AstAnalyser, TsSourceParser, type Warning } from '@nodesecure/js-x-ray'
import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW'

export interface Finding {
  rule: string
  severity: Severity
  file: string
  line: number
  hint: string
}

export type Verdict = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS'

export interface ScanStats {
  files: number
  sourceFiles: number
  astWarnings: number
  deobfuscatedFragments: number
}

export interface Report {
  verdict: Verdict
  findings: Finding[]
  summary: string
  stats: ScanStats
}

interface Rule {
  id: string
  severity: Severity
  re: RegExp
  hint: string
}

/** Regex heuristics - a fallback for non-code files and obvious literals. */
const RULES: Rule[] = [
  {
    id: 'exfil-keys',
    severity: 'HIGH',
    re: /(?:~\/|home\/|\b)(?:\.ssh|\.aws|\.gnupg|\.npmrc|\.gitconfig)|\b(?:id_rsa|id_ed25519|id_ecdsa|\.pem)\b|BEGIN [A-Z ]*PRIVATE KEY/i,
    hint: 'touches SSH/AWS/GPG private keys or PEM material',
  },
  {
    id: 'exfil-secrets',
    severity: 'HIGH',
    re: /(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTHORIZATION|PRIVATE[_-]?KEY)/i,
    hint: 'references credential-style names; combined with network egress this is exfiltration',
  },
  {
    id: 'dynamic-eval',
    severity: 'HIGH',
    re: /\beval\s*\(|new\s+Function\s*\(|Function\s*\([^)]*\)\s*\{|\bvm\.runIn/i,
    hint: 'dynamic code execution (eval / new Function / vm) - a common obfuscation gateway',
  },
  {
    id: 'network-egress',
    severity: 'MEDIUM',
    re: /\bfetch\s*\(|https?\.(?:request|get)\s*\(|\bnet\.connect\s*\(|\bWebSocket\b|\baxios\b|\bgot\s*\(|\bcurl\b|\bwget\b/i,
    hint: 'makes outbound network requests',
  },
  {
    id: 'child-process',
    severity: 'MEDIUM',
    re: /child_process|\bspawn(?:Sync)?\s*\(|\bexec(?:Sync|File)?\s*\(|\bfork\s*\(/i,
    hint: 'spawns subprocesses / executes commands',
  },
  {
    id: 'env-read',
    severity: 'LOW',
    re: /process\.env/i,
    hint: 'reads environment variables',
  },
  {
    id: 'obfuscation',
    severity: 'LOW',
    re: /\batob\s*\(|\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\)/i,
    hint: 'base64-decoded data (possible obfuscation)',
  },
]

/** Install-time scripts that run arbitrary code before you ever load the plugin. */
const INSTALL_SCRIPTS = ['prepare', 'postinstall', 'install', 'preinstall']

/** js-x-ray warning kind -> our severity. Anything unmapped falls back to the
 *  warning's own severity. */
const AST_SEVERITY: Record<string, Severity> = {
  'data-exfiltration': 'HIGH',
  'unsafe-stmt': 'HIGH',
  'unsafe-command': 'HIGH',
  'unsafe-import': 'HIGH',
  'unsafe-vm-context': 'HIGH',
  'obfuscated-code': 'HIGH',
  'suspicious-file': 'HIGH',
  'serialize-environment': 'MEDIUM',
  'suspicious-literal': 'MEDIUM',
  'shady-link': 'MEDIUM',
  'sql-injection': 'MEDIUM',
  'monkey-patch': 'MEDIUM',
  'prototype-pollution': 'MEDIUM',
  'unsafe-regex': 'LOW',
  'short-identifiers': 'LOW',
  'encoded-literal': 'LOW',
  'crypto.weak-algorithm': 'LOW',
  'insecure-random': 'LOW',
  'parsing-error': 'LOW',
}

const AST_HINTS: Record<string, string> = {
  'data-exfiltration': 'exfiltration of sensitive data (private paths or serialized system info)',
  'unsafe-stmt': 'dynamic code execution via eval() / Function() / vm',
  'unsafe-command': 'shell command embedded in spawn()/exec()',
  'unsafe-import': 'obfuscated or untraceable import (require/import of a computed value)',
  'unsafe-vm-context': 'runs code in an unsafe vm context',
  'obfuscated-code': 'obfuscated code detected',
  'suspicious-file': 'file with many encoded literals (likely obfuscated)',
  'serialize-environment': 'reads/serializes process.env (potential secret harvest)',
  'suspicious-literal': 'suspicious literal value',
  'shady-link': 'suspicious or malicious URL',
  'sql-injection': 'possible SQL injection sink',
  'monkey-patch': 'modifies built-in prototypes',
  'prototype-pollution': 'attempts prototype pollution via __proto__',
  'unsafe-regex': 'regular expression vulnerable to ReDoS',
  'short-identifiers': 'identifiers are extremely short (obfuscation signal)',
  'encoded-literal': 'encoded literal (hex/unicode/base64)',
  'crypto.weak-algorithm': 'weak cryptographic algorithm',
  'insecure-random': 'uses a non-cryptographic random source',
  'parsing-error': 'source could not be parsed',
}

function severityRank(severity: Severity): number {
  return severity === 'HIGH' ? 3 : severity === 'MEDIUM' ? 2 : 1
}

function findingsForText(text: string, file: string): Finding[] {
  const out: Finding[] = []
  const lines = text.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const rule of RULES) {
      if (rule.re.test(line)) {
        out.push({ rule: rule.id, severity: rule.severity, file, line: i + 1, hint: rule.hint })
      }
    }
  }
  return out
}

/* ── AST layer (NodeSecure JS-X-Ray) ─────────────────────────────────────── */

function warningLine(loc: Warning['location']): number {
  if (!loc || !Array.isArray(loc)) return 0
  const first = loc[0]
  if (Array.isArray(first)) {
    if (Array.isArray(first[0])) return (first[0] as unknown as number[])[0]
    return first[0]
  }
  return 0
}

function warningSeverity(kind: string, fallback: Warning['severity']): Severity {
  if (kind in AST_SEVERITY) return AST_SEVERITY[kind]
  if (fallback === 'Critical') return 'HIGH'
  if (fallback === 'Warning') return 'MEDIUM'
  return 'LOW'
}

function analyseSource(
  text: string,
  file: string,
  analyser: AstAnalyser,
  tsParser: TsSourceParser,
): Finding[] {
  const isTs = /\.tsx?$/i.test(file)
  let report
  try {
    report = analyser.analyse(text, {
      location: file,
      ...(isTs ? { customParser: tsParser } : {}),
    })
  } catch (err) {
    return [{
      rule: 'ast/parsing-error',
      severity: 'LOW',
      file,
      line: 1,
      hint: `could not parse for AST analysis: ${err instanceof Error ? err.message : String(err)}`,
    }]
  }

  const out: Finding[] = []
  for (const w of report.warnings) {
    let hint = AST_HINTS[w.kind] ?? w.kind
    if (typeof w.value === 'string' && w.value.trim() !== '' && w.value.length < 240) {
      hint += ` - ${w.value}`
    }
    out.push({
      rule: `ast/${w.kind}`,
      severity: warningSeverity(w.kind, w.severity),
      file,
      line: warningLine(w.location),
      hint,
    })
  }
  return out
}

/* ── Deobfuscation decoder ───────────────────────────────────────────────── */

function decodeBase64(s: string): string | null {
  try {
    const buf = Buffer.from(s, 'base64')
    if (buf.length === 0) return null
    const str = buf.toString('utf8')
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(str)) return null
    return str
  } catch {
    return null
  }
}

function decodeHex(s: string): string | null {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(s)) return null
  try {
    const str = Buffer.from(s, 'hex').toString('utf8')
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(str)) return null
    return str
  } catch {
    return null
  }
}

function decodeEscapes(run: string): string {
  return run
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_m, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)))
}

interface Decoded {
  decoded: string
  line: number
}

function lineAt(text: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++
  }
  return line
}

/** Pull hidden strings out of common obfuscation wrappers and return decoded text. */
function decodeFragments(text: string): Decoded[] {
  const out: Decoded[] = []
  const push = (decoded: string, index: number) => {
    const clean = decoded.trim()
    if (clean.length < 3) return
    out.push({ decoded: clean, line: lineAt(text, index) })
  }

  let m: RegExpExecArray | null

  // atob("...") / atob('...')
  const atobRe = /\batob\s*\(\s*(['"`])([A-Za-z0-9+/=]+)\1\s*\)/g
  while ((m = atobRe.exec(text)) !== null) {
    const d = decodeBase64(m[2])
    if (d) push(d, m.index)
  }

  // Buffer.from("...", "base64" | "hex")
  const bufRe = /Buffer\.from\s*\(\s*(['"`])([^'"`]+)\1\s*,\s*(['"`])(base64|hex)\3\s*\)/gi
  while ((m = bufRe.exec(text)) !== null) {
    const kind = m[4].toLowerCase()
    const d = kind === 'hex' ? decodeHex(m[2]) : decodeBase64(m[2])
    if (d) push(d, m.index)
  }

  // String.fromCharCode(65,66,67) / String.fromCharCode([65,66,67])
  const fccRe = /String\.fromCharCode\s*\(\s*([^)]*)\)/g
  while ((m = fccRe.exec(text)) !== null) {
    const nums = m[1].match(/(?:0x[0-9a-fA-F]+|\d+)/g)
    if (nums && nums.length >= 3) {
      try {
        const str = nums.map(n => String.fromCharCode(n.startsWith('0x') ? parseInt(n, 16) : parseInt(n, 10))).join('')
        push(str, m.index)
      } catch {
        // ignore malformed fromCharCode
      }
    }
  }

  // runs of \xNN / \uNNNN / \u{NN} escapes
  const escRe = /(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}){2,}/g
  while ((m = escRe.exec(text)) !== null) {
    push(decodeEscapes(m[0]), m.index)
  }

  return out
}

const SECRET_RE = /(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTHORIZATION|PRIVATE[_-]?KEY|BEGIN [A-Z ]*PRIVATE KEY)/i
const KEYPATH_RE = /(?:~\/|home\/|\b)(?:\.ssh|\.aws|\.gnupg|\.npmrc|\.gitconfig)|\b(?:id_rsa|id_ed25519|id_ecdsa|\.pem)\b/i
const URL_RE = /https?:\/\/[^\s"'`<>]+/i
const CMD_RE = /\b(?:curl|wget|nc|ncat|netcat|bash\s+-c|sh\s+-c|powershell|iwr|base64\s+-[dD])\b/i

function findingsForDecoded(fragments: Decoded[], file: string): Finding[] {
  const out: Finding[] = []
  for (const f of fragments) {
    if (SECRET_RE.test(f.decoded)) {
      out.push({ rule: 'deobfuscated-secret', severity: 'HIGH', file, line: f.line, hint: `decoded obfuscated credential reference: ${truncate(f.decoded)}` })
    }
    if (KEYPATH_RE.test(f.decoded)) {
      out.push({ rule: 'deobfuscated-key', severity: 'HIGH', file, line: f.line, hint: `decoded obfuscated private-key path: ${truncate(f.decoded)}` })
    }
    if (URL_RE.test(f.decoded)) {
      out.push({ rule: 'deobfuscated-url', severity: 'MEDIUM', file, line: f.line, hint: `decoded obfuscated URL: ${truncate(f.decoded)}` })
    }
    if (CMD_RE.test(f.decoded)) {
      out.push({ rule: 'deobfuscated-command', severity: 'HIGH', file, line: f.line, hint: `decoded obfuscated shell command: ${truncate(f.decoded)}` })
    }
  }
  return out
}

function truncate(s: string, max = 160): string {
  const one = s.replace(/\s+/g, ' ').trim()
  return one.length > max ? one.slice(0, max) + '...' : one
}

/* ── Public scanner ──────────────────────────────────────────────────────── */

const SOURCE_EXT = /\.(js|ts|mjs|cjs|jsx|tsx)$/i

/**
 * Scan a plugin's source files + package manifest. `files` maps a relative
 * path to its text contents.
 */
export function scanPlugin(files: Record<string, string>): Report {
  const findings: Finding[] = []
  const analyser = new AstAnalyser({ sensitivity: 'aggressive' })
  const tsParser = new TsSourceParser()

  let astWarnings = 0
  let deobfuscatedFragments = 0
  let sourceFiles = 0

  const pkgPath = Object.keys(files).find(p => p === 'package.json' || p.endsWith('/package.json'))
  if (pkgPath) {
    try {
      const pkg = JSON.parse(files[pkgPath]) as { scripts?: Record<string, string> }
      for (const name of INSTALL_SCRIPTS) {
        const script = pkg.scripts?.[name]
        if (typeof script === 'string' && script.trim() !== '') {
          for (const rule of RULES) {
            if (rule.re.test(script)) {
              findings.push({
                rule: `install-script/${rule.id}`,
                severity: rule.severity,
                file: pkgPath,
                line: 1,
                hint: `the "${name}" script ${rule.hint.toLowerCase()}`,
              })
            }
          }
          findings.push({
            rule: 'install-script',
            severity: 'MEDIUM',
            file: pkgPath,
            line: 1,
            hint: `declares a "${name}" script (runs arbitrary code at install time)`,
          })
        }
      }
    } catch {
      findings.push({ rule: 'bad-manifest', severity: 'MEDIUM', file: pkgPath, line: 1, hint: 'package.json is not valid JSON' })
    }
  }

  for (const [file, text] of Object.entries(files)) {
    const isSource = SOURCE_EXT.test(file)
    if (isSource) sourceFiles++

    if (isSource && text.length <= 2 * 1024 * 1024) {
      const ast = analyseSource(text, file, analyser, tsParser)
      astWarnings += ast.length
      findings.push(...ast)

      const decoded = decodeFragments(text)
      deobfuscatedFragments += decoded.length
      findings.push(...findingsForDecoded(decoded, file))
    }

    // Regex fallback for every file (catches non-code files and obvious literals).
    findings.push(...findingsForText(text, file))
  }

  const hasSecrets = findings.some(f =>
    f.rule === 'exfil-secrets'
    || f.rule === 'exfil-keys'
    || f.rule === 'deobfuscated-secret'
    || f.rule === 'deobfuscated-key'
    || f.rule === 'ast/data-exfiltration'
    || f.rule === 'ast/serialize-environment'
    || f.rule === 'env-read',
  )
  const hasNetwork = findings.some(f =>
    f.rule === 'network-egress'
    || f.rule === 'deobfuscated-url'
    || f.rule === 'ast/shady-link'
    || f.rule === 'ast/data-exfiltration',
  )
  if (hasSecrets && hasNetwork) {
    findings.push({
      rule: 'exfil-combo',
      severity: 'HIGH',
      file: '(whole plugin)',
      line: 0,
      hint: 'reads credentials/secrets AND makes network requests - the classic exfiltration shape',
    })
  }

  const dedup = new Map<string, Finding>()
  for (const f of findings) dedup.set(`${f.rule}:${f.file}:${f.line}:${f.hint}`, f)
  const unique = [...dedup.values()].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))

  const high = unique.filter(f => f.severity === 'HIGH')
  const medium = unique.filter(f => f.severity === 'MEDIUM')
  const verdict: Verdict = high.length > 0 ? 'MALICIOUS' : medium.length > 0 ? 'SUSPICIOUS' : 'CLEAN'
  const summary = verdict === 'CLEAN'
    ? 'no obvious poisoning signature found (static scan is not a guarantee)'
    : `${high.length} high / ${medium.length} medium / ${unique.filter(f => f.severity === 'LOW').length} low finding(s)`

  return {
    verdict,
    findings: unique,
    summary,
    stats: {
      files: Object.keys(files).length,
      sourceFiles,
      astWarnings,
      deobfuscatedFragments,
    },
  }
}

/* ── in-DSH tool ── */

export const name = 'dsh-poison-guard'
export const inject = ['tools']

const SKIP_DIRS = new Set(['node_modules', '.git', '.pnpm', '.store'])

function collectFiles(root: string): Record<string, string> {
  const files: Record<string, string> = {}
  const walk = (dir: string, depth: number): void => {
    if (depth > 8) return
    let entries: string[] = []
    try { entries = readdirSync(dir) } catch { return }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry)) continue
      const full = join(dir, entry)
      let stat
      try { stat = statSync(full) } catch { continue }
      if (stat.isDirectory()) { walk(full, depth + 1); continue }
      if (stat.size > 2 * 1024 * 1024) continue
      try {
        files[relative(root, full).replaceAll('\\', '/')] = readFileSync(full, 'utf8')
      } catch { /* binary / unreadable */ }
    }
  }
  walk(root, 0)
  return files
}

export function apply(ctx: Context): void {
  ctx.tools.register(defineTool({
    name: 'plugin_scan',
    description:
      'Statically scan a DeepSeek Harness plugin directory for supply-chain '
      + 'poisoning signals using AST analysis (NodeSecure JS-X-Ray), a '
      + 'deobfuscation decoder, and regex heuristics. Detects credential '
      + 'exfiltration, dynamic code execution, obfuscated imports, install-time '
      + 'scripts, and network egress. Heuristic only - not a security guarantee.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path to the plugin directory' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const report = scanPlugin(collectFiles(String(args.path)))
      const lines = [
        `verdict: ${report.verdict}`,
        report.summary,
        `engine: AST(x-ray) + deobfuscation + regex | ${report.stats.sourceFiles} source file(s), ${report.stats.astWarnings} AST warning(s), ${report.stats.deobfuscatedFragments} decoded fragment(s)`,
        '',
      ]
      for (const f of report.findings) {
        lines.push(`[${f.severity}] ${f.rule}  ${f.file}:${f.line} - ${f.hint}`)
      }
      if (report.findings.length === 0) lines.push('(no findings)')
      lines.push('', 'Static analysis only: obfuscated code can still bypass it. Keep untrusted plugins in workspace-write, never danger-full-access.')
      return lines.join('\n')
    },
    presentCall: (args) => ({ card: 'generic', title: `scan plugin · ${args.path}`, kind: 'other', rawInput: args }),
  }))
}
