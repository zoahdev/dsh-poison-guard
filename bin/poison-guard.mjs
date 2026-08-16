#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { scanPlugin } from '../lib/index.js'

function usage() {
  process.stderr.write(`dsh-poison-guard — pre-install supply-chain scanner for DSH plugins

Usage:
  dsh-poison-guard scan <plugin-dir> [--json]
  (scans source files + package.json install scripts, prints a verdict)
`)
  process.exit(2)
}

const args = process.argv.slice(2)
const cmd = args[0]
if (cmd !== 'scan' || !args[1] || args.includes('--help')) usage()

const root = args[1]
const asJson = args.includes('--json')

const SKIP = new Set(['node_modules', '.git', '.pnpm', '.store'])
function walk(dir, depth) {
  if (depth > 8) return
  let entries = []
  try { entries = readdirSync(dir) } catch { return }
  for (const entry of entries) {
    if (SKIP.has(entry)) continue
    const full = join(dir, entry)
    let stat
    try { stat = statSync(full) } catch { continue }
    if (stat.isDirectory()) { walk(full, depth + 1); continue }
    if (stat.size > 2 * 1024 * 1024) continue // skip huge files (binaries, lockfiles)
    const rel = relative(root, full).replaceAll('\\', '/')
    try {
      files[rel] = readFileSync(full, 'utf8')
    } catch {
      // binary / unreadable — skip
    }
  }
}

const files = {}
walk(root, 0)
const report = scanPlugin(files)

if (asJson) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n')
} else {
  const label = { MALICIOUS: '🔴 MALICIOUS', SUSPICIOUS: '🟡 SUSPICIOUS', CLEAN: '🟢 CLEAN' }[report.verdict]
  process.stdout.write(`${label}  ${report.summary}\n\n`)
  for (const f of report.findings) {
    const sev = { HIGH: 'HIGH ', MEDIUM: 'MED  ', LOW: 'LOW  ' }[f.severity]
    process.stdout.write(`[${sev}] ${f.rule}  ${f.file}:${f.line}\n        ${f.hint}\n`)
  }
  if (report.findings.length === 0) process.stdout.write('(no findings)\n')
  process.stdout.write(`\n静态扫描≠安全保证；被混淆的恶意代码仍可能绕过。安装前请优先选用有 verified 标记、有维护者、来源明确的插件。\n`)
}

process.exit(report.verdict === 'CLEAN' ? 0 : 1)
