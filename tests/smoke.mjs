import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const bin = join(root, 'bin', 'poison-guard.mjs')

function scan(dir) {
  return spawnSync(process.execPath, [bin, 'scan', dir, '--json'], { encoding: 'utf8' })
}

const evil = scan(join(here, 'fixtures', 'evil'))
if (evil.status !== 1) {
  console.error('FAIL: evil fixture expected exit 1, got', evil.status)
  console.error(evil.stdout, evil.stderr)
  process.exit(1)
}
const evilReport = JSON.parse(evil.stdout)
if (evilReport.verdict !== 'MALICIOUS') {
  console.error('FAIL: evil fixture expected MALICIOUS, got', evilReport.verdict)
  process.exit(1)
}
for (const rule of ['deobfuscated-url', 'ast/unsafe-import', 'exfil-combo']) {
  if (!evilReport.findings.some(f => f.rule === rule)) {
    console.error(`FAIL: evil fixture missing expected rule ${rule}`)
    process.exit(1)
  }
}

const clean = scan(join(here, 'fixtures', 'clean'))
if (clean.status !== 0) {
  console.error('FAIL: clean fixture expected exit 0, got', clean.status)
  console.error(clean.stdout, clean.stderr)
  process.exit(1)
}
const cleanReport = JSON.parse(clean.stdout)
if (cleanReport.verdict !== 'CLEAN') {
  console.error('FAIL: clean fixture expected CLEAN, got', cleanReport.verdict)
  process.exit(1)
}

console.log('smoke ok: obfuscated malware -> MALICIOUS (exit 1), benign -> CLEAN (exit 0)')
