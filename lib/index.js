/**
 * dsh-poison-guard — pre-install supply-chain scanner for DeepSeek Harness
 * plugins.
 *
 * THREAT MODEL (be honest): this is a static, heuristic scanner. It flags
 * suspicious source patterns a novice would never notice, but a determined
 * attacker can obfuscate past it. It is a first line of defense, NOT a
 * security boundary — it reduces risk, it does not eliminate it. The real
 * boundary is the harness sandbox; keep untrusted plugins in workspace-write,
 * never danger-full-access.
 *
 * @module dsh-poison-guard
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { defineTool } from '@deepseek-ai/dsh-tools';
/** Patterns ordered roughly by blast radius. */
const RULES = [
    {
        id: 'exfil-keys',
        severity: 'HIGH',
        re: /(?:~\/|home\/|\b)(?:\.ssh|\.aws|\.gnupg)|\b(?:id_rsa|id_ed25519|id_ecdsa|\.pem)\b|BEGIN [A-Z ]*PRIVATE KEY/i,
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
        hint: 'dynamic code execution (eval / new Function / vm) — a common obfuscation gateway',
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
];
/** Install-time scripts that run arbitrary code before you ever load the plugin. */
const INSTALL_SCRIPTS = ['prepare', 'postinstall', 'install', 'preinstall'];
function findingsForText(text, file) {
    const out = [];
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const rule of RULES) {
            if (rule.re.test(line)) {
                out.push({ rule: rule.id, severity: rule.severity, file, line: i + 1, hint: rule.hint });
            }
        }
    }
    return out;
}
/**
 * Scan a plugin's source files + package manifest. `files` maps a relative
 * path to its text contents.
 */
export function scanPlugin(files) {
    const findings = [];
    const pkgPath = Object.keys(files).find(p => p === 'package.json' || p.endsWith('/package.json'));
    if (pkgPath) {
        try {
            const pkg = JSON.parse(files[pkgPath]);
            for (const name of INSTALL_SCRIPTS) {
                const script = pkg.scripts?.[name];
                if (typeof script === 'string' && script.trim() !== '') {
                    for (const rule of RULES) {
                        if (rule.re.test(script)) {
                            findings.push({
                                rule: `install-script/${rule.id}`,
                                severity: rule.severity,
                                file: pkgPath,
                                line: 1,
                                hint: `the "${name}" script ${rule.hint.toLowerCase()}`,
                            });
                        }
                    }
                    findings.push({
                        rule: 'install-script',
                        severity: 'MEDIUM',
                        file: pkgPath,
                        line: 1,
                        hint: `declares a "${name}" script (runs arbitrary code at install time)`,
                    });
                }
            }
        }
        catch {
            findings.push({ rule: 'bad-manifest', severity: 'MEDIUM', file: pkgPath, line: 1, hint: 'package.json is not valid JSON' });
        }
    }
    for (const [file, text] of Object.entries(files)) {
        if (/\.(js|ts|mjs|cjs|jsx|tsx)$/i.test(file)) {
            findings.push(...findingsForText(text, file));
        }
    }
    const hasSecrets = findings.some(f => f.rule.includes('exfil') || f.rule === 'env-read');
    const hasNetwork = findings.some(f => f.rule === 'network-egress' || f.rule.includes('network'));
    if (hasSecrets && hasNetwork) {
        findings.push({
            rule: 'exfil-combo',
            severity: 'HIGH',
            file: '(whole plugin)',
            line: 0,
            hint: 'reads credentials/secrets AND makes network requests — the classic exfiltration shape',
        });
    }
    const dedup = new Map();
    for (const f of findings)
        dedup.set(`${f.rule}:${f.file}:${f.line}`, f);
    const unique = [...dedup.values()].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    const high = unique.filter(f => f.severity === 'HIGH');
    const medium = unique.filter(f => f.severity === 'MEDIUM');
    const verdict = high.length > 0 ? 'MALICIOUS' : medium.length > 0 ? 'SUSPICIOUS' : 'CLEAN';
    const summary = verdict === 'CLEAN'
        ? 'no obvious poisoning signature found (static scan is not a guarantee)'
        : `${high.length} high / ${medium.length} medium / ${unique.filter(f => f.severity === 'LOW').length} low finding(s)`;
    return { verdict, findings: unique, summary };
}
function severityRank(severity) {
    return severity === 'HIGH' ? 3 : severity === 'MEDIUM' ? 2 : 1;
}
/* ── in-DSH tool ── */
export const name = 'dsh-poison-guard';
export const inject = ['tools'];
const SKIP_DIRS = new Set(['node_modules', '.git', '.pnpm', '.store']);
function collectFiles(root) {
    const files = {};
    const walk = (dir, depth) => {
        if (depth > 8)
            return;
        let entries = [];
        try {
            entries = readdirSync(dir);
        }
        catch {
            return;
        }
        for (const entry of entries) {
            if (SKIP_DIRS.has(entry))
                continue;
            const full = join(dir, entry);
            let stat;
            try {
                stat = statSync(full);
            }
            catch {
                continue;
            }
            if (stat.isDirectory()) {
                walk(full, depth + 1);
                continue;
            }
            if (stat.size > 2 * 1024 * 1024)
                continue;
            try {
                files[relative(root, full).replaceAll('\\', '/')] = readFileSync(full, 'utf8');
            }
            catch { /* binary / unreadable */ }
        }
    };
    walk(root, 0);
    return files;
}
export function apply(ctx) {
    ctx.tools.register(defineTool({
        name: 'plugin_scan',
        description: 'Statically scan a DeepSeek Harness plugin directory for supply-chain '
            + 'poisoning signals (credential exfiltration, dynamic code execution, '
            + 'install-time scripts, network egress). Heuristic only — not a security '
            + 'guarantee.',
        parameters: {
            path: { type: 'string', required: true, description: 'Absolute path to the plugin directory' },
        },
        output: {
            schema: { type: 'string' },
            render: (_args, value) => [{ type: 'text', text: value }],
        },
        async execute(args) {
            const report = scanPlugin(collectFiles(String(args.path)));
            const lines = [`verdict: ${report.verdict}`, report.summary, ''];
            for (const f of report.findings) {
                lines.push(`[${f.severity}] ${f.rule}  ${f.file}:${f.line} — ${f.hint}`);
            }
            if (report.findings.length === 0)
                lines.push('(no findings)');
            lines.push('', 'Heuristic scan only: obfuscated code can bypass it. Keep untrusted plugins in workspace-write, never danger-full-access.');
            return lines.join('\n');
        },
        presentCall: (args) => ({ card: 'generic', title: `scan plugin · ${args.path}`, kind: 'other', rawInput: args }),
    }));
}
