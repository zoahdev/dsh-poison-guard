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
import type { Context } from '@deepseek-ai/cordis';
export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';
export interface Finding {
    rule: string;
    severity: Severity;
    file: string;
    line: number;
    hint: string;
}
export type Verdict = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
export interface ScanStats {
    files: number;
    sourceFiles: number;
    astWarnings: number;
    deobfuscatedFragments: number;
}
export interface Report {
    verdict: Verdict;
    findings: Finding[];
    summary: string;
    stats: ScanStats;
}
/**
 * Scan a plugin's source files + package manifest. `files` maps a relative
 * path to its text contents.
 */
export declare function scanPlugin(files: Record<string, string>): Report;
export declare const name = "dsh-poison-guard";
export declare const inject: string[];
export declare function apply(ctx: Context): void;
