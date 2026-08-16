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
export interface Report {
    verdict: Verdict;
    findings: Finding[];
    summary: string;
}
/**
 * Scan a plugin's source files + package manifest. `files` maps a relative
 * path to its text contents.
 */
export declare function scanPlugin(files: Record<string, string>): Report;
export declare const name = "dsh-poison-guard";
export declare const inject: string[];
export declare function apply(ctx: Context): void;
