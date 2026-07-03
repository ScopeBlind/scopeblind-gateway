/**
 * @scopeblind/protect-mcp — Hook Patterns Library
 *
 * Pre-built dangerous pattern filters for Claude Code's `if` condition field.
 * These layer ON TOP of Cedar policies as a first-pass regex filter,
 * reducing the number of hook invocations that reach protect-mcp.
 *
 * Shipped with `npx protect-mcp init-hooks` and customizable by the user.
 */
interface HookPattern {
    /** Matcher: which tool this pattern applies to */
    matcher: string;
    /** Condition: Claude Code's `if` field (regex-like tool input matching) */
    condition: string;
    /** Default decision for this pattern */
    decision: 'deny' | 'ask';
    /** Human-readable description */
    description: string;
    /** Risk category */
    category: 'destructive' | 'exfiltration' | 'privilege_escalation' | 'sensitive_file' | 'network';
}
/**
 * Built-in dangerous patterns that ship with protect-mcp.
 * These are conservative — they catch the most common dangerous commands
 * without generating excessive false positives.
 */
declare const BUILTIN_PATTERNS: HookPattern[];
/**
 * Generate Claude Code settings.json hook entries with pattern-based filtering.
 */
declare function generateHookSettings(hookUrl: string, patterns?: HookPattern[]): Record<string, unknown>;
/**
 * Generate a sample Cedar policy from the built-in patterns.
 */
declare function generateSampleCedarPolicy(): string;
/**
 * Generate the /verify-receipt skill file for Claude Code.
 */
declare function generateVerifyReceiptSkill(): string;

export { BUILTIN_PATTERNS, type HookPattern, generateHookSettings, generateSampleCedarPolicy, generateVerifyReceiptSkill };
