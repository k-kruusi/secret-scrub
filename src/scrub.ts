import { PATTERNS, type Hit } from "./patterns.js";

export interface ScrubOpts {
  /** Override the pattern list (for testing). Defaults to the full battery. */
  patterns?: typeof PATTERNS;
}

export interface ScrubResult {
  /** The text with secrets replaced by [REDACTED:<kind>] tokens. */
  text: string;
  /**
   * One entry per kind that had at least one redaction. Empty when no secrets
   * were found (byte-identical passthrough — the caller must NOT append a
   * disclosure line in that case).
   */
  hits: Hit[];
}

/**
 * Scan `text` for secrets and replace each with `[REDACTED:<kind>]`.
 *
 * Invariants:
 *   - NEVER throws — worst case returns the input unchanged with empty hits.
 *   - Idempotent: scrubSecrets(scrubSecrets(x).text).text === scrubSecrets(x).text
 *     (the [REDACTED:…] tokens are structurally excluded from every value
 *     char-class so a second pass cannot re-match them).
 *   - Passthrough: if hits is empty, result.text === input (byte-identical).
 *   - Deterministic: same input always produces the same output.
 *   - Zero runtime npm dependencies (node builtins only — supply-chain constraint).
 */
export function scrubSecrets(text: string, opts?: ScrubOpts): ScrubResult {
  try {
    if (typeof text !== "string" || text.length === 0) {
      return { text, hits: [] };
    }

    const patterns = opts?.patterns ?? PATTERNS;
    const counts = new Map<string, number>();
    let result = text;

    for (const pattern of patterns) {
      // Always reset lastIndex — the regexes are shared across calls (global flag).
      pattern.re.lastIndex = 0;

      result = result.replace(pattern.re, (...args: unknown[]): string => {
        const match = args[0] as string;
        // args = [match, ...captureGroups, offset, inputStr]
        // Slice off offset and inputStr (last 2) to get only capture groups.
        const groups = (args.slice(1, args.length - 2) as string[]);

        const replacement = pattern.replace
          ? pattern.replace(match, ...groups)
          : `[REDACTED:${pattern.kind}]`;

        if (replacement !== match) {
          counts.set(pattern.kind, (counts.get(pattern.kind) ?? 0) + 1);
        }
        return replacement;
      });
    }

    const hits: Hit[] = Array.from(counts.entries()).map(([kind, count]) => ({ kind, count }));
    return { text: result, hits };
  } catch {
    // Never propagate — a scrubber that crashes a tool path is worse than
    // no scrubber. The caller gets the original text so data is not lost.
    return { text, hits: [] };
  }
}
