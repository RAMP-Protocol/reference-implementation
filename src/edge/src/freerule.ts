// Free-index rule matching — the edge-config projection of ADR-015 D5/D9/D12,
// realized here as a static, table-driven list.
//
// In production a control-plane background job (D9) collapses the high-fidelity
// per-resource catalog (ADR-014) into a minimal set of path-pattern rules and
// an exclude-only exception list (D12); the edge only ever READS the result.
// For this demo the table is hand-authored config. Exceptions only ever shrink
// the fast set — a non-match falls through to the Exchange (403), never widens
// access.

export interface FreeRule {
  /**
   * Path pattern. Either an exact path or a prefix glob ending in '*'
   * (e.g. '/articles/philosophers/*'). Most-specific (longest literal prefix)
   * wins when several match.
   */
  pathPattern: string;
  /** Immutable license identifier (prefer a data-labels TDL id), for notice (D4). */
  licenseId: string;
  /** AIPREF Content-Usage response header value (D4). */
  contentUsage: string;
  /** Optional precomputed sha256 of the served resource, for the access record. */
  contentHash?: string;
}

export interface FreeMatch {
  licenseId: string;
  contentUsage: string;
  contentHash?: string;
}

export function matchFreeRule(path: string, rules: readonly FreeRule[]): FreeMatch | undefined {
  let best: FreeRule | undefined;
  let bestSpecificity = -1;
  for (const rule of rules) {
    const specificity = matchSpecificity(path, rule.pathPattern);
    if (specificity > bestSpecificity) {
      best = rule;
      bestSpecificity = specificity;
    }
  }
  if (!best) return undefined;

  const match: FreeMatch = {
    licenseId: best.licenseId,
    contentUsage: best.contentUsage,
  };
  if (best.contentHash !== undefined) match.contentHash = best.contentHash;
  return match;
}

// Returns the length of the literal prefix that matched (higher = more
// specific), or -1 if the pattern does not match the path at all.
function matchSpecificity(path: string, pattern: string): number {
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return path.startsWith(prefix) ? prefix.length : -1;
  }
  return path === pattern ? pattern.length : -1;
}
