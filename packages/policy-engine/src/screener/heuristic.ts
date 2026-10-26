/**
 * Tier 2: Fast Heuristic Risk Screener.
 *
 * Runs in <0.1ms to triage incoming payloads:
 * - 'clean': obviously benign content (e.g. numbers, basic text) -> skips expensive AI inference.
 * - 'hard_violation': matches deterministic invariant -> short-circuits to block.
 * - 'ambiguous': contains semantic risk markers -> routes to Tier 3 Meta Muse inspection.
 */

import type { RuleMatch } from '../rules/deterministic.js';
import { DeterministicRuleSet } from '../rules/deterministic.js';

export type ScreenerVerdict =
  | { readonly type: 'hard_violation'; readonly match: RuleMatch }
  | { readonly type: 'clean' }
  | { readonly type: 'ambiguous'; readonly suspiciousSignals: readonly string[] };

export class HeuristicRiskScreener {
  private readonly deterministicRules = new DeterministicRuleSet();

  // Keywords that warrant deeper semantic model inspection if present in untrusted data
  private readonly semanticRiskKeywords: readonly { pattern: RegExp; signal: string }[] = [
    {
      pattern: /\b(?:override|bypass|disregard|ignore)\b/i,
      signal: 'Instruction override terminology',
    },
    {
      pattern: /\b(?:exfiltrat|leak|steal|send\s+to|webhook)\b/i,
      signal: 'Data transmission / exfiltration terminology',
    },
    {
      pattern: /\b(?:secret|password|credential|token|api[_-]?key|private[_-]?key)\b/i,
      signal: 'High-value credential terminology',
    },
    {
      pattern: /\b(?:exec|eval|system|subprocess|spawn|shell)\b/i,
      signal: 'Code execution terminology',
    },
    {
      pattern: /\b(?:admin|root|superuser|sudo|elevated)\b/i,
      signal: 'Privilege escalation terminology',
    },
    {
      pattern: /\b(?:hidden|invisible|instruction|payload)\b/i,
      signal: 'Steganographic / payload terminology',
    },
    { pattern: /base64\s*,\s*[A-Za-z0-9+/=]{40,}/i, signal: 'Embedded Base64 payload' },
  ];

  /**
   * Screen target data.
   */
  screen(data: unknown, stage: 'discovery' | 'call_arguments' | 'call_response'): ScreenerVerdict {
    // 1. Check deterministic hard violation first
    const hardMatch = this.deterministicRules.scan(data, stage);
    if (hardMatch) {
      return { type: 'hard_violation', match: hardMatch };
    }

    // 2. Scan for semantic risk signals
    const signals = this.findSemanticSignals(data);
    if (signals.length > 0) {
      return { type: 'ambiguous', suspiciousSignals: signals };
    }

    // 3. Otherwise clean
    return { type: 'clean' };
  }

  private findSemanticSignals(data: unknown): string[] {
    const signals: string[] = [];

    const walk = (item: unknown) => {
      if (item === null || item === undefined) return;
      if (typeof item === 'string') {
        for (const k of this.semanticRiskKeywords) {
          if (k.pattern.test(item)) {
            if (!signals.includes(k.signal)) signals.push(k.signal);
          }
        }
      } else if (Array.isArray(item)) {
        for (const el of item) walk(el);
      } else if (typeof item === 'object') {
        for (const val of Object.values(item)) walk(val);
      }
    };

    walk(data);
    return signals;
  }
}
