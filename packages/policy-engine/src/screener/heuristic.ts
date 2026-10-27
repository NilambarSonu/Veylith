/**
 * Tier 2: Fast Heuristic Risk Screener.
 *
 * Runs in <0.1ms to triage incoming payloads:
 * - 'clean': obviously benign content (e.g. numbers, basic text) -> skips expensive AI inference.
 * - 'hard_violation': matches deterministic invariant -> short-circuits to block.
 * - 'ambiguous': contains semantic risk markers -> routes to Tier 3 Meta Muse inspection.
 */

import type { RuleMatch, ScanOptions } from '../rules/deterministic.js';
import { DeterministicRuleSet } from '../rules/deterministic.js';
import type { InspectionStage } from '@veylith/core';

export type ScreenerVerdict =
  | { readonly type: 'hard_violation'; readonly match: RuleMatch }
  | { readonly type: 'clean' }
  | {
      readonly type: 'ambiguous';
      readonly suspiciousSignals: readonly string[];
      readonly riskLevel: 'high' | 'medium';
    };

export class HeuristicRiskScreener {
  private readonly deterministicRules = new DeterministicRuleSet();

  // Keywords that warrant deeper semantic model inspection if present in untrusted data
  private readonly semanticRiskKeywords: readonly {
    pattern: RegExp;
    signal: string;
    highRisk: boolean;
    isExecKeyword?: boolean;
  }[] = [
    {
      pattern: /\b(?:override|bypass|disregard|ignore)\b/i,
      signal: 'Instruction override terminology',
      highRisk: true,
    },
    {
      pattern: /\b(?:exfiltrat|leak|steal|send\s+to|webhook)\b/i,
      signal: 'Data transmission / exfiltration terminology',
      highRisk: true,
    },
    {
      pattern: /\b(?:secret|password|credential|token|api[_-]?key|private[_-]?key)\b/i,
      signal: 'High-value credential terminology',
      highRisk: true,
    },
    {
      pattern: /\b(?:exec|eval|system|subprocess|spawn|shell)\b/i,
      signal: 'Code execution terminology',
      highRisk: true,
      isExecKeyword: true,
    },
    {
      pattern: /\b(?:admin|root|superuser|sudo|elevated)\b/i,
      signal: 'Privilege escalation terminology',
      highRisk: true,
    },
    {
      pattern: /\b(?:hidden|invisible|instruction|payload)\b/i,
      signal: 'Steganographic / payload terminology',
      highRisk: false,
    },
    {
      pattern: /base64\s*,\s*[A-Za-z0-9+/=]{40,}/i,
      signal: 'Embedded Base64 payload',
      highRisk: true,
    },
  ];

  /**
   * Screen target data.
   */
  screen(data: unknown, stageOrOptions: InspectionStage | ScanOptions): ScreenerVerdict {
    const options: ScanOptions =
      typeof stageOrOptions === 'string'
        ? { stage: stageOrOptions, capability: 'UNKNOWN' }
        : stageOrOptions;

    // 1. Check deterministic hard violation first (capability-aware)
    const hardMatch = this.deterministicRules.scan(data, options);
    if (hardMatch) {
      return { type: 'hard_violation', match: hardMatch };
    }

    // 2. Scan for semantic risk signals
    const { signals, hasHighRisk } = this.findSemanticSignals(data, options);
    if (signals.length > 0) {
      const riskLevel = hasHighRisk || signals.length >= 2 ? 'high' : 'medium';
      return { type: 'ambiguous', suspiciousSignals: signals, riskLevel };
    }

    // 3. Otherwise clean
    return { type: 'clean' };
  }

  private findSemanticSignals(
    data: unknown,
    options?: ScanOptions,
  ): { signals: string[]; hasHighRisk: boolean } {
    const signals: string[] = [];
    let hasHighRisk = false;
    const isPureOrRead = options?.capability === 'PURE_OR_READ';

    const walk = (item: unknown) => {
      if (item === null || item === undefined) return;
      if (typeof item === 'string') {
        for (const k of this.semanticRiskKeywords) {
          // If tool is verified PURE_OR_READ, execution keywords in arguments represent quoted content or search text
          if (isPureOrRead && options?.stage === 'call_arguments' && k.isExecKeyword) {
            continue;
          }

          if (k.pattern.test(item)) {
            if (!signals.includes(k.signal)) signals.push(k.signal);
            if (k.highRisk) hasHighRisk = true;
          }
        }
      } else if (Array.isArray(item)) {
        for (const el of item) walk(el);
      } else if (typeof item === 'object') {
        for (const val of Object.values(item)) walk(val);
      }
    };

    walk(data);
    return { signals, hasHighRisk };
  }
}
