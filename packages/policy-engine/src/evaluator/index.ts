/**
 * Deterministic policy evaluator.
 *
 * Phase 0 implementation: evaluates a static list of rules against an
 * incoming MCP method + tool name. No LLM involvement — purely deterministic.
 *
 * Default behaviour: allow (fail-open for Phase 0 development convenience).
 * Production deployments should switch to fail-closed and explicitly allow
 * known-safe operations.
 */

import type { PolicyRule, PolicyEvaluationResult, SecurityDecision } from '@veylith/core';

export interface EvaluationContext {
  /** The JSON-RPC method being called (e.g. 'tools/call'). */
  readonly method: string;
  /** For tools/call: the name of the tool. */
  readonly toolName?: string;
}

export class PolicyEvaluator {
  private readonly rules: readonly PolicyRule[];
  private readonly defaultDecision: SecurityDecision;

  constructor(rules: readonly PolicyRule[], defaultDecision: SecurityDecision = 'allow') {
    this.rules = rules;
    this.defaultDecision = defaultDecision;
  }

  /**
   * Evaluate all enabled rules against the given context.
   * First matching rule wins. If no rule matches, the default decision applies.
   */
  evaluate(ctx: EvaluationContext): PolicyEvaluationResult {
    const start = performance.now();

    for (const rule of this.rules) {
      if (!rule.enabled) continue;

      const methodMatch = rule.method === '*' || rule.method === ctx.method;
      if (!methodMatch) continue;

      // For tool-specific rules, only match if the tool name matches
      if (rule.toolName !== undefined) {
        if (ctx.toolName !== rule.toolName) continue;
      }

      const durationMs = performance.now() - start;
      return {
        decision: rule.decision,
        matchedRule: rule,
        reason: `Matched rule '${rule.id}': ${rule.description}`,
        evaluationDurationMs: Math.round(durationMs * 100) / 100,
      };
    }

    const durationMs = performance.now() - start;
    return {
      decision: this.defaultDecision,
      matchedRule: null,
      reason: `No rule matched; default decision: ${this.defaultDecision}`,
      evaluationDurationMs: Math.round(durationMs * 100) / 100,
    };
  }
}
