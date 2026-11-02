/**
 * Unit tests for @veylith/policy-engine
 */

import { describe, it, expect } from 'vitest';
import { PolicyEvaluator } from '../src/evaluator/index.js';
import type { PolicyRule } from '@veylith/core';

const RULES: PolicyRule[] = [
  {
    id: 'block-restricted',
    description: 'Block calls to restricted_demo_tool',
    method: 'tools/call',
    toolName: 'restricted_demo_tool',
    decision: 'block',
    enabled: true,
  },
  {
    id: 'review-admin',
    description: 'Flag calls to admin_tool for review',
    method: 'tools/call',
    toolName: 'admin_tool',
    decision: 'review',
    enabled: true,
  },
  {
    id: 'disabled-rule',
    description: 'This rule is disabled and should not match',
    method: '*',
    decision: 'block',
    enabled: false,
  },
];

describe('PolicyEvaluator', () => {
  const evaluator = new PolicyEvaluator(RULES, 'allow');

  it('blocks a specifically configured tool', () => {
    const result = evaluator.evaluate({ method: 'tools/call', toolName: 'restricted_demo_tool' });
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('block-restricted');
    expect(result.reason).toContain('block-restricted');
  });

  it('allows a non-blocked tool (default allow)', () => {
    const result = evaluator.evaluate({ method: 'tools/call', toolName: 'echo' });
    expect(result.decision).toBe('allow');
    expect(result.matchedRule).toBeNull();
  });

  it('returns review for admin_tool', () => {
    const result = evaluator.evaluate({ method: 'tools/call', toolName: 'admin_tool' });
    expect(result.decision).toBe('review');
    expect(result.matchedRule?.id).toBe('review-admin');
  });

  it('does not match disabled rules', () => {
    const result = evaluator.evaluate({ method: 'tools/list' });
    expect(result.decision).toBe('allow');
    expect(result.matchedRule).toBeNull();
  });

  it('uses the configured default decision', () => {
    const strictEvaluator = new PolicyEvaluator([], 'block');
    const result = strictEvaluator.evaluate({ method: 'tools/call', toolName: 'anything' });
    expect(result.decision).toBe('block');
    expect(result.reason).toContain('default decision: block');
  });

  it('includes evaluation duration', () => {
    const result = evaluator.evaluate({ method: 'tools/call', toolName: 'echo' });
    expect(typeof result.evaluationDurationMs).toBe('number');
    expect(result.evaluationDurationMs).toBeGreaterThanOrEqual(0);
  });

  it('matches wildcard method rules when enabled', () => {
    const wildcardRules: PolicyRule[] = [
      {
        id: 'block-all',
        description: 'Block everything',
        method: '*',
        decision: 'block',
        enabled: true,
      },
    ];
    const strictEvaluator = new PolicyEvaluator(wildcardRules);
    const result = strictEvaluator.evaluate({ method: 'tools/list' });
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('block-all');
  });
});
