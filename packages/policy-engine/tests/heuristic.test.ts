import { describe, it, expect } from 'vitest';
import { HeuristicRiskScreener } from '../src/index.js';

describe('HeuristicRiskScreener', () => {
  const screener = new HeuristicRiskScreener();

  it('marks benign numbers and text as clean', () => {
    const verdict = screener.screen({ a: 100, b: 200, label: 'sum calculation' }, 'call_arguments');
    expect(verdict.type).toBe('clean');
  });

  it('flags deterministic hard violation immediately', () => {
    const verdict = screener.screen({ cmd: 'rm -rf /' }, 'call_arguments');
    expect(verdict.type).toBe('hard_violation');
    if (verdict.type === 'hard_violation') {
      expect(verdict.match.ruleId).toBe('rule-shell-rm-rf-root');
    }
  });

  it('identifies ambiguous content containing sensitive keywords', () => {
    const verdict = screener.screen(
      { query: 'how to override default password policy' },
      'call_arguments',
    );
    expect(verdict.type).toBe('ambiguous');
    if (verdict.type === 'ambiguous') {
      expect(verdict.suspiciousSignals.length).toBeGreaterThan(0);
    }
  });
});
