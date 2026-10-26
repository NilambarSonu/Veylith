import { describe, it, expect, beforeEach } from 'vitest';
import { UsageTracker } from '../src/tracker.js';

describe('UsageTracker', () => {
  let tracker: UsageTracker;

  beforeEach(() => {
    tracker = new UsageTracker(5, 0.1); // max 5 requests, max $0.10
  });

  it('initializes with empty counters', () => {
    const report = tracker.getReport();
    expect(report.requestCount).toBe(0);
    expect(report.totalTokens).toBe(0);
    expect(report.estimatedCostUsd).toBe(0);
    expect(report.failureCount).toBe(0);
  });

  it('records successful requests and calculates costs correctly', () => {
    tracker.recordSuccess(1000, 500, 120);

    const report = tracker.getReport();
    expect(report.requestCount).toBe(1);
    expect(report.promptTokens).toBe(1000);
    expect(report.completionTokens).toBe(500);
    expect(report.totalTokens).toBe(1500);
    expect(report.averageLatencyMs).toBe(120);

    // Cost: 1000 * 0.00000015 + 500 * 0.0000006 = 0.00015 + 0.00030 = 0.00045
    expect(report.estimatedCostUsd).toBeCloseTo(0.00045, 5);
  });

  it('records failures without inflating token counts', () => {
    tracker.recordFailure();
    const report = tracker.getReport();
    expect(report.requestCount).toBe(1);
    expect(report.failureCount).toBe(1);
    expect(report.totalTokens).toBe(0);
  });

  it('enforces maximum requests per run limit', () => {
    for (let i = 0; i < 5; i++) {
      tracker.assertWithinBudget();
      tracker.recordSuccess(100, 50, 10);
    }

    expect(() => tracker.assertWithinBudget()).toThrowError(
      /Maximum requests per run limit reached/,
    );
  });

  it('enforces budget cap', () => {
    // Inject enough tokens to exceed $0.10 cap
    tracker.recordSuccess(1000000, 0, 10); // 1M tokens * $0.00000015 = $0.15 > $0.10
    expect(() => tracker.assertWithinBudget()).toThrowError(/Daily budget cap reached/);
  });
});
