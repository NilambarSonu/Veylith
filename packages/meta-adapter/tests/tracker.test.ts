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

  it('records successful requests and calculates costs correctly with standard and cached rates', () => {
    // 1000 total prompt tokens, 400 cached, 500 completion tokens
    tracker.recordSuccess(1000, 500, 120, 400);

    const report = tracker.getReport();
    expect(report.requestCount).toBe(1);
    expect(report.promptTokens).toBe(1000);
    expect(report.cachedPromptTokens).toBe(400);
    expect(report.completionTokens).toBe(500);
    expect(report.totalTokens).toBe(1500);
    expect(report.averageLatencyMs).toBe(120);

    // Cost:
    // (1000 - 400) uncached prompt tokens * $0.00000125 = 600 * 0.00000125 = $0.00075
    // 400 cached prompt tokens * $0.00000015 = 400 * 0.00000015 = $0.00006
    // 500 completion tokens * $0.00000425 = 500 * 0.00000425 = $0.002125
    // Total = 0.00075 + 0.00006 + 0.002125 = 0.002935
    expect(report.estimatedCostUsd).toBeCloseTo(0.00294, 4);
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

  it('records reasoning tokens and reports them in usage summary', () => {
    // 500 prompt tokens, 300 completion tokens, 100 latency, 0 cached, 150 reasoning tokens
    tracker.recordSuccess(500, 300, 100, 0, 150);

    const report = tracker.getReport();
    expect(report.promptTokens).toBe(500);
    expect(report.completionTokens).toBe(300);
    expect(report.reasoningTokens).toBe(150);
    expect(report.totalTokens).toBe(800);
  });

  it('enforces budget cap with official pricing', () => {
    // Inject enough tokens to exceed $0.10 cap
    // 100,000 standard tokens * $0.00000125 ($1.25/1M) = $0.125 > $0.10
    tracker.recordSuccess(100000, 0, 10);
    expect(() => tracker.assertWithinBudget()).toThrowError(/Daily budget cap reached/);
  });
});
