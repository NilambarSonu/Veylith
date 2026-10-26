/**
 * Local usage, cost, and budget tracker for Meta Muse inference.
 *
 * Provides application-level safeguards against unexpected API spend.
 * Pricing defaults for muse-spark-1.3:
 *   Input: $0.15 per 1,000,000 tokens ($0.00000015 / token)
 *   Output: $0.60 per 1,000,000 tokens ($0.0000006 / token)
 */

export interface UsageReport {
  readonly requestCount: number;
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly totalTokens: number;
  readonly estimatedCostUsd: number;
  readonly failureCount: number;
  readonly averageLatencyMs: number;
  readonly maxRequestsPerRun: number;
  readonly dailyBudgetUsd: number;
}

export class UsageTracker {
  private requestCount = 0;
  private promptTokens = 0;
  private completionTokens = 0;
  private failureCount = 0;
  private totalLatencyMs = 0;

  // Pricing constants (USD per token)
  private readonly inputTokenPriceUsd = 0.00000015; // $0.15 / 1M
  private readonly outputTokenPriceUsd = 0.0000006; // $0.60 / 1M

  constructor(
    private readonly maxRequestsPerRun: number = 10,
    private readonly dailyBudgetUsd: number = 0.25,
  ) {}

  /**
   * Pre-check before executing an inference request.
   * Throws an error if budget or request limit is exceeded.
   */
  assertWithinBudget(): void {
    if (this.requestCount >= this.maxRequestsPerRun) {
      throw new Error(
        `Local usage safeguard: Maximum requests per run limit reached (${this.maxRequestsPerRun}). Inference blocked.`,
      );
    }

    const currentCost = this.getEstimatedCostUsd();
    if (currentCost >= this.dailyBudgetUsd) {
      throw new Error(
        `Local budget safeguard: Daily budget cap reached ($${currentCost.toFixed(4)} >= $${this.dailyBudgetUsd.toFixed(4)}). Inference blocked.`,
      );
    }
  }

  /** Record a completed inference request with tokens and latency. */
  recordSuccess(promptTokens: number, completionTokens: number, latencyMs: number): void {
    this.requestCount += 1;
    this.promptTokens += promptTokens;
    this.completionTokens += completionTokens;
    this.totalLatencyMs += latencyMs;
  }

  /** Record an inference failure. */
  recordFailure(): void {
    this.requestCount += 1;
    this.failureCount += 1;
  }

  /** Calculate current estimated cost in USD. */
  getEstimatedCostUsd(): number {
    return (
      this.promptTokens * this.inputTokenPriceUsd + this.completionTokens * this.outputTokenPriceUsd
    );
  }

  /** Generate an immutable summary report. */
  getReport(): UsageReport {
    const totalTokens = this.promptTokens + this.completionTokens;
    const avgLatency =
      this.requestCount > 0
        ? this.totalLatencyMs / (this.requestCount - this.failureCount || 1)
        : 0;

    return {
      requestCount: this.requestCount,
      promptTokens: this.promptTokens,
      completionTokens: this.completionTokens,
      totalTokens,
      estimatedCostUsd: Math.round(this.getEstimatedCostUsd() * 100000) / 100000,
      failureCount: this.failureCount,
      averageLatencyMs: Math.round(avgLatency * 100) / 100,
      maxRequestsPerRun: this.maxRequestsPerRun,
      dailyBudgetUsd: this.dailyBudgetUsd,
    };
  }

  /** Reset all usage counters. */
  reset(): void {
    this.requestCount = 0;
    this.promptTokens = 0;
    this.completionTokens = 0;
    this.failureCount = 0;
    this.totalLatencyMs = 0;
  }
}
