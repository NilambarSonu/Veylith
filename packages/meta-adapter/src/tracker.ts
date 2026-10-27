/**
 * Local usage, cost, and budget tracker for Meta Muse inference.
 *
 * Provides application-level safeguards against unexpected API spend.
 * Official Pricing for Meta Muse Spark 1.3 (Standard Mode):
 *   Standard Input:     $1.25 per 1,000,000 tokens ($0.00000125 / token)
 *   Cached Input:       $0.15 per 1,000,000 tokens ($0.00000015 / token)
 *   Output:             $4.25 per 1,000,000 tokens ($0.00000425 / token)
 */

export interface UsageReport {
  readonly requestCount: number;
  readonly promptTokens: number;
  readonly cachedPromptTokens: number;
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
  private cachedPromptTokens = 0;
  private completionTokens = 0;
  private failureCount = 0;
  private totalLatencyMs = 0;

  // Official Pricing constants (USD per token)
  private readonly standardInputPriceUsd = 0.00000125; // $1.25 / 1M
  private readonly cachedInputPriceUsd = 0.00000015; // $0.15 / 1M
  private readonly outputTokenPriceUsd = 0.00000425; // $4.25 / 1M

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
  recordSuccess(
    promptTokens: number,
    completionTokens: number,
    latencyMs: number,
    cachedPromptTokens = 0,
  ): void {
    this.requestCount += 1;
    this.promptTokens += promptTokens;
    this.cachedPromptTokens += Math.min(cachedPromptTokens, promptTokens);
    this.completionTokens += completionTokens;
    this.totalLatencyMs += latencyMs;
  }

  /** Record an inference failure. */
  recordFailure(): void {
    this.requestCount += 1;
    this.failureCount += 1;
  }

  /** Calculate current estimated cost in USD based on standard vs cached input and output rates. */
  getEstimatedCostUsd(): number {
    const uncachedPromptTokens = Math.max(0, this.promptTokens - this.cachedPromptTokens);
    return (
      uncachedPromptTokens * this.standardInputPriceUsd +
      this.cachedPromptTokens * this.cachedInputPriceUsd +
      this.completionTokens * this.outputTokenPriceUsd
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
      cachedPromptTokens: this.cachedPromptTokens,
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
    this.cachedPromptTokens = 0;
    this.completionTokens = 0;
    this.failureCount = 0;
    this.totalLatencyMs = 0;
  }
}
