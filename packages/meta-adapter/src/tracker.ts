/**
 * Local usage, cost, and budget tracker for AI security inference providers.
 *
 * Provides application-level safeguards against unexpected API spend.
 * Official Pricing for Meta Muse Spark 1.3 (Standard Mode):
 *   Standard Input:     $1.25 per 1,000,000 tokens ($0.00000125 / token)
 *   Cached Input:       $0.15 per 1,000,000 tokens ($0.00000015 / token)
 *   Output:             $4.25 per 1,000,000 tokens ($0.00000425 / token)
 *
 * NOTE: Meta Responses API `usage.output_tokens` already includes
 * `usage.output_tokens_details.reasoning_tokens`. Do not add reasoning
 * tokens again when calculating costs. Reasoning tokens are tracked as
 * a subset for observability only.
 */

export interface TokenUsageMetrics {
  promptTokens?: number;
  completionTokens?: number;
  cachedPromptTokens?: number;
  reasoningTokens?: number;
}

export interface UsageTrackerOptions {
  readonly maxRequestsPerRun?: number;
  readonly dailyBudgetUsd?: number;
  readonly pricingVerified?: boolean;
  readonly standardInputPriceUsd?: number;
  readonly cachedInputPriceUsd?: number;
  readonly outputTokenPriceUsd?: number;
  readonly allowUnverifiedPricing?: boolean;
}

export interface UsageReport {
  readonly requestCount: number;
  readonly completedProviderRequests: number;
  readonly successfulClassifications: number;
  readonly failedClassifications: number;
  readonly failureCount: number; // Backward compatibility alias
  readonly promptTokens: number;
  readonly cachedPromptTokens: number;
  readonly completionTokens: number; // Represents total output tokens (including reasoning tokens)
  readonly reasoningTokens: number; // Subset of completionTokens tracked for observability
  readonly totalTokens: number;
  readonly hasUnknownUsage: boolean;
  readonly unknownUsageCount: number;
  readonly estimatedCostUsd: number;
  readonly pricingVerified: boolean;
  readonly hasUnverifiedPricing: boolean;
  readonly dollarBudgetEnforced: boolean;
  readonly costStatus: 'verified_pricing' | 'unverified_unbounded_cost';
  readonly averageLatencyMs: number;
  readonly maxRequestsPerRun: number;
  readonly dailyBudgetUsd: number;
}

export class UsageTracker {
  private requestCount = 0;
  private completedProviderRequests = 0;
  private successfulClassifications = 0;
  private failedClassifications = 0;
  private failureCount = 0;
  private promptTokens = 0;
  private cachedPromptTokens = 0;
  private completionTokens = 0; // Total output tokens (reasoning tokens already included)
  private reasoningTokens = 0; // Observability subset
  private hasUnknownUsage = false;
  private unknownUsageCount = 0;
  private totalLatencyMs = 0;
  private latencyRecordedCount = 0;

  private readonly maxRequestsPerRun: number;
  private readonly dailyBudgetUsd: number;
  public readonly pricingVerified: boolean;
  public readonly allowUnverifiedPricing: boolean;
  private readonly standardInputPriceUsd: number;
  private readonly cachedInputPriceUsd: number;
  private readonly outputTokenPriceUsd: number;

  constructor(
    maxRequestsOrOptions: number | UsageTrackerOptions = 10,
    dailyBudgetUsd = 0.25,
  ) {
    if (typeof maxRequestsOrOptions === 'object') {
      this.maxRequestsPerRun = maxRequestsOrOptions.maxRequestsPerRun ?? 10;
      this.dailyBudgetUsd = maxRequestsOrOptions.dailyBudgetUsd ?? 0.25;
      this.pricingVerified = maxRequestsOrOptions.pricingVerified ?? true;
      this.allowUnverifiedPricing = maxRequestsOrOptions.allowUnverifiedPricing ?? false;
      this.standardInputPriceUsd =
        maxRequestsOrOptions.standardInputPriceUsd ?? 0.00000125;
      this.cachedInputPriceUsd =
        maxRequestsOrOptions.cachedInputPriceUsd ?? 0.00000015;
      this.outputTokenPriceUsd =
        maxRequestsOrOptions.outputTokenPriceUsd ?? 0.00000425;
    } else {
      this.maxRequestsPerRun = maxRequestsOrOptions;
      this.dailyBudgetUsd = dailyBudgetUsd;
      this.pricingVerified = true;
      this.allowUnverifiedPricing = false;
      this.standardInputPriceUsd = 0.00000125;
      this.cachedInputPriceUsd = 0.00000015;
      this.outputTokenPriceUsd = 0.00000425;
    }
  }

  /**
   * Pre-check before executing an inference request.
   * Throws an error if budget or request limit is exceeded.
   *
   * Invariant: A dollar budget is only represented as enforced when pricing
   * assumptions are verified. If pricing is unverified, execution is refused
   * unless explicit unverified pricing authorization (allowUnverifiedPricing: true)
   * is provided, in which case request-count limits remain strictly enforced.
   */
  assertWithinBudget(): void {
    if (this.requestCount >= this.maxRequestsPerRun) {
      throw new Error(
        `Local usage safeguard: Maximum requests per run limit reached (${this.maxRequestsPerRun}). Inference blocked.`,
      );
    }

    if (this.pricingVerified) {
      const currentCost = this.getEstimatedCostUsd();
      if (currentCost >= this.dailyBudgetUsd) {
        throw new Error(
          `Local budget safeguard: Daily budget cap reached ($${currentCost.toFixed(4)} >= $${this.dailyBudgetUsd.toFixed(4)}). Inference blocked.`,
        );
      }
    } else {
      if (!this.allowUnverifiedPricing) {
        throw new Error(
          'Local budget safeguard: Provider pricing is unverified. An application dollar budget cap cannot be guaranteed or enforced. To proceed under strict request-count and output-token limits only, pass explicit unverified pricing authorization (allowUnverifiedPricing: true).',
        );
      }
    }
  }

  /** Record a completed inference request that produced a valid classification. */
  recordSuccess(
    promptTokens: number,
    completionTokens: number,
    latencyMs: number,
    cachedPromptTokens = 0,
    reasoningTokens = 0,
  ): void {
    this.requestCount += 1;
    this.completedProviderRequests += 1;
    this.successfulClassifications += 1;
    this.promptTokens += promptTokens;
    this.cachedPromptTokens += Math.min(cachedPromptTokens, promptTokens);
    this.completionTokens += completionTokens;
    this.reasoningTokens += reasoningTokens;
    if (latencyMs > 0) {
      this.totalLatencyMs += latencyMs;
      this.latencyRecordedCount += 1;
    }
  }

  /**
   * Record a failed inference request (e.g. truncation, malformed JSON, network error).
   * Billable tokens from incomplete provider responses are captured if present.
   */
  recordFailure(
    tokens?: TokenUsageMetrics | null,
    latencyMs?: number,
    isProviderResponse = false,
  ): void {
    this.requestCount += 1;
    this.failureCount += 1;
    this.failedClassifications += 1;
    if (isProviderResponse) {
      this.completedProviderRequests += 1;
    }

    if (
      tokens &&
      (typeof tokens.promptTokens === 'number' || typeof tokens.completionTokens === 'number')
    ) {
      const p = tokens.promptTokens ?? 0;
      const c = tokens.completionTokens ?? 0;
      const cached = tokens.cachedPromptTokens ?? 0;
      const r = tokens.reasoningTokens ?? 0;
      this.promptTokens += p;
      this.cachedPromptTokens += Math.min(cached, p);
      this.completionTokens += c;
      this.reasoningTokens += r;
    } else if (isProviderResponse) {
      this.hasUnknownUsage = true;
      this.unknownUsageCount += 1;
    }

    if (typeof latencyMs === 'number' && latencyMs > 0) {
      this.totalLatencyMs += latencyMs;
      this.latencyRecordedCount += 1;
    }
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
      this.latencyRecordedCount > 0 ? this.totalLatencyMs / this.latencyRecordedCount : 0;

    return {
      requestCount: this.requestCount,
      completedProviderRequests: this.completedProviderRequests,
      successfulClassifications: this.successfulClassifications,
      failedClassifications: this.failedClassifications,
      failureCount: this.failureCount,
      promptTokens: this.promptTokens,
      cachedPromptTokens: this.cachedPromptTokens,
      completionTokens: this.completionTokens,
      reasoningTokens: this.reasoningTokens,
      totalTokens,
      hasUnknownUsage: this.hasUnknownUsage,
      unknownUsageCount: this.unknownUsageCount,
      estimatedCostUsd: this.pricingVerified
        ? Math.round(this.getEstimatedCostUsd() * 1000000) / 1000000
        : 0,
      pricingVerified: this.pricingVerified,
      hasUnverifiedPricing: !this.pricingVerified,
      dollarBudgetEnforced: this.pricingVerified,
      costStatus: this.pricingVerified ? 'verified_pricing' : 'unverified_unbounded_cost',
      averageLatencyMs: Math.round(avgLatency * 100) / 100,
      maxRequestsPerRun: this.maxRequestsPerRun,
      dailyBudgetUsd: this.dailyBudgetUsd,
    };
  }

  /** Reset all usage counters. */
  reset(): void {
    this.requestCount = 0;
    this.completedProviderRequests = 0;
    this.successfulClassifications = 0;
    this.failedClassifications = 0;
    this.failureCount = 0;
    this.promptTokens = 0;
    this.cachedPromptTokens = 0;
    this.completionTokens = 0;
    this.reasoningTokens = 0;
    this.hasUnknownUsage = false;
    this.unknownUsageCount = 0;
    this.totalLatencyMs = 0;
    this.latencyRecordedCount = 0;
  }
}
