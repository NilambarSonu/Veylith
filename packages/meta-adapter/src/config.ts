/**
 * Configuration for the Meta Muse Security Adapter.
 *
 * All values default to safe local settings:
 * - Default mode is 'mock' (zero external network requests)
 * - Strict timeout and bounded output tokens
 * - Local cost and request budget guards
 */

import type { MetaAiMode } from './types.js';

export interface MetaAdapterConfig {
  readonly apiBaseUrl: string;
  readonly apiKey?: string;
  readonly model: string;
  readonly mode: MetaAiMode;
  readonly maxOutputTokens: number;
  readonly timeoutMs: number;
  readonly dailyBudgetUsd: number;
  readonly maxRequestsPerRun: number;
  readonly reasoningEffort: 'low' | 'medium' | 'high';
}

export function loadMetaConfig(overrides?: Partial<MetaAdapterConfig>): MetaAdapterConfig {
  const modeRaw = overrides?.mode ?? process.env['META_AI_MODE'] ?? 'mock';
  const mode: MetaAiMode = ['mock', 'live', 'disabled'].includes(modeRaw)
    ? (modeRaw as MetaAiMode)
    : 'mock';

  const apiBaseUrl =
    overrides?.apiBaseUrl ?? process.env['META_MODEL_API_BASE_URL'] ?? 'https://api.meta.ai/v1';

  const apiKey =
    overrides?.apiKey ?? process.env['META_MODEL_API_KEY'] ?? process.env['META_API_KEY'];
  const model = overrides?.model ?? process.env['META_MODEL'] ?? 'muse-spark-1.3';

  const maxOutputTokens =
    overrides?.maxOutputTokens ?? parseInt(process.env['META_MAX_OUTPUT_TOKENS'] ?? '256', 10);

  const timeoutMs =
    overrides?.timeoutMs ?? parseInt(process.env['META_REQUEST_TIMEOUT_MS'] ?? '5000', 10);

  const dailyBudgetUsd =
    overrides?.dailyBudgetUsd ?? parseFloat(process.env['META_DAILY_BUDGET_USD'] ?? '0.25');

  const maxRequestsPerRun =
    overrides?.maxRequestsPerRun ?? parseInt(process.env['META_MAX_REQUESTS_PER_RUN'] ?? '10', 10);

  const reasoningEffortRaw =
    overrides?.reasoningEffort ?? process.env['META_REASONING_EFFORT'] ?? 'low';
  const reasoningEffort: 'low' | 'medium' | 'high' = ['low', 'medium', 'high'].includes(
    reasoningEffortRaw,
  )
    ? (reasoningEffortRaw as 'low' | 'medium' | 'high')
    : 'low';

  // If live mode is requested, an API key is required
  if (mode === 'live' && (!apiKey || apiKey.trim().length === 0)) {
    throw new Error(
      'Cannot operate in live mode: META_MODEL_API_KEY is missing or empty. Please set META_MODEL_API_KEY or use mode=mock.',
    );
  }

  return {
    apiBaseUrl,
    apiKey,
    model,
    mode,
    maxOutputTokens: isNaN(maxOutputTokens) ? 256 : maxOutputTokens,
    timeoutMs: isNaN(timeoutMs) ? 5000 : timeoutMs,
    dailyBudgetUsd: isNaN(dailyBudgetUsd) ? 0.25 : dailyBudgetUsd,
    maxRequestsPerRun: isNaN(maxRequestsPerRun) ? 10 : maxRequestsPerRun,
    reasoningEffort,
  };
}
