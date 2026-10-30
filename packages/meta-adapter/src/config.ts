/**
 * Configuration for the Meta Muse Security Adapter and third-party AI security providers.
 *
 * All values default to safe local settings:
 * - Default mode is 'mock' (zero external network requests)
 * - Strict timeout and bounded output tokens
 * - Local cost and request budget guards
 */

import type { MetaAiMode } from './types.js';
import {
  type ModelProvider,
  APPROVED_PROVIDERS,
  resolveProviderApiKey,
  validateProviderConfiguration,
} from './providers.js';

export interface MetaAdapterConfig {
  readonly provider: ModelProvider;
  readonly endpoint: string;
  readonly apiBaseUrl: string; // Kept for backwards compatibility
  readonly apiKey?: string;
  readonly model: string;
  readonly mode: MetaAiMode;
  readonly maxOutputTokens: number;
  readonly timeoutMs: number;
  readonly dailyBudgetUsd: number;
  readonly maxRequestsPerRun: number;
  readonly reasoningEffort: 'minimal' | 'low' | 'medium' | 'high';
  readonly allowUnverifiedPricing?: boolean;
}

export function loadMetaConfig(overrides?: Partial<MetaAdapterConfig>): MetaAdapterConfig {
  const providerRaw =
    overrides?.provider ?? (process.env['META_AI_PROVIDER'] as ModelProvider | undefined) ?? 'meta';
  const provider: ModelProvider = (['meta', 'fireworks', 'baseten'] as const).includes(
    providerRaw as ModelProvider,
  )
    ? (providerRaw as ModelProvider)
    : 'meta';

  const def = APPROVED_PROVIDERS[provider];
  if (!def) {
    throw new Error(`Unsupported provider: ${providerRaw}`);
  }

  const modeRaw = overrides?.mode ?? process.env['META_AI_MODE'] ?? 'mock';
  const mode: MetaAiMode = ['mock', 'live', 'disabled'].includes(modeRaw)
    ? (modeRaw as MetaAiMode)
    : 'mock';

  const allowUnverifiedPricing =
    overrides?.allowUnverifiedPricing ??
    process.env['META_ALLOW_UNVERIFIED_PRICING'] === 'true';

  let endpoint: string;
  if (overrides?.endpoint && overrides.endpoint.trim().length > 0) {
    endpoint = overrides.endpoint.trim();
  } else if (overrides?.apiBaseUrl && overrides.apiBaseUrl.trim().length > 0) {
    const trimmed = overrides.apiBaseUrl.trim();
    if (provider === 'meta' && !trimmed.endsWith('/responses')) {
      endpoint = `${trimmed.replace(/\/$/, '')}/responses`;
    } else {
      endpoint = trimmed;
    }
  } else if (process.env['META_MODEL_API_ENDPOINT']) {
    const envEndpoint = process.env['META_MODEL_API_ENDPOINT']!.trim();
    if (mode === 'live' && envEndpoint !== def.defaultEndpoint) {
      throw new Error(
        `Conflicting ambient META_MODEL_API_ENDPOINT='${envEndpoint}'. In live mode, endpoint must match approved destination '${def.defaultEndpoint}'.`,
      );
    }
    endpoint = envEndpoint;
  } else if (process.env['META_MODEL_API_BASE_URL']) {
    const baseUrl = process.env['META_MODEL_API_BASE_URL']!.trim();
    const derivedEndpoint =
      provider === 'meta' && !baseUrl.endsWith('/responses')
        ? `${baseUrl.replace(/\/$/, '')}/responses`
        : baseUrl;
    if (mode === 'live' && derivedEndpoint !== def.defaultEndpoint) {
      throw new Error(
        `Conflicting ambient META_MODEL_API_BASE_URL='${baseUrl}'. In live mode, endpoint must match approved destination '${def.defaultEndpoint}'.`,
      );
    }
    endpoint = derivedEndpoint;
  } else {
    endpoint = def.defaultEndpoint;
  }

  const apiBaseUrl =
    overrides?.apiBaseUrl ??
    (endpoint.endsWith('/responses') ? endpoint.slice(0, -10) : endpoint);

  const apiKey = resolveProviderApiKey(provider, overrides?.apiKey);
  const model = overrides?.model ?? process.env['META_MODEL'] ?? def.defaultModel;

  const maxOutputTokens =
    overrides?.maxOutputTokens ?? parseInt(process.env['META_MAX_OUTPUT_TOKENS'] ?? '1024', 10);

  const timeoutMs =
    overrides?.timeoutMs ?? parseInt(process.env['META_REQUEST_TIMEOUT_MS'] ?? '5000', 10);

  const dailyBudgetUsd =
    overrides?.dailyBudgetUsd ?? parseFloat(process.env['META_DAILY_BUDGET_USD'] ?? '0.25');

  const maxRequestsPerRun =
    overrides?.maxRequestsPerRun ?? parseInt(process.env['META_MAX_REQUESTS_PER_RUN'] ?? '10', 10);

  const reasoningEffortRaw =
    overrides?.reasoningEffort ?? process.env['META_REASONING_EFFORT'] ?? 'minimal';
  const reasoningEffort: 'minimal' | 'low' | 'medium' | 'high' = [
    'minimal',
    'low',
    'medium',
    'high',
  ].includes(reasoningEffortRaw)
    ? (reasoningEffortRaw as 'minimal' | 'low' | 'medium' | 'high')
    : 'minimal';

  // If live mode is requested, an API key is required and configuration must be allowlisted
  if (mode === 'live') {
    if (!apiKey || apiKey.trim().length === 0) {
      throw new Error(
        `Cannot operate in live mode: ${def.credentialEnvVar} is missing or empty. Please set ${def.credentialEnvVar} or use mode=mock.`,
      );
    }
    validateProviderConfiguration(provider, endpoint, model);
  }

  return {
    provider,
    endpoint,
    apiBaseUrl,
    apiKey,
    model,
    mode,
    maxOutputTokens: isNaN(maxOutputTokens) ? 256 : maxOutputTokens,
    timeoutMs: isNaN(timeoutMs) ? 5000 : timeoutMs,
    dailyBudgetUsd: isNaN(dailyBudgetUsd) ? 0.25 : dailyBudgetUsd,
    maxRequestsPerRun: isNaN(maxRequestsPerRun) ? 10 : maxRequestsPerRun,
    reasoningEffort,
    allowUnverifiedPricing,
  };
}
