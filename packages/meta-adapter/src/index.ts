/**
 * @veylith/meta-adapter — AI Security Inspection Adapter.
 *
 * Implements the semantic inspection boundary powered by Meta Muse (muse-spark-1.3),
 * Fireworks AI, or Baseten. Supports 'mock' (offline test simulation), 'live' (real API with budget controls),
 * and 'disabled' modes.
 */

export type {
  MetaAdapter,
  SemanticInspectionResult,
  MetaAiMode,
  TokenUsage,
  ModelClassification,
  ModelProvider,
} from './types.js';
export { ModelClassificationSchema } from './types.js';
export type { ProviderProtocol, ProviderDefinition, ProviderPricing } from './providers.js';
export {
  APPROVED_PROVIDERS,
  validateProviderConfiguration,
  isLoopbackEndpoint,
  isPrivateNetworkEndpoint,
  extractIpv4Bytes,
  resolveProviderApiKey,
  sanitizeProviderError,
} from './providers.js';
export type { MetaAdapterConfig } from './config.js';
export { loadMetaConfig } from './config.js';
export type { UsageReport, TokenUsageMetrics, UsageTrackerOptions } from './tracker.js';
export { UsageTracker } from './tracker.js';
export {
  MetaMuseSecurityAdapter,
  CLASSIFICATION_JSON_SCHEMA,
  isValidTokenCount,
  resolveTokenCountWithAliases,
  resolveOptionalTokenCount,
  extractValidatedUsage,
} from './adapter.js';

/** Legacy stub implementation kept for backwards compatibility. */
export class StubMetaAdapter {
  async inspect(_content: string) {
    return {
      flagged: false,
      categories: [] as readonly string[],
      explanation: 'Meta Muse integration stub',
    };
  }
}
