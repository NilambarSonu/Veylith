/**
 * @veylith/meta-adapter — Meta Muse security inspection adapter.
 *
 * Implements the semantic inspection boundary powered by Meta Muse (muse-spark-1.3).
 * Supports 'mock' (offline test simulation), 'live' (real API with budget controls),
 * and 'disabled' modes.
 */

export type {
  MetaAdapter,
  SemanticInspectionResult,
  MetaAiMode,
  TokenUsage,
  ModelClassification,
} from './types.js';
export { ModelClassificationSchema } from './types.js';
export type { MetaAdapterConfig } from './config.js';
export { loadMetaConfig } from './config.js';
export type { UsageReport, TokenUsageMetrics } from './tracker.js';
export { UsageTracker } from './tracker.js';
export { MetaMuseSecurityAdapter, CLASSIFICATION_JSON_SCHEMA } from './adapter.js';

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
