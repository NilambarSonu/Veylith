/**
 * Provider registry, allowlists, and credential routing for supported AI security providers.
 *
 * Supported providers:
 * - 'meta': Official Meta Responses API (POST https://api.meta.ai/v1/responses)
 * - 'fireworks': Fireworks AI OpenAI-compatible Chat Completions (POST https://api.fireworks.ai/inference/v1/chat/completions)
 * - 'baseten': Baseten OpenAI-compatible Chat Completions (POST https://inference.baseten.co/v1/chat/completions)
 */

export type ModelProvider = 'meta' | 'fireworks' | 'baseten';
export type ProviderProtocol = 'meta-responses' | 'openai-chat-completions';

export interface ProviderPricing {
  readonly standardInputPriceUsd: number;
  readonly cachedInputPriceUsd: number;
  readonly outputTokenPriceUsd: number;
}

export interface ProviderDefinition {
  readonly id: ModelProvider;
  readonly name: string;
  readonly protocol: ProviderProtocol;
  readonly defaultEndpoint: string;
  readonly approvedEndpoints: readonly string[];
  readonly defaultModel: string;
  readonly approvedModels: readonly string[];
  readonly credentialEnvVar: string;
  readonly alternateCredentialEnvVars: readonly string[];
  readonly pricingVerified: boolean;
  readonly pricing?: ProviderPricing;
}

export const APPROVED_PROVIDERS: Record<ModelProvider, ProviderDefinition> = {
  meta: {
    id: 'meta',
    name: 'Meta Model API',
    protocol: 'meta-responses',
    defaultEndpoint: 'https://api.meta.ai/v1/responses',
    approvedEndpoints: ['https://api.meta.ai/v1/responses', 'https://api.meta.ai/v1'],
    defaultModel: 'muse-spark-1.3',
    approvedModels: ['muse-spark-1.3'],
    credentialEnvVar: 'META_MODEL_API_KEY',
    alternateCredentialEnvVars: ['META_API_KEY'],
    pricingVerified: true,
    pricing: {
      standardInputPriceUsd: 0.00000125, // $1.25 / 1M
      cachedInputPriceUsd: 0.00000015, // $0.15 / 1M
      outputTokenPriceUsd: 0.00000425, // $4.25 / 1M
    },
  },
  fireworks: {
    id: 'fireworks',
    name: 'Fireworks AI',
    protocol: 'openai-chat-completions',
    defaultEndpoint: 'https://api.fireworks.ai/inference/v1/chat/completions',
    approvedEndpoints: ['https://api.fireworks.ai/inference/v1/chat/completions'],
    defaultModel: 'accounts/fireworks/models/muse-spark-open',
    approvedModels: ['accounts/fireworks/models/muse-spark-open'],
    credentialEnvVar: 'FIREWORKS_API_KEY',
    alternateCredentialEnvVars: [],
    pricingVerified: false, // Custom/fine-tuned deployment pricing unverified
  },
  baseten: {
    id: 'baseten',
    name: 'Baseten',
    protocol: 'openai-chat-completions',
    defaultEndpoint: 'https://inference.baseten.co/v1/chat/completions',
    approvedEndpoints: ['https://inference.baseten.co/v1/chat/completions'],
    defaultModel: 'meta-models/muse-spark-open-1026',
    approvedModels: ['meta-models/muse-spark-open-1026'],
    credentialEnvVar: 'BASETEN_API_KEY',
    alternateCredentialEnvVars: [],
    pricingVerified: false, // Dedicated/custom model deployment pricing unverified
  },
};

/**
 * Checks if a given URL is a loopback destination (strictly for local unit test fixtures).
 */
export function isLoopbackEndpoint(urlString: string): boolean {
  try {
    const url = new URL(urlString);
    const host = url.hostname.toLowerCase();
    return (
      host === '127.0.0.1' ||
      host === 'localhost' ||
      host === '::1' ||
      host === '[::1]' ||
      host === '0.0.0.0'
    );
  } catch {
    return false;
  }
}

/**
 * Validates that the requested provider, endpoint, and model strictly conform to the approved allowlist.
 */
export function validateProviderConfiguration(
  provider: ModelProvider,
  endpoint: string,
  model: string,
): void {
  const def = APPROVED_PROVIDERS[provider];
  if (!def) {
    throw new Error(
      `Unsupported provider '${String(provider)}'. Approved providers: ${Object.keys(APPROVED_PROVIDERS).join(', ')}`,
    );
  }

  // Model validation
  if (!def.approvedModels.includes(model)) {
    throw new Error(
      `Provider '${provider}' does not permit model '${model}'. Approved models for ${def.name}: ${def.approvedModels.join(', ')}`,
    );
  }

  // Endpoint validation: must be in approvedEndpoints or loopback (test-only)
  const normalizedEndpoint = endpoint.replace(/\/$/, '');
  const isApproved = def.approvedEndpoints.some(
    (approved) => approved.replace(/\/$/, '') === normalizedEndpoint,
  );
  const isLoopback = isLoopbackEndpoint(endpoint);

  if (!isApproved && !isLoopback) {
    throw new Error(
      `Endpoint '${endpoint}' is not an approved destination for provider '${provider}'. Approved destinations: ${def.approvedEndpoints.join(', ')}`,
    );
  }
}

/**
 * Securely resolves the API key for a specified provider from environment variables.
 * Never logs or prints the credential value.
 */
export function resolveProviderApiKey(
  provider: ModelProvider,
  overrideKey?: string,
): string | undefined {
  if (overrideKey && overrideKey.trim().length > 0) {
    return overrideKey.trim();
  }

  const def = APPROVED_PROVIDERS[provider];
  if (!def) return undefined;

  const primaryKey = process.env[def.credentialEnvVar];
  if (primaryKey && primaryKey.trim().length > 0) {
    return primaryKey.trim();
  }

  for (const altVar of def.alternateCredentialEnvVars) {
    const altKey = process.env[altVar];
    if (altKey && altKey.trim().length > 0) {
      return altKey.trim();
    }
  }

  return undefined;
}

/**
 * Sanitizes error messages by scrubbing Bearer tokens, API keys, and secret substrings.
 */
export function sanitizeProviderError(errorMessage: string, activeApiKey?: string): string {
  let sanitized = errorMessage;

  // Scrub active key if provided
  if (activeApiKey && activeApiKey.length >= 8) {
    sanitized = sanitized.split(activeApiKey).join('[REDACTED_API_KEY]');
  }

  // Scrub common Bearer tokens and key formats
  return sanitized
    .replace(/(?:Bearer\s+)[a-zA-Z0-9_\-.]+/gi, 'Bearer [REDACTED]')
    .replace(/\b(?:sk|fw|fwa|base|key)_[a-zA-Z0-9_\-]{16,}\b/gi, '[REDACTED_KEY]')
    .replace(/\bsk-[a-zA-Z0-9_\-.]{16,}\b/gi, 'sk-[REDACTED]');
}
