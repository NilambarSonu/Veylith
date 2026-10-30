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
    approvedEndpoints: ['https://api.meta.ai/v1/responses'],
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
 * Checks if a given URL is a loopback destination.
 * Covers IPv4 loopback (127.0.0.0/8, 0.0.0.0), localhost, IPv6 loopback (::1, [::1], ::),
 * and IPv4-mapped IPv6 loopback addresses (::ffff:127.0.0.0/104 or ::ffff:7f00:0/104).
 */
export function isLoopbackEndpoint(urlString: string): boolean {
  try {
    const url = new URL(urlString);
    const host = url.hostname.toLowerCase();
    const cleanHost = host.replace(/^\[|\]$/g, '');
    return (
      cleanHost === '127.0.0.1' ||
      cleanHost === 'localhost' ||
      cleanHost === '::1' ||
      cleanHost === '::' ||
      cleanHost === '0.0.0.0' ||
      cleanHost.startsWith('127.') ||
      cleanHost.startsWith('::ffff:127.') ||
      cleanHost.startsWith('::ffff:7f')
    );
  } catch {
    return false;
  }
}

/**
 * Checks if a given URL points to a private or link-local network destination.
 * Covers RFC 1918 IPv4 private subnets, RFC 3927 link-local, .local/.internal/.lan mDNS/internal names,
 * IPv6 Unique-Local (RFC 4193 fc00::/7), IPv6 Link-Local (RFC 4291 fe80::/10),
 * and IPv4-mapped IPv6 private ranges.
 */
export function isPrivateNetworkEndpoint(urlString: string): boolean {
  try {
    const url = new URL(urlString);
    const host = url.hostname.toLowerCase();
    if (isLoopbackEndpoint(urlString)) return true;
    const cleanHost = host.replace(/^\[|\]$/g, '');

    if (
      cleanHost.endsWith('.local') ||
      cleanHost.endsWith('.internal') ||
      cleanHost.endsWith('.lan')
    ) {
      return true;
    }

    // IPv6 Unique-Local (fc00::/7 -> fc.. or fd..) and Link-Local (fe80::/10 -> fe8.. to feb..)
    if (/^f[cd][0-9a-f]{2}:/i.test(cleanHost) || cleanHost.startsWith('fc') || cleanHost.startsWith('fd')) {
      return true;
    }
    if (/^fe[89ab][0-9a-f]:/i.test(cleanHost) || cleanHost.startsWith('fe80')) {
      return true;
    }

    // IPv4-mapped IPv6 private ranges (e.g. ::ffff:10.0.0.1, ::ffff:192.168.1.1, ::ffff:169.254.1.1, ::ffff:a00:, ::ffff:c0a8:, ::ffff:a9fe:)
    if (
      cleanHost.startsWith('::ffff:10.') ||
      cleanHost.startsWith('::ffff:192.168.') ||
      cleanHost.startsWith('::ffff:169.254.') ||
      cleanHost.startsWith('::ffff:a00:') ||
      cleanHost.startsWith('::ffff:c0a8:') ||
      cleanHost.startsWith('::ffff:a9fe:')
    ) {
      return true;
    }

    // IPv4 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
    const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(cleanHost);
    if (ipv4Match) {
      const b0 = parseInt(ipv4Match[1]!, 10);
      const b1 = parseInt(ipv4Match[2]!, 10);
      if (b0 === 10) return true;
      if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
      if (b0 === 192 && b1 === 168) return true;
      if (b0 === 169 && b1 === 254) return true;
      if (b0 === 0) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Validates that the requested provider, endpoint, and model strictly conform to the approved allowlist.
 * Live mode MUST accept only the exact approved HTTPS endpoint for the selected provider.
 * Loopback, private IP, non-HTTPS, unexpected ports, and cross-provider destinations are strictly rejected.
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

  // Model validation: must be an approved model for this provider
  if (!def.approvedModels.includes(model)) {
    throw new Error(
      `Provider '${provider}' does not permit model '${model}'. Approved models for ${def.name}: ${def.approvedModels.join(', ')}`,
    );
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(endpoint);
  } catch {
    throw new Error(`Invalid URL format for provider endpoint: '${endpoint}'`);
  }

  // Strict HTTPS protocol enforcement
  if (parsedUrl.protocol !== 'https:') {
    throw new Error(
      `Insecure protocol '${parsedUrl.protocol}' for provider '${provider}'. Live model inference strictly requires HTTPS destinations.`,
    );
  }

  // Strict rejection of loopback and localhost
  if (isLoopbackEndpoint(endpoint)) {
    throw new Error(
      `Loopback destination '${endpoint}' is strictly forbidden for live provider '${provider}' inference. Live inference requires approved external HTTPS destinations.`,
    );
  }

  // Strict rejection of private network destinations
  if (isPrivateNetworkEndpoint(endpoint)) {
    throw new Error(
      `Private network destination '${endpoint}' is strictly forbidden for live provider '${provider}' inference.`,
    );
  }

  // Strict rejection of non-standard ports
  if (parsedUrl.port && parsedUrl.port !== '443') {
    throw new Error(
      `Non-standard port '${parsedUrl.port}' for endpoint '${endpoint}' is forbidden. Live inference permits standard HTTPS destinations only.`,
    );
  }

  // Endpoint validation: must be in approvedEndpoints
  const normalizedEndpoint = endpoint.replace(/\/$/, '');
  const isApproved = def.approvedEndpoints.some(
    (approved) => approved.replace(/\/$/, '') === normalizedEndpoint,
  );

  if (!isApproved) {
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
