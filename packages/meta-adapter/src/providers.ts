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
 * Extracts IPv4 bytes [b0, b1, b2, b3] from:
 * 1. Dotted-decimal IPv4 (e.g. "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1")
 * 2. IPv4-mapped IPv6 in dotted format (e.g. "::ffff:127.0.0.1", "::ffff:172.16.0.1")
 * 3. IPv4-mapped IPv6 in WHATWG hex format (e.g. "::ffff:7f00:1", "::ffff:ac10:1", "::ffff:a00:1")
 */
export function extractIpv4Bytes(cleanHost: string): [number, number, number, number] | null {
  const normalized = cleanHost.replace(/^\[|\]$/g, '').trim().toLowerCase();

  // Check dotted-decimal IPv4 or ::ffff:d.d.d.d or 0:0:0:0:0:ffff:d.d.d.d
  const dotted = /^(?:::ffff:|(?:0+:){5}ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/i.exec(normalized);
  if (dotted) {
    const b0 = parseInt(dotted[1]!, 10);
    const b1 = parseInt(dotted[2]!, 10);
    const b2 = parseInt(dotted[3]!, 10);
    const b3 = parseInt(dotted[4]!, 10);
    if (b0 <= 255 && b1 <= 255 && b2 <= 255 && b3 <= 255) {
      return [b0, b1, b2, b3];
    }
  }

  // Check WHATWG-normalized hex form ::ffff:H1:H2 or 0:0:0:0:0:ffff:H1:H2
  const hex = /^(?:::ffff:|(?:0+:){5}ffff:)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(normalized);
  if (hex) {
    const h1 = parseInt(hex[1]!, 16);
    const h2 = parseInt(hex[2]!, 16);
    return [(h1 >> 8) & 0xff, h1 & 0xff, (h2 >> 8) & 0xff, h2 & 0xff];
  }

  return null;
}

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

    // Hostname checks
    if (cleanHost === 'localhost' || cleanHost === '::1' || cleanHost === '::' || cleanHost === '0.0.0.0') {
      return true;
    }

    const bytes = extractIpv4Bytes(cleanHost);
    if (bytes) {
      const [b0] = bytes;
      // 127.0.0.0/8 or 0.0.0.0/8
      return b0 === 127 || b0 === 0;
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Checks if a given URL points to a private or link-local network destination.
 * Covers RFC 1918 IPv4 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
 * RFC 3927 link-local (169.254.0.0/16), .local/.internal/.lan mDNS/internal names,
 * IPv6 Unique-Local (RFC 4193 fc00::/7), IPv6 Link-Local (RFC 4291 fe80::/10),
 * and IPv4-mapped IPv6 equivalents for all of the above.
 */
export function isPrivateNetworkEndpoint(urlString: string): boolean {
  try {
    const url = new URL(urlString);
    const host = url.hostname.toLowerCase();
    if (isLoopbackEndpoint(urlString)) return true;
    const cleanHost = host.replace(/^\[|\]$/g, '');

    // Internal/mDNS domain names
    if (
      cleanHost.endsWith('.local') ||
      cleanHost.endsWith('.internal') ||
      cleanHost.endsWith('.lan')
    ) {
      return true;
    }

    // IPv6 Unique-Local (RFC 4193 fc00::/7 -> fc.. or fd..)
    if (/^f[cd][0-9a-f]{0,2}:/i.test(cleanHost) || cleanHost.startsWith('fc') || cleanHost.startsWith('fd')) {
      return true;
    }

    // IPv6 Link-Local (RFC 4291 fe80::/10 -> fe8.. to feb..)
    if (/^fe[89ab][0-9a-f]{0,2}:/i.test(cleanHost) || cleanHost.startsWith('fe80')) {
      return true;
    }

    // Extract IPv4 bytes (covers native IPv4, ::ffff:d.d.d.d, and ::ffff:hex:hex)
    const bytes = extractIpv4Bytes(cleanHost);
    if (bytes) {
      const [b0, b1] = bytes;
      // 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
      if (b0 === 10) return true;
      // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
      if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
      // 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
      if (b0 === 192 && b1 === 168) return true;
      // 169.254.0.0/16 (169.254.0.0 - 169.254.255.255, RFC 3927 Link-Local)
      if (b0 === 169 && b1 === 254) return true;
      // 127.0.0.0/8 or 0.0.0.0/8
      if (b0 === 127 || b0 === 0) return true;
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
