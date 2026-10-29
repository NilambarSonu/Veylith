import type { IncomingMessage } from 'node:http';

/**
 * Validates that an incoming HTTP request originates strictly from loopback.
 * Rejects remote IP addresses, DNS rebinding, and cross-origin browser access.
 */
export function validateLoopbackAccess(
  req: IncomingMessage,
  expectedPort: number,
): { allowed: boolean; reason?: string } {
  const remoteAddress = req.socket.remoteAddress;
  const loopbackAddresses = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];

  if (!remoteAddress || !loopbackAddresses.includes(remoteAddress)) {
    return { allowed: false, reason: 'Remote HTTP access is disabled (127.0.0.1 only)' };
  }

  const hostHeader = req.headers['host'];
  if (!hostHeader) {
    return { allowed: false, reason: 'Missing Host header' };
  }

  try {
    const targetUrl = new URL(`http://${hostHeader}`);
    const allowedHostnames = ['127.0.0.1', 'localhost', '[::1]'];

    if (!allowedHostnames.includes(targetUrl.hostname)) {
      return { allowed: false, reason: 'Host header must specify loopback' };
    }

    if (
      targetUrl.username ||
      targetUrl.password ||
      targetUrl.pathname !== '/' ||
      targetUrl.search ||
      targetUrl.hash
    ) {
      return {
        allowed: false,
        reason: 'Host header must identify loopback without userinfo, path, query, or hash',
      };
    }

    const hostPort = targetUrl.port ? Number.parseInt(targetUrl.port, 10) : 80;
    if (hostPort !== expectedPort) {
      return { allowed: false, reason: `Host port must match ${expectedPort}` };
    }

    // Origin header verification if present (prevent cross-origin POST/GET hijacking from malicious websites)
    const originHeader = req.headers['origin'];
    if (originHeader) {
      const originUrl = new URL(originHeader);
      if (
        originUrl.origin !== originHeader ||
        !['http:', 'https:'].includes(originUrl.protocol) ||
        !allowedHostnames.includes(originUrl.hostname) ||
        originUrl.username ||
        originUrl.password
      ) {
        return { allowed: false, reason: 'Cross-origin access is disabled' };
      }
      const originPort = originUrl.port
        ? Number.parseInt(originUrl.port, 10)
        : originUrl.protocol === 'https:'
          ? 443
          : 80;
      if (originPort !== expectedPort) {
        return { allowed: false, reason: 'Cross-origin port mismatch' };
      }
    }
  } catch {
    return { allowed: false, reason: 'Malformed Host or Origin header' };
  }

  return { allowed: true };
}

/**
 * Comprehensive HTML escaping utility to ensure zero arbitrary HTML injection.
 */
export function escapeHtml(input: string): string {
  if (typeof input !== 'string') return '';
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/\//g, '&#x2F;')
    .replace(/`/g, '&#x60;');
}

const SECRET_KEY_PATTERN =
  /(?:api[_-]?key|secret|token|bearer|auth(?:orization)?|password|credential)/i;

/**
 * Recursively redacts sensitive credentials, tokens, session IDs, and API keys.
 */
export function redactSecrets<T>(data: T): T {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    // Redact bearer tokens if embedded in strings
    let sanitized = data.replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [REDACTED_TOKEN]');
    sanitized = sanitized.replace(
      /META_[A-Z0-9_]*KEY\s*=\s*['"]?[^'"\s]+['"]?/gi,
      'META_API_KEY=[REDACTED]',
    );
    return sanitized as unknown as T;
  }

  if (Array.isArray(data)) {
    return data.map((item) => redactSecrets(item)) as unknown as T;
  }

  if (typeof data === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      if (
        key === 'tokenUsage' ||
        key === 'promptTokens' ||
        key === 'completionTokens' ||
        key === 'totalTokens'
      ) {
        result[key] = redactSecrets(value);
      } else if (SECRET_KEY_PATTERN.test(key)) {
        if (typeof value === 'string') {
          result[key] = '[REDACTED]';
        } else {
          result[key] = '[REDACTED]';
        }
      } else if (key === 'sessionId' && typeof value === 'string') {
        // Partially mask session identifier: show prefix, mask middle/end
        if (value.startsWith('vyl-sess-')) {
          result[key] = `vyl-sess-***${value.slice(-6)}`;
        } else {
          result[key] = `***${value.slice(-4)}`;
        }
      } else {
        result[key] = redactSecrets(value);
      }
    }
    return result as unknown as T;
  }

  return data;
}

/**
 * Standard HTTP security headers for read-only local dashboard.
 */
export function getSecurityHeaders(): Record<string, string> {
  return {
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
  };
}
