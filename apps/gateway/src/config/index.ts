/**
 * Gateway configuration — loaded from environment variables.
 *
 * All configuration is validated at startup. Invalid or missing required
 * values cause the process to exit with a clear error message.
 */

import type { MetaAiMode } from '@veylith/meta-adapter';
import type { TrustedToolBinding } from '@veylith/policy-engine';
import type { ToolCapability } from '@veylith/core';

export interface GatewayConfig {
  readonly host: string;
  readonly port: number;
  readonly upstreamMcpUrl: string;
  readonly blockedTools: readonly string[];
  readonly logLevel: string;
  readonly redactSecrets: boolean;
  readonly requestTimeoutMs: number;
  readonly metaAiMode: MetaAiMode;
  readonly metaApiBaseUrl: string;
  readonly metaApiKey?: string;
  readonly metaModel: string;
  readonly failClosed: boolean;
  readonly capabilityBindings: readonly TrustedToolBinding[];
  readonly enforceSessions: boolean;
  readonly allowBinaryResources: boolean;
  readonly maxResourceContentBytes: number;
  readonly maxRequestBodyBytes: number;
  readonly maxConcurrentRequests: number;
  readonly maxConnections: number;
  readonly discoveryCacheTtlMs: number;
  readonly circuitBreakerFailureThreshold: number;
  readonly circuitBreakerResetTimeoutMs: number;
  readonly auditLogPath?: string;
}

export function loadConfig(): GatewayConfig {
  const host = process.env['GATEWAY_HOST'] ?? '127.0.0.1';
  if (!['127.0.0.1', '::1', 'localhost'].includes(host))
    throw new Error('Local client labels are not authentication: gateway must bind to loopback');
  const port = parseInt(process.env['GATEWAY_PORT'] ?? '8787', 10);
  const upstreamMcpUrl = process.env['UPSTREAM_MCP_URL'] ?? 'http://127.0.0.1:8788/mcp';
  const blockedToolsRaw = process.env['BLOCKED_TOOLS'] ?? 'restricted_demo_tool';
  const logLevel = process.env['LOG_LEVEL'] ?? 'info';
  const redactSecrets = process.env['LOG_REDACT_SECRETS'] !== 'false';
  const requestTimeoutMs = parseInt(process.env['REQUEST_TIMEOUT_MS'] ?? '30000', 10);

  const rawMode = process.env['META_AI_MODE'] ?? 'mock';
  const metaAiMode: MetaAiMode = ['mock', 'live', 'disabled'].includes(rawMode)
    ? (rawMode as MetaAiMode)
    : 'mock';

  const metaApiBaseUrl = process.env['META_MODEL_API_BASE_URL'] ?? 'https://api.meta.ai/v1';
  const metaApiKey = process.env['META_MODEL_API_KEY'];
  const metaModel = process.env['META_MODEL'] ?? 'muse-spark-1.3';
  const failClosed = process.env['FAIL_CLOSED'] !== 'false';

  if (isNaN(port) || port < 1 || port > 65535) {
    console.error(`[config] Invalid GATEWAY_PORT: ${process.env['GATEWAY_PORT']}`);
    process.exit(1);
  }

  const blockedTools = blockedToolsRaw
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const rawToolCapabilities = process.env['TOOL_CAPABILITIES'];
  const capabilityBindings: TrustedToolBinding[] = [];
  if (rawToolCapabilities) {
    try {
      if (rawToolCapabilities.trim().startsWith('[')) {
        const parsed = JSON.parse(rawToolCapabilities) as TrustedToolBinding[];
        capabilityBindings.push(...parsed);
      } else {
        const entries = rawToolCapabilities
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        for (const entry of entries) {
          const parts = entry.split(':').map((s) => s.trim());
          if (parts.length >= 2) {
            const toolName = parts[0]!;
            const cap = parts[1]! as ToolCapability;
            const sId = parts.length > 2 ? parts.slice(2).join(':') : upstreamMcpUrl;
            capabilityBindings.push({
              serverId: sId,
              toolName,
              capability: cap,
            });
          }
        }
      }
    } catch (e) {
      console.warn(`[config] Failed to parse TOOL_CAPABILITIES: ${e}`);
    }
  }

  const enforceSessions = process.env['ENFORCE_SESSIONS'] === 'true';
  const allowBinaryResources = process.env['ALLOW_BINARY_RESOURCES'] === 'true';
  const maxResourceContentBytes = parseInt(
    process.env['MAX_RESOURCE_BYTES'] ?? `${5 * 1024 * 1024}`,
    10,
  );
  const maxRequestBodyBytes = parseInt(
    process.env['MAX_REQUEST_BODY_BYTES'] ?? `${1 * 1024 * 1024}`,
    10,
  );
  const maxConcurrentRequests = parseInt(process.env['MAX_CONCURRENT_REQUESTS'] ?? '50', 10);
  const maxConnections = parseInt(process.env['MAX_CONNECTIONS'] ?? '100', 10);
  const discoveryCacheTtlMs = parseInt(process.env['DISCOVERY_CACHE_TTL_MS'] ?? '2000', 10);
  const circuitBreakerFailureThreshold = parseInt(
    process.env['CIRCUIT_BREAKER_FAILURE_THRESHOLD'] ?? '5',
    10,
  );
  const circuitBreakerResetTimeoutMs = parseInt(
    process.env['CIRCUIT_BREAKER_RESET_TIMEOUT_MS'] ?? '10000',
    10,
  );
  const auditLogPath = process.env['AUDIT_LOG_PATH'];

  return {
    host,
    port,
    upstreamMcpUrl,
    blockedTools,
    logLevel,
    redactSecrets,
    requestTimeoutMs,
    metaAiMode,
    metaApiBaseUrl,
    metaApiKey,
    metaModel,
    failClosed,
    capabilityBindings,
    enforceSessions,
    allowBinaryResources,
    maxResourceContentBytes,
    maxRequestBodyBytes,
    maxConcurrentRequests,
    maxConnections,
    discoveryCacheTtlMs,
    circuitBreakerFailureThreshold,
    circuitBreakerResetTimeoutMs,
    auditLogPath,
  };
}
