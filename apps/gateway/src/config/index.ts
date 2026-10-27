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
}

export function loadConfig(): GatewayConfig {
  const host = process.env['GATEWAY_HOST'] ?? '127.0.0.1';
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
  const failClosed = process.env['FAIL_CLOSED'] === 'true';

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
  };
}
