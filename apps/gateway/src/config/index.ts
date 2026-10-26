/**
 * Gateway configuration — loaded from environment variables.
 *
 * All configuration is validated at startup. Invalid or missing required
 * values cause the process to exit with a clear error message.
 */

export interface GatewayConfig {
  readonly host: string;
  readonly port: number;
  readonly upstreamMcpUrl: string;
  readonly blockedTools: readonly string[];
  readonly logLevel: string;
  readonly redactSecrets: boolean;
  readonly requestTimeoutMs: number;
}

export function loadConfig(): GatewayConfig {
  const host = process.env['GATEWAY_HOST'] ?? '127.0.0.1';
  const port = parseInt(process.env['GATEWAY_PORT'] ?? '8787', 10);
  const upstreamMcpUrl = process.env['UPSTREAM_MCP_URL'] ?? 'http://127.0.0.1:8788/mcp';
  const blockedToolsRaw = process.env['BLOCKED_TOOLS'] ?? 'restricted_demo_tool';
  const logLevel = process.env['LOG_LEVEL'] ?? 'info';
  const redactSecrets = process.env['LOG_REDACT_SECRETS'] !== 'false';
  const requestTimeoutMs = parseInt(process.env['REQUEST_TIMEOUT_MS'] ?? '30000', 10);

  if (isNaN(port) || port < 1 || port > 65535) {
    console.error(`[config] Invalid GATEWAY_PORT: ${process.env['GATEWAY_PORT']}`);
    process.exit(1);
  }

  const blockedTools = blockedToolsRaw
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  return {
    host,
    port,
    upstreamMcpUrl,
    blockedTools,
    logLevel,
    redactSecrets,
    requestTimeoutMs,
  };
}
