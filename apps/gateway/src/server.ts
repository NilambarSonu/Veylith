/**
 * Veylith Gateway — MCP Security Gateway (Phase 0 Proof of Concept)
 *
 * Architecture: MCP bridge gateway.
 * The gateway presents itself as an MCP server to downstream clients, and
 * acts as an MCP client toward the upstream server. This is NOT a transparent
 * HTTP proxy — it terminates the MCP protocol on both sides.
 *
 * What this preserves:
 *   ✓ JSON-RPC request/response semantics
 *   ✓ Tool listing, tool calling, and results
 *   ✓ Protocol initialization and capability negotiation
 *   ✓ Error propagation
 *
 * What this does NOT preserve (Phase 0 limitations):
 *   ✗ SSE streaming passthrough (requests are fully buffered)
 *   ✗ Server-initiated notifications to clients
 *   ✗ Session state across requests (stateless per-request model)
 *   ✗ Resource subscriptions
 *   ✗ Prompt templates passthrough
 *
 * The gateway intercepts tools/call requests to apply policy rules
 * before forwarding to the upstream server.
 */

import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createServer } from 'node:http';
import { loadConfig } from './config/index.js';
import { Logger } from './observability/logger.js';
import { PolicyEvaluator } from '@veylith/policy-engine';
import type { PolicyRule } from '@veylith/core';
import * as z from 'zod/v4';

const config = loadConfig();
const logger = new Logger(config.logLevel, config.redactSecrets);

// Build policy rules from configuration
const policyRules: PolicyRule[] = config.blockedTools.map((toolName, idx) => ({
  id: `block-tool-${idx}`,
  description: `Block calls to tool: ${toolName}`,
  method: 'tools/call',
  toolName,
  decision: 'block' as const,
  enabled: true,
}));

const policyEvaluator = new PolicyEvaluator(policyRules, 'allow');

/**
 * Create an MCP client connected to the upstream server.
 * A new client is created per request for stateless operation.
 */
async function createUpstreamClient(): Promise<Client> {
  const client = new Client({ name: 'veylith-gateway', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL(config.upstreamMcpUrl));
  await client.connect(transport);
  return client;
}

/**
 * Gateway server factory — creates an McpServer that proxies to upstream.
 *
 * The factory pattern means each HTTP request gets a fresh server instance,
 * which in turn creates a fresh upstream client connection.
 */
const handler = createMcpHandler(async () => {
  const server = new McpServer({
    name: 'veylith-gateway',
    version: '0.1.0',
  });

  // Discover upstream tools and register proxied versions
  let upstreamClient: Client | null = null;

  try {
    upstreamClient = await createUpstreamClient();
    const { tools } = await upstreamClient.listTools();

    for (const tool of tools) {
      const toolName = tool.name;

      server.registerTool(
        toolName,
        {
          description: tool.description ?? '',
          // Use a permissive schema since we forward arguments verbatim
          inputSchema: z.record(z.string(), z.unknown()).optional(),
        },
        async (args) => {
          const requestId = crypto.randomUUID();
          const start = performance.now();

          // Evaluate policy
          const policyResult = policyEvaluator.evaluate({
            method: 'tools/call',
            toolName,
          });

          logger.info('Policy evaluation', {
            requestId,
            method: 'tools/call',
            toolName,
            decision: policyResult.decision,
            reason: policyResult.reason,
            evaluationDurationMs: policyResult.evaluationDurationMs,
          });

          if (policyResult.decision === 'block') {
            const durationMs = Math.round((performance.now() - start) * 100) / 100;
            logger.warn('Request blocked by policy', {
              requestId,
              toolName,
              ruleId: policyResult.matchedRule?.id,
              durationMs,
            });

            // Return as a tool error result (protocol-compatible)
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `Veylith policy blocked this call: ${policyResult.reason}`,
                },
              ],
              isError: true,
            };
          }

          // Forward to upstream
          try {
            let forwardClient: Client;
            try {
              forwardClient = await createUpstreamClient();
            } catch (err) {
              const durationMs = Math.round((performance.now() - start) * 100) / 100;
              logger.error('Upstream connection failed', {
                requestId,
                toolName,
                error: err instanceof Error ? err.message : String(err),
                durationMs,
              });
              return {
                content: [
                  {
                    type: 'text' as const,
                    text: 'Veylith gateway: upstream server unavailable',
                  },
                ],
                isError: true,
              };
            }

            try {
              const result = await forwardClient.callTool({
                name: toolName,
                arguments: args as Record<string, unknown>,
              });

              const durationMs = Math.round((performance.now() - start) * 100) / 100;
              logger.info('Request forwarded successfully', {
                requestId,
                toolName,
                decision: 'allow',
                durationMs,
              });

              return {
                content: result.content as Array<{ type: 'text'; text: string }>,
                isError: result.isError ?? false,
              };
            } finally {
              await forwardClient.close().catch(() => {});
            }
          } catch (err) {
            const durationMs = Math.round((performance.now() - start) * 100) / 100;
            logger.error('Upstream call failed', {
              requestId,
              toolName,
              error: err instanceof Error ? err.message : String(err),
              durationMs,
            });
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `Veylith gateway: upstream error — ${err instanceof Error ? err.message : 'unknown'}`,
                },
              ],
              isError: true,
            };
          }
        },
      );
    }
  } finally {
    if (upstreamClient) {
      await upstreamClient.close().catch(() => {});
    }
  }

  return server;
});

// HTTP server
const httpServer = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${config.host}:${config.port}`);

  if (url.pathname !== '/mcp') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found. Veylith gateway endpoint is at /mcp' }));
    return;
  }

  // Build web-standard Request
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value !== undefined) {
      if (Array.isArray(value)) {
        for (const v of value) headers.append(key, v);
      } else {
        headers.set(key, value);
      }
    }
  }

  const bodyChunks: Buffer[] = [];
  for await (const chunk of req) {
    bodyChunks.push(chunk as Buffer);
  }
  const body = Buffer.concat(bodyChunks);

  const webRequest = new Request(url.toString(), {
    method: req.method ?? 'POST',
    headers,
    body: ['GET', 'HEAD'].includes(req.method ?? 'GET') ? undefined : body,
  });

  try {
    const webResponse = await handler.fetch(webRequest);
    res.writeHead(webResponse.status, Object.fromEntries(webResponse.headers.entries()));

    if (webResponse.body) {
      const reader = webResponse.body.getReader();
      const pump = async (): Promise<void> => {
        const { done, value } = await reader.read();
        if (done) {
          res.end();
          return;
        }
        res.write(value);
        return pump();
      };
      await pump();
    } else {
      res.end(await webResponse.text());
    }
  } catch (err) {
    logger.error('Gateway handler error', {
      error: err instanceof Error ? err.message : String(err),
    });
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal gateway error' }));
  }
});

httpServer.listen(config.port, config.host, () => {
  logger.info('Veylith gateway started', {
    host: config.host,
    port: config.port,
    upstreamMcpUrl: config.upstreamMcpUrl,
    blockedTools: config.blockedTools as unknown as string[],
    policyRuleCount: policyRules.length,
  });
});

// Graceful shutdown
const shutdown = () => {
  logger.info('Gateway shutting down');
  handler.close();
  httpServer.close(() => {
    logger.info('Gateway closed');
    process.exit(0);
  });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
