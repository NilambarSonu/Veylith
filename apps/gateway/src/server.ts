/**
 * Veylith Gateway — MCP Security Gateway (Phase 2C: Complete MCP Inspection & Hardening)
 *
 * Architecture: MCP bridge gateway with multi-tier security inspection:
 *   - Tier 1: Deterministic security invariants (unoverrideable hard rules)
 *   - Tier 2: Heuristic risk screener (<0.1ms triage of clean vs ambiguous payloads)
 *   - Tier 3: Meta Muse semantic model (evaluates complex ambiguous prompts)
 *
 * Security Inspection Stages:
 *   1. Tool Discovery (tools/list metadata & tool description poisoning)
 *   2. Argument Inspection (tools/call parameters & destructive execution)
 *   3. Response Inspection (tools/call outputs & indirect prompt injection)
 *   4. Resource Discovery (resources/list & resources/templates/list)
 *   5. Resource Content (resources/read, binary policy & output size caps)
 *   6. Prompt Discovery (prompts/list)
 *   7. Prompt Messages (prompts/get & instruction hijacking)
 *
 * Session Security & Audit Integrity:
 *   - Cryptographically linked SHA-256 audit log chain
 *   - Per-client session validation & tool/resource whitelisting
 */

import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createServer } from 'node:http';
import { loadConfig } from './config/index.js';
import { Logger } from './observability/logger.js';
import {
  SecurityInspectionEngine,
  ClientSessionManager,
  AuditLogChain,
} from '@veylith/policy-engine';
import { MetaMuseSecurityAdapter } from '@veylith/meta-adapter';
import type {
  PolicyRule,
  InspectionContext,
  ResourceContentItem,
  PromptMessageItem,
} from '@veylith/core';
import * as z from 'zod/v4';

export const config = loadConfig();
export const logger = new Logger(config.logLevel, config.redactSecrets);

// Build static policy rules from configuration (e.g. BLOCKED_TOOLS)
export const policyRules: PolicyRule[] = config.blockedTools.map((toolName, idx) => ({
  id: `block-tool-${idx}`,
  description: `Block calls to tool: ${toolName}`,
  method: 'tools/call',
  toolName,
  decision: 'block' as const,
  enabled: true,
}));

// Instantiate Meta Muse adapter
export const metaAdapter = new MetaMuseSecurityAdapter({
  mode: config.metaAiMode,
  apiBaseUrl: config.metaApiBaseUrl,
  apiKey: config.metaApiKey,
  model: config.metaModel,
});

// Shared session manager and audit chain
export const sessionManager = new ClientSessionManager();
export const auditChain = new AuditLogChain();

// Instantiate Hybrid Security Inspection Engine
export const securityEngine = new SecurityInspectionEngine(policyRules, metaAdapter, {
  failClosed: config.failClosed,
  policyVersion: 'v1.0.0',
  capabilityBindings: config.capabilityBindings,
  sessionManager,
  auditChain,
  maxResourceContentBytes: config.maxResourceContentBytes,
  allowBinaryResources: config.allowBinaryResources,
});

/**
 * Create an MCP client connected to the upstream server.
 * A new client is created per request for stateless operation.
 */
export async function createUpstreamClient(): Promise<Client> {
  const client = new Client({ name: 'veylith-gateway', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL(config.upstreamMcpUrl));
  await client.connect(transport);
  return client;
}

/**
 * Gateway server factory — creates an McpServer that proxies to upstream with full security mediation.
 */
export const handler = createMcpHandler(async ({ requestInfo }) => {
  const server = new McpServer({
    name: 'veylith-gateway',
    version: '0.1.0',
  });

  // Extract session context from request headers if available
  const headers = requestInfo?.headers;
  const sessionId = headers?.get('x-veylith-session-id') ?? undefined;
  const clientIdentity =
    headers?.get('x-veylith-client-id') ?? (sessionId ? undefined : 'local-anonymous');

  let upstreamClient: Client | null = null;

  try {
    upstreamClient = await createUpstreamClient();

    // ----------------------------------------------------
    // 1. TOOL DISCOVERY & REGISTRATION
    // ----------------------------------------------------
    let tools: readonly { name: string; description?: string; inputSchema?: unknown }[] = [];
    try {
      const toolsResult = await upstreamClient.listTools();
      tools = toolsResult.tools;
    } catch {
      // Upstream does not support tools or error
    }

    if (tools.length > 0) {
      const discoveryOutcome = await securityEngine.inspectDiscovery(tools, {
        serverId: config.upstreamMcpUrl,
        clientIdentity,
        sessionId,
      });

      for (const blocked of discoveryOutcome.blockedTools) {
        logger.warn('Tool blocked from discovery (tool-description poisoning or static rule)', {
          toolName: blocked.name,
          threatCategory: blocked.threatCategory,
          reason: blocked.reason,
        });
      }

      for (const tool of discoveryOutcome.cleanTools) {
        const toolName = tool.name;

        server.registerTool(
          toolName,
          {
            description: tool.description ?? '',
            inputSchema: z.record(z.string(), z.unknown()).optional(),
          },
          async (args) => {
            const requestId = crypto.randomUUID();
            const start = performance.now();
            const ctx: InspectionContext = {
              requestId,
              stage: 'call_arguments',
              method: 'tools/call',
              toolName,
              serverId: config.upstreamMcpUrl,
              clientIdentity,
              sessionId,
              timestamp: new Date().toISOString(),
            };

            const argInspection = await securityEngine.inspectArguments(
              ctx,
              toolName,
              (args as Record<string, unknown>) ?? {},
              tool,
            );

            logger.info('Argument security evaluation', {
              requestId,
              toolName,
              action: argInspection.action,
              threatCategory: argInspection.threatCategory,
              origin: argInspection.origin,
              durationMs: argInspection.evaluationDurationMs,
            });

            if (
              argInspection.action === 'block' ||
              (argInspection.action === 'review' && config.failClosed)
            ) {
              const durationMs = Math.round((performance.now() - start) * 100) / 100;
              logger.warn('Tool call blocked by security engine', {
                requestId,
                toolName,
                threatCategory: argInspection.threatCategory,
                explanation: argInspection.explanation,
                ruleId: argInspection.ruleId,
                durationMs,
              });

              return {
                content: [
                  {
                    type: 'text' as const,
                    text: `Veylith policy blocked this call: ${argInspection.explanation}`,
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
                const rawResult = await forwardClient.callTool({
                  name: toolName,
                  arguments: args as Record<string, unknown>,
                });

                const respCtx: InspectionContext = {
                  requestId,
                  stage: 'call_response',
                  method: 'tools/call',
                  toolName,
                  serverId: config.upstreamMcpUrl,
                  clientIdentity,
                  sessionId,
                  timestamp: new Date().toISOString(),
                };

                const respOutcome = await securityEngine.inspectResponse(
                  respCtx,
                  toolName,
                  (rawResult.content as Array<{ type: string; text?: string }>) ?? [],
                );

                if (respOutcome.isRedacted) {
                  logger.warn('Tool response sanitized by security engine', {
                    requestId,
                    toolName,
                    threatCategory: respOutcome.result.threatCategory,
                    explanation: respOutcome.result.explanation,
                  });
                }

                const durationMs = Math.round((performance.now() - start) * 100) / 100;
                logger.info('Request completed', {
                  requestId,
                  toolName,
                  action: 'allow',
                  isRedacted: respOutcome.isRedacted,
                  durationMs,
                });

                return {
                  content: respOutcome.sanitizedContent as Array<{ type: 'text'; text: string }>,
                  isError: (rawResult.isError ?? false) || respOutcome.isRedacted,
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
    }

    // ----------------------------------------------------
    // 2. RESOURCE DISCOVERY & REGISTRATION
    // ----------------------------------------------------
    try {
      const { resources } = await upstreamClient.listResources();
      const templatesRes = await upstreamClient.listResourceTemplates().catch(() => ({
        resourceTemplates: [],
      }));
      const templates = templatesRes.resourceTemplates ?? [];

      const resourceOutcome = await securityEngine.inspectResourceDiscovery(resources, templates, {
        requestId: crypto.randomUUID(),
        stage: 'resource_discovery',
        method: 'resources/list',
        serverId: config.upstreamMcpUrl,
        clientIdentity,
        sessionId,
        timestamp: new Date().toISOString(),
      });

      for (const blocked of resourceOutcome.blockedResources) {
        logger.warn('Resource blocked from discovery', {
          uri: blocked.uri,
          name: blocked.name,
          threatCategory: blocked.threatCategory,
          reason: blocked.reason,
        });
      }

      for (const res of resourceOutcome.cleanResources) {
        server.registerResource(
          res.name,
          res.uri,
          {
            description: res.description,
            mimeType: res.mimeType,
          },
          async (uri) => {
            const requestId = crypto.randomUUID();
            const start = performance.now();
            const forwardClient = await createUpstreamClient();

            try {
              const rawResult = await forwardClient.readResource({ uri: uri.href });
              const ctx: InspectionContext = {
                requestId,
                stage: 'resource_content',
                method: 'resources/read',
                resourceUri: uri.href,
                serverId: config.upstreamMcpUrl,
                clientIdentity,
                sessionId,
                timestamp: new Date().toISOString(),
              };

              const contentOutcome = await securityEngine.inspectResourceContent(
                ctx,
                uri.href,
                (rawResult.contents as ResourceContentItem[]) ?? [],
              );

              if (contentOutcome.isBlocked) {
                logger.warn('Resource content blocked by security engine', {
                  uri: uri.href,
                  reason: contentOutcome.blockReason,
                });
                return {
                  contents: [
                    {
                      uri: uri.href,
                      text: `[Veylith Security Notice]: Resource '${uri.href}' access blocked. Reason: ${contentOutcome.blockReason}`,
                      mimeType: 'text/plain',
                    },
                  ],
                };
              }

              const durationMs = Math.round((performance.now() - start) * 100) / 100;
              logger.info('Resource read completed', {
                uri: uri.href,
                isRedacted: contentOutcome.isRedacted,
                durationMs,
              });

              return {
                contents: contentOutcome.sanitizedItems.map((item) =>
                  item.blob !== undefined
                    ? {
                        uri: item.uri,
                        mimeType: item.mimeType ?? 'application/octet-stream',
                        blob: item.blob,
                      }
                    : {
                        uri: item.uri,
                        mimeType: item.mimeType ?? 'text/plain',
                        text: item.text ?? '',
                      },
                ),
              };
            } finally {
              await forwardClient.close().catch(() => {});
            }
          },
        );
      }

      // Register capability & handlers for subscribe/unsubscribe
      server.server.registerCapabilities({
        resources: {
          subscribe: true,
          listChanged: true,
        },
      });

      server.server.setRequestHandler('resources/subscribe', async (req) => {
        const uri = (req.params as { uri?: string })?.uri;
        if (!uri) throw new Error('Missing uri parameter');
        const forwardClient = await createUpstreamClient();
        try {
          await forwardClient.subscribeResource({ uri });
          return {};
        } finally {
          await forwardClient.close().catch(() => {});
        }
      });

      server.server.setRequestHandler('resources/unsubscribe', async (req) => {
        const uri = (req.params as { uri?: string })?.uri;
        if (!uri) throw new Error('Missing uri parameter');
        const forwardClient = await createUpstreamClient();
        try {
          await forwardClient.unsubscribeResource({ uri });
          return {};
        } finally {
          await forwardClient.close().catch(() => {});
        }
      });
    } catch {
      // Upstream does not support resources or empty
    }

    // ----------------------------------------------------
    // 3. PROMPT DISCOVERY & REGISTRATION
    // ----------------------------------------------------
    try {
      const { prompts } = await upstreamClient.listPrompts();
      const promptOutcome = await securityEngine.inspectPromptDiscovery(prompts, {
        requestId: crypto.randomUUID(),
        stage: 'prompt_discovery',
        method: 'prompts/list',
        serverId: config.upstreamMcpUrl,
        clientIdentity,
        sessionId,
        timestamp: new Date().toISOString(),
      });

      for (const blocked of promptOutcome.blockedPrompts) {
        logger.warn('Prompt blocked from discovery', {
          name: blocked.name,
          threatCategory: blocked.threatCategory,
          reason: blocked.reason,
        });
      }

      for (const prompt of promptOutcome.cleanPrompts) {
        const promptHandler = async (args?: Record<string, unknown>) => {
          const requestId = crypto.randomUUID();
          const start = performance.now();
          const forwardClient = await createUpstreamClient();

          try {
            const rawResult = await forwardClient.getPrompt({
              name: prompt.name,
              arguments: (args as Record<string, string>) ?? {},
            });

            const ctx: InspectionContext = {
              requestId,
              stage: 'prompt_messages',
              method: 'prompts/get',
              promptName: prompt.name,
              serverId: config.upstreamMcpUrl,
              clientIdentity,
              sessionId,
              timestamp: new Date().toISOString(),
            };

            const msgOutcome = await securityEngine.inspectPromptMessages(
              ctx,
              prompt.name,
              (rawResult.messages as PromptMessageItem[]) ?? [],
              args,
            );

            if (msgOutcome.isBlocked) {
              logger.warn('Prompt messages blocked by security engine', {
                promptName: prompt.name,
                reason: msgOutcome.blockReason,
              });
              return {
                description: rawResult.description,
                messages: [
                  {
                    role: 'user' as const,
                    content: {
                      type: 'text' as const,
                      text: `[Veylith Security Notice]: Prompt '${prompt.name}' blocked. Reason: ${msgOutcome.blockReason}`,
                    },
                  },
                ],
              };
            }

            const durationMs = Math.round((performance.now() - start) * 100) / 100;
            logger.info('Prompt get completed', {
              promptName: prompt.name,
              isRedacted: msgOutcome.isRedacted,
              durationMs,
            });

            return {
              description: rawResult.description,
              messages: msgOutcome.sanitizedMessages.map((m) => ({
                role: (m.role === 'assistant' ? 'assistant' : 'user') as 'user' | 'assistant',
                content: {
                  type: 'text' as const,
                  text:
                    typeof m.content.text === 'string' ? m.content.text : JSON.stringify(m.content),
                },
              })),
            };
          } finally {
            await forwardClient.close().catch(() => {});
          }
        };

        if (prompt.arguments && prompt.arguments.length > 0) {
          const argsShape: Record<string, z.ZodType> = {};
          for (const arg of prompt.arguments) {
            argsShape[arg.name] = arg.required ? z.string() : z.string().optional();
          }
          server.registerPrompt(
            prompt.name,
            {
              description: prompt.description,
              argsSchema: argsShape,
            },
            promptHandler,
          );
        } else {
          server.registerPrompt(
            prompt.name,
            {
              description: prompt.description,
            },
            () => promptHandler(),
          );
        }
      }
    } catch {
      // Upstream does not support prompts or empty
    }
  } finally {
    if (upstreamClient) {
      await upstreamClient.close().catch(() => {});
    }
  }

  return server;
});

// HTTP server
export const httpServer = createServer(async (req, res) => {
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

  // Also support ?sessionId=... query parameter
  if (!headers.has('x-veylith-session-id') && url.searchParams.has('sessionId')) {
    headers.set('x-veylith-session-id', url.searchParams.get('sessionId')!);
  }
  if (!headers.has('x-veylith-client-id') && url.searchParams.has('clientId')) {
    headers.set('x-veylith-client-id', url.searchParams.get('clientId')!);
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

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  httpServer.listen(config.port, config.host, () => {
    logger.info('Veylith gateway started', {
      host: config.host,
      port: config.port,
      upstreamMcpUrl: config.upstreamMcpUrl,
      blockedTools: config.blockedTools as unknown as string[],
      metaAiMode: config.metaAiMode,
      metaModel: config.metaModel,
      policyRuleCount: policyRules.length,
      enforceSessions: config.enforceSessions,
    });
  });

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
}
