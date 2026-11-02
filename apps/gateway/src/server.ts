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
import { once } from 'node:events';
import { loadConfig } from './config/index.js';
import { localBoundaryError } from './http/local-boundary.js';
import { Logger } from './observability/logger.js';
import {
  SecurityInspectionEngine,
  ClientSessionManager,
  AuditLogChain,
  toolInputContract,
  collectClientArgumentText,
} from '@veylith/policy-engine';
import { MetaMuseSecurityAdapter } from '@veylith/meta-adapter';
import { CircuitBreaker, CircuitBreakerOpenError } from './resilience/circuit-breaker.js';
import type {
  PolicyRule,
  InspectionContext,
  ResourceContentItem,
  PromptMessageItem,
} from '@veylith/core';
import * as z from 'zod/v4';

export const config = loadConfig();
export const logger = new Logger(config.logLevel, config.redactSecrets);

// Circuit breaker for protecting upstream connections and failing fast
export const upstreamCircuitBreaker = new CircuitBreaker({
  failureThreshold: config.circuitBreakerFailureThreshold,
  resetTimeoutMs: config.circuitBreakerResetTimeoutMs,
});

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

// Shared session manager and audit chain with optional persistence
export const sessionManager = new ClientSessionManager();
export const auditChain = new AuditLogChain({
  storagePath: config.auditLogPath,
});

// Instantiate Hybrid Security Inspection Engine
export const securityEngine = new SecurityInspectionEngine(policyRules, metaAdapter, {
  failClosed: config.failClosed,
  policyVersion: 'v2f.1',
  capabilityBindings: config.capabilityBindings,
  sessionManager,
  auditChain,
  maxResourceContentBytes: config.maxResourceContentBytes,
  allowBinaryResources: config.allowBinaryResources,
});

// Discovery cache interface and storage
interface DiscoveredUpstreamState {
  readonly tools: readonly { name: string; description?: string; inputSchema?: unknown }[];
  readonly resources: readonly ResourceContentItem[];
  readonly templates: readonly unknown[];
  readonly prompts: readonly {
    name: string;
    description?: string;
    arguments?: readonly { name: string; description?: string; required?: boolean }[];
  }[];
  readonly cachedAt: number;
}

const upstreamDiscoveryCache = new Map<string, DiscoveredUpstreamState>();

export function invalidateDiscoveryCache(): void {
  upstreamDiscoveryCache.clear();
}

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
export const handler = createMcpHandler(
  async ({ requestInfo }) => {
    const server = new McpServer({
      name: 'veylith-gateway',
      version: '0.1.0',
    });

    // Extract session context from request headers if available
    const headers = requestInfo?.headers;
    const sessionId = headers?.get('x-veylith-session-id') ?? undefined;
    const clientIdentity =
      headers?.get('x-veylith-client-id') ?? (sessionId ? undefined : 'local-anonymous');

    // Only the HTTP adapter sets this marker, after removing any client-supplied value.
    // Invocations always refresh discovery; a TTL is a performance hint, not authorization.
    const cacheable = headers?.get('x-veylith-internal-cache') === 'list';
    const cacheKey = JSON.stringify([
      config.upstreamMcpUrl,
      'v1.0.0',
      metaAdapter.mode,
      clientIdentity,
      sessionId,
      securityEngine.capabilityRegistry.baselineRevision,
    ]);
    const cached = upstreamDiscoveryCache.get(cacheKey);
    const now = Date.now();
    let discovered: DiscoveredUpstreamState;

    if (
      cacheable &&
      cached &&
      config.discoveryCacheTtlMs > 0 &&
      now - cached.cachedAt < config.discoveryCacheTtlMs
    ) {
      discovered = cached;
    } else {
      let fetchedTools: readonly { name: string; description?: string; inputSchema?: unknown }[] =
        [];
      let fetchedResources: readonly ResourceContentItem[] = [];
      let fetchedTemplates: readonly unknown[] = [];
      let fetchedPrompts: readonly {
        name: string;
        description?: string;
        arguments?: readonly { name: string; description?: string; required?: boolean }[];
      }[] = [];

      let upstreamClient: Client | null = null;
      try {
        upstreamClient = await upstreamCircuitBreaker.execute(() => createUpstreamClient());
        try {
          const toolsResult = await upstreamClient.listTools(undefined, { cacheMode: 'refresh' });
          fetchedTools = toolsResult.tools;
        } catch {
          // Upstream does not support tools or error
        }
        try {
          const { resources } = await upstreamClient.listResources(undefined, {
            cacheMode: 'refresh',
          });
          fetchedResources = (resources as unknown as ResourceContentItem[]) ?? [];
          const templatesRes = await upstreamClient
            .listResourceTemplates(undefined, { cacheMode: 'refresh' })
            .catch(() => ({
              resourceTemplates: [],
            }));
          fetchedTemplates = templatesRes.resourceTemplates ?? [];
        } catch {
          // Upstream does not support resources or empty
        }
        try {
          const { prompts } = await upstreamClient.listPrompts(undefined, { cacheMode: 'refresh' });
          fetchedPrompts = (prompts as unknown as typeof fetchedPrompts) ?? [];
        } catch {
          // Upstream does not support prompts or empty
        }
      } finally {
        if (upstreamClient) {
          await upstreamClient.close().catch(() => {});
        }
      }

      discovered = {
        tools: fetchedTools,
        resources: fetchedResources,
        templates: fetchedTemplates,
        prompts: fetchedPrompts,
        cachedAt: now,
      };
      if (cacheable) {
        if (upstreamDiscoveryCache.size >= 128) upstreamDiscoveryCache.clear();
        upstreamDiscoveryCache.set(cacheKey, discovered);
      }
    }

    // ----------------------------------------------------
    // 1. TOOL DISCOVERY & REGISTRATION
    // ----------------------------------------------------
    const tools = discovered.tools;
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

        let inputContract;
        try {
          inputContract = toolInputContract(config.upstreamMcpUrl, tool.inputSchema);
        } catch (error) {
          logger.warn('Unsupported tool contract quarantined', { toolName, error: String(error) });
          continue;
        }
        server.registerTool(
          toolName,
          {
            description: tool.description ?? '',
            inputSchema: inputContract,
          },
          async (args, extra) => {
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
                forwardClient = await upstreamCircuitBreaker.execute(() => createUpstreamClient());
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
                // Revalidate on the same connection immediately before forwarding.
                // MCP has no atomic definition-version + invocation primitive: server-side
                // behavior changes after this check remain a documented residual race.
                const current = (
                  await forwardClient.listTools(undefined, {
                    signal: extra.mcpReq.signal,
                    cacheMode: 'refresh',
                  })
                ).tools.find((t) => t.name === toolName);
                if (!current)
                  return {
                    content: [
                      {
                        type: 'text' as const,
                        text: 'Veylith: tool disappeared before invocation',
                      },
                    ],
                    isError: true,
                  };
                const freshInspection = await securityEngine.inspectArguments(
                  ctx,
                  toolName,
                  (args as Record<string, unknown>) ?? {},
                  current,
                );
                if (freshInspection.action === 'block' || freshInspection.action === 'review') {
                  return {
                    content: [
                      {
                        type: 'text' as const,
                        text: `Veylith policy ${freshInspection.action === 'review' ? 'quarantined' : 'blocked'} this call: ${freshInspection.explanation}`,
                      },
                    ],
                    isError: true,
                  };
                }
                const validated = await toolInputContract(
                  config.upstreamMcpUrl,
                  current.inputSchema,
                )['~standard'].validate(args ?? {});
                if (validated.issues)
                  return {
                    content: [
                      {
                        type: 'text' as const,
                        text: 'Veylith policy blocked this call: current input contract rejected arguments',
                      },
                    ],
                    isError: true,
                  };
                extra.mcpReq.signal.throwIfAborted();
                const rawResult = await upstreamCircuitBreaker.execute(() =>
                  forwardClient.callTool(
                    {
                      name: toolName,
                      arguments: args as Record<string, unknown>,
                    },
                    { signal: extra.mcpReq.signal },
                  ),
                );

                const respCtx: InspectionContext = {
                  requestId,
                  stage: 'call_response',
                  clientArgumentText: collectClientArgumentText(args),
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
      const resources = discovered.resources as unknown as readonly {
        uri: string;
        name: string;
        description?: string;
        mimeType?: string;
      }[];
      const templates = discovered.templates as readonly {
        uriTemplate: string;
        name: string;
        description?: string;
        mimeType?: string;
      }[];

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
          async (uri, extra) => {
            const requestId = crypto.randomUUID();
            const start = performance.now();
            const forwardClient = await upstreamCircuitBreaker.execute(() =>
              createUpstreamClient(),
            );

            try {
              extra.mcpReq.signal.throwIfAborted();
              if (
                sessionId &&
                (!sessionManager.validateSession(sessionId, clientIdentity, config.upstreamMcpUrl)
                  .valid ||
                  !sessionManager.isResourceAuthorized(sessionId, uri.href, config.upstreamMcpUrl))
              )
                throw new Error('Resource authorization expired before forwarding');
              const rawResult = await upstreamCircuitBreaker.execute(() =>
                forwardClient.readResource(
                  { uri: uri.href },
                  { signal: extra.mcpReq.signal, cacheMode: 'refresh' },
                ),
              );
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

      server.server.registerCapabilities({ resources: { subscribe: false, listChanged: false } });
      // Per-request transport has no persistent, scoped notification relay. Do not
      // advertise or forward subscribe/unsubscribe/listChanged until that lifecycle exists.
    } catch {
      // Upstream does not support resources or empty
    }

    // ----------------------------------------------------
    // 3. PROMPT DISCOVERY & REGISTRATION
    // ----------------------------------------------------
    try {
      const prompts = discovered.prompts;
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
        const promptHandler = async (args?: Record<string, unknown>, signal?: AbortSignal) => {
          const requestId = crypto.randomUUID();
          const start = performance.now();
          const forwardClient = await upstreamCircuitBreaker.execute(() => createUpstreamClient());

          try {
            signal?.throwIfAborted();
            if (
              sessionId &&
              (!sessionManager.validateSession(sessionId, clientIdentity, config.upstreamMcpUrl)
                .valid ||
                !sessionManager.isPromptAuthorized(sessionId, prompt.name, config.upstreamMcpUrl))
            )
              throw new Error('Prompt authorization expired before forwarding');
            const rawResult = await upstreamCircuitBreaker.execute(() =>
              forwardClient.getPrompt(
                {
                  name: prompt.name,
                  arguments: (args as Record<string, string>) ?? {},
                },
                { signal },
              ),
            );

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
            (args, extra) => promptHandler(args, extra.mcpReq.signal),
          );
        } else {
          server.registerPrompt(
            prompt.name,
            {
              description: prompt.description,
            },
            (extra) => promptHandler(undefined, extra.mcpReq.signal),
          );
        }
      }
    } catch {
      // Upstream does not support prompts or empty
    }

    if (server.server.getCapabilities().tools)
      server.server.registerCapabilities({ tools: { listChanged: false } });
    if (server.server.getCapabilities().prompts)
      server.server.registerCapabilities({ prompts: { listChanged: false } });
    return server;
  },
  { maxSubscriptions: 0 },
);

// HTTP server with concurrency, body-size, and timeout controls
let activeInFlightRequests = 0;

export const httpServer = createServer(async (req, res) => {
  const address = httpServer.address();
  const port = address && typeof address !== 'string' ? address.port : config.port;
  const localError = localBoundaryError(
    req.socket.remoteAddress,
    req.headers.host,
    req.headers.origin,
    port,
  );
  if (localError) {
    res
      .writeHead(403, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ error: localError }));
    req.resume();
    return;
  }
  const url = new URL(req.url ?? '/', `http://${config.host}:${config.port}`);
  if (url.pathname !== '/mcp') {
    res
      .writeHead(404, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ error: 'Not found. Veylith gateway endpoint is at /mcp' }));
    return;
  }
  if (activeInFlightRequests >= config.maxConcurrentRequests) {
    res
      .writeHead(429, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ error: 'Too many concurrent requests' }));
    req.resume();
    return;
  }
  // Admission includes clients that are still uploading their request body.
  activeInFlightRequests++;
  const controller = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  const disconnected = () => {
    controller.abort();
    void reader?.cancel().catch(() => {});
  };
  req.on('aborted', disconnected);
  res.on('close', disconnected);
  req.setTimeout(config.requestTimeoutMs, () => {
    if (!res.headersSent) res.writeHead(408).end();
    controller.abort();
    req.destroy();
  });
  try {
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(', ') : value);
    }
    headers.delete('x-veylith-internal-cache');
    if (!headers.has('x-veylith-session-id') && url.searchParams.has('sessionId'))
      headers.set('x-veylith-session-id', url.searchParams.get('sessionId')!);
    if (!headers.has('x-veylith-client-id') && url.searchParams.has('clientId'))
      headers.set('x-veylith-client-id', url.searchParams.get('clientId')!);
    const sessionId = headers.get('x-veylith-session-id') ?? undefined;
    const clientIdentity = headers.get('x-veylith-client-id') ?? undefined;
    const bodyChunks: Buffer[] = [];
    let totalBytes = 0;
    for await (const chunk of req) {
      const buf = Buffer.from(chunk);
      totalBytes += buf.length;
      if (totalBytes > config.maxRequestBodyBytes) {
        // Do not destroy the socket before the client receives its 413.
        res.writeHead(413, { 'Content-Type': 'application/json', Connection: 'close' }).end(
          JSON.stringify({
            error: `Payload too large. Maximum request body is ${config.maxRequestBodyBytes} bytes`,
          }),
        );
        req.resume();
        return;
      }
      bodyChunks.push(buf);
    }
    const body = Buffer.concat(bodyChunks);
    if (
      config.enforceSessions &&
      !sessionManager.validateSession(sessionId, clientIdentity, config.upstreamMcpUrl).valid
    ) {
      auditChain.append({
        serverId: config.upstreamMcpUrl,
        clientIdentity,
        sessionId,
        mcpMethod: 'http/admission',
        stage: 'call_arguments',
        decision: 'block',
        reasonCode: 'unauthorized_access',
        policyVersion: 'v2f.1',
        latencyMs: 0,
      });
      res.writeHead(403).end(JSON.stringify({ error: 'Valid local session required' }));
      req.resume();
      return;
    }

    if (req.method === 'POST') {
      let method: unknown;
      try {
        method = (JSON.parse(body.toString()) as { method?: unknown }).method;
      } catch {
        res.writeHead(400).end(JSON.stringify({ error: 'Malformed JSON' }));
        return;
      }
      if (
        typeof method === 'string' &&
        ['tools/list', 'resources/list', 'resources/templates/list', 'prompts/list'].includes(
          method,
        )
      )
        headers.set('x-veylith-internal-cache', 'list');
    }
    const webRequest = new Request(url.toString(), {
      method: req.method ?? 'POST',
      headers,
      body: ['GET', 'HEAD'].includes(req.method ?? 'GET') ? undefined : body,
      signal: controller.signal,
    });
    const webResponse = await handler.fetch(webRequest);
    if (res.destroyed) {
      await webResponse.body?.cancel();
      return;
    }
    res.writeHead(webResponse.status, Object.fromEntries(webResponse.headers.entries()));
    if (webResponse.body) {
      reader = webResponse.body.getReader();
      while (!res.destroyed) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!res.write(value)) await once(res, 'drain', { signal: controller.signal });
      }
    }
    if (!res.destroyed) res.end();
  } catch (err) {
    if (controller.signal.aborted || res.destroyed) return;
    logger.error('Gateway request failure', {
      error: err instanceof Error ? err.message : String(err),
    });
    if (!res.headersSent)
      res
        .writeHead(err instanceof CircuitBreakerOpenError ? 503 : 500)
        .end(JSON.stringify({ error: 'Gateway request failed closed' }));
    else res.destroy();
  } finally {
    activeInFlightRequests--;
    req.off('aborted', disconnected);
    res.off('close', disconnected);
  }
});

httpServer.maxConnections = config.maxConnections;

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
