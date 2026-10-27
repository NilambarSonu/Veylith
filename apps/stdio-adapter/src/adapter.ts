/**
 * Veylith Stdio Adapter — Real Client MCP Security Boundary.
 *
 * Implements a lightweight, executable MCP stdio adapter connecting real MCP clients
 * (such as Claude Desktop, Cursor, and custom agent runtimes) to Veylith's security boundary.
 *
 * Protocols & Transports:
 *   - Downstream: stdio (JSON-RPC 2.0 over process.stdin / process.stdout) via official SDK
 *   - Upstream: Streamable HTTP (to Veylith Gateway or MCP server) OR Child Process Stdio
 *
 * Security Enforcement:
 *   - Stage 1: Discovery Inspection (filters poisoned tool descriptions)
 *   - Stage 2: Argument Inspection (blocks dangerous commands / arguments before forwarding)
 *   - Stage 3: Response Inspection (sanitizes indirect prompt injections and prevents credential leaks)
 *   - Stage 4: Resource Discovery & Content Inspection (binary policy, size limits, prompt injection in docs)
 *   - Stage 5: Prompt Discovery & Message Inspection (instruction hijacking & role spoofing detection)
 *   - Protocol Invariant: Zero non-protocol bytes on stdout; all logs strictly to stderr.
 */

import { McpServer } from '@modelcontextprotocol/server';
import {
  serveStdio,
  StdioServerTransport,
  type StdioServerHandle,
} from '@modelcontextprotocol/server/stdio';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import type { Transport } from '@modelcontextprotocol/server';
import {
  SecurityInspectionEngine,
  ClientSessionManager,
  AuditLogChain,
  type TrustedToolBinding,
} from '@veylith/policy-engine';
import { MetaMuseSecurityAdapter } from '@veylith/meta-adapter';
import type {
  PolicyRule,
  InspectionContext,
  ResourceContentItem,
  PromptMessageItem,
} from '@veylith/core';
import * as z from 'zod/v4';
import { StdioLogger, type LogLevel } from './logger.js';
import {
  validateCommand,
  getSafeChildEnvironment,
  DEFAULT_MAX_BUFFER_SIZE,
  type ServerCredentialPolicy,
} from './security.js';
import type { Readable, Writable } from 'node:stream';

export interface StdioAdapterConfig {
  /** Mode: 'gateway' bridges to Veylith HTTP Gateway; 'standalone' runs policy engine in-process. */
  mode?: 'gateway' | 'standalone';
  /** Gateway HTTP URL (for gateway mode). Default: http://127.0.0.1:8787/mcp */
  gatewayUrl?: string;
  /** Upstream MCP HTTP URL (for standalone HTTP mode). */
  upstreamUrl?: string;
  /** Upstream command executable (for standalone stdio mode). */
  upstreamCommand?: string;
  /** Arguments for upstream command. */
  upstreamArgs?: string[];
  /** Custom environment variables for upstream command. */
  upstreamEnv?: Record<string, string>;
  /** Unique server identifier for credential isolation and capability bindings. */
  serverId?: string;
  /** Explicit per-server credential allowlisting policies. */
  credentialPolicy?: ServerCredentialPolicy | readonly ServerCredentialPolicy[];
  /** Verified capability bindings for upstream tools. */
  capabilityBindings?: readonly TrustedToolBinding[];
  /** Tools explicitly blocked by configuration. */
  blockedTools?: string[];
  /** Fail closed if security evaluation fails or returns review. Default: true */
  failClosed?: boolean;
  /** Maximum read buffer size in bytes. Default: 10 MB */
  maxBufferSize?: number;
  /** Log level. Default: 'info' */
  logLevel?: LogLevel;
  /** Redact secrets in logs. Default: true */
  redactSecrets?: boolean;
  /** Meta AI mode for semantic inspection in standalone mode. Default: 'mock' */
  metaAiMode?: 'mock' | 'live';
  /** Meta API base URL (for live mode). */
  metaApiBaseUrl?: string;
  /** Meta API key (for live mode). */
  metaApiKey?: string;
  /** Meta Model (for live mode). */
  metaModel?: string;
  /** Session identifier for client authorization. */
  sessionId?: string;
  /** Client identity string. */
  clientIdentity?: string;
  /** Whether to permit uninspected binary resources. Default: false */
  allowBinaryResources?: boolean;
  /** Maximum resource content size in bytes. Default: 5MB */
  maxResourceContentBytes?: number;
  /** Custom stdin stream (for testing). Default: process.stdin */
  stdin?: Readable;
  /** Custom stdout stream (for testing). Default: process.stdout */
  stdout?: Writable;
}

export class VeylithStdioAdapter {
  private readonly config: StdioAdapterConfig;
  private readonly logger: StdioLogger;
  private readonly mode: 'gateway' | 'standalone';
  public readonly securityEngine?: SecurityInspectionEngine;
  public readonly sessionManager: ClientSessionManager;
  public readonly auditChain: AuditLogChain;
  private serverHandle: StdioServerHandle | null = null;
  private running = false;
  private activeUpstreamClients = new Set<Client>();
  private persistentUpstreamClient: Client | null = null;

  constructor(config: StdioAdapterConfig = {}) {
    this.config = {
      mode:
        config.mode ?? (config.upstreamCommand || config.upstreamUrl ? 'standalone' : 'gateway'),
      gatewayUrl:
        config.gatewayUrl ?? process.env['VEYLITH_GATEWAY_URL'] ?? 'http://127.0.0.1:8787/mcp',
      failClosed: config.failClosed ?? true,
      maxBufferSize: config.maxBufferSize ?? DEFAULT_MAX_BUFFER_SIZE,
      logLevel: config.logLevel ?? 'info',
      redactSecrets: config.redactSecrets ?? true,
      metaAiMode: config.metaAiMode ?? 'mock',
      ...config,
    };

    this.mode = this.config.mode!;
    this.logger = new StdioLogger(this.config.logLevel, this.config.redactSecrets);
    this.sessionManager = new ClientSessionManager();
    this.auditChain = new AuditLogChain();

    // If standalone mode, initialize in-process SecurityInspectionEngine
    if (this.mode === 'standalone') {
      const policyRules: PolicyRule[] = (this.config.blockedTools ?? []).map((toolName, idx) => ({
        id: `stdio-block-tool-${idx}`,
        description: `Block calls to tool: ${toolName}`,
        method: 'tools/call',
        toolName,
        decision: 'block' as const,
        enabled: true,
      }));

      const metaAdapter = new MetaMuseSecurityAdapter({
        mode: this.config.metaAiMode,
        apiBaseUrl: this.config.metaApiBaseUrl,
        apiKey: this.config.metaApiKey,
        model: this.config.metaModel,
      });

      this.securityEngine = new SecurityInspectionEngine(policyRules, metaAdapter, {
        failClosed: this.config.failClosed,
        policyVersion: 'v1.0.0',
        capabilityBindings: this.config.capabilityBindings,
        sessionManager: this.sessionManager,
        auditChain: this.auditChain,
        maxResourceContentBytes: this.config.maxResourceContentBytes,
        allowBinaryResources: this.config.allowBinaryResources,
      });
    }
  }

  /**
   * Starts serving the MCP stdio connection.
   */
  async start(): Promise<void> {
    if (this.running) {
      throw new Error('Stdio adapter is already running');
    }

    this.logger.info('Starting Veylith stdio adapter', {
      mode: this.mode,
      gatewayUrl: this.mode === 'gateway' ? this.config.gatewayUrl : undefined,
      upstreamCommand: this.config.upstreamCommand,
      upstreamUrl: this.config.upstreamUrl,
      failClosed: this.config.failClosed,
      maxBufferSize: this.config.maxBufferSize,
    });

    let transport: Transport | undefined;
    if (this.config.stdin || this.config.stdout) {
      transport = new StdioServerTransport(
        this.config.stdin ?? process.stdin,
        this.config.stdout ?? process.stdout,
        { maxBufferSize: this.config.maxBufferSize },
      );
    }

    this.serverHandle = serveStdio(() => this.createMcpServerInstance(), {
      legacy: 'serve',
      transport,
      onerror: (err: Error) => {
        this.logger.error('Stdio transport error', { error: err.message });
      },
    });

    this.running = true;
    this.logger.info('Veylith stdio adapter ready for client connections');
  }

  /**
   * Closes the adapter and all active upstream connections.
   */
  async close(): Promise<void> {
    if (!this.running) return;
    this.running = false;

    this.logger.info('Closing Veylith stdio adapter');

    for (const client of this.activeUpstreamClients) {
      await client.close().catch(() => {});
    }
    this.activeUpstreamClients.clear();

    if (this.persistentUpstreamClient) {
      await this.persistentUpstreamClient.close().catch(() => {});
      this.persistentUpstreamClient = null;
    }

    if (this.serverHandle) {
      await this.serverHandle.close().catch(() => {});
      this.serverHandle = null;
    }

    this.logger.info('Veylith stdio adapter stopped');
  }

  /**
   * Returns whether the adapter is actively running.
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Creates an McpServer instance wired to upstream and protected by Veylith security.
   */
  private async createMcpServerInstance(): Promise<McpServer> {
    const server = new McpServer({
      name: 'veylith-stdio-adapter',
      version: '0.1.0',
    });

    let upstreamClient: Client | null = null;
    try {
      upstreamClient = await this.createUpstreamClient();
      this.activeUpstreamClients.add(upstreamClient);

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

      let cleanTools: readonly { name: string; description?: string; inputSchema?: unknown }[] =
        tools;
      if (this.mode === 'standalone' && this.securityEngine) {
        const serverId =
          this.config.serverId ?? this.config.upstreamCommand ?? this.config.upstreamUrl;
        const discoveryOutcome = await this.securityEngine.inspectDiscovery(tools, {
          serverId,
          sessionId: this.config.sessionId,
          clientIdentity: this.config.clientIdentity,
        });

        for (const blocked of discoveryOutcome.blockedTools) {
          this.logger.warn(
            'Tool blocked from discovery (tool-description poisoning or static rule)',
            {
              toolName: blocked.name,
              threatCategory: blocked.threatCategory,
              reason: blocked.reason,
            },
          );
        }
        cleanTools = discoveryOutcome.cleanTools;
      }

      // Register clean tools downstream
      for (const tool of cleanTools) {
        const toolName = tool.name;

        server.registerTool(
          toolName,
          {
            description: tool.description ?? '',
            inputSchema: z.record(z.string(), z.unknown()).optional(),
          },
          async (args) => {
            return this.handleToolCall(toolName, (args as Record<string, unknown>) ?? {}, tool);
          },
        );
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

        const resourceList: Array<{
          name: string;
          uri: string;
          description?: string;
          mimeType?: string;
        }> = [...resources];

        if (this.mode === 'standalone' && this.securityEngine) {
          const serverId =
            this.config.serverId ?? this.config.upstreamCommand ?? this.config.upstreamUrl;
          const resOutcome = await this.securityEngine.inspectResourceDiscovery(
            resources,
            templates,
            {
              requestId: crypto.randomUUID(),
              stage: 'resource_discovery',
              method: 'resources/list',
              serverId,
              sessionId: this.config.sessionId,
              clientIdentity: this.config.clientIdentity,
              timestamp: new Date().toISOString(),
            },
          );
          resourceList.length = 0;
          resourceList.push(...resOutcome.cleanResources);
        }

        for (let i = 0; i < resourceList.length; i++) {
          const res = resourceList[i]!;
          server.registerResource(
            res.name,
            res.uri,
            {
              description: res.description,
              mimeType: res.mimeType,
            },
            async (uri) => {
              const resRead = await this.handleResourceRead(uri.href);
              return {
                contents: resRead.contents.map((c) =>
                  c.blob !== undefined
                    ? {
                        uri: c.uri,
                        mimeType: c.mimeType ?? 'application/octet-stream',
                        blob: c.blob,
                      }
                    : {
                        uri: c.uri,
                        mimeType: c.mimeType ?? 'text/plain',
                        text: c.text ?? '',
                      },
                ),
              };
            },
          );
        }

        // Support subscribe and unsubscribe
        server.server.registerCapabilities({
          resources: {
            subscribe: true,
            listChanged: true,
          },
        });

        server.server.setRequestHandler('resources/subscribe', async (req) => {
          const uri = (req.params as { uri?: string })?.uri;
          if (!uri) throw new Error('Missing uri parameter');

          if (this.config.sessionId && this.sessionManager) {
            const serverId =
              this.config.serverId ?? this.config.upstreamCommand ?? this.config.upstreamUrl;
            const sessVal = this.sessionManager.validateSession(
              this.config.sessionId,
              this.config.clientIdentity,
              serverId,
            );
            if (!sessVal.valid) {
              throw new Error(`Unauthorized session for subscribe: ${sessVal.reason}`);
            }
            if (!this.sessionManager.isResourceAuthorized(this.config.sessionId, uri, serverId)) {
              throw new Error(`Session not authorized to subscribe to resource: ${uri}`);
            }
          }

          const forwardClient = await this.createUpstreamClient();
          try {
            await forwardClient.subscribeResource({ uri });
            return {};
          } finally {
            if (!this.config.upstreamCommand) {
              await forwardClient.close().catch(() => {});
            }
          }
        });

        server.server.setRequestHandler('resources/unsubscribe', async (req) => {
          const uri = (req.params as { uri?: string })?.uri;
          if (!uri) throw new Error('Missing uri parameter');

          if (this.config.sessionId && this.sessionManager) {
            const serverId =
              this.config.serverId ?? this.config.upstreamCommand ?? this.config.upstreamUrl;
            const sessVal = this.sessionManager.validateSession(
              this.config.sessionId,
              this.config.clientIdentity,
              serverId,
            );
            if (!sessVal.valid) {
              throw new Error(`Unauthorized session for unsubscribe: ${sessVal.reason}`);
            }
            if (!this.sessionManager.isResourceAuthorized(this.config.sessionId, uri, serverId)) {
              throw new Error(`Session not authorized to unsubscribe from resource: ${uri}`);
            }
          }

          const forwardClient = await this.createUpstreamClient();
          try {
            await forwardClient.unsubscribeResource({ uri });
            return {};
          } finally {
            if (!this.config.upstreamCommand) {
              await forwardClient.close().catch(() => {});
            }
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
        const promptList: Array<{
          name: string;
          description?: string;
          arguments?: readonly { name: string; description?: string; required?: boolean }[];
        }> = [...prompts];

        if (this.mode === 'standalone' && this.securityEngine) {
          const serverId =
            this.config.serverId ?? this.config.upstreamCommand ?? this.config.upstreamUrl;
          const promptOutcome = await this.securityEngine.inspectPromptDiscovery(prompts, {
            requestId: crypto.randomUUID(),
            stage: 'prompt_discovery',
            method: 'prompts/list',
            serverId,
            sessionId: this.config.sessionId,
            clientIdentity: this.config.clientIdentity,
            timestamp: new Date().toISOString(),
          });
          promptList.length = 0;
          promptList.push(...promptOutcome.cleanPrompts);
        }

        for (let i = 0; i < promptList.length; i++) {
          const prompt = promptList[i]!;
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
              async (args) => {
                return this.handlePromptGet(prompt.name, (args as Record<string, unknown>) ?? {});
              },
            );
          } else {
            server.registerPrompt(
              prompt.name,
              {
                description: prompt.description,
              },
              async () => {
                return this.handlePromptGet(prompt.name, {});
              },
            );
          }
        }
      } catch {
        // Upstream does not support prompts or empty
      }
    } catch (err) {
      this.logger.error('Failed to initialize upstream MCP server tools', {
        error: err instanceof Error ? err.message : String(err),
      });
      // Register a fallback status tool so client has visibility
      server.registerTool(
        'veylith_status',
        {
          description: 'Reports current Veylith gateway connectivity status',
          inputSchema: z.record(z.string(), z.unknown()).optional(),
        },
        async () => ({
          content: [
            {
              type: 'text' as const,
              text: `Veylith stdio adapter: upstream server initialization failed (${err instanceof Error ? err.message : String(err)})`,
            },
          ],
          isError: true,
        }),
      );
    }

    return server;
  }

  /**
   * Handles a tool call from the downstream client with full 3-stage security inspection.
   */
  private async handleToolCall(
    toolName: string,
    args: Record<string, unknown>,
    toolDef?: { name: string; description?: string; inputSchema?: unknown },
  ): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
    const requestId = crypto.randomUUID();
    const start = performance.now();
    const serverId = this.config.serverId ?? this.config.upstreamCommand ?? this.config.upstreamUrl;
    const ctx: InspectionContext = {
      requestId,
      stage: 'call_arguments',
      method: 'tools/call',
      toolName,
      serverId,
      sessionId: this.config.sessionId,
      clientIdentity: this.config.clientIdentity,
      timestamp: new Date().toISOString(),
    };

    // In standalone mode, execute Stage 2 Argument Inspection locally
    if (this.mode === 'standalone' && this.securityEngine) {
      const argInspection = await this.securityEngine.inspectArguments(
        ctx,
        toolName,
        args,
        toolDef,
      );

      this.logger.info('Argument security evaluation', {
        requestId,
        toolName,
        action: argInspection.action,
        threatCategory: argInspection.threatCategory,
        origin: argInspection.origin,
        durationMs: argInspection.evaluationDurationMs,
      });

      if (
        argInspection.action === 'block' ||
        (argInspection.action === 'review' && this.config.failClosed)
      ) {
        const durationMs = Math.round((performance.now() - start) * 100) / 100;
        this.logger.warn('Tool call blocked by security engine', {
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
              type: 'text',
              text: `Veylith policy blocked this call: ${argInspection.explanation}`,
            },
          ],
          isError: true,
        };
      }
    }

    // Connect to upstream for execution
    let forwardClient: Client;
    try {
      forwardClient = await this.createUpstreamClient();
    } catch (err) {
      const durationMs = Math.round((performance.now() - start) * 100) / 100;
      this.logger.error('Upstream connection failed', {
        requestId,
        toolName,
        error: err instanceof Error ? err.message : String(err),
        durationMs,
      });
      return {
        content: [
          {
            type: 'text',
            text: 'Veylith gateway: upstream server unavailable',
          },
        ],
        isError: true,
      };
    }

    try {
      const rawResult = await forwardClient.callTool({
        name: toolName,
        arguments: args,
      });

      // In standalone mode, execute Stage 3 Response Inspection locally
      if (this.mode === 'standalone' && this.securityEngine) {
        const respCtx: InspectionContext = {
          requestId,
          stage: 'call_response',
          method: 'tools/call',
          toolName,
          serverId,
          sessionId: this.config.sessionId,
          clientIdentity: this.config.clientIdentity,
          timestamp: new Date().toISOString(),
        };

        const respOutcome = await this.securityEngine.inspectResponse(
          respCtx,
          toolName,
          (rawResult.content as Array<{ type: string; text?: string }>) ?? [],
        );

        if (respOutcome.isRedacted) {
          this.logger.warn('Tool response sanitized by security engine', {
            requestId,
            toolName,
            threatCategory: respOutcome.result.threatCategory,
            explanation: respOutcome.result.explanation,
          });
        }

        const durationMs = Math.round((performance.now() - start) * 100) / 100;
        this.logger.info('Request completed (standalone)', {
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
      }

      // In Gateway mode, Gateway already applied all stages
      const durationMs = Math.round((performance.now() - start) * 100) / 100;
      this.logger.info('Request completed (gateway bridged)', {
        requestId,
        toolName,
        durationMs,
        isError: rawResult.isError ?? false,
      });

      return {
        content: (rawResult.content as Array<{ type: 'text'; text: string }>) ?? [],
        isError: rawResult.isError ?? false,
      };
    } catch (err) {
      const durationMs = Math.round((performance.now() - start) * 100) / 100;
      this.logger.error('Upstream tool call failed', {
        requestId,
        toolName,
        error: err instanceof Error ? err.message : String(err),
        durationMs,
      });
      return {
        content: [
          {
            type: 'text',
            text: `Veylith gateway: upstream error — ${err instanceof Error ? err.message : 'unknown'}`,
          },
        ],
        isError: true,
      };
    } finally {
      if (!this.config.upstreamCommand) {
        await forwardClient.close().catch(() => {});
      }
    }
  }

  /**
   * Handles a resource read request with security inspection.
   */
  private async handleResourceRead(uri: string): Promise<{
    contents: Array<{ uri: string; text?: string; blob?: string; mimeType?: string }>;
  }> {
    const forwardClient = await this.createUpstreamClient();
    const serverId = this.config.serverId ?? this.config.upstreamCommand ?? this.config.upstreamUrl;

    try {
      const rawResult = await forwardClient.readResource({ uri });

      if (this.mode === 'standalone' && this.securityEngine) {
        const ctx: InspectionContext = {
          requestId: crypto.randomUUID(),
          stage: 'resource_content',
          method: 'resources/read',
          resourceUri: uri,
          serverId,
          sessionId: this.config.sessionId,
          clientIdentity: this.config.clientIdentity,
          timestamp: new Date().toISOString(),
        };

        const contentOutcome = await this.securityEngine.inspectResourceContent(
          ctx,
          uri,
          (rawResult.contents as ResourceContentItem[]) ?? [],
        );

        if (contentOutcome.isBlocked) {
          return {
            contents: [
              {
                uri,
                text: `[Veylith Security Notice]: Resource '${uri}' access blocked. Reason: ${contentOutcome.blockReason}`,
                mimeType: 'text/plain',
              },
            ],
          };
        }

        return {
          contents: contentOutcome.sanitizedItems as Array<{
            uri: string;
            text?: string;
            blob?: string;
            mimeType?: string;
          }>,
        };
      }

      return {
        contents: rawResult.contents as Array<{
          uri: string;
          text?: string;
          blob?: string;
          mimeType?: string;
        }>,
      };
    } finally {
      if (!this.config.upstreamCommand) {
        await forwardClient.close().catch(() => {});
      }
    }
  }

  /**
   * Handles a prompt get request with security inspection.
   */
  private async handlePromptGet(
    promptName: string,
    args: Record<string, unknown>,
  ): Promise<{
    description?: string;
    messages: Array<{ role: 'user' | 'assistant'; content: { type: 'text'; text: string } }>;
  }> {
    const forwardClient = await this.createUpstreamClient();
    const serverId = this.config.serverId ?? this.config.upstreamCommand ?? this.config.upstreamUrl;

    try {
      const rawResult = await forwardClient.getPrompt({
        name: promptName,
        arguments: args as Record<string, string>,
      });

      if (this.mode === 'standalone' && this.securityEngine) {
        const ctx: InspectionContext = {
          requestId: crypto.randomUUID(),
          stage: 'prompt_messages',
          method: 'prompts/get',
          promptName,
          serverId,
          sessionId: this.config.sessionId,
          clientIdentity: this.config.clientIdentity,
          timestamp: new Date().toISOString(),
        };

        const msgOutcome = await this.securityEngine.inspectPromptMessages(
          ctx,
          promptName,
          (rawResult.messages as PromptMessageItem[]) ?? [],
          args,
        );

        if (msgOutcome.isBlocked) {
          return {
            description: rawResult.description,
            messages: [
              {
                role: 'user' as const,
                content: {
                  type: 'text' as const,
                  text: `[Veylith Security Notice]: Prompt '${promptName}' blocked. Reason: ${msgOutcome.blockReason}`,
                },
              },
            ],
          };
        }

        return {
          description: rawResult.description,
          messages: msgOutcome.sanitizedMessages.map((m) => ({
            role: (m.role === 'assistant' ? 'assistant' : 'user') as 'user' | 'assistant',
            content: {
              type: 'text' as const,
              text: typeof m.content.text === 'string' ? m.content.text : JSON.stringify(m.content),
            },
          })),
        };
      }

      return {
        description: rawResult.description,
        messages: ((rawResult.messages as PromptMessageItem[]) ?? []).map((m) => ({
          role: (m.role === 'assistant' ? 'assistant' : 'user') as 'user' | 'assistant',
          content: {
            type: 'text' as const,
            text: typeof m.content.text === 'string' ? m.content.text : JSON.stringify(m.content),
          },
        })),
      };
    } finally {
      if (!this.config.upstreamCommand) {
        await forwardClient.close().catch(() => {});
      }
    }
  }

  /**
   * Creates and connects a fresh MCP client to the configured upstream.
   */
  private async createUpstreamClient(): Promise<Client> {
    const client = new Client({ name: 'veylith-stdio-adapter-upstream', version: '0.1.0' });

    if (this.mode === 'gateway') {
      const url = new URL(this.config.gatewayUrl!);
      const transport = new StreamableHTTPClientTransport(url);
      await client.connect(transport);
      return client;
    }

    // Standalone mode: child process command OR upstream HTTP URL
    if (this.config.upstreamCommand) {
      if (this.persistentUpstreamClient) {
        return this.persistentUpstreamClient;
      }

      const validation = validateCommand(this.config.upstreamCommand, this.config.upstreamArgs);
      if (!validation.valid) {
        throw new Error(`Command validation failed: ${validation.reason}`);
      }

      const env = getSafeChildEnvironment({
        serverId: this.config.serverId ?? this.config.upstreamCommand,
        policy: this.config.credentialPolicy,
        customEnv: this.config.upstreamEnv,
      });
      const transport = new StdioClientTransport({
        command: this.config.upstreamCommand,
        args: this.config.upstreamArgs,
        env,
        stderr: 'inherit',
        maxBufferSize: this.config.maxBufferSize,
      });

      await client.connect(transport);
      this.persistentUpstreamClient = client;
      this.activeUpstreamClients.add(client);
      return client;
    }

    if (this.config.upstreamUrl) {
      const url = new URL(this.config.upstreamUrl);
      const transport = new StreamableHTTPClientTransport(url);
      await client.connect(transport);
      return client;
    }

    throw new Error(
      'No valid upstream configured (must provide gatewayUrl, upstreamCommand, or upstreamUrl)',
    );
  }
}
