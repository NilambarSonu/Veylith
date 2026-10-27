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
import { SecurityInspectionEngine } from '@veylith/policy-engine';
import { MetaMuseSecurityAdapter } from '@veylith/meta-adapter';
import type { PolicyRule, InspectionContext } from '@veylith/core';
import * as z from 'zod/v4';
import { StdioLogger, type LogLevel } from './logger.js';
import { validateCommand, getSafeChildEnvironment, DEFAULT_MAX_BUFFER_SIZE } from './security.js';
import type { Readable, Writable } from 'node:stream';

export interface StdioAdapterConfig {
  /** Mode: 'gateway' bridges to Veylith HTTP Gateway; 'standalone' runs policy engine in-process. */
  mode?: 'gateway' | 'standalone';
  /** Gateway HTTP URL (for gateway mode). Default: http://127.0.0.1:3000/mcp */
  gatewayUrl?: string;
  /** Upstream MCP HTTP URL (for standalone HTTP mode). */
  upstreamUrl?: string;
  /** Upstream command executable (for standalone stdio mode). */
  upstreamCommand?: string;
  /** Arguments for upstream command. */
  upstreamArgs?: string[];
  /** Custom environment variables for upstream command. */
  upstreamEnv?: Record<string, string>;
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
  /** Custom stdin stream (for testing). Default: process.stdin */
  stdin?: Readable;
  /** Custom stdout stream (for testing). Default: process.stdout */
  stdout?: Writable;
}

export class VeylithStdioAdapter {
  private readonly config: StdioAdapterConfig;
  private readonly logger: StdioLogger;
  private readonly mode: 'gateway' | 'standalone';
  private readonly securityEngine?: SecurityInspectionEngine;
  private serverHandle: StdioServerHandle | null = null;
  private running = false;
  private activeUpstreamClients = new Set<Client>();
  private persistentUpstreamClient: Client | null = null;

  constructor(config: StdioAdapterConfig = {}) {
    this.config = {
      mode:
        config.mode ?? (config.upstreamCommand || config.upstreamUrl ? 'standalone' : 'gateway'),
      gatewayUrl:
        config.gatewayUrl ?? process.env['VEYLITH_GATEWAY_URL'] ?? 'http://127.0.0.1:3000/mcp',
      failClosed: config.failClosed ?? true,
      maxBufferSize: config.maxBufferSize ?? DEFAULT_MAX_BUFFER_SIZE,
      logLevel: config.logLevel ?? 'info',
      redactSecrets: config.redactSecrets ?? true,
      metaAiMode: config.metaAiMode ?? 'mock',
      ...config,
    };

    this.mode = this.config.mode!;
    this.logger = new StdioLogger(this.config.logLevel, this.config.redactSecrets);

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

      const { tools } = await upstreamClient.listTools();

      // Tool Discovery & Registration
      let cleanTools: readonly { name: string; description?: string }[] = tools;
      if (this.mode === 'standalone' && this.securityEngine) {
        // Stage 1: Discovery Inspection (Tool-description poisoning & static block rules)
        const discoveryOutcome = await this.securityEngine.inspectDiscovery(tools);

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
            return this.handleToolCall(toolName, (args as Record<string, unknown>) ?? {});
          },
        );
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
  ): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
    const requestId = crypto.randomUUID();
    const start = performance.now();
    const ctx: InspectionContext = {
      requestId,
      stage: 'call_arguments',
      method: 'tools/call',
      toolName,
      timestamp: new Date().toISOString(),
    };

    // In standalone mode, execute Stage 2 Argument Inspection locally
    if (this.mode === 'standalone' && this.securityEngine) {
      const argInspection = await this.securityEngine.inspectArguments(ctx, toolName, args);

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

      // In Gateway mode, Gateway already applied all 3 stages
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

      const env = getSafeChildEnvironment(this.config.upstreamEnv);
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
