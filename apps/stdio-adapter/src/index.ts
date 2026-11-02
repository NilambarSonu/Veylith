#!/usr/bin/env node
/**
 * Veylith Stdio Adapter CLI Entry Point.
 *
 * Connects an MCP client (such as Claude Desktop or Cursor) to Veylith's security boundary.
 *
 * Usage:
 *   # Gateway Bridge Mode (connects to running Veylith Gateway):
 *   veylith-stdio --gateway-url http://127.0.0.1:8787/mcp
 *
 *   # Standalone Command Mode (runs security engine in-process and wraps upstream command):
 *   veylith-stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
 *
 *   # Standalone HTTP Mode (runs security engine in-process and wraps upstream HTTP server):
 *   veylith-stdio --upstream-url http://127.0.0.1:8788/mcp
 */

import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { VeylithStdioAdapter, type StdioAdapterConfig } from './adapter.js';
import type { LogLevel } from './logger.js';

function printHelp(): void {
  process.stderr.write(`
Veylith — AI Agent Security Boundary for Model Context Protocol (MCP)

USAGE:
  veylith [OPTIONS] [-- UPSTREAM_COMMAND [UPSTREAM_ARGS...]]
  veylith-stdio [OPTIONS] [-- UPSTREAM_COMMAND [UPSTREAM_ARGS...]]

MODES:
  1. Standalone Subprocess (Recommended)
     Runs Veylith's 3-stage security boundary in-process and wraps an upstream tool command.
     Example: veylith -- npx -y @modelcontextprotocol/server-filesystem /tmp

  2. Gateway Bridge
     Bridges downstream stdio to a running Veylith HTTP Gateway instance.
     Example: veylith --gateway-url http://127.0.0.1:8787/mcp

  3. Standalone HTTP
     Runs Veylith in-process and mediates an upstream MCP HTTP server.
     Example: veylith --upstream-url http://127.0.0.1:8788/mcp

OPTIONS:
  --gateway-url <url>      URL of Veylith Gateway (default: http://127.0.0.1:8787/mcp)
  --upstream-url <url>     URL of upstream MCP HTTP server (standalone mode)
  --command <cmd>          Executable command for upstream MCP server (standalone mode)
  --args <args>            Comma-separated arguments for upstream command
  --blocked-tools <list>   Comma-separated list of tool names to block
  --log-level <level>      Log level: debug, info, warn, error (default: info)
  --fail-closed <bool>     Block requests if security evaluation fails (default: true)
  --max-buffer-size <size> Maximum stdio buffer size in bytes (default: 10485760 / 10MB)
  --meta-mode <mode>       Meta AI mode: mock | live (default: mock)
  --help, -h               Show this help message

ENVIRONMENT VARIABLES:
  VEYLITH_GATEWAY_URL      Overrides default gateway URL
  UPSTREAM_MCP_URL         Overrides upstream MCP URL
  UPSTREAM_COMMAND         Upstream command to execute
  BLOCKED_TOOLS            Comma-separated tool blocklist
  LOG_LEVEL                Logging verbosity (default: info)
  FAIL_CLOSED              Set to 'false' to fail open (default: true)
`);
}

function parseArgs(argv: string[]): StdioAdapterConfig {
  const config: StdioAdapterConfig = {
    gatewayUrl: process.env['VEYLITH_GATEWAY_URL'] ?? 'http://127.0.0.1:8787/mcp',
    upstreamUrl: process.env['UPSTREAM_MCP_URL'],
    upstreamCommand: process.env['UPSTREAM_COMMAND'],
    blockedTools: process.env['BLOCKED_TOOLS']
      ? process.env['BLOCKED_TOOLS'].split(',').map((s) => s.trim())
      : [],
    logLevel: (process.env['LOG_LEVEL'] as LogLevel) ?? 'info',
    failClosed: process.env['FAIL_CLOSED'] !== 'false',
    metaAiMode: (process.env['META_AI_MODE'] as 'mock' | 'live') ?? 'mock',
  };

  const args = argv.slice(2);
  const doubleDashIdx = args.indexOf('--');

  // Everything after '--' is the upstream command and its arguments
  if (doubleDashIdx !== -1) {
    const upstreamParts = args.slice(doubleDashIdx + 1);
    if (upstreamParts.length > 0) {
      config.upstreamCommand = upstreamParts[0];
      config.upstreamArgs = upstreamParts.slice(1);
      config.mode = 'standalone';
    }
    // Remove the '--' and following arguments from standard option parsing
    args.splice(doubleDashIdx);
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg) continue;

    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (arg === '--gateway-url' && args[i + 1]) {
      config.gatewayUrl = args[++i];
      config.mode = 'gateway';
    } else if (arg === '--upstream-url' && args[i + 1]) {
      config.upstreamUrl = args[++i];
      config.mode = 'standalone';
    } else if (arg === '--command' && args[i + 1]) {
      config.upstreamCommand = args[++i];
      config.mode = 'standalone';
    } else if (arg === '--args' && args[i + 1]) {
      config.upstreamArgs = args[++i]?.split(',').map((s) => s.trim()) ?? [];
    } else if (arg === '--blocked-tools' && args[i + 1]) {
      config.blockedTools = args[++i]?.split(',').map((s) => s.trim()) ?? [];
    } else if (arg === '--log-level' && args[i + 1]) {
      config.logLevel = (args[++i] as LogLevel) ?? 'info';
    } else if (arg === '--fail-closed' && args[i + 1]) {
      config.failClosed = args[++i] !== 'false';
    } else if (arg === '--max-buffer-size' && args[i + 1]) {
      config.maxBufferSize = parseInt(args[++i] ?? '10485760', 10);
    } else if (arg === '--meta-mode' && args[i + 1]) {
      config.metaAiMode = (args[++i] as 'mock' | 'live') ?? 'mock';
    }
  }

  // If command or upstream URL is provided, default to standalone mode
  if (config.upstreamCommand || config.upstreamUrl) {
    config.mode = 'standalone';
  }

  return config;
}

async function main(): Promise<void> {
  const config = parseArgs(process.argv);
  const adapter = new VeylithStdioAdapter(config);

  const shutdown = async (signal: string) => {
    process.stderr.write(`[veylith-stdio] Received ${signal}, shutting down gracefully...\n`);
    await adapter.close();
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  // Exit cleanly when stdin closes (client disconnect)
  process.stdin.on('end', () => {
    void shutdown('stdin EOF');
  });

  try {
    await adapter.start();
  } catch (err) {
    process.stderr.write(
      `[veylith-stdio] Fatal error starting adapter: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
}

// Only execute when invoked directly as a binary (handling symlinks, npx wrappers, bin wrappers, and direct invocations)
function isEntrypoint(): boolean {
  if (!process.argv[1]) return false;
  try {
    const currentPath = fileURLToPath(import.meta.url);
    const invokedPath = realpathSync(process.argv[1]);
    if (currentPath === invokedPath) return true;
    if (
      invokedPath.endsWith('/bin/veylith.js') ||
      invokedPath.endsWith('/bin/veylith-stdio.js') ||
      invokedPath.endsWith('\\bin\\veylith.js') ||
      invokedPath.endsWith('\\bin\\veylith-stdio.js')
    ) {
      return true;
    }
    return false;
  } catch {
    return import.meta.url === `file://${process.argv[1]}`;
  }
}

if (isEntrypoint()) {
  main().catch((err) => {
    process.stderr.write(
      `[veylith-stdio] Unhandled exception: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  });
}

export { VeylithStdioAdapter, parseArgs };
