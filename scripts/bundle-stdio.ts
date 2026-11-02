/**
 * Standalone bundle builder for @veylith/stdio-adapter.
 *
 * Compiles TypeScript source and inlines internal monorepo packages
 * (@veylith/core, @veylith/policy-engine, @veylith/meta-adapter) into a single
 * pure JavaScript distribution file (apps/stdio-adapter/dist/standalone.mjs).
 *
 * This allows the stdio adapter to be executed with standard Node.js (>=20.0.0)
 * WITHOUT requiring tsx, typescript, or development dependencies at runtime.
 */

import { build } from 'esbuild';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chmodSync, mkdirSync, copyFileSync, writeFileSync } from 'node:fs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function main(): Promise<void> {
  const stdioOutfile = resolve(repoRoot, 'apps/stdio-adapter/dist/standalone.mjs');
  const pkgDistDir = resolve(repoRoot, 'packages/veylith/dist');
  const pkgOutfile = resolve(pkgDistDir, 'index.mjs');
  const entryPoint = resolve(repoRoot, 'apps/stdio-adapter/src/index.ts');

  mkdirSync(pkgDistDir, { recursive: true });

  console.log('[bundle-stdio] Bundling @veylith/stdio-adapter for standalone Node execution...');

  await build({
    entryPoints: [entryPoint],
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node20',
    outfile: stdioOutfile,
    external: [
      '@modelcontextprotocol/server',
      '@modelcontextprotocol/client',
      '@modelcontextprotocol/server/stdio',
      '@modelcontextprotocol/client/stdio',
      'node:*',
    ],
  });

  try {
    chmodSync(stdioOutfile, 0o755);
  } catch {
    // ignore
  }

  // Copy to packages/veylith/dist/index.mjs for the public npm package
  copyFileSync(stdioOutfile, pkgOutfile);
  try {
    chmodSync(pkgOutfile, 0o755);
  } catch {
    // ignore
  }

  // Write TypeScript declaration file for packages/veylith
  const dtsContent = `/**
 * Veylith — AI Agent Security Boundary for Model Context Protocol (MCP)
 * @packageDocumentation
 */

export interface StdioAdapterConfig {
  mode?: 'gateway' | 'standalone';
  gatewayUrl?: string;
  upstreamUrl?: string;
  upstreamCommand?: string;
  upstreamArgs?: string[];
  upstreamEnv?: Record<string, string>;
  serverId?: string;
  blockedTools?: string[];
  failClosed?: boolean;
  maxBufferSize?: number;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  redactSecrets?: boolean;
  metaAiMode?: 'mock' | 'live';
  metaApiBaseUrl?: string;
  metaApiKey?: string;
  metaModel?: string;
  sessionId?: string;
  clientIdentity?: string;
}

export declare class VeylithStdioAdapter {
  constructor(config: StdioAdapterConfig);
  start(): Promise<void>;
  close(): Promise<void>;
}

export declare function parseArgs(argv: string[]): StdioAdapterConfig;
`;
  writeFileSync(resolve(pkgDistDir, 'index.d.ts'), dtsContent, 'utf8');

  console.log(`[bundle-stdio] Successfully generated standalone bundle at: ${stdioOutfile}`);
  console.log(`[bundle-stdio] Successfully generated npm package bundle at: ${pkgOutfile}`);
}

main().catch((err) => {
  console.error('[bundle-stdio] Build failed:', err);
  process.exit(1);
});
