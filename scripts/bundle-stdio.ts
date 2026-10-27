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
import { chmodSync } from 'node:fs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function main(): Promise<void> {
  const outfile = resolve(repoRoot, 'apps/stdio-adapter/dist/standalone.mjs');
  const entryPoint = resolve(repoRoot, 'apps/stdio-adapter/src/index.ts');
  console.log('[bundle-stdio] Bundling @veylith/stdio-adapter for standalone Node execution...');

  await build({
    entryPoints: [entryPoint],
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node20',
    outfile,
    external: [
      '@modelcontextprotocol/server',
      '@modelcontextprotocol/client',
      '@modelcontextprotocol/server/stdio',
      '@modelcontextprotocol/client/stdio',
      'node:*',
    ],
  });

  try {
    chmodSync(outfile, 0o755);
  } catch {
    // ignore
  }

  console.log(`[bundle-stdio] Successfully generated standalone bundle at: ${outfile}`);
}

main().catch((err) => {
  console.error('[bundle-stdio] Build failed:', err);
  process.exit(1);
});
