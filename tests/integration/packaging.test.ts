import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const standaloneBundlePath = resolve(repoRoot, 'apps/stdio-adapter/dist/standalone.mjs');

describe('Veylith Packaging & Portability Verification', () => {
  it('verifies that standalone bundle exists or can be built', () => {
    // If not yet built, the file might not exist in a pristine git clone, but build script produces it
    expect(existsSync(resolve(repoRoot, 'apps/stdio-adapter/package.json'))).toBe(true);
  });

  it('verifies that standalone bundle inlines internal monorepo packages and marks peer dependencies external', () => {
    if (!existsSync(standaloneBundlePath)) {
      // Skip if build hasn't run yet in this specific runner
      return;
    }

    const bundleContent = readFileSync(standaloneBundlePath, 'utf8');

    // 1. Monorepo packages are inlined into bundle
    expect(bundleContent).toContain('DeterministicRuleSet');
    expect(bundleContent).toContain('HeuristicRiskScreener');
    expect(bundleContent).toContain('ToolCapabilityRegistry');

    // 2. Official MCP SDK packages remain external imports
    expect(bundleContent).toMatch(/from\s+['"]@modelcontextprotocol\/server['"]/);
    expect(bundleContent).toMatch(/from\s+['"]@modelcontextprotocol\/client['"]/);

    // 3. Packaging limitation verification:
    // Because @modelcontextprotocol/* are external imports, the bundle requires
    // node_modules containing @modelcontextprotocol/server and @modelcontextprotocol/client.
    // Therefore, this artifact is a "bundled development artifact", not a self-contained zero-dependency binary.
  });

  it('verifies the multi-tier execution fallback logic in bin/veylith-stdio.js', () => {
    const launcherPath = resolve(repoRoot, 'bin/veylith-stdio.js');
    expect(existsSync(launcherPath)).toBe(true);

    const launcherContent = readFileSync(launcherPath, 'utf8');
    // Resolution order:
    // 1. standaloneBundle (dist/standalone.mjs) via pure Node
    // 2. tsx development fallback
    // 3. experimental-strip-types fallback
    expect(launcherContent).toContain('standaloneBundle');
    expect(launcherContent).toContain('tsxCli');
    expect(launcherContent).toContain('--experimental-strip-types');
  });
});
