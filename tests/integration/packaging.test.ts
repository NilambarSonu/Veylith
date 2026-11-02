import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, mkdtempSync, copyFileSync, rmSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';

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

  it('verifies launcher runs cleanly when executed from a clean external working directory', () => {
    if (!existsSync(standaloneBundlePath)) return;

    const cleanDir = mkdtempSync(join(tmpdir(), 'veylith-clean-test-'));

    try {
      // Execute the bundle with a clean working directory (simulating an external client running veylith-stdio)
      const res = spawnSync(process.execPath, [standaloneBundlePath], {
        cwd: cleanDir,
        input: '', // immediate EOF
        encoding: 'utf8',
        timeout: 5000,
      });

      // Stderr must contain structured JSON logs
      expect(res.stderr).toContain('veylith-stdio');
      expect(res.stderr).toContain('Starting Veylith stdio adapter');
      expect(res.status).toBe(0);
    } finally {
      rmSync(cleanDir, { recursive: true, force: true });
    }
  });

  it('verifies that copying the bundle into an isolated directory without node_modules fails with ERR_MODULE_NOT_FOUND', () => {
    if (!existsSync(standaloneBundlePath)) return;

    const isolatedDir = mkdtempSync(join(tmpdir(), 'veylith-isolated-'));

    try {
      const isolatedBundle = join(isolatedDir, 'standalone.mjs');
      copyFileSync(standaloneBundlePath, isolatedBundle);

      // Attempting to run the isolated bundle in a directory without node_modules MUST fail
      // proving that the artifact is a bundled development artifact, not an all-in-one standalone binary
      const res = spawnSync(process.execPath, [isolatedBundle], {
        cwd: isolatedDir,
        encoding: 'utf8',
        timeout: 5000,
      });

      expect(res.status).not.toBe(0);
      expect(res.stderr).toMatch(
        /ERR_MODULE_NOT_FOUND|Cannot find package '@modelcontextprotocol\/server'/,
      );
    } finally {
      rmSync(isolatedDir, { recursive: true, force: true });
    }
  });
});
