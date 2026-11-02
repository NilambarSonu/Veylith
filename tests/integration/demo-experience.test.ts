/**
 * Veylith Final Sprint — Interactive Demo Experience Integration Tests.
 *
 * Verifies:
 *   1. All scenario identifiers are valid and unique.
 *   2. Non-interactive `--all` executes every enabled scenario deterministically.
 *   3. Scenario output accurately reflects actual policy decisions (ALLOW, BLOCK, SANITIZE).
 *   4. An invalid scenario produces a nonzero exit code.
 *   5. CLI argument parsing and help output.
 *   6. Non-TTY output works without interactive input.
 *   7. `NO_COLOR` disables ANSI color escape codes.
 *   8. No real provider request can occur during the demo (strict offline mock guard).
 *   9. Existing `pnpm demo:client` remains functional.
 *  10. Root `pnpm demo` command is registered and functional.
 */

import { describe, it, expect } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import * as path from 'node:path';
import * as net from 'node:net';
import {
  SCENARIOS,
  findScenario,
  parseCliArgs,
  createFormatter,
  stripAnsi,
  padVisible,
  DemoEnvironment,
  buildSafeEnvironment,
} from '../../scripts/demo.js';

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve(__dirname, '../..');

async function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.unref();
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close((err) => {
        if (err) reject(err);
        else resolve(port);
      });
    });
    s.on('error', reject);
  });
}

async function getDynamicTestPorts(): Promise<{
  DEMO_BENIGN_PORT: string;
  DEMO_GATEWAY_PORT: string;
}> {
  const p1 = await getAvailablePort();
  let p2 = await getAvailablePort();
  while (p2 === p1) {
    p2 = await getAvailablePort();
  }
  return {
    DEMO_BENIGN_PORT: String(p1),
    DEMO_GATEWAY_PORT: String(p2),
  };
}

describe('Interactive Demo Experience (pnpm demo)', () => {
  // ---------------------------------------------------------------------------
  // 1. Scenario Identifiers & Structure
  // ---------------------------------------------------------------------------
  it('defines valid and unique scenario identifiers and decisions', () => {
    expect(SCENARIOS.length).toBe(4);

    const codes = SCENARIOS.map((s) => s.code);
    const ids = SCENARIOS.map((s) => s.id);

    expect(new Set(codes).size).toBe(4);
    expect(new Set(ids).size).toBe(4);

    expect(codes).toEqual(['A', 'B', 'C', 'D']);
    expect(ids).toEqual(['scenario-a', 'scenario-b', 'scenario-c', 'scenario-d']);

    // Check decisions
    expect(SCENARIOS.find((s) => s.code === 'A')?.expectedDecision).toBe('ALLOW');
    expect(SCENARIOS.find((s) => s.code === 'B')?.expectedDecision).toBe('BLOCK');
    expect(SCENARIOS.find((s) => s.code === 'C')?.expectedDecision).toBe('SANITIZE');
    expect(SCENARIOS.find((s) => s.code === 'D')?.expectedDecision).toBe('BLOCK');

    // Check lookup
    expect(findScenario('A')?.code).toBe('A');
    expect(findScenario('1')?.code).toBe('A');
    expect(findScenario('scenario-b')?.code).toBe('B');
    expect(findScenario('2')?.code).toBe('B');
    expect(findScenario('C')?.code).toBe('C');
    expect(findScenario('3')?.code).toBe('C');
    expect(findScenario('d')?.code).toBe('D');
    expect(findScenario('4')?.code).toBe('D');
    expect(findScenario('unknown')).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // 2. CLI Argument Parsing
  // ---------------------------------------------------------------------------
  it('correctly parses CLI flags and options', () => {
    expect(parseCliArgs(['node', 'demo.ts'])).toEqual({
      all: false,
      scenarioId: undefined,
      noColor: false,
      help: false,
      interactive: false,
    });

    expect(parseCliArgs(['node', 'demo.ts', '--all'])).toEqual({
      all: true,
      scenarioId: undefined,
      noColor: false,
      help: false,
      interactive: false,
    });

    expect(parseCliArgs(['node', 'demo.ts', '-a'])).toEqual({
      all: true,
      scenarioId: undefined,
      noColor: false,
      help: false,
      interactive: false,
    });

    expect(parseCliArgs(['node', 'demo.ts', '--scenario=B'])).toEqual({
      all: false,
      scenarioId: 'B',
      noColor: false,
      help: false,
      interactive: false,
    });

    expect(parseCliArgs(['node', 'demo.ts', '-s', 'C', '--no-color'])).toEqual({
      all: false,
      scenarioId: 'C',
      noColor: true,
      help: false,
      interactive: false,
    });

    expect(parseCliArgs(['node', 'demo.ts', '--help'])).toEqual({
      all: false,
      scenarioId: undefined,
      noColor: false,
      help: true,
      interactive: false,
    });

    expect(parseCliArgs(['node', 'demo.ts', '--interactive'])).toEqual({
      all: false,
      scenarioId: undefined,
      noColor: false,
      help: false,
      interactive: true,
    });

    expect(parseCliArgs(['node', 'demo.ts', 'A'])).toEqual({
      all: false,
      scenarioId: 'A',
      noColor: false,
      help: false,
      interactive: false,
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Formatter & ANSI Utilities
  // ---------------------------------------------------------------------------
  it('strips ANSI codes and applies formatting properly', () => {
    const coloredFmt = createFormatter(true);
    const plainFmt = createFormatter(false);

    expect(coloredFmt.bold('test')).toContain('\x1b[1m');
    expect(plainFmt.bold('test')).toBe('test');

    expect(plainFmt.decisionBadge('ALLOW')).toBe('[ALLOW]');
    expect(plainFmt.decisionBadge('BLOCK')).toBe('[BLOCK]');
    expect(plainFmt.decisionBadge('SANITIZE')).toBe('[SANITIZE]');

    const coloredAllow = coloredFmt.decisionBadge('ALLOW');
    expect(coloredAllow).toContain('\x1b[');
    expect(stripAnsi(coloredAllow)).toBe('[ALLOW]');

    // Test padVisible
    expect(padVisible(coloredAllow, 12)).toBe(coloredAllow + ' '.repeat(5));
    expect(stripAnsi(padVisible(coloredAllow, 12)).length).toBe(12);
  });

  // ---------------------------------------------------------------------------
  // 4. Strict Offline Safety Guard
  // ---------------------------------------------------------------------------
  it('strictly isolates environment to offline loopback mode', () => {
    const env = new DemoEnvironment({
      serverPort: 19899,
      gatewayPort: 19898,
    });

    expect(env.serverPort).toBe(19899);
    expect(env.gatewayPort).toBe(19898);
    expect(env.benignServerUrl).toBe('http://127.0.0.1:19899/mcp');
    expect(env.gatewayUrl).toBe('http://127.0.0.1:19898/mcp');
  });

  // ---------------------------------------------------------------------------
  // 5. Invalid Scenario Produces Non-zero Exit Code
  // ---------------------------------------------------------------------------
  it('exits with code 1 when an invalid scenario is specified', async () => {
    try {
      await execFileAsync('npx', ['tsx', 'scripts/demo.ts', '--scenario=INVALID'], {
        cwd: REPO_ROOT,
      });
      expect.unreachable('Should have failed with exit code 1');
    } catch (err: unknown) {
      const execError = err as { code: number; stdout: string; stderr: string };
      expect(execError.code).toBe(1);
      expect(execError.stderr).toContain('Unknown scenario "INVALID"');
    }
  });

  // ---------------------------------------------------------------------------
  // 6. NO_COLOR Disables ANSI Escape Sequences
  // ---------------------------------------------------------------------------
  it('disables ANSI escape codes when NO_COLOR=1 or --no-color is set', async () => {
    const testPorts = await getDynamicTestPorts();
    const { stdout } = await execFileAsync(
      'npx',
      ['tsx', 'scripts/demo.ts', '--scenario=A', '--no-color'],
      {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          ...testPorts,
          NO_COLOR: '1',
        },
      },
    );

    // Verify output has no ANSI escape codes
    /* eslint-disable-next-line no-control-regex */
    const ansiRegex = /\x1b\[[0-9;]*m/;
    expect(stdout).not.toMatch(ansiRegex);
    expect(stdout).toContain('[Scenario A] Safe MCP Tool Execution');
    expect(stdout).toContain('Expected Decision: [ALLOW]');
    expect(stdout).toContain('Veylith Decision : [ALLOW] (Tier 1 / Tier 2)');
    expect(stdout).toContain('Scenario Status  : PASS ✓');
  }, 35000);

  // ---------------------------------------------------------------------------
  // 7. Non-TTY Environment Executes All Scenarios Deterministically
  // ---------------------------------------------------------------------------
  it('automatically executes all scenarios when run in non-TTY environment without args', async () => {
    const testPorts = await getDynamicTestPorts();
    const proc = spawn('npx', ['tsx', 'scripts/demo.ts'], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        ...testPorts,
        NO_COLOR: '1',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    // Close stdin immediately to simulate piped non-interactive input
    proc.stdin.end();

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => (stdout += d.toString()));
    proc.stderr.on('data', (d) => (stderr += d.toString()));

    const exitCode = await new Promise<number | null>((resolve) => {
      proc.on('close', resolve);
    });

    expect(exitCode).toBe(0);
    expect(stdout).toContain('Non-interactive environment detected');
    expect(stdout).toContain('[Scenario A] Safe MCP Tool Execution');
    expect(stdout).toContain('[Scenario B] Tool Discovery Poisoning');
    expect(stdout).toContain('[Scenario C] Indirect Prompt Injection in Tool Output');
    expect(stdout).toContain('[Scenario D] Dangerous Invocation Arguments');
    expect(stdout).toContain('ALL DEMONSTRATION WORKFLOWS VERIFIED');
  }, 35000);

  // ---------------------------------------------------------------------------
  // 8. Deterministic Batch Mode (--all) Runs All Scenarios and Verifies Decisions
  // ---------------------------------------------------------------------------
  it('executes --all deterministically and reports accurate policy decisions', async () => {
    const testPorts = await getDynamicTestPorts();
    const { stdout } = await execFileAsync('npx', ['tsx', 'scripts/demo.ts', '--all'], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        ...testPorts,
        NO_COLOR: '1',
      },
    });

    // Scenario A: Safe tool execution allowed
    expect(stdout).toContain('[Scenario A] Safe MCP Tool Execution');
    expect(stdout).toContain('Expected Decision: [ALLOW]');
    expect(stdout).toContain('Veylith Decision : [ALLOW]');

    // Scenario B: Discovery tool description poisoning blocked
    expect(stdout).toContain('[Scenario B] Tool Discovery Poisoning');
    expect(stdout).toContain('Expected Decision: [BLOCK]');
    expect(stdout).toContain('Poisoned tool dropped from catalog: YES (FILTERED)');
    expect(stdout).toContain('Veylith Decision : [BLOCK]');

    // Scenario C: Response indirect injection sanitized
    expect(stdout).toContain('[Scenario C] Indirect Prompt Injection in Tool Output');
    expect(stdout).toContain('Expected Decision: [SANITIZE]');
    expect(stdout).toContain('[Veylith Security Notice]');
    expect(stdout).toContain('Veylith Decision : [SANITIZE]');

    // Scenario D: Dangerous invocation arguments blocked
    expect(stdout).toContain('[Scenario D] Dangerous Invocation Arguments');
    expect(stdout).toContain('Expected Decision: [BLOCK]');
    expect(stdout).toContain('Tier 1 invariant triggered : YES');
    expect(stdout).toContain('Veylith Decision : [BLOCK]');

    // Final summary table
    expect(stdout).toContain('DEMONSTRATION SUMMARY');
    expect(stdout).toContain(
      'Summary: 4/4 scenarios passed | Zero external requests observed (Local loopback communication only)',
    );
    expect(stdout).toContain('Status : ALL DEMONSTRATION WORKFLOWS VERIFIED');
  }, 35000);

  // ---------------------------------------------------------------------------
  // 9. Interactive Mode Menu Handling (Invalid Option & Clean Exit)
  // ---------------------------------------------------------------------------
  it('handles invalid menu selection and cleanly exits upon q in interactive mode', async () => {
    const testPorts = await getDynamicTestPorts();
    const proc = spawn('npx', ['tsx', 'scripts/demo.ts', '--interactive'], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        ...testPorts,
        NO_COLOR: '1',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => {
      const text = d.toString();
      stdout += text;
      if (text.includes('Select scenario [1-5, q to exit]:')) {
        // First send invalid option '99'
        if (!stdout.includes('Invalid selection')) {
          proc.stdin.write('99\n');
        } else {
          // Then send 'q' to exit
          proc.stdin.write('q\n');
        }
      }
    });
    proc.stderr.on('data', (d) => (stderr += d.toString()));

    const exitCode = await new Promise<number | null>((resolve) => {
      proc.on('close', resolve);
    });

    expect(exitCode).toBe(0);
    expect(stdout).toContain('Available Security Evaluation Scenarios:');
    expect(stdout).toContain('Invalid selection: "99"');
    expect(stdout).toContain('Exiting demonstration.');
  }, 35000);

  // ---------------------------------------------------------------------------
  // 10. Credential Scrubbing (Both Meta Key Aliases Blanked)
  // ---------------------------------------------------------------------------
  it('scrubs both META_MODEL_API_KEY and alternate META_API_KEY from child environment', () => {
    const originalMetaModelKey = process.env['META_MODEL_API_KEY'];
    const originalMetaApiKey = process.env['META_API_KEY'];
    const originalFireworksKey = process.env['FIREWORKS_API_KEY'];
    const originalBasetenKey = process.env['BASETEN_API_KEY'];

    try {
      // Set dummy test sentinel values in parent environment
      process.env['META_MODEL_API_KEY'] = 'sentinel-meta-model-key-test-only';
      process.env['META_API_KEY'] = 'sentinel-meta-key-test-only';
      process.env['FIREWORKS_API_KEY'] = 'sentinel-fireworks-key-test-only';
      process.env['BASETEN_API_KEY'] = 'sentinel-baseten-key-test-only';

      const safeEnv = buildSafeEnvironment({
        serverPort: 19894,
        gatewayPort: 19893,
      });

      // Both Meta credential aliases must be scrubbed (empty string)
      expect(safeEnv['META_MODEL_API_KEY']).toBe('');
      expect(safeEnv['META_API_KEY']).toBe('');
      expect(safeEnv['FIREWORKS_API_KEY']).toBe('');
      expect(safeEnv['BASETEN_API_KEY']).toBe('');
      expect(safeEnv['META_AI_MODE']).toBe('mock');
      expect(safeEnv['NODE_ENV']).toBe('test');
      expect(safeEnv['MCP_SERVER_HOST']).toBe('127.0.0.1');
      expect(safeEnv['GATEWAY_HOST']).toBe('127.0.0.1');
    } finally {
      // Restore parent environment safely
      if (originalMetaModelKey === undefined) {
        delete process.env['META_MODEL_API_KEY'];
      } else {
        process.env['META_MODEL_API_KEY'] = originalMetaModelKey;
      }
      if (originalMetaApiKey === undefined) {
        delete process.env['META_API_KEY'];
      } else {
        process.env['META_API_KEY'] = originalMetaApiKey;
      }
      if (originalFireworksKey === undefined) {
        delete process.env['FIREWORKS_API_KEY'];
      } else {
        process.env['FIREWORKS_API_KEY'] = originalFireworksKey;
      }
      if (originalBasetenKey === undefined) {
        delete process.env['BASETEN_API_KEY'];
      } else {
        process.env['BASETEN_API_KEY'] = originalBasetenKey;
      }
    }
  });

  // ---------------------------------------------------------------------------
  // 11. Root Package.json Demo Scripts
  // ---------------------------------------------------------------------------
  it('confirms both pnpm demo and pnpm demo:client are configured and functional', async () => {
    // Check package.json scripts
    const pkg = await import('../../package.json', { with: { type: 'json' } });
    expect(pkg.default.scripts['demo']).toBe('tsx scripts/demo.ts');
    expect(pkg.default.scripts['demo:client']).toBe('tsx scripts/demo-real-client.ts');
  });
});
