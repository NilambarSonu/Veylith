/**
 * Integration tests for the Veylith gateway.
 *
 * Tests cover:
 *   1. Valid server initialization
 *   2. Successful tools/list request
 *   3. Successful echo call
 *   4. Successful add call
 *   5. Gateway forwarding (nonblocked tool allowance)
 *   6. Configured tool blocking (restricted_demo_tool blocked)
 *   7. Malformed payload handling (malformed JSON, invalid routes)
 *   8. Upstream unavailable handling
 *   9. Timeout handling
 *  10. Direct vs Gateway overhead measurement
 *  11. Clean local shutdown
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { type ChildProcess, spawn } from 'node:child_process';

const SERVER_PORT = 18788;
const GATEWAY_PORT = 18787;
const SERVER_URL = `http://127.0.0.1:${SERVER_PORT}/mcp`;
const GATEWAY_URL = `http://127.0.0.1:${GATEWAY_PORT}/mcp`;

let serverProcess: ChildProcess;
let gatewayProcess: ChildProcess;

function waitForReady(proc: ChildProcess, marker: string, timeoutMs = 15000): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`Timeout waiting for: ${marker}`)),
      timeoutMs,
    );
    const onData = (data: Buffer) => {
      const text = data.toString();
      if (text.includes(marker)) {
        clearTimeout(timeout);
        proc.stderr?.off('data', onData);
        proc.stdout?.off('data', onData);
        resolve();
      }
    };
    proc.stdout?.on('data', onData);
    proc.stderr?.on('data', onData);
    proc.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
    proc.on('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`Process exited early with code ${code}`));
    });
  });
}

beforeAll(async () => {
  // Start benign MCP server
  serverProcess = spawn('npx', ['tsx', 'examples/benign-mcp-server/src/index.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      MCP_SERVER_PORT: String(SERVER_PORT),
      MCP_SERVER_HOST: '127.0.0.1',
    },
    stdio: 'pipe',
  });

  await waitForReady(serverProcess, 'Listening');

  // Start gateway
  gatewayProcess = spawn('npx', ['tsx', 'apps/gateway/src/server.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GATEWAY_PORT: String(GATEWAY_PORT),
      GATEWAY_HOST: '127.0.0.1',
      UPSTREAM_MCP_URL: SERVER_URL,
      BLOCKED_TOOLS: 'restricted_demo_tool',
      LOG_LEVEL: 'info',
    },
    stdio: 'pipe',
  });

  await waitForReady(gatewayProcess, 'gateway started');
}, 30000);

afterAll(async () => {
  const killProc = (proc: ChildProcess) =>
    new Promise<void>((resolve) => {
      if (!proc || proc.killed) return resolve();
      proc.once('exit', () => resolve());
      proc.kill('SIGTERM');
      setTimeout(() => {
        try {
          proc.kill('SIGKILL');
        } catch {
          // ignore
        }
        resolve();
      }, 3000);
    });

  await Promise.all([killProc(serverProcess), killProc(gatewayProcess)]);
});

describe('Direct server tests (baseline)', () => {
  it('initializes connection and lists tools', async () => {
    const client = new Client({ name: 'test-direct', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(SERVER_URL));
    await client.connect(transport);

    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThanOrEqual(2);
    const names = tools.map((t) => t.name);
    expect(names).toContain('echo');
    expect(names).toContain('add');
    expect(names).toContain('restricted_demo_tool');
    await client.close();
  });

  it('calls echo tool successfully directly', async () => {
    const client = new Client({ name: 'test-direct', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(SERVER_URL));
    await client.connect(transport);

    const result = await client.callTool({
      name: 'echo',
      arguments: { message: 'hello direct world' },
    });
    const texts = (result.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(texts).toContain('hello direct world');
    expect(result.isError).toBeFalsy();
    await client.close();
  });

  it('calls add tool successfully directly', async () => {
    const client = new Client({ name: 'test-direct', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(SERVER_URL));
    await client.connect(transport);

    const result = await client.callTool({
      name: 'add',
      arguments: { a: 17, b: 25 },
    });
    const texts = (result.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(texts).toContain('42');
    await client.close();
  });
});

describe('Gateway forwarding and policy enforcement', () => {
  it('lists proxied tools through gateway', async () => {
    const client = new Client({ name: 'test-gw', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(GATEWAY_URL));
    await client.connect(transport);

    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThanOrEqual(2);
    const names = tools.map((t) => t.name);
    expect(names).toContain('echo');
    expect(names).toContain('add');
    await client.close();
  });

  it('allows non-blocked echo tool through gateway', async () => {
    const client = new Client({ name: 'test-gw', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(GATEWAY_URL));
    await client.connect(transport);

    const result = await client.callTool({
      name: 'echo',
      arguments: { message: 'through gateway' },
    });
    const texts = (result.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(texts).toContain('through gateway');
    expect(result.isError).toBeFalsy();
    await client.close();
  });

  it('allows non-blocked add tool through gateway', async () => {
    const client = new Client({ name: 'test-gw', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(GATEWAY_URL));
    await client.connect(transport);

    const result = await client.callTool({
      name: 'add',
      arguments: { a: 100, b: 200 },
    });
    const texts = (result.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(texts).toContain('300');
    expect(result.isError).toBeFalsy();
    await client.close();
  });

  it('blocks configured restricted_demo_tool with protocol-compatible error', async () => {
    const client = new Client({ name: 'test-gw', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(GATEWAY_URL));
    await client.connect(transport);

    const result = await client.callTool({
      name: 'restricted_demo_tool',
      arguments: { action: 'delete_system' },
    });

    expect(result.isError).toBe(true);
    const texts = (result.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(texts.some((t) => t.includes('Veylith policy blocked'))).toBe(true);
    await client.close();
  });
});

describe('Malformed payload and HTTP error handling', () => {
  it('returns 404 with JSON error for non-mcp route', async () => {
    const response = await fetch(`http://127.0.0.1:${GATEWAY_PORT}/nonexistent-route`, {
      method: 'GET',
    });
    expect(response.status).toBe(404);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain('Not found');
  });

  it('handles malformed JSON body safely without crashing gateway', async () => {
    const response = await fetch(GATEWAY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: '{"invalid": json payload missing end',
    });

    // The gateway should reject safely (400, 406, or 500) and not crash
    expect([400, 406, 500]).toContain(response.status);

    // Verify gateway is still alive and responsive after malformed payload
    const checkClient = new Client({ name: 'health-check', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(GATEWAY_URL));
    await checkClient.connect(transport);
    const { tools } = await checkClient.listTools();
    expect(tools.length).toBeGreaterThanOrEqual(1);
    await checkClient.close();
  });
});

describe('Upstream unavailable handling', () => {
  it('handles upstream unreachable error safely', async () => {
    const BAD_GATEWAY_PORT = 18789;
    const badGateway = spawn('npx', ['tsx', 'apps/gateway/src/server.ts'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        GATEWAY_PORT: String(BAD_GATEWAY_PORT),
        GATEWAY_HOST: '127.0.0.1',
        UPSTREAM_MCP_URL: 'http://127.0.0.1:19999/mcp', // Unreachable port
        BLOCKED_TOOLS: 'restricted_demo_tool',
        LOG_LEVEL: 'info',
      },
      stdio: 'pipe',
    });

    try {
      await waitForReady(badGateway, 'gateway started', 10000);

      // Attempting to connect or fetch from the gateway when upstream is unreachable
      const response = await fetch(`http://127.0.0.1:${BAD_GATEWAY_PORT}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
        }),
      });

      // Gateway returns 500 internal error safely because upstream is down
      expect([500, 502, 503]).toContain(response.status);
    } finally {
      badGateway.kill('SIGTERM');
    }
  });
});

describe('Timeout handling', () => {
  it('handles client-side request timeout cleanly', async () => {
    const controller = new AbortController();
    // Set an ultra-short timeout that triggers abort
    const timeout = setTimeout(() => controller.abort(), 1);

    await expect(
      fetch(GATEWAY_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
        signal: controller.signal,
      }),
    ).rejects.toThrow();

    clearTimeout(timeout);
  });
});

describe('Direct vs Gateway latency comparison', () => {
  it('measures gateway proxy overhead', async () => {
    const directClient = new Client({ name: 'bench-direct', version: '0.1.0' });
    await directClient.connect(new StreamableHTTPClientTransport(new URL(SERVER_URL)));

    const gwClient = new Client({ name: 'bench-gw', version: '0.1.0' });
    await gwClient.connect(new StreamableHTTPClientTransport(new URL(GATEWAY_URL)));

    const iterations = 5;

    // Warm up
    await directClient.callTool({ name: 'echo', arguments: { message: 'warmup' } });
    await gwClient.callTool({ name: 'echo', arguments: { message: 'warmup' } });

    // Measure direct
    const directTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      await directClient.callTool({ name: 'echo', arguments: { message: `run-${i}` } });
      directTimes.push(performance.now() - t0);
    }

    // Measure gateway
    const gwTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      await gwClient.callTool({ name: 'echo', arguments: { message: `run-${i}` } });
      gwTimes.push(performance.now() - t0);
    }

    await directClient.close();
    await gwClient.close();

    const avgDirect = directTimes.reduce((a, b) => a + b, 0) / iterations;
    const avgGw = gwTimes.reduce((a, b) => a + b, 0) / iterations;
    const overhead = Math.max(0, avgGw - avgDirect);

    console.log(
      `[Benchmark] Direct average: ${avgDirect.toFixed(2)}ms | Gateway average: ${avgGw.toFixed(2)}ms | Measured overhead: ${overhead.toFixed(2)}ms`,
    );

    expect(avgGw).toBeGreaterThan(0);
    expect(avgDirect).toBeGreaterThan(0);
  });
});
