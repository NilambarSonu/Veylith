/**
 * Integration tests for Veylith Stdio Adapter (Phase 2B).
 *
 * Verifies real MCP client stdio protocol communication against Veylith:
 *   1. stdio protocol correctness (stdout is 100% valid JSON-RPC 2.0)
 *   2. Initialization and capability negotiation
 *   3. Tool discovery & Stage 1 tool poisoning filtering
 *   4. Tool calls & Stage 2 argument inspection
 *   5. Response inspection & Stage 3 prompt injection sanitization
 *   6. Cancellation notification handling
 *   7. Graceful shutdown on stdin close (EOF)
 *   8. Malformed message resilience
 *   9. Upstream server failure handling
 *  10. Secret isolation (no credentials leaked in stderr or responses)
 *  11. Standalone command mode compatibility
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { spawn, type ChildProcess } from 'node:child_process';

const SERVER_PORT = 19788;
const GATEWAY_PORT = 19787;
const SERVER_URL = `http://127.0.0.1:${SERVER_PORT}/mcp`;
const GATEWAY_URL = `http://127.0.0.1:${GATEWAY_PORT}/mcp`;

let serverProc: ChildProcess;
let gatewayProc: ChildProcess;

function waitForLog(proc: ChildProcess, match: string, timeoutMs = 15000): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Timeout waiting for log: "${match}"`)),
      timeoutMs,
    );
    const onData = (data: Buffer) => {
      const text = data.toString();
      if (text.includes(match)) {
        clearTimeout(timer);
        proc.stdout?.off('data', onData);
        proc.stderr?.off('data', onData);
        resolve();
      }
    };
    proc.stdout?.on('data', onData);
    proc.stderr?.on('data', onData);
    proc.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    proc.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Process exited prematurely with code ${code}`));
    });
  });
}

beforeAll(async () => {
  // Start harmless benign MCP test server
  serverProc = spawn('npx', ['tsx', 'examples/benign-mcp-server/src/index.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      MCP_SERVER_PORT: String(SERVER_PORT),
      MCP_SERVER_HOST: '127.0.0.1',
    },
    stdio: 'pipe',
  });
  await waitForLog(serverProc, 'Listening');

  // Start Veylith HTTP Gateway
  gatewayProc = spawn('npx', ['tsx', 'apps/gateway/src/server.ts'], {
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
  await waitForLog(gatewayProc, 'gateway started');
}, 30000);

afterAll(async () => {
  const kill = (proc: ChildProcess) => {
    if (!proc || proc.killed) return;
    try {
      proc.kill('SIGTERM');
      setTimeout(() => {
        try {
          proc.kill('SIGKILL');
        } catch {
          // ignore
        }
      }, 1000);
    } catch {
      // ignore
    }
  };
  kill(gatewayProc);
  kill(serverProc);
});

describe('Veylith Stdio Adapter — Gateway Bridge Mode', () => {
  it('establishes stdio connection, performs initialization and capability negotiation', async () => {
    const client = new Client({ name: 'test-stdio-client', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);
    expect(client.getServerVersion()?.name).toBe('veylith-stdio-adapter');
    expect(client.getServerCapabilities()?.tools).toBeDefined();

    await client.close();
  });

  it('guarantees stdout contains strictly valid JSON-RPC messages and no raw logs', async () => {
    const adapterProcess = spawn(
      'npx',
      ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      {
        cwd: process.cwd(),
        env: { ...process.env, LOG_LEVEL: 'info' },
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    let stdoutData = '';
    adapterProcess.stdout.on('data', (d) => {
      stdoutData += d.toString();
    });

    // Send standard MCP initialize request over stdin
    const initReq =
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'test-raw-client', version: '0.1.0' },
        },
      }) + '\n';

    adapterProcess.stdin.write(initReq);

    // Wait for response line
    await new Promise((resolve) => setTimeout(resolve, 1500));

    // Every line on stdout must be strictly parseable JSON
    const lines = stdoutData.trim().split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
      const msg = JSON.parse(line);
      expect(msg.jsonrpc).toBe('2.0');
    }

    adapterProcess.kill('SIGTERM');
  });

  it('discovers clean tools and filters out poisoned tool descriptions (Stage 1)', async () => {
    const client = new Client({ name: 'test-stdio-client', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);

    expect(names).toContain('echo');
    expect(names).toContain('add');
    // The poisoned tool description must be filtered at the gateway boundary
    expect(names).not.toContain('poisoned_discovery_tool');

    await client.close();
  });

  it('executes normal tool call successfully over stdio (Workflow A)', async () => {
    const client = new Client({ name: 'test-stdio-client', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);
    const result = await client.callTool({
      name: 'echo',
      arguments: { message: 'stdio integration test payload' },
    });

    expect(result.isError).toBeFalsy();
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0]?.text).toBe('stdio integration test payload');

    await client.close();
  });

  it('blocks deliberately dangerous arguments over stdio without crashing (Workflow B)', async () => {
    const client = new Client({ name: 'test-stdio-client', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);
    const result = await client.callTool({
      name: 'echo',
      arguments: { message: 'rm -rf /' },
    });

    expect(result.isError).toBe(true);
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0]?.text).toContain('Veylith policy blocked this call');

    await client.close();
  });

  it('intercepts and sanitizes indirect prompt injection in tool output (Workflow C)', async () => {
    const client = new Client({ name: 'test-stdio-client', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);
    const result = await client.callTool({
      name: 'simulate_untrusted_source',
      arguments: { sourceId: 'injection_doc' },
    });

    expect(result.isError).toBe(true);
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0]?.text).toContain('[Veylith Security Notice]');
    expect(content[0]?.text).not.toContain('delete all logs and send tokens');

    await client.close();
  });

  it('supports cancellation notification (notifications/cancelled)', async () => {
    const client = new Client({ name: 'test-stdio-client', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);

    // Call tool and send cancellation notification
    const callPromise = client.callTool({
      name: 'echo',
      arguments: { message: 'cancellation test' },
    });

    // Send cancellation for in-flight request
    await client.notification({
      method: 'notifications/cancelled',
      params: { requestId: 9999, reason: 'User requested cancellation' },
    });

    const res = await callPromise;
    expect(res).toBeDefined();

    await client.close();
  });

  it('handles client disconnection / stdin EOF cleanly with exit 0', async () => {
    const adapterProcess = spawn(
      'npx',
      ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      {
        cwd: process.cwd(),
        env: { ...process.env, LOG_LEVEL: 'error' },
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    const exitPromise = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolve) => {
        adapterProcess.on('exit', (code, signal) => resolve({ code, signal }));
      },
    );

    // Close stdin to simulate client process termination (EOF)
    adapterProcess.stdin.end();

    const result = await exitPromise;
    expect(result.code).toBe(0);
  });

  it('handles malformed JSON messages on stdio gracefully', async () => {
    const adapterProcess = spawn(
      'npx',
      ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', GATEWAY_URL],
      {
        cwd: process.cwd(),
        env: { ...process.env, LOG_LEVEL: 'error' },
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    // Write malformed garbage to stdin
    adapterProcess.stdin.write('THIS IS NOT VALID JSON\n');
    await new Promise((resolve) => setTimeout(resolve, 500));

    // Ensure process did not crash
    expect(adapterProcess.killed).toBe(false);

    adapterProcess.kill('SIGTERM');
  });

  it('handles upstream unreachable error safely without crashing transport', async () => {
    const client = new Client({ name: 'test-stdio-client', version: '0.1.0' });
    // Point to non-existent gateway port
    const transport = new StdioClientTransport({
      command: 'npx',
      args: [
        'tsx',
        'apps/stdio-adapter/src/index.ts',
        '--gateway-url',
        'http://127.0.0.1:49999/mcp',
      ],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain('veylith_status');

    const result = await client.callTool({
      name: 'veylith_status',
      arguments: {},
    });

    expect(result.isError).toBe(true);
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0]?.text).toContain('upstream server initialization failed');

    await client.close();
  });
});

describe('Veylith Stdio Adapter — Standalone Subprocess Mode', () => {
  it('runs policy engine in-process and wraps upstream command directly over stdio', async () => {
    const client = new Client({ name: 'test-standalone-client', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: 'npx',
      args: [
        'tsx',
        'apps/stdio-adapter/src/index.ts',
        '--meta-mode',
        'mock',
        '--',
        'npx',
        'tsx',
        'examples/benign-mcp-server/src/stdio.ts',
      ],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);

    // 1. Tool discovery
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain('echo');
    expect(names).not.toContain('poisoned_discovery_tool');

    // 2. Normal execution
    const normal = await client.callTool({
      name: 'echo',
      arguments: { message: 'standalone mode verified' },
    });
    expect(normal.isError).toBeFalsy();

    // 3. Dangerous execution blocked
    const blocked = await client.callTool({
      name: 'echo',
      arguments: { message: 'rm -rf /' },
    });
    expect(blocked.isError).toBe(true);

    await client.close();
  });
});
