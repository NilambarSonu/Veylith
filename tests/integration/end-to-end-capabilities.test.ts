/**
 * End-to-End Capability-Aware Policy Verification across Both HTTP and Stdio Transports.
 *
 * Requirements:
 *   1. HTTP Gateway Path:
 *      - Verified PURE_OR_READ tool ('echo') calling 'rm -rf /' is ALLOWED over HTTP.
 *      - Unverified/UNKNOWN tool calling 'rm -rf /' is BLOCKED by hard invariant over HTTP.
 *   2. Stdio Adapter Path:
 *      - Verified PURE_OR_READ tool calling 'rm -rf /' is ALLOWED over stdio.
 *      - Unverified/UNKNOWN tool calling 'rm -rf /' is BLOCKED by hard invariant over stdio.
 *   3. Guarantees real client-server protocol behavior across both MCP transports.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { type ChildProcess, spawn } from 'node:child_process';

const TEST_SERVER_PORT = 20788;
const TEST_GATEWAY_PORT = 20787;
const TEST_SERVER_URL = `http://127.0.0.1:${TEST_SERVER_PORT}/mcp`;
const TEST_GATEWAY_URL = `http://127.0.0.1:${TEST_GATEWAY_PORT}/mcp`;

let serverProc: ChildProcess;
let gatewayProc: ChildProcess;

function waitForReady(proc: ChildProcess, marker: string, timeoutMs = 15000): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`Timeout waiting for marker: ${marker}`)),
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
  // 1. Start benign upstream MCP HTTP server
  serverProc = spawn('npx', ['tsx', 'examples/benign-mcp-server/src/index.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      MCP_SERVER_PORT: String(TEST_SERVER_PORT),
      MCP_SERVER_HOST: '127.0.0.1',
    },
    stdio: 'pipe',
  });

  await waitForReady(serverProc, 'Listening');

  // 2. Start Veylith HTTP Gateway with TOOL_CAPABILITIES explicitly binding 'echo' as PURE_OR_READ
  // Notice that 'simulate_untrusted_source' is NOT bound, so it defaults to UNKNOWN
  gatewayProc = spawn('npx', ['tsx', 'apps/gateway/src/server.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GATEWAY_PORT: String(TEST_GATEWAY_PORT),
      GATEWAY_HOST: '127.0.0.1',
      UPSTREAM_MCP_URL: TEST_SERVER_URL,
      BLOCKED_TOOLS: 'restricted_demo_tool',
      TOOL_CAPABILITIES: `echo:PURE_OR_READ:${TEST_SERVER_URL}`,
      LOG_LEVEL: 'info',
    },
    stdio: 'pipe',
  });

  await waitForReady(gatewayProc, 'gateway started');
}, 30000);

afterAll(async () => {
  const killProc = (proc?: ChildProcess) =>
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
      }, 2000);
    });

  await Promise.all([killProc(gatewayProc), killProc(serverProc)]);
});

describe('End-to-End Capability-Aware Enforcement over HTTP Transport', () => {
  it('allows rm -rf / inside verified PURE_OR_READ tool over HTTP gateway', async () => {
    const client = new Client({ name: 'http-cap-client', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(TEST_GATEWAY_URL));
    await client.connect(transport);

    const res = await client.callTool({
      name: 'echo',
      arguments: { message: 'safe explanation: do not run rm -rf / on unix systems' },
    });

    expect(res.isError).toBeFalsy();
    const texts = (res.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(texts[0]).toContain('safe explanation: do not run rm -rf / on unix systems');

    await client.close();
  });

  it('allows DROP TABLE inside verified PURE_OR_READ tool over HTTP gateway', async () => {
    const client = new Client({ name: 'http-cap-client', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(TEST_GATEWAY_URL));
    await client.connect(transport);

    const res = await client.callTool({
      name: 'echo',
      arguments: { message: 'SELECT id FROM users; DROP TABLE audits;' },
    });

    expect(res.isError).toBeFalsy();
    const texts = (res.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(texts[0]).toContain('DROP TABLE audits');

    await client.close();
  });

  it('blocks rm -rf / in unverified UNKNOWN tool over HTTP gateway', async () => {
    const client = new Client({ name: 'http-cap-client', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(TEST_GATEWAY_URL));
    await client.connect(transport);

    // 'simulate_untrusted_source' has no capability binding -> defaults to UNKNOWN
    const res = await client.callTool({
      name: 'simulate_untrusted_source',
      arguments: { sourceId: 'rm -rf /' },
    });

    expect(res.isError).toBe(true);
    const texts = (res.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(texts.some((t) => t.includes('Dangerous arguments blocked'))).toBe(true);

    await client.close();
  });
});

describe('End-to-End Capability-Aware Enforcement over Stdio Transport', () => {
  it('allows rm -rf / in verified PURE_OR_READ tool and blocks in UNKNOWN tool over Stdio', async () => {
    const client = new Client({ name: 'stdio-cap-test-client', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', TEST_GATEWAY_URL],
      env: { ...process.env, LOG_LEVEL: 'error' },
      stderr: 'pipe',
    });

    await client.connect(transport);

    // 1. Invoke verified PURE_OR_READ tool over stdio with destructive argument string
    const allowedRes = await client.callTool({
      name: 'echo',
      arguments: { message: 'documentation note: rm -rf / is dangerous' },
    });

    expect(allowedRes.isError).toBeFalsy();
    const allowedTexts = (allowedRes.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(allowedTexts[0]).toContain('rm -rf / is dangerous');

    // 2. Invoke unverified UNKNOWN tool over stdio with destructive argument string
    const blockedRes = await client.callTool({
      name: 'simulate_untrusted_source',
      arguments: { sourceId: 'rm -rf /' },
    });

    expect(blockedRes.isError).toBe(true);
    const blockedTexts = (blockedRes.content as Array<{ type: string; text: string }>)
      .filter((b) => b.type === 'text')
      .map((b) => b.text);
    expect(blockedTexts.some((t) => t.includes('Dangerous arguments blocked'))).toBe(true);

    await client.close();
  });
});
