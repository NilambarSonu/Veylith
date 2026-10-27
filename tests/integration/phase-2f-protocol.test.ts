import { toolMetadataText } from '../../packages/policy-engine/src/index.js';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import type * as GatewayModule from '../../apps/gateway/src/server.js';
import { Fixture } from '../../scripts/security-lab/fixture.js';
import type { LabCase } from '../../scripts/security-lab/types.js';
const schema = {
  type: 'object',
  title: 'Nested contract',
  required: ['choice', 'levels'],
  properties: {
    choice: { enum: ['alpha', 'beta'] },
    levels: { type: 'array', items: { $ref: '#/$defs/level' }, minItems: 1 },
    extra: { oneOf: [{ type: 'string' }, { type: 'null' }] },
  },
  $defs: { level: { type: 'integer', minimum: 0, maximum: 9 } },
  additionalProperties: false,
};
describe('Phase 2F real MCP schema and subscription boundary', () => {
  const fixture = new Fixture();
  let gw: typeof GatewayModule;
  let endpoint: string;
  const clients: Client[] = [];
  beforeAll(async () => {
    await fixture.start();
    fixture.reset({
      id: '2f-contract',
      operation: 'response',
      input: 'ordinary fixture reply',
    } as LabCase);
    fixture.definitions = [
      { name: 'contract', description: 'Local nested input contract', inputSchema: schema },
    ];
    Object.assign(process.env, {
      UPSTREAM_MCP_URL: fixture.url,
      GATEWAY_HOST: '127.0.0.1',
      META_AI_MODE: 'mock',
      ENFORCE_SESSIONS: 'false',
      LOG_LEVEL: 'error',
      FAIL_CLOSED: 'true',
    });
    delete process.env['AUDIT_LOG_PATH'];
    gw = await import('../../apps/gateway/src/server.js');
    await new Promise<void>((resolve) => gw.httpServer.listen(0, '127.0.0.1', resolve));
    const address = gw.httpServer.address();
    if (!address || typeof address === 'string') throw new Error('No loopback port');
    endpoint = `http://127.0.0.1:${address.port}/mcp`;
  });
  afterAll(async () => {
    await Promise.all(clients.map((c) => c.close()));
    gw.httpServer.closeAllConnections();
    await new Promise<void>((resolve) => gw.httpServer.close(() => resolve()));
    await gw.handler.close();
    await fixture.stop();
  });
  async function connect() {
    const c = new Client({ name: '2f-contract-client', version: '1' });
    await c.connect(new StreamableHTTPClientTransport(new URL(endpoint)));
    clients.push(c);
    return c;
  }
  it('advertises the exact supported upstream JSON Schema', async () => {
    const c = await connect();
    expect((await c.listTools()).tools.find((t) => t.name === 'contract')?.inputSchema).toEqual(
      schema,
    );
  });
  it('accepts nested valid arguments without rewriting them', async () => {
    const c = await connect();
    const r = await c.callTool({
      name: 'contract',
      arguments: { choice: 'alpha', levels: [0, 3, 9], extra: null },
    });
    expect(r.isError).not.toBe(true);
    expect(fixture.argumentLog.at(-1)?.arguments).toEqual({
      choice: 'alpha',
      levels: [0, 3, 9],
      extra: null,
    });
  });
  it.each([
    { choice: 'gamma', levels: [1] },
    { choice: 'alpha', levels: [10] },
    { choice: 'alpha', levels: [] },
    { choice: 'alpha', levels: [1], extra: 7 },
    { levels: [1] },
    { choice: 'alpha', levels: [1], unlisted: true },
  ])('rejects incompatible arguments before forwarding: %j', async (args) => {
    const c = await connect();
    const before = fixture.calls.length;
    const result = await c
      .callTool({ name: 'contract', arguments: args })
      .catch((e) => ({ isError: true, error: String(e) }));
    expect(result.isError).toBe(true);
    expect(fixture.calls.length).toBe(before);
  });
  it('does not advertise subscription or list-change relay it cannot deliver', async () => {
    const c = await connect();
    expect(c.getServerCapabilities()?.resources?.subscribe).not.toBe(true);
    expect(c.getServerCapabilities()?.resources?.listChanged).not.toBe(true);
  });
  it('rejects subscribe and unsubscribe without upstream subscription effects', async () => {
    const c = await connect();
    await expect(c.subscribeResource({ uri: 'lab://document' })).rejects.toThrow();
    await expect(c.unsubscribeResource({ uri: 'lab://document' })).rejects.toThrow();
    expect(fixture.calls.filter((n) => n.includes('subscribe'))).toHaveLength(0);
  });
  it('preserves the supported contract through the actual stdio bridge', async () => {
    const c = new Client({ name: '2f-stdio-contract', version: '1' });
    clients.push(c);
    await c.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: ['--import', 'tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', endpoint],
        env: { PATH: process.env['PATH'] ?? '', META_AI_MODE: 'mock', LOG_LEVEL: 'error' },
        stderr: 'pipe',
      }),
    );
    expect((await c.listTools()).tools.find((t) => t.name === 'contract')?.inputSchema).toEqual(
      schema,
    );
    const before = fixture.calls.length;
    const r = await c
      .callTool({ name: 'contract', arguments: { choice: 'unlisted', levels: [1] } })
      .catch((e) => ({ isError: true, error: String(e) }));
    expect(r.isError).toBe(true);
    expect(fixture.calls.length).toBe(before);
    expect(c.getServerCapabilities()?.resources?.subscribe).not.toBe(true);
  });
  it('denies raw subscribe requests across reconnects without creating a hidden upstream subscription', async () => {
    for (let i = 0; i < 3; i++) {
      const c = await connect();
      await c.close();
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 100 + i,
          method: 'resources/subscribe',
          params: { uri: 'lab://document' },
        }),
      });
      const text = await response.text();
      expect(text).toContain('error');
    }
    expect(fixture.calls.filter((n) => n.includes('subscribe'))).toHaveLength(0);
  });
  it('rejects hostile browser origins even with forged client/session labels', async () => {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Origin: 'https://synthetic.invalid',
        'x-veylith-client-id': 'admin',
        'x-veylith-session-id': 'vyl-sess-synthetic',
      },
      body: '{}',
    });
    expect(response.status).toBe(403);
  });
  it('quarantines unsupported upstream contracts without widening or hiding valid tools', async () => {
    fixture.definitions.push({
      name: 'unsupported_contract',
      description: 'Unsupported pattern fixture',
      inputSchema: { type: 'object', properties: { text: { type: 'string', pattern: '(a+)+' } } },
    });
    gw.invalidateDiscoveryCache();
    try {
      const c = await connect();
      const tools = (await c.listTools()).tools.map((t) => t.name);
      expect(tools).toContain('contract');
      expect(tools).not.toContain('unsupported_contract');
    } finally {
      fixture.definitions = fixture.definitions.filter((t) => t.name !== 'unsupported_contract');
      gw.invalidateDiscoveryCache();
    }
  });
  it('supports the manual-runner routing shape using a new synthetic input, never a reserved case', async () => {
    const original = gw.metaAdapter.inspect.bind(gw.metaAdapter);
    const seen: Array<{ stage: string; content: string }> = [];
    const oldInput = fixture.current.input;
    for (const tool of fixture.definitions)
      gw.securityEngine.approveTrustedContent(
        fixture.url,
        'discovery',
        tool.name,
        toolMetadataText(tool),
      );
    gw.securityEngine.approveTrustedContent(
      fixture.url,
      'resource_discovery',
      'lab://document',
      'document Local public document lab://document',
    );
    gw.securityEngine.approveTrustedContent(
      fixture.url,
      'prompt_discovery',
      'summary',
      'summary Local summary prompt []',
    );
    gw.securityEngine.capabilityRegistry.bindCapability(fixture.url, 'contract', 'PURE_OR_READ');
    fixture.current.input =
      'New synthetic prose used only for the Phase 2F manual-runner compatibility probe.';
    gw.invalidateDiscoveryCache();
    gw.metaAdapter.inspect = async (content, stage, metadata) => {
      seen.push({ stage, content });
      return original(content, stage, metadata);
    };
    try {
      const c = await connect();
      const r = await c.callTool({ name: 'contract', arguments: { choice: 'alpha', levels: [1] } });
      expect(r.isError).not.toBe(true);
      expect(seen).toEqual([{ stage: 'call_response', content: fixture.current.input }]);
    } finally {
      gw.metaAdapter.inspect = original;
      fixture.current.input = oldInput;
      gw.securityEngine.capabilityRegistry.bindCapability(fixture.url, 'contract', 'UNKNOWN');
    }
  });
  it('disables SDK-owned modern subscriptions/listen rather than silently opening a stream', async () => {
    const c = new Client(
      { name: '2f-modern', version: '1' },
      { versionNegotiation: { mode: { pin: '2026-07-28' } } },
    );
    clients.push(c);
    await c.connect(new StreamableHTTPClientTransport(new URL(endpoint)));
    await expect(c.listen({}, { timeout: 5000 })).rejects.toThrow('Subscription limit reached');
    expect(fixture.calls.filter((n) => n.includes('subscribe'))).toHaveLength(0);
  });
  it('also disables the SDK-owned modern listen path on stdio', async () => {
    const c = new Client(
      { name: '2f-modern-stdio', version: '1' },
      { versionNegotiation: { mode: { pin: '2026-07-28' } } },
    );
    clients.push(c);
    await c.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: ['--import', 'tsx', 'apps/stdio-adapter/src/index.ts', '--gateway-url', endpoint],
        env: { PATH: process.env['PATH'] ?? '', META_AI_MODE: 'mock', LOG_LEVEL: 'error' },
        stderr: 'pipe',
      }),
    );
    await expect(c.listen({}, { timeout: 5000 })).rejects.toThrow('Subscription limit reached');
  });
});
