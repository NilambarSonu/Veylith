import { createServer, type Server } from 'node:http';
import type { LabCase } from './types.js';
export interface Definition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}
export class Fixture {
  current!: LabCase;
  calls: string[] = [];
  argumentLog: Array<{ tool: string; arguments: unknown }> = [];
  methods: string[] = [];
  definitions: Definition[] = [];
  outage = false;
  revision = 0;
  barrier?: () => void;
  release?: () => void;
  held?: Promise<void>;
  server: Server;
  url = '';
  constructor() {
    this.server = createServer(async (req, res) => {
      try {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(Buffer.from(chunk));
        if (!chunks.length) {
          res.writeHead(405).end();
          return;
        }
        const msg = JSON.parse(Buffer.concat(chunks).toString());
        if (!('id' in msg)) {
          res.writeHead(202).end();
          return;
        }
        if (this.outage) {
          res.writeHead(503).end('synthetic outage');
          return;
        }
        const method = msg.method as string;
        const params = msg.params ?? {};
        this.methods.push(method);
        let result: unknown;
        const input = this.current?.input ?? 'local fixture';
        const parts = Array.isArray(input) ? input : [input];
        switch (method) {
          case 'initialize':
            result = {
              protocolVersion: params.protocolVersion,
              capabilities: { tools: {}, resources: { subscribe: true }, prompts: {} },
              serverInfo: { name: 'isolated-lab-fixture', version: '1' },
            };
            break;
          case 'ping':
            result = {};
            break;
          case 'tools/list': {
            result = { tools: structuredClone(this.definitions) };
            const barrier = this.barrier;
            this.barrier = undefined;
            barrier?.();
            break;
          }
          case 'tools/call': {
            this.calls.push(params.name);
            if (this.argumentLog.length >= 64) this.argumentLog.shift();
            this.argumentLog.push({
              tool: params.name,
              arguments: structuredClone(params.arguments ?? {}),
            });
            if (this.held) await this.held;
            const text =
              params.name === 'add'
                ? String(Number(params.arguments.a) + Number(params.arguments.b))
                : (params.arguments?.marker ?? parts[0]);
            result = {
              content:
                this.current.operation === 'fragments-response'
                  ? parts.map((text) => ({ type: 'text', text }))
                  : [{ type: 'text', text }],
            };
            break;
          }
          case 'resources/list':
            result = {
              resources: [
                { uri: 'lab://document', name: 'document', description: 'Local public document' },
              ],
            };
            break;
          case 'resources/templates/list':
            result = { resourceTemplates: [] };
            break;
          case 'resources/read': {
            this.calls.push('resources/read');
            let items: unknown[] = parts.map((text) => ({
              uri: params.uri,
              text,
              mimeType: 'text/plain',
            }));
            if (this.current.operation === 'binary')
              items = [
                {
                  uri: params.uri,
                  blob: Buffer.from('SYNTHETIC').toString('base64'),
                  mimeType: 'application/octet-stream',
                },
              ];
            if (this.current.operation === 'resource-limit')
              items = [{ uri: params.uri, text: 'A'.repeat(4097) }];
            if (this.current.operation === 'sequential')
              items = [{ uri: params.uri, text: parts[this.revision++ % parts.length] }];
            result = { contents: items };
            break;
          }
          case 'prompts/list':
            result = { prompts: [{ name: 'summary', description: 'Local summary prompt' }] };
            break;
          case 'prompts/get':
            this.calls.push('prompts/get');
            result = {
              messages: parts.map((text) => ({ role: 'user', content: { type: 'text', text } })),
            };
            break;
          case 'resources/subscribe':
          case 'resources/unsubscribe':
            this.calls.push(method);
            result = {};
            break;
          default:
            res.writeHead(200, { 'Content-Type': 'application/json' }).end(
              JSON.stringify({
                jsonrpc: '2.0',
                id: msg.id,
                error: { code: -32601, message: 'Unsupported synthetic method' },
              }),
            );
            return;
        }
        res
          .writeHead(200, { 'Content-Type': 'application/json' })
          .end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result }));
      } catch {
        if (!res.headersSent) res.writeHead(400).end();
      }
    });
  }
  async start() {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    const address = this.server.address();
    if (!address || typeof address === 'string') throw new Error('No local port');
    this.url = `http://127.0.0.1:${address.port}/mcp`;
  }
  reset(c: LabCase) {
    this.current = c;
    this.calls = [];
    this.argumentLog = [];
    this.methods = [];
    this.outage = false;
    this.revision = 0;
    this.barrier = undefined;
    this.held = undefined;
    this.definitions = ['reader', 'unknown', 'restricted_demo_tool', 'privileged_sink', 'add'].map(
      (name) => ({
        name,
        description: 'Local fixture utility',
        inputSchema: {
          type: 'object',
          properties: { marker: { type: 'string' } },
          additionalProperties: true,
        },
      }),
    );
    const first = this.definitions[0]!;
    if (c.operation === 'metadata') first.description = String(c.input);
    if (c.operation === 'schema')
      first.inputSchema = {
        type: 'object',
        properties: { query: { type: 'string', description: c.input } },
      };
    if (c.operation === 'annotation')
      this.definitions[1]!.annotations = { readOnlyHint: true, destructiveHint: false };
  }
  mutate(text: string) {
    this.definitions[0]!.description = `Updated local definition: ${text}`;
  }
  hold() {
    this.held = new Promise<void>((resolve) => {
      this.release = resolve;
    });
  }
  async stop() {
    this.release?.();
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}
