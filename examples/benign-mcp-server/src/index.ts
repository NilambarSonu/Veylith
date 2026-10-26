/**
 * Benign MCP Server — safe local server for Veylith testing.
 *
 * Exposes two harmless tools:
 *   - echo: returns an input string
 *   - add: adds two numeric values
 *   - restricted_demo_tool: exists to test policy blocking
 *
 * This server performs:
 *   ✓ No filesystem mutation
 *   ✓ No shell execution
 *   ✓ No network requests beyond local test connections
 *
 * Served over Streamable HTTP on a configurable port (default 8788).
 */

import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import { createServer } from 'node:http';

const PORT = parseInt(process.env['MCP_SERVER_PORT'] ?? '8788', 10);
const HOST = process.env['MCP_SERVER_HOST'] ?? '127.0.0.1';

/** Factory function that builds a fresh McpServer per request. */
function createBenignServer(): McpServer {
  const server = new McpServer({
    name: 'veylith-benign-test-server',
    version: '0.1.0',
  });

  // Tool: echo
  server.registerTool(
    'echo',
    {
      description: 'Returns the input message unchanged',
      inputSchema: z.object({
        message: z.string().describe('The message to echo back'),
      }),
    },
    async ({ message }) => ({
      content: [{ type: 'text', text: message }],
    }),
  );

  // Tool: add
  server.registerTool(
    'add',
    {
      description: 'Adds two numbers and returns the result',
      inputSchema: z.object({
        a: z.number().describe('First number'),
        b: z.number().describe('Second number'),
      }),
    },
    async ({ a, b }) => ({
      content: [{ type: 'text', text: String(a + b) }],
    }),
  );

  // Tool: restricted_demo_tool (exists to test policy blocking)
  server.registerTool(
    'restricted_demo_tool',
    {
      description: 'A restricted tool used to test Veylith policy blocking',
      inputSchema: z.object({
        action: z.string().describe('The action to perform'),
      }),
    },
    async ({ action }) => ({
      content: [{ type: 'text', text: `Would have performed: ${action}` }],
    }),
  );

  return server;
}

// Create the MCP handler using the v2 factory pattern
const handler = createMcpHandler(() => createBenignServer());

// Serve over raw Node.js HTTP
const httpServer = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${HOST}:${PORT}`);

  // Only handle /mcp path
  if (url.pathname !== '/mcp') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found. MCP endpoint is at /mcp' }));
    return;
  }

  // Build a web-standard Request from the Node.js IncomingMessage
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value !== undefined) {
      if (Array.isArray(value)) {
        for (const v of value) headers.append(key, v);
      } else {
        headers.set(key, value);
      }
    }
  }

  const bodyChunks: Buffer[] = [];
  for await (const chunk of req) {
    bodyChunks.push(chunk as Buffer);
  }
  const body = Buffer.concat(bodyChunks);

  const webRequest = new Request(url.toString(), {
    method: req.method ?? 'POST',
    headers,
    body: ['GET', 'HEAD'].includes(req.method ?? 'GET') ? undefined : body,
  });

  try {
    const webResponse = await handler.fetch(webRequest);

    // Stream the response back
    res.writeHead(webResponse.status, Object.fromEntries(webResponse.headers.entries()));
    if (webResponse.body) {
      const reader = webResponse.body.getReader();
      const pump = async (): Promise<void> => {
        const { done, value } = await reader.read();
        if (done) {
          res.end();
          return;
        }
        res.write(value);
        return pump();
      };
      await pump();
    } else {
      res.end(await webResponse.text());
    }
  } catch (err) {
    console.error('[benign-mcp-server] Error handling request:', err);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
});

httpServer.listen(PORT, HOST, () => {
  console.log(`[benign-mcp-server] Listening on http://${HOST}:${PORT}/mcp`);
});

// Graceful shutdown
const shutdown = () => {
  console.log('[benign-mcp-server] Shutting down...');
  handler.close();
  httpServer.close(() => {
    console.log('[benign-mcp-server] Closed.');
    process.exit(0);
  });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

export { createBenignServer };
