/**
 * Benign MCP Server — Stdio Mode.
 *
 * Runs the harmless local MCP test server over standard I/O (stdio)
 * using the official MCP server SDK.
 */

import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { createBenignServer } from './index.js';

serveStdio(() => createBenignServer(), {
  legacy: 'serve',
  onerror: (err) => {
    process.stderr.write(`[benign-mcp-server:stdio] Error: ${err.message}\n`);
  },
});
