#!/usr/bin/env node
/**
 * Executable launcher for Veylith Stdio Adapter.
 *
 * Runs the TypeScript entrypoint directly via tsx, suitable for:
 *   - Claude Desktop configuration
 *   - Cursor MCP configuration
 *   - Terminal CLI usage
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import process from 'node:process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const target = join(__dirname, '../apps/stdio-adapter/src/index.ts');

const child = spawn(
  process.execPath,
  [join(__dirname, '../node_modules/tsx/dist/cli.mjs'), target, ...process.argv.slice(2)],
  {
    stdio: 'inherit',
    env: process.env,
  },
);

child.on('exit', (code) => {
  process.exit(code ?? 0);
});
