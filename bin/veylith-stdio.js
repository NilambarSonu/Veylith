#!/usr/bin/env node
/**
 * Executable launcher for Veylith Stdio Adapter.
 *
 * Execution Resolution Order:
 *   1. Production standalone bundle (dist/standalone.mjs) via pure Node.js (zero TS dependencies)
 *   2. Local development source (src/index.ts) via tsx
 *   3. Native Node.js type-stripping fallback (--experimental-strip-types)
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { existsSync } from 'node:fs';
import process from 'node:process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const standaloneBundle = join(__dirname, '../apps/stdio-adapter/dist/standalone.mjs');
const tsSource = join(__dirname, '../apps/stdio-adapter/src/index.ts');
const tsxCli = join(__dirname, '../node_modules/tsx/dist/cli.mjs');

let childArgs = [];

if (existsSync(standaloneBundle)) {
  // Production standalone bundle: runs with pure Node, zero devDependencies required
  childArgs = [standaloneBundle, ...process.argv.slice(2)];
} else if (existsSync(tsxCli)) {
  // Development fallback: runs TypeScript source via local tsx
  childArgs = [tsxCli, tsSource, ...process.argv.slice(2)];
} else {
  // Node.js native type-stripping fallback (Node >=22.6)
  childArgs = ['--experimental-strip-types', tsSource, ...process.argv.slice(2)];
}

const child = spawn(process.execPath, childArgs, {
  stdio: 'inherit',
  env: process.env,
});

child.on('exit', (code) => {
  process.exit(code ?? 0);
});
