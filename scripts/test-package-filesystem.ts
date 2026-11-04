import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

async function runTest(): Promise<void> {
  const testRoot = '/tmp/veylith-fs-smoke';
  const sandboxDir = resolve(testRoot, 'sandbox');

  if (existsSync(testRoot)) {
    rmSync(testRoot, { recursive: true, force: true });
  }
  mkdirSync(sandboxDir, { recursive: true });

  const safeFilePath = resolve(sandboxDir, 'test.txt');
  writeFileSync(safeFilePath, 'Hello from Veylith secured sandbox!', 'utf8');

  const veylithBin = resolve(process.cwd(), 'packages/veylith/bin/veylith.js');

  console.log('[test] Launching Veylith stdio wrapper wrapping server-filesystem...');
  console.log(`[test] Binary: ${veylithBin}`);
  console.log(`[test] Sandbox: ${sandboxDir}`);

  const transport = new StdioClientTransport({
    command: 'node',
    args: [
      veylithBin,
      '--blocked-tools',
      'move_file',
      '--',
      'npx',
      '-y',
      '@modelcontextprotocol/server-filesystem',
      sandboxDir,
    ],
    stderr: 'inherit',
  });

  const client = new Client({ name: 'smoke-test-client', version: '1.0.0' }, { capabilities: {} });

  try {
    console.log('[test] Connecting client to Veylith...');
    await client.connect(transport);
    console.log('[test] Connected successfully!');

    // 1. List tools
    console.log('[test] Listing tools via Veylith discovery...');
    const toolsResult = await client.listTools();
    const toolNames = toolsResult.tools.map((t) => t.name);
    console.log('[test] Discovered tools:', toolNames);

    if (!toolNames.includes('read_file')) {
      throw new Error(`Expected 'read_file' in discovered tools, got: ${toolNames.join(', ')}`);
    }

    // 2. Blocked tool call test (--blocked-tools move_file)
    console.log('[test] Calling blocked tool (move_file)...');
    const blockedCallResult = await client.callTool({
      name: 'move_file',
      arguments: { source: safeFilePath, destination: safeFilePath + '.bak' },
    });
    console.log('[test] Blocked call result:', JSON.stringify(blockedCallResult));
    const blockedText =
      (blockedCallResult.content as Array<{ type: string; text?: string }>)?.[0]?.text ?? '';
    if (!blockedCallResult.isError || !blockedText.includes('Veylith policy blocked this call')) {
      throw new Error(
        `Expected move_file to be blocked by Veylith policy, got: ${JSON.stringify(blockedCallResult)}`,
      );
    }
    console.log('[test] Blocked tool execution successfully intercepted by policy engine!');

    // 2. Safe tool call (read_file inside sandbox)
    console.log('[test] Executing safe tool call (read_file in sandbox)...');
    const safeReadResult = await client.callTool({
      name: 'read_file',
      arguments: { path: safeFilePath },
    });
    console.log('[test] Safe read result:', JSON.stringify(safeReadResult));

    const contentText = (safeReadResult.content as Array<{ type: string; text: string }>)?.[0]
      ?.text;
    if (!contentText || !contentText.includes('Hello from Veylith')) {
      throw new Error(`Safe read failed or content mismatched: ${JSON.stringify(safeReadResult)}`);
    }
    console.log('[test] Safe tool execution verified!');

    // 3. Dangerous tool call (path traversal / unauthorized file access)
    console.log('[test] Testing dangerous tool call (path traversal / unauthorized access)...');
    const dangerousResult = await client.callTool({
      name: 'read_file',
      arguments: { path: '/etc/passwd' },
    });
    console.log('[test] Dangerous call result:', JSON.stringify(dangerousResult));

    // Verify it was either blocked by Veylith or rejected as an error
    if (!dangerousResult.isError) {
      throw new Error('Dangerous access was NOT blocked or marked as error!');
    }
    console.log('[test] Dangerous access was properly contained!');

    console.log('[test] ALL REAL MCP INTEGRATION CHECKS PASSED!');
  } finally {
    console.log('[test] Closing client transport...');
    await client.close();
    if (existsSync(testRoot)) {
      rmSync(testRoot, { recursive: true, force: true });
    }
    console.log('[test] Cleaned up temporary test files.');
  }
}

runTest().catch((err) => {
  console.error('[test] SMOKE TEST FAILED:', err);
  process.exit(1);
});
